//! `launch` argv contract and memory cap, proven through the real helper
//! binary, plus the lib's memory-limit and pipe-readiness wrappers: any
//! pre-`--` token other than one canonical `--memory-budget` or one
//! `--resource-profile check` fails closed before exec; the cap is fixed
//! on Linux and relative to the measured map size on macOS; a launch
//! without the flags keeps today's limits. The check profile proves its
//! measured limits against a real offline Cargo test, and the lib's
//! process/uid/resident reads prove their surfaces.
//!
//! This binary installs a no-op SIGUSR1 handler for the interrupted-wait
//! test; nothing else here sends SIGUSR1.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures use expect for setup failures and panic on wrong outcomes (standards §14)"
)]
use std::ffi::CString;
use std::io::{Read as _, Write as _};
use std::os::fd::AsFd as _;
use std::os::raw::{c_char, c_int, c_uint};
use std::os::unix::process::CommandExt as _;
use std::os::unix::thread::{JoinHandleExt as _, RawPthread};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use rivect_sandbox_helper::{
    EXIT_PROTOCOL, INDEX_WORKER_MEMORY_BUDGET, MEMORY_BUDGET_FLAG, ProcessReadError,
    RESOURCE_PROFILE_FLAG, kill_process_group, memory_limit, process_group_members, resident_bytes,
    set_nonblocking, uid_process_count, wait_ready,
};

const HELPER: &str = env!("CARGO_BIN_EXE_rivect-sandbox-helper");
const MIB: u64 = 1024 * 1024;
const TOUCH: &str = "/usr/bin/touch";

/// Independent DEC-040 check-profile limits, pinned as literals on
/// purpose: these expectations must NOT read the implementation's
/// CHECK_* constants, or a ceiling bump in lib.rs would pass this suite
/// silently. Hard CPU 120 s inside the 300 s ceiling, per-file 512 MiB,
/// NOFILE 4096, NPROC headroom 256, Linux address space 8 GiB, sampled
/// group RSS 4 GiB.
const PROFILE_CPU_SECONDS: u64 = 120;
const PROFILE_FSIZE_BYTES: u64 = 512 * MIB;
const PROFILE_NOFILE: u64 = 4096;
const PROFILE_NPROC_HEADROOM: u64 = 256;
#[cfg(target_os = "linux")]
const PROFILE_AS_BYTES: u64 = 8 * 1024 * MIB;
const PROFILE_GROUP_RSS_BYTES: u64 = 4 * 1024 * MIB;

/// Set on the re-executed test binary so it reports instead of recursing.
const CHILD_MARKER: &str = "RIVECT_LAUNCH_TEST_CHILD";
/// Set on the re-executed test binary inside the setpriv nobody chain so
/// it runs the over-limit fork loop (Linux non-root NPROC leg only).
#[cfg(target_os = "linux")]
const NONROOT_NPROC_CHILD_MARKER: &str = "RIVECT_NONROOT_NPROC_CHILD";
/// A timeout leg must wait at least this long and return well before ten
/// times it, so a wait that stretches the timeout fails.
const IDLE_TIMEOUT: Duration = Duration::from_millis(300);
const IDLE_MAX: Duration = Duration::from_secs(2);
/// A readiness leg waits up to this long and must return well before it.
const READY_TIMEOUT: Duration = Duration::from_secs(30);
const READY_MAX: Duration = Duration::from_secs(10);
/// The lowered-limit shell exits with this when it refuses its `ulimit`.
const ULIMIT_REFUSED: i32 = 97;
/// Launches allowed per lowered-limit leg before a refusal fails the test.
const ULIMIT_ATTEMPTS: u32 = 5;
#[cfg(target_os = "macos")]
const SIGUSR1: i32 = 30;
#[cfg(target_os = "linux")]
const SIGUSR1: i32 = 10;
/// `SIGKILL` (raw 9 on both platforms): fixture teardown's member kill.
const SIGKILL: i32 = 9;
/// `ESRCH`: a process that exited between listing and reading (3 on both
/// platforms; std does not map it to `ErrorKind::NotFound`).
const ESRCH: i32 = 3;
/// `SIG_ERR`: `signal` reports failure as the handler value `-1`.
const SIG_ERR: usize = usize::MAX;
/// `EPERM` (raw 1): the errno the kernel answers a `mount(2)` from a
/// process without CAP_SYS_ADMIN over the mount namespace's owning user
/// namespace.
#[cfg(target_os = "linux")]
const EPERM: i32 = 1;

extern "C" fn ignore_signal(_signal: i32) {}

// SAFETY: the declarations mirror the POSIX libc signatures on macOS and
// Linux; `RawPthread` is the platform `pthread_t`.
unsafe extern "C" {
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
    fn siginterrupt(signum: i32, flag: i32) -> i32;
    fn pthread_kill(thread: RawPthread, signum: i32) -> i32;
    fn geteuid() -> u32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn mkfifo(path: *const c_char, mode: c_uint) -> c_int;
    #[cfg(target_os = "linux")]
    fn mount(
        source: *const c_char,
        target: *const c_char,
        filesystemtype: *const c_char,
        mountflags: std::os::raw::c_ulong,
        data: *const std::os::raw::c_void,
    ) -> c_int;
}

/// The PATH every test child gets: the host's own PATH, or the standard
/// default when the harness runs without one.
fn child_path() -> std::ffi::OsString {
    std::env::var_os("PATH")
        .unwrap_or_else(|| std::ffi::OsString::from("/usr/local/bin:/usr/bin:/bin"))
}

/// A test child with exactly the allowlisted environment: cleared, then
/// PATH, plus whatever the caller adds (test markers). Ambient env — a
/// developer shell's BASH_ENV, proxy variables, CI secrets — never
/// crosses into a spawned child (standards §10).
fn test_child(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(program);
    command.env_clear().env("PATH", child_path());
    command
}

fn launch(options: &[&str], program: &[&str]) -> Output {
    test_child(HELPER)
        .arg("launch")
        .args(options)
        .arg("--")
        .args(program)
        .output()
        .expect("run the helper")
}

struct TempTree(tempfile::TempDir);

impl std::ops::Deref for TempTree {
    type Target = Path;
    fn deref(&self) -> &Path {
        self.0.path()
    }
}

impl AsRef<Path> for TempTree {
    fn as_ref(&self) -> &Path {
        self.0.path()
    }
}

impl AsRef<std::ffi::OsStr> for TempTree {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.0.path().as_os_str()
    }
}

fn scratch(tag: &str) -> TempTree {
    TempTree(
        tempfile::Builder::new()
            .prefix(&format!("rivect-launch-{tag}-"))
            .tempdir()
            .expect("fresh native scratch directory"),
    )
}

fn assert_rejected_before_exec(output: &Output, marker: &Path, case: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(EXIT_PROTOCOL),
        "{case}: expected EXIT_PROTOCOL, stderr {stderr:?}"
    );
    assert!(
        stderr.starts_with("rivect-sandbox-helper:"),
        "{case}: stderr must carry the helper prefix, got {stderr:?}"
    );
    assert!(!marker.exists(), "{case}: the program must never run");
}

/// A shell's soft and hard address-space and data limits under
/// `launch <options> --`, in KiB; `None` is `unlimited`.
#[derive(Debug)]
struct LaunchedLimits {
    address_space: Option<u64>,
    data: Option<u64>,
    hard_address_space: Option<u64>,
    hard_data: Option<u64>,
}

fn launched_limits(options: &[&str]) -> LaunchedLimits {
    let output = launch(
        options,
        &[
            "/bin/sh",
            "-c",
            "ulimit -v; ulimit -d; ulimit -H -v; ulimit -H -d",
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "launch {options:?}: {:?} stdout {stdout:?} stderr {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let views: Vec<Option<u64>> = stdout
        .lines()
        .map(|line| parse_ulimit(line.trim()))
        .collect();
    let [address_space, data, hard_address_space, hard_data] = views[..] else {
        panic!("launch {options:?}: expected four ulimit lines, got {stdout:?}");
    };
    LaunchedLimits {
        address_space,
        data,
        hard_address_space,
        hard_data,
    }
}

fn parse_ulimit(view: &str) -> Option<u64> {
    if view == "unlimited" {
        None
    } else {
        Some(view.parse().expect("ulimit prints KiB or unlimited"))
    }
}

#[test]
fn launch_rejects_unknown_options_before_the_separator() {
    let dir = scratch("unknown");
    let marker = dir.join("M");
    let marker_arg = marker.to_str().expect("utf-8 scratch path");

    let bogus = launch(&["--bogus"], &[TOUCH, marker_arg]);
    assert_rejected_before_exec(&bogus, &marker, "--bogus");

    let repeated = launch(
        &[MEMORY_BUDGET_FLAG, "1", MEMORY_BUDGET_FLAG, "2"],
        &[TOUCH, marker_arg],
    );
    assert_rejected_before_exec(&repeated, &marker, "repeated --memory-budget");

    // Control: the same program runs once nothing precedes the separator.
    let plain = launch(&[], &[TOUCH, marker_arg]);
    assert!(plain.status.success(), "plain launch: {:?}", plain.status);
    assert!(marker.exists(), "plain launch must run the program");
}

#[test]
fn memory_budget_flag_rejects_zero_overflow_and_garbage() {
    let dir = scratch("budget");
    let marker = dir.join("M");
    let marker_arg = marker.to_str().expect("utf-8 scratch path");
    let above_bound = (INDEX_WORKER_MEMORY_BUDGET + 1).to_string();
    // `--` right after the flag is a missing value, not the separator.
    for value in [
        "0",
        "18446744073709551616",
        "-1",
        "+1",
        "01",
        "1k",
        "",
        " 1",
        above_bound.as_str(),
        "--",
    ] {
        let output = launch(&[MEMORY_BUDGET_FLAG, value], &[TOUCH, marker_arg]);
        assert_rejected_before_exec(&output, &marker, &format!("value {value:?}"));
    }

    let at_bound = INDEX_WORKER_MEMORY_BUDGET.to_string();
    let accepted = launch(&[MEMORY_BUDGET_FLAG, &at_bound], &[TOUCH, marker_arg]);
    assert!(
        accepted.status.success(),
        "the bound itself is accepted: {:?} stderr {:?}",
        accepted.status,
        String::from_utf8_lossy(&accepted.stderr)
    );
    assert!(marker.exists(), "a valid budget must run the program");
}

#[test]
fn launch_without_the_flag_keeps_existing_limits() {
    let kib = launched_limits(&[]).address_space;
    eprintln!("ulimit -v without the flag: {kib:?}");
    #[cfg(target_os = "macos")]
    assert_eq!(kib, None, "macOS launch sets no address-space limit");
    #[cfg(target_os = "linux")]
    assert_eq!(
        kib,
        Some(524_288),
        "Linux launch keeps the 512 MiB RLIMIT_AS"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn launch_memory_cap_is_relative_to_measured_map_size() {
    let small = 256 * MIB;
    let large = 512 * MIB;
    let small_limits = launched_limits(&[MEMORY_BUDGET_FLAG, &small.to_string()]);
    let large_limits = launched_limits(&[MEMORY_BUDGET_FLAG, &large.to_string()]);
    for (budget, limits) in [(small, &small_limits), (large, &large_limits)] {
        eprintln!("budget {budget} bytes: {limits:?}");
        let cap = limits
            .address_space
            .expect("a capped launch has a finite limit");
        assert_eq!(limits.data, Some(cap), "RLIMIT_DATA carries the same cap");
        assert_eq!(
            limits.hard_address_space,
            Some(cap),
            "the hard AS equals the soft cap"
        );
        assert_eq!(
            limits.hard_data,
            Some(cap),
            "the hard DATA equals the soft cap"
        );
    }
    let small_kib = small_limits
        .address_space
        .expect("a capped launch has a finite limit");
    let large_kib = large_limits
        .address_space
        .expect("a capped launch has a finite limit");
    let map = rivect_sandbox_helper::current_map_size().expect("measure this process");
    eprintln!(
        "ulimit -v: B1={small_kib} KiB, B2={large_kib} KiB; helper map at exec ≈ {} bytes; test-process map {map} bytes",
        (small_kib * 1024).saturating_sub(small)
    );
    for kib in [small_kib, large_kib] {
        assert!(
            kib * 1024 >= 1 << 38,
            "the cap must sit above the measured map, got {kib} KiB"
        );
    }
    let delta = i128::from(large_kib * 1024) - i128::from(small_kib * 1024);
    let expected = i128::from(large - small);
    assert!(
        (delta - expected).abs() <= i128::from(16 * MIB),
        "the cap must move with the budget: delta {delta}, expected {expected}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn launch_memory_budget_sets_fixed_address_space() {
    let budget = 256 * MIB;
    let limits = launched_limits(&[MEMORY_BUDGET_FLAG, &budget.to_string()]);
    eprintln!("ulimit with a {budget}-byte budget: {limits:?}");
    assert_eq!(limits.address_space.map(|kib| kib * 1024), Some(budget));
    assert_eq!(
        limits.hard_address_space.map(|kib| kib * 1024),
        Some(budget),
        "the hard AS equals the budget"
    );
    let uncapped = launched_limits(&[]);
    assert_eq!(
        limits.data, uncapped.data,
        "Linux leaves the soft DATA limit as launched without the flag"
    );
    assert_eq!(
        limits.hard_data, uncapped.hard_data,
        "Linux leaves the hard DATA limit as launched without the flag"
    );
}

#[test]
fn memory_limit_agrees_with_the_shell_view() {
    if std::env::var_os(CHILD_MARKER).is_some() {
        let limit = memory_limit().expect("read the capped limit");
        println!("memory_limit={limit:?}");
        #[cfg(target_os = "macos")]
        println!(
            "map_size={}",
            rivect_sandbox_helper::current_map_size().expect("measure the capped child")
        );
        return;
    }

    let shell = test_child("/bin/sh")
        .args(["-c", "ulimit -v; ulimit -d"])
        .output()
        .expect("run sh");
    let shell_kib = String::from_utf8_lossy(&shell.stdout)
        .lines()
        .filter_map(|line| parse_ulimit(line.trim()))
        .min();
    assert_eq!(
        memory_limit().expect("read this process's limit"),
        shell_kib.map(|kib| kib * 1024),
        "uncapped view"
    );

    let budget = 256 * MIB;
    let probe_kib = launched_limits(&[MEMORY_BUDGET_FLAG, &budget.to_string()])
        .address_space
        .expect("a capped launch has a finite limit");
    // Lowering one soft limit below the cap forces `memory_limit` to pick
    // the smaller soft value; 64 MiB clears the launch-to-launch drift of
    // the macOS map-relative cap.
    let pinned_kib = probe_kib - 64 * 1024;
    let exe = std::env::current_exe().expect("test binary path");
    for lowered in [
        String::new(),
        format!("ulimit -S -v {pinned_kib} || exit {ULIMIT_REFUSED}; "),
        format!("ulimit -S -d {pinned_kib} || exit {ULIMIT_REFUSED}; "),
    ] {
        // The shell prints its view, then execs (no fork, so the helper's
        // NPROC limit is irrelevant) this test binary, which reports the
        // lib's.
        let script = format!(
            "ulimit -v; {lowered}exec \"$0\" --exact memory_limit_agrees_with_the_shell_view --nocapture --test-threads=1"
        );
        // Under load Darwin intermittently rejects the lowered soft limit
        // with EINVAL; only that refusal earns another launch, so a limit
        // the child ignores still fails on its first report.
        let mut refusals = 0;
        let output = loop {
            let output = test_child(HELPER)
                .args([
                    "launch",
                    MEMORY_BUDGET_FLAG,
                    &budget.to_string(),
                    "--",
                    "/bin/sh",
                    "-c",
                    &script,
                ])
                .arg(&exe)
                .env(CHILD_MARKER, "1")
                .output()
                .expect("run the capped child");
            if output.status.code() != Some(ULIMIT_REFUSED) {
                break output;
            }
            refusals += 1;
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!(
                "capped {lowered:?}: ulimit refused ({refusals}/{ULIMIT_ATTEMPTS}): {stderr:?}"
            );
            assert!(
                refusals < ULIMIT_ATTEMPTS,
                "capped {lowered:?}: the shell refused the lowered limit on all {ULIMIT_ATTEMPTS} launches, stderr {stderr:?}"
            );
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "capped child {lowered:?}: {:?} stdout {stdout:?} stderr {:?}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let capped_kib = stdout
            .lines()
            .next()
            .and_then(|line| parse_ulimit(line.trim()))
            .expect("the capped shell reports a finite limit");
        let reported = child_report(&stdout, "memory_limit=");
        eprintln!("capped {lowered:?}: ulimit -v {capped_kib} KiB, memory_limit {reported}");
        let expected_kib = if lowered.is_empty() {
            capped_kib
        } else {
            assert!(
                pinned_kib < capped_kib,
                "the lowered limit sits below the cap"
            );
            pinned_kib
        };
        assert_eq!(reported, format!("{:?}", Some(expected_kib * 1024)));
        // The index worker refuses unless its limit minus its live map lies
        // within twice the budget: that holds only when the cap tracks the
        // measured map.
        #[cfg(target_os = "macos")]
        {
            let map: u64 = child_report(&stdout, "map_size=")
                .parse()
                .expect("the child reports its map size");
            let headroom = i128::from(expected_kib * 1024) - i128::from(map);
            eprintln!("capped {lowered:?}: child map {map} bytes, headroom {headroom} bytes");
            assert!(
                headroom > 0 && headroom <= 2 * i128::from(budget),
                "the cap must sit within twice the budget above the child's map, headroom {headroom}"
            );
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn phys_footprint_tracks_a_live_allocation() {
    let pid = std::process::id();
    let before = rivect_sandbox_helper::phys_footprint(pid).expect("read this process");
    // 1 KiB blocks are the small-allocation class the relative RLIMIT
    // misses; each is written, so every page is resident.
    let blocks: Vec<Box<[u8; 1024]>> = (0..256 * 1024).map(|_| Box::new([0x5a; 1024])).collect();
    let after = rivect_sandbox_helper::phys_footprint(pid).expect("read this process again");
    std::hint::black_box(&blocks);
    eprintln!("footprint before {before} bytes, after 256 MiB of 1 KiB blocks {after} bytes");
    assert!(
        after.saturating_sub(before) >= 224 * MIB,
        "the footprint must grow with the allocation: before {before}, after {after}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn phys_footprint_reads_a_child_until_it_is_reaped() {
    let mut child = test_child("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let pid = child.id();
    let live = rivect_sandbox_helper::phys_footprint(pid).expect("read the live child");
    eprintln!("live child footprint {live} bytes");
    assert!(live < 64 * MIB, "a sleeping child is small, read {live}");

    child.kill().expect("kill the child");
    // `ps` is the independent oracle for the exited, unreaped state.
    let deadline = Instant::now() + READY_MAX;
    loop {
        let stat = test_child("/bin/ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .expect("run ps");
        if String::from_utf8_lossy(&stat.stdout)
            .trim_start()
            .starts_with('Z')
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the killed child never became a zombie"
        );
        wait_ready(&[], &[], Duration::from_millis(10)).expect("pace the probe");
    }
    let zombie = rivect_sandbox_helper::phys_footprint(pid).expect("read the unreaped child");
    eprintln!("exited, unreaped child footprint {zombie} bytes");

    child.wait().expect("reap the child");
    let reaped = rivect_sandbox_helper::phys_footprint(pid);
    assert!(reaped.is_err(), "a reaped pid never reads, got {reaped:?}");

    let beyond =
        rivect_sandbox_helper::phys_footprint(u32::MAX).expect_err("a pid past pid_t is refused");
    assert_eq!(beyond.kind(), std::io::ErrorKind::InvalidInput);
}

/// The value after `key` on the capped child's report line.
fn child_report<'a>(stdout: &'a str, key: &str) -> &'a str {
    stdout
        .lines()
        .find_map(|line| line.split_once(key).map(|(_, value)| value.trim()))
        .unwrap_or_else(|| panic!("the child reports {key} in {stdout:?}"))
}

/// Whether a member's read failed because the process demonstrably
/// exited between the listing and the read — ENOENT, or ESRCH (raw 3,
/// which std does not map to NotFound) — whatever wrapper carries the
/// OS error. Such a member holds no slot anymore; any other failure is
/// a measurement failure.
fn exited_mid_read(error: &ProcessReadError) -> bool {
    match error {
        ProcessReadError::Io(error) | ProcessReadError::ReadFailed { source: error, .. } => {
            error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(ESRCH)
        }
        _ => false,
    }
}

fn assert_waited_the_timeout(start: Instant, case: &str) {
    let elapsed = start.elapsed();
    assert!(
        elapsed >= IDLE_TIMEOUT && elapsed < IDLE_MAX,
        "{case} waits the {IDLE_TIMEOUT:?} timeout and no longer, took {elapsed:?}"
    );
}

fn assert_returned_early(start: Instant, case: &str) {
    let elapsed = start.elapsed();
    assert!(
        elapsed < READY_MAX,
        "{case} returns well before the {READY_TIMEOUT:?} timeout, took {elapsed:?}"
    );
}

#[test]
fn wait_ready_wakes_on_readable_and_times_out() {
    let (reader, mut writer) = std::io::pipe().expect("pipe");

    let start = Instant::now();
    wait_ready(&[], &[], IDLE_TIMEOUT).expect("empty wait");
    assert_waited_the_timeout(start, "empty sets");

    let start = Instant::now();
    wait_ready(&[reader.as_fd()], &[], IDLE_TIMEOUT).expect("idle wait");
    assert_waited_the_timeout(start, "an empty pipe");

    writer.write_all(b"x").expect("write one byte");
    let start = Instant::now();
    wait_ready(&[reader.as_fd()], &[], READY_TIMEOUT).expect("readable wait");
    assert_returned_early(start, "a readable pipe");
}

#[test]
fn wait_ready_wakes_when_the_writer_closes() {
    const CLOSE_DELAY: Duration = Duration::from_millis(100);
    let (reader, writer) = std::io::pipe().expect("pipe");
    // Started before the closer, so the hang-up lands at least CLOSE_DELAY
    // in and a wait that returns without it fails the lower bound.
    let start = Instant::now();
    let closer = std::thread::spawn(move || {
        std::thread::sleep(CLOSE_DELAY);
        drop(writer);
    });
    wait_ready(&[reader.as_fd()], &[], READY_TIMEOUT).expect("hang-up wait");
    let elapsed = start.elapsed();
    closer.join().expect("closer thread");
    assert!(
        elapsed >= CLOSE_DELAY,
        "the wait must block until the writer closes, took {elapsed:?}"
    );
    assert_returned_early(start, "a hung-up pipe");
}

#[test]
fn wait_ready_wakes_on_writable() {
    let (mut reader, mut writer) = std::io::pipe().expect("pipe");
    set_nonblocking(&writer).expect("non-blocking writer");
    // Fill to zero free bytes: page-sized writes, then single bytes, so no
    // platform low-water mark can still report the pipe writable.
    let mut filled = 0;
    for chunk in [&[0_u8; 4096][..], &[0_u8; 1][..]] {
        loop {
            match writer.write(chunk) {
                Ok(written) => filled += written,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("fill the pipe: {error}"),
            }
        }
    }

    let start = Instant::now();
    wait_ready(&[], &[writer.as_fd()], IDLE_TIMEOUT).expect("full wait");
    assert_waited_the_timeout(start, "a full pipe");

    let drainer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        let mut sink = vec![0_u8; filled];
        reader.read_exact(&mut sink).expect("drain the pipe");
    });
    let start = Instant::now();
    wait_ready(&[], &[writer.as_fd()], READY_TIMEOUT).expect("writable wait");
    drainer.join().expect("drainer thread");
    assert_returned_early(start, "a drained pipe");
}

#[test]
fn wait_ready_returns_ok_when_a_signal_interrupts_the_wait() {
    // SAFETY: `ignore_signal` does nothing, so it is async-signal-safe, and
    // only this test sends SIGUSR1, to its own waiter thread.
    let previous = unsafe { signal(SIGUSR1, ignore_signal) };
    assert_ne!(previous, SIG_ERR, "install the SIGUSR1 handler");
    // SAFETY: clears SA_RESTART for SIGUSR1 alone, so an interrupted poll
    // reports EINTR instead of restarting.
    let interrupting = unsafe { siginterrupt(SIGUSR1, 1) };
    assert_eq!(interrupting, 0, "make SIGUSR1 interrupt system calls");

    let (reader, _writer) = std::io::pipe().expect("pipe");
    let waiter = std::thread::spawn(move || {
        let start = Instant::now();
        let outcome =
            wait_ready(&[reader.as_fd()], &[], READY_TIMEOUT).map_err(|error| error.kind());
        (outcome, start.elapsed())
    });
    // A signal that lands before the waiter enters poll is absorbed by the
    // handler, so keep signalling until the waiter returns.
    while !waiter.is_finished() {
        // SAFETY: the waiter is joined below, so its pthread id stays valid
        // for every signal sent here.
        let sent = unsafe { pthread_kill(waiter.as_pthread_t(), SIGUSR1) };
        assert!(
            sent == 0 || waiter.is_finished(),
            "pthread_kill failed with {sent}"
        );
        wait_ready(&[], &[], Duration::from_millis(10)).expect("pace the signals");
    }
    let (outcome, elapsed) = waiter.join().expect("waiter thread");
    assert_eq!(
        outcome,
        Ok(()),
        "an interrupted wait is a normal early return"
    );
    assert!(
        elapsed < READY_MAX,
        "the interrupted wait returns well before the timeout, took {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// --resource-profile check: the isolated Cargo-check substrate
// ---------------------------------------------------------------------------

/// Set on the re-executed test binary so it reports its measured uid
/// process count from inside the check-profile child.
const CHECK_CHILD_MARKER: &str = "RIVECT_CHECK_PROFILE_CHILD";
/// Set on the re-executed test binary so it holds a live allocation the
/// resident-bytes read must track.
const RESIDENT_CHILD_MARKER: &str = "RIVECT_RESIDENT_CHILD";
/// The resident-tracking child allocates this much, written page by page.
const RESIDENT_ALLOCATION_BLOCKS: usize = 128 * 1024;
/// The read must see at least this much of the child's allocation.
const RESIDENT_THRESHOLD: u64 = 96 * MIB;
/// Same-uid churn allowed between the helper's startup NPROC measurement
/// and the child's own count. Where the measured count is below the slack,
/// the comparison alone cannot tell a measured limit from a fixed one near
/// count + headroom; the floor rejects only a headroom-only limit.
const NPROC_CHURN_SLACK: u64 = 64;
/// The nobody uid's process count may exceed the hard NPROC by this many
/// at the refusal: the count is taken just after the EAGAIN, so only
/// same-uid churn in flight can move it past the limit.
///
/// The hard NPROC is checked by the kernel against tasks that may already be
/// mid-exit and absent from `/proc`, so the visible count at refusal sits
/// below the limit. On a default-concurrency suite of this size the measured
/// deficit reached 10 across four full runs (2026-10-19 logs
/// `target/uid65534/h0-workspace-*.log`); 16 covers that ordinary churn
/// while still binding the refusal to the hard limit.
#[cfg(target_os = "linux")]
const NPROC_REFUSAL_SLACK: u64 = 16;
/// The cgroup pids ceiling must clear the estimated hard NPROC by at
/// least the fork loop's spawn cap: a nearer ceiling could fire the
/// EAGAIN the leg reads as the rlimit's own refusal.
#[cfg(target_os = "linux")]
const NPROC_CGROUP_SLACK: u64 = 4096;

#[test]
fn resource_profile_rejects_unknown_repeated_and_combined_values() {
    let dir = scratch("profile");
    let marker = dir.join("M");
    let marker_arg = marker.to_str().expect("utf-8 scratch path");
    for case in [
        vec!["--resource-profile", "bogus"],
        vec!["--resource-profile", "Check"],
        vec!["--resource-profile", "--"],
        vec!["--resource-profile", "check", "--resource-profile", "check"],
        vec!["--resource-profile", "check", MEMORY_BUDGET_FLAG, "1"],
        vec![MEMORY_BUDGET_FLAG, "1", "--resource-profile", "check"],
    ] {
        let output = launch(&case, &[TOUCH, marker_arg]);
        assert_rejected_before_exec(&output, &marker, &format!("profile case {case:?}"));
    }

    // Parse order under a lowered hard ceiling: the grammar rejection
    // (exit 30) must precede any rlimit application — if the argv check
    // ran after apply_rlimits, an unprivileged launch under hard NOFILE
    // 128 would refuse at setrlimit (EPERM, exit 10) instead. A fresh
    // marker keeps the absent-program proof independent of the control
    // leg above, which already touched its marker.
    // SAFETY: geteuid takes no arguments and returns the effective uid;
    // the value is only compared.
    if unsafe { geteuid() } != 0 {
        let order_marker = dir.join("order");
        let order_arg = order_marker.to_str().expect("utf-8 scratch path");
        let lowered = test_child("/bin/sh")
            .arg("-c")
            .arg(format!(
                "ulimit -S -n 128; ulimit -H -n 128 || exit {ULIMIT_REFUSED}; \
                 exec \"$1\" launch --resource-profile bogus -- \"$2\" \"$3\""
            ))
            .arg("sh")
            .arg(HELPER)
            .arg(TOUCH)
            .arg(order_arg)
            .output()
            .expect("run the invalid-profile launch under hard NOFILE 128");
        assert_rejected_before_exec(
            &lowered,
            &order_marker,
            "grammar rejection under a lowered hard NOFILE ceiling",
        );
    }
}

/// A lowered inherited hard NOFILE discriminates the legacy refusal from
/// the check-profile clamp: the worker defaults and the memory budget
/// must REFUSE (setrlimit EPERM, exit 10) when a limit exceeds the
/// inherited hard ceiling, while the check profile — the only clamping
/// path — accepts at the lowered ceiling. Root can RAISE a lowered hard
/// ceiling (CAP_SYS_RESOURCE), so the refusal half is asserted
/// unprivileged; the root half proves the complement — the worker
/// defaults still REQUEST 256, where a regressed universal clamp would
/// silently land the child at 128.
#[test]
fn lowered_inherited_hard_nofile_refuses_default_and_budget_accepts_check() {
    // SAFETY: geteuid takes no arguments and returns the effective uid;
    // the value is only compared.
    let unprivileged = unsafe { geteuid() } != 0;
    // `ulimit` lowers the HARD limit irreversibly for the shell and
    // every process it execs, so the helper inherits hard NOFILE 128
    // under the worker default's 256. The soft limit drops first:
    // setrlimit refuses a hard ceiling below the live soft value. The
    // launched child reports its hard NOFILE, so one launch serves both
    // the refusal and the root-raise verdicts.
    let default_launch = test_child("/bin/sh")
        .arg("-c")
        .arg(format!(
            "ulimit -S -n 128; ulimit -H -n 128 || exit {ULIMIT_REFUSED}; \
             exec \"$1\" launch -- \"$2\" \"$3\" \"$4\""
        ))
        .arg("sh")
        .arg(HELPER)
        .arg("/bin/sh")
        .arg("-c")
        .arg("ulimit -H -n")
        .output()
        .expect("run the default launch under hard NOFILE 128");
    let stdout = String::from_utf8_lossy(&default_launch.stdout);
    let stderr = String::from_utf8_lossy(&default_launch.stderr);
    if unprivileged {
        assert_eq!(
            default_launch.status.code(),
            Some(rivect_sandbox_helper::EXIT_SANDBOX_INIT),
            "the default launch must refuse above the inherited hard ceiling: stderr {stderr:?}"
        );
    } else {
        assert!(
            default_launch.status.success(),
            "root raises the lowered ceiling (kernel-permitted), and the \
             default launch must proceed: {:?} stdout {stdout:?} stderr {stderr:?}",
            default_launch.status
        );
        assert_eq!(
            stdout.trim(),
            "256",
            "the worker default must still REQUEST hard NOFILE 256, not clamp to the inherited 128"
        );
    }
    let budget_launch = test_child("/bin/sh")
        .arg("-c")
        .arg(format!(
            "ulimit -S -n 128; ulimit -H -n 128 || exit {ULIMIT_REFUSED}; \
             exec \"$1\" launch {MEMORY_BUDGET_FLAG} 268435456 -- \"$2\" \"$3\" \"$4\""
        ))
        .arg("sh")
        .arg(HELPER)
        .arg("/bin/sh")
        .arg("-c")
        .arg("ulimit -H -n")
        .output()
        .expect("run the budget launch under hard NOFILE 128");
    let stdout = String::from_utf8_lossy(&budget_launch.stdout);
    let stderr = String::from_utf8_lossy(&budget_launch.stderr);
    if unprivileged {
        assert_eq!(
            budget_launch.status.code(),
            Some(rivect_sandbox_helper::EXIT_SANDBOX_INIT),
            "the memory-budget launch must refuse above the inherited hard ceiling: stderr {stderr:?}"
        );
    } else {
        assert!(
            budget_launch.status.success(),
            "root raises the lowered ceiling (kernel-permitted), and the \
             budget launch must proceed: {:?} stdout {stdout:?} stderr {stderr:?}",
            budget_launch.status
        );
        assert_eq!(
            stdout.trim(),
            "256",
            "the budget path must still REQUEST hard NOFILE 256, not clamp to the inherited 128"
        );
    }
    // The check profile clamps at the inherited ceiling instead: the
    // launch succeeds and the chain observes hard NOFILE exactly 128,
    // privileged or not — the clamp is the helper's own, never the
    // kernel's raise.
    let check_accepted = test_child("/bin/sh")
        .arg("-c")
        .arg(format!(
            "ulimit -S -n 128; ulimit -H -n 128 || exit {ULIMIT_REFUSED}; \
             exec \"$1\" launch {RESOURCE_PROFILE_FLAG} check -- \"$2\" \"$3\" \"$4\""
        ))
        .arg("sh")
        .arg(HELPER)
        .arg("/bin/sh")
        .arg("-c")
        .arg("ulimit -H -n")
        .output()
        .expect("run the check launch under hard NOFILE 128");
    let stdout = String::from_utf8_lossy(&check_accepted.stdout);
    assert!(
        check_accepted.status.success(),
        "the check launch must accept at the lowered ceiling: {:?} stdout {stdout:?} stderr {:?}",
        check_accepted.status,
        String::from_utf8_lossy(&check_accepted.stderr)
    );
    assert_eq!(
        stdout.trim(),
        "128",
        "the check profile clamps NOFILE to the inherited hard ceiling"
    );
}

/// DEC-040 contract pins: the exported ceilings are pinned to
/// independent literals — never the implementation's own arithmetic — so
/// a headroom or ceiling bump cannot pass this suite silently. These
/// pins stand apart from the runtime churn/peak assertions, which
/// observe behavior, not the exported contract.
#[test]
fn exported_check_profile_ceilings_stay_pinned() {
    assert_eq!(rivect_sandbox_helper::CHECK_NPROC_HEADROOM, 256);
    assert_eq!(
        rivect_sandbox_helper::CHECK_GROUP_RSS_BYTES,
        4 * 1024 * 1024 * 1024
    );
}

/// Set on the re-executed test binary so it runs the hostile-env probe
/// with attacker-named variables in its own ambient environment.
const HOSTILE_ENV_CHILD_MARKER: &str = "RIVECT_HOSTILE_ENV_CHILD";

/// Ambient hostility must not cross into a launched non-Cargo chain:
/// this leg re-execs the test binary with `BASH_ENV` and a marker in its
/// environment, and from inside that hostile ambient every spawn this
/// file performs is explicit — the launched bash must neither see the
/// marker nor source the `BASH_ENV` payload. A spawn that regresses to
/// inheriting ambient env turns the payload's `export RIVECT_PWNED=1`
/// into the child's environment and fails this probe.
#[test]
fn launched_children_do_not_inherit_hostile_ambient_env() {
    if std::env::var_os(HOSTILE_ENV_CHILD_MARKER).is_some() {
        let pwned = std::env::var_os("BASH_ENV")
            .expect("BASH_ENV reaches the hostile child")
            .into_string()
            .expect("utf-8 BASH_ENV path");
        // The direct fork-spawn path (the same `.spawn()` the NPROC fork
        // loop uses): the loader marker and the hostile variables must
        // not reach a spawned child either.
        let env_view = test_child("/usr/bin/env")
            .output()
            .expect("spawn env from inside the hostile ambient");
        let env_text = String::from_utf8_lossy(&env_view.stdout);
        assert!(
            env_view.status.success()
                && !env_text.contains("RIVECT_HOSTILE_MARKER")
                && !env_text.contains("BASH_ENV")
                && !env_text.contains("LD_DEBUG"),
            "a spawned child must not inherit the hostile ambient env: \
             {:?} stdout {env_text:?} stderr {:?}",
            env_view.status,
            String::from_utf8_lossy(&env_view.stderr)
        );
        let output = launch(
            &[],
            &[
                "/bin/bash",
                "-c",
                "test -z \"$RIVECT_HOSTILE_MARKER\" && test -z \"$RIVECT_PWNED\" && echo CLEAN",
            ],
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.trim() == "CLEAN",
            "the launched child must not inherit hostile ambient env (BASH_ENV {pwned:?}): \
             {:?} stdout {stdout:?} stderr {:?}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let dir = scratch("hostile-env");
    let pwned = dir.join("pwned.sh");
    std::fs::write(&pwned, "export RIVECT_PWNED=1\n").expect("write the BASH_ENV payload");
    let exe = std::env::current_exe().expect("test binary path");
    let output = test_child(&exe)
        .args([
            "--exact",
            "launched_children_do_not_inherit_hostile_ambient_env",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(HOSTILE_ENV_CHILD_MARKER, "1")
        .env("BASH_ENV", &pwned)
        .env("RIVECT_HOSTILE_MARKER", "1")
        .env("LD_DEBUG", "statistics")
        .output()
        .expect("run the hostile-ambient child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "hostile-ambient child: {:?} stdout {stdout:?} stderr {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn check_resource_profile_sets_the_check_limits() {
    if std::env::var_os(CHECK_CHILD_MARKER).is_some() {
        let count = uid_process_count().expect("count this uid inside the check-profile child");
        println!("uid_count={count}");
        return;
    }
    // The macOS NPROC leg compares two uid counts taken around the
    // launch inside the churn slack; the boundary legs' 1100-process
    // spawn windows would blow that slack if they ran concurrently.
    let _serialized = UID_COUNT_SENSITIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let exe = std::env::current_exe().expect("test binary path");
    let script = "ulimit -H -t; ulimit -H -f; ulimit -H -n; ulimit -H -u; ulimit -H -v; ulimit -H -d; \
                  exec \"$0\" --exact check_resource_profile_sets_the_check_limits --nocapture --test-threads=1";
    let output = test_child(HELPER)
        .args([
            "launch",
            RESOURCE_PROFILE_FLAG,
            "check",
            "--",
            "/bin/bash",
            "-c",
            script,
        ])
        .arg(&exe)
        .env(CHECK_CHILD_MARKER, "1")
        .output()
        .expect("run the check-profile child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "check-profile child: {:?} stdout {stdout:?} stderr {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let lines: Vec<&str> = stdout.lines().collect();
    // The re-executed harness banner follows the six ulimit lines.
    let Some([cpu, fsize, nofile, nproc, address, _data]) = lines.first_chunk::<6>() else {
        panic!("expected six ulimit lines before the uid report, got {stdout:?}");
    };
    assert_eq!(cpu, &PROFILE_CPU_SECONDS.to_string(), "hard CPU seconds");
    // bash — the only shell whose ulimit spans -u on both platforms —
    // reports -f in 1024-byte blocks everywhere; the byte ceiling is
    // what the assert pins, not a per-platform block dialect.
    let fsize_block = PROFILE_FSIZE_BYTES / 1024;
    assert_eq!(fsize, &fsize_block.to_string(), "hard FSIZE blocks");
    assert_eq!(nofile, &PROFILE_NOFILE.to_string(), "hard NOFILE");
    let reported_count: u64 = child_report(&stdout, "uid_count=")
        .parse()
        .expect("the child reports its uid process count");
    let nproc: u64 = nproc.parse().expect("ulimit prints the hard NPROC");
    eprintln!("check profile: hard NPROC {nproc}, uid count inside {reported_count}");
    // The helper measured the uid count at startup and added the headroom;
    // the child measures again milliseconds later, so only same-uid churn
    // moves the two apart. Root is exempt from RLIMIT_NPROC (kernel), so
    // this leg asserts only where the child is unprivileged — the macOS
    // host user; the Docker root leg explicitly does NOT prove NPROC.
    #[cfg(target_os = "macos")]
    assert!(
        nproc.abs_diff(reported_count + PROFILE_NPROC_HEADROOM) <= NPROC_CHURN_SLACK,
        "hard NPROC must be the measured uid count plus the headroom: {nproc} vs {reported_count}+{PROFILE_NPROC_HEADROOM}"
    );
    // Darwin rejects an absolute address-space cap below its baseline map,
    // so the check profile bounds memory through the hard per-process
    // limits plus the parent-sampled group RSS, never AS/DATA.
    #[cfg(target_os = "macos")]
    assert_eq!(
        *address, "unlimited",
        "the check profile sets no macOS AS cap"
    );
    #[cfg(target_os = "macos")]
    assert_eq!(
        *_data, "unlimited",
        "the check profile sets no macOS DATA cap"
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        *address,
        (PROFILE_AS_BYTES / 1024).to_string(),
        "hard AS in KiB"
    );

    // Regression: the worker defaults and the memory-budget path keep
    // today's limits.
    let worker = launch(
        &[],
        &[
            "/bin/bash",
            "-c",
            "ulimit -H -u; ulimit -H -n; ulimit -H -t; ulimit -H -f",
        ],
    );
    assert!(
        worker.status.success(),
        "default launch: {:?}",
        String::from_utf8_lossy(&worker.stderr)
    );
    let worker_stdout = String::from_utf8_lossy(&worker.stdout);
    let worker_views: Vec<&str> = worker_stdout.lines().collect();
    let [worker_nproc, worker_nofile, worker_cpu, worker_fsize] = worker_views[..] else {
        panic!("default launch reports four limits");
    };
    assert_eq!(worker_nproc, "64", "default NPROC stays fixed");
    assert_eq!(worker_nofile, "256", "default NOFILE stays fixed");
    assert_eq!(worker_cpu, "30", "default CPU stays fixed");
    // The pre-slice worker RLIMIT_FSIZE (RLIMITS at HEAD 7e374d7) is
    // 64 MiB; bash reports -f in 1024-byte blocks everywhere.
    assert_eq!(
        worker_fsize, "65536",
        "default FSIZE stays 64 MiB in 1024-byte blocks"
    );
    let budget = launch(
        &[MEMORY_BUDGET_FLAG, "268435456"],
        &[
            "/bin/bash",
            "-c",
            "ulimit -H -u; ulimit -H -t; ulimit -H -n; ulimit -H -f",
        ],
    );
    assert!(
        budget.status.success(),
        "budget launch: {:?}",
        String::from_utf8_lossy(&budget.stderr)
    );
    let budget_stdout = String::from_utf8_lossy(&budget.stdout);
    let budget_views: Vec<&str> = budget_stdout.lines().collect();
    let [budget_nproc, budget_cpu, budget_nofile, budget_fsize] = budget_views[..] else {
        panic!("budget launch reports four limits");
    };
    assert_eq!(
        budget_nproc, "64",
        "the budget path keeps the default NPROC"
    );
    assert_eq!(budget_cpu, "30", "the budget path keeps the default CPU");
    assert_eq!(
        budget_nofile, "256",
        "the budget path keeps the default hard NOFILE"
    );
    assert_eq!(
        budget_fsize, "65536",
        "the budget path keeps the 64 MiB FSIZE in 1024-byte blocks"
    );
}

#[test]
fn check_profile_admits_a_real_cargo_test() {
    run_confined_cargo_scenario();
}

/// The real confined-Cargo scenario both the plain and the
/// hostile-ambient legs run: an offline fixture test under the check
/// profile, sampled by the parent-side observer, with every verdict
/// asserted in place. Returns the confined cargo's own stdout so a
/// re-executed leg can report the fixture's named outcome upstream.
fn run_confined_cargo_scenario() -> String {
    // The confined chain forks under hard NPROC = uid count at the
    // helper's startup + 256 headroom; a concurrent boundary leg's
    // 1100 same-uid spawns would eat that headroom and refuse the
    // chain's own forks, so the legs serialize.
    let _serialized = UID_COUNT_SENSITIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = scratch("cargo-fixture");
    let fixture = root.join("fixture");
    std::fs::create_dir_all(fixture.join("src")).expect("create the fixture src");
    std::fs::create_dir_all(fixture.join("tests")).expect("create the fixture tests");
    std::fs::write(
        fixture.join("Cargo.toml"),
        "[package]\nname = \"check-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write the fixture manifest");
    std::fs::write(
        fixture.join("src").join("lib.rs"),
        "pub fn answer() -> u8 { 42 }\n",
    )
    .expect("write the fixture lib");
    std::fs::write(
        fixture.join("tests").join("it.rs"),
        "#[test]\nfn fixture_answers() {\n    assert_eq!(check_fixture::answer(), 42);\n}\n",
    )
    .expect("write the fixture test");
    std::fs::create_dir_all(root.join("cargo-home")).expect("create the isolated CARGO_HOME");
    std::fs::create_dir_all(root.join("tmp")).expect("create the isolated TMPDIR");

    let mut command = Command::new(HELPER);
    command
        .arg("launch")
        .arg(RESOURCE_PROFILE_FLAG)
        .arg("check")
        .arg("--")
        // A shell wrapper runs the chain and reports its cumulative CPU
        // via `times` (the children line), so the CPU ceiling is asserted
        // against measured child CPU seconds rather than wall time.
        .arg("/bin/sh")
        .arg("-c")
        .arg("\"$1\" test --offline; status=$?; echo CPU-REPORT; times; exit \"$status\"")
        .arg("sh")
        .arg(env!("CARGO"))
        .current_dir(&fixture)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // The chain starts from an EMPTY environment and receives exactly
        // what an isolated check needs: a private CARGO_HOME (no host
        // registry, config, or credentials), a private TMPDIR, the
        // pinned target dir, offline mode, and — when the host has them
        // — HOME/RUSTUP_HOME/PATH, so a rustup-proxied cargo resolves
        // its toolchain and the linker. Nothing else crosses: an ambient
        // RUSTC/RUSTC_WRAPPER/CC or proxy variable must not steer the
        // confined cargo (reviewer probe: RUSTC=/no/such/… exited 101).
        .env_clear()
        .env("CARGO_HOME", root.join("cargo-home"))
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TARGET_DIR", fixture.join("target"))
        .env("TMPDIR", root.join("tmp"))
        .process_group(0);
    for key in ["HOME", "RUSTUP_HOME"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command.env("PATH", child_path());
    let mut child = command.spawn().expect("launch the confined cargo test");
    let start = Instant::now();
    // The parent-side observer surface: the group members and their
    // resident bytes, sampled at the 10 ms cadence the executor uses.
    // The sample is advisory (peak evidence for the constants), never the
    // hard bound — the hard bounds are the rlimits above. An unreadable
    // sample is a measurement failure, never a silent zero: only a member
    // that demonstrably exited between the listing and its read
    // (NotFound) is skipped.
    let mut peak_members = 0_usize;
    let mut peak_group_rss = 0_u64;
    let status = loop {
        let members = process_group_members(child.id())
            .unwrap_or_else(|error| panic!("unreadable group sample: {error}"));
        peak_members = peak_members.max(members.len());
        let mut sample = 0_u64;
        for pid in &members {
            match resident_bytes(*pid) {
                Ok(bytes) => sample = sample.saturating_add(bytes),
                Err(error) if exited_mid_read(&error) => {}
                Err(error) => panic!("unreadable resident sample for pid {pid}: {error}"),
            }
        }
        peak_group_rss = peak_group_rss.max(sample);
        if let Some(status) = child.try_wait().expect("poll the cargo child") {
            break status;
        }
        wait_ready(&[], &[], Duration::from_millis(10)).expect("pace the resource sampling");
    };
    // The fixture's output is far below the pipe buffer; draining after
    // the exit cannot block.
    let mut stdout_bytes = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        pipe.read_to_end(&mut stdout_bytes)
            .expect("read cargo stdout");
    }
    let mut stderr_bytes = Vec::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_end(&mut stderr_bytes)
            .expect("read cargo stderr");
    }
    let stdout = String::from_utf8_lossy(&stdout_bytes);
    let stderr = String::from_utf8_lossy(&stderr_bytes);
    let elapsed = start.elapsed();
    let largest =
        largest_file_bytes(&fixture.join("target")).expect("measure the largest confined artifact");
    // The shell's `times` output follows the CPU-REPORT marker: the first
    // line is the wrapper's own usage, the second the chain's children.
    let lines: Vec<&str> = stdout.lines().collect();
    let report_at = lines
        .iter()
        .position(|line| line.trim() == "CPU-REPORT")
        .expect("the shell reports the chain's CPU times");
    let children_cpu = lines
        .get(report_at + 2)
        .copied()
        .map(sh_cpu_seconds)
        .expect("the children CPU line follows the shell's own");
    eprintln!(
        "confined cargo test: {status:?}, peak group members {peak_members}, \
         peak sampled group rss {peak_group_rss} bytes, largest artifact {largest} bytes, \
         child cpu {children_cpu}s, wall {elapsed:?} (diagnostic)"
    );
    assert!(
        status.success(),
        "cargo test must pass under the check profile: {status} stdout {stdout:?} stderr {stderr:?}"
    );
    // Exactly the fixture's one test must have executed — a run that
    // executed zero tests still prints "test result: ok".
    assert!(
        stdout.contains("test fixture_answers ... ok"),
        "cargo must report the fixture test by name: {stdout:?}"
    );
    assert!(
        stdout.contains("test result: ok. 1 passed; 0 failed;"),
        "cargo must report exactly one passed fixture test: {stdout:?}"
    );
    // The constants are derived from these measured benign peaks ×4
    // inside the approved ceilings; a peak that outgrows its constant is
    // a human decision, never a quiet bump. A zero peak means the
    // sampler observed nothing — that is a measurement failure too.
    assert!(
        peak_members > 0,
        "the sampler must observe the cargo chain's members"
    );
    assert!(
        peak_group_rss > 0,
        "the sampler must observe the cargo chain's residency"
    );
    assert!(
        largest > 0,
        "the confined build must produce artifacts to measure"
    );
    assert!(
        (peak_members as u64) * 4 <= PROFILE_NPROC_HEADROOM,
        "four times the peak member count must fit the headroom: {peak_members}"
    );
    assert!(
        peak_group_rss * 4 <= PROFILE_GROUP_RSS_BYTES,
        "four times the peak sampled group rss must fit the ceiling: {peak_group_rss}"
    );
    assert!(
        largest * 4 <= PROFILE_FSIZE_BYTES,
        "four times the largest artifact must fit the per-file cap: {largest}"
    );
    // Wall time stays a diagnostic (printed above): scheduling noise, not
    // the enforced bound. The CPU ceiling is asserted against the
    // measured child CPU seconds the rlimit actually charges.
    assert!(
        children_cpu * 4.0 <= PROFILE_CPU_SECONDS as f64,
        "four times the measured child cpu seconds must fit the hard CPU ceiling: {children_cpu}s"
    );
    stdout.into_owned()
}

/// Set on the re-executed test binary so it runs the confined-Cargo
/// scenario from inside a hostile ambient environment.
const HOSTILE_CARGO_CHILD_MARKER: &str = "RIVECT_HOSTILE_CARGO_CHILD";

/// The confined-Cargo constructor's env sanitization, discriminated the
/// only way it can be: the HARNESS itself — this already-built test
/// binary re-exec'ing the scenario, never the outer cargo — runs with
/// hostile ambient (compiler, wrapper, linker-loader, and shell-hijack
/// variables) injected around it. If the helper command's
/// `.env_clear()` regressed into inheritance, the confined cargo would
/// steer by `RUSTC`/`RUSTC_WRAPPER`/`CC`, source `BASH_ENV`, or trace
/// under `LD_DEBUG`, and the fixture test would lose its named
/// one-test verdict. HOME/RUSTUP_HOME still cross (the constructor's
/// allowlist copies them when present) so the fixture stays buildable;
/// everything hostile must be dropped at the constructor.
#[test]
fn confined_cargo_test_runs_clean_inside_hostile_ambient_env() {
    if std::env::var_os(HOSTILE_CARGO_CHILD_MARKER).is_some() {
        let cargo_stdout = run_confined_cargo_scenario();
        println!(
            "fixture_ok={}",
            cargo_stdout.contains("test fixture_answers ... ok")
        );
        println!(
            "one_test={}",
            cargo_stdout.contains("test result: ok. 1 passed; 0 failed;")
        );
        return;
    }
    // The re-executed child's chain forks under NPROC headroom its own
    // helper measured, so this parent serializes against the boundary
    // legs' spawn windows exactly like the plain scenario leg.
    let _serialized = UID_COUNT_SENSITIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let exe = std::env::current_exe().expect("test binary path");
    let mut command = test_child(&exe);
    command.args([
        "--exact",
        "confined_cargo_test_runs_clean_inside_hostile_ambient_env",
        "--nocapture",
        "--test-threads=1",
    ]);
    for key in ["HOME", "RUSTUP_HOME"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    let output = command
        .env(HOSTILE_CARGO_CHILD_MARKER, "1")
        .env("RUSTC", "/no/such/rustc")
        .env("RUSTC_WRAPPER", "/no/such/rustc-wrapper")
        .env("CC", "/no/such/cc")
        .env("BASH_ENV", "/no/such/bash-env")
        .env("LD_DEBUG", "statistics")
        .output()
        .expect("run the hostile-ambient cargo child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "the confined cargo scenario must pass inside the hostile ambient: {:?} \
         stdout {stdout:?} stderr {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("fixture_ok=true") && stdout.contains("one_test=true"),
        "the fixture test must still pass with its expected one-test count: {stdout:?}"
    );
}

/// One `times` line — `user sys` fields spelled `MmS.SSs` or bare
/// `S.SSs`, integer minutes and unsigned plain-decimal seconds only —
/// summed to seconds. Exactly two valid nonnegative fields parse;
/// day/hour spellings such as `1d2h3m4.56s` are not supported and,
/// like any malformed, empty, or unboundable line, read as infinity
/// so the ceiling assertion fails loudly instead of passing loosely
/// on an unparsed unit.
fn sh_cpu_seconds(line: &str) -> f64 {
    let mut fields = line.split_whitespace();
    let (Some(user), Some(sys)) = (fields.next(), fields.next()) else {
        return f64::INFINITY;
    };
    if fields.next().is_some() {
        return f64::INFINITY;
    }
    sh_cpu_field_seconds(user) + sh_cpu_field_seconds(sys)
}

/// One `times` field: `MmS.SSs` minutes-and-seconds — the minute prefix
/// is load bearing, `1m0.00s` is exactly sixty seconds — or a bare
/// `S.SSs`. The lexical grammar is validated BEFORE any numeric
/// conversion: minutes must be a plain integer, seconds an unsigned
/// plain decimal. Bare `f64` parsing would admit `1e-9s` (a
/// nanosecond), `0.5m0s` (thirty seconds from a fractional minute),
/// `+1s` and `-0s`; those spellings read as infinity here.
fn sh_cpu_field_seconds(field: &str) -> f64 {
    if field.contains(['d', 'h']) {
        return f64::INFINITY;
    }
    let Some(tail) = field.strip_suffix('s') else {
        return f64::INFINITY;
    };
    match tail.split_once('m') {
        None => plain_decimal_seconds(tail).unwrap_or(f64::INFINITY),
        Some((minutes, seconds)) => {
            let (Some(minutes), Some(seconds)) =
                (plain_minutes(minutes), plain_decimal_seconds(seconds))
            else {
                return f64::INFINITY;
            };
            minutes * 60.0 + seconds
        }
    }
}

/// A plain-integer minute count: digits only — no sign, no fraction, no
/// exponent. `None` refuses `0.5`, `+1`, `1e2` and the empty string.
fn plain_minutes(minutes: &str) -> Option<f64> {
    if minutes.is_empty() || !minutes.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    minutes.parse::<u64>().ok().map(|minutes| minutes as f64)
}

/// An unsigned plain-decimal seconds value: digits, optionally one '.'
/// followed by at least one digit — no sign, no exponent, no bare dot.
fn plain_decimal_seconds(seconds: &str) -> Option<f64> {
    let plain = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    match seconds.split_once('.') {
        Some((whole, fraction)) if plain(whole) && plain(fraction) => {}
        None if plain(seconds) => {}
        _ => return None,
    }
    seconds.parse().ok()
}

#[test]
fn sh_cpu_seconds_parses_minutes_and_rejects_malformed_lines() {
    assert_eq!(sh_cpu_seconds("1m0.00s 0m0.00s"), 60.0);
    assert_eq!(sh_cpu_seconds("0m1.50s 1m30.00s"), 91.5);
    assert_eq!(sh_cpu_seconds("12.34s 0.00s"), 12.34);
    assert_eq!(sh_cpu_seconds("1d2h3m4.56s 0m0.00s"), f64::INFINITY);
    assert_eq!(
        sh_cpu_seconds("1m 0m0.00s"),
        f64::INFINITY,
        "a field missing its seconds must not parse as zero"
    );
    assert_eq!(
        sh_cpu_seconds("0m0.00s"),
        f64::INFINITY,
        "exactly two fields are required"
    );
    assert_eq!(sh_cpu_seconds(""), f64::INFINITY);
    assert_eq!(
        sh_cpu_seconds("-1s 0m0.00s"),
        f64::INFINITY,
        "negative cpu is unboundable"
    );
    assert_eq!(
        sh_cpu_seconds("0m0.00s 0m0.00s extra"),
        f64::INFINITY,
        "a trailing field refuses the line"
    );
    assert_eq!(
        sh_cpu_seconds("1e-9s 0m0.00s"),
        f64::INFINITY,
        "an exponent is not a plain decimal"
    );
    assert_eq!(
        sh_cpu_seconds("0.5m0s 0m0.00s"),
        f64::INFINITY,
        "a fractional minute must not read as thirty seconds"
    );
    assert_eq!(
        sh_cpu_seconds("+1s 0m0.00s"),
        f64::INFINITY,
        "a signed second is not unsigned"
    );
    assert_eq!(
        sh_cpu_seconds("-0s 0m0.00s"),
        f64::INFINITY,
        "negative zero still carries a sign"
    );
    assert_eq!(
        sh_cpu_seconds("1m2e3s 0m0.00s"),
        f64::INFINITY,
        "an exponent after minutes is refused too"
    );
    assert_eq!(
        sh_cpu_seconds("1.5m2s 0m0.00s"),
        f64::INFINITY,
        "a fractional minute anywhere is refused"
    );
    assert_eq!(
        sh_cpu_seconds("1.s 0m0.00s"),
        f64::INFINITY,
        "a bare dot needs fraction digits"
    );
    assert_eq!(
        sh_cpu_seconds(".5s 0m0.00s"),
        f64::INFINITY,
        "a bare fraction needs whole digits"
    );
}

/// The largest regular file under `path`, recursing into directories.
/// Every traversal, entry, or metadata failure propagates: a target
/// tree the sampler cannot read is a measurement failure, never a
/// silent zero. Non-file, non-directory entries (symlinks) contribute
/// nothing.
fn largest_file_bytes(path: &Path) -> std::io::Result<u64> {
    let mut largest = 0_u64;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_dir() {
            largest = largest.max(largest_file_bytes(&entry.path())?);
        } else if meta.is_file() {
            largest = largest.max(meta.len());
        }
    }
    Ok(largest)
}

/// Set on the re-executed test binary so it runs the unreadable-subtree
/// probe (as nobody under Linux, so the chmod bites in the root Docker
/// gate too).
const UNREADABLE_CHILD_MARKER: &str = "RIVECT_UNREADABLE_CHILD";

#[test]
fn largest_file_bytes_fails_on_an_unreadable_subtree() {
    if std::env::var_os(UNREADABLE_CHILD_MARKER).is_some() {
        // SAFETY: geteuid takes no arguments and returns the effective
        // uid; the value is only compared.
        if unsafe { geteuid() } == 0 {
            // Root without a privilege-dropping discriminator cannot run
            // this probe: root reads through mode 000, so a green return
            // here would assert nothing. Fail loudly instead of
            // reporting an asserting PASS the leg never performed
            // (Linux Docker runs as root WITH setpriv, so the nobody leg
            // still executes there; a non-root host never reaches this).
            panic!(
                "the unreadable-subtree probe cannot discriminate as root: \
                 run the suite non-root or through a setpriv discriminator"
            );
        }
        let root = scratch("unreadable");
        let blocked = root.join("blocked");
        std::fs::create_dir_all(&blocked).expect("create the blocked subtree");
        std::fs::write(blocked.join("big"), [0_u8; 4096]).expect("plant the blocked file");
        std::fs::write(root.join("top"), b"x").expect("plant a readable file");
        std::fs::set_permissions(
            &blocked,
            std::os::unix::fs::PermissionsExt::from_mode(0o000),
        )
        .expect("make the subtree unreadable");
        let outcome = largest_file_bytes(&root);
        std::fs::set_permissions(
            &blocked,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("restore the subtree before any verdict");
        assert!(
            outcome.is_err(),
            "a chmod-000 subtree must fail the sampler, got {outcome:?}"
        );
        return;
    }
    let exe = std::env::current_exe().expect("test binary path");
    // Under Linux root the chmod probe would read straight through mode
    // 000, so the child drops to nobody first — the same setpriv the
    // confined chain uses; elsewhere it re-execs at the host's own uid.
    #[cfg(target_os = "linux")]
    // SAFETY: geteuid takes no arguments and only reports this caller.
    let mut command = if unsafe { geteuid() } == 0 {
        let mut command = Command::new("/usr/bin/setpriv");
        command
            .args(["--reuid=65534", "--regid=65534", "--clear-groups"])
            .arg(&exe);
        command
    } else {
        Command::new(&exe)
    };
    #[cfg(not(target_os = "linux"))]
    let mut command = Command::new(&exe);
    let output = command
        .args([
            "--exact",
            "largest_file_bytes_fails_on_an_unreadable_subtree",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env(UNREADABLE_CHILD_MARKER, "1")
        .output()
        .expect("run the unreadable-subtree child");
    assert!(
        output.status.success(),
        "the unreadable-subtree child must pass its probe: stdout {:?} stderr {:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The artifact oracle counts regular files only: a symlink's TARGET
/// size must not leak into the measurement (a followed link would count
/// a file outside the measured tree), and a nonregular entry (a fifo)
/// contributes nothing.
#[test]
fn largest_file_bytes_ignores_symlinks_and_nonregular_entries() {
    let root = scratch("largest");
    let outside = scratch("largest-outside");
    std::fs::create_dir_all(root.join("sub")).expect("create the nested dir");
    std::fs::write(root.join("a"), [0_u8; 100]).expect("plant the small file");
    std::fs::write(root.join("sub").join("b"), [0_u8; 4096])
        .expect("plant the nested regular maximum");
    std::fs::write(outside.join("huge"), [0_u8; 8192])
        .expect("plant the larger symlink target outside the root");
    std::os::unix::fs::symlink(outside.join("huge"), root.join("big-link"))
        .expect("plant the symlink");
    let fifo = root.join("fifo");
    let fifo_c = CString::new(fifo.as_os_str().as_encoded_bytes()).expect("utf-8 fifo path");
    // SAFETY: owned NUL-terminated path; mode 0644 grants rw to the
    // owner; the return is checked.
    let made = unsafe { mkfifo(fifo_c.as_ptr(), 0o644) };
    assert_eq!(made, 0, "mkfifo plants the nonregular entry");
    assert_eq!(
        largest_file_bytes(&root).expect("measure the fixture"),
        4096,
        "the regular-file maximum must ignore symlink targets and nonregular entries"
    );
}

/// The twin of the fixture above with a ONE-byte regular maximum: there
/// the 4096-B regular file dwarfs a symlink's own metadata size, so an
/// oracle that wrongly charges a link's lstat size still answers 4096
/// and passes. Here the link's own metadata — its target path string —
/// is by far the larger nonregular entry, the external target stays
/// 8192 B, and the fifo still contributes nothing, so the only passing
/// answer is exactly 1.
#[test]
fn largest_file_bytes_ignores_symlink_metadata_size() {
    let root = scratch("largest-meta");
    let outside = scratch("largest-meta-outside");
    std::fs::write(root.join("one"), [0_u8; 1]).expect("plant the one-byte regular maximum");
    std::fs::write(outside.join("huge"), [0_u8; 8192])
        .expect("plant the larger symlink target outside the root");
    std::os::unix::fs::symlink(outside.join("huge"), root.join("meta-link"))
        .expect("plant the metadata-heavy symlink");
    let fifo = root.join("fifo");
    let fifo_c = CString::new(fifo.as_os_str().as_encoded_bytes()).expect("utf-8 fifo path");
    // SAFETY: owned NUL-terminated path; mode 0644 grants rw to the
    // owner; the return is checked.
    let made = unsafe { mkfifo(fifo_c.as_ptr(), 0o644) };
    assert_eq!(made, 0, "mkfifo plants the nonregular entry");
    assert_eq!(
        largest_file_bytes(&root).expect("measure the fixture"),
        1,
        "the one-byte regular maximum must not be outgrown by a symlink's metadata, its target, or a fifo"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn check_setup_mode_is_refused_outside_linux() {
    let dir = scratch("check-setup");
    let output = test_child(HELPER)
        .args(["check-setup", dir.to_str().expect("utf-8 scratch path")])
        .output()
        .expect("run check-setup");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(EXIT_PROTOCOL));
    assert!(
        stderr.starts_with("rivect-sandbox-helper:") && stderr.contains("check-setup"),
        "a linux-only mode fails typed on macOS, got {stderr:?}"
    );
}

/// SIGKILLs one listed group member from fixture teardown. `ESRCH`
/// means the member exited and was reaped between the listing and this
/// call, so its group membership already ended; any other failure
/// propagates.
fn kill_member(pid: u32) {
    // SAFETY: a plain kill(2) to one listed pid; the return is checked.
    if unsafe { kill(pid as i32, SIGKILL) } == -1 {
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(ESRCH),
            "kill the listed member {pid}"
        );
    }
}

#[test]
fn process_group_members_lists_a_forked_grandchild() {
    let mut leader = test_child("/bin/sh")
        .arg("-c")
        .arg("sleep 5 & sleep 5; wait")
        .process_group(0)
        .spawn()
        .expect("spawn the group leader");
    let pgid = leader.id();
    // The forked sleeps appear a scheduling beat after the leader, so poll
    // until the group holds the leader plus both grandchildren.
    let deadline = Instant::now() + READY_MAX;
    let mut members = Vec::new();
    while members.len() < 3 {
        assert!(
            Instant::now() < deadline,
            "the group never listed three members"
        );
        members = process_group_members(pgid).expect("list the live group");
        wait_ready(&[], &[], Duration::from_millis(10)).expect("pace the group poll");
    }
    assert!(
        members.contains(&pgid),
        "the leader lists itself: {members:?}"
    );
    // Fixture teardown owns reaping. SIGKILLing the whole group can kill
    // the leader before it reaps its children, and inside the pinned
    // Linux container no init reaper adopts the orphaned zombies — they
    // would keep the pgid forever and the dead-group listing would never
    // empty. Killing only the members leaves the leader alive to reap
    // both grandchildren through its `wait`, and reaping the leader here
    // ends the group deterministically.
    for pid in members.iter().copied().filter(|pid| *pid != pgid) {
        kill_member(pid);
    }
    leader
        .wait()
        .expect("reap the leader after it reaps its members");
    let gone = process_group_members(pgid).expect("list the dead group");
    assert!(gone.is_empty(), "a dead group lists nothing: {gone:?}");
}

/// The Darwin FFI call-site discriminator: `proc_listallpids` takes a
/// BYTE capacity while its return is a pid COUNT, so a call-site
/// regression that passes the count shrinks the buffer fourfold — a
/// 4096-slot listing then admits only 1024 pids and silently truncates.
/// 1100 members of ONE process group (a leader plus joiners under
/// `setpgid`, all `/bin/sleep`, killed and reaped before any verdict)
/// cannot fit a truncated listing, so the exact-count assert fails on
/// the regression.
#[cfg(target_os = "macos")]
#[test]
fn process_group_members_surfaces_a_group_past_the_ffi_byte_boundary() {
    const MEMBERS: usize = 1100;
    let _serialized = UID_COUNT_SENSITIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut children: Vec<std::process::Child> = Vec::with_capacity(MEMBERS);
    let leader = test_child("/bin/sleep")
        .arg("120")
        .process_group(0)
        .spawn()
        .expect("spawn the group leader");
    let pgid = leader.id();
    // The joiners' setpgid needs the leader's group to exist already,
    // so wait until the listing sees the leader before spawning them.
    let deadline = Instant::now() + READY_MAX;
    loop {
        let listed = process_group_members(pgid)
            .map(|members| members.contains(&pgid))
            .unwrap_or(false);
        if listed {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the leader never joined its own group"
        );
        wait_ready(&[], &[], Duration::from_millis(10)).expect("pace the group poll");
    }
    children.push(leader);
    for _ in 1..MEMBERS {
        children.push(
            test_child("/bin/sleep")
                .arg("120")
                .process_group(pgid as i32)
                .spawn()
                .expect("spawn a boundary group member"),
        );
    }
    // Capture-first cleanup: every member dies and is reaped before the
    // verdicts, so concurrent uid-count tests never observe the
    // teardown.
    let members = process_group_members(pgid).expect("list the boundary group");
    kill_process_group(pgid).expect("kill the boundary group");
    for child in &mut children {
        child.wait().expect("reap a boundary member");
    }
    eprintln!(
        "macOS group boundary: listed {} of {MEMBERS} members",
        members.len()
    );
    assert!(
        members.len() > 1024,
        "a fourfold-shrunk buffer truncates at 1024 entries: {}",
        members.len()
    );
    assert_eq!(
        members.len(),
        MEMBERS,
        "the listing must surface every member of the one group"
    );
    assert!(members.contains(&pgid), "the leader lists itself");
}

/// A pid that exits between the `/proc` scan and its stat read must
/// skip, never fail the listing: ordinary churn (cargo's rustc
/// children, a fork loop) retires pids mid-scan, and the recorded
/// Docker flake failed the whole test on the resulting ESRCH /
/// empty-stat reads. The oracle is the retained set, not mere Ok: the
/// leader plus one long-lived sleeper must appear in EVERY scan's
/// result while the short-lived churn children exit around them, and
/// after the deterministic teardown the drained listing is exactly
/// empty — an always-empty implementation cannot pass the
/// retained-member asserts, and live churn stays the supplemental
/// stress for the skip itself.
#[cfg(target_os = "linux")]
#[test]
fn process_group_members_skips_pids_exiting_mid_scan() {
    // The 250-sleeper churn moves this uid's count past the slack the
    // uid-count measurements tolerate, so it serializes with them.
    let _serialized = UID_COUNT_SENSITIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut churn = test_child("/bin/sh")
        .arg("-c")
        .arg("i=0; while [ \"$i\" -lt 250 ]; do sleep 0.02 & i=$((i+1)); done; wait")
        .process_group(0)
        .spawn()
        .expect("spawn the churning group");
    let pgid = churn.id();
    let mut retained = test_child("/bin/sleep")
        .arg("30")
        .process_group(pgid as i32)
        .spawn()
        .expect("spawn the retained sleeper");
    // The sleeper's setpgid settles within a scheduling beat; wait for
    // the full retained set before the scan loop (the same leader-poll
    // pattern the boundary leg uses).
    let deadline = Instant::now() + READY_MAX;
    loop {
        let members = process_group_members(pgid).expect("list the group");
        if members.contains(&pgid) && members.contains(&retained.id()) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the retained members never joined the group: {members:?}"
        );
        wait_ready(&[], &[], Duration::from_millis(5)).expect("pace the join poll");
    }
    while churn.try_wait().expect("poll the churn leader").is_none() {
        let members = process_group_members(pgid).unwrap_or_else(|error| {
            panic!("a mid-scan exit must skip, not fail the listing: {error}")
        });
        assert!(
            members.contains(&pgid) && members.contains(&retained.id()),
            "the retained members must survive every churn scan: {members:?}"
        );
        wait_ready(&[], &[], Duration::from_millis(5)).expect("pace the churn scans");
    }
    // Deterministic teardown: kill and reap every remaining member, then
    // the drained listing must be exactly empty.
    kill_process_group(pgid).expect("kill the drained group");
    churn.wait().expect("reap the churn leader");
    retained.wait().expect("reap the retained sleeper");
    let deadline = Instant::now() + READY_MAX;
    let drained = loop {
        let drained = process_group_members(pgid).expect("list the drained group");
        if drained.is_empty() || Instant::now() > deadline {
            break drained;
        }
        wait_ready(&[], &[], Duration::from_millis(5)).expect("pace the reap poll");
    };
    assert!(
        drained.is_empty(),
        "a deterministically torn-down group lists exactly nothing: {drained:?}"
    );
}

#[test]
fn uid_process_count_counts_a_spawned_child() {
    #[cfg(target_os = "linux")]
    {
        use std::collections::BTreeSet;
        use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

        const MARKER: &str = "RIVECT_UID_CENSUS_CHILD";
        const PARENT_PID_NS: &str = "RIVECT_UID_CENSUS_PARENT_PID_NS";
        const PARENT_MOUNT_NS: &str = "RIVECT_UID_CENSUS_PARENT_MOUNT_NS";
        const SUCCESS: &str = "RIVECT_UID_CENSUS_PRIVATE_OK children=8 reaped=8 delta=8";
        const OUTPUT_CAP: u64 = 64 * 1024;
        let _serialized = UID_COUNT_SENSITIVE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let marker = std::env::var_os(MARKER);
        let parent_pid_ns = std::env::var_os(PARENT_PID_NS);
        let parent_mount_ns = std::env::var_os(PARENT_MOUNT_NS);
        let panic_family = |panic: &(dyn std::any::Any + Send)| -> String {
            let message = if let Some(message) = panic.downcast_ref::<String>() {
                message.as_str()
            } else if let Some(message) = panic.downcast_ref::<&str>() {
                message
            } else {
                "non-string panic"
            };
            message.chars().take(512).collect()
        };

        // All handles survive a measurement panic until the whole group has been cleaned up.
        let cleanup = |children: &mut [std::process::Child]| {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut reaped = vec![false; children.len()];
            let mut poll_failed = vec![false; children.len()];
            let mut errors = Vec::new();
            for (index, child) in children.iter_mut().enumerate() {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        reaped[index] = true;
                        continue;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        errors.push(format!("initial poll pid {}: {error}", child.id()));
                        poll_failed[index] = true;
                    }
                }
                if let Err(error) = child.kill() {
                    errors.push(format!("kill pid {}: {error}", child.id()));
                }
            }
            while reaped.iter().any(|done| !done) && Instant::now() < deadline {
                for (index, child) in children.iter_mut().enumerate() {
                    if reaped[index] {
                        continue;
                    }
                    match child.try_wait() {
                        Ok(Some(_)) => reaped[index] = true,
                        Ok(None) => {}
                        Err(error) => {
                            if !poll_failed[index] {
                                errors.push(format!("reap poll pid {}: {error}", child.id()));
                                poll_failed[index] = true;
                            }
                        }
                    }
                }
                if reaped.iter().any(|done| !done)
                    && let Err(error) = wait_ready(&[], &[], Duration::from_millis(5))
                {
                    errors.push(format!("cleanup pacing: {error}"));
                    break;
                }
            }
            for (child, done) in children.iter().zip(&reaped) {
                if !done {
                    errors.push(format!(
                        "cleanup deadline: pid {} not confirmed reaped",
                        child.id()
                    ));
                }
            }
            (reaped.iter().filter(|done| **done).count(), errors)
        };

        if marker.is_none() && parent_pid_ns.is_none() && parent_mount_ns.is_none() {
            let tree = scratch("uid-census");
            let stdout_path = tree.join("stdout");
            let stderr_path = tree.join("stderr");
            let stdout = std::fs::File::create(&stdout_path).expect("create census stdout file");
            let stderr = std::fs::File::create(&stderr_path).expect("create census stderr file");
            let mut child = test_child("unshare")
                .args([
                    "--user",
                    "--map-root-user",
                    "--mount",
                    "--propagation",
                    "private",
                    "--pid",
                    "--fork",
                    "--kill-child=SIGKILL",
                    "--mount-proc",
                    "--",
                ])
                .arg(std::env::current_exe().expect("current census test executable"))
                .args([
                    "--exact",
                    "uid_process_count_counts_a_spawned_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(MARKER, "private-v1")
                .env(
                    PARENT_PID_NS,
                    std::fs::read_link("/proc/self/ns/pid").expect("parent pid namespace"),
                )
                .env(
                    PARENT_MOUNT_NS,
                    std::fs::read_link("/proc/self/ns/mnt").expect("parent mount namespace"),
                )
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::from(stderr))
                .spawn()
                .expect("spawn private census namespace");
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                eprintln!("uid census parent: unshare pid {}", child.id());
                let deadline = Instant::now() + Duration::from_secs(40);
                loop {
                    if let Some(status) = child.try_wait().expect("poll private census namespace") {
                        return status;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "private census execution deadline"
                    );
                    wait_ready(&[], &[], Duration::from_millis(5))
                        .expect("pace census parent poll");
                }
            }));
            let primary = outcome
                .as_ref()
                .err()
                .map(|panic| panic_family(panic.as_ref()));
            let (reaped, errors) = cleanup(std::slice::from_mut(&mut child));
            eprintln!("uid census parent: primary={primary:?}");
            eprintln!("uid census parent cleanup: reaped={reaped}, errors={errors:?}");
            let read_output = |path: &Path| -> std::io::Result<Vec<u8>> {
                let mut bytes = Vec::new();
                std::fs::File::open(path)?
                    .take(OUTPUT_CAP + 1)
                    .read_to_end(&mut bytes)?;
                Ok(bytes)
            };
            let stdout = read_output(&stdout_path);
            let stderr = read_output(&stderr_path);
            for (name, output) in [("stdout", &stdout), ("stderr", &stderr)] {
                match output {
                    Ok(bytes) => eprintln!(
                        "uid census child {name}:\n{}",
                        String::from_utf8_lossy(bytes)
                    ),
                    Err(error) => eprintln!("uid census child {name} read failed: {error}"),
                }
            }
            let status = match outcome {
                Ok(status) => status,
                Err(panic) => resume_unwind(panic),
            };
            assert!(errors.is_empty(), "unshare cleanup gap: {errors:?}");
            assert_eq!(reaped, 1, "the direct unshare child must be reaped");
            let stdout = stdout.expect("read bounded census stdout");
            let stderr = stderr.expect("read bounded census stderr");
            assert!(
                stdout.len() as u64 <= OUTPUT_CAP && stderr.len() as u64 <= OUTPUT_CAP,
                "census child output overflow"
            );
            assert!(
                status.success(),
                "private census setup/measurement failed: {status}"
            );
            let stdout = String::from_utf8(stdout).expect("census stdout is utf8");
            let stderr = String::from_utf8(stderr).expect("census stderr is utf8");
            assert_eq!(
                stdout
                    .lines()
                    .filter(|line| *line == "running 1 test")
                    .count(),
                1
            );
            let summaries: Vec<_> = stdout
                .lines()
                .filter(|line| line.starts_with("test result:"))
                .collect();
            assert_eq!(summaries.len(), 1, "exactly one child libtest result");
            assert!(
                summaries[0]
                    .starts_with("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ")
            );
            assert!(summaries[0].contains(" filtered out; finished in "));
            assert_eq!(
                stdout
                    .lines()
                    .chain(stderr.lines())
                    .filter(|line| *line == SUCCESS)
                    .count(),
                1,
                "exactly one complete private census terminal marker"
            );
            return;
        }

        assert_eq!(
            marker.as_deref(),
            Some(std::ffi::OsStr::new("private-v1")),
            "unknown or partial census marker"
        );
        let namespace_identity = |identity: std::ffi::OsString, prefix: &str| {
            let number = identity
                .to_str()
                .expect("namespace identity is utf8")
                .strip_prefix(prefix)
                .and_then(|identity| identity.strip_suffix(']'))
                .expect("canonical parent namespace marker");
            assert!(
                !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()),
                "numeric parent namespace marker"
            );
            assert!(number.parse::<u64>().expect("parent namespace number") > 0);
            PathBuf::from(identity)
        };
        let parent_pid_ns = namespace_identity(
            parent_pid_ns.expect("census parent pid namespace marker"),
            "pid:[",
        );
        let parent_mount_ns = namespace_identity(
            parent_mount_ns.expect("census parent mount namespace marker"),
            "mnt:[",
        );
        let pid_ns = std::fs::read_link("/proc/self/ns/pid").expect("private pid namespace");
        let mount_ns = std::fs::read_link("/proc/self/ns/mnt").expect("private mount namespace");
        assert_eq!(
            std::process::id(),
            1,
            "private census must be namespace pid1"
        );
        assert_eq!(
            std::fs::read_link("/proc/self").expect("private proc self"),
            Path::new("1")
        );
        assert_eq!(
            pid_ns,
            std::fs::read_link("/proc/1/ns/pid").expect("proc pid1 namespace")
        );
        assert_ne!(
            pid_ns, parent_pid_ns,
            "pid namespace must differ from parent"
        );
        assert_ne!(
            mount_ns, parent_mount_ns,
            "mount namespace must differ from parent"
        );
        let proc_directory = std::fs::File::open("/proc").expect("open the active proc mount");
        let fdinfo = std::fs::read_to_string(format!(
            "/proc/self/fdinfo/{}",
            std::os::fd::AsRawFd::as_raw_fd(&proc_directory)
        ))
        .expect("active proc directory fdinfo");
        let proc_mount_id = fdinfo
            .lines()
            .find_map(|line| line.strip_prefix("mnt_id:"))
            .expect("active proc mount id")
            .trim();
        assert!(
            proc_mount_id.parse::<u64>().expect("numeric proc mount id") > 0,
            "positive active proc mount id"
        );
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("private mountinfo");
        let proc_mounts: Vec<_> = mountinfo
            .lines()
            .filter(|line| line.split_whitespace().next() == Some(proc_mount_id))
            .collect();
        assert_eq!(proc_mounts.len(), 1, "exactly one active proc mount id");
        assert_eq!(proc_mounts[0].split_whitespace().nth(4), Some("/proc"));
        let (mount, filesystem) = proc_mounts[0]
            .split_once(" - ")
            .expect("proc mountinfo separator");
        assert_eq!(filesystem.split_whitespace().next(), Some("proc"));
        assert!(
            !mount
                .split_whitespace()
                .skip(6)
                .any(|field| field.starts_with("shared:") || field.starts_with("master:")),
            "proc mount must have private propagation"
        );
        let uid_map = std::fs::read_to_string("/proc/self/uid_map").expect("private uid mapping");
        let mapping: Vec<_> = uid_map.split_whitespace().collect();
        assert_eq!(mapping.len(), 3, "one mapped real uid");
        assert_eq!(mapping[0], "0");
        assert_eq!(mapping[2], "1");
        eprintln!("uid census namespaces: pid={pid_ns:?}, mount={mount_ns:?}, private proc=true");

        let numeric_entries = |path: &Path| -> BTreeSet<u32> {
            let mut pids = BTreeSet::new();
            for entry in std::fs::read_dir(path).expect("read independent proc directory") {
                let entry = entry.expect("read independent proc entry");
                let name = entry.file_name();
                let name = name.to_str().expect("proc entry name is utf8");
                if !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit()) {
                    if path == Path::new("/proc") {
                        assert!(pids.len() < 16, "private proc population exceeds sixteen");
                    }
                    assert!(
                        pids.insert(name.parse().expect("numeric proc entry")),
                        "unique proc entry"
                    );
                }
            }
            pids
        };
        let status_number = |status: &str, field: &str| -> u64 {
            status
                .lines()
                .find_map(|line| line.strip_prefix(field))
                .expect("required independent status field")
                .split_whitespace()
                .next()
                .expect("nonempty independent status field")
                .parse()
                .expect("numeric independent status field")
        };
        let self_tasks = || {
            let tasks = numeric_entries(Path::new("/proc/1/task"));
            let status =
                std::fs::read_to_string("/proc/1/status").expect("independent pid1 status");
            assert_eq!(status_number(&status, "Uid:"), 0, "mapped real uid");
            assert!(!tasks.is_empty(), "pid1 must have tasks");
            assert_eq!(
                status_number(&status, "Threads:"),
                tasks.len() as u64,
                "task listing agrees with Threads"
            );
            tasks
        };
        assert_eq!(numeric_entries(Path::new("/proc")), BTreeSet::from([1]));
        let tasks = self_tasks();
        let base = tasks.len() as u64;
        let before = uid_process_count().expect("count the private uid baseline");
        assert_eq!(
            before, base,
            "private before census equals independent tasks"
        );
        eprintln!("uid census baseline: B={base}, before={before}, task_ids={tasks:?}");
        let sleep_exe = std::fs::canonicalize("/bin/sleep").expect("canonical sleep executable");
        let mut children = Vec::with_capacity(8);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let deadline = Instant::now() + Duration::from_secs(10);
            for _ in 0..8 {
                children.push(
                    test_child("/bin/sleep")
                        .arg("30")
                        .spawn()
                        .expect("spawn a private counted child"),
                );
                eprintln!(
                    "uid census owned pid {}",
                    children.last().expect("retained child").id()
                );
            }
            let expected: BTreeSet<_> = std::iter::once(1)
                .chain(children.iter().map(std::process::Child::id))
                .collect();
            assert_eq!(expected.len(), 9, "eight unique owned children plus pid1");
            assert!(children.iter().all(|child| child.id() > 1));
            for child in &mut children {
                loop {
                    assert!(
                        child
                            .try_wait()
                            .expect("readiness child liveness")
                            .is_none(),
                        "H3: counted child exited before readiness"
                    );
                    let exe = std::fs::read_link(format!("/proc/{}/exe", child.id()))
                        .expect("H3: counted child executable");
                    if exe == sleep_exe {
                        break;
                    }
                    assert!(Instant::now() < deadline, "H3: group readiness deadline");
                    wait_ready(&[], &[], Duration::from_millis(5)).expect("pace group readiness");
                }
                assert!(Instant::now() < deadline, "H3: group readiness deadline");
            }
            let mut verify_population = |boundary: &str| {
                assert_eq!(
                    numeric_entries(Path::new("/proc")),
                    expected,
                    "private population at {boundary}"
                );
                assert_eq!(
                    self_tasks(),
                    tasks,
                    "pid1 tasks remain stable at {boundary}"
                );
                for child in &mut children {
                    let pid = child.id();
                    let alive = child
                        .try_wait()
                        .expect("H3: boundary liveness poll")
                        .is_none();
                    eprintln!("uid census {boundary}: pid={pid}, alive={alive}");
                    assert!(alive, "H3: child exited at {boundary}");
                    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
                        .expect("H3: child OS status");
                    assert_eq!(status_number(&status, "Pid:"), u64::from(pid));
                    assert_eq!(status_number(&status, "PPid:"), 1);
                    assert_eq!(status_number(&status, "Uid:"), 0);
                    assert_eq!(status_number(&status, "Threads:"), 1);
                    let state = status
                        .lines()
                        .find_map(|line| line.strip_prefix("State:"))
                        .expect("H3: child state")
                        .split_whitespace()
                        .next()
                        .expect("H3: nonempty child state");
                    assert!(
                        !state.starts_with('Z') && !state.starts_with('X'),
                        "H3: child must be live: {state}"
                    );
                    assert_eq!(
                        std::fs::read_link(format!("/proc/{pid}/exe"))
                            .expect("H3: boundary executable"),
                        sleep_exe
                    );
                }
            };
            verify_population("before after-census");
            let after = uid_process_count();
            verify_population("after after-census");
            eprintln!("uid census measurement: B={base}, before={before}, after={after:?}");
            let after = after.expect("H2: private after census failed with proven population");
            assert!(
                after >= before + 4,
                "the count must include the spawned children: before {before}, after {after}"
            );
            assert_eq!(
                after,
                base + 8,
                "H2: private census counts all eight child tasks"
            );
            assert_eq!(after - before, 8, "H2: private census delta");
        }));
        let primary = outcome
            .as_ref()
            .err()
            .map(|panic| panic_family(panic.as_ref()));
        let (reaped, errors) = cleanup(&mut children);
        eprintln!(
            "uid census measurement: primary={primary:?}, owned={}",
            children.len()
        );
        eprintln!("uid census cleanup: reaped={reaped}, errors={errors:?}");
        let drained = catch_unwind(|| numeric_entries(Path::new("/proc")));
        match &drained {
            Ok(pids) => eprintln!("uid census post-cleanup population: {pids:?}"),
            Err(panic) => eprintln!(
                "uid census post-cleanup population error: {}",
                panic_family(panic.as_ref())
            ),
        }
        if let Err(panic) = outcome {
            resume_unwind(panic);
        }
        assert!(errors.is_empty(), "private child cleanup gap: {errors:?}");
        assert_eq!(reaped, 8, "eight children must be confirmed reaped");
        assert_eq!(
            match drained {
                Ok(pids) => pids,
                Err(panic) => resume_unwind(panic),
            },
            BTreeSet::from([1]),
            "post-cleanup private population"
        );
        println!("\n{SUCCESS}");
    }
    #[cfg(target_os = "macos")]
    {
        // The before/after comparison sits inside the churn slack the
        // boundary legs' spawn/kill windows blow past, so they serialize.
        let _serialized = UID_COUNT_SENSITIVE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let before = uid_process_count().expect("count this uid");
        let mut children: Vec<std::process::Child> = (0..8)
            .map(|_| {
                test_child("/bin/sleep")
                    .arg("30")
                    .spawn()
                    .expect("spawn a counted child")
            })
            .collect();
        let after = uid_process_count().expect("count this uid again");
        eprintln!("uid process count: before {before}, with eight children {after}");
        // Eight same-uid children exist; churn on a shared host may retire a
        // few, but half the spawns surviving pins the count to real processes.
        assert!(
            after >= before + 4,
            "the count must include the spawned children: before {before}, after {after}"
        );
        for child in &mut children {
            child.kill().expect("kill the counted child");
            child.wait().expect("reap the counted child");
        }
    }
}

/// Set on the re-executed test binary (value: the uid to count) so it
/// counts one real uid's processes while itself running with a
/// mismatched effective uid.
#[cfg(target_os = "linux")]
const REAL_UID_CHILD_MARKER: &str = "RIVECT_REAL_UID_CHILD";

/// Real uids this suite deliberately keeps otherwise unused, so the
/// per-uid deltas below are attributable to this leg's holders alone:
/// the heavy uid carries four mismatch holders, the idle uid none.
#[cfg(target_os = "linux")]
const REAL_UID_HEAVY: &str = "65533";
#[cfg(target_os = "linux")]
const REAL_UID_IDLE: &str = "65532";

/// The count must follow the REAL uid, proven by deliberately UNEQUAL
/// per-uid populations: `/proc/<pid>`'s directory owner tracks the
/// EFFECTIVE uid, so a count that trusted it (or `geteuid`) would read
/// the root population for BOTH counting children and the delta would
/// collapse. Four mismatch holders (real uid 65533, effective uid 0)
/// stay alive while one counting child per uid scans; the difference
/// between the two independent counts must carry the holders — a global
/// floor any unrelated same-uid population satisfies cannot.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "root-only: real/effective uid mismatch needs CAP_SETUID; closed at uid 0 by test-plan.md helper_root_only_uid0"]
fn uid_process_count_follows_the_real_uid_not_the_effective() {
    if std::env::var_os(REAL_UID_CHILD_MARKER).is_some() {
        // The count itself reads this process's real uid; the marker's
        // value only names which outer uid planted this child.
        let count =
            uid_process_count().expect("count the real uid with a mismatched effective uid");
        println!("real_uid_count={count}");
        return;
    }
    let mismatch_holder = |uid: &str| {
        let mut command = Command::new("/usr/bin/setpriv");
        command
            .args([
                format!("--ruid={uid}"),
                "--euid=0".to_string(),
                format!("--regid={uid}"),
                "--clear-groups".to_string(),
            ])
            .arg("/bin/sleep")
            .arg("30")
            .env_clear();
        command
            .spawn()
            .expect("spawn the mismatched-credential holder")
    };
    let mut holders: Vec<std::process::Child> =
        (0..4).map(|_| mismatch_holder(REAL_UID_HEAVY)).collect();
    let count_for = |uid: &str| -> u64 {
        let exe = std::env::current_exe().expect("test binary path");
        let output = Command::new("/usr/bin/setpriv")
            .args([
                format!("--ruid={uid}"),
                "--euid=0".to_string(),
                format!("--regid={uid}"),
                "--clear-groups".to_string(),
            ])
            .arg(&exe)
            .args([
                "--exact",
                "uid_process_count_follows_the_real_uid_not_the_effective",
                "--include-ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env(REAL_UID_CHILD_MARKER, uid)
            .output()
            .expect("run the real-uid counting child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "real-uid {uid} counting child: {:?} stdout {stdout:?} stderr {:?}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        child_report(&stdout, "real_uid_count=")
            .parse()
            .expect("the child reports its real-uid count")
    };
    let heavy = count_for(REAL_UID_HEAVY);
    let idle = count_for(REAL_UID_IDLE);
    for holder in &mut holders {
        holder.kill().expect("kill a mismatch holder");
        holder.wait().expect("reap a mismatch holder");
    }
    eprintln!(
        "mismatched-credential real-uid counts: heavy {heavy} (uid {REAL_UID_HEAVY}, four holders), \
         idle {idle} (uid {REAL_UID_IDLE}, no holders)"
    );
    assert!(
        idle >= 1,
        "the idle counting child must count itself under its real uid, got {idle}"
    );
    assert!(
        heavy >= idle + 4,
        "the per-uid delta must carry the four mismatch holders: heavy {heavy}, idle {idle}"
    );
}

/// The old enumeration truncation boundary: the F3 regression truncated
/// listings at 1024 entries, and this leg drives the live population
/// past it (1100 bounded, cleaned-up processes) and requires the scan to
/// surface every member.
#[cfg(target_os = "linux")]
const ENUMERATION_BOUNDARY_CHILDREN: usize = 1100;

/// Serializes the tests whose uid-count measurements a boundary leg would
/// otherwise churn past the NPROC slack: the spawn/kill window moves the
/// same-uid count by 1100 while it runs (the Linux enumeration leg, the
/// macOS FFI-group leg, and the NPROC churn assert in the check-profile
/// test).
static UID_COUNT_SENSITIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(target_os = "linux")]
#[test]
fn enumeration_surfaces_a_population_past_the_truncation_boundary() {
    let _serialized = UID_COUNT_SENSITIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let before = uid_process_count().expect("count this uid before the boundary spawn");
    // The first child leads the group; the rest join it, so the group
    // listing proves the same population the uid count does.
    let mut children: Vec<std::process::Child> = Vec::with_capacity(ENUMERATION_BOUNDARY_CHILDREN);
    let leader = test_child("/bin/sleep")
        .arg("60")
        .process_group(0)
        .spawn()
        .expect("spawn the boundary group leader");
    let pgid = leader.id();
    children.push(leader);
    for _ in 1..ENUMERATION_BOUNDARY_CHILDREN {
        children.push(
            test_child("/bin/sleep")
                .arg("60")
                .process_group(pgid as i32)
                .spawn()
                .expect("spawn a boundary group member"),
        );
    }
    let after = uid_process_count().expect("count this uid past the boundary");
    let members = process_group_members(pgid).expect("list the boundary group");
    // Capture-first cleanup: every member dies and is reaped before the
    // verdicts, so concurrent uid-count tests never observe the teardown.
    kill_process_group(pgid).expect("kill the boundary group");
    for child in &mut children {
        child.wait().expect("reap a boundary member");
    }
    eprintln!(
        "enumeration boundary: uid count {before} -> {after}, group members {} (spawned {ENUMERATION_BOUNDARY_CHILDREN})",
        members.len()
    );
    // The floor is absolute, not before-relative: concurrent same-uid
    // churn can retire baseline processes between the two counts, but
    // this test binary plus all 1100 members must be surfaced — an
    // enumeration that truncates near 1024 cannot reach the floor.
    assert!(
        after > ENUMERATION_BOUNDARY_CHILDREN as u64,
        "the uid count must surface every live member past the old 1024 truncation: before {before}, after {after}"
    );
    assert!(
        members.len() >= ENUMERATION_BOUNDARY_CHILDREN,
        "the group listing must surface every live member past the old 1024 truncation: {}",
        members.len()
    );
}

/// PID 1 (launchd) is live on every Darwin host and leads its own
/// process group, yet a non-root `proc_pidinfo` read of it answers zero
/// with EPERM under SIP — the exact case a zero return cannot classify
/// as vanished. The enumeration must read it through the kinfo
/// fallback, or refuse typed; an empty successful listing is the silent
/// omission of a live pid the fail-closed contract forbids.
#[cfg(target_os = "macos")]
#[test]
fn process_group_members_reads_live_launchd_or_refuses_typed() {
    match process_group_members(1) {
        Ok(members) => assert!(
            members.contains(&1),
            "live pid 1 was silently omitted from a successful group listing: {members:?}"
        ),
        // The refusal carries pid 1 as a typed field — never prose.
        Err(ProcessReadError::ReadFailed { pid: 1, .. })
        | Err(ProcessReadError::MalformedRecord { pid: 1 }) => {}
        Err(error) => {
            panic!("a live unreadable pid must refuse typed naming the pid, got: {error}")
        }
    }
}

#[test]
fn resident_bytes_tracks_a_live_allocation_and_errs_once_reaped() {
    if std::env::var_os(RESIDENT_CHILD_MARKER).is_some() {
        // The child signals readiness BEFORE allocating (one stdout
        // byte), then waits on stdin for the parent's go: the parent
        // reads its baseline from this same pid in between, so the
        // allocation's growth is measured against the child's own
        // pre-allocation residency, not an arbitrary threshold.
        std::io::stdout()
            .write_all(b"r")
            .and_then(|()| std::io::stdout().flush())
            .expect("signal readiness");
        let mut go = [0_u8; 1];
        std::io::stdin()
            .read_exact(&mut go)
            .expect("wait for the parent's go");
        // 1 KiB blocks are the small-allocation class a relative cap can
        // miss; every page is written, so every page is resident.
        let blocks: Vec<Box<[u8; 1024]>> = (0..RESIDENT_ALLOCATION_BLOCKS)
            .map(|_| Box::new([0x5a; 1024]))
            .collect();
        std::hint::black_box(&blocks);
        std::thread::sleep(READY_MAX);
        return;
    }
    let exe = std::env::current_exe().expect("test binary path");
    let mut child = test_child(exe)
        .args([
            "--exact",
            "resident_bytes_tracks_a_live_allocation_and_errs_once_reaped",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(RESIDENT_CHILD_MARKER, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn the resident child");
    let pid = child.id();
    // The read end stays open for the child's whole life: libtest writes
    // its banner to stdout, and a closed read end would kill the child
    // with EPIPE before it ever allocates.
    let mut child_stdout = child.stdout.take().expect("the child's stdout is piped");
    let mut ready = [0_u8; 1];
    child_stdout
        .read_exact(&mut ready)
        .expect("wait for the child's readiness signal");
    let baseline = resident_bytes(pid).expect("read the pre-allocation baseline");
    child
        .stdin
        .take()
        .expect("the child's stdin is piped")
        .write_all(b"g")
        .expect("release the child's allocation");
    let deadline = Instant::now() + READY_MAX;
    let mut peak = 0_u64;
    let mut observed = false;
    while Instant::now() < deadline {
        let resident = resident_bytes(pid).expect("read the live child");
        peak = peak.max(resident);
        if resident >= baseline + RESIDENT_THRESHOLD {
            observed = true;
            break;
        }
        wait_ready(&[], &[], Duration::from_millis(10)).expect("pace the resident poll");
    }
    eprintln!(
        "resident bytes: baseline {baseline}, peak {peak}, growth threshold {RESIDENT_THRESHOLD}"
    );
    assert!(
        observed,
        "the read must track at least {RESIDENT_THRESHOLD} bytes of growth over the same-pid baseline {baseline}, peak {peak}"
    );
    child.kill().expect("kill the resident child");
    child.wait().expect("reap the resident child");
    match resident_bytes(pid) {
        Err(ProcessReadError::ReadFailed {
            pid: reaped_pid, ..
        }) if reaped_pid == pid => {}
        other => panic!("a reaped pid must refuse ReadFailed naming the pid, got {other:?}"),
    }
}

/// Runs `check-setup <root>` inside fresh user/mount/PID/net namespaces —
/// the only invocation the mode accepts. The root crosses as ONE quoted
/// positional ("$1"), never interpolated shell text, so a path with
/// spaces still reaches the helper as a single argument.
#[cfg(target_os = "linux")]
fn unshare_check_setup(root: &str) -> Output {
    let script = format!("\"{HELPER}\" check-setup \"$1\"");
    test_child("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--pid",
            "--net",
            "--fork",
        ])
        .args(["/bin/sh", "-c", &script])
        .arg("sh")
        .arg(root)
        .output()
        .expect("run check-setup inside fresh namespaces")
}

/// Runs the refused check-setup inside fresh namespaces and inspects
/// the outcome from a CONTINUING shell in the SAME mount namespace,
/// before the unshare child exits: the shell snapshots the target's
/// fstype and the whole mount table, runs the helper, then compares and
/// prints `fstype-`/`mounts-`/`planted-` verdicts, exiting with the
/// helper's own status. Every measurement is a guarded assignment with
/// its own exit code (96/97 pre-refusal, 98/99/95 post-refusal):
/// command substitution swallows a producer's exit status, so a stat or
/// cat that emits the expected text and still fails must reject the leg
/// instead of printing the clean verdicts its text would earn. A
/// nonempty `shadow_bin` is prepended to the shell's PATH for the
/// fault-discriminator test. A helper that mounts tmpfs over the target
/// and only then refuses (probe executed: content hidden, exit 10) is
/// caught here, inside the namespace where it mounted; the parent's
/// post-exit view is restored and blind to it.
#[cfg(target_os = "linux")]
fn unshare_check_setup_inspected(
    root: &str,
    target: &str,
    planted: &str,
    shadow_bin: &Path,
) -> Output {
    let script = format!(
        "if [ -n \"$4\" ]; then PATH=\"$4:$PATH\"; fi\n\
         fstype=$(stat -f -c %T \"$2\") || exit 96\n\
         mounts=$(cat /proc/mounts) || exit 97\n\
         \"{HELPER}\" check-setup \"$1\"; rc=$?\n\
         after=$(stat -f -c %T \"$2\") || exit 98\n\
         if [ \"$fstype\" = \"$after\" ]; then echo fstype-unchanged; else echo fstype-changed; fi\n\
         after_mounts=$(cat /proc/mounts) || exit 99\n\
         if [ \"$mounts\" = \"$after_mounts\" ]; then echo mounts-unchanged; else echo mounts-changed; fi\n\
         planted=$(cat \"$3\" 2>/dev/null) || exit 95\n\
         if [ \"$planted\" = \"x\" ]; then echo planted-intact; else echo planted-missing; fi\n\
         exit \"$rc\""
    );
    test_child("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--pid",
            "--net",
            "--fork",
        ])
        .args(["/bin/sh", "-c", &script])
        .arg("sh")
        .arg(root)
        .arg(target)
        .arg(planted)
        .arg(shadow_bin)
        .output()
        .expect("run and inspect the refused check-setup inside the namespace")
}

/// Asserts the in-namespace verdicts of a refused check-setup: the
/// continuing shell inside the mount namespace must report the target's
/// fstype, the mount table, and the planted content all unchanged.
/// These catch a helper that mounts before refusing, which every
/// parent-side check after the namespace dies misses.
#[cfg(target_os = "linux")]
fn assert_namespace_refused_cleanly(refused: &Output, case: &str) {
    let stdout = String::from_utf8_lossy(&refused.stdout);
    for verdict in ["fstype-unchanged", "mounts-unchanged", "planted-intact"] {
        assert!(
            stdout.contains(verdict),
            "{case}: the in-namespace inspection must report {verdict}: {stdout:?}"
        );
    }
}

/// Writes one shadow producer into a fresh bin dir and marks it
/// executable; `script` receives the bin dir so its fault marker can
/// live beside it. The dir prepends to the inspection shell's PATH.
#[cfg(target_os = "linux")]
fn plant_shadow_bin(name: &str, script: impl FnOnce(&Path) -> String) -> TempTree {
    use std::os::unix::fs::PermissionsExt as _;
    let bin = scratch(&format!("shadow-{name}"));
    let producer = bin.join(name);
    std::fs::write(&producer, script(&bin)).expect("write the shadow producer");
    std::fs::set_permissions(&producer, std::fs::Permissions::from_mode(0o755))
        .expect("make the shadow producer executable");
    bin
}

/// The post-refusal measurements are guarded assignments, not bare
/// command substitutions: a producer that emits the expected text and
/// still exits nonzero must reject the leg with that measurement's own
/// exit code, never print the clean verdicts its emitted text would
/// earn. Each leg shadows ONE producer with a script that answers the
/// expected text on its first call and re-emits it with a failing
/// status afterwards.
#[cfg(target_os = "linux")]
#[test]
fn refused_check_setup_inspection_rejects_failing_measurement_producers() {
    // The refused-dirty-rw fixture: planted content makes the rw an
    // unsafe mount point, so check-setup refuses without touching
    // anything and the inspection script reaches its post-refusal
    // measurements.
    let root = scratch("fault-probe");
    let rw = root.join("rw");
    std::fs::create_dir(&rw).expect("create the attempt rw");
    std::fs::write(rw.join("planted"), b"x").expect("plant content in rw");
    let root_arg = root.to_string_lossy().into_owned();
    let rw_arg = rw.to_string_lossy().into_owned();
    let planted_arg = rw.join("planted").to_string_lossy().into_owned();

    // The faulted post-refusal stat: answers tmpfs cleanly once, then
    // re-emits tmpfs with status 42 — the leg must exit 98 before any
    // verdict is printed.
    let stat_bin = plant_shadow_bin("stat", |bin| {
        format!(
            "#!/bin/sh\n\
             if [ -e \"{}/used\" ]; then echo tmpfs; exit 42; fi\n\
             : > \"{}/used\"\n\
             echo tmpfs\n\
             exit 0\n",
            bin.display(),
            bin.display()
        )
    });
    let out = unshare_check_setup_inspected(&root_arg, &rw_arg, &planted_arg, &stat_bin);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(98),
        "the faulted post-refusal stat must reject the leg: stdout {stdout:?} stderr {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !stdout.contains("fstype-unchanged"),
        "a failing producer's emitted text must not earn a clean verdict: {stdout:?}"
    );

    // The faulted post-refusal mounts read: the shadowed cat answers a
    // fixed table cleanly for the pre-refusal snapshot, then re-emits
    // it with status 43 — the leg must exit 99 after the fstype
    // verdict (stat stays real) and without the mounts verdict.
    let mounts_bin = plant_shadow_bin("cat", |bin| {
        format!(
            "#!/bin/sh\n\
             if [ \"$1\" = \"/proc/mounts\" ]; then\n\
             if [ -e \"{}/used\" ]; then echo rivect-fake-mounts; exit 43; fi\n\
             : > \"{}/used\"\n\
             echo rivect-fake-mounts\n\
             exit 0\n\
             fi\n\
             exec /bin/cat \"$@\"\n",
            bin.display(),
            bin.display()
        )
    });
    let out = unshare_check_setup_inspected(&root_arg, &rw_arg, &planted_arg, &mounts_bin);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(99),
        "the faulted post-refusal mounts read must reject the leg: stdout {stdout:?} stderr {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("fstype-unchanged"),
        "the unshadowed stat still reports its verdict: {stdout:?}"
    );
    assert!(
        !stdout.contains("mounts-unchanged"),
        "a failing producer's emitted text must not earn a clean verdict: {stdout:?}"
    );

    // The faulted planted-content read: the shadowed cat passes
    // /proc/mounts through to the real one and answers the expected
    // content with status 44 for the planted file — the leg must exit
    // 95 after both mount verdicts and without the planted verdict.
    let planted_bin = plant_shadow_bin("cat", |_bin| {
        "#!/bin/sh\n\
         if [ \"$1\" = \"/proc/mounts\" ]; then exec /bin/cat \"$@\"; fi\n\
         echo x\n\
         exit 44\n"
            .to_owned()
    });
    let out = unshare_check_setup_inspected(&root_arg, &rw_arg, &planted_arg, &planted_bin);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(95),
        "the faulted planted-content read must reject the leg: stdout {stdout:?} stderr {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("fstype-unchanged") && stdout.contains("mounts-unchanged"),
        "the unshadowed producers still report their verdicts: {stdout:?}"
    );
    assert!(
        !stdout.contains("planted-intact"),
        "a failing producer's emitted text must not earn a clean verdict: {stdout:?}"
    );
}

/// A space-containing attempt root must reach the helper as ONE argv
/// element through every namespace script (quoted "$1" positional
/// passing): the reviewer probe split the unquoted root into two
/// arguments and turned the typed refusal (exit 10) into a protocol
/// error (exit 30).
#[cfg(target_os = "linux")]
#[test]
fn check_setup_refusal_survives_a_space_in_the_attempt_root() {
    let root = scratch("space root");
    let rw = root.join("rw");
    std::fs::create_dir(&rw).expect("create the attempt rw");
    std::fs::write(rw.join("planted"), b"x").expect("plant content in rw");
    let root_arg = root.to_str().expect("utf-8 scratch path");
    let identity_before = mount_identity(&rw);
    let dirty = unshare_check_setup(root_arg);
    let stderr = String::from_utf8_lossy(&dirty.stderr);
    assert_eq!(
        dirty.status.code(),
        Some(rivect_sandbox_helper::EXIT_SANDBOX_INIT),
        "the typed refusal must survive the space in the root: stderr {stderr:?}"
    );
    assert!(
        stderr.contains("empty"),
        "the refusal names the non-empty rw: {stderr:?}"
    );
    let planted = std::fs::read(rw.join("planted")).expect("the planted content survives");
    assert_eq!(
        planted, b"x",
        "a refused setup must not hide the planted content"
    );
    assert_eq!(
        mount_identity(&rw),
        identity_before,
        "a refused dirty rw must leave its mount identity unchanged"
    );
}

/// Decodes the octal escape sequences the kernel encodes
/// `/proc/mounts`'s whitespace-separated fields with: space `\040`,
/// tab `\011`, backslash `\134`, newline `\012`. A space-containing
/// attempt root appears escaped in the mount table, so a literal
/// substring match would miss its row entirely.
#[cfg(target_os = "linux")]
fn decode_mount_escapes(field: &str) -> String {
    let mut decoded = String::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            decoded.push(c);
            continue;
        }
        let mut escape = String::with_capacity(3);
        for _ in 0..3 {
            match chars.next() {
                Some(digit) => escape.push(digit),
                None => break,
            }
        }
        match escape.as_str() {
            "040" => decoded.push(' '),
            "011" => decoded.push('\t'),
            "134" => decoded.push('\\'),
            "012" => decoded.push('\n'),
            // Not a kernel escape: keep the bytes verbatim.
            _ => {
                decoded.push('\\');
                decoded.push_str(&escape);
            }
        }
    }
    decoded
}

/// The escape-decoded mount point of a `/proc/mounts` row.
#[cfg(target_os = "linux")]
fn mount_point_decoded(row: &str) -> Option<String> {
    row.split_whitespace().nth(1).map(decode_mount_escapes)
}

/// The identity of the mount `path` lives on: the `/proc/mounts` row
/// whose decoded mount point is the longest component-prefix of the
/// canonical `path`, as a `device fstype` pair. The negative legs prove
/// "no new mount happened" by comparing this identity across a refused
/// attempt and checking the planted content survived — an oracle that
/// holds even when the scratch directory itself already sits on tmpfs
/// (a bare `fstype != "tmpfs"` comparison does not).
#[cfg(target_os = "linux")]
fn mount_identity(path: &Path) -> String {
    let canonical = std::fs::canonicalize(path).expect("canonicalize the probe path");
    let mounts = std::fs::read_to_string("/proc/mounts").expect("read the host mount table");
    mounts
        .lines()
        .filter_map(|row| {
            let mut fields = row.split_whitespace();
            let device = fields.next()?;
            let point = PathBuf::from(mount_point_decoded(row)?);
            let fstype = fields.next()?;
            canonical
                .starts_with(&point)
                .then(|| (point.as_os_str().len(), format!("{device} {fstype}")))
        })
        .max_by_key(|(len, _)| *len)
        .map(|(_, identity)| identity)
        .unwrap_or_else(|| panic!("no mount row covers {}", canonical.display()))
}

/// Set on the re-executed test binary that runs as the CONTINUING
/// process after check-setup dropped the namespace privileges: it
/// reports its own `/proc/self/status` and a raw mount(2) verdict.
#[cfg(target_os = "linux")]
const DROPPED_MOUNT_CHILD_MARKER: &str = "RIVECT_DROPPED_MOUNT_CHILD";
/// The attempt-root path handed to the continuing process (env, not
/// argv: the re-executed harness owns argv).
#[cfg(target_os = "linux")]
const DROPPED_MOUNT_ROOT: &str = "RIVECT_DROPPED_MOUNT_ROOT";

#[cfg(target_os = "linux")]
#[test]
fn check_setup_mounts_bounded_tmpfs_and_refuses_missing_namespace() {
    // The continuing-process branch (see the drop leg at the bottom):
    // this process IS the post-drop runner, so it reads its own status
    // and attempts its own raw mount(2) — same process, same credential.
    if std::env::var_os(DROPPED_MOUNT_CHILD_MARKER).is_some() {
        let root = std::env::var_os(DROPPED_MOUNT_ROOT).expect("the attempt root crosses");
        let root = PathBuf::from(root);
        let status = std::fs::read_to_string("/proc/self/status").expect("read own status");
        let field = |name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .map(str::trim)
                .unwrap_or_else(|| panic!("own status reports {name}"))
        };
        println!("cap_eff={}", field("CapEff:"));
        println!("cap_prm={}", field("CapPrm:"));
        println!("cap_inh={}", field("CapInh:"));
        println!("no_new_privs={}", field("NoNewPrivs:"));
        let target = root.join("rw").join("mount-refused");
        std::fs::create_dir(&target).expect("create the refused mount point");
        let target_c =
            CString::new(target.as_os_str().as_encoded_bytes()).expect("utf-8 mount target");
        // SAFETY: owned NUL-terminated literals; mountflags 0; a
        // non-zero return is the verdict this branch reports, never an
        // abort.
        let refused = unsafe {
            mount(
                c"probe-tmpfs".as_ptr(),
                target_c.as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                std::ptr::null(),
            )
        };
        let errno = if refused == 0 {
            None
        } else {
            std::io::Error::last_os_error().raw_os_error()
        };
        println!("mount_errno={errno:?}");
        assert_eq!(
            errno,
            Some(EPERM),
            "the continuing process's own mount(2) must be refused EPERM"
        );
        return;
    }
    // Mount-target race (the helper's fchdir pin, main.rs): the
    // microsecond window between the validation open and the mount(2)
    // cannot be forced from outside the helper process — a deterministic
    // pathname swap mid-window would need a test-only hook inside the
    // production path, which this crate's argv-only contract forbids —
    // so the pin is proven compositionally: O_NOFOLLOW refuses a
    // symlinked rw at the open (the symlink leg below), and mount(2)
    // binds to the inode the pinned fd names, never a re-walked path.
    // Forcing the mid-flight window itself remains an unproven residual.
    // The attempt root itself carries a space: the full positive
    // quota/drop scenario below then runs under a space-containing root,
    // not just the refusal legs.
    let root = scratch("check-setup linux");
    let rw = root.join("rw");
    std::fs::create_dir(&rw).expect("create the attempt rw");
    let root_arg = root.to_str().expect("utf-8 scratch path");

    // Outside a fresh user namespace (docker root) the mount would be
    // namespace-visible to the host: typed refusal, nothing mounted, and
    // never a plain-directory fallback the child could fill the host with.
    let identity_before = mount_identity(&rw);
    let outside = test_child(HELPER)
        .args(["check-setup", root_arg])
        .output()
        .expect("run check-setup outside any namespace");
    let stderr = String::from_utf8_lossy(&outside.stderr);
    assert_eq!(
        outside.status.code(),
        Some(rivect_sandbox_helper::EXIT_SANDBOX_INIT),
        "stderr {stderr:?}"
    );
    assert!(
        stderr.contains("fresh user namespace"),
        "the refusal names the missing namespace: {stderr:?}"
    );
    assert_eq!(
        mount_identity(&rw),
        identity_before,
        "nothing may mount outside a namespace"
    );

    let rw_arg = rw.to_str().expect("utf-8 scratch path");
    // An rw with planted content is an unsafe mount point: never mounted
    // over, even inside the namespaces — and the proof runs INSIDE the
    // namespace, from a continuing shell that inspects before the
    // unshare child exits: after the exit the parent sees only its
    // restored view, so a helper that mounts and then refuses (probe:
    // tmpfs over the planted rw, exit 10) passes every parent-side
    // check.
    let planted = rw.join("planted");
    std::fs::write(&planted, b"x").expect("plant content in rw");
    let planted_arg = planted.to_str().expect("utf-8 scratch path");
    let dirty = unshare_check_setup_inspected(root_arg, rw_arg, planted_arg, Path::new(""));
    let stderr = String::from_utf8_lossy(&dirty.stderr);
    assert_eq!(
        dirty.status.code(),
        Some(rivect_sandbox_helper::EXIT_SANDBOX_INIT),
        "stderr {stderr:?}"
    );
    assert!(
        stderr.contains("empty"),
        "the refusal names the non-empty rw: {stderr:?}"
    );
    assert_namespace_refused_cleanly(&dirty, "a refused dirty rw");
    let planted_read = std::fs::read(&planted).expect("the planted content survives");
    assert_eq!(
        planted_read, b"x",
        "a refused setup must not hide the planted content"
    );
    assert_eq!(
        mount_identity(&rw),
        identity_before,
        "a refused dirty rw must leave its mount identity unchanged"
    );
    std::fs::remove_file(&planted).expect("clean rw");

    // A symlinked rw is refused and its target is never mounted over —
    // inspected inside the namespace like the dirty leg, with the
    // target carrying its own planted content.
    let real = root.join("rw-real");
    std::fs::create_dir(&real).expect("create the symlink target");
    let real_planted = real.join("planted");
    std::fs::write(&real_planted, b"x").expect("plant content in the symlink target");
    let real_arg = real.to_str().expect("utf-8 scratch path");
    let real_planted_arg = real_planted.to_str().expect("utf-8 scratch path");
    let real_identity = mount_identity(&real);
    std::fs::remove_dir(&rw).expect("remove rw");
    std::os::unix::fs::symlink(&real, &rw).expect("plant the rw symlink");
    let linked = unshare_check_setup_inspected(root_arg, real_arg, real_planted_arg, Path::new(""));
    assert_eq!(
        linked.status.code(),
        Some(rivect_sandbox_helper::EXIT_SANDBOX_INIT),
        "the symlinked rw is refused typed: stderr {:?}",
        String::from_utf8_lossy(&linked.stderr)
    );
    assert_namespace_refused_cleanly(&linked, "a refused symlink rw");
    assert_eq!(
        mount_identity(&real),
        real_identity,
        "a refused symlink rw must not mount its target"
    );
    std::fs::remove_file(&rw).expect("remove the symlink");
    std::fs::create_dir(&rw).expect("restore rw");
    drop(std::fs::remove_dir(&real));

    // The positive leg: bounded tmpfs, then a multi-file fill to ENOSPC —
    // every file below the per-file FSIZE cap, the total pinned to the
    // 512 MiB quota the kernel itself reports. The helper's exit-0
    // carries its own post-drop self-check (CapEff zeroed, NoNewPrivs
    // set); the continuing-process handoff is proven by the drop leg
    // below.
    let dd_err = root.join("dd.err");
    let dd_err_arg = dd_err.to_str().expect("utf-8 scratch path");
    // Every path crosses as a quoted positional ("$1".."$3"), never
    // interpolated shell text: an unquoted path with a space splits into
    // two argv elements and turns typed refusals into protocol errors.
    // Every measurement command's own failure fails the script through
    // its checked assignment: the shell's final status otherwise belongs
    // to grep alone, so a stat that prints a parseable value but exits
    // nonzero would be accepted as a measurement (probe executed). The
    // dd ENOSPC failure is the one expected failure — it ends the fill
    // loop, and the trailing grep proves it was ENOSPC.
    let script = format!(
        "\"{HELPER}\" check-setup \"$1\" || exit 90\n\
         fstype=$(stat -f -c %T \"$2\") || exit 91\n\
         printf '%s\\n' \"$fstype\"\n\
         mounts=$(cat /proc/mounts) || exit 92\n\
         printf '%s\\n' \"$mounts\"\n\
         echo CAPACITY\n\
         capacity=$(df -B1 \"$2\") || exit 93\n\
         printf '%s\\n' \"$capacity\"\n\
         block=$(stat -f -c %s \"$2\") || exit 94\n\
         printf '%s\\n' \"$block\"\n\
         : > \"$3\" || exit 95\n\
         n=0\n\
         while dd if=/dev/zero of=\"$2/f$n\" bs=1M count=64 2>>\"$3\"; do n=$((n+1)); done\n\
         echo files=$n\n\
         bytes=0\n\
         for f in \"$2\"/f*; do size=$(stat -c %s \"$f\") || exit 96; bytes=$((bytes + size)); done\n\
         echo bytes=$bytes\n\
         grep -q \"No space left on device\" \"$3\"\n"
    );
    let mounted = test_child("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--pid",
            "--net",
            "--fork",
        ])
        .args(["/bin/sh", "-c", &script])
        .arg("sh")
        .arg(root_arg)
        .arg(rw_arg)
        .arg(dd_err_arg)
        .output()
        .expect("run the namespaced mount and fill");
    let stdout = String::from_utf8_lossy(&mounted.stdout);
    assert!(
        mounted.status.success(),
        "namespaced check-setup + fill: {:?} stdout {stdout:?} stderr {:?}",
        mounted.status,
        String::from_utf8_lossy(&mounted.stderr)
    );
    assert!(
        stdout.lines().any(|line| line.trim() == "tmpfs"),
        "rw must be a tmpfs inside the namespace: {stdout:?}"
    );
    // The mount options come from the kernel's own /proc/mounts view
    // inside the namespace, not from what check-setup asked for. The
    // row's mount point is matched escape-decoded: a space-containing
    // root appears in the table as `\040`, so a literal contains() would
    // miss the row and the parser would latch onto the wrong one.
    let mount_entry = stdout
        .lines()
        .find(|line| {
            line.starts_with("tmpfs ") && mount_point_decoded(line).as_deref() == Some(rw_arg)
        })
        .expect("the tmpfs mount entry appears in /proc/mounts");
    assert!(
        mount_entry.contains("nosuid"),
        "the tmpfs must mount nosuid: {mount_entry}"
    );
    assert!(
        mount_entry.contains("nodev"),
        "the tmpfs must mount nodev: {mount_entry}"
    );
    let files = stdout
        .lines()
        .find_map(|line| line.strip_prefix("files="))
        .expect("the fill reports its file count");
    let files: u32 = files.parse().expect("files is decimal");
    eprintln!("namespaced fill: {files} files of at most 64 MiB before ENOSPC");
    // The quota oracle is the kernel's own capacity report — df's total
    // column (f_blocks × f_bsize) plus statfs's fundamental block size —
    // pinned to exactly 512 MiB within one block of page rounding: the
    // old bytes-written window let an executed 448 MiB quota pass.
    let lines: Vec<&str> = stdout.lines().map(str::trim).collect();
    let capacity_at = lines
        .iter()
        .position(|line| *line == "CAPACITY")
        .expect("the script reports the tmpfs capacity");
    let capacity: u64 = lines
        .iter()
        .skip(capacity_at + 1)
        // df prints a header line first; the data row is the next line
        // whose second field (the 1-byte-block total) parses.
        .find_map(|line| {
            line.split_whitespace()
                .nth(1)
                .and_then(|total| total.parse().ok())
        })
        .expect("df reports the 1-byte-block total");
    let block: u64 = lines
        .iter()
        .skip(capacity_at + 1)
        // `stat -f -c %s` answers a single decimal on its own line.
        .find_map(|line| line.parse::<u64>().ok())
        .expect("stat reports the fundamental block size");
    eprintln!("namespaced tmpfs capacity: {capacity} bytes, block size {block}");
    assert!(
        capacity.abs_diff(512 * MIB) <= block,
        "the kernel-reported quota must be exactly 512 MiB within one block: {capacity} bytes (block {block})"
    );
    let observed = lines
        .iter()
        .find_map(|line| line.strip_prefix("bytes="))
        .expect("the fill reports its observed byte total");
    let observed: u64 = observed.parse().expect("bytes is decimal");
    eprintln!("namespaced fill: {observed} bytes written before ENOSPC");
    assert!(
        observed <= capacity + block,
        "the fill cannot write past the reported capacity: {observed} > {capacity}+{block}"
    );
    assert!(
        observed + 64 * MIB > capacity,
        "ENOSPC must come from the 512 MiB quota, not an earlier cap: wrote {observed} of {capacity}"
    );
    assert!(
        (4..=8).contains(&files),
        "the 512 MiB quota must stop several sub-limit files: {files}"
    );
    // dd's own stderr carries the ENOSPC diagnosis; the script's final
    // grep only proves the message, the file read here shows it.
    let dd_stderr = std::fs::read_to_string(&dd_err).expect("read the captured dd stderr");
    assert!(
        dd_stderr.contains("No space left on device"),
        "the fill must end in ENOSPC, dd stderr {dd_stderr:?}"
    );

    // The full-chain privilege handoff (tasks.md: unshare → check-setup →
    // setpriv/landlock/seccomp → untrusted code). The helper's own
    // post-drop self-check vouches only for the helper PROCESS; the
    // CONTINUING process — the one that would exec untrusted code — is
    // what must land without capabilities and with no_new_privs. The
    // first check-setup is the positive pre-drop mount control (a real
    // tmpfs mount succeeded moments before). The continuing process is a
    // RE-EXEC of this test binary: after setpriv drops the namespace
    // privileges it runs the DROPPED_MOUNT_CHILD branch above, reading
    // its OWN /proc/self/status and invoking mount(2) DIRECTLY via the
    // raw syscall from that same process — no external `mount` utility
    // (whose exit 32 covers non-permission failures), no other process,
    // no helper re-run standing in as the negative (the helper has its
    // own precheck that could refuse for reasons other than privilege).
    // The branch prints a structured verdict this parent asserts below.
    let drop_script = format!(
        "\"{HELPER}\" check-setup \"$1\" || exit 91\n\
         exec /usr/bin/setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
         --no-new-privs \"$2\" --exact \
         check_setup_mounts_bounded_tmpfs_and_refuses_missing_namespace \
         --nocapture --test-threads=1\n"
    );
    let dropped = test_child("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--pid",
            "--net",
            "--fork",
        ])
        .args(["/bin/sh", "-c", &drop_script])
        .arg("sh")
        .arg(root_arg)
        .arg(std::env::current_exe().expect("test binary path"))
        .env(DROPPED_MOUNT_CHILD_MARKER, "1")
        .env(DROPPED_MOUNT_ROOT, root_arg)
        .output()
        .expect("run the full-chain privilege handoff");
    let drop_stdout = String::from_utf8_lossy(&dropped.stdout);
    let drop_stderr = String::from_utf8_lossy(&dropped.stderr);
    assert!(
        dropped.status.success(),
        "full-chain handoff: {:?} stdout {drop_stdout:?} stderr {drop_stderr:?}",
        dropped.status
    );
    // All three capability sets come from the CONTINUING process's own
    // /proc view; each must be zero — an unset set is exactly what
    // CapEff-only assertions missed.
    let cap_eff = child_report(&drop_stdout, "cap_eff=");
    let cap_prm = child_report(&drop_stdout, "cap_prm=");
    let cap_inh = child_report(&drop_stdout, "cap_inh=");
    for (name, cap) in [
        ("CapEff", cap_eff),
        ("CapPrm", cap_prm),
        ("CapInh", cap_inh),
    ] {
        let value = u64::from_str_radix(cap.trim(), 16)
            .unwrap_or_else(|error| panic!("{name} {cap:?} is not hex: {error}"));
        assert_eq!(
            value, 0,
            "the continuing process must hold no {name} capability at all — CAP_SYS_ADMIN is bit 21 — got {name} {cap}"
        );
    }
    let no_new_privs = child_report(&drop_stdout, "no_new_privs=");
    assert_eq!(
        no_new_privs, "1",
        "the continuing process must carry NoNewPrivs=1, got {no_new_privs:?}"
    );
    // The mount negative is a raw mount(2) from the continuing process
    // itself: the kernel must answer EPERM to THIS process's credential.
    let mount_errno = child_report(&drop_stdout, "mount_errno=");
    assert_eq!(
        mount_errno, "Some(1)",
        "an actual mount(2) from the continuing process must be refused EPERM by the kernel"
    );
}

/// The helper's own mount(2) failure branch (main.rs: "tmpfs mount
/// failed"): every other negative refuses PRE-syscall (initial user
/// namespace, dirty rw, symlinked rw). A fresh user namespace WITHOUT
/// `--mount` — the mount namespace stays the parent's, owned by the
/// initial user namespace — passes the helper's own validation (a
/// mapped-down uid map, an empty canonical rw) while mount(2) answers
/// EPERM, so the refusal the leg observes is the mount syscall itself.
/// `--map-current-user` maps a single uid (not the whole uid space
/// `--map-root-user` spans), which is what keeps the helper's
/// initial-namespace precheck honest here.
#[cfg(target_os = "linux")]
#[test]
fn check_setup_mount_failure_is_a_typed_refusal_without_the_mount_namespace() {
    let root = scratch("mount-refused");
    let rw = root.join("rw");
    std::fs::create_dir(&rw).expect("create the empty rw");
    let root_arg = root.to_str().expect("utf-8 scratch path");
    let marker = root.join("continuation");
    let marker_arg = marker.to_str().expect("utf-8 scratch path");
    let identity_before = mount_identity(&rw);
    let script = format!("\"{HELPER}\" check-setup \"$1\" && touch \"$2\"");
    let refused = test_child("unshare")
        .args(["--user", "--map-current-user", "--fork"])
        .args(["/bin/sh", "-c", &script])
        .arg("sh")
        .arg(root_arg)
        .arg(marker_arg)
        .output()
        .expect("run check-setup without a mount namespace");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert_eq!(
        refused.status.code(),
        Some(rivect_sandbox_helper::EXIT_SANDBOX_INIT),
        "the mount refusal is the typed init refusal: stderr {stderr:?}"
    );
    assert!(
        stderr.contains("tmpfs mount failed"),
        "the refusal names the mount failure itself: {stderr:?}"
    );
    assert!(
        stderr.contains("Operation not permitted"),
        "the kernel's EPERM prose reaches the diagnostics: {stderr:?}"
    );
    assert_eq!(
        mount_identity(&rw),
        identity_before,
        "the refused setup must leave the mount the rw lives on unchanged"
    );
    assert!(
        !marker.exists(),
        "no continuation may follow the typed mount refusal"
    );
}

/// Sum of `/proc/<pid>/task` entries for every process whose real uid is this
/// process's real uid. `RLIMIT_NPROC` counts tasks (threads included), while
/// the top-level `/proc` enumeration counts process leaders only; the NPROC
/// refusal must be compared against the unit the kernel actually checks.
#[cfg(target_os = "linux")]
fn uid_task_count() -> Result<u64, String> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(|error| error.to_string())?;
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| "the real uid is readable from /proc/self/status".to_string())?;
    let mut total = 0_u64;
    for entry in std::fs::read_dir("/proc").map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|text| text.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(process_status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            continue;
        };
        let process_uid = process_status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u32>().ok());
        if process_uid != Some(uid) {
            continue;
        }
        if let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) {
            total += tasks.count() as u64;
        }
    }
    Ok(total)
}

/// The Linux non-root NPROC leg (the root Docker proof): the check
/// profile's hard NPROC is the measured uid count plus the headroom, and
/// a fork loop past it is refused with EAGAIN — the kernel exempts root
/// from RLIMIT_NPROC, so only an unprivileged child can prove either.
/// `setpriv` is util-linux 2.41+, the same launcher the production
/// confined chain already requires.
#[cfg(target_os = "linux")]
#[test]
fn check_nproc_bounds_an_unprivileged_nobody_child() {
    if std::env::var_os(NONROOT_NPROC_CHILD_MARKER).is_some() {
        // Unreaped (zombie) children still hold their pid — NPROC counts
        // pids, not RSS — so dropping each Child handle without waiting
        // fills the uid's process count at near-zero memory cost.
        let mut spawned: u32 = 0;
        loop {
            // test_child, never a bare Command::new: the fork loop's
            // spawns are allowlisted clean too — a reviewer probe showed
            // ambient env (LD_DEBUG) propagating into fork children
            // through the bare constructor.
            match test_child("/bin/true").spawn() {
                Ok(_child) => spawned += 1,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    // EAGAIN alone names no source: bind the refusal to
                    // RLIMIT_NPROC by counting this uid's processes AT the
                    // refusal — the kernel checked exactly that count
                    // against the hard limit before saying no.
                    let at_refusal =
                        uid_task_count().expect("count this uid's tasks at the refusal");
                    println!("uid_count_at_refusal={at_refusal}");
                    println!("refused=eagain");
                    println!("spawned={spawned}");
                    return;
                }
                Err(error) => panic!("unexpected spawn failure inside the limit: {error}"),
            }
            assert!(
                spawned < 4096,
                "the hard NPROC never refused the fork loop after {spawned} spawns"
            );
        }
    }
    // Serialize against the 1100-process enumeration leg and the 250-sleeper
    // churn leg: their spawn/kill windows move this uid's count past the slack.
    let _serialized = UID_COUNT_SENSITIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Fail closed before the fork loop: a cgroup pids ceiling near the
    // hard NPROC refuses forks through the cgroup, and that EAGAIN would
    // impersonate the rlimit leg. Only an unbounded effective ceiling, or
    // one the loop cannot reach, is discriminating; a finite-close,
    // unparseable, or absent cgroup answer at any level of the
    // hierarchy fails here instead of passing silently.
    let pre_launch = uid_process_count().expect("count this uid before the launch");
    let estimated = pre_launch + PROFILE_NPROC_HEADROOM;
    match effective_cgroup_pids_ceiling(estimated) {
        Ok(None) => eprintln!("cgroup ceiling unbounded -- discriminating"),
        Ok(Some(ceiling)) => eprintln!(
            "cgroup pids.max {ceiling} clears pids.current + NPROC {estimated} + slack {NPROC_CGROUP_SLACK} at every bounded level"
        ),
        Err(why) => panic!("environment cannot discriminate rlimit vs cgroup: {why}"),
    }
    let exe = std::env::current_exe().expect("test binary path");
    let script = "ulimit -H -u; exec \"$0\" --exact check_nproc_bounds_an_unprivileged_nobody_child --nocapture --test-threads=1";
    let mut command = test_child(HELPER);
    command.args(["launch", RESOURCE_PROFILE_FLAG, "check", "--"]);
    // SAFETY: geteuid takes no arguments and only reports this caller.
    if unsafe { geteuid() } == 0 {
        command.args([
            "/usr/bin/setpriv",
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
        ]);
    }
    let output = command
        .args(["/bin/bash", "-c", script])
        .arg(&exe)
        .env(NONROOT_NPROC_CHILD_MARKER, "1")
        .output()
        .expect("run the nobody check-profile child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "nobody check-profile child: {:?} stdout {stdout:?} stderr {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let nproc: u64 = stdout
        .lines()
        .next()
        .and_then(|line| line.trim().parse().ok())
        .expect("the confined shell prints its hard NPROC");
    // The pre-launch sample is the parent's only count taken before helper
    // startup; a post-run count would include the child's unreaped fork-loop
    // zombies. The slack covers only same-uid churn in between.
    eprintln!("nobody child hard NPROC {nproc}, pre-launch uid count {pre_launch}");
    // The measuring helper is itself a live process of the measured real
    // uid, so a measured limit is at least the headroom plus one.
    assert!(
        nproc > PROFILE_NPROC_HEADROOM,
        "hard NPROC must exceed the headroom alone: {nproc} vs {PROFILE_NPROC_HEADROOM}"
    );
    assert!(
        nproc.abs_diff(pre_launch + PROFILE_NPROC_HEADROOM) <= NPROC_CHURN_SLACK,
        "hard NPROC must be the pre-launch uid count plus the headroom: {nproc} vs {pre_launch}+{PROFILE_NPROC_HEADROOM}"
    );
    assert_eq!(
        child_report(&stdout, "refused="),
        "eagain",
        "the over-limit spawn must be refused with EAGAIN"
    );
    let spawned: u32 = child_report(&stdout, "spawned=")
        .parse()
        .expect("the child reports how many spawns fit");
    assert!(
        spawned > 0,
        "the fork loop must have spawned before the refusal"
    );
    // The refusal must sit AT the hard NPROC — the count the kernel
    // checked — so an EAGAIN with headroom left, or one fired by another
    // ceiling, cannot impersonate the rlimit leg. The child reports the
    // kernel's own unit, tasks, not process leaders, so the count already
    // carries the suite's own threads; the slack now covers only the
    // mid-exit race, where a task can hold its kernel counter slot after
    // its /proc entry is gone (observed one below on every refusal), plus
    // same-uid churn moving it the other way by the same few.
    let at_refusal: u64 = child_report(&stdout, "uid_count_at_refusal=")
        .parse()
        .expect("the child reports its uid count at the refusal");
    eprintln!("nobody uid count at refusal {at_refusal}, hard NPROC {nproc}");
    assert!(
        at_refusal + NPROC_REFUSAL_SLACK >= nproc,
        "the uid count at the refusal must have reached the hard NPROC within the accounting slack: {at_refusal}+{NPROC_REFUSAL_SLACK} < {nproc}"
    );
    assert!(
        at_refusal <= nproc + NPROC_REFUSAL_SLACK,
        "the uid count at the refusal must sit at the hard NPROC, not far past it: {at_refusal} > {nproc}+{NPROC_REFUSAL_SLACK}"
    );
}

/// This test process's own cgroup v2 directory, resolved from
/// `/proc/self/cgroup`'s `0::` entry under the mounted hierarchy root.
#[cfg(target_os = "linux")]
fn own_cgroup_dir() -> Result<PathBuf, String> {
    let cgroups = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| format!("read /proc/self/cgroup: {error}"))?;
    let rel = cgroups
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| "no cgroup v2 `0::` entry in /proc/self/cgroup".to_string())?
        .trim();
    Ok(Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

/// The effective cgroup v2 pids ceiling, gated at every level: each
/// ancestor from this process's own cgroup up through the visible
/// hierarchy root must answer, and each finite `pids.max` must clear
/// that level's own `pids.current` plus `estimated` and the slack — an
/// ancestor crowded with sibling tasks can starve the fork loop while
/// the leaf alone still looks roomy. `Ok(None)` when every level reads
/// `max`; an unreadable or unparseable answer at any level fails closed
/// as `Err`.
#[cfg(target_os = "linux")]
fn effective_cgroup_pids_ceiling(estimated: u64) -> Result<Option<u64>, String> {
    let root = Path::new("/sys/fs/cgroup");
    let mut dir = own_cgroup_dir()?;
    let mut effective = None;
    loop {
        let leaf = dir == root;
        match std::fs::read_to_string(dir.join("pids.max")) {
            Ok(text) => match text.trim() {
                "max" => {}
                digits => {
                    let ceiling = digits.parse::<u64>().map_err(|error| {
                        format!(
                            "unparseable pids.max {digits:?} at {}: {error}",
                            dir.display()
                        )
                    })?;
                    let current_path = dir.join("pids.current");
                    let current = std::fs::read_to_string(&current_path)
                        .map_err(|error| format!("read {}: {error}", current_path.display()))?
                        .trim()
                        .parse::<u64>()
                        .map_err(|error| {
                            format!(
                                "unparseable pids.current at {}: {error}",
                                current_path.display()
                            )
                        })?;
                    if ceiling <= current + estimated + NPROC_CGROUP_SLACK {
                        return Err(format!(
                            "pids.max {ceiling} at {} within pids.current {current} + NPROC {estimated} + slack {NPROC_CGROUP_SLACK}",
                            dir.display()
                        ));
                    }
                    effective =
                        Some(effective.map_or(ceiling, |smallest: u64| smallest.min(ceiling)));
                }
            },
            Err(error)
                if leaf
                    && error.kind() == std::io::ErrorKind::NotFound
                    && root.join("cgroup.controllers").is_file()
                    && !root.join("cgroup.type").try_exists().map_err(|source| {
                        format!("read cgroup.type at {}: {source}", root.display())
                    })? => {}
            Err(error) => return Err(format!("read {}: {error}", dir.join("pids.max").display())),
        }
        if leaf {
            return Ok(effective);
        }
        dir = dir
            .parent()
            .expect("a cgroup path above the root")
            .to_path_buf();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn owned_launch_pre_fence_socketpair_tuple_is_exact() {
    use rivect_sandbox_helper::{SeccompStage, compile_seccomp};
    let program = compile_seccomp(SeccompStage::PreInjection).expect("compile the export fence");
    let (arch, socketpair) = match std::env::consts::ARCH {
        "x86_64" => (0xc000003e_u32, 53_u32),
        "aarch64" => (0xc00000b7_u32, 199_u32),
        _ => panic!("the native fence needs an admitted architecture"),
    };
    let verdict = |arch: u32, number: u32, args: [u64; 3]| {
        let mut data = [0_u8; 64];
        data[..4].copy_from_slice(&number.to_le_bytes());
        data[4..8].copy_from_slice(&arch.to_le_bytes());
        for (index, argument) in args.iter().enumerate() {
            data[16 + index * 8..24 + index * 8].copy_from_slice(&argument.to_le_bytes());
        }
        let mut accumulator = 0_u32;
        let mut pc = 0_usize;
        for _ in 0..256 {
            let instruction = &program[pc * 8..pc * 8 + 8];
            let code = u16::from_le_bytes(instruction[..2].try_into().expect("opcode"));
            let k = u32::from_le_bytes(instruction[4..].try_into().expect("operand"));
            match code {
                0x20 => {
                    accumulator = u32::from_le_bytes(
                        data[k as usize..k as usize + 4].try_into().expect("word"),
                    )
                }
                0x54 => accumulator &= k,
                0x15 | 0x45 => {
                    let yes = if code == 0x15 {
                        accumulator == k
                    } else {
                        accumulator & k != 0
                    };
                    pc += usize::from(instruction[if yes { 2 } else { 3 }]);
                }
                0x06 => return k,
                _ => panic!("unexpected classic BPF opcode: {code}"),
            }
            pc += 1;
        }
        panic!("the bounded filter must return a verdict");
    };
    assert_eq!(verdict(arch, socketpair, [1, 524293, 0]), 0x7fff0000);
    for arguments in [
        [1, 524289, 0],
        [1, 524290, 0],
        [1, 5, 0],
        [1, 526341, 0],
        [2, 524293, 0],
        [1, 524293, 1],
        [0x100000001, 524293, 0],
        [1, 0x100080005, 0],
        [1, 524293, 0x100000000],
    ] {
        assert_eq!(
            verdict(arch, socketpair, arguments),
            0x00050001,
            "the early fence must reject the full-width tuple {arguments:?}"
        );
    }
    assert_eq!(verdict(arch ^ 1, socketpair, [1, 524293, 0]), 0x00050001);
    if arch == 0xc000003e {
        for number in [
            0x40000027, 0x40000029, 0x40000035, 0x40000206, 0x40000207, 0x40000209, 0x40000219,
            0x4000021a, 0x4000021b, 0x4000021c, 0xffffffff,
        ] {
            assert_eq!(
                verdict(arch, number, [1, 524293, 0]),
                0x00050001,
                "every raw x32 number must be refused before masking"
            );
        }
    }
    let other_tuples = [[1, 524289, 0], [1, 524290, 0], [1, 5, 0], [1, 526341, 0]];
    for arguments in other_tuples {
        drop(owned_test_socketpair(arguments).expect("unfiltered native tuple must be supported"));
    }
    for arguments in [
        [0x100000001, 524293, 0],
        [1, 0x100080005, 0],
        [1, 524293, 0x100000000],
    ] {
        drop(
            owned_test_socketpair(arguments)
                .expect("the kernel truncates native integer arguments"),
        );
    }
    #[cfg(target_arch = "x86_64")]
    {
        unsafe extern "C" {
            fn syscall(number: std::os::raw::c_long, ...) -> std::os::raw::c_long;
        }
        assert_eq!(
            // SAFETY: getpid has no pointer operands; this checks current x32 availability.
            unsafe { syscall(0x40000027) },
            i64::from(std::process::id())
        );
    }
    install_owned_test_filter(SeccompStage::PreInjection);
    let pair = owned_test_socketpair([1, 524293, 0]).expect("exact native anonymous tuple");
    {
        use std::os::fd::AsRawFd as _;
        unsafe extern "C" {
            fn fcntl(fd: i32, command: i32, ...) -> i32;
        }
        for endpoint in &pair {
            // SAFETY: F_GETFD observes the held endpoint without changing its flags.
            assert_eq!(unsafe { fcntl(endpoint.as_raw_fd(), 1) }, 1);
        }
    }
    let [left, right] = pair;
    let mut left = std::fs::File::from(left);
    let mut right = std::fs::File::from(right);
    left.write_all(b"native tuple")
        .expect("bounded native pair write");
    let mut received = [0_u8; 12];
    right
        .read_exact(&mut received)
        .expect("bounded native pair read");
    assert_eq!(&received, b"native tuple");
    for arguments in other_tuples.into_iter().chain([
        [0x100000001, 524293, 0],
        [1, 0x100080005, 0],
        [1, 524293, 0x100000000],
    ]) {
        assert_eq!(
            owned_test_socketpair(arguments)
                .expect_err("filtered tuple must refuse before fd creation")
                .raw_os_error(),
            Some(1)
        );
    }
    #[cfg(target_arch = "x86_64")]
    {
        unsafe extern "C" {
            fn syscall(number: std::os::raw::c_long, ...) -> std::os::raw::c_long;
        }
        // SAFETY: the raw x32 getpid probe has no pointer operands.
        assert_eq!(unsafe { syscall(0x40000027) }, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(1));
    }
}

#[cfg(target_os = "linux")]
fn install_owned_test_filter(stage: rivect_sandbox_helper::SeccompStage) {
    #[repr(C)]
    struct Filter {
        code: u16,
        jt: u8,
        jf: u8,
        value: u32,
    }
    #[repr(C)]
    struct Program {
        length: u16,
        filter: *const Filter,
    }
    unsafe extern "C" {
        fn prctl(option: i32, ...) -> i32;
    }
    let bytes = rivect_sandbox_helper::compile_seccomp(stage).expect("canonical filter");
    let filters: Vec<_> = bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|word| Filter {
            code: u16::from_le_bytes([word[0], word[1]]),
            jt: word[2],
            jf: word[3],
            value: u32::from_le_bytes([word[4], word[5], word[6], word[7]]),
        })
        .collect();
    let program = Program {
        length: u16::try_from(filters.len()).expect("bounded filter"),
        filter: filters.as_ptr(),
    };
    // SAFETY: these fixed prctl options only restrict this disposable test thread;
    // the aligned immutable instructions live throughout the kernel copy.
    assert_eq!(unsafe { prctl(38, 1, 0, 0, 0) }, 0);
    // SAFETY: the kernel copies the live aligned program and its immutable filters.
    assert_eq!(unsafe { prctl(22, 2, &program, 0, 0) }, 0);
}

#[cfg(target_os = "linux")]
fn owned_test_socketpair(arguments: [u64; 3]) -> std::io::Result<[std::os::fd::OwnedFd; 2]> {
    use std::os::fd::FromRawFd as _;
    unsafe extern "C" {
        fn syscall(number: std::os::raw::c_long, ...) -> std::os::raw::c_long;
    }
    #[cfg(target_arch = "x86_64")]
    const NUMBER: std::os::raw::c_long = 53;
    #[cfg(target_arch = "aarch64")]
    const NUMBER: std::os::raw::c_long = 199;
    let mut pair = [-1_i32; 2];
    // SAFETY: the syscall receives two writable native fd slots; successful
    // descriptors are adopted once, and failure never adopts an output slot.
    let result = unsafe {
        syscall(
            NUMBER,
            arguments[0],
            arguments[1],
            arguments[2],
            pair.as_mut_ptr(),
        )
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the successful socketpair returned two distinct fresh descriptors.
    Ok(unsafe {
        [
            std::os::fd::OwnedFd::from_raw_fd(pair[0]),
            std::os::fd::OwnedFd::from_raw_fd(pair[1]),
        ]
    })
}

#[cfg(target_os = "linux")]
#[test]
fn owned_launch_pre_fence_preserves_fork_spawn_and_errno() {
    for stage in [
        rivect_sandbox_helper::SeccompStage::PreInjection,
        rivect_sandbox_helper::SeccompStage::Final,
    ] {
        install_owned_test_filter(stage);
        for forced in [false, true] {
            let mut command = test_child("sh");
            command
                .env_clear()
                .env("PATH", "/bin:/usr/bin")
                .args(["-c", "exit 23"]);
            if forced {
                // SAFETY: the test callback has no shared state, allocation, or effects.
                unsafe {
                    command.pre_exec(|| Ok(()));
                }
            }
            let mut child = command
                .spawn()
                .expect("filtered std spawn must execute the payload");
            assert_eq!(child.wait().expect("reap finite payload").code(), Some(23));
            let mut missing = test_child("/no/such/owned-native-spawn-control");
            if forced {
                // SAFETY: the empty child callback only forces std's fork path.
                unsafe {
                    missing.pre_exec(|| Ok(()));
                }
            }
            assert_eq!(
                missing
                    .spawn()
                    .expect_err("missing exec preserves errno")
                    .raw_os_error(),
                Some(2)
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn owned_launch_export_fence_blocks_scm_rights() {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::net::UnixDatagram;

    #[repr(C)]
    struct IoVector {
        base: *mut u8,
        length: usize,
    }
    #[repr(C)]
    struct Message {
        name: *mut u8,
        name_length: u32,
        vectors: *mut IoVector,
        vector_count: usize,
        control: *mut u8,
        control_length: usize,
        flags: i32,
    }
    #[repr(C)]
    struct MultiMessage {
        message: Message,
        length: u32,
    }
    unsafe extern "C" {
        fn syscall(number: std::os::raw::c_long, ...) -> std::os::raw::c_long;
        fn recvmsg(fd: i32, message: *mut Message, flags: i32) -> isize;
        #[cfg(target_arch = "x86_64")]
        fn mmap(
            address: *mut u8,
            length: usize,
            protection: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut u8;
        #[cfg(target_arch = "x86_64")]
        fn munmap(address: *mut u8, length: usize) -> i32;
    }

    fn send(socket: i32, artifact: i32, multiple: bool, compat: bool) -> std::io::Result<()> {
        #[cfg(target_arch = "x86_64")]
        if compat {
            // The installed kernel's compat_msghdr/cmsghdr/iovec use u32
            // pointers and lengths. Every pointed-to byte lives below 2 GiB.
            // SAFETY: anonymous MAP_32BIT storage is privately owned and writable.
            let allocation = unsafe { mmap(std::ptr::null_mut(), 4096, 3, 0x62, -1, 0) };
            assert_ne!(allocation as usize, usize::MAX);
            struct LowBuffer(*mut u8);
            impl Drop for LowBuffer {
                fn drop(&mut self) {
                    // SAFETY: this is the original live mmap allocation, retired once.
                    assert_eq!(unsafe { munmap(self.0, 4096) }, 0);
                }
            }
            let allocation = LowBuffer(allocation);
            let base = u32::try_from(allocation.0 as usize).expect("low compat allocation");
            let fields = [0_u32, 0, base + 64, 1, base + 80, 16, 0, 0];
            // SAFETY: all writes are in the fresh writable 4096-byte mapping;
            // offsets are aligned for u32 and each ABI pointer targets that mapping.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    fields.as_ptr().cast::<u8>(),
                    allocation.0,
                    size_of_val(&fields),
                );
                allocation.0.add(64).cast::<u32>().write(base + 128);
                allocation.0.add(68).cast::<u32>().write(1);
                allocation.0.add(80).cast::<u32>().write(16);
                allocation.0.add(84).cast::<u32>().write(1);
                allocation.0.add(88).cast::<u32>().write(1);
                allocation.0.add(92).cast::<i32>().write(artifact);
                allocation.0.add(128).write(b'x');
            }
            let number = if multiple { 0x4000021a } else { 0x40000206 };
            // SAFETY: the compat header, iovec, payload and cmsg are ABI-correct,
            // live low-address buffers; the descriptors remain borrowed.
            let result = unsafe {
                if multiple {
                    syscall(number, socket, allocation.0, 1_u32, 0_u32)
                } else {
                    syscall(number, socket, allocation.0, 0_u32)
                }
            };
            if result == -1 {
                return Err(std::io::Error::last_os_error());
            }
            assert_eq!(result, 1);
            return Ok(());
        }
        assert!(
            !compat,
            "compat controls require the native x86_64 kernel ABI"
        );
        let mut byte = b'x';
        let mut vector = IoVector {
            base: &raw mut byte,
            length: 1,
        };
        let mut control = [0_usize; 3];
        control[0] = 20;
        // SAFETY: the three-word buffer has the native cmsghdr alignment and
        // room for the 16-byte header plus one borrowed descriptor.
        unsafe {
            let bytes = control.as_mut_ptr().cast::<u8>();
            bytes.add(8).cast::<i32>().write(1);
            bytes.add(12).cast::<i32>().write(1);
            bytes.add(16).cast::<i32>().write(artifact);
        }
        let mut message = MultiMessage {
            message: Message {
                name: std::ptr::null_mut(),
                name_length: 0,
                vectors: &raw mut vector,
                vector_count: 1,
                control: control.as_mut_ptr().cast(),
                control_length: 24,
                flags: 0,
            },
            length: 0,
        };
        #[cfg(target_arch = "x86_64")]
        let number = if multiple { 307 } else { 46 };
        #[cfg(target_arch = "aarch64")]
        let number = if multiple { 269 } else { 211 };
        // SAFETY: the native message and its pointed-to buffers remain alive
        // through this synchronous syscall; descriptors are only borrowed.
        let result = unsafe {
            if multiple {
                syscall(number, socket, &raw mut message, 1_u32, 0_u32)
            } else {
                syscall(number, socket, &raw mut message.message, 0_u32)
            }
        };
        if result == -1 {
            return Err(std::io::Error::last_os_error());
        }
        assert_eq!(result, 1);
        Ok(())
    }

    fn receive(socket: i32) -> std::io::Result<OwnedFd> {
        let mut byte = 0_u8;
        let mut vector = IoVector {
            base: &raw mut byte,
            length: 1,
        };
        let mut control = [0_usize; 3];
        let mut message = Message {
            name: std::ptr::null_mut(),
            name_length: 0,
            vectors: &raw mut vector,
            vector_count: 1,
            control: control.as_mut_ptr().cast(),
            control_length: 24,
            flags: 0,
        };
        // SAFETY: the complete writable native message buffers are live; the
        // nonblocking call runs only after the sole sender has joined.
        let result = unsafe { recvmsg(socket, &raw mut message, 0x40000040) };
        if result == -1 {
            return Err(std::io::Error::last_os_error());
        }
        assert_eq!(result, 1);
        assert_eq!(byte, b'x');
        assert_eq!(message.flags & 8, 0, "ancillary data cannot be truncated");
        assert_eq!(message.control_length, 24);
        assert_eq!(control[0], 20);
        // SAFETY: the successful untruncated message supplies exactly one
        // SCM_RIGHTS descriptor in the validated native ancillary buffer.
        let descriptor = unsafe {
            let bytes = control.as_ptr().cast::<u8>();
            assert_eq!(bytes.add(8).cast::<i32>().read(), 1);
            assert_eq!(bytes.add(12).cast::<i32>().read(), 1);
            bytes.add(16).cast::<i32>().read()
        };
        assert!(descriptor >= 0);
        // SAFETY: the kernel transferred ownership of this fresh received fd.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }

    let fixture = tempfile::tempdir().expect("own the export fixture");
    let artifact_path = fixture.path().join("artifact");
    std::fs::write(&artifact_path, b"independent owned artifact").expect("write export artifact");
    let expected = std::fs::metadata(&artifact_path).expect("freeze artifact identity");
    let abis: &[bool] = if cfg!(target_arch = "x86_64") {
        &[false, true]
    } else {
        &[false]
    };
    for &compat in abis {
        for multiple in [false, true] {
            for anonymous in [false, true] {
                for filtered in [false, true] {
                    let pathname = fixture.path().join(format!(
                        "receiver-{compat}-{multiple}-{anonymous}-{filtered}"
                    ));
                    let (sender, receiver): (OwnedFd, OwnedFd) = if anonymous {
                        let [sender, receiver] =
                            owned_test_socketpair([1, 524293, 0]).expect("exact anonymous control");
                        (sender, receiver)
                    } else {
                        let receiver = UnixDatagram::bind(&pathname).expect("park host receiver");
                        let sender = UnixDatagram::unbound().expect("own export sender");
                        sender
                            .connect(&pathname)
                            .expect("preconnect host export endpoint");
                        (sender.into(), receiver.into())
                    };
                    let sender_lifetime = sender
                        .try_clone()
                        .expect("hold the export peer through drain");
                    let artifact = std::fs::File::open(&artifact_path).expect("own artifact fd");
                    let (ready, parked) = std::sync::mpsc::sync_channel(1);
                    let (release, released) = std::sync::mpsc::sync_channel(1);
                    let sender = std::thread::spawn(move || {
                        ready.send(()).expect("publish prepared sender");
                        released
                            .recv_timeout(READY_TIMEOUT)
                            .expect("bounded export start barrier");
                        if filtered {
                            install_owned_test_filter(
                                rivect_sandbox_helper::SeccompStage::PreInjection,
                            );
                        }
                        send(sender.as_raw_fd(), artifact.as_raw_fd(), multiple, compat)
                    });
                    parked
                        .recv_timeout(READY_TIMEOUT)
                        .expect("sender is parked");
                    release.send(()).expect("receiver is ready before export");
                    let result = sender.join().expect("join the sole finite export sender");
                    let received = receive(receiver.as_raw_fd());
                    drop(sender_lifetime);
                    if let Ok(received) = &received {
                        let identity = std::fs::File::from(
                            received.try_clone().expect("borrow received identity"),
                        )
                        .metadata()
                        .expect("observe native transferred identity");
                        assert_eq!(
                            (identity.dev(), identity.ino()),
                            (expected.dev(), expected.ino())
                        );
                        use std::os::unix::fs::FileExt as _;
                        let file = std::fs::File::from(
                            received.try_clone().expect("borrow received bytes"),
                        );
                        let mut bytes = [0_u8; 26];
                        assert_eq!(
                            file.read_at(&mut bytes, 0)
                                .expect("read native transferred bytes"),
                            26
                        );
                        assert_eq!(&bytes, b"independent owned artifact");
                        println!(
                            "owned export received actual artifact dev={} ino={} bytes_match=true compat={compat} multiple={multiple} filtered={filtered}",
                            identity.dev(),
                            identity.ino()
                        );
                    }
                    if filtered {
                        assert_eq!(
                            result
                                .expect_err("the early fence must refuse export")
                                .raw_os_error(),
                            Some(1)
                        );
                        assert_eq!(
                            received
                                .expect_err("no artifact fd may reach the host receiver")
                                .raw_os_error(),
                            Some(11)
                        );
                    } else {
                        result.expect("the ABI-correct unfiltered control must export");
                        let mut received = std::fs::File::from(
                            received.expect("the host receives the actual artifact fd"),
                        );
                        let identity = received.metadata().expect("received artifact identity");
                        assert_eq!(
                            (identity.dev(), identity.ino()),
                            (expected.dev(), expected.ino())
                        );
                        let mut bytes = Vec::new();
                        received
                            .read_to_end(&mut bytes)
                            .expect("read transferred artifact");
                        assert_eq!(bytes, b"independent owned artifact");
                    }
                    println!(
                        "owned export compat={compat} multiple={multiple} anonymous={anonymous} filtered={filtered} sender_reaped=true receiver_drained=true"
                    );
                }
            }
        }
    }
}
