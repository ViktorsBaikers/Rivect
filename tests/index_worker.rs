//! The isolated index worker (DEC-028/030/031/033/038): untrusted parsing
//! and the whole build+answer run in a capped `rivect --index-worker`
//! child under the sandbox helper — typed per-seam failures, a clamped
//! deadline, cancellation that reaches the child, a bounded answer, the
//! parent's macOS footprint stop, the ignore env allowlist, and no
//! in-process fallback.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "test assertions fail loudly with the observed payload; evidence lines print under --nocapture (standards §14)"
)]

mod support;

use rivect::context::{
    ContextError, IgnorePolicy, IsolatedCause, IsolatedRun, Query, QueryKind, WORKER_ANSWER_MAX,
    WORKER_KILL_GRACE, query, query_isolated,
};
use rivect::contracts::ErrorCode;
use rivect::executor::{ExecutorError, INDEX_WORKER_FLAG, Unattested, WorkerError};
use rivect::index::{Completeness, PartialReason, QueryResult};
use rivect::lsp::{DocumentPin, MAX_INDEX_PARSE_TIME, MAX_SYMBOL_ROWS, SymbolOp};
use rivect_sandbox_helper::{INDEX_WORKER_MEMORY_BUDGET, MEMORY_BUDGET_FLAG, ReuseTokenError};
use serde_json::Value;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, UNIX_EPOCH};
use support::{
    TempTree, ast_corpus, ensure_helper, rivect_binary, search_corpus, search_query, symbol_corpus,
    symbol_query, tree_of,
};

const SIGABRT: i32 = 6;
const SIGKILL: i32 = 9;
const SIGSEGV: i32 = 11;
const SIGXCPU: i32 = 24;

/// The real helper, built beside the test harness.
fn helper() -> PathBuf {
    ensure_helper();
    rivect_sandbox_helper::helper_binary().expect("helper resolves beside the test harness")
}

/// The real `rivect` executable the worker mode re-runs.
fn worker() -> PathBuf {
    PathBuf::from(rivect_binary())
}

fn never() -> bool {
    false
}

/// One isolated run with the default answer cap and no cancellation.
fn isolated(
    request: &Query,
    program: &Path,
    helper: &Path,
    deadline: Option<Instant>,
) -> Result<QueryResult, ContextError> {
    query_isolated(
        request,
        &IsolatedRun {
            program,
            helper,
            deadline,
            cancel: &never,
            answer_cap: WORKER_ANSWER_MAX,
        },
    )
}

fn cause_of(outcome: Result<QueryResult, ContextError>) -> IsolatedCause {
    match outcome {
        Err(ContextError::IsolatedRun { cause, .. }) => cause,
        other => panic!("expected an isolated-run cause, got {other:?}"),
    }
}

/// An executable script at `dir/name`.
fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write shim");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod shim");
    path
}

/// A program run in place of the worker: it drains the request, then
/// runs `body`. Builtins and `exec` only — the helper's NPROC cap leaves
/// no room to fork on a busy host.
fn program_shim(dir: &Path, name: &str, body: &str) -> PathBuf {
    script(
        dir,
        name,
        &format!("#!/bin/sh\nwhile read -r line; do :; done\n{body}\n"),
    )
}

fn sh_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn quoted(path: &Path) -> String {
    sh_quote(&path.display().to_string())
}

/// Where a worker shim records its pid: `echo` writes it with its newline
/// in one write, so a pid is read only once it is whole.
fn recorded_pid(pid_file: &Path) -> Option<u32> {
    std::fs::read_to_string(pid_file)
        .ok()
        .filter(|text| text.ends_with('\n'))
        .and_then(|text| text.trim().parse().ok())
}

/// Clock ticks per second from the process auxiliary vector (`AT_CLKTCK`).
fn clock_ticks() -> u64 {
    let Ok(bytes) = std::fs::read("/proc/self/auxv") else {
        return 100;
    };
    for chunk in bytes.as_chunks::<16>().0 {
        let kind = u64::from_ne_bytes(chunk[0..8].try_into().expect("auxv kind"));
        let value = u64::from_ne_bytes(chunk[8..16].try_into().expect("auxv value"));
        if kind == 17 && value > 0 {
            return value;
        }
    }
    100
}

fn boot_unix() -> Option<u64> {
    std::fs::read_to_string("/proc/stat").ok().and_then(|stat| {
        stat.lines().find_map(|line| {
            line.strip_prefix("btime ")
                .and_then(|rest| rest.trim().parse().ok())
        })
    })
}

/// `starttime` from `/proc/<pid>/stat`, in clock ticks since boot.
fn start_ticks(stat: &str) -> Option<u64> {
    let rest = stat.rsplit_once(')')?.1;
    // Field 3 is the first token after `comm`; field 22 is starttime.
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// `ESRCH`: the kernel's answer to a `/proc/<pid>` read once the process
/// has exited after the file was opened. Std maps it to no `ErrorKind`.
const ESRCH: i32 = 3;

/// A `/proc/<pid>` file's text, or `None` when that process is gone.
/// A process that exits mid-scan is absence; any other read failure leaves
/// the table scan incomplete and is the caller's error.
fn read_proc_file(path: &Path) -> std::io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(ESRCH) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// Host pids of the namespaced worker that wrote `inner` into `pid_file`.
///
/// `owned` runs the payload in a new pid namespace, so `echo $$` records a
/// namespace-local pid (often 2). That number is not a host pid: host pid 2
/// is `kthreadd`, and `kill -0 2` stays true after the worker is gone. A
/// match needs a nested `NSpid` whose last id is `inner` and a start time
/// at the pid file's mtime. An unreaped zombie still has both, so it counts
/// as present.
fn host_worker_pids(proc_root: &Path, pid_file: &Path, inner: u32) -> std::io::Result<Vec<u32>> {
    let file_mtime = std::fs::metadata(pid_file)?
        .modified()?
        .duration_since(UNIX_EPOCH)
        .map_err(std::io::Error::other)?
        .as_secs();
    let hz = clock_ticks();
    let boot = boot_unix().ok_or_else(|| std::io::Error::other("no btime in /proc/stat"))?;
    let mut found = Vec::new();
    for entry in std::fs::read_dir(proc_root)? {
        let entry = entry?;
        let Ok(host) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Some(status) = read_proc_file(&entry.path().join("status"))? else {
            continue;
        };
        let Some(nspid) = status.lines().find_map(|line| line.strip_prefix("NSpid:")) else {
            continue;
        };
        let ids: Vec<u32> = nspid
            .split_whitespace()
            .filter_map(|word| word.parse().ok())
            .collect();
        if ids.len() < 2 || ids.last().copied() != Some(inner) {
            continue;
        }
        let Some(stat) = read_proc_file(&entry.path().join("stat"))? else {
            continue;
        };
        let Some(ticks) = start_ticks(&stat) else {
            continue;
        };
        let started = boot.saturating_add(ticks / hz);
        let near_file =
            started <= file_mtime.saturating_add(2) && file_mtime.saturating_sub(started) <= 5;
        if near_file {
            found.push(host);
        }
    }
    Ok(found)
}

/// `/bin/sh -c` with a cleared environment and `PATH=/usr/bin:/bin`.
/// The pid is `$1`, not text inside the script: `sh -c` is the only way
/// to pass that id without interpolating it into `kill`.
fn observer_command(script: &str, pid: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args(["-c", script, "sh", pid]);
    command
}

/// One `kill -0` of a host pid. Exit 0 is alive and exit 1 is gone; any
/// other status or a spawn failure is that status or io error alone.
fn alive(pid: &str) -> std::io::Result<bool> {
    let status = observer_command("kill -0 \"$1\" 2>/dev/null", pid).status()?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(std::io::Error::other(status.to_string())),
    }
}

/// The parent's stop ended the worker: the host process for its
/// namespace-local pid is killed and reaped within a short bound, never
/// left running or a zombie. Host pid 2 is not that worker, and `kill -0`
/// runs only against resolved host pids.
fn assert_worker_gone(
    pid_file: &Path,
    fixture: &str,
    retain: impl FnOnce(),
    caller_asserts: impl FnOnce(),
) {
    assert_worker_gone_in(
        Path::new("/proc"),
        pid_file,
        fixture,
        retain,
        caller_asserts,
    );
}

/// [`assert_worker_gone`] over a chosen process-table directory.
fn assert_worker_gone_in(
    proc_root: &Path,
    pid_file: &Path,
    fixture: &str,
    retain: impl FnOnce(),
    caller_asserts: impl FnOnce(),
) {
    // Every observation stays a value: the roots are retained (once) when
    // the pid was never recorded, the table cannot be read, a host pid's
    // liveness cannot be read, or the worker is still present at the
    // bound, and the caller's own assertions run (once) before any of
    // this function's panics.
    let recorded = recorded_pid(pid_file);
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut observation = None;
    let mut liveness = Ok(false);
    if let Some(inner) = recorded {
        loop {
            let seen = host_worker_pids(proc_root, pid_file, inner);
            let settled = match &seen {
                Ok(hosts) if !hosts.is_empty() => {
                    liveness = Ok(false);
                    for host in hosts {
                        match alive(&host.to_string()) {
                            Ok(true) => liveness = Ok(true),
                            Ok(false) => {}
                            Err(error) => {
                                liveness = Err(error);
                                break;
                            }
                        }
                    }
                    !matches!(&liveness, Ok(true)) || Instant::now() >= deadline
                }
                _ => {
                    liveness = Ok(false);
                    true
                }
            };
            observation = Some(seen);
            if settled {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let unproven = match &observation {
        None | Some(Err(_)) => true,
        Some(Ok(hosts)) if hosts.is_empty() => false,
        Some(Ok(_)) => !matches!(&liveness, Ok(false)),
    };
    if unproven {
        retain();
    }
    caller_asserts();
    let inner = recorded.expect("the worker recorded its pid");
    let hosts = observation
        .expect("the recorded pid was observed")
        .expect("read the process table");
    if let Err(error) = &liveness {
        panic!("run kill -0: {error}");
    }
    assert!(
        matches!(&liveness, Ok(false)),
        "{fixture}: worker namespace pid {inner} host {hosts:?} outlived the parent's stop"
    );
}

fn gone_worker_is_never_retained_and_the_caller_asserts_once() {
    let dir = tempfile::TempDir::with_prefix("rivect-iw-gone-observer-").expect("fixture root");
    let pid_file = dir.path().join("worker.pid");
    // A recorded pid no process carries as its namespace-local id.
    std::fs::write(&pid_file, "4000000000\n").expect("record a pid");
    let calls = std::cell::RefCell::new(Vec::new());
    assert_worker_gone(
        &pid_file,
        "no such worker",
        || calls.borrow_mut().push("retain"),
        || calls.borrow_mut().push("caller_asserts"),
    );
    assert_eq!(*calls.borrow(), ["caller_asserts"]);
}

fn unrecorded_worker_retains_then_asserts_before_the_observer_fails() {
    let dir =
        tempfile::TempDir::with_prefix("rivect-iw-unrecorded-observer-").expect("fixture root");
    let pid_file = dir.path().join("never-written.pid");
    let calls = std::cell::RefCell::new(Vec::new());
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_worker_gone(
            &pid_file,
            "unrecorded",
            || calls.borrow_mut().push("retain"),
            || calls.borrow_mut().push("caller_asserts"),
        );
    }));
    assert!(outcome.is_err(), "an unrecorded worker fails the observer");
    assert_eq!(*calls.borrow(), ["retain", "caller_asserts"]);
}

/// A numeric proc entry whose `status` or `stat` is a directory fails to
/// read with `EISDIR` (not `NotFound`): the table scan is incomplete, so
/// the observer must retain the roots once, run the caller's assertions,
/// and then fail — never accept the unread entry as a gone worker. So does
/// a process table that does not exist. An entry whose files vanished
/// (`NotFound`) or whose process exited after the open (a real `ESRCH`) is
/// plain absence. Linux only: the scan reads the real `/proc/stat` boot
/// time before any entry, so elsewhere the fixture entries would never be
/// reached.
#[cfg(target_os = "linux")]
fn incomplete_process_scan_retains_before_caller_assertions() {
    let dir =
        tempfile::TempDir::with_prefix("rivect-iw-unknown-scan-observer-").expect("fixture root");
    let root = dir.path().to_path_buf();
    let pid_file = root.join("worker.pid");
    std::fs::write(&pid_file, "7\n").expect("record a pid");
    let observe = |proc_root: &Path| {
        let calls = std::cell::RefCell::new(Vec::new());
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_worker_gone_in(
                proc_root,
                &pid_file,
                "unknown scan",
                || calls.borrow_mut().push("retain"),
                || calls.borrow_mut().push("caller_asserts"),
            );
        }));
        (outcome, calls.into_inner())
    };

    let status_scan = root.join("status-scan");
    std::fs::create_dir_all(status_scan.join("4242/status")).expect("unreadable status entry");
    let (outcome, calls) = observe(&status_scan);
    assert!(
        outcome.is_err(),
        "an incomplete process scan must fail the observer, not count as gone"
    );
    assert_eq!(calls, ["retain", "caller_asserts"]);

    // A matching `NSpid` makes the scan read `stat`, here a directory.
    let stat_scan = root.join("stat-scan");
    std::fs::create_dir_all(stat_scan.join("4243/stat")).expect("unreadable stat entry");
    std::fs::write(stat_scan.join("4243/status"), "NSpid:\t4243\t7\n").expect("matching status");
    let (outcome, calls) = observe(&stat_scan);
    assert!(
        outcome.is_err(),
        "an unreadable stat must fail the observer, not count as gone"
    );
    assert_eq!(calls, ["retain", "caller_asserts"]);

    // One entry vanished before `status`, another before `stat`.
    let vanished = root.join("vanished");
    std::fs::create_dir_all(vanished.join("4244")).expect("entry without status");
    std::fs::create_dir_all(vanished.join("4245")).expect("entry without stat");
    std::fs::write(vanished.join("4245/status"), "NSpid:\t4245\t7\n").expect("matching status");
    let (outcome, calls) = observe(&vanished);
    assert!(
        outcome.is_ok(),
        "entries that disappeared mid-scan are absence, not a failed scan"
    );
    assert_eq!(calls, ["caller_asserts"]);

    // A missing process table is not a vanished process: the scan itself
    // cannot read its directory, so it fails like any unknown error.
    let (outcome, calls) = observe(&root.join("no-process-table"));
    assert!(
        outcome.is_err(),
        "a missing process table must fail the observer, not count as gone"
    );
    assert_eq!(calls, ["retain", "caller_asserts"]);

    // A process that exits between the scan's open and read gets the
    // kernel's `ESRCH`, which is absence. A real child's `status` is opened
    // while it lives and held; the entry's `status` links to that
    // descriptor, so the scanner's own read fails with the kernel's `ESRCH`
    // once the child is reaped. The child is given no fixture path, and is
    // closed and reaped before any fallible fixture step.
    let mut child = Command::new("/bin/cat")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the exiting process");
    let held = std::fs::File::open(format!("/proc/{}/status", child.id()));
    drop(child.stdin.take());
    let reaped = child.wait();
    let held = held.expect("open the live process status");
    assert!(reaped.expect("reap the exited process").success());
    let exited = root.join("exited");
    std::fs::create_dir_all(exited.join("4246")).expect("entry for the exited process");
    let status = exited.join("4246/status");
    std::os::unix::fs::symlink(format!("/proc/self/fd/{}", held.as_raw_fd()), &status)
        .expect("link the held status");
    let read = std::fs::read_to_string(&status);
    assert_eq!(
        read.expect_err("a reaped process's status cannot be read")
            .raw_os_error(),
        Some(ESRCH),
        "the kernel answers ESRCH for a process gone after the open"
    );
    let (outcome, calls) = observe(&exited);
    assert!(
        outcome.is_ok(),
        "a process that exited mid-scan is absence, not a failed scan"
    );
    assert_eq!(calls, ["caller_asserts"]);
    drop(held);
}

/// The observer's command is a cleared env with only the PATH allowlist.
/// A synthetic key on the parent does not show up in that command's `env`.
#[test]
fn alive_observer_passes_only_the_allowlist() {
    // The observer's own call-order subcases run first: they share the
    // parent's leg so the executed-test count carries one observer leg.
    gone_worker_is_never_retained_and_the_caller_asserts_once();
    unrecorded_worker_retains_then_asserts_before_the_observer_fails();
    #[cfg(target_os = "linux")]
    incomplete_process_scan_retains_before_caller_assertions();
    let dir =
        tempfile::TempDir::with_prefix("rivect-iw-allowlist-observer-").expect("fixture root");
    let pid_file = dir.path().join("worker.pid");
    // A recorded pid no process carries as its namespace-local id.
    std::fs::write(&pid_file, "4000000000\n").expect("record a pid");
    let retained = std::cell::Cell::new(false);
    assert_worker_gone(&pid_file, "no such worker", || retained.set(true), || {});
    assert!(!retained.get(), "a pid no process carries is not retained");

    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("RIVECT_SYNTHETIC_KEY", "rivect-synthetic-not-a-secret")
        .args([
            "alive_observer_env_probe_child",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .output();
    let output = output.expect("spawn the observer env probe");
    assert!(output.status.success(), "{output:?}");
    let passed = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains("1 passed; 0 failed; 0 ignored"))
        .count();
    assert_eq!(passed, 1, "{output:?}");
}

#[test]
#[ignore = "child entry: spawned by alive_observer_passes_only_the_allowlist"]
fn alive_observer_env_probe_child() {
    assert_eq!(
        std::env::var("RIVECT_SYNTHETIC_KEY").as_deref(),
        Ok("rivect-synthetic-not-a-secret"),
        "RIVECT_SYNTHETIC_KEY"
    );
    let output = observer_command("env", "0").output();
    let output = output.expect("run env in the observer command");
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    let paths = text
        .lines()
        .filter(|line| *line == "PATH=/usr/bin:/bin")
        .count();
    assert_eq!(paths, 1, "{output:?}");
    assert!(
        text.lines()
            .all(|line| !line.contains("RIVECT_SYNTHETIC_KEY")),
        "{output:?}"
    );
}

/// A program that records its pid in `pid_file` and then execs `tail`,
/// so the recorded pid is the worker's own for the whole run.
fn pid_shim(dir: &Path, name: &str, pid_file: &Path, tail: &str) -> PathBuf {
    script(
        dir,
        name,
        &format!("#!/bin/sh\necho $$ > {}\n{tail}\n", quoted(pid_file)),
    )
}

/// A perl program that records its pid, reads the request, holds
/// `bytes` in 1000-byte strings — the small blocks only the macOS
/// footprint poll bounds (DEC-038) — and then sleeps.
#[cfg(target_os = "macos")]
fn holder_shim(dir: &Path, name: &str, pid_file: &Path, bytes: u64) -> PathBuf {
    script(
        dir,
        name,
        &format!(
            "#!/usr/bin/perl\nopen(my $pid, '>', {}) or exit 9;\nprint $pid \"$$\\n\";\nclose($pid);\nlocal $/; my $request = <STDIN>;\nmy @held;\npush @held, 'x' x 1000 for 1 .. {};\nsleep 30;\n",
            quoted(pid_file),
            bytes / 1000
        ),
    )
}

/// A worker launched with `SENTINEL=1` beside the allowlisted env.
fn env_sentinel(dir: &Path) -> PathBuf {
    script(
        dir,
        "env-sentinel",
        &format!(
            "#!/bin/sh\nexec /usr/bin/env SENTINEL=1 {} {INDEX_WORKER_FLAG}\n",
            quoted(&worker())
        ),
    )
}

/// A program that only creates `marker` — its absence proves no worker
/// ever started.
fn marker_shim(dir: &Path) -> (PathBuf, PathBuf) {
    let marker = dir.join("spawned");
    let program = program_shim(dir, "marker", &format!(": > {}", quoted(&marker)));
    (program, marker)
}

/// The request the parent really sends, captured by a program that
/// saves its stdin and answers nothing.
fn capture_request(request: &Query, deadline: Option<Instant>) -> Value {
    let dir = tempfile::TempDir::with_prefix("rivect-iw-capture-").expect("fixture root");
    let file = dir.path().join("request.json");
    let tee = script(
        dir.path(),
        "tee-request",
        &format!("#!/bin/sh\nexec /bin/cat > {}\n", quoted(&file)),
    );
    let cause = cause_of(isolated(request, &tee, &helper(), deadline));
    assert_eq!(
        cause,
        IsolatedCause::EmptyAnswer,
        "the capture answers nothing"
    );
    serde_json::from_slice(&std::fs::read(&file).expect("captured request"))
        .expect("the request is JSON")
}

/// The test's own spawn of the real worker under the real helper, with
/// an explicit environment — so a request can be edited and the env
/// chosen. Returns the worker's stdout.
fn direct_worker(request: &Value, env: &[(&str, &Path)], retain: impl FnOnce()) -> Vec<u8> {
    let encoded = serde_json::to_vec(request).expect("encode request");
    let spawned = Command::new(helper())
        .arg("launch")
        .arg(MEMORY_BUDGET_FLAG)
        .arg(INDEX_WORKER_MEMORY_BUDGET.to_string())
        .arg("--")
        .arg(worker())
        .arg(INDEX_WORKER_FLAG)
        .env_clear()
        .envs(env.iter().map(|(key, value)| (key, value)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    // Every step stays a value until the child is reaped: a failed step
    // leaves the reap unproven, so the roots it names are retained
    // before any panic site consumes the error.
    let steps = spawned.map(|mut child| {
        let wrote = child.stdin.take().map(|mut pipe| pipe.write_all(&encoded));
        (wrote, child.wait_with_output())
    });
    let failed = match &steps {
        Err(_) => true,
        Ok((wrote, waited)) => !matches!(wrote, Some(Ok(()))) || waited.is_err(),
    };
    if failed {
        retain();
    }
    let (wrote, waited) = steps.expect("spawn the worker");
    wrote.expect("worker stdin").expect("write the request");
    let output = waited.expect("worker output");
    assert!(output.status.success(), "the worker exits 0: {output:?}");
    output.stdout
}

/// The two uncapped fixtures use the same real worker without a launcher cap.
fn uncapped_worker(request: &Query) -> (Result<QueryResult, ContextError>, String) {
    use sha2::{Digest as _, Sha256};
    use std::io::{Read as _, Seek as _};
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::MetadataExt as _;

    fn executable_hash(file: &mut std::fs::File) -> String {
        file.rewind().expect("rewind the held worker executable");
        let mut digest = Sha256::new();
        let mut block = [0_u8; 65536];
        loop {
            let count = file
                .read(&mut block)
                .expect("hash the held worker executable");
            if count == 0 {
                break;
            }
            digest.update(&block[..count]);
        }
        rivect::config::hex(&digest.finalize())
    }

    #[cfg(target_os = "linux")]
    fn native_limits(pid: u32) -> String {
        let bytes = std::fs::read(format!("/proc/{pid}/limits"))
            .expect("read the held native child's limits");
        assert!(bytes.len() <= 65536);
        let text = String::from_utf8(bytes).expect("native limit rows are ASCII");
        for name in ["Max address space", "Max data size"] {
            let row = text
                .lines()
                .find_map(|row| row.strip_prefix(name))
                .expect("native AS/DATA row");
            assert_eq!(
                row.split_whitespace().collect::<Vec<_>>(),
                ["unlimited", "unlimited", "bytes"],
                "{name}: {row}"
            );
        }
        text
    }

    let wire = serde_json::to_vec(&capture_request(request, None))
        .expect("encode the actual bounded request");
    assert!(wire.len() <= 1024 * 1024);
    let target = worker();
    let mut executable = std::fs::File::open(&target).expect("hold the actual worker target");
    let identity = executable.metadata().expect("freeze worker identity");
    assert!(identity.is_file());
    let mut magic = [0_u8; 4];
    executable
        .read_exact(&mut magic)
        .expect("read native executable magic");
    #[cfg(target_os = "linux")]
    assert_eq!(
        &magic, b"\x7fELF",
        "the fixed target is a native executable, never a shim"
    );
    let hash = executable_hash(&mut executable);
    assert_eq!(
        rivect_sandbox_helper::memory_limit().expect("read inherited native memory limits"),
        None
    );
    let mut command = Command::new(&target);
    command
        .arg(INDEX_WORKER_FLAG)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    assert_eq!(command.get_program(), target.as_os_str());
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        [OsStr::new(INDEX_WORKER_FLAG)]
    );
    assert_eq!(command.get_envs().count(), 0);
    let work_cutoff = Instant::now() + MAX_INDEX_PARSE_TIME;
    let deadline = work_cutoff + WORKER_KILL_GRACE;
    let mut child = command.spawn().expect("exec the fixed uncapped worker");
    let pid = child.id();
    let mut wait_attempted = false;
    let captured = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert!(
            Instant::now() < work_cutoff,
            "spawn consumed the existing capture budget"
        );
        let mut stdin = child.stdin.take().expect("hold the EOF barrier");
        let mut stdout = child.stdout.take().expect("worker stdout");
        let mut stderr = child.stderr.take().expect("worker stderr");
        for fd in [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()] {
            rivect_sandbox_helper::set_nonblocking(fd).expect("bound the actual worker pipes");
        }
        #[cfg(target_os = "linux")]
        let before = native_limits(pid);
        assert_eq!(
            child.try_wait().expect("observe the unreaped parked child"),
            None
        );
        let mut probe = [0_u8; 1];
        let no_answer = stdout
            .read(&mut probe)
            .expect_err("held stdin forbids an early envelope");
        assert_eq!(no_answer.kind(), std::io::ErrorKind::WouldBlock);
        let mut written = 0;
        while written < wire.len() {
            assert!(
                Instant::now() < work_cutoff,
                "request write keeps the original work cutoff"
            );
            match stdin.write(&wire[written..]) {
                Ok(0) => panic!("worker request write made no progress"),
                Ok(count) => written += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    rivect_sandbox_helper::wait_ready(
                        &[],
                        &[stdin.as_fd()],
                        work_cutoff.saturating_duration_since(Instant::now()),
                    )
                    .expect("bounded request readiness");
                }
                Err(error) => panic!("actual worker request write failed: {error}"),
            }
        }
        assert_eq!(
            child
                .try_wait()
                .expect("the same child remains parked before EOF"),
            None
        );
        let no_answer = stdout
            .read(&mut probe)
            .expect_err("the complete request remains unanswered until its one EOF");
        assert_eq!(no_answer.kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(
            rivect_sandbox_helper::memory_limit().expect("native held-stdin memory readback"),
            None
        );
        drop(stdin);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let (mut out_eof, mut err_eof) = (false, false);
        while !out_eof || !err_eof {
            assert!(
                Instant::now() < work_cutoff,
                "capture keeps its original work cutoff"
            );
            let pipes: [(&mut dyn std::io::Read, &mut Vec<u8>, usize, &mut bool); 2] = [
                (&mut stdout, &mut out, WORKER_ANSWER_MAX, &mut out_eof),
                (&mut stderr, &mut err, 64 * 1024, &mut err_eof),
            ];
            for (pipe, bytes, cap, eof) in pipes {
                if *eof {
                    continue;
                }
                let mut block = [0_u8; 4096];
                match pipe.read(&mut block) {
                    Ok(0) => *eof = true,
                    Ok(count) => {
                        bytes.extend_from_slice(&block[..count]);
                        assert!(bytes.len() <= cap, "capture overflow is a failed fixture");
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) => panic!("actual worker output read failed: {error}"),
                }
                assert!(
                    Instant::now() < work_cutoff,
                    "native reads preserve the work cutoff"
                );
            }
            let mut readable = Vec::new();
            if !out_eof {
                readable.push(stdout.as_fd());
            }
            if !err_eof {
                readable.push(stderr.as_fd());
            }
            if !readable.is_empty() {
                rivect_sandbox_helper::wait_ready(
                    &readable,
                    &[],
                    work_cutoff.saturating_duration_since(Instant::now()),
                )
                .expect("bounded worker output readiness");
            }
        }
        #[cfg(target_os = "linux")]
        let after = native_limits(pid);
        assert_eq!(
            rivect_sandbox_helper::memory_limit().expect("native post-capture memory readback"),
            None
        );
        assert!(Instant::now() < deadline);
        wait_attempted = true;
        let status = child.wait().expect("own the only final child wait");
        assert!(
            status.success(),
            "the actual worker exits zero: {status:?} stderr={err:?}"
        );
        let observed =
            std::fs::metadata(&target).expect("observe the admitted worker path after capture");
        assert_eq!(
            (identity.dev(), identity.ino()),
            (observed.dev(), observed.ino())
        );
        assert_eq!(executable_hash(&mut executable), hash);
        let mut custody = format!(
            "fixed uncapped worker: target={target:?} identity={:?} sha256={hash} pid={pid} held_stdin=true early_envelope=false status={status:?} stdout={out:?} stderr={err:?}",
            (identity.dev(), identity.ino())
        );
        #[cfg(target_os = "linux")]
        custody.push_str(&format!(" native_before={before:?} native_after={after:?}"));
        (out, custody)
    }));
    let (bytes, custody) = match captured {
        Ok(captured) => captured,
        Err(primary) => {
            if !wait_attempted {
                let signal = child.kill();
                let waited = child.wait();
                let message = format!(
                    "fixed uncapped capture failed: pid={pid} signal={signal:?} owned_wait={waited:?} custody=unproven\n"
                );
                let _receipt = std::io::stderr().write_all(message.as_bytes());
            }
            std::panic::resume_unwind(primary);
        }
    };
    assert!(wait_attempted);
    (decode_via_parent(&bytes, WORKER_ANSWER_MAX), custody)
}

/// The parent's decode of `bytes`: a program that prints them and
/// exits 0.
fn decode_via_parent(bytes: &[u8], answer_cap: usize) -> Result<QueryResult, ContextError> {
    let dir = tempfile::TempDir::with_prefix("rivect-iw-decode-").expect("fixture root");
    let file = dir.path().join("envelope.json");
    std::fs::write(&file, bytes).expect("write envelope");
    let program = program_shim(
        dir.path(),
        "cat-envelope",
        &format!("exec /bin/cat {}", quoted(&file)),
    );
    query_isolated(
        &search_query(QueryKind::Path, dir.path(), "*"),
        &IsolatedRun {
            program: &program,
            helper: &helper(),
            deadline: None,
            cancel: &never,
            answer_cap,
        },
    )
}

/// A real envelope for a benign query, captured from the real worker.
fn real_envelope(request: &Query, retain_request_root: impl FnOnce()) -> Vec<u8> {
    let mut home = tempfile::TempDir::with_prefix("rivect-iw-home-").expect("fixture root");
    let home_path = home.path().to_path_buf();
    direct_worker(
        &capture_request(request, None),
        &[("HOME", &home_path)],
        || {
            support::retain_root(&mut home);
            retain_request_root();
        },
    )
}

/// `x<y,` repeated past 64 KiB: tree-sitter-typescript's GLR recovery
/// grows memory without bound on it (review4 F1). Measured on macOS
/// under the worker, its physical footprint crosses the 512 MiB budget
/// about 3 s in (AST) — well inside MAX_INDEX_PARSE_TIME.
fn hostile_tree(name: &str) -> TempTree {
    tree_of(name, &[("src/hostile.ts", &"x<y,".repeat(16_400))])
}

/// The calibrated slow input: TypeScript recovery-heavy files whose
/// structural parse runs for seconds while each file's parse stays far
/// under the worker's memory cap (S4) — about 53 MiB peak footprint,
/// measured on macOS, so the footprint stop never ends it.
fn slow_tree(name: &str) -> TempTree {
    let unit = "x<y,".repeat(SLOW_FILE_UNITS);
    let files: Vec<(String, String)> = (0..SLOW_FILES)
        .map(|n| (format!("src/slow_{n:03}.ts"), unit.clone()))
        .collect();
    let refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(path, body)| (path.as_str(), body.as_str()))
        .collect();
    tree_of(name, &refs)
}

const SLOW_FILES: usize = 400;
const SLOW_FILE_UNITS: usize = 1_024;

/// A structural pattern no slow file matches, so the walk parses every
/// file instead of stopping at the match bound.
const SLOW_PATTERN: &str = "never_matched($X)";

#[test]
fn hostile_typescript_in_worker_ends_as_typed_bounded_failure() {
    let tree = hostile_tree("iw-hostile");
    for (kind, pattern) in [(QueryKind::Ast, "x < y"), (QueryKind::Symbol, "x")] {
        let mut request = search_query(kind, &tree.path, pattern);
        if kind == QueryKind::Symbol {
            request.symbol_op = Some(SymbolOp::Definition);
        }
        let start = Instant::now();
        let outcome = isolated(&request, &worker(), &helper(), None);
        let elapsed = start.elapsed();
        println!("EVID-474 hostile {kind:?}: {elapsed:?} -> {outcome:?}");
        assert!(
            elapsed <= MAX_INDEX_PARSE_TIME + WORKER_KILL_GRACE + Duration::from_secs(3),
            "the hostile run is bounded: {elapsed:?}"
        );
        match outcome {
            Err(ContextError::IsolatedRun {
                cause:
                    IsolatedCause::ResourceLimit { .. }
                    | IsolatedCause::MemoryExceeded
                    | IsolatedCause::DeadlineExceeded,
                ..
            }) => {}
            Ok(result) if result.completeness != Completeness::Complete => {}
            other => panic!("a hostile parse never answers complete: {other:?}"),
        }
    }
}

#[test]
fn worker_memory_cap_stops_hostile_parse_before_the_deadline() {
    let tree = hostile_tree("iw-cap");
    let request = search_query(QueryKind::Ast, &tree.path, "x < y");
    let start = Instant::now();
    let cause = cause_of(isolated(&request, &worker(), &helper(), None));
    let elapsed = start.elapsed();
    println!("EVID-474 memory cap: {elapsed:?} -> {cause:?}");
    // macOS: the relative RLIMIT misses GLR's small blocks, so the
    // parent's footprint poll is what stops the run (DEC-038).
    #[cfg(target_os = "macos")]
    assert_eq!(
        cause,
        IsolatedCause::MemoryExceeded,
        "the footprint poll ends the hostile parse"
    );
    #[cfg(target_os = "linux")]
    {
        let IsolatedCause::ResourceLimit { signal } = cause else {
            panic!("the memory cap ends the hostile parse, got {cause:?}");
        };
        assert!(
            signal == SIGABRT || signal == SIGKILL,
            "a cap hit surfaces as SIGABRT or SIGKILL, got {signal}"
        );
    }
    assert!(
        elapsed < MAX_INDEX_PARSE_TIME,
        "the cap stops the parse before the clamped deadline: {elapsed:?}"
    );
}

#[test]
fn worker_refuses_to_serve_without_a_memory_cap() {
    let corpus = search_corpus("iw-uncapped");
    let (outcome, custody) = uncapped_worker(&search_query(QueryKind::Path, &corpus.path, "*.rs"));
    println!("{custody}");
    let cause = cause_of(outcome);
    assert_eq!(cause, IsolatedCause::WorkerUncapped);
    assert_eq!(cause.error_code(), ErrorCode::CapabilityUnavailable);
}

/// The worker mode is exactly one argument: beside any other argument
/// the main CLI owns argv and refuses the flag as unknown, and alone it
/// serves one envelope. The gate reads argv as OS strings, so a program
/// path that is not UTF-8 still reaches it — `env::args` panics there
/// and takes the envelope with it.
#[test]
fn worker_flag_is_the_worker_mode_only_when_it_is_alone() {
    let mut corpus = search_corpus("iw-flag");
    let request = search_query(QueryKind::Path, &corpus.path, "*.rs");

    for (fixture, args) in [
        (
            "a positional argument beside the flag",
            vec![INDEX_WORKER_FLAG, "extra"],
        ),
        (
            "another flag beside it",
            vec![INDEX_WORKER_FLAG, "--headless"],
        ),
        (
            "another flag before it",
            vec!["--headless", INDEX_WORKER_FLAG],
        ),
    ] {
        let output = Command::new(worker())
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("run the CLI");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{fixture}: {stderr}");
        assert!(
            stderr.contains(&format!("unknown flag {INDEX_WORKER_FLAG}")),
            "{fixture}: the worker flag is an unknown one there: {stderr}"
        );
        assert!(
            output.stdout.is_empty(),
            "{fixture}: no worker ran, so there is no envelope"
        );
    }

    let payload = capture_request(&request, None);
    let mut home = tempfile::TempDir::with_prefix("rivect-iw-flag-home-").expect("fixture root");
    let home_path = home.path().to_path_buf();
    let envelope = direct_worker(&payload, &[("HOME", &home_path)], || {
        support::retain_root(&mut home);
        corpus.retain();
    });
    assert_eq!(
        decode_via_parent(&envelope, WORKER_ANSWER_MAX).map_err(|error| error.error_code()),
        query(&request).map_err(|error| error.error_code()),
        "the flag alone serves the envelope the parent decodes"
    );
}

/// The gate reads argv without requiring a UTF-8 program path, which a
/// symlink named outside Unicode gives it. Only Linux: APFS refuses such
/// an entry name, so the path cannot be built on macOS.
#[cfg(target_os = "linux")]
#[test]
fn worker_flag_serves_under_a_program_path_that_is_not_utf8() {
    let mut dir = tempfile::TempDir::with_prefix("rivect-iw-non-utf8-link-").expect("fixture root");
    let mut home =
        tempfile::TempDir::with_prefix("rivect-iw-non-utf8-home-").expect("fixture root");
    let link = dir.path().join(OsStr::from_bytes(b"rivect-\xff"));
    std::os::unix::fs::symlink(worker(), &link).expect("link the worker under a non-UTF-8 name");
    let mut corpus = search_corpus("iw-non-utf8-path");
    let request = search_query(QueryKind::Path, &corpus.path, "*.rs");
    let payload = capture_request(&request, None);
    let encoded = serde_json::to_vec(&payload).expect("encode request");
    let spawned = Command::new(&link)
        .arg(INDEX_WORKER_FLAG)
        .env_clear()
        .env("HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    // Every step stays a value until the child is reaped: a failed step
    // retains the roots it names (program link, HOME, request root)
    // before any panic site consumes the error.
    let steps = spawned.map(|mut child| {
        let wrote = child.stdin.take().map(|mut pipe| pipe.write_all(&encoded));
        (wrote, child.wait_with_output())
    });
    let failed = match &steps {
        Err(_) => true,
        Ok((wrote, waited)) => !matches!(wrote, Some(Ok(()))) || waited.is_err(),
    };
    if failed {
        support::retain_root(&mut dir);
        support::retain_root(&mut home);
        corpus.retain();
    }
    let (wrote, waited) = steps.expect("run the worker through the non-UTF-8 path");
    wrote.expect("worker stdin").expect("write the request");
    let output = waited.expect("worker output");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let envelope: Value = serde_json::from_slice(&output.stdout).expect("one envelope");
    assert_eq!(
        envelope["crate_version"],
        Value::from(env!("CARGO_PKG_VERSION")),
        "{envelope}"
    );
    // This exec is not the helper's, so the declared answer is the
    // refusal: the gate ran far enough to read the request and check its
    // own preconditions.
    assert_eq!(
        (
            envelope["body"]["outcome"].clone(),
            envelope["body"]["reason"].clone()
        ),
        (Value::from("refused"), Value::from("uncapped")),
        "{envelope}"
    );
}

#[test]
fn caller_deadline_is_clamped_to_max_index_parse_time() {
    let corpus = search_corpus("iw-clamp");
    let request = search_query(QueryKind::Path, &corpus.path, "*.rs");
    let max_ms = MAX_INDEX_PARSE_TIME.as_millis() as u64;
    let wire = |deadline: Option<Instant>| {
        capture_request(&request, deadline)["deadline_ms"]
            .as_u64()
            .expect("deadline_ms rides the request")
    };

    for (label, deadline) in [
        ("absent", None),
        (
            "distant",
            Instant::now().checked_add(Duration::from_secs(3_600)),
        ),
    ] {
        let ms = wire(deadline);
        assert!(
            ms <= max_ms && ms + 3_000 >= max_ms,
            "{label} deadline clamps to MAX_INDEX_PARSE_TIME: {ms} ms"
        );
    }
    let ms = wire(Instant::now().checked_add(Duration::from_secs(3)));
    assert!(
        (1_000..=3_000).contains(&ms),
        "a nearer deadline is kept: {ms} ms"
    );

    let dir = tempfile::TempDir::with_prefix("rivect-iw-past-").expect("fixture root");
    let (program, marker) = marker_shim(dir.path());
    let past = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .expect("an instant a moment ago");
    let cause = cause_of(isolated(&request, &program, &helper(), Some(past)));
    assert_eq!(cause, IsolatedCause::DeadlinePassed);
    assert!(!marker.exists(), "a past deadline starts no worker");
}

#[test]
fn worker_side_deadline_clamp_ignores_a_wider_wire_value() {
    let mut tree = slow_tree("iw-wire-clamp");
    let mut request = symbol_query(&tree.path, "x", SymbolOp::Definition);
    request.limit = 1;
    let mut wire = capture_request(&request, None);
    wire["deadline_ms"] = Value::from(u64::MAX);
    let mut home = tempfile::TempDir::with_prefix("rivect-iw-wire-home-").expect("fixture root");
    let start = Instant::now();
    let home_path = home.path().to_path_buf();
    let envelope = direct_worker(&wire, &[("HOME", &home_path)], || {
        support::retain_root(&mut home);
        tree.retain();
    });
    let elapsed = start.elapsed();
    let result = decode_via_parent(&envelope, WORKER_ANSWER_MAX).expect("a clamped answer");
    println!(
        "EVID-474 worker clamp: {elapsed:?} -> {:?}",
        result.completeness
    );
    assert!(
        elapsed <= MAX_INDEX_PARSE_TIME + Duration::from_secs(3),
        "the worker's own deadline is at most MAX_INDEX_PARSE_TIME: {elapsed:?}"
    );
    let Completeness::Partial { reasons } = &result.completeness else {
        panic!("files past the clamped deadline fail: {result:?}");
    };
    assert!(
        reasons
            .iter()
            .any(|reason| matches!(reason, PartialReason::EntriesFailed { .. })),
        "the clamp fails the unparsed files: {reasons:?}"
    );
}

#[test]
fn cancellation_reaches_the_worker_and_ends_the_run() {
    let mut tree = slow_tree("iw-cancel");
    let request = search_query(QueryKind::Ast, &tree.path, SLOW_PATTERN);
    // Both paths resolve (the helper may build) before anything is timed,
    // and the hook flips on the worker's own pid, never on wall time.
    let helper = helper();
    let mut dir = tempfile::TempDir::with_prefix("rivect-iw-cancel-pid-").expect("fixture root");
    let pid_file = dir.path().join("worker.pid");
    let program = pid_shim(
        dir.path(),
        "pid-worker",
        &pid_file,
        &format!(
            "exec /usr/bin/env -i {} {INDEX_WORKER_FLAG}",
            quoted(&worker())
        ),
    );
    let flip = Duration::from_millis(200);
    let started = std::cell::Cell::new(None::<Instant>);
    let cancel = || match started.get() {
        Some(at) => at.elapsed() >= flip,
        None => {
            if recorded_pid(&pid_file).is_some() {
                started.set(Some(Instant::now()));
            }
            false
        }
    };
    let outcome = query_isolated(
        &request,
        &IsolatedRun {
            program: &program,
            helper: &helper,
            deadline: None,
            cancel: &cancel,
            answer_cap: WORKER_ANSWER_MAX,
        },
    );
    let elapsed = started.get().map(|at| at.elapsed());
    assert_worker_gone(
        &pid_file,
        "cancelled slow parse",
        || {
            support::retain_root(&mut dir);
            tree.retain();
        },
        move || {
            let elapsed = elapsed.expect("the worker started before the cancel");
            println!("EVID-474 cancel: {elapsed:?} after the worker started -> {outcome:?}");
            assert_eq!(cause_of(outcome), IsolatedCause::Cancelled);
            assert!(
                elapsed <= flip + Duration::from_secs(1),
                "cancellation ends the run within a second: {elapsed:?}"
            );
        },
    );
}

#[test]
fn cancel_before_spawn_starts_no_worker() {
    let dir = tempfile::TempDir::with_prefix("rivect-iw-cancel-first-").expect("fixture root");
    let (program, marker) = marker_shim(dir.path());
    let corpus = search_corpus("iw-cancel-first");
    let cancelled = || true;
    let outcome = query_isolated(
        &search_query(QueryKind::Path, &corpus.path, "*.rs"),
        &IsolatedRun {
            program: &program,
            helper: &helper(),
            deadline: None,
            cancel: &cancelled,
            answer_cap: WORKER_ANSWER_MAX,
        },
    );
    assert_eq!(cause_of(outcome), IsolatedCause::CancelledBeforeSpawn);
    assert!(!marker.exists(), "a cancelled query starts no worker");
}

#[test]
fn ast_query_past_the_deadline_ends_as_deadline_exceeded_never_a_partial_answer() {
    let tree = slow_tree("iw-ast-deadline");
    let request = search_query(QueryKind::Ast, &tree.path, SLOW_PATTERN);
    let deadline = Duration::from_secs(1);
    let start = Instant::now();
    let outcome = isolated(&request, &worker(), &helper(), start.checked_add(deadline));
    let elapsed = start.elapsed();
    println!("EVID-474 ast past deadline: {elapsed:?} -> {outcome:?}");
    assert_eq!(cause_of(outcome), IsolatedCause::DeadlineExceeded);
    assert!(
        elapsed >= deadline && elapsed <= deadline + WORKER_KILL_GRACE + Duration::from_secs(1),
        "the wall-kill ends the run at deadline + grace: {elapsed:?}"
    );
}

#[test]
fn worker_env_is_only_the_ignore_allowlist() {
    let dir = tempfile::TempDir::with_prefix("rivect-iw-env-").expect("fixture root");
    let dump = dir.path().join("env.txt");
    let program = script(
        dir.path(),
        "dump-env",
        &format!(
            "#!/usr/bin/perl\nlocal $/; my $request = <STDIN>;\nopen(my $out, '>', {}) or exit 9;\nprint $out join(\"\\n\", map {{ \"$_=$ENV{{$_}}\" }} sort keys %ENV);\nclose($out);\nexit 0;\n",
            quoted(&dump)
        ),
    );
    let corpus = search_corpus("iw-env");
    let cause = cause_of(isolated(
        &search_query(QueryKind::Path, &corpus.path, "*.rs"),
        &program,
        &helper(),
        None,
    ));
    assert_eq!(cause, IsolatedCause::EmptyAnswer);
    let dumped = std::fs::read_to_string(&dump).expect("the program saw its env");
    let env: Vec<(&str, &str)> = dumped
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    let allowlist = [
        "HOME",
        "XDG_CONFIG_HOME",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
    ];
    // Key names only: a failure must never print an environment value.
    let outside: Vec<&str> = env
        .iter()
        .map(|(key, _)| *key)
        .filter(|key| !allowlist.contains(key))
        .collect();
    assert!(
        outside.is_empty(),
        "keys outside the allowlist: {outside:?}"
    );
    let parent_home = std::env::var("HOME").expect("the test runs with HOME");
    assert_eq!(
        env.iter()
            .find(|(key, _)| *key == "HOME")
            .map(|(_, value)| *value),
        Some(parent_home.as_str()),
        "HOME is forwarded unchanged"
    );
}

#[test]
fn worker_refuses_env_outside_the_allowlist() {
    let dir = tempfile::TempDir::with_prefix("rivect-iw-env-refused-").expect("fixture root");
    let program = env_sentinel(dir.path());
    let corpus = search_corpus("iw-env-refused");
    let cause = cause_of(isolated(
        &search_query(QueryKind::Path, &corpus.path, "*.rs"),
        &program,
        &helper(),
        None,
    ));
    assert_eq!(cause, IsolatedCause::WorkerEnvRejected);
}

#[test]
fn worker_applies_forwarded_global_git_excludes() {
    let mut tree = tree_of(
        "iw-global-excludes",
        &[
            ("src/kept.rs", "fn kept() {}\n"),
            ("src/globally_excluded.rs", "fn excluded() {}\n"),
        ],
    );
    let mut xdg = tempfile::TempDir::with_prefix("rivect-iw-xdg-").expect("fixture root");
    std::fs::create_dir_all(xdg.path().join("git")).expect("xdg git dir");
    std::fs::write(xdg.path().join("git/ignore"), "globally_excluded.rs\n")
        .expect("global excludes");
    let mut empty_xdg =
        tempfile::TempDir::with_prefix("rivect-iw-xdg-empty-").expect("fixture root");
    let mut home = tempfile::TempDir::with_prefix("rivect-iw-xdg-home-").expect("fixture root");
    let request = capture_request(&search_query(QueryKind::Path, &tree.path, "*.rs"), None);

    let mut served = |xdg: &mut tempfile::TempDir| -> BTreeSet<PathBuf> {
        let home_path = home.path().to_path_buf();
        let xdg_path = xdg.path().to_path_buf();
        let envelope = direct_worker(
            &request,
            &[("HOME", &home_path), ("XDG_CONFIG_HOME", &xdg_path)],
            || {
                support::retain_root(&mut home);
                support::retain_root(xdg);
                tree.retain();
            },
        );
        decode_via_parent(&envelope, WORKER_ANSWER_MAX)
            .expect("a path answer")
            .matches
            .into_iter()
            .map(|hit| hit.source.path)
            .collect()
    };
    let with_excludes = served(&mut xdg);
    assert!(
        with_excludes.contains(Path::new("src/kept.rs")),
        "{with_excludes:?}"
    );
    assert!(
        !with_excludes.contains(Path::new("src/globally_excluded.rs")),
        "the forwarded global excludes filter the walk: {with_excludes:?}"
    );
    let without = served(&mut empty_xdg);
    assert!(
        without.contains(Path::new("src/globally_excluded.rs")),
        "the exclusion comes from the forwarded XDG_CONFIG_HOME: {without:?}"
    );
}

#[test]
fn oversized_answer_is_output_limit_never_a_decoded_prefix() {
    let mut corpus = search_corpus("iw-oversized");
    let request = search_query(QueryKind::Path, &corpus.path, "*.rs");
    let envelope = real_envelope(&request, || corpus.retain());

    let over = decode_via_parent(&envelope, envelope.len() - 1);
    assert_eq!(cause_of(over), IsolatedCause::AnswerTooLarge);
    let exact = decode_via_parent(&envelope, envelope.len()).expect("an answer at the cap");
    assert_eq!(
        Ok(exact),
        query(&request).map_err(|error| error.error_code())
    );

    let dir = tempfile::TempDir::with_prefix("rivect-iw-flood-").expect("fixture root");
    let flood = program_shim(dir.path(), "flood", "exec /usr/bin/yes");
    let start = Instant::now();
    let cause = cause_of(isolated(&request, &flood, &helper(), None));
    assert_eq!(cause, IsolatedCause::AnswerTooLarge);
    assert!(
        start.elapsed() < MAX_INDEX_PARSE_TIME,
        "an endless answer is stopped at the cap, not the deadline"
    );

    let small = query_isolated(
        &request,
        &IsolatedRun {
            program: &worker(),
            helper: &helper(),
            deadline: None,
            cancel: &never,
            answer_cap: 128,
        },
    );
    assert_eq!(cause_of(small), IsolatedCause::AnswerTooLarge);
}

#[test]
fn worker_failure_classification_is_typed_per_seam() {
    let dir = tempfile::TempDir::with_prefix("rivect-iw-seams-").expect("fixture root");
    let mut corpus = search_corpus("iw-seams");
    let request = search_query(QueryKind::Path, &corpus.path, "*.rs");
    let source_fixture = tempfile::tempdir().expect("own the source-survival fixture");
    let unavailable = source_fixture.path().join("nonexecutable-helper");
    std::fs::write(&unavailable, b"not an executable\n").expect("write the refused helper");
    std::fs::set_permissions(&unavailable, std::fs::Permissions::from_mode(0o600))
        .expect("make the helper nonexecutable");
    let direct = Command::new(&unavailable)
        .env_clear()
        .spawn()
        .expect_err("the OS must refuse this executable before creating a payload");
    assert_eq!(
        direct.raw_os_error(),
        Some(13),
        "the independent source is EACCES"
    );
    let launch_error = isolated(&request, &worker(), &unavailable, None)
        .expect_err("the isolated launch must preserve the refused helper outcome");
    assert_eq!(launch_error.error_code(), ErrorCode::CapabilityUnavailable);
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&launch_error);
    let mut worker_source = false;
    let mut original_errno = false;
    while let Some(error) = source {
        worker_source |= error.downcast_ref::<WorkerError>().is_some();
        original_errno |= error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.raw_os_error() == Some(13));
        source = error.source();
    }
    assert!(
        worker_source && original_errno,
        "the public index consumer must retain the typed worker primary and original EACCES source: {launch_error:?}"
    );
    let envelope =
        String::from_utf8(real_envelope(&request, || corpus.retain())).expect("utf-8 envelope");
    let half = &envelope[..envelope.len() / 2];
    let real = helper();
    let rivect = worker();
    let near = || {
        Instant::now()
            .checked_add(Duration::from_millis(500))
            .expect("a near deadline")
    };
    let mut table = Vec::new();
    let mut expect =
        |fixture: &str, outcome: Result<QueryResult, ContextError>, tag: &str, code: ErrorCode| {
            let error = outcome.expect_err(fixture);
            let observed = match &error {
                ContextError::IsolatedRun { cause, .. } => cause.tag().to_string(),
                ContextError::WorkerRefused { tag, .. } => format!("worker_refused/{tag}"),
                other => panic!("{fixture}: not an isolated outcome: {other:?}"),
            };
            assert_eq!(observed, tag, "{fixture}: {error:?}");
            assert_eq!(error.error_code(), code, "{fixture}: {error:?}");
            table.push(format!("{fixture} -> {observed} -> {}", code.as_str()));
        };

    // Request.
    let mut non_utf8 = request.clone();
    non_utf8.root = PathBuf::from(OsStr::from_bytes(b"/tmp/rivect-\xff"));
    let (marker_program, marker) = marker_shim(dir.path());
    expect(
        "non-UTF-8 root",
        isolated(&non_utf8, &marker_program, &real, None),
        "request_unencodable",
        ErrorCode::InvalidInput,
    );
    assert!(!marker.exists(), "an unencodable request starts no worker");
    let past = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .expect("a past instant");
    expect(
        "past deadline",
        isolated(&request, &rivect, &real, Some(past)),
        "deadline_passed",
        ErrorCode::BudgetExhausted,
    );
    expect(
        "cancel before spawn",
        query_isolated(
            &request,
            &IsolatedRun {
                program: &rivect,
                helper: &real,
                deadline: None,
                cancel: &|| true,
                answer_cap: WORKER_ANSWER_MAX,
            },
        ),
        "cancelled_before_spawn",
        ErrorCode::Cancelled,
    );

    // Helper.
    expect(
        "missing helper",
        isolated(
            &request,
            &rivect,
            Path::new("/no/such/rivect-sandbox-helper"),
            None,
        ),
        "helper_unavailable",
        ErrorCode::CapabilityUnavailable,
    );
    // The helper shims never read the request, like a helper failing
    // before its exec: the prefixed exit decides, whichever of the exit
    // and the parent's request write comes first.
    let init = script(
        dir.path(),
        "helper-10",
        "#!/bin/sh\necho 'rivect-sandbox-helper: shim init failure' >&2\nexit 10\n",
    );
    expect(
        "helper exit 10",
        isolated(&request, &rivect, &init, None),
        "helper_init_failed",
        ErrorCode::CapabilityUnavailable,
    );
    let protocol = script(
        dir.path(),
        "helper-30",
        "#!/bin/sh\necho 'rivect-sandbox-helper: shim protocol failure' >&2\nexit 30\n",
    );
    expect(
        "helper exit 30",
        isolated(&request, &rivect, &protocol, None),
        "helper_protocol",
        ErrorCode::CapabilityUnavailable,
    );
    // A request larger than any pipe buffer: the unread write must meet
    // the closed pipe, and the helper's exit still decides.
    let mut large = request.clone();
    large.kind = QueryKind::Text;
    large.pattern = "a".repeat(900 * 1024);
    expect(
        "helper exit 30 before reading a large request",
        isolated(&large, &rivect, &protocol, None),
        "helper_protocol",
        ErrorCode::CapabilityUnavailable,
    );
    let (uncapped, custody) = uncapped_worker(&request);
    println!("{custody}");
    expect(
        "uncapped helper",
        uncapped,
        "worker_uncapped",
        ErrorCode::CapabilityUnavailable,
    );

    // Program.
    expect(
        "missing program",
        isolated(&request, &dir.path().join("no-such-worker"), &real, None),
        "worker_missing",
        ErrorCode::CapabilityUnavailable,
    );
    let not_executable = dir.path().join("not-executable");
    std::fs::write(&not_executable, "#!/bin/sh\nexit 0\n").expect("write 0644 program");
    std::fs::set_permissions(&not_executable, std::fs::Permissions::from_mode(0o644))
        .expect("chmod 0644");
    expect(
        "program mode 0644",
        isolated(&request, &not_executable, &real, None),
        "worker_exec_failed",
        ErrorCode::CapabilityUnavailable,
    );
    for (seam, (fixture, body, tag, code)) in [
        (
            "kill -SEGV",
            "kill -SEGV $$",
            "worker_crashed",
            ErrorCode::InternalError,
        ),
        (
            "kill -ABRT",
            "kill -ABRT $$",
            "resource_limit",
            ErrorCode::BudgetExhausted,
        ),
        (
            "exit 5",
            "exit 5",
            "worker_failed",
            ErrorCode::InternalError,
        ),
        (
            "empty stdout, exit 0",
            "exit 0",
            "empty_answer",
            ErrorCode::InternalError,
        ),
        (
            "garbage stdout, exit 0",
            "printf '%s' 'not an envelope'; exit 0",
            "worker_protocol",
            ErrorCode::InternalError,
        ),
        (
            "half envelope, exit 3",
            format!("printf '%s' {}; exit 3", sh_quote(half)).as_str(),
            "worker_failed",
            ErrorCode::InternalError,
        ),
        (
            "half envelope, kill -KILL",
            format!("printf '%s' {}; kill -KILL $$", sh_quote(half)).as_str(),
            "resource_limit",
            ErrorCode::BudgetExhausted,
        ),
        // A complete, valid envelope is still never decoded off exit 0.
        (
            "full envelope, exit 3",
            format!("printf '%s' {}; exit 3", sh_quote(&envelope)).as_str(),
            "worker_failed",
            ErrorCode::InternalError,
        ),
        (
            "full envelope, kill -KILL",
            format!("printf '%s' {}; kill -KILL $$", sh_quote(&envelope)).as_str(),
            "resource_limit",
            ErrorCode::BudgetExhausted,
        ),
        // Helper verdict codes from the worker itself carry no helper
        // prefix: they are the worker's own failure.
        (
            "exit 10 without the helper prefix",
            "exit 10",
            "worker_failed",
            ErrorCode::InternalError,
        ),
        (
            "exit 126 without the helper prefix",
            "exit 126",
            "worker_failed",
            ErrorCode::InternalError,
        ),
        (
            "exit 127 without the helper prefix",
            "exit 127",
            "worker_failed",
            ErrorCode::InternalError,
        ),
        (
            "kill -XCPU",
            "kill -XCPU $$",
            "resource_limit",
            ErrorCode::BudgetExhausted,
        ),
        (
            "endless answer",
            "exec /usr/bin/yes",
            "answer_too_large",
            ErrorCode::OutputLimit,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let program = program_shim(dir.path(), &format!("seam-{seam}"), body);
        expect(
            fixture,
            isolated(&request, &program, &real, None),
            tag,
            code,
        );
    }
    // The signal rides the cause: SIGXCPU (24 on Linux and macOS) is a
    // declared resource-limit signal, not a crash.
    let xcpu = program_shim(dir.path(), "seam-xcpu-signal", "kill -XCPU $$");
    assert_eq!(
        cause_of(isolated(&request, &xcpu, &real, None)),
        IsolatedCause::ResourceLimit { signal: SIGXCPU }
    );
    // A prefixed code outside the helper's verdicts is the run's failure.
    let prefixed_other = script(
        dir.path(),
        "helper-42",
        "#!/bin/sh\necho 'rivect-sandbox-helper: shim other failure' >&2\nexit 42\n",
    );
    expect(
        "helper-prefixed exit 42",
        isolated(&request, &rivect, &prefixed_other, None),
        "worker_failed",
        ErrorCode::InternalError,
    );
    // Small heap blocks the macOS relative RLIMIT lets through: only the
    // parent's footprint poll stops them, well before the deadline.
    #[cfg(target_os = "macos")]
    {
        let hoarder = script(
            dir.path(),
            "hoarder",
            "#!/usr/bin/perl\nlocal $/; my $request = <STDIN>;\nmy @held;\npush @held, 'x' x 1000 while 1;\n",
        );
        let start = Instant::now();
        let outcome = isolated(&request, &hoarder, &real, None);
        let elapsed = start.elapsed();
        expect(
            "perl pushing 1000-byte strings",
            outcome,
            "memory_exceeded",
            ErrorCode::BudgetExhausted,
        );
        assert!(
            elapsed < MAX_INDEX_PARSE_TIME,
            "the footprint poll stops the hoarder before the deadline: {elapsed:?}"
        );
    }
    let sleeper = program_shim(dir.path(), "sleeper", "exec /bin/sleep 30");
    expect(
        "exec sleep 30 past a 500 ms deadline",
        isolated(&request, &sleeper, &real, Some(near())),
        "deadline_exceeded",
        ErrorCode::BudgetExhausted,
    );
    let flip = Instant::now();
    let cancel_later = move || flip.elapsed() >= Duration::from_millis(200);
    expect(
        "cancel while sleeping",
        query_isolated(
            &request,
            &IsolatedRun {
                program: &sleeper,
                helper: &real,
                deadline: None,
                cancel: &cancel_later,
                answer_cap: WORKER_ANSWER_MAX,
            },
        ),
        "cancelled",
        ErrorCode::Cancelled,
    );

    // Envelope and refusals.
    let mut header: Value = serde_json::from_str(&envelope).expect("envelope JSON");
    header["protocol"] = Value::from(header["protocol"].as_u64().expect("protocol") + 1);
    let mismatched = dir.path().join("mismatched.json");
    std::fs::write(&mismatched, serde_json::to_vec(&header).expect("encode")).expect("write");
    let replay = program_shim(
        dir.path(),
        "replay",
        &format!("exec /bin/cat {}", quoted(&mismatched)),
    );
    expect(
        "envelope protocol + 1",
        isolated(&request, &replay, &real, None),
        "version_mismatch",
        ErrorCode::UnsupportedVersion,
    );
    let mut wire = capture_request(&request, None);
    wire["protocol"] = Value::from(wire["protocol"].as_u64().expect("protocol") + 1);
    let edited = dir.path().join("request-protocol.json");
    std::fs::write(&edited, serde_json::to_vec(&wire).expect("encode")).expect("write");
    let rejected = program_shim(
        dir.path(),
        "request-protocol",
        &format!(
            "exec /usr/bin/env -i {} {INDEX_WORKER_FLAG} < {}",
            quoted(&rivect),
            quoted(&edited)
        ),
    );
    expect(
        "request protocol + 1",
        isolated(&request, &rejected, &real, None),
        "request_rejected",
        ErrorCode::UnsupportedVersion,
    );
    expect(
        "env outside the allowlist",
        isolated(&request, &env_sentinel(dir.path()), &real, None),
        "worker_env_rejected",
        ErrorCode::InternalError,
    );
    let mut missing_root = request;
    missing_root.root = dir.path().join("no-such-root");
    expect(
        "typed engine refusal",
        isolated(&missing_root, &rivect, &real, None),
        "worker_refused/invalid_root",
        ErrorCode::NotFound,
    );
    assert_eq!(
        query(&missing_root).map_err(|error| error.error_code()),
        Err(ErrorCode::NotFound),
        "the refusal carries the in-process code"
    );

    for row in &table {
        println!("EVID-474 seam: {row}");
    }
}

/// Each parent stop kills and reaps the worker — `memory_exceeded`'s leg
/// is `footprint_stop_threshold_is_the_memory_budget` (macOS only).
#[test]
fn cancel_stop_kills_and_reaps_the_worker() {
    let real = helper();
    let mut dir = tempfile::TempDir::with_prefix("rivect-iw-cancel-reaps-").expect("fixture root");
    let mut corpus = search_corpus("iw-cancel-reaps");
    let request = search_query(QueryKind::Path, &corpus.path, "*.rs");
    let pid_file = dir.path().join("sleeper.pid");
    let sleeper = pid_shim(dir.path(), "sleeper", &pid_file, "exec /bin/sleep 30");
    let cancel = || recorded_pid(&pid_file).is_some();
    let outcome = query_isolated(
        &request,
        &IsolatedRun {
            program: &sleeper,
            helper: &real,
            deadline: None,
            cancel: &cancel,
            answer_cap: WORKER_ANSWER_MAX,
        },
    );
    assert_worker_gone(
        &pid_file,
        "cancelled",
        || {
            support::retain_root(&mut dir);
            corpus.retain();
        },
        move || assert_eq!(cause_of(outcome), IsolatedCause::Cancelled),
    );
}

#[test]
fn answer_cap_stop_kills_and_reaps_the_worker() {
    let real = helper();
    let mut dir = tempfile::TempDir::with_prefix("rivect-iw-cap-reaps-").expect("fixture root");
    let mut corpus = search_corpus("iw-cap-reaps");
    let request = search_query(QueryKind::Path, &corpus.path, "*.rs");
    let pid_file = dir.path().join("flood.pid");
    let flood = pid_shim(dir.path(), "flood", &pid_file, "exec /usr/bin/yes");
    let outcome = isolated(&request, &flood, &real, None);
    assert_worker_gone(
        &pid_file,
        "answer_too_large",
        || {
            support::retain_root(&mut dir);
            corpus.retain();
        },
        move || assert_eq!(cause_of(outcome), IsolatedCause::AnswerTooLarge),
    );
}

/// The footprint stop fires exactly above the budget (DEC-038): a worker
/// holding 64 MiB past it is stopped, one 128 MiB under it runs on to
/// the wall-kill.
///
/// Calibration: the over-budget leg has to cross before its 3 s caller
/// deadline, or the cause would read `deadline_exceeded` instead of
/// `memory_exceeded`. Measured on macOS 27.0 arm64 at 0.27 s running
/// alone and 0.69 s inside this suite's default parallelism, so the
/// bound still holds at ~11× the unloaded crossing. The under-budget
/// leg ends at its 1 s deadline plus the 2 s kill grace.
#[cfg(target_os = "macos")]
#[test]
fn footprint_stop_threshold_is_the_memory_budget() {
    let real = helper();
    let mut dir =
        tempfile::TempDir::with_prefix("rivect-iw-footprint-threshold-").expect("fixture root");
    let mut corpus = search_corpus("iw-footprint-threshold");
    let request = search_query(QueryKind::Path, &corpus.path, "*.rs");
    const MIB: u64 = 1024 * 1024;

    let pid_file = dir.path().join("over.pid");
    let over = holder_shim(
        dir.path(),
        "over",
        &pid_file,
        INDEX_WORKER_MEMORY_BUDGET + 64 * MIB,
    );
    let start = Instant::now();
    let outcome = isolated(
        &request,
        &over,
        &real,
        start.checked_add(Duration::from_secs(3)),
    );
    let elapsed = start.elapsed();
    assert_worker_gone(
        &pid_file,
        "budget + 64 MiB",
        || {
            support::retain_root(&mut dir);
            corpus.retain();
        },
        move || {
            let cause = cause_of(outcome);
            println!("EVID-474 footprint over budget: {elapsed:?} -> {cause:?}");
            assert_eq!(cause, IsolatedCause::MemoryExceeded);
        },
    );

    let pid_file = dir.path().join("under.pid");
    let under = holder_shim(
        dir.path(),
        "under",
        &pid_file,
        INDEX_WORKER_MEMORY_BUDGET - 128 * MIB,
    );
    let start = Instant::now();
    let outcome = isolated(
        &request,
        &under,
        &real,
        start.checked_add(Duration::from_secs(1)),
    );
    let elapsed = start.elapsed();
    assert_worker_gone(
        &pid_file,
        "budget - 128 MiB",
        || {
            support::retain_root(&mut dir);
            corpus.retain();
        },
        move || {
            let cause = cause_of(outcome);
            println!("EVID-474 footprint under budget: {elapsed:?} -> {cause:?}");
            assert_eq!(cause, IsolatedCause::DeadlineExceeded);
        },
    );
}

#[test]
fn isolated_cause_map_is_injective_and_matches_the_declared_table() {
    // The DEC-033 declared map with the DEC-038 `memory_exceeded` row,
    // literally.
    let declared: [(IsolatedCause, &str, ErrorCode); 22] = [
        (
            IsolatedCause::RequestUnencodable,
            "request_unencodable",
            ErrorCode::InvalidInput,
        ),
        (
            IsolatedCause::DeadlinePassed,
            "deadline_passed",
            ErrorCode::BudgetExhausted,
        ),
        (
            IsolatedCause::CancelledBeforeSpawn,
            "cancelled_before_spawn",
            ErrorCode::Cancelled,
        ),
        (
            IsolatedCause::HelperUnavailable,
            "helper_unavailable",
            ErrorCode::CapabilityUnavailable,
        ),
        (
            IsolatedCause::HelperInitFailed,
            "helper_init_failed",
            ErrorCode::CapabilityUnavailable,
        ),
        (
            IsolatedCause::HelperProtocol,
            "helper_protocol",
            ErrorCode::CapabilityUnavailable,
        ),
        (
            IsolatedCause::WorkerMissing,
            "worker_missing",
            ErrorCode::CapabilityUnavailable,
        ),
        (
            IsolatedCause::WorkerExecFailed,
            "worker_exec_failed",
            ErrorCode::CapabilityUnavailable,
        ),
        (IsolatedCause::Cancelled, "cancelled", ErrorCode::Cancelled),
        (
            IsolatedCause::DeadlineExceeded,
            "deadline_exceeded",
            ErrorCode::BudgetExhausted,
        ),
        (
            IsolatedCause::AnswerTooLarge,
            "answer_too_large",
            ErrorCode::OutputLimit,
        ),
        (
            IsolatedCause::MemoryExceeded,
            "memory_exceeded",
            ErrorCode::BudgetExhausted,
        ),
        (
            IsolatedCause::ResourceLimit { signal: SIGABRT },
            "resource_limit",
            ErrorCode::BudgetExhausted,
        ),
        (
            IsolatedCause::WorkerCrashed { signal: SIGSEGV },
            "worker_crashed",
            ErrorCode::InternalError,
        ),
        (
            IsolatedCause::WorkerFailed { code: 5 },
            "worker_failed",
            ErrorCode::InternalError,
        ),
        (
            IsolatedCause::EmptyAnswer,
            "empty_answer",
            ErrorCode::InternalError,
        ),
        (
            IsolatedCause::WorkerProtocol,
            "worker_protocol",
            ErrorCode::InternalError,
        ),
        (
            IsolatedCause::VersionMismatch,
            "version_mismatch",
            ErrorCode::UnsupportedVersion,
        ),
        (
            IsolatedCause::RequestRejected,
            "request_rejected",
            ErrorCode::UnsupportedVersion,
        ),
        (
            IsolatedCause::WorkerUncapped,
            "worker_uncapped",
            ErrorCode::CapabilityUnavailable,
        ),
        (
            IsolatedCause::WorkerEnvRejected,
            "worker_env_rejected",
            ErrorCode::InternalError,
        ),
        (
            IsolatedCause::ObserveFailed,
            "observe_failed",
            ErrorCode::CapabilityUnavailable,
        ),
    ];
    let mut tags = BTreeSet::new();
    for (cause, tag, code) in &declared {
        // Exhaustive with no `_` arm: a new cause breaks this build until
        // the declared table names it.
        match cause {
            IsolatedCause::RequestUnencodable
            | IsolatedCause::DeadlinePassed
            | IsolatedCause::CancelledBeforeSpawn
            | IsolatedCause::HelperUnavailable
            | IsolatedCause::HelperInitFailed
            | IsolatedCause::HelperProtocol
            | IsolatedCause::WorkerMissing
            | IsolatedCause::WorkerExecFailed
            | IsolatedCause::Cancelled
            | IsolatedCause::DeadlineExceeded
            | IsolatedCause::AnswerTooLarge
            | IsolatedCause::MemoryExceeded
            | IsolatedCause::ResourceLimit { .. }
            | IsolatedCause::WorkerCrashed { .. }
            | IsolatedCause::WorkerFailed { .. }
            | IsolatedCause::EmptyAnswer
            | IsolatedCause::WorkerProtocol
            | IsolatedCause::VersionMismatch
            | IsolatedCause::RequestRejected
            | IsolatedCause::WorkerUncapped
            | IsolatedCause::WorkerEnvRejected
            | IsolatedCause::ObserveFailed => {}
        }
        assert_eq!(
            (cause.tag(), cause.error_code()),
            (*tag, *code),
            "{cause:?}"
        );
        let wrapped = ContextError::IsolatedRun {
            cause: cause.clone(),
            source: None,
        };
        assert_eq!(
            wrapped.error_code(),
            *code,
            "{cause:?} through ContextError"
        );
        assert!(tags.insert(*tag), "tag {tag} is declared twice");
    }
    // The signal is carried, never part of the identity.
    assert_eq!(
        IsolatedCause::ResourceLimit { signal: SIGKILL }.tag(),
        IsolatedCause::ResourceLimit { signal: SIGABRT }.tag()
    );
}

#[test]
fn envelope_version_mismatch_is_never_decoded() {
    let mut corpus = search_corpus("iw-version");
    let request = search_query(QueryKind::Path, &corpus.path, "*.rs");
    let envelope = real_envelope(&request, || corpus.retain());
    assert_eq!(
        decode_via_parent(&envelope, WORKER_ANSWER_MAX).map_err(|error| error.error_code()),
        query(&request).map_err(|error| error.error_code()),
        "the unedited envelope decodes to the in-process answer"
    );
    let edited = |edit: &dyn Fn(&mut Value)| {
        let mut value: Value = serde_json::from_slice(&envelope).expect("envelope JSON");
        edit(&mut value);
        serde_json::to_vec(&value).expect("encode")
    };

    let protocol = edited(&|value| {
        value["protocol"] = Value::from(value["protocol"].as_u64().expect("protocol") + 1);
    });
    assert_eq!(
        cause_of(decode_via_parent(&protocol, WORKER_ANSWER_MAX)),
        IsolatedCause::VersionMismatch
    );
    let crate_version = edited(&|value| {
        value["crate_version"] = Value::from("0.0.0-other");
    });
    assert_eq!(
        cause_of(decode_via_parent(&crate_version, WORKER_ANSWER_MAX)),
        IsolatedCause::VersionMismatch
    );
    let body_field = edited(&|value| {
        let body = value["body"].as_object_mut().expect("body object");
        let key = body
            .keys()
            .find(|key| *key != "outcome")
            .cloned()
            .expect("a body field");
        body.remove(&key);
    });
    assert_eq!(
        cause_of(decode_via_parent(&body_field, WORKER_ANSWER_MAX)),
        IsolatedCause::WorkerProtocol
    );
    let truncated = &envelope[..envelope.len() - 1];
    assert_eq!(
        cause_of(decode_via_parent(truncated, WORKER_ANSWER_MAX)),
        IsolatedCause::WorkerProtocol
    );
}

#[test]
fn worker_refusal_code_must_match_its_tag() {
    let mut dir = tempfile::TempDir::with_prefix("rivect-iw-refusal-code-").expect("fixture root");
    let mut request = search_query(QueryKind::Path, dir.path(), "*");
    request.root = dir.path().join("no-such-root");
    let envelope = real_envelope(&request, || support::retain_root(&mut dir));
    let Err(ContextError::WorkerRefused { code, tag, .. }) =
        decode_via_parent(&envelope, WORKER_ANSWER_MAX)
    else {
        panic!("a missing root is the engine's own refusal");
    };
    assert_eq!((code, tag.as_str()), (ErrorCode::NotFound, "invalid_root"));

    let edited = |field: &str, value: &str| {
        let mut body: Value = serde_json::from_slice(&envelope).expect("envelope JSON");
        body["body"][field] = Value::from(value);
        serde_json::to_vec(&body).expect("encode")
    };
    // A worker cannot relabel a refusal: the code must be the one the
    // in-process engine gives that tag, and the tag one it can give.
    for (fixture, bytes) in [
        ("code denied for invalid_root", edited("code", "denied")),
        ("unknown tag", edited("tag", "no_such_refusal")),
        ("parent-only tag", edited("tag", "isolated_run")),
    ] {
        assert_eq!(
            cause_of(decode_via_parent(&bytes, WORKER_ANSWER_MAX)),
            IsolatedCause::WorkerProtocol,
            "{fixture}"
        );
    }
}

#[test]
fn helper_missing_is_helper_unavailable_never_in_process_fallback() {
    let dir = tempfile::TempDir::with_prefix("rivect-iw-no-helper-").expect("fixture root");
    let (program, marker) = marker_shim(dir.path());
    let corpus = search_corpus("iw-no-helper");
    let request = search_query(QueryKind::Path, &corpus.path, "*.rs");
    assert!(query(&request).is_ok(), "the query itself is answerable");
    for helper in [dir.path().join("no-such-helper"), dir.path().to_path_buf()] {
        let cause = cause_of(isolated(&request, &program, &helper, None));
        assert_eq!(cause, IsolatedCause::HelperUnavailable, "{helper:?}");
        assert_eq!(cause.error_code(), ErrorCode::CapabilityUnavailable);
    }
    assert!(!marker.exists(), "no worker ran without the helper");
}

#[test]
fn query_limit_ceiling_refused_before_spawn() {
    let dir = tempfile::TempDir::with_prefix("rivect-iw-limit-").expect("fixture root");
    let (program, marker) = marker_shim(dir.path());
    let corpus = search_corpus("iw-limit");

    let mut rows = search_query(QueryKind::Text, &corpus.path, "shared_marker");
    rows.limit = MAX_SYMBOL_ROWS + 1;
    let Err(ContextError::LimitTooLarge { limit, ceiling }) =
        isolated(&rows, &program, &helper(), None)
    else {
        panic!("a row bound past MAX_SYMBOL_ROWS is refused");
    };
    assert_eq!((limit, ceiling), (MAX_SYMBOL_ROWS + 1, MAX_SYMBOL_ROWS));
    assert!(!marker.exists(), "the refusal comes before any spawn");
    rows.limit = MAX_SYMBOL_ROWS;
    assert_eq!(
        cause_of(isolated(&rows, &program, &helper(), None)),
        IsolatedCause::EmptyAnswer,
        "the ceiling itself is served"
    );
    assert!(marker.exists(), "a bound at the ceiling spawns");
    std::fs::remove_file(&marker).expect("reset marker");

    for answer_cap in [WORKER_ANSWER_MAX, 1024 * 1024] {
        let mut source = search_query(QueryKind::Source, &corpus.path, "src/lib.rs");
        source.limit = usize::MAX;
        let run = IsolatedRun {
            program: &program,
            helper: &helper(),
            deadline: None,
            cancel: &never,
            answer_cap,
        };
        let Err(ContextError::LimitTooLarge { ceiling, .. }) = query_isolated(&source, &run) else {
            panic!("a byte bound past the answer cap is refused");
        };
        assert!(
            ceiling > 0 && ceiling * 6 < answer_cap,
            "the byte ceiling fits the cap at worst-case escaping: {ceiling}"
        );
        // Exactly (cap − the 64 KiB envelope margin) / 6, the worst-case
        // JSON escape per byte (AC-036c).
        assert_eq!(ceiling, (answer_cap - 64 * 1024) / 6);
        source.limit = ceiling + 1;
        assert!(matches!(
            query_isolated(&source, &run),
            Err(ContextError::LimitTooLarge { .. })
        ));
        assert!(!marker.exists(), "the refusal comes before any spawn");
        source.limit = ceiling;
        assert_eq!(
            cause_of(query_isolated(&source, &run)),
            IsolatedCause::EmptyAnswer
        );
        assert!(marker.exists(), "a byte bound at the ceiling spawns");
        std::fs::remove_file(&marker).expect("reset marker");
    }
}

#[test]
fn context_error_codes_are_pinned() {
    let io = || std::io::Error::other("io");
    let text_error = grep_regex::RegexMatcherBuilder::new()
        .build("(")
        .expect_err("an unclosed group");
    let glob_error = globset::Glob::new("[").expect_err("an unclosed class");
    let cases = [
        ContextError::UnknownKind {
            name: "x".into(),
            known: &[],
        },
        ContextError::UnsupportedKind {
            kind: "code.impact",
        },
        ContextError::InvalidRoot {
            path: "x".into(),
            source: io(),
        },
        ContextError::RootNotDirectory { path: "x".into() },
        ContextError::EmptyPattern {
            kind: "search.text",
        },
        ContextError::UnboundedLimit,
        ContextError::ScopeNotApplicable {
            kind: "source.slice",
        },
        ContextError::InvalidTextPattern {
            pattern: "(".into(),
            source: text_error,
        },
        ContextError::InvalidGlob {
            glob: "[".into(),
            source: glob_error,
        },
        ContextError::EscapedRoot { path: "..".into() },
        ContextError::InvalidAstPattern {
            pattern: "x".into(),
            languages: "rust".into(),
            detail: "d".into(),
        },
        ContextError::AstPatternTooLarge { limit: 1 },
        ContextError::SymbolFieldNotApplicable {
            field: "document",
            kind: "search.text",
        },
        ContextError::SymbolOpRequired,
        ContextError::SymbolPatternTooLarge { limit: 1 },
        ContextError::StaleDocumentVersion {
            path: "x".into(),
            pinned: 1,
            actual: 2,
        },
        ContextError::UnverifiableDocumentVersion { path: "x".into() },
        ContextError::UnsupportedPositionEncoding { encoding: "utf-16" },
        ContextError::IsolatedRun {
            cause: IsolatedCause::WorkerProtocol,
            source: None,
        },
        ContextError::IsolatedRun {
            cause: IsolatedCause::MemoryExceeded,
            source: None,
        },
        ContextError::WorkerRefused {
            code: ErrorCode::Conflict,
            tag: "stale_document_version".into(),
            message: "m".into(),
        },
        ContextError::LimitTooLarge {
            limit: 2,
            ceiling: 1,
        },
    ];
    for error in &cases {
        let expected = match error {
            ContextError::UnsupportedKind { .. } => ErrorCode::CapabilityUnavailable,
            ContextError::InvalidRoot { .. } => ErrorCode::NotFound,
            ContextError::EscapedRoot { .. } => ErrorCode::Denied,
            ContextError::StaleDocumentVersion { .. }
            | ContextError::UnverifiableDocumentVersion { .. } => ErrorCode::Conflict,
            ContextError::UnknownKind { .. }
            | ContextError::RootNotDirectory { .. }
            | ContextError::EmptyPattern { .. }
            | ContextError::UnboundedLimit
            | ContextError::ScopeNotApplicable { .. }
            | ContextError::InvalidTextPattern { .. }
            | ContextError::InvalidGlob { .. }
            | ContextError::InvalidAstPattern { .. }
            | ContextError::AstPatternTooLarge { .. }
            | ContextError::SymbolFieldNotApplicable { .. }
            | ContextError::SymbolOpRequired
            | ContextError::SymbolPatternTooLarge { .. }
            | ContextError::UnsupportedPositionEncoding { .. }
            | ContextError::LimitTooLarge { .. } => ErrorCode::InvalidInput,
            ContextError::IsolatedRun {
                cause: IsolatedCause::MemoryExceeded,
                ..
            } => ErrorCode::BudgetExhausted,
            ContextError::IsolatedRun { .. } => ErrorCode::InternalError,
            ContextError::WorkerRefused { .. } => ErrorCode::Conflict,
        };
        assert_eq!(error.error_code(), expected, "{error:?}");
    }
}

#[test]
fn worker_error_codes_are_pinned() {
    let io = || std::io::Error::other("io");
    let overflow = u8::try_from(300_u32).expect_err("300 overflows u8");
    let path = || PathBuf::from("/tmp/target");
    let cases = [
        WorkerError::ScopeRootUnavailable { source: io() },
        WorkerError::TargetMissing { target: path() },
        WorkerError::OutsideScope { target: path() },
        WorkerError::MetadataUnavailable { source: io() },
        WorkerError::NotRegularFile { target: path() },
        WorkerError::TargetChanged { target: path() },
        WorkerError::ReadFailed { source: io() },
        WorkerError::WriteFailed { source: io() },
        WorkerError::WriteMutationFailed { source: io() },
        WorkerError::WriteUnavailable,
        WorkerError::ExecUnavailable,
        WorkerError::EgressUnavailable,
        WorkerError::WriteTooLarge,
        WorkerError::WriteLengthOverflow { source: overflow },
        WorkerError::TooLarge,
        WorkerError::SandboxDenied { target: path() },
        WorkerError::SandboxSpawnFailed { source: io() },
        WorkerError::SandboxUnavailable { reason: "r".into() },
        WorkerError::ConfinedRunTimedOut,
        WorkerError::ConfinedRunKilled { source: io() },
        WorkerError::WriteIdentityUnattested {
            cause: Unattested::Unsupported,
        },
        WorkerError::WriteIdentityUnavailable {
            source: ReuseTokenError::Io(io()),
        },
    ];
    for error in cases {
        let expected = match &error {
            WorkerError::OwnedLaunch { .. }
            | WorkerError::OwnedPreparation { .. }
            | WorkerError::OwnedParent { .. }
            | WorkerError::OwnedReleaseUnavailable
            | WorkerError::OwnedSeccomp { .. }
            | WorkerError::SandboxSpawnFailed { .. }
            | WorkerError::SandboxUnavailable { .. }
            | WorkerError::ConfinedRunTimedOut
            | WorkerError::ConfinedRunKilled { .. }
            | WorkerError::WriteIdentityUnattested { .. }
            | WorkerError::WriteIdentityUnavailable { .. } => ErrorCode::CapabilityUnavailable,
            WorkerError::WriteMutationFailed { .. } => ErrorCode::OutcomeUnknown,
            WorkerError::ScopeRootUnavailable { .. }
            | WorkerError::TargetMissing { .. }
            | WorkerError::OutsideScope { .. }
            | WorkerError::MetadataUnavailable { .. }
            | WorkerError::NotRegularFile { .. }
            | WorkerError::TargetChanged { .. }
            | WorkerError::ReadFailed { .. }
            | WorkerError::WriteFailed { .. }
            | WorkerError::WriteUnavailable
            | WorkerError::ExecUnavailable
            | WorkerError::EgressUnavailable
            | WorkerError::WriteTooLarge
            | WorkerError::WriteLengthOverflow { .. }
            | WorkerError::TooLarge
            | WorkerError::SandboxDenied { .. } => ErrorCode::Denied,
        };
        let display = error.to_string();
        if matches!(error, WorkerError::WriteIdentityUnavailable { .. }) {
            assert!(
                matches!(
                    std::error::Error::source(&error)
                        .and_then(|source| source.downcast_ref::<ReuseTokenError>()),
                    Some(ReuseTokenError::Io(_))
                ),
                "{display}"
            );
        }
        assert_eq!(
            ExecutorError::Worker(error).error_code(),
            expected,
            "{display}"
        );
    }
}

/// The benign corpus both paths answer: every kind, both ignore
/// policies, pins, typed refusals, and Rivect's own `src/`.
fn benign_queries(
    search: &Path,
    ast: &Path,
    symbols: &Path,
    own_src: &Path,
    missing: &Path,
) -> Vec<(&'static str, Query)> {
    let mut include = search_query(QueryKind::Text, search, "shared_marker");
    include.ignore = IgnorePolicy::Include;
    let mut scoped = search_query(QueryKind::Path, search, "*");
    scoped.scope_glob = Some("src/**".into());
    let mut truncated = search_query(QueryKind::Text, search, "repeated_marker");
    truncated.limit = 3;
    let mut pinned = symbol_query(symbols, "helper", SymbolOp::Definition);
    pinned.document = Some(DocumentPin {
        path: PathBuf::from("src/lib.rs"),
        version: None,
        encoding: None,
    });
    vec![
        (
            "text",
            search_query(QueryKind::Text, search, "shared_marker"),
        ),
        ("text include", include),
        ("text truncated", truncated),
        ("path", search_query(QueryKind::Path, search, "*.rs")),
        ("path scoped", scoped),
        (
            "source",
            search_query(QueryKind::Source, search, "src/unicode.rs"),
        ),
        (
            "ast rust",
            search_query(QueryKind::Ast, ast, "fn $NAME() {}"),
        ),
        (
            "ast ts",
            search_query(QueryKind::Ast, ast, "function $F($$$A) { $$$B }"),
        ),
        (
            "symbol definition",
            symbol_query(symbols, "helper", SymbolOp::Definition),
        ),
        (
            "symbol references",
            symbol_query(symbols, "helper", SymbolOp::References),
        ),
        (
            "symbol type",
            symbol_query(symbols, "helper", SymbolOp::Type),
        ),
        ("symbol pinned", pinned),
        (
            "own src symbol",
            symbol_query(own_src, "query_isolated", SymbolOp::References),
        ),
        (
            "own src ast",
            search_query(QueryKind::Ast, own_src, "fn $NAME() {}"),
        ),
        (
            "own src text",
            search_query(QueryKind::Text, own_src, "IsolatedCause"),
        ),
        ("invalid regex", search_query(QueryKind::Text, search, "(")),
        (
            "escaped source",
            search_query(QueryKind::Source, search, "../outside"),
        ),
        ("missing root", search_query(QueryKind::Path, missing, "*")),
        ("graph", search_query(QueryKind::Graph, search, "x")),
    ]
}

#[test]
fn benign_corpus_isolated_equals_in_process() {
    let search = search_corpus("iw-benign");
    let ast = ast_corpus("iw-benign");
    let symbols = symbol_corpus("iw-benign");
    let own_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let missing_owner =
        tempfile::TempDir::with_prefix("rivect-iw-benign-missing-").expect("fixture root");
    let missing = missing_owner.path().join("absent");
    let (mut answers, mut errors) = (0, 0);
    for (label, request) in
        benign_queries(&search.path, &ast.path, &symbols.path, &own_src, &missing)
    {
        let in_process = query(&request);
        let separate = isolated(&request, &worker(), &helper(), None);
        match (&in_process, &separate) {
            (Ok(expected), Ok(actual)) => {
                assert_eq!(actual, expected, "{label}");
                answers += 1;
            }
            (Err(expected), Err(actual)) => {
                assert!(
                    matches!(actual, ContextError::WorkerRefused { .. }),
                    "{label}: an engine refusal crosses as WorkerRefused: {actual:?}"
                );
                assert_eq!(actual.error_code(), expected.error_code(), "{label}");
                errors += 1;
            }
            _ => panic!("{label}: in-process {in_process:?} vs isolated {separate:?}"),
        }
    }
    println!("EVID-474 benign equivalence: {answers} answers, {errors} refusals equal");
    assert!(answers >= 15 && errors >= 3);
}

/// A non-UTF-8 entry name (Linux allows one; APFS does not) has no JSON
/// spelling: the worker answers partial with that entry failed, never a
/// lost envelope. The entry holds two matching lines, so the count also
/// pins that `EntriesFailed` counts entries — one dropped entry, not one
/// dropped match.
#[cfg(target_os = "linux")]
#[test]
fn non_utf8_entry_name_answers_partial_never_worker_failed() {
    let tree = tree_of(
        "iw-non-utf8-name",
        &[("good.txt", "shared_marker\n"), ("other.txt", "x\n")],
    );
    let bad = tree.path.join(OsStr::from_bytes(b"bad\xff.txt"));
    std::fs::write(&bad, "shared_marker\nshared_marker\n").expect("write the non-UTF-8 name");
    for kind in [QueryKind::Path, QueryKind::Text] {
        let pattern = if kind == QueryKind::Path {
            "*.txt"
        } else {
            "shared_marker"
        };
        let request = search_query(kind, &tree.path, pattern);
        let result = isolated(&request, &worker(), &helper(), None)
            .unwrap_or_else(|error| panic!("{kind:?}: the query answers, got {error:?}"));
        assert_eq!(
            result.completeness,
            Completeness::Partial {
                reasons: vec![PartialReason::EntriesFailed { count: 1 }]
            },
            "{kind:?}"
        );
        assert!(
            result
                .matches
                .iter()
                .any(|hit| hit.source.path == Path::new("good.txt")),
            "{kind:?}: the encodable entries are served: {result:?}"
        );
        assert!(
            result
                .matches
                .iter()
                .all(|hit| hit.source.path.to_str().is_some()),
            "{kind:?}"
        );
    }
}

fn percentile(samples: &mut [Duration], pct: usize) -> Duration {
    samples.sort();
    samples[(samples.len() - 1) * pct / 100]
}

/// This process's CPU time (user + system).
#[cfg(target_os = "macos")]
fn process_cpu() -> Duration {
    let output = Command::new("/bin/ps")
        .args(["-o", "cputime=", "-p", &std::process::id().to_string()])
        .output()
        .expect("ps");
    let text = String::from_utf8(output.stdout).expect("ps output");
    // `[[hh:]mm:]ss.cc`
    text.trim().split(':').fold(Duration::ZERO, |total, part| {
        total * 60 + Duration::from_secs_f64(part.parse::<f64>().expect("ps time field"))
    })
}

/// This process's CPU time (user + system) from `/proc/self/stat`.
#[cfg(target_os = "linux")]
fn process_cpu() -> Duration {
    let stat = std::fs::read_to_string("/proc/self/stat").expect("proc stat");
    let fields: Vec<&str> = stat
        .rsplit_once(')')
        .expect("stat comm")
        .1
        .split_whitespace()
        .collect();
    // utime and stime are stat fields 14 and 15; `fields` starts at 3.
    let ticks: u64 =
        fields[11].parse::<u64>().expect("utime") + fields[12].parse::<u64>().expect("stime");
    let hz = Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .expect("getconf");
    let hz: u64 = String::from_utf8(hz.stdout)
        .expect("clk tck")
        .trim()
        .parse()
        .expect("clk tck value");
    Duration::from_millis(ticks * 1000 / hz)
}

#[test]
#[ignore = "measurement: run alone on a quiet host with --test-threads=1 (EVID-474)"]
fn isolated_query_cost_is_recorded() {
    let search = search_corpus("iw-cost");
    let ast = ast_corpus("iw-cost");
    let symbols = symbol_corpus("iw-cost");
    let own_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let missing_owner =
        tempfile::TempDir::with_prefix("rivect-iw-cost-missing-").expect("fixture root");
    let missing = missing_owner.path().join("absent");
    let queries = benign_queries(&search.path, &ast.path, &symbols.path, &own_src, &missing);
    let (mut isolated_samples, mut in_process_samples) = (Vec::new(), Vec::new());
    for _ in 0..20 {
        for (_, request) in &queries {
            let start = Instant::now();
            drop(query(request));
            in_process_samples.push(start.elapsed());
            let start = Instant::now();
            drop(isolated(request, &worker(), &helper(), None));
            isolated_samples.push(start.elapsed());
        }
    }
    println!(
        "EVID-474 cost: isolated p50 {:?} p95 {:?}; in-process p50 {:?} p95 {:?}; n = {}",
        percentile(&mut isolated_samples, 50),
        percentile(&mut isolated_samples, 95),
        percentile(&mut in_process_samples, 50),
        percentile(&mut in_process_samples, 95),
        isolated_samples.len()
    );

    let tree = slow_tree("iw-cost-hostile");
    let request = search_query(QueryKind::Ast, &tree.path, SLOW_PATTERN);
    let cpu_before = process_cpu();
    let start = Instant::now();
    let outcome = isolated(
        &request,
        &worker(),
        &helper(),
        start.checked_add(Duration::from_secs(8)),
    );
    let wall = start.elapsed();
    let cpu = process_cpu().saturating_sub(cpu_before);
    println!("EVID-474 cost: hostile run {wall:?} -> {outcome:?}; parent CPU {cpu:?}");
    assert!(wall >= Duration::from_secs(8), "the run lasted: {wall:?}");
    assert!(
        cpu.as_secs_f64() <= wall.as_secs_f64() * 0.10,
        "the parent idles while the worker runs: {cpu:?} of {wall:?}"
    );
}
