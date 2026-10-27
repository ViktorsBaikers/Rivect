//! The confined helper binary (DEC-009/DEC-018): applies the OS sandbox —
//! Seatbelt `sandbox_init` on macOS, Landlock (deny-by-default) on Linux —
//! then performs ONE admitted data-plane operation on an fd inherited from
//! the parent, or launches a confined program under rlimits and a closed fd
//! table. The host process never performs data-plane I/O for admitted
//! effects; this child is where the bytes move, and it can never re-open the
//! admitted target by path (it only ever holds the inherited fd).
//!
//! This crate is the one place `unsafe` is allowed (DEC-009): the syscall
//! surface (sandbox_init, landlock, setrlimit, execv, open) has no safe
//! standard-library equivalent. Every block carries its SAFETY comment.
//!
//! Modes (parsed from argv, never from the environment):
//! ```text
//!   launch [--memory-budget <bytes> | --resource-profile check] -- <program> [args...]
//!       rlimits + cloexec sweep, then exec the confined chain; the budget
//!       additionally caps the program's memory, the check profile raises
//!       the finite limits to the isolated-Cargo ceilings (DEC-040)
//!   confined <macos|linux> <read|write> [<profile>]
//!       apply the sandbox, then read fd 0 -> stdout (read) or
//!       read stdin -> fd 1 after truncating it (write)
//!   probe-write <macos|linux> <profile|scope> <path>
//!       apply the sandbox, then open the probe artifact for write
//!       (O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW) and write one byte
//!   check-setup <attempt>                      (Linux only)
//!       inside the fresh user/mount/PID/net namespace: validate the empty
//!       canonical <attempt>/rw, mount the bounded tmpfs on it, then drop
//!       namespace privileges — a typed refusal, never a directory fallback
//! ```
//! Exit verdicts are the crate's `EXIT_*` codes: 0 ok, 10 sandbox init
//! failure, 20 data I/O failure before any mutation, 21 data failure
//! after the write truncated its target, 30 protocol error, 126/127
//! launch exec failure — the host maps them to the worker's typed
//! errors. Diagnostics go to stderr (fd 2), which is the only stream the
//! host captures.

use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::os::fd::FromRawFd as _;
use std::process::ExitCode;

#[cfg(target_os = "linux")]
use rivect_sandbox_helper::CHECK_AS_BYTES;
use rivect_sandbox_helper::{
    CHECK_CPU_SECONDS, CHECK_FSIZE_BYTES, CHECK_NOFILE, CHECK_NPROC_HEADROOM, EXIT_DATA_IO,
    EXIT_DATA_MUTATED, EXIT_LAUNCH_EXEC, EXIT_LAUNCH_NOT_FOUND, EXIT_OK, EXIT_PROTOCOL,
    EXIT_SANDBOX_INIT, INDEX_WORKER_MEMORY_BUDGET, MEMORY_BUDGET_FLAG, RESOURCE_PROFILE_CHECK,
    RESOURCE_PROFILE_FLAG, RLIMIT_AS, Rlimit,
};
#[cfg(target_os = "linux")]
use std::ffi::OsStr;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;

/// Data-plane byte budget, mirroring the executor's read cap: a confined
/// child can never move more bytes than the admitted effect's own size.
const DATA_MAX_BYTES: usize = 1 << 20;

/// Stdio fd range the inherited data fd lives on (0/1/2).
const STDIO_TOP_FD: i32 = 2;

/// `open(2)` write-only.
const O_WRONLY: i32 = 0o1;
/// `open(2)` create. Darwin and Linux disagree on the bit.
#[cfg(target_os = "macos")]
const O_CREAT: i32 = 0x0200;
#[cfg(target_os = "linux")]
const O_CREAT: i32 = 0o100;
/// `open(2)` exclusive create.
#[cfg(target_os = "macos")]
const O_EXCL: i32 = 0x0800;
#[cfg(target_os = "linux")]
const O_EXCL: i32 = 0o200;
/// `open(2)` do not follow symlinks. The bit is not uniform across Linux
/// arch families: x86 carries its historic value, every asm-generic arch
/// (aarch64 here) the other — and a wrong pick silently names O_DIRECT,
/// which open(2) rejects with EINVAL — so any other arch fails the build
/// instead of guessing.
#[cfg(target_os = "macos")]
const O_NOFOLLOW: i32 = 0x0100;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_NOFOLLOW: i32 = 0o100_000;
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
const O_NOFOLLOW: i32 = {
    compile_error!(
        "rivect-sandbox-helper: no open(2) O_NOFOLLOW value is pinned for this linux architecture"
    );
    0
};

// The syscall surface: one module so every `unsafe` block has a named home.
mod sys {
    use std::os::raw::{c_char, c_int, c_void};
    #[cfg(target_os = "linux")]
    use std::os::raw::{c_long, c_ulong};

    use rivect_sandbox_helper::Rlimit;

    // SAFETY: the declarations mirror the platform libc/kernel ABI; every
    // call site passes owned NUL-terminated data and checks the return.
    #[cfg(target_os = "linux")]
    unsafe extern "C" {
        pub fn syscall(number: c_long, ...) -> c_long;
        pub fn prctl(option: c_int, ...) -> c_int;
        pub fn setrlimit(resource: c_int, rlim: *const Rlimit) -> c_int;
        pub fn getrlimit(resource: c_int, rlim: *mut Rlimit) -> c_int;
        pub fn fchdir(fd: c_int) -> c_int;
        pub fn close(fd: c_int) -> c_int;
        pub fn execv(path: *const c_char, argv: *const *const c_char) -> c_int;
        pub fn open(path: *const c_char, oflag: c_int, mode: c_int) -> c_int;
        pub fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
        pub fn __errno_location() -> *mut c_int;
        pub fn mount(
            source: *const c_char,
            target: *const c_char,
            filesystemtype: *const c_char,
            mountflags: c_ulong,
            data: *const c_void,
        ) -> c_int;
    }

    /// glibc/musl `<linux/capability.h>` `struct __user_cap_header_struct`
    /// with `_LINUX_CAPABILITY_VERSION_3`: a version word plus a pid.
    #[cfg(target_os = "linux")]
    #[repr(C)]
    pub struct CapHeader {
        pub version: u32,
        pub pid: i32,
    }

    /// `struct __user_cap_data_struct`: one capability word triple; the V3
    /// ABI passes two of them, covering capabilities 0–63.
    #[cfg(target_os = "linux")]
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct CapData {
        pub effective: u32,
        pub permitted: u32,
        pub inheritable: u32,
    }

    #[cfg(target_os = "linux")]
    const _: () = assert!(size_of::<CapData>() == 12);
    #[cfg(target_os = "linux")]
    const _: () = assert!(size_of::<CapHeader>() == 8);

    // SAFETY: the declarations mirror the platform libc/kernel ABI; every
    // call site passes owned NUL-terminated data and checks the return.
    #[cfg(target_os = "macos")]
    unsafe extern "C" {
        pub fn sandbox_init(
            profile: *const c_char,
            flags: u32,
            errorbuf: *mut *mut c_char,
        ) -> c_int;
        pub fn sandbox_free_error(errorbuf: *mut c_char);
        pub fn setrlimit(resource: c_int, rlim: *const Rlimit) -> c_int;
        pub fn getrlimit(resource: c_int, rlim: *mut Rlimit) -> c_int;
        pub fn close(fd: c_int) -> c_int;
        pub fn execv(path: *const c_char, argv: *const *const c_char) -> c_int;
        pub fn open(path: *const c_char, oflag: c_int, mode: c_int) -> c_int;
        pub fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
        pub fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
        pub fn __error() -> *mut c_int;
    }

    /// glibc/musl `struct dirent` on 64-bit Linux: `d_name` is the last field.
    #[cfg(target_os = "linux")]
    #[repr(C)]
    pub struct Dirent {
        pub d_ino: u64,
        pub d_off: i64,
        pub d_reclen: u16,
        pub d_type: u8,
        pub d_name: [c_char; 256],
    }

    /// Darwin `struct dirent`: `d_name` is the last field.
    #[cfg(target_os = "macos")]
    #[repr(C)]
    pub struct Dirent {
        pub d_ino: u64,
        pub d_seekoff: u64,
        pub d_reclen: u16,
        pub d_namlen: u16,
        pub d_type: u8,
        pub d_name: [c_char; 1024],
    }

    // SAFETY: POSIX directory iteration; `Dirent::d_name` is a
    // NUL-terminated C string at the documented offset on each platform.
    unsafe extern "C" {
        pub fn opendir(name: *const c_char) -> *mut c_void;
        pub fn readdir(dirp: *mut c_void) -> *mut Dirent;
        pub fn closedir(dirp: *mut c_void) -> c_int;
        pub fn dirfd(dirp: *mut c_void) -> c_int;
    }
}

fn main() -> ExitCode {
    let args: Vec<CString> = std::env::args_os()
        .map(|arg| CString::new(arg.into_encoded_bytes()))
        .collect::<Result<_, _>>()
        .unwrap_or_else(|_| {
            eprintln!("rivect-sandbox-helper: an argument contains an interior NUL");
            std::process::exit(EXIT_PROTOCOL);
        });
    #[cfg(target_os = "linux")]
    if args.get(1).is_some_and(|arg| arg.as_bytes() == b"owned") {
        owned::run(&args);
    }
    // The check profile must be chosen before any hard rlimit exists: a
    // hard limit can only tighten, so deciding after apply_rlimits would
    // clamp a Cargo chain to the worker defaults (D-115). An invalid
    // launch grammar fails here with the verdict cmd_launch would give —
    // still before any exec.
    let profile = match args.get(1).map(|arg| arg.as_bytes()) {
        Some(b"launch") => match launch_options(&args) {
            Ok((_, profile, _)) => profile,
            Err(code) => return exit(code),
        },
        _ => ResourceProfile::Worker,
    };
    if let Err(code) = apply_rlimits(profile) {
        return exit(code);
    }
    // Every mode wastes no time on the parent's file descriptor table: the
    // only fds that exist here are the inherited stdio (0/1/2) — close
    // anything else before any sandbox exists, so a confined program can
    // never inherit a stray fd (S6). RLIMIT_NOFILE does not close existing
    // fds, so the sweep must cover the whole table, not a 256-wide window.
    if let Err(code) = close_stray_fds() {
        return exit(code);
    }
    let verdict = match args.get(1).map(|arg| arg.as_bytes()) {
        Some(b"launch") => cmd_launch(&args),
        Some(b"confined") => cmd_confined(&args),
        Some(b"probe-write") => cmd_probe_write(&args),
        Some(b"check-setup") => cmd_check_setup(&args),
        _ => {
            eprintln!("rivect-sandbox-helper: unknown mode");
            Err(EXIT_PROTOCOL)
        }
    };
    let code = match verdict {
        Ok(()) => EXIT_OK,
        Err(code) => code,
    };
    exit(code)
}

fn exit(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(EXIT_PROTOCOL as u8))
}

// ---------------------------------------------------------------------------
// launch: rlimits + exec the confined chain
// ---------------------------------------------------------------------------

/// Executes the launcher chain (`sandbox-exec`, `unshare`/`setpriv`, then
/// the confined program). The rlimits set at startup — the worker
/// defaults, or the check profile main already applied — survive every
/// exec in the chain; this is what bounds a fork-bombed or disk-filling
/// confined program — and the fd table is already closed above.
fn cmd_launch(args: &[CString]) -> Result<(), i32> {
    // The profile is ignored here: main applied it before this parse.
    let (budget, _profile, dashdash) = launch_options(args)?;
    let program = args.get(dashdash + 1).ok_or_else(|| {
        eprintln!("rivect-sandbox-helper: launch requires a program");
        EXIT_PROTOCOL
    })?;
    let mut pointers: Vec<*const std::os::raw::c_char> = args[dashdash + 1..]
        .iter()
        .map(|arg| arg.as_ptr())
        .collect();
    pointers.push(std::ptr::null());
    // Measured and set last, so no helper allocation lands after the cap.
    if let Some(budget) = budget {
        apply_memory_budget(budget)?;
    }
    // SAFETY: the argv is a NUL-terminated list of NUL-terminated strings
    // built above from owned CStrings that outlive the call. execv replaces
    // the process image; a returned value is the failure path checked next.
    let attempted = unsafe { sys::execv(program.as_ptr(), pointers.as_ptr()) };
    if attempted == -1 {
        let error = std::io::Error::last_os_error();
        eprintln!(
            "rivect-sandbox-helper: exec failed for {}: {error}",
            program.to_string_lossy()
        );
        return Err(if error.kind() == std::io::ErrorKind::NotFound {
            EXIT_LAUNCH_NOT_FOUND
        } else {
            EXIT_LAUNCH_EXEC
        });
    }
    Err(EXIT_LAUNCH_EXEC)
}

/// The `launch` resource profile: the worker defaults, or the check
/// profile's finite Cargo ceilings (DEC-040).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResourceProfile {
    /// The index-worker defaults — tight enough for a parser, too tight
    /// to host a Cargo chain (D-115).
    Worker,
    /// The isolated-check ceilings: a measured NPROC with headroom, wide
    /// NOFILE/FSIZE/CPU, and (Linux) an 8 GiB address space.
    Check,
}

/// One `--memory-budget <bytes>` at `index`; returns the next index.
/// A second budget, or any budget beside the check profile, fails closed.
fn budget_flag(
    args: &[CString],
    index: usize,
    budget: Option<u64>,
    profile: ResourceProfile,
) -> Result<(Option<u64>, usize), i32> {
    if budget.is_some() {
        eprintln!("rivect-sandbox-helper: {MEMORY_BUDGET_FLAG} given more than once");
        return Err(EXIT_PROTOCOL);
    }
    if profile == ResourceProfile::Check {
        eprintln!(
            "rivect-sandbox-helper: {RESOURCE_PROFILE_FLAG} cannot combine with {MEMORY_BUDGET_FLAG}"
        );
        return Err(EXIT_PROTOCOL);
    }
    let value = args
        .get(index + 1)
        .map(|value| value.to_bytes())
        .unwrap_or_default();
    let Some(parsed) = memory_budget(value) else {
        eprintln!(
            "rivect-sandbox-helper: {MEMORY_BUDGET_FLAG} must be a canonical decimal byte count from 1 to {INDEX_WORKER_MEMORY_BUDGET}"
        );
        return Err(EXIT_PROTOCOL);
    };
    Ok((Some(parsed), index + 2))
}

/// One `--resource-profile check` at `index`; returns the next index. A
/// second profile, or any profile beside a budget, fails closed.
fn profile_flag(
    args: &[CString],
    index: usize,
    budget: Option<u64>,
) -> Result<(ResourceProfile, usize), i32> {
    if budget.is_some() {
        eprintln!(
            "rivect-sandbox-helper: {RESOURCE_PROFILE_FLAG} cannot combine with {MEMORY_BUDGET_FLAG}"
        );
        return Err(EXIT_PROTOCOL);
    }
    let value = args
        .get(index + 1)
        .map(|value| value.to_bytes())
        .unwrap_or_default();
    if value != RESOURCE_PROFILE_CHECK.as_bytes() {
        eprintln!(
            "rivect-sandbox-helper: {RESOURCE_PROFILE_FLAG} must be {RESOURCE_PROFILE_CHECK}"
        );
        return Err(EXIT_PROTOCOL);
    }
    Ok((ResourceProfile::Check, index + 2))
}

/// Parses the tokens between `launch` and the first `--` (later `--`
/// belong to the launched chain) and returns the budget, the resource
/// profile, and the separator index. At most one `--memory-budget <bytes>`
/// OR one `--resource-profile check` is accepted — the two caps describe
/// different launches — and any other token fails closed before exec, so a
/// caller that meant to bound the program can never launch it unbounded.
fn launch_options(args: &[CString]) -> Result<(Option<u64>, ResourceProfile, usize), i32> {
    let mut budget = None;
    let mut profile = ResourceProfile::Worker;
    let mut index = 2;
    loop {
        let Some(token) = args.get(index) else {
            eprintln!("rivect-sandbox-helper: launch requires a -- separator");
            return Err(EXIT_PROTOCOL);
        };
        match token.to_bytes() {
            b"--" => return Ok((budget, profile, index)),
            flag if flag == MEMORY_BUDGET_FLAG.as_bytes() => {
                let (parsed, next) = budget_flag(args, index, budget, profile)?;
                budget = parsed;
                index = next;
            }
            flag if flag == RESOURCE_PROFILE_FLAG.as_bytes() => {
                if profile == ResourceProfile::Check {
                    eprintln!(
                        "rivect-sandbox-helper: {RESOURCE_PROFILE_FLAG} given more than once"
                    );
                    return Err(EXIT_PROTOCOL);
                }
                let (selected, next) = profile_flag(args, index, budget)?;
                profile = selected;
                index = next;
            }
            _ => {
                eprintln!(
                    "rivect-sandbox-helper: unknown launch option {:?}",
                    token.to_string_lossy()
                );
                return Err(EXIT_PROTOCOL);
            }
        }
    }
}

/// Canonical ASCII decimal — digits only, no sign, no leading zero — within
/// `1..=INDEX_WORKER_MEMORY_BUDGET`; anything else is `None`.
fn memory_budget(value: &[u8]) -> Option<u64> {
    if value.first().is_none_or(|first| *first == b'0') {
        return None;
    }
    value
        .iter()
        .try_fold(0_u64, |budget, digit| {
            let digit = digit.is_ascii_digit().then(|| u64::from(digit - b'0'))?;
            budget.checked_mul(10)?.checked_add(digit)
        })
        .filter(|budget| *budget <= INDEX_WORKER_MEMORY_BUDGET)
}

/// Linux: tightens `RLIMIT_AS`, already hard-capped at startup, to the
/// budget; the limit survives execv.
#[cfg(target_os = "linux")]
fn apply_memory_budget(budget: u64) -> Result<(), i32> {
    set_rlimit(RLIMIT_AS, budget)
}

/// macOS: Darwin rejects an absolute `RLIMIT_AS`/`RLIMIT_DATA` below its
/// multi-hundred-GiB baseline map (DEC-031), so both are capped at the
/// measured map plus the budget; the limits survive execv.
#[cfg(target_os = "macos")]
fn apply_memory_budget(budget: u64) -> Result<(), i32> {
    use rivect_sandbox_helper::RLIMIT_DATA;
    let map_size = rivect_sandbox_helper::current_map_size().map_err(|error| {
        eprintln!("rivect-sandbox-helper: map size measurement failed: {error}");
        EXIT_SANDBOX_INIT
    })?;
    let cap = relative_cap(map_size, budget)?;
    set_rlimit(RLIMIT_AS, cap)?;
    set_rlimit(RLIMIT_DATA, cap)
}

/// The macOS cap: the measured map plus the budget. An overflow fails
/// closed instead of wrapping to a tiny or meaningless limit.
#[cfg(target_os = "macos")]
fn relative_cap(map_size: u64, budget: u64) -> Result<u64, i32> {
    map_size.checked_add(budget).ok_or_else(|| {
        eprintln!("rivect-sandbox-helper: memory cap overflows the address space");
        EXIT_SANDBOX_INIT
    })
}

// ---------------------------------------------------------------------------
// confined: apply the sandbox, then move the admitted fd bytes
// ---------------------------------------------------------------------------

/// `confined <platform> <read|write> [<profile>]`.
fn cmd_confined(args: &[CString]) -> Result<(), i32> {
    let (platform, mode) = match (args.get(2), args.get(3)) {
        (Some(platform), Some(mode)) => (platform.to_bytes(), mode.to_bytes()),
        _ => {
            eprintln!("rivect-sandbox-helper: confined requires a platform and a mode");
            return Err(EXIT_PROTOCOL);
        }
    };
    let profile = args.get(4).map(|arg| arg.to_bytes()).unwrap_or_default();
    apply_sandbox(platform, profile)?;
    match mode {
        b"read" => confined_read(),
        b"write" => confined_write(),
        _ => {
            eprintln!("rivect-sandbox-helper: confined mode must be read or write");
            Err(EXIT_PROTOCOL)
        }
    }
}

/// Applies the platform's OS boundary before any fd byte moves.
fn apply_sandbox(platform: &[u8], profile: &[u8]) -> Result<(), i32> {
    match platform {
        b"macos" => apply_macos_sandbox(profile),
        b"linux" => apply_linux_landlock(profile),
        _ => {
            eprintln!("rivect-sandbox-helper: confined platform must be macos or linux");
            Err(EXIT_PROTOCOL)
        }
    }
}

/// Reads the admitted target (fd 0) up to the data cap and writes the bytes
/// to stdout (fd 1). The boundary is already applied: the only path the
/// child can touch is the inherited fd — it never re-opens the target.
fn confined_read() -> Result<(), i32> {
    // SAFETY: fd 0 was inherited from the parent as this helper's stdin —
    // the checked, O_NOFOLLOW-opened data fd.
    let input = unsafe { std::fs::File::from_raw_fd(0) };
    let mut bytes = Vec::with_capacity(DATA_MAX_BYTES.min(64 * 1024));
    input
        .take((DATA_MAX_BYTES as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            eprintln!("rivect-sandbox-helper: admitted read failed: {error}");
            EXIT_DATA_IO
        })?;
    if bytes.len() > DATA_MAX_BYTES {
        eprintln!("rivect-sandbox-helper: admitted read exceeds the data cap");
        return Err(EXIT_DATA_IO);
    }
    std::io::stdout().write_all(&bytes).map_err(|error| {
        eprintln!("rivect-sandbox-helper: admitted read delivery failed: {error}");
        EXIT_DATA_IO
    })?;
    Ok(())
}

/// Reads the admitted payload from stdin (fd 0) and writes it to the target
/// fd (fd 1) after truncating — the write fd is the checked fd the parent
/// opened and re-verified; this child performs the mutation under the
/// boundary already applied.
fn confined_write() -> Result<(), i32> {
    let mut payload = Vec::new();
    std::io::stdin()
        .take((DATA_MAX_BYTES as u64) + 1)
        .read_to_end(&mut payload)
        .map_err(|error| {
            eprintln!("rivect-sandbox-helper: admitted payload read failed: {error}");
            EXIT_DATA_IO
        })?;
    if payload.len() > DATA_MAX_BYTES {
        eprintln!("rivect-sandbox-helper: admitted payload exceeds the data cap");
        return Err(EXIT_DATA_IO);
    }
    // SAFETY: fd 1 was inherited from the parent as this helper's stdout —
    // the checked, O_NOFOLLOW-opened data fd.
    let mut target = unsafe { std::fs::File::from_raw_fd(1) };
    let length = u64::try_from(payload.len()).map_err(|_conversion| {
        eprintln!("rivect-sandbox-helper: payload length does not fit the data fd");
        EXIT_DATA_IO
    })?;
    target.set_len(length).map_err(|error| {
        eprintln!("rivect-sandbox-helper: admitted truncate failed: {error}");
        EXIT_DATA_IO
    })?;
    // The truncate already landed: every failure past this point leaves
    // the target mutated, so the host must read the outcome as unknown,
    // never as a clean rejection.
    target.write_all(&payload).map_err(|error| {
        eprintln!("rivect-sandbox-helper: admitted write failed: {error}");
        EXIT_DATA_MUTATED
    })?;
    // Durability is the verdict's last leg: the bytes reached the
    // kernel, but a sync failure leaves the target's durable state
    // unknown — the same post-mutation code, never a clean rejection.
    target.sync_all().map_err(|error| {
        eprintln!("rivect-sandbox-helper: admitted write sync failed: {error}");
        EXIT_DATA_MUTATED
    })
}

/// `probe-write <macos|linux> <profile|scope> <path>` — the write-boundary
/// probe: opens the worker-owned probe artifact for write under the sandbox
/// and writes one byte. The open is the admission being proven (S8: a write
/// gate must prove write-open, never `touch`), and `O_NOFOLLOW` keeps a
/// planted symlink from being followed by the probe.
fn cmd_probe_write(args: &[CString]) -> Result<(), i32> {
    let (platform, profile, path) = match (args.get(2), args.get(3), args.get(4)) {
        (Some(platform), Some(profile), Some(path)) => {
            (platform.to_bytes(), profile.to_bytes(), path)
        }
        _ => {
            eprintln!("rivect-sandbox-helper: probe-write requires platform, profile and path");
            return Err(EXIT_PROTOCOL);
        }
    };
    apply_sandbox(platform, profile)?;
    open_for_write(path)?;
    Ok(())
}

/// Opens the probe artifact for the write boundary and mutates one byte.
/// The caller (the worker) owns the artifact name — fresh and unpredictable
/// — so this open can never truncate or follow a file another process
/// planted; `O_EXCL` refuses a pre-existing name. The opened fd is closed
/// before returning.
fn open_for_write(path: &CString) -> Result<(), i32> {
    // SAFETY: the path is an owned NUL-terminated CString; the flags are the
    // literal platform open(2) constants; mode 0o600 applies only because
    // O_CREAT is set; the fd is closed on every path.
    unsafe {
        let fd = sys::open(
            path.as_ptr(),
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
            0o600,
        );
        if fd < 0 {
            eprintln!(
                "rivect-sandbox-helper: probe-write open denied: {}",
                std::io::Error::last_os_error()
            );
            return Err(EXIT_DATA_IO);
        }
        // The write itself is the point: an open without a write proves
        // nothing about the write boundary.
        if sys::write(fd, b"x".as_ptr().cast(), 1) != 1 {
            eprintln!(
                "rivect-sandbox-helper: probe-write write failed: {}",
                std::io::Error::last_os_error()
            );
            let _ = sys::close(fd);
            return Err(EXIT_DATA_IO);
        }
        let _ = sys::close(fd);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// check-setup: the bounded writable root for one isolated check (DEC-040)
// ---------------------------------------------------------------------------

/// `prctl(PR_SET_NO_NEW_PRIVS)` option id: documented on both sides of the
/// landlock path and the check-setup drop below.
#[cfg(target_os = "linux")]
const PR_SET_NO_NEW_PRIVS: i32 = 38;

/// Closes a check-setup directory fd, reporting a failed close(2)
/// instead of discarding it: on the success path a failed close leaves
/// the fd alive into the exec'd untrusted chain — an fd-boundary
/// breach — so the setup fails closed; on a primary-failure path the
/// caller folds the close failure into its refusal, never silently.
#[cfg(target_os = "linux")]
fn close_checked(fd: i32) -> std::io::Result<()> {
    // SAFETY: `fd` is a live descriptor this call owns once; close(2)
    // either releases it or reports why it could not.
    if unsafe { sys::close(fd) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// `check-setup <attempt>` (Linux only): validates that the canonical
/// `<attempt>/rw` is an empty directory, mounts a hard-quota tmpfs
/// (`size=512MiB`, `nosuid,nodev`) on it, then drops this process's
/// namespace privileges (no_new_privs plus empty capability sets) so a
/// successful setup never leaves CAP_SYS_ADMIN behind. Invoked inside the
/// fresh user/mount/PID/net namespace the launcher chain created, before
/// setpriv/landlock/seccomp and before any untrusted Cargo/test code; a
/// mount failure is a typed refusal — there is never a plain-directory
/// fallback the child could fill the host with.
#[cfg(target_os = "linux")]
fn cmd_check_setup(args: &[CString]) -> Result<(), i32> {
    /// tmpfs quota per attempt: the DEC-040 writable-root ceiling.
    const CHECK_TMPFS_MIB: u64 = 512;
    const MS_NOSUID: c_ulong_alias = 2;
    const MS_NODEV: c_ulong_alias = 4;

    let attempt = match args.get(2) {
        Some(attempt) if args.len() == 3 => attempt,
        _ => {
            eprintln!("rivect-sandbox-helper: check-setup requires exactly one attempt root");
            return Err(EXIT_PROTOCOL);
        }
    };
    refuse_initial_user_namespace()?;
    let canonical =
        std::fs::canonicalize(OsStr::from_bytes(attempt.as_bytes())).map_err(|error| {
            eprintln!("rivect-sandbox-helper: check-setup attempt root does not resolve: {error}");
            EXIT_SANDBOX_INIT
        })?;
    let rw = canonical.join("rw");
    let rw_c = CString::new(rw.as_os_str().as_encoded_bytes()).map_err(|_nul| {
        eprintln!("rivect-sandbox-helper: check-setup rw path contains an interior NUL");
        EXIT_PROTOCOL
    })?;
    let dirfd = open_empty_rw(&rw_c)?;
    // mount(2) takes a pathname, and a pathname on the shared host fs can
    // be swapped between the validation open and the mount (the attempt
    // root is not namespace-private). fchdir(dirfd) pins the cwd to the
    // validated directory's inode, and "." resolves through that pinned
    // dentry — never by re-walking the swappable path — so the mount
    // lands on exactly the directory proven empty. What the pin cannot
    // do is keep the directory empty: any writer with access to this
    // inode — a host process just as much as a namespace-mate, the
    // filesystem underneath is the host's — can add content after the
    // fd-relative empty listing, and the tmpfs would mount over it. The
    // residual guarantee is the fd-anchored mount on the directory that
    // was empty at validation, not empty forever.
    // SAFETY: `dirfd` is the live directory fd open_empty_rw returned;
    // the process exits after check-setup, so the cwd change is local.
    if unsafe { sys::fchdir(dirfd) } != 0 {
        // The failing syscall's errno is captured before the close:
        // close(2) on the same fd can replace it and misdiagnose the
        // refusal.
        let error = std::io::Error::last_os_error();
        // A close failure joins the refusal instead of vanishing: the
        // fd this leg could not use is still closed by the checked
        // helper, and a close that also fails names itself.
        match close_checked(dirfd) {
            Ok(()) => {
                eprintln!(
                    "rivect-sandbox-helper: check-setup cannot enter the validated rw: {error}"
                );
            }
            Err(close_error) => eprintln!(
                "rivect-sandbox-helper: check-setup cannot enter the validated rw: {error}; closing the validated rw also failed: {close_error}"
            ),
        }
        return Err(EXIT_SANDBOX_INIT);
    }
    // memparse suffixes are k/m/g/t only — the "MiB" spelling util-linux
    // documents is not one the kernel's tmpfs parser accepts (EINVAL).
    let data = CString::new(format!("size={CHECK_TMPFS_MIB}M")).map_err(|_nul| EXIT_PROTOCOL)?;
    // SAFETY: the literals are owned NUL-terminated strings; the flags
    // are the documented mount(2) constants and `data` is the bounded
    // tmpfs quota option; a non-zero return is the typed refusal.
    let mounted = unsafe {
        sys::mount(
            c"tmpfs".as_ptr(),
            c".".as_ptr(),
            c"tmpfs".as_ptr(),
            MS_NOSUID | MS_NODEV,
            data.as_ptr().cast(),
        )
    };
    // The mount errno is captured before the checked close: close(2) can
    // replace it and misdiagnose the refusal. `then` reads the error
    // only when the mount failed.
    let mount_error = (mounted != 0).then(std::io::Error::last_os_error);
    if let Err(close_error) = close_checked(dirfd) {
        // On the failed-mount path the refusal names both failures; on
        // the success path a failed close leaves the fd alive into the
        // exec'd untrusted chain — an fd-boundary breach — so the setup
        // fails closed instead of reporting success.
        if let Some(error) = mount_error.as_ref() {
            eprintln!(
                "rivect-sandbox-helper: check-setup tmpfs mount failed: {error}; closing the validated rw also failed: {close_error}"
            );
        } else {
            eprintln!(
                "rivect-sandbox-helper: check-setup closing the validated rw failed: {close_error}"
            );
        }
        return Err(EXIT_SANDBOX_INIT);
    }
    if let Some(error) = mount_error {
        eprintln!("rivect-sandbox-helper: check-setup tmpfs mount failed: {error}");
        return Err(EXIT_SANDBOX_INIT);
    }
    drop_namespace_privileges()
}

#[cfg(target_os = "linux")]
use std::os::raw::c_ulong as c_ulong_alias;

/// The mode is Linux-only: on macOS the bounded writable root is enforced
/// by the Seatbelt profile, so a typed refusal — never a silent no-op.
#[cfg(not(target_os = "linux"))]
fn cmd_check_setup(_args: &[CString]) -> Result<(), i32> {
    eprintln!("rivect-sandbox-helper: the check-setup mode is only built on Linux");
    Err(EXIT_PROTOCOL)
}

/// Refuses to run in the initial user namespace: a mount there is visible
/// to the host, exactly what check-setup exists to prevent. The initial
/// namespace is the only one whose uid_map spans the whole uid space; a
/// mapped-down (or empty) map means the kernel confines this process's
/// mounts to its own namespaces — and a mount namespace this process does
/// not own is refused by the kernel itself (EPERM), which surfaces as the
/// typed mount refusal.
#[cfg(target_os = "linux")]
fn refuse_initial_user_namespace() -> Result<(), i32> {
    let uid_map = std::fs::read_to_string("/proc/self/uid_map").map_err(|error| {
        eprintln!("rivect-sandbox-helper: check-setup cannot read its uid map: {error}");
        EXIT_SANDBOX_INIT
    })?;
    let initial = uid_map
        .lines()
        .any(|line| line.split_whitespace().nth(2) == Some("4294967295"));
    if initial {
        eprintln!("rivect-sandbox-helper: check-setup requires a fresh user namespace");
        return Err(EXIT_SANDBOX_INIT);
    }
    Ok(())
}

/// Opens `<attempt>/rw` and proves it empty. `O_DIRECTORY|O_NOFOLLOW`
/// refuses a symlink or a non-directory, and the fd-relative listing
/// (`/proc/self/fd/<fd>`) refuses any content: mounting over a populated
/// directory would hide it. The fd is returned for the caller to close
/// after mounting.
#[cfg(target_os = "linux")]
fn open_empty_rw(rw: &CString) -> Result<i32, i32> {
    const O_RDONLY: i32 = 0;
    // O_DIRECTORY shares O_NOFOLLOW's arch split above: the x86 bit is
    // not the asm-generic (aarch64) one, and a wrong pick is EINVAL.
    #[cfg(target_arch = "x86_64")]
    const O_DIRECTORY: i32 = 0o200_000;
    #[cfg(target_arch = "aarch64")]
    const O_DIRECTORY: i32 = 0o40_000;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const O_DIRECTORY: i32 = {
        compile_error!(
            "rivect-sandbox-helper: no open(2) O_DIRECTORY value is pinned for this linux architecture"
        );
        0
    };
    const O_CLOEXEC: i32 = 0o2_000_000;

    // SAFETY: `rw` is an owned NUL-terminated path; the flags are literal
    // open(2) constants; mode is irrelevant without O_CREAT; the fd is
    // closed by the caller after the mount.
    let fd = unsafe {
        sys::open(
            rw.as_ptr(),
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        eprintln!(
            "rivect-sandbox-helper: check-setup rw must be an empty directory the helper can open: {}",
            std::io::Error::last_os_error()
        );
        return Err(EXIT_SANDBOX_INIT);
    }
    let listing = format!("/proc/self/fd/{fd}");
    if !dir_is_empty(&listing) {
        // A close failure joins the refusal instead of vanishing.
        match close_checked(fd) {
            Ok(()) => eprintln!("rivect-sandbox-helper: check-setup rw must be empty"),
            Err(close_error) => eprintln!(
                "rivect-sandbox-helper: check-setup rw must be empty; closing the rw also failed: {close_error}"
            ),
        }
        return Err(EXIT_SANDBOX_INIT);
    }
    Ok(fd)
}

/// Whether `dir` (a `/proc/self/fd/<n>` directory listing) holds nothing
/// but `.` and `..`. A walk that cannot even open or read the listing
/// counts as non-empty: refusing beats mounting over unverifiable content.
#[cfg(target_os = "linux")]
fn dir_is_empty(dir: &str) -> bool {
    let Ok(dir_c) = CString::new(dir) else {
        return false;
    };
    // SAFETY: POSIX directory iteration as in walk_fd_dir — `d_name` is a
    // NUL-terminated string at the documented offset; only names are
    // inspected and closedir owns the directory fd's single close.
    unsafe {
        let dirp = sys::opendir(dir_c.as_ptr());
        if dirp.is_null() {
            return false;
        }
        let mut empty = true;
        loop {
            set_errno(0);
            let entry = sys::readdir(dirp);
            if entry.is_null() {
                if get_errno() != 0 {
                    empty = false;
                }
                break;
            }
            let name = CStr::from_ptr((*entry).d_name.as_ptr()).to_bytes();
            if name != b"." && name != b".." {
                empty = false;
                break;
            }
        }
        if sys::closedir(dirp) != 0 {
            return false;
        }
        empty
    }
}

/// Drops this process's namespace privileges after the mount:
/// `PR_SET_NO_NEW_PRIVS`, then empty capability sets. In the user namespace
/// the chain created, that removes CAP_SYS_ADMIN/CAP_SETUID — no further
/// mount, uid-map write, or setns escape — before any untrusted code runs.
/// `capset` goes through the raw syscall: musl ships no libc wrapper.
#[cfg(target_os = "linux")]
fn drop_namespace_privileges() -> Result<(), i32> {
    /// `_LINUX_CAPABILITY_VERSION_3`.
    const CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    /// `SYS_capset` per architecture: 126 on x86-64
    /// (`arch/x86/entry/syscalls/syscall_64.tbl`), 91 on aarch64 (kernel
    /// `include/uapi/asm-generic/unistd.h`). The number is NOT uniform —
    /// a wrong pick calls an unrelated syscall and every check-setup
    /// refuses — so any other Linux arch fails the build instead of
    /// guessing.
    #[cfg(target_arch = "x86_64")]
    const SYS_CAPSET: i64 = 126;
    #[cfg(target_arch = "aarch64")]
    const SYS_CAPSET: i64 = 91;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const SYS_CAPSET: i64 = {
        compile_error!(
            "rivect-sandbox-helper: no capset syscall number is pinned for this linux architecture"
        );
        0
    };

    // SAFETY: the documented PR_SET_NO_NEW_PRIVS option with argument 1;
    // the return is checked.
    if unsafe { sys::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        eprintln!(
            "rivect-sandbox-helper: check-setup no_new_privs failed: {}",
            std::io::Error::last_os_error()
        );
        return Err(EXIT_SANDBOX_INIT);
    }
    let header = sys::CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [sys::CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: the header/data pair matches the V3 capset ABI (layouts
    // asserted in sys); pid 0 addresses this process; the call only clears
    // this process's capability sets.
    let dropped = unsafe {
        sys::syscall(
            SYS_CAPSET,
            std::ptr::from_ref(&header),
            std::ptr::from_ref(&data),
        )
    };
    if dropped != 0 {
        eprintln!(
            "rivect-sandbox-helper: check-setup capability drop failed: {}",
            std::io::Error::last_os_error()
        );
        return Err(EXIT_SANDBOX_INIT);
    }
    verify_dropped_privileges()
}

/// Confirms the drop took, from the kernel's own view of this process
/// (`/proc/self/status`): `CapEff` zeroed and `NoNewPrivs` set. The
/// syscalls returning 0 alone does not prove the effective state the
/// check-setup exit code vouches for — a wrong syscall number or a
/// kernel refusal would otherwise pass silently.
#[cfg(target_os = "linux")]
fn verify_dropped_privileges() -> Result<(), i32> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(|error| {
        eprintln!("rivect-sandbox-helper: check-setup cannot read its status: {error}");
        EXIT_SANDBOX_INIT
    })?;
    let cap_eff = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:").map(str::trim));
    let no_new_privs = status
        .lines()
        .find_map(|line| line.strip_prefix("NoNewPrivs:").map(str::trim));
    if matches!(
        (cap_eff, no_new_privs),
        (Some("0000000000000000"), Some("1"))
    ) {
        return Ok(());
    }
    eprintln!(
        "rivect-sandbox-helper: check-setup drop did not take (CapEff {cap_eff:?}, NoNewPrivs {no_new_privs:?})"
    );
    Err(EXIT_SANDBOX_INIT)
}

// ---------------------------------------------------------------------------
// Platform sandbox application
// ---------------------------------------------------------------------------

/// Seatbelt `sandbox_init` with the host-built profile string: the profile
/// filters path-based operations, so the inherited data fd (already open,
/// already verified) stays the only data path the child can touch.
#[cfg(target_os = "macos")]
fn apply_macos_sandbox(profile: &[u8]) -> Result<(), i32> {
    // SAFETY: sandbox_init takes a NUL-terminated profile (built below) and
    // writes an allocated error message into errorbuf that
    // sandbox_free_error releases; the linkage comes from the sandbox
    // framework (build.rs).
    unsafe {
        let profile_c = CString::new(profile).map_err(|_nul| {
            eprintln!("rivect-sandbox-helper: profile contains an interior NUL");
            EXIT_PROTOCOL
        })?;
        let mut errorbuf: *mut std::os::raw::c_char = std::ptr::null_mut();
        let verdict = sys::sandbox_init(profile_c.as_ptr(), 0, &mut errorbuf);
        if verdict != 0 {
            let message = if errorbuf.is_null() {
                "sandbox_init failed".to_string()
            } else {
                let message = CStr::from_ptr(errorbuf).to_string_lossy().into_owned();
                sys::sandbox_free_error(errorbuf);
                message
            };
            eprintln!("rivect-sandbox-helper: sandbox_init failed: {message}");
            return Err(EXIT_SANDBOX_INIT);
        }
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn apply_macos_sandbox(_profile: &[u8]) -> Result<(), i32> {
    eprintln!("rivect-sandbox-helper: the macos confined mode is only built on macOS");
    Err(EXIT_PROTOCOL)
}

/// Landlock deny-by-default: handles the ABI-1 filesystem access rights.
/// With no scope, zero rules mean the helper cannot open ANY path — the
/// only I/O left is the inherited data fd. With a scope (probe-write), a
/// path-beneath rule admits create/write inside that directory so the
/// probe can open its artifact. The network namespace is applied by the
/// parent's `unshare --net` wrapper, so a confined helper has neither a
/// path nor a network escape.
#[cfg(target_os = "linux")]
fn apply_linux_landlock(scope: &[u8]) -> Result<(), i32> {
    // Landlock syscall numbers are 444/445/446 on both aarch64 and x86_64.
    const SYS_LANDLOCK_CREATE_RULESET: i64 = 444;
    const SYS_LANDLOCK_ADD_RULE: i64 = 445;
    const SYS_LANDLOCK_RESTRICT_SELF: i64 = 446;
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

    const ACCESS_FS_EXECUTE: u64 = 1 << 0;
    const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const ACCESS_FS_READ_DIR: u64 = 1 << 3;
    const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
    // ABI-1 set only: ACCESS_FS_REFER (ABI 2) and ACCESS_FS_TRUNCATE
    // (ABI 3) are omitted. Handling TRUNCATE without a grant would deny
    // ftruncate/set_len on the inherited write fd on ABI3+ kernels.
    const HANDLED_FS: u64 = ACCESS_FS_EXECUTE
        | ACCESS_FS_WRITE_FILE
        | ACCESS_FS_READ_FILE
        | ACCESS_FS_READ_DIR
        | ACCESS_FS_REMOVE_DIR
        | ACCESS_FS_REMOVE_FILE
        | ACCESS_FS_MAKE_CHAR
        | ACCESS_FS_MAKE_DIR
        | ACCESS_FS_MAKE_REG
        | ACCESS_FS_MAKE_SOCK
        | ACCESS_FS_MAKE_FIFO
        | ACCESS_FS_MAKE_BLOCK
        | ACCESS_FS_MAKE_SYM;

    const O_DIRECTORY: i32 = 0o200_000;
    const O_CLOEXEC: i32 = 0o2_000_000;
    const O_PATH: i32 = 0o10_000_000;

    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
    }
    #[repr(C)]
    struct LandlockPathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    // SAFETY: the attribute is the kernel ABI layout and outlives the
    // syscall; the integer constants are the documented landlock/prctl
    // values shown above; dirfds opened here are closed on every path.
    unsafe {
        let nnp = sys::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if nnp != 0 {
            eprintln!(
                "rivect-sandbox-helper: prctl no_new_privs failed: {}",
                std::io::Error::last_os_error()
            );
            return Err(EXIT_SANDBOX_INIT);
        }
        // size=0 + VERSION flag is the ABI query, not ruleset creation.
        let abi = sys::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        );
        if abi < 1 {
            eprintln!(
                "rivect-sandbox-helper: landlock ABI probe failed (abi={abi}): {}",
                std::io::Error::last_os_error()
            );
            return Err(EXIT_SANDBOX_INIT);
        }
        let attr = LandlockRulesetAttr {
            handled_access_fs: HANDLED_FS,
        };
        let ruleset = sys::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::from_ref(&attr),
            size_of::<LandlockRulesetAttr>(),
            0u32,
        );
        if ruleset < 0 {
            eprintln!(
                "rivect-sandbox-helper: landlock_create_ruleset failed: {}",
                std::io::Error::last_os_error()
            );
            return Err(EXIT_SANDBOX_INIT);
        }
        let ruleset_fd = ruleset as i32;
        if !scope.is_empty() {
            let scope_c = match CString::new(scope) {
                Ok(scope_c) => scope_c,
                Err(_) => {
                    eprintln!("rivect-sandbox-helper: landlock scope contains an interior NUL");
                    let _ = sys::close(ruleset_fd);
                    return Err(EXIT_PROTOCOL);
                }
            };
            let dirfd = sys::open(
                scope_c.as_ptr(),
                O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
                0,
            );
            if dirfd < 0 {
                eprintln!(
                    "rivect-sandbox-helper: landlock scope open failed: {}",
                    std::io::Error::last_os_error()
                );
                let _ = sys::close(ruleset_fd);
                return Err(EXIT_SANDBOX_INIT);
            }
            let path_beneath = LandlockPathBeneathAttr {
                allowed_access: ACCESS_FS_WRITE_FILE
                    | ACCESS_FS_MAKE_REG
                    | ACCESS_FS_READ_FILE
                    | ACCESS_FS_READ_DIR,
                parent_fd: dirfd,
            };
            let added = sys::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH,
                std::ptr::from_ref(&path_beneath),
                0u32,
            );
            let _ = sys::close(dirfd);
            if added != 0 {
                eprintln!(
                    "rivect-sandbox-helper: landlock_add_rule failed: {}",
                    std::io::Error::last_os_error()
                );
                let _ = sys::close(ruleset_fd);
                return Err(EXIT_SANDBOX_INIT);
            }
        }
        if sys::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) != 0 {
            eprintln!(
                "rivect-sandbox-helper: landlock_restrict_self failed: {}",
                std::io::Error::last_os_error()
            );
            let _ = sys::close(ruleset_fd);
            return Err(EXIT_SANDBOX_INIT);
        }
        let _ = sys::close(ruleset_fd);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_linux_landlock(_scope: &[u8]) -> Result<(), i32> {
    eprintln!("rivect-sandbox-helper: the linux confined mode is only built on Linux");
    Err(EXIT_PROTOCOL)
}

// ---------------------------------------------------------------------------
// rlimits (S5): every confined child is bounded
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
const RLIMITS: &[(i32, u64)] = &[
    // Darwin `setrlimit(RLIMIT_AS)` returns EINVAL: the dyld shared
    // region already exceeds any useful virtual-size cap, so CPU /
    // FSIZE / NPROC / NOFILE carry the bound.
    (0, 30),               // RLIMIT_CPU seconds
    (1, 64 * 1024 * 1024), // RLIMIT_FSIZE
    (7, 64),               // RLIMIT_NPROC
    (8, 256),              // RLIMIT_NOFILE
];
#[cfg(target_os = "linux")]
const RLIMITS: &[(i32, u64)] = &[
    (RLIMIT_AS, 512 * 1024 * 1024),
    (0, 30),               // RLIMIT_CPU seconds
    (1, 64 * 1024 * 1024), // RLIMIT_FSIZE
    (6, 64),               // RLIMIT_NPROC
    (7, 256),              // RLIMIT_NOFILE
];

/// Sets the confined child's resource limits at startup, before any mode
/// logic: the limits stop a fork bomb, a disk fill, and an fd storm without
/// ever touching a legitimate program. Hard limits can only tighten; a
/// failure to set them is a sandbox-init failure (fail closed).
fn apply_rlimits(profile: ResourceProfile) -> Result<(), i32> {
    match profile {
        ResourceProfile::Worker => {
            for &(resource, value) in RLIMITS {
                set_rlimit(resource, value)?;
            }
        }
        ResourceProfile::Check => {
            for (resource, value) in check_rlimits()? {
                set_rlimit_capped(resource, value)?;
            }
        }
    }
    Ok(())
}

/// The check profile's limits: the same dimensions as the worker defaults
/// at the Cargo ceilings, with NPROC measured against this host's uid count
/// instead of fixed (D-115 — the worker's fixed 64 counts a busy host's own
/// processes against Cargo). The kernel exempts root from NPROC, so the
/// value is still set there but only an unprivileged leg can prove it.
#[cfg(target_os = "macos")]
fn check_rlimits() -> Result<[(i32, u64); 4], i32> {
    Ok([
        (0, CHECK_CPU_SECONDS),    // RLIMIT_CPU seconds
        (1, CHECK_FSIZE_BYTES),    // RLIMIT_FSIZE per file
        (7, check_nproc_limit()?), // RLIMIT_NPROC, measured + headroom
        (8, CHECK_NOFILE),         // RLIMIT_NOFILE
    ])
}

#[cfg(target_os = "linux")]
fn check_rlimits() -> Result<[(i32, u64); 5], i32> {
    Ok([
        (RLIMIT_AS, CHECK_AS_BYTES), // per-process address space
        (0, CHECK_CPU_SECONDS),      // RLIMIT_CPU seconds
        (1, CHECK_FSIZE_BYTES),      // RLIMIT_FSIZE per file
        (6, check_nproc_limit()?),   // RLIMIT_NPROC, measured + headroom
        (7, CHECK_NOFILE),           // RLIMIT_NOFILE
    ])
}

/// The measured same-uid process count plus the headroom. An unmeasurable
/// host is a sandbox-init refusal: NPROC must be derived, never guessed.
fn check_nproc_limit() -> Result<u64, i32> {
    let count = rivect_sandbox_helper::uid_process_count().map_err(|error| {
        eprintln!("rivect-sandbox-helper: uid process count measurement failed: {error}");
        EXIT_SANDBOX_INIT
    })?;
    Ok(count.saturating_add(CHECK_NPROC_HEADROOM))
}

/// Sets both the soft and hard `resource` limit to `value`; a failure is
/// a sandbox-init failure (fail closed). A requested limit above the
/// inherited hard ceiling fails the setrlimit itself (EPERM) — the
/// legacy refusal the worker defaults and the memory budget keep.
fn set_rlimit(resource: i32, value: u64) -> Result<(), i32> {
    let limit = Rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: setrlimit reads the libc rlimit layout (two u64 words), which
    // the repr(C) struct matches, for a documented platform resource id; a
    // non-zero return is an init failure.
    if unsafe { sys::setrlimit(resource, &limit) } != 0 {
        eprintln!(
            "rivect-sandbox-helper: setrlimit({resource}) failed: {}",
            std::io::Error::last_os_error()
        );
        return Err(EXIT_SANDBOX_INIT);
    }
    Ok(())
}

/// The check-profile variant: the DEC-040 ceilings can exceed a hard
/// ceiling the launching host lowered (a CI container with hard NOFILE
/// 128 must still host an isolated check), so the requested value is
/// clamped at the inherited hard limit instead of refused — raising
/// above that ceiling would need CAP_SYS_RESOURCE, exactly the
/// privilege a confined child must never rely on, and hard limits only
/// ever tighten. Only this profile clamps: the worker defaults and the
/// memory budget keep the legacy refusal above.
fn set_rlimit_capped(resource: i32, value: u64) -> Result<(), i32> {
    let mut inherited = Rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes the libc rlimit layout (two u64 words)
    // into the live `inherited` buffer for a documented resource id; the
    // initial zeros are never read on success.
    if unsafe { sys::getrlimit(resource, &mut inherited) } != 0 {
        eprintln!(
            "rivect-sandbox-helper: getrlimit({resource}) failed: {}",
            std::io::Error::last_os_error()
        );
        return Err(EXIT_SANDBOX_INIT);
    }
    set_rlimit(resource, value.min(inherited.rlim_max))
}

// ---------------------------------------------------------------------------
// fd sweep: close every inherited fd above stdio
// ---------------------------------------------------------------------------

/// Closes every inherited fd above stdio. Linux prefers `close_range` and
/// walks `/proc/self/fd` if that syscall is missing; macOS walks `/dev/fd`
/// and always unions `F_MAXFD` so a partial walk cannot leave strays. If
/// every method fails, this is a sandbox init failure — never
/// exec-with-inherited-fds.
fn close_stray_fds() -> Result<(), i32> {
    #[cfg(target_os = "linux")]
    {
        const SYS_CLOSE_RANGE: i64 = 436;
        let first = (STDIO_TOP_FD + 1) as u32;
        // SAFETY: close_range(STDIO_TOP_FD+1, UINT_MAX, 0) closes every fd
        // above stdio; a negative return is ENOSYS or a similar miss, and
        // the walk covers the table instead.
        let closed = unsafe { sys::syscall(SYS_CLOSE_RANGE, first, u32::MAX, 0u32) };
        if closed == 0 {
            return Ok(());
        }
        if walk_fd_dir("/proc/self/fd") {
            return Ok(());
        }
        eprintln!(
            "rivect-sandbox-helper: fd sweep failed: close_range and /proc/self/fd walk both failed"
        );
        Err(EXIT_SANDBOX_INIT)
    }
    #[cfg(target_os = "macos")]
    {
        let walked = walk_fd_dir("/dev/fd");
        const F_MAXFD: i32 = 51;
        // SAFETY: F_MAXFD reports the largest open fd in this process;
        // the query fd must be live — stderr (2) is piped by the host,
        // so it survives even when stdin is the data fd or closed.
        let max = unsafe { sys::fcntl(2, F_MAXFD) };
        if max < 0 {
            if walked {
                return Ok(());
            }
            eprintln!(
                "rivect-sandbox-helper: fd sweep failed: /dev/fd walk and F_MAXFD both failed"
            );
            return Err(EXIT_SANDBOX_INIT);
        }
        if max > STDIO_TOP_FD {
            for fd in (STDIO_TOP_FD + 1)..=max {
                // SAFETY: those fds are the parent's strays, never owned
                // handles of this freshly spawned child. A number the walk
                // already closed returns EBADF, which is ignored.
                let _ = unsafe { sys::close(fd) };
            }
        }
        Ok(())
    }
}

/// Collects numeric fd names from a kernel fd directory, then closes each
/// fd above stdio except the directory fd itself (`closedir` owns that
/// close). Returns false when the directory cannot be opened, `readdir`
/// fails (NULL with errno set — not EOF), `closedir` fails, or a dirent
/// name is not UTF-8 or not a decimal fd (other than `.`/`..`). A vacuous
/// walk (open succeeds, readdir errors, we still return true) would leave
/// inherited fds alive; skipping unparseable names would hide the same.
fn walk_fd_dir(dir: &str) -> bool {
    let Ok(dir_c) = CString::new(dir) else {
        return false;
    };
    // SAFETY: `dir_c` is a valid CString; opendir/readdir/dirfd/closedir
    // follow the POSIX DIR contract. Names are collected before closedir,
    // the directory fd is excluded from the close list, and closedir
    // closes that fd once — never a double-close of the walk's dirfd.
    // errno is cleared before each readdir so a NULL return with errno
    // set is an error, not EOF.
    unsafe {
        let dirp = sys::opendir(dir_c.as_ptr());
        if dirp.is_null() {
            return false;
        }
        let dirfd = sys::dirfd(dirp);
        if dirfd < 0 {
            let _ = sys::closedir(dirp);
            return false;
        }
        let mut fds = Vec::new();
        loop {
            set_errno(0);
            let entry = sys::readdir(dirp);
            if entry.is_null() {
                if get_errno() != 0 {
                    let _ = sys::closedir(dirp);
                    return false;
                }
                break;
            }
            let name = match CStr::from_ptr((*entry).d_name.as_ptr()).to_str() {
                Ok(name) => name,
                Err(_) => {
                    let _ = sys::closedir(dirp);
                    return false;
                }
            };
            match fd_dirent_close_candidate(name, dirfd) {
                Ok(Some(fd)) => fds.push(fd),
                Ok(None) => {}
                Err(()) => {
                    let _ = sys::closedir(dirp);
                    return false;
                }
            }
        }
        if sys::closedir(dirp) != 0 {
            return false;
        }
        for fd in fds {
            let _ = sys::close(fd);
        }
    }
    true
}

/// `.`/`..` are skipped; a decimal fd name is a close candidate when it is
/// above stdio and not the walk's dirfd. Kernel fd names never have leading
/// zeros, so a multi-digit name that starts with `0` is rejected. Any other
/// spelling is a walk failure — an unparseable name is not silently ignored.
fn fd_dirent_close_candidate(name: &str, dirfd: i32) -> Result<Option<i32>, ()> {
    if name == "." || name == ".." {
        return Ok(None);
    }
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    if name.len() > 1 && name.starts_with('0') {
        return Err(());
    }
    let fd = name.parse::<i32>().map_err(|_parse| ())?;
    Ok((fd > STDIO_TOP_FD && fd != dirfd).then_some(fd))
}

/// Writes this thread's errno. POSIX `readdir` uses a NULL return with
/// errno unchanged for EOF, so the walk must start each iteration at 0.
///
/// # Safety
/// Caller must invoke from a context that owns this thread's errno word
/// (the helper's fd-walk, never a concurrent libc call on the same thread).
unsafe fn set_errno(value: std::os::raw::c_int) {
    // SAFETY: libc's errno pointer is thread-local; we only store an int.
    unsafe {
        #[cfg(target_os = "linux")]
        {
            *sys::__errno_location() = value;
        }
        #[cfg(target_os = "macos")]
        {
            *sys::__error() = value;
        }
    }
}

/// Reads this thread's errno after `readdir`/`closedir`.
///
/// # Safety
/// Same as [`set_errno`]: this thread's errno word only.
unsafe fn get_errno() -> std::os::raw::c_int {
    // SAFETY: libc's errno pointer is thread-local; we only load an int.
    unsafe {
        #[cfg(target_os = "linux")]
        {
            *sys::__errno_location()
        }
        #[cfg(target_os = "macos")]
        {
            *sys::__error()
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "helper unit tests assert setup and outcomes"
)]
mod tests {
    use super::*;

    /// Serializes the cases that call [`walk_fd_dir`]: the strays case walks
    /// the kernel fd directory and closes every fd above stdio except its own
    /// dirfd — including a `DIR*` a parallel case opened, whose `closedir`
    /// then panics on the EBADF. The sweep is correct for the shipped child,
    /// which owns its whole fd table; only the shared test table needs one
    /// walk at a time, so any case in this binary that opens a descriptor
    /// takes this lock too.
    static FD_WALK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Takes [`FD_WALK_LOCK`] for a whole fd-walk case body. A poisoned lock
    /// still serializes: a sibling's panic must fail that sibling's case, not
    /// cascade into this one.
    fn serialize_fd_walk() -> std::sync::MutexGuard<'static, ()> {
        FD_WALK_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn walk_fd_dir_rejects_a_missing_directory() {
        let _serialized = serialize_fd_walk();
        assert!(!walk_fd_dir("/no/such/rivect-fd-dir"));
    }

    #[test]
    fn walk_fd_dir_rejects_a_regular_file() {
        let _serialized = serialize_fd_walk();
        let path = std::env::temp_dir().join(format!("rivect-not-a-dir-{}", std::process::id()));
        std::fs::write(&path, b"x").expect("create non-directory");
        let rejected = path.to_str().is_some_and(|name| !walk_fd_dir(name));
        drop(std::fs::remove_file(&path));
        assert!(rejected, "opendir on a regular file must fail closed");
    }

    #[test]
    fn walk_fd_dir_rejects_unparseable_names() {
        let _serialized = serialize_fd_walk();
        let dir = std::env::temp_dir().join(format!("rivect-fd-walk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create fd-walk dir");
        std::fs::write(dir.join("not-an-fd"), b"x").expect("plant unparseable name");
        let rejected = dir.to_str().is_some_and(|name| !walk_fd_dir(name));
        drop(std::fs::remove_dir_all(&dir));
        assert!(
            rejected,
            "a non-decimal dirent name must fail the walk, not skip"
        );
        assert_eq!(fd_dirent_close_candidate(".", 8), Ok(None));
        assert_eq!(fd_dirent_close_candidate("..", 8), Ok(None));
        assert_eq!(fd_dirent_close_candidate("9", 8), Ok(Some(9)));
        assert_eq!(fd_dirent_close_candidate("8", 8), Ok(None));
        assert_eq!(fd_dirent_close_candidate("not-an-fd", 8), Err(()));
        assert_eq!(fd_dirent_close_candidate("-1", 8), Err(()));
        assert_eq!(fd_dirent_close_candidate("+3", 8), Err(()));
        assert_eq!(fd_dirent_close_candidate("0", 8), Ok(None));
        assert_eq!(fd_dirent_close_candidate("00", 8), Err(()));
        assert_eq!(fd_dirent_close_candidate("08", 8), Err(()));
    }

    #[test]
    fn walk_fd_dir_closes_strays_without_double_closing_its_dirfd() {
        let _serialized = serialize_fd_walk();
        #[cfg(target_os = "linux")]
        {
            owned::assert_private_fault_roles();
            owned::assert_map_validation_retires_once();
        }
        use std::os::fd::IntoRawFd;
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let raw = file.into_raw_fd();
        assert!(raw > STDIO_TOP_FD);
        let dir = if cfg!(target_os = "linux") {
            "/proc/self/fd"
        } else {
            "/dev/fd"
        };
        assert!(walk_fd_dir(dir), "fd directory walk must succeed");
        // SAFETY: `raw` was closed by the walk; a second close is EBADF,
        // proving the dirfd was not recycled onto this number.
        let rc = unsafe { sys::close(raw) };
        assert_eq!(rc, -1, "the stray fd must already be closed");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn memory_cap_tracks_the_live_map_size() {
        const RESERVATION: u64 = 1 << 30;
        let before = rivect_sandbox_helper::current_map_size().expect("measure before");
        let reservation = std::hint::black_box(Vec::<u8>::with_capacity(1 << 30));
        let after = rivect_sandbox_helper::current_map_size().expect("measure after");
        drop(reservation);
        eprintln!("map size before {before} bytes, after a 1 GiB reservation {after} bytes");
        assert!(
            after.saturating_sub(before) >= RESERVATION - 64 * 1024 * 1024,
            "the measured map must grow with a reservation: before {before}, after {after}"
        );
        assert_eq!(
            relative_cap(after, INDEX_WORKER_MEMORY_BUDGET),
            Ok(after + INDEX_WORKER_MEMORY_BUDGET)
        );
    }

    #[test]
    fn memory_budget_accepts_exactly_one_through_the_bound() {
        assert_eq!(memory_budget(b"1"), Some(1));
        assert_eq!(
            memory_budget(b"536870912"),
            Some(INDEX_WORKER_MEMORY_BUDGET)
        );
        assert_eq!(memory_budget(b"536870913"), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn memory_cap_overflow_fails_closed() {
        assert_eq!(
            relative_cap(u64::MAX - 1, INDEX_WORKER_MEMORY_BUDGET),
            Err(EXIT_SANDBOX_INIT)
        );
    }
}

#[cfg(target_os = "linux")]
mod owned {
    use super::{CString, Rlimit, sys};
    use rivect_sandbox_helper::{
        OwnedFault, OwnedFaultCause as Cause, OwnedProfile, OwnedRecord, OwnedStop,
    };
    use std::fs::File;
    use std::io::{self, Read};
    use std::os::fd::{FromRawFd, IntoRawFd};
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, Instant};

    unsafe extern "C" {
        fn unshare(flags: i32) -> i32;
        fn fork() -> i32;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn getuid() -> u32;
        fn getgid() -> u32;
        fn fcntl(fd: i32, command: i32, ...) -> i32;
        fn socketpair(domain: i32, kind: i32, protocol: i32, pair: *mut i32) -> i32;
        fn read(fd: i32, bytes: *mut u8, length: usize) -> isize;
        fn poll(fds: *mut PollFd, length: usize, timeout: i32) -> i32;
        fn kill(pid: i32, signal: i32) -> i32;
        fn execve(path: *const i8, argv: *const *const i8, env: *const *const i8) -> i32;
    }

    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        returned: i16,
    }

    #[derive(Debug, thiserror::Error)]
    enum Failure {
        #[error("owned launch failed at {boundary}: {cause:?}")]
        Observed {
            boundary: &'static str,
            cause: Cause,
            #[source]
            source: Option<io::Error>,
        },
        #[error(transparent)]
        Parent(#[from] rivect_sandbox_helper::OwnedParentError),
        #[error(
            "owned launch failed and descriptor retirement also failed: {primary}; {secondary}"
        )]
        Retirement {
            #[source]
            primary: Box<Failure>,
            secondary: Box<Failure>,
        },
    }

    impl Failure {
        fn with_retirement(self, secondary: Self) -> Self {
            if matches!(self, Self::Retirement { .. }) {
                self
            } else {
                Self::Retirement {
                    primary: Box::new(self),
                    secondary: Box::new(secondary),
                }
            }
        }

        fn fault(&self) -> Option<OwnedFault> {
            let (boundary, cause) = match self {
                Self::Observed {
                    boundary, cause, ..
                } => (*boundary, *cause),
                Self::Parent(error) => (error.boundary(), error.cause()),
                Self::Retirement { primary, .. } => return primary.fault(),
            };
            OwnedFault::new(boundary, cause).ok()
        }
    }

    fn observed(boundary: &'static str, cause: Cause) -> Failure {
        Failure::Observed {
            boundary,
            cause,
            source: None,
        }
    }

    fn os_error(boundary: &'static str, operation: u8, field: u8) -> Failure {
        let source = io::Error::last_os_error();
        let cause = match source.raw_os_error() {
            Some(errno) => Cause::Io {
                operation,
                field,
                errno,
            },
            None => Cause::Unverifiable { field },
        };
        Failure::Observed {
            boundary,
            cause,
            source: Some(source),
        }
    }

    fn io_error(boundary: &'static str, operation: u8, field: u8, source: io::Error) -> Failure {
        let cause = match source.raw_os_error() {
            Some(errno) => Cause::Io {
                operation,
                field,
                errno,
            },
            None => Cause::Unverifiable { field },
        };
        Failure::Observed {
            boundary,
            cause,
            source: Some(source),
        }
    }

    #[derive(Debug)]
    enum PrivateObservation {
        Pending,
        Eof,
        Record(OwnedRecord),
    }

    fn read_private_record(fd: i32) -> Result<PrivateObservation, Failure> {
        let mut buffer = [0; 129];
        // SAFETY: the held private receiver is nonblocking. One packet and the
        // 129-byte sentinel fit this live buffer; a longer packet reports only
        // the captured prefix.
        let count = unsafe { read(fd, buffer.as_mut_ptr(), buffer.len()) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(PrivateObservation::Pending);
            }
            return Err(io_error("owned.child.spawn", 5, 24, error));
        }
        if count == 0 {
            return Ok(PrivateObservation::Eof);
        }
        match rivect_sandbox_helper::parse_owned_record_observed(&buffer[..count as usize]) {
            Ok(record) => Ok(PrivateObservation::Record(record)),
            Err(cause) => Err(observed("owned.child.spawn", cause)),
        }
    }

    fn budget(deadline: Instant, boundary: &'static str) -> Result<(), Failure> {
        if Instant::now() >= deadline {
            Err(observed(boundary, Cause::Deadline))
        } else {
            Ok(())
        }
    }

    fn decimal(bytes: &[u8]) -> Option<u32> {
        if bytes.is_empty()
            || (bytes.len() > 1 && bytes[0] == b'0')
            || !bytes.iter().all(u8::is_ascii_digit)
        {
            return None;
        }
        std::str::from_utf8(bytes).ok()?.parse().ok()
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Absorb {
        Eof(usize),
        More(usize),
        Over { observed: usize },
    }

    /// A zero read finishes the file and keeps bytes already held.
    /// A positive read under the cap is more of that file, not a deadline.
    fn absorb_read(held: usize, count: usize, cap: usize) -> Absorb {
        if count == 0 {
            return Absorb::Eof(held);
        }
        let observed = held.saturating_add(count);
        if observed > cap {
            Absorb::Over { observed }
        } else {
            Absorb::More(observed)
        }
    }

    fn read_limit(boundary: &'static str, field: u8, cap: usize, seen: usize) -> Failure {
        observed(
            boundary,
            Cause::Limit {
                field,
                limit: cap as u64,
                observed: seen as u64,
            },
        )
    }

    fn read_file(
        path: &str,
        cap: usize,
        field: u8,
        boundary: &'static str,
        deadline: Instant,
    ) -> Result<Vec<u8>, Failure> {
        budget(deadline, boundary)?;
        let mut file = File::open(path).map_err(|error| io_error(boundary, 4, field, error))?;
        budget(deadline, boundary)?;
        let mut bytes = vec![0; cap + 1];
        let mut length = 0;
        loop {
            let count = file
                .read(&mut bytes[length..])
                .map_err(|error| io_error(boundary, 5, field, error))?;
            match absorb_read(length, count, cap) {
                Absorb::Eof(done) => {
                    bytes.truncate(done);
                    return Ok(bytes);
                }
                Absorb::Over { observed } => {
                    return Err(read_limit(boundary, field, cap, observed));
                }
                Absorb::More(next) => {
                    length = next;
                    // Bytes already landed. A deadline here must not drop a
                    // file whose next read is EOF. One probe decides that.
                    if budget(deadline, boundary).is_err() {
                        let extra = file
                            .read(&mut bytes[length..])
                            .map_err(|error| io_error(boundary, 5, field, error))?;
                        match absorb_read(length, extra, cap) {
                            Absorb::Eof(done) => {
                                bytes.truncate(done);
                                return Ok(bytes);
                            }
                            Absorb::Over { observed } => {
                                return Err(read_limit(boundary, field, cap, observed));
                            }
                            Absorb::More(_) => {
                                return Err(observed(boundary, Cause::Deadline));
                            }
                        }
                    }
                }
            }
        }
    }

    fn tracer(boundary: &'static str, deadline: Instant) -> Result<(), Failure> {
        let bytes = read_file("/proc/self/status", 65_536, 2, boundary, deadline)?;
        let mut tracer = None;
        let mut count = 0;
        // The status file is already complete. A later deadline must not
        // turn a TracerPid that is already in those bytes into a fault.
        for line in bytes.split_inclusive(|byte| *byte == b'\n') {
            if let Some(value) = line.strip_prefix(b"TracerPid:") {
                count += 1;
                if count > 1 {
                    return Err(observed(boundary, Cause::Duplicate { field: 2, count }));
                }
                let word = value.strip_suffix(b"\n").ok_or_else(|| {
                    observed(
                        boundary,
                        Cause::EarlyEof {
                            field: 2,
                            expected: bytes.len() as u64 + 1,
                            observed: bytes.len() as u64,
                        },
                    )
                })?;
                let width = word
                    .iter()
                    .take_while(|byte| matches!(byte, b' ' | b'\t'))
                    .count();
                let actual = decimal(&word[width..]).ok_or_else(|| {
                    observed(
                        boundary,
                        Cause::Malformed {
                            field: 2,
                            offset: 0,
                        },
                    )
                })?;
                if width == 0 {
                    return Err(observed(
                        boundary,
                        Cause::Malformed {
                            field: 2,
                            offset: 0,
                        },
                    ));
                }
                if actual != 0 {
                    return Err(observed(
                        boundary,
                        Cause::Readback {
                            field: 2,
                            actual: i64::from(actual),
                        },
                    ));
                }
                tracer = Some(actual);
            }
        }
        if tracer.is_none() {
            return Err(observed(boundary, Cause::Missing { field: 2 }));
        }
        Ok(())
    }

    fn dumpable(boundary: &'static str, initial: bool, deadline: Instant) -> Result<(), Failure> {
        budget(deadline, boundary)?;
        // SAFETY: these prctl options take only integer operands.
        if !initial && unsafe { sys::prctl(4, 0, 0, 0, 0) } == -1 {
            return Err(os_error(boundary, 1, 1));
        }
        // SAFETY: PR_GET_DUMPABLE has no pointer operands.
        // The set already landed. A deadline during that prctl must not
        // skip the readback or replace a matching value with a fault.
        let actual = unsafe { sys::prctl(3, 0, 0, 0, 0) };
        if actual == -1 {
            return Err(os_error(boundary, 2, 1));
        }
        if (initial && actual != 0 && actual != 1) || (!initial && actual != 0) {
            return Err(observed(
                boundary,
                Cause::Readback {
                    field: 1,
                    actual: i64::from(actual),
                },
            ));
        }
        Ok(())
    }

    fn protected(init: bool, deadline: Instant) -> Result<(), Failure> {
        dumpable(
            if init {
                "owned.init.dumpable"
            } else {
                "owned.waiter.dumpable"
            },
            false,
            deadline,
        )?;
        tracer("owned.waiter.tracer", deadline)
    }

    fn overflow(
        path: &str,
        field: u8,
        boundary: &'static str,
        deadline: Instant,
    ) -> Result<u32, Failure> {
        let bytes = read_file(path, 32, field, boundary, deadline)?;
        let body = bytes.strip_suffix(b"\n").ok_or_else(|| {
            observed(
                boundary,
                Cause::EarlyEof {
                    field,
                    expected: bytes.len() as u64 + 1,
                    observed: bytes.len() as u64,
                },
            )
        })?;
        decimal(body).ok_or_else(|| observed(boundary, Cause::Malformed { field, offset: 0 }))
    }

    fn close(fd: i32, boundary: &'static str, field: u8, deadline: Instant) -> Result<(), Failure> {
        let _ = deadline;
        // SAFETY: this caller transfers the acquired fd's sole ownership; no retry follows.
        let closed = unsafe { sys::close(fd) };
        if closed == -1 {
            return Err(os_error(boundary, 7, field));
        }
        // The descriptor is already closed. An elapsed deadline must not
        // turn that success into a fault or skip a record already in hand.
        Ok(())
    }

    fn write_record(
        fd: i32,
        record: OwnedRecord,
        deadline: Instant,
        boundary: &'static str,
    ) -> Result<(), Failure> {
        budget(deadline, boundary)?;
        write_frame(fd, record, boundary)
    }

    /// Publishes one record that is already the result. An elapsed grace
    /// must not skip this write; the caller already decided the bytes.
    fn write_frame(fd: i32, record: OwnedRecord, boundary: &'static str) -> Result<(), Failure> {
        let frame = record.encode().map_err(|_malformed| {
            observed("owned.child.spawn", Cause::Unverifiable { field: 24 })
        })?;
        // SAFETY: the complete bounded encoded record lives for this single write.
        let written = unsafe { sys::write(fd, frame.as_ptr().cast(), frame.len()) };
        if written < 0 {
            return Err(os_error(boundary, 6, 24));
        }
        if written as usize != frame.len() {
            return Err(observed(
                boundary,
                Cause::WriteCount {
                    requested: frame.len() as u64,
                    returned: written as u64,
                },
            ));
        }
        Ok(())
    }

    /// A validated entry is ready once its EOF arrives, or once a stop finds
    /// the private receiver empty. A stop that has not yet seen an empty
    /// receiver waits for one more read. An entry already published, or a
    /// primary fault, is not published again.
    fn entry_ready_to_publish(
        private_ready: bool,
        private_eof: bool,
        stop_set: bool,
        private_settled: bool,
        entered: bool,
        has_primary: bool,
    ) -> bool {
        !entered && !has_primary && private_ready && (private_eof || (stop_set && private_settled))
    }

    fn fail_stop() -> ! {
        loop {
            // SAFETY: a zero-length poll has no fd pointers; the init's absolute bound tears down this child.
            unsafe {
                poll(std::ptr::null_mut(), 0, 50);
            }
        }
    }

    fn fatal(fd: i32, error: Failure, deadline: Instant, child: bool) -> ! {
        let _ = deadline;
        let sent = error.fault().is_some_and(|fault| {
            // The fault is already in hand. Write it even when the grace
            // clock has elapsed; a refused write still exits below.
            write_frame(
                fd,
                OwnedRecord::Fault(fault),
                if child {
                    "owned.child.spawn"
                } else {
                    "owned.protocol.write"
                },
            )
            .is_ok()
        });
        let _error = std::mem::ManuallyDrop::new(error);
        if child && !sent {
            fail_stop();
        }
        std::process::exit(super::EXIT_SANDBOX_INIT);
    }

    fn namespace(flags: i32, boundary: &'static str, deadline: Instant) -> Result<(), Failure> {
        budget(deadline, boundary)?;
        // SAFETY: unshare accepts the fixed namespace flag, without pointer operands.
        if unsafe { unshare(flags) } == -1 {
            return Err(os_error(boundary, 3, 0));
        }
        // The namespace is already changed. A deadline during unshare must
        // not turn that success into a fault.
        Ok(())
    }

    fn map_fd(
        path: &std::ffi::CStr,
        boundary: &'static str,
        deadline: Instant,
    ) -> Result<i32, Failure> {
        budget(deadline, boundary)?;
        // SAFETY: fixed proc path, write-only without creation, and atomic CLOEXEC.
        let raw = unsafe { sys::open(path.as_ptr(), 1 | 0o2_000_000, 0) };
        if raw == -1 {
            return Err(os_error(boundary, 4, 0));
        }
        // SAFETY: raw is a newly acquired descriptor and this File uniquely owns it.
        let file = unsafe { File::from_raw_fd(raw) };
        validate_map_fd(file, boundary, deadline, &mut |file| {
            retire_map_fd(file, mapping_close_boundary(boundary), deadline)
        })
    }

    fn retire_map_fd(file: File, boundary: &'static str, deadline: Instant) -> Result<(), Failure> {
        // Validation already froze the primary failure. Check the bound around
        // retirement without replacing it or skipping the acquired descriptor.
        drop(budget(deadline, boundary));
        let fd = file.into_raw_fd();
        // SAFETY: ownership is consumed once; an error never retries this number.
        let result = if unsafe { sys::close(fd) } == -1 {
            Err(os_error(boundary, 7, 0))
        } else {
            Ok(())
        };
        drop(budget(deadline, boundary));
        result
    }

    fn mapping_close_boundary(boundary: &'static str) -> &'static str {
        match boundary {
            "owned.namespace.setgroups.open" => "owned.namespace.setgroups.close",
            "owned.namespace.uid_map.open" => "owned.namespace.uid_map.close",
            _ => "owned.namespace.gid_map.close",
        }
    }

    fn validate_map_fd(
        file: File,
        boundary: &'static str,
        deadline: Instant,
        retire: &mut impl FnMut(File) -> Result<(), Failure>,
    ) -> Result<i32, Failure> {
        use std::os::fd::AsRawFd as _;
        let raw = file.as_raw_fd();
        let validation = (|| {
            let metadata = file
                .metadata()
                .map_err(|error| io_error(boundary, 11, 19, error))?;
            if raw < 3 {
                return Err(observed(
                    boundary,
                    Cause::Mismatch {
                        field: 19,
                        expected: 3,
                        observed: raw as u64,
                    },
                ));
            }
            if !metadata.is_file() {
                return Err(observed(
                    boundary,
                    Cause::Mismatch {
                        field: 33,
                        expected: 1,
                        observed: 0,
                    },
                ));
            }
            if metadata.nlink() != 1 {
                return Err(observed(
                    boundary,
                    Cause::Mismatch {
                        field: 34,
                        expected: 1,
                        observed: metadata.nlink(),
                    },
                ));
            }
            // SAFETY: F_GETFD observes the live descriptor's flags.
            let flags = unsafe { fcntl(raw, 1) };
            if flags == -1 {
                return Err(os_error(boundary, 19, 32));
            }
            if flags & 1 == 0 {
                return Err(observed(
                    boundary,
                    Cause::Mismatch {
                        field: 32,
                        expected: 1,
                        observed: flags as u64,
                    },
                ));
            }
            // Every check already passed. A deadline during the last flag
            // read must not retire this descriptor or replace it with a fault.
            // The next map write consults the deadline before using it.
            let _ = deadline;
            Ok(())
        })();
        if let Err(primary) = validation {
            return Err(match retire(file) {
                Ok(()) => primary,
                Err(secondary) => primary.with_retirement(secondary),
            });
        }
        Ok(file.into_raw_fd())
    }

    fn private_fault_admitted(fault: OwnedFault, ready: bool) -> bool {
        if ready {
            return fault.boundary() == "owned.child.spawn"
                && matches!(
                    fault.cause(),
                    Cause::Io {
                        operation: 25,
                        field: 0,
                        ..
                    }
                );
        }
        fault.boundary() != "owned.child.spawn"
            || !matches!(
                fault.cause(),
                Cause::Io {
                    operation: 5 | 22,
                    field: 24,
                    ..
                } | Cause::Io {
                    operation: 7,
                    field: 20,
                    ..
                } | Cause::Io {
                    operation: 14,
                    field: 0,
                    ..
                } | Cause::Missing { field: 24 }
                    | Cause::Duplicate { field: 24, .. }
                    | Cause::Malformed { field: 24, .. }
                    | Cause::NumericOverflow { field: 24, .. }
                    | Cause::Trailing { field: 24, .. }
                    | Cause::Limit { field: 24, .. }
                    | Cause::EarlyEof { field: 24, .. }
            )
    }

    #[cfg(test)]
    pub(super) fn assert_private_fault_roles() {
        assert_parent_stop_frames();
        assert_parent_stop_reads();
        assert_init_fault_admission();
        assert_private_record_reads();
        assert_deadline_grace();
        assert_entry_ready_to_publish();
    }

    #[cfg(test)]
    fn assert_parent_stop_frames() {
        for (frame, stop) in [
            (
                &b"owned-launch-v1 stop cancelled\n"[..],
                OwnedStop::Cancelled,
            ),
            (&b"owned-launch-v1 stop deadline\n"[..], OwnedStop::Deadline),
            (
                &b"owned-launch-v1 stop observation\n"[..],
                OwnedStop::Observation,
            ),
            (
                &b"owned-launch-v1 stop control_lost\n"[..],
                OwnedStop::ControlLost,
            ),
        ] {
            let parsed = decode_parent_stop(frame);
            assert!(
                parsed.as_ref().is_ok_and(|parsed| *parsed == stop),
                "parent stop {frame:?} must stay the typed stop {stop:?}, got {parsed:?}"
            );
        }
        let trailing = decode_parent_stop(b"owned-launch-v1 stop cancelledX\n");
        assert!(
            matches!(
                trailing,
                Err(Failure::Observed {
                    cause: Cause::Malformed { field: 24, offset },
                    ..
                }) if offset == b"owned-launch-v1 stop cancelled".len() as u64
            ),
            "a trailing stop byte must be malformed at its own offset, got {trailing:?}"
        );
        let wrong_first = decode_parent_stop(b"Xwned-launch-v1 stop cancelled\n");
        assert!(
            matches!(
                wrong_first,
                Err(Failure::Observed {
                    cause: Cause::Malformed {
                        field: 24,
                        offset: 0,
                    },
                    ..
                })
            ),
            "a wrong first byte must be malformed at offset 0, got {wrong_first:?}"
        );
        let empty = finish_parent_eof(b"");
        assert!(
            matches!(empty, Ok(OwnedStop::ControlLost)),
            "an empty control close must be control loss, got {empty:?}"
        );
        let partial_stop = finish_parent_eof(b"owned-launch-v1 stop");
        assert!(
            matches!(
                partial_stop,
                Err(Failure::Observed {
                    cause:
                        Cause::EarlyEof {
                            field: 24,
                            expected,
                            observed,
                        },
                    ..
                }) if observed == b"owned-launch-v1 stop".len() as u64 && expected == observed + 1
            ),
            "a partial stop must be early eof at its length, got {partial_stop:?}"
        );
    }

    #[cfg(test)]
    fn assert_parent_stop_reads() {
        let mut stop_pair = [0_i32; 2];
        // SAFETY: this fixture owns both ends of a fresh control stream.
        assert_eq!(unsafe { socketpair(1, 1, 0, stop_pair.as_mut_ptr()) }, 0);
        // SAFETY: F_SETFL/O_NONBLOCK matches the init control reader.
        assert_eq!(unsafe { fcntl(stop_pair[0], 4, 2048) }, 0);
        let cancel = b"owned-launch-v1 stop cancelled\n";
        // SAFETY: the writer end is live and the frame remains immutable.
        let cancel_written =
            unsafe { sys::write(stop_pair[1], cancel.as_ptr().cast(), cancel.len()) };
        assert_eq!(cancel_written, cancel.len() as isize);
        let mut stop_bytes = Vec::new();
        let stopped = parent_stop(
            stop_pair[0],
            &mut stop_bytes,
            Instant::now() + Duration::from_secs(5),
        );
        assert!(
            matches!(stopped, Ok(Some(OwnedStop::Cancelled))),
            "a complete parent stop must be returned, got {stopped:?}"
        );
        // SAFETY: both fixture ends are still open and owned by this test.
        unsafe {
            sys::close(stop_pair[0]);
            sys::close(stop_pair[1]);
        }
        let mut partial_pair = [0_i32; 2];
        // SAFETY: this fixture owns both ends of a fresh control stream.
        assert_eq!(unsafe { socketpair(1, 1, 0, partial_pair.as_mut_ptr()) }, 0);
        // SAFETY: F_SETFL/O_NONBLOCK matches the init control reader.
        assert_eq!(unsafe { fcntl(partial_pair[0], 4, 2048) }, 0);
        let partial = b"owned-launch-v1 stop";
        // SAFETY: the writer end is live and the partial frame remains immutable.
        let partial_written =
            unsafe { sys::write(partial_pair[1], partial.as_ptr().cast(), partial.len()) };
        assert_eq!(partial_written, partial.len() as isize);
        let mut partial_bytes = Vec::new();
        let buffered = parent_stop(
            partial_pair[0],
            &mut partial_bytes,
            Instant::now() + Duration::from_secs(5),
        );
        assert!(
            matches!(buffered, Ok(None)),
            "an incomplete parent frame must stay buffered, got {buffered:?}"
        );
        assert_eq!(partial_bytes, partial);
        // SAFETY: both fixture ends are still open and owned by this test.
        unsafe {
            sys::close(partial_pair[0]);
            sys::close(partial_pair[1]);
        }
        let mut queued = [0_i32; 2];
        // SAFETY: this fixture owns both ends of a fresh control stream.
        assert_eq!(unsafe { socketpair(1, 1, 0, queued.as_mut_ptr()) }, 0);
        // SAFETY: F_SETFL/O_NONBLOCK matches the init control reader.
        assert_eq!(unsafe { fcntl(queued[0], 4, 2048) }, 0);
        // SAFETY: the writer end is live and the frame remains immutable.
        let queued_written = unsafe { sys::write(queued[1], cancel.as_ptr().cast(), cancel.len()) };
        assert_eq!(queued_written, cancel.len() as isize);
        let mut queued_bytes = Vec::new();
        let outranked = parent_stop(queued[0], &mut queued_bytes, Instant::now());
        assert!(
            matches!(outranked, Ok(Some(OwnedStop::Cancelled))),
            "a queued cancel outranks an already elapsed deadline, got {outranked:?}"
        );
        // SAFETY: both fixture ends are still open and owned by this test.
        unsafe {
            sys::close(queued[0]);
            sys::close(queued[1]);
        }
        let mut idle = [0_i32; 2];
        // SAFETY: this fixture owns both ends of a fresh control stream.
        assert_eq!(unsafe { socketpair(1, 1, 0, idle.as_mut_ptr()) }, 0);
        // SAFETY: F_SETFL/O_NONBLOCK matches the init control reader.
        assert_eq!(unsafe { fcntl(idle[0], 4, 2048) }, 0);
        let mut idle_bytes = Vec::new();
        let elapsed = parent_stop(idle[0], &mut idle_bytes, Instant::now());
        assert!(
            matches!(elapsed, Ok(Some(OwnedStop::Deadline))),
            "an idle elapsed deadline is a stop, not a fault, got {elapsed:?}"
        );
        assert!(idle_bytes.is_empty());
        // SAFETY: both fixture ends are still open and owned by this test.
        unsafe {
            sys::close(idle[0]);
            sys::close(idle[1]);
        }
        let mut late_partial = [0_i32; 2];
        // SAFETY: this fixture owns both ends of a fresh control stream.
        assert_eq!(unsafe { socketpair(1, 1, 0, late_partial.as_mut_ptr()) }, 0);
        // SAFETY: F_SETFL/O_NONBLOCK matches the init control reader.
        assert_eq!(unsafe { fcntl(late_partial[0], 4, 2048) }, 0);
        // SAFETY: the writer end is live and the partial frame remains immutable.
        let late_written =
            unsafe { sys::write(late_partial[1], partial.as_ptr().cast(), partial.len()) };
        assert_eq!(late_written, partial.len() as isize);
        let mut late_partial_bytes = Vec::new();
        let kept_partial = parent_stop(late_partial[0], &mut late_partial_bytes, Instant::now());
        assert!(
            matches!(kept_partial, Ok(None)),
            "an elapsed deadline must not turn a partial frame into a fault, got {kept_partial:?}"
        );
        assert_eq!(late_partial_bytes, partial);
        // SAFETY: both fixture ends are still open and owned by this test.
        unsafe {
            sys::close(late_partial[0]);
            sys::close(late_partial[1]);
        }
    }

    #[cfg(test)]
    fn assert_init_fault_admission() {
        for (operation, field) in [(5, 24), (22, 24), (7, 20), (14, 0)] {
            let fault = OwnedFault::new(
                "owned.child.spawn",
                Cause::Io {
                    operation,
                    field,
                    errno: 5,
                },
            )
            .expect("independent valid init-only fault");
            for ready in [false, true] {
                assert!(
                    !private_fault_admitted(fault, ready),
                    "an init receiver fault cannot be delivered as a child fault"
                );
            }
        }
        for cause in [
            Cause::Missing { field: 24 },
            Cause::Duplicate {
                field: 24,
                count: 2,
            },
            Cause::Malformed {
                field: 24,
                offset: 4,
            },
            Cause::NumericOverflow {
                field: 24,
                offset: 4,
            },
            Cause::Trailing {
                field: 24,
                offset: 4,
            },
            Cause::Limit {
                field: 24,
                limit: 128,
                observed: 129,
            },
            Cause::EarlyEof {
                field: 24,
                expected: 5,
                observed: 4,
            },
        ] {
            let fault = OwnedFault::new("owned.child.spawn", cause)
                .expect("independent valid init shape fault");
            assert!(!private_fault_admitted(fault, false));
            assert!(!private_fault_admitted(fault, true));
        }
        let cap = OwnedFault::new(
            "owned.child.capabilities",
            Cause::Io {
                operation: 16,
                field: 0,
                errno: 5,
            },
        )
        .expect("independent child capset fault");
        assert!(private_fault_admitted(cap, false));
        assert!(
            !private_fault_admitted(cap, true),
            "a capset fault cannot follow readiness"
        );
        let exec = OwnedFault::new(
            "owned.child.spawn",
            Cause::Io {
                operation: 25,
                field: 0,
                errno: 2,
            },
        )
        .expect("independent returned exec fault");
        assert!(private_fault_admitted(exec, true));
    }

    #[cfg(test)]
    fn assert_private_record_reads() {
        let mut pair = [0_i32; 2];
        // SAFETY: this fixture owns both ends of a fresh private seqpacket.
        let created = unsafe { socketpair(1, 5 | 0x80000, 0, pair.as_mut_ptr()) };
        assert_eq!(created, 0);
        // SAFETY: F_SETFL/O_NONBLOCK matches the init receiver and no other fd.
        assert_eq!(unsafe { fcntl(pair[0], 4, 2048) }, 0);
        assert!(matches!(
            read_private_record(pair[0]),
            Ok(PrivateObservation::Pending)
        ));
        let literal = b"owned-launch-v1 terminal fault owned.child.spawn 0g\n";
        // SAFETY: the writer end is live and the literal remains immutable.
        let literal_written =
            unsafe { sys::write(pair[1], literal.as_ptr().cast(), literal.len()) };
        assert_eq!(literal_written, literal.len() as isize);
        let kept_byte = read_private_record(pair[0]);
        assert!(
            matches!(
                kept_byte,
                Err(Failure::Observed {
                    boundary: "owned.child.spawn",
                    cause: Cause::Malformed {
                        field: 24,
                        offset: 50,
                    },
                    source: None,
                })
            ),
            "receiver must keep the 0g byte, got {kept_byte:?}"
        );
        let over = [1_u8; 200];
        // SAFETY: the same writer end is still live; the packet is longer than the receiver buffer.
        let over_written = unsafe { sys::write(pair[1], over.as_ptr().cast(), over.len()) };
        assert_eq!(over_written, over.len() as isize);
        let capped = read_private_record(pair[0]);
        assert!(
            matches!(
                capped,
                Err(Failure::Observed {
                    cause: Cause::Limit {
                        field: 24,
                        limit: 128,
                        observed: 129,
                    },
                    ..
                })
            ),
            "over-cap prefix is the captured 129 bytes, got {capped:?}"
        );
        // SAFETY: closing only this fixture writer produces the receiver EOF.
        assert_eq!(unsafe { sys::close(pair[1]) }, 0);
        assert!(matches!(
            read_private_record(pair[0]),
            Ok(PrivateObservation::Eof)
        ));
        // SAFETY: the reader end is still open and owned by this fixture.
        assert_eq!(unsafe { sys::close(pair[0]) }, 0);
        assert_eq!(absorb_read(12, 0, 64), Absorb::Eof(12));
        assert_eq!(absorb_read(12, 4, 64), Absorb::More(16));
        assert_eq!(absorb_read(60, 8, 64), Absorb::Over { observed: 68 });
    }

    #[cfg(test)]
    fn assert_deadline_grace() {
        let fresh = Instant::now() + Duration::from_secs(5);
        let status = read_file("/proc/self/status", 65_536, 2, "owned.waiter.tracer", fresh)
            .expect("a live status file inside the deadline");
        assert!(
            status.windows(10).any(|window| window == b"TracerPid:"),
            "a finished status read keeps TracerPid"
        );
        assert!(matches!(
            read_file(
                "/proc/self/status",
                65_536,
                2,
                "owned.waiter.tracer",
                Instant::now(),
            ),
            Err(Failure::Observed {
                cause: Cause::Deadline,
                ..
            })
        ));
        assert!(matches!(tracer("owned.waiter.tracer", fresh), Ok(())));
        assert!(matches!(
            tracer("owned.waiter.tracer", Instant::now()),
            Err(Failure::Observed {
                cause: Cause::Deadline,
                ..
            })
        ));
        assert!(matches!(
            dumpable("owned.waiter.dumpable", true, fresh),
            Ok(())
        ));
        let held = File::open("/dev/null").expect("close control");
        let held_fd = held.into_raw_fd();
        assert!(
            close(held_fd, "owned.child.spawn", 0, Instant::now()).is_ok(),
            "a successful close stays success after the deadline"
        );
        // SAFETY: F_GETFD only observes the descriptor that close retired, with no retry close.
        assert_eq!(unsafe { fcntl(held_fd, 1) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(9));
        let mut late = [0_i32; 2];
        // SAFETY: this fixture owns both ends of a fresh control stream.
        assert_eq!(unsafe { socketpair(1, 1, 0, late.as_mut_ptr()) }, 0);
        // SAFETY: F_SETFL/O_NONBLOCK matches the init control reader.
        assert_eq!(unsafe { fcntl(late[0], 4, 2048) }, 0);
        assert!(matches!(
            write_record(
                late[1],
                OwnedRecord::Stop(OwnedStop::Cancelled),
                Instant::now(),
                "owned.protocol.terminal",
            ),
            Err(Failure::Observed {
                cause: Cause::Deadline,
                ..
            })
        ));
        let mut missed = [0_u8; 8];
        // SAFETY: the reader end is live and the buffer is valid for its full length.
        let missed_count = unsafe { read(late[0], missed.as_mut_ptr(), missed.len()) };
        assert_eq!(missed_count, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(11));
        assert!(
            write_frame(
                late[1],
                OwnedRecord::Stop(OwnedStop::Cancelled),
                "owned.protocol.terminal",
            )
            .is_ok(),
            "a record already in hand is written after the deadline"
        );
        let mut landed = [0_u8; 64];
        // SAFETY: the reader end is live and the buffer is valid for its full length.
        let count = unsafe { read(late[0], landed.as_mut_ptr(), landed.len()) };
        assert!(count > 0, "the grace publication must reach the socket");
        assert_eq!(
            &landed[..count as usize],
            b"owned-launch-v1 terminal stop cancelled\n"
        );
        // SAFETY: both fixture ends are still open and owned by this test.
        unsafe {
            sys::close(late[0]);
            sys::close(late[1]);
        }
    }

    #[cfg(test)]
    fn assert_entry_ready_to_publish() {
        assert!(entry_ready_to_publish(
            true, true, false, false, false, false
        ));
        assert!(entry_ready_to_publish(
            true, false, true, true, false, false
        ));
        assert!(!entry_ready_to_publish(
            true, false, false, false, false, false
        ));
        assert!(!entry_ready_to_publish(
            true, false, true, false, false, false
        ));
        assert!(!entry_ready_to_publish(true, true, true, true, true, false));
        assert!(!entry_ready_to_publish(true, true, true, true, false, true));
        assert!(!entry_ready_to_publish(
            false, true, true, true, false, false
        ));
    }

    #[cfg(test)]
    pub(super) fn assert_map_validation_retires_once() {
        use std::os::fd::AsRawFd as _;
        let file = File::open("/dev/null").expect("native nonregular validation control");
        let fd = file.as_raw_fd();
        let mut closes = 0;
        let result = validate_map_fd(
            file,
            "owned.namespace.uid_map.open",
            Instant::now() + Duration::from_secs(1),
            &mut |file| {
                closes += 1;
                close(
                    file.into_raw_fd(),
                    "owned.namespace.uid_map.close",
                    0,
                    Instant::now() + Duration::from_secs(1),
                )
            },
        );
        assert_eq!(
            closes, 1,
            "an acquired map FD must receive checked once retirement on validation failure"
        );
        assert!(matches!(
            result,
            Err(Failure::Observed {
                boundary: "owned.namespace.uid_map.open",
                cause: Cause::Mismatch {
                    field: 33,
                    expected: 1,
                    observed: 0
                },
                ..
            })
        ));
        // SAFETY: F_GETFD only observes the retired descriptor, with no retry close.
        assert_eq!(unsafe { fcntl(fd, 1) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(9));
        let path = std::env::temp_dir().join(format!("rivect-map-validate-{}", std::process::id()));
        std::fs::write(&path, b"map").expect("validated map fixture");
        let file = File::open(&path).expect("validated map file");
        let mut kept_closes = 0;
        let kept = validate_map_fd(
            file,
            "owned.namespace.uid_map.open",
            Instant::now(),
            &mut |file| {
                kept_closes += 1;
                close(
                    file.into_raw_fd(),
                    "owned.namespace.uid_map.close",
                    0,
                    Instant::now(),
                )
            },
        );
        drop(std::fs::remove_file(&path));
        let kept_fd = kept.expect("a validated map fd must survive an elapsed deadline");
        assert_eq!(
            kept_closes, 0,
            "a validated map fd must not be retired when its checks already passed"
        );
        // SAFETY: the validated descriptor is still open and owned by this test.
        unsafe {
            sys::close(kept_fd);
        }
    }

    fn map_write(
        fd: i32,
        bytes: &[u8],
        boundary: &'static str,
        deadline: Instant,
    ) -> Result<(), Failure> {
        budget(deadline, boundary)?;
        // SAFETY: the held mapping descriptor and immutable exact mapping bytes remain live.
        let count = unsafe { sys::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if count < 0 {
            return Err(os_error(boundary, 6, 0));
        }
        if count as usize != bytes.len() {
            return Err(observed(
                boundary,
                Cause::WriteCount {
                    requested: bytes.len() as u64,
                    returned: count as u64,
                },
            ));
        }
        // The mapping bytes are already written. A deadline during that
        // write must not turn it into a fault.
        Ok(())
    }

    fn map_state(
        stage: usize,
        uid: u32,
        gid: u32,
        overflow_uid: u32,
        overflow_gid: u32,
        deadline: Instant,
    ) -> Result<(), Failure> {
        let boundary = [
            "owned.namespace.setgroups.readback",
            "owned.namespace.uid_map.readback",
            "owned.namespace.gid_map.readback",
        ][stage];
        let setgroups = read_file("/proc/self/setgroups", 65_536, 14, boundary, deadline)?;
        if setgroups == b"allow\n" {
            return Err(observed(boundary, Cause::SetgroupsAllow));
        }
        if setgroups != b"deny\n" {
            return Err(observed(
                boundary,
                Cause::Malformed {
                    field: 14,
                    offset: 0,
                },
            ));
        }
        for (ordinal, (path, field, wanted)) in [
            ("/proc/self/uid_map", 15, uid),
            ("/proc/self/gid_map", 16, gid),
        ]
        .into_iter()
        .enumerate()
        {
            let bytes = read_file(path, 65_536, field, boundary, deadline)?;
            let written = stage > ordinal;
            let lines: Vec<_> = bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .collect();
            let expected_count = usize::from(written);
            if lines.len() > expected_count {
                let words: Vec<_> = lines[expected_count]
                    .split(|byte| byte.is_ascii_whitespace())
                    .filter(|word| !word.is_empty())
                    .collect();
                let inside = words
                    .first()
                    .and_then(|word| decimal(word))
                    .ok_or_else(|| observed(boundary, Cause::Malformed { field, offset: 0 }))?;
                let outside = words
                    .get(1)
                    .and_then(|word| decimal(word))
                    .ok_or_else(|| observed(boundary, Cause::Malformed { field, offset: 0 }))?;
                let ordinal_count = ((expected_count as u64) << 32) | lines.len() as u64;
                return Err(observed(
                    boundary,
                    if ordinal == 0 {
                        Cause::ExtraMap {
                            ordinal_count,
                            inside,
                            outside,
                        }
                    } else {
                        Cause::ExtraGidMap {
                            ordinal_count,
                            inside,
                            outside,
                        }
                    },
                ));
            }
            if lines.len() < expected_count {
                return Err(observed(boundary, Cause::Missing { field }));
            }
            if written {
                let words: Vec<_> = lines[0]
                    .split(|byte| byte.is_ascii_whitespace())
                    .filter(|word| !word.is_empty())
                    .collect();
                if words.len() != 3 {
                    return Err(observed(boundary, Cause::Malformed { field, offset: 0 }));
                }
                let mut actual = [0; 3];
                for (index, word) in words.iter().enumerate() {
                    actual[index] = decimal(word)
                        .ok_or_else(|| observed(boundary, Cause::Malformed { field, offset: 0 }))?;
                }
                let expected = [wanted, wanted, 1];
                if expected != actual {
                    let pair = |index: usize| {
                        (u64::from(expected[index]) << 32) | u64::from(actual[index])
                    };
                    return Err(observed(
                        boundary,
                        if ordinal == 0 {
                            Cause::MapMismatch {
                                inside_pair: pair(0),
                                outside_pair: pair(1),
                                count_pair: pair(2),
                            }
                        } else {
                            Cause::GidMapMismatch {
                                inside_pair: pair(0),
                                outside_pair: pair(1),
                                count_pair: pair(2),
                            }
                        },
                    ));
                }
            }
        }
        // SAFETY: getuid/getgid are infallible observations of this process.
        let (actual_uid, actual_gid) = unsafe { (getuid(), getgid()) };
        for (field, expected, actual) in [
            (17, if stage > 0 { uid } else { overflow_uid }, actual_uid),
            (18, if stage > 1 { gid } else { overflow_gid }, actual_gid),
        ] {
            if expected != actual {
                return Err(observed(
                    boundary,
                    Cause::Mismatch {
                        field,
                        expected: u64::from(expected),
                        observed: u64::from(actual),
                    },
                ));
            }
        }
        // SAFETY: PR_GET_DUMPABLE has no pointer operands.
        let dumpable = unsafe { sys::prctl(3, 0, 0, 0, 0) };
        if dumpable == -1 {
            return Err(os_error(boundary, 2, 1));
        }
        if dumpable != 0 {
            return Err(observed(
                boundary,
                Cause::Readback {
                    field: 1,
                    actual: i64::from(dumpable),
                },
            ));
        }
        tracer(boundary, deadline)
    }

    fn bootstrap(parent: u32, deadline: Instant) -> Result<u32, Failure> {
        dumpable("owned.waiter.initial_dumpable", true, deadline)?;
        tracer("owned.waiter.initial_tracer", deadline)?;
        // SAFETY: the IDs are frozen before creating the user namespace.
        let (uid, gid) = unsafe { (getuid(), getgid()) };
        let overflow_uid = overflow(
            "/proc/sys/kernel/overflowuid",
            12,
            "owned.waiter.overflow_uid",
            deadline,
        )?;
        let overflow_gid = overflow(
            "/proc/sys/kernel/overflowgid",
            13,
            "owned.waiter.overflow_gid",
            deadline,
        )?;
        rivect_sandbox_helper::arm_owned_parent(false, parent, deadline)?;
        namespace(0x1000_0000, "owned.namespace.user", deadline)?;
        rivect_sandbox_helper::arm_owned_parent(false, parent, deadline)?;
        let mut maps = [None; 3];
        let result: Result<(), Failure> = (|| {
            for (index, (path, boundary)) in [
                (c"/proc/self/setgroups", "owned.namespace.setgroups.open"),
                (c"/proc/self/uid_map", "owned.namespace.uid_map.open"),
                (c"/proc/self/gid_map", "owned.namespace.gid_map.open"),
            ]
            .into_iter()
            .enumerate()
            {
                maps[index] = Some(map_fd(path, boundary, deadline)?);
            }
            protected(false, deadline)?;
            let uid_map = format!("{uid} {uid} 1\n");
            let gid_map = format!("{gid} {gid} 1\n");
            for (index, (bytes, boundary)) in [
                (b"deny\n".as_slice(), "owned.namespace.setgroups"),
                (uid_map.as_bytes(), "owned.namespace.uid_map"),
                (gid_map.as_bytes(), "owned.namespace.gid_map"),
            ]
            .into_iter()
            .enumerate()
            {
                if let Some(fd) = maps[index] {
                    map_write(fd, bytes, boundary, deadline)?;
                    // uid_map and gid_map change euid/egid and clear PDEATHSIG.
                    // setgroups does not. Re-arm before the next effect.
                    if index > 0 {
                        rivect_sandbox_helper::arm_owned_parent(false, parent, deadline)?;
                    }
                }
                map_state(index, uid, gid, overflow_uid, overflow_gid, deadline)?;
            }
            Ok(())
        })();
        let mut close_error = None;
        for (index, slot) in maps.iter_mut().enumerate() {
            if let Some(fd) = slot.take() {
                let boundary = [
                    "owned.namespace.setgroups.close",
                    "owned.namespace.uid_map.close",
                    "owned.namespace.gid_map.close",
                ][index];
                if let Err(error) = close(fd, boundary, 0, deadline)
                    && close_error.is_none()
                {
                    close_error = Some(error);
                }
            }
        }
        if let Err(primary) = result {
            return Err(match close_error {
                Some(secondary) => primary.with_retirement(secondary),
                None => primary,
            });
        }
        if let Some(error) = close_error {
            return Err(error);
        }
        namespace(0x0002_0000, "owned.namespace.mount", deadline)?;
        protected(false, deadline)?;
        rivect_sandbox_helper::arm_owned_parent(false, parent, deadline)?;
        namespace(0x2000_0000, "owned.namespace.pid", deadline)?;
        protected(false, deadline)?;
        rivect_sandbox_helper::arm_owned_parent(false, parent, deadline)?;
        rivect_sandbox_helper::owned_init_parent_identity(deadline).map_err(Failure::from)
    }

    fn private_proc(deadline: Instant) -> Result<(), Failure> {
        budget(deadline, "owned.init.proc")?;
        // SAFETY: fixed trusted mount points and flags; no caller mount data.
        if unsafe {
            sys::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                (1 << 18) | (1 << 14),
                std::ptr::null(),
            )
        } == -1
        {
            return Err(os_error("owned.init.proc", 15, 0));
        }
        budget(deadline, "owned.init.proc")?;
        // SAFETY: mounting proc in the private mount namespace exposes only this PID namespace.
        if unsafe {
            sys::mount(
                c"proc".as_ptr(),
                c"/proc".as_ptr(),
                c"proc".as_ptr(),
                2 | 4 | 8,
                std::ptr::null(),
            )
        } == -1
        {
            return Err(os_error("owned.init.proc", 15, 0));
        }
        // Both mounts are already in place. A deadline during the second
        // mount must not turn that success into a fault.
        Ok(())
    }

    fn resources(profile: OwnedProfile, deadline: Instant) -> Result<(u32, u32), Failure> {
        budget(deadline, "owned.resource.census")?;
        let mut baseline = 1_u32;
        let entries = std::fs::read_dir("/proc")
            .map_err(|error| io_error("owned.resource.census", 4, 8, error))?;
        for entry in entries {
            budget(deadline, "owned.resource.census")?;
            let entry = entry.map_err(|error| io_error("owned.resource.census", 10, 8, error))?;
            if decimal(entry.file_name().as_encoded_bytes()).is_none() {
                continue;
            }
            let tasks = std::fs::read_dir(entry.path().join("task"))
                .map_err(|error| io_error("owned.resource.census", 4, 8, error))?;
            for task in tasks {
                budget(deadline, "owned.resource.census")?;
                let task = task.map_err(|error| io_error("owned.resource.census", 10, 8, error))?;
                if decimal(task.file_name().as_encoded_bytes()).is_none() {
                    return Err(observed(
                        "owned.resource.census",
                        Cause::Malformed {
                            field: 6,
                            offset: 0,
                        },
                    ));
                }
                baseline = baseline.checked_add(1).ok_or_else(|| {
                    observed("owned.resource.census", Cause::Unverifiable { field: 22 })
                })?;
                if baseline > 4096 {
                    return Err(observed(
                        "owned.resource.census",
                        Cause::Limit {
                            field: 8,
                            limit: 4095,
                            observed: u64::from(baseline),
                        },
                    ));
                }
            }
        }
        let nproc = if profile == OwnedProfile::Check {
            baseline + 256
        } else {
            64
        };
        let limits: Vec<(i32, u8, u64)> = if profile == OwnedProfile::Check {
            vec![
                (9, 35, super::CHECK_AS_BYTES),
                (0, 36, super::CHECK_CPU_SECONDS),
                (1, 37, super::CHECK_FSIZE_BYTES),
                (7, 38, super::CHECK_NOFILE),
                (6, 39, u64::from(nproc)),
            ]
        } else {
            vec![
                (
                    9,
                    35,
                    if profile == OwnedProfile::Index {
                        super::INDEX_WORKER_MEMORY_BUDGET
                    } else {
                        512 * 1024 * 1024
                    },
                ),
                (0, 36, 30),
                (1, 37, 64 * 1024 * 1024),
                (6, 39, 64),
                (7, 38, 256),
            ]
        };
        for (resource, field, requested) in limits {
            budget(deadline, "owned.resource.limit")?;
            let mut inherited = Rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: getrlimit writes the documented repr(C) two-word limit.
            if unsafe { sys::getrlimit(resource, &mut inherited) } == -1 {
                return Err(os_error("owned.resource.limit", 27, field));
            }
            let expected = if profile == OwnedProfile::Check {
                requested.min(inherited.rlim_max)
            } else {
                requested
            };
            let limit = Rlimit {
                rlim_cur: expected,
                rlim_max: expected,
            };
            budget(deadline, "owned.resource.limit")?;
            // SAFETY: setrlimit reads this live repr(C) value and only tightens limits.
            if unsafe { sys::setrlimit(resource, &limit) } == -1 {
                return Err(os_error("owned.resource.limit", 26, field));
            }
            // The limit is already installed. A deadline during setrlimit
            // must not skip the readback or replace a matching pair with a fault.
            // SAFETY: fresh readback verifies both independently relevant limit words.
            if unsafe { sys::getrlimit(resource, &mut inherited) } == -1 {
                return Err(os_error("owned.resource.limit", 27, field));
            }
            if inherited.rlim_cur != expected {
                return Err(observed(
                    "owned.resource.limit",
                    Cause::Mismatch {
                        field,
                        expected,
                        observed: inherited.rlim_cur,
                    },
                ));
            }
            if inherited.rlim_max != expected {
                return Err(observed(
                    "owned.resource.limit",
                    Cause::HardLimitMismatch {
                        field,
                        expected,
                        observed: inherited.rlim_max,
                    },
                ));
            }
        }
        // Every limit word is already verified. A deadline during the last
        // readback must not drop that census.
        Ok((baseline, nproc))
    }

    fn pair(deadline: Instant) -> Result<[i32; 2], Failure> {
        budget(deadline, "owned.child.spawn")?;
        let mut pair = [-1; 2];
        // SAFETY: pair provides exactly two writable fd slots for this anonymous tuple.
        if unsafe { socketpair(1, 524293, 0, pair.as_mut_ptr()) } == -1 {
            return Err(os_error("owned.child.spawn", 23, 20));
        }
        for &fd in &pair {
            if fd < 3 {
                return Err(observed(
                    "owned.child.spawn",
                    Cause::Mismatch {
                        field: 20,
                        expected: 3,
                        observed: fd as u64,
                    },
                ));
            }
            budget(deadline, "owned.child.spawn")?;
            // SAFETY: F_SETFL affects only this uniquely held fresh private descriptor.
            if unsafe { fcntl(fd, 4, 0o4000) } == -1 {
                return Err(os_error("owned.child.spawn", 19, 20));
            }
            // Nonblocking is already set. A deadline during that fcntl must
            // not skip the cloexec readback or drop the pair.
            // SAFETY: F_GETFD observes the same live private descriptor.
            let flags = unsafe { fcntl(fd, 1) };
            if flags == -1 {
                return Err(os_error("owned.child.spawn", 19, 32));
            }
            if flags & 1 == 0 {
                return Err(observed(
                    "owned.child.spawn",
                    Cause::Mismatch {
                        field: 32,
                        expected: 1,
                        observed: flags as u64,
                    },
                ));
            }
        }
        // Both ends are already a cloexec private pair. A deadline during
        // the last flag read must not drop them.
        Ok(pair)
    }

    fn capabilities(deadline: Instant) -> Result<(), Failure> {
        let boundary = "owned.child.capabilities";
        budget(deadline, boundary)?;
        for cap in 0..64 {
            budget(deadline, boundary)?;
            // SAFETY: PR_CAPBSET_READ observes the fixed kernel capability index.
            let set = unsafe { sys::prctl(23, cap, 0, 0, 0) };
            if set == -1 {
                let source = io::Error::last_os_error();
                if source.raw_os_error() == Some(22) {
                    break;
                }
                return Err(io_error(boundary, 28, 29, source));
            }
            if set == 1 {
                // SAFETY: PR_CAPBSET_DROP irreversibly drops this capability in the child.
                if unsafe { sys::prctl(24, cap, 0, 0, 0) } == -1 {
                    return Err(os_error(boundary, 29, 29));
                }
            }
            // This capability is already clear. A deadline during the drop
            // must not skip its readback.
            // SAFETY: fresh bounding-set readback of the same capability.
            let actual = unsafe { sys::prctl(23, cap, 0, 0, 0) };
            if actual == -1 {
                return Err(os_error(boundary, 28, 29));
            }
            if actual != 0 {
                return Err(observed(
                    boundary,
                    Cause::Mismatch {
                        field: 29,
                        expected: 0,
                        observed: actual as u64,
                    },
                ));
            }
        }
        budget(deadline, boundary)?;
        // SAFETY: PR_CAP_AMBIENT_CLEAR_ALL clears the child's ambient set.
        if unsafe { sys::prctl(47, 4, 0, 0, 0) } == -1 {
            return Err(os_error(boundary, 30, 28));
        }
        let header = sys::CapHeader {
            version: 0x2008_0522,
            pid: 0,
        };
        let mut data = [sys::CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        #[cfg(target_arch = "x86_64")]
        let (set, get) = (126, 125);
        #[cfg(target_arch = "aarch64")]
        let (set, get) = (91, 90);
        budget(deadline, boundary)?;
        // SAFETY: V3 capset consumes the two capability words in this documented layout.
        if unsafe { sys::syscall(set, &header, data.as_ptr()) } == -1 {
            return Err(os_error(boundary, 16, 0));
        }
        // The capability set already landed. A deadline during capset must
        // not skip the readback.
        // SAFETY: V3 capget writes the same live two-word layout for this process.
        if unsafe { sys::syscall(get, &header, data.as_mut_ptr()) } == -1 {
            return Err(os_error(boundary, 17, 0));
        }
        for (field, mask) in [
            (
                25,
                u64::from(data[0].effective) | u64::from(data[1].effective) << 32,
            ),
            (
                26,
                u64::from(data[0].permitted) | u64::from(data[1].permitted) << 32,
            ),
            (
                27,
                u64::from(data[0].inheritable) | u64::from(data[1].inheritable) << 32,
            ),
        ] {
            if mask != 0 {
                return Err(observed(
                    boundary,
                    Cause::Mismatch {
                        field,
                        expected: 0,
                        observed: mask,
                    },
                ));
            }
        }
        for cap in 0..64 {
            budget(deadline, boundary)?;
            // SAFETY: PR_CAP_AMBIENT_IS_SET observes one fixed capability index.
            let actual = unsafe { sys::prctl(47, 1, cap, 0, 0) };
            if actual == -1 {
                let source = io::Error::last_os_error();
                if source.raw_os_error() == Some(22) {
                    break;
                }
                return Err(io_error(boundary, 31, 28, source));
            }
            if actual != 0 {
                return Err(observed(
                    boundary,
                    Cause::Mismatch {
                        field: 28,
                        expected: 0,
                        observed: actual as u64,
                    },
                ));
            }
        }
        budget(deadline, boundary)?;
        // SAFETY: PR_SET_NO_NEW_PRIVS irreversibly sets the documented integer value.
        if unsafe { sys::prctl(38, 1, 0, 0, 0) } == -1 {
            return Err(os_error(boundary, 32, 41));
        }
        // No-new-privs is already set. A deadline during that prctl must
        // not skip the readback.
        // SAFETY: PR_GET_NO_NEW_PRIVS observes the child's value.
        let actual = unsafe { sys::prctl(39, 0, 0, 0, 0) };
        if actual == -1 {
            return Err(os_error(boundary, 33, 41));
        }
        if actual != 1 {
            return Err(observed(
                boundary,
                Cause::Mismatch {
                    field: 41,
                    expected: 1,
                    observed: actual as u64,
                },
            ));
        }
        // No-new-privs is already verified. A deadline during that readback
        // must not turn the cleared set into a fault.
        Ok(())
    }

    fn fence(deadline: Instant) -> Result<(), Failure> {
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
        let bytes = rivect_sandbox_helper::compile_seccomp(
            rivect_sandbox_helper::SeccompStage::PreInjection,
        )
        .map_err(|_architecture| {
            observed("owned.child.spawn", Cause::Unverifiable { field: 24 })
        })?;
        let instructions: Vec<_> = bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|bytes| Filter {
                code: u16::from_le_bytes([bytes[0], bytes[1]]),
                jt: bytes[2],
                jf: bytes[3],
                value: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            })
            .collect();
        let length = u16::try_from(instructions.len())
            .map_err(|_range| observed("owned.child.spawn", Cause::Unverifiable { field: 24 }))?;
        let program = Program {
            length,
            filter: instructions.as_ptr(),
        };
        budget(deadline, "owned.child.fence")?;
        // SAFETY: PR_SET_SECCOMP receives a live aligned sock_fprog and its immutable instructions.
        if unsafe { sys::prctl(22, 2, &program, 0, 0) } == -1 {
            return Err(os_error("owned.child.fence", 18, 0));
        }
        // The pre-injection fence is already installed. A deadline during
        // that prctl must not turn it into a fault.
        Ok(())
    }

    fn sweep(held: &[i32], deadline: Instant) -> Result<(), Failure> {
        budget(deadline, "owned.child.spawn")?;
        let mut first = 3_u32;
        let mut held = held.to_vec();
        held.sort_unstable();
        for fd in held {
            let fd = u32::try_from(fd).map_err(|_range| {
                observed("owned.child.spawn", Cause::Unverifiable { field: 24 })
            })?;
            if first < fd {
                // SAFETY: close_range closes only the unowned gap, excluding each held role.
                if unsafe { sys::syscall(436, first, fd - 1, 0_u32) } == -1 {
                    return Err(os_error("owned.child.spawn", 7, 0));
                }
            }
            first = fd + 1;
        }
        // SAFETY: all held descriptors precede first; the suffix contains only inherited strays.
        if unsafe { sys::syscall(436, first, u32::MAX, 0_u32) } == -1 {
            return Err(os_error("owned.child.spawn", 7, 0));
        }
        // The unowned suffix is already closed. A deadline during that
        // close_range must not turn it into a fault.
        Ok(())
    }

    fn decode_parent_stop(bytes: &[u8]) -> Result<OwnedStop, Failure> {
        const PREFIX: &[u8] = b"owned-launch-v1 stop ";
        const REASONS: [(&[u8], OwnedStop); 4] = [
            (b"cancelled\n", OwnedStop::Cancelled),
            (b"deadline\n", OwnedStop::Deadline),
            (b"observation\n", OwnedStop::Observation),
            (b"control_lost\n", OwnedStop::ControlLost),
        ];
        let malformed = |offset: usize| {
            observed(
                "owned.protocol.grammar",
                Cause::Malformed {
                    field: 24,
                    offset: offset as u64,
                },
            )
        };
        for (index, expected) in PREFIX.iter().enumerate() {
            if bytes.get(index) != Some(expected) {
                return Err(malformed(index));
            }
        }
        let rest = &bytes[PREFIX.len()..];
        if let Some((_, stop)) = REASONS.iter().find(|(reason, _)| *reason == rest) {
            return Ok(*stop);
        }
        let mut index = 0;
        loop {
            let alive = REASONS
                .iter()
                .any(|(reason, _)| reason.len() > index && reason.get(index) == rest.get(index));
            if !alive || index > PREFIX.len() + rest.len() {
                return Err(malformed(PREFIX.len() + index));
            }
            index += 1;
        }
    }

    fn finish_parent_eof(bytes: &[u8]) -> Result<OwnedStop, Failure> {
        if bytes.is_empty() {
            return Ok(OwnedStop::ControlLost);
        }
        let length = bytes.len() as u64;
        Err(observed(
            "owned.protocol.grammar",
            Cause::EarlyEof {
                field: 24,
                expected: length + 1,
                observed: length,
            },
        ))
    }

    fn parent_stop(
        control: i32,
        bytes: &mut Vec<u8>,
        deadline: Instant,
    ) -> Result<Option<OwnedStop>, Failure> {
        // Read before consulting the deadline. A complete frame already
        // queued is the parent's decision: `cancelled` outranks an elapsed
        // deadline, and a deadline check here would turn that frame into a
        // fault. An idle receiver with the deadline already past is the
        // deadline stop itself, not `Cause::Deadline`.
        let mut chunk = [0; 129];
        // SAFETY: the live endpoint is nonblocking and chunk is a bounded writable buffer.
        let count = unsafe { read(control, chunk.as_mut_ptr(), chunk.len()) };
        if count == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                if bytes.is_empty() && Instant::now() >= deadline {
                    return Ok(Some(OwnedStop::Deadline));
                }
                return Ok(None);
            }
            return Err(io_error("owned.protocol.read", 5, 24, error));
        }
        if count == 0 {
            // An empty close is control loss. A partial frame is not a stop.
            return finish_parent_eof(bytes).map(Some);
        }
        bytes.extend_from_slice(&chunk[..count as usize]);
        if bytes.len() > 128 {
            return Err(observed(
                "owned.protocol.grammar",
                Cause::Limit {
                    field: 24,
                    limit: 128,
                    observed: 129,
                },
            ));
        }
        if bytes.last() != Some(&b'\n') {
            // Bytes are already buffered. A deadline that elapses during the
            // read must not turn the incomplete frame into a fault; the loop
            // classifies OwnedStop::Deadline on its next check.
            return Ok(None);
        }
        let stop = decode_parent_stop(bytes)?;
        bytes.clear();
        // The frame is already authenticated. A deadline that elapses while
        // it is decoded must not replace the stop the parent wrote.
        Ok(Some(stop))
    }

    fn init(
        control: i32,
        parent: u32,
        deadline: Instant,
        profile: OwnedProfile,
        payload: &[CString],
    ) -> ! {
        let setup = (|| {
            protected(true, deadline)?;
            rivect_sandbox_helper::arm_owned_parent(true, parent, deadline)?;
            private_proc(deadline)?;
            let (baseline, nproc) = resources(profile, deadline)?;
            sweep(&[control], deadline)?;
            let pair = pair(deadline)?;
            Ok((baseline, nproc, pair))
        })();
        let (baseline, nproc, pair) = match setup {
            Ok(value) => value,
            Err(error) => fatal(control, error, deadline, false),
        };
        let argv: Vec<_> = payload
            .iter()
            .map(|arg| arg.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let mut decoded = std::collections::BTreeMap::new();
        for (key, value) in std::env::vars_os() {
            let Some(index) = key.as_encoded_bytes().strip_prefix(b"RIVECT_OWNED_ENV_") else {
                continue;
            };
            if let Err(error) = budget(deadline, "owned.child.spawn") {
                fatal(control, error, deadline, false);
            }
            let Some(index) = decimal(index) else {
                fatal(
                    control,
                    observed(
                        "owned.child.spawn",
                        Cause::Malformed {
                            field: 24,
                            offset: 0,
                        },
                    ),
                    deadline,
                    false,
                );
            };
            let bytes = value.as_encoded_bytes();
            let Some(colon) = bytes.iter().position(|byte| *byte == b':') else {
                fatal(
                    control,
                    observed(
                        "owned.child.spawn",
                        Cause::Malformed {
                            field: 24,
                            offset: 0,
                        },
                    ),
                    deadline,
                    false,
                );
            };
            let Some(length) = decimal(&bytes[..colon])
                .and_then(|length| usize::try_from(length).ok())
                .filter(|length| *length > 0)
            else {
                fatal(
                    control,
                    observed(
                        "owned.child.spawn",
                        Cause::Malformed {
                            field: 24,
                            offset: 0,
                        },
                    ),
                    deadline,
                    false,
                );
            };
            let Some(end) = (colon + 1)
                .checked_add(length)
                .filter(|end| *end <= bytes.len())
            else {
                fatal(
                    control,
                    observed(
                        "owned.child.spawn",
                        Cause::Malformed {
                            field: 24,
                            offset: 0,
                        },
                    ),
                    deadline,
                    false,
                );
            };
            let name = &bytes[colon + 1..end];
            if name.contains(&b'=') || name == b"RIVECT_OWNED_PARENT_PID" {
                fatal(
                    control,
                    observed(
                        "owned.child.spawn",
                        Cause::Malformed {
                            field: 24,
                            offset: 0,
                        },
                    ),
                    deadline,
                    false,
                );
            }
            let mut word = name.to_vec();
            word.push(b'=');
            word.extend_from_slice(&bytes[end..]);
            let word = match CString::new(word) {
                Ok(word) => word,
                Err(source) => fatal(
                    control,
                    io_error("owned.child.spawn", 24, 24, io::Error::other(source)),
                    deadline,
                    false,
                ),
            };
            if decoded.insert(index, word).is_some() {
                fatal(
                    control,
                    observed(
                        "owned.child.spawn",
                        Cause::Duplicate {
                            field: 24,
                            count: 2,
                        },
                    ),
                    deadline,
                    false,
                );
            }
        }
        if decoded.keys().copied().ne(0..decoded.len() as u32) {
            fatal(
                control,
                observed(
                    "owned.child.spawn",
                    Cause::Malformed {
                        field: 24,
                        offset: 0,
                    },
                ),
                deadline,
                false,
            );
        }
        let environment: Vec<_> = decoded.into_values().collect();
        let env: Vec<_> = environment
            .iter()
            .map(|word| word.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let candidates: Vec<CString> = if payload[0].as_bytes().contains(&b'/') {
            vec![payload[0].clone()]
        } else {
            let path = environment
                .iter()
                .find_map(|word| word.as_bytes().strip_prefix(b"PATH="))
                .unwrap_or(b"/bin:/usr/bin");
            path.split(|byte| *byte == b':')
                .map(|directory| {
                    let mut name = directory.to_vec();
                    if !name.is_empty() {
                        name.push(b'/');
                    }
                    name.extend_from_slice(payload[0].as_bytes());
                    match CString::new(name) {
                        Ok(name) => name,
                        Err(source) => fatal(
                            control,
                            io_error("owned.child.spawn", 24, 24, io::Error::other(source)),
                            deadline,
                            false,
                        ),
                    }
                })
                .collect()
        };
        let ready = OwnedRecord::Entry {
            profile,
            baseline,
            nproc,
            verified: 63,
        };
        // SAFETY: the helper is single-threaded; both branches use only the prepared native lifecycle.
        let child = unsafe { fork() };
        if child == -1 {
            fatal(
                control,
                os_error("owned.child.spawn", 13, 0),
                deadline,
                false,
            );
        }
        if child == 0 {
            let prepared = (|| {
                protected(true, deadline)?;
                close(pair[0], "owned.child.spawn", 0, deadline)?;
                // The legacy check and data-plane chains are `unshare` then
                // `setpriv`. Cap drop and no-new-privs run before exec, and
                // a nested `unshare` cannot write uid_map after that drop.
                // Keep privileges for the trusted `unshare` binary and for
                // an alternate helper whose `launch` verb execs that chain.
                // `setpriv` still applies the final no-new-privs and seccomp
                // fence to the payload. Direct payloads stay dropped.
                let trusted_launcher = payload
                    .first()
                    .is_some_and(|arg| arg.as_bytes() == b"/usr/bin/unshare")
                    || payload
                        .get(1)
                        .is_some_and(|arg| arg.as_bytes() == b"launch");
                if !trusted_launcher {
                    capabilities(deadline)?;
                    fence(deadline)?;
                }
                close(control, "owned.child.control_close", 20, deadline)?;
                write_record(pair[1], ready, deadline, "owned.child.spawn")?;
                // The readiness frame is already on the private socket. A
                // deadline fault here is a second record, and init does not
                // admit it once the entry is in hand. Wait for the deadline
                // kill instead of publishing a false predicate failure.
                if budget(deadline, "owned.child.spawn").is_err() {
                    fail_stop();
                }
                let mut denied = None;
                let mut last = None;
                for candidate in &candidates {
                    if budget(deadline, "owned.child.spawn").is_err() {
                        fail_stop();
                    }
                    // SAFETY: all argv/env and search candidates were prepared before fork.
                    unsafe {
                        execve(candidate.as_ptr(), argv.as_ptr(), env.as_ptr());
                    }
                    let source = io::Error::last_os_error();
                    match source.raw_os_error() {
                        Some(13) => denied = Some(source),
                        Some(2 | 20) => last = Some(source),
                        _ => return Err(io_error("owned.child.spawn", 25, 0, source)),
                    }
                }
                Err(io_error(
                    "owned.child.spawn",
                    25,
                    0,
                    denied
                        .or(last)
                        .unwrap_or_else(|| io::Error::from_raw_os_error(2)),
                ))
            })();
            match prepared {
                Err(error) => fatal(pair[1], error, deadline, true),
                Ok(()) => fail_stop(),
            }
        }
        if let Err(error) = close(pair[1], "owned.child.spawn", 0, deadline) {
            fatal(control, error, deadline, false);
        }
        let mut receiver_open = true;
        let mut private_ready = false;
        let mut private_eof = false;
        let mut primary = None;
        let mut secondary = None;
        let mut entered = false;
        let mut child_status = None;
        let mut stop_bytes = Vec::with_capacity(128);
        let mut stop = None;
        let mut kill_sent = false;
        loop {
            if stop.is_none() {
                match parent_stop(control, &mut stop_bytes, deadline) {
                    Ok(Some(reason)) => stop = Some(reason),
                    Ok(None) => {
                        // A partial frame stays buffered. Only an elapsed
                        // deadline with nothing complete queued is this stop.
                        if Instant::now() >= deadline {
                            stop = Some(OwnedStop::Deadline);
                        }
                    }
                    Err(error) => {
                        if primary.is_none() {
                            primary = error.fault();
                        }
                        stop = Some(OwnedStop::Observation);
                    }
                }
            }
            let mut private_settled = false;
            // A control-plane fault already owns the result. Do not adopt a
            // later private frame as its secondary; close and reap instead.
            if stop.is_some() && primary.is_some() && !private_ready && !private_eof {
                private_settled = true;
            } else if !private_eof && receiver_open {
                let observation = match read_private_record(pair[0]) {
                    Ok(PrivateObservation::Pending) => {
                        // Stop does not wait for a new fault. Bytes already queued
                        // are read above; an empty receiver is then closed.
                        if stop.is_some() {
                            private_settled = true;
                        }
                        Ok(None)
                    }
                    Ok(PrivateObservation::Eof) => {
                        private_eof = true;
                        Ok(None)
                    }
                    Ok(PrivateObservation::Record(record)) => Ok(Some(record)),
                    Err(error) => Err(error),
                };
                match observation {
                    Ok(Some(OwnedRecord::Entry {
                        profile: actual_profile,
                        baseline: actual_baseline,
                        nproc: actual_nproc,
                        verified,
                    })) if !private_ready && primary.is_none() => {
                        let mismatch = if actual_profile != profile {
                            Some(Cause::Unverifiable { field: 24 })
                        } else if actual_baseline != baseline {
                            Some(Cause::Mismatch {
                                field: 22,
                                expected: u64::from(baseline),
                                observed: u64::from(actual_baseline),
                            })
                        } else if actual_nproc != nproc {
                            Some(Cause::Mismatch {
                                field: 39,
                                expected: u64::from(nproc),
                                observed: u64::from(actual_nproc),
                            })
                        } else if verified != 63 {
                            Some(Cause::Mismatch {
                                field: 21,
                                expected: 63,
                                observed: u64::from(verified),
                            })
                        } else {
                            None
                        };
                        if let Some(cause) = mismatch {
                            primary = OwnedFault::new("owned.child.spawn", cause).ok();
                            stop = Some(OwnedStop::Observation);
                            private_settled = true;
                        } else {
                            private_ready = true;
                        }
                    }
                    Ok(Some(OwnedRecord::Fault(fault))) if primary.is_none() => {
                        if private_fault_admitted(fault, private_ready) {
                            primary = Some(fault);
                        } else {
                            primary =
                                observed("owned.child.spawn", Cause::Unverifiable { field: 24 })
                                    .fault();
                            stop = Some(OwnedStop::Observation);
                            private_settled = true;
                        }
                    }
                    Ok(Some(_)) => {
                        let error = observed(
                            "owned.child.spawn",
                            Cause::Duplicate {
                                field: 24,
                                count: 2,
                            },
                        );
                        if primary.is_none() {
                            primary = error.fault();
                        } else if secondary.is_none() {
                            secondary = error.fault();
                        }
                        stop = Some(OwnedStop::Observation);
                        private_settled = true;
                    }
                    Err(error) => {
                        if primary.is_none() {
                            primary = error.fault();
                        } else if secondary.is_none() {
                            secondary = error.fault();
                        }
                        stop = Some(OwnedStop::Observation);
                        private_settled = true;
                    }
                    Ok(None) => {}
                }
            }
            // EOF with no entry is the missing-entry fault. A validated
            // entry is published on EOF, and also when a stop finds the
            // receiver empty: closing it would otherwise drop the entry
            // and the stop together.
            if private_eof && !entered && primary.is_none() && !private_ready {
                primary = observed("owned.child.spawn", Cause::Missing { field: 24 }).fault();
                stop = Some(OwnedStop::Observation);
            }
            if entry_ready_to_publish(
                private_ready,
                private_eof,
                stop.is_some(),
                private_settled,
                entered,
                primary.is_some(),
            ) {
                receiver_open = false;
                let grace = deadline + Duration::from_secs(1);
                if let Err(error) = close(pair[0], "owned.child.spawn", 20, grace) {
                    primary = error.fault();
                    stop = Some(OwnedStop::Observation);
                } else if let Err(error) = write_frame(control, ready, "owned.protocol.entry") {
                    fatal(control, error, deadline, false);
                } else {
                    entered = true;
                }
            }
            // Queued private bytes are parsed before the receiver is closed.
            // An empty receiver under stop closes without waiting for a new fault.
            if receiver_open && (private_eof || private_settled) {
                receiver_open = false;
                if let Err(error) = close(
                    pair[0],
                    "owned.child.spawn",
                    20,
                    deadline + Duration::from_secs(1),
                ) {
                    if primary.is_none() {
                        primary = error.fault();
                    } else if secondary.is_none() {
                        secondary = error.fault();
                    }
                }
            }
            if stop.is_some() && !receiver_open && child_status.is_none() && !kill_sent {
                kill_sent = true;
                // SAFETY: child is a positive held unreaped direct child, never a recycled or reaped numeric pid.
                unsafe {
                    kill(child, 9);
                }
            }
            if child_status.is_none() && !receiver_open {
                let mut status = 0;
                // SAFETY: child remains this init's unreaped direct child and status is writable.
                let waited = unsafe { waitpid(child, &mut status, 1) };
                if waited == child {
                    child_status = Some(status);
                } else if waited == -1 {
                    let error = os_error("owned.child.spawn", 14, 0);
                    if primary.is_none() {
                        primary = error.fault();
                    } else if secondary.is_none() {
                        secondary = error.fault();
                    }
                    break;
                }
            }
            if child_status.is_some() && (private_eof || stop.is_some()) {
                break;
            }
            let mut fds = [
                PollFd {
                    fd: control,
                    events: 1,
                    returned: 0,
                },
                PollFd {
                    fd: if private_eof || !receiver_open {
                        -1
                    } else {
                        pair[0]
                    },
                    events: 1,
                    returned: 0,
                },
            ];
            // SAFETY: two initialized pollfd records live through this bounded poll.
            if unsafe { poll(fds.as_mut_ptr(), fds.len(), 1) } == -1 {
                let error = os_error("owned.child.spawn", 22, 24);
                if primary.is_none() {
                    primary = error.fault();
                } else if secondary.is_none() {
                    secondary = error.fault();
                }
                stop = Some(OwnedStop::Observation);
            }
            if stop.is_some() && Instant::now() >= deadline + Duration::from_secs(1) {
                // The grace is over. A fault or proven entry already in hand
                // is written below; a bare exit here would drop it. PID 1
                // leaving still tears the namespace down.
                if !kill_sent && child_status.is_none() {
                    // SAFETY: child is a positive held unreaped direct child.
                    unsafe {
                        kill(child, 9);
                    }
                }
                break;
            }
        }
        if receiver_open
            && let Err(error) = close(
                pair[0],
                "owned.child.spawn",
                20,
                deadline + Duration::from_secs(1),
            )
        {
            if primary.is_none() {
                primary = error.fault();
            } else if secondary.is_none() {
                secondary = error.fault();
            }
        }
        if let Some(primary) = primary {
            if write_frame(
                control,
                OwnedRecord::Fault(primary),
                "owned.protocol.terminal",
            )
            .is_err()
            {
                std::process::exit(super::EXIT_SANDBOX_INIT);
            }
            if let Some(secondary) = secondary {
                let valid = !entered && rivect_sandbox_helper::owned_fault_pair(primary, secondary);
                if valid
                    && write_frame(
                        control,
                        OwnedRecord::Fault(secondary),
                        "owned.protocol.terminal",
                    )
                    .is_err()
                {
                    std::process::exit(super::EXIT_SANDBOX_INIT);
                }
            }
            std::process::exit(super::EXIT_SANDBOX_INIT);
        }
        let terminal = if let Some(stop) = stop {
            OwnedRecord::Stop(stop)
        } else if let Some(status) = child_status {
            if status & 0x7f == 0 {
                OwnedRecord::Exit(((status >> 8) & 255) as u8)
            } else {
                OwnedRecord::Signal((status & 0x7f) as u8)
            }
        } else {
            std::process::exit(super::EXIT_SANDBOX_INIT);
        };
        if !entered || write_frame(control, terminal, "owned.protocol.terminal").is_err() {
            std::process::exit(super::EXIT_SANDBOX_INIT);
        }
        std::process::exit(0);
    }

    pub(super) fn run(args: &[CString]) -> ! {
        let Some(control) = args
            .get(3)
            .and_then(|arg| decimal(arg.as_bytes()))
            .and_then(|fd| i32::try_from(fd).ok())
            .filter(|fd| *fd >= 3)
        else {
            std::process::exit(super::EXIT_PROTOCOL);
        };
        let Some(profile) = args.get(2).and_then(|arg| match arg.as_bytes() {
            b"worker" => Some(OwnedProfile::Worker),
            b"index" => Some(OwnedProfile::Index),
            b"check" => Some(OwnedProfile::Check),
            _ => None,
        }) else {
            std::process::exit(super::EXIT_PROTOCOL);
        };
        let Some(absolute) = args
            .get(4)
            .and_then(|arg| std::str::from_utf8(arg.as_bytes()).ok())
            .and_then(|word| word.parse::<u64>().ok())
        else {
            std::process::exit(super::EXIT_PROTOCOL);
        };
        let Ok(now) = rivect_sandbox_helper::owned_monotonic_ns() else {
            std::process::exit(super::EXIT_SANDBOX_INIT);
        };
        let deadline = Instant::now() + Duration::from_nanos(absolute.saturating_sub(now));
        if args.get(5).is_none_or(|arg| arg.as_bytes() != b"--") || args.len() < 7 {
            std::process::exit(super::EXIT_PROTOCOL);
        }
        let parent = std::env::var_os("RIVECT_OWNED_PARENT_PID")
            .and_then(|word| decimal(word.as_encoded_bytes()))
            .filter(|pid| *pid > 0 && i32::try_from(*pid).is_ok());
        let Some(parent) = parent else {
            fatal(
                control,
                observed(
                    "owned.waiter.parent_death",
                    Cause::Unverifiable { field: 3 },
                ),
                deadline,
                false,
            );
        };
        // SAFETY: the inherited endpoint is the unique verified envelope descriptor.
        if unsafe { fcntl(control, 4, 0o4000) } == -1 {
            fatal(
                control,
                os_error("owned.child.spawn", 19, 20),
                deadline,
                false,
            );
        }
        let waiter = match bootstrap(parent, deadline) {
            Ok(waiter) => waiter,
            Err(error) => fatal(control, error, deadline, false),
        };
        if let Err(error) = sweep(&[control], deadline) {
            fatal(control, error, deadline, false);
        }
        // SAFETY: the trusted waiter is single-threaded and all mapping/status descriptors are retired.
        let child = unsafe { fork() };
        if child == -1 {
            fatal(control, os_error("owned.init.fork", 13, 0), deadline, false);
        }
        if child == 0 {
            init(control, waiter, deadline, profile, &args[6..]);
        }
        let mut status = 0;
        // SAFETY: this is the waiter's only held child; no endpoint I/O or explicit close occurs after fork.
        let waited = unsafe { waitpid(child, &mut status, 0) };
        std::process::exit(if waited == child && status == 0 {
            0
        } else {
            super::EXIT_SANDBOX_INIT
        });
    }
}
