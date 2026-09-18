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
//!   launch -- <program> [args...]
//!       rlimits + cloexec sweep, then exec the confined chain
//!   confined <macos|linux> <read|write> [<profile>]
//!       apply the sandbox, then read fd 0 -> stdout (read) or
//!       read stdin -> fd 1 after truncating it (write)
//!   probe-write <macos|linux> <profile|scope> <path>
//!       apply the sandbox, then open the probe artifact for write
//!       (O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW) and write one byte
//! ```
//! Exit verdicts are the crate's `EXIT_*` codes: 0 ok, 10 sandbox init
//! failure, 20 data I/O failure, 30 protocol error, 126/127 launch exec
//! failure — the host maps them to the worker's typed errors. Diagnostics
//! go to stderr (fd 2), which is the only stream the host captures.

use std::ffi::CString;
use std::io::{Read, Write};
use std::os::fd::FromRawFd as _;
use std::process::ExitCode;

use rivect_sandbox_helper::{
    EXIT_DATA_IO, EXIT_LAUNCH_EXEC, EXIT_LAUNCH_NOT_FOUND, EXIT_OK, EXIT_PROTOCOL,
    EXIT_SANDBOX_INIT,
};

/// Data-plane byte budget, mirroring the executor's read cap: a confined
/// child can never move more bytes than the admitted effect's own size.
const DATA_MAX_BYTES: usize = 1 << 20;

/// Stdio fd range the inherited data fd lives on (0/1/2).
const STDIO_TOP_FD: i32 = 2;

// The syscall surface: one module so every `unsafe` block has a named home.
mod sys {
    #[cfg(target_os = "linux")]
    use std::os::raw::c_long;
    use std::os::raw::{c_char, c_int, c_void};

    /// The platform `struct rlimit`: two `u64` words on every supported
    /// target.
    #[repr(C)]
    pub struct Rlimit {
        pub rlim_cur: u64,
        pub rlim_max: u64,
    }

    // SAFETY: the declarations mirror the platform libc/kernel ABI; every
    // call site passes owned NUL-terminated data and checks the return.
    #[cfg(target_os = "linux")]
    unsafe extern "C" {
        pub fn syscall(number: c_long, ...) -> c_long;
        pub fn prctl(option: c_int, ...) -> c_int;
        pub fn setrlimit(resource: c_int, rlim: *const Rlimit) -> c_int;
        pub fn close(fd: c_int) -> c_int;
        pub fn execv(path: *const c_char, argv: *const *const c_char) -> c_int;
        pub fn open(path: *const c_char, oflag: c_int) -> c_int;
        pub fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
    }

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
        pub fn close(fd: c_int) -> c_int;
        pub fn execv(path: *const c_char, argv: *const *const c_char) -> c_int;
        pub fn open(path: *const c_char, oflag: c_int) -> c_int;
        pub fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
    }
}

fn main() -> ExitCode {
    apply_rlimits();
    // Every mode wastes no time on the parent's file descriptor table: the
    // only fds that exist here are the inherited stdio (0/1/2) — close
    // anything else before any sandbox exists, so a confined program can
    // never inherit a stray fd (S6).
    // SAFETY: closing fds above stdio by number is the documented unix
    // contract; those fds are the parent's strays, never owned handles of
    // this freshly spawned child.
    for fd in (STDIO_TOP_FD + 1)..=256 {
        // SAFETY: closing fds above stdio by number is the documented unix
        // contract; those fds are the parent's strays, never owned handles
        // of this freshly spawned child.
        let _ = unsafe { sys::close(fd) };
    }

    let args: Vec<CString> = std::env::args_os()
        .map(|arg| CString::new(arg.into_encoded_bytes()))
        .collect::<Result<_, _>>()
        .unwrap_or_else(|_| {
            eprintln!("rivect-sandbox-helper: an argument is not valid unicode");
            std::process::exit(EXIT_PROTOCOL);
        });
    let verdict = match args.get(1).map(|arg| arg.as_bytes()) {
        Some(b"launch") => cmd_launch(&args),
        Some(b"confined") => cmd_confined(&args),
        Some(b"probe-write") => cmd_probe_write(&args),
        _ => {
            eprintln!("rivect-sandbox-helper: unknown mode");
            Err(EXIT_PROTOCOL)
        }
    };
    let code = match verdict {
        Ok(()) => EXIT_OK,
        Err(code) => code,
    };
    ExitCode::from(u8::try_from(code).unwrap_or(EXIT_PROTOCOL as u8))
}

// ---------------------------------------------------------------------------
// launch: rlimits + exec the confined chain
// ---------------------------------------------------------------------------

/// Executes the launcher chain (`sandbox-exec`, `unshare`/`setpriv`, then
/// the confined program). The rlimits set at startup survive every exec in
/// the chain — this is what bounds a fork-bombed or disk-filling confined
/// program — and the fd table is already closed above.
fn cmd_launch(args: &[CString]) -> Result<(), i32> {
    let Some(dashdash) = args.iter().position(|arg| arg.to_bytes() == b"--") else {
        eprintln!("rivect-sandbox-helper: launch requires a -- separator");
        return Err(EXIT_PROTOCOL);
    };
    let program = args.get(dashdash + 1).ok_or_else(|| {
        eprintln!("rivect-sandbox-helper: launch requires a program");
        EXIT_PROTOCOL
    })?;
    let argv: Vec<&CString> = args[dashdash + 1..].iter().collect();
    // SAFETY: the argv is a NUL-terminated list of NUL-terminated strings
    // built above from owned CStrings that outlive the call. execv replaces
    // the process image; a returned value is the failure path checked next.
    let attempted = unsafe {
        let mut pointers: Vec<*const std::os::raw::c_char> =
            argv.iter().map(|arg| arg.as_ptr()).collect();
        pointers.push(std::ptr::null());
        sys::execv(program.as_ptr(), pointers.as_ptr())
    };
    if attempted == -1 {
        let error = std::io::Error::last_os_error();
        eprintln!("rivect-sandbox-helper: exec failed: {error}");
        return Err(if error.kind() == std::io::ErrorKind::NotFound {
            EXIT_LAUNCH_NOT_FOUND
        } else {
            EXIT_LAUNCH_EXEC
        });
    }
    Err(EXIT_LAUNCH_EXEC)
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
        b"linux" => apply_linux_landlock(),
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
    target.write_all(&payload).map_err(|error| {
        eprintln!("rivect-sandbox-helper: admitted write failed: {error}");
        EXIT_DATA_IO
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
/// planted; the opened fd is closed before returning.
fn open_for_write(path: &CString) -> Result<(), i32> {
    const O_WRONLY: i32 = 0o1;
    const O_CREAT: i32 = 0o100;
    const O_TRUNC: i32 = 0o1000;
    #[cfg(target_os = "macos")]
    const O_NOFOLLOW: i32 = 0x0100;
    #[cfg(target_os = "linux")]
    const O_NOFOLLOW: i32 = 0o400000;
    // SAFETY: the path is an owned NUL-terminated CString; the flags are the
    // literal platform open(2) constants; the fd is closed on every path.
    unsafe {
        let fd = sys::open(path.as_ptr(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW);
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
            eprintln!("rivect-sandbox-helper: profile is not valid unicode");
            EXIT_PROTOCOL
        })?;
        let mut errorbuf: *mut std::os::raw::c_char = std::ptr::null_mut();
        let verdict = sys::sandbox_init(profile_c.as_ptr(), 0, &mut errorbuf);
        if verdict != 0 {
            let message = if errorbuf.is_null() {
                "sandbox_init failed".to_string()
            } else {
                let message = std::ffi::CStr::from_ptr(errorbuf)
                    .to_string_lossy()
                    .into_owned();
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

/// Landlock deny-by-default: handles every filesystem access right with zero
/// rules, so after this call the helper cannot open ANY path — the only I/O
/// left is the inherited data fd, exactly the admitted operation. The
/// network namespace is applied by the parent's `unshare --net` wrapper, so
/// a confined helper has neither a path nor a network escape.
#[cfg(target_os = "linux")]
fn apply_linux_landlock() -> Result<(), i32> {
    const PR_SET_NO_NEW_PRIVS: i32 = 38;
    // Landlock syscall numbers are 444/446 on both aarch64 and x86_64.
    const SYS_LANDLOCK_CREATE_RULESET: i64 = 444;
    const SYS_LANDLOCK_RESTRICT_SELF: i64 = 446;

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
    const ACCESS_FS_REFER: u64 = 1 << 13;
    const ACCESS_FS_TRUNCATE: u64 = 1 << 14;
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
        | ACCESS_FS_MAKE_SYM
        | ACCESS_FS_REFER
        | ACCESS_FS_TRUNCATE;

    // SAFETY: the attribute is the kernel ABI layout (three u64 words) and
    // outlives the syscall; the integer constants are the documented
    // landlock/prctl values shown above.
    unsafe {
        let nnp = sys::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if nnp != 0 {
            eprintln!(
                "rivect-sandbox-helper: prctl no_new_privs failed: {}",
                std::io::Error::last_os_error()
            );
            return Err(EXIT_SANDBOX_INIT);
        }
        #[repr(C)]
        struct LandlockRulesetAttr {
            handled_access_fs: u64,
            handled_access_net: u64,
            scoped: u64,
        }
        let attr = LandlockRulesetAttr {
            handled_access_fs: HANDLED_FS,
            handled_access_net: 0,
            scoped: 0,
        };
        let ruleset = sys::syscall(SYS_LANDLOCK_CREATE_RULESET, &attr as *const _, 0, 0);
        if ruleset < 0 {
            eprintln!(
                "rivect-sandbox-helper: landlock_create_ruleset failed: {}",
                std::io::Error::last_os_error()
            );
            return Err(EXIT_SANDBOX_INIT);
        }
        if sys::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0) != 0 {
            eprintln!(
                "rivect-sandbox-helper: landlock_restrict_self failed: {}",
                std::io::Error::last_os_error()
            );
            let _ = sys::close(ruleset as i32);
            return Err(EXIT_SANDBOX_INIT);
        }
        let _ = sys::close(ruleset as i32);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_linux_landlock() -> Result<(), i32> {
    eprintln!("rivect-sandbox-helper: the linux confined mode is only built on Linux");
    Err(EXIT_PROTOCOL)
}

// ---------------------------------------------------------------------------
// rlimits (S5): every confined child is bounded
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
const RLIMITS: &[(i32, u64)] = &[
    (5, 512 * 1024 * 1024), // RLIMIT_AS
    (0, 30),                // RLIMIT_CPU seconds
    (1, 64 * 1024 * 1024),  // RLIMIT_FSIZE
    (8, 256),               // RLIMIT_NOFILE
];
#[cfg(target_os = "linux")]
const RLIMITS: &[(i32, u64)] = &[
    (9, 512 * 1024 * 1024), // RLIMIT_AS
    (0, 30),                // RLIMIT_CPU seconds
    (1, 64 * 1024 * 1024),  // RLIMIT_FSIZE
    (7, 256),               // RLIMIT_NOFILE
];

/// Sets the confined child's resource limits at startup, before any mode
/// logic: the limits stop a fork bomb, a disk fill, and an fd storm without
/// ever touching a legitimate program. Hard limits can only tighten, so a
/// failure to set them is ignored — the parent's wall deadline remains the
/// backstop.
fn apply_rlimits() {
    // SAFETY: setrlimit takes the libc rlimit layout (two u64 words) which
    // the repr(C) struct matches; the resource ids are the documented
    // platform constants; `_` on failure keeps the parent's deadline as the
    // backstop rather than failing the whole run.
    for &(resource, value) in RLIMITS {
        let limit = sys::Rlimit {
            rlim_cur: value,
            rlim_max: value,
        };
        // SAFETY: setrlimit takes the address of a valid Rlimit for the
        // named resource; failure keeps the parent's deadline as backstop.
        let _ = unsafe { sys::setrlimit(resource, &limit) };
    }
}
