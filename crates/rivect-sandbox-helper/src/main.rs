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
//!       (O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW) and write one byte
//! ```
//! Exit verdicts are the crate's `EXIT_*` codes: 0 ok, 10 sandbox init
//! failure, 20 data I/O failure, 30 protocol error, 126/127 launch exec
//! failure — the host maps them to the worker's typed errors. Diagnostics
//! go to stderr (fd 2), which is the only stream the host captures.

use std::ffi::{CStr, CString};
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
/// `open(2)` do not follow symlinks.
#[cfg(target_os = "macos")]
const O_NOFOLLOW: i32 = 0x0100;
#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400000;

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
        pub fn open(path: *const c_char, oflag: c_int, mode: c_int) -> c_int;
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
        pub fn open(path: *const c_char, oflag: c_int, mode: c_int) -> c_int;
        pub fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
        pub fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
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
    if let Err(code) = apply_rlimits() {
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

    let args: Vec<CString> = std::env::args_os()
        .map(|arg| CString::new(arg.into_encoded_bytes()))
        .collect::<Result<_, _>>()
        .unwrap_or_else(|_| {
            eprintln!("rivect-sandbox-helper: an argument contains an interior NUL");
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
    exit(code)
}

fn exit(code: i32) -> ExitCode {
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
    const PR_SET_NO_NEW_PRIVS: i32 = 38;
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
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
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
                &path_beneath as *const LandlockPathBeneathAttr,
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
    (9, 512 * 1024 * 1024), // RLIMIT_AS
    (0, 30),                // RLIMIT_CPU seconds
    (1, 64 * 1024 * 1024),  // RLIMIT_FSIZE
    (6, 64),                // RLIMIT_NPROC
    (7, 256),               // RLIMIT_NOFILE
];

/// Sets the confined child's resource limits at startup, before any mode
/// logic: the limits stop a fork bomb, a disk fill, and an fd storm without
/// ever touching a legitimate program. Hard limits can only tighten; a
/// failure to set them is a sandbox-init failure (fail closed).
fn apply_rlimits() -> Result<(), i32> {
    // SAFETY: setrlimit takes the libc rlimit layout (two u64 words) which
    // the repr(C) struct matches; the resource ids are the documented
    // platform constants.
    for &(resource, value) in RLIMITS {
        let limit = sys::Rlimit {
            rlim_cur: value,
            rlim_max: value,
        };
        // SAFETY: setrlimit takes the address of a valid Rlimit for the
        // named resource; a non-zero return is an init failure.
        if unsafe { sys::setrlimit(resource, &limit) } != 0 {
            eprintln!(
                "rivect-sandbox-helper: setrlimit({resource}) failed: {}",
                std::io::Error::last_os_error()
            );
            return Err(EXIT_SANDBOX_INIT);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// fd sweep: close every inherited fd above stdio
// ---------------------------------------------------------------------------

/// Closes every inherited fd above stdio. Linux prefers `close_range` and
/// walks `/proc/self/fd` if that syscall is missing; macOS walks `/dev/fd`
/// and falls back to `F_MAXFD`. If every method fails, this is a sandbox
/// init failure — never exec-with-inherited-fds.
fn close_stray_fds() -> Result<(), i32> {
    #[cfg(target_os = "linux")]
    {
        const SYS_CLOSE_RANGE: i64 = 436;
        // SAFETY: close_range(3, UINT_MAX, 0) closes every fd above stdio;
        // a negative return is ENOSYS or a similar miss, and the walk
        // covers the table instead.
        let closed = unsafe { sys::syscall(SYS_CLOSE_RANGE, 3u32, u32::MAX, 0u32) };
        if closed == 0 {
            return Ok(());
        }
        if walk_fd_dir("/proc/self/fd") {
            return Ok(());
        }
        eprintln!(
            "rivect-sandbox-helper: fd sweep failed: close_range and /proc/self/fd walk both failed"
        );
        return Err(EXIT_SANDBOX_INIT);
    }
    #[cfg(target_os = "macos")]
    {
        if walk_fd_dir("/dev/fd") {
            return Ok(());
        }
        const F_MAXFD: i32 = 51;
        // SAFETY: F_MAXFD reports the largest open fd in this process;
        // closing numbers above stdio is the documented unix contract.
        let max = unsafe { sys::fcntl(0, F_MAXFD) };
        if max < 0 {
            eprintln!(
                "rivect-sandbox-helper: fd sweep failed: /dev/fd walk and F_MAXFD both failed"
            );
            return Err(EXIT_SANDBOX_INIT);
        }
        if max > STDIO_TOP_FD {
            for fd in (STDIO_TOP_FD + 1)..=max {
                // SAFETY: those fds are the parent's strays, never owned
                // handles of this freshly spawned child.
                let _ = unsafe { sys::close(fd) };
            }
        }
        Ok(())
    }
}

/// Collects numeric fd names from a kernel fd directory, then closes each
/// fd above stdio except the directory fd itself (`closedir` owns that
/// close). Returns false when the directory cannot be opened.
fn walk_fd_dir(dir: &str) -> bool {
    let Ok(dir_c) = CString::new(dir) else {
        return false;
    };
    // SAFETY: `dir_c` is a valid CString; opendir/readdir/dirfd/closedir
    // follow the POSIX DIR contract. Names are collected before closedir,
    // the directory fd is excluded from the close list, and closedir
    // closes that fd once — never a double-close of the walk's dirfd.
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
            let entry = sys::readdir(dirp);
            if entry.is_null() {
                break;
            }
            let Ok(name) = CStr::from_ptr((*entry).d_name.as_ptr()).to_str() else {
                continue;
            };
            let Ok(fd) = name.parse::<i32>() else {
                continue;
            };
            if fd > STDIO_TOP_FD && fd != dirfd {
                fds.push(fd);
            }
        }
        let _ = sys::closedir(dirp);
        for fd in fds {
            let _ = sys::close(fd);
        }
    }
    true
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

    #[test]
    fn walk_fd_dir_rejects_a_missing_directory() {
        assert!(!walk_fd_dir("/no/such/rivect-fd-dir"));
    }

    #[test]
    fn walk_fd_dir_closes_strays_without_double_closing_its_dirfd() {
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
}
