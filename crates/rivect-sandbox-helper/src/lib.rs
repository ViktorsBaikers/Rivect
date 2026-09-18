//! The confined-effect protocol the rivect executor and this helper share:
//! exit verdicts and the binary-resolution rule. The crate carries no
//! dependencies — the unsafe syscall surface lives in the binary, this lib
//! holds only what the host process needs to spawn it.

use std::io;
use std::path::PathBuf;

/// The confined run succeeded.
pub const EXIT_OK: i32 = 0;
/// The confined child could not apply its sandbox (sandbox_init / Landlock):
/// a mechanism-init failure, never an effect denial.
pub const EXIT_SANDBOX_INIT: i32 = 10;
/// The data-plane fd I/O failed inside the confined child.
pub const EXIT_DATA_IO: i32 = 20;
/// The helper was invoked with an invalid mode/argument contract.
pub const EXIT_PROTOCOL: i32 = 30;
/// `launch` could not execute the target program for a reason other than a
/// missing binary.
pub const EXIT_LAUNCH_EXEC: i32 = 126;
/// `launch` could not find the target program to execute.
pub const EXIT_LAUNCH_NOT_FOUND: i32 = 127;

/// Resolves the confined helper binary that performs admitted fd I/O.
/// Cargo sets `CARGO_BIN_EXE_rivect_sandbox_helper` for this crate's binary
/// in test builds; a `RIVECT_SANDBOX_HELPER` override pins an explicit
/// install; and the production layout expects the helper installed beside
/// the rivect executable (or two levels up from a `deps/` test harness).
///
/// # Errors
/// Returns an `io::Error` naming the resolution rule when no candidate
/// exists — the executor surfaces that as the mechanism being unavailable,
/// never as an ambient in-process fallback.
pub fn helper_binary() -> io::Result<PathBuf> {
    if let Some(path) = std::env::var_os("RIVECT_SANDBOX_HELPER") {
        return Ok(PathBuf::from(path));
    }
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "cannot resolve the current executable directory",
        )
    })?;
    let beside = dir.join("rivect-sandbox-helper");
    if beside.is_file() {
        return Ok(beside);
    }
    // A `target/debug/deps/rivect-<hash>` test harness keeps the helper at
    // `target/debug/rivect-sandbox-helper`; one level up from `deps/`.
    let up = dir.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "cannot resolve the parent of the current executable directory",
        )
    })?;
    let deps_beside = up.join("rivect-sandbox-helper");
    if deps_beside.is_file() {
        return Ok(deps_beside);
    }
    // The helper builds as this package's example during `cargo test`:
    // `target/debug/examples/rivect-sandbox-helper`.
    let examples = up.join("examples").join("rivect-sandbox-helper");
    if examples.is_file() {
        return Ok(examples);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "rivect-sandbox-helper binary not found beside the rivect executable (or in deps/ or examples/ next to a test harness); install it beside the binary or set RIVECT_SANDBOX_HELPER",
    ))
}

/// Marks a pipe fd non-blocking so the host can drain a confined child
/// without `thread::sleep`.
///
/// # Errors
/// Returns the OS error when `fcntl` cannot read or set the flags.
pub fn set_nonblocking(fd: impl std::os::fd::AsFd) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let raw = fd.as_fd().as_raw_fd();
    // SAFETY: `raw` is a live fd borrowed from `AsFd`; F_GETFL/F_SETFL
    // only read and write the fd flags word and never alias memory.
    let flags = unsafe { fcntl(raw, F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same fd; the flags word is the F_GETFL result plus O_NONBLOCK.
    let rc = unsafe { fcntl(raw, F_SETFL, flags | O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;

#[cfg(target_os = "macos")]
const O_NONBLOCK: i32 = 0x0004;
#[cfg(target_os = "linux")]
const O_NONBLOCK: i32 = 0o4000;

unsafe extern "C" {
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
}
