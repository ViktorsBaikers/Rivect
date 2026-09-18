//! macOS effect backend for the execution world (architecture «Shell/PTY»).
//! Exactly one scoped existing-file read or checked-fd managed write per
//! admitted effect; everything else is denied before any byte is touched.
//! Every effect crosses the Seatbelt boundary in a fixed order: a one-time
//! conformance probe proves the boundary denies as well as admits (the
//! denied legs run first and touch only system or worker-owned probe
//! files, so a non-enforcing mechanism is detected before any leg touches
//! the user's target), then a confined OS leg proves the kernel admits
//! this operation inside the scope, and only then does the checked
//! in-process leg move bytes — no ambient path.

use super::{
    denied_write_candidate, helper_confined_read, helper_confined_write, helper_launch_command,
    helper_launch_init_failed, helper_probe_write, inspect_regular_target, observe_confined_child,
    same_regular_file,
};
use sha2::Digest;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Mutex, PoisonError};
/// The one injected backend seam: every effect the executor performs —
/// read, write, exec, egress — crosses a worker leg, so confinement is
/// intrinsic to the backend implementations. Legs a backend has not
/// shipped deny closed with their typed `*Unavailable` variant instead
/// of silently skipping the boundary.
pub trait ReadWorker: Send {
    fn read_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
    ) -> Result<ReadObservation, WorkerError>;

    fn write_once(
        &mut self,
        _scope_root: &Path,
        _target: &Path,
        _expected: FileIdentity,
        _bytes: &[u8],
    ) -> Result<(), WorkerError> {
        Err(WorkerError::WriteUnavailable)
    }

    fn exec_once(&mut self, _scope_root: &Path, _program: &Path) -> Result<(), WorkerError> {
        Err(WorkerError::ExecUnavailable)
    }

    fn egress_once(&mut self, _url: &str) -> Result<(), WorkerError> {
        Err(WorkerError::EgressUnavailable)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MacosReadWorker;

impl ReadWorker for MacosReadWorker {
    fn read_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
    ) -> Result<ReadObservation, WorkerError> {
        // Confinement is intrinsic to the free functions: the probe and
        // gate run inside them, so every caller — this seam, the managed
        // write leg, the config publication recovery — crosses the
        // boundary. There is no unconfined variant to call by mistake.
        read_once(scope_root, target)
    }

    fn write_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
        expected: FileIdentity,
        bytes: &[u8],
    ) -> Result<(), WorkerError> {
        write_once(scope_root, target, expected, bytes)
    }

    fn exec_once(&mut self, scope_root: &Path, program: &Path) -> Result<(), WorkerError> {
        exec_once(scope_root, program)
    }

    fn egress_once(&mut self, url: &str) -> Result<(), WorkerError> {
        egress_once(url)
    }
}

pub const BACKEND: &str = "macos";

pub const READ_MAX_BYTES: usize = 1 << 20;
pub const WRITE_MAX_BYTES: usize = READ_MAX_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
}

impl FileIdentity {
    pub(crate) fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }
}

/// macOS `O_NONBLOCK` (Darwin fcntl.h: 0x0004; no libc dependency here).
/// Opening a FIFO read-only with this flag returns immediately even when no
/// writer holds the other end, so a target swapped to a FIFO between the
/// metadata check and `open(2)` cannot block this worker forever. Regular
/// files ignore the flag, so the read path below is unaffected.
const O_NONBLOCK: i32 = 0x0004;

/// macOS `O_NOFOLLOW` (Darwin fcntl.h: 0x0100): the write probe's
/// in-process writability fallback must never open through a symlink
/// planted on the artifact path — a tampered artifact stays a typed
/// denial instead of an ambient write outside the scope.
const O_NOFOLLOW: i32 = 0x0100;

#[derive(Debug, Clone, PartialEq)]
pub struct ReadObservation {
    pub bytes: Vec<u8>,
    pub digest: String,
}

#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error("denied: scope root unavailable: {source}")]
    ScopeRootUnavailable { source: std::io::Error },
    #[error("not found: target does not exist: {}", target.display())]
    TargetMissing { target: PathBuf },
    #[error("denied: target {} is outside the admitted scope", target.display())]
    OutsideScope { target: PathBuf },
    #[error("denied: target metadata unavailable: {source}")]
    MetadataUnavailable { source: std::io::Error },
    #[error("denied: target {} is not a regular file", target.display())]
    NotRegularFile { target: PathBuf },
    #[error("denied: target changed while opening: {}", target.display())]
    TargetChanged { target: PathBuf },
    #[error("denied: read failed: {source}")]
    ReadFailed { source: std::io::Error },
    #[error("denied: write failed: {source}")]
    WriteFailed { source: std::io::Error },
    #[error("denied: managed write failed after mutation: {source}")]
    WriteMutationFailed { source: std::io::Error },
    #[error("denied: managed write backend unavailable")]
    WriteUnavailable,
    #[error("denied: exec backend unavailable")]
    ExecUnavailable,
    #[error("denied: egress backend unavailable")]
    EgressUnavailable,
    #[error("denied: managed write exceeds the {WRITE_MAX_BYTES} byte limit")]
    WriteTooLarge,
    #[error("denied: managed write length conversion failed: {source}")]
    WriteLengthOverflow { source: std::num::TryFromIntError },
    #[error("denied: target exceeds the {READ_MAX_BYTES} byte read limit")]
    TooLarge,
    #[error("denied: the seatbelt boundary rejected {}", target.display())]
    SandboxDenied { target: PathBuf },
    #[error(
        "capability unavailable: seatbelt sandbox-exec could not be started: {source}; recovery: fix the environment or run on a capable kernel"
    )]
    SandboxSpawnFailed { source: std::io::Error },
    // Mechanism-agnostic prefix: the reason names the failed mechanism
    // (Seatbelt on macOS, Landlock/seccomp/netns on Linux) — a fixed
    // "seatbelt" here put the wrong mechanism name on Linux wires.
    #[error(
        "capability unavailable: sandbox {reason}; recovery: fix the environment or run on a capable kernel"
    )]
    SandboxUnavailable { reason: String },
    #[error(
        "capability unavailable: confined run exceeded the wall deadline; recovery: fix the environment or run on a capable kernel"
    )]
    ConfinedRunTimedOut,
}

pub(crate) fn target_identity(
    scope_root: &Path,
    target: &Path,
) -> Result<FileIdentity, WorkerError> {
    let (_, metadata) = inspect_regular_target(scope_root, target)?;
    Ok(FileIdentity::from_metadata(&metadata))
}

/// One bounded read of an existing regular file inside the canonical scope
/// root. Symlinks that escape the scope are denied via canonicalisation; the
/// opened handle is re-checked as a regular file and for dev/ino identity
/// (fail-closed on swaps), and the FIFO-before-open window is bounded by an
/// `O_NONBLOCK` open instead of a potentially unbounded blocking `open(2)`.
/// Confinement is intrinsic: the conformance probe runs first, then the
/// confined read gate, and only then does the checked in-process leg open
/// anything.
pub fn read_once(scope_root: &Path, target: &Path) -> Result<ReadObservation, WorkerError> {
    let (canonical_target, canonical_meta) = inspect_regular_target(scope_root, target)?;
    if canonical_meta.len() > READ_MAX_BYTES as u64 {
        return Err(WorkerError::TooLarge);
    }
    let sandbox_exec = Path::new(SANDBOX_EXEC);
    probe_read_conformance(sandbox_exec, scope_root, &canonical_target)?;
    confined_read_gate(sandbox_exec, scope_root, &canonical_target)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(target)
        .map_err(|source| WorkerError::ReadFailed { source })?;
    let opened_meta = file
        .metadata()
        .map_err(|source| WorkerError::MetadataUnavailable { source })?;
    if !opened_meta.is_file() {
        return Err(WorkerError::NotRegularFile {
            target: target.to_path_buf(),
        });
    }
    if !same_regular_file(&canonical_meta, &opened_meta) {
        return Err(WorkerError::TargetChanged {
            target: target.to_path_buf(),
        });
    }
    if opened_meta.len() > READ_MAX_BYTES as u64 {
        return Err(WorkerError::TooLarge);
    }
    let profile = read_profile(scope_root)?;
    let bounded = helper_confined_read("macos", &profile, file)?;
    if bounded.len() > READ_MAX_BYTES {
        return Err(WorkerError::TooLarge);
    }
    let digest = crate::config::hex(&sha2::Sha256::digest(&bounded));
    Ok(ReadObservation {
        bytes: bounded,
        digest,
    })
}

/// One checked-fd managed write of an existing regular file inside the
/// canonical scope root. Confinement is intrinsic to this path — probe,
/// then gate, then the checked in-process leg — so every caller (the
/// executor's managed-write leg and the config publication recovery
/// alike) crosses the Seatbelt boundary; there is no unconfined variant.
pub fn write_once(
    scope_root: &Path,
    target: &Path,
    expected: FileIdentity,
    bytes: &[u8],
) -> Result<(), WorkerError> {
    if bytes.len() > WRITE_MAX_BYTES {
        return Err(WorkerError::WriteTooLarge);
    }
    let (_, canonical_meta) = inspect_regular_target(scope_root, target)?;
    let sandbox_exec = Path::new(SANDBOX_EXEC);
    probe_write_conformance(sandbox_exec, scope_root)?;
    confined_write_gate(sandbox_exec, scope_root, target)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(target)
        .map_err(|source| WorkerError::WriteFailed { source })?;
    write_opened_file(
        scope_root,
        target,
        &canonical_meta,
        &mut file,
        expected,
        bytes,
    )
}

/// Writes through an already-opened file after checking its current identity.
pub fn write_once_on_opened_file(
    scope_root: &Path,
    target: &Path,
    file: &mut File,
    expected: FileIdentity,
    bytes: &[u8],
) -> Result<(), WorkerError> {
    if bytes.len() > WRITE_MAX_BYTES {
        return Err(WorkerError::WriteTooLarge);
    }
    let (_, canonical_meta) = inspect_regular_target(scope_root, target)?;
    write_opened_file(scope_root, target, &canonical_meta, file, expected, bytes)
}

fn write_opened_file(
    scope_root: &Path,
    target: &Path,
    canonical_meta: &Metadata,
    file: &mut File,
    expected: FileIdentity,
    bytes: &[u8],
) -> Result<(), WorkerError> {
    let opened_meta = file
        .metadata()
        .map_err(|source| WorkerError::MetadataUnavailable { source })?;
    if !same_regular_file(canonical_meta, &opened_meta)
        || FileIdentity::from_metadata(&opened_meta) != expected
    {
        return Err(WorkerError::TargetChanged {
            target: target.to_path_buf(),
        });
    }
    let profile = write_profile(scope_root)?;
    let clone = file
        .try_clone()
        .map_err(|source| WorkerError::WriteFailed { source })?;
    helper_confined_write("macos", &profile, clone, bytes)
}

// ---------------------------------------------------------------------------
// Seatbelt confinement: every admitted effect crosses the OS boundary
// before the checked in-process leg can move a byte.
// ---------------------------------------------------------------------------

/// The only Seatbelt launcher macOS still ships; deprecated but
/// functional. A wrong or missing path fails every spawn closed.
pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Exact stderr prefix `sandbox-exec` prints on hosts that warn about the
/// deprecation. Filtered by prefix only and never treated as a failure
/// (EDGE-010); a line that merely contains the text stays untouched.
const DEPRECATION_PREFIX: &str = "WARNING: sandbox-exec is deprecated";

/// Canonical probe target for the read boundary's denied leg: world
/// readable, so a denied confined read names enforcement, never
/// filesystem permission. A grant scope that already covers this path is
/// not confinable and fails the probe.
const DENIED_PROBE_TARGET: &str = "/private/etc/hosts";

/// Read conformance verdicts already proven this process holds, keyed by
/// the mechanism binary and the canonical scope: the kernel's enforcement
/// does not change per effect, but a degenerate scope must not poison a
/// healthy one. Failed probes are not cached — a broken boundary re-probes
/// on every effect and stays at zero effects.
static CONFORMANT_READ_SCOPES: Mutex<BTreeSet<(PathBuf, PathBuf)>> = Mutex::new(BTreeSet::new());

/// Write conformance verdicts already proven this process holds, under
/// the same caching rules as the read set: the verdict is all a later
/// gate needs, because every confined write leg runs on its own fresh
/// probe artifact.
static CONFORMANT_WRITE_SCOPES: Mutex<BTreeSet<(PathBuf, PathBuf)>> = Mutex::new(BTreeSet::new());

/// Read allowances every confined helper needs before its own scope rules.
/// dyld's `CacheFinder` stats the root directory itself while hunting the
/// shared cache, and a `subpath` allowance never matches an ancestor:
/// denied there, dyld aborts the child (`ignition_halt`) with empty stderr,
/// which looks like a crash rather than a denial — hence the literal `/`.
/// The system trees carry the dynamic linker and the helper binaries; they
/// never include user data.
const SYSTEM_READ_RULES: &str = concat!(
    "    (allow file-read* (literal \"/\"))\n",
    "    (allow file-read* (subpath \"/bin\"))\n",
    "    (allow file-read* (subpath \"/usr/bin\"))\n",
    "    (allow file-read* (subpath \"/usr/lib\"))\n",
    "    (allow file-read* (subpath \"/usr/libexec\"))\n",
    "    (allow file-read* (subpath \"/usr/share\"))\n",
    "    (allow file-read* (subpath \"/System\"))\n",
    "    (allow file-read* (subpath \"/dev\"))\n",
);

const EXEC_SYSTEM_READ_RULES: &str = concat!(
    "    (allow file-read* (literal \"/\"))\n",
    "    (allow file-read* (subpath \"/bin\"))\n",
    "    (allow file-read* (subpath \"/usr/bin\"))\n",
    "    (allow file-read* (subpath \"/usr/lib\"))\n",
    "    (allow file-read* (subpath \"/usr/libexec\"))\n",
    "    (allow file-read* (subpath \"/usr/share\"))\n",
    "    (allow file-read* (subpath \"/System\"))\n",
);

/// Canonicalizes one scope root for a Seatbelt profile. Seatbelt filters
/// match canonical paths, so a `/var/folders` spelling would deny the very
/// scope the grant admits.
fn canonical_scope(scope_root: &Path) -> Result<PathBuf, WorkerError> {
    let canonical = scope_root
        .canonicalize()
        .map_err(|source| WorkerError::ScopeRootUnavailable { source })?;
    if canonical.to_str().is_none() {
        return Err(WorkerError::SandboxUnavailable {
            reason: "scope root is not valid unicode".to_string(),
        });
    }
    Ok(canonical)
}

/// Escapes one canonical path into a Seatbelt string literal. Control
/// characters would splice into SBPL, so a scope that contains them is
/// not confinable.
fn scheme_literal(canonical: &Path) -> Result<String, WorkerError> {
    let text = canonical
        .to_str()
        .ok_or_else(|| WorkerError::SandboxUnavailable {
            reason: "scope root is not valid unicode".to_string(),
        })?;
    if text.chars().any(char::is_control) {
        return Err(WorkerError::SandboxUnavailable {
            reason: "scope root contains control characters".to_string(),
        });
    }
    Ok(format!(
        "\"{}\"",
        text.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

/// Seatbelt profile that admits exactly one read of the granted scope.
///
/// # Errors
/// Returns [`WorkerError::ScopeRootUnavailable`] when the scope root cannot
/// be canonicalized.
pub fn read_profile(scope_root: &Path) -> Result<String, WorkerError> {
    let scope = scheme_literal(&canonical_scope(scope_root)?)?;
    Ok(format!(
        "(version 1)\n    (allow process-exec (literal \"/bin/cat\"))\n{SYSTEM_READ_RULES}    (allow file-read* (subpath {scope}))\n"
    ))
}

/// Seatbelt profile that admits reads of system trees and the granted
/// scope, and writes only inside the granted scope.
///
/// # Errors
/// Returns [`WorkerError::ScopeRootUnavailable`] when the scope root cannot
/// be canonicalized.
pub fn write_profile(scope_root: &Path) -> Result<String, WorkerError> {
    let scope = scheme_literal(&canonical_scope(scope_root)?)?;
    Ok(format!(
        "(version 1)\n    (allow process-exec (literal \"/usr/bin/touch\"))\n{SYSTEM_READ_RULES}    (allow file-read* (subpath {scope}))\n    (allow file-write* (subpath {scope}))\n"
    ))
}

/// Seatbelt profile that admits process execution only inside the granted
/// scope; everything outside is denied by the kernel.
///
/// # Errors
/// Returns [`WorkerError::ScopeRootUnavailable`] when the scope root cannot
/// be canonicalized.
pub fn exec_profile(scope_root: &Path) -> Result<String, WorkerError> {
    let scope = scheme_literal(&canonical_scope(scope_root)?)?;
    Ok(format!(
        "(version 1)\n{EXEC_SYSTEM_READ_RULES}    (allow process-exec (subpath {scope}))\n"
    ))
}

/// Seatbelt profile for the egress boundary: the helper runs, and no
/// network operation carries an allowance, so the kernel denies egress.
#[must_use = "the profile is a pure builder; an unused one proves nothing"]
pub fn egress_profile() -> String {
    format!("(version 1)\n    (allow process-exec (literal \"/usr/bin/nc\"))\n{SYSTEM_READ_RULES}")
}

/// Outcome of one confined run. The child's stdout is never captured —
/// gates and probes decide on the exit status alone — so no run can
/// buffer an unbounded child stream in this process. `stderr` carries the
/// deprecation-filtered remainder; the filtered warning lines survive in
/// `deprecation_notices` as diagnostics and never influence `exit_ok`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfinedOutcome {
    pub exit_ok: bool,
    pub stderr: String,
    pub deprecation_notices: String,
}

/// Runs one program under the Seatbelt profile. Arguments are passed
/// separately, the child inherits no environment, and only the exit
/// status decides success — deprecation stderr never does (EDGE-010).
/// The child's stdout goes to `/dev/null`: no caller consumes it, and
/// piping it into this process would buffer whatever the confined
/// program produces before any byte limit could apply. Stderr is drained
/// to EOF but only its first 64 KiB are retained, so no run buffers an
/// unbounded stream here either.
///
/// # Errors
/// Returns [`WorkerError::SandboxSpawnFailed`] when the sandbox mechanism
/// itself cannot be started or observed — an init failure, never an
/// effect denial.
pub fn run_confined(
    sandbox_exec: &Path,
    profile: &str,
    program: &Path,
    args: &[&OsStr],
) -> Result<ConfinedOutcome, WorkerError> {
    let mut child = helper_launch_command()?
        .arg(sandbox_exec)
        .arg("-p")
        .arg(profile)
        .arg("--")
        .arg(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| WorkerError::SandboxSpawnFailed { source })?;
    let stderr = child.stderr.take();
    let observed = observe_confined_child(&mut child, None, &[], None, stderr)?;
    if let Some(error) = helper_launch_init_failed(&observed) {
        return Err(error);
    }
    let (stderr, deprecation_notices) =
        split_deprecation_stderr(&String::from_utf8_lossy(&observed.stderr));
    Ok(ConfinedOutcome {
        exit_ok: observed.status.success(),
        stderr,
        deprecation_notices,
    })
}

/// Splits raw stderr into (retained lines, exact-prefix deprecation
/// notices). Only a line that starts with the exact prefix is filtered;
/// a line that merely contains the text stays.
#[must_use = "the split is pure; discarding it discards the diagnostics"]
pub fn split_deprecation_stderr(raw: &str) -> (String, String) {
    let mut retained = Vec::new();
    let mut notices = Vec::new();
    for line in raw.lines() {
        if line.starts_with(DEPRECATION_PREFIX) {
            notices.push(line);
        } else {
            retained.push(line);
        }
    }
    (retained.join("\n"), notices.join("\n"))
}

/// Verdict of one confined gate or effect leg: an admitted run is `Ok`;
/// a denied run is the typed OS denial naming the target.
fn expect_admitted(outcome: ConfinedOutcome, target: &Path) -> Result<(), WorkerError> {
    if outcome.exit_ok {
        Ok(())
    } else {
        Err(WorkerError::SandboxDenied {
            target: target.to_path_buf(),
        })
    }
}

/// Verdict of one denied probe leg: a run the boundary admitted is a
/// capability failure; the expected denial is plain `Ok`.
fn expect_denied(outcome: ConfinedOutcome, reason: &str) -> Result<(), WorkerError> {
    if outcome.exit_ok {
        Err(WorkerError::SandboxUnavailable {
            reason: reason.to_string(),
        })
    } else {
        Ok(())
    }
}

/// OS-boundary gate for one read effect: the kernel itself must admit a
/// read of exactly this target before the checked in-process leg runs.
fn confined_read_gate(
    sandbox_exec: &Path,
    scope_root: &Path,
    canonical_target: &Path,
) -> Result<(), WorkerError> {
    let profile = read_profile(scope_root)?;
    let outcome = run_confined(
        sandbox_exec,
        &profile,
        Path::new("/bin/cat"),
        &[canonical_target.as_os_str()],
    )?;
    expect_admitted(outcome, canonical_target)
}

/// OS-boundary gate for one managed write. The confined leg touches a
/// fresh worker-owned probe artifact inside the scope — never the user's
/// target, so the gate cannot mutate it, truncate it, or recreate it
/// should it vanish mid-flight; the profile's allowance is the scope
/// subpath, and proving it on the artifact proves exactly the admission
/// the checked-fd leg then uses.
fn confined_write_gate(
    sandbox_exec: &Path,
    scope_root: &Path,
    target: &Path,
) -> Result<(), WorkerError> {
    probe_write_conformance(sandbox_exec, scope_root)?;
    let profile = write_profile(scope_root)?;
    let artifact = fresh_write_artifact(scope_root)?;
    let result = helper_probe_write("macos", &profile, &artifact);
    drop(std::fs::remove_file(&artifact));
    match result {
        Err(WorkerError::SandboxDenied { .. }) => Err(WorkerError::SandboxDenied {
            target: target.to_path_buf(),
        }),
        other => other,
    }
}

fn fresh_write_artifact(scope_root: &Path) -> Result<PathBuf, WorkerError> {
    Ok(canonical_scope(scope_root)?.join(format!(
        ".rivect-write-gate-{}-{}",
        std::process::id(),
        crate::contracts::TaskId::generate().0
    )))
}

/// One confined process execution inside the granted scope: the
/// confined run of the program IS the effect — there is no in-process
/// exec leg, so a program the boundary admits is exactly the effect
/// that happened. A bare program's own nonzero exit is indistinguishable
/// from a boundary denial here and denies the effect (the request
/// carries no arguments, so a well-formed target program exits zero).
///
/// # Errors
/// Returns [`WorkerError::ScopeRootUnavailable`] when the scope root
/// cannot be canonicalized, [`WorkerError::SandboxSpawnFailed`] when
/// the sandbox mechanism cannot start, and [`WorkerError::SandboxDenied`]
/// when the boundary rejects the program.
pub fn exec_once(scope_root: &Path, program: &Path) -> Result<(), WorkerError> {
    exec_once_with(Path::new(SANDBOX_EXEC), scope_root, program)
}

/// Same as [`exec_once`] with an injected Seatbelt launcher so a
/// non-enforcing binary fails closed at the denied control.
pub fn exec_once_with(
    sandbox_exec: &Path,
    scope_root: &Path,
    program: &Path,
) -> Result<(), WorkerError> {
    let profile = exec_profile(scope_root)?;
    let denied = run_confined(sandbox_exec, &profile, Path::new("/usr/bin/true"), &[])?;
    expect_denied(
        denied,
        "seatbelt exec boundary admitted the denied control /usr/bin/true",
    )?;
    let outcome = run_confined(sandbox_exec, &profile, program, &[])?;
    expect_admitted(outcome, program)
}

/// The egress control leg's helper binary (macOS ships nc).
const EGRESS_HELPER: &str = "/usr/bin/nc";

/// One egress attempt against the Seatbelt boundary. This backend
/// grants no egress allowance anywhere, so the confined leg exists to
/// prove the denial is the OS boundary's, never a stub: the control
/// target is a listener this worker holds itself — a passthrough
/// mechanism would connect and is a capability failure, caught before
/// any externally visible connect. The requested URL never enters a
/// child argument list; the typed denial names it.
///
/// # Errors
/// Returns [`WorkerError::SandboxUnavailable`] when the control
/// listener cannot be held or the boundary admits the denied control
/// connect, [`WorkerError::SandboxSpawnFailed`] when the mechanism
/// cannot start, and [`WorkerError::SandboxDenied`] naming the
/// requested URL — the typed form of the OS denial every egress effect
/// meets here.
pub fn egress_once(url: &str) -> Result<(), WorkerError> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|source| {
        WorkerError::SandboxUnavailable {
            reason: format!("egress control listener unavailable: {source}"),
        }
    })?;
    let port = listener
        .local_addr()
        .map_err(|source| WorkerError::SandboxUnavailable {
            reason: format!("egress control listener unavailable: {source}"),
        })?
        .port();
    let control = run_confined(
        Path::new(SANDBOX_EXEC),
        &egress_profile(),
        Path::new(EGRESS_HELPER),
        &[
            OsStr::new("-w"),
            OsStr::new("1"),
            OsStr::new("127.0.0.1"),
            OsStr::new(&port.to_string()),
        ],
    )?;
    if control.exit_ok {
        return Err(WorkerError::SandboxUnavailable {
            reason: "seatbelt egress boundary admitted the denied control connect".to_string(),
        });
    }
    Err(WorkerError::SandboxDenied {
        target: PathBuf::from(url),
    })
}

/// Proves the Seatbelt read boundary enforces before the first read
/// effect in a scope (PROH-001, EDGE-009/010): the kernel must deny a
/// confined read of the denied probe target and admit a confined read of
/// this target. The denied leg runs first, so a non-enforcing mechanism
/// is caught before any leg touches the user's target. Both legs
/// discriminate enforcement from filesystem permission — an unreadable
/// probe target proves nothing, and a target this process cannot read is
/// a typed effect denial, never a capability failure.
///
/// # Errors
/// Returns [`WorkerError::SandboxSpawnFailed`] when the mechanism cannot
/// start, [`WorkerError::SandboxUnavailable`] when the boundary does not
/// enforce or the scope is not confinable, and the worker's typed effect
/// denials for targets this process cannot observe.
pub fn probe_read_conformance(
    sandbox_exec: &Path,
    scope_root: &Path,
    target: &Path,
) -> Result<(), WorkerError> {
    let key = (sandbox_exec.to_path_buf(), canonical_scope(scope_root)?);
    if CONFORMANT_READ_SCOPES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .contains(&key)
    {
        return Ok(());
    }
    let canonical_target = target
        .canonicalize()
        .map_err(|_source| WorkerError::TargetMissing {
            target: target.to_path_buf(),
        })?;
    let profile = read_profile(scope_root)?;
    // Denied leg first: on a non-enforcing mechanism this read succeeds
    // and the probe fails before any leg touches the user's target. The
    // verdict discriminates only while this process could read the probe
    // target without the boundary at all.
    let denied = run_confined(
        sandbox_exec,
        &profile,
        Path::new("/bin/cat"),
        &[Path::new(DENIED_PROBE_TARGET).as_os_str()],
    )?;
    expect_denied(
        denied,
        "conformance probe: the boundary admitted the denied read leg",
    )?;
    if File::open(DENIED_PROBE_TARGET).is_err() {
        return Err(WorkerError::SandboxUnavailable {
            reason: "conformance probe: the denied read target is unreadable, so enforcement cannot be proven"
                .to_string(),
        });
    }
    // Admitted leg on the user's canonical target: a failure distinguishes
    // a target this process cannot read (a typed effect denial) from a
    // boundary that wrongly denies in-scope reads (a capability failure).
    match run_confined(
        sandbox_exec,
        &profile,
        Path::new("/bin/cat"),
        &[canonical_target.as_os_str()],
    ) {
        Ok(outcome) if outcome.exit_ok => {}
        Ok(_) => {
            File::open(&canonical_target).map_err(|source| WorkerError::ReadFailed { source })?;
            return Err(WorkerError::SandboxUnavailable {
                reason: "conformance probe: the boundary denied the in-scope read leg".to_string(),
            });
        }
        Err(error) => return Err(error),
    }
    CONFORMANT_READ_SCOPES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key);
    Ok(())
}

/// Proves the Seatbelt write boundary enforces before the first managed
/// write in a scope: the kernel must deny a confined write to a file this
/// process owns outside the scope and admit one to a fresh artifact inside
/// the scope. The denied leg runs first, so a non-enforcing mechanism is
/// caught before any in-scope ambient I/O. The admitted artifact is
/// unlinked after the probe — later gates use their own fresh names. A
/// scope this process cannot write is a typed effect denial, never a
/// capability failure.
///
/// # Errors
/// Returns [`WorkerError::SandboxSpawnFailed`] when the mechanism cannot
/// start, [`WorkerError::SandboxUnavailable`] when the boundary does not
/// enforce or the scope is not confinable, and [`WorkerError::WriteFailed`]
/// when the scope is not writable by this process.
pub fn probe_write_conformance(sandbox_exec: &Path, scope_root: &Path) -> Result<(), WorkerError> {
    let key = (sandbox_exec.to_path_buf(), canonical_scope(scope_root)?);
    if CONFORMANT_WRITE_SCOPES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .contains(&key)
    {
        return Ok(());
    }
    let profile = write_profile(scope_root)?;
    // Denied leg first: the candidate lives in a private directory this
    // process just created outside the scope, so only the boundary can
    // deny the write — and a confined write that succeeds means it never
    // denied anything. The stray a passthrough touch created and its
    // directory are removed either way.
    let candidate = denied_write_candidate(
        &key.1,
        "conformance probe: no securable write-denial probe root outside the scope, so it is not confinable",
    )?;
    let denied = run_confined(
        sandbox_exec,
        &profile,
        Path::new("/usr/bin/touch"),
        &[candidate.as_os_str()],
    );
    drop(std::fs::remove_file(&candidate));
    if let Some(parent) = candidate.parent() {
        drop(std::fs::remove_dir(parent));
    }
    expect_denied(
        denied?,
        "conformance probe: the boundary admitted the denied write leg",
    )?;
    // Admitted leg on a fresh artifact this worker owns inside the scope;
    // no confined leg ever touches the user's write target. A failure
    // distinguishes a scope this process cannot write (an effect denial)
    // from a boundary that wrongly denies in-scope writes (a capability
    // failure).
    let artifact = key.1.join(format!(
        ".rivect-write-probe-{}-{}",
        std::process::id(),
        crate::contracts::TaskId::generate().0
    ));
    let admitted = run_confined(
        sandbox_exec,
        &profile,
        Path::new("/usr/bin/touch"),
        &[artifact.as_os_str()],
    );
    match admitted {
        Ok(outcome) if outcome.exit_ok => {
            drop(std::fs::remove_file(&artifact));
        }
        Ok(_) => {
            // `O_NOFOLLOW` keeps this writability check from ever opening
            // through a symlink planted on the artifact path — a tampered
            // artifact surfaces as the same typed write denial as a scope
            // this process cannot write.
            let fallback = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .custom_flags(O_NOFOLLOW)
                .open(&artifact);
            drop(std::fs::remove_file(&artifact));
            return match fallback {
                Ok(_) => Err(WorkerError::SandboxUnavailable {
                    reason: "conformance probe: the boundary denied the in-scope write leg"
                        .to_string(),
                }),
                Err(source) => Err(WorkerError::WriteFailed { source }),
            };
        }
        Err(error) => {
            drop(std::fs::remove_file(&artifact));
            return Err(error);
        }
    }
    CONFORMANT_WRITE_SCOPES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::executor::{STDERR_RETAIN_BYTES, drain_retaining_cap, same_regular_file};
    use std::io::Read as _;

    #[test]
    fn target_identity_requires_same_regular_file() -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "rivect-worker-{}",
            crate::contracts::TaskId::generate().0
        ));
        std::fs::create_dir_all(&root)?;
        let first = root.join("first");
        let second = root.join("second");
        std::fs::write(&first, b"first")?;
        std::fs::write(&second, b"second")?;
        let first_meta = std::fs::metadata(&first)?;
        let second_meta = std::fs::metadata(&second)?;
        let directory_meta = std::fs::metadata(&root)?;
        assert!(same_regular_file(&first_meta, &first_meta));
        assert!(!same_regular_file(&first_meta, &second_meta));
        assert!(!same_regular_file(&first_meta, &directory_meta));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn drain_retains_only_the_cap_and_drains_to_eof() {
        let oversized = STDERR_RETAIN_BYTES + 4096;
        let mut stream = std::io::Cursor::new(vec![b'e'; oversized]);
        let retained = drain_retaining_cap(&mut stream).expect("drain oversized stderr");
        assert_eq!(
            retained.len(),
            STDERR_RETAIN_BYTES,
            "a spamming child retains exactly the cap"
        );
        assert!(retained.iter().all(|&byte| byte == b'e'));
        // EOF was reached, not merely the cap: a second read yields nothing.
        let mut tail = Vec::new();
        stream
            .read_to_end(&mut tail)
            .expect("stream already at eof");
        assert!(tail.is_empty());

        let mut small = std::io::Cursor::new(b"operation not permitted".to_vec());
        let retained = drain_retaining_cap(&mut small).expect("drain bounded stderr");
        assert_eq!(retained, b"operation not permitted");
    }
}
