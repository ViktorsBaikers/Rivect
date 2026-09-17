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

use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, PoisonError};
/// The one injected backend seam: everything the executor reads goes
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
    fn from_metadata(metadata: &Metadata) -> Self {
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
    #[error(
        "capability unavailable: seatbelt {reason}; recovery: fix the environment or run on a capable kernel"
    )]
    SandboxUnavailable { reason: String },
}

fn same_regular_file(expected: &Metadata, opened: &Metadata) -> bool {
    expected.is_file()
        && opened.is_file()
        && expected.dev() == opened.dev()
        && expected.ino() == opened.ino()
}
fn inspect_regular_target(
    scope_root: &Path,
    target: &Path,
) -> Result<(PathBuf, Metadata), WorkerError> {
    let scope = scope_root
        .canonicalize()
        .map_err(|source| WorkerError::ScopeRootUnavailable { source })?;
    let canonical_target = target
        .canonicalize()
        // Every canonicalize failure — missing, permission, symlink loop —
        // denies the effect the same way: the target is unavailable.
        .map_err(|_source| WorkerError::TargetMissing {
            target: target.to_path_buf(),
        })?;
    if !canonical_target.starts_with(&scope) {
        return Err(WorkerError::OutsideScope {
            target: target.to_path_buf(),
        });
    }
    let canonical_meta = std::fs::metadata(&canonical_target)
        .map_err(|source| WorkerError::MetadataUnavailable { source })?;
    if !canonical_meta.is_file() {
        return Err(WorkerError::NotRegularFile {
            target: target.to_path_buf(),
        });
    }
    Ok((canonical_target, canonical_meta))
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
    // The open re-walks the original path without O_NOFOLLOW: a swap to a
    // different regular file is caught by the dev/ino identity check below
    // (fail-closed), and a swap to a FIFO cannot hang this bounded open
    // (O_NONBLOCK) before the fd-level regular-file check denies it.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
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
    // Hardlinks inside the granted scope share dev+inode and remain allowed.
    if !same_regular_file(&canonical_meta, &opened_meta) {
        return Err(WorkerError::TargetChanged {
            target: target.to_path_buf(),
        });
    }
    if opened_meta.len() > READ_MAX_BYTES as u64 {
        return Err(WorkerError::TooLarge);
    }
    let mut bounded = Vec::with_capacity(opened_meta.len() as usize);
    file.take((READ_MAX_BYTES as u64) + 1)
        .read_to_end(&mut bounded)
        .map_err(|source| WorkerError::ReadFailed { source })?;
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
    // The open re-walks the original path. Both the admitted identity and the
    // canonical-path identity must match the opened handle before any fd
    // mutation can happen.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(O_NONBLOCK)
        .open(target)
        .map_err(|source| WorkerError::WriteFailed { source })?;
    write_opened_file(target, &canonical_meta, &mut file, expected, bytes)
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
    write_opened_file(target, &canonical_meta, file, expected, bytes)
}

fn write_opened_file(
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
    let length =
        u64::try_from(bytes.len()).map_err(|source| WorkerError::WriteLengthOverflow { source })?;
    file.set_len(length)
        .map_err(|source| WorkerError::WriteMutationFailed { source })?;
    file.write_all(bytes)
        .map_err(|source| WorkerError::WriteMutationFailed { source })
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

/// Write conformance verdicts plus the in-scope probe artifact each later
/// write gate reuses, under the same caching rules as the read set.
static CONFORMANT_WRITE_SCOPES: Mutex<BTreeMap<(PathBuf, PathBuf), PathBuf>> =
    Mutex::new(BTreeMap::new());

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

/// Escapes one canonical path into a Seatbelt string literal.
fn scheme_literal(canonical: &Path) -> Result<String, WorkerError> {
    let text = canonical
        .to_str()
        .ok_or_else(|| WorkerError::SandboxUnavailable {
            reason: "scope root is not valid unicode".to_string(),
        })?;
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
        "(version 1)\n{SYSTEM_READ_RULES}    (allow process-exec (subpath {scope}))\n"
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

/// Upper bound on retained child stderr: plenty for every denial or
/// diagnostic a gate decides on, while a stderr-spamming child can never
/// buffer an unbounded stream in this process.
const STDERR_RETAIN_BYTES: usize = 64 * 1024;

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
    let mut child = Command::new(sandbox_exec)
        .arg("-p")
        .arg(profile)
        .arg(program)
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| WorkerError::SandboxSpawnFailed { source })?;
    // Drain stderr to EOF before waiting: a child holding a full stderr
    // pipe could otherwise block forever against a wait()ing parent.
    let raw = match child.stderr.take() {
        Some(pipe) => drain_retaining_cap(pipe)
            .map_err(|source| WorkerError::SandboxSpawnFailed { source })?,
        None => Vec::new(),
    };
    let status = child
        .wait()
        .map_err(|source| WorkerError::SandboxSpawnFailed { source })?;
    let (stderr, deprecation_notices) = split_deprecation_stderr(&String::from_utf8_lossy(&raw));
    Ok(ConfinedOutcome {
        exit_ok: status.success(),
        stderr,
        deprecation_notices,
    })
}

/// Reads one stream to EOF but retains only its first
/// [`STDERR_RETAIN_BYTES`]: the read loop never stops early, so the
/// writer can always drain, while this process holds a bounded buffer.
fn drain_retaining_cap(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut retained = Vec::new();
    let mut scratch = [0u8; 8192];
    loop {
        let read = reader.read(&mut scratch)?;
        if read == 0 {
            return Ok(retained);
        }
        let room = STDERR_RETAIN_BYTES.saturating_sub(retained.len());
        retained.extend_from_slice(&scratch[..read.min(room)]);
    }
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
    if outcome.exit_ok {
        Ok(())
    } else {
        Err(WorkerError::SandboxDenied {
            target: canonical_target.to_path_buf(),
        })
    }
}

/// OS-boundary gate for one managed write. The confined leg touches the
/// probe artifact [`probe_write_conformance`] owns inside the scope —
/// never the user's target, so the gate cannot mutate it, truncate it, or
/// recreate it should it vanish mid-flight; the profile's allowance is
/// the scope subpath, and proving it on the artifact proves exactly the
/// admission the checked-fd leg then uses.
fn confined_write_gate(
    sandbox_exec: &Path,
    scope_root: &Path,
    target: &Path,
) -> Result<(), WorkerError> {
    let artifact = probe_write_conformance(sandbox_exec, scope_root)?;
    let profile = write_profile(scope_root)?;
    let outcome = run_confined(
        sandbox_exec,
        &profile,
        Path::new("/usr/bin/touch"),
        &[artifact.as_os_str()],
    )?;
    if outcome.exit_ok {
        Ok(())
    } else {
        Err(WorkerError::SandboxDenied {
            target: target.to_path_buf(),
        })
    }
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
    match run_confined(
        sandbox_exec,
        &profile,
        Path::new("/bin/cat"),
        &[Path::new(DENIED_PROBE_TARGET).as_os_str()],
    ) {
        Ok(outcome) if outcome.exit_ok => {
            return Err(WorkerError::SandboxUnavailable {
                reason: "conformance probe: the boundary admitted the denied read leg".to_string(),
            });
        }
        Ok(_) => {
            if File::open(DENIED_PROBE_TARGET).is_err() {
                return Err(WorkerError::SandboxUnavailable {
                    reason: "conformance probe: the denied read target is unreadable, so enforcement cannot be proven"
                        .to_string(),
                });
            }
        }
        Err(error) => return Err(error),
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

/// One write-denial probe target: a path inside a private directory
/// outside the scope, freshly created 0700 under an unpredictable name
/// so only this process can populate it. A denied confined write there
/// names enforcement alone — never filesystem permission, never a
/// symlink planted in a shared temporary directory. A scope covering
/// every candidate root has no outside left to deny and is not
/// confinable.
fn denied_write_candidate(scope: &Path) -> Result<PathBuf, WorkerError> {
    for root in [
        std::env::temp_dir(),
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
    ] {
        let Ok(parent) = root.canonicalize() else {
            continue;
        };
        if parent.starts_with(scope) {
            continue;
        }
        let dir = parent.join(format!(
            "rivect-sandbox-probe-{}-{}",
            std::process::id(),
            crate::contracts::TaskId::generate().0
        ));
        if std::fs::create_dir(&dir).is_ok() && set_private_mode(&dir) {
            return Ok(dir.join("deny"));
        }
    }
    Err(WorkerError::SandboxUnavailable {
        reason: "conformance probe: no securable write-denial probe root outside the scope, so it is not confinable"
            .to_string(),
    })
}

/// Drops group and other access on a freshly created probe directory.
fn set_private_mode(dir: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).is_ok()
}

/// Proves the Seatbelt write boundary enforces before the first managed
/// write in a scope and returns the in-scope probe artifact later gates
/// reuse: the kernel must deny a confined write to a file this process
/// owns outside the scope and admit one to an artifact inside the scope.
/// The denied leg runs first, so a non-enforcing mechanism is caught
/// before any in-scope ambient I/O. A scope this process cannot write is
/// a typed effect denial, never a capability failure.
///
/// # Errors
/// Returns [`WorkerError::SandboxSpawnFailed`] when the mechanism cannot
/// start, [`WorkerError::SandboxUnavailable`] when the boundary does not
/// enforce or the scope is not confinable, and [`WorkerError::WriteFailed`]
/// when the scope is not writable by this process.
pub fn probe_write_conformance(
    sandbox_exec: &Path,
    scope_root: &Path,
) -> Result<PathBuf, WorkerError> {
    let key = (sandbox_exec.to_path_buf(), canonical_scope(scope_root)?);
    if let Some(artifact) = CONFORMANT_WRITE_SCOPES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&key)
    {
        return Ok(artifact.clone());
    }
    let profile = write_profile(scope_root)?;
    // Denied leg first: the candidate lives in a private directory this
    // process just created outside the scope, so only the boundary can
    // deny the write — and a confined write that succeeds means it never
    // denied anything. The stray a passthrough touch created and its
    // directory are removed either way.
    let candidate = denied_write_candidate(&key.1)?;
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
    match denied {
        Ok(outcome) if outcome.exit_ok => {
            return Err(WorkerError::SandboxUnavailable {
                reason: "conformance probe: the boundary admitted the denied write leg".to_string(),
            });
        }
        Ok(_) => {}
        Err(error) => return Err(error),
    }
    // Admitted leg on an artifact this worker owns inside the scope; the
    // per-effect gates reuse it, so no confined leg ever touches the
    // user's write target. A failure distinguishes a scope this process
    // cannot write (an effect denial) from a boundary that wrongly denies
    // in-scope writes (a capability failure).
    let artifact = key
        .1
        .join(format!(".rivect-write-probe-{}", std::process::id()));
    match run_confined(
        sandbox_exec,
        &profile,
        Path::new("/usr/bin/touch"),
        &[artifact.as_os_str()],
    ) {
        Ok(outcome) if outcome.exit_ok => {}
        Ok(_) => {
            // `O_NOFOLLOW` keeps this writability check from ever opening
            // through a symlink planted on the artifact path — a tampered
            // artifact surfaces as the same typed write denial as a scope
            // this process cannot write.
            return match std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .custom_flags(O_NOFOLLOW)
                .open(&artifact)
            {
                Ok(_) => {
                    drop(std::fs::remove_file(&artifact));
                    Err(WorkerError::SandboxUnavailable {
                        reason: "conformance probe: the boundary denied the in-scope write leg"
                            .to_string(),
                    })
                }
                Err(source) => Err(WorkerError::WriteFailed { source }),
            };
        }
        Err(error) => return Err(error),
    }
    CONFORMANT_WRITE_SCOPES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key, artifact.clone());
    Ok(artifact)
}

#[cfg(test)]
mod tests {
    use super::{STDERR_RETAIN_BYTES, drain_retaining_cap, same_regular_file};
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
