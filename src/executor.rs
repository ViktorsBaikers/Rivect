//! Effect executor: admission, pre-open policy checks, and opened-fd identity
//! checks before effects. The permission-mode consult (DEC-014/016) rides
//! the admit→execute path: an Allow cell of any effect class reaches the
//! confined worker, ask and deny verdicts fail closed at the gates, and
//! out-of-scope effects meet the worker's OS boundary instead of a
//! pre-worker class bypass. Managed writes stay policy-gated control
//! writes on the explicit checked-fd path.

pub mod linux;
pub mod macos;

use crate::config::hex;
use crate::contracts::{EffectClass, ErrorCode, TaskId};
use crate::policy::{
    AdmissionContext, ModeDecision, PermissionMode, Policy, PolicyError, preapproval_scope,
};
use crate::resources::{ReadFlightKey, ReadFlights, ReadRights, SnapshotBinding};
use crate::state::{StoreError, TaskStore};
use sha2::Digest as _;
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

pub use macos::{FileIdentity, ReadObservation, ReadWorker, WorkerError};

#[derive(Debug, Clone, PartialEq)]
pub enum EffectRequest {
    Read {
        grant_id: String,
        path: PathBuf,
    },
    Write {
        grant_id: String,
        path: PathBuf,
        bytes: Vec<u8>,
    },
    Exec {
        grant_id: String,
        program: PathBuf,
    },
    Egress {
        grant_id: String,
        url: String,
    },
}

impl EffectRequest {
    pub fn class(&self) -> EffectClass {
        match self {
            Self::Read { .. } => EffectClass::Read,
            Self::Write { .. } => EffectClass::Write,
            Self::Exec { .. } => EffectClass::Exec,
            Self::Egress { .. } => EffectClass::Egress,
        }
    }

    /// The grant identity every arm carries: the admission the policy
    /// checks at plan and again immediately before the effect.
    pub fn grant_id(&self) -> &str {
        match self {
            Self::Read { grant_id, .. }
            | Self::Write { grant_id, .. }
            | Self::Exec { grant_id, .. }
            | Self::Egress { grant_id, .. } => grant_id,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Read { path, .. } => format!("read {}", path.display()),
            Self::Write { path, .. } => format!("write {}", path.display()),
            Self::Exec { program, .. } => format!("exec {}", program.display()),
            Self::Egress { url, .. } => format!("egress {url}"),
        }
    }

    /// Decision-consult identity of the request target. Egress names a
    /// URL: the class-routed deny consult matches it against the enrolled
    /// raw denies first, and a filesystem-shaped spelling (an absolute
    /// path or a `file://` URL) additionally consults the filesystem
    /// deny set (DEC-012).
    pub fn target_path(&self) -> PathBuf {
        match self {
            Self::Read { path, .. } | Self::Write { path, .. } => path.clone(),
            Self::Exec { program, .. } => program.clone(),
            Self::Egress { url, .. } => PathBuf::from(url),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdmittedEffect {
    pub task_id: TaskId,
    pub attempt_id: String,
    pub request: EffectRequest,
    /// The caller's permission mode this effect was admitted under
    /// (DEC-016). The execute-time reconsult reuses exactly this mode —
    /// never a fresh default — so the verdict cannot drift between the
    /// gates.
    pub mode: PermissionMode,
    /// Admit-time occupant identity for write effects (INV-029): the
    /// execute-time checked-fd write compares the opened handle against
    /// exactly this snapshot — the same binding `AdmittedManagedWrite`
    /// carries — so an occupant swap between admit and execute denies
    /// instead of landing the payload on the swapped file. Non-write
    /// effects pin no occupant; a write without this binding denies
    /// closed at execute.
    pub expected_identity: Option<FileIdentity>,
    pub scope_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdmittedManagedWrite {
    task_id: TaskId,
    attempt_id: String,
    grant_id: String,
    scope_root: PathBuf,
    path: PathBuf,
    bytes: Vec<u8>,
    expected_identity: FileIdentity,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EffectOutcome {
    Read {
        bytes: Vec<u8>,
        digest: String,
    },
    /// A non-read effect the confined worker performed; `detail` is the
    /// same observation string the confirmed ledger row carries.
    Executed {
        detail: String,
    },
    Denied {
        reason: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    #[error("effect denied: {0}")]
    Policy(#[from] PolicyError),
    #[error("effect denied: {0}")]
    Worker(#[from] WorkerError),
    #[error("effect denied: {TASK_CANCELLED}")]
    Cancelled,
    #[error("effect denied: policy deny")]
    PolicyDenied,
    #[error("effect denied: {MODE_ASK_REASON}")]
    ModeAsk,
    #[error("effect denied: {MODE_DENY_REASON}")]
    ModeDenied,
    #[error("effect denied: {}", readonly_rejection(*class))]
    Readonly { class: EffectClass },
    #[error("effect store: {0}")]
    Store(#[from] StoreError),
}

impl ExecutorError {
    /// Wire code for the failed effect path, mapped at one boundary. A
    /// sandbox that cannot start or does not enforce is a capability
    /// failure with a recovery read; every other denial is a denied
    /// effect, and a store failure keeps its storage code.
    #[must_use = "the code exists to be carried to the wire; discarding it loses the mapping"]
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Worker(
                WorkerError::SandboxSpawnFailed { .. }
                | WorkerError::SandboxUnavailable { .. }
                | WorkerError::ConfinedRunTimedOut,
            ) => ErrorCode::CapabilityUnavailable,
            Self::Worker(_)
            | Self::Policy(_)
            | Self::PolicyDenied
            | Self::ModeAsk
            | Self::ModeDenied
            | Self::Readonly { .. } => ErrorCode::Denied,
            Self::Cancelled => ErrorCode::Cancelled,
            Self::Store(_) => ErrorCode::StorageUnavailable,
        }
    }
}

pub const TASK_CANCELLED: &str = "task cancelled";
/// Ledger reason when the mode verdict is `ask`: the effect waits for human
/// permission and never runs on its own.
pub const MODE_ASK_REASON: &str = "mode ask: permission required";
/// Ledger reason when the mode verdict denies the request outright.
pub const MODE_DENY_REASON: &str = "mode deny";
/// Ledger reason for preview-only submissions: the verdict is recorded, no
/// effect can run (AC-089 dry-run conjunct).
pub const DRY_RUN_REASON: &str = "dry run: preview only, no effect";

fn readonly_rejection(class: EffectClass) -> String {
    format!(
        "read-only worker rejects {} effects; no ambient fallback",
        match class {
            EffectClass::Write => "write",
            EffectClass::Exec => "exec",
            EffectClass::Egress => "direct egress",
            _ => "this",
        }
    )
}

/// The ledger outcome of one performed read: the effect result and its
/// confirmation detail share one digest, whichever flight member
/// journalled it.
fn read_result(observation: ReadObservation) -> (EffectOutcome, String) {
    (
        EffectOutcome::Read {
            bytes: observation.bytes,
            digest: observation.digest.clone(),
        },
        format!("read-performed sha256={}", observation.digest),
    )
}

// ---------------------------------------------------------------------------
// Backend-neutral worker helpers the macOS and Linux backends share:
// every backend keeps its own confinement mechanism, while the target
// inspection and probe discipline below are one discipline.
// ---------------------------------------------------------------------------

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

/// Upper bound on retained child stderr: plenty for every denial or
/// diagnostic a gate decides on, while a stderr-spamming child can never
/// buffer an unbounded stream in this process.
const STDERR_RETAIN_BYTES: usize = 64 * 1024;

/// Reads one stream to EOF but retains only its first
/// [`STDERR_RETAIN_BYTES`]: the read loop never stops early, so the
/// writer can always drain, while this process holds a bounded buffer.
#[cfg(test)]
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

/// Wall deadline for one confined child: a hung FIFO or a wedged helper
/// is killed instead of blocking the executor forever.
pub(crate) const CONFINED_DEADLINE: Duration = Duration::from_secs(5);

pub(crate) struct ObservedChild {
    pub status: std::process::ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub(crate) fn helper_path() -> Result<PathBuf, WorkerError> {
    require_helper_file(
        rivect_sandbox_helper::helper_binary()
            .map_err(|source| WorkerError::SandboxSpawnFailed { source })?,
    )
}

fn require_helper_file(path: PathBuf) -> Result<PathBuf, WorkerError> {
    if path.is_file() {
        Ok(path)
    } else {
        Err(WorkerError::SandboxUnavailable {
            reason: format!("confined helper is not a file: {}", path.display()),
        })
    }
}

fn configure_confined_command(command: &mut Command) {
    command.process_group(0).env_clear();
}

pub(crate) fn helper_launch_command() -> Result<Command, WorkerError> {
    let mut command = Command::new(helper_path()?);
    command.arg("launch").arg("--");
    configure_confined_command(&mut command);
    Ok(command)
}

/// Linux data-plane helper: Landlock is inside the binary; the parent
/// supplies the same `unshare --net` / `setpriv --nnp --seccomp-filter`
/// chain `run_confined` uses, with `--` before the helper so a path
/// named like an option cannot be parsed as a launcher flag.
#[cfg(target_os = "linux")]
fn linux_wrapped_helper() -> Result<Command, WorkerError> {
    let helper = helper_path()?;
    let mut command = helper_launch_command()?;
    command
        .arg(linux::UNSHARE)
        .arg("--net")
        .arg("--")
        .arg(linux::SETPRIV)
        .arg("--nnp")
        .arg("--seccomp-filter")
        .arg(linux::net_deny_filter_file()?)
        .arg("--")
        .arg(&helper);
    Ok(command)
}

pub(crate) fn helper_confined_command(
    platform: &str,
    mode: &str,
    profile: &str,
) -> Result<Command, WorkerError> {
    #[cfg(target_os = "linux")]
    {
        let mut command = linux_wrapped_helper()?;
        command.arg("confined").arg(platform).arg(mode);
        if !profile.is_empty() {
            command.arg(profile);
        }
        Ok(command)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut command = Command::new(helper_path()?);
        command.arg("confined").arg(platform).arg(mode);
        if !profile.is_empty() {
            command.arg(profile);
        }
        configure_confined_command(&mut command);
        Ok(command)
    }
}

fn pipe_nonblocking(fd: impl AsFd) -> Result<(), WorkerError> {
    rivect_sandbox_helper::set_nonblocking(fd)
        .map_err(|source| WorkerError::SandboxSpawnFailed { source })
}

fn write_stdin_nonblocking(
    stdin: &mut Option<ChildStdin>,
    payload: &mut &[u8],
) -> Result<(), WorkerError> {
    let Some(pipe) = stdin.as_mut() else {
        return Ok(());
    };
    if payload.is_empty() {
        *stdin = None;
        return Ok(());
    }
    match pipe.write(payload) {
        Ok(0) => Ok(()),
        Ok(n) => {
            *payload = &payload[n..];
            Ok(())
        }
        Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::Interrupted =>
        {
            Ok(())
        }
        Err(source) => Err(WorkerError::SandboxSpawnFailed { source }),
    }
}

/// Drains a confined child via nonblocking pipes, `yield_now`, and a wall
/// deadline that kills the child.
pub(crate) fn observe_confined_child(
    child: &mut Child,
    mut stdin: Option<ChildStdin>,
    mut payload: &[u8],
    mut stdout: Option<ChildStdout>,
    mut stderr: Option<ChildStderr>,
) -> Result<ObservedChild, WorkerError> {
    if let Some(ref pipe) = stdin {
        pipe_nonblocking(pipe.as_fd())?;
    }
    if let Some(ref pipe) = stdout {
        pipe_nonblocking(pipe.as_fd())?;
    }
    if let Some(ref pipe) = stderr {
        pipe_nonblocking(pipe.as_fd())?;
    }
    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let mut scratch = [0u8; 8192];
    let deadline = Instant::now() + CONFINED_DEADLINE;
    loop {
        write_stdin_nonblocking(&mut stdin, &mut payload)?;
        drain_nonblocking_pipe(&mut stdout, &mut stdout_buf, &mut scratch, READ_MAX_CAP)?;
        drain_nonblocking_pipe(
            &mut stderr,
            &mut stderr_buf,
            &mut scratch,
            STDERR_RETAIN_BYTES,
        )?;
        match child.try_wait() {
            Ok(Some(status)) => {
                // The leader has exited: SIGKILL the process group before
                // the post-exit drain. A forked grandchild inherits the
                // piped stderr write end and would otherwise keep
                // WouldBlock until CONFINED_DEADLINE, which surfaces
                // ConfinedRunTimedOut instead of success. After killpg,
                // those write ends close and the drain reaches EOF. The
                // timeout path still reaps via `terminate_confined_child`
                // when the leader itself has not exited.
                drop(rivect_sandbox_helper::kill_process_group(child.id()));
                drain_pipe_to_eof(
                    &mut stdout,
                    &mut stdout_buf,
                    &mut scratch,
                    READ_MAX_CAP,
                    deadline,
                    child,
                )?;
                drain_pipe_to_eof(
                    &mut stderr,
                    &mut stderr_buf,
                    &mut scratch,
                    STDERR_RETAIN_BYTES,
                    deadline,
                    child,
                )?;
                return Ok(ObservedChild {
                    status,
                    stdout: stdout_buf,
                    stderr: stderr_buf,
                });
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    terminate_confined_child(child);
                    return Err(WorkerError::ConfinedRunTimedOut);
                }
                std::thread::yield_now();
            }
            Err(source) => return Err(WorkerError::SandboxSpawnFailed { source }),
        }
    }
}

const READ_MAX_CAP: usize = (1 << 20) + 1;

fn drain_nonblocking_pipe<T: Read>(
    pipe: &mut Option<T>,
    retained: &mut Vec<u8>,
    scratch: &mut [u8],
    cap: usize,
) -> Result<(), WorkerError> {
    let Some(reader) = pipe.as_mut() else {
        return Ok(());
    };
    match reader.read(scratch) {
        Ok(0) => {
            *pipe = None;
            Ok(())
        }
        Ok(n) => {
            let room = cap.saturating_sub(retained.len());
            retained.extend_from_slice(&scratch[..n.min(room)]);
            Ok(())
        }
        Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::Interrupted =>
        {
            Ok(())
        }
        Err(source) => Err(WorkerError::SandboxSpawnFailed { source }),
    }
}

/// Post-exit drain: after the leader exits, the caller SIGKILLs the
/// process group so a grandchild cannot hold the write end. Remaining
/// bytes then return and the pipe hits EOF. A write end still held
/// after that kill (outside the group) keeps `WouldBlock` until the
/// wall deadline, which surfaces [`WorkerError::ConfinedRunTimedOut`].
fn drain_pipe_to_eof<T: Read>(
    pipe: &mut Option<T>,
    retained: &mut Vec<u8>,
    scratch: &mut [u8],
    cap: usize,
    deadline: Instant,
    child: &mut Child,
) -> Result<(), WorkerError> {
    while pipe.is_some() {
        if Instant::now() >= deadline {
            terminate_confined_child(child);
            return Err(WorkerError::ConfinedRunTimedOut);
        }
        drain_nonblocking_pipe(pipe, retained, scratch, cap)?;
        if pipe.is_some() {
            std::thread::yield_now();
        }
    }
    Ok(())
}

fn terminate_confined_child(child: &mut Child) {
    drop(rivect_sandbox_helper::kill_process_group(child.id()));
    drop(child.kill());
    drop(child.wait());
}

pub(crate) fn helper_confined_read(
    platform: &str,
    profile: &str,
    file: File,
) -> Result<Vec<u8>, WorkerError> {
    let mut child = helper_confined_command(platform, "read", profile)?
        .stdin(Stdio::from(file))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| WorkerError::SandboxSpawnFailed { source })?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let observed = observe_confined_child(&mut child, None, &[], stdout, stderr)?;
    helper_io_bytes(observed, true)
}

pub(crate) fn helper_confined_write(
    platform: &str,
    profile: &str,
    file: File,
    bytes: &[u8],
) -> Result<(), WorkerError> {
    let mut child = helper_confined_command(platform, "write", profile)?
        .stdin(Stdio::piped())
        .stdout(Stdio::from(file))
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| WorkerError::SandboxSpawnFailed { source })?;
    let stdin = child.stdin.take();
    let stderr = child.stderr.take();
    let observed = observe_confined_child(&mut child, stdin, bytes, None, stderr)?;
    helper_io_bytes(observed, false).map(|_| ())
}

pub(crate) fn helper_probe_write(
    platform: &str,
    profile: &str,
    path: &Path,
) -> Result<(), WorkerError> {
    #[cfg(target_os = "linux")]
    let mut command = linux_wrapped_helper()?;
    #[cfg(not(target_os = "linux"))]
    let mut command = Command::new(helper_path()?);
    #[cfg(not(target_os = "linux"))]
    configure_confined_command(&mut command);
    command
        .arg("probe-write")
        .arg(platform)
        .arg(profile)
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|source| WorkerError::SandboxSpawnFailed { source })?;
    let stderr = child.stderr.take();
    let observed = observe_confined_child(&mut child, None, &[], None, stderr)?;
    helper_probe_verdict(&observed, path)
}

fn helper_exit_code(observed: &ObservedChild) -> i32 {
    observed
        .status
        .code()
        .unwrap_or(rivect_sandbox_helper::EXIT_LAUNCH_EXEC)
}

/// Maps a probe-write exit onto the same taxonomy as [`helper_io_bytes`]:
/// init → [`WorkerError::SandboxUnavailable`], protocol/launch →
/// [`WorkerError::SandboxSpawnFailed`] (wire `capability_unavailable`),
/// data I/O → [`WorkerError::SandboxDenied`].
fn helper_probe_verdict(observed: &ObservedChild, target: &Path) -> Result<(), WorkerError> {
    let code = helper_exit_code(observed);
    let stderr = String::from_utf8_lossy(&observed.stderr).into_owned();
    match code {
        rivect_sandbox_helper::EXIT_OK => Ok(()),
        rivect_sandbox_helper::EXIT_SANDBOX_INIT => {
            Err(WorkerError::SandboxUnavailable { reason: stderr })
        }
        rivect_sandbox_helper::EXIT_PROTOCOL
        | rivect_sandbox_helper::EXIT_LAUNCH_EXEC
        | rivect_sandbox_helper::EXIT_LAUNCH_NOT_FOUND => Err(WorkerError::SandboxSpawnFailed {
            source: std::io::Error::other(stderr),
        }),
        _ => Err(WorkerError::SandboxDenied {
            target: target.to_path_buf(),
        }),
    }
}

/// `launch` could not exec the sandbox mechanism: the helper itself
/// reported init/exec/protocol failure. After a successful helper `exec`,
/// util-linux `setpriv`/`unshare` reuse 126/127 (`errexec` on EACCES/ENOENT,
/// `SETPRIV_EXIT_PRIVERR` on Landlock/seccomp apply). Those are confined-run
/// outcomes — Landlock denying the deny-first control, or a probe shim
/// naming a missing ABI — never helper init. Discriminate by the helper's
/// stderr prefix (bytes produced pre-`execv`), not by which call site
/// opted into classification. Signal-killed children are left to the caller
/// (timeout already mapped [`WorkerError::ConfinedRunTimedOut`]).
pub(crate) fn helper_launch_init_failed(observed: &ObservedChild) -> Option<WorkerError> {
    let stderr = String::from_utf8_lossy(&observed.stderr);
    let from_helper = stderr
        .lines()
        .any(|line| line.starts_with("rivect-sandbox-helper:"));
    match observed.status.code() {
        Some(rivect_sandbox_helper::EXIT_SANDBOX_INIT) if from_helper => {
            Some(WorkerError::SandboxUnavailable {
                reason: stderr.into_owned(),
            })
        }
        Some(rivect_sandbox_helper::EXIT_LAUNCH_EXEC)
        | Some(rivect_sandbox_helper::EXIT_LAUNCH_NOT_FOUND)
        | Some(rivect_sandbox_helper::EXIT_PROTOCOL)
            if from_helper =>
        {
            Some(WorkerError::SandboxSpawnFailed {
                source: std::io::Error::other(stderr.into_owned()),
            })
        }
        _ => None,
    }
}

fn helper_io_bytes(observed: ObservedChild, read: bool) -> Result<Vec<u8>, WorkerError> {
    let code = helper_exit_code(&observed);
    let stderr = String::from_utf8_lossy(&observed.stderr).into_owned();
    match code {
        rivect_sandbox_helper::EXIT_OK => Ok(observed.stdout),
        rivect_sandbox_helper::EXIT_SANDBOX_INIT => {
            Err(WorkerError::SandboxUnavailable { reason: stderr })
        }
        rivect_sandbox_helper::EXIT_DATA_IO if read => Err(WorkerError::ReadFailed {
            source: std::io::Error::other(stderr),
        }),
        rivect_sandbox_helper::EXIT_DATA_IO => Err(WorkerError::WriteFailed {
            source: std::io::Error::other(stderr),
        }),
        _ => Err(WorkerError::SandboxSpawnFailed {
            source: std::io::Error::other(stderr),
        }),
    }
}

/// One write-denial probe target: a path inside a private directory
/// outside the scope, freshly created 0700 under an unpredictable name
/// so only this process can populate it. A denied confined write there
/// names enforcement alone — never filesystem permission, never a
/// symlink planted in a shared temporary directory. A scope covering
/// every candidate root has no outside left to deny and is not
/// confinable.
fn denied_write_candidate(scope: &Path, unavailable: &str) -> Result<PathBuf, WorkerError> {
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
            TaskId::generate().0
        ));
        if std::fs::create_dir(&dir).is_ok() && set_private_mode(&dir) {
            return Ok(dir.join("deny"));
        }
    }
    Err(WorkerError::SandboxUnavailable {
        reason: unavailable.to_string(),
    })
}

/// Drops group and other access on a freshly created probe directory.
fn set_private_mode(dir: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).is_ok()
}

pub struct Executor<'a> {
    pub policy: &'a mut Policy,
    pub store: &'a mut TaskStore,
    pub worker: &'a mut dyn ReadWorker,
    /// The single-flight registry for permitted reads (INV-023), when
    /// the call site runs reads merged. Absent, every admitted read
    /// executes its own physical charge — the pre-single-flight
    /// behavior.
    flights: Option<&'a mut ReadFlights>,
}
/// Assembles the DEC-014 decision inputs at an admit call site under the
/// caller's permission mode (DEC-016); call sites without a Settings
/// mode carrier still pass the interim `manual` default (DEC-015). The
/// only persisted input is preapproval (`TaskStore::is_preapproved`),
/// keyed per effect class so a write consent never admits another class.
/// Inputs that cannot yet be observed at an admit stay conservative
/// rather than granting.
///
/// `in_trusted_scope` equals `in_grant_scope` because DEC-014 does not
/// yet observe a separate trusted-folder signal. AcceptEdits reads are
/// mode-level (Allow) and the worker still confines the path at execute;
/// AcceptEdits writes consult `in_trusted_scope` together with a
/// retained checkpoint keyed as `ret:checkpoint:{canonical_scope}`.
///
/// # Errors
/// Returns [`ExecutorError::Store`] when the preapproval lookup fails and
/// [`ExecutorError::Worker`] ([`WorkerError::OutsideScope`]) when the
/// canonicalized target lies outside the canonicalized grant scope root —
/// the same typed denial the worker produces at read time.
pub fn admission_context(
    store: &TaskStore,
    mode: PermissionMode,
    class: EffectClass,
    scope_root: &Path,
    target: &Path,
) -> Result<AdmissionContext, ExecutorError> {
    let in_grant_scope = derive_in_grant_scope(scope_root, target)?;
    let scope_key = scope_root
        .canonicalize()
        .ok()
        .and_then(|path| path.to_str().map(str::to_string));
    let budget_remaining = match scope_key.as_deref() {
        Some(scope) => budget_has_remaining(store, scope)?,
        None => false,
    };
    let has_checkpoint = match scope_key.as_deref() {
        Some(scope) => store.has_retained(&checkpoint_boundary_id(scope))?,
        None => false,
    };
    let previously_approved = target
        .to_str()
        .and_then(|text| preapproval_scope(class, text))
        .map(|key| store.is_preapproved(&key))
        .transpose()?
        .unwrap_or(false);
    Ok(AdmissionContext {
        mode,
        in_grant_scope,
        budget_remaining,
        in_trusted_scope: in_grant_scope,
        has_checkpoint,
        previously_approved,
        // Exec bounds are the grant scope. Egress has no filesystem
        // scope: a recorded preapproval (canonical URL key) is the
        // declared bound, so Auto Allow is reachable for a URL that
        // was previously approved and stays Ask otherwise.
        within_declared_bounds: match class {
            EffectClass::Exec => in_grant_scope,
            EffectClass::Egress => previously_approved,
            EffectClass::Read | EffectClass::Write | EffectClass::Model | EffectClass::Control => {
                false
            }
        },
        dry_run: false,
    })
}

/// Retain key for a permission checkpoint on one canonical grant scope.
/// Production attempt evidence uses [`crate::verification::boundary_id`];
/// this key is the scope-stable id `has_checkpoint` looks up.
#[must_use]
pub fn checkpoint_boundary_id(canonical_scope: &str) -> String {
    format!("ret:checkpoint:{canonical_scope}")
}

fn budget_has_remaining(store: &TaskStore, scope: &str) -> Result<bool, ExecutorError> {
    match store.budget_status(scope) {
        Ok(status) => Ok(status.spent.saturating_add(status.reserved) < status.limit_units),
        Err(StoreError::NotFound(_)) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Conservative scope derivation for the decision context: both paths must
/// canonicalize, and a canonical target outside the canonical scope root is
/// the worker's `OutsideScope` denial surfaced before any ledger row. A
/// scope or target that cannot be observed fails closed as out-of-scope
/// input instead of granting.
fn derive_in_grant_scope(scope_root: &Path, target: &Path) -> Result<bool, ExecutorError> {
    let (Ok(scope), Ok(canonical_target)) = (scope_root.canonicalize(), target.canonicalize())
    else {
        return Ok(false);
    };
    if canonical_target.starts_with(&scope) {
        Ok(true)
    } else {
        Err(ExecutorError::Worker(WorkerError::OutsideScope {
            target: target.to_path_buf(),
        }))
    }
}

/// Ledger reason for a non-allow mode verdict; `Allow` never reaches a
/// rejection because every caller gates on `decision != Allow`.
pub(crate) fn mode_reason(decision: ModeDecision) -> &'static str {
    match decision {
        ModeDecision::Ask => MODE_ASK_REASON,
        ModeDecision::Deny => MODE_DENY_REASON,
        ModeDecision::Allow => unreachable!("internal error: allow is not a rejection"),
    }
}

impl<'a> Executor<'a> {
    pub fn new(
        policy: &'a mut Policy,
        store: &'a mut TaskStore,
        worker: &'a mut dyn ReadWorker,
    ) -> Self {
        Self {
            policy,
            store,
            worker,
            flights: None,
        }
    }

    /// The single-flight seam: identical permitted reads admitted
    /// through this executor merge into one physical charge in
    /// `flights` (INV-023); effects, differing rights, and differing
    /// snapshots never merge.
    #[must_use]
    pub fn with_flights(
        policy: &'a mut Policy,
        store: &'a mut TaskStore,
        worker: &'a mut dyn ReadWorker,
        flights: &'a mut ReadFlights,
    ) -> Self {
        Self {
            policy,
            store,
            worker,
            flights: Some(flights),
        }
    }

    /// Durable planned intent, then admission. The attempt is visible in the
    /// ledger before any effect can happen. The permission-mode consult
    /// (DEC-014) runs between the grant gate and the plan under the
    /// caller's mode (DEC-016): an enrolled deny outranks every mode, and
    /// `ask`/`deny` verdicts fail closed — only the permission panel may
    /// convert an `ask` into consent.
    pub fn admit(
        &mut self,
        task_id: &TaskId,
        request: EffectRequest,
        mode: PermissionMode,
    ) -> Result<AdmittedEffect, ExecutorError> {
        let grant_id = request.grant_id();
        let grant = self.policy.admit(grant_id, request.class())?;
        let target = request.target_path();
        let ctx = admission_context(
            self.store,
            mode,
            request.class(),
            &grant.scope_root,
            &target,
        )?;
        let scope_root = grant.scope_root.clone();
        // INV-029: pin the write occupant at admit — the same binding the
        // managed control-write path takes — so the execute-time
        // checked-fd write compares against the admit-time snapshot,
        // never a fresh execute-time one.
        let expected_identity = match &request {
            EffectRequest::Write { path, .. } => Some(macos::target_identity(&scope_root, path)?),
            _ => None,
        };
        let decision = self.policy.decide(&target, request.class(), &ctx);
        let attempt_id = self
            .store
            .plan_attempt(task_id, request.class(), &request.describe())?;
        if decision != ModeDecision::Allow {
            self.reject_mode(&attempt_id, decision)?;
        }
        // Single-flight (INV-023): a permitted read joins its identical
        // open flight, keyed by target, snapshot, scope, and rights. A
        // target whose snapshot cannot be observed stays unmerged — one
        // conservative non-merge, never a wrong merge.
        if let Some(flights) = self.flights.as_deref_mut()
            && let EffectRequest::Read { path, .. } = &request
            && let Ok(snapshot) = macos::target_identity(&scope_root, path)
        {
            flights.subscribe(
                ReadFlightKey {
                    target: path.clone(),
                    snapshot: SnapshotBinding(snapshot),
                    scope_root: scope_root.clone(),
                    rights: ReadRights::new(grant_id, mode),
                },
                &attempt_id,
            );
        }
        Ok(AdmittedEffect {
            task_id: task_id.clone(),
            attempt_id,
            request,
            mode,
            expected_identity,
            scope_root,
        })
    }

    /// Preview-only submission (AC-089 dry-run): consults the mode matrix
    /// with the caller's decision context, journals the intent as a
    /// rejected attempt carrying [`DRY_RUN_REASON`], and performs no worker
    /// effect in every mode. The grant gate is not modeled here — a real
    /// submission re-checks the grant and can fail before the verdict —
    /// so the returned verdict names the matrix answer, not the full
    /// admission outcome. `dry_run` is forced on here so a caller cannot
    /// mislabel a live submission.
    pub fn submit_preview(
        &mut self,
        task_id: &TaskId,
        request: EffectRequest,
        ctx: &AdmissionContext,
    ) -> Result<ModeDecision, ExecutorError> {
        let mut ctx = ctx.clone();
        ctx.dry_run = true;
        let target = request.target_path();
        let decision = self.policy.decide(&target, request.class(), &ctx);
        let attempt_id = self
            .store
            .plan_attempt(task_id, request.class(), &request.describe())?;
        self.store.attempt_rejected(&attempt_id, DRY_RUN_REASON)?;
        Ok(decision)
    }

    /// Admits an explicit control write against the current scoped grant.
    pub fn admit_managed_write(
        &mut self,
        task_id: &TaskId,
        request: EffectRequest,
    ) -> Result<AdmittedManagedWrite, ExecutorError> {
        let description = request.describe();
        let (grant_id, path, bytes) = match request {
            EffectRequest::Write {
                grant_id,
                path,
                bytes,
            } => (grant_id, path, bytes),
            request => {
                return Err(ExecutorError::Readonly {
                    class: request.class(),
                });
            }
        };
        // Managed control writes intentionally use EffectClass::Read on a
        // read-only grant: the admit signature stays pinned, and the
        // control-plane authorization stays Policy::admit plus the
        // Policy::covers re-check at finalize — control writes are not
        // agent effects routed through the permission-mode matrix.
        let scope_root = self
            .policy
            .admit(&grant_id, EffectClass::Read)?
            .scope_root
            .clone();
        let expected_identity = macos::target_identity(&scope_root, &path)?;
        let attempt_id = self
            .store
            .plan_attempt(task_id, EffectClass::Write, &description)?;
        Ok(AdmittedManagedWrite {
            task_id: task_id.clone(),
            attempt_id,
            grant_id,
            scope_root,
            path,
            bytes,
            expected_identity,
        })
    }

    /// Re-checks grant, cancellation, and deny before opening; only occupant
    /// identity is checked on the opened fd before mutation.
    pub fn execute_managed_write(
        &mut self,
        admitted: &AdmittedManagedWrite,
    ) -> Result<(), ExecutorError> {
        let scope_root =
            self.admit_settled(&admitted.attempt_id, &admitted.grant_id, EffectClass::Read)?;
        if scope_root != admitted.scope_root {
            self.store
                .attempt_rejected(&admitted.attempt_id, "grant changed")?;
            return Err(ExecutorError::PolicyDenied);
        }
        if self.store.task_cancelled(&admitted.task_id)? {
            self.store
                .attempt_rejected(&admitted.attempt_id, TASK_CANCELLED)?;
            return Err(ExecutorError::Cancelled);
        }
        if self.policy.covers(&admitted.path) {
            self.store
                .attempt_rejected(&admitted.attempt_id, "policy deny")?;
            return Err(ExecutorError::PolicyDenied);
        }
        self.store.attempt_running(&admitted.attempt_id)?;
        match self.worker.write_once(
            &admitted.scope_root,
            &admitted.path,
            admitted.expected_identity,
            &admitted.bytes,
        ) {
            Ok(()) => {}
            Err(error) => {
                let detail = error.to_string();
                match &error {
                    WorkerError::WriteMutationFailed { .. } => {
                        self.store.attempt_unknown(&admitted.attempt_id, &detail)?
                    }
                    _ => self.store.attempt_rejected(&admitted.attempt_id, &detail)?,
                }
                return Err(ExecutorError::Worker(error));
            }
        }
        self.store.attempt_confirmed(&admitted.attempt_id)?;
        Ok(())
    }

    /// Grant re-check immediately before the effect: a failed
    /// admission — a revoked or unknown grant among the causes —
    /// settles the attempt rejected with the error's reason first —
    /// the ledger never keeps a failed gate planned forever — and
    /// then propagates the typed error. Returns the still-admitted
    /// grant's scope root for the callers that re-check it.
    fn admit_settled(
        &mut self,
        attempt_id: &str,
        grant_id: &str,
        class: EffectClass,
    ) -> Result<PathBuf, ExecutorError> {
        match self.policy.admit(grant_id, class) {
            Ok(grant) => Ok(grant.scope_root.clone()),
            Err(error) => {
                let error = ExecutorError::Policy(error);
                let detail = error.to_string();
                self.store.attempt_rejected(attempt_id, &detail)?;
                Err(error)
            }
        }
    }

    /// Re-consult of the decision context immediately before the effect,
    /// under the admitted mode and the request's own class — an egress
    /// reconsult therefore hits the class-routed URL deny consult instead
    /// of the filesystem fail-closed. A context-assembly failure settles
    /// the attempt rejected with the error's reason first — the ledger
    /// never keeps a failed consult planned forever — and then propagates
    /// the typed error.
    fn reconsult_context(
        &mut self,
        admitted: &AdmittedEffect,
        target: &Path,
    ) -> Result<AdmissionContext, ExecutorError> {
        match admission_context(
            self.store,
            admitted.mode,
            admitted.request.class(),
            &admitted.scope_root,
            target,
        ) {
            Ok(ctx) => Ok(ctx),
            Err(error) => {
                let detail = error.to_string();
                self.store.attempt_rejected(&admitted.attempt_id, &detail)?;
                Err(error)
            }
        }
    }

    /// Reject tail shared by the mode gates: the ledger reason is
    /// recorded before the typed error leaves the executor.
    fn reject_mode(
        &mut self,
        attempt_id: &str,
        decision: ModeDecision,
    ) -> Result<(), ExecutorError> {
        let error = match decision {
            ModeDecision::Ask => ExecutorError::ModeAsk,
            ModeDecision::Deny => ExecutorError::ModeDenied,
            ModeDecision::Allow => unreachable!("internal error: allow is not a rejection"),
        };
        self.store
            .attempt_rejected(attempt_id, mode_reason(decision))?;
        Err(error)
    }

    /// Fail-closed mode consult immediately before the effect: a verdict
    /// that is not a clear allow — a deny enrolled after admission among
    /// them — blocks the effect before the worker runs anything. Ask and
    /// deny never reach the worker.
    fn mode_gate(&mut self, admitted: &AdmittedEffect, target: &Path) -> Result<(), ExecutorError> {
        let ctx = self.reconsult_context(admitted, target)?;
        let decision = self.policy.decide(target, admitted.request.class(), &ctx);
        if decision != ModeDecision::Allow {
            self.reject_mode(&admitted.attempt_id, decision)?;
        }
        Ok(())
    }

    /// The shared observation of one read member's flight, when the
    /// one physical read already happened (INV-023).
    fn take_shared_observation(&mut self, attempt_id: &str) -> Option<ReadObservation> {
        self.flights
            .as_deref_mut()
            .and_then(|flights| flights.take_shared(attempt_id))
    }

    /// Leaves the read flight without an observation: a member denied
    /// or cancelled at execute time no longer claims the shared read;
    /// the remaining members keep theirs.
    fn abandon_flight(&mut self, attempt_id: &str) {
        if let Some(flights) = self.flights.as_deref_mut() {
            flights.drop_member(attempt_id);
        }
    }
    /// One read member's observation (INV-023): the shared observation
    /// when the flight's single physical read already happened, else
    /// the one physical read that settles the flight for the remaining
    /// members.
    fn read_member(
        &mut self,
        admitted: &AdmittedEffect,
        path: &Path,
    ) -> Result<ReadObservation, WorkerError> {
        if let Some(observation) = self.take_shared_observation(&admitted.attempt_id) {
            return Ok(observation);
        }
        let observation = self.worker.read_once(&admitted.scope_root, path)?;
        if let Some(flights) = self.flights.as_deref_mut() {
            flights.settle(&admitted.attempt_id, observation.clone());
        }
        Ok(observation)
    }

    /// Mutable admission immediately before the effect: the grant is
    /// re-checked, cancellation settles the attempt, and the mode verdict
    /// is re-consulted under the admitted mode (an enrolled deny added
    /// after admission included). An Allow cell of any effect class then
    /// reaches the confined worker; anything out of scope is denied by
    /// the OS boundary the worker runs under, never by a pre-worker class
    /// bypass. Ask and deny verdicts fail closed at the gates above.
    pub fn execute(&mut self, admitted: &AdmittedEffect) -> Result<EffectOutcome, ExecutorError> {
        let grant_id = admitted.request.grant_id();
        if let Err(error) =
            self.admit_settled(&admitted.attempt_id, grant_id, admitted.request.class())
        {
            self.abandon_flight(&admitted.attempt_id);
            return Err(error);
        }
        if self.store.task_cancelled(&admitted.task_id)? {
            self.store
                .attempt_rejected(&admitted.attempt_id, TASK_CANCELLED)?;
            self.abandon_flight(&admitted.attempt_id);
            return Err(ExecutorError::Cancelled);
        }
        // Mutable mode consult before the worker runs anything.
        let target = admitted.request.target_path();
        if let Err(error) = self.mode_gate(admitted, &target) {
            self.abandon_flight(&admitted.attempt_id);
            return Err(error);
        }
        // Single-flight (INV-023): a read member denied at any
        // execute-time gate leaves its flight without an observation;
        // the remaining members keep their own claim on the physical
        // read, so verdicts and cancels stay per-member.
        self.store.attempt_running(&admitted.attempt_id)?;
        let effect = match &admitted.request {
            EffectRequest::Read { path, .. } => {
                // Single-flight (INV-023): a member of a settled flight
                // takes the shared observation instead of charging its
                // own physical read; the first member to execute
                // performs the one read and settles the flight.
                self.read_member(admitted, path).map(read_result)
            }
            EffectRequest::Write { path, bytes, .. } => admitted
                .expected_identity
                // A write without an admit-time binding (a forged
                // admission) denies closed rather than guess the
                // occupant (INV-029).
                .ok_or_else(|| WorkerError::TargetChanged {
                    target: path.clone(),
                })
                .and_then(|expected| {
                    self.worker
                        .write_once(&admitted.scope_root, path, expected, bytes)
                })
                .map(|()| {
                    let detail = format!(
                        "write-performed sha256={}",
                        hex(&sha2::Sha256::digest(bytes))
                    );
                    (
                        EffectOutcome::Executed {
                            detail: detail.clone(),
                        },
                        detail,
                    )
                }),
            EffectRequest::Exec { program, .. } => self
                .worker
                .exec_once(&admitted.scope_root, program)
                .map(|()| {
                    let detail = "exec-performed exit=ok".to_string();
                    (
                        EffectOutcome::Executed {
                            detail: detail.clone(),
                        },
                        detail,
                    )
                }),
            EffectRequest::Egress { url, .. } => self.worker.egress_once(url).map(|()| {
                (
                    EffectOutcome::Executed {
                        detail: format!("egress-performed {url}"),
                    },
                    format!("egress-performed {url}"),
                )
            }),
        };
        match effect {
            Ok((outcome, detail)) => {
                self.store
                    .set_attempt_state(&admitted.attempt_id, "confirmed", Some(&detail))?;
                Ok(outcome)
            }
            Err(error) => {
                self.abandon_flight(&admitted.attempt_id);
                let detail = error.to_string();
                match &error {
                    WorkerError::WriteMutationFailed { .. } => {
                        self.store.attempt_unknown(&admitted.attempt_id, &detail)?
                    }
                    _ => self.store.attempt_rejected(&admitted.attempt_id, &detail)?,
                }
                Err(ExecutorError::Worker(error))
            }
        }
    }

    /// Performs the admitted read effect and deliberately loses the
    /// confirmation: the durable record ends `unknown`, modeling a process
    /// death after the effect committed but before the receipt landed. The
    /// real worker read happens exactly once and is marked in the ledger.
    pub fn execute_unconfirmed(
        &mut self,
        admitted: &AdmittedEffect,
    ) -> Result<ReadObservation, ExecutorError> {
        if admitted.request.class() != EffectClass::Read {
            return Err(ExecutorError::Readonly {
                class: admitted.request.class(),
            });
        }
        let grant_id = match &admitted.request {
            EffectRequest::Read { grant_id, .. } => grant_id.clone(),
            _ => unreachable!("read class checked above"),
        };
        if let Err(error) = self.admit_settled(&admitted.attempt_id, &grant_id, EffectClass::Read) {
            self.abandon_flight(&admitted.attempt_id);
            return Err(error);
        }
        if self.store.task_cancelled(&admitted.task_id)? {
            self.store
                .attempt_rejected(&admitted.attempt_id, TASK_CANCELLED)?;
            self.abandon_flight(&admitted.attempt_id);
            return Err(ExecutorError::Cancelled);
        }
        let EffectRequest::Read { path, .. } = &admitted.request else {
            unreachable!("read class checked above")
        };
        // Same mutable mode consult as `execute`: the crash emulation must
        // not read past a verdict that stopped being a clear allow.
        if let Err(error) = self.mode_gate(admitted, path) {
            self.abandon_flight(&admitted.attempt_id);
            return Err(error);
        }
        self.store.attempt_running(&admitted.attempt_id)?;
        // Single-flight (INV-023): the crash emulation keeps one
        // physical charge — it takes a settled flight's shared
        // observation, and its own physical read settles the flight for
        // the remaining members.
        let observation = self.read_member(admitted, path)?;
        self.store.set_attempt_state(
            &admitted.attempt_id,
            "unknown",
            Some(&format!(
                "read-performed sha256={}; receipt lost after dispatch",
                observation.digest
            )),
        )?;
        Ok(observation)
    }
}

/// The effect backend this build runs: the Linux Landlock/seccomp/netns
/// worker on Linux, Seatbelt on every other target.
pub fn backend() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        linux::BACKEND
    }
    #[cfg(not(target_os = "linux"))]
    {
        macos::BACKEND
    }
}

#[cfg(test)]
mod tests {
    use super::{ObservedChild, WorkerError, helper_launch_init_failed, require_helper_file};
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    use std::process::ExitStatus;

    fn exited(code: i32) -> ExitStatus {
        ExitStatus::from_raw(code << 8)
    }

    #[test]
    fn a_missing_helper_path_is_sandbox_unavailable() {
        let result = require_helper_file(PathBuf::from("/no/such/rivect-sandbox-helper"));
        assert!(
            matches!(result, Err(WorkerError::SandboxUnavailable { .. })),
            "missing helper must surface SandboxUnavailable, got {result:?}"
        );
    }

    #[test]
    fn setpriv_exec_denied_is_not_helper_init_failure() {
        let observed = ObservedChild {
            status: exited(126),
            stdout: Vec::new(),
            stderr:
                b"setpriv: failed to execute /tmp/rivect-denied-exec/denied-exec: Permission denied"
                    .to_vec(),
        };
        assert!(
            helper_launch_init_failed(&observed).is_none(),
            "Landlock-denied setpriv 126 must stay a confined-run outcome"
        );
    }

    #[test]
    fn helper_prefixed_launch_exec_is_init_failure() {
        let observed = ObservedChild {
            status: exited(126),
            stdout: Vec::new(),
            stderr: b"rivect-sandbox-helper: exec failed: No such file or directory".to_vec(),
        };
        assert!(
            matches!(
                helper_launch_init_failed(&observed),
                Some(WorkerError::SandboxSpawnFailed { .. })
            ),
            "helper-prefixed 126 is launcher init failure"
        );
    }

    #[test]
    fn helper_prefix_must_be_a_full_line() {
        let observed = ObservedChild {
            status: exited(10),
            stdout: Vec::new(),
            stderr: b"confined-program said rivect-sandbox-helper: spoof\n".to_vec(),
        };
        assert!(
            helper_launch_init_failed(&observed).is_none(),
            "a substring that is not a full-line prefix must not spoof helper init"
        );
    }
}
