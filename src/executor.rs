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
    AdmissionContext, ModeDecision, PermissionMode, Policy, PolicyError, canonical_egress_target,
    preapproval_scope,
};
use crate::resources::{
    ReadFlightKey, ReadFlights, ReadRights, ResourceError, ResourceHolder, SnapshotBinding,
    capability_generations,
};
use crate::state::{StoreError, TaskStore};
use sha2::Digest as _;
use std::convert::Infallible;
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
#[cfg(any(test, target_os = "macos"))]
use std::process::{ChildStderr, ChildStdout};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

pub use macos::{
    FileIdentity, ReadObservation, ReadWorker, Unattested, WorkerError, WriteIdentity,
};

/// A private native directory and one artifact borrowed from it.
///
/// Keep this owner until it is transferred to a [`PreparedLaunch`]. Merely
/// copying its borrowed path does not transfer cleanup or launch authority.
#[derive(Debug)]
pub struct OwnedArtifact {
    directory: tempfile::TempDir,
    path: PathBuf,
    identity: FileIdentity,
    deadline: Instant,
}

impl OwnedArtifact {
    fn create(prefix: &str, name: &str) -> Result<Self, WorkerError> {
        Self::create_with_context(prefix, name, Instant::now() + CONFINED_DEADLINE, None)
    }

    fn create_with_context(
        prefix: &str,
        name: &str,
        deadline: Instant,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Self, WorkerError> {
        #[cfg(target_os = "linux")]
        match cancel {
            Some(cancel) => rivect_sandbox_helper::protect_owned_request(deadline, cancel),
            None => rivect_sandbox_helper::protect_owned_direct(deadline),
        }
        .map_err(|source| WorkerError::OwnedParent { source })?;
        #[cfg(not(target_os = "linux"))]
        return Err(WorkerError::OwnedReleaseUnavailable);
        let directory = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir()
            .map_err(|source| WorkerError::OwnedPreparation {
                boundary: "owned.prepare.create",
                source,
            })?;
        let metadata = std::fs::symlink_metadata(directory.path()).map_err(|source| {
            WorkerError::OwnedPreparation {
                boundary: "owned.prepare.identity",
                source,
            }
        })?;
        let path = directory.path().join(name);
        Ok(Self {
            directory,
            path,
            identity: FileIdentity::from_metadata(&metadata),
            deadline,
        })
    }

    /// Borrows the artifact path without detaching its native owner.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for OwnedArtifact {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

impl std::ops::Deref for OwnedArtifact {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.path()
    }
}

/// The resource disposition established by the owning observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnedDisposition {
    NeverExposed,
    Released,
    Unproven,
}

/// A bounded payload result after authenticated namespace teardown.
#[derive(Debug)]
pub struct OwnedOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub disposition: OwnedDisposition,
    stdout_capture: BoundedCapture,
    stderr_capture: BoundedCapture,
}

/// Original launch facts and any distinct root-local release failure.
#[derive(Debug, thiserror::Error)]
pub enum OwnedLaunchError {
    #[error("owned helper failed at {}: {}; {source}; {}", fault.boundary(), owned_helper_diagnostic(fault).0, owned_helper_diagnostic(fault).1)]
    Helper {
        fault: rivect_sandbox_helper::OwnedFault,
        secondary: Option<rivect_sandbox_helper::OwnedFault>,
        #[source]
        source: std::io::Error,
    },
    #[error("owned control protocol failed: {source}")]
    Protocol {
        #[source]
        source: rivect_sandbox_helper::OwnedProtocolError,
    },
    #[error("owned launch observation failed at {boundary}: {source}")]
    Observation {
        boundary: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("owned waiter ended abnormally: {status}")]
    Waiter { status: ExitStatus },
    #[error("owned launch release is unproven: {primary}")]
    Unproven {
        #[source]
        primary: Box<WorkerError>,
        release: Option<Box<WorkerError>>,
        locators: Vec<PathBuf>,
        /// Frozen identities in the same order as `locators`.
        expected_identities: Vec<FileIdentity>,
        stop: Option<rivect_sandbox_helper::OwnedStop>,
    },
    #[error("owned launch failed and release also failed: {primary}; {secondary}")]
    Release {
        #[source]
        primary: Box<WorkerError>,
        secondary: Box<WorkerError>,
    },
    #[error("owned payload resources could not be closed: {release}")]
    OutputRelease {
        output: Option<Box<OwnedOutput>>,
        terminal: Option<rivect_sandbox_helper::OwnedRecord>,
        #[source]
        release: Box<WorkerError>,
        stop: Option<rivect_sandbox_helper::OwnedStop>,
    },
    #[error("owned directory identity changed at {}", locator.display())]
    Identity {
        locator: PathBuf,
        expected: FileIdentity,
        observed: Option<FileIdentity>,
        #[source]
        source: Option<std::io::Error>,
    },
    #[error("owned directory close failed at {}: {source}", locator.display())]
    Close {
        locator: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

fn owned_helper_diagnostic(
    fault: &rivect_sandbox_helper::OwnedFault,
) -> (&'static str, &'static str) {
    use rivect_sandbox_helper::OwnedFaultCause;
    match (fault.boundary(), fault.cause()) {
        (
            "owned.namespace.user",
            OwnedFaultCause::Io {
                operation: 3,
                field: 0,
                ..
            },
        ) => (
            "linux user namespace unavailable (unshare --user)",
            linux::LINUX_USERNS_RECOVERY,
        ),
        (
            "owned.child.spawn",
            OwnedFaultCause::Io {
                operation: 25,
                field: 0,
                ..
            },
        ) => (
            "the sandbox launcher could not be started",
            "recovery: fix the environment or run on a capable kernel",
        ),
        _ => (
            "sandbox mechanism unavailable",
            "recovery: fix the environment or run on a capable kernel",
        ),
    }
}

fn owned_error(source: OwnedLaunchError) -> WorkerError {
    WorkerError::OwnedLaunch {
        source: Box::new(source),
    }
}

fn owned_observation(boundary: &'static str, source: std::io::Error) -> WorkerError {
    owned_error(OwnedLaunchError::Observation { boundary, source })
}

/// The refusal for a capability transition the launch cannot complete: no
/// child starts under a generation that never became current (AC-015).
fn capability_error(boundary: &'static str, source: ResourceError) -> WorkerError {
    WorkerError::OwnedPreparation {
        boundary,
        source: std::io::Error::other(source),
    }
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "the five grace predicate facts are one reviewed launch state"
)]
#[cfg(target_os = "linux")]
struct GraceFacts {
    has_entry: bool,
    has_terminal: bool,
    pending_empty: bool,
    waiter_success: bool,
    release_clear: bool,
}

/// A finished entry and terminal with a successful waiter are the launch
/// result. Grace expiry must not discard them when no further frame is buffered.
#[cfg(target_os = "linux")]
fn grace_keeps_transcript(facts: GraceFacts) -> bool {
    facts.has_entry
        && facts.has_terminal
        && facts.pending_empty
        && facts.waiter_success
        && facts.release_clear
}

/// A helper deadline is the caller's wall timeout, not a predicate failure.
#[cfg(target_os = "linux")]
fn owned_helper_fault(
    fault: rivect_sandbox_helper::OwnedFault,
    secondary: Option<rivect_sandbox_helper::OwnedFault>,
) -> WorkerError {
    if matches!(
        fault.cause(),
        rivect_sandbox_helper::OwnedFaultCause::Deadline
    ) {
        return WorkerError::ConfinedRunTimedOut;
    }
    let source = match fault.cause() {
        rivect_sandbox_helper::OwnedFaultCause::Io { errno, .. } => {
            std::io::Error::from_raw_os_error(errno)
        }
        _ => std::io::Error::other("owned helper predicate failed"),
    };
    owned_error(OwnedLaunchError::Helper {
        fault,
        secondary,
        source,
    })
}

/// The executor name every launch registers its capability generation under.
pub const LAUNCH_EXECUTOR: &str = "rivect-executor";

/// The one-segment resource scope every launch's generation root is named by:
/// one unpredictable name per process, so a root a dead process left behind
/// can never refuse a launch here, and a number is never reissued.
static LAUNCH_RESOURCE_SCOPE: LazyLock<String> =
    LazyLock::new(|| format!("rivect-launch-{}", TaskId::generate().0));

/// The resource scope this process's launches acquire their generations under.
#[must_use]
pub fn launch_resource_scope() -> &'static str {
    &LAUNCH_RESOURCE_SCOPE
}

/// A payload and its native artifacts, consumed by exactly one bounded run.
/// Payload setters cannot mutate the trusted helper envelope or detach a child.
///
/// ```
/// use rivect::executor::{OwnedDisposition, OwnedLaunchError, PreparedLaunch, WorkerError};
/// use std::process::Stdio;
/// let artifact = match rivect::executor::linux::denied_exec_control() {
///     Ok(artifact) => artifact,
///     Err(WorkerError::OwnedReleaseUnavailable) => {
///         // Artifact exposure currently has a typed refusal outside Linux.
///         assert!(!cfg!(target_os = "linux"));
///         return Ok(());
///     }
///     Err(error) => return Err(error),
/// };
/// assert!(artifact.path().is_absolute()); // Borrow before transferring the owner.
/// let mut launch = PreparedLaunch::direct("/bin/true");
/// launch.artifact_arg(artifact);
/// launch.env_clear().stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
/// assert_eq!(launch.get_program(), "/bin/true");
/// assert_eq!(launch.get_args().count(), 1);
/// match launch.run(&[]) {
///     Ok(output) => {
///         assert_eq!(output.disposition, OwnedDisposition::Released);
///         assert!(output.status.success()); // The payload's original status.
///     }
///     Err(error @ WorkerError::OwnedLaunch { .. }) => match &error {
///         WorkerError::OwnedLaunch { source } => match source.as_ref() {
///             OwnedLaunchError::Unproven { primary, release, locators, expected_identities, .. } => {
///                 assert!(!locators.is_empty());
///                 assert_eq!(locators.len(), expected_identities.len());
///                 let _retained_diagnostics = (primary, release, locators, expected_identities);
///                 // These locators remain owned by the unresolved native run.
///             }
///             OwnedLaunchError::Observation { boundary, source }
///                 if *boundary == "owned.prepare.create"
///                     && source.kind() == std::io::ErrorKind::NotFound => {
///                 // A rustdoc executable may have no installed helper beside it.
///                 assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
///             }
///             _ => return Err(error),
///         },
///         _ => unreachable!(),
///     },
///     Err(error) => return Err(error),
/// }
/// # Ok::<(), WorkerError>(())
/// ```
#[derive(Debug)]
pub struct PreparedLaunch {
    payload: Command,
    inherit_env: bool,
    stdin: Option<Stdio>,
    stdout: Option<Stdio>,
    stderr: Option<Stdio>,
    artifacts: Vec<OwnedArtifact>,
    filters: Vec<usize>,
    deadline: Instant,
    profile: rivect_sandbox_helper::OwnedProfile,
    capability: Option<CapabilityHold>,
}

/// One launch's capability generation: prepared before the launch creates its
/// first owned artifact and published once its child starts.
///
/// Publishing empties the hold. Every other end of the launch — a refused
/// prepare, a failed artifact, a spawn that never happened — releases the
/// generation through the process-wide registry, so such a launch publishes
/// nothing and leaves no owned root behind (AC-015).
#[derive(Debug)]
struct CapabilityHold {
    prepared: Option<ResourceHolder>,
}

impl CapabilityHold {
    /// Publishes the held generation now that the child started. A generation
    /// a newer launch already published is not this child's to replace: the
    /// registry keeps that registration current and the refused draft releases
    /// the roots it acquired.
    fn publish(&mut self) {
        let Some(prepared) = self.prepared.take() else {
            return;
        };
        capability_generations().publish_started(prepared);
    }
}

impl Drop for CapabilityHold {
    fn drop(&mut self) {
        let Some(prepared) = self.prepared.take() else {
            return;
        };
        // The launch never published: the registry retires the number and
        // releases every root the prepare acquired. A release it could not
        // prove is not reportable from a drop — the launch has already ended.
        let _ = capability_generations().abandon(prepared);
    }
}

impl PreparedLaunch {
    /// Prepares one direct payload with the fixed finite worker bound.
    #[must_use]
    pub fn direct(program: impl AsRef<std::ffi::OsStr>) -> Self {
        Self::new(program, rivect_sandbox_helper::OwnedProfile::Worker)
    }

    fn new(
        program: impl AsRef<std::ffi::OsStr>,
        profile: rivect_sandbox_helper::OwnedProfile,
    ) -> Self {
        let duration = if profile == rivect_sandbox_helper::OwnedProfile::Check {
            CHECK_PHASE_DEADLINE
        } else {
            CONFINED_DEADLINE
        };
        Self {
            payload: Command::new(program),
            inherit_env: true,
            stdin: None,
            stdout: None,
            stderr: None,
            artifacts: Vec::new(),
            filters: Vec::new(),
            deadline: Instant::now() + duration,
            profile,
            capability: None,
        }
    }

    /// Prepares this launch's capability generation through the process-wide
    /// registry, before the launch acquires its first owned artifact. A launch
    /// that already prepared one keeps it, so one launch publishes exactly one
    /// generation.
    ///
    /// # Errors
    /// Returns [`WorkerError::OwnedPreparation`] when the generation root
    /// cannot be acquired; the launch then starts no child.
    fn prepare_capability(&mut self) -> Result<(), WorkerError> {
        if self.capability.is_some() {
            return Ok(());
        }
        let prepared = capability_generations()
            .prepare(
                &std::env::temp_dir(),
                LAUNCH_EXECUTOR,
                launch_resource_scope(),
                &[],
            )
            .map_err(|error| capability_error("capability.prepare", error))?;
        self.capability = Some(CapabilityHold {
            prepared: Some(prepared),
        });
        Ok(())
    }

    /// Publishes this launch's prepared generation now that its child started.
    fn publish_capability(&mut self) {
        if let Some(hold) = self.capability.as_mut() {
            hold.publish();
        }
    }

    pub fn arg(&mut self, arg: impl AsRef<std::ffi::OsStr>) -> &mut Self {
        self.payload.arg(arg);
        self
    }
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.payload.args(args);
        self
    }
    pub fn env(
        &mut self,
        key: impl AsRef<std::ffi::OsStr>,
        value: impl AsRef<std::ffi::OsStr>,
    ) -> &mut Self {
        self.payload.env(key, value);
        self
    }
    pub fn env_clear(&mut self) -> &mut Self {
        self.payload.env_clear();
        self.inherit_env = false;
        self
    }
    pub fn current_dir(&mut self, path: impl AsRef<Path>) -> &mut Self {
        self.payload.current_dir(path);
        self
    }
    pub fn stdin(&mut self, value: Stdio) -> &mut Self {
        self.stdin = Some(value);
        self
    }
    pub fn stdout(&mut self, value: Stdio) -> &mut Self {
        self.stdout = Some(value);
        self
    }
    pub fn stderr(&mut self, value: Stdio) -> &mut Self {
        self.stderr = Some(value);
        self
    }
    #[must_use]
    pub fn get_program(&self) -> &std::ffi::OsStr {
        self.payload.get_program()
    }
    pub fn get_args(&self) -> std::process::CommandArgs<'_> {
        self.payload.get_args()
    }

    /// Transfers artifact custody and appends its borrowed path to the payload.
    pub fn artifact_arg(&mut self, artifact: OwnedArtifact) -> &mut Self {
        self.deadline = self.deadline.min(artifact.deadline);
        self.payload.arg(artifact.path());
        self.artifacts.push(artifact);
        self
    }

    fn filter_arg(&mut self) -> &mut Self {
        self.filters.push(self.payload.get_args().count());
        self.payload.arg("");
        self
    }

    /// Consumes one direct run under the bound fixed before preparation.
    ///
    /// # Errors
    /// Returns the original preparation, protocol, observation, or release failure.
    pub fn run(self, payload: &[u8]) -> Result<OwnedOutput, WorkerError> {
        let deadline = self.deadline;
        let bounds = ObserveBounds {
            deadline,
            stdout_cap: READ_MAX_CAP,
            stop: |_| None::<Infallible>,
            stdin_close_ends_payload: false,
        };
        match self.run_owned(payload, None, bounds, &|never| match *never {})? {
            OwnedObserve::Exited(output) => Ok(output),
            OwnedObserve::Stopped(never) => match never {},
        }
    }

    /// Consumes one check run with its actual cancellation owner.
    ///
    /// # Errors
    /// Returns the original failure with retained resource disposition.
    pub fn run_check(
        self,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<OwnedOutput, WorkerError> {
        use std::sync::atomic::Ordering;
        let deadline = self.deadline;
        let predicate = || cancel.load(Ordering::Acquire);
        let bounds = ObserveBounds {
            deadline,
            stdout_cap: READ_MAX_CAP,
            stop: |_| if predicate() { Some(()) } else { None },
            stdin_close_ends_payload: false,
        };
        match self.run_owned(&[], Some(&predicate), bounds, &|()| {
            rivect_sandbox_helper::OwnedStop::Cancelled
        })? {
            OwnedObserve::Exited(output) => Ok(output),
            OwnedObserve::Stopped(()) => Err(owned_observation(
                "owned.protocol.terminal",
                std::io::Error::other("owned check was cancelled"),
            )),
        }
    }

    #[cfg(target_os = "macos")]
    fn spawn_legacy(mut self) -> Result<Child, WorkerError> {
        if !self.artifacts.is_empty() || !self.filters.is_empty() {
            return Err(WorkerError::OwnedReleaseUnavailable);
        }
        self.payload.process_group(0);
        if let Some(value) = self.stdin.take() {
            self.payload.stdin(value);
        }
        if let Some(value) = self.stdout.take() {
            self.payload.stdout(value);
        }
        if let Some(value) = self.stderr.take() {
            self.payload.stderr(value);
        }
        let child = self
            .payload
            .spawn()
            .map_err(|source| spawn_failed(&self.payload, source))?;
        // The child is running: the generation this launch prepared becomes the
        // published one, and a refused spawn never reaches here.
        self.publish_capability();
        Ok(child)
    }

    #[cfg(target_os = "macos")]
    fn run_owned<S>(
        mut self,
        payload: &[u8],
        _cancel: Option<&dyn Fn() -> bool>,
        mut bounds: ObserveBounds<impl FnMut(usize) -> Option<S>>,
        _stop_kind: &dyn Fn(&S) -> rivect_sandbox_helper::OwnedStop,
    ) -> Result<OwnedObserve<S>, WorkerError> {
        bounds.deadline = bounds.deadline.min(self.deadline);
        self.prepare_capability()?;
        let mut child = self.spawn_legacy()?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        match observe_bounded(&mut child, stdin, payload, stdout, stderr, bounds)? {
            ObserveOutcome::Stopped(reason) => Ok(OwnedObserve::Stopped(reason)),
            ObserveOutcome::Exited(observed) => {
                let mut stdout_capture = BoundedCapture::empty();
                let mut stderr_capture = BoundedCapture::empty();
                stdout_capture.extend(&observed.stdout);
                stderr_capture.extend(&observed.stderr);
                Ok(OwnedObserve::Exited(OwnedOutput {
                    status: observed.status,
                    stdout: observed.stdout,
                    stderr: observed.stderr,
                    disposition: OwnedDisposition::Unproven,
                    stdout_capture,
                    stderr_capture,
                }))
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn run_owned<S>(
        mut self,
        mut payload: &[u8],
        cancel: Option<&dyn Fn() -> bool>,
        mut bounds: ObserveBounds<impl FnMut(usize) -> Option<S>>,
        stop_kind: &dyn Fn(&S) -> rivect_sandbox_helper::OwnedStop,
    ) -> Result<OwnedObserve<S>, WorkerError> {
        use rivect_sandbox_helper::{OwnedRecord, OwnedSequence, OwnedStop};
        use std::os::fd::AsRawFd as _;
        use std::os::unix::net::UnixStream;
        let deadline = self.deadline.min(bounds.deadline);
        let protect = || {
            match cancel {
                Some(cancel) => rivect_sandbox_helper::protect_owned_request(deadline, cancel),
                None => rivect_sandbox_helper::protect_owned_direct(deadline),
            }
            .map_err(|source| WorkerError::OwnedParent { source })
        };
        protect()?;
        // The generation is prepared before the first owned artifact, under the
        // parent protection the artifacts themselves need.
        self.prepare_capability()?;
        // Deferred native allocation sees the original cancellation and deadline.
        let mut args: Vec<std::ffi::OsString> = self
            .payload
            .get_args()
            .map(std::ffi::OsStr::to_os_string)
            .collect();
        for position in &self.filters {
            protect()?;
            let artifact = linux::net_deny_filter_file_with_context(deadline, cancel)?;
            args[*position] = artifact.path().as_os_str().to_os_string();
            self.artifacts.push(artifact);
        }
        protect()?;
        self.artifacts.push(OwnedArtifact::create_with_context(
            "rivect-launch-",
            "payload",
            deadline,
            cancel,
        )?);
        let trusted = rivect_sandbox_helper::owned_helper_binary()
            .map_err(|source| owned_observation("owned.prepare.create", source))?;
        protect()?;
        let (mut control, child_control) = UnixStream::pair()
            .map_err(|source| owned_observation("owned.protocol.read", source))?;
        control
            .set_nonblocking(true)
            .map_err(|source| owned_observation("owned.protocol.read", source))?;
        protect()?;
        let now = rivect_sandbox_helper::owned_monotonic_ns()
            .map_err(|source| owned_observation("owned.protocol.entry", source))?;
        let remaining = u64::try_from(
            deadline
                .saturating_duration_since(Instant::now())
                .as_nanos(),
        )
        .map_err(|source| {
            owned_observation("owned.protocol.entry", std::io::Error::other(source))
        })?;
        let absolute = now.checked_add(remaining).ok_or_else(|| {
            owned_observation(
                "owned.protocol.entry",
                std::io::Error::other("owned deadline exceeds monotonic range"),
            )
        })?;
        let mut command = Command::new(&trusted);
        command
            .arg("owned")
            .arg(self.profile.token())
            .arg(child_control.as_raw_fd().to_string())
            .arg(absolute.to_string());
        let mut environment: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> =
            if self.inherit_env {
                std::env::vars_os().collect()
            } else {
                std::collections::BTreeMap::new()
            };
        for (key, value) in self.payload.get_envs() {
            if let Some(value) = value {
                environment.insert(key.to_os_string(), value.to_os_string());
            } else {
                environment.remove(key);
            }
        }
        command.env_clear();
        use std::os::unix::ffi::OsStringExt as _;
        let mut ordinal = 0;
        for (key, value) in environment {
            if key == "RIVECT_OWNED_PARENT_PID" {
                continue;
            }
            let key = key.into_encoded_bytes();
            let mut record = format!("{}:", key.len()).into_bytes();
            record.extend(key);
            record.extend(value.into_encoded_bytes());
            command.env(
                format!("RIVECT_OWNED_ENV_{ordinal}"),
                std::ffi::OsString::from_vec(record),
            );
            ordinal += 1;
        }
        command.arg("--");
        // The installed helper's legacy launcher is replaced by this native
        // profile. Explicit alternate helpers remain payloads with their argv.
        if self.payload.get_program() == trusted.as_os_str()
            && args.first().is_some_and(|arg| arg == "launch")
        {
            let start = args.iter().position(|arg| arg == "--").ok_or_else(|| {
                owned_observation(
                    "owned.prepare.create",
                    std::io::Error::other("missing helper payload delimiter"),
                )
            })?;
            command.args(&args[start + 1..]);
        } else {
            command.arg(self.payload.get_program()).args(&args);
        }
        if let Some(path) = self.payload.get_current_dir() {
            command.current_dir(path);
        }
        if let Some(value) = self.stdin.take() {
            command.stdin(value);
        }
        if let Some(value) = self.stdout.take() {
            command.stdout(value);
        }
        if let Some(value) = self.stderr.take() {
            command.stderr(value);
        }
        protect()?;
        for artifact in &mut self.artifacts {
            artifact.directory.disable_cleanup(true);
        }
        let spawned =
            rivect_sandbox_helper::spawn_owned_control(command, &child_control, deadline, cancel);
        drop(child_control);
        let mut child = match spawned {
            Ok(child) => child,
            Err(source) => {
                for artifact in &mut self.artifacts {
                    artifact.directory.disable_cleanup(false);
                }
                return Err(parent_spawn_error(source));
            }
        };
        // The child is running: the generation this launch prepared becomes the
        // published one, and a launch that never reached here published nothing.
        self.publish_capability();
        // Acquisition precedes every potentially blocking startup observation.
        let pidfd = rivect_sandbox_helper::owned_waiter_pidfd(child.id());
        let mut primary = None;
        let pidfd = match pidfd {
            Ok(fd) => Some(fd),
            Err(source) => {
                primary = Some(owned_observation("owned.release.waiter", source));
                None
            }
        };
        let mut stdin = child.stdin.take();
        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();
        for fd in stdin
            .as_ref()
            .map(AsFd::as_fd)
            .into_iter()
            .chain(stdout.as_ref().map(AsFd::as_fd))
            .chain(stderr.as_ref().map(AsFd::as_fd))
        {
            if let Err(source) = rivect_sandbox_helper::set_nonblocking(fd)
                && primary.is_none()
            {
                primary = Some(owned_observation("owned.protocol.read", source));
            }
        }
        let mut sequence = OwnedSequence::default();
        let mut pending = Vec::with_capacity(256);
        let mut eof = false;
        let mut waiter = None;
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let mut stdout_capture = BoundedCapture::empty();
        let mut stderr_capture = BoundedCapture::empty();
        let mut scratch = [0; 8192];
        let mut reason = None;
        let mut requested = None;
        let mut stop_sent = false;
        let mut emergency_sent = false;
        let mut release = None;
        let mut kept_transcript = false;
        loop {
            if primary.is_none() && requested.is_none() {
                if let Some(stop) = (bounds.stop)(stdout_buf.len()) {
                    requested = Some(stop_kind(&stop));
                    reason = Some(stop);
                } else if Instant::now() >= deadline {
                    requested = Some(OwnedStop::Deadline);
                }
            }
            if !eof {
                let mut bytes = [0; 257];
                match control.read(&mut bytes) {
                    Ok(0) => {
                        eof = true;
                        if !pending.is_empty() {
                            sequence.lost();
                            if primary.is_none() {
                                primary = Some(owned_error(OwnedLaunchError::Protocol {
                                    source: rivect_sandbox_helper::OwnedProtocolError::Malformed,
                                }));
                            }
                        }
                    }
                    Ok(count) => {
                        pending.extend_from_slice(&bytes[..count]);
                        while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                            let frame: Vec<_> = pending.drain(..=end).collect();
                            let parsed = rivect_sandbox_helper::parse_owned_record(&frame).and_then(|record| {
                                if let OwnedRecord::Entry { profile, baseline, nproc, verified } = record {
                                    let expected = if profile == rivect_sandbox_helper::OwnedProfile::Check {
                                        u64::from(baseline).checked_add(rivect_sandbox_helper::CHECK_NPROC_HEADROOM)
                                    } else { Some(64) };
                                    if profile != self.profile || verified != 63 || baseline == 0
                                        || expected != Some(u64::from(nproc)) {
                                        return Err(rivect_sandbox_helper::OwnedProtocolError::Malformed);
                                    }
                                }
                                sequence.push(record)
                            });
                            if let Err(source) = parsed {
                                sequence.lost();
                                if primary.is_none() {
                                    primary =
                                        Some(owned_error(OwnedLaunchError::Protocol { source }));
                                }
                            }
                        }
                        if pending.len() > 128 {
                            sequence.lost();
                            pending.clear();
                            if primary.is_none() {
                                primary = Some(owned_error(OwnedLaunchError::Protocol {
                                    source: rivect_sandbox_helper::OwnedProtocolError::Oversize,
                                }));
                            }
                        }
                    }
                    Err(source) if source.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(source) => {
                        sequence.lost();
                        eof = true;
                        if primary.is_none() {
                            primary = Some(owned_observation("owned.protocol.read", source));
                        }
                    }
                }
            }
            if let Some(WorkerError::OwnedLaunch { source }) = primary.as_mut()
                && let OwnedLaunchError::Helper { secondary, .. } = source.as_mut()
            {
                *secondary = sequence.secondary();
            }
            if primary.is_none()
                && let Some(fault) = sequence.primary()
            {
                primary = Some(owned_helper_fault(fault, sequence.secondary()));
            }
            if primary.is_none() && requested.is_none() {
                let io = write_stdin_nonblocking(
                    &mut stdin,
                    &mut payload,
                    bounds.stdin_close_ends_payload,
                )
                .and_then(|()| {
                    owned_drain(
                        &mut stdout,
                        &mut stdout_buf,
                        &mut stdout_capture,
                        &mut scratch,
                        bounds.stdout_cap,
                    )
                })
                .and_then(|()| {
                    owned_drain(
                        &mut stderr,
                        &mut stderr_buf,
                        &mut stderr_capture,
                        &mut scratch,
                        STDERR_RETAIN_BYTES,
                    )
                });
                if let Err(error) = io {
                    sequence.lost();
                    primary = Some(error);
                }
            } else {
                stdin = None;
                for result in [
                    owned_drain(
                        &mut stdout,
                        &mut stdout_buf,
                        &mut stdout_capture,
                        &mut scratch,
                        bounds.stdout_cap,
                    ),
                    owned_drain(
                        &mut stderr,
                        &mut stderr_buf,
                        &mut stderr_capture,
                        &mut scratch,
                        STDERR_RETAIN_BYTES,
                    ),
                ] {
                    if let Err(error) = result {
                        sequence.lost();
                        if release.is_none() {
                            release = Some(error);
                        }
                    }
                }
            }
            if (primary.is_some() || requested.is_some()) && waiter.is_none() {
                if sequence.entry().is_some() && sequence.terminal().is_none() && !stop_sent {
                    stop_sent = true;
                    let stop = requested.unwrap_or(OwnedStop::Observation);
                    let frame = format!("owned-launch-v1 stop {}\n", stop.token());
                    match control.write(frame.as_bytes()) {
                        Ok(count) if count == frame.len() => {}
                        Ok(_) => {
                            sequence.lost();
                            release = Some(owned_observation(
                                "owned.protocol.terminal",
                                std::io::Error::other("short owned stop write"),
                            ));
                        }
                        Err(source) => {
                            sequence.lost();
                            release = Some(owned_observation("owned.protocol.terminal", source));
                        }
                    }
                }
                let known_fault = sequence.primary().is_some() && requested.is_none();
                if (!known_fault && !stop_sent && sequence.terminal().is_none()
                    || release.is_some()
                    || Instant::now() >= deadline + Duration::from_millis(500))
                    && !emergency_sent
                {
                    emergency_sent = true;
                    sequence.lost();
                    if let Some(fd) = &pidfd
                        && let Err(source) = rivect_sandbox_helper::kill_owned_waiter(fd.as_fd())
                        && release.is_none()
                    {
                        release = Some(owned_observation("owned.release.waiter", source));
                    }
                }
            }
            if waiter.is_none() {
                match child.try_wait() {
                    Ok(status) => waiter = status,
                    Err(source) => {
                        sequence.lost();
                        if release.is_none() {
                            release = Some(owned_observation("owned.release.waiter", source));
                        }
                    }
                }
            }
            if waiter.is_some() && eof && stdout.is_none() && stderr.is_none() {
                break;
            }
            if Instant::now() >= deadline + Duration::from_secs(1) {
                // A finished transcript is already the result. Losing it here
                // would turn a completed entry and terminal into a timeout.
                kept_transcript = grace_keeps_transcript(GraceFacts {
                    has_entry: sequence.entry().is_some(),
                    has_terminal: sequence.terminal().is_some(),
                    pending_empty: pending.is_empty(),
                    waiter_success: waiter.is_some_and(|status| status.success()),
                    release_clear: release.is_none(),
                });
                if !kept_transcript {
                    sequence.lost();
                }
                break;
            }
            let readable: Vec<_> = std::iter::once(control.as_fd())
                .chain(stdout.as_ref().map(AsFd::as_fd))
                .chain(stderr.as_ref().map(AsFd::as_fd))
                .collect();
            if let Err(source) =
                rivect_sandbox_helper::wait_ready(&readable, &[], OBSERVE_POLL_SLICE)
            {
                sequence.lost();
                if primary.is_none() {
                    primary = Some(owned_observation("owned.protocol.read", source));
                }
            }
        }
        let released = sequence.released(
            eof || kept_transcript,
            waiter.is_some_and(|status| status.success()),
        ) && release.is_none();
        let primary = owned_release_result(
            OwnedReleaseFacts {
                released,
                stop: requested,
                waiter,
            },
            primary,
            release,
            self.artifacts
                .iter()
                .map(|artifact| artifact.directory.path().to_path_buf())
                .collect(),
            self.artifacts
                .iter()
                .map(|artifact| artifact.identity)
                .collect(),
        )?;
        let mut cleanup = None;
        for artifact in self.artifacts {
            if let Err(error) = artifact.close_verified()
                && cleanup.is_none()
            {
                cleanup = Some(error);
            }
        }
        if let Some(primary) = primary {
            return Err(match cleanup {
                Some(secondary) => owned_error(OwnedLaunchError::Release {
                    primary: Box::new(primary),
                    secondary: Box::new(secondary),
                }),
                None => primary,
            });
        }
        let terminal = sequence.terminal();
        let output = owned_terminal_status(terminal).map(|status| OwnedOutput {
            status,
            stdout: stdout_buf,
            stderr: stderr_buf,
            disposition: OwnedDisposition::Released,
            stdout_capture,
            stderr_capture,
        });
        if let Some(release) = cleanup {
            return Err(owned_error(OwnedLaunchError::OutputRelease {
                output: output.map(Box::new),
                terminal,
                release: Box::new(release),
                stop: requested,
            }));
        }
        if let Some(reason) = reason {
            return Ok(OwnedObserve::Stopped(reason));
        }
        match output {
            Some(output) => Ok(OwnedObserve::Exited(output)),
            None => Err(WorkerError::ConfinedRunTimedOut),
        }
    }
}

#[cfg(target_os = "linux")]
struct OwnedReleaseFacts {
    released: bool,
    stop: Option<rivect_sandbox_helper::OwnedStop>,
    waiter: Option<ExitStatus>,
}

#[cfg(target_os = "linux")]
fn owned_release_result(
    facts: OwnedReleaseFacts,
    primary: Option<WorkerError>,
    release: Option<WorkerError>,
    locators: Vec<PathBuf>,
    expected_identities: Vec<FileIdentity>,
) -> Result<Option<WorkerError>, WorkerError> {
    if !facts.released {
        if facts.stop == Some(rivect_sandbox_helper::OwnedStop::Deadline) && release.is_none() {
            return Err(WorkerError::ConfinedRunTimedOut);
        }
        let primary = primary.unwrap_or_else(|| {
            if let Some(status) = facts.waiter.filter(|status| !status.success()) {
                owned_error(OwnedLaunchError::Waiter { status })
            } else {
                owned_error(OwnedLaunchError::Protocol {
                    source: rivect_sandbox_helper::OwnedProtocolError::Malformed,
                })
            }
        });
        return Err(owned_error(OwnedLaunchError::Unproven {
            primary: Box::new(primary),
            release: release.map(Box::new),
            locators,
            expected_identities,
            stop: facts.stop,
        }));
    }
    Ok(primary)
}

fn owned_terminal_status(
    terminal: Option<rivect_sandbox_helper::OwnedRecord>,
) -> Option<ExitStatus> {
    use rivect_sandbox_helper::OwnedRecord;
    match terminal {
        Some(OwnedRecord::Exit(code)) => Some(ExitStatus::from_raw(i32::from(code) << 8)),
        Some(OwnedRecord::Signal(signal)) => Some(ExitStatus::from_raw(i32::from(signal))),
        _ => None,
    }
}

enum OwnedObserve<S> {
    Exited(OwnedOutput),
    Stopped(S),
}

fn owned_drain<T: Read>(
    pipe: &mut Option<T>,
    retained: &mut Vec<u8>,
    capture: &mut BoundedCapture,
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
        Ok(count) => {
            capture.extend(&scratch[..count]);
            retained.extend_from_slice(&scratch[..count.min(cap.saturating_sub(retained.len()))]);
            Ok(())
        }
        Err(source) if source.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        Err(source) => Err(owned_observation("owned.protocol.read", source)),
    }
}

fn owned_classify<T>(
    result: Result<OwnedOutput, WorkerError>,
    classify: impl FnOnce(ObservedChild) -> Result<T, WorkerError>,
) -> Result<T, WorkerError> {
    match result {
        Ok(output) => classify(observed_owned(output)),
        Err(WorkerError::OwnedLaunch { source }) => match *source {
            OwnedLaunchError::OutputRelease {
                output: Some(output),
                release,
                stop: None,
                ..
            } => match classify(observed_owned(*output)) {
                Ok(_) => Err(*release),
                Err(primary) => Err(owned_error(OwnedLaunchError::Release {
                    primary: Box::new(primary),
                    secondary: release,
                })),
            },
            source => Err(owned_error(source)),
        },
        Err(error) => Err(error),
    }
}

fn owned_observed_stop(error: &WorkerError) -> Option<rivect_sandbox_helper::OwnedStop> {
    match error {
        WorkerError::ConfinedRunTimedOut => Some(rivect_sandbox_helper::OwnedStop::Deadline),
        WorkerError::OwnedLaunch { source } => match source.as_ref() {
            OwnedLaunchError::Unproven { stop, .. }
            | OwnedLaunchError::OutputRelease { stop, .. } => *stop,
            OwnedLaunchError::Release { primary, .. } => owned_observed_stop(primary),
            _ => None,
        },
        _ => None,
    }
}

fn parent_spawn_error(source: std::io::Error) -> WorkerError {
    if source
        .get_ref()
        .is_some_and(|source| source.is::<rivect_sandbox_helper::OwnedParentError>())
    {
        let source = source.into_inner().and_then(|source| {
            source
                .downcast::<rivect_sandbox_helper::OwnedParentError>()
                .ok()
        });
        if let Some(source) = source {
            return WorkerError::OwnedParent { source: *source };
        }
        unreachable!("the checked parent error type must downcast");
    }
    WorkerError::SandboxSpawnFailed { source }
}

impl OwnedArtifact {
    fn close_verified(self) -> Result<(), WorkerError> {
        let locator = self.directory.path().to_path_buf();
        match std::fs::symlink_metadata(&locator) {
            Ok(metadata)
                if metadata.is_dir() && FileIdentity::from_metadata(&metadata) == self.identity => {
            }
            Ok(metadata) => {
                return Err(owned_error(OwnedLaunchError::Identity {
                    locator,
                    expected: self.identity,
                    observed: Some(FileIdentity::from_metadata(&metadata)),
                    source: None,
                }));
            }
            Err(source) => {
                return Err(owned_error(OwnedLaunchError::Identity {
                    locator,
                    expected: self.identity,
                    observed: None,
                    source: Some(source),
                }));
            }
        }
        // TempDir::close wraps and hides the native errno. After verified
        // release, consume its owner and make the single cleanup attempt here.
        let directory = self.directory.keep();
        std::fs::remove_dir_all(directory)
            .map_err(|source| owned_error(OwnedLaunchError::Close { locator, source }))
    }
}

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
            Self::Egress { url, .. } => format!("egress {}", redact_egress_url(url)),
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

    /// The one path field this class carries — the argument the
    /// `effect.request` hook may rewrite (I6). Egress names a URL rather
    /// than a path, so it carries none and no hook rewrites it.
    fn path_field(&mut self) -> Option<&mut PathBuf> {
        match self {
            Self::Read { path, .. } | Self::Write { path, .. } => Some(path),
            Self::Exec { program, .. } => Some(program),
            Self::Egress { .. } => None,
        }
    }
}

/// The hook caps (AC-076, I6): one bounded run, one bounded answer, and no
/// recursion — an answer is never fed back into another hook.
pub const HOOK_TIMEOUT_MS: u64 = 200;
pub const HOOK_STDOUT_MAX_BYTES: usize = 64 * 1024;
pub const HOOK_MAX_DEPTH: usize = 1;

/// The environment a hook inherits: the minimum a program needs to run.
/// Credentials, provider keys and the assistant's own session state stay
/// out of a user program's environment (AGENTS §11G).
const HOOK_ENV_ALLOWLIST: &[&str] = &["PATH", "HOME"];

/// What one answer's `decision` may say (I6). `deny` and `stop` both refuse
/// the request — one hook run has nothing further to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HookDecision {
    Allow,
    Deny,
    Stop,
}

impl HookDecision {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            "stop" => Some(Self::Stop),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Stop => "stop",
        }
    }
}

/// The answer one hook returned: its decision and, when it rewrote them, the
/// request's arguments. Data only — admission re-reads the rewritten path at
/// the same site before any effect happens.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HookAnswer {
    decision: HookDecision,
    path: Option<PathBuf>,
}

/// Failures of one bounded hook run. Every arm is a refusal of the request
/// the hook was asked about: a hook that cannot answer opaquely cannot be
/// taken as consent.
#[derive(Debug, thiserror::Error)]
pub enum HookError {
    #[error("hook {hook} could not start: {source}")]
    Spawn {
        hook: String,
        #[source]
        source: std::io::Error,
    },
    #[error("hook {hook} could not be observed: {source}")]
    Observe {
        hook: String,
        #[source]
        source: std::io::Error,
    },
    #[error("hook {hook} did not answer within {millis} ms")]
    TimedOut { hook: String, millis: u64 },
    #[error("hook {hook} answered more than {limit} bytes")]
    OutputTooLarge { hook: String, limit: usize },
    #[error("hook {hook} answered malformed json: {detail}")]
    Malformed { hook: String, detail: String },
    #[error("hook {hook} answered an unknown decision {decision}")]
    UnknownDecision { hook: String, decision: String },
}

impl HookError {
    /// The wire code this failure reports (P-001): a program that cannot
    /// run or cannot answer in time is a capability failure, while a
    /// well-formed run that answers outside the contract is a denial.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Spawn { .. } | Self::Observe { .. } | Self::TimedOut { .. } => {
                ErrorCode::CapabilityUnavailable
            }
            Self::OutputTooLarge { .. } | Self::Malformed { .. } | Self::UnknownDecision { .. } => {
                ErrorCode::Denied
            }
        }
    }
}

/// The admitted request as the hook left it: which hook answered, the path it
/// saw, and the path it returned.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HookRewrite {
    hook: String,
    original: PathBuf,
    transformed: PathBuf,
}

/// Runs one declared hook over one request path and reads its answer: a
/// separate process, a cleared environment plus an explicit allowlist, the
/// program kept apart from its arguments, one bounded stdout read, and one
/// wall deadline. The request goes to stdin as `{event, scope, args:{path}}`;
/// the answer comes back as `{decision, args:{path}}`.
fn run_hook(entry: &crate::config::HookEntry, path: &Path) -> Result<HookAnswer, HookError> {
    let hook = entry.id();
    let payload = serde_json::json!({
        "event": entry.event,
        "scope": entry.scope,
        "args": { "path": path.to_string_lossy() },
    })
    .to_string()
    .into_bytes();
    let mut command = Command::new(&entry.command);
    command
        .args(&entry.args)
        .env_clear()
        // Its own process group, like every confined child: [`end_hook`]
        // kills the group, so a forked descendant does not outlive the run.
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for name in HOOK_ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command.spawn().map_err(|source| HookError::Spawn {
        hook: hook.clone(),
        source,
    })?;
    let answer = exchange_with_hook(&mut child, &payload, &hook);
    end_hook(&mut child);
    answer
}

/// The one exchange with a started hook: the payload, the deadline, and the
/// capped answer. The request is a few hundred bytes — far below a pipe's
/// capacity — so writing it before the first read cannot deadlock, and the
/// deadline bounds a program that never reads it. The answer is read under
/// that same deadline: a descendant that keeps the write end open is a run
/// past its bound, never a read the parent waits out.
fn exchange_with_hook(
    child: &mut Child,
    payload: &[u8],
    hook: &str,
) -> Result<HookAnswer, HookError> {
    if let Some(mut stdin) = child.stdin.take()
        && let Err(source) = stdin.write_all(payload)
    {
        return Err(HookError::Observe {
            hook: hook.to_string(),
            source,
        });
    }
    let mut pipe = child.stdout.take();
    if let Some(stdout) = pipe.as_ref() {
        rivect_sandbox_helper::set_nonblocking(stdout.as_fd()).map_err(|source| {
            HookError::Observe {
                hook: hook.to_string(),
                source,
            }
        })?;
    }
    let deadline = Instant::now() + Duration::from_millis(HOOK_TIMEOUT_MS);
    let mut raw = Vec::new();
    let mut scratch = [0u8; 8192];
    let mut exited = false;
    loop {
        if let Some(stdout) = pipe.as_mut() {
            // Never one byte past the cap: the refusal below is the cap's
            // verdict, not the buffer's.
            let room = (HOOK_STDOUT_MAX_BYTES + 1 - raw.len()).min(scratch.len());
            match stdout.read(&mut scratch[..room]) {
                Ok(0) => pipe = None,
                Ok(read) => raw.extend_from_slice(&scratch[..read]),
                Err(source)
                    if source.kind() == std::io::ErrorKind::WouldBlock
                        || source.kind() == std::io::ErrorKind::Interrupted => {}
                Err(source) => {
                    return Err(HookError::Observe {
                        hook: hook.to_string(),
                        source,
                    });
                }
            }
        }
        if raw.len() > HOOK_STDOUT_MAX_BYTES {
            return Err(HookError::OutputTooLarge {
                hook: hook.to_string(),
                limit: HOOK_STDOUT_MAX_BYTES,
            });
        }
        if !exited {
            match child.try_wait() {
                Ok(Some(_)) => exited = true,
                Ok(None) => {}
                Err(source) => {
                    return Err(HookError::Observe {
                        hook: hook.to_string(),
                        source,
                    });
                }
            }
        }
        // The run is over only when the program exited and its answer pipe
        // reached EOF; either half alone is what a descendant can fake.
        if exited && pipe.is_none() {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            // [`run_hook`] ends the run after this returns, so the process
            // group is killed and reaped before the refusal is reported:
            // `Child::drop` does neither.
            return Err(HookError::TimedOut {
                hook: hook.to_string(),
                millis: HOOK_TIMEOUT_MS,
            });
        }
        // The idle wait the confined pipeline already uses, on the pipes that
        // can still move: the wait itself is the park, so no thread and no
        // spin. A drained pipe is already `None`.
        let readable: Vec<BorrowedFd<'_>> = pipe.as_ref().map(AsFd::as_fd).into_iter().collect();
        if let Err(source) = rivect_sandbox_helper::wait_ready(
            &readable,
            &[],
            OBSERVE_POLL_SLICE.min(deadline - now),
        ) {
            return Err(HookError::Observe {
                hook: hook.to_string(),
                source,
            });
        }
    }
    parse_hook_answer(hook, &raw)
}

/// The answer one hook's stdout carries, read as data: the contract's two
/// fields are read, everything else the program printed is ignored, so no
/// returned text ever becomes authority.
fn parse_hook_answer(hook: &str, raw: &[u8]) -> Result<HookAnswer, HookError> {
    let text = std::str::from_utf8(raw).map_err(|source| HookError::Malformed {
        hook: hook.to_string(),
        detail: source.to_string(),
    })?;
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|source| HookError::Malformed {
            hook: hook.to_string(),
            detail: source.to_string(),
        })?;
    let Some(decision) = value.get("decision").and_then(serde_json::Value::as_str) else {
        return Err(HookError::Malformed {
            hook: hook.to_string(),
            detail: "missing decision".to_string(),
        });
    };
    let decision = HookDecision::parse(decision).ok_or_else(|| HookError::UnknownDecision {
        hook: hook.to_string(),
        decision: decision.to_string(),
    })?;
    let path = value
        .get("args")
        .and_then(|args| args.get("path"))
        .and_then(serde_json::Value::as_str)
        .map(PathBuf::from);
    Ok(HookAnswer { decision, path })
}

/// Ends one hook run: `Child::drop` neither kills nor reaps, so a program
/// past its bound or past a failed exchange would still be running when the
/// caller hears about the failure. The hook is spawned as its own process
/// group's leader, so the group kill reaches a forked descendant that
/// `Child::kill` cannot. A kill or wait error means the process is already
/// gone, and the caller already reports the cause that ended the run — the
/// same choice [`terminate_confined_child`] records.
fn end_hook(child: &mut Child) {
    drop(rivect_sandbox_helper::kill_process_group(child.id()));
    drop(child.kill());
    drop(child.wait());
}

/// Ledger/UI spelling of an egress URL: userinfo and query are stripped so
/// credentials never persist in `attempts.describe`, confirmed detail,
/// `attempts.detail`, or `WorkerError` Display.
fn redact_egress_url(url: &str) -> String {
    canonical_egress_target(url)
}

/// Describe-path spelling of a sandbox-denied target. UTF-8 URLs follow
/// [`redact_egress_url`]; non-UTF-8 filesystem paths keep their OsStr.
pub(crate) fn denied_target_spelling(target: &Path) -> String {
    target
        .to_str()
        .map(redact_egress_url)
        .unwrap_or_else(|| target.display().to_string())
}

/// [`WorkerError::SandboxDenied`] with the describe-path spelling, so
/// userinfo and query never persist in the variant or its Display string
/// (and therefore never in `attempts.detail`).
pub(crate) fn sandbox_denied(target: impl AsRef<Path>) -> WorkerError {
    let target = target.as_ref();
    WorkerError::SandboxDenied {
        target: match target.to_str() {
            Some(raw) => PathBuf::from(redact_egress_url(raw)),
            None => target.to_path_buf(),
        },
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
    pub expected_identity: Option<WriteIdentity>,
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
    expected_identity: WriteIdentity,
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
    #[error("effect outcome is unknown: {primary}")]
    WorkerUnproven {
        #[source]
        primary: WorkerError,
    },
    #[error("effect settlement failed: {secondary}")]
    WorkerSettlement {
        #[source]
        primary: WorkerError,
        secondary: Box<StoreError>,
    },
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
    /// A run hook could not answer: its program failed to start, overran its
    /// bound, or answered outside the contract. The request is refused,
    /// never taken as if the hook had allowed it.
    #[error("effect denied: {0}")]
    Hook(#[from] HookError),
    /// The hook itself refused the request: `deny` and `stop` both end it
    /// before any admission is planned.
    #[error("effect denied: hook {hook} answered {decision}")]
    HookDenied {
        hook: String,
        decision: &'static str,
    },
    /// The hook rewrote the request's arguments and the admission of the
    /// rewritten request refused it: the re-check runs at the same site the
    /// hook fired before, so a permitted path cannot be steered into a
    /// denied one.
    #[error("effect denied: hook {hook} rewrote {original} to {transformed}")]
    HookTransform {
        hook: String,
        original: String,
        transformed: String,
    },
    #[error("effect store: {0}")]
    Store(#[from] StoreError),
    #[error("effect procedure: {0}")]
    Procedure(#[from] crate::procedure::ProcedureError),
    #[error("confined check failed: {0}")]
    Check(#[from] CheckError),
}

/// The wire code one worker failure carries wherever the family
/// surfaces — the executor's own effect path and the publication path
/// share this single map, so the same failure never answers two codes.
/// A sandbox that cannot start or does not enforce — and a confined
/// run that timed out or died before any verdict — is a capability
/// failure; a post-mutation write failure keeps the unknown outcome
/// its ledger settlement already carries; every other worker denial
/// is a denied effect.
pub(crate) fn worker_error_code(error: &WorkerError) -> ErrorCode {
    match error {
        WorkerError::OwnedLaunch { source } => match source.as_ref() {
            OwnedLaunchError::Release { primary, .. }
            | OwnedLaunchError::Unproven { primary, .. } => worker_error_code(primary),
            _ => ErrorCode::CapabilityUnavailable,
        },
        WorkerError::SandboxSpawnFailed { .. }
        | WorkerError::OwnedPreparation { .. }
        | WorkerError::OwnedParent { .. }
        | WorkerError::OwnedReleaseUnavailable
        | WorkerError::OwnedSeccomp { .. }
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
    }
}

impl ExecutorError {
    /// The canonical bounded helper facts for durable failure retention.
    #[must_use]
    pub fn owned_cause(&self) -> Option<String> {
        fn worker(error: &WorkerError) -> Option<String> {
            match error {
                WorkerError::OwnedLaunch { source } => match source.as_ref() {
                    OwnedLaunchError::Helper {
                        fault, secondary, ..
                    } => {
                        let mut value = fault.encode().ok()?;
                        if let Some(secondary) = secondary {
                            value.push_str(&secondary.encode().ok()?);
                        }
                        Some(value)
                    }
                    OwnedLaunchError::Unproven { primary, .. }
                    | OwnedLaunchError::Release { primary, .. } => worker(primary),
                    _ => None,
                },
                _ => None,
            }
        }
        match self {
            Self::Worker(primary)
            | Self::WorkerSettlement { primary, .. }
            | Self::WorkerUnproven { primary } => worker(primary),
            _ => None,
        }
    }
}

impl ExecutorError {
    /// Wire code for the failed effect path, mapped at one boundary. A
    /// sandbox that cannot start or does not enforce is a capability
    /// failure with a recovery read; a post-mutation write failure
    /// reports its honest unknown outcome; every other denial is a
    /// denied effect, and a store failure keeps its storage code.
    #[must_use = "the code exists to be carried to the wire; discarding it loses the mapping"]
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Worker(worker) => worker_error_code(worker),
            Self::WorkerUnproven { .. } => ErrorCode::OutcomeUnknown,
            Self::Policy(_)
            | Self::PolicyDenied
            | Self::ModeAsk
            | Self::ModeDenied
            | Self::Readonly { .. }
            | Self::HookDenied { .. }
            | Self::HookTransform { .. } => ErrorCode::Denied,
            Self::Hook(error) => error.code(),
            Self::Cancelled => ErrorCode::Cancelled,
            Self::Store(_) | Self::WorkerSettlement { .. } => ErrorCode::StorageUnavailable,
            Self::Procedure(error) => error.code(),
            Self::Check(error) => check_error_code(error),
        }
    }
}

/// Wire code of one check failure: authorization and binding denials are
/// denied effects; missing setups, unsupported capabilities, and phase
/// infrastructure are capability failures with an offline correction;
/// cancellation keeps its own code and retention failures stay storage.
fn check_error_code(error: &CheckError) -> ErrorCode {
    match error {
        CheckError::OwnedLaunch { source, .. } => check_error_code(&source.primary),
        CheckError::ExecGrant { .. }
        | CheckError::ProjectReadGrant { .. }
        | CheckError::DependencyGrant { .. }
        | CheckError::SelectionMismatch { .. }
        | CheckError::TargetLayout { .. }
        | CheckError::DigestMismatch { .. }
        | CheckError::CacheScope { .. }
        | CheckError::CacheRevoked { .. }
        | CheckError::CacheDenied { .. }
        | CheckError::CacheAncestry { .. }
        | CheckError::CacheFdIdentity { .. }
        | CheckError::CacheLinks { .. }
        | CheckError::CacheKind { .. }
        | CheckError::CacheLeaf { .. }
        | CheckError::CacheComponent { .. }
        | CheckError::VendorLockChanged { .. }
        | CheckError::VendorAdmit { .. }
        | CheckError::TestAdmit { .. } => ErrorCode::Denied,
        // Cancellation keeps the wire's own code (exit 130): the phase
        // cancels and the close-time task cancellation (exact equality
        // with the published constant at the one wire boundary, never a
        // substring). Any other close-selection refusal — a stale
        // selection at close — is a denied effect.
        CheckError::TestCancel { .. } | CheckError::VendorCancel { .. } => ErrorCode::Cancelled,
        CheckError::CloseSelection { detail } if detail == TASK_CANCELLED => ErrorCode::Cancelled,
        CheckError::CloseSelection { .. } => ErrorCode::Denied,
        CheckError::EvidenceRetention { .. } => ErrorCode::StorageUnavailable,
        _ => ErrorCode::CapabilityUnavailable,
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

fn executed(detail: String) -> (EffectOutcome, String) {
    (
        EffectOutcome::Executed {
            detail: detail.clone(),
        },
        detail,
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

/// The admitted occupant of one write target: its `(dev, ino)` and the
/// reuse token, both taken from one observation of the canonical target.
/// Linux opens that target once identity-only (`O_PATH`, no read cap)
/// and takes both from the opened fd; macOS takes `(dev, ino)` from the
/// canonical metadata and the volume token from the same path. A
/// filesystem without a reuse discriminator yields an identity marked
/// [`Unattested::Unsupported`], never a guessed token.
///
/// # Errors
/// The target-inspection denials ([`WorkerError::ScopeRootUnavailable`],
/// [`WorkerError::TargetMissing`], [`WorkerError::OutsideScope`],
/// [`WorkerError::MetadataUnavailable`], [`WorkerError::NotRegularFile`]);
/// on Linux [`WorkerError::MetadataUnavailable`] when the identity open
/// or its metadata fails, [`WorkerError::NotRegularFile`] when the opened
/// fd is no regular file and [`WorkerError::TargetChanged`] when it is
/// not the canonical file; and [`WorkerError::WriteIdentityUnavailable`]
/// with the complete facade error for every token failure other than an
/// unsupported filesystem.
pub fn write_target_identity(
    scope_root: &Path,
    target: &Path,
) -> Result<WriteIdentity, WorkerError> {
    let (canonical_target, canonical_meta) = inspect_regular_target(scope_root, target)?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                rivect_sandbox_helper::OPEN_PATH | rivect_sandbox_helper::ANCHOR_O_NOFOLLOW,
            )
            .open(&canonical_target)
            .map_err(|source| WorkerError::MetadataUnavailable { source })?;
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
        let reuse = attested_reuse(rivect_sandbox_helper::reuse_token(&file))?;
        Ok(WriteIdentity::new(
            FileIdentity::from_metadata(&opened_meta),
            reuse,
        ))
    }
    #[cfg(target_os = "macos")]
    {
        let reuse = attested_reuse(rivect_sandbox_helper::reuse_token_at(
            &canonical_target,
            canonical_meta.dev(),
        ))?;
        Ok(WriteIdentity::new(
            FileIdentity::from_metadata(&canonical_meta),
            reuse,
        ))
    }
}

/// Keeps an unsupported filesystem as an explicitly unattested identity;
/// every other facade failure propagates with its complete source.
fn attested_reuse(
    token: Result<rivect_sandbox_helper::ReuseToken, rivect_sandbox_helper::ReuseTokenError>,
) -> Result<Result<rivect_sandbox_helper::ReuseToken, Unattested>, WorkerError> {
    match token {
        Ok(token) => Ok(Ok(token)),
        Err(rivect_sandbox_helper::ReuseTokenError::Unsupported) => {
            Ok(Err(Unattested::Unsupported))
        }
        Err(source) => Err(WorkerError::WriteIdentityUnavailable { source }),
    }
}

/// Post-open occupant check of every write path: the opened handle must
/// still be the canonical regular file, still carry the admitted
/// `(dev, ino)` and still carry the admitted reuse token, or the write
/// denies before any byte moves. `(dev, ino)` alone can name a later file
/// reusing the pair, so an identity without a token never authorizes a
/// write, and neither does a live handle whose token cannot be taken.
fn confirm_write_occupant(
    target: &Path,
    canonical_meta: &Metadata,
    file: &File,
    expected: WriteIdentity,
) -> Result<(), WorkerError> {
    let opened_meta = file
        .metadata()
        .map_err(|source| WorkerError::MetadataUnavailable { source })?;
    if !same_regular_file(canonical_meta, &opened_meta)
        || FileIdentity::from_metadata(&opened_meta) != expected.file()
    {
        return Err(WorkerError::TargetChanged {
            target: target.to_path_buf(),
        });
    }
    let admitted = expected
        .reuse()
        .map_err(|cause| WorkerError::WriteIdentityUnattested { cause })?;
    let current = rivect_sandbox_helper::reuse_token(file)
        .map_err(|source| WorkerError::WriteIdentityUnavailable { source })?;
    if current != admitted {
        return Err(WorkerError::TargetChanged {
            target: target.to_path_buf(),
        });
    }
    Ok(())
}

/// Post-open occupant check shared by both backends' read legs: the
/// opened handle must still be a regular file, still the canonical
/// identity, and still under the read cap. The `is_file` check stays
/// ahead of [`same_regular_file`] so a swapped non-file is
/// [`WorkerError::NotRegularFile`], not [`WorkerError::TargetChanged`].
fn confirm_opened_regular(
    target: &Path,
    canonical_meta: &Metadata,
    file: &File,
) -> Result<(), WorkerError> {
    let opened_meta = file
        .metadata()
        .map_err(|source| WorkerError::MetadataUnavailable { source })?;
    if !opened_meta.is_file() {
        return Err(WorkerError::NotRegularFile {
            target: target.to_path_buf(),
        });
    }
    if !same_regular_file(canonical_meta, &opened_meta) {
        return Err(WorkerError::TargetChanged {
            target: target.to_path_buf(),
        });
    }
    if opened_meta.len() > macos::READ_MAX_BYTES as u64 {
        return Err(WorkerError::TooLarge);
    }
    Ok(())
}

fn read_observation_from(
    platform: &str,
    profile: &str,
    file: File,
) -> Result<ReadObservation, WorkerError> {
    let bounded = helper_confined_read(platform, profile, file)?;
    if bounded.len() > macos::READ_MAX_BYTES {
        return Err(WorkerError::TooLarge);
    }
    let digest = hex(&sha2::Sha256::digest(&bounded));
    Ok(ReadObservation {
        bytes: bounded,
        digest,
    })
}

fn canonical_scope(scope_root: &Path, unicode_reason: &str) -> Result<PathBuf, WorkerError> {
    let canonical = scope_root
        .canonicalize()
        .map_err(|source| WorkerError::ScopeRootUnavailable { source })?;
    if canonical.to_str().is_none() {
        return Err(WorkerError::SandboxUnavailable {
            reason: unicode_reason.to_string(),
        });
    }
    Ok(canonical)
}

fn expect_admitted(exit_ok: bool, target: &Path) -> Result<(), WorkerError> {
    if exit_ok {
        Ok(())
    } else {
        Err(sandbox_denied(target))
    }
}

fn expect_denied(exit_ok: bool, reason: &str) -> Result<(), WorkerError> {
    if exit_ok {
        Err(WorkerError::SandboxUnavailable {
            reason: reason.to_string(),
        })
    } else {
        Ok(())
    }
}

/// Denied-first / admitted-leg / fail-closed flow both backends share.
/// The caller owns cache lookup and insert; failed probes must not be
/// cached. `admitted_fail_reason` receives the confined stderr so Linux
/// can embed an excerpt while macOS keeps a fixed string.
fn probe_read_conformance_legs(
    target: &Path,
    denied_target: &str,
    denied_admitted_reason: &str,
    denied_unreadable_reason: &str,
    mut run: impl FnMut(&Path) -> Result<(bool, String), WorkerError>,
    admitted_fail_reason: impl FnOnce(&str) -> String,
) -> Result<(), WorkerError> {
    let canonical_target = target
        .canonicalize()
        .map_err(|_source| WorkerError::TargetMissing {
            target: target.to_path_buf(),
        })?;
    let (denied_ok, _) = run(Path::new(denied_target))?;
    expect_denied(denied_ok, denied_admitted_reason)?;
    if File::open(denied_target).is_err() {
        return Err(WorkerError::SandboxUnavailable {
            reason: denied_unreadable_reason.to_string(),
        });
    }
    match run(&canonical_target) {
        Ok((true, _)) => Ok(()),
        Ok((false, stderr)) => {
            File::open(&canonical_target).map_err(|source| WorkerError::ReadFailed { source })?;
            Err(WorkerError::SandboxUnavailable {
                reason: admitted_fail_reason(&stderr),
            })
        }
        Err(error) => Err(error),
    }
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

fn observed_owned(output: OwnedOutput) -> ObservedChild {
    ObservedChild {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

pub(crate) struct ObservedChild {
    pub status: ExitStatus,
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
    if !path.is_file() {
        return Err(WorkerError::SandboxUnavailable {
            reason: format!("confined helper is not a file: {}", path.display()),
        });
    }
    // A file with no execute bit fails execve with EACCES. Refuse it before
    // the owned launcher so that errno stays on the helper-unavailable chain.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(metadata) = std::fs::metadata(&path)
            && metadata.permissions().mode() & 0o111 == 0
        {
            return Err(WorkerError::SandboxSpawnFailed {
                source: std::io::Error::from_raw_os_error(13),
            });
        }
    }
    Ok(path)
}

fn configure_confined_command(command: &mut Command) {
    command.process_group(0).env_clear();
}

pub(crate) fn helper_launch_command() -> Result<PreparedLaunch, WorkerError> {
    let mut command =
        PreparedLaunch::new(helper_path()?, rivect_sandbox_helper::OwnedProfile::Worker);
    command.arg("launch").arg("--");
    command.env_clear();
    Ok(command)
}

/// `helper launch --resource-profile check --`: unlike
/// [`helper_launch_command`] the first `--` lands after the check
/// profile option, so the launched chain starts right after it.
pub(crate) fn helper_check_launch_command() -> Result<PreparedLaunch, WorkerError> {
    let mut command =
        PreparedLaunch::new(helper_path()?, rivect_sandbox_helper::OwnedProfile::Check);
    command
        .arg("launch")
        .arg(rivect_sandbox_helper::RESOURCE_PROFILE_FLAG)
        .arg(rivect_sandbox_helper::RESOURCE_PROFILE_CHECK)
        .arg("--");
    command.env_clear();
    Ok(command)
}

/// The argv — exactly this one argument — that runs `rivect` as the
/// index worker.
pub const INDEX_WORKER_FLAG: &str = "--index-worker";

/// The only environment the worker runs with, forwarded when set in the
/// parent: exactly the keys `ignore` reads for global git excludes, so
/// the isolated walk filters as the in-process one does (DEC-033 S6).
pub(crate) const WORKER_ENV_ALLOWLIST: [&str; 4] = [
    "HOME",
    "XDG_CONFIG_HOME",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
];

/// `helper launch --memory-budget <INDEX_WORKER_MEMORY_BUDGET> -- <program>
/// --index-worker`, all three stdio piped. The environment is cleared and
/// then carries only the allowlisted keys the parent has set — the ones
/// the worker's ignore walk reads, so global git excludes resolve as
/// they would in-process.
fn index_worker_command(helper: PathBuf, program: &Path) -> PreparedLaunch {
    let mut command = PreparedLaunch::new(helper, rivect_sandbox_helper::OwnedProfile::Index);
    command
        .arg("launch")
        .arg(rivect_sandbox_helper::MEMORY_BUDGET_FLAG)
        .arg(rivect_sandbox_helper::INDEX_WORKER_MEMORY_BUDGET.to_string())
        .arg("--")
        .arg(program)
        .arg(INDEX_WORKER_FLAG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.env_clear();
    for key in WORKER_ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
}

/// Why an index-worker run produced no observation of its own. Each
/// variant keeps the failure typed by the seam it came from: a launch
/// refusal the worker's own [`WorkerError`], a failed observation the
/// [`std::io::Error`] that read produced.
#[derive(Debug, thiserror::Error)]
pub(crate) enum IndexRunError {
    /// The helper is not a file, or `Command::spawn` refused it.
    #[error("index worker launch unavailable")]
    Unavailable {
        #[source]
        source: WorkerError,
        worker_payload: bool,
    },
    /// The wall deadline passed; the process group was killed and the
    /// leader reaped.
    #[error("index worker ran past its deadline")]
    #[cfg(target_os = "macos")]
    TimedOut,
    /// The worker's physical footprint crossed its memory budget; the
    /// process group was killed and the leader reaped. Only macOS polls
    /// it — Linux's fixed address-space cap bounds the worker itself.
    #[cfg(target_os = "macos")]
    #[error("index worker exceeded its memory budget")]
    MemoryExceeded,
    /// Observing the running worker failed; it was killed and reaped.
    #[error("index worker observation failed")]
    #[cfg(target_os = "macos")]
    Observe {
        #[source]
        source: std::io::Error,
    },
}

/// Runs one capped index worker to its end: writes `request` to its
/// stdin, keeps at most `bounds.stdout_cap` stdout bytes, and stops it
/// when `bounds.stop` asks, when its footprint crosses the memory budget
/// (macOS) or when the deadline passes. The caller classifies what the
/// worker answered; nothing here falls back in-process.
pub(crate) fn run_index_worker<S>(
    helper: &Path,
    program: &Path,
    request: &[u8],
    original_deadline: Instant,
    cancel: &dyn Fn() -> bool,
    bounds: ObserveBounds<impl FnMut(usize) -> Option<S>>,
    stop_kind: &dyn Fn(&S) -> rivect_sandbox_helper::OwnedStop,
) -> Result<ObserveOutcome<S>, IndexRunError> {
    let helper =
        require_helper_file(helper.to_path_buf()).map_err(|source| IndexRunError::Unavailable {
            source,
            worker_payload: false,
        })?;
    #[cfg(target_os = "linux")]
    let worker_payload =
        rivect_sandbox_helper::owned_helper_binary().is_ok_and(|trusted| trusted == helper);
    let mut command = index_worker_command(helper, program);
    command.deadline = original_deadline;
    #[cfg(target_os = "macos")]
    {
        let mut child = command
            .spawn_legacy()
            .map_err(|source| IndexRunError::Unavailable {
                source,
                worker_payload: false,
            })?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let leader = child.id();
        let ObserveBounds {
            deadline,
            stdout_cap,
            mut stop,
            stdin_close_ends_payload,
        } = bounds;
        let bounds = ObserveBounds {
            deadline,
            stdout_cap,
            stdin_close_ends_payload,
            stop: move |retained| match stop(retained) {
                Some(reason) => Some(Ok(reason)),
                None => footprint_stop(leader).map(Err),
            },
        };
        return match observe_bounded(&mut child, stdin, request, stdout, stderr, bounds) {
            Ok(ObserveOutcome::Exited(output)) => Ok(ObserveOutcome::Exited(output)),
            Ok(ObserveOutcome::Stopped(Ok(reason))) => Ok(ObserveOutcome::Stopped(reason)),
            Ok(ObserveOutcome::Stopped(Err(error))) => Err(error),
            Err(WorkerError::ConfinedRunTimedOut) => Err(IndexRunError::TimedOut),
            Err(WorkerError::ConfinedRunKilled { source }) => {
                Err(IndexRunError::Observe { source })
            }
            Err(source) => Err(IndexRunError::Unavailable {
                source,
                worker_payload: false,
            }),
        };
    }
    #[cfg(target_os = "linux")]
    match command.run_owned(request, Some(cancel), bounds, stop_kind) {
        Ok(OwnedObserve::Exited(output)) => Ok(ObserveOutcome::Exited(observed_owned(output))),
        Ok(OwnedObserve::Stopped(reason)) => Ok(ObserveOutcome::Stopped(reason)),
        Err(source) => Err(IndexRunError::Unavailable {
            source,
            worker_payload,
        }),
    }
}

impl IndexRunError {
    pub(crate) fn worker_exec_errno(&self) -> Option<i32> {
        fn delivered(error: &WorkerError) -> Option<i32> {
            let WorkerError::OwnedLaunch { source } = error else {
                return None;
            };
            match source.as_ref() {
                OwnedLaunchError::Unproven { primary, .. }
                | OwnedLaunchError::Release { primary, .. } => delivered(primary),
                OwnedLaunchError::Helper { fault, source, .. }
                    if fault.boundary() == "owned.child.spawn" =>
                {
                    match fault.cause() {
                        rivect_sandbox_helper::OwnedFaultCause::Io {
                            operation: 25,
                            field: 0,
                            errno,
                        } if source.raw_os_error() == Some(errno) => Some(errno),
                        _ => None,
                    }
                }
                _ => None,
            }
        }
        match self {
            Self::Unavailable {
                source,
                worker_payload: true,
            } => delivered(source),
            Self::Unavailable { .. } => None,
            #[cfg(target_os = "macos")]
            _ => None,
        }
    }

    pub(crate) fn request_stop(&self) -> Option<rivect_sandbox_helper::OwnedStop> {
        match self {
            Self::Unavailable {
                source: WorkerError::OwnedParent { source },
                ..
            } => source.request_stop(),
            _ => None,
        }
    }
    pub(crate) fn observed_stop(&self) -> Option<rivect_sandbox_helper::OwnedStop> {
        match self {
            Self::Unavailable { source, .. } => owned_observed_stop(source),
            #[cfg(target_os = "macos")]
            _ => None,
        }
    }

    pub(crate) fn observation_lost(&self) -> bool {
        fn lost(error: &WorkerError) -> bool {
            match error {
                WorkerError::OwnedLaunch { source } => match source.as_ref() {
                    OwnedLaunchError::Unproven { primary, .. } => lost(primary),
                    OwnedLaunchError::Helper { .. } => false,
                    _ => true,
                },
                WorkerError::ConfinedRunKilled { .. } => true,
                _ => false,
            }
        }
        matches!(self, Self::Unavailable { source, .. } if lost(source))
    }
}

/// The index worker's memory stop on macOS, where the relative
/// RLIMIT_AS/DATA the helper sets bounds only large allocations and
/// small heap blocks grow past it (DEC-038). It reads the unreaped
/// leader — an exited one reads zero, so its own exit still decides.
/// A footprint that cannot be read stops the run too: an unmeasured
/// worker is never taken as under budget.
#[cfg(target_os = "macos")]
fn footprint_stop(leader: u32) -> Option<IndexRunError> {
    match rivect_sandbox_helper::phys_footprint(leader) {
        Ok(bytes) if bytes > rivect_sandbox_helper::INDEX_WORKER_MEMORY_BUDGET => {
            Some(IndexRunError::MemoryExceeded)
        }
        Ok(_) => None,
        Err(source) => Some(IndexRunError::Observe { source }),
    }
}

/// Linux data-plane helper: Landlock is inside the binary; the parent
/// supplies the same `unshare --user --map-current-user --net` /
/// `setpriv --nnp --seccomp-filter`
/// chain `run_confined` uses, with `--` before the helper so a path
/// named like an option cannot be parsed as a launcher flag.
#[cfg(target_os = "linux")]
fn linux_wrapped_helper() -> Result<PreparedLaunch, WorkerError> {
    let helper = helper_path()?;
    let mut command = helper_launch_command()?;
    command
        .arg(linux::UNSHARE)
        .arg("--user")
        .arg("--map-current-user")
        .arg("--net")
        .arg("--")
        .arg(linux::SETPRIV)
        .arg("--nnp")
        .arg("--seccomp-filter")
        .filter_arg()
        .arg("--")
        .arg(&helper);
    Ok(command)
}

/// Data-plane confined helper: Linux is `helper launch -- unshare --user
/// --map-current-user --net --
/// setpriv --nnp --seccomp-filter -- helper confined`; macOS is `helper
/// confined` with in-helper `sandbox_init`.
///
/// # Errors
/// Returns [`WorkerError::SandboxSpawnFailed`] when the helper binary
/// cannot be resolved, and [`WorkerError::SandboxUnavailable`] when the
/// helper is not a file or (on Linux) the seccomp net-deny filter cannot
/// be prepared.
pub fn helper_confined_command(
    platform: &str,
    mode: &str,
    profile: &str,
) -> Result<PreparedLaunch, WorkerError> {
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
        let mut command =
            PreparedLaunch::new(helper_path()?, rivect_sandbox_helper::OwnedProfile::Worker);
        command.arg("confined").arg(platform).arg(mode);
        if !profile.is_empty() {
            command.arg(profile);
        }
        command.env_clear();
        Ok(command)
    }
}

/// A `Command::spawn` refusal names the attempted program in its
/// diagnostic: the bare OS error ("no such file") says nothing about
/// which sandbox launcher could not start.
#[derive(Debug, thiserror::Error)]
#[error("spawn of {} failed: {source}", program.display())]
#[cfg(any(test, target_os = "macos"))]
struct SpawnFailure {
    program: PathBuf,
    #[source]
    source: std::io::Error,
}

#[cfg(any(test, target_os = "macos"))]
fn spawn_failed(command: &Command, source: std::io::Error) -> WorkerError {
    WorkerError::SandboxSpawnFailed {
        source: std::io::Error::new(
            source.kind(),
            SpawnFailure {
                program: command.get_program().into(),
                source,
            },
        ),
    }
}

#[cfg(any(test, target_os = "macos"))]
fn pipe_nonblocking(fd: impl AsFd) -> Result<(), WorkerError> {
    rivect_sandbox_helper::set_nonblocking(fd)
        .map_err(|source| WorkerError::SandboxSpawnFailed { source })
}

fn write_stdin_nonblocking(
    stdin: &mut Option<ChildStdin>,
    payload: &mut &[u8],
    close_ends_payload: bool,
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
        Err(err) if close_ends_payload && err.kind() == std::io::ErrorKind::BrokenPipe => {
            *stdin = None;
            Ok(())
        }
        Err(source) => Err(WorkerError::SandboxSpawnFailed { source }),
    }
}

/// The longest idle wait between two observation steps. A child's exit
/// raises no pipe event while its pipes stay open, so this bounds how
/// late an exit, a stop request or the deadline is seen — without the
/// parent burning a core the way a yield spin does.
const OBSERVE_POLL_SLICE: Duration = Duration::from_millis(10);

/// What bounds one observation beside the child's own exit.
pub(crate) struct ObserveBounds<F> {
    /// Past it the process group is killed.
    pub deadline: Instant,
    /// Stdout bytes retained; the rest is read and dropped.
    pub stdout_cap: usize,
    /// Asked with the retained stdout length before every exit check;
    /// `Some` kills the process group and ends the observation.
    pub stop: F,
    /// Whether a child that closes its stdin before taking the whole
    /// payload just ends the payload — its exit then decides — or loses
    /// the observation. A confined write must consume every byte, so
    /// there an early close is a lost run; a launcher that fails before
    /// it execs its program never reads the request at all, and its exit
    /// code is the verdict.
    pub stdin_close_ends_payload: bool,
}

/// How a bounded observation ended: the child exited on its own — a
/// signal death included, for the caller to classify — or the caller's
/// stop ended it after its process group was killed and reaped.
pub(crate) enum ObserveOutcome<S> {
    Exited(ObservedChild),
    Stopped(S),
}

/// Drains a confined child via nonblocking pipes, a `poll` idle wait,
/// and a wall deadline that kills the child: [`CONFINED_DEADLINE`],
/// stdout retained up to [`READ_MAX_CAP`], no early stop. A signal death
/// is [`WorkerError::ConfinedRunKilled`].
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn observe_confined_child(
    child: &mut Child,
    stdin: Option<ChildStdin>,
    payload: &[u8],
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
) -> Result<ObservedChild, WorkerError> {
    let bounds = ObserveBounds {
        deadline: Instant::now() + CONFINED_DEADLINE,
        stdout_cap: READ_MAX_CAP,
        stop: |_retained: usize| None::<Infallible>,
        stdin_close_ends_payload: false,
    };
    match observe_bounded(child, stdin, payload, stdout, stderr, bounds)? {
        // A signal ended the run before it produced a verdict: the spawn
        // already succeeded, so this is a capability anomaly — never a
        // launch failure the synthesized exit code used to fabricate,
        // and never an enforcement denial.
        ObserveOutcome::Exited(observed) if observed.status.code().is_none() => {
            Err(confined_run_killed(&observed.status))
        }
        ObserveOutcome::Exited(observed) => Ok(observed),
        ObserveOutcome::Stopped(never) => match never {},
    }
}

/// Observes a child under `bounds`. Any failure inside the observation
/// loop — pipe setup, payload write, drains, the idle wait, `try_wait` —
/// kills the process group and reaps the leader before returning:
/// `Child::drop` does neither, so an unobserved child must never outlive
/// its failed observation. The spawn already succeeded, so such a
/// failure is a mid-run loss reported as [`WorkerError::ConfinedRunKilled`],
/// never "the launcher could not be started".
#[cfg(any(test, target_os = "macos"))]
fn observe_bounded<S>(
    child: &mut Child,
    stdin: Option<ChildStdin>,
    payload: &[u8],
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    bounds: ObserveBounds<impl FnMut(usize) -> Option<S>>,
) -> Result<ObserveOutcome<S>, WorkerError> {
    match observe_bounded_io(child, stdin, payload, stdout, stderr, bounds) {
        Ok(observed) => Ok(observed),
        Err(error) => {
            // Terminal verdicts are exactly the paths that no longer
            // need terminate: the pre-exit timeout arm already ran
            // terminate_confined_child, and post-reap outcomes — a
            // killed run, a timed-out or failed post-exit drain — only
            // exist after the leader was reaped and its process group
            // killed. killpg keys on the leader pid; once it is reaped
            // and freed it can be recycled as another process group
            // leader, so a second killpg could signal an unrelated
            // group. Every pre-reap failure still needs the terminate.
            if !matches!(
                error,
                WorkerError::ConfinedRunTimedOut | WorkerError::ConfinedRunKilled { .. }
            ) {
                terminate_confined_child(child);
            }
            Err(match error {
                WorkerError::SandboxSpawnFailed { source } => {
                    WorkerError::ConfinedRunKilled { source }
                }
                other => other,
            })
        }
    }
}

#[cfg(any(test, target_os = "macos"))]
fn observe_bounded_io<S>(
    child: &mut Child,
    mut stdin: Option<ChildStdin>,
    mut payload: &[u8],
    mut stdout: Option<ChildStdout>,
    mut stderr: Option<ChildStderr>,
    mut bounds: ObserveBounds<impl FnMut(usize) -> Option<S>>,
) -> Result<ObserveOutcome<S>, WorkerError> {
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
    let deadline = bounds.deadline;
    loop {
        write_stdin_nonblocking(&mut stdin, &mut payload, bounds.stdin_close_ends_payload)?;
        drain_nonblocking_pipe(
            &mut stdout,
            &mut stdout_buf,
            &mut scratch,
            bounds.stdout_cap,
        )?;
        drain_nonblocking_pipe(
            &mut stderr,
            &mut stderr_buf,
            &mut scratch,
            STDERR_RETAIN_BYTES,
        )?;
        // The caller's own stop is decided before the exit check, so a
        // kill it causes is never read back as the child's signal death.
        if let Some(reason) = (bounds.stop)(stdout_buf.len()) {
            terminate_confined_child(child);
            return Ok(ObserveOutcome::Stopped(reason));
        }
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
                    bounds.stdout_cap,
                    deadline,
                )?;
                drain_pipe_to_eof(
                    &mut stderr,
                    &mut stderr_buf,
                    &mut scratch,
                    STDERR_RETAIN_BYTES,
                    deadline,
                )?;
                return Ok(ObserveOutcome::Exited(ObservedChild {
                    status,
                    stdout: stdout_buf,
                    stderr: stderr_buf,
                }));
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    terminate_confined_child(child);
                    return Err(WorkerError::ConfinedRunTimedOut);
                }
                // Drained and hung-up pipes are already `None`, so only
                // live fds wake the wait.
                let readable: Vec<BorrowedFd<'_>> = stdout
                    .as_ref()
                    .map(AsFd::as_fd)
                    .into_iter()
                    .chain(stderr.as_ref().map(AsFd::as_fd))
                    .collect();
                let writable: Vec<BorrowedFd<'_>> = stdin
                    .as_ref()
                    .filter(|_| !payload.is_empty())
                    .map(AsFd::as_fd)
                    .into_iter()
                    .collect();
                rivect_sandbox_helper::wait_ready(&readable, &writable, OBSERVE_POLL_SLICE)
                    .map_err(|source| WorkerError::SandboxSpawnFailed { source })?;
            }
            Err(source) => return Err(WorkerError::SandboxSpawnFailed { source }),
        }
    }
}

const READ_MAX_CAP: usize = (1 << 20) + 1;

#[cfg(any(test, target_os = "macos"))]
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
/// Nothing here terminates again: the leader is already reaped and its
/// group already killed, so a re-fired killpg would key on a freed pid
/// — and a mid-drain loss reports the same [`WorkerError::ConfinedRunKilled`]
/// the outer remap would produce, never a `SandboxSpawnFailed` that
/// escapes the terminate skip. The remap below owns that guarantee, not
/// the helper's current body: only terminal variants leave this loop.
#[cfg(any(test, target_os = "macos"))]
fn drain_pipe_to_eof<T: Read + AsFd>(
    pipe: &mut Option<T>,
    retained: &mut Vec<u8>,
    scratch: &mut [u8],
    cap: usize,
    deadline: Instant,
) -> Result<(), WorkerError> {
    while pipe.is_some() {
        if Instant::now() >= deadline {
            return Err(WorkerError::ConfinedRunTimedOut);
        }
        drain_nonblocking_pipe(pipe, retained, scratch, cap).map_err(|error| match error {
            WorkerError::SandboxSpawnFailed { source } => WorkerError::ConfinedRunKilled { source },
            // Only a terminal verdict may escape a post-reap drain — any
            // other variant re-arms `terminate_confined_child` on the
            // freed leader pgid — so a non-terminal failure folds into
            // the same killed verdict a mid-drain loss reports.
            terminal @ (WorkerError::ConfinedRunTimedOut
            | WorkerError::ConfinedRunKilled { .. }) => terminal,
            other => WorkerError::ConfinedRunKilled {
                source: std::io::Error::other(other.to_string()),
            },
        })?;
        if let Some(reader) = pipe.as_ref() {
            rivect_sandbox_helper::wait_ready(&[reader.as_fd()], &[], OBSERVE_POLL_SLICE)
                .map_err(|source| WorkerError::ConfinedRunKilled { source })?;
        }
    }
    Ok(())
}

#[cfg(any(test, target_os = "macos"))]
fn terminate_confined_child(child: &mut Child) {
    drop(rivect_sandbox_helper::kill_process_group(child.id()));
    drop(child.kill());
    drop(child.wait());
}

/// A signal ended the confined run before it produced a verdict — the
/// spawn already succeeded, so this is never "the launcher could not
/// be started". The signal is the honest cause; a status with neither
/// an exit code nor a signal keeps its raw debug form.
fn confined_run_killed(status: &ExitStatus) -> WorkerError {
    WorkerError::ConfinedRunKilled {
        source: std::io::Error::other(match status.signal() {
            Some(signal) => format!("signal {signal}"),
            None => format!("{status:?}"),
        }),
    }
}

/// The child's exit code, or the killed verdict when a signal ended the
/// run before any code — one classification the helper verdict paths
/// share.
fn helper_exit_code(status: &ExitStatus) -> Result<i32, WorkerError> {
    status.code().ok_or_else(|| confined_run_killed(status))
}

pub(crate) fn helper_confined_read(
    platform: &str,
    profile: &str,
    file: File,
) -> Result<Vec<u8>, WorkerError> {
    let mut command = helper_confined_command(platform, "read", profile)?;
    command
        .stdin(Stdio::from(file))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    owned_classify(command.run(&[]), |observed| helper_io_bytes(observed, true))
}

pub(crate) fn helper_confined_write(
    platform: &str,
    profile: &str,
    file: File,
    bytes: &[u8],
) -> Result<(), WorkerError> {
    let mut command = helper_confined_command(platform, "write", profile)?;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::from(file))
        .stderr(Stdio::piped());
    owned_classify(command.run(bytes), |observed| {
        helper_io_bytes(observed, false).map(|_| ())
    })
}

pub(crate) fn helper_probe_write(
    platform: &str,
    profile: &str,
    path: &Path,
) -> Result<(), WorkerError> {
    #[cfg(target_os = "linux")]
    let mut command = linux_wrapped_helper()?;
    #[cfg(not(target_os = "linux"))]
    let mut command =
        PreparedLaunch::new(helper_path()?, rivect_sandbox_helper::OwnedProfile::Worker);
    #[cfg(not(target_os = "linux"))]
    command.env_clear();
    command
        .arg("probe-write")
        .arg(platform)
        .arg(profile)
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    owned_classify(command.run(&[]), |observed| {
        helper_probe_verdict(&observed, path)
    })
}

/// Maps a probe-write exit onto the same taxonomy as [`helper_io_bytes`]:
/// init → [`WorkerError::SandboxUnavailable`], protocol/launch →
/// [`WorkerError::SandboxSpawnFailed`] (wire `capability_unavailable`),
/// data I/O → [`WorkerError::SandboxDenied`], and a run that died before
/// producing any exit code → [`WorkerError::ConfinedRunKilled`].
/// Init/protocol/launch verdicts require the helper's line-start stderr
/// prefix; a non-helper child cannot produce them. After that gate,
/// [`rivect_sandbox_helper::EXIT_DATA_IO`] is the only enforcement
/// denial; any other code is a capability failure.
fn helper_probe_verdict(observed: &ObservedChild, target: &Path) -> Result<(), WorkerError> {
    if let Some(err) = helper_launch_init_failed(observed) {
        return Err(err);
    }
    let code = helper_exit_code(&observed.status)?;
    let stderr = String::from_utf8_lossy(&observed.stderr).into_owned();
    match code {
        rivect_sandbox_helper::EXIT_OK => Ok(()),
        rivect_sandbox_helper::EXIT_DATA_IO => Err(sandbox_denied(target)),
        _ => Err(WorkerError::SandboxSpawnFailed {
            source: std::io::Error::other(stderr),
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
/// opted into classification. A run that died without an exit code is
/// the caller's [`WorkerError::ConfinedRunKilled`], not this gate's.
pub(crate) fn helper_launch_init_failed(observed: &ObservedChild) -> Option<WorkerError> {
    let stderr = String::from_utf8_lossy(&observed.stderr);
    let from_helper = stderr
        .lines()
        .any(|line| line.starts_with("rivect-sandbox-helper:"));
    let Ok(code) = helper_exit_code(&observed.status) else {
        return None;
    };
    match code {
        rivect_sandbox_helper::EXIT_SANDBOX_INIT if from_helper => {
            Some(WorkerError::SandboxUnavailable {
                reason: stderr.into_owned(),
            })
        }
        rivect_sandbox_helper::EXIT_LAUNCH_EXEC
        | rivect_sandbox_helper::EXIT_LAUNCH_NOT_FOUND
        | rivect_sandbox_helper::EXIT_PROTOCOL
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
    if let Some(err) = helper_launch_init_failed(&observed) {
        return Err(err);
    }
    let code = helper_exit_code(&observed.status)?;
    let stderr = String::from_utf8_lossy(&observed.stderr).into_owned();
    #[cfg(target_os = "linux")]
    if let Some(error) = linux::launcher_userns_failure(Some(code), &stderr) {
        return Err(error);
    }
    match code {
        rivect_sandbox_helper::EXIT_OK => Ok(observed.stdout),
        // The confined write reported a failure after its truncate
        // landed: the target may be mutated, so the outcome is unknown —
        // never a clean rejection.
        rivect_sandbox_helper::EXIT_DATA_MUTATED => Err(WorkerError::WriteMutationFailed {
            source: std::io::Error::other(stderr),
        }),
        rivect_sandbox_helper::EXIT_DATA_IO if read => Err(WorkerError::ReadFailed {
            source: std::io::Error::other(stderr),
        }),
        rivect_sandbox_helper::EXIT_DATA_IO => Err(WorkerError::WriteFailed {
            source: std::io::Error::other(stderr),
        }),
        _ if read => Err(WorkerError::SandboxSpawnFailed {
            source: std::io::Error::other(stderr),
        }),
        // An unlisted code on the write leg cannot prove the target is
        // unmutated — the confined writer may have truncated it and
        // then died — so it takes the same never-a-clean-rejection
        // outcome as EXIT_DATA_MUTATED.
        _ => Err(WorkerError::WriteMutationFailed {
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

/// The executor's closed borrows: its policy, store and worker are lent by
/// the runtime and never swapped or reached from outside the crate.
///
/// ```compile_fail
/// use rivect::{commands::Runtime, policy::Policy};
/// fn f(rt: &mut Runtime) { let mut e = rt.executor(); let _p: &mut Policy = &mut *e.policy; }
/// ```
///
/// ```
/// use rivect::{commands::Runtime, policy::Policy};
/// fn f(rt: &mut Runtime) { let e = rt.executor(); drop(e); let _p: &Policy = rt.policy(); }
/// ```
///
/// ```compile_fail
/// use rivect::{commands::Runtime, state::TaskStore};
/// fn f(rt: &mut Runtime, mut foreign: TaskStore) {
///     let mut e = rt.executor();
///     std::mem::swap(&mut *e.store, &mut foreign);
/// }
/// ```
///
/// ```
/// use rivect::{commands::Runtime, state::TaskStore};
/// fn f(rt: &mut Runtime, mut foreign: TaskStore) {
///     let e = rt.executor();
///     drop(e);
///     let _ = &mut foreign;
/// }
/// ```
///
/// ```compile_fail
/// use rivect::commands::Runtime;
/// fn f(rt: &mut Runtime) { let mut e = rt.executor(); let _w = &mut *e.worker; }
/// ```
///
/// ```
/// use rivect::commands::Runtime;
/// fn f(rt: &mut Runtime) { let e = rt.executor(); drop(e); }
/// ```
///
/// ```compile_fail
/// use rivect::{executor::{Executor, ReadWorker}, policy::Policy, state::TaskStore};
/// fn f(policy: &mut Policy, store: &mut TaskStore, worker: &mut dyn ReadWorker) {
///     let _e = Executor::new(policy, store, worker);
/// }
/// ```
///
/// ```
/// use rivect::{executor::{Executor, ReadWorker}, policy::Policy, state::TaskStore};
/// fn f(policy: &mut Policy, store: &mut TaskStore, worker: &mut dyn ReadWorker) {
///     let _ = (policy, store, worker);
///     let _: Option<Executor<'_>> = None;
/// }
/// ```
///
/// ```compile_fail
/// use rivect::{executor::{Executor, ReadWorker}, policy::Policy, resources::ReadFlights, state::TaskStore};
/// fn f(policy: &mut Policy, store: &mut TaskStore, worker: &mut dyn ReadWorker, flights: &mut ReadFlights) {
///     let _e = Executor::with_flights(policy, store, worker, flights);
/// }
/// ```
///
/// ```
/// use rivect::{executor::{Executor, ReadWorker}, policy::Policy, resources::ReadFlights, state::TaskStore};
/// fn f(policy: &mut Policy, store: &mut TaskStore, worker: &mut dyn ReadWorker, flights: &mut ReadFlights) {
///     let _ = (policy, store, worker, flights);
///     let _: Option<Executor<'_>> = None;
/// }
/// ```
pub struct Executor<'a> {
    policy: &'a mut Policy,
    store: &'a mut TaskStore,
    worker: &'a mut dyn ReadWorker,
    /// The single-flight registry for permitted reads (INV-023), when
    /// the call site runs reads merged. Absent, every admitted read
    /// executes its own physical charge — the pre-single-flight
    /// behavior.
    flights: Option<&'a mut ReadFlights>,
    /// The in-flight attempt root allocation, keyed by its owning
    /// attempt: a failure settles with that attempt's own root removed
    /// best-effort after the terminal row is retained, and a later
    /// attempt's settle never cleans an earlier attempt's preserved
    /// root.
    check_attempt_root: Option<AttemptRoot>,
    /// The document's hook declarations (DEC-010). Absent, admission takes
    /// the caller's request as it stands — the pre-hook behavior.
    hooks: Option<&'a crate::config::Hooks>,
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
    grant_id: &str,
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
        .and_then(|text| preapproval_scope(class, grant_id, text))
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
    pub(crate) fn new(
        policy: &'a mut Policy,
        store: &'a mut TaskStore,
        worker: &'a mut dyn ReadWorker,
    ) -> Self {
        Self {
            policy,
            store,
            worker,
            flights: None,
            check_attempt_root: None,
            hooks: None,
        }
    }

    /// Binds the document's hook declarations: admission consults them at
    /// its one instrumented event, before the request is judged.
    #[must_use]
    pub fn with_hooks(mut self, hooks: Option<&'a crate::config::Hooks>) -> Self {
        self.hooks = hooks;
        self
    }

    /// The single-flight seam: identical permitted reads admitted
    /// through this executor merge into one physical charge in
    /// `flights` (INV-023); effects, differing rights, and differing
    /// snapshots never merge.
    #[must_use]
    pub(crate) fn with_flights(
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
            check_attempt_root: None,
            hooks: None,
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
        // The one instrumented event (I6): the hook answers before the
        // request is judged, and whatever it leaves behind is judged at
        // this same site — never at a second, weaker one.
        let (request, rewrite) = self.hook_transform(request)?;
        let grant_id = request.grant_id();
        let grant = self.policy.admit(grant_id, request.class())?;
        let target = request.target_path();
        let ctx = admission_context(
            self.store,
            mode,
            request.class(),
            grant_id,
            &grant.scope_root,
            &target,
        )?;
        let scope_root = grant.scope_root.clone();
        // INV-029: pin the write occupant at admit — the same binding the
        // managed control-write path takes — so the execute-time
        // checked-fd write compares against the admit-time snapshot,
        // never a fresh execute-time one.
        let expected_identity = match &request {
            EffectRequest::Write { path, .. } => Some(write_target_identity(&scope_root, path)?),
            _ => None,
        };
        let decision = self.policy.decide(&target, request.class(), &ctx);
        let attempt_id = self
            .store
            .plan_attempt(task_id, request.class(), &request.describe())?;
        if decision != ModeDecision::Allow {
            // A rewritten request that the admission refuses is refused
            // *for its rewritten target*: the reason names the hook and
            // both paths, so a steering attempt is visible rather than
            // looking like the caller's own denial.
            if let Some(rewrite) = rewrite {
                let detail = format!(
                    "hook {} rewrote {} to {}",
                    rewrite.hook,
                    rewrite.original.display(),
                    rewrite.transformed.display()
                );
                self.store.attempt_rejected(&attempt_id, &detail)?;
                return Err(ExecutorError::HookTransform {
                    hook: rewrite.hook,
                    original: rewrite.original.display().to_string(),
                    transformed: rewrite.transformed.display().to_string(),
                });
            }
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
        let expected_identity = write_target_identity(&scope_root, &path)?;
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
                // A managed write mutates its target: any worker failure
                // here settles against a possibly-changed file.
                return self.commit_worker_error(&admitted.attempt_id, error, true);
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
            admitted.request.grant_id(),
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

    /// The `effect.request` consult (AC-076, I6): the one instrumented event,
    /// before admission judges the request. The answer is data — a `deny` or
    /// `stop` refuses the request, and a rewritten path replaces the request's
    /// own before the same admission reads it. At most [`HOOK_MAX_DEPTH`]
    /// runs answer, so an answer is never fed back into another hook.
    fn hook_transform(
        &self,
        mut request: EffectRequest,
    ) -> Result<(EffectRequest, Option<HookRewrite>), ExecutorError> {
        let Some(hooks) = self.hooks else {
            return Ok((request, None));
        };
        if request.path_field().is_none() {
            return Ok((request, None));
        }
        let Some(entry) = hooks.for_event(crate::config::HOOK_EVENT_EFFECT_REQUEST) else {
            return Ok((request, None));
        };
        let original = request.target_path();
        let mut current = original.clone();
        for _ in 0..HOOK_MAX_DEPTH {
            let answer = run_hook(entry, &current)?;
            match answer.decision {
                HookDecision::Allow => {}
                refused => {
                    return Err(ExecutorError::HookDenied {
                        hook: entry.id(),
                        decision: refused.as_str(),
                    });
                }
            }
            let Some(rewritten) = answer.path else {
                break;
            };
            current = rewritten;
        }
        if current == original {
            return Ok((request, None));
        }
        if let Some(field) = request.path_field() {
            *field = current.clone();
        }
        Ok((
            request,
            Some(HookRewrite {
                hook: entry.id(),
                original,
                transformed: current,
            }),
        ))
    }

    /// Reject tail shared by the mode gates: the ledger reason is
    /// recorded before the typed error leaves the executor.
    fn reject_mode(
        &mut self,
        attempt_id: &str,
        decision: ModeDecision,
    ) -> Result<(), ExecutorError> {
        let reason = mode_reason(decision);
        let error = if matches!(decision, ModeDecision::Ask) {
            ExecutorError::ModeAsk
        } else {
            ExecutorError::ModeDenied
        };
        self.store.attempt_rejected(attempt_id, reason)?;
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

    /// Shared execute-time gates for an admitted effect: grant re-check,
    /// cancel, mode consult, then running. Gate failures leave the flight
    /// without an observation so remaining members keep their own claim.
    fn execute_gates(&mut self, admitted: &AdmittedEffect) -> Result<(), ExecutorError> {
        let grant_id = admitted.request.grant_id();
        let class = admitted.request.class();
        let target = admitted.request.target_path();
        if let Err(error) = self.admit_settled(&admitted.attempt_id, grant_id, class) {
            self.abandon_flight(&admitted.attempt_id);
            return Err(error);
        }
        if self.store.task_cancelled(&admitted.task_id)? {
            self.store
                .attempt_rejected(&admitted.attempt_id, TASK_CANCELLED)?;
            self.abandon_flight(&admitted.attempt_id);
            return Err(ExecutorError::Cancelled);
        }
        if let Err(error) = self.mode_gate(admitted, &target) {
            self.abandon_flight(&admitted.attempt_id);
            return Err(error);
        }
        self.store.attempt_running(&admitted.attempt_id)?;
        Ok(())
    }

    /// Settles the worker failure in the attempt ledger. `mutating`
    /// names whether the effect path could already have changed its
    /// target: a post-mutation write failure and a mutating effect
    /// whose confined run timed out or was killed both record
    /// `unknown` — the dead child may have landed its change — while a
    /// failure on a non-mutating path stays a clean rejection.
    fn commit_worker_error(
        &mut self,
        attempt_id: &str,
        error: WorkerError,
        mutating: bool,
    ) -> Result<(), ExecutorError> {
        let detail = error.to_string();
        fn mutation_unknown(error: &WorkerError) -> bool {
            match error {
                WorkerError::WriteMutationFailed { .. }
                | WorkerError::ConfinedRunTimedOut
                | WorkerError::ConfinedRunKilled { .. } => true,
                WorkerError::OwnedLaunch { source } => match source.as_ref() {
                    OwnedLaunchError::Unproven { .. } => true,
                    OwnedLaunchError::Release { primary, .. } => mutation_unknown(primary),
                    OwnedLaunchError::OutputRelease { output, .. } => {
                        output.as_ref().is_none_or(|output| {
                            output.status.signal().is_some()
                                || output.status.code()
                                    == Some(rivect_sandbox_helper::EXIT_DATA_MUTATED)
                        })
                    }
                    _ => false,
                },
                _ => false,
            }
        }
        let unproven = mutating
            && matches!(&error, WorkerError::OwnedLaunch { source } if matches!(source.as_ref(), OwnedLaunchError::Unproven { .. }));
        let unknown = matches!(error, WorkerError::WriteMutationFailed { .. })
            || (mutating && mutation_unknown(&error));
        let settlement = if unknown {
            self.store.attempt_unknown(attempt_id, &detail)
        } else {
            self.store.attempt_rejected(attempt_id, &detail)
        };
        match settlement {
            Ok(()) if unproven => Err(ExecutorError::WorkerUnproven { primary: error }),
            Ok(()) => Err(ExecutorError::Worker(error)),
            Err(secondary) => Err(ExecutorError::WorkerSettlement {
                primary: error,
                secondary: Box::new(secondary),
            }),
        }
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
        self.execute_gates(admitted)?;
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
                    executed(format!(
                        "write-performed sha256={}",
                        hex(&sha2::Sha256::digest(bytes))
                    ))
                }),
            EffectRequest::Exec { program, .. } => self
                .worker
                .exec_once(&admitted.scope_root, program)
                .map(|()| executed("exec-performed exit=ok".to_string())),
            EffectRequest::Egress { url, .. } => self
                .worker
                .egress_once(url)
                .map(|()| executed(format!("egress-performed {}", redact_egress_url(url)))),
        };
        match effect {
            Ok((outcome, detail)) => {
                self.store
                    .set_attempt_state(&admitted.attempt_id, "confirmed", Some(&detail))?;
                Ok(outcome)
            }
            Err(error) => {
                self.abandon_flight(&admitted.attempt_id);
                // Write is the only effect that declares a mutated
                // artifact; confined Exec grants no file-write rights
                // today — revisit if Exec gains write rights.
                self.commit_worker_error(
                    &admitted.attempt_id,
                    error,
                    matches!(&admitted.request, EffectRequest::Write { .. }),
                )?;
                unreachable!("internal error: worker error commit always errors")
            }
        }
    }

    /// One step of a saved segment through this executor's own admission and
    /// settlement (INV-002): the step enters the same gates a first-time effect
    /// enters — the hook transform, the grant re-check at admission and again
    /// immediately before the effect, the mode consult, and the attempt ledger
    /// — and no second effect path exists for it. The run's cursor names the
    /// step, so a resumed run continues after the last settled one and never
    /// re-issues it (PROH-003).
    ///
    /// The step is prepared between its admission and its effect, stamped with
    /// the attempt that performs it: an interrupted step is then readable
    /// through that attempt's own state rather than through how this call
    /// happened to return.
    ///
    /// The effect's own settlement decides the answer: an unresolved attempt and
    /// a revoked right come back as [`crate::procedure::StepOutcome::Stopped`]
    /// because the segment must not run its remainder past them (EDGE-003,
    /// EDGE-004); any other refusal keeps its typed error and settles the
    /// attempt as the effect path already did.
    ///
    /// # Errors
    /// Returns [`ExecutorError::Procedure`] for a step the run cannot reach — a
    /// cursor past the segment's steps or an unbound parameter — and the
    /// effect's own typed refusal for anything that is not a stop condition.
    pub fn run_segment_step(
        &mut self,
        task_id: &TaskId,
        segment: &crate::procedure::SegmentTemplate,
        run: &crate::procedure::ProcedureRun,
        binding: &crate::procedure::SegmentBinding,
        mode: PermissionMode,
    ) -> Result<crate::procedure::StepOutcome, ExecutorError> {
        use crate::procedure::{
            ProcedureError, StepOutcome, StepStanding, StopCause, settled_result,
        };
        let position = run.cursor + 1;
        let step = segment
            .step(position)
            .ok_or_else(|| ProcedureError::CursorPastSteps {
                procedure_id: segment.procedure_id.clone(),
                cursor: run.cursor,
                steps: u64::try_from(segment.steps.len()).unwrap_or(u64::MAX),
            })?;
        let request = binding
            .request(position)
            .ok_or(ProcedureError::UnboundParameter { position })?
            .clone();
        let admitted = match self.admit(task_id, request, mode) {
            Ok(admitted) => admitted,
            // The effect-time re-check is the admission's own: a right revoked
            // before this step refuses here exactly as it would on a first run.
            Err(ExecutorError::Policy(PolicyError::Revoked { grant_id })) => {
                return Ok(StepOutcome::Stopped(StopCause::RevokedRight { grant_id }));
            }
            Err(error) => return Err(error),
        };
        let attempt_id = admitted.attempt_id.clone();
        // The prepared row is the run's durable record of this step, and it
        // names the attempt that performs it: the step's own effect is then
        // answered by the ledger, never by how this call returned (PROH-003).
        self.store
            .prepare_procedure_step(run, position, &step.tool, &attempt_id)?;
        let effect = self.execute(&admitted);
        // The durable settlement, not the returned value, is what the segment
        // continues on: the same column the task's blocker projection reads.
        let (_, state, detail) = self
            .store
            .attempt_record(&attempt_id)?
            .ok_or_else(|| StoreError::missing_attempt(&attempt_id))?;
        match StepStanding::parse(Some(&state)) {
            // The effect may have landed and the ledger holds no settled
            // answer: the remainder does not run past it, whatever the call
            // returned.
            Some(StepStanding::Unresolved) => {
                return Ok(StepOutcome::Stopped(StopCause::UnknownEffect {
                    attempt_id,
                }));
            }
            // The attempt never reached the worker: the call's own refusal is
            // the answer to keep.
            Some(StepStanding::NotStarted) => {
                return match effect {
                    Err(ExecutorError::Policy(PolicyError::Revoked { grant_id })) => {
                        Ok(StepOutcome::Stopped(StopCause::RevokedRight { grant_id }))
                    }
                    Err(other) => Err(other),
                    // A value the ledger does not back is not a settled step:
                    // reporting it as one would claim what the record cannot
                    // prove.
                    Ok(_unbacked) => Ok(StepOutcome::Stopped(StopCause::UnknownEffect {
                        attempt_id,
                    })),
                };
            }
            // The effect landed and its settlement is durable.
            Some(StepStanding::Landed) => {
                effect?;
            }
            // A state this build does not write is not a landed step.
            None => {
                return Ok(StepOutcome::Stopped(StopCause::UnknownEffect {
                    attempt_id,
                }));
            }
        }
        Ok(StepOutcome::Settled {
            result: settled_result(&step.tool, detail.as_deref()),
            attempt_id,
        })
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
        self.execute_gates(admitted)?;
        let EffectRequest::Read { path, .. } = &admitted.request else {
            unreachable!("internal error: read class checked above")
        };
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

    /// Runs one confined Cargo check (SLICE-178, DEC-040/041/042): the
    /// admitted Exec effect and an independent project Read grant bound
    /// to the recorded candidate identity. Re-verifies task, grants,
    /// canonical Cargo, and the workspace before anything spawns;
    /// snapshots the candidate into an exclusive attempt root; stages
    /// only lockfile-named, checksum-verified dependency bytes through
    /// the fd-anchored walk; proves the boundary with deny-first
    /// controls; runs `cargo vendor` (phase A) and `cargo test` (phase B)
    /// under the helper's check profile with both grants reconsulted
    /// before each spawn; promotes and seals the verified vendor; and
    /// settles every seam in the retained ledger. A nonzero test exit is
    /// the observed RED, returned as [`CheckRun`] — never an `Err`.
    ///
    /// # Errors
    /// Returns [`ExecutorError::Check`] with the failing seam's typed
    /// cause; nothing is retried and no unconfined fallback exists.
    pub fn execute_check(
        &mut self,
        admission: &mut CheckAdmission,
        check: &ConfinedCheck,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<CheckRun, ExecutorError> {
        // The issuer binding: identity of the Policy and TaskStore this
        // admission was minted over, and the phase gate. A foreign
        // presentation holds no disposal authority either — the issuing
        // pair's allocation and pending phase survive it untouched.
        if !std::sync::Arc::ptr_eq(self.policy.identity(), admission.policy_identity())
            || !std::sync::Arc::ptr_eq(self.store.identity(), admission.store_identity())
        {
            return Err(ExecutorError::Check(CheckError::Claim {
                site: "admit.issuer",
                detail: "the admission was issued by another policy or store".to_string(),
            }));
        }
        match admission.phase() {
            CheckPhase::Spent => {
                return Err(ExecutorError::Check(CheckError::Claim {
                    site: "admit.issuer",
                    detail: "the admission is spent".to_string(),
                }));
            }
            CheckPhase::Claimed => {
                return Err(ExecutorError::Check(CheckError::Claim {
                    site: "admit.replay",
                    detail: "the admission already claimed its dispatch".to_string(),
                }));
            }
            CheckPhase::Pending => {}
        }
        // Every exit below this point happens BEFORE the first claim:
        // each is the prescribed typed refusal plus the release of the
        // presentation's own allocation only — no authoritative
        // attempt-keyed row, no ledger rejection, no root removal
        // (DEC-048 items 6–7; the legitimate attempt stays planned).
        // The ONE absolute check deadline is armed here, at the
        // presentation, and shared by the claim, the controls, and both
        // phases (DEC-056) — phase B never receives a fresh full budget.
        let deadline = Instant::now() + CHECK_PHASE_DEADLINE;
        // The binding re-verification before any root, byte, or spawn.
        if let Err(error) = self.verify_check_binding(admission, check) {
            return Err(self.refuse_pre_claim(admission, error));
        }
        let admitted = admission.admitted().clone();
        if let Err(error) = self.verify_check_admission(&admitted, check, admission.is_native()) {
            return Err(self.refuse_pre_claim(admission, error));
        }
        // DEC-054: the CURRENT config-owner snapshot must still be the
        // admission's bound generation/mode/digest — both variants. A
        // toggled workflow, a moved generation (off→on→identical-off
        // included), or a changed sources digest refuses before the
        // claim, exactly like a moved native selection.
        {
            let (state, generation, sources_digest, explicit_off) = admission.owner_view();
            if let Err(error) =
                verify_owner_context(state, generation, sources_digest, explicit_off)
            {
                return Err(self.refuse_pre_claim(admission, error));
            }
        }
        // The complete presented receipt and required dependency
        // authority are validated BEFORE the first claim, root, or
        // copied project byte (DEC-048 item 4): an unregistered,
        // partial, aliased, or wide pair, and a registry lock without
        // its pair, refuse here while the attempt is still planned. The
        // lockfile read is best-effort at this gate — the authoritative
        // check stays on the claimed path — and a malformed lockfile is
        // a pre-claim refusal like every other gate here, never a `?`
        // exit that strands the presentation's own allocation.
        if let Some(receipt) = admission.receipt() {
            if let Err(error) = self.verify_dependency_pair(&admitted.attempt_id, check, receipt) {
                return Err(self.refuse_pre_claim(admission, error));
            }
        } else {
            // The pre-claim lock ingress reads one bounded, nofollow,
            // nonblocking regular file (DEC-056): a FIFO swapped onto
            // the name can neither block nor redirect the read, an
            // absent file is its own answer, and an enrolled deny on
            // the descendant refuses before any byte — the root grant
            // never reads a denied child.
            let lock_path = check.project_root.join("Cargo.lock");
            if self.policy.covers(&lock_path) {
                return Err(self.refuse_pre_claim(
                    admission,
                    CheckError::ProjectReadGrant {
                        detail: "an enrolled deny covers the lockfile; the project read grant cannot read a denied child"
                            .to_string(),
                    },
                ));
            }
            let lock_gate = match read_inventory_file(&lock_path, Path::new("Cargo.lock")) {
                Ok(lock_bytes) => {
                    lock_registry_dependencies(&lock_bytes).map(|deps| !deps.is_empty())
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(CheckError::LockRefused {
                    detail: format!("the pre-claim lock read: {error}"),
                }),
            };
            match lock_gate {
                Ok(false) => {}
                Ok(true) => {
                    return Err(self.refuse_pre_claim(
                        admission,
                        CheckError::CacheScope {
                            detail: "the lockfile names registry dependencies but no cache/index Read pair was provided"
                                .to_string(),
                        },
                    ));
                }
                Err(error) => return Err(self.refuse_pre_claim(admission, error)),
            }
        }
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(self.refuse_pre_claim(
                admission,
                CheckError::VendorCancel {
                    detail: "cancellation before the claim".to_string(),
                },
            ));
        }
        // DEC-048 item 4: the first-only claim in the TaskStore before
        // root creation, dependency bytes, or any A/B spawn. The claim
        // shares the invocation's existing wall bound — no second
        // arbitrary deadline constant.
        let claim = admission.claim_binding();
        let outcome = match self.store.claim_check(&claim, cancel, deadline) {
            Ok(outcome) => outcome,
            Err(store_error) => {
                // The store is quarantined or closed: no further store
                // call may run; the pair is released in memory only.
                return Err(self.refuse_pre_claim_unrecorded(
                    admission,
                    CheckError::Claim {
                        site: "admit.claim",
                        detail: format!(
                            "the claim call refused: {store_error}; denial row unavailable"
                        ),
                    },
                ));
            }
        };
        match outcome {
            crate::state::ClaimOutcome::Claimed => {
                admission.mark_claimed();
                let (owner_state, owner_generation, owner_digest, owner_off) =
                    admission.owner_view();
                let result = self.execute_check_inner(
                    &admitted,
                    check,
                    admission.receipt(),
                    admission.is_native(),
                    (owner_state, owner_generation, owner_digest, owner_off),
                    (cancel, deadline),
                );
                match result {
                    Ok(run) => {
                        // The owning dispatch consumes its pair; the
                        // project Read and Exec grants survive.
                        self.policy.consume_check_pair(admission);
                        Ok(run)
                    }
                    Err(error) => {
                        self.policy.consume_check_pair(admission);
                        Err(self.settle_check_failure(&admitted, error))
                    }
                }
            }
            crate::state::ClaimOutcome::Refused(refusal) => {
                // A refused claim never happened: the claim's own
                // zero-wait rejection row (where one was writable) is
                // the whole record — the executor adds no second
                // rejection row and no attempt-keyed settlement under
                // the restored timeout.
                Err(self.refuse_pre_claim_unrecorded(
                    admission,
                    CheckError::Claim {
                        site: refusal.site.suffix(),
                        detail: format!(
                            "the claim refused at {}: retained={} restore-failed={}",
                            refusal.site.suffix(),
                            matches!(refusal.retention, crate::state::RetentionOutcome::Retained),
                            refusal.restore_failed,
                        ),
                    },
                ))
            }
        }
    }

    /// One executor-originated pre-claim refusal: the typed cause, the
    /// one server-invocation-scoped non-authoritative denial row
    /// (DEC-048 item 6 — a retention failure has no effect and never
    /// creates a terminal row), and the release of the presentation's
    /// own allocation — never an authoritative attempt-keyed row, ledger
    /// rejection, or root removal. The legitimate attempt stays
    /// planned.
    fn refuse_pre_claim(
        &mut self,
        admission: &mut CheckAdmission,
        error: CheckError,
    ) -> ExecutorError {
        let site = error.site();
        let binding_digest = admission.claim_binding().binding_digest;
        // The rejection row is bounded, non-authoritative diagnostics:
        // an unwritable store leaves the typed refusal standing alone —
        // never a terminal row and never a change to the refusal's
        // variant or site. The outcome is surfaced on the refusal
        // itself, so an unavailable retention is reported honestly
        // instead of reading as retained.
        let note = match self.store.retain_preclaim_rejection(site, &binding_digest) {
            crate::state::RetentionOutcome::Retained => "denial row retained",
            crate::state::RetentionOutcome::Unavailable => "denial row unavailable",
        };
        self.refuse_pre_claim_unrecorded(admission, error.with_note(note))
    }

    /// The pre-claim refusal tail whose denial row another owner
    /// already wrote (the store's claim refusals) or cannot exist (the
    /// store is quarantined): release only.
    fn refuse_pre_claim_unrecorded(
        &mut self,
        admission: &mut CheckAdmission,
        error: CheckError,
    ) -> ExecutorError {
        self.policy
            .release_check_dependencies(self.store, admission);
        ExecutorError::Check(error)
    }

    /// DEC-048 item 1 / DEC-054: mints the opaque issuer-bound check
    /// admission over the existing admission owner — the planned Exec
    /// effect, the immutable binding (Policy/TaskStore identity,
    /// server-owned attempt/task, canonical inputs, candidate digest,
    /// selector and harness threads, journey-declared expected
    /// phase/assertion identity), and the owner-derived context. The
    /// Runtime-issued [`CheckHandoff`] is mandatory: a Custom admission
    /// requires its bound explicit workflow-off (creating no native
    /// selection, plan rows, or gate hold), a Native admission binds the
    /// handoff's owner generation and digest alongside the store's
    /// actual selection. A task without a recorded selection refuses
    /// typed here — zero claim, root, byte, or spawn.
    ///
    /// # Errors
    /// Returns [`ExecutorError::Check`] when the handoff is foreign or
    /// task-mismatched, the store has no selection for the task, and
    /// the underlying admission failures of [`Executor::admit`]
    /// unchanged.
    pub fn admit_check(
        &mut self,
        task_id: &TaskId,
        request: EffectRequest,
        mode: PermissionMode,
        check: &ConfinedCheck,
        handoff: &CheckHandoff,
    ) -> Result<CheckAdmission, ExecutorError> {
        // The handoff's owner authority is Runtime-issued and never
        // portable: a handoff minted by another Runtime's Policy or
        // TaskStore, or for another task, refuses before any planning,
        // attempt row, or grant — zero claim, root, cache byte, or spawn
        // on this runtime (DEC-048 item 1, DEC-054).
        if !std::sync::Arc::ptr_eq(self.policy.identity(), handoff.policy_identity())
            || !std::sync::Arc::ptr_eq(self.store.identity(), handoff.store_identity())
        {
            return Err(ExecutorError::Check(CheckError::SelectionMismatch {
                detail: "the check handoff was issued by another runtime's policy or store"
                    .to_string(),
            }));
        }
        if handoff.task_id() != task_id {
            return Err(ExecutorError::Check(CheckError::SelectionMismatch {
                detail: "the check handoff was issued for another task".to_string(),
            }));
        }
        if !check.target.is_well_formed() || !plain_selector(&check.exact_test, true) {
            return Err(ExecutorError::Check(CheckError::TargetLayout {
                detail: "the test selector is not a plain target name and test path".to_string(),
            }));
        }
        if check.harness_threads == 0 || check.harness_threads > CHECK_MAX_HARNESS_THREADS {
            return Err(ExecutorError::Check(CheckError::TargetLayout {
                detail: format!(
                    "the harness thread bound {} is outside 1..={CHECK_MAX_HARNESS_THREADS}",
                    check.harness_threads
                ),
            }));
        }
        // DEC-054: the handoff's owner context must still be the config
        // owner's CURRENT snapshot — for both variants — BEFORE any
        // generic admission or planning runs: a toggled workflow or a
        // moved generation never mints a fresh admission, and
        // off→on→identical-off never resurrects an older handoff.
        {
            let state = handoff.state();
            if let Err(error) = verify_owner_context(
                state,
                handoff.generation(),
                handoff.sources_digest(),
                handoff.explicit_off(),
            ) {
                return Err(ExecutorError::Check(error));
            }
        }
        let admitted = self.admit(task_id, request, mode)?;
        // The live owner state travels with the admission so every later
        // reconsult compares against the config owner's CURRENT
        // snapshot, not the mint-time one.
        let off_state = std::sync::Arc::clone(handoff.state());
        let context = if handoff.explicit_off() {
            CheckContext::Custom {
                sources_digest: handoff.sources_digest().to_string(),
                generation: handoff.generation(),
            }
        } else {
            let selection = self.store.plan_selection(task_id)?;
            match selection {
                Some(record) => CheckContext::Native {
                    selection_revision: record.revision,
                    facts_digest: record.facts_digest.clone(),
                    request_kind: record.request_kind,
                    owner_generation: handoff.generation(),
                    owner_sources_digest: handoff.sources_digest().to_string(),
                },
                None => {
                    return Err(ExecutorError::Check(CheckError::SelectionMismatch {
                        detail: "no selection is recorded for the task the check binds".to_string(),
                    }));
                }
            }
        };
        Ok(CheckAdmission {
            binding: CheckBinding {
                task_id: task_id.clone(),
                attempt_id: admitted.attempt_id.clone(),
                project_grant_id: check.project_grant_id.clone(),
                project_root: check.project_root.clone(),
                manifest_rel: check.manifest_rel.clone(),
                cargo: check.cargo.clone(),
                cargo_home: check.cargo_home.clone(),
                target: check.target.clone(),
                harness_threads: check.harness_threads,
                exact_test: check.exact_test.clone(),
                expected_selection_revision: check.expected_selection_revision,
                expected_candidate_digest: check.expected_candidate_digest.clone(),
                expected_phase: check.expected_phase.clone(),
                expected_assertion_identity: check.expected_assertion_identity.clone(),
            },
            admitted,
            policy_identity: std::sync::Arc::clone(self.policy.identity()),
            store_identity: std::sync::Arc::clone(self.store.identity()),
            context,
            off_state,
            phase: CheckPhase::Pending,
            allocation: std::sync::Arc::new(()),
            receipt: None,
        })
    }

    /// The binding re-verification every `execute_check` presentation
    /// runs first: each canonical field of the presented check must
    /// equal the admission's immutable binding (`admit.binding`).
    fn verify_check_binding(
        &self,
        admission: &CheckAdmission,
        check: &ConfinedCheck,
    ) -> Result<(), CheckError> {
        let bound = admission.bound();
        let matches = bound.task_id.0 == check.task_id.0
            && bound.project_grant_id == check.project_grant_id
            && bound.project_root == check.project_root
            && bound.manifest_rel == check.manifest_rel
            && bound.cargo == check.cargo
            && bound.cargo_home == check.cargo_home
            && bound.target == check.target
            && bound.harness_threads == check.harness_threads
            && bound.exact_test == check.exact_test
            && bound.expected_selection_revision == check.expected_selection_revision
            && bound.expected_candidate_digest == check.expected_candidate_digest
            && bound.expected_phase == check.expected_phase
            && bound.expected_assertion_identity == check.expected_assertion_identity;
        if matches {
            Ok(())
        } else {
            Err(CheckError::Claim {
                site: "admit.binding",
                detail: "the presented check does not match the admission binding".to_string(),
            })
        }
    }

    fn execute_check_inner(
        &mut self,
        admitted: &AdmittedEffect,
        check: &ConfinedCheck,
        receipt: Option<&crate::policy::DependencyReceipt>,
        native: bool,
        owner: (&std::sync::Arc<WorkflowOffState>, u64, &str, bool),
        stop: (&std::sync::atomic::AtomicBool, Instant),
    ) -> Result<CheckRun, CheckError> {
        let (cancel, deadline) = stop;
        // A store failure is never silently "cancelled": the retention
        // seam owns it and the attempt root is never touched.
        let cancelled = self
            .store
            .task_cancelled(&admitted.task_id)
            .map_err(|source| CheckError::EvidenceRetention {
                detail: format!("the task cancellation state is unreadable: {source}"),
            })?;
        if cancelled {
            return Err(CheckError::CloseSelection {
                detail: TASK_CANCELLED.to_string(),
            });
        }
        self.verify_check_admission(admitted, check, native)?;
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(CheckError::VendorCancel {
                detail: "cancellation before the snapshot".to_string(),
            });
        }
        // The exclusive, privately created, durably recorded allocation
        // (DEC-047 locator): a pre-existing path at the name refuses —
        // an existing directory or symlink is never adopted — and the
        // canonical spelling from here on is the one Seatbelt's literal
        // profile rules match, so the /var → /private/var alias never
        // splits the two.
        let allocated = create_recorded_attempt_root(self.store, &admitted.attempt_id)?;
        self.check_attempt_root = Some(allocated.clone());
        let attempt_root = allocated.canonical_root;
        let snapshot_dir = attempt_root.join("src");
        let rw = attempt_root.join("rw");
        let env = check_phase_env(&attempt_root, &toolchain_bin_dir(&check.cargo)?);
        for dir in [
            snapshot_dir.as_path(),
            &rw,
            env.staged_source.as_deref().unwrap_or(&env.cargo_home),
        ] {
            std::fs::create_dir_all(dir).map_err(|source| CheckError::CopyFailed {
                detail: format!("attempt root layout: {source}"),
            })?;
        }
        // The bounded rw is an empty mountpoint on Linux: the namespace
        // script builds the private layout inside the mounted tmpfs, so
        // parent-created subdirs would both refuse check-setup's empty
        // check and never be seen past the mount.
        #[cfg(not(target_os = "linux"))]
        for dir in [
            &env.home,
            &env.tmpdir,
            &rw.join("vendor"),
            &rw.join("target"),
        ] {
            std::fs::create_dir_all(dir).map_err(|source| CheckError::CopyFailed {
                detail: format!("attempt root layout: {source}"),
            })?;
        }
        let live = inventory_under(&check.project_root, &|path| self.policy.covers(path)).map_err(
            |error| match error {
                InventoryError::Denied { rel } => CheckError::ProjectReadGrant {
                    detail: format!(
                        "an enrolled deny covers {}; the project read grant cannot read a denied child",
                        rel.display()
                    ),
                },
                other => CheckError::InventoryRefused {
                    detail: format!("live workspace: {other}"),
                },
            },
        )?;
        if live.digest != check.expected_candidate_digest {
            return Err(CheckError::DigestMismatch {
                detail: "the live workspace no longer matches the recorded candidate digest"
                    .to_string(),
            });
        }
        let project_digest = copy_inventory(&check.project_root, &live, &snapshot_dir, &|path| {
            self.policy.covers(path)
        })?;
        let lock_bytes =
            read_inventory_file(&snapshot_dir.join("Cargo.lock"), Path::new("Cargo.lock"))
                .map_err(|source| CheckError::LockRefused {
                    detail: format!("the snapshot lockfile is unreadable: {source}"),
                })?;
        let deps = lock_registry_dependencies(&lock_bytes)?;
        if !deps.is_empty() {
            let receipt = receipt.ok_or_else(|| {
                CheckError::CacheScope {
                    detail: format!(
                        "the lockfile names {} registry dependencies but no cache/index Read pair was provided",
                        deps.len()
                    ),
                }
            })?;
            self.verify_dependency_pair(&admitted.attempt_id, check, receipt)?;
            self.retain_check_row(
                &admitted.attempt_id,
                "pre.effect",
                crate::verification::RetainedStage::PreEffect,
                "confined check before the first cache byte and spawn",
            )?;
            let (anchored, regdir) = anchor_dependencies(&check.cargo_home)?;
            stage_dependencies(
                &deps,
                regdir,
                &anchored,
                (
                    &check.cargo_home,
                    env.staged_source.as_deref().unwrap_or(&env.cargo_home),
                ),
                receipt,
                self.policy,
                cancel,
            )?;
            drop(anchored);
        } else if let Some(receipt) = receipt {
            self.verify_dependency_pair(&admitted.attempt_id, check, receipt)?;
            self.retain_check_row(
                &admitted.attempt_id,
                "pre.effect",
                crate::verification::RetainedStage::PreEffect,
                "confined check before the first confined spawn",
            )?;
        } else {
            self.retain_check_row(
                &admitted.attempt_id,
                "pre.effect",
                crate::verification::RetainedStage::PreEffect,
                "confined check before the first confined spawn",
            )?;
        }
        run_check_controls(check, &attempt_root, cancel, deadline)?;
        self.reconsult_phase_grants(admitted, check, receipt, native, owner, "vendor")?;
        phase_deadline_check(deadline, "vendor")?;
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(CheckError::VendorCancel {
                detail: "cancellation before the vendor phase".to_string(),
            });
        }
        let vendor_args: Vec<std::ffi::OsString> = vec![
            "vendor".into(),
            "--locked".into(),
            "--offline".into(),
            "--versioned-dirs".into(),
            "--manifest-path".into(),
            snapshot_dir.join(&check.manifest_rel).into_os_string(),
            rw.join("vendor").into_os_string(),
        ];
        let vendor_command = check_phase_command(check, &attempt_root, &vendor_args, false, &env)?;
        let vendor_command = vendor_command;
        let vendor = run_check_phase(vendor_command, cancel, deadline, &map_vendor_stop)?;
        if !vendor.status.success() {
            // The durable cause carries the fixed typed status only:
            // raw child output never reaches the retained rows (the
            // bounded capture stays on the returned run for display).
            return Err(CheckError::VendorResult {
                detail: format!("cargo vendor exited {}", vendor.status.code().unwrap_or(-1),),
            });
        }
        let after_vendor =
            inventory(&snapshot_dir).map_err(|error| CheckError::VendorValidate {
                detail: format!("snapshot after vendor: {error}"),
            })?;
        if after_vendor.digest != project_digest {
            return Err(CheckError::VendorValidate {
                detail: "the sealed project bytes changed during the vendor phase".to_string(),
            });
        }
        let fresh_lock =
            read_inventory_file(&snapshot_dir.join("Cargo.lock"), Path::new("Cargo.lock"))
                .map_err(|source| CheckError::VendorLockChanged {
                    detail: format!("the lockfile is unreadable after vendor: {source}"),
                })?;
        if fresh_lock != lock_bytes {
            return Err(CheckError::VendorLockChanged {
                detail: "Cargo.lock is not byte-identical after the vendor phase".to_string(),
            });
        }
        let vendor_dest = snapshot_dir.join(".rivect-vendor");
        // A dependency-free workspace vendors nothing: cargo's vendor
        // phase succeeds with no output, and the run records no digest.
        let vendor_digest = if deps.is_empty() {
            None
        } else {
            // The namespace script copies the vendor tree out of the
            // bounded tmpfs to the parent-visible vendor-out on Linux;
            // on macOS rw is a plain directory the vendor phase wrote.
            #[cfg(target_os = "linux")]
            let vendor_source = attempt_root.join("vendor-out");
            #[cfg(not(target_os = "linux"))]
            let vendor_source = rw.join("vendor");
            Some(promote_tree(&vendor_source, &vendor_dest)?)
        };
        // The seal is a typed vendor failure, never best-effort: a
        // chmod or inventory error refuses the run before phase B can
        // execute against an unsealed tree (DEC-056).
        seal_read_only(&snapshot_dir)?;
        self.reconsult_phase_grants(admitted, check, receipt, native, owner, "test")?;
        phase_deadline_check(deadline, "test")?;
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(CheckError::TestCancel {
                detail: "cancellation before the test phase".to_string(),
            });
        }
        let replace_config = "source.crates-io.replace-with=\"rivect-vendor\"".to_string();
        let vendor_config = format!(
            "source.rivect-vendor.directory=\"{}\"",
            vendor_dest.display()
        );
        let mut test_args: Vec<std::ffi::OsString> =
            vec!["test".into(), "--locked".into(), "--offline".into()];
        match &check.target {
            CheckTarget::Library => test_args.push("--lib".into()),
            CheckTarget::Integration(name) => {
                test_args.push("--test".into());
                test_args.push(name.clone().into());
            }
        }
        test_args.push("-j".into());
        test_args.push("1".into());
        #[cfg(target_os = "macos")]
        test_args.extend(check_linker_config_args());
        test_args.extend([
            "--config".into(),
            replace_config.into(),
            "--config".into(),
            vendor_config.into(),
            "--manifest-path".into(),
            snapshot_dir.join(&check.manifest_rel).into_os_string(),
            "--target-dir".into(),
            rw.join("target").into_os_string(),
            "--".into(),
            "--exact".into(),
            check.exact_test.clone().into(),
            format!("--test-threads={}", check.harness_threads).into(),
            "--nocapture".into(),
        ]);
        let test_command = check_phase_command(check, &attempt_root, &test_args, true, &env)?;
        let test_command = test_command;
        let test = run_check_phase(test_command, cancel, deadline, &map_test_stop)?;
        // A selector that matched zero tests is neither a RED nor a
        // PASS: the transport observation refuses typed so a moved or
        // mistyped selector can never read as a passing check
        // (INV-004, `close.zero_tests`). Cargo prints one `running N
        // tests` line per selected binary; an all-zero set is the gap.
        let stdout_text = String::from_utf8_lossy(&test.stdout.head);
        let running_lines: Vec<&str> = stdout_text
            .lines()
            .filter(|line| line.contains("running ") && line.ends_with(" tests"))
            .collect();
        if !running_lines.is_empty()
            && running_lines
                .iter()
                .all(|line| line.ends_with("running 0 tests"))
        {
            return Err(CheckError::ZeroTests {
                detail: format!(
                    "the selector {} matched no test in the snapshot",
                    check.target.spelling()
                ),
            });
        }
        let summary = String::from_utf8_lossy(&test.stdout.head)
            .lines()
            .find(|line| line.contains("test result:"))
            .map(str::to_string);
        let (digest_v1, digest_v2) = check_command_digest(
            &project_digest,
            vendor_digest.as_deref(),
            &check.target.spelling(),
            &check.exact_test,
            check.harness_threads,
        );
        let run = CheckRun {
            attempt_root: Some(attempt_root),
            exit_code: test.status.code(),
            signal: test.status.signal(),
            stdout: test.stdout,
            stderr: test.stderr,
            project_digest,
            vendor_digest,
            check_digest_v1: digest_v1,
            check_digest_v2: digest_v2,
            summary,
            cleanup: cleanup_claim(),
        };
        let (_, owner_generation, owner_digest, owner_off) = owner;
        let custom = owner_off.then_some((owner_generation, owner_digest));
        // DEC-054: the owner context is reconsulted BEFORE the success
        // close — both variants. A config owner that moved while the
        // test phase ran refuses at the close-selection seam, so the
        // settle path records it as a failed close transport and the
        // success rows never read as a confirmed observation.
        let (owner_state, owner_generation, owner_digest, owner_off) = owner;
        if let Err(moved) =
            verify_owner_context(owner_state, owner_generation, owner_digest, owner_off)
        {
            return Err(CheckError::CloseSelection {
                detail: format!(
                    "the config owner moved before the close: {}",
                    moved.detail()
                ),
            });
        }
        self.close_check_rows(admitted, check, &run, native, custom)?;
        // DEC-047: transport success keeps the attempt root in place and
        // the verdict unclosed — the executor never decides RED/GREEN
        // and never confirms the attempt; a journey disposition (024)
        // owns the closing. The snapshot stays sealed; only the
        // executor's own failure path may remove a root.
        self.check_attempt_root = None;
        let detail = format!(
            "check-performed exit={} project={} vendor={}",
            run.exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "signal".to_string()),
            run.project_digest,
            run.vendor_digest.as_deref().unwrap_or("-")
        );
        self.store
            .set_attempt_state(&admitted.attempt_id, "running", Some(&detail))
            .map_err(|source| CheckError::EvidenceRetention {
                detail: format!("the attempt ledger observation failed: {source}"),
            })?;
        Ok(run)
    }

    /// The admission re-verification every check runs before spawn: the
    /// admitted effect is the Exec on the check's canonical Cargo, the
    /// Exec grant still admits, an independent project Read grant still
    /// admits and covers the project root, the task binding matches, and
    /// the cargo_home/attempt layout does not overlap.
    fn verify_check_admission(
        &mut self,
        admitted: &AdmittedEffect,
        check: &ConfinedCheck,
        native: bool,
    ) -> Result<(), CheckError> {
        let EffectRequest::Exec { grant_id, program } = &admitted.request else {
            return Err(CheckError::ExecGrant {
                detail: "the admitted effect is not an Exec".to_string(),
            });
        };
        if admitted.task_id != check.task_id {
            return Err(CheckError::SelectionMismatch {
                detail: "the admission belongs to a different task than the check".to_string(),
            });
        }
        // Native only: the store's current selection revision must still
        // equal the revision the check pinned — a selection changed
        // mid-run, or a check minted against a vanished selection,
        // refuses before any phase reconsult can falsely confirm
        // currency (CR-I5). A Custom-off check binds no native
        // selection (DEC-048 item 4).
        if native {
            let selection = self
                .store
                .plan_selection(&check.task_id)
                .map_err(|source| CheckError::EvidenceRetention {
                    detail: format!("the task selection is unreadable at admission: {source}"),
                })?;
            match selection {
                Some(record) if record.revision == check.expected_selection_revision => {}
                Some(record) => {
                    return Err(CheckError::SelectionMismatch {
                        detail: format!(
                            "the current selection revision {} is not the check's pinned {}",
                            record.revision, check.expected_selection_revision
                        ),
                    });
                }
                None => {
                    return Err(CheckError::SelectionMismatch {
                        detail: "no selection is recorded for the task the check binds".to_string(),
                    });
                }
            }
        }
        let canonical_cargo =
            check
                .cargo
                .canonicalize()
                .map_err(|source| CheckError::TargetLayout {
                    detail: format!("cargo canonicalization: {source}"),
                })?;
        if program != &canonical_cargo {
            return Err(CheckError::ExecGrant {
                detail: "the admitted Exec program is not the check's canonical cargo".to_string(),
            });
        }
        // Deny-first reconsult (DEC-054): an active grant never bypasses
        // the mode matrix or an enrolled deny. The check's own Exec on
        // the canonical Cargo and its project Read are decided exactly
        // like the generic path — before the claim, the copy, and both
        // phases — without a second dispatch or settlement.
        let exec_scope = self
            .policy
            .admit(grant_id, EffectClass::Exec)
            .map_err(|error| CheckError::ExecGrant {
                detail: format!("the exec grant no longer admits: {error}"),
            })?
            .scope_root
            .clone();
        let exec_context = admission_context(
            self.store,
            admitted.mode,
            EffectClass::Exec,
            grant_id,
            &exec_scope,
            &canonical_cargo,
        )
        .map_err(|error| CheckError::ExecGrant {
            detail: format!("the exec mode decision context refused: {error}"),
        })?;
        let exec_decision = self
            .policy
            .decide(&canonical_cargo, EffectClass::Exec, &exec_context);
        if exec_decision != ModeDecision::Allow {
            return Err(CheckError::ExecGrant {
                detail: format!(
                    "the mode decision denied the check exec: {}",
                    mode_reason(exec_decision)
                ),
            });
        }
        let project_scope = self
            .policy
            .admit(&check.project_grant_id, EffectClass::Read)
            .map_err(|error| CheckError::ProjectReadGrant {
                detail: format!("the project read grant no longer admits: {error}"),
            })?
            .scope_root
            .clone();
        let read_context = admission_context(
            self.store,
            admitted.mode,
            EffectClass::Read,
            &check.project_grant_id,
            &project_scope,
            &check.project_root,
        )
        .map_err(|error| CheckError::ProjectReadGrant {
            detail: format!("the project read mode decision context refused: {error}"),
        })?;
        let read_decision =
            self.policy
                .decide(&check.project_root, EffectClass::Read, &read_context);
        if read_decision != ModeDecision::Allow {
            return Err(CheckError::ProjectReadGrant {
                detail: format!(
                    "the mode decision denied the check project read: {}",
                    mode_reason(read_decision)
                ),
            });
        }
        let scope =
            project_scope
                .canonicalize()
                .map_err(|source| CheckError::ProjectReadGrant {
                    detail: format!("the project grant scope: {source}"),
                })?;
        let project =
            check
                .project_root
                .canonicalize()
                .map_err(|source| CheckError::ProjectReadGrant {
                    detail: format!("the project root: {source}"),
                })?;
        if !project.starts_with(&scope) {
            return Err(CheckError::ProjectReadGrant {
                detail: "the project root lies outside the read grant scope".to_string(),
            });
        }
        let cargo_home =
            check
                .cargo_home
                .canonicalize()
                .map_err(|source| CheckError::TargetLayout {
                    detail: format!("cargo_home canonicalization: {source}"),
                })?;
        if !cargo_home.is_absolute() || cargo_home == Path::new("/") {
            return Err(CheckError::TargetLayout {
                detail: "cargo_home is not an absolute canonical directory".to_string(),
            });
        }
        let attempt_probe = attempt_root_of(&admitted.attempt_id);
        if cargo_home.starts_with(&attempt_probe) || attempt_probe.starts_with(&cargo_home) {
            return Err(CheckError::TargetLayout {
                detail: "the attempt root overlaps the host cargo_home".to_string(),
            });
        }
        if project.starts_with(&attempt_probe) || attempt_probe.starts_with(&project) {
            return Err(CheckError::TargetLayout {
                detail: "the attempt root overlaps the project root".to_string(),
            });
        }
        // DEC-056: the cargo home is disjoint from every EFFECTIVE
        // sandbox read/execute root, derived from both platform profile
        // builders — before the claim, for both provider siblings.
        assert_cargo_home_disjoint(check, &cargo_home, &attempt_probe)?;
        Ok(())
    }

    /// Validates the DEC-042 pair through its opaque receipt: both
    /// entries of the issuer's pair are alive Read grants of the same
    /// allocation, minted for exactly this admission's attempt id, and
    /// their canonical scope roots are exactly the canonical cache and
    /// index roots of the check's cargo_home — the roots the issuer
    /// derived from the admission binding (DEC-048 item 2).
    fn verify_dependency_pair(
        &self,
        attempt_id: &str,
        check: &ConfinedCheck,
        receipt: &crate::policy::DependencyReceipt,
    ) -> Result<(), CheckError> {
        if receipt.cache_grant_id == receipt.index_grant_id {
            return Err(CheckError::DependencyGrant {
                detail: "the cache and index grants share one id".to_string(),
            });
        }
        // A pair minted for another attempt must not confirm this one's
        // ledger: the server-owned attempt id is part of the pair's
        // binding (CR-I5).
        if receipt.attempt_id != attempt_id {
            return Err(CheckError::DependencyGrant {
                detail: format!(
                    "the dependency pair was minted for attempt {other}, not {attempt_id}",
                    other = receipt.attempt_id
                ),
            });
        }
        let cargo_home =
            check
                .cargo_home
                .canonicalize()
                .map_err(|source| CheckError::DependencyGrant {
                    detail: format!("cargo_home canonicalization: {source}"),
                })?;
        let (cache, index) = self.policy.reconsult_check_pair(receipt).map_err(|error| {
            CheckError::DependencyGrant {
                detail: format!("the dependency pair does not admit: {error}"),
            }
        })?;
        for (grant, expected, label) in [
            (cache, cargo_home.join("registry/cache"), "cache"),
            (index, cargo_home.join("registry/index"), "index"),
        ] {
            let scope =
                grant
                    .scope_root
                    .canonicalize()
                    .map_err(|source| CheckError::DependencyGrant {
                        detail: format!("the {label} grant scope: {source}"),
                    })?;
            if scope != expected {
                return Err(CheckError::DependencyGrant {
                    detail: format!(
                        "the {label} grant root is not the canonical registry {label} root"
                    ),
                });
            }
        }
        Ok(())
    }

    /// The pre-spawn reconsult of both phases: Exec, project Read, and —
    /// when the lock names dependencies — the cache/index pair. A
    /// refusal keeps its failing category's own suffix under the phase
    /// prefix (`vendor.admit.exec`, `test.admit.read`, …) through the
    /// finite map — never an alias of every error to the dep seam.
    fn reconsult_phase_grants(
        &mut self,
        admitted: &AdmittedEffect,
        check: &ConfinedCheck,
        receipt: Option<&crate::policy::DependencyReceipt>,
        native: bool,
        owner: (&std::sync::Arc<WorkflowOffState>, u64, &str, bool),
        phase: &str,
    ) -> Result<(), CheckError> {
        if let Err(error) = self.verify_check_admission(admitted, check, native) {
            return Err(phase_admit_error(error, phase));
        }
        let (state, generation, sources_digest, explicit_off) = owner;
        if let Err(error) = verify_owner_context(state, generation, sources_digest, explicit_off) {
            return Err(phase_admit_error(error, phase));
        }
        if let Some(receipt) = receipt
            && let Err(error) = self.verify_dependency_pair(&admitted.attempt_id, check, receipt)
        {
            return Err(phase_admit_error(error, phase));
        }
        Ok(())
    }

    /// Retains one check seam row durably; a retention failure leaves the
    /// attempt root untouched and surfaces the typed retention failure.
    fn retain_check_row(
        &mut self,
        attempt_id: &str,
        site: &str,
        stage: crate::verification::RetainedStage,
        cause: &str,
    ) -> Result<(), CheckError> {
        let boundary_id = check_boundary_id(attempt_id, site);
        let record = crate::verification::RetainedAttempt {
            attempt_id: attempt_id.to_string(),
            boundary_id: boundary_id.clone(),
            stage,
            cause: cause.to_string(),
            digest: crate::verification::record_digest(attempt_id, cause),
            build_attempt: attempt_id.to_string(),
            admitted_attempt_id: Some(attempt_id.to_string()),
        };
        self.store
            .retain_attempt(&record)
            .map_err(|source| CheckError::EvidenceRetention {
                detail: format!("retaining {boundary_id} failed: {source}"),
            })
    }

    /// The close rows: the live selection (Native only) and inventory
    /// are rechecked and recorded, and the result row carries the
    /// observed exit, both check digests, the retained attempt root,
    /// and the journey-declared expected phase and assertion identity.
    /// DEC-047: the executor never decides RED/GREEN — there is no
    /// `close.confirmed` and the attempt stays unclosed until a journey
    /// disposition arrives. A Native selection whose revision moved
    /// since the check pinned it refuses typed here: no `close.result`
    /// follows, the settle path retains the refusal and rejects the
    /// ledger — the ledger never falsely asserts currency (CR-I5).
    fn close_check_rows(
        &mut self,
        admitted: &AdmittedEffect,
        check: &ConfinedCheck,
        run: &CheckRun,
        native: bool,
        custom: Option<(u64, &str)>,
    ) -> Result<(), CheckError> {
        if native {
            let selection = self
                .store
                .plan_selection(&check.task_id)
                .map_err(|source| CheckError::EvidenceRetention {
                    detail: format!("the task selection is unreadable at close: {source}"),
                })?;
            if !selection.is_some_and(|record| record.revision == check.expected_selection_revision)
            {
                return Err(CheckError::CloseSelection {
                    detail: format!(
                        "the task selection is not the check's pinned revision {} at close",
                        check.expected_selection_revision
                    ),
                });
            }
            self.retain_check_row(
                &admitted.attempt_id,
                "close.selection",
                crate::verification::RetainedStage::Terminal,
                "the task selection is current at close",
            )?;
        }
        let live = inventory(&check.project_root);
        let inventory_cause = match live {
            Ok(tree) if tree.digest == check.expected_candidate_digest => {
                "the live workspace matches the candidate at close"
            }
            Ok(_) => "the live workspace changed after the check bound its candidate",
            Err(_) => "the live workspace could not be inventoried at close",
        };
        self.retain_check_row(
            &admitted.attempt_id,
            "close.inventory",
            crate::verification::RetainedStage::Terminal,
            inventory_cause,
        )?;
        // DEC-054: a Custom close retains its authentic bounded owner
        // context (generation and sources digest) in the result row —
        // never a fabricated native selection.
        let custom_context = custom
            .map(|(generation, digest)| format!(" off-gen={generation} off-sources={digest}"))
            .unwrap_or_default();
        self.retain_check_row(
            &admitted.attempt_id,
            "close.result",
            crate::verification::RetainedStage::Terminal,
            &format!(
                "exit={} signal={:?} root={} phase={} assertion={} digest-v1={} digest-v2={}{}",
                run.exit_code
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                run.signal,
                run.attempt_root
                    .as_deref()
                    .map(|root| root.to_string_lossy())
                    .unwrap_or_else(|| "-".into()),
                check.expected_phase,
                check.expected_assertion_identity,
                run.check_digest_v1,
                run.check_digest_v2,
                custom_context,
            ),
        )
    }

    /// Settles one failed check: the failing seam's terminal row and the
    /// ledger row rejected. The dependency pair's cleanup belongs to
    /// the admission owner — `release_check_dependencies` /
    /// `consume_check_pair` in [`Executor::execute_check`] — never to
    /// the settle path. A retention failure keeps the original cause
    /// inside the retention error and deliberately leaves any attempt
    /// root in place.
    fn settle_check_failure(
        &mut self,
        admitted: &AdmittedEffect,
        error: CheckError,
    ) -> ExecutorError {
        let site = error.site();
        // A failure at a success-close site must stay distinguishable
        // from a successful close observation forever: the fixed
        // structured prefix is durable evidence in the retained row —
        // the site keeps its owner, and the settlement predicate reads
        // the marker, never prose (DEC-054).
        let cause = if SUCCESS_CLOSE_SITES.contains(&site) {
            format!("{FAILED_CLOSE_TRANSPORT}: {}", error.cause())
        } else {
            error.cause()
        };
        if let Err(retention) = self.retain_check_row(
            &admitted.attempt_id,
            site,
            crate::verification::RetainedStage::Terminal,
            &cause,
        ) {
            return ExecutorError::Check(CheckError::EvidenceRetention {
                detail: format!(
                    "the original failure ({cause}) could not be retained: {}",
                    retention.cause()
                ),
            });
        }
        if let Err(store_error) = self.store.attempt_rejected(&admitted.attempt_id, &cause) {
            return ExecutorError::Check(CheckError::EvidenceRetention {
                detail: format!("the attempt ledger rejection failed: {store_error}"),
            });
        }
        // Attempt-root cleanup decision, bound to the failing attempt's
        // own allocation: the terminal row is retained, so the durable
        // evidence already outlives the root. A root preserved by an
        // earlier attempt's retention failure — or any other attempt's —
        // is not this failure's to clean. Only an absent root retires
        // the cleanup authority durably; a present root is refused
        // before any destructive effect (DEC-056), leaves its debris,
        // retires nothing, and is named on the returned refusal — it
        // never overwrites the cause.
        let Some(root) = self.check_attempt_root.take() else {
            return ExecutorError::Check(error);
        };
        if root.attempt_id != admitted.attempt_id {
            return ExecutorError::Check(error);
        }
        let outcome = remove_recorded_attempt_root(&root.canonical_root, root.dev, root.ino);
        if let Some(cause) = retirement_cause(&outcome)
            && let Err(retention) = self.retain_check_row(
                &admitted.attempt_id,
                "cleanup.root",
                crate::verification::RetainedStage::Terminal,
                cause,
            )
        {
            return ExecutorError::Check(CheckError::EvidenceRetention {
                detail: format!(
                    "the cleanup retirement row failed after the cleanup: {}",
                    retention.cause()
                ),
            });
        }
        match outcome {
            RootRemoval::Refused(reason) => ExecutorError::Check(
                error.with_note(&format!("attempt root cleanup refused: {reason}")),
            ),
            RootRemoval::Absent => ExecutorError::Check(error),
        }
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

/// Platform-routed checked write: Landlock on Linux, Seatbelt otherwise.
///
/// Same dispatch as [`backend`] and `Runtime::open`.
///
/// # Errors
/// Returns the platform writer's [`WorkerError`].
pub fn write_once(
    scope_root: &Path,
    target: &Path,
    expected: WriteIdentity,
    bytes: &[u8],
) -> Result<(), WorkerError> {
    #[cfg(target_os = "linux")]
    {
        linux::write_once(scope_root, target, expected, bytes)
    }
    #[cfg(not(target_os = "linux"))]
    {
        macos::write_once(scope_root, target, expected, bytes)
    }
}

// ---------------------------------------------------------------------------
// Confined Cargo check (DEC-040/041/042, SLICE-178): one admitted Exec
// effect runs an immutable candidate snapshot through two Cargo phases
// (vendor, then test) inside the platform sandbox via the helper's check
// resource profile. The trusted parent owns admission, inventory, snapshot,
// dependency staging, promotion, capture, cancellation, and the attempt
// ledger; the child never sees the host cache, config, credentials, or
// network.
// ---------------------------------------------------------------------------

/// The one-shot retained-boundary prefix every check seam keys on:
/// `ret:check:<attempt-id>:<site>`.
pub const CHECK_BOUNDARY: &str = "check";

/// The retained-boundary suffixes a successful close transport writes:
/// an observation of a returned `CheckRun`, never a failed provider
/// result.
pub(crate) const SUCCESS_CLOSE_SITES: [&str; 3] =
    ["close.selection", "close.inventory", "close.result"];

/// The fixed structured prefix a failed close transport carries in its
/// retained row at a success-close site: the durable discriminator the
/// settlement predicate reads — the site keeps its one owner, and a
/// successful observation never carries the marker.
pub(crate) const FAILED_CLOSE_TRANSPORT: &str = "close-transport-failed";

/// Retained boundary id of one check emit site.
#[must_use]
pub fn check_boundary_id(attempt_id: &str, site: &str) -> String {
    format!("ret:{CHECK_BOUNDARY}:{attempt_id}:{site}")
}

/// The phase of one check admission (DEC-048): `Pending` until the
/// first-only claim commits, `Claimed` for the owning dispatch, and
/// `Spent` once a pre-claim release consumed the allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckPhase {
    Pending,
    Claimed,
    Spent,
}

/// The owner-derived immutable process context of one admission
/// (DEC-048 item 1): `Native` binds the store's actual selection
/// revision, facts digest, and request kind; `Custom` binds the
/// resolved explicit workflow-off of the config owner with its
/// sources digest — never a native selection or a sentinel revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckContext {
    Native {
        selection_revision: u64,
        facts_digest: String,
        request_kind: crate::state::RequestKind,
        /// The config-owner generation and sources digest the Native
        /// admission bound: any meaningful owner transition — a workflow
        /// toggle included — invalidates the admission (DEC-054).
        owner_generation: u64,
        owner_sources_digest: String,
    },
    Custom {
        sources_digest: String,
        generation: u64,
    },
}

/// The immutable binding one confined check claims under: the identity
/// of the owning Policy/TaskStore instances, the server-owned
/// attempt/task, the original request/program/mode/scope and project
/// Read, the canonical project/manifest/Cargo/cargo_home, the candidate
/// production digest, the full selector, and the journey-declared
/// expected phase and assertion identity (DEC-047).
struct CheckBinding {
    task_id: TaskId,
    attempt_id: String,
    project_grant_id: String,
    project_root: PathBuf,
    manifest_rel: PathBuf,
    cargo: PathBuf,
    cargo_home: PathBuf,
    target: CheckTarget,
    harness_threads: u32,
    exact_test: String,
    expected_selection_revision: u64,
    expected_candidate_digest: String,
    expected_phase: String,
    expected_assertion_identity: String,
}

impl CheckBinding {
    /// The opaque digest of the whole binding: any field mutation a
    /// re-presentation carries refuses at `admit.binding` against it.
    fn digest(&self) -> String {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.task_id.0.as_bytes());
        hasher.update(self.attempt_id.as_bytes());
        hasher.update(self.project_grant_id.as_bytes());
        hasher.update(self.project_root.to_string_lossy().as_bytes());
        hasher.update(self.manifest_rel.to_string_lossy().as_bytes());
        hasher.update(self.cargo.to_string_lossy().as_bytes());
        hasher.update(self.cargo_home.to_string_lossy().as_bytes());
        hasher.update(self.target.spelling().as_bytes());
        hasher.update(self.harness_threads.to_string().as_bytes());
        hasher.update(self.exact_test.as_bytes());
        hasher.update(self.expected_selection_revision.to_string().as_bytes());
        hasher.update(self.expected_candidate_digest.as_bytes());
        hasher.update(self.expected_phase.as_bytes());
        hasher.update(self.expected_assertion_identity.as_bytes());
        hex(&hasher.finalize())
    }
}

/// The opaque issuer-bound check admission (DEC-048 item 1): the real
/// planned Exec effect, the immutable binding, and the owner-derived
/// context. No public constructor, `Clone`, or serde exists; `Debug`
/// hides every right. Only [`Executor::admit_check`] mints one.
pub struct CheckAdmission {
    admitted: AdmittedEffect,
    policy_identity: std::sync::Arc<()>,
    store_identity: std::sync::Arc<()>,
    binding: CheckBinding,
    context: CheckContext,
    /// The live config-owner state every reconsult reads — both variants:
    /// a Native admission invalidates on a meaningful owner transition
    /// (a workflow toggle included) exactly like a Custom one.
    off_state: std::sync::Arc<WorkflowOffState>,
    phase: CheckPhase,
    /// The opaque allocation identity: entries of the dependency pair
    /// link to it weakly, so dropping the admission ends the
    /// allocation without a registry.
    allocation: std::sync::Arc<()>,
    receipt: Option<crate::policy::DependencyReceipt>,
}

impl std::fmt::Debug for CheckAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Task, attempt, and phase only: no grant, root, or receipt.
        f.debug_struct("CheckAdmission")
            .field("task_id", &self.binding.task_id.0)
            .field("attempt_id", &self.binding.attempt_id)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl CheckAdmission {
    pub(crate) fn policy_identity(&self) -> &std::sync::Arc<()> {
        &self.policy_identity
    }

    pub(crate) fn store_identity(&self) -> &std::sync::Arc<()> {
        &self.store_identity
    }

    pub(crate) fn allocation(&self) -> &std::sync::Arc<()> {
        &self.allocation
    }

    pub(crate) fn attempt_id(&self) -> &str {
        &self.binding.attempt_id
    }

    /// The bound attempt id on the public surface (already shown by
    /// `Debug`; no right travels with it).
    pub fn bound_attempt_id(&self) -> &str {
        &self.binding.attempt_id
    }

    /// The bound cargo home the issuer derives its cache/index roots
    /// from (DEC-048 item 2): read-only access for
    /// [`crate::policy::Policy::issue_check_dependencies`].
    pub(crate) fn bound_cargo_home(&self) -> &Path {
        &self.binding.cargo_home
    }

    /// The bound task the issuer's live owner/store reconsult reads.
    pub(crate) fn bound_task_id(&self) -> &TaskId {
        &self.binding.task_id
    }

    pub(crate) fn is_pending(&self) -> bool {
        self.phase == CheckPhase::Pending
    }

    pub(crate) fn is_spent(&self) -> bool {
        self.phase == CheckPhase::Spent
    }

    pub(crate) fn receipt(&self) -> Option<&crate::policy::DependencyReceipt> {
        self.receipt.as_ref()
    }

    pub(crate) fn set_receipt(&mut self, receipt: crate::policy::DependencyReceipt) {
        self.receipt = Some(receipt);
    }

    pub(crate) fn mark_spent(&mut self) {
        self.phase = CheckPhase::Spent;
    }

    /// The current phase on the public surface (DEC-048 item 7 proofs).
    pub fn phase(&self) -> CheckPhase {
        self.phase
    }

    /// The bound context on the public surface.
    pub fn context(&self) -> &CheckContext {
        &self.context
    }

    /// Whether a pending admission may still be issued a dependency
    /// pair: a receipt is present and the pair has not been consumed.
    pub fn holds_receipt(&self) -> bool {
        self.receipt.is_some()
    }

    /// The owner-context reconsult binding: the live state plus the
    /// bound generation, sources digest, and mode flag.
    pub(crate) fn owner_view(&self) -> (&std::sync::Arc<WorkflowOffState>, u64, &str, bool) {
        let (generation, sources_digest, explicit_off) = match &self.context {
            CheckContext::Native {
                owner_generation,
                owner_sources_digest,
                ..
            } => (*owner_generation, owner_sources_digest.as_str(), false),
            CheckContext::Custom {
                generation,
                sources_digest,
                ..
            } => (*generation, sources_digest.as_str(), true),
        };
        (&self.off_state, generation, sources_digest, explicit_off)
    }

    pub(crate) fn admitted(&self) -> &AdmittedEffect {
        &self.admitted
    }

    fn bound(&self) -> &CheckBinding {
        &self.binding
    }

    pub(crate) fn mark_claimed(&mut self) {
        self.phase = CheckPhase::Claimed;
    }

    pub(crate) fn is_native(&self) -> bool {
        matches!(self.context, CheckContext::Native { .. })
    }

    /// The DEC-048 claim binding of this admission: the explicit
    /// variant flag carries the process-context kind — a Native claim
    /// binds the actual selection facts, a Custom-off claim carries no
    /// native selection, so the claim skips the selection and gate
    /// statements by the flag, never by sentinel field values.
    pub(crate) fn claim_binding(&self) -> crate::state::CheckClaim {
        let native = matches!(self.context, CheckContext::Native { .. });
        let (selection_revision, facts_digest, request_kind) = match &self.context {
            CheckContext::Native {
                selection_revision,
                facts_digest,
                request_kind,
                ..
            } => (*selection_revision, facts_digest.clone(), *request_kind),
            // Never read on the Custom path: the store consults only
            // the explicit `native` flag.
            CheckContext::Custom { .. } => (0, String::new(), crate::state::RequestKind::PlanOnly),
        };
        crate::state::CheckClaim {
            task_id: self.binding.task_id.clone(),
            attempt_id: self.binding.attempt_id.clone(),
            native,
            selection_revision,
            facts_digest,
            request_kind,
            binding_digest: self.binding.digest(),
        }
    }
}

/// The config owner's live view of its effective snapshot (DEC-054): a
/// monotonic generation, the actual workflow mode, and the current
/// sources digest. The Runtime refreshes it whenever its effective
/// snapshot changes — a toggle, an edit, a rollback, or a landed
/// publication error — and every admission reconsult compares its bound
/// generation/mode/digest against it, so a toggled, stale, or unknown
/// context refuses instead of silently reading as current. Returning to
/// byte-identical sources still moves the generation: off→on→off never
/// resurrects an older admission's authority. The digest is not a
/// right; `Debug` keeps it hidden anyway.
pub struct WorkflowOffState {
    snapshot: std::sync::Mutex<OwnerSnapshot>,
}

/// The actual workflow mode of the owner's effective snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowOwnerMode {
    /// `workflow.enabled` is not an explicit user `false`.
    Enabled,
    /// A visible user-sourced `workflow.enabled = false`.
    ExplicitOff,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnerSnapshot {
    generation: u64,
    mode: WorkflowOwnerMode,
    sources_digest: String,
}

impl WorkflowOffState {
    pub(crate) fn new(config: &crate::config::EffectiveConfig) -> Self {
        let state = Self {
            snapshot: std::sync::Mutex::new(OwnerSnapshot {
                generation: 0,
                mode: WorkflowOwnerMode::Enabled,
                sources_digest: String::new(),
            }),
        };
        state.refresh(config);
        state
    }

    /// Re-resolves the owner's current snapshot from the config owner's
    /// actual effective state. A meaningful transition — the mode or the
    /// sources digest moved — bumps the monotonic generation; an
    /// identical refresh is idempotent.
    pub(crate) fn refresh(&self, config: &crate::config::EffectiveConfig) {
        let mode = owner_mode(config);
        // A poisoned holder never observed a torn value: the snapshot is
        // always one whole `OwnerSnapshot`, so recovery is sound here.
        let mut snapshot = self
            .snapshot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if snapshot.mode != mode || snapshot.sources_digest != config.sources_digest {
            snapshot.generation = snapshot.generation.saturating_add(1);
            snapshot.mode = mode;
            snapshot.sources_digest = config.sources_digest.clone();
        }
    }

    /// Records one applied edit transition — an accepted retained edit,
    /// its landed publication error, or its rollback — by moving the
    /// generation unconditionally: the applied effective document
    /// changed even when the mode and the sources digest did not, so no
    /// older handoff may read as current across it.
    pub(crate) fn advance(&self, config: &crate::config::EffectiveConfig) {
        let mode = owner_mode(config);
        let mut snapshot = self
            .snapshot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        snapshot.generation = snapshot.generation.saturating_add(1);
        snapshot.mode = mode;
        snapshot.sources_digest = config.sources_digest.clone();
    }

    /// Whether the owner's current snapshot still lets a native dispatch
    /// start (AC-024): only an explicit user off closes it. Read from the
    /// owner itself at every entry, never from a copy a caller kept.
    pub(crate) fn native_dispatch_open(&self) -> bool {
        self.current().1 == WorkflowOwnerMode::Enabled
    }

    /// The current owner snapshot: (generation, mode, sources digest).
    pub(crate) fn current(&self) -> (u64, WorkflowOwnerMode, String) {
        let snapshot = self
            .snapshot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            snapshot.generation,
            snapshot.mode,
            snapshot.sources_digest.clone(),
        )
    }
}

/// The opaque Runtime-issued check handoff (DEC-054): constructed only
/// from the config owner's live state with the task, the issuing
/// Runtime's Policy/TaskStore identities, the monotonic generation, the
/// sources digest, and the actual workflow mode bound in. Public callers
/// cannot mint, clone, or serialize one, and a handoff minted by another
/// Runtime's pair refuses before planning on this one. A Custom
/// admission requires the bound mode `ExplicitOff` (the owner-derived
/// explicit false); a Native admission binds the same owner context and
/// invalidates on any meaningful transition too.
pub struct CheckHandoff {
    state: std::sync::Arc<WorkflowOffState>,
    generation: u64,
    sources_digest: String,
    explicit_off: bool,
    task_id: TaskId,
    policy_identity: std::sync::Arc<()>,
    store_identity: std::sync::Arc<()>,
}

impl CheckHandoff {
    /// The one constructor, owner-private: binds the config owner's
    /// CURRENT snapshot (generation, mode, digest) and the task the
    /// check will be admitted for.
    pub(crate) fn from_owner(
        state: &std::sync::Arc<WorkflowOffState>,
        task_id: &TaskId,
        policy_identity: std::sync::Arc<()>,
        store_identity: std::sync::Arc<()>,
    ) -> Self {
        let (generation, mode, sources_digest) = state.current();
        Self {
            state: std::sync::Arc::clone(state),
            generation,
            sources_digest,
            explicit_off: mode == WorkflowOwnerMode::ExplicitOff,
            task_id: task_id.clone(),
            policy_identity,
            store_identity,
        }
    }

    pub(crate) fn state(&self) -> &std::sync::Arc<WorkflowOffState> {
        &self.state
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn sources_digest(&self) -> &str {
        &self.sources_digest
    }

    /// Whether the bound owner context is the explicit user
    /// workflow-off — the only context a Custom admission may carry.
    pub(crate) fn explicit_off(&self) -> bool {
        self.explicit_off
    }

    /// The task this handoff was issued for.
    pub(crate) fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// The issuing Runtime's Policy identity a presentation must match.
    pub(crate) fn policy_identity(&self) -> &std::sync::Arc<()> {
        &self.policy_identity
    }

    /// The issuing Runtime's TaskStore identity a presentation must
    /// match.
    pub(crate) fn store_identity(&self) -> &std::sync::Arc<()> {
        &self.store_identity
    }
}

impl std::fmt::Debug for CheckHandoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No digest or owner identity leaks through Debug.
        f.debug_struct("CheckHandoff").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for WorkflowOffState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkflowOffState").finish_non_exhaustive()
    }
}

/// The explicit user workflow-off predicate shared by the refresh: a
/// visible `workflow.enabled = false` whose source is the user's own
/// config — never a shipped default.
fn explicit_user_off(config: &crate::config::EffectiveConfig) -> bool {
    matches!(
        (
            &config.workflow_entry.effective,
            config.workflow_entry.source.kind.as_str()
        ),
        (
            crate::config::ConfigViewValue::Visible {
                value: serde_json::Value::Bool(false),
            },
            "user",
        )
    )
}

/// The owner's actual workflow mode for one effective snapshot.
fn owner_mode(config: &crate::config::EffectiveConfig) -> WorkflowOwnerMode {
    if explicit_user_off(config) {
        WorkflowOwnerMode::ExplicitOff
    } else {
        WorkflowOwnerMode::Enabled
    }
}

/// The owner-context reconsult both variants run: the bound generation,
/// mode, and sources digest must still be the config owner's current
/// snapshot. A toggled, stale, or moved context refuses — it never
/// reads as current, and returning to identical bytes never resurrects
/// an older generation. Crate-visible: the issuer's reconsult shares it.
pub(crate) fn verify_owner_context(
    state: &WorkflowOffState,
    generation: u64,
    sources_digest: &str,
    explicit_off: bool,
) -> Result<(), CheckError> {
    let (current, mode, digest) = state.current();
    if current != generation {
        return Err(CheckError::SelectionMismatch {
            detail: format!(
                "the config owner moved: generation {current} is not the bound {generation}"
            ),
        });
    }
    if (mode == WorkflowOwnerMode::ExplicitOff) != explicit_off {
        return Err(CheckError::SelectionMismatch {
            detail: if explicit_off {
                "the bound explicit workflow-off is no longer the owner's mode: the workflow was toggled"
                    .to_string()
            } else {
                "the workflow was toggled off after the native admission bound an enabled owner"
                    .to_string()
            },
        });
    }
    if digest != sources_digest {
        return Err(CheckError::SelectionMismatch {
            detail:
                "the workflow-off context is stale: the config sources changed since the handoff"
                    .to_string(),
        });
    }
    Ok(())
}

/// The finite admission-category map of the phase reconsults: each of
/// the five categories keeps its own suffix under the phase prefix, so
/// a failing exec stays distinguishable from a failing read, dep,
/// selection, or target at both phases. Any other failure site returns
/// `None` and keeps its own variant untouched.
fn phase_admit_site(category: &'static str, phase: &str) -> Option<&'static str> {
    match (category, phase) {
        ("admit.exec", "test") => Some("test.admit.exec"),
        ("admit.exec", _) => Some("vendor.admit.exec"),
        ("admit.read", "test") => Some("test.admit.read"),
        ("admit.read", _) => Some("vendor.admit.read"),
        ("admit.dep", "test") => Some("test.admit.dep"),
        ("admit.dep", _) => Some("vendor.admit.dep"),
        ("admit.selection", "test") => Some("test.admit.selection"),
        ("admit.selection", _) => Some("vendor.admit.selection"),
        ("admit.target", "test") => Some("test.admit.target"),
        ("admit.target", _) => Some("vendor.admit.target"),
        _ => None,
    }
}

/// Wraps one failing phase-reconsult category in its phase-specific
/// admission site: the category survives under the phase prefix and the
/// wire code stays a denied effect; a non-category failure is returned
/// unchanged with its own variant and site.
fn phase_admit_error(error: CheckError, phase: &str) -> CheckError {
    let Some(site) = phase_admit_site(error.site(), phase) else {
        return error;
    };
    let detail = error.detail().to_string();
    if phase == "test" {
        CheckError::TestAdmit { site, detail }
    } else {
        CheckError::VendorAdmit { site, detail }
    }
}

/// The shared absolute deadline gate before each phase spawns: an
/// expired budget refuses typed before any effect — never a fresh full
/// budget for phase B (DEC-056).
fn phase_deadline_check(deadline: Instant, phase: &str) -> Result<(), CheckError> {
    if Instant::now() >= deadline {
        return Err(if phase == "test" {
            CheckError::TestDeadline {
                detail: "the shared check deadline expired before the test phase".to_string(),
            }
        } else {
            CheckError::VendorDeadline {
                detail: "the shared check deadline expired before the vendor phase".to_string(),
            }
        });
    }
    Ok(())
}

/// The typed test-target selector of one confined check (DEC-054): a
/// private-unit (`--lib`) run or one named integration target
/// (`--test <name>`). The selector never travels as a bare string, so
/// it cannot slip into an option position of the Cargo argv, and it is
/// part of the admission binding — a re-presented check with a moved
/// selector refuses at `admit.binding`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckTarget {
    /// The crate's own private unit tests (`cargo test --lib`).
    Library,
    /// One named integration test target (`cargo test --test <name>`).
    Integration(String),
}

impl CheckTarget {
    /// The stable selector spelling the binding digest and the
    /// `cargo-test` command identity carry.
    #[must_use]
    pub fn spelling(&self) -> String {
        match self {
            Self::Library => "lib".to_string(),
            Self::Integration(name) => format!("test:{name}"),
        }
    }

    /// Whether the selector is a plain target name: it never starts with
    /// `-`, so it can never read as an option of the Cargo argv.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        match self {
            Self::Library => true,
            Self::Integration(name) => plain_selector(name, false),
        }
    }
}

/// A plain identifier-shaped selector token: non-empty, ASCII
/// alphanumerics and `_`, plus `-` in a target name or `::` module
/// separators in a test path, and never a leading `-`.
#[must_use]
fn plain_selector(token: &str, module_path: bool) -> bool {
    !token.is_empty()
        && !token.starts_with('-')
        && token.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || c == '_'
                || (c == '-' && !module_path)
                || (c == ':' && module_path)
        })
}

/// The ceiling on one check's harness threads: the thread count is part
/// of the admission binding, so a presentation cannot widen it after
/// the fact.
pub const CHECK_MAX_HARNESS_THREADS: u32 = 8;

/// Everything one confined check binds before any effect byte: the task
/// and candidate identity, the selection revision the candidate was
/// admitted under, the project Read grant, the canonical toolchain
/// Cargo, the canonical cargo home, the exact test selection, and the
/// optional dependency Read pair. Target and exact-test travel as
/// separate fields and never enter an option position of the Cargo
/// argv.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfinedCheck {
    /// The task the admitted Exec effect belongs to; a mismatch with the
    /// admission denies before spawn (`admit.selection`).
    pub task_id: TaskId,
    /// The selection revision the candidate digest was recorded under;
    /// every phase reconsult and the close recheck refuse typed when the
    /// store's current revision has moved (`admit.selection` /
    /// `close.selection`).
    pub expected_selection_revision: u64,
    /// Independent active project Read grant covering `project_root`.
    pub project_grant_id: String,
    /// The live workspace root whose candidate digest is pinned.
    pub project_root: PathBuf,
    /// Workspace manifest, relative to the project root.
    pub manifest_rel: PathBuf,
    /// Canonical toolchain `cargo` (never the rustup proxy — the proxy
    /// directory is not a toolchain root and refuses at `admit.target`).
    pub cargo: PathBuf,
    /// Absolute canonical Cargo home owning the registry cache/index.
    pub cargo_home: PathBuf,
    /// The typed test-target selector (`--lib` or one `--test <name>`).
    pub target: CheckTarget,
    /// The bounded harness thread count of the test phase: the libtest
    /// `--test-threads` value (Cargo's own `-j` stays 1), part of the
    /// admission binding.
    pub harness_threads: u32,
    /// The exact test filter after `--` (an identifier, never argv
    /// punctuation that could inject options).
    pub exact_test: String,
    /// The journey-declared expected phase (DEC-047): the executor
    /// never decides RED/GREEN; this identity travels into the
    /// retained close rows.
    pub expected_phase: String,
    /// The journey-declared expected assertion identity (DEC-047).
    pub expected_assertion_identity: String,
    /// The recorded candidate digest the copied bytes must reproduce.
    pub expected_candidate_digest: String,
}

/// Head+tail+total bounded capture of one child stream: the retained head
/// and tail are each bounded by [`CHECK_CAPTURE_EDGE_BYTES`] while `total`
/// counts every byte the stream produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedCapture {
    pub head: Vec<u8>,
    pub tail: Vec<u8>,
    pub total: u64,
}

impl BoundedCapture {
    fn empty() -> Self {
        Self {
            head: Vec::new(),
            tail: Vec::new(),
            total: 0,
        }
    }

    fn extend(&mut self, bytes: &[u8]) {
        self.total = self.total.saturating_add(bytes.len() as u64);
        let room = CHECK_CAPTURE_EDGE_BYTES.saturating_sub(self.head.len());
        self.head.extend_from_slice(&bytes[..bytes.len().min(room)]);
        // Tail: keep the newest `CHECK_CAPTURE_EDGE_BYTES` bytes of the
        // whole stream.
        let overflow = (self.tail.len() + bytes.len()).saturating_sub(CHECK_CAPTURE_EDGE_BYTES);
        let drop_front = overflow.min(self.tail.len());
        if drop_front > 0 {
            self.tail.drain(..drop_front);
        }
        let room = CHECK_CAPTURE_EDGE_BYTES.saturating_sub(self.tail.len());
        // When the chunk itself overflows the room, the tail keeps the
        // chunk's NEWEST bytes — its last `room` — not its first.
        let keep = bytes.len().saturating_sub(room);
        self.tail.extend_from_slice(&bytes[keep..]);
    }
}

/// What the executor honestly claims about the attempt root and the
/// descendants after the check ended (DEC-041): Linux proves descendant
/// stop (setsid/setpgid are denied by the check filter), while macOS keeps
/// an explicit residual — a typed stop is not a proof of death, and an
/// empty group never proves absence of a `setsid` child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupClaim {
    /// Linux: the process group was empty after the stop, inside the PID
    /// namespace that confines the run.
    DescendantsStopped,
    /// macOS accepted residual: best-effort killpg plus per-process
    /// rlimits bound the ordinary path; a `setsid` survivor may outlive
    /// the stop and hold hold-free unlinked-open bytes. Never a
    /// full-cleanup claim.
    MacosBestEffort,
}

/// The completed outcome of one confined check. A nonzero `exit_code` is a
/// legitimate observation (a real RED), never an `Err` by itself.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckRun {
    /// The exclusive attempt root the run owned (None after clean
    /// cleanup).
    pub attempt_root: Option<PathBuf>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: BoundedCapture,
    pub stderr: BoundedCapture,
    /// Digest of the sealed project snapshot the run proved.
    pub project_digest: String,
    /// Digest of the promoted, verified vendor tree (dependency runs).
    pub vendor_digest: Option<String>,
    /// `cargo-test-v1` identity: target + exact test + project digest.
    pub check_digest_v1: String,
    /// `cargo-test-v2` identity: v1 inputs plus the vendor digest.
    pub check_digest_v2: String,
    /// The bounded "test result:" summary line when Cargo printed one.
    pub summary: Option<String>,
    pub cleanup: CleanupClaim,
}

/// Upper bound on each retained capture edge (head and tail separately).
pub const CHECK_CAPTURE_EDGE_BYTES: usize = 8 * 1024;
/// Per-file ceiling of the bounded workspace inventory.
pub const INVENTORY_FILE_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// Whole-tree byte ceiling of the bounded workspace inventory.
pub const INVENTORY_TREE_MAX_BYTES: u64 = 256 * 1024 * 1024;
/// Whole-tree entry ceiling of the bounded workspace inventory.
pub const INVENTORY_MAX_ENTRIES: usize = 20_000;
/// Depth ceiling of the bounded workspace inventory walk.
pub const INVENTORY_MAX_DEPTH: usize = 48;
/// Per-archive ceiling for one staged `.crate` (separate from the 1 MiB
/// read cap: Cargo archives must not be silently capped by it).
pub const DEP_ARCHIVE_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Per-entry ceiling for one staged offline-index file.
pub const DEP_INDEX_ENTRY_MAX_BYTES: u64 = 1024 * 1024;
/// Total staged-byte ceiling across one attempt's dependency staging.
pub const DEP_STAGED_MAX_BYTES: u64 = 512 * 1024 * 1024;
/// Wall deadline for each confined phase.
pub const CHECK_PHASE_DEADLINE: Duration = Duration::from_secs(600);

/// A check phase's semantic failure and original owning-launch diagnostic.
#[derive(Debug, Clone)]
pub struct OwnedCheckSource {
    primary: Box<CheckError>,
    worker: std::sync::Arc<WorkerError>,
}

impl PartialEq for OwnedCheckSource {
    fn eq(&self, other: &Self) -> bool {
        self.primary == other.primary
    }
}
impl Eq for OwnedCheckSource {}
impl std::fmt::Display for OwnedCheckSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.worker.fmt(formatter)
    }
}
impl std::error::Error for OwnedCheckSource {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.worker.as_ref())
    }
}

/// Every distinct failure emit site of the confined check, one retained
/// seam each: a collapsed site id loses the one-shot offline correction
/// after cleanup (D-123/D-124). `detail` stays bounded and non-secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckError {
    #[error("check owned launch failed: {detail}")]
    OwnedLaunch {
        detail: String,
        #[source]
        source: OwnedCheckSource,
    },
    /// `admit.exec` — the admitted effect is not the Exec on the check's
    /// canonical Cargo, or the grant is revoked/unknown/wrong class.
    #[error("check exec admission denied: {detail}")]
    ExecGrant { detail: String },
    /// `admit.read` — no independent active project Read grant.
    #[error("check project read admission denied: {detail}")]
    ProjectReadGrant { detail: String },
    /// `admit.dep` — the cache/index Read pair is not two distinct active
    /// single-root grants on exactly the canonical roots.
    #[error("check dependency admission denied: {detail}")]
    DependencyGrant { detail: String },
    /// `admit.selection` — task/selection/revision binding mismatch.
    #[error("check selection binding denied: {detail}")]
    SelectionMismatch { detail: String },
    /// `admit.target` — canonical Cargo/toolchain/cargo-home/attempt-root
    /// layout refused before spawn.
    #[error("check target layout refused: {detail}")]
    TargetLayout { detail: String },
    /// `snapshot.inventory` — the workspace tree is not bounded-inventory
    /// safe (hardlink, special, non-UTF-8, oversized, too deep).
    #[error("check workspace inventory refused: {detail}")]
    InventoryRefused { detail: String },
    /// `snapshot.copy` — copying into the fresh attempt root failed.
    #[error("check snapshot copy failed: {detail}")]
    CopyFailed { detail: String },
    /// `snapshot.digest` — copied bytes do not reproduce the recorded
    /// candidate digest.
    #[error("check snapshot digest mismatch: {detail}")]
    DigestMismatch { detail: String },
    /// `dep.lock` — the lockfile cannot be parsed or names an unsupported
    /// source kind.
    #[error("check lockfile refused: {detail}")]
    LockRefused { detail: String },
    /// `dep.cache_scope` — registry dependencies exist but no complete
    /// cache/index Read pair was provided (a setup gap before any cache
    /// access, never a RED).
    #[error("check dependency cache scope missing: {detail}")]
    CacheScope { detail: String },
    /// `dep.cache_revoked` — a dependency Read grant was revoked mid-run.
    #[error("check dependency grant revoked: {detail}")]
    CacheRevoked { detail: String },
    /// `dep.cache_denied` — a dependency Read grant no longer admits.
    #[error("check dependency grant denied: {detail}")]
    CacheDenied { detail: String },
    /// `dep.cache_root_fd` — the fd-anchored walk could not pin the
    /// filesystem root or a cargo-home component.
    #[error("check dependency root fd refused: {detail}")]
    CacheRootFd { detail: String },
    /// `dep.cache_component` — a walk component (or nested index
    /// component) is a symlink, missing, or of the wrong kind.
    #[error("check dependency component refused: {detail}")]
    CacheComponent { detail: String },
    /// `dep.cache_ancestry` — the pinned lineage changed between checks.
    #[error("check dependency ancestry drifted: {detail}")]
    CacheAncestry { detail: String },
    /// `dep.cache_capability` — the platform lacks the fd-open capability;
    /// a typed setup refusal, never a weaker fallback.
    #[error("check dependency capability unsupported: {detail}")]
    CacheCapability { detail: String },
    /// `dep.cache_leaf` — the required leaf open refused.
    #[error("check dependency leaf refused: {detail}")]
    CacheLeaf { detail: String },
    /// `dep.cache_fd_identity` — the open leaf's identity changed before
    /// its first byte.
    #[error("check dependency fd identity changed: {detail}")]
    CacheFdIdentity { detail: String },
    /// `dep.cache_links` — the leaf carries multiple hard links.
    #[error("check dependency leaf has multiple links: {detail}")]
    CacheLinks { detail: String },
    /// `dep.cache_kind` — the leaf is not a regular file.
    #[error("check dependency leaf has wrong kind: {detail}")]
    CacheKind { detail: String },
    /// `dep.cache_size` — the leaf exceeds its byte bound.
    #[error("check dependency leaf exceeds size bound: {detail}")]
    CacheSize { detail: String },
    /// `dep.cache_missing` — the lockfile-named archive or index entry is
    /// absent from the canonical cache.
    #[error("check dependency missing: {detail}")]
    CacheMissing { detail: String },
    /// `dep.checksum` — staged bytes do not match the lockfile checksum.
    #[error("check dependency checksum mismatch: {detail}")]
    ChecksumMismatch { detail: String },
    /// `dep.index` — staging the bounded offline index refused.
    #[error("check dependency index staging refused: {detail}")]
    IndexStaging { detail: String },
    /// `dep.config` — an unsafe or unfamiliar Cargo config/path/source
    /// outside the finite vetted inputs.
    #[error("check dependency config refused: {detail}")]
    ConfigRefused { detail: String },
    /// `vendor.admit.{exec,read,dep,selection,target}` — one admission
    /// category refused right before the vendor spawn; the site keeps
    /// the failing category's own suffix under the phase prefix.
    #[error("check vendor admission denied: {detail}")]
    VendorAdmit { site: &'static str, detail: String },
    /// `vendor.setup` — the sandbox could not be proven to deny the
    /// denied controls first, or the bounded rw root could not be set up.
    #[error("check vendor setup refused: {detail}")]
    VendorSetup { detail: String },
    /// `vendor.spawn` — the confined vendor phase could not be spawned.
    #[error("check vendor spawn failed: {detail}")]
    VendorSpawn { detail: String },
    /// `vendor.exec` — the confined vendor phase could not exec Cargo.
    #[error("check vendor exec failed: {detail}")]
    VendorExec { detail: String },
    /// `vendor.observe` — observing the vendor phase failed.
    #[error("check vendor observation failed: {detail}")]
    VendorObserve { detail: String },
    /// `vendor.capture` — the bounded capture of the vendor phase failed.
    #[error("check vendor capture failed: {detail}")]
    VendorCapture { detail: String },
    /// `vendor.deadline` — the vendor phase passed the wall deadline.
    #[error("check vendor deadline exceeded: {detail}")]
    VendorDeadline { detail: String },
    /// `vendor.cancel` — cancellation stopped the vendor phase.
    #[error("check vendor cancelled: {detail}")]
    VendorCancel { detail: String },
    /// `vendor.signal` — a descendant survived the vendor-phase stop.
    #[error("check vendor descendant survived stop: {detail}")]
    VendorSignal { detail: String },
    /// `vendor.result` — the vendor phase itself failed.
    #[error("check vendor failed: {detail}")]
    VendorResult { detail: String },
    /// `vendor.validate` — the vendor output is not bounded-inventory
    /// safe, or other project bytes changed.
    #[error("check vendor output refused: {detail}")]
    VendorValidate { detail: String },
    /// `vendor.lock_changed` — `Cargo.lock` did not stay byte-identical.
    #[error("check lockfile changed: {detail}")]
    VendorLockChanged { detail: String },
    /// `vendor.promote` — copying the verified vendor tree into the
    /// snapshot refused.
    #[error("check vendor promotion failed: {detail}")]
    VendorPromote { detail: String },
    /// `vendor.seal` — sealing the snapshot read-only failed.
    #[error("check seal failed: {detail}")]
    VendorSeal { detail: String },
    /// `vendor.digest` — the promoted vendor digest is not reproducible.
    #[error("check vendor digest failed: {detail}")]
    VendorDigest { detail: String },
    /// `test.admit.{exec,read,dep,selection,target}` — one admission
    /// category refused right before the test spawn; the site keeps
    /// the failing category's own suffix under the phase prefix.
    #[error("check test admission denied: {detail}")]
    TestAdmit { site: &'static str, detail: String },
    /// `test.setup` — preparing the confined test phase refused.
    #[error("check test setup refused: {detail}")]
    TestSetup { detail: String },
    /// `test.spawn` — the confined test phase could not be spawned.
    #[error("check test spawn failed: {detail}")]
    TestSpawn { detail: String },
    /// `test.exec` — the confined test phase could not exec Cargo.
    #[error("check test exec failed: {detail}")]
    TestExec { detail: String },
    /// `test.observe` — observing the test phase failed.
    #[error("check test observation failed: {detail}")]
    TestObserve { detail: String },
    /// `test.capture` — the bounded capture of the test phase failed.
    #[error("check test capture failed: {detail}")]
    TestCapture { detail: String },
    /// `test.deadline` — the test phase passed the wall deadline.
    #[error("check test deadline exceeded: {detail}")]
    TestDeadline { detail: String },
    /// `test.cancel` — cancellation stopped the test phase.
    #[error("check test cancelled: {detail}")]
    TestCancel { detail: String },
    /// `test.signal` — a descendant survived the test-phase stop.
    #[error("check test descendant survived stop: {detail}")]
    TestSignal { detail: String },
    /// `close.selection` — the live selection went away before the row
    /// closed.
    #[error("check close selection stale: {detail}")]
    CloseSelection { detail: String },
    /// `close.inventory` — the live workspace inventory no longer matches
    /// the candidate.
    #[error("check close inventory changed: {detail}")]
    CloseInventory { detail: String },
    /// `close.zero_tests` — the selector matched zero tests: not a RED,
    /// not a PASS; the transport observation refuses typed so a wrong
    /// selector can never read as a passing check (INV-004).
    #[error("check selected zero tests: {detail}")]
    ZeroTests { detail: String },
    /// `cleanup.root` — removing the attempt root failed (appended, never
    /// overwriting a prior cause).
    #[error("check cleanup failed: {detail}")]
    CleanupRoot { detail: String },
    /// `admit.issuer` / `admit.binding` / `admit.replay` / the DEC-048
    /// claim sites — the issuer gate or the first-only store claim
    /// refused the presentation before any effect byte.
    #[error("check claim refused at {site}: {detail}")]
    Claim { site: &'static str, detail: String },
    /// `evidence_retention_failed` — a durable retention failed; the
    /// attempt root is deliberately left in place.
    #[error("check evidence retention failed: {detail}")]
    EvidenceRetention { detail: String },
}

/// The one list of `detail`-carrying variants: the shared and the
/// mutable accessors both expand it, so a new variant cannot be
/// missed by one of them.
macro_rules! check_error_detail {
    ($error:expr) => {
        match $error {
            CheckError::OwnedLaunch { detail, .. }
            | CheckError::ExecGrant { detail }
            | CheckError::ProjectReadGrant { detail }
            | CheckError::DependencyGrant { detail }
            | CheckError::SelectionMismatch { detail }
            | CheckError::TargetLayout { detail }
            | CheckError::InventoryRefused { detail }
            | CheckError::CopyFailed { detail }
            | CheckError::DigestMismatch { detail }
            | CheckError::LockRefused { detail }
            | CheckError::CacheScope { detail }
            | CheckError::CacheRevoked { detail }
            | CheckError::CacheDenied { detail }
            | CheckError::CacheRootFd { detail }
            | CheckError::CacheComponent { detail }
            | CheckError::CacheAncestry { detail }
            | CheckError::CacheCapability { detail }
            | CheckError::CacheLeaf { detail }
            | CheckError::CacheFdIdentity { detail }
            | CheckError::CacheLinks { detail }
            | CheckError::CacheKind { detail }
            | CheckError::CacheSize { detail }
            | CheckError::CacheMissing { detail }
            | CheckError::ChecksumMismatch { detail }
            | CheckError::IndexStaging { detail }
            | CheckError::ConfigRefused { detail }
            | CheckError::VendorAdmit { detail, .. }
            | CheckError::VendorSetup { detail }
            | CheckError::VendorSpawn { detail }
            | CheckError::VendorExec { detail }
            | CheckError::VendorObserve { detail }
            | CheckError::VendorCapture { detail }
            | CheckError::VendorDeadline { detail }
            | CheckError::VendorCancel { detail }
            | CheckError::VendorSignal { detail }
            | CheckError::VendorResult { detail }
            | CheckError::VendorValidate { detail }
            | CheckError::VendorLockChanged { detail }
            | CheckError::VendorPromote { detail }
            | CheckError::VendorSeal { detail }
            | CheckError::VendorDigest { detail }
            | CheckError::TestAdmit { detail, .. }
            | CheckError::TestSetup { detail }
            | CheckError::TestSpawn { detail }
            | CheckError::TestExec { detail }
            | CheckError::TestObserve { detail }
            | CheckError::TestCapture { detail }
            | CheckError::TestDeadline { detail }
            | CheckError::TestCancel { detail }
            | CheckError::TestSignal { detail }
            | CheckError::CloseSelection { detail }
            | CheckError::CloseInventory { detail }
            | CheckError::ZeroTests { detail }
            | CheckError::CleanupRoot { detail }
            | CheckError::Claim { detail, .. }
            | CheckError::EvidenceRetention { detail } => detail,
        }
    };
}

impl CheckError {
    /// The retained site suffix of this failure (`admit.exec`, …).
    #[must_use]
    pub fn site(&self) -> &'static str {
        match self {
            Self::OwnedLaunch { source, .. } => source.primary.site(),
            Self::ExecGrant { .. } => "admit.exec",
            Self::ProjectReadGrant { .. } => "admit.read",
            Self::DependencyGrant { .. } => "admit.dep",
            Self::SelectionMismatch { .. } => "admit.selection",
            Self::TargetLayout { .. } => "admit.target",
            Self::InventoryRefused { .. } => "snapshot.inventory",
            Self::CopyFailed { .. } => "snapshot.copy",
            Self::DigestMismatch { .. } => "snapshot.digest",
            Self::LockRefused { .. } => "dep.lock",
            Self::CacheScope { .. } => "dep.cache_scope",
            Self::CacheRevoked { .. } => "dep.cache_revoked",
            Self::CacheDenied { .. } => "dep.cache_denied",
            Self::CacheRootFd { .. } => "dep.cache_root_fd",
            Self::CacheComponent { .. } => "dep.cache_component",
            Self::CacheAncestry { .. } => "dep.cache_ancestry",
            Self::CacheCapability { .. } => "dep.cache_capability",
            Self::CacheLeaf { .. } => "dep.cache_leaf",
            Self::CacheFdIdentity { .. } => "dep.cache_fd_identity",
            Self::CacheLinks { .. } => "dep.cache_links",
            Self::CacheKind { .. } => "dep.cache_kind",
            Self::CacheSize { .. } => "dep.cache_size",
            Self::CacheMissing { .. } => "dep.cache_missing",
            Self::ChecksumMismatch { .. } => "dep.checksum",
            Self::IndexStaging { .. } => "dep.index",
            Self::ConfigRefused { .. } => "dep.config",
            Self::VendorAdmit { site, .. } => site,
            Self::VendorSetup { .. } => "vendor.setup",
            Self::VendorSpawn { .. } => "vendor.spawn",
            Self::VendorExec { .. } => "vendor.exec",
            Self::VendorObserve { .. } => "vendor.observe",
            Self::VendorCapture { .. } => "vendor.capture",
            Self::VendorDeadline { .. } => "vendor.deadline",
            Self::VendorCancel { .. } => "vendor.cancel",
            Self::VendorSignal { .. } => "vendor.signal",
            Self::VendorResult { .. } => "vendor.result",
            Self::VendorValidate { .. } => "vendor.validate",
            Self::VendorLockChanged { .. } => "vendor.lock_changed",
            Self::VendorPromote { .. } => "vendor.promote",
            Self::VendorSeal { .. } => "vendor.seal",
            Self::VendorDigest { .. } => "vendor.digest",
            Self::TestAdmit { site, .. } => site,
            Self::TestSetup { .. } => "test.setup",
            Self::TestSpawn { .. } => "test.spawn",
            Self::TestExec { .. } => "test.exec",
            Self::TestObserve { .. } => "test.observe",
            Self::TestCapture { .. } => "test.capture",
            Self::TestDeadline { .. } => "test.deadline",
            Self::TestCancel { .. } => "test.cancel",
            Self::TestSignal { .. } => "test.signal",
            Self::CloseSelection { .. } => "close.selection",
            Self::CloseInventory { .. } => "close.inventory",
            Self::ZeroTests { .. } => "close.zero_tests",
            Self::CleanupRoot { .. } => "cleanup.root",
            Self::Claim { site, .. } => site,
            Self::EvidenceRetention { .. } => "evidence_retention_failed",
        }
    }

    fn detail(&self) -> &str {
        check_error_detail!(self)
    }

    /// Appends one bounded note to the detail: the refusal keeps its
    /// variant and site, and the note names a secondary outcome that
    /// would otherwise be silent.
    #[must_use]
    fn with_note(mut self, note: &str) -> Self {
        let detail: &mut String = check_error_detail!(&mut self);
        detail.push_str("; ");
        detail.push_str(note);
        self
    }

    /// Bounded non-secret cause text for the retained row: the site plus a
    /// 512-character cap on the detail.
    #[must_use]
    pub fn cause(&self) -> String {
        let bounded: String = self.detail().chars().take(512).collect();
        format!("{}: {}", self.site(), bounded)
    }
}

/// One inventory entry of a bounded workspace tree.
#[derive(Debug, Clone, PartialEq, Eq)]
struct InventoryEntry {
    rel: PathBuf,
    kind: InventoryKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum InventoryKind {
    File { digest: String },
    Directory,
    Symlink { target: String },
}

/// A bounded, deterministic inventory of one workspace tree: only regular
/// files, directories, and symlinks, hashed in sorted path order so the
/// digest pins exactly the copied bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceInventory {
    entries: Vec<InventoryEntry>,
    digest: String,
}

/// Refusal inside the bounded walk, named by the discriminating cause.
#[derive(Debug, thiserror::Error)]
enum InventoryError {
    #[error("entry {rel} is a hard link ({nlink} links)")]
    HardLink { rel: PathBuf, nlink: u64 },
    #[error("entry {rel} is a special file (mode {kind:o})")]
    Special { rel: PathBuf, kind: u32 },
    #[error("entry name is not valid UTF-8")]
    NonUtf8 { rel: PathBuf },
    #[error("file {rel} exceeds the per-file bound ({size} bytes)")]
    FileTooLarge { rel: PathBuf, size: u64 },
    #[error("tree exceeds the total byte bound ({size} bytes)")]
    TreeTooLarge { size: u64 },
    #[error("tree exceeds the entry count bound ({count} entries)")]
    TooManyEntries { count: usize },
    #[error("tree exceeds the depth bound at {rel}")]
    TooDeep { rel: PathBuf },
    #[error("symlink {rel} has an absolute or non-UTF-8 target")]
    BadSymlink { rel: PathBuf },
    #[error("entry {rel} is covered by an enrolled deny")]
    Denied { rel: PathBuf },
    #[error("walk failed at {rel}: {source}")]
    Walk {
        rel: PathBuf,
        source: std::io::Error,
    },
}

fn inventory(root: &Path) -> Result<WorkspaceInventory, InventoryError> {
    inventory_under(root, &|_| false)
}

/// The deny-guarded walk (DEC-056): every descendant actually read —
/// hashed, copied, or listed — is first consulted against the live
/// policy, so a root Read grant never reads a denied child. The plain
/// [`inventory`] keeps an always-admitting guard for the executor's own
/// private trees.
fn inventory_under(
    root: &Path,
    denied: &dyn Fn(&Path) -> bool,
) -> Result<WorkspaceInventory, InventoryError> {
    let mut entries = Vec::new();
    let mut total_bytes = 0u64;
    inventory_walk(
        root,
        PathBuf::new(),
        &mut entries,
        &mut total_bytes,
        0,
        denied,
    )?;
    entries.sort_by(|a, b| a.rel.cmp(&b.rel));
    let mut hasher = sha2::Sha256::new();
    for entry in &entries {
        match &entry.kind {
            InventoryKind::File { digest } => {
                hasher.update(format!("f {}\n{digest}\n", entry.rel.display()).as_bytes());
            }
            InventoryKind::Directory => {
                hasher.update(format!("d {}\n", entry.rel.display()).as_bytes());
            }
            InventoryKind::Symlink { target } => {
                hasher.update(format!("l {} -> {target}\n", entry.rel.display()).as_bytes());
            }
        }
    }
    Ok(WorkspaceInventory {
        entries,
        digest: hex(&hasher.finalize()),
    })
}

fn inventory_walk(
    root: &Path,
    rel: PathBuf,
    entries: &mut Vec<InventoryEntry>,
    total_bytes: &mut u64,
    depth: usize,
    denied: &dyn Fn(&Path) -> bool,
) -> Result<(), InventoryError> {
    if depth > INVENTORY_MAX_DEPTH {
        return Err(InventoryError::TooDeep { rel });
    }
    if entries.len() >= INVENTORY_MAX_ENTRIES {
        return Err(InventoryError::TooManyEntries {
            count: entries.len(),
        });
    }
    if rel.file_name().is_some_and(|name| name.to_str().is_none()) {
        return Err(InventoryError::NonUtf8 { rel });
    }
    let absolute = root.join(&rel);
    // Deny-first (DEC-056): the consult precedes every hash, read, and
    // listing of the entry — before the metadata walk touches it.
    if denied(&absolute) {
        return Err(InventoryError::Denied { rel });
    }
    let meta = std::fs::symlink_metadata(&absolute).map_err(|source| InventoryError::Walk {
        rel: rel.clone(),
        source,
    })?;
    let kind = meta.file_type();
    if kind.is_symlink() {
        return inventory_symlink(&absolute, rel, entries);
    }
    reject_unusual_inode(&meta, &rel, kind.is_dir())?;
    if kind.is_dir() {
        entries.push(InventoryEntry {
            rel: rel.clone(),
            kind: InventoryKind::Directory,
        });
        for child in sorted_child_names(&absolute, &rel)? {
            inventory_walk(
                root,
                rel.join(&child),
                entries,
                total_bytes,
                depth + 1,
                denied,
            )?;
        }
        return Ok(());
    }
    inventory_file(&absolute, rel, &meta, entries, total_bytes)
}

/// Records one relative symlink, refusing absolute and non-UTF-8 targets.
fn inventory_symlink(
    absolute: &Path,
    rel: PathBuf,
    entries: &mut Vec<InventoryEntry>,
) -> Result<(), InventoryError> {
    if rel.as_os_str().is_empty() {
        return Err(InventoryError::BadSymlink { rel });
    }
    let target = std::fs::read_link(absolute).map_err(|source| InventoryError::Walk {
        rel: rel.clone(),
        source,
    })?;
    let target = target
        .to_str()
        .ok_or(InventoryError::BadSymlink { rel: rel.clone() })?;
    if target.starts_with('/') {
        return Err(InventoryError::BadSymlink { rel });
    }
    entries.push(InventoryEntry {
        rel,
        kind: InventoryKind::Symlink {
            target: target.to_string(),
        },
    });
    Ok(())
}

/// Rejects a special inode (FIFO, socket, device) or a multi-link
/// non-directory: both fail the bounded inventory closed.
fn reject_unusual_inode(meta: &Metadata, rel: &Path, is_dir: bool) -> Result<(), InventoryError> {
    use std::os::unix::fs::MetadataExt as _;
    let kind = meta.file_type();
    if !kind.is_dir() && !kind.is_file() {
        return Err(InventoryError::Special {
            rel: rel.to_path_buf(),
            kind: meta.mode(),
        });
    }
    if meta.nlink() > 1 && !is_dir {
        return Err(InventoryError::HardLink {
            rel: rel.to_path_buf(),
            nlink: meta.nlink(),
        });
    }
    Ok(())
}

/// Sorted UTF-8 child names of one inventoried directory; a non-UTF-8 or
/// unreadable name refuses the whole walk.
fn sorted_child_names(absolute: &Path, rel: &Path) -> Result<Vec<String>, InventoryError> {
    let children = std::fs::read_dir(absolute).map_err(|source| InventoryError::Walk {
        rel: rel.to_path_buf(),
        source,
    })?;
    let mut names: Vec<(std::ffi::OsString, Option<String>)> = Vec::new();
    for child in children {
        let entry = child.map_err(|source| InventoryError::Walk {
            rel: rel.to_path_buf(),
            source,
        })?;
        let name = entry.file_name();
        let spelled = name.to_str().map(str::to_string);
        names.push((name, spelled));
    }
    names.sort();
    names
        .into_iter()
        .map(|(name, spelled)| {
            spelled.ok_or(InventoryError::NonUtf8 {
                rel: rel.join(name),
            })
        })
        .collect()
}

/// Records one regular file under the per-file and whole-tree byte bounds.
fn inventory_file(
    absolute: &Path,
    rel: PathBuf,
    meta: &Metadata,
    entries: &mut Vec<InventoryEntry>,
    total_bytes: &mut u64,
) -> Result<(), InventoryError> {
    if meta.len() > INVENTORY_FILE_MAX_BYTES {
        return Err(InventoryError::FileTooLarge {
            rel,
            size: meta.len(),
        });
    }
    *total_bytes = total_bytes.saturating_add(meta.len());
    if *total_bytes > INVENTORY_TREE_MAX_BYTES {
        return Err(InventoryError::TreeTooLarge { size: *total_bytes });
    }
    let digest = hash_file(absolute).map_err(|source| InventoryError::Walk {
        rel: rel.clone(),
        source,
    })?;
    entries.push(InventoryEntry {
        rel,
        kind: InventoryKind::File { digest },
    });
    Ok(())
}

/// Hashes one regular file's bytes through a single checked open:
/// `O_NOFOLLOW|O_NONBLOCK` refuses a symlink or FIFO swapped onto the
/// path after the inventory's metadata walk — a FIFO swap cannot hang
/// the hash with no writer — and the opened fd's own metadata must name
/// a regular file before any byte is read.
fn hash_file(path: &Path) -> std::io::Result<String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = File::options()
        .read(true)
        .custom_flags(
            rivect_sandbox_helper::ANCHOR_O_NOFOLLOW | rivect_sandbox_helper::OPEN_NONBLOCK,
        )
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "hashed path is not a regular file",
        ));
    }
    let mut file = file;
    let mut hasher = sha2::Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(hex(&hasher.finalize()))
}

/// Reads one inventoried file's whole content through a single checked
/// open — `O_NOFOLLOW|O_NONBLOCK`, regular-file verified, bounded by the
/// inventory's per-file ceiling — so a hostile swap between the metadata
/// walk and this read refuses typed instead of hanging or following.
/// The error kinds stay raw: an absent file is distinguishable from an
/// unreadable one at the call sites that need it.
fn read_inventory_file(path: &Path, rel: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = File::options()
        .read(true)
        .custom_flags(
            rivect_sandbox_helper::ANCHOR_O_NOFOLLOW | rivect_sandbox_helper::OPEN_NONBLOCK,
        )
        .open(path)
        .map_err(|source| {
            std::io::Error::new(
                source.kind(),
                format!("open of {}: {source}", rel.display()),
            )
        })?;
    let meta = file.metadata().map_err(|source| {
        std::io::Error::new(
            source.kind(),
            format!("metadata of {}: {source}", rel.display()),
        )
    })?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} is not a regular file after the inventory",
                rel.display()
            ),
        ));
    }
    if meta.len() > INVENTORY_FILE_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            format!(
                "{} grew past the inventory bound after the walk",
                rel.display()
            ),
        ));
    }
    // The read itself is take-bounded: growth between the fstat and the
    // read refuses here instead of reading unbounded (the same one-fd
    // discipline as the leaf reads).
    let mut limited = file.take(INVENTORY_FILE_MAX_BYTES + 1);
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    limited
        .read_to_end(&mut bytes)
        .map_err(|source| std::io::Error::other(format!("read of {}: {source}", rel.display())))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > INVENTORY_FILE_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            format!(
                "{} grew past the inventory bound during the read",
                rel.display()
            ),
        ));
    }
    Ok(bytes)
}

/// Copies the inventoried tree into a fresh destination without following
/// symlinks: files are copied by byte with their digest verified after the
/// write, symlinks are recreated as symlinks, and directories are
/// recreated. Returns the digest of the copied tree.
fn copy_inventory(
    source_root: &Path,
    tree: &WorkspaceInventory,
    dest_root: &Path,
    denied: &dyn Fn(&Path) -> bool,
) -> Result<String, CheckError> {
    for entry in &tree.entries {
        let source = source_root.join(&entry.rel);
        let dest = dest_root.join(&entry.rel);
        match &entry.kind {
            InventoryKind::Directory => {
                std::fs::create_dir_all(&dest).map_err(copy_failed(&entry.rel))?;
            }
            InventoryKind::Symlink { target } => {
                std::os::unix::fs::symlink(target, &dest).map_err(copy_failed(&entry.rel))?;
            }
            InventoryKind::File { digest } => {
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent).map_err(copy_failed(&entry.rel))?;
                }
                // Deny-first (DEC-056): the copy re-consults the live
                // policy on the source byte read — the root grant never
                // reads a denied child even after the walk admitted it.
                if denied(&source) {
                    return Err(CheckError::ProjectReadGrant {
                        detail: format!(
                            "an enrolled deny covers {}; the project read grant cannot read a denied child",
                            entry.rel.display()
                        ),
                    });
                }
                // The source bytes are read through ONE checked open
                // (no-follow, nonblocking, regular-file verified, bounded
                // by the inventory's per-file cap): a FIFO or symlink
                // swapped between the inventory and the copy can neither
                // hang nor redirect the read, and the source digest is
                // proven BEFORE the destination is written.
                let bytes =
                    read_inventory_file(&source, &entry.rel).map_err(copy_failed(&entry.rel))?;
                let source_digest = hex(&sha2::Sha256::digest(&bytes));
                if source_digest != *digest {
                    return Err(CheckError::CopyFailed {
                        detail: format!(
                            "source bytes changed for {} after the inventory",
                            entry.rel.display()
                        ),
                    });
                }
                std::fs::write(&dest, &bytes).map_err(copy_failed(&entry.rel))?;
                let copied_digest = hash_file(&dest).map_err(copy_failed(&entry.rel))?;
                if copied_digest != *digest {
                    return Err(CheckError::CopyFailed {
                        detail: format!("copied bytes changed for {}", entry.rel.display()),
                    });
                }
            }
        }
    }
    let copied = inventory(dest_root).map_err(|error| CheckError::CopyFailed {
        detail: format!("copied tree inventory failed: {error}"),
    })?;
    if copied.digest != tree.digest {
        return Err(CheckError::CopyFailed {
            detail: "copied tree digest does not reproduce the source inventory".to_string(),
        });
    }
    Ok(copied.digest)
}

fn copy_failed(rel: &Path) -> impl FnOnce(std::io::Error) -> CheckError + '_ {
    move |source| CheckError::CopyFailed {
        detail: format!("copy of {} failed: {source}", rel.display()),
    }
}

/// Drops every write bit under `root`: the OS boundary is the
/// enforcement during the run; the seal keeps an honest read-only state
/// afterwards. Both the seal inventory and each chmod surface as the
/// owner-local typed `vendor.seal` failure — never a best-effort
/// silent return (DEC-056).
fn seal_read_only(root: &Path) -> Result<(), CheckError> {
    use std::os::unix::fs::PermissionsExt as _;
    let walk = inventory(root).map_err(|error| CheckError::VendorSeal {
        detail: format!("the sealed inventory refused: {error}"),
    })?;
    for entry in &walk.entries {
        let path = root.join(&entry.rel);
        let mode = match entry.kind {
            InventoryKind::Directory => 0o555,
            InventoryKind::File { .. } => 0o444,
            InventoryKind::Symlink { .. } => continue,
        };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).map_err(
            |source| CheckError::VendorSeal {
                detail: format!("sealing {} failed: {source}", entry.rel.display()),
            },
        )?;
    }
    Ok(())
}

// ----- lockfile dependencies and fd-anchored staging (DEC-042) ----------

/// One registry dependency the lockfile names: the archive filename and
/// the lock checksum the staged bytes must reproduce.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LockDependency {
    name: String,
    version: String,
    checksum: String,
}

/// Parses the registry dependencies out of one Cargo.lock. Path and git
/// sources outside the project refuse closed (`dep.config`); only the
/// crates.io registry source is a vetted dependency input.
fn lock_registry_dependencies(lock_bytes: &[u8]) -> Result<Vec<LockDependency>, CheckError> {
    let text = std::str::from_utf8(lock_bytes).map_err(|source| CheckError::LockRefused {
        detail: format!("lockfile is not UTF-8: {source}"),
    })?;
    let parsed: toml_edit::DocumentMut =
        text.parse().map_err(|source| CheckError::LockRefused {
            detail: format!("lockfile does not parse: {source}"),
        })?;
    let Some(packages) = parsed
        .get("package")
        .and_then(|value| value.as_array_of_tables())
    else {
        return Ok(Vec::new());
    };
    let mut dependencies = Vec::new();
    for package in packages.iter() {
        let Some(source) = package.get("source").and_then(|v| v.as_str()) else {
            continue; // path dependency inside the workspace
        };
        if !source.starts_with("registry+https://github.com/rust-lang/crates.io-index") {
            return Err(CheckError::ConfigRefused {
                detail: format!("unsupported lockfile source kind: {source}"),
            });
        }
        let name = package
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CheckError::LockRefused {
                detail: "lockfile package without a name".to_string(),
            })?;
        let version = package
            .get("version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CheckError::LockRefused {
                detail: format!("lockfile package {name} without a version"),
            })?;
        let checksum = package
            .get("checksum")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CheckError::LockRefused {
                detail: format!("lockfile package {name} {version} without a checksum"),
            })?;
        // The name and version become fd-relative open names (archive
        // filename, index shard dirs): a name outside the crate charset
        // could carry a path, separator, or dot-dot escape, so it is a
        // config refusal before any cache byte (CR-I1).
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(CheckError::ConfigRefused {
                detail: format!("lockfile package name is not a crate name: {name}"),
            });
        }
        if version.is_empty()
            || !version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
        {
            return Err(CheckError::ConfigRefused {
                detail: format!(
                    "lockfile package {name} version is not a semver string: {version}"
                ),
            });
        }
        dependencies.push(LockDependency {
            name: name.to_string(),
            version: version.to_string(),
            checksum: checksum.to_string(),
        });
    }
    dependencies.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    dependencies.dedup_by(|a, b| a.name == b.name && a.version == b.version);
    Ok(dependencies)
}

/// The registry directory spellings modern Cargo uses beneath
/// `<cargo_home>/registry/{cache,index}`; an unfamiliar layout fails
/// closed rather than guessing (`dep.config`).
const REGISTRY_DIRS: &[&str] = &[
    "index.crates.io-6f17d22bba15001f",
    "index.crates.io-1949cf8c6b5b557f",
];

/// The pinned fd-anchored dependency roots plus the lineage the per-leaf
/// reconsult re-walks: root → cargo_home → registry → cache/index →
/// registry dir. After the anchor, every leaf opens relative to these
/// pinned parents with no pathname reopen.
struct AnchoredDependencies {
    cargo_home: rivect_sandbox_helper::AnchoredDir,
    registry: rivect_sandbox_helper::AnchoredDir,
    cache_root: rivect_sandbox_helper::AnchoredDir,
    index_root: rivect_sandbox_helper::AnchoredDir,
    cache_registry_dir: rivect_sandbox_helper::AnchoredDir,
    index_registry_dir: rivect_sandbox_helper::AnchoredDir,
    /// The registry-dir spelling (`index.crates.io-*`) the leaves open
    /// through; the lineage recheck re-opens exactly this component.
    regdir: &'static str,
    /// (component, identity) pairs of the cargo_home walk from `/`.
    lineage: Vec<(Vec<u8>, rivect_sandbox_helper::FdIdentity)>,
}

impl AnchoredDependencies {
    /// Re-walks `/` → cargo_home fd-relatively, compares every pinned
    /// identity, then re-opens the registry, cache, and index roots from
    /// the verified cargo_home and compares those pinned identities too:
    /// an ancestor moved, replaced, or turned into a symlink refuses
    /// before any byte even when the leaf inode and checksum would still
    /// match.
    fn verify_lineage(&self) -> Result<(), CheckError> {
        let mut current = rivect_sandbox_helper::open_filesystem_root()
            .map_err(dependency_fd_error("cargo_home lineage root".to_string()))?;
        for (component, pinned) in &self.lineage {
            let next = rivect_sandbox_helper::openat_directory(&current, component).map_err(
                dependency_fd_error("cargo_home lineage component".to_string()),
            )?;
            if !next.identity.same_directory_inode(pinned) {
                return Err(CheckError::CacheAncestry {
                    detail: "a cargo-home ancestor changed identity since the anchor".to_string(),
                });
            }
            current = next;
        }
        if !current
            .identity
            .same_directory_inode(&self.cargo_home.identity)
        {
            return Err(CheckError::CacheAncestry {
                detail: "cargo_home changed identity since the anchor".to_string(),
            });
        }
        let registry = rivect_sandbox_helper::openat_directory(&current, b"registry").map_err(
            dependency_fd_error("lineage registry component".to_string()),
        )?;
        if !registry
            .identity
            .same_directory_inode(&self.registry.identity)
        {
            return Err(CheckError::CacheAncestry {
                detail: "the registry root changed identity since the anchor".to_string(),
            });
        }
        for (name, pinned, regdir_pinned) in [
            ("cache", &self.cache_root, &self.cache_registry_dir),
            ("index", &self.index_root, &self.index_registry_dir),
        ] {
            let reopened = rivect_sandbox_helper::openat_directory(&registry, name.as_bytes())
                .map_err(dependency_fd_error(
                    "lineage registry component".to_string(),
                ))?;
            if !reopened.identity.same_directory_inode(&pinned.identity) {
                return Err(CheckError::CacheAncestry {
                    detail: format!("the registry {name} root changed identity since the anchor"),
                });
            }
            // The registry dir the leaves actually open through is part
            // of the lineage: renamed out and symlinked back post-anchor
            // (same leaf inode and SHA behind the link), the reopen must
            // refuse — a held fd would keep reading the moved tree
            // otherwise (CR-I6).
            let regdir = rivect_sandbox_helper::openat_directory(&reopened, self.regdir.as_bytes())
                .map_err(dependency_fd_error(
                    "lineage registry dir component".to_string(),
                ))?;
            if !regdir
                .identity
                .same_directory_inode(&regdir_pinned.identity)
            {
                return Err(CheckError::CacheAncestry {
                    detail: format!(
                        "the registry {name} dir {} changed identity since the anchor",
                        self.regdir
                    ),
                });
            }
        }
        Ok(())
    }
}

/// Maps one fd-anchored open refusal to the dependency seam whose offline
/// correction differs (D-124): capability, root, component, and leaf
/// causes stay separable.
fn dependency_fd_error(
    where_: String,
) -> impl Fn(rivect_sandbox_helper::FdOpenError) -> CheckError {
    move |error| match error {
        rivect_sandbox_helper::FdOpenError::UnsupportedCapability { source } => {
            CheckError::CacheCapability {
                detail: format!("{where_}: {source}"),
            }
        }
        rivect_sandbox_helper::FdOpenError::Io { source } => CheckError::CacheRootFd {
            detail: format!("{where_}: {source}"),
        },
        other => CheckError::CacheRootFd {
            detail: format!("{where_}: {other}"),
        },
    }
}

/// Maps one leaf-open refusal (already relative to a pinned parent) to its
/// distinct seam: link count, kind, and size keep three separate sites.
fn dependency_leaf_error(
    where_: String,
) -> impl Fn(rivect_sandbox_helper::FdOpenError) -> CheckError {
    move |error| match error {
        rivect_sandbox_helper::FdOpenError::MultipleLinks => CheckError::CacheLinks {
            detail: where_.clone(),
        },
        rivect_sandbox_helper::FdOpenError::WrongKind => CheckError::CacheKind {
            detail: where_.clone(),
        },
        rivect_sandbox_helper::FdOpenError::Oversize => CheckError::CacheSize {
            detail: where_.clone(),
        },
        rivect_sandbox_helper::FdOpenError::Missing => CheckError::CacheMissing {
            detail: where_.clone(),
        },
        rivect_sandbox_helper::FdOpenError::SymlinkComponent => CheckError::CacheLeaf {
            detail: format!("{where_}: the leaf itself is a symlink"),
        },
        rivect_sandbox_helper::FdOpenError::UnsupportedCapability { source } => {
            CheckError::CacheCapability {
                detail: format!("{where_}: {source}"),
            }
        }
        rivect_sandbox_helper::FdOpenError::Io { source } => CheckError::CacheLeaf {
            detail: format!("{where_}: {source}"),
        },
    }
}

/// Maps one nested index-component open refusal: components of the index
/// cache layout (`.cache`, the letter shards) keep the component seam.
fn dependency_component_error(
    where_: String,
) -> impl Fn(rivect_sandbox_helper::FdOpenError) -> CheckError {
    move |error| match error {
        rivect_sandbox_helper::FdOpenError::UnsupportedCapability { source } => {
            CheckError::CacheCapability {
                detail: format!("{where_}: {source}"),
            }
        }
        other => CheckError::CacheComponent {
            detail: format!("{where_}: {other}"),
        },
    }
}

/// Anchors the dependency roots for one canonical cargo_home: opens `/`
/// once, walks each cargo_home component with
/// `O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, then pins the registry,
/// cache, index, and registry-dir directories. The returned spelling names
/// the registry directory that resolved under both roots.
fn anchor_dependencies(
    cargo_home: &Path,
) -> Result<(AnchoredDependencies, &'static str), CheckError> {
    let mut lineage = Vec::new();
    let mut current = rivect_sandbox_helper::open_filesystem_root()
        .map_err(dependency_fd_error("filesystem root open".to_string()))?;
    for component in cargo_home.components() {
        use std::path::Component as C;
        let bytes = match component {
            C::RootDir | C::Prefix(_) => continue,
            C::CurDir => {
                return Err(CheckError::CacheRootFd {
                    detail: "cargo_home carries a `.` component".to_string(),
                });
            }
            C::ParentDir => {
                return Err(CheckError::CacheRootFd {
                    detail: "cargo_home carries a `..` component".to_string(),
                });
            }
            C::Normal(name) => name.as_encoded_bytes().to_vec(),
        };
        let next = rivect_sandbox_helper::openat_directory(&current, &bytes)
            .map_err(dependency_fd_error("cargo_home component walk".to_string()))?;
        lineage.push((bytes, next.identity));
        current = next;
    }
    let cargo_home_dir = current;
    let registry = rivect_sandbox_helper::openat_directory(&cargo_home_dir, b"registry")
        .map_err(dependency_fd_error("registry component".to_string()))?;
    let cache_root = rivect_sandbox_helper::openat_directory(&registry, b"cache")
        .map_err(dependency_fd_error("registry/cache component".to_string()))?;
    let index_root = rivect_sandbox_helper::openat_directory(&registry, b"index")
        .map_err(dependency_fd_error("registry/index component".to_string()))?;
    let mut resolved = None;
    for spelling in REGISTRY_DIRS {
        let Ok(cache_dir) =
            rivect_sandbox_helper::openat_directory(&cache_root, spelling.as_bytes())
        else {
            continue;
        };
        let Ok(index_dir) =
            rivect_sandbox_helper::openat_directory(&index_root, spelling.as_bytes())
        else {
            continue;
        };
        resolved = Some((cache_dir, index_dir, *spelling));
        break;
    }
    let Some((cache_registry_dir, index_registry_dir, spelling)) = resolved else {
        return Err(CheckError::ConfigRefused {
            detail: "no familiar cargo registry directory layout under registry/{cache,index}"
                .to_string(),
        });
    };
    Ok((
        AnchoredDependencies {
            cargo_home: cargo_home_dir,
            registry,
            cache_root,
            index_root,
            cache_registry_dir,
            index_registry_dir,
            regdir: spelling,
            lineage,
        },
        spelling,
    ))
}

/// The sparse-index cache shard layout for one crate name: 1–3 character
/// names shard by length, longer names by the first four characters.
fn index_entry_shards(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    match chars.len() {
        0 => Vec::new(),
        1 | 2 => vec![chars.len().to_string(), name.to_string()],
        3 => vec!["3".to_string(), chars[0].to_string(), name.to_string()],
        _ => vec![
            chars[..2].iter().collect(),
            chars[2..4].iter().collect(),
            name.to_string(),
        ],
    }
}

/// Reads one pinned leaf's whole content through the opened fd, checking
/// the identity again right before the first byte and bounding the read
/// itself at `max_bytes + 1`: a held fd cannot redirect to a foreign
/// inode, any drift refuses, and a file that GREW after the open-time
/// size check still refuses at the size seam instead of reading
/// unbounded bytes.
fn read_leaf(
    leaf: &mut rivect_sandbox_helper::AnchoredLeaf,
    where_: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, CheckError> {
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt as _;
    let fresh = leaf
        .file
        .metadata()
        .map_err(|source| CheckError::CacheFdIdentity {
            detail: format!("{where_}: {source}"),
        })?;
    if fresh.dev() != leaf.identity.dev
        || fresh.ino() != leaf.identity.ino
        || fresh.nlink() != leaf.identity.nlink
    {
        return Err(CheckError::CacheFdIdentity {
            detail: format!("{where_}: the open leaf identity changed before its first byte"),
        });
    }
    if fresh.len() > max_bytes {
        return Err(CheckError::CacheSize {
            detail: format!(
                "{where_}: the leaf grew to {} bytes before its first byte, past the {max_bytes} bound",
                fresh.len()
            ),
        });
    }
    // The metadata check above bounds the reserve: capacity never
    // exceeds the byte bound, so a leaf grown into a huge sparse file
    // refuses before any allocation — a metadata-sized reserve would
    // hand the attacker the allocation itself (CR A11).
    let mut bytes = Vec::with_capacity(usize::try_from(fresh.len()).unwrap_or(0));
    (&mut leaf.file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| CheckError::CacheLeaf {
            detail: format!("{where_}: {source}"),
        })?;
    if bytes.len() as u64 > max_bytes {
        return Err(CheckError::CacheSize {
            detail: format!("{where_}: the leaf grew past {max_bytes} bytes after open"),
        });
    }
    Ok(bytes)
}

/// Consults the live deny policy on one host cache/index descendant
/// BEFORE its fd-relative open (DEC-056): the dependency pair's root
/// grants never read a denied child. A leaf the policy cannot observe
/// fails closed.
fn deny_first_leaf(policy: &Policy, leaf: &Path, label: &str) -> Result<(), CheckError> {
    if policy.covers(leaf) {
        return Err(CheckError::CacheDenied {
            detail: format!("the deny policy covers the {label} dependency leaf"),
        });
    }
    Ok(())
}

/// Stages one dependency set into the private attempt cargo-home: only the
/// lockfile-named `.crate` archives (each SHA-256 verified against the
/// lock checksum) and the required offline-index entries, all read through
/// archive byte total for the retained row.
fn stage_dependencies(
    deps: &[LockDependency],
    regdir: &str,
    anchored: &AnchoredDependencies,
    homes: (&Path, &Path),
    receipt: &crate::policy::DependencyReceipt,
    policy: &mut Policy,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<u64, CheckError> {
    let (host_cargo_home, staged_cargo_home) = homes;
    let mut staged_bytes = 0u64;
    let staged_cache = staged_cargo_home.join("registry/cache").join(regdir);
    let staged_index_root = staged_cargo_home.join("registry/index").join(regdir);
    std::fs::create_dir_all(&staged_cache).map_err(|source| CheckError::IndexStaging {
        detail: format!("staged cache directory: {source}"),
    })?;
    std::fs::create_dir_all(&staged_index_root).map_err(|source| CheckError::IndexStaging {
        detail: format!("staged index directory: {source}"),
    })?;
    let host_cache = host_cargo_home.join("registry/cache").join(regdir);
    let host_index = host_cargo_home.join("registry/index").join(regdir);
    // Every index leaf read re-verifies cancellation, the grants, and
    // the pinned lineage at the read itself (`recheck_index_read`);
    // config.json is the first such read (CR-I6).
    deny_first_leaf(policy, &host_index.join("config.json"), "index")?;
    stage_index_config(anchored, receipt, policy, cancel, &staged_index_root)?;
    for dep in deps {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(CheckError::VendorCancel {
                detail: "cancellation during dependency staging".to_string(),
            });
        }
        reconsult_dependency_grants(receipt, policy)?;
        anchored.verify_lineage()?;
        deny_first_leaf(
            policy,
            &host_cache.join(format!("{}-{}.crate", dep.name, dep.version)),
            "cache",
        )?;
        staged_bytes = staged_bytes.saturating_add(stage_one_archive(
            dep,
            &anchored.cache_registry_dir,
            &staged_cache,
        )?);
        if staged_bytes > DEP_STAGED_MAX_BYTES {
            return Err(CheckError::CacheSize {
                detail: "staged dependency bytes exceed the attempt bound".to_string(),
            });
        }
        let mut entry_path = host_index.join(".cache");
        for shard in index_entry_shards(&dep.name) {
            entry_path = entry_path.join(shard);
        }
        deny_first_leaf(policy, &entry_path, "index")?;
        stage_index_entry(dep, anchored, receipt, policy, cancel, &staged_index_root)?;
    }
    Ok(staged_bytes)
}

/// Stages the registry root descriptor `config.json`: a sparse index is
/// unusable offline without it, so it belongs to the bounded offline-index
/// bytes every dependency run stages — read through the pinned fd anchor
/// like every other index byte.
fn stage_index_config(
    anchored: &AnchoredDependencies,
    receipt: &crate::policy::DependencyReceipt,
    policy: &mut Policy,
    cancel: &std::sync::atomic::AtomicBool,
    staged_index_root: &Path,
) -> Result<(), CheckError> {
    recheck_index_read(cancel, receipt, policy, anchored)?;
    let mut leaf = rivect_sandbox_helper::openat_leaf(
        &anchored.index_registry_dir,
        b"config.json",
        DEP_INDEX_ENTRY_MAX_BYTES,
    )
    .map_err(dependency_leaf_error("config.json".to_string()))?;
    let bytes = read_leaf(&mut leaf, "config.json", DEP_INDEX_ENTRY_MAX_BYTES)?;
    std::fs::write(staged_index_root.join("config.json"), &bytes).map_err(|source| {
        CheckError::IndexStaging {
            detail: format!("staging config.json: {source}"),
        }
    })
}

/// Stages one lockfile-named `.crate` archive: pinned-parent open, fd
/// identity recheck, SHA-256 against the lock checksum, then the write
/// into the private attempt cache. Returns the staged byte count.
fn stage_one_archive(
    dep: &LockDependency,
    cache_registry_dir: &rivect_sandbox_helper::AnchoredDir,
    staged_cache: &Path,
) -> Result<u64, CheckError> {
    let archive_name = format!("{}-{}.crate", dep.name, dep.version);
    let mut leaf = rivect_sandbox_helper::openat_leaf(
        cache_registry_dir,
        archive_name.as_bytes(),
        DEP_ARCHIVE_MAX_BYTES,
    )
    .map_err(dependency_leaf_error(archive_name.clone()))?;
    let bytes = read_leaf(&mut leaf, &archive_name, DEP_ARCHIVE_MAX_BYTES)?;
    let digest = hex(&sha2::Sha256::digest(&bytes));
    if digest != dep.checksum {
        return Err(CheckError::ChecksumMismatch {
            detail: format!("{archive_name}: staged sha256 does not match the lock checksum"),
        });
    }
    std::fs::write(staged_cache.join(&archive_name), &bytes).map_err(|source| {
        CheckError::IndexStaging {
            detail: format!("staging {archive_name}: {source}"),
        }
    })?;
    Ok(bytes.len() as u64)
}

/// Stages one package's sparse-index entry: opens the shard walk
/// `.cache/<shard1>/<shard2>/<name>` relative to the pinned index root and
/// copies the bounded entry bytes into the private attempt index.
fn stage_index_entry(
    dep: &LockDependency,
    anchored: &AnchoredDependencies,
    receipt: &crate::policy::DependencyReceipt,
    policy: &mut Policy,
    cancel: &std::sync::atomic::AtomicBool,
    staged_index_root: &Path,
) -> Result<(), CheckError> {
    recheck_index_read(cancel, receipt, policy, anchored)?;
    let mut parent =
        rivect_sandbox_helper::openat_directory(&anchored.index_registry_dir, b".cache").map_err(
            dependency_component_error("index .cache component".to_string()),
        )?;
    let shards = index_entry_shards(&dep.name);
    let Some((leaf_name, dirs)) = shards.split_last() else {
        return Err(CheckError::IndexStaging {
            detail: format!("dependency {} has an empty name", dep.name),
        });
    };
    for dir in dirs {
        parent = rivect_sandbox_helper::openat_directory(&parent, dir.as_bytes()).map_err(
            dependency_component_error("index shard component".to_string()),
        )?;
    }
    let mut leaf = rivect_sandbox_helper::openat_leaf(
        &parent,
        leaf_name.as_bytes(),
        DEP_INDEX_ENTRY_MAX_BYTES,
    )
    .map_err(dependency_leaf_error(leaf_name.clone()))?;
    let bytes = read_leaf(&mut leaf, leaf_name, DEP_INDEX_ENTRY_MAX_BYTES)?;
    // The sparse-index `.cache` entry is cargo's binary format (version
    // header, etag, then JSON lines); plain JSON lines only appear in a
    // raw non-cache index layout. The bytes stage verbatim either way.
    if !bytes.starts_with(b"{")
        && !bytes.windows(2).any(|window| window == b"\n\"")
        && !bytes.starts_with(&[0x03, 0x02, 0x00, 0x00, 0x00])
    {
        return Err(CheckError::IndexStaging {
            detail: format!(
                "index entry for {} does not look like an index line",
                dep.name
            ),
        });
    }
    let mut dest = staged_index_root.join(".cache");
    for dir in dirs {
        dest = dest.join(dir);
    }
    std::fs::create_dir_all(&dest).map_err(|source| CheckError::IndexStaging {
        detail: format!("staged index directory: {source}"),
    })?;
    std::fs::write(dest.join(leaf_name), &bytes).map_err(|source| CheckError::IndexStaging {
        detail: format!("staging index entry {}: {source}", dep.name),
    })?;
    Ok(())
}

/// The fresh recheck immediately before every index leaf read. The
/// archive staging between the loop-top recheck and the index entry is
/// the widest window an attacker can move the index registry dir in —
/// a held fd would keep reading the moved tree — so cancellation, the
/// grants, and the pinned lineage are re-verified at the read itself,
/// not only at the anchor or the loop top (CR A6).
fn recheck_index_read(
    cancel: &std::sync::atomic::AtomicBool,
    receipt: &crate::policy::DependencyReceipt,
    policy: &mut Policy,
    anchored: &AnchoredDependencies,
) -> Result<(), CheckError> {
    if cancel.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(CheckError::VendorCancel {
            detail: "cancellation before an index read".to_string(),
        });
    }
    reconsult_dependency_grants(receipt, policy)?;
    anchored.verify_lineage()
}

/// Re-admits the issuer's dependency Read pair and re-consults the deny
/// policy on its roots before every leaf: a revoked, rebound, or
/// unregistered receipt stops staging with its typed seam.
fn reconsult_dependency_grants(
    receipt: &crate::policy::DependencyReceipt,
    policy: &mut Policy,
) -> Result<(), CheckError> {
    let (cache, index) = policy
        .reconsult_check_pair(receipt)
        .map_err(|error| match error {
            crate::policy::CheckIssuerError::OwnerEnded => CheckError::CacheRevoked {
                detail: "a dependency grant of the pair is revoked or its owner ended".to_string(),
            },
            other => CheckError::CacheDenied {
                detail: format!("the dependency pair no longer admits: {other}"),
            },
        })?;
    for (grant, label) in [(cache, "cache"), (index, "index")] {
        if policy.covers(&grant.scope_root) {
            return Err(CheckError::CacheDenied {
                detail: format!("the deny policy covers the {label} dependency root"),
            });
        }
    }
    Ok(())
}

// ----- confined phase observation ----------------------------------------

/// Why a confined check phase ended without its own observation: a stop
/// the observer caused, or an observation failure. The caller maps each
/// to its phase's typed seam.
#[derive(Debug)]
enum PhaseStop {
    Cancelled,
    Deadline,
    /// macOS sampled group RSS crossed the DEC-040 ceiling; Linux keeps
    /// its hard total bound in the tmpfs quota and rlimits instead.
    #[cfg(target_os = "macos")]
    AggregateRss,
    /// A descendant held the phase pipes open after the leader-exit
    /// killpg — on Linux that is the signal seam (escape denied, but the
    /// drain window closed); on macOS it feeds the accepted residual.
    #[cfg(any(test, target_os = "macos"))]
    DescendantHoldsPipes,
    ObserveFailed(std::io::Error),
}

/// Head+tail captures of both streams plus the leader's exit status.
struct PhaseObserved {
    status: ExitStatus,
    stdout: BoundedCapture,
    stderr: BoundedCapture,
}

/// The fixed environment one confined check phase runs with — exactly
/// these keys, nothing ambient, never a host `RUSTUP_*` or credential.
pub const CHECK_ENV_KEYS: [&str; 4] = ["CARGO_HOME", "HOME", "PATH", "TMPDIR"];

/// Applies the fixed check environment to an already env-cleared command.
fn apply_check_env(
    command: &mut Command,
    cargo_home: &Path,
    home: &Path,
    tmpdir: &Path,
    path: &str,
    sdkroot: Option<&Path>,
) {
    command
        .env("CARGO_HOME", cargo_home)
        .env("HOME", home)
        .env("TMPDIR", tmpdir)
        .env("PATH", path);
    if let Some(sdkroot) = sdkroot {
        command.env("SDKROOT", sdkroot);
    }
}

/// The live pipes and captures of one running phase, plus the loop's
/// own step and finish logic.
#[cfg(any(test, target_os = "macos"))]
struct PhasePipes<T: Read + AsFd, U: Read + AsFd> {
    stdout: Option<T>,
    stderr: Option<U>,
    stdout_capture: BoundedCapture,
    stderr_capture: BoundedCapture,
}

/// One iteration of the running-phase loop: drain both pipes into their
/// bounded captures, then apply the stops in their fixed order —
/// cancellation, deadline, and the macOS sampled group-RSS ceiling.
#[cfg(any(test, target_os = "macos"))]
enum Step {
    Continue,
    Stop(PhaseStop),
}

#[cfg(any(test, target_os = "macos"))]
impl<T: Read + AsFd, U: Read + AsFd> PhasePipes<T, U> {
    fn new(stdout: Option<T>, stderr: Option<U>) -> Self {
        Self {
            stdout,
            stderr,
            stdout_capture: BoundedCapture::empty(),
            stderr_capture: BoundedCapture::empty(),
        }
    }

    /// Marks both live pipes nonblocking; a failure names the phase's
    /// observation seam.
    fn setup(&mut self) -> Result<(), std::io::Error> {
        if let Some(pipe) = self.stdout.as_ref() {
            pipe_nonblocking(pipe.as_fd())
                .map_err(|error| std::io::Error::other(error.to_string()))?;
        }
        if let Some(pipe) = self.stderr.as_ref() {
            pipe_nonblocking(pipe.as_fd())
                .map_err(|error| std::io::Error::other(error.to_string()))?;
        }
        Ok(())
    }

    // tick/leader feed only the macOS sampled group-RSS stop, so a
    // Linux build sees them unused; the expectation is cfg'd to the
    // platforms where it holds.
    #[cfg_attr(
        not(target_os = "macos"),
        expect(
            unused_variables,
            reason = "tick and leader feed the macOS-only sampled group-RSS stop"
        )
    )]
    fn step(
        &mut self,
        cancel: &std::sync::atomic::AtomicBool,
        deadline: Instant,
        tick: u32,
        leader: u32,
    ) -> Step {
        let drained = drain_phase(&mut self.stdout, &mut self.stdout_capture)
            .and_then(|()| drain_phase(&mut self.stderr, &mut self.stderr_capture));
        if let Err(source) = drained {
            return Step::Stop(PhaseStop::ObserveFailed(source));
        }
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return Step::Stop(PhaseStop::Cancelled);
        }
        if Instant::now() >= deadline {
            return Step::Stop(PhaseStop::Deadline);
        }
        #[cfg(target_os = "macos")]
        if tick.is_multiple_of(50) && group_rss_over_ceiling(leader) {
            return Step::Stop(PhaseStop::AggregateRss);
        }
        Step::Continue
    }

    /// Reads once from one pipe into its bounded capture; EOF closes it.
    fn readable(&self) -> Vec<BorrowedFd<'_>> {
        self.stdout
            .as_ref()
            .map(AsFd::as_fd)
            .into_iter()
            .chain(self.stderr.as_ref().map(AsFd::as_fd))
            .collect()
    }

    /// The post-exit tail: SIGKILL the process group so a grandchild
    /// cannot hold the write ends, then drain both pipes to EOF inside a
    /// bounded window. A write end still held after the kill closes the
    /// window as [`PhaseStop::DescendantHoldsPipes`].
    fn finish(
        mut self,
        child_id: u32,
        deadline: Instant,
        status: ExitStatus,
    ) -> Result<PhaseObserved, PhaseStop> {
        drop(rivect_sandbox_helper::kill_process_group(child_id));
        let drain_deadline = deadline + CONFINED_DEADLINE;
        while self.stdout.is_some() || self.stderr.is_some() {
            if Instant::now() >= drain_deadline {
                return Err(PhaseStop::DescendantHoldsPipes);
            }
            let drained = drain_phase(&mut self.stdout, &mut self.stdout_capture)
                .and_then(|()| drain_phase(&mut self.stderr, &mut self.stderr_capture));
            if let Err(source) = drained {
                return Err(PhaseStop::ObserveFailed(source));
            }
            let readable = self.readable();
            if !readable.is_empty()
                && rivect_sandbox_helper::wait_ready(&readable, &[], OBSERVE_POLL_SLICE).is_err()
            {
                return Err(PhaseStop::ObserveFailed(std::io::Error::other(
                    "the post-exit drain poll failed",
                )));
            }
        }
        Ok(PhaseObserved {
            status,
            stdout: self.stdout_capture,
            stderr: self.stderr_capture,
        })
    }
}

/// Reads once from one pipe into its bounded capture; EOF closes it.
#[cfg(any(test, target_os = "macos"))]
fn drain_phase<V: Read>(
    pipe: &mut Option<V>,
    capture: &mut BoundedCapture,
) -> Result<(), std::io::Error> {
    let Some(reader) = pipe.as_mut() else {
        return Ok(());
    };
    let mut scratch = [0u8; 8192];
    match reader.read(&mut scratch) {
        Ok(0) => {
            *pipe = None;
            Ok(())
        }
        Ok(n) => {
            capture.extend(&scratch[..n]);
            Ok(())
        }
        Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::Interrupted =>
        {
            Ok(())
        }
        Err(source) => Err(source),
    }
}

/// Observes one confined check phase to its end: nonblocking pipes, a
/// poll idle wait, cancellation, the wall deadline, and the macOS sampled
/// group-RSS stop inside the loop; the leader-exit killpg and a bounded
/// post-exit drain after. Capture keeps head+tail+total per stream.
#[cfg(any(test, target_os = "macos"))]
fn observe_check_phase(
    child: &mut Child,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    cancel: &std::sync::atomic::AtomicBool,
    deadline: Instant,
) -> Result<PhaseObserved, PhaseStop> {
    let leader = child.id();
    let mut pipes = PhasePipes::new(stdout, stderr);
    if let Err(source) = pipes.setup() {
        terminate_confined_child(child);
        return Err(PhaseStop::ObserveFailed(source));
    }
    let mut tick = 0u32;
    loop {
        match pipes.step(cancel, deadline, tick, leader) {
            Step::Continue => {}
            Step::Stop(stop) => {
                terminate_confined_child(child);
                return Err(stop);
            }
        }
        tick = tick.wrapping_add(1);
        match child.try_wait() {
            Ok(Some(status)) => return pipes.finish(child.id(), deadline, status),
            Ok(None) => {
                let readable = pipes.readable();
                if let Err(source) =
                    rivect_sandbox_helper::wait_ready(&readable, &[], OBSERVE_POLL_SLICE)
                {
                    terminate_confined_child(child);
                    return Err(PhaseStop::ObserveFailed(source));
                }
            }
            Err(source) => {
                terminate_confined_child(child);
                return Err(PhaseStop::ObserveFailed(source));
            }
        }
    }
}

/// Darwin `ESRCH` (errno 3): `proc_pid_rusage` reports it for a pid that
/// was reaped between the group enumeration and this sample.
#[cfg(target_os = "macos")]
const ESRCH: i32 = 3;

/// Whether the sampled group RSS crossed the DEC-040 ceiling. The
/// ceiling is a GROUP bound: the SUM of every member's resident bytes
/// is compared, because a hog that fans out across children each
/// comfortably under the ceiling would slip a per-member comparison
/// while holding the same memory. An unreadable member fails the
/// sample closed (an unmeasured group is never taken as under budget);
/// a member reaped between the enumeration and the sample (ESRCH)
/// holds no resident bytes — a vanished member is not an unmeasured
/// one.
#[cfg(target_os = "macos")]
fn group_rss_over_ceiling(leader: u32) -> bool {
    group_rss_sum_over(leader, rivect_sandbox_helper::CHECK_GROUP_RSS_BYTES)
}

/// The sum-semantics core of [`group_rss_over_ceiling`] with the
/// ceiling injected: the sampler's discriminating unit tests drive a
/// live group across a small ceiling instead of the 4 GiB production
/// one.
#[cfg(target_os = "macos")]
fn group_rss_sum_over(leader: u32, ceiling: u64) -> bool {
    let Ok(members) = rivect_sandbox_helper::process_group_members(leader) else {
        return true;
    };
    let mut sum: u64 = 0;
    for pid in members {
        match rivect_sandbox_helper::resident_bytes(pid) {
            Ok(rss) => sum = sum.saturating_add(rss),
            Err(rivect_sandbox_helper::ProcessReadError::ReadFailed { source, .. })
                if source.raw_os_error() == Some(ESRCH) => {}
            Err(_) => return true,
        }
    }
    sum > ceiling
}

// ----- confined check orchestration --------------------------------------

/// Both versions of the check identity: `cargo-test-v1` binds target +
/// exact test + admitted harness threads + project digest;
/// `cargo-test-v2` adds the immutable vendor digest (a dependency-free
/// run hashes the `-` sentinel).
pub fn check_command_digest(
    project_digest: &str,
    vendor_digest: Option<&str>,
    target: &str,
    exact_test: &str,
    harness_threads: u32,
) -> (String, String) {
    let v1 = hex(&sha2::Sha256::digest(
        format!("cargo-test-v1|{target}|{exact_test}|{harness_threads}|{project_digest}")
            .as_bytes(),
    ));
    let v2 = hex(&sha2::Sha256::digest(
        format!(
            "cargo-test-v2|{target}|{exact_test}|{harness_threads}|{project_digest}|{}",
            vendor_digest.unwrap_or("-")
        )
        .as_bytes(),
    ));
    (v1, v2)
}

/// One exclusive attempt root under the process temp directory: the
/// name is the server-owned attempt id itself — unique and
/// unpredictable, so only this process populates it. The name is public
/// because it is derivable from the public attempt id; the right to
/// remove it is not the name — only the recorded dev/ino identity of
/// the exclusive creation is.
pub fn attempt_root_of(attempt_id: &str) -> PathBuf {
    std::env::temp_dir().join(format!("rivect-check-{attempt_id}"))
}

/// One exclusively created attempt root allocation with its verified
/// on-disk identity (the dev/ino of the created directory, read through
/// a nofollow fd walk — never an lstat-then-act): removal re-verifies
/// the identity, so a pre-existing, substituted, renamed, or name-reused
/// directory is refused, never deleted.
#[derive(Debug, Clone)]
pub(crate) struct AttemptRoot {
    pub(crate) attempt_id: String,
    pub(crate) canonical_root: PathBuf,
    pub(crate) dev: u64,
    pub(crate) ino: u64,
}

/// The observed outcome of one owned-root cleanup attempt.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RootRemoval {
    /// No directory exists at the recorded name: the observation
    /// discharges the cleanup obligation without any destructive
    /// effect.
    Absent,
    /// The removal did not run to completion; nothing was touched.
    /// A refusal over a present, identity-verified root preserves the
    /// debris byte-for-byte and leaves the cleanup obligation open —
    /// it is never a success and never retires `cleanup.root`
    /// (DEC-056 strict protection).
    Refused(String),
}

/// The durable retirement cause of a cleanup that finished: only an
/// absent root retires the attempt's cleanup authority; a refusal
/// retires nothing and leaves the obligation pending for the next
/// reconcile or a human resolution.
pub(crate) fn retirement_cause(outcome: &RootRemoval) -> Option<&'static str> {
    match outcome {
        RootRemoval::Absent => Some("cleanup retired: no directory exists at the recorded root"),
        RootRemoval::Refused(_) => None,
    }
}

/// Durably retires one attempt's cleanup authority (`cleanup.root`): a
/// restart never re-authorizes deletion at a recycled name or inode,
/// and a successful cleanup is never represented by the pathname alone.
///
/// # Errors
/// Returns the store's typed error when the row cannot be written.
pub(crate) fn retire_cleanup_authority(
    store: &mut TaskStore,
    attempt_id: &str,
    cause: &str,
) -> Result<(), StoreError> {
    store.retain_attempt(&crate::verification::RetainedAttempt {
        attempt_id: attempt_id.to_string(),
        boundary_id: check_boundary_id(attempt_id, "cleanup.root"),
        stage: crate::verification::RetainedStage::Terminal,
        cause: cause.to_string(),
        digest: crate::verification::record_digest(attempt_id, cause),
        build_attempt: attempt_id.to_string(),
        admitted_attempt_id: Some(attempt_id.to_string()),
    })
}

/// The bounded, non-secret locator record of one attempt root: the
/// canonical path — hex-encoded byte-for-byte, so any delimiter the
/// path itself contains and any non-UTF-8 temp directory round-trip
/// losslessly — plus the dev/ino identity verified at creation. The
/// durable row makes DEC-047 cleanup-resume independent of any later
/// environment: the recorded canonical root, never a recomputed
/// temp-directory path, is the allocation.
pub(crate) fn attempt_root_record_cause(root: &AttemptRoot) -> String {
    format!(
        "root-hex={} dev={} ino={}",
        hex(root.canonical_root.as_os_str().as_encoded_bytes()),
        root.dev,
        root.ino
    )
}

/// Parses the locator record written at creation; `None` for any other
/// cause shape — never a guess. Metadata is parsed from the tail, so
/// the hex path cannot collide with the ` dev=`/` ino=` delimiters.
pub(crate) fn parse_attempt_root_cause(cause: &str) -> Option<(PathBuf, u64, u64)> {
    let rest = cause.strip_prefix("root-hex=")?;
    let (path_hex, rest) = rest.split_once(" dev=")?;
    let (dev, ino) = rest.split_once(" ino=")?;
    if path_hex.is_empty() || path_hex.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(path_hex.len() / 2);
    let hex_digits = path_hex.as_bytes();
    let mut index = 0;
    while index < hex_digits.len() {
        let high = (hex_digits[index] as char).to_digit(16)?;
        let low = (hex_digits[index + 1] as char).to_digit(16)?;
        bytes.push((high * 16 + low) as u8);
        index += 2;
    }
    Some((
        PathBuf::from(<std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(&bytes)),
        dev.parse().ok()?,
        ino.parse().ok()?,
    ))
}

/// Opens `path` through a nofollow fd walk from the filesystem root and
/// returns the directory's fstat identity. The path is canonical (every
/// component already resolved), so a symlinked name squatting on any
/// component refuses here instead of resolving.
fn anchored_dir_identity(path: &Path) -> Result<rivect_sandbox_helper::FdIdentity, String> {
    let mut current = rivect_sandbox_helper::open_filesystem_root()
        .map_err(|error| format!("filesystem root open: {error}"))?;
    for component in path.components().skip(1) {
        current = rivect_sandbox_helper::openat_directory(
            &current,
            component.as_os_str().as_encoded_bytes(),
        )
        .map_err(|error| format!("root component open: {error}"))?;
    }
    Ok(current.identity)
}

/// Creates the attempt's exclusive private root and durably records the
/// canonical locator with its verified identity
/// (`ret:check:<attempt>:attempt.root`) through the existing
/// retained-table owner, so DEC-047 cleanup-resume finds the allocation
/// independent of any later environment. Creation is `create_dir`, not
/// `create_dir_all`: a pre-existing directory, symlink, or any other
/// name squatter refuses typed, and the refusal never deletes from or
/// writes into the foreign path. The window between the creation and
/// the durable record is a recorded residual: a crash there leaves an
/// unowned empty directory no cleanup claims — never a wrong delete.
pub(crate) fn create_recorded_attempt_root(
    store: &mut TaskStore,
    attempt_id: &str,
) -> Result<AttemptRoot, CheckError> {
    let raw = attempt_root_of(attempt_id);
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(&raw)
        .map_err(|source| CheckError::CopyFailed {
            detail: format!(
                "attempt root creation at {} refused: {source} — an existing path is never adopted",
                raw.display()
            ),
        })?;
    let canonical = raw
        .canonicalize()
        .map_err(|source| CheckError::CopyFailed {
            detail: format!("attempt root canonicalization: {source}"),
        })?;
    let identity = anchored_dir_identity(&canonical).map_err(|detail| CheckError::CopyFailed {
        detail: format!("attempt root identity anchor: {detail}"),
    })?;
    let root = AttemptRoot {
        attempt_id: attempt_id.to_string(),
        canonical_root: canonical,
        dev: identity.dev,
        ino: identity.ino,
    };
    let cause = attempt_root_record_cause(&root);
    let record = crate::verification::RetainedAttempt {
        attempt_id: attempt_id.to_string(),
        boundary_id: check_boundary_id(attempt_id, "attempt.root"),
        stage: crate::verification::RetainedStage::PreEffect,
        digest: crate::verification::record_digest(attempt_id, &cause),
        cause,
        build_attempt: attempt_id.to_string(),
        admitted_attempt_id: Some(attempt_id.to_string()),
    };
    store
        .retain_attempt(&record)
        .map_err(|source| CheckError::EvidenceRetention {
            detail: format!("the attempt root locator record failed: {source}"),
        })?;
    Ok(root)
}

/// Decides one recorded allocation's cleanup without ever performing an
/// unprovable destructive effect. The read-only verification walk is
/// unchanged: the canonical root is re-anchored with a nofollow fd walk
/// from the filesystem root and its `(dev, ino)` compared with the
/// record — a missing name answers [`RootRemoval::Absent`] (the
/// obligation is discharged without touching anything), while a
/// symlink, a foreign kind, or an identity mismatch answers
/// [`RootRemoval::Refused`] before any effect.
///
/// What this deliberately does NOT do (DEC-056 strict protection): a
/// present, identity-verified root is still refused. No admitted
/// platform primitive on Linux or Darwin binds a by-name child removal
/// to the inode that was observed — a plain child unlink addresses
/// whatever holds the name at call time (a raced child swap), and a
/// re-verified directory rmdir leaves a stale-inode/name reuse window —
/// and hostile writers cannot be assumed quiescent without proof.
/// Refusing before the first destructive effect preserves the debris
/// byte-for-byte (its permissions included) and leaves the cleanup
/// obligation pending; the diagnostic names the manual resolution. No
/// no-op success or emptied fallback exists.
pub(crate) fn remove_recorded_attempt_root(
    canonical_root: &Path,
    dev: u64,
    ino: u64,
) -> RootRemoval {
    let mut current = match rivect_sandbox_helper::open_filesystem_root() {
        Ok(root) => root,
        Err(error) => {
            return RootRemoval::Refused(format!("the filesystem root anchor: {error}"));
        }
    };
    let components: Vec<std::ffi::OsString> = canonical_root
        .components()
        .skip(1)
        .map(|component| component.as_os_str().to_os_string())
        .collect();
    let Some(root_name) = components.last() else {
        return RootRemoval::Refused("the recorded root has no name".to_string());
    };
    for component in &components[..components.len() - 1] {
        match rivect_sandbox_helper::openat_directory(
            &current,
            component.as_os_str().as_encoded_bytes(),
        ) {
            Ok(next) => current = next,
            Err(rivect_sandbox_helper::FdOpenError::Missing) => {
                return RootRemoval::Absent;
            }
            Err(error) => {
                return RootRemoval::Refused(format!(
                    "the recorded root's parent walk refused at {}: {error}",
                    component.to_string_lossy()
                ));
            }
        }
    }
    let root_dir = match rivect_sandbox_helper::openat_directory(
        &current,
        root_name.as_os_str().as_encoded_bytes(),
    ) {
        Ok(dir) => dir,
        Err(rivect_sandbox_helper::FdOpenError::Missing) => return RootRemoval::Absent,
        Err(error) => {
            return RootRemoval::Refused(format!(
                "the recorded root name refused: {error} — a symlink or foreign kind is never adopted"
            ));
        }
    };
    if root_dir.identity.dev != dev || root_dir.identity.ino != ino {
        return RootRemoval::Refused(
            "identity mismatch: the recorded root name holds a different directory".to_string(),
        );
    }
    RootRemoval::Refused(
        "no admitted platform primitive binds a by-name child removal to the observed inode; \
         raced child files and stale inode/name reuse cannot be proven safe, so strict \
         protection refuses before any destructive effect and preserves the debris for \
         manual resolution"
            .to_string(),
    )
}

fn phase_setup_failed(error: WorkerError) -> CheckError {
    CheckError::VendorSetup {
        detail: format!("the check confinement could not be built: {error}"),
    }
}

/// The private environment of one attempt: a private cargo home under rw,
/// a private HOME, a private TMPDIR, and a PATH of exactly the toolchain
/// plus the system bin directories. On Linux the parent stages dependency
/// bytes into `staged_source` outside the namespace mount; the namespace
/// script copies them into the bounded rw tmpfs before Cargo runs.
struct CheckPhaseEnv {
    cargo_home: PathBuf,
    staged_source: Option<PathBuf>,
    home: PathBuf,
    tmpdir: PathBuf,
    path: String,
}

fn check_phase_env(attempt_root: &Path, toolchain: &Path) -> CheckPhaseEnv {
    let rw = attempt_root.join("rw");
    #[cfg(target_os = "linux")]
    let staged_source = Some(attempt_root.join("staged-cargo-home"));
    #[cfg(not(target_os = "linux"))]
    let staged_source = None;
    CheckPhaseEnv {
        cargo_home: rw.join("cargo-home"),
        staged_source,
        home: rw.join("home"),
        tmpdir: rw.join("tmp"),
        path: format!("{}:/usr/bin:/bin", toolchain.display()),
    }
}

/// The recorded candidate identity of one workspace tree: the bounded
/// inventory digest `ConfinedCheck::expected_candidate_digest` binds.
///
/// # Errors
/// Returns [`CheckError::InventoryRefused`] when the tree is not
/// bounded-inventory safe.
pub fn workspace_digest(root: &Path) -> Result<String, CheckError> {
    inventory(root)
        .map(|tree| tree.digest)
        .map_err(|error| CheckError::InventoryRefused {
            detail: format!("{error}"),
        })
}

/// The canonical toolchain `bin` directory of a canonical cargo: the
/// parent must also hold `rustc` — the rustup proxy directory does not,
/// and a proxy is never the toolchain root (Known-Gotchas, DEC-041).
fn toolchain_bin_dir(cargo: &Path) -> Result<PathBuf, CheckError> {
    let canonical = cargo
        .canonicalize()
        .map_err(|source| CheckError::TargetLayout {
            detail: format!(
                "cargo {} cannot be canonicalized: {source}",
                cargo.display()
            ),
        })?;
    let Some(parent) = canonical.parent().map(Path::to_path_buf) else {
        return Err(CheckError::TargetLayout {
            detail: format!("cargo {} has no parent directory", canonical.display()),
        });
    };
    if !parent.join("rustc").is_file() {
        return Err(CheckError::TargetLayout {
            detail: format!(
                "{} is not a toolchain bin directory: no sibling rustc (the rustup proxy is not a toolchain root)",
                parent.display()
            ),
        });
    }
    Ok(parent)
}

/// The effective sandbox read/execute roots of one check, read out of
/// the platform profile builders themselves — the Landlock rule list
/// and the Seatbelt profile text are both pure renderers, so the
/// disjointness gate tracks the ACTUAL allowances of both siblings
/// without a second spelling of them and without executing any
/// platform code (DEC-056). Seatbelt renders against a stand-in for the
/// not-yet-created attempt layout (its roots canonicalize); the real
/// attempt `src`/`rw` join the set directly. Only subtree allowances
/// count: the dyld `literal "/"` stat allowance is a single-inode
/// grant, not a subtree.
fn effective_check_roots(
    check: &ConfinedCheck,
    attempt_root: &Path,
) -> Result<Vec<PathBuf>, CheckError> {
    // The toolchain root this check would execute from. A cargo without
    // a sibling rustc is refused later at the phase command; the gate
    // still guards the one directory that cargo's own grant covers.
    let bin = match toolchain_bin_dir(&check.cargo) {
        Ok(bin) => bin,
        Err(_) => check
            .cargo
            .canonicalize()
            .ok()
            .and_then(|cargo| cargo.parent().map(Path::to_path_buf))
            .ok_or_else(|| CheckError::TargetLayout {
                detail: "the cargo has no resolvable toolchain directory".to_string(),
            })?,
    };
    let toolchain = bin.parent().map_or_else(|| bin.clone(), Path::to_path_buf);
    let snapshot = attempt_root.join("src");
    let rw = attempt_root.join("rw");
    let mut roots: Vec<PathBuf> = linux::check_landlock_rules(&linux::CheckRules {
        toolchain: toolchain.clone(),
        snapshot: snapshot.clone(),
        rw: rw.clone(),
        test_binaries: true,
    })
    .iter()
    .filter_map(|rule| {
        let (_, rest) = rule.split_once("path-beneath:")?;
        let (_, path) = rest.split_once(':')?;
        Some(PathBuf::from(path))
    })
    .collect();
    let profile = macos::check_profile(&macos::CheckProfile {
        toolchain: toolchain.clone(),
        snapshot: toolchain.clone(),
        rw: toolchain,
        test_binaries: true,
    })
    .map_err(|error| CheckError::TargetLayout {
        detail: format!("the seatbelt root derivation refused: {error}"),
    })?;
    roots.extend(profile.lines().filter_map(seatbelt_subpath));
    roots.push(snapshot);
    roots.push(rw);
    roots.sort();
    roots.dedup();
    Ok(roots)
}

/// The path of one `(subpath "…")` allowance in a rendered Seatbelt
/// profile line; `None` for any other rule shape.
fn seatbelt_subpath(line: &str) -> Option<PathBuf> {
    let (_, rest) = line.split_once("(subpath \"")?;
    let (quoted, _) = rest.split_once("\")")?;
    Some(PathBuf::from(
        quoted.replace("\\\"", "\"").replace("\\\\", "\\"),
    ))
}

/// The cargo-home disjointness gate (DEC-056): the canonical cargo home
/// must not overlap ANY effective sandbox read/execute root of either
/// platform profile — in either direction — not merely the project and
/// attempt roots. A non-canonical or unobservable root is compared by
/// its spelling and still refuses on overlap.
fn assert_cargo_home_disjoint(
    check: &ConfinedCheck,
    cargo_home: &Path,
    attempt_root: &Path,
) -> Result<(), CheckError> {
    for root in effective_check_roots(check, attempt_root)? {
        let canonical = root.canonicalize().unwrap_or_else(|_| root.clone());
        if canonical.starts_with(cargo_home) || cargo_home.starts_with(&canonical) {
            return Err(CheckError::TargetLayout {
                detail: format!(
                    "the cargo home {} overlaps the effective sandbox root {}",
                    cargo_home.display(),
                    canonical.display()
                ),
            });
        }
    }
    Ok(())
}

/// Builds the platform check-phase command for one Cargo argv. macOS
/// composes the helper's check rlimits with `sandbox-exec -p <check
/// profile>`; Linux runs the namespace script that mounts the bounded rw
/// tmpfs through check-setup, then the Landlock/seccomp chain.
#[cfg(target_os = "macos")]
fn check_linker_config_args() -> Vec<std::ffi::OsString> {
    let Some(linker) = macos::check_linker_toolchain() else {
        return Vec::new();
    };
    vec![
        "--config".into(),
        format!(
            "target.{}-apple-darwin.linker='{}'",
            std::env::consts::ARCH,
            linker.clang.display()
        )
        .into(),
    ]
}

/// Builds the platform check-phase command for one Cargo argv. macOS
/// composes the helper's check rlimits with `sandbox-exec -p <check
/// profile>`; Linux runs the namespace script that mounts the bounded rw
/// tmpfs through check-setup, then the Landlock/seccomp chain.
fn check_phase_command(
    check: &ConfinedCheck,
    attempt_root: &Path,
    cargo_args: &[std::ffi::OsString],
    test_binaries: bool,
    env: &CheckPhaseEnv,
) -> Result<PreparedLaunch, CheckError> {
    let toolchain = toolchain_bin_dir(&check.cargo)?;
    // The allowance anchors at the toolchain ROOT (bin + lib): rustc's
    // driver dylib lives beside the binaries, not inside bin/.
    let toolchain = toolchain
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or(toolchain);
    #[cfg(target_os = "linux")]
    let mut command = linux::check_phase_command(
        &linux::CheckRules {
            toolchain,
            snapshot: attempt_root.join("src"),
            rw: attempt_root.join("rw"),
            test_binaries,
        },
        attempt_root,
        env.staged_source.as_deref(),
        &check.cargo,
        cargo_args,
    )
    .map_err(phase_setup_failed)?;
    #[cfg(not(target_os = "linux"))]
    let mut command = {
        let mut command = helper_check_launch_command().map_err(phase_setup_failed)?;
        command
            .arg(macos::SANDBOX_EXEC)
            .arg("-p")
            .arg(
                macos::check_profile(&macos::CheckProfile {
                    toolchain,
                    snapshot: attempt_root.join("src"),
                    rw: attempt_root.join("rw"),
                    test_binaries,
                })
                .map_err(|error| CheckError::VendorSetup {
                    detail: format!("seatbelt check profile: {error}"),
                })?,
            )
            .arg("--")
            .arg(&check.cargo)
            .args(cargo_args);
        command
    };
    // Both platform arms cross the same spawn boundary discipline: an
    // env-cleared, own-group child (standards §10). The Linux namespace
    // chain never clears the environment itself, and without this the
    // confined child inherits the whole host env beside the fixed
    // allowlist applied below — the rust image's SSL_CERT_DIR was
    // observable inside the sandbox exactly that way (T10 follow-up).
    command.env_clear();
    #[cfg(target_os = "macos")]
    let sdkroot = macos::check_linker_toolchain().map(|linker| linker.sdkroot);
    #[cfg(not(target_os = "macos"))]
    let sdkroot: Option<PathBuf> = None;
    apply_check_env(
        &mut command.payload,
        &env.cargo_home,
        &env.home,
        &env.tmpdir,
        &env.path,
        sdkroot.as_deref(),
    );
    // The confined child works from its own snapshot: `getcwd` stays
    // inside the read allowances instead of the parent's checkout.
    command.current_dir(attempt_root.join("src"));

    Ok(command)
}

/// Spawns and observes one check phase, mapping every stop to the
/// phase's typed seams through `map`. The observation runs under the
/// ONE absolute deadline the admission armed — never a fresh full
/// budget per phase (DEC-056).
fn run_check_phase(
    mut command: PreparedLaunch,
    cancel: &std::sync::atomic::AtomicBool,
    deadline: Instant,
    map: &dyn Fn(PhaseStop) -> CheckError,
) -> Result<PhaseObserved, CheckError> {
    command.deadline = deadline;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let predicate = || cancel.load(std::sync::atomic::Ordering::Acquire);
    let bounds = ObserveBounds {
        deadline,
        stdout_cap: 0,
        stop: |_| {
            if predicate() {
                Some(PhaseStop::Cancelled)
            } else {
                None
            }
        },
        stdin_close_ends_payload: false,
    };
    #[cfg(target_os = "macos")]
    {
        if predicate() {
            return Err(map(PhaseStop::Cancelled));
        }
        if Instant::now() >= deadline {
            return Err(map(PhaseStop::Deadline));
        }
        let mut child = command
            .spawn_legacy()
            .map_err(|source| CheckError::OwnedLaunch {
                detail: "check phase could not be started".to_string(),
                source: OwnedCheckSource {
                    primary: Box::new(map(PhaseStop::ObserveFailed(std::io::Error::other(
                        "check phase could not be started",
                    )))),
                    worker: std::sync::Arc::new(source),
                },
            })?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        return observe_check_phase(&mut child, stdout, stderr, cancel, deadline).map_err(map);
    }
    #[cfg(target_os = "linux")]
    match command.run_owned(&[], Some(&predicate), bounds, &|stop| match stop {
        PhaseStop::Cancelled => rivect_sandbox_helper::OwnedStop::Cancelled,
        PhaseStop::Deadline => rivect_sandbox_helper::OwnedStop::Deadline,
        _ => rivect_sandbox_helper::OwnedStop::Observation,
    }) {
        Ok(OwnedObserve::Exited(output)) => Ok(PhaseObserved {
            status: output.status,
            stdout: output.stdout_capture,
            stderr: output.stderr_capture,
        }),
        Ok(OwnedObserve::Stopped(reason)) => Err(map(reason)),
        Err(worker) => {
            let stop = match &worker {
                WorkerError::OwnedParent { source } => source.request_stop(),
                WorkerError::ConfinedRunTimedOut => {
                    Some(rivect_sandbox_helper::OwnedStop::Deadline)
                }
                _ => owned_observed_stop(&worker),
            };
            let worker = std::sync::Arc::new(worker);
            let primary = map(match stop {
                Some(rivect_sandbox_helper::OwnedStop::Cancelled) => PhaseStop::Cancelled,
                Some(rivect_sandbox_helper::OwnedStop::Deadline) => PhaseStop::Deadline,
                _ => PhaseStop::ObserveFailed(std::io::Error::other(
                    "owned check observation failed",
                )),
            });
            Err(CheckError::OwnedLaunch {
                detail: primary.detail().to_string(),
                source: OwnedCheckSource {
                    primary: Box::new(primary),
                    worker,
                },
            })
        }
    }
}

/// The evidence expectations one control leg's denial must satisfy: the
/// read and write legs require EVERY evidence string — the read leg's
/// exact secret path included, never just the probe's name (CR A2) —
/// while the network leg requires its own operation words.
fn control_leg_expectations(label: &str, evidence: &[&str]) -> (Vec<String>, Vec<String>) {
    match label {
        "network" => (
            Vec::new(),
            vec!["socket".to_string(), "connect".to_string()],
        ),
        _ => (
            evidence.iter().map(|needle| needle.to_string()).collect(),
            Vec::new(),
        ),
    }
}

/// One deny-first control leg: the confined control must FAIL (a nonzero
/// exit) with its own denial cause — the stderr must name the leg's
/// target (an exec denial names no target) and an OS permission wording.
/// An admitted control, or a control failing for the wrong reason, means
/// the boundary does not enforce, which is a setup refusal before any
/// real phase spawns.
fn run_check_control(
    command: PreparedLaunch,
    label: &str,
    cancel: &std::sync::atomic::AtomicBool,
    deadline: Instant,
) -> Result<PhaseObserved, CheckError> {
    let observed = run_check_phase(command, cancel, deadline, &|stop| match stop {
        PhaseStop::Cancelled => CheckError::VendorCancel {
            detail: format!("cancellation during the {label} control"),
        },
        PhaseStop::Deadline => CheckError::VendorDeadline {
            detail: format!("deadline during the {label} control"),
        },
        other => CheckError::VendorSetup {
            detail: format!("the {label} control observation stopped: {other:?}"),
        },
    })?;
    if observed.status.success() {
        return Err(CheckError::VendorSetup {
            detail: format!("the confined check boundary admitted the {label} control"),
        });
    }
    Ok(observed)
}

/// The OS permission wordings the control denials may carry: Seatbelt
/// and seccomp answer EPERM ("Operation not permitted"), Landlock
/// answers EACCES ("Permission denied"). Any other failure text is the
/// probe's own defect, not the boundary's denial.
const CONTROL_DENIED_CAUSES: [&str; 2] = ["Operation not permitted", "Permission denied"];

/// Exec-failure wordings the exec boundary produces (`sandbox-exec`'s
/// execvp report, the helper's launch exec failure). An exec denial
/// names the PROGRAM, never the leg's data target, and proves nothing
/// about the read/write rules — accepting its permission wording as a
/// data denial green-lights a mechanism that denied only the exec (the
/// CR probe: a read-allowed/exec-denied profile exits 71 naming cat
/// with zero read attempts).
const CONTROL_EXEC_FAILURES: [&str; 2] = ["execvp() of", "exec failed"];

/// Asserts one denied control leg's own cause: the stderr carries no
/// exec-failure wording, names every `all` substring (for the read leg
/// that includes the exact secret path, not just the probe's name), at
/// least one of `any`, and one OS permission wording; the leg's exit
/// was already nonzero. A vacuous leg — failing because the probe is
/// broken, the shell cannot express the operation, the target is the
/// wrong kind, or the EXEC was denied instead of the data rule — fails
/// here instead of green-lighting the boundary.
fn assert_denied_control_cause(
    observed: &PhaseObserved,
    label: &str,
    all: &[String],
    any: &[String],
) -> Result<(), CheckError> {
    // The durable causes below name the leg and the fixed failure kind
    // only: raw child stderr is matched here but never persisted
    // (DEC-056) — the bounded capture stays on the observation.
    let stderr = String::from_utf8_lossy(&observed.stderr.head);
    #[cfg(target_os = "linux")]
    if linux::launcher_userns_failure(observed.status.code(), &stderr).is_some() {
        return Err(CheckError::VendorSetup {
            detail: format!(
                "the {label} control could not start: linux user namespace unavailable (unshare --user); {}",
                linux::LINUX_USERNS_RECOVERY
            ),
        });
    }
    if CONTROL_EXEC_FAILURES
        .iter()
        .any(|wording| stderr.contains(*wording))
    {
        return Err(CheckError::VendorSetup {
            detail: format!(
                "the {label} control denial is an exec failure, not the leg's own data denial"
            ),
        });
    }
    if let Some(expected) = all.iter().find(|expected| !stderr.contains(*expected)) {
        return Err(CheckError::VendorSetup {
            detail: format!(
                "the {label} control denial does not name {expected} — the leg failed for a foreign reason"
            ),
        });
    }
    if !any.is_empty() && !any.iter().any(|needle| stderr.contains(needle)) {
        return Err(CheckError::VendorSetup {
            detail: format!(
                "the {label} control denial names none of its own operations ({any:?})"
            ),
        });
    }
    if !CONTROL_DENIED_CAUSES
        .iter()
        .any(|cause| stderr.contains(cause))
    {
        return Err(CheckError::VendorSetup {
            detail: format!("the {label} control denial carries no OS permission cause"),
        });
    }
    Ok(())
}

/// The compiled loopback connect probe the network control runs: a real
/// `socket`+`connect` pair a shell cannot express (`/dev/tcp` does not
/// exist on this shell — the old leg always "succeeded at failing").
/// Exit 3 = socket refused, 4 = connect refused, 0 = connected.
const NETWORK_PROBE_SOURCE: &str = r#"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: netprobe port\n"); return 2; }
    int port = atoi(argv[1]);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 3; }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((short)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("connect");
        return 4;
    }
    close(fd);
    return 0;
}
"#;

/// Compiles the network control probe into the control binary directory
/// (outside the attempt, worker-owned). The parent compiles unconfined;
/// only the confined leg runs under the control profile.
fn compile_network_probe(bin_dir: &Path) -> Result<PathBuf, CheckError> {
    let source = bin_dir.join("netprobe.c");
    std::fs::write(&source, NETWORK_PROBE_SOURCE).map_err(|source_err| {
        CheckError::VendorSetup {
            detail: format!("the network control probe source: {source_err}"),
        }
    })?;
    let binary = bin_dir.join("netprobe");
    let mut command = Command::new("/usr/bin/cc");
    command
        .args(["-O0", "-o"])
        .arg(&binary)
        .arg(&source)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    configure_confined_command(&mut command);
    command.env("PATH", "/usr/bin:/bin");
    command.env("TMPDIR", std::env::temp_dir());
    let output = command
        .output()
        .map_err(|source_err| CheckError::VendorSetup {
            detail: format!("the network control probe compiler could not spawn: {source_err}"),
        })?;
    if !output.status.success() {
        return Err(CheckError::VendorSetup {
            detail: format!(
                "the network control probe could not be compiled: cc exited {}",
                output.status.code().unwrap_or(-1)
            ),
        });
    }
    Ok(binary)
}

/// Proves both probes work UNCONFINED before any confined leg runs: the
/// cat probe reads the secret's exact bytes and the connect probe
/// reaches the held listener. A broken probe would otherwise make every
/// confined leg "succeed at failing" (TA-I2).
fn controls_probes_work(secret: &Path, probe: &Path, port: u16) -> Result<(), CheckError> {
    let mut cat = Command::new("/bin/cat");
    cat.arg(secret)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_confined_command(&mut cat);
    let read = cat.output().map_err(|source| CheckError::VendorSetup {
        detail: format!("the read control probe could not spawn unconfined: {source}"),
    })?;
    if !read.status.success() || read.stdout != b"host-cache-secret" {
        return Err(CheckError::VendorSetup {
            detail: format!(
                "the read control probe does not work unconfined: exit={}",
                read.status.code().unwrap_or(-1)
            ),
        });
    }
    let mut connect = Command::new(probe);
    connect
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    configure_confined_command(&mut connect);
    let connected = connect.output().map_err(|source| CheckError::VendorSetup {
        detail: format!("the network control probe could not spawn unconfined: {source}"),
    })?;
    if !connected.status.success() {
        return Err(CheckError::VendorSetup {
            detail: format!(
                "the network control probe does not connect unconfined: exit={}",
                connected.status.code().unwrap_or(-1)
            ),
        });
    }
    Ok(())
}

/// The deny-first control set every attempt proves before phase A: a
/// read outside the roots, a write outside rw, and a network connect —
/// each must fail inside the check confinement with its OWN denial
/// cause (position-3 deny-first, SLICE-174 discipline). The read leg
/// cats a REGULAR secret file planted in a worker-owned control root —
/// the old directory target made `/bin/cat` fail EISDIR whether or not
/// the boundary denied, and the old network leg asked a shell for
/// `/dev/tcp`, which cannot express a socket at all.
fn run_check_controls(
    check: &ConfinedCheck,
    attempt_root: &Path,
    cancel: &std::sync::atomic::AtomicBool,
    deadline: Instant,
) -> Result<(), CheckError> {
    let toolchain_bin = toolchain_bin_dir(&check.cargo)?;
    let Some(toolchain) = toolchain_bin.parent().map(Path::to_path_buf) else {
        return Err(CheckError::TargetLayout {
            detail: "the toolchain bin has no parent root".to_string(),
        });
    };
    let outside = denied_write_candidate(
        attempt_root,
        "no securable control root outside the attempt for the denied controls",
    )
    .map_err(phase_setup_failed)?;
    let control_root = outside
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| outside.clone());
    // The probe binary lives in its own executable control directory;
    // the data directory (secret, write target) keeps NO read allowance,
    // so a granted probe exec can never read the secret through it.
    let control_bin = control_root.join("bin");
    std::fs::create_dir_all(&control_bin).map_err(|source| CheckError::VendorSetup {
        detail: format!("the control binary directory: {source}"),
    })?;
    let secret = control_root.join("secret");
    std::fs::write(&secret, b"host-cache-secret").map_err(|source| CheckError::VendorSetup {
        detail: format!("the control secret could not be written: {source}"),
    })?;
    let write_target = control_root.join("deny");
    let probe = compile_network_probe(&control_bin)?;
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|source| {
        CheckError::VendorSetup {
            detail: format!("the network control listener could not be held: {source}"),
        }
    })?;
    let port = listener
        .local_addr()
        .map_err(|source| CheckError::VendorSetup {
            detail: format!("the network control listener address is unreadable: {source}"),
        })?
        .port();
    controls_probes_work(&secret, &probe, port)?;
    let secret_text = secret.to_string_lossy().into_owned();
    let write_text = write_target.to_string_lossy().into_owned();
    let port_text = port.to_string();
    let legs: [(&str, PathBuf, Vec<std::ffi::OsString>, Vec<&str>); 3] = [
        (
            "read",
            PathBuf::from("/bin/cat"),
            vec![secret.clone().into_os_string()],
            vec!["cat", secret_text.as_str()],
        ),
        (
            "write",
            PathBuf::from("/bin/sh"),
            vec![
                "-c".into(),
                format!("echo x > {}", write_target.display()).into(),
            ],
            vec![write_text.as_str()],
        ),
        (
            "network",
            probe,
            vec![port_text.into()],
            vec!["socket", "connect"],
        ),
    ];
    for (label, program, args, evidence) in legs {
        #[cfg(target_os = "linux")]
        let mut command = linux::check_control_command(
            &linux::CheckRules {
                toolchain: toolchain.clone(),
                snapshot: attempt_root.join("src"),
                rw: attempt_root.join("rw"),
                test_binaries: false,
            },
            &program,
            &args,
            &[
                PathBuf::from("/bin/cat"),
                PathBuf::from("/bin/sh"),
                control_bin.clone(),
            ],
        )
        .map_err(phase_setup_failed)?;
        #[cfg(not(target_os = "linux"))]
        let mut command = {
            let mut command = helper_check_launch_command().map_err(phase_setup_failed)?;
            command
                .arg(macos::SANDBOX_EXEC)
                .arg("-p")
                .arg(
                    macos::check_control_profile(
                        &macos::CheckProfile {
                            toolchain: toolchain.clone(),
                            snapshot: attempt_root.join("src"),
                            rw: attempt_root.join("rw"),
                            test_binaries: false,
                        },
                        &control_bin,
                    )
                    .map_err(|error| CheckError::VendorSetup {
                        detail: format!("seatbelt control profile: {error}"),
                    })?,
                )
                .arg("--")
                .arg(&program)
                .args(&args);
            command
        };
        // Same spawn-boundary discipline on both platforms: the Linux
        // control chain also starts env-cleared and in its own group.
        command.env_clear();
        let observed = run_check_control(command, label, cancel, deadline)?;
        let (all, any) = control_leg_expectations(label, &evidence);
        assert_denied_control_cause(&observed, label, &all, &any)?;
    }
    drop(std::fs::remove_file(&secret));
    drop(std::fs::remove_file(&write_target));
    drop(std::fs::remove_dir_all(&control_bin));
    if let Some(parent) = secret.parent() {
        drop(std::fs::remove_dir(parent));
    }
    Ok(())
}

/// Copies one inventoried tree into a destination directory (the vendor
/// promotion), refusing symlinks and specials in the source — a vendor
/// output may only contain regular files and directories.
fn promote_tree(source_root: &Path, dest_root: &Path) -> Result<String, CheckError> {
    let tree = inventory(source_root).map_err(|error| CheckError::VendorValidate {
        detail: format!("vendor tree inventory refused: {error}"),
    })?;
    for entry in &tree.entries {
        if let InventoryKind::Symlink { .. } = entry.kind {
            return Err(CheckError::VendorValidate {
                detail: format!(
                    "vendor output contains a symlink at {}",
                    entry.rel.display()
                ),
            });
        }
    }
    std::fs::create_dir_all(dest_root).map_err(|source| CheckError::VendorPromote {
        detail: format!("vendor destination: {source}"),
    })?;
    copy_inventory(source_root, &tree, dest_root, &|_| false)
}

/// Maps one vendor-phase stop to its typed seam.
fn map_vendor_stop(stop: PhaseStop) -> CheckError {
    match stop {
        PhaseStop::Cancelled => CheckError::VendorCancel {
            detail: "cancellation stopped the vendor phase".to_string(),
        },
        PhaseStop::Deadline => CheckError::VendorDeadline {
            detail: "the vendor phase passed the wall deadline".to_string(),
        },
        #[cfg(target_os = "macos")]
        PhaseStop::AggregateRss => CheckError::VendorObserve {
            detail: "the sampled group RSS crossed the check ceiling".to_string(),
        },
        #[cfg(any(test, target_os = "macos"))]
        PhaseStop::DescendantHoldsPipes => CheckError::VendorSignal {
            detail: "a descendant held the vendor pipes after the stop".to_string(),
        },
        PhaseStop::ObserveFailed(source) => CheckError::VendorObserve {
            detail: format!("observing the vendor phase failed: {source}"),
        },
    }
}

/// Maps one test-phase stop to its typed seam.
fn map_test_stop(stop: PhaseStop) -> CheckError {
    match stop {
        PhaseStop::Cancelled => CheckError::TestCancel {
            detail: "cancellation stopped the test phase".to_string(),
        },
        PhaseStop::Deadline => CheckError::TestDeadline {
            detail: "the test phase passed the wall deadline".to_string(),
        },
        #[cfg(target_os = "macos")]
        PhaseStop::AggregateRss => CheckError::TestObserve {
            detail: "the sampled group RSS crossed the check ceiling".to_string(),
        },
        #[cfg(any(test, target_os = "macos"))]
        PhaseStop::DescendantHoldsPipes => CheckError::TestSignal {
            detail: "a descendant held the test pipes after the stop".to_string(),
        },
        PhaseStop::ObserveFailed(source) => CheckError::TestObserve {
            detail: format!("observing the test phase failed: {source}"),
        },
    }
}

/// The platform's honest cleanup claim (DEC-041): Linux proves the
/// descendant stop; macOS keeps the accepted residual.
fn cleanup_claim() -> CleanupClaim {
    #[cfg(target_os = "linux")]
    {
        CleanupClaim::DescendantsStopped
    }
    #[cfg(not(target_os = "linux"))]
    {
        CleanupClaim::MacosBestEffort
    }
}
/// The integration suites' helper producer, so in-crate tests that launch
/// the real helper build it first.
#[cfg(test)]
#[path = "../tests/support/helper.rs"]
pub(crate) mod test_helper;

#[cfg(test)]
mod tests {
    use super::{
        CHECK_PHASE_DEADLINE, CONFINED_DEADLINE, CheckError, EffectRequest, ObserveBounds,
        ObserveOutcome, ObservedChild, PhaseStop, WorkerError, drain_pipe_to_eof, helper_io_bytes,
        helper_launch_init_failed, helper_probe_verdict, map_test_stop, map_vendor_stop,
        observe_bounded, observe_check_phase, observe_confined_child, require_helper_file,
        sandbox_denied, spawn_failed,
    };
    use std::os::unix::process::{CommandExt as _, ExitStatusExt};
    use std::path::{Path, PathBuf};
    use std::process::{ExitStatus, Stdio};
    use std::time::Instant;

    #[cfg(target_os = "linux")]
    fn h022_converge(
        primary: Option<WorkerError>,
        release: Option<WorkerError>,
        waiter: Option<ExitStatus>,
    ) -> WorkerError {
        match super::owned_release_result(
            super::OwnedReleaseFacts {
                released: false,
                stop: Some(rivect_sandbox_helper::OwnedStop::Observation),
                waiter,
            },
            primary,
            release,
            vec![
                PathBuf::from("/inert/first"),
                PathBuf::from("/inert/second"),
            ],
            vec![
                super::FileIdentity::new(7, 11),
                super::FileIdentity::new(7, 12),
            ],
        ) {
            Err(error) => error,
            Ok(_) => unreachable!("unreleased convergence must refuse"),
        }
    }

    #[cfg(target_os = "linux")]
    fn h022_assert_custody(error: &WorkerError) -> (&WorkerError, Option<&WorkerError>) {
        let WorkerError::OwnedLaunch { source } = error else {
            unreachable!("an owned stop must preserve typed unproven custody: {error:?}");
        };
        let super::OwnedLaunchError::Unproven {
            primary,
            release,
            locators,
            expected_identities,
            stop,
        } = source.as_ref()
        else {
            unreachable!("unreleased convergence must retain custody: {source:?}");
        };
        assert_eq!(*stop, Some(rivect_sandbox_helper::OwnedStop::Observation));
        assert_eq!(
            locators,
            &[
                PathBuf::from("/inert/first"),
                PathBuf::from("/inert/second")
            ]
        );
        assert_eq!(
            expected_identities,
            &[
                super::FileIdentity::new(7, 11),
                super::FileIdentity::new(7, 12)
            ]
        );
        (primary, release.as_deref())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn h022_missing_terminal_keeps_unproven_custody() {
        let error = h022_converge(None, None, Some(ExitStatus::from_raw(0)));
        let (primary, secondary) = h022_assert_custody(&error);
        assert!(matches!(primary, WorkerError::OwnedLaunch { source }
            if matches!(source.as_ref(), super::OwnedLaunchError::Protocol { source: rivect_sandbox_helper::OwnedProtocolError::Malformed })));
        assert!(secondary.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn h022_abnormal_waiter_keeps_exact_status() {
        let error = h022_converge(None, None, Some(ExitStatus::from_raw(23 << 8)));
        let (primary, _) = h022_assert_custody(&error);
        assert!(matches!(primary, WorkerError::OwnedLaunch { source }
            if matches!(source.as_ref(), super::OwnedLaunchError::Waiter { status } if status.code() == Some(23))));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn h022_grace_expiry_keeps_known_protocol_and_release_causes() {
        let error = h022_converge(
            Some(super::owned_error(super::OwnedLaunchError::Protocol {
                source: rivect_sandbox_helper::OwnedProtocolError::Oversize,
            })),
            Some(super::owned_observation(
                "owned.release.waiter",
                std::io::Error::from_raw_os_error(5),
            )),
            None,
        );
        let (primary, secondary) = h022_assert_custody(&error);
        assert!(matches!(primary, WorkerError::OwnedLaunch { source }
            if matches!(source.as_ref(), super::OwnedLaunchError::Protocol { source: rivect_sandbox_helper::OwnedProtocolError::Oversize })));
        assert!(
            matches!(secondary, Some(WorkerError::OwnedLaunch { source })
            if matches!(source.as_ref(), super::OwnedLaunchError::Observation { boundary: "owned.release.waiter", source } if source.raw_os_error() == Some(5)))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn h022_deadline_keeps_read_errno_and_release_secondary() {
        let error = h022_converge(
            Some(super::owned_observation(
                "owned.protocol.read",
                std::io::Error::from_raw_os_error(104),
            )),
            Some(super::owned_observation(
                "owned.release.waiter",
                std::io::Error::from_raw_os_error(9),
            )),
            None,
        );
        let (primary, secondary) = h022_assert_custody(&error);
        assert!(matches!(primary, WorkerError::OwnedLaunch { source }
            if matches!(source.as_ref(), super::OwnedLaunchError::Observation { boundary: "owned.protocol.read", source } if source.raw_os_error() == Some(104))));
        assert!(
            matches!(secondary, Some(WorkerError::OwnedLaunch { source })
            if matches!(source.as_ref(), super::OwnedLaunchError::Observation { boundary: "owned.release.waiter", source } if source.raw_os_error() == Some(9)))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn h022_verified_release_preserves_timeout_and_cancel() {
        for stop in [
            rivect_sandbox_helper::OwnedStop::Deadline,
            rivect_sandbox_helper::OwnedStop::Cancelled,
        ] {
            let mut sequence = rivect_sandbox_helper::OwnedSequence::default();
            harness_ok(
                sequence.push(rivect_sandbox_helper::OwnedRecord::Entry {
                    profile: rivect_sandbox_helper::OwnedProfile::Worker,
                    baseline: 1,
                    nproc: 2,
                    verified: 63,
                }),
                "complete entry",
            );
            assert!(!sequence.released(true, true), "entry alone cannot release");
            harness_ok(
                sequence.push(rivect_sandbox_helper::OwnedRecord::Stop(stop)),
                "complete terminal",
            );
            assert!(sequence.released(true, true));
            assert!(
                !sequence.released(true, false),
                "abnormal waiter cannot release a complete transcript"
            );
            assert!(
                !super::grace_keeps_transcript(super::GraceFacts {
                    has_entry: true,
                    has_terminal: true,
                    pending_empty: false,
                    waiter_success: true,
                    release_clear: true,
                }),
                "pending transcript cannot survive grace as a released result"
            );
            let result = harness_ok(
                super::owned_release_result(
                    super::OwnedReleaseFacts {
                        released: sequence.released(true, true),
                        stop: Some(stop),
                        waiter: Some(ExitStatus::from_raw(0)),
                    },
                    Some(super::owned_helper_fault(
                        harness_ok(
                            rivect_sandbox_helper::OwnedFault::new(
                                "owned.child.spawn",
                                rivect_sandbox_helper::OwnedFaultCause::Deadline,
                            ),
                            "canonical deadline fault",
                        ),
                        None,
                    )),
                    None,
                    vec![],
                    vec![],
                ),
                "verified release",
            );
            assert!(matches!(result, Some(WorkerError::ConfinedRunTimedOut)));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn h022_settlement_retains_unknown_and_storage_precedence() {
        let unproven = || {
            h022_converge(
                Some(super::owned_observation(
                    "owned.protocol.read",
                    std::io::Error::from_raw_os_error(104),
                )),
                Some(super::owned_observation(
                    "owned.release.waiter",
                    std::io::Error::from_raw_os_error(9),
                )),
                None,
            )
        };
        let assert_causes = |error: &WorkerError| {
            let (primary, secondary) = h022_assert_custody(error);
            assert!(matches!(primary, WorkerError::OwnedLaunch { source }
                if matches!(source.as_ref(), super::OwnedLaunchError::Observation { boundary: "owned.protocol.read", source } if source.raw_os_error() == Some(104))));
            assert!(
                matches!(secondary, Some(WorkerError::OwnedLaunch { source })
                if matches!(source.as_ref(), super::OwnedLaunchError::Observation { boundary: "owned.release.waiter", source } if source.raw_os_error() == Some(9)))
            );
        };
        let (_root, mut store, _session, task) = bound_store("unproven-settlement");
        let attempt = harness_ok(
            store.plan_attempt(
                &task,
                crate::contracts::EffectClass::Exec,
                "inert release fixture",
            ),
            "plan attempt",
        );
        harness_ok(store.attempt_running(&attempt), "running attempt");
        let mut policy = crate::policy::Policy::default();
        let mut worker = NoWorker;
        let error = unproven();
        assert_eq!(
            super::owned_observed_stop(&error),
            Some(rivect_sandbox_helper::OwnedStop::Observation)
        );
        let result = super::Executor::new(&mut policy, &mut store, &mut worker)
            .commit_worker_error(&attempt, error, true);
        assert!(
            matches!(&result, Err(super::ExecutorError::WorkerUnproven { primary }) if matches!(primary, WorkerError::OwnedLaunch { .. }))
        );
        let Err(error) = result else {
            unreachable!("unproven cannot settle successfully")
        };
        assert_eq!(
            error.error_code(),
            crate::contracts::ErrorCode::OutcomeUnknown
        );
        let super::ExecutorError::WorkerUnproven { primary } = &error else {
            unreachable!("successful settlement must retain unproven primary")
        };
        assert_causes(primary);
        assert_eq!(
            harness_ok(store.attempt_state(&attempt), "attempt state").as_deref(),
            Some("unknown")
        );
        let error = unproven();
        let result = super::Executor::new(&mut policy, &mut store, &mut worker)
            .commit_worker_error("missing-attempt", error, true);
        let Err(error) = result else {
            unreachable!("missing settlement must fail")
        };
        assert!(
            matches!(&error, super::ExecutorError::WorkerSettlement { primary, .. } if matches!(primary, WorkerError::OwnedLaunch { .. }))
        );
        assert_eq!(
            error.error_code(),
            crate::contracts::ErrorCode::StorageUnavailable
        );
        let super::ExecutorError::WorkerSettlement { primary, .. } = &error else {
            unreachable!("failed settlement must retain unproven primary")
        };
        assert_causes(primary);
        assert_eq!(
            super::owned_observed_stop(primary),
            Some(rivect_sandbox_helper::OwnedStop::Observation)
        );
        assert!(
            harness_ok(
                store.attempt_state("missing-attempt"),
                "missing attempt state"
            )
            .is_none()
        );
        assert_eq!(
            harness_ok(store.attempt_state(&attempt), "original attempt state").as_deref(),
            Some("unknown")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owned_launch_expired_deadline_is_timed_out_not_a_waiter_failure() {
        super::test_helper::ensure_helper();
        use super::PreparedLaunch;
        let Ok(fault) = rivect_sandbox_helper::OwnedFault::new(
            "owned.child.spawn",
            rivect_sandbox_helper::OwnedFaultCause::Deadline,
        ) else {
            unreachable!("deadline is a closed child cause");
        };
        assert!(
            matches!(
                super::owned_helper_fault(fault, None),
                WorkerError::ConfinedRunTimedOut
            ),
            "a helper deadline fault is ConfinedRunTimedOut, not a predicate failure"
        );
        assert!(super::grace_keeps_transcript(super::GraceFacts {
            has_entry: true,
            has_terminal: true,
            pending_empty: true,
            waiter_success: true,
            release_clear: true,
        }));
        assert!(!super::grace_keeps_transcript(super::GraceFacts {
            has_entry: true,
            has_terminal: false,
            pending_empty: true,
            waiter_success: true,
            release_clear: true,
        }));
        assert!(!super::grace_keeps_transcript(super::GraceFacts {
            has_entry: true,
            has_terminal: true,
            pending_empty: false,
            waiter_success: true,
            release_clear: true,
        }));
        assert!(!super::grace_keeps_transcript(super::GraceFacts {
            has_entry: true,
            has_terminal: true,
            pending_empty: true,
            waiter_success: false,
            release_clear: true,
        }));
        assert!(!super::grace_keeps_transcript(super::GraceFacts {
            has_entry: true,
            has_terminal: true,
            pending_empty: true,
            waiter_success: true,
            release_clear: false,
        }));
        let mut launch = PreparedLaunch::direct("/bin/sleep");
        launch.arg("30");
        launch.stdin(Stdio::null());
        launch.stdout(Stdio::piped());
        launch.stderr(Stdio::piped());
        launch.deadline = Instant::now() + std::time::Duration::from_secs(3);
        let result = launch.run(&[]);
        assert!(
            matches!(result, Err(WorkerError::ConfinedRunTimedOut)),
            "an expired owned deadline must be ConfinedRunTimedOut, not a waiter status: {result:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owned_deadline_stop_decides_before_the_release_observation() {
        let converge = |stop| {
            super::owned_release_result(
                super::OwnedReleaseFacts {
                    released: false,
                    stop,
                    waiter: None,
                },
                Some(super::owned_observation(
                    "owned.protocol.read",
                    std::io::Error::from_raw_os_error(104),
                )),
                None,
                vec![PathBuf::from("/inert/first")],
                vec![super::FileIdentity::new(7, 11)],
            )
        };
        assert!(
            matches!(
                converge(Some(rivect_sandbox_helper::OwnedStop::Deadline)),
                Err(WorkerError::ConfinedRunTimedOut)
            ),
            "the parent's own deadline stop decides before the observation the release surfaced"
        );
        let Err(WorkerError::OwnedLaunch { source }) = converge(None) else {
            unreachable!("an unreleased run without a parent stop keeps its unproven verdict");
        };
        let super::OwnedLaunchError::Unproven {
            primary,
            release,
            locators,
            expected_identities,
            stop,
        } = source.as_ref()
        else {
            unreachable!("an unreleased run without a parent stop retains custody: {source:?}");
        };
        assert!(
            matches!(primary.as_ref(), WorkerError::OwnedLaunch { source }
                if matches!(source.as_ref(), super::OwnedLaunchError::Observation { boundary: "owned.protocol.read", source } if source.kind() == std::io::ErrorKind::ConnectionReset)),
            "without a parent stop the read reset stays the primary cause"
        );
        assert!(release.is_none());
        assert_eq!(locators, &[PathBuf::from("/inert/first")]);
        assert_eq!(expected_identities, &[super::FileIdentity::new(7, 11)]);
        assert_eq!(*stop, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owned_failed_release_keeps_the_deadline_stop_unproven() {
        let result = super::owned_release_result(
            super::OwnedReleaseFacts {
                released: false,
                stop: Some(rivect_sandbox_helper::OwnedStop::Deadline),
                waiter: None,
            },
            Some(super::owned_observation(
                "owned.protocol.read",
                std::io::Error::from_raw_os_error(104),
            )),
            Some(super::owned_observation(
                "owned.release.waiter",
                std::io::Error::from_raw_os_error(9),
            )),
            vec![PathBuf::from("/inert/first")],
            vec![super::FileIdentity::new(7, 11)],
        );
        let Err(WorkerError::OwnedLaunch { source }) = result else {
            unreachable!("a failed teardown must not collapse into a plain deadline: {result:?}");
        };
        let super::OwnedLaunchError::Unproven {
            primary,
            release,
            locators,
            expected_identities,
            stop,
        } = source.as_ref()
        else {
            unreachable!("a deadline stop with a failed release retains custody: {source:?}");
        };
        assert!(
            matches!(primary.as_ref(), WorkerError::OwnedLaunch { source }
                if matches!(source.as_ref(), super::OwnedLaunchError::Observation { boundary: "owned.protocol.read", source } if source.raw_os_error() == Some(104))),
            "the read reset stays the primary cause of the unproven launch"
        );
        assert!(
            matches!(release.as_deref(), Some(WorkerError::OwnedLaunch { source })
                if matches!(source.as_ref(), super::OwnedLaunchError::Observation { boundary: "owned.release.waiter", source } if source.raw_os_error() == Some(9))),
            "the failed teardown stays the release secondary: {release:?}"
        );
        assert_eq!(locators, &[PathBuf::from("/inert/first")]);
        assert_eq!(expected_identities, &[super::FileIdentity::new(7, 11)]);
        assert_eq!(*stop, Some(rivect_sandbox_helper::OwnedStop::Deadline));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owned_launch_parent_protection_precedes_control_exposure() {
        super::test_helper::ensure_helper();
        use super::{OwnedArtifact, OwnedDisposition, PreparedLaunch};
        use rivect_sandbox_helper::OwnedStop;
        use std::time::Duration;
        for stop in [
            OwnedStop::Cancelled,
            OwnedStop::Deadline,
            OwnedStop::ControlLost,
            OwnedStop::Observation,
        ] {
            assert!(
                super::owned_terminal_status(Some(rivect_sandbox_helper::OwnedRecord::Stop(stop)))
                    .is_none(),
                "a stop record carries no observed payload exit status"
            );
        }
        assert!(
            super::owned_terminal_status(None).is_none(),
            "missing terminal status remains unknown"
        );
        for stop in [
            OwnedStop::Cancelled,
            OwnedStop::Deadline,
            OwnedStop::ControlLost,
            OwnedStop::Observation,
        ] {
            let error = super::owned_error(super::OwnedLaunchError::OutputRelease {
                output: None,
                terminal: Some(rivect_sandbox_helper::OwnedRecord::Stop(stop)),
                release: Box::new(super::owned_observation(
                    "owned.cleanup.close",
                    std::io::Error::from_raw_os_error(5),
                )),
                stop: None,
            });
            assert_eq!(
                super::owned_observed_stop(&error),
                None,
                "helper stop cannot manufacture original-request provenance"
            );
            let classified = std::cell::Cell::new(false);
            let retained = super::owned_classify::<()>(Err(error), |_| {
                classified.set(true);
                Ok(())
            })
            .expect_err("cleanup error retains the stop without synthesizing an exit");
            assert!(
                !classified.get(),
                "unknown status cannot reach the payload classifier"
            );
            assert!(matches!(retained, WorkerError::OwnedLaunch { source }
                if matches!(*source, super::OwnedLaunchError::OutputRelease { output: None, terminal: Some(rivect_sandbox_helper::OwnedRecord::Stop(actual)), .. } if actual == stop)));
        }
        let cancelled = || true;
        let future = Instant::now() + CONFINED_DEADLINE;
        let refused = rivect_sandbox_helper::protect_owned_request(future, &cancelled)
            .expect_err("live cancellation must refuse before native allocation");
        assert_eq!(refused.request_stop(), Some(OwnedStop::Cancelled));
        assert_eq!(
            refused.cause(),
            rivect_sandbox_helper::OwnedFaultCause::Cancelled
        );
        let active = || false;
        let refused = rivect_sandbox_helper::protect_owned_request(Instant::now(), &active)
            .expect_err("the original deadline must refuse before native allocation");
        assert_eq!(refused.request_stop(), Some(OwnedStop::Deadline));
        let simultaneous = rivect_sandbox_helper::protect_owned_request(Instant::now(), &cancelled)
            .expect_err("cancellation has priority over an expired deadline");
        assert_eq!(simultaneous.request_stop(), Some(OwnedStop::Cancelled));
        let prefix = format!("rivect-owned-census-stop-{}-", std::process::id());
        let allocations = || {
            std::fs::read_dir(std::env::temp_dir())
                .expect("read fixture allocation directory")
                .map(|entry| entry.expect("read fixture allocation entry"))
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
                .count()
        };
        assert_eq!(allocations(), 0);
        let controls: [(Instant, &dyn Fn() -> bool, OwnedStop); 3] = [
            (future, &cancelled, OwnedStop::Cancelled),
            (Instant::now(), &active, OwnedStop::Deadline),
            (Instant::now(), &cancelled, OwnedStop::Cancelled),
        ];
        for (deadline, cancel, expected) in controls {
            let error =
                OwnedArtifact::create_with_context(&prefix, "payload-data", deadline, Some(cancel))
                    .expect_err("the actual artifact factory must refuse before allocation");
            let source = match &error {
                WorkerError::OwnedParent { source } => Some(source),
                _ => None,
            }
            .expect("the artifact factory must retain the typed parent refusal");
            assert_eq!(source.request_stop(), Some(expected));
            assert_eq!(
                source.cause(),
                if expected == OwnedStop::Cancelled {
                    rivect_sandbox_helper::OwnedFaultCause::Cancelled
                } else {
                    rivect_sandbox_helper::OwnedFaultCause::Deadline
                }
            );
            assert!(
                std::error::Error::source(&error).is_some(),
                "the consumer retains its parent source object"
            );
            assert_eq!(
                allocations(),
                0,
                "a parent refusal cannot allocate a native artifact"
            );
        }
        for (script, code, signal) in [
            ("exit 0", Some(0), None),
            ("exit 23", Some(23), None),
            ("kill -TERM $$", None, Some(15)),
        ] {
            let (ready, received) = std::sync::mpsc::sync_channel(1);
            let (release, released) = std::sync::mpsc::sync_channel(1);
            let sibling = std::thread::spawn(move || {
                let tid = std::fs::read_link("/proc/thread-self")
                    .expect("controlled consumer sibling identity");
                ready
                    .send(tid)
                    .expect("publish independently parked consumer sibling");
                released
                    .recv_timeout(Duration::from_secs(5))
                    .expect("bounded consumer sibling release");
            });
            let sibling_identity = received
                .recv_timeout(Duration::from_secs(5))
                .expect("consumer sibling parked before preparation");
            let artifact = OwnedArtifact::create("rivect-owned-consumer-", "payload-data")
                .expect("private owned artifact");
            std::fs::write(artifact.path(), b"owned-data").expect("artifact bytes");
            let root = artifact.directory.path().to_path_buf();
            let mut launch = PreparedLaunch::direct("/bin/sh");
            launch
                .arg("-c")
                .arg(script)
                .arg("owned-payload")
                .artifact_arg(artifact)
                .env("RIVECT_OWNED_PARENT_PID", "hostile-payload-value")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let output = launch
                .run(&[])
                .expect("the actual native consumer must finish");
            assert_eq!(output.status.code(), code);
            assert_eq!(output.status.signal(), signal);
            assert_eq!(output.disposition, OwnedDisposition::Released);
            assert!(
                !root.exists(),
                "native identity-gated close removes the original root"
            );
            assert!(
                Path::new("/proc").join(&sibling_identity).exists(),
                "the controlled sibling survives preparation, count and native release"
            );
            release
                .send(())
                .expect("release the controlled consumer sibling after terminal cleanup");
            sibling
                .join()
                .expect("join the controlled consumer sibling");
        }

        fn assert_identity_replacement() {
            let artifact = OwnedArtifact::create("rivect-owned-identity-", "payload-data")
                .expect("own the post-exposure identity fixture");
            std::fs::write(artifact.path(), b"original-owned-bytes")
                .expect("write the original native artifact");
            let root = artifact.directory.path().to_path_buf();
            let retained = root.with_extension("retained");
            let expected = artifact.identity;
            assert!(!retained.exists());
            println!(
                "owned identity before root={root:?} retained={retained:?} expected={expected:?}"
            );
            let mut launch = PreparedLaunch::direct("/bin/sh");
            launch
                .arg("-c")
                .arg("mv \"$1\" \"$1.retained\" && mkdir \"$1\" && printf victim-bytes > \"$1/victim\"")
                .arg("owned-identity")
                .arg(&root)
                .artifact_arg(artifact)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let result = launch.run(&[]);
            println!(
                "owned identity after root={root:?} retained={retained:?} victim_exists={} original_exists={}",
                root.join("victim").exists(),
                retained.join("payload-data").exists()
            );
            assert_eq!(
                std::fs::read(root.join("victim")).expect("the replacement victim must survive"),
                b"victim-bytes"
            );
            assert_eq!(
                std::fs::read(retained.join("payload-data"))
                    .expect("the relocated original survives"),
                b"original-owned-bytes"
            );
            let native = std::fs::symlink_metadata(&retained).expect("read relocated identity");
            assert_eq!(super::FileIdentity::from_metadata(&native), expected);
            let error = result.expect_err("changed root identity cannot claim cleanup");
            let release = match &error {
                WorkerError::OwnedLaunch { source } => match source.as_ref() {
                    super::OwnedLaunchError::OutputRelease {
                        output: Some(output),
                        terminal: Some(rivect_sandbox_helper::OwnedRecord::Exit(0)),
                        release,
                        stop: None,
                    } => {
                        assert_eq!(output.status.code(), Some(0));
                        assert_eq!(output.disposition, OwnedDisposition::Released);
                        Some(release)
                    }
                    _ => None,
                },
                _ => None,
            }
            .expect("the observed payload status and identity refusal stay owned and typed");
            let identity = match release.as_ref() {
                WorkerError::OwnedLaunch { source } => match source.as_ref() {
                    super::OwnedLaunchError::Identity {
                        locator,
                        expected: original,
                        observed: Some(observed),
                        source: None,
                    } => Some((locator, original, observed)),
                    _ => None,
                },
                _ => None,
            }
            .expect("retain the original native identity mismatch");
            assert_eq!(identity.0, &root);
            assert_eq!(*identity.1, expected);
            assert_ne!(*identity.2, expected);
            drop(error);
            assert!(root.join("victim").is_file());
            assert!(retained.join("payload-data").is_file());
            println!(
                "owned identity retained after last drop root={root:?} relocated={retained:?}"
            );
        }
        assert_identity_replacement();
        fn assert_native_cleanup_failure(cancelled: bool) {
            use std::os::unix::fs::PermissionsExt as _;
            let mut artifacts = Vec::new();
            let mut roots = Vec::new();
            let mut identities = Vec::new();
            for _ in 0..3 {
                let artifact = OwnedArtifact::create("rivect-owned-close-", "payload-data")
                    .expect("own partial cleanup fixture");
                std::fs::write(artifact.path(), b"retained-cleanup-bytes")
                    .expect("write cleanup fixture bytes");
                roots.push(artifact.directory.path().to_path_buf());
                identities.push(artifact.identity);
                artifacts.push(artifact);
            }
            let marker = roots[0].join("stop-ready");
            let mut launch = PreparedLaunch::direct("/bin/sh");
            launch
                .arg("-c")
                .arg(if cancelled {
                    "chmod 000 \"$2\" && printf ready > \"$1\"; sleep 5"
                } else {
                    "chmod 000 \"$2\""
                })
                .arg("owned-cleanup")
                .arg(&marker)
                .arg(&roots[1])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            for artifact in artifacts {
                launch.artifact_arg(artifact);
            }
            println!(
                "owned native cleanup before roots={roots:?} identities={identities:?} cancelled={cancelled}"
            );
            let result = if cancelled {
                let cancel = || marker.exists();
                let bounds = ObserveBounds {
                    deadline: launch.deadline,
                    stdout_cap: super::READ_MAX_CAP,
                    stop: |_| if cancel() { Some(()) } else { None },
                    stdin_close_ends_payload: false,
                };
                launch
                    .run_owned(&[], Some(&cancel), bounds, &|()| OwnedStop::Cancelled)
                    .map(|_| ())
            } else {
                launch.run(&[]).map(|_| ())
            };
            println!(
                "owned native cleanup roots={roots:?} identities={identities:?} survivors={:?}",
                roots.iter().map(|root| root.exists()).collect::<Vec<_>>()
            );
            let error = result
                .expect_err("a native cleanup error must preserve the original payload status");
            let release = match &error {
                WorkerError::OwnedLaunch { source } => match source.as_ref() {
                    super::OwnedLaunchError::OutputRelease {
                        output,
                        terminal,
                        release,
                        stop,
                    } => {
                        if cancelled {
                            assert!(
                                output.is_none(),
                                "a stopped payload has no invented exit status"
                            );
                            assert_eq!(
                                *terminal,
                                Some(rivect_sandbox_helper::OwnedRecord::Stop(
                                    OwnedStop::Cancelled
                                ))
                            );
                            assert_eq!(*stop, Some(OwnedStop::Cancelled));
                        } else {
                            let output = output.as_ref().expect("retain actual exit0 output");
                            assert_eq!(output.status.code(), Some(0));
                            assert_eq!(output.disposition, OwnedDisposition::Released);
                            assert_eq!(
                                *terminal,
                                Some(rivect_sandbox_helper::OwnedRecord::Exit(0))
                            );
                            assert_eq!(*stop, None);
                        }
                        Some(release.as_ref())
                    }
                    _ => None,
                },
                _ => None,
            }
            .expect("native close failure retains observed exit0 and release evidence");
            let (locator, source) = match release {
                WorkerError::OwnedLaunch { source } => match source.as_ref() {
                    super::OwnedLaunchError::Close { locator, source } => Some((locator, source)),
                    _ => None,
                },
                _ => None,
            }
            .expect("retain the original native directory cleanup error");
            assert_eq!(locator, &roots[1]);
            assert_eq!(source.raw_os_error(), Some(13));
            assert!(std::error::Error::source(release).is_some());
            assert!(
                !roots[0].exists(),
                "successful earlier cleanup remains complete"
            );
            assert!(
                !roots[2].exists(),
                "later eligible cleanup is still attempted"
            );
            let metadata =
                std::fs::symlink_metadata(&roots[1]).expect("retain the failed cleanup identity");
            assert_eq!(super::FileIdentity::from_metadata(&metadata), identities[1]);
            assert_eq!(metadata.permissions().mode() & 0o777, 0);
            println!(
                "owned native cleanup retained locator={locator:?} identity={:?} errno=13 cancelled={cancelled}",
                identities[1]
            );
            drop(error);
            assert!(
                roots[1].is_dir(),
                "last drop retains failed native cleanup custody"
            );
        }
        assert_native_cleanup_failure(false);
        assert_native_cleanup_failure(true);
        use std::os::unix::fs::MetadataExt as _;
        let mut frozen = Vec::new();
        let mut retained_originals = Vec::new();
        let mut missing = PreparedLaunch::direct("/nonexistent/rivect-owned-payload");
        assert_eq!(
            std::process::Command::new("/nonexistent/rivect-owned-payload")
                .env_clear()
                .spawn()
                .expect_err("independent missing payload control")
                .raw_os_error(),
            Some(2)
        );
        for relocated in [false, true] {
            let artifact = OwnedArtifact::create("rivect-owned-unproven-", "payload-data")
                .expect("own the unresolved native artifact");
            let root = artifact.directory.path().to_path_buf();
            let metadata =
                std::fs::symlink_metadata(&root).expect("freeze original identity before transfer");
            assert!(metadata.file_type().is_dir());
            let identity = super::FileIdentity::new(metadata.dev(), metadata.ino());
            assert_eq!(artifact.identity, identity);
            frozen.push((root.clone(), identity));
            if relocated {
                let retained = root.with_extension("retained");
                assert!(!retained.exists());
                std::fs::rename(&root, &retained)
                    .expect("retain the original native directory identity");
                std::fs::create_dir(&root)
                    .expect("install an independent victim at the original locator");
                let victim = std::fs::symlink_metadata(&root)
                    .expect("observe the replacement victim identity");
                assert_ne!(
                    super::FileIdentity::new(victim.dev(), victim.ino()),
                    identity
                );
                retained_originals.push(retained);
            }
            missing.artifact_arg(artifact);
        }
        missing
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let error = missing
            .run(&[])
            .expect_err("missing payload retains unresolved native launch custody");
        let source = match &error {
            WorkerError::OwnedLaunch { source } => Some(source),
            _ => None,
        }
        .expect("retain the owned native error");
        let (primary, release, locators, expected_identities, stop) = match source.as_ref() {
            super::OwnedLaunchError::Unproven {
                primary,
                release,
                locators,
                expected_identities,
                stop,
            } => Some((primary, release, locators, expected_identities, stop)),
            _ => None,
        }
        .expect("retain unresolved native artifacts");
        assert!(std::error::Error::source(&error).is_some());
        assert!(std::error::Error::source(source.as_ref()).is_some());
        assert_eq!(*stop, None);
        assert!(
            release.is_none(),
            "the complete bootstrap fault has no later release failure"
        );
        let primary = match primary.as_ref() {
            WorkerError::OwnedLaunch { source } => Some(source),
            _ => None,
        }
        .expect("retain the original typed helper fault");
        let (fault, secondary, native) = match primary.as_ref() {
            super::OwnedLaunchError::Helper {
                fault,
                secondary,
                source,
            } => Some((fault, secondary, source)),
            _ => None,
        }
        .expect("missing payload must reach its actual native exec seam");
        assert_eq!(fault.boundary(), "owned.child.spawn");
        assert_eq!(
            fault.cause(),
            rivect_sandbox_helper::OwnedFaultCause::Io {
                operation: 25,
                field: 0,
                errno: 2
            }
        );
        assert_eq!(native.raw_os_error(), Some(2));
        assert!(
            secondary.is_none(),
            "the clean singleton bootstrap fault has no init-secondary frame"
        );
        println!(
            "owned unresolved identities: locators={locators:?} retained_originals={retained_originals:?} expected={expected_identities:?} primary={primary:?} release={release:?}"
        );
        assert_eq!(
            locators.len(),
            expected_identities.len(),
            "every retained locator carries its original frozen identity"
        );
        assert!(
            locators.len() > frozen.len(),
            "the helper envelope retains its own native artifact"
        );
        for (index, (locator, identity)) in frozen.iter().enumerate() {
            assert_eq!(&locators[index], locator);
            assert_eq!(
                &expected_identities[index], identity,
                "replacement stat cannot reconstruct the original identity"
            );
            assert!(
                locator.is_dir(),
                "unproven custody cannot remove the victim or original locator"
            );
        }
        for retained in retained_originals {
            assert!(
                retained.is_dir(),
                "retain the relocated original until release is established"
            );
        }

        let mut launch = PreparedLaunch::direct("/bin/sh");
        launch
            .arg("-c")
            .arg("test -z \"${RIVECT_OWNED_PARENT_PID+x}\"")
            .env("RIVECT_OWNED_PARENT_PID", "hostile-payload-value")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        assert!(
            launch
                .run(&[])
                .expect("private carrier control")
                .status
                .success(),
            "the payload cannot inherit the private parent carrier"
        );
        use std::os::unix::ffi::OsStringExt as _;
        let mut bytes = PreparedLaunch::direct("/usr/bin/env");
        bytes
            .env_clear()
            .env(
                "BYTE_VALUE",
                std::ffi::OsString::from_vec(b"value\xff:=\n".to_vec()),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = bytes
            .run(&[])
            .expect("environment values preserve non-UTF-8 bytes");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"BYTE_VALUE=value\xff:=\n\n");
        assert_eq!(output.disposition, OwnedDisposition::Released);

        let mut loader = PreparedLaunch::direct("/bin/true");
        loader
            .env_clear()
            .env("LD_TRACE_LOADED_OBJECTS", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = loader
            .run(&[])
            .expect("workload loader keys cannot affect the trusted helper loader");
        assert!(output.status.success());
        assert!(
            !output.stdout.is_empty(),
            "the workload loader must receive its own requested key"
        );
        assert_eq!(output.disposition, OwnedDisposition::Released);

        let mut carrier = PreparedLaunch::direct("/bin/sh");
        carrier
            .env_clear()
            .env("PRIVATE_VALUE", "owned-environment-value-control")
            .arg("-c")
            .arg("cat /proc/1/cmdline")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = carrier
            .run(&[])
            .expect("observe the actual private init argv");
        assert!(output.status.success());
        assert!(
            !output.stdout.is_empty(),
            "argv absence needs an actual visible positive control"
        );
        assert!(
            !output
                .stdout
                .windows(b"owned-environment-value-control".len())
                .any(|word| word == b"owned-environment-value-control"),
            "environment values cannot be encoded in helper argv"
        );
        for value in [
            std::ffi::OsString::from_vec(b"invalid\0value".to_vec()),
            std::ffi::OsString::from("x".repeat(131_072)),
        ] {
            let mut invalid = PreparedLaunch::direct("/bin/true");
            invalid
                .env_clear()
                .env("INVALID_ENV", value)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let error = invalid
                .run(&[])
                .expect_err("invalid or over-kernel-bound environment cannot launch");
            assert!(matches!(error, WorkerError::SandboxSpawnFailed { source }
                if source.kind() == std::io::ErrorKind::InvalidInput || source.raw_os_error() == Some(7)));
        }
    }

    fn exited(code: i32) -> ExitStatus {
        ExitStatus::from_raw(code << 8)
    }

    fn signaled(signal: i32) -> ExitStatus {
        ExitStatus::from_raw(signal)
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

    #[test]
    fn helper_probe_data_io_is_enforcement_denial() {
        let target = Path::new("/tmp/rivect-probe-target");
        let observed = ObservedChild {
            status: exited(rivect_sandbox_helper::EXIT_DATA_IO),
            stdout: Vec::new(),
            stderr: b"rivect-sandbox-helper: probe-write open denied\n".to_vec(),
        };
        assert!(
            matches!(
                helper_probe_verdict(&observed, target),
                Err(WorkerError::SandboxDenied { ref target }) if target == Path::new("/tmp/rivect-probe-target")
            ),
            "EXIT_DATA_IO is the confined write denial"
        );
    }

    #[test]
    fn helper_write_post_mutation_exit_is_mutation_failed() {
        let observed = ObservedChild {
            status: exited(rivect_sandbox_helper::EXIT_DATA_MUTATED),
            stdout: Vec::new(),
            stderr: b"rivect-sandbox-helper: admitted write failed: disk full\n".to_vec(),
        };
        assert!(
            matches!(
                helper_io_bytes(observed, false),
                Err(WorkerError::WriteMutationFailed { .. })
            ),
            "EXIT_DATA_MUTATED is the post-mutation write failure"
        );
        let pre_mutation = ObservedChild {
            status: exited(rivect_sandbox_helper::EXIT_DATA_IO),
            stdout: Vec::new(),
            stderr: b"rivect-sandbox-helper: admitted truncate failed: io error\n".to_vec(),
        };
        assert!(
            matches!(
                helper_io_bytes(pre_mutation, false),
                Err(WorkerError::WriteFailed { .. })
            ),
            "EXIT_DATA_IO on the write path stays the pre-mutation failure"
        );
    }

    #[test]
    fn helper_write_unlisted_exit_is_mutation_failed() {
        // An exit code the contract does not bless cannot prove the
        // write never mutated its target, so the write leg reports the
        // honest unknown outcome while the read leg stays a capability
        // failure.
        let observed = ObservedChild {
            status: exited(42),
            stdout: Vec::new(),
            stderr: b"confined writer died oddly\n".to_vec(),
        };
        assert!(
            matches!(
                helper_io_bytes(observed, false),
                Err(WorkerError::WriteMutationFailed { .. })
            ),
            "an unlisted write exit is WriteMutationFailed, never a clean rejection"
        );
        let observed = ObservedChild {
            status: exited(42),
            stdout: Vec::new(),
            stderr: b"confined reader died oddly\n".to_vec(),
        };
        assert!(
            matches!(
                helper_io_bytes(observed, true),
                Err(WorkerError::SandboxSpawnFailed { .. })
            ),
            "an unlisted read exit stays a capability failure"
        );
    }

    #[test]
    fn spawn_refusal_names_the_attempted_program() {
        let mut command = std::process::Command::new("/no/such/rivect-sandbox-helper");
        command.arg("confined");
        let error = spawn_failed(&command, std::io::Error::last_os_error());
        let display = error.to_string();
        assert!(
            display.contains("/no/such/rivect-sandbox-helper"),
            "a spawn refusal names the attempted launcher: {display}"
        );
        assert!(
            !display.contains("seatbelt") && !display.contains("sandbox-exec"),
            "the shared variant names no single mechanism: {display}"
        );
    }

    #[test]
    fn helper_probe_unprefixed_is_spawn_failed_signaled_is_killed() {
        let target = Path::new("/tmp/rivect-probe-target");
        let unprefixed = ObservedChild {
            status: exited(rivect_sandbox_helper::EXIT_PROTOCOL),
            stdout: Vec::new(),
            stderr: b"not the helper prefix\n".to_vec(),
        };
        assert!(
            matches!(
                helper_probe_verdict(&unprefixed, target),
                Err(WorkerError::SandboxSpawnFailed { .. })
            ),
            "an unprefixed protocol miss is a capability failure, not a denial"
        );
        let killed = ObservedChild {
            status: signaled(9),
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        match helper_probe_verdict(&killed, target) {
            Err(WorkerError::ConfinedRunKilled { source }) => assert!(
                source.to_string().contains("signal 9"),
                "a signal-killed probe child names its signal: {source}"
            ),
            other => {
                unreachable!("a signal-killed probe child is ConfinedRunKilled, got {other:?}")
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn launcher_stage_unshare_failure_has_a_fixed_check_wording() {
        const RECOVERY: &str = "linux recovery: let this user create unprivileged user namespaces (an AppArmor profile granting userns to this program, or kernel.apparmor_restrict_unprivileged_userns=0), keep user.max_user_namespaces above 0 and use util-linux 2.38 or newer; see docs/operations/linux-prerequisites.md";
        let stderr = b"\nunshare: unshare failed: Operation not permitted\n";
        let read_error = helper_io_bytes(
            ObservedChild {
                status: exited(1),
                stdout: Vec::new(),
                stderr: stderr.to_vec(),
            },
            true,
        )
        .expect_err("read launcher never ran");
        let write_error = helper_io_bytes(
            ObservedChild {
                status: exited(1),
                stdout: Vec::new(),
                stderr: stderr.to_vec(),
            },
            false,
        )
        .expect_err("write launcher never ran");
        eprintln!("helper-io read: {read_error:?}");
        eprintln!("helper-io write: {write_error:?}");
        let mut capture = BoundedCapture::empty();
        capture.extend(stderr);
        let observed = super::PhaseObserved {
            status: exited(1),
            stdout: BoundedCapture::empty(),
            stderr: capture,
        };
        let check = assert_denied_control_cause(&observed, "read", &["secret".to_string()], &[]);
        eprintln!("fixed-check wording: {check:?}");
        let unknown = helper_io_bytes(
            ObservedChild {
                status: exited(1),
                stdout: Vec::new(),
                stderr: b"cat: secret".to_vec(),
            },
            false,
        )
        .expect_err("an unknown write outcome is retained");
        assert!(
            matches!(unknown, WorkerError::WriteMutationFailed { .. }),
            "{unknown:?}"
        );
        assert_eq!(
            super::ExecutorError::Worker(unknown).error_code(),
            crate::contracts::ErrorCode::OutcomeUnknown
        );
        let mut denied_stderr = BoundedCapture::empty();
        denied_stderr.extend(b"/bin/cat: secret: Permission denied");
        let denied = super::PhaseObserved {
            status: exited(1),
            stdout: BoundedCapture::empty(),
            stderr: denied_stderr,
        };
        assert!(assert_denied_control_cause(&denied, "read", &["secret".to_string()], &[]).is_ok());
        let worker_reason = format!(
            "linux user namespace unavailable (unshare --user): unshare: unshare failed: Operation not permitted; {RECOVERY}"
        );
        let mut helper_correct = Vec::new();
        for (label, error) in [("read", read_error), ("write", write_error)] {
            let correct = matches!(&error, WorkerError::SandboxUnavailable { reason } if reason == &worker_reason)
                && super::ExecutorError::Worker(error).error_code()
                    == crate::contracts::ErrorCode::CapabilityUnavailable;
            eprintln!("helper-io {label} diagnosis correct={correct}");
            helper_correct.push(correct);
        }
        let check_correct = matches!(check, Err(CheckError::VendorSetup { ref detail })
            if detail == &format!("the read control could not start: linux user namespace unavailable (unshare --user); {RECOVERY}")
                && !detail.contains("Operation not permitted"));
        assert_eq!(
            (check_correct, helper_correct),
            (true, vec![true, true]),
            "fixed-check and helper read/write diagnosis must all hold"
        );
    }

    #[test]
    fn helper_io_signaled_child_is_confined_run_killed() {
        for read in [false, true] {
            let observed = ObservedChild {
                status: signaled(15),
                stdout: Vec::new(),
                stderr: Vec::new(),
            };
            match helper_io_bytes(observed, read) {
                Err(WorkerError::ConfinedRunKilled { source }) => assert!(
                    source.to_string().contains("signal 15"),
                    "the killed cause names its signal: {source}"
                ),
                other => {
                    unreachable!("a signaled helper run is ConfinedRunKilled, got {other:?}")
                }
            }
        }
    }

    #[test]
    fn observer_reports_signal_death_as_killed_and_reaps() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("kill -TERM $$")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        match observe_confined_child(&mut child, None, &[], None, None) {
            Err(WorkerError::ConfinedRunKilled { source }) => assert!(
                source.to_string().contains("signal"),
                "the killed cause names its signal: {source}"
            ),
            Err(other) => {
                unreachable!("a signal death is ConfinedRunKilled, got {other:?}")
            }
            Ok(_) => unreachable!("a signal death must not yield a verdict"),
        }
        // `try_wait` already reaped the leader: a second wait returns
        // the same signal status, not a zombie.
        let status = child.wait()?;
        assert_eq!(status.code(), None, "the reaped status stays signaled");
        Ok(())
    }

    /// The caller's stop is asked before `try_wait`, so a stop raised by
    /// a child that has already exited still wins: the parent's own stop
    /// is classified before any exit status or signal is read.
    #[test]
    fn a_stop_outranks_an_exit_already_waiting() -> Result<(), Box<dyn std::error::Error>> {
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        // Unreaped and exited: `ps` reports the leader as a zombie.
        let pid = child.id().to_string();
        let deadline = Instant::now() + CONFINED_DEADLINE;
        loop {
            let state = std::process::Command::new("ps")
                .args(["-o", "stat=", "-p", &pid])
                .output()?;
            if String::from_utf8_lossy(&state.stdout)
                .trim_start()
                .starts_with('Z')
            {
                break;
            }
            assert!(Instant::now() < deadline, "the child never exited");
        }
        let bounds = ObserveBounds {
            deadline,
            stdout_cap: 0,
            stop: |_retained: usize| Some("stopped"),
            stdin_close_ends_payload: false,
        };
        match observe_bounded(&mut child, None, &[], None, None, bounds) {
            Ok(ObserveOutcome::Stopped("stopped")) => {}
            Ok(ObserveOutcome::Stopped(other)) => unreachable!("an unexpected stop {other}"),
            Ok(ObserveOutcome::Exited(observed)) => {
                unreachable!("the exit was read before the stop: {:?}", observed.status)
            }
            Err(error) => unreachable!("the observation failed: {error:?}"),
        }
        Ok(())
    }

    #[test]
    fn observer_kills_and_reaps_on_observation_io_failure() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child.stdin.take();
        // A megabyte cannot fit the pipe buffer, so the nonblocking
        // write loop outlives the exiting child and hits EPIPE — a
        // mid-run observation loss, never a launch refusal.
        let payload = vec![b'x'; 1 << 20];
        match observe_confined_child(&mut child, stdin, &payload, None, None) {
            Err(WorkerError::ConfinedRunKilled { .. }) => {}
            Err(other) => {
                unreachable!("a lost observation is ConfinedRunKilled, got {other:?}")
            }
            Ok(_) => unreachable!("a lost observation must not yield a verdict"),
        }
        // The wrapper reaped the leader before returning the error.
        let status = child.wait()?;
        assert_eq!(status.code(), Some(0), "the reaped status is the exit");
        Ok(())
    }

    /// A pipe read that always fails: the post-reap drain must report
    /// the loss as the killed run it is — never `SandboxSpawnFailed`,
    /// which would escape the terminate skip and re-fire killpg on the
    /// freed leader pgid.
    /// The fd stands in for the pipe's readiness wait, which neither
    /// stub reaches.
    struct FailingRead(std::io::Stdin);

    impl std::io::Read for FailingRead {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("pipe read failed"))
        }
    }

    impl std::os::fd::AsFd for FailingRead {
        fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
            std::os::fd::AsFd::as_fd(&self.0)
        }
    }

    /// A pipe whose write end never closes: reads `WouldBlock` forever,
    /// so only the wall deadline ends the drain.
    struct PendingRead(std::io::Stdin);

    impl std::io::Read for PendingRead {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
        }
    }

    impl std::os::fd::AsFd for PendingRead {
        fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
            std::os::fd::AsFd::as_fd(&self.0)
        }
    }

    #[test]
    fn post_reap_drain_read_failure_is_confined_run_killed() {
        let mut pipe = Some(FailingRead(std::io::stdin()));
        let result = drain_pipe_to_eof(
            &mut pipe,
            &mut Vec::new(),
            &mut [0u8; 64],
            64,
            Instant::now() + CONFINED_DEADLINE,
        );
        match result {
            Err(WorkerError::ConfinedRunKilled { source }) => {
                // The verbatim source — not the folded display text —
                // proves the dedicated `SandboxSpawnFailed` arm ran.
                assert_eq!(source.to_string(), "pipe read failed");
            }
            other => {
                unreachable!("a mid-drain loss after the reap is ConfinedRunKilled, got {other:?}")
            }
        }
    }

    #[test]
    fn post_reap_drain_held_open_past_deadline_is_timed_out() {
        let mut pipe = Some(PendingRead(std::io::stdin()));
        // The already-elapsed deadline fires on the first loop check —
        // the stub read under it would never produce EOF.
        let result = drain_pipe_to_eof(
            &mut pipe,
            &mut Vec::new(),
            &mut [0u8; 64],
            64,
            Instant::now(),
        );
        assert!(
            matches!(result, Err(WorkerError::ConfinedRunTimedOut)),
            "a write end held past the deadline is ConfinedRunTimedOut, got {result:?}"
        );
    }

    /// A pid the footprint read cannot serve must stop the run as an
    /// observation failure — an unreadable worker is never taken as one
    /// under its memory budget.
    #[cfg(target_os = "macos")]
    #[test]
    fn footprint_read_failure_fails_closed() {
        assert!(matches!(
            super::footprint_stop(u32::MAX),
            Some(super::IndexRunError::Observe { .. })
        ));
        // The same check on this live, far-under-budget process lets the
        // run continue, so the refusal above is the read error's alone.
        assert!(super::footprint_stop(std::process::id()).is_none());
    }

    #[test]
    fn egress_describe_redacts_userinfo_and_query() {
        let request = EffectRequest::Egress {
            grant_id: "grant-1".to_string(),
            url: "https://user:pass@evil.example/path?token=secret#frag".to_string(),
        };
        assert_eq!(request.describe(), "egress https://evil.example/path");
        let explicit_port = EffectRequest::Egress {
            grant_id: "grant-1".to_string(),
            url: "http://user@evil.example:8080/x?token=1".to_string(),
        };
        assert_eq!(
            explicit_port.describe(),
            "egress http://evil.example:8080/x"
        );
    }

    #[test]
    fn egress_sandbox_denied_mirrors_describe_redaction() {
        let url = "https://user:pass@evil.example/path?token=secret#frag";
        let request = EffectRequest::Egress {
            grant_id: "grant-1".to_string(),
            url: url.to_string(),
        };
        let redacted = request
            .describe()
            .strip_prefix("egress ")
            .expect("describe prefix")
            .to_string();
        assert_eq!(redacted, "https://evil.example/path");
        let error = sandbox_denied(Path::new(url));
        assert!(
            matches!(
                &error,
                WorkerError::SandboxDenied { target } if target == Path::new(&redacted)
            ),
            "SandboxDenied must store the describe-path spelling, got {error:?}"
        );
        let display = error.to_string();
        assert_eq!(
            display,
            format!("denied: the sandbox boundary rejected {redacted}")
        );
        assert!(
            !display.contains("user:pass") && !display.contains("token="),
            "Display must not carry userinfo or query, got {display}"
        );
        let explicit_port = sandbox_denied(Path::new("http://user@evil.example:8080/x?token=1"));
        assert!(
            matches!(
                &explicit_port,
                WorkerError::SandboxDenied { target }
                    if target == Path::new("http://evil.example:8080/x")
            ),
            "explicit-port deny must mirror describe, got {explicit_port:?}"
        );
        assert_eq!(
            explicit_port.to_string(),
            "denied: the sandbox boundary rejected http://evil.example:8080/x"
        );
    }

    #[test]
    fn filesystem_sandbox_denied_keeps_the_path_spelling() {
        let path = Path::new("/tmp/rivect-probe-target");
        let error = sandbox_denied(path);
        assert!(
            matches!(
                &error,
                WorkerError::SandboxDenied { target } if target == path
            ),
            "filesystem deny spelling must stay the path, got {error:?}"
        );
    }

    // ----- confined check (SLICE-178) unit discriminators ----------------

    use super::{
        AnchoredDependencies, BoundedCapture, CHECK_CAPTURE_EDGE_BYTES, LockDependency,
        anchor_dependencies, assert_denied_control_cause, check_boundary_id, check_command_digest,
        check_error_code, dependency_component_error, dependency_leaf_error, inventory,
        lock_registry_dependencies, read_leaf, stage_index_config, stage_index_entry,
        workspace_digest,
    };

    /// An owning scratch root: the `TempDir` removes it when the test
    /// drops it, after every store and child declared below it.
    fn scratch_tree(tag: &str) -> tempfile::TempDir {
        tempfile::TempDir::with_prefix(format!("rivect-check-unit-{tag}-"))
            .unwrap_or_else(|error| unreachable!("the scratch root is created: {error}"))
    }

    #[test]
    fn bounded_capture_keeps_head_and_tail_and_total() {
        let mut capture = BoundedCapture::empty();
        let head_marker = b"HEAD-MARKER".to_vec();
        let filler = vec![b'x'; 4 * CHECK_CAPTURE_EDGE_BYTES];
        let tail_marker = b"TAIL-MARKER".to_vec();
        let total = head_marker.len() + filler.len() + tail_marker.len();
        capture.extend(&head_marker);
        capture.extend(&filler);
        capture.extend(&tail_marker);
        assert_eq!(
            capture.total as usize, total,
            "total counts every byte the stream produced"
        );
        assert_eq!(capture.head.len(), CHECK_CAPTURE_EDGE_BYTES);
        assert!(
            capture.head.starts_with(&head_marker),
            "the head keeps the stream's first bytes"
        );
        assert_eq!(capture.tail.len(), CHECK_CAPTURE_EDGE_BYTES);
        assert!(
            capture.tail.ends_with(&tail_marker),
            "the tail keeps the stream's newest bytes"
        );
        assert!(
            !capture.head.ends_with(&tail_marker),
            "an overflowing stream never keeps the tail in the head"
        );
    }

    #[test]
    fn check_command_digest_versions_are_deterministic_and_distinct() {
        let (v1a, v2a) = check_command_digest("p-digest", Some("v-digest"), "target", "exact", 1);
        let (v1b, v2b) = check_command_digest("p-digest", Some("v-digest"), "target", "exact", 1);
        assert_eq!(v1a, v1b, "the v1 identity is deterministic");
        assert_eq!(v2a, v2b, "the v2 identity is deterministic");
        assert_ne!(v1a, v2a, "v1 and v2 are distinct identities");
        let (_, v2_changed) = check_command_digest("p-digest", Some("other"), "target", "exact", 1);
        let (v1_threads, v2_threads) =
            check_command_digest("p-digest", Some("v-digest"), "target", "exact", 2);
        assert_ne!(v1a, v1_threads, "the admitted harness threads bind v1");
        assert_ne!(v2a, v2_threads, "the admitted harness threads bind v2");
        assert_ne!(v2_changed, v2a, "the vendor digest binds v2");
    }

    #[test]
    fn check_sites_keep_distinct_boundary_ids() {
        let samples = [
            CheckError::ExecGrant {
                detail: "x".to_string(),
            },
            CheckError::ProjectReadGrant {
                detail: "x".to_string(),
            },
            CheckError::DependencyGrant {
                detail: "x".to_string(),
            },
            CheckError::SelectionMismatch {
                detail: "x".to_string(),
            },
            CheckError::TargetLayout {
                detail: "x".to_string(),
            },
            CheckError::InventoryRefused {
                detail: "x".to_string(),
            },
            CheckError::CopyFailed {
                detail: "x".to_string(),
            },
            CheckError::DigestMismatch {
                detail: "x".to_string(),
            },
            CheckError::LockRefused {
                detail: "x".to_string(),
            },
            CheckError::CacheScope {
                detail: "x".to_string(),
            },
            CheckError::CacheRevoked {
                detail: "x".to_string(),
            },
            CheckError::CacheDenied {
                detail: "x".to_string(),
            },
            CheckError::CacheRootFd {
                detail: "x".to_string(),
            },
            CheckError::CacheComponent {
                detail: "x".to_string(),
            },
            CheckError::CacheAncestry {
                detail: "x".to_string(),
            },
            CheckError::CacheCapability {
                detail: "x".to_string(),
            },
            CheckError::CacheLeaf {
                detail: "x".to_string(),
            },
            CheckError::CacheFdIdentity {
                detail: "x".to_string(),
            },
            CheckError::CacheLinks {
                detail: "x".to_string(),
            },
            CheckError::CacheKind {
                detail: "x".to_string(),
            },
            CheckError::CacheSize {
                detail: "x".to_string(),
            },
            CheckError::CacheMissing {
                detail: "x".to_string(),
            },
            CheckError::ChecksumMismatch {
                detail: "x".to_string(),
            },
            CheckError::IndexStaging {
                detail: "x".to_string(),
            },
            CheckError::ConfigRefused {
                detail: "x".to_string(),
            },
            CheckError::VendorAdmit {
                site: "vendor.admit.dep",
                detail: "x".to_string(),
            },
            CheckError::VendorSetup {
                detail: "x".to_string(),
            },
            CheckError::VendorSpawn {
                detail: "x".to_string(),
            },
            CheckError::VendorExec {
                detail: "x".to_string(),
            },
            CheckError::VendorObserve {
                detail: "x".to_string(),
            },
            CheckError::VendorCapture {
                detail: "x".to_string(),
            },
            CheckError::VendorDeadline {
                detail: "x".to_string(),
            },
            CheckError::VendorCancel {
                detail: "x".to_string(),
            },
            CheckError::VendorSignal {
                detail: "x".to_string(),
            },
            CheckError::VendorResult {
                detail: "x".to_string(),
            },
            CheckError::VendorValidate {
                detail: "x".to_string(),
            },
            CheckError::VendorLockChanged {
                detail: "x".to_string(),
            },
            CheckError::VendorPromote {
                detail: "x".to_string(),
            },
            CheckError::VendorSeal {
                detail: "x".to_string(),
            },
            CheckError::VendorDigest {
                detail: "x".to_string(),
            },
            CheckError::TestAdmit {
                site: "test.admit.dep",
                detail: "x".to_string(),
            },
            CheckError::TestSetup {
                detail: "x".to_string(),
            },
            CheckError::TestSpawn {
                detail: "x".to_string(),
            },
            CheckError::TestExec {
                detail: "x".to_string(),
            },
            CheckError::TestObserve {
                detail: "x".to_string(),
            },
            CheckError::TestCapture {
                detail: "x".to_string(),
            },
            CheckError::TestDeadline {
                detail: "x".to_string(),
            },
            CheckError::TestCancel {
                detail: "x".to_string(),
            },
            CheckError::TestSignal {
                detail: "x".to_string(),
            },
            CheckError::CloseSelection {
                detail: "x".to_string(),
            },
            CheckError::CloseInventory {
                detail: "x".to_string(),
            },
            CheckError::CleanupRoot {
                detail: "x".to_string(),
            },
            CheckError::EvidenceRetention {
                detail: "x".to_string(),
            },
        ];
        let mut sites: Vec<&'static str> = samples.iter().map(CheckError::site).collect();
        let total = sites.len();
        sites.sort_unstable();
        sites.dedup();
        assert_eq!(
            sites.len(),
            total,
            "every check seam keeps its own distinct site id"
        );
        for sample in &samples {
            assert_eq!(
                check_boundary_id("attempt-1", sample.site()),
                format!("ret:check:attempt-1:{}", sample.site())
            );
        }
    }

    #[test]
    fn retained_check_site_collision_is_denied() {
        let root_dir = scratch_tree("collision");
        let root = root_dir.path();
        let store_path = root.join("state.sqlite");
        let mut store = crate::state::TaskStore::open(&store_path).expect("open store");
        let record = crate::verification::RetainedAttempt {
            attempt_id: "a1".to_string(),
            boundary_id: check_boundary_id("a1", "dep.cache_links"),
            stage: crate::verification::RetainedStage::Terminal,
            cause: "first cause".to_string(),
            digest: crate::verification::record_digest("a1", "first cause"),
            build_attempt: "a1".to_string(),
            admitted_attempt_id: Some("a1".to_string()),
        };
        store.retain_attempt(&record).expect("first retention");
        // The one-shot discipline: the same site with a DIFFERENT cause is
        // a collision the store denies — after cleanup the seam's cause
        // stays uniquely recoverable.
        let collided = crate::verification::RetainedAttempt {
            boundary_id: check_boundary_id("a1", "dep.cache_links"),
            cause: "second cause".to_string(),
            digest: crate::verification::record_digest("a1", "second cause"),
            ..record
        };
        assert!(
            store.retain_attempt(&collided).is_err(),
            "two aliased site ids with different causes must be denied"
        );
    }

    #[test]
    fn inventory_refuses_hardlinks_specials_and_oversize() {
        let root_dir = scratch_tree("refusals");
        let root = root_dir.path();
        let ok = root.join("nested");
        std::fs::create_dir_all(&ok).expect("nested dir");
        std::fs::write(ok.join("file.txt"), b"bytes").expect("file");
        assert!(inventory(root).is_ok(), "a plain tree inventories");

        let linked = root.join("linked");
        std::fs::hard_link(ok.join("file.txt"), &linked).expect("hard link");
        let refused = inventory(root).expect_err("a hard link refuses");
        assert!(
            matches!(refused, super::InventoryError::HardLink { .. }),
            "{refused}"
        );
        std::fs::remove_file(&linked).expect("remove link");

        // A unix-socket path must stay under SUN_LEN, so the special file
        // lives in a short-named directory of its own.
        let socket_owner = tempfile::TempDir::with_prefix("rivect-ck-")
            .unwrap_or_else(|error| unreachable!("the scratch root is created: {error}"));
        let socket_dir = socket_owner.path();
        let socket_path = socket_dir.join("s");
        std::os::unix::net::UnixListener::bind(&socket_path).expect("special file");
        let refused = inventory(socket_dir).expect_err("a special file refuses");
        assert!(
            matches!(refused, super::InventoryError::Special { .. }),
            "{refused}"
        );

        let oversized = root.join("oversized");
        let file = std::fs::File::create(&oversized).expect("oversized create");
        file.set_len(super::INVENTORY_FILE_MAX_BYTES + 1)
            .expect("sparse oversize");
        drop(file);
        let refused = inventory(root).expect_err("an oversized file refuses");
        assert!(
            matches!(refused, super::InventoryError::FileTooLarge { .. }),
            "{refused}"
        );
        drop(std::fs::remove_file(&oversized));
    }

    #[test]
    fn inventory_digest_ignores_creation_order() {
        let first_dir = scratch_tree("order-a");
        let first = first_dir.path();
        let second_dir = scratch_tree("order-b");
        let second = second_dir.path();
        let files = [("a/one", b"1"), ("z/two", b"2"), ("top", b"3")];
        for (root, order) in [(&first, 0usize), (&second, 1usize)] {
            std::fs::create_dir_all(root.join("z")).expect("z");
            std::fs::create_dir_all(root.join("a")).expect("a");
            // The two trees genuinely create the same files in DIFFERENT
            // orders (the second walks the list backwards) — a digest
            // that keyed on creation order would differ.
            let mut sequence = files;
            if order == 1 {
                sequence.reverse();
            }
            for (name, bytes) in sequence {
                std::fs::write(root.join(name), bytes).expect("file");
            }
        }
        assert_eq!(
            workspace_digest(first).expect("digest a"),
            workspace_digest(second).expect("digest b"),
            "the inventory digest is creation-order independent"
        );
        std::fs::write(second.join("top"), b"changed").expect("change");
        assert_ne!(
            workspace_digest(first).expect("digest a"),
            workspace_digest(second).expect("digest b"),
            "a byte change moves the digest"
        );
    }

    #[test]
    fn dependency_leaf_errors_map_to_distinct_sites() {
        let links = dependency_leaf_error("x".to_string())(
            rivect_sandbox_helper::FdOpenError::MultipleLinks,
        );
        assert_eq!(links.site(), "dep.cache_links");
        let kind =
            dependency_leaf_error("x".to_string())(rivect_sandbox_helper::FdOpenError::WrongKind);
        assert_eq!(kind.site(), "dep.cache_kind");
        let size =
            dependency_leaf_error("x".to_string())(rivect_sandbox_helper::FdOpenError::Oversize);
        assert_eq!(size.site(), "dep.cache_size");
        let missing =
            dependency_leaf_error("x".to_string())(rivect_sandbox_helper::FdOpenError::Missing);
        assert_eq!(missing.site(), "dep.cache_missing");
        let symlink = dependency_leaf_error("x".to_string())(
            rivect_sandbox_helper::FdOpenError::SymlinkComponent,
        );
        assert_eq!(symlink.site(), "dep.cache_leaf");
        let capability = dependency_leaf_error("x".to_string())(
            rivect_sandbox_helper::FdOpenError::UnsupportedCapability {
                source: std::io::Error::other("unsupported"),
            },
        );
        assert_eq!(capability.site(), "dep.cache_capability");
        let component = dependency_component_error("x".to_string())(
            rivect_sandbox_helper::FdOpenError::SymlinkComponent,
        );
        assert_eq!(component.site(), "dep.cache_component");
    }

    #[test]
    fn check_error_codes_map_cancels_and_split_close_selections() {
        use crate::contracts::ErrorCode;
        let cancel = CheckError::TestCancel {
            detail: "x".to_string(),
        };
        assert_eq!(check_error_code(&cancel), ErrorCode::Cancelled);
        let cancel = CheckError::VendorCancel {
            detail: "x".to_string(),
        };
        assert_eq!(check_error_code(&cancel), ErrorCode::Cancelled);
        // The TASK_CANCELLED close keeps the cancellation code; any other
        // close-selection refusal (a stale selection at close) is a
        // denied effect.
        let cancelled_close = CheckError::CloseSelection {
            detail: super::TASK_CANCELLED.to_string(),
        };
        assert_eq!(check_error_code(&cancelled_close), ErrorCode::Cancelled);
        let stale_close = CheckError::CloseSelection {
            detail: "the task selection is not the check's pinned revision 1 at close".to_string(),
        };
        assert_eq!(check_error_code(&stale_close), ErrorCode::Denied);
        // Deadlines stay capability failures through the catch-all arm.
        let deadline = CheckError::VendorDeadline {
            detail: "x".to_string(),
        };
        assert_eq!(
            check_error_code(&deadline),
            ErrorCode::CapabilityUnavailable
        );
        let denied = CheckError::ExecGrant {
            detail: "x".to_string(),
        };
        assert_eq!(check_error_code(&denied), ErrorCode::Denied);
    }

    #[test]
    fn bounded_capture_single_oversized_chunk_keeps_newest_tail() {
        // One chunk larger than the whole edge bound: the tail must keep
        // the chunk's NEWEST bytes, not its first `room` bytes.
        let mut capture = BoundedCapture::empty();
        let mut chunk = vec![b'a'; 2 * CHECK_CAPTURE_EDGE_BYTES];
        let tail_len = 16;
        let new_tail = chunk.len() - tail_len;
        chunk[new_tail..].fill(b'T');
        capture.extend(&chunk);
        assert_eq!(capture.total as usize, chunk.len());
        assert_eq!(capture.head.len(), CHECK_CAPTURE_EDGE_BYTES);
        assert!(
            capture.head.iter().all(|byte| *byte == b'a'),
            "head keeps the oldest bytes"
        );
        assert_eq!(capture.tail.len(), CHECK_CAPTURE_EDGE_BYTES);
        assert!(
            capture
                .tail
                .iter()
                .rev()
                .take(tail_len)
                .all(|byte| *byte == b'T'),
            "the tail keeps the chunk's newest bytes"
        );
    }

    #[test]
    fn lock_refuses_path_bearing_and_non_semver_identities() {
        let hostile_name = concat!(
            "[[package]]\nname = \"a/../b\"\nversion = \"1.0.0\"\n",
            "source = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"x\"\n"
        );
        let refused = lock_registry_dependencies(hostile_name.as_bytes())
            .expect_err("a path-bearing name is a config refusal");
        assert_eq!(refused.site(), "dep.config");
        let slashed = hostile_name.replace("a/../b", "x/y");
        let refused = lock_registry_dependencies(slashed.as_bytes())
            .expect_err("a slashed name is a config refusal");
        assert_eq!(refused.site(), "dep.config");
        let hostile_version = hostile_name.replace("1.0.0", "1.0/../../etc");
        let refused = lock_registry_dependencies(hostile_version.as_bytes())
            .expect_err("a path-bearing version is a config refusal");
        assert_eq!(refused.site(), "dep.config");
        // A clean registry entry still parses.
        let clean = hostile_name.replace("a/../b", "cfg-if");
        assert_eq!(
            lock_registry_dependencies(clean.as_bytes())
                .expect("a clean registry entry parses")
                .len(),
            1
        );
    }

    #[test]
    fn read_leaf_refuses_growth_after_open() {
        let holder_dir = scratch_tree("leaf-growth");
        let holder = holder_dir.path();
        std::fs::write(holder.join("grow"), b"12345678").expect("seed 8 bytes");
        // The walk needs the canonical spelling: a host temp dir under
        // /var is itself a symlink on macOS.
        let root = holder.join("grow");
        let root = root.parent().map(Path::to_path_buf).unwrap_or(root);
        let root = root.canonicalize().expect("canonical scratch tree");
        let mut parent = rivect_sandbox_helper::open_filesystem_root().unwrap();
        for component in root.components().skip(1) {
            parent = rivect_sandbox_helper::openat_directory(
                &parent,
                component.as_os_str().as_encoded_bytes(),
            )
            .unwrap();
        }
        let mut leaf = rivect_sandbox_helper::openat_leaf(&parent, b"grow", 8).unwrap();
        // The file GROWS after the open-time size check passed: the read
        // itself must refuse at the size seam, never read unbounded.
        std::fs::write(root.join("grow"), b"123456789012").expect("grow past the bound");
        match read_leaf(&mut leaf, "grow", 8) {
            Err(error) => assert_eq!(error.site(), "dep.cache_size"),
            Ok(bytes) => unreachable!(
                "growth past the bound must refuse, read {} bytes",
                bytes.len()
            ),
        }
    }

    #[test]
    fn registry_dir_lineage_recheck_refuses_post_anchor_swap() {
        let holder_dir = scratch_tree("regdir-swap");
        let holder = holder_dir.path();
        let home = holder.join("home");
        let regdir = "index.crates.io-6f17d22bba15001f";
        std::fs::create_dir_all(home.join("registry/cache").join(regdir)).unwrap();
        std::fs::create_dir_all(home.join("registry/index").join(regdir)).unwrap();
        let home = home.canonicalize().unwrap();
        let (anchored, _) = anchor_dependencies(&home).expect("the fake home anchors");
        // Post-anchor replacement by a DIFFERENT directory inode: the
        // reopen succeeds, so only the pinned regdir identity catches
        // the swap — the exact window a held fd would keep reading
        // through (CR-I6).
        let index_regdir = home.join("registry/index").join(regdir);
        let stolen = holder.join("stolen-index");
        std::fs::rename(&index_regdir, &stolen).unwrap();
        std::fs::create_dir(&index_regdir).unwrap();
        match anchored.verify_lineage() {
            Err(error) => assert_eq!(error.site(), "dep.cache_ancestry"),
            Ok(()) => unreachable!("a replaced registry dir must refuse the lineage recheck"),
        }
        // A symlink in the regdir position refuses at its own fd seam:
        // the anchored walk never follows it.
        drop(std::fs::remove_dir(&index_regdir));
        std::os::unix::fs::symlink(&stolen, &index_regdir).unwrap();
        match anchored.verify_lineage() {
            Err(error) => assert!(
                matches!(
                    error.site(),
                    "dep.cache_ancestry" | "dep.cache_root_fd" | "dep.cache_component"
                ),
                "a symlinked registry dir refuses typed, got {}",
                error.site()
            ),
            Ok(()) => unreachable!("a symlinked registry dir must refuse the lineage recheck"),
        }
        drop(std::fs::remove_file(&index_regdir));
    }

    /// Opens a scratch directory through the fd-anchored walk from `/`:
    /// the read_leaf tests need a pinned parent, and the walk requires
    /// the canonical spelling (a host temp dir under /var is itself a
    /// symlink on macOS).
    fn anchored_scratch_dir(
        root: &Path,
    ) -> Result<rivect_sandbox_helper::AnchoredDir, Box<dyn std::error::Error>> {
        let canonical = root.canonicalize()?;
        let mut parent = rivect_sandbox_helper::open_filesystem_root()?;
        for component in canonical.components().skip(1) {
            parent = rivect_sandbox_helper::openat_directory(
                &parent,
                component.as_os_str().as_encoded_bytes(),
            )?;
        }
        Ok(parent)
    }

    /// The dependency-staging unit fixtures pinned to a fake cargo home:
    /// grants minted on its canonical cache/index roots, one
    /// lockfile-named dependency the index legs stage, and an empty
    /// staged-index destination whose byte count the legs assert.
    fn staged_index_fixture(
        tag: &str,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        AnchoredDependencies,
        super::CheckAdmission,
        crate::policy::Policy,
        crate::state::TaskStore,
        std::sync::atomic::AtomicBool,
        PathBuf,
    ) {
        let (root_dir, mut store, _session, task) = bound_store(tag);
        let root = root_dir.path();
        let home = root.join("home");
        let regdir = "index.crates.io-6f17d22bba15001f";
        std::fs::create_dir_all(home.join("registry/cache").join(regdir)).ok();
        std::fs::create_dir_all(home.join("registry/index").join(regdir)).ok();
        let canonical = home.canonicalize().ok().filter(|path| path.is_dir());
        let home = canonical.unwrap_or_else(|| unreachable!("the fixture home canonicalizes"));
        let (anchored, _) = anchor_dependencies(&home)
            .ok()
            .unwrap_or_else(|| unreachable!("the fake home anchors like a real registry"));
        let mut policy = crate::policy::Policy::default();
        let cargo = PathBuf::from("/nonexistent/cargo");
        let exec_grant = policy.grant_classes(
            cargo.parent().expect("toolchain dir").to_path_buf(),
            vec![crate::contracts::EffectClass::Exec],
        );
        let project_grant_id = policy.grant_read(PathBuf::from("/nonexistent/project"));
        let check = super::ConfinedCheck {
            task_id: task.clone(),
            expected_selection_revision: 1,
            project_grant_id,
            project_root: PathBuf::from("/nonexistent/project"),
            manifest_rel: PathBuf::from("Cargo.toml"),
            cargo: cargo.clone(),
            cargo_home: home.clone(),
            target: super::CheckTarget::Integration("check".to_string()),
            harness_threads: 1,
            exact_test: "green_passes".to_string(),
            expected_phase: "candidate-review".to_string(),
            expected_assertion_identity: "green_passes".to_string(),
            expected_candidate_digest: "digest".to_string(),
        };
        let handoff = native_handoff(&task, &policy, &store);
        let mut admission = {
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            executor
                .admit_check(
                    &task,
                    EffectRequest::Exec {
                        grant_id: exec_grant,
                        program: cargo,
                    },
                    crate::policy::PermissionMode::Yolo,
                    &check,
                    &handoff,
                )
                .unwrap_or_else(|error| unreachable!("the admission mints: {error:?}"))
        };
        policy
            .issue_check_dependencies(&store, &mut admission)
            .unwrap_or_else(|error| unreachable!("the sanctioned pair issues: {error:?}"));
        let staged = root.join("staged-index");
        std::fs::create_dir_all(&staged).ok();
        (
            root_dir,
            home,
            anchored,
            admission,
            policy,
            store,
            std::sync::atomic::AtomicBool::new(false),
            staged,
        )
    }

    /// The staged destination carries no index byte after a refused leg.
    fn assert_staged_empty(staged: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let count = std::fs::read_dir(staged)?.count();
        assert_eq!(count, 0, "no index byte was staged, found {count} entries");
        Ok(())
    }

    #[test]
    fn post_archive_index_reads_recheck_lineage_grants_and_cancel()
    -> Result<(), Box<dyn std::error::Error>> {
        let dep = LockDependency {
            name: "cfg-if".to_string(),
            version: "1.0.0".to_string(),
            checksum: "0".to_string(),
        };
        let regdir = "index.crates.io-6f17d22bba15001f";
        // Post-archive swap: the archives already staged, the index
        // regdir replaced by a different directory inode between the
        // archive read and the index entry read (CR A6) — the exact
        // window a held fd would keep reading through. The entry leg
        // refuses at the lineage seam with zero staged bytes.
        let (holder_dir, home, anchored, admission, mut policy, _store, cancel, staged) =
            staged_index_fixture("post-archive-swap");
        let holder = holder_dir.path();
        let index_regdir = home.join("registry/index").join(regdir);
        std::fs::rename(&index_regdir, holder.join("stolen-index"))?;
        std::fs::create_dir(&index_regdir)?;
        match stage_index_entry(
            &dep,
            &anchored,
            admission.receipt().expect("receipt"),
            &mut policy,
            &cancel,
            &staged,
        ) {
            Err(error) => assert_eq!(
                error.site(),
                "dep.cache_ancestry",
                "the post-archive swap refuses at the lineage seam"
            ),
            Ok(()) => unreachable!("a swapped index regdir must refuse the entry read"),
        }
        assert_staged_empty(&staged)?;

        // config.json holds the same recheck at its own read.
        let (holder_dir, home, anchored, admission, mut policy, _store, cancel, staged) =
            staged_index_fixture("post-archive-swap-config");
        let holder = holder_dir.path();
        let index_regdir = home.join("registry/index").join(regdir);
        std::fs::rename(&index_regdir, holder.join("stolen-index"))?;
        std::fs::create_dir(&index_regdir)?;
        match stage_index_config(
            &anchored,
            admission.receipt().expect("receipt"),
            &mut policy,
            &cancel,
            &staged,
        ) {
            Err(error) => assert_eq!(error.site(), "dep.cache_ancestry"),
            Ok(()) => unreachable!("a swapped index regdir must refuse the config read"),
        }
        assert_staged_empty(&staged)?;

        // In-run death of the pair stops the index read at its own seam
        // — a released allocation's entries are gone, so the reconsult
        // at the read itself refuses (TA revocation-per-site; the opaque
        // receipt design consumes the pair through the issuer's release,
        // never through a generic revoke).
        let (_holder, _home, anchored, mut admission, mut policy, store, cancel, staged) =
            staged_index_fixture("post-archive-revoke");
        policy.release_check_dependencies(&store, &mut admission);
        match stage_index_entry(
            &dep,
            &anchored,
            admission.receipt().expect("receipt"),
            &mut policy,
            &cancel,
            &staged,
        ) {
            Err(error) => assert_eq!(
                error.site(),
                "dep.cache_denied",
                "a released pair must refuse the entry read"
            ),
            Ok(()) => unreachable!("a released pair must refuse the entry read"),
        }
        assert_staged_empty(&staged)?;

        // Cancellation between the archive read and the index read is
        // the vendor-cancel seam, never a partial stage.
        let (_holder, _home, anchored, admission, mut policy, _store, cancel, staged) =
            staged_index_fixture("post-archive-cancel");
        cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        match stage_index_entry(
            &dep,
            &anchored,
            admission.receipt().expect("receipt"),
            &mut policy,
            &cancel,
            &staged,
        ) {
            Err(error) => assert_eq!(error.site(), "vendor.cancel"),
            Ok(()) => unreachable!("a cancelled index read must refuse"),
        }
        assert_staged_empty(&staged)?;

        Ok(())
    }

    #[test]
    fn read_leaf_refuses_identity_swap_after_open() -> Result<(), Box<dyn std::error::Error>> {
        let holder_dir = scratch_tree("leaf-identity-swap");
        let holder = holder_dir.path();
        std::fs::write(holder.join("leaf"), b"authorized bytes")?;
        let parent = anchored_scratch_dir(holder)?;
        let mut leaf = rivect_sandbox_helper::openat_leaf(&parent, b"leaf", 64)?;
        // A same-name DIFFERENT-inode regular file replaces the leaf
        // between the open and the read: the held fd still names the
        // ORIGINAL inode, but its link count dropped to zero, so only
        // the identity comparison refuses — without it the read would
        // happily stream the original inode's bytes (TA M4).
        std::fs::write(holder.join("impostor"), b"replacement bytes")?;
        std::fs::rename(holder.join("impostor"), holder.join("leaf"))?;
        match read_leaf(&mut leaf, "leaf", 64) {
            Err(error) => assert_eq!(
                error.site(),
                "dep.cache_fd_identity",
                "the mid-flight identity swap refuses at the fd seam"
            ),
            Ok(bytes) => unreachable!(
                "a swapped leaf name must refuse, read {} bytes",
                bytes.len()
            ),
        }

        Ok(())
    }

    #[test]
    fn read_leaf_refuses_oversize_metadata_without_allocating()
    -> Result<(), Box<dyn std::error::Error>> {
        let holder_dir = scratch_tree("leaf-oversize-metadata");
        let holder = holder_dir.path();
        std::fs::write(holder.join("sparse"), b"12345678")?;
        let parent = anchored_scratch_dir(holder)?;
        let mut leaf = rivect_sandbox_helper::openat_leaf(&parent, b"sparse", 8)?;
        // The file grows into a 256 MiB sparse hole after the open-time
        // size check passed: the read must refuse at the size seam
        // BEFORE any allocation — a metadata-sized reserve would hand
        // the attacker the allocation itself (CR A11).
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(holder.join("sparse"))?;
        file.set_len(256 * 1024 * 1024)?;
        drop(file);
        match read_leaf(&mut leaf, "sparse", 8) {
            Err(error) => {
                assert_eq!(error.site(), "dep.cache_size");
                assert!(
                    error.cause().contains("before its first byte"),
                    "the refusal names the pre-read bound, got {}",
                    error.cause()
                );
            }
            Ok(bytes) => unreachable!("oversize metadata must refuse, read {} bytes", bytes.len()),
        }

        Ok(())
    }

    #[test]
    fn read_control_exec_failure_is_not_the_legs_own_denial() {
        // The CR probe shape: sandbox-exec denying only the EXEC exits
        // nonzero naming cat with zero read attempts. The exec-failure
        // wording must refuse the leg even when every evidence string
        // is present — an exec denial proves nothing about the data
        // rules.
        let mut stderr = BoundedCapture::empty();
        stderr.extend(
            b"cat: /control/secret: sandbox-exec: execvp() of '/bin/cat' failed: Operation not permitted",
        );
        let observed = super::PhaseObserved {
            status: exited(71),
            stdout: BoundedCapture::empty(),
            stderr,
        };
        match assert_denied_control_cause(
            &observed,
            "read",
            &["cat".to_string(), "/control/secret".to_string()],
            &[],
        ) {
            Err(error) => assert!(
                error.cause().contains("exec failure"),
                "the exec-denied control fails on its exec cause, got {}",
                error.cause()
            ),
            Ok(()) => unreachable!("an exec denial must not pass as the read denial"),
        }
    }

    #[test]
    fn read_control_denial_requires_the_exact_secret_path() {
        // The wiring itself is load-bearing (CR A2): the read leg's
        // expectations must carry EVERY evidence string — the exact
        // secret path, not only the probe's name — so a denial naming no
        // target can never satisfy the leg.
        let (all, any) = super::control_leg_expectations("read", &["cat", "/control/secret"]);
        assert_eq!(
            all,
            vec!["cat".to_string(), "/control/secret".to_string()],
            "the read leg requires the exact secret path in the denial"
        );
        assert!(any.is_empty(), "the read leg has no any-of set");
        let (all, _) = super::control_leg_expectations("write", &["/control/deny"]);
        assert_eq!(all, vec!["/control/deny".to_string()]);
        let (all, any) = super::control_leg_expectations("network", &[]);
        assert!(all.is_empty(), "the network leg requires no target");
        assert_eq!(any, vec!["socket".to_string(), "connect".to_string()]);

        // A denial that names the probe and the OS permission wording
        // but NOT the target names no read attempt: the predicate must
        // refuse on the missing path. No exec wording here — the exec
        // arm is the sibling test's own discriminator.
        let mut stderr = BoundedCapture::empty();
        stderr.extend(b"cat: cannot open probe input: Operation not permitted");
        let observed = super::PhaseObserved {
            status: exited(71),
            stdout: BoundedCapture::empty(),
            stderr,
        };
        match assert_denied_control_cause(
            &observed,
            "read",
            &["cat".to_string(), "/control/secret".to_string()],
            &[],
        ) {
            Err(error) => assert!(
                error.cause().contains("/control/secret"),
                "the refusal names the missing evidence, got {}",
                error.cause()
            ),
            Ok(()) => unreachable!("a denial that names no target must not pass"),
        }
        // The honest read denial — cat naming its target with the OS
        // permission wording — still passes.
        let mut stderr = BoundedCapture::empty();
        stderr.extend(b"cat: /control/secret: Operation not permitted");
        let observed = super::PhaseObserved {
            status: exited(1),
            stdout: BoundedCapture::empty(),
            stderr,
        };
        assert!(
            assert_denied_control_cause(
                &observed,
                "read",
                &["cat".to_string(), "/control/secret".to_string()],
                &[]
            )
            .is_ok(),
            "an honest read denial passes the predicate"
        );
    }

    /// The sampled group-RSS stop must fire on the SUM of the group's
    /// members: a group whose every member sits under the ceiling (its
    /// own largest member's RSS) still crosses in aggregate — the
    /// fan-out hog the group ceiling exists for. A per-member
    /// comparison returns false here. The real 4 GiB crossing stays
    /// recorded under DEC-041.
    #[cfg(target_os = "macos")]
    #[test]
    fn group_rss_stop_fires_on_the_sum_not_one_member() -> Result<(), Box<dyn std::error::Error>> {
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30 & sleep 30 & wait")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let leader = child.id();
        let deadline = Instant::now() + std::time::Duration::from_secs(20);
        let members = loop {
            let members = rivect_sandbox_helper::process_group_members(leader)?;
            let live = members
                .iter()
                .filter(|pid| {
                    matches!(
                        rivect_sandbox_helper::resident_bytes(**pid),
                        Ok(rss) if rss > 0
                    )
                })
                .count();
            if members.len() >= 3 && live == members.len() {
                break members;
            }
            assert!(
                Instant::now() < deadline,
                "the group never held three live members"
            );
            // The helper's own bounded idle wait stands in for a sleep
            // here: src/ keeps no untracked thread sleeps (standards §5).
            rivect_sandbox_helper::wait_ready(&[], &[], std::time::Duration::from_millis(50))?;
        };
        let largest = members
            .iter()
            .map(|pid| rivect_sandbox_helper::resident_bytes(*pid))
            .filter_map(Result::ok)
            .max()
            .unwrap_or(0);
        assert!(largest > 0, "a live member holds resident bytes");
        assert!(
            super::group_rss_sum_over(leader, largest),
            "the group's sum crosses its own largest member ({} members)",
            members.len()
        );
        assert!(
            !super::group_rss_sum_over(leader, u64::MAX),
            "a group under the ceiling does not fire"
        );
        assert!(
            !super::group_rss_over_ceiling(leader),
            "the tiny fixture group stays far under the 4 GiB ceiling"
        );
        rivect_sandbox_helper::kill_process_group(leader).ok();
        child.wait().ok();
        Ok(())
    }

    // ----- selection/attempt binding (CR-I5) unit discriminators ------

    /// A read worker stub none of the binding paths reach: admission
    /// verification never consults a worker.
    struct NoWorker;

    impl super::ReadWorker for NoWorker {
        fn read_once(
            &mut self,
            _scope_root: &Path,
            _target: &Path,
        ) -> Result<super::ReadObservation, WorkerError> {
            Err(WorkerError::SandboxUnavailable {
                reason: "the binding tests never read".to_string(),
            })
        }
    }

    /// One open store holding a session, a task, and its first recorded
    /// plan selection — the server-side state the binding rechecks read.
    fn bound_store(
        tag: &str,
    ) -> (
        tempfile::TempDir,
        crate::state::TaskStore,
        crate::contracts::SessionId,
        crate::contracts::TaskId,
    ) {
        let root_dir = scratch_tree(tag);
        let root = root_dir.path();
        let mut store = crate::state::TaskStore::open(&root.join("state.sqlite")).expect("store");
        let (session, _, _, _) = store
            .open_session("binding-session", "binding-connection", None)
            .expect("session");
        let result = store
            .create_task(
                &session,
                "binding-command",
                "unit",
                "binding goal",
                (&[], &[]),
            )
            .expect("task");
        let task = result.task_id;
        let record = store
            .record_plan_selection(
                &session,
                &task,
                &crate::state::PlanSelectionWrite {
                    facts_digest: "unit-facts",
                    request_kind: crate::state::RequestKind::PlanOnly,
                    rows: &[],
                },
            )
            .expect("selection records");
        assert_eq!(record.revision, 1, "the first selection is revision 1");
        (root_dir, store, session, task)
    }

    fn binding_admitted(task: &crate::contracts::TaskId) -> super::AdmittedEffect {
        super::AdmittedEffect {
            task_id: task.clone(),
            attempt_id: "attempt-unit".to_string(),
            request: EffectRequest::Exec {
                grant_id: "grant-unit".to_string(),
                program: PathBuf::from("/nonexistent/cargo"),
            },
            mode: crate::policy::PermissionMode::Yolo,
            expected_identity: None,
            scope_root: PathBuf::from("/nonexistent"),
        }
    }

    #[test]
    fn admission_refuses_a_stale_selection_revision() {
        let (_root, mut store, _session, task) = bound_store("stale-selection");
        let mut policy = crate::policy::Policy::default();
        let mut worker = NoWorker;
        let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
        let check = super::ConfinedCheck {
            task_id: task.clone(),
            // The store holds revision 1; a check pinned to any other
            // revision must refuse before anything else runs.
            expected_selection_revision: 2,
            project_grant_id: "grant-unit".to_string(),
            project_root: PathBuf::from("/nonexistent/project"),
            manifest_rel: PathBuf::from("Cargo.toml"),
            cargo: PathBuf::from("/nonexistent/cargo"),
            cargo_home: PathBuf::from("/nonexistent/home"),
            target: super::CheckTarget::Integration("check".to_string()),
            harness_threads: 1,
            exact_test: "green_passes".to_string(),
            expected_phase: "candidate-review".to_string(),
            expected_assertion_identity: "green_passes".to_string(),
            expected_candidate_digest: "digest".to_string(),
        };
        let admitted = binding_admitted(&task);
        match executor.verify_check_admission(&admitted, &check, true) {
            Err(error) => {
                assert_eq!(
                    error.site(),
                    "admit.selection",
                    "a stale selection refuses at the selection seam"
                );
            }
            Ok(()) => unreachable!("a stale selection revision must refuse admission"),
        }
    }

    #[test]
    fn foreign_attempt_pair_refuses_at_admit_dep() {
        let (root_dir, mut store, _session, task) = bound_store("foreign-attempt");
        let root = root_dir.path();
        let mut policy = crate::policy::Policy::default();
        let cargo_home = root.join("home");
        std::fs::create_dir_all(cargo_home.join("registry/cache")).expect("cache root");
        std::fs::create_dir_all(cargo_home.join("registry/index")).expect("index root");
        let cargo = PathBuf::from("/nonexistent/cargo");
        let exec_grant = policy.grant_classes(
            cargo.parent().expect("toolchain dir").to_path_buf(),
            vec![crate::contracts::EffectClass::Exec],
        );
        let project_grant_id = policy.grant_read(PathBuf::from("/nonexistent/project"));
        let check = super::ConfinedCheck {
            task_id: task.clone(),
            expected_selection_revision: 1,
            project_grant_id,
            project_root: PathBuf::from("/nonexistent/project"),
            manifest_rel: PathBuf::from("Cargo.toml"),
            cargo: cargo.clone(),
            cargo_home,
            target: super::CheckTarget::Integration("check".to_string()),
            harness_threads: 1,
            exact_test: "green_passes".to_string(),
            expected_phase: "candidate-review".to_string(),
            expected_assertion_identity: "green_passes".to_string(),
            expected_candidate_digest: "digest".to_string(),
        };
        let handoff = native_handoff(&task, &policy, &store);
        let mut admission = {
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            executor
                .admit_check(
                    &task,
                    EffectRequest::Exec {
                        grant_id: exec_grant,
                        program: cargo,
                    },
                    crate::policy::PermissionMode::Yolo,
                    &check,
                    &handoff,
                )
                .expect("the admission mints")
        };
        policy
            .issue_check_dependencies(&store, &mut admission)
            .expect("the sanctioned pair issues");
        {
            let mut worker = NoWorker;
            let executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            executor
                .verify_dependency_pair(
                    admission.attempt_id(),
                    &check,
                    admission.receipt().expect("receipt"),
                )
                .expect("the own-attempt pair admits");
            // A pair minted for a DIFFERENT attempt id must not confirm
            // that attempt's ledger: the server-owned attempt id is part
            // of the pair's binding (CR-I5).
            match executor.verify_dependency_pair(
                "attempt-unit",
                &check,
                admission.receipt().expect("receipt"),
            ) {
                Err(error) => assert_eq!(
                    error.site(),
                    "admit.dep",
                    "a foreign-attempt pair refuses at the pair seam"
                ),
                Ok(()) => unreachable!("a pair minted for another attempt must refuse"),
            }
        }
    }

    #[test]
    fn aliased_or_wide_dependency_roots_refuse_at_admit_dep() {
        let (root_dir, mut store, _session, task) = bound_store("aliased-roots");
        let root = root_dir.path();
        let mut policy = crate::policy::Policy::default();
        let home = root.join("home");
        std::fs::create_dir_all(home.join("registry/cache")).expect("cache root");
        std::fs::create_dir_all(home.join("registry/index")).expect("index root");
        // The aliased spelling points at a DIFFERENT registry tree, the
        // forged pair the old public-tuple legs expressed.
        std::fs::create_dir_all(root.join("forged-registry/cache")).expect("forgged root");
        let cargo = PathBuf::from("/nonexistent/cargo");
        let exec_grant = policy.grant_classes(
            cargo.parent().expect("toolchain dir").to_path_buf(),
            vec![crate::contracts::EffectClass::Exec],
        );
        let project_grant_id = policy.grant_read(PathBuf::from("/nonexistent/project"));
        let check = super::ConfinedCheck {
            task_id: task.clone(),
            expected_selection_revision: 1,
            project_grant_id,
            project_root: PathBuf::from("/nonexistent/project"),
            manifest_rel: PathBuf::from("Cargo.toml"),
            cargo: cargo.clone(),
            cargo_home: home.clone(),
            target: super::CheckTarget::Integration("check".to_string()),
            harness_threads: 1,
            exact_test: "green_passes".to_string(),
            expected_phase: "candidate-review".to_string(),
            expected_assertion_identity: "green_passes".to_string(),
            expected_candidate_digest: "digest".to_string(),
        };
        let handoff = native_handoff(&task, &policy, &store);
        let mut admission = {
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            executor
                .admit_check(
                    &task,
                    EffectRequest::Exec {
                        grant_id: exec_grant,
                        program: cargo,
                    },
                    crate::policy::PermissionMode::Yolo,
                    &check,
                    &handoff,
                )
                .expect("the admission mints")
        };
        policy
            .issue_check_dependencies(&store, &mut admission)
            .expect("the sanctioned pair issues");
        let receipt = admission.receipt().expect("receipt");
        let cache_root = home.join("registry/cache");
        let index_root = home.join("registry/index");
        {
            let mut worker = NoWorker;
            let executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            executor
                .verify_dependency_pair(admission.attempt_id(), &check, receipt)
                .expect("the canonical pair admits");
        }
        // An ALIASED cache root — a different tree spelled as the cache
        // root — refuses at the consumer-visible seam before any byte.
        policy.rebind_check_root_for_test(
            receipt,
            crate::policy::CheckRootHalf::Cache,
            root.join("forged-registry/cache"),
        );
        {
            let mut worker = NoWorker;
            let executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            match executor.verify_dependency_pair(admission.attempt_id(), &check, receipt) {
                Err(error) => assert_eq!(
                    error.site(),
                    "admit.dep",
                    "an aliased cache root refuses at the pair seam"
                ),
                Ok(()) => unreachable!("an aliased cache root must refuse"),
            }
        }
        // A WIDE cache root — the cargo home itself, a strict parent of
        // the authorized registry cache — refuses the same way.
        policy.rebind_check_root_for_test(
            receipt,
            crate::policy::CheckRootHalf::Cache,
            home.clone(),
        );
        {
            let mut worker = NoWorker;
            let executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            match executor.verify_dependency_pair(admission.attempt_id(), &check, receipt) {
                Err(error) => assert_eq!(
                    error.site(),
                    "admit.dep",
                    "a wide cache root refuses at the pair seam"
                ),
                Ok(()) => unreachable!("a wide cache root must refuse"),
            }
        }
        // A WIDE index root refuses on the other half of the pair.
        policy.rebind_check_root_for_test(receipt, crate::policy::CheckRootHalf::Cache, cache_root);
        policy.rebind_check_root_for_test(receipt, crate::policy::CheckRootHalf::Index, home);
        {
            let mut worker = NoWorker;
            let executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            match executor.verify_dependency_pair(admission.attempt_id(), &check, receipt) {
                Err(error) => assert_eq!(
                    error.site(),
                    "admit.dep",
                    "a wide index root refuses at the pair seam"
                ),
                Ok(()) => unreachable!("a wide index root must refuse"),
            }
        }
        // Restoring both canonical roots admits again: the holder, the
        // ordinary grants, and the untouched half all survived the
        // mutations.
        policy.rebind_check_root_for_test(receipt, crate::policy::CheckRootHalf::Index, index_root);
        {
            let mut worker = NoWorker;
            let executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            executor
                .verify_dependency_pair(admission.attempt_id(), &check, receipt)
                .expect("the restored canonical pair admits again");
        }
        drop(admission);
    }

    /// Test-harness unwrap: the inline tests route their fixtures
    /// through this explicit helper so new panic-family text never
    /// enters the module.
    fn harness_ok<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => unreachable!("{what} failed: {error:?}"),
        }
    }

    /// A Runtime-shaped native handoff over the given policy/store pair:
    /// the config owner's default (workflow not explicitly off) snapshot.
    fn native_handoff(
        task: &crate::contracts::TaskId,
        policy: &crate::policy::Policy,
        store: &crate::state::TaskStore,
    ) -> super::CheckHandoff {
        let effective = harness_ok(
            crate::config::resolve_effective(None),
            "the default effective config",
        );
        let state = std::sync::Arc::new(super::WorkflowOffState::new(&effective));
        super::CheckHandoff::from_owner(
            &state,
            task,
            std::sync::Arc::clone(policy.identity()),
            std::sync::Arc::clone(store.identity()),
        )
    }

    /// A check whose every pre-claim gate passes: real canonical cargo
    /// (this test binary — never spawned on the refusal legs), a real
    /// project root, and a real cargo home with both registry roots, so
    /// `verify_check_admission` admits and the pre-claim exits under
    /// test are reached through the production order.
    fn executable_check_parts(
        root: &Path,
        task: &crate::contracts::TaskId,
        policy: &mut crate::policy::Policy,
        revision: u64,
    ) -> (super::ConfinedCheck, String, PathBuf) {
        let binary = harness_ok(std::env::current_exe(), "the test binary");
        let cargo = harness_ok(binary.canonicalize(), "the canonical test binary");
        let project = root.join("project");
        harness_ok(std::fs::create_dir_all(&project), "project root");
        let home = root.join("home");
        harness_ok(
            std::fs::create_dir_all(home.join("registry/cache")),
            "cache root",
        );
        harness_ok(
            std::fs::create_dir_all(home.join("registry/index")),
            "index root",
        );
        let toolchain_dir = harness_ok(cargo.parent().ok_or(()), "toolchain dir");
        let exec_grant = policy.grant_classes(
            toolchain_dir.to_path_buf(),
            vec![crate::contracts::EffectClass::Exec],
        );
        let project_grant_id = policy.grant_read(project.clone());
        (
            super::ConfinedCheck {
                task_id: task.clone(),
                expected_selection_revision: revision,
                project_grant_id,
                project_root: project,
                manifest_rel: PathBuf::from("Cargo.toml"),
                cargo: cargo.clone(),
                cargo_home: home,
                target: super::CheckTarget::Integration("check".to_string()),
                harness_threads: 1,
                exact_test: "green_passes".to_string(),
                expected_phase: "candidate-review".to_string(),
                expected_assertion_identity: "green_passes".to_string(),
                expected_candidate_digest: "digest".to_string(),
            },
            exec_grant,
            cargo,
        )
    }

    /// Mints one admission over the given policy and store through the
    /// sanctioned issuer path.
    fn mint_executable_admission(
        store: &mut crate::state::TaskStore,
        policy: &mut crate::policy::Policy,
        task: &crate::contracts::TaskId,
        check: &super::ConfinedCheck,
        exec_grant: &str,
        cargo: &Path,
    ) -> super::CheckAdmission {
        let handoff = native_handoff(task, policy, store);
        let mut worker = NoWorker;
        let mut executor = super::Executor::new(policy, store, &mut worker);
        harness_ok(
            executor.admit_check(
                task,
                EffectRequest::Exec {
                    grant_id: exec_grant.to_string(),
                    program: cargo.to_path_buf(),
                },
                crate::policy::PermissionMode::Yolo,
                check,
                &handoff,
            ),
            "the admission mints",
        )
    }

    #[test]
    fn pre_claim_exits_settle_nothing_and_keep_the_attempt_planned() {
        // Leg A — a failed admission re-verification (stale selection)
        // is a typed refusal, never an authoritative settlement.
        let (root_dir, mut store, _session, task) = bound_store("pre-claim-stale");
        let root = root_dir.path();
        let mut policy = crate::policy::Policy::default();
        let (stale_check, exec_grant, cargo) = executable_check_parts(root, &task, &mut policy, 2);
        let mut admission = mint_executable_admission(
            &mut store,
            &mut policy,
            &task,
            &stale_check,
            &exec_grant,
            &cargo,
        );
        {
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            match executor.execute_check(
                &mut admission,
                &stale_check,
                &std::sync::atomic::AtomicBool::new(false),
            ) {
                Err(super::ExecutorError::Check(CheckError::SelectionMismatch { .. })) => {}
                other => unreachable!("a stale selection must refuse typed, got {other:?}"),
            }
        }
        assert_eq!(
            harness_ok(
                store.attempt_state(admission.bound_attempt_id()),
                "attempt state"
            ),
            Some("planned".to_string()),
            "a pre-claim refusal never settles the planned attempt"
        );
        assert!(
            !harness_ok(
                store.has_retained(&check_boundary_id(
                    admission.bound_attempt_id(),
                    "admit.selection"
                )),
                "retained lookup"
            ),
            "a pre-claim refusal writes no attempt-keyed row"
        );

        // Leg B — cancellation before the claim: typed refusal, the
        // attempt stays planned, no row, no rejection.
        let (root_dir, mut store, _session, task) = bound_store("pre-claim-cancel");
        let root = root_dir.path();
        let mut policy = crate::policy::Policy::default();
        let (check, exec_grant, cargo) = executable_check_parts(root, &task, &mut policy, 1);
        let mut admission =
            mint_executable_admission(&mut store, &mut policy, &task, &check, &exec_grant, &cargo);
        {
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            match executor.execute_check(
                &mut admission,
                &check,
                &std::sync::atomic::AtomicBool::new(true),
            ) {
                Err(super::ExecutorError::Check(CheckError::VendorCancel { .. })) => {}
                other => unreachable!("pre-claim cancellation must refuse typed, got {other:?}"),
            }
        }
        assert_eq!(
            harness_ok(
                store.attempt_state(admission.bound_attempt_id()),
                "attempt state"
            ),
            Some("planned".to_string()),
            "a cancelled pre-claim presentation leaves the attempt planned"
        );
        assert!(
            !harness_ok(
                store.has_retained(&check_boundary_id(
                    admission.bound_attempt_id(),
                    "vendor.cancel"
                )),
                "retained lookup"
            ),
            "a cancelled pre-claim presentation writes no attempt-keyed row"
        );

        // Leg C — a Busy claim refusal after the scoped restoration: the
        // claim's own rejection row is the whole record; the executor
        // adds no attempt-keyed settlement under the restored timeout.
        let (root_dir, mut store, _session, task) = bound_store("pre-claim-busy");
        let root = root_dir.path();
        let mut policy = crate::policy::Policy::default();
        let (check, exec_grant, cargo) = executable_check_parts(root, &task, &mut policy, 1);
        let mut admission =
            mint_executable_admission(&mut store, &mut policy, &task, &check, &exec_grant, &cargo);
        crate::state::proof::arm_fault(crate::state::proof::Site::Busy);
        {
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            match executor.execute_check(
                &mut admission,
                &check,
                &std::sync::atomic::AtomicBool::new(false),
            ) {
                Err(super::ExecutorError::Check(CheckError::Claim {
                    site: "admit.claim_busy",
                    ..
                })) => {}
                other => {
                    unreachable!("an injected busy BEGIN must refuse at its site, got {other:?}")
                }
            }
        }
        assert_eq!(
            harness_ok(
                store.attempt_state(admission.bound_attempt_id()),
                "attempt state"
            ),
            Some("planned".to_string()),
            "a busy claim refusal never settles the attempt"
        );
        assert!(
            !harness_ok(
                store.has_retained(&check_boundary_id(
                    admission.bound_attempt_id(),
                    "admit.claim_busy"
                )),
                "retained lookup"
            ),
            "the executor writes no attempt-keyed row over the claim's own rejection"
        );
    }

    #[test]
    fn foreign_store_presentation_keeps_the_real_holders_allocation() {
        let (root_dir, mut store, _session, task) = bound_store("foreign-store-holder");
        let root = root_dir.path();
        let mut policy = crate::policy::Policy::default();
        let (check, exec_grant, cargo) = executable_check_parts(root, &task, &mut policy, 1);
        let mut admission =
            mint_executable_admission(&mut store, &mut policy, &task, &check, &exec_grant, &cargo);
        harness_ok(
            policy.issue_check_dependencies(&store, &mut admission),
            "the sanctioned pair issues",
        );
        // A second store on the SAME policy: the presentation is foreign
        // at the store identity and must dispose nothing.
        let peer_dir = scratch_tree("foreign-store-peer");
        let peer_root = peer_dir.path();
        let mut peer_store = harness_ok(
            crate::state::TaskStore::open(&peer_root.join("state.sqlite")),
            "peer store",
        );
        {
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut policy, &mut peer_store, &mut worker);
            match executor.execute_check(
                &mut admission,
                &check,
                &std::sync::atomic::AtomicBool::new(false),
            ) {
                Err(super::ExecutorError::Check(CheckError::Claim {
                    site: "admit.issuer",
                    ..
                })) => {}
                other => unreachable!("a foreign-store presentation must refuse, got {other:?}"),
            }
        }
        assert_eq!(
            admission.phase(),
            super::CheckPhase::Pending,
            "a foreign presentation never spends the holder's admission"
        );
        // The legitimate issuer/store pair still dispatches past the
        // issuer gate (it refuses later, at the pre-claim cancellation).
        {
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            match executor.execute_check(
                &mut admission,
                &check,
                &std::sync::atomic::AtomicBool::new(true),
            ) {
                Err(super::ExecutorError::Check(CheckError::VendorCancel { .. })) => {}
                other => unreachable!("the genuine pair must pass the issuer gate, got {other:?}"),
            }
        }
    }

    #[test]
    fn settle_failure_never_removes_another_attempt_s_root() {
        let (root_dir, mut store, _session, task) = bound_store("cross-attempt-root");
        let root = root_dir.path();
        let mut policy = crate::policy::Policy::default();
        let (check, exec_grant, cargo) = executable_check_parts(root, &task, &mut policy, 1);
        let admission =
            mint_executable_admission(&mut store, &mut policy, &task, &check, &exec_grant, &cargo);
        let mut worker = NoWorker;
        let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
        let survivor = root.join("rivect-check-earlier-attempt");
        harness_ok(
            std::fs::create_dir_all(&survivor),
            "the earlier attempt's root",
        );
        harness_ok(
            std::fs::write(survivor.join("sentinel"), b"earlier attempt debris"),
            "sentinel",
        );
        executor.check_attempt_root = Some(super::AttemptRoot {
            attempt_id: "earlier-attempt".to_string(),
            canonical_root: survivor.clone(),
            dev: 0,
            ino: 0,
        });
        let settled = executor.settle_check_failure(
            admission.admitted(),
            CheckError::VendorResult {
                detail: "the later attempt failed".to_string(),
            },
        );
        assert!(
            matches!(
                settled,
                super::ExecutorError::Check(CheckError::VendorResult { .. })
            ),
            "the original cause returns unchanged: {settled:?}"
        );
        assert!(
            survivor.join("sentinel").exists(),
            "a later attempt's settle is not cleanup authority over an earlier attempt's root"
        );
        drop(admission);
    }

    #[test]
    fn unregistered_pending_receipt_refuses_before_the_first_claim() {
        let (root_dir, mut store, _session, task) = bound_store("pending-receipt");
        let root = root_dir.path();
        let mut policy = crate::policy::Policy::default();
        let (check, exec_grant, cargo) = executable_check_parts(root, &task, &mut policy, 1);
        let mut admission =
            mint_executable_admission(&mut store, &mut policy, &task, &check, &exec_grant, &cargo);
        harness_ok(
            policy.issue_check_dependencies(&store, &mut admission),
            "the sanctioned pair issues",
        );
        // The entries die while the admission stays Pending: an
        // unregistered receipt must refuse before the first claim, root,
        // or copied project byte.
        policy.consume_check_pair(&mut admission);
        assert_eq!(
            admission.phase(),
            super::CheckPhase::Pending,
            "the unregistration keeps the phase pending"
        );
        {
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            match executor.execute_check(
                &mut admission,
                &check,
                &std::sync::atomic::AtomicBool::new(false),
            ) {
                Err(super::ExecutorError::Check(CheckError::DependencyGrant { .. })) => {}
                other => unreachable!("an unregistered receipt must refuse typed, got {other:?}"),
            }
        }
        assert_eq!(
            harness_ok(
                store.attempt_state(admission.bound_attempt_id()),
                "attempt state"
            ),
            Some("planned".to_string()),
            "the pre-claim receipt refusal never claims or settles"
        );
        assert!(
            !super::attempt_root_of(admission.bound_attempt_id()).exists(),
            "no attempt root is created for a refused presentation"
        );
    }

    #[test]
    fn foreign_workflow_off_handoff_refuses_before_planning() {
        let (_root, holder_store, _session, task) = bound_store("handoff-holder-runtime");
        let holder_policy = crate::policy::Policy::default();
        // The off handoff is minted over the HOLDING runtime's pair…
        let off_config = crate::config::resolve_effective(Some(&format!(
            "{OFF_BASE_CONFIG}[workflow]\nenabled = false\n"
        )))
        .expect("the off config resolves");
        let off_state = std::sync::Arc::new(super::WorkflowOffState::new(&off_config));
        let handoff = super::CheckHandoff::from_owner(
            &off_state,
            &task,
            std::sync::Arc::clone(holder_policy.identity()),
            std::sync::Arc::clone(holder_store.identity()),
        );
        // …and presented to a DIFFERENT runtime's executor: it must
        // refuse before planning, with zero attempt rows on the target.
        let peer_dir = scratch_tree("handoff-target-runtime");
        let peer_root = peer_dir.path();
        let mut peer_store = harness_ok(
            crate::state::TaskStore::open(&peer_root.join("state.sqlite")),
            "peer store",
        );
        let (peer_session, _, _, _) = harness_ok(
            peer_store.open_session("peer-session", "peer-connection", None),
            "peer session",
        );
        let peer_task = harness_ok(
            peer_store.create_task(
                &peer_session,
                "peer-command",
                "unit",
                "peer goal",
                (&[], &[]),
            ),
            "peer task",
        )
        .task_id;
        harness_ok(
            peer_store.record_plan_selection(
                &peer_session,
                &peer_task,
                &crate::state::PlanSelectionWrite {
                    facts_digest: "peer-facts",
                    request_kind: crate::state::RequestKind::PlanOnly,
                    rows: &[],
                },
            ),
            "peer selection",
        );
        let mut peer_policy = crate::policy::Policy::default();
        let (peer_check, peer_exec_grant, peer_cargo) =
            executable_check_parts(peer_root, &peer_task, &mut peer_policy, 1);
        {
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut peer_policy, &mut peer_store, &mut worker);
            match executor.admit_check(
                &peer_task,
                EffectRequest::Exec {
                    grant_id: peer_exec_grant.clone(),
                    program: peer_cargo.clone(),
                },
                crate::policy::PermissionMode::Yolo,
                &peer_check,
                &handoff,
            ) {
                Err(super::ExecutorError::Check(CheckError::SelectionMismatch { detail })) => {
                    assert!(
                        detail.contains("another runtime"),
                        "the refusal names the foreign handoff: {detail}"
                    );
                }
                other => unreachable!("a foreign handoff must refuse, got {other:?}"),
            }
        }
        // The target runtime stays untouched: no attempt, claim, root, or
        // byte on it, and its own native admission still mints.
        {
            let peer_handoff = native_handoff(&peer_task, &peer_policy, &peer_store);
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut peer_policy, &mut peer_store, &mut worker);
            harness_ok(
                executor.admit_check(
                    &peer_task,
                    EffectRequest::Exec {
                        grant_id: peer_exec_grant,
                        program: peer_cargo,
                    },
                    crate::policy::PermissionMode::Yolo,
                    &peer_check,
                    &peer_handoff,
                ),
                "the target runtime's own native admission still mints",
            );
        }
    }

    #[test]
    fn attempt_root_creation_refuses_preexisting_names_without_deleting() {
        let (root_dir, mut store, _session, _task) = bound_store("preexisting-root");
        let root = root_dir.path();
        let prefix = format!("preexisting-{}", std::process::id());
        // A pre-existing directory at the attempt's root name — with a
        // foreign sentinel inside — is never adopted and never deleted.
        let squatted = super::attempt_root_of(&prefix);
        harness_ok(std::fs::create_dir_all(&squatted), "the squatter directory");
        harness_ok(
            std::fs::write(squatted.join("foreign-sentinel"), b"not this allocation"),
            "sentinel",
        );
        match super::create_recorded_attempt_root(&mut store, &prefix) {
            Err(CheckError::CopyFailed { detail }) => assert!(
                detail.contains("never adopted"),
                "the refusal names the adoption refusal: {detail}"
            ),
            other => unreachable!("a pre-existing root name must refuse, got {other:?}"),
        }
        assert!(
            squatted.join("foreign-sentinel").exists(),
            "the foreign directory survives the refusal byte-for-byte"
        );
        assert!(
            !harness_ok(
                store.has_retained(&check_boundary_id(&prefix, "attempt.root")),
                "retained lookup"
            ),
            "no locator row is recorded for a refused creation"
        );
        // A symlink at the name is refused the same way and its target
        // survives.
        let link_name = format!("{prefix}-link");
        let symlinked = super::attempt_root_of(&link_name);
        harness_ok(
            std::os::unix::fs::symlink(&squatted, &symlinked),
            "the squatting symlink",
        );
        match super::create_recorded_attempt_root(&mut store, &link_name) {
            Err(CheckError::CopyFailed { .. }) => {}
            other => unreachable!("a symlinked root name must refuse, got {other:?}"),
        }
        assert!(
            symlinked
                .symlink_metadata()
                .is_ok_and(|meta| meta.file_type().is_symlink()),
            "the symlink survives the refusal"
        );
        // The fresh name allocates: private, recorded, removable by its
        // own record, and the name is reusable only after that removal.
        let fresh = format!("{prefix}-fresh");
        let allocated = harness_ok(
            super::create_recorded_attempt_root(&mut store, &fresh),
            "the fresh allocation",
        );
        assert!(
            {
                use std::os::unix::fs::PermissionsExt as _;
                harness_ok(
                    allocated.canonical_root.symlink_metadata(),
                    "allocated metadata",
                )
                .permissions()
                .mode()
                    & 0o777
                    == 0o700
            },
            "the allocated root is private to this process"
        );
        assert!(
            harness_ok(
                store.has_retained(&check_boundary_id(&fresh, "attempt.root")),
                "retained lookup"
            ),
            "the locator row names the allocation"
        );
        // What a sealed check leaves behind: a read-only nested tree and a
        // symlink aimed outside the root.
        let outside = root.join("outside-sentinel");
        harness_ok(std::fs::write(&outside, b"outside"), "outside sentinel");
        let nested = allocated.canonical_root.join("src/deep");
        harness_ok(std::fs::create_dir_all(&nested), "nested tree");
        harness_ok(
            std::fs::write(nested.join("sealed.txt"), b"sealed"),
            "sealed file",
        );
        harness_ok(
            std::os::unix::fs::symlink(&outside, allocated.canonical_root.join("escape")),
            "escape link",
        );
        {
            use std::os::unix::fs::PermissionsExt as _;
            for sealed in [nested, allocated.canonical_root.join("src")] {
                harness_ok(
                    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o555)),
                    "seal the nested tree",
                );
            }
        }
        // DEC-056 strict protection: no admitted platform primitive
        // binds a by-name child removal to the observed inode, so the
        // cleanup refuses BEFORE any destructive effect — the sealed
        // debris, its permissions, and the root's name all survive.
        let refusal = super::remove_recorded_attempt_root(
            &allocated.canonical_root,
            allocated.dev,
            allocated.ino,
        );
        match &refusal {
            super::RootRemoval::Refused(reason) => assert!(
                reason.contains("no admitted platform primitive"),
                "the refusal names the missing primitive: {reason}"
            ),
            other => unreachable!("a present root must refuse, got {other:?}"),
        }
        assert!(
            allocated.canonical_root.is_dir(),
            "the refused cleanup keeps the root and its name"
        );
        assert_eq!(
            harness_ok(
                std::fs::read(allocated.canonical_root.join("src/deep/sealed.txt")),
                "the sealed debris read"
            ),
            b"sealed",
            "no byte under the verified root was removed"
        );
        assert!(
            outside.exists(),
            "an outside target is never touched by a refusal"
        );
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = harness_ok(
                std::fs::metadata(allocated.canonical_root.join("src")),
                "sealed dir metadata",
            )
            .permissions()
            .mode();
            assert_eq!(
                mode & 0o777,
                0o555,
                "the refusal unseals nothing: no destructive effect runs"
            );
        }
        assert!(
            super::retirement_cause(&refusal).is_none(),
            "a refused cleanup retires no authority"
        );
        // The refusal is idempotent and the debris stays put.
        assert!(
            matches!(
                super::remove_recorded_attempt_root(
                    &allocated.canonical_root,
                    allocated.dev,
                    allocated.ino
                ),
                super::RootRemoval::Refused(_)
            ),
            "a repeated cleanup refuses again"
        );
        assert!(
            allocated
                .canonical_root
                .join("src/deep/sealed.txt")
                .is_file(),
            "the debris survives the repeated refusal"
        );
        // A name-reused directory at the root's name is refused by the
        // stale record's identity check. The harness unseals and clears
        // the debris first (a product cleanup cannot), so the reuser's
        // inode differs by construction.
        {
            use std::os::unix::fs::PermissionsExt as _;
            for sealed in [
                allocated.canonical_root.join("src/deep"),
                allocated.canonical_root.join("src"),
            ] {
                harness_ok(
                    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700)),
                    "the harness unseals its own debris",
                );
            }
        }
        let reuser = root.join("reuser");
        harness_ok(std::fs::create_dir_all(&reuser), "the foreign reuser");
        harness_ok(
            std::fs::write(
                reuser.join("foreign-sentinel"),
                b"a later directory at the same name",
            ),
            "reuser sentinel",
        );
        harness_ok(
            std::fs::remove_dir_all(&allocated.canonical_root),
            "the test removes the debris shell itself",
        );
        harness_ok(
            std::fs::rename(&reuser, &allocated.canonical_root),
            "the reuser takes the recorded name",
        );
        assert!(
            matches!(
                super::remove_recorded_attempt_root(
                    &allocated.canonical_root,
                    allocated.dev,
                    allocated.ino
                ),
                super::RootRemoval::Refused(_)
            ),
            "a different directory at the recorded name is refused, never emptied"
        );
        assert!(
            allocated.canonical_root.join("foreign-sentinel").exists(),
            "the name-reusing directory survives"
        );
        // An absent root retires: nothing exists at the recorded name,
        // so the observation discharges the obligation without any
        // destructive effect.
        harness_ok(
            std::fs::remove_dir_all(&allocated.canonical_root),
            "the reuser goes",
        );
        let absent = super::remove_recorded_attempt_root(
            &allocated.canonical_root,
            allocated.dev,
            allocated.ino,
        );
        assert_eq!(absent, super::RootRemoval::Absent, "no name, no debris");
        assert!(
            super::retirement_cause(&absent).is_some(),
            "an absent root retires its cleanup authority"
        );
        drop(std::fs::remove_dir_all(&squatted));
        drop(std::fs::remove_file(&symlinked));
    }

    #[test]
    fn pending_receipt_faults_refuse_pre_claim_through_execute_check() {
        // The restored per-fault discriminators: each live-pending
        // receipt fault drives `execute_check` itself and refuses at the
        // pre-claim gate — attempt planned, no root, no settlement row.
        let (root_dir, mut store, _session, task) = bound_store("pending-receipt-faults");
        let root = root_dir.path();
        let mut policy = crate::policy::Policy::default();
        let (check, exec_grant, cargo) = executable_check_parts(root, &task, &mut policy, 1);
        let forged = root.join("forged-registry/cache");
        harness_ok(std::fs::create_dir_all(&forged), "the forged cache root");
        let refuse =
            |policy: &mut crate::policy::Policy,
             store: &mut crate::state::TaskStore,
             mutation: &dyn Fn(&mut crate::policy::Policy, &crate::policy::DependencyReceipt),
             what: &str| {
                let mut admission =
                    mint_executable_admission(store, policy, &task, &check, &exec_grant, &cargo);
                harness_ok(
                    policy.issue_check_dependencies(store, &mut admission),
                    "the pair issues",
                );
                mutation(policy, admission.receipt().expect("the issued receipt"));
                let outcome = {
                    let mut worker = NoWorker;
                    let mut executor = super::Executor::new(policy, store, &mut worker);
                    executor.execute_check(
                        &mut admission,
                        &check,
                        &std::sync::atomic::AtomicBool::new(false),
                    )
                };
                match outcome {
                    Err(super::ExecutorError::Check(CheckError::DependencyGrant { detail })) => {
                        assert!(
                            !detail.is_empty(),
                            "{what}: the refusal carries its typed cause"
                        );
                    }
                    other => unreachable!("{what} must refuse at admit.dep, got {other:?}"),
                }
                assert_eq!(
                    harness_ok(
                        store.attempt_state(admission.bound_attempt_id()),
                        "attempt state"
                    ),
                    Some("planned".to_string()),
                    "{what}: the attempt stays planned"
                );
                assert!(
                    !super::attempt_root_of(admission.bound_attempt_id()).exists(),
                    "{what}: no attempt root exists"
                );
            };
        refuse(
            &mut policy,
            &mut store,
            &|policy, receipt| {
                policy.rebind_check_root_for_test(
                    receipt,
                    crate::policy::CheckRootHalf::Cache,
                    forged.clone(),
                );
            },
            "an aliased cache root",
        );
        refuse(
            &mut policy,
            &mut store,
            &|policy, receipt| {
                policy.rebind_check_root_for_test(
                    receipt,
                    crate::policy::CheckRootHalf::Index,
                    root.join("home"),
                );
            },
            "a wide index root",
        );
        refuse(
            &mut policy,
            &mut store,
            &|policy, receipt| {
                policy.revoke_check_half_for_test(receipt, crate::policy::CheckRootHalf::Cache);
            },
            "a revoked cache half",
        );
        refuse(
            &mut policy,
            &mut store,
            &|policy, receipt| {
                policy.revoke_check_half_for_test(receipt, crate::policy::CheckRootHalf::Index);
            },
            "a revoked index half",
        );
    }

    /// The validated base config every off-context test appends its
    /// `[workflow]` override to.
    const OFF_BASE_CONFIG: &str = "config_version = 1\n\
         [connections.primary]\n\
         kind = \"api_key\"\n\
         endpoint = \"https://api.openai.com/v1\"\n\
         credential_ref = \"keyring:primary\"\n\
         [models.defaults]\n\
         model = { mode = \"auto\" }\n\
         effort = { mode = \"auto\" }\n\
         fallback = { mode = \"auto\" }\n";

    #[test]
    fn off_handoff_reconsult_refuses_stale_toggled_and_unknown_contexts() {
        let off_toml = format!("{OFF_BASE_CONFIG}[workflow]\nenabled = false\n");
        let off_config = harness_ok(
            crate::config::resolve_effective(Some(&off_toml)),
            "the off config resolves",
        );
        let state = std::sync::Arc::new(super::WorkflowOffState::new(&off_config));
        let task = crate::contracts::TaskId("task-owner-context".to_string());
        let handoff = super::CheckHandoff::from_owner(
            &state,
            &task,
            std::sync::Arc::new(()),
            std::sync::Arc::new(()),
        );
        assert!(
            handoff.explicit_off(),
            "the owner derives the explicit off from the user source"
        );
        let verify = |owner: &super::WorkflowOffState| {
            super::verify_owner_context(
                owner,
                handoff.generation(),
                handoff.sources_digest(),
                handoff.explicit_off(),
            )
        };
        harness_ok(verify(&state), "the current context admits the handoff");

        // Stale: the config sources changed while still resolving an
        // explicit off — the owner moved its generation, so the
        // reconsult refuses instead of reading as off.
        let edited = harness_ok(
            crate::config::resolve_effective(Some(&format!("{off_toml}# edited\n"))),
            "the edited off config resolves",
        );
        state.refresh(&edited);
        match verify(&state) {
            Err(CheckError::SelectionMismatch { detail }) => assert!(
                detail.contains("moved"),
                "the stale refusal names the moved owner: {detail}"
            ),
            other => unreachable!("a stale off context must refuse, got {other:?}"),
        }

        // Returning to byte-identical off sources still moves the
        // generation: the older handoff is never resurrected.
        state.refresh(&off_config);
        match verify(&state) {
            Err(CheckError::SelectionMismatch { detail }) => assert!(
                detail.contains("moved"),
                "an identical return keeps the old generation dead: {detail}"
            ),
            other => unreachable!("an identical-off return must not resurrect, got {other:?}"),
        }

        // A forged digest at the live generation never matches the owner.
        let (generation, _, _) = state.current();
        match super::verify_owner_context(&state, generation, "forged-sources-digest", true) {
            Err(CheckError::SelectionMismatch { detail }) => assert!(
                detail.contains("stale"),
                "the forged digest refuses as stale: {detail}"
            ),
            other => unreachable!("a forged digest must refuse, got {other:?}"),
        }

        // Toggled: the workflow is enabled again — the bound explicit
        // off is no longer the owner's mode.
        let on_config = harness_ok(
            crate::config::resolve_effective(Some(&format!(
                "{OFF_BASE_CONFIG}[workflow]\nenabled = true\n"
            ))),
            "the on config resolves",
        );
        state.refresh(&on_config);
        let (generation, _, digest) = state.current();
        match super::verify_owner_context(&state, generation, &digest, true) {
            Err(CheckError::SelectionMismatch { detail }) => assert!(
                detail.contains("toggled"),
                "the toggled refusal names the vanished off mode: {detail}"
            ),
            other => unreachable!("a toggled off context must refuse, got {other:?}"),
        }

        // Unknown: a fresh owner that never observed an explicit off
        // refuses the off handoff — public config strings cannot
        // conjure the authority.
        let unknown = super::WorkflowOffState::new(&on_config);
        match verify(&unknown) {
            Err(CheckError::SelectionMismatch { detail }) => assert!(
                detail.contains("toggled"),
                "the unknown-context refusal names it: {detail}"
            ),
            other => unreachable!("an unknown context must refuse, got {other:?}"),
        }
    }

    #[test]
    fn custom_handoff_admits_without_selection_and_native_stays_native() {
        let (_root, mut store, session, _selected_task) = bound_store("custom-handoff");
        // A task with NO recorded plan selection: the discriminator the
        // Custom/Native split hangs on.
        let task = store
            .create_task(
                &session,
                "custom-command",
                "unit",
                "custom goal",
                (&[], &[]),
            )
            .expect("the selectionless task")
            .task_id;
        let mut policy = crate::policy::Policy::default();
        let off_config = crate::config::resolve_effective(Some(&format!(
            "{OFF_BASE_CONFIG}[workflow]\nenabled = false\n"
        )))
        .expect("the off config resolves");
        let off_state = std::sync::Arc::new(super::WorkflowOffState::new(&off_config));
        let handoff = super::CheckHandoff::from_owner(
            &off_state,
            &task,
            std::sync::Arc::clone(policy.identity()),
            std::sync::Arc::clone(store.identity()),
        );
        let cargo = PathBuf::from("/nonexistent/cargo");
        let exec_grant = policy.grant_classes(
            cargo.parent().expect("toolchain dir").to_path_buf(),
            vec![crate::contracts::EffectClass::Exec],
        );
        let project_grant_id = policy.grant_read(PathBuf::from("/nonexistent/project"));
        let check = super::ConfinedCheck {
            task_id: task.clone(),
            expected_selection_revision: 1,
            project_grant_id,
            project_root: PathBuf::from("/nonexistent/project"),
            manifest_rel: PathBuf::from("Cargo.toml"),
            cargo: cargo.clone(),
            cargo_home: PathBuf::from("/nonexistent/home"),
            target: super::CheckTarget::Integration("check".to_string()),
            harness_threads: 1,
            exact_test: "green_passes".to_string(),
            expected_phase: "candidate-review".to_string(),
            expected_assertion_identity: "green_passes".to_string(),
            expected_candidate_digest: "digest".to_string(),
        };
        // The task carries NO recorded selection: the Custom handoff
        // admits anyway (no native selection, no sentinel revision),
        // while the public Native admission refuses typed.
        {
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            let custom = executor
                .admit_check(
                    &task,
                    EffectRequest::Exec {
                        grant_id: exec_grant.clone(),
                        program: cargo.clone(),
                    },
                    crate::policy::PermissionMode::Yolo,
                    &check,
                    &handoff,
                )
                .expect("the custom handoff admits without a selection");
            match custom.context() {
                super::CheckContext::Custom { sources_digest, .. } => assert_eq!(
                    sources_digest, &off_config.sources_digest,
                    "the custom context binds the config owner's sources digest"
                ),
                other => unreachable!("the handoff mints a Custom context, got {other:?}"),
            }
            assert!(
                !custom.is_native(),
                "a handoff admission is Custom, never Native"
            );
        }
        {
            let native = native_handoff(&task, &policy, &store);
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            match executor.admit_check(
                &task,
                EffectRequest::Exec {
                    grant_id: exec_grant,
                    program: cargo,
                },
                crate::policy::PermissionMode::Yolo,
                &check,
                &native,
            ) {
                Err(super::ExecutorError::Check(CheckError::SelectionMismatch { .. })) => {}
                other => {
                    unreachable!(
                        "the public Native admission refuses without a selection, got {other:?}"
                    )
                }
            }
        }
    }

    #[test]
    fn close_refuses_a_moved_selection_without_confirming() {
        let (root_dir, mut store, _session, task) = bound_store("stale-close");
        let root = root_dir.path();
        let mut policy = crate::policy::Policy::default();
        let mut worker = NoWorker;
        let project = root.join("project");
        std::fs::create_dir_all(&project).expect("project dir");
        std::fs::write(project.join("Cargo.toml"), b"[package]\n").expect("manifest");
        let expected = workspace_digest(&project).expect("project digest");
        let base = |revision: u64| super::ConfinedCheck {
            task_id: task.clone(),
            expected_selection_revision: revision,
            project_grant_id: "grant-unit".to_string(),
            project_root: project.clone(),
            manifest_rel: PathBuf::from("Cargo.toml"),
            cargo: PathBuf::from("/nonexistent/cargo"),
            cargo_home: PathBuf::from("/nonexistent/home"),
            target: super::CheckTarget::Integration("check".to_string()),
            harness_threads: 1,
            exact_test: "green_passes".to_string(),
            expected_phase: "candidate-review".to_string(),
            expected_assertion_identity: "green_passes".to_string(),
            expected_candidate_digest: expected.clone(),
        };
        let run = super::CheckRun {
            attempt_root: None,
            exit_code: Some(0),
            signal: None,
            stdout: BoundedCapture::empty(),
            stderr: BoundedCapture::empty(),
            project_digest: expected.clone(),
            vendor_digest: None,
            check_digest_v1: "v1".to_string(),
            check_digest_v2: "v2".to_string(),
            summary: None,
            cleanup: super::CleanupClaim::MacosBestEffort,
        };
        let admitted = binding_admitted(&task);
        // The current revision (1) closes: selection, inventory, and
        // result rows land — and DEC-047 keeps the verdict unclosed, so
        // no close.confirmed row ever exists.
        {
            let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            executor
                .close_check_rows(&admitted, &base(1), &run, true, None)
                .expect("the current revision closes");
        }
        for site in ["close.selection", "close.inventory", "close.result"] {
            assert!(
                store
                    .has_retained(&check_boundary_id("attempt-unit", site))
                    .expect("retained lookup"),
                "the {site} row exists for the closing attempt"
            );
        }
        assert!(
            !store
                .has_retained(&check_boundary_id("attempt-unit", "close.confirmed"))
                .expect("retained lookup"),
            "the executor never decides RED/GREEN: no close.confirmed row"
        );
        // A check pinned to a revision the store no longer holds refuses
        // typed BEFORE any close row — no close.result ever follows.
        let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
        match executor.close_check_rows(&admitted, &base(2), &run, true, None) {
            Err(error) => assert_eq!(
                error.site(),
                "close.selection",
                "a moved selection refuses the close"
            ),
            Ok(()) => unreachable!("a moved selection must refuse the close"),
        }
    }

    /// A mid-phase cancellation must stop and reap the running child,
    /// not merely return: the observe loop's stop routes through
    /// `terminate_confined_child`, and the vendor-phase mapping keeps
    /// its typed seam.
    #[test]
    fn check_phase_cancellation_stops_and_reaps_the_child() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let cancel = std::sync::atomic::AtomicBool::new(true);
        match observe_check_phase(
            &mut child,
            None,
            None,
            &cancel,
            Instant::now() + CHECK_PHASE_DEADLINE,
        ) {
            Err(stop @ PhaseStop::Cancelled) => assert!(
                matches!(map_vendor_stop(stop), CheckError::VendorCancel { .. }),
                "a cancelled vendor phase keeps its typed seam"
            ),
            Err(_) | Ok(_) => unreachable!("a cancelled phase stops cancelled"),
        }
        // The stop already reaped the leader: wait returns at once with
        // the kill status, never a clean 30-second sleep exit.
        let status = child.wait()?;
        assert!(
            status.code().is_none(),
            "the stopped child was killed, not exited: {status}"
        );
        Ok(())
    }

    /// The wall deadline stops a running phase the same way: the
    /// already-elapsed deadline fires on the first loop step, the child
    /// is killed and reaped, and the test-phase mapping keeps its typed
    /// seam. (The full-path deadline leg is CHECK_PHASE_DEADLINE = 600 s
    /// — impractical to cross for real; the stop, terminate, and typed
    /// mapping it shares with cancellation are what this pins.)
    #[test]
    fn check_phase_deadline_stops_and_reaps_the_child() -> Result<(), Box<dyn std::error::Error>> {
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let cancel = std::sync::atomic::AtomicBool::new(false);
        match observe_check_phase(
            &mut child,
            None,
            None,
            &cancel,
            Instant::now() - CHECK_PHASE_DEADLINE,
        ) {
            Err(stop @ PhaseStop::Deadline) => assert!(
                matches!(map_test_stop(stop), CheckError::TestDeadline { .. }),
                "a deadline-stopped test phase keeps its typed seam"
            ),
            Err(_) | Ok(_) => unreachable!("an expired deadline stops the phase"),
        }
        let status = child.wait()?;
        assert!(
            status.code().is_none(),
            "the stopped child was killed, not exited: {status}"
        );
        Ok(())
    }

    #[test]
    fn binding_refuses_a_mutated_exact_test_selector() {
        let (root_dir, mut store, _session, task) = bound_store("binding-exact-test");
        let root = root_dir.path();
        let mut policy = crate::policy::Policy::default();
        let (check, exec_grant, cargo) = executable_check_parts(root, &task, &mut policy, 1);
        let mut admission =
            mint_executable_admission(&mut store, &mut policy, &task, &check, &exec_grant, &cargo);
        let attempt = admission.bound_attempt_id().to_string();
        // The option-shaped mutation: the same binding with a different
        // exact test name — a re-presentation must refuse at
        // `admit.binding`, spend its own admission, and release only
        // its own allocation while the legitimate attempt stays
        // planned with no root, claim, copied byte, or spawn.
        let mut mutated = check.clone();
        mutated.exact_test = "other_test".to_string();
        {
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            match executor.execute_check(
                &mut admission,
                &mutated,
                &std::sync::atomic::AtomicBool::new(false),
            ) {
                Err(super::ExecutorError::Check(error)) => assert_eq!(
                    error.site(),
                    "admit.binding",
                    "a mutated exact test refuses at the binding seam"
                ),
                other => unreachable!("a mutated selector must refuse typed, got {other:?}"),
            }
        }
        assert_eq!(
            admission.phase(),
            super::CheckPhase::Spent,
            "the refused presentation spends its own admission"
        );
        assert_eq!(
            harness_ok(store.attempt_state(&attempt), "attempt state"),
            Some("planned".to_string()),
            "the binding refusal never claims the attempt"
        );
        assert!(
            !super::attempt_root_of(&attempt).exists(),
            "the binding refusal creates no attempt root"
        );
    }

    #[test]
    fn admit_check_refuses_a_toggled_owner_before_planning() {
        // Native leg: the handoff minted over the enabled owner, the
        // workflow toggled off before admit_check — no admission, no
        // planned attempt, no grant may result.
        let (root_dir, mut store, _session, task) = bound_store("admit-toggled-owner");
        let root = root_dir.path();
        let mut policy = crate::policy::Policy::default();
        let (check, exec_grant, cargo) = executable_check_parts(root, &task, &mut policy, 1);
        let effective = harness_ok(crate::config::resolve_effective(None), "default config");
        let state = std::sync::Arc::new(super::WorkflowOffState::new(&effective));
        let handoff = super::CheckHandoff::from_owner(
            &state,
            &task,
            std::sync::Arc::clone(policy.identity()),
            std::sync::Arc::clone(store.identity()),
        );
        let off_toml = format!("{OFF_BASE_CONFIG}[workflow]\nenabled = false\n");
        let off_config = harness_ok(
            crate::config::resolve_effective(Some(&off_toml)),
            "off config",
        );
        state.refresh(&off_config);
        {
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            match executor.admit_check(
                &task,
                EffectRequest::Exec {
                    grant_id: exec_grant,
                    program: cargo,
                },
                crate::policy::PermissionMode::Yolo,
                &check,
                &handoff,
            ) {
                Err(super::ExecutorError::Check(CheckError::SelectionMismatch { detail })) => {
                    assert!(
                        detail.contains("moved") || detail.contains("toggled"),
                        "the refusal names the moved owner context: {detail}"
                    );
                }
                other => unreachable!("a toggled owner must refuse admit_check, got {other:?}"),
            }
        }

        // Custom leg: an explicit-off handoff whose workflow was
        // enabled again refuses the same way — the mint never happens.
        let (root_dir, mut store, _session, task) = bound_store("admit-toggled-custom");
        let root = root_dir.path();
        let mut policy = crate::policy::Policy::default();
        let (check, exec_grant, cargo) = executable_check_parts(root, &task, &mut policy, 1);
        let state = std::sync::Arc::new(super::WorkflowOffState::new(&off_config));
        let handoff = super::CheckHandoff::from_owner(
            &state,
            &task,
            std::sync::Arc::clone(policy.identity()),
            std::sync::Arc::clone(store.identity()),
        );
        assert!(
            handoff.explicit_off(),
            "the off owner derives the explicit off"
        );
        state.refresh(&effective);
        {
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            match executor.admit_check(
                &task,
                EffectRequest::Exec {
                    grant_id: exec_grant,
                    program: cargo,
                },
                crate::policy::PermissionMode::Yolo,
                &check,
                &handoff,
            ) {
                Err(super::ExecutorError::Check(CheckError::SelectionMismatch { detail })) => {
                    assert!(
                        detail.contains("moved") || detail.contains("toggled"),
                        "the custom refusal names the moved owner context: {detail}"
                    );
                }
                other => unreachable!("a toggled custom owner must refuse, got {other:?}"),
            }
        }
    }

    #[test]
    fn phase_reconsult_keeps_the_failing_category_site() {
        let (root_dir, mut store, _session, task) = bound_store("phase-category-site");
        let root = root_dir.path();
        let mut policy = crate::policy::Policy::default();
        let (check, exec_grant, cargo) = executable_check_parts(root, &task, &mut policy, 1);
        let admission =
            mint_executable_admission(&mut store, &mut policy, &task, &check, &exec_grant, &cargo);
        let admitted = admission.admitted().clone();
        let (state, generation, digest, off) = admission.owner_view();
        let owner = (state, generation, digest, off);
        // A denied project read at the test reconsult keeps the read
        // category under the test prefix.
        let denied_project =
            harness_ok(check.project_root.canonicalize(), "canonical project root");
        harness_ok(
            policy.enroll_deny(denied_project),
            "enroll the project deny",
        );
        {
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            match executor.reconsult_phase_grants(&admitted, &check, None, true, owner, "test") {
                Err(error) => assert_eq!(
                    error.site(),
                    "test.admit.read",
                    "a denied project read keeps its category at the test seam"
                ),
                Ok(()) => unreachable!("a denied project read must refuse the reconsult"),
            }
        }
        // A revoked Exec grant at the vendor reconsult keeps the exec
        // category under the phase prefix — never aliased to dep — and
        // the exec check outranks the read check.
        policy.revoke(&exec_grant);
        {
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            match executor.reconsult_phase_grants(&admitted, &check, None, true, owner, "vendor") {
                Err(error) => {
                    assert_eq!(
                        error.site(),
                        "vendor.admit.exec",
                        "a revoked exec keeps its category at the vendor seam"
                    );
                    assert_eq!(
                        super::ExecutorError::Check(error).error_code(),
                        crate::contracts::ErrorCode::Denied,
                        "a phase admission refusal is a denied effect"
                    );
                }
                Ok(()) => unreachable!("a revoked exec grant must refuse the reconsult"),
            }
        }
    }

    #[test]
    fn an_enrolled_deny_on_the_pre_claim_lockfile_read_refuses() {
        let (root_dir, mut store, _session, task) = bound_store("deny-lock-read");
        let root = root_dir.path();
        let mut policy = crate::policy::Policy::default();
        let (check, exec_grant, cargo) = executable_check_parts(root, &task, &mut policy, 1);
        harness_ok(
            std::fs::write(check.project_root.join("Cargo.lock"), b"version = 3\n"),
            "the lockfile fixture",
        );
        let denied_lock = harness_ok(
            check.project_root.join("Cargo.lock").canonicalize(),
            "canonical lock path",
        );
        policy
            .enroll_deny(denied_lock)
            .map_err(|error| unreachable!("enroll the lock deny: {error:?}"))
            .ok();
        let mut admission =
            mint_executable_admission(&mut store, &mut policy, &task, &check, &exec_grant, &cargo);
        {
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            match executor.execute_check(
                &mut admission,
                &check,
                &std::sync::atomic::AtomicBool::new(false),
            ) {
                Err(super::ExecutorError::Check(error)) => assert_eq!(
                    error.site(),
                    "admit.read",
                    "a denied lockfile descendant refuses the pre-claim read"
                ),
                other => unreachable!("a denied lockfile must refuse pre-claim, got {other:?}"),
            }
        }
        assert_eq!(
            harness_ok(
                store.attempt_state(admission.bound_attempt_id()),
                "attempt state"
            ),
            Some("planned".to_string()),
            "the denied read never claims the attempt"
        );
    }

    #[test]
    fn an_enrolled_deny_on_a_project_descendant_refuses_before_hash_and_copy() {
        let root_dir = scratch_tree("deny-descendant");
        let root = root_dir.path();
        let project = root.join("project");
        harness_ok(
            std::fs::create_dir_all(project.join("secrets")),
            "secrets dir",
        );
        harness_ok(std::fs::create_dir_all(project.join("src")), "src dir");
        harness_ok(
            std::fs::write(project.join("src/lib.rs"), b"pub fn f() {}\n"),
            "source",
        );
        harness_ok(
            std::fs::write(project.join("secrets/keys"), b"host-secret-bytes"),
            "the denied descendant",
        );
        let denied_dir = harness_ok(project.join("secrets").canonicalize(), "canonical secrets");
        let mut policy = crate::policy::Policy::default();
        harness_ok(
            policy.enroll_deny(&denied_dir),
            "enroll the descendant deny",
        );
        // The walk consults the live policy BEFORE it touches the denied
        // entry: the root grant never reads a denied child, and the
        // refusal names the denied entry — not a hash or a copy error.
        match super::inventory_under(&project, &|path| policy.covers(path)) {
            Err(super::InventoryError::Denied { rel }) => {
                assert_eq!(rel, PathBuf::from("secrets"), "the denied entry is named");
            }
            other => unreachable!("a denied descendant must refuse the walk, got {other:?}"),
        }
        // The unguarded walk (the executor's own private trees) still
        // inventories the same tree: the guard, not the tree, refuses.
        let tree = harness_ok(inventory(&project), "the unguarded inventory");
        // The copy re-consults the live policy on every source read: a
        // deny enrolled AFTER the walk admitted the tree still refuses
        // before any denied byte is read or written.
        let dest = root.join("copy");
        harness_ok(std::fs::create_dir_all(&dest), "copy destination");
        match super::copy_inventory(&project, &tree, &dest, &|path| policy.covers(path)) {
            Err(error) => assert_eq!(
                error.site(),
                "admit.read",
                "a denied source read refuses at the read seam"
            ),
            Ok(digest) => unreachable!("a denied descendant must not copy, got {digest}"),
        }
        assert!(
            !dest.join("secrets/keys").exists(),
            "no denied byte reached the destination"
        );
    }

    #[test]
    fn cargo_home_inside_an_effective_sandbox_root_refuses() {
        let (root_dir, mut store, _session, task) = bound_store("cargo-home-overlap");
        let root = root_dir.path();
        let mut policy = crate::policy::Policy::default();
        // A real on-disk toolchain shape (cargo with a sibling rustc) so
        // the effective-root derivation resolves it; the cargo home
        // squats on the toolchain root itself — an effective
        // read/execute root of both platform profiles.
        let bin = root.join("toolchain/bin");
        harness_ok(std::fs::create_dir_all(&bin), "toolchain bin");
        harness_ok(std::fs::write(bin.join("cargo"), b""), "cargo");
        harness_ok(std::fs::write(bin.join("rustc"), b""), "rustc");
        let cargo = bin.join("cargo");
        let project = root.join("project");
        harness_ok(std::fs::create_dir_all(&project), "project root");
        let exec_grant = policy.grant_classes(bin, vec![crate::contracts::EffectClass::Exec]);
        let project_grant_id = policy.grant_read(project.clone());
        let check = super::ConfinedCheck {
            task_id: task.clone(),
            expected_selection_revision: 1,
            project_grant_id,
            project_root: project,
            manifest_rel: PathBuf::from("Cargo.toml"),
            cargo: cargo.clone(),
            cargo_home: root.join("toolchain"),
            target: super::CheckTarget::Integration("check".to_string()),
            harness_threads: 1,
            exact_test: "green_passes".to_string(),
            expected_phase: "candidate-review".to_string(),
            expected_assertion_identity: "green_passes".to_string(),
            expected_candidate_digest: "digest".to_string(),
        };
        let admitted = super::AdmittedEffect {
            task_id: task,
            attempt_id: "attempt-overlap".to_string(),
            request: EffectRequest::Exec {
                grant_id: exec_grant,
                program: cargo,
            },
            mode: crate::policy::PermissionMode::Yolo,
            expected_identity: None,
            scope_root: root.to_path_buf(),
        };
        {
            let mut worker = NoWorker;
            let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
            match executor.verify_check_admission(&admitted, &check, true) {
                Err(error) => assert_eq!(
                    error.site(),
                    "admit.target",
                    "a cargo home inside an effective sandbox root refuses the layout"
                ),
                Ok(()) => unreachable!("an overlapping cargo home must refuse the layout"),
            }
        }
    }

    /// Seeds one fake registry home with a lockfile-named dependency's
    /// descriptor, archive, and sparse-index entry; returns the three
    /// host leaf paths.
    fn seed_dependency_leaves(
        home: &Path,
        regdir: &str,
        dep: &LockDependency,
        archive: &[u8],
    ) -> Result<(PathBuf, PathBuf, PathBuf), Box<dyn std::error::Error>> {
        let index = home.join("registry/index").join(regdir);
        let cache = home.join("registry/cache").join(regdir);
        let config = index.join("config.json");
        std::fs::write(&config, b"{\"dl\":\"offline\"}")?;
        let archive_path = cache.join(format!("{}-{}.crate", dep.name, dep.version));
        std::fs::write(&archive_path, archive)?;
        let mut entry = index.join(".cache");
        for shard in super::index_entry_shards(&dep.name) {
            entry = entry.join(shard);
        }
        if let Some(parent) = entry.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&entry, b"{\"name\":\"cfg-if\"}\n")?;
        Ok((config, archive_path, entry))
    }

    #[test]
    fn an_enrolled_deny_on_each_dependency_leaf_refuses_before_its_read()
    -> Result<(), Box<dyn std::error::Error>> {
        let regdir = "index.crates.io-6f17d22bba15001f";
        let archive = b"synthetic crate archive".to_vec();
        let dep = LockDependency {
            name: "cfg-if".to_string(),
            version: "1.0.0".to_string(),
            checksum: super::hex(&<sha2::Sha256 as sha2::Digest>::digest(&archive)),
        };
        for leg in ["control", "config", "archive", "entry"] {
            let (holder_dir, home, anchored, admission, mut policy, _store, cancel, _staged) =
                staged_index_fixture(&format!("leaf-deny-{leg}"));
            let holder = holder_dir.path();
            // On the archive leg the host bytes disagree with the lock
            // checksum: a read would surface the checksum refusal, so
            // only a deny consulted BEFORE the read can win.
            let on_disk: &[u8] = if leg == "archive" {
                b"tampered"
            } else {
                &archive
            };
            let (config, archive_path, entry) =
                seed_dependency_leaves(&home, regdir, &dep, on_disk)?;
            match leg {
                "config" => policy.enroll_deny(&config)?,
                "archive" => policy.enroll_deny(&archive_path)?,
                "entry" => policy.enroll_deny(&entry)?,
                _ => {}
            }
            let staged_home = holder.join("staged-home");
            let receipt = admission.receipt().ok_or("the pair receipt")?;
            let result = super::stage_dependencies(
                std::slice::from_ref(&dep),
                regdir,
                &anchored,
                (&home, &staged_home),
                receipt,
                &mut policy,
                &cancel,
            );
            let staged_index = staged_home.join("registry/index").join(regdir);
            let staged_archive = staged_home
                .join("registry/cache")
                .join(regdir)
                .join("cfg-if-1.0.0.crate");
            let staged_entry = staged_index.join(".cache/cf/g-/cfg-if");
            match leg {
                "control" => {
                    assert!(result.is_ok(), "the seeded home stages cleanly: {result:?}");
                    assert!(staged_index.join("config.json").is_file());
                    assert!(staged_archive.is_file());
                    assert!(staged_entry.is_file());
                }
                _ => {
                    match result {
                        Err(error) => assert_eq!(
                            error.site(),
                            "dep.cache_denied",
                            "{leg}: the deny refuses before the leaf read"
                        ),
                        Ok(bytes) => {
                            unreachable!("{leg}: a denied leaf must not stage, staged {bytes}")
                        }
                    }
                    // Nothing at or past the denied leaf reached the
                    // staged tree.
                    assert_eq!(staged_index.join("config.json").is_file(), leg != "config");
                    assert_eq!(staged_archive.is_file(), leg == "entry");
                    assert!(!staged_entry.exists(), "{leg}: no index entry staged");
                }
            }
        }
        Ok(())
    }

    #[test]
    fn phase_admission_sites_are_a_finite_injective_map_with_decoded_retained_bodies()
    -> Result<(), Box<dyn std::error::Error>> {
        fn category_error(category: &str, detail: String) -> Option<CheckError> {
            Some(match category {
                "admit.exec" => CheckError::ExecGrant { detail },
                "admit.read" => CheckError::ProjectReadGrant { detail },
                "admit.dep" => CheckError::DependencyGrant { detail },
                "admit.selection" => CheckError::SelectionMismatch { detail },
                "admit.target" => CheckError::TargetLayout { detail },
                _ => return None,
            })
        }
        let expected = [
            ("admit.exec", "vendor", "vendor.admit.exec"),
            ("admit.exec", "test", "test.admit.exec"),
            ("admit.read", "vendor", "vendor.admit.read"),
            ("admit.read", "test", "test.admit.read"),
            ("admit.dep", "vendor", "vendor.admit.dep"),
            ("admit.dep", "test", "test.admit.dep"),
            ("admit.selection", "vendor", "vendor.admit.selection"),
            ("admit.selection", "test", "test.admit.selection"),
            ("admit.target", "vendor", "vendor.admit.target"),
            ("admit.target", "test", "test.admit.target"),
        ];
        let (_root, mut store, _session, task) = bound_store("phase-site-map");
        let mut policy = crate::policy::Policy::default();
        let mut causes = Vec::new();
        for (category, phase, site) in expected {
            let detail = format!("{category}@{phase}");
            let error = category_error(category, detail.clone())
                .ok_or("every mapped category has a constructor")?;
            let wrapped = super::phase_admit_error(error, phase);
            assert_eq!(wrapped.site(), site, "{category} at {phase}");
            assert_eq!(
                matches!(wrapped, CheckError::TestAdmit { .. }),
                phase == "test",
                "{category} at {phase} keeps the phase's own variant"
            );
            let attempt =
                store.plan_attempt(&task, crate::contracts::EffectClass::Exec, "phase site map")?;
            let admitted = super::AdmittedEffect {
                attempt_id: attempt.clone(),
                ..binding_admitted(&task)
            };
            {
                let mut worker = NoWorker;
                let mut executor = super::Executor::new(&mut policy, &mut store, &mut worker);
                match executor.settle_check_failure(&admitted, wrapped) {
                    super::ExecutorError::Check(settled) => {
                        assert_eq!(settled.site(), site, "settlement keeps the site");
                    }
                    other => unreachable!("settlement returns the typed check error: {other:?}"),
                }
            }
            // The decoded retained body: exactly one terminal row at the
            // phase-specific boundary, carrying this pair's own detail.
            let rows = store.retained_check_rows(&attempt)?;
            assert_eq!(rows.len(), 1, "{category} at {phase}: one row: {rows:?}");
            assert_eq!(rows[0].boundary_id, check_boundary_id(&attempt, site));
            assert_eq!(
                rows[0].stage,
                crate::verification::RetainedStage::Terminal,
                "{category} at {phase}: a terminal row"
            );
            assert_eq!(rows[0].cause, format!("{site}: {detail}"));
            causes.push(rows[0].cause.clone());
        }
        // Injective and finite: ten distinct sites, none aliasing a plain
        // category, and every other site keeps its own variant untouched.
        let mut sites: Vec<&str> = expected.iter().map(|(_, _, site)| *site).collect();
        sites.sort_unstable();
        sites.dedup();
        assert_eq!(sites.len(), 10, "the ten phase sites are pairwise distinct");
        causes.sort_unstable();
        causes.dedup();
        assert_eq!(
            causes.len(),
            10,
            "the ten retained bodies are pairwise distinct"
        );
        for plain in [
            "admit.exec",
            "admit.read",
            "admit.dep",
            "admit.selection",
            "admit.target",
        ] {
            assert!(
                !sites.contains(&plain),
                "{plain} never aliases a phase site"
            );
        }
        for foreign in [
            "admit.claim",
            "dep.cache_denied",
            "vendor.cancel",
            "snapshot.copy",
        ] {
            assert_eq!(super::phase_admit_site(foreign, "vendor"), None);
            assert_eq!(super::phase_admit_site(foreign, "test"), None);
        }
        let untouched = super::phase_admit_error(
            CheckError::CacheDenied {
                detail: "x".to_string(),
            },
            "vendor",
        );
        assert_eq!(untouched.site(), "dep.cache_denied");
        assert!(matches!(untouched, CheckError::CacheDenied { .. }));

        Ok(())
    }

    #[test]
    fn the_shared_deadline_expires_before_each_phase_and_never_resets_for_phase_b() {
        let Some(expired) = Instant::now().checked_sub(std::time::Duration::from_secs(1)) else {
            unreachable!("the monotonic clock is older than one second");
        };
        // Expiry before the first effect: each phase refuses typed.
        match super::phase_deadline_check(expired, "vendor") {
            Err(error) => {
                assert_eq!(error.site(), "vendor.deadline");
                assert!(matches!(error, CheckError::VendorDeadline { .. }));
            }
            Ok(()) => unreachable!("an expired deadline must refuse phase A"),
        }
        match super::phase_deadline_check(expired, "test") {
            Err(error) => {
                assert_eq!(error.site(), "test.deadline");
                assert!(matches!(error, CheckError::TestDeadline { .. }));
            }
            Ok(()) => unreachable!("an expired deadline must refuse phase B"),
        }
        // ONE Instant spans both phases: phase A passes inside the
        // budget, and once the same Instant passes, phase B refuses —
        // it never receives a fresh full budget.
        let shared = Instant::now() + std::time::Duration::from_millis(30);
        assert!(super::phase_deadline_check(shared, "vendor").is_ok());
        while Instant::now() < shared {
            std::hint::spin_loop();
        }
        match super::phase_deadline_check(shared, "test") {
            Err(error) => assert_eq!(error.site(), "test.deadline"),
            Ok(()) => unreachable!("phase B must not reset the shared budget"),
        }
    }

    #[test]
    fn a_seal_failure_is_the_typed_vendor_seal_refusal_and_seals_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;
        let root_dir = scratch_tree("seal-failure");
        let root = root_dir.path();
        // An unreadable root: the seal inventory refuses typed.
        match super::seal_read_only(&root.join("absent")) {
            Err(error) => {
                assert_eq!(error.site(), "vendor.seal");
                assert!(
                    error.cause().contains("sealed inventory"),
                    "{}",
                    error.cause()
                );
            }
            Ok(()) => unreachable!("a missing tree cannot be sealed"),
        }
        // A socket inside the tree fails the bounded inventory closed
        // BEFORE any chmod: the regular file keeps its write bit.
        let tree = root.join("tree");
        std::fs::create_dir_all(&tree)?;
        std::fs::write(tree.join("member.rs"), b"fn member() {}\n")?;
        std::fs::set_permissions(
            tree.join("member.rs"),
            std::fs::Permissions::from_mode(0o600),
        )?;
        let listener = std::os::unix::net::UnixListener::bind(tree.join("special.sock"))?;
        match super::seal_read_only(&tree) {
            Err(error) => assert_eq!(error.site(), "vendor.seal"),
            Ok(()) => unreachable!("a tree with a special inode must not seal"),
        }
        assert_eq!(
            std::fs::metadata(tree.join("member.rs"))?
                .permissions()
                .mode()
                & 0o222,
            0o200,
            "a refused seal leaves the member writable, never half-sealed"
        );
        drop(listener);
        // Control: a clean tree seals read-only.
        let clean = root.join("clean");
        std::fs::create_dir_all(&clean)?;
        std::fs::write(clean.join("member.rs"), b"fn member() {}\n")?;
        super::seal_read_only(&clean)?;
        assert_eq!(
            std::fs::metadata(clean.join("member.rs"))?
                .permissions()
                .mode()
                & 0o222,
            0,
            "a clean tree drops every write bit"
        );
        std::fs::set_permissions(&clean, std::fs::Permissions::from_mode(0o755))?;

        Ok(())
    }

    #[test]
    fn a_source_swapped_after_the_inventory_never_follows_or_copies()
    -> Result<(), Box<dyn std::error::Error>> {
        let root_dir = scratch_tree("copy-crossing");
        let root = root_dir.path();
        let project = root.join("project");
        std::fs::create_dir_all(project.join("src"))?;
        let member = project.join("src/lib.rs");
        std::fs::write(&member, b"alpha-bytes")?;
        let secret = root.join("outside-secret");
        std::fs::write(&secret, b"host-secret-bytes")?;
        let tree = inventory(&project)?;
        let mut crossings = 0;
        // Crossing 1: same-length bytes change between the inventory and
        // the copy — the source digest check refuses before any write.
        std::fs::write(&member, b"omega-bytes")?;
        // Crossing 2 is prepared per leg below; each leg copies into its
        // own destination so a prior leg never masks the next.
        for leg in ["changed", "symlink", "socket"] {
            if leg == "symlink" {
                std::fs::remove_file(&member)?;
                std::os::unix::fs::symlink(&secret, &member)?;
            }
            let mut _listener = None;
            if leg == "socket" {
                std::fs::remove_file(&member)?;
                _listener = Some(std::os::unix::net::UnixListener::bind(&member)?);
            }
            let dest = root.join(format!("copy-{leg}"));
            std::fs::create_dir_all(&dest)?;
            match super::copy_inventory(&project, &tree, &dest, &|_| false) {
                Err(error) => {
                    assert_eq!(error.site(), "snapshot.copy", "{leg}");
                    crossings += 1;
                }
                Ok(digest) => unreachable!("{leg}: a swapped source must not copy, got {digest}"),
            }
            assert!(
                !dest.join("src/lib.rs").exists(),
                "{leg}: no destination byte exists for the swapped member"
            );
        }
        assert_eq!(crossings, 3, "every crossing refused");

        Ok(())
    }
}

/// The in-crate twins of the closed-surface doctests: the same
/// expressions over `crate::` paths must compile, so each doctest's
/// failure is attributable to visibility only.
#[cfg(test)]
mod closed_surface_twins {
    use super::{Executor, ReadWorker};
    use crate::commands::Runtime;
    use crate::policy::Policy;
    use crate::resources::ReadFlights;
    use crate::state::TaskStore;

    fn policy_borrow(rt: &mut Runtime) {
        let e = rt.executor();
        let _p: &mut Policy = &mut *e.policy;
    }

    fn store_swap(rt: &mut Runtime, mut foreign: TaskStore) {
        let e = rt.executor();
        std::mem::swap(&mut *e.store, &mut foreign);
    }

    fn worker_borrow(rt: &mut Runtime) {
        let e = rt.executor();
        let _w = &mut *e.worker;
    }

    fn new_ctor(policy: &mut Policy, store: &mut TaskStore, worker: &mut dyn ReadWorker) {
        let _e = Executor::new(policy, store, worker);
    }

    fn flights_ctor(
        policy: &mut Policy,
        store: &mut TaskStore,
        worker: &mut dyn ReadWorker,
        flights: &mut ReadFlights,
    ) {
        let _e = Executor::with_flights(policy, store, worker, flights);
    }

    #[test]
    fn the_closed_executor_items_are_reachable_inside_the_crate() {
        let _: fn(&mut Runtime) = policy_borrow;
        let _: fn(&mut Runtime, TaskStore) = store_swap;
        let _: fn(&mut Runtime) = worker_borrow;
        let _: fn(&mut Policy, &mut TaskStore, &mut dyn ReadWorker) = new_ctor;
        let _: fn(&mut Policy, &mut TaskStore, &mut dyn ReadWorker, &mut ReadFlights) =
            flights_ctor;
    }
}
