//! Effect executor: admission, pre-open policy checks, and opened-fd identity
//! checks before effects. Ordinary write/exec/egress effects fail
//! closed; managed writes use the explicit checked-fd path.

pub mod macos;

use crate::contracts::{EffectClass, ErrorCode, TaskId};
use crate::policy::{
    AdmissionContext, ModeDecision, PermissionMode, Policy, PolicyError, preapproval_scope,
};
use crate::state::{StoreError, TaskStore};
use std::path::{Path, PathBuf};

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
    Read { bytes: Vec<u8>, digest: String },
    Denied { reason: String },
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
                WorkerError::SandboxSpawnFailed { .. } | WorkerError::SandboxUnavailable { .. },
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

pub struct Executor<'a> {
    pub policy: &'a mut Policy,
    pub store: &'a mut TaskStore,
    pub worker: &'a mut dyn ReadWorker,
}

/// Assembles the DEC-014 decision inputs at an admit call site. The only
/// persisted input is preapproval (`TaskStore::is_preapproved`), keyed per
/// effect class so a write consent never admits another class; the mode
/// carrier arrives with the Settings surface, so the interim mode is the
/// `manual` default (DEC-015). Inputs that cannot yet be observed at an
/// admit stay conservative rather than granting.
///
/// # Errors
/// Returns [`ExecutorError::Store`] when the preapproval lookup fails and
/// [`ExecutorError::Worker`] ([`WorkerError::OutsideScope`]) when the
/// canonicalized target lies outside the canonicalized grant scope root —
/// the same typed denial the worker produces at read time.
pub fn admission_context(
    store: &TaskStore,
    class: EffectClass,
    scope_root: &Path,
    target: &Path,
) -> Result<AdmissionContext, ExecutorError> {
    Ok(AdmissionContext {
        mode: PermissionMode::default(),
        in_grant_scope: derive_in_grant_scope(scope_root, target)?,
        budget_remaining: false,
        in_trusted_scope: false,
        has_checkpoint: false,
        previously_approved: store
            .is_preapproved(&preapproval_scope(class, &target.display().to_string()))?,
        within_declared_bounds: false,
        dry_run: false,
    })
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
        }
    }

    /// Durable planned intent, then admission. The attempt is visible in the
    /// ledger before any effect can happen. The permission-mode consult
    /// (DEC-014) runs between the grant gate and the plan: an enrolled deny
    /// outranks every mode, and `ask`/`deny` verdicts fail closed — only the
    /// permission panel may convert an `ask` into consent.
    pub fn admit(
        &mut self,
        task_id: &TaskId,
        request: EffectRequest,
    ) -> Result<AdmittedEffect, ExecutorError> {
        let grant_id = match &request {
            EffectRequest::Read { grant_id, .. }
            | EffectRequest::Write { grant_id, .. }
            | EffectRequest::Exec { grant_id, .. }
            | EffectRequest::Egress { grant_id, .. } => grant_id.clone(),
        };
        let grant = self.policy.admit(&grant_id, request.class())?;
        let target = request.target_path();
        let ctx = admission_context(self.store, request.class(), &grant.scope_root, &target)?;
        let scope_root = grant.scope_root.clone();
        let decision = self.policy.decide(&target, request.class(), &ctx);
        let attempt_id = self
            .store
            .plan_attempt(task_id, request.class(), &request.describe())?;
        if decision != ModeDecision::Allow {
            self.reject_mode(&attempt_id, decision)?;
        }
        Ok(AdmittedEffect {
            task_id: task_id.clone(),
            attempt_id,
            request,
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

    /// Re-consult of the decision context immediately before the read
    /// effect. A context-assembly failure settles the attempt rejected
    /// with the error's reason first — the ledger never keeps a failed
    /// consult planned forever — and then propagates the typed error.
    fn reconsult_context(
        &mut self,
        admitted: &AdmittedEffect,
        path: &Path,
    ) -> Result<AdmissionContext, ExecutorError> {
        match admission_context(self.store, EffectClass::Read, &admitted.scope_root, path) {
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

    /// Fail-closed mode consult immediately before the read effect: a
    /// verdict that is not a clear allow — a deny enrolled after
    /// admission among them — blocks the read before the worker opens
    /// anything.
    fn mode_gate(&mut self, admitted: &AdmittedEffect, path: &Path) -> Result<(), ExecutorError> {
        let ctx = self.reconsult_context(admitted, path)?;
        let decision = self.policy.decide(path, EffectClass::Read, &ctx);
        if decision != ModeDecision::Allow {
            self.reject_mode(&admitted.attempt_id, decision)?;
        }
        Ok(())
    }

    /// Mutable admission: non-read effects are rejected unconditionally by
    /// the read-only backend before any policy or byte is touched; reads
    /// re-check revocation, cancellation, and the mode verdict (an enrolled
    /// deny added after admission included) immediately before the effect.
    pub fn execute(&mut self, admitted: &AdmittedEffect) -> Result<EffectOutcome, ExecutorError> {
        if admitted.request.class() != EffectClass::Read {
            let reason = readonly_rejection(admitted.request.class());
            self.store.attempt_rejected(&admitted.attempt_id, &reason)?;
            return Ok(EffectOutcome::Denied { reason });
        }
        let grant_id = match &admitted.request {
            EffectRequest::Read { grant_id, .. } => grant_id.clone(),
            _ => unreachable!("read class checked above"),
        };
        self.admit_settled(&admitted.attempt_id, &grant_id, EffectClass::Read)?;
        if self.store.task_cancelled(&admitted.task_id)? {
            self.store
                .attempt_rejected(&admitted.attempt_id, TASK_CANCELLED)?;
            return Ok(EffectOutcome::Denied {
                reason: TASK_CANCELLED.to_string(),
            });
        }
        let EffectRequest::Read { path, .. } = &admitted.request else {
            unreachable!("read class checked above")
        };
        // Mutable mode consult before the worker opens anything.
        self.mode_gate(admitted, path)?;
        self.store.attempt_running(&admitted.attempt_id)?;
        let observation = self
            .worker
            .read_once(&admitted.scope_root, path)
            .map_err(ExecutorError::from)?;
        self.store.set_attempt_state(
            &admitted.attempt_id,
            "confirmed",
            Some(&format!("read-performed sha256={}", observation.digest)),
        )?;
        Ok(EffectOutcome::Read {
            bytes: observation.bytes,
            digest: observation.digest,
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
        let grant_id = match &admitted.request {
            EffectRequest::Read { grant_id, .. } => grant_id.clone(),
            _ => unreachable!("read class checked above"),
        };
        self.admit_settled(&admitted.attempt_id, &grant_id, EffectClass::Read)?;
        if self.store.task_cancelled(&admitted.task_id)? {
            self.store
                .attempt_rejected(&admitted.attempt_id, TASK_CANCELLED)?;
            return Err(ExecutorError::Cancelled);
        }
        let EffectRequest::Read { path, .. } = &admitted.request else {
            unreachable!("read class checked above")
        };
        // Same mutable mode consult as `execute`: the crash emulation must
        // not read past a verdict that stopped being a clear allow.
        self.mode_gate(admitted, path)?;
        self.store.attempt_running(&admitted.attempt_id)?;
        let observation = self
            .worker
            .read_once(&admitted.scope_root, path)
            .map_err(ExecutorError::from)?;
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

pub fn backend() -> &'static str {
    macos::BACKEND
}
