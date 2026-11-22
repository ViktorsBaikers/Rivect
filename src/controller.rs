//! Controller: the local reconcile loop between question, broker, executor
//! and evidence. No hidden controller model call: a local check that
//! unblocks the only known admitted action starts it directly, and
//! revocation/cancellation block the next dispatch before any provider
//! effect.

mod preview;

use crate::commands::{ForegroundWork, PausedAttempt, Runtime};
use crate::contracts::Lifecycle;
use crate::contracts::{
    AnswerSelection, Availability, EffectClass, ErrorCode, OptionId, Question, QuestionId,
    QuestionOption, SessionId, TaskId, TaskSnapshot,
};
use crate::executor::{EffectOutcome, EffectRequest, ExecutorError};
use crate::model::{
    LedgerError, ModelError, PendingFallback, RankingFacts, RecordedFacts, RequestManifest,
};
use crate::policy::PolicyError;
use crate::providers::{ProviderError, ProviderReply};
use crate::resources::{Delivery, OutputSettlement};
use crate::scheduler::{NodeId, SchedulerError, WaitTransition};
use crate::state::{ConflictCause, InvalidCause, StoreError, WorkBudgetState};
use crate::supervisor::{Observation, OperationClass};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn foreground_signal<'a>(
    work: Option<&'a ForegroundWork>,
    task: &TaskId,
) -> Option<&'a std::sync::atomic::AtomicBool> {
    work.filter(|work| &work.task_id == task)
        .map(|work| work.cancel.as_ref())
}

/// One bounded scheduler pass over the task tree.
#[derive(Debug, Clone, PartialEq)]
pub enum SchedulerStep {
    /// Nothing was admitted: the tree is idle, fully blocked on waiting
    /// parents, or cancelled.
    Idle,
    /// One admitted node ran one decision step to its outcome.
    Ran {
        node: NodeId,
        outcome: Box<StepOutcome>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum StepOutcome {
    Completed {
        snapshot: TaskSnapshot,
    },
    EffectDenied {
        reason: String,
        snapshot: TaskSnapshot,
    },
    OutcomeUnknown {
        attempt_id: String,
        snapshot: TaskSnapshot,
    },
    Waiting {
        snapshot: TaskSnapshot,
    },
    NoAction {
        snapshot: TaskSnapshot,
    },
    /// The native workflow is off or the task carries an off pause nothing
    /// has displaced yet, so this step never dispatched (AC-024).
    Paused {
        snapshot: TaskSnapshot,
    },
    /// The worker reached its recorded deadline, settled-send bound or
    /// ledger-unit bound, or was stopped explicitly: the step never
    /// dispatched, the row is terminal, and nothing renews it (AC-083a).
    WorkStopped {
        reason: String,
        snapshot: TaskSnapshot,
    },
}

/// What one bounded step of a saved procedure segment did (AC-053).
///
/// The segment's next step runs through the executor's own admission and its
/// settlement is kept; one of the three conditions ends the remainder and
/// returns control, so a stopped run never grows its executed-step count.
#[derive(Debug, Clone, PartialEq)]
pub enum SegmentStepOutcome {
    /// One step settled and the segment has more ahead of it.
    Stepped {
        run: crate::procedure::ProcedureRun,
        step: crate::procedure::SettledStep,
    },
    /// The remainder did not run: control returns with the task's snapshot and
    /// the condition that ended it.
    Stopped {
        run: crate::procedure::ProcedureRun,
        snapshot: TaskSnapshot,
        cause: crate::procedure::StopCause,
    },
    /// The last step settled.
    Completed {
        run: crate::procedure::ProcedureRun,
        snapshot: TaskSnapshot,
    },
}

/// What resuming one task's continuation did (AC-049). The four
/// outcomes are the four honest answers of a resume: the remainder ran,
/// nothing of this task remained, a pinned input moved so replay is
/// refused, or the task never had a checkpoint to resume from. An empty
/// step is never reported as a verdict that nothing further is needed.
#[derive(Debug, Clone, PartialEq)]
pub enum ContinuationOutcome {
    /// The step ran against the pinned state: the context the next
    /// request carries is `context_bytes` long.
    Resumed {
        snapshot: Box<TaskSnapshot>,
        context_bytes: usize,
    },
    /// Nothing of this task remained to run.
    NoContinuation,
    /// A pinned input moved between the compaction and this resume: the
    /// recorded step is refused instead of replayed against stale state.
    Stale { pin: String },
    /// The resume is a native dispatch and the workflow did not let one
    /// start: the task stays paused until a new intent displaces the
    /// pause (AC-024).
    Paused,
}

impl ContinuationOutcome {
    /// The one lowercase line a surface shows for this outcome.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Resumed { context_bytes, .. } => {
                format!("continuation resumed: {context_bytes} bytes of context")
            }
            Self::NoContinuation => "no continuation".to_string(),
            Self::Paused => {
                "continuation paused: the native workflow is not running; steer the task to resume it"
                    .to_string()
            }
            Self::Stale { pin } => {
                format!("continuation is stale: {pin} changed since the compaction; replay refused")
            }
        }
    }
}

/// The snapshot one settled step reports, whichever outcome it reached.
fn step_snapshot(outcome: &StepOutcome) -> TaskSnapshot {
    match outcome {
        StepOutcome::Completed { snapshot }
        | StepOutcome::EffectDenied { snapshot, .. }
        | StepOutcome::OutcomeUnknown { snapshot, .. }
        | StepOutcome::Waiting { snapshot }
        | StepOutcome::NoAction { snapshot }
        | StepOutcome::Paused { snapshot }
        | StepOutcome::WorkStopped { snapshot, .. } => snapshot.clone(),
    }
}

/// The control path's answer for a segment whose remainder stopped (AC-053):
/// the condition that fired names the state, and the outcome is the one the
/// ordinary path already answers that state with, so a stop invents no
/// vocabulary of its own.
fn stopped_outcome(cause: crate::procedure::StopCause, snapshot: TaskSnapshot) -> StepOutcome {
    use crate::procedure::StopCause;
    let stop = crate::procedure::stop_decision(&cause);
    match cause {
        StopCause::UnknownEffect { attempt_id } | StopCause::PreparedStep { attempt_id, .. } => {
            StepOutcome::OutcomeUnknown {
                attempt_id,
                snapshot,
            }
        }
        StopCause::ReceiptMismatch { .. } => StepOutcome::WorkStopped {
            reason: stop.detail,
            snapshot,
        },
        // Revocation at admission prevented the effect.
        StopCause::RevokedRight { .. } => StepOutcome::EffectDenied {
            reason: stop.detail,
            snapshot,
        },
        // The snapshot moved to a fork: the path that already waits on it
        // continues from here.
        StopCause::NewMaterialChoice { .. } => StepOutcome::Waiting { snapshot },
    }
}

/// A granted restore that ran through executor admission. The original
/// check is returned so the caller reruns the same expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedEnvironment {
    pub attempt_id: String,
    pub original: crate::verification::AssumptionCheckRecord,
}

#[derive(Debug, thiserror::Error)]
pub enum ControllerError {
    #[error("environment failure retention failed: {secondary}")]
    EnvironmentRetention {
        #[source]
        primary: ExecutorError,
        secondary: Box<ControllerError>,
    },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Procedure(#[from] crate::procedure::ProcedureError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Executor(#[from] ExecutorError),
    #[error(transparent)]
    Scheduler(#[from] SchedulerError),
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Action(#[from] crate::actions::ActionError),
    #[error("environment preparation was denied: {reason}")]
    EnvironmentDenied { reason: String },
    #[error("environment preparation returned an unexpected outcome")]
    UnexpectedEnvironmentOutcome,
    #[error("applicability evaluation could not decide the obligations of this step")]
    ApplicabilityUnknown,
}

impl ControllerError {
    #[must_use = "the code exists to be carried to the wire; discarding it loses the mapping"]
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Store(error) => error.code(),
            Self::Procedure(error) => error.code(),
            Self::EnvironmentRetention { .. } => ErrorCode::StorageUnavailable,
            Self::Policy(_) => ErrorCode::Denied,
            Self::Model(ModelError::RequestTooLarge { .. }) => ErrorCode::ContextOverflow,
            // The accounted image (raw plus its encoded data URL) crossing
            // either bound is the same request-size class; the wire line
            // names both numbers.
            Self::Model(ModelError::ImageTooLarge { .. }) => ErrorCode::ContextOverflow,
            // A declared/detected media disagreement is the caller's own
            // input, never a denial of the connection.
            Self::Model(
                ModelError::ImageMediaMismatch { .. } | ModelError::ImageUnsupportedMedia { .. },
            ) => ErrorCode::InvalidInput,
            // A pinned connection or model that does not answer the image
            // capability is unavailable for this request, not a policy
            // denial of the operator's grant.
            Self::Model(ModelError::ImageUnsupported { .. }) => ErrorCode::CapabilityUnavailable,
            Self::Model(
                ModelError::Config(_)
                | ModelError::NoEligibleCandidate { .. }
                | ModelError::ManualChoiceRejected { .. },
            ) => ErrorCode::CapabilityUnavailable,
            // The pending choice is normally bridged into a Waiting
            // outcome; when it propagates — no candidates left, no
            // publishable question — the honest class is a blocked
            // decision dependency, never a denial.
            Self::Model(ModelError::ManualFallbackPending { .. }) => ErrorCode::DependencyBlocked,
            // A parameter the frozen request cannot honour, or a base
            // the connection declaration must supply, is the caller's
            // own input, never a denial of the connection: sibling
            // caller-input causes carry their own code too.
            Self::Model(ModelError::Provider(
                ProviderError::UnsupportedParameter { .. } | ProviderError::EndpointRequired { .. },
            )) => ErrorCode::InvalidInput,
            // A ledger refusal keeps its own class: the budget arm is the
            // one that never entered a send, every other is the store's.
            Self::Model(ModelError::BudgetExhausted { .. }) => ErrorCode::BudgetExhausted,
            Self::Model(ModelError::Ledger(error)) => error.code(),
            Self::Model(ModelError::Provider(ProviderError::Interrupted { .. })) => {
                ErrorCode::OutcomeUnknown
            }
            Self::Model(_) => ErrorCode::Denied,
            Self::Executor(error) => error.error_code(),
            Self::Scheduler(SchedulerError::UnitsExceedCap { .. }) => ErrorCode::BudgetExhausted,
            Self::Scheduler(_) => ErrorCode::Conflict,
            Self::Serialization(_) => ErrorCode::InvalidInput,
            Self::Action(error) => error.error_code(),
            Self::EnvironmentDenied { .. } => ErrorCode::Denied,
            Self::UnexpectedEnvironmentOutcome => ErrorCode::InternalError,
            Self::ApplicabilityUnknown => ErrorCode::OutcomeUnknown,
        }
    }
}

/// Typed settlement of the external-output projection for one decision
/// step: a completed run completes the stream, an unknown attempt marks
/// the already-shown output partial, and a denial fails it with the
/// typed reason. Waiting and no-action outcomes settle nothing — their
/// stream keeps streaming until a later outcome settles it.
#[must_use]
pub fn output_settlement(outcome: &StepOutcome) -> Option<OutputSettlement> {
    match outcome {
        StepOutcome::Completed { .. } => Some(OutputSettlement::Complete),
        StepOutcome::OutcomeUnknown { attempt_id, .. } => Some(OutputSettlement::Partial {
            cause: format!("attempt {attempt_id} outcome unknown"),
        }),
        StepOutcome::EffectDenied { reason, .. } => Some(OutputSettlement::Failed {
            cause: reason.clone(),
        }),
        // A terminal stop ends the run without completing it: the stream is
        // failed by the bound that ended it, never left streaming.
        StepOutcome::WorkStopped { reason, .. } => Some(OutputSettlement::Failed {
            cause: reason.clone(),
        }),
        StepOutcome::Waiting { .. } | StepOutcome::NoAction { .. } | StepOutcome::Paused { .. } => {
            None
        }
    }
}

/// One decision step's outcome as the supervisor's typed observation
/// fingerprint: every `StepOutcome` variant feeds the detectors, each
/// with its own stable tool/args/result triple, so no outcome class
/// bypasses the feed (AC-011, DEC-016). The fingerprint's tool is the
/// only permitted action (`read_file`); the frozen answer names the
/// inputs, and the result names the variant.
#[must_use]
pub fn step_outcome_observation(
    task: &TaskId,
    answer: &AnswerSelection,
    outcome: &StepOutcome,
) -> Observation {
    let result = match outcome {
        StepOutcome::Completed { .. } => "completed".to_string(),
        StepOutcome::EffectDenied { reason, .. } => reason.clone(),
        StepOutcome::OutcomeUnknown { attempt_id, .. } => {
            format!("outcome unknown: {attempt_id}")
        }
        StepOutcome::Waiting { .. } => "waiting".to_string(),
        StepOutcome::NoAction { .. } => "no action".to_string(),
        StepOutcome::Paused { .. } => "paused".to_string(),
        StepOutcome::WorkStopped { reason, .. } => format!("work stopped: {reason}"),
    };
    Observation::failure(
        task.clone(),
        OperationClass::Read,
        "read_file",
        &answer_text(answer),
        &result,
    )
}

/// One failed decision step as the supervisor's typed observation
/// fingerprint: every `ControllerError` class keeps its own
/// `decision_step`-tooled fingerprint, so no error class bypasses the
/// feed and errors never collapse into the effect-denied fingerprint
/// (AC-011, DEC-016).
///
/// # Examples
///
/// ```
/// use rivect::contracts::{AnswerSelection, TaskId};
/// use rivect::controller::{ControllerError, step_error_observation};
/// use rivect::scheduler::SchedulerError;
///
/// let observation = step_error_observation(
///     &TaskId("task-loop".to_string()),
///     &AnswerSelection::Custom {
///         text: "read /scope/f".to_string(),
///     },
///     &ControllerError::Scheduler(SchedulerError::UnknownNode { node: 3 }),
/// );
/// assert_eq!(observation.signature.tool, "decision_step");
/// assert_eq!(
///     observation.signature.result,
///     "scheduler error: unknown scheduler node 3"
/// );
/// ```
#[must_use]
pub fn step_error_observation(
    task: &TaskId,
    answer: &AnswerSelection,
    error: &ControllerError,
) -> Observation {
    let result = match error {
        ControllerError::EnvironmentRetention { primary, secondary } => {
            format!("executor error: {primary}; retention error: {secondary}")
        }
        ControllerError::Store(source) => format!("store error: {source}"),
        ControllerError::Procedure(source) => format!("procedure error: {source}"),
        ControllerError::Policy(source) => format!("policy error: {source}"),
        ControllerError::Model(source) => format!("model error: {source}"),
        ControllerError::Executor(source) => format!("executor error: {source}"),
        ControllerError::Scheduler(source) => format!("scheduler error: {source}"),
        ControllerError::Serialization(source) => format!("serialization error: {source}"),
        ControllerError::Action(source) => format!("action error: {source}"),
        ControllerError::EnvironmentDenied { reason } => {
            format!("environment error: preparation denied: {reason}")
        }
        ControllerError::UnexpectedEnvironmentOutcome => {
            "environment error: preparation returned an unexpected outcome".to_string()
        }
        ControllerError::ApplicabilityUnknown => {
            "applicability error: evaluation could not decide the obligations of this step"
                .to_string()
        }
    };
    Observation::failure(
        task.clone(),
        OperationClass::Read,
        "decision_step",
        &answer_text(answer),
        &result,
    )
}

/// Mirrors the runtime notification queue capacity: one pass drains at
/// most one full queue, so bounded work never grows with the backlog.
pub(crate) const SCHEDULER_DRAIN_LIMIT: usize = 8;

/// The interim DEC-068 applicability-evaluation sentinel, mirroring
/// `KNOWN_READY_OPTION`: an answer selecting this option reports the
/// evaluation of the materialized obligations returned unknown/error.
/// The step then marks them unresolved (never stale) and fails through
/// the supervisor's Err feed.
pub const APPLICABILITY_UNKNOWN_OPTION: &str = "applicability-unknown";

/// The three recorded bounds a step checks before dispatch, and the reason
/// each one records on the row when it ends the worker. The explicit stop's
/// reason is shared with the ingress (`state::WORK_STOPPED_REASON`), so a
/// stopped row names the same cause wherever it was read.
const WORK_DEADLINE_REACHED: &str = "work deadline reached";
const WORK_SEND_BOUND_REACHED: &str = "work send bound reached";
const WORK_UNIT_BOUND_REACHED: &str = "work unit bound reached";

/// The scope a dispatch refusal names when a worker's send bound was already
/// filled. One classifier for every dispatch arm — primary, auto fallback and
/// manual substitute — so the same ledger refusal always maps to the same
/// terminal stop.
fn work_send_bound_scope(error: &ModelError) -> Option<String> {
    match error {
        ModelError::Ledger(LedgerError::Store(StoreError::Conflict(
            ConflictCause::WorkSendBoundReached { task_id, .. },
        ))) => Some(task_id.clone()),
        _ => None,
    }
}

/// One confirmed scoped read handed to the evidence and completion guard:
/// the dispatch identity and the resolved target travel together.
struct ConfirmedRead<'a> {
    session_id: &'a SessionId,
    task_id: &'a TaskId,
    target: &'a std::path::Path,
    bytes: &'a [u8],
    digest: &'a str,
    retained_attempt_id: Option<String>,
    effect_attempt: String,
    grant_id: &'a str,
    preview: Option<&'a dyn Fn(&str)>,
    auto_reads: u8,
}

pub(crate) const FILE_SHARE_QUESTION: &str = "share-file:";
const SHARE_ONCE: &str = "share-once";
/// One ordinary prompt may read this many files before the step stops for a
/// fresh operator turn; each read is one model reply and one scoped effect.
const AUTO_FILE_READS: u8 = 64;
pub(crate) const FILE_WRITE_QUESTION: &str = "write-file:";
pub(crate) const PROJECT_CHECK_QUESTION: &str = "run-check:";
const ALLOW_WRITE: &str = "allow-write-once";
const ALLOW_CHECK: &str = "allow-check-once";

impl Question {
    /// Scoped effect questions accept only the owner's enumerated choices.
    #[must_use]
    pub fn accepts_custom(&self) -> bool {
        !self.question_id.0.starts_with(FILE_SHARE_QUESTION) && !self.is_permission()
    }

    /// Whether this decision guards a write or project-check effect.
    #[must_use]
    pub fn is_permission(&self) -> bool {
        self.question_id.0.starts_with(FILE_WRITE_QUESTION)
            || self.question_id.0.starts_with(PROJECT_CHECK_QUESTION)
    }
}

pub(crate) struct PendingFileShare {
    question: QuestionId,
    pub(crate) task: TaskId,
    path: PathBuf,
    digest: String,
    recipient: ApprovedRecipient,
    inputs: serde_json::Value,
}

struct ApprovedRecipient {
    connection: String,
    endpoint: String,
    config_revision: String,
    identity: String,
}

pub(crate) struct PendingFileWrite {
    question: QuestionId,
    session: SessionId,
    summary: String,
    preview: Option<String>,
    pub(crate) task: TaskId,
    path: PathBuf,
    edit: crate::executor::ProjectEdit,
    bytes: Vec<u8>,
    recipient: ApprovedRecipient,
}

pub(crate) struct PendingProjectCheck {
    question: QuestionId,
    pub(crate) task: TaskId,
    cargo: PathBuf,
    cargo_home: PathBuf,
    selector: String,
    candidate: String,
    recipient: ApprovedRecipient,
}

fn local_check_toolchain() -> Option<(PathBuf, PathBuf)> {
    use std::path::Path;
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map_or_else(|| home.join(".cargo"), PathBuf::from)
        .canonicalize()
        .ok()?;
    let direct = std::env::var_os("CARGO").into_iter().map(PathBuf::from);
    let search = std::env::var_os("PATH").unwrap_or_default();
    let local = direct.chain(
        std::env::split_paths(&search)
            .filter(|dir| dir.is_absolute())
            .map(|dir| dir.join("cargo")),
    );
    let usable = |path: PathBuf| {
        if !path.is_absolute() {
            return None;
        }
        let canonical = path.canonicalize().ok()?;
        (canonical.is_file() && canonical.parent()?.join("rustc").is_file()).then_some(canonical)
    };
    if let Some(cargo) = local.filter_map(usable).next() {
        return Some((cargo, cargo_home));
    }
    let rustup_home =
        std::env::var_os("RUSTUP_HOME").map_or_else(|| home.join(".rustup"), PathBuf::from);
    let settings = std::fs::read_to_string(rustup_home.join("settings.toml"))
        .ok()?
        .parse::<toml_edit::DocumentMut>()
        .ok()?;
    let name = std::env::var("RUSTUP_TOOLCHAIN").ok().or_else(|| {
        settings
            .get("default_toolchain")?
            .as_str()
            .map(str::to_owned)
    })?;
    if !matches!(
        Path::new(&name).components().collect::<Vec<_>>().as_slice(),
        [std::path::Component::Normal(_)]
    ) {
        return None;
    }
    let cargo = usable(rustup_home.join("toolchains").join(name).join("bin/cargo"))?;
    Some((cargo, cargo_home))
}

impl Runtime {
    /// Projects an in-memory write offer only while its session and question are current.
    ///
    /// # Errors
    /// Returns a storage error if the current question cannot be checked.
    pub fn proposed_diff(
        &self,
        session: &SessionId,
        task: &TaskId,
    ) -> Result<Option<(&str, bool)>, StoreError> {
        Ok(self
            .current_write(session, task, None)?
            .map(|write| (write.summary.as_str(), write.preview.is_some())))
    }

    /// The paired terminal's explicit reveal checks the complete current consent pin.
    pub fn reveal_proposed_diff(
        &self,
        session: &SessionId,
        task: &TaskId,
        question: &str,
        revision: u64,
        intent: u64,
    ) -> Result<Option<&str>, StoreError> {
        Ok(self
            .current_write(session, task, Some((question, revision, intent)))?
            .and_then(|write| write.preview.as_deref()))
    }

    fn current_write(
        &self,
        session: &SessionId,
        task: &TaskId,
        pin: Option<(&str, u64, u64)>,
    ) -> Result<Option<&PendingFileWrite>, StoreError> {
        let Some(write) = self
            .file_write
            .as_ref()
            .filter(|w| &w.session == session && &w.task == task)
        else {
            return Ok(None);
        };
        if self.policy.covers(&write.path)
            || self.effective().sources_digest != write.recipient.config_revision
        {
            return Ok(None);
        }
        Ok(self
            .owner
            .store
            .current_question(task)?
            .filter(|(q, _)| {
                q.question_id == write.question
                    && pin.is_none_or(|(id, revision, intent)| {
                        q.question_id.0 == id
                            && q.question_revision == revision
                            && q.intent_revision == intent
                    })
            })
            .map(|_| write))
    }

    pub fn drain_scheduler(&mut self, session_id: &SessionId) -> Result<(), ControllerError> {
        self.drain_scheduler_with_preview(session_id, None)
    }

    pub(crate) fn drain_scheduler_with_preview(
        &mut self,
        session_id: &SessionId,
        preview: Option<&dyn Fn(&str)>,
    ) -> Result<(), ControllerError> {
        for _ in 0..SCHEDULER_DRAIN_LIMIT {
            match self.scheduler_step_with_preview(session_id, preview)? {
                SchedulerStep::Idle => return Ok(()),
                SchedulerStep::Ran { .. } => {}
            }
        }
        Ok(())
    }

    /// One decision step for a task whose pending question has been
    /// answered: the broker dispatches the frozen manifest once, the only
    /// permitted action is a scoped read, evidence and the completion guard
    /// close the loop. A task whose executed plan saved a procedure segment
    /// runs that segment instead, on this same path and behind the same gates
    /// (AC-053). `crash_after_dispatch` emulates process death after
    /// the durable dispatched record, before effect confirmation.
    pub fn run_decision_step(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        answer: &AnswerSelection,
        grant_id: &str,
        crash_after_dispatch: bool,
    ) -> Result<StepOutcome, ControllerError> {
        self.run_decision_step_with_preview(
            session_id,
            task_id,
            answer,
            grant_id,
            crash_after_dispatch,
            None,
        )
    }

    fn run_decision_step_with_preview(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        answer: &AnswerSelection,
        grant_id: &str,
        crash_after_dispatch: bool,
        preview: Option<&dyn Fn(&str)>,
    ) -> Result<StepOutcome, ControllerError> {
        let outcome = self.run_decision_step_inner(
            session_id,
            task_id,
            answer,
            grant_id,
            crash_after_dispatch,
            preview,
        )?;
        let settled = match &outcome {
            StepOutcome::Completed { snapshot } => Some((snapshot, "output.complete")),
            StepOutcome::OutcomeUnknown { snapshot, .. } => Some((snapshot, "output.partial")),
            StepOutcome::WorkStopped { snapshot, .. } => Some((snapshot, "output.stopped")),
            StepOutcome::EffectDenied { snapshot, reason } => Some((
                snapshot,
                match reason.as_str() {
                    crate::executor::MODE_ASK_REASON => "output.mode_ask",
                    crate::executor::MODE_DENY_REASON => "output.mode_deny",
                    _ => "output.denied",
                },
            )),
            StepOutcome::Waiting { .. }
            | StepOutcome::Paused { .. }
            | StepOutcome::NoAction { .. } => None,
        };
        if let Some((pin, kind)) = settled {
            self.owner
                .store
                .record_step_output(session_id, task_id, pin.revision, kind)?;
        }
        Ok(outcome)
    }

    fn run_decision_step_inner(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        answer: &AnswerSelection,
        grant_id: &str,
        crash_after_dispatch: bool,
        preview: Option<&dyn Fn(&str)>,
    ) -> Result<StepOutcome, ControllerError> {
        if let Some(cancelled) = self.foreground_cancellation(session_id, task_id)? {
            return Ok(cancelled);
        }
        if let Some(gated) = self.gate_decision_dispatch(session_id, task_id, grant_id)? {
            return Ok(gated);
        }
        if matches!(
            answer,
            AnswerSelection::Option { option_id }
                if option_id.0.as_str() == APPLICABILITY_UNKNOWN_OPTION
        ) {
            self.fail_applicability(task_id)?;
        }
        self.owner.store.recover_procedure_receipt(task_id)?;
        let names_input = match answer {
            AnswerSelection::Custom { text } => {
                text.strip_prefix("read ").map(std::path::Path::new)
                    == Some(self.scoped_file.as_path())
            }
            AnswerSelection::Option { option_id } => {
                option_id.0 == crate::contracts::KNOWN_READY_OPTION
            }
        };
        if names_input
            && !self.paused_attempts.contains_key(&task_id.0)
            && !self
                .foreground
                .as_ref()
                .is_some_and(|work| &work.task_id == task_id && work.share_reads)
            && let Some(segment) = self.saved_segment(task_id)?
            && let Some(binding) = self.segment_binding(&segment, grant_id)
            && !self
                .owner
                .store
                .latest_applied_answer_question(task_id)?
                .is_some_and(|question| {
                    [
                        FILE_SHARE_QUESTION,
                        FILE_WRITE_QUESTION,
                        PROJECT_CHECK_QUESTION,
                    ]
                    .iter()
                    .any(|prefix| question.0.starts_with(prefix))
                })
        {
            return self.run_saved_segment(session_id, task_id, &binding, &segment);
        }
        let resolved = self.resolve_read_target(session_id, task_id, answer, preview);
        if let Some(cancelled) = self.foreground_cancellation(session_id, task_id)? {
            return Ok(cancelled);
        }
        let (target, retained_attempt_id) = match resolved? {
            Ok(pair) => pair,
            Err(waiting) => return Ok(waiting),
        };
        self.execute_read(
            session_id,
            task_id,
            target,
            retained_attempt_id,
            grant_id,
            preview,
            crash_after_dispatch,
            AUTO_FILE_READS,
        )
    }

    /// Admits and executes one scoped read, then hands the confirmed bytes to
    /// the evidence/share continuation. An ordinary prompt's automatic share
    /// may recurse here for the next file; the bound keeps one scheduler step
    /// from becoming an unbounded model/file loop.
    #[expect(
        clippy::too_many_arguments,
        reason = "a read carries its task, target, retained model attempt, grant, preview sink and loop bound"
    )]
    fn execute_read(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        target: PathBuf,
        retained_attempt_id: Option<String>,
        grant_id: &str,
        preview: Option<&dyn Fn(&str)>,
        crash_after_dispatch: bool,
        auto_reads: u8,
    ) -> Result<StepOutcome, ControllerError> {
        let request = EffectRequest::Read {
            grant_id: grant_id.to_string(),
            path: target,
        };
        let admitted = {
            let mut executor = self.executor();
            // The production step driver still inlines the interim `manual`
            // default (DEC-015) until the Settings surface lands.
            executor.admit(task_id, request, crate::policy::PermissionMode::Manual)?
        };
        let effect_attempt = admitted.attempt_id.clone();
        // No model attempt named the target: the effect attempt carries
        // the pre-effect retention instead.
        if retained_attempt_id.is_none() {
            self.retain_pre_effect(&effect_attempt, "fixed option admitted read")?;
        }
        let mut executor = self.executor();
        if crash_after_dispatch {
            executor.execute_unconfirmed(&admitted)?;
            self.owner.store.mark_outcome_unknown(task_id)?;
            let snapshot = self.owner.store.snapshot(task_id)?;
            return Ok(StepOutcome::OutcomeUnknown {
                attempt_id: effect_attempt,
                snapshot,
            });
        }
        match executor.execute(&admitted) {
            Ok(EffectOutcome::Read { bytes, digest }) => {
                let target = admitted.request.target_path();
                self.complete_read_with_evidence(ConfirmedRead {
                    session_id,
                    task_id,
                    target: &target,
                    bytes: &bytes,
                    digest: &digest,
                    retained_attempt_id,
                    effect_attempt,
                    grant_id,
                    preview,
                    auto_reads,
                })
            }
            Ok(EffectOutcome::Denied { reason }) => {
                let snapshot = self.owner.store.snapshot(task_id)?;
                Ok(StepOutcome::EffectDenied { reason, snapshot })
            }
            // The dispatch constructs only read requests, so a performed
            // non-read outcome is structurally unreachable here; the
            // production step driver (DEC-016) owns that observation map.
            Ok(EffectOutcome::Executed { .. }) => {
                unreachable!("internal error: the dispatch only admits reads")
            }
            Err(err) => Err(err.into()),
        }
    }

    fn foreground_cancellation(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
    ) -> Result<Option<StepOutcome>, ControllerError> {
        if !foreground_signal(self.foreground.as_ref(), task_id)
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire))
        {
            return Ok(None);
        }
        let snapshot = self.owner.store.snapshot(task_id)?;
        if snapshot.lifecycle.is_terminal() {
            return Ok(Some(StepOutcome::NoAction { snapshot }));
        }
        self.owner.store.cancel_task(
            session_id,
            task_id,
            snapshot.intent_revision,
            Some(crate::executor::TASK_CANCELLED),
        )?;
        self.tombstone_paused(task_id);
        self.clear_budget_wait(session_id, task_id);
        Ok(Some(StepOutcome::NoAction {
            snapshot: self.owner.store.snapshot(task_id)?,
        }))
    }

    /// Resumes one task's continuation after a forced compaction
    /// (AC-049): the checkpoint's pinned inputs are re-checked against
    /// the live state first, so a moved input refuses the replay instead
    /// of running a stale step, and the step itself is one scheduler step
    /// — resuming is a decision, never a second loop. The assembled
    /// context is read before the step because that is what the next
    /// request carries; a compaction that changed nothing but a record
    /// would leave it the same size.
    pub fn resume_continuation(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
    ) -> Result<ContinuationOutcome, ControllerError> {
        let Some(checkpoint) = self.owner.store.continuation_checkpoint(task_id)? else {
            return Ok(ContinuationOutcome::NoContinuation);
        };
        let live = self.owner.store.pinned_inputs(task_id)?;
        if let Some(pin) = checkpoint.stale_pin(&live) {
            return Ok(ContinuationOutcome::Stale {
                pin: pin.to_string(),
            });
        }
        let context = self.owner.store.assembled_context(task_id)?;
        let Some(node) = self.scheduler.node_of_task(task_id) else {
            return Ok(ContinuationOutcome::NoContinuation);
        };
        match self.scheduler_step(session_id)? {
            SchedulerStep::Ran { node: ran, outcome } if ran == node => match *outcome {
                // The step never dispatched, so this task's remainder is
                // exactly where the compaction left it (AC-024).
                StepOutcome::Paused { .. } => Ok(ContinuationOutcome::Paused),
                settled => Ok(ContinuationOutcome::Resumed {
                    snapshot: Box::new(step_snapshot(&settled)),
                    context_bytes: context.text.len(),
                }),
            },
            // Another node took the slot, or the tree was already idle:
            // this task's remainder is not what the step resumed.
            SchedulerStep::Ran { .. } | SchedulerStep::Idle => {
                Ok(ContinuationOutcome::NoContinuation)
            }
        }
    }

    /// No-repeat, mutable admission, permission-mode, and cancel gates
    /// that must hold before any provider call or worker effect. A
    /// `Some` outcome is the step's answer; `None` continues the dispatch.
    fn gate_decision_dispatch(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        grant_id: &str,
    ) -> Result<Option<StepOutcome>, ControllerError> {
        if self.owner.store.task_lifecycle(task_id)?.is_terminal() {
            self.clear_budget_wait(session_id, task_id);
            let snapshot = self.owner.store.snapshot(task_id)?;
            return Ok(Some(StepOutcome::NoAction { snapshot }));
        }
        // The recorded work bound is checked before every dispatch (AC-083a):
        // a reached deadline, send bound or ledger sum ends the worker
        // terminally, and so does a stop already recorded.
        if let Some(stopped) = self.work_budget_gate(task_id)? {
            return Ok(Some(stopped));
        }
        if let Some(paused) = self.off_gate(session_id, task_id)? {
            return Ok(Some(paused));
        }
        // No-repeat guard: any unresolved running/unknown attempt of this
        // task blocks the next decision before a single provider call or
        // worker effect; the caller reconciles or starts a new task.
        if let Some(unresolved) = self.owner.store.latest_unresolved_attempt(task_id)? {
            let snapshot = self.owner.store.snapshot(task_id)?;
            return Ok(Some(StepOutcome::OutcomeUnknown {
                attempt_id: unresolved,
                snapshot,
            }));
        }
        // Mutable admission gates before the first provider effect:
        // revocation and task cancellation both deny the dispatch itself.
        self.policy.admit(grant_id, EffectClass::Read)?;
        // Permission-mode consult (DEC-014) on the only permitted action
        // target. The dispatch carrier is the interim `manual` default
        // (DEC-015) until the Settings surface lands; an enrolled deny
        // outranks it, and any verdict that is not a clear allow — ask
        // included — gates the dispatch read before any provider effect,
        // mirroring the executor's fail-closed rule.
        let dispatch_ctx = crate::executor::admission_context(
            &self.owner.store,
            crate::policy::PermissionMode::Manual,
            EffectClass::Read,
            grant_id,
            &self.scope_root,
            &self.scoped_file,
        )?;
        let dispatch_verdict =
            self.policy
                .decide(&self.scoped_file, EffectClass::Read, &dispatch_ctx);
        if dispatch_verdict != crate::policy::ModeDecision::Allow {
            let snapshot = self.owner.store.snapshot(task_id)?;
            return Ok(Some(StepOutcome::EffectDenied {
                reason: crate::executor::mode_reason(dispatch_verdict).to_string(),
                snapshot,
            }));
        }
        if self.owner.store.task_cancelled(task_id)? {
            let snapshot = self.owner.store.snapshot(task_id)?;
            return Ok(Some(StepOutcome::EffectDenied {
                reason: crate::executor::TASK_CANCELLED.to_string(),
                snapshot,
            }));
        }
        self.owner.store.materialize_obligations(task_id)?;
        Ok(None)
    }

    /// The recorded bounds of one long-running worker (AC-083a), checked
    /// before any dispatch. The walk follows the task's scheduler scope chain
    /// — its own ledger scope and every node-carrying ancestor — so a
    /// delegated child cannot spend past a parent's recorded bound. For each
    /// open row the injectable clock, the settled sends the shared ledger
    /// counted and its own unit sum are checked; a reached bound, or a stop
    /// already recorded, ends that worker terminally. The row moves `open` to
    /// `stopped` once and no later step renews it. The read is the existing
    /// ledger and settlement rows, so a second counter never exists.
    fn work_budget_gate(
        &mut self,
        task_id: &TaskId,
    ) -> Result<Option<StepOutcome>, ControllerError> {
        let mut chain = self.budget_scopes(task_id)?;
        if chain.is_empty() {
            // A task the scheduler never submitted still answers for its own
            // recorded row, so a budget never becomes invisible.
            chain.push(task_id.0.clone());
        }
        for scope in chain {
            let scope_task = TaskId(scope);
            let Some(budget) = self.owner.store.work_budget(&scope_task)? else {
                continue;
            };
            let reason = match budget.state {
                WorkBudgetState::Stopped => Some(
                    budget
                        .stop_reason
                        .clone()
                        .unwrap_or_else(|| crate::state::WORK_STOPPED_REASON.to_string()),
                ),
                WorkBudgetState::Open => {
                    if (self.work_clock)() >= budget.deadline_unix_seconds {
                        Some(WORK_DEADLINE_REACHED.to_string())
                    } else if budget.settled_sends >= budget.send_bound {
                        Some(WORK_SEND_BOUND_REACHED.to_string())
                    } else if budget.spent.saturating_add(budget.reserved) >= budget.unit_bound {
                        Some(WORK_UNIT_BOUND_REACHED.to_string())
                    } else {
                        None
                    }
                }
            };
            let Some(reason) = reason else {
                continue;
            };
            if budget.state == WorkBudgetState::Open {
                self.stop_reached_work_budget(&scope_task, &reason)?;
            }
            let snapshot = self.owner.store.snapshot(task_id)?;
            return Ok(Some(StepOutcome::WorkStopped { reason, snapshot }));
        }
        Ok(None)
    }

    /// The terminal stop a dispatch refusal or the gate records (AC-083a):
    /// the named scope's open work row moves to stopped, and the step answers
    /// the stop with the dispatching task's snapshot.
    fn stop_at_work_bound(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        scope: &str,
        reason: &str,
    ) -> Result<StepOutcome, ControllerError> {
        self.stop_reached_work_budget(&TaskId(scope.to_string()), reason)?;
        self.clear_budget_wait(session_id, task_id);
        let snapshot = self.owner.store.snapshot(task_id)?;
        Ok(StepOutcome::WorkStopped {
            reason: reason.to_string(),
            snapshot,
        })
    }

    /// The unit-bound stop a refused dispatch earns when the exhausted scope
    /// is a worker's own ledger scope: the budget cannot fund the frozen
    /// bound, so the worker stops instead of waiting for a resolution that
    /// never comes. `None` leaves the ordinary waiting outcome in place.
    fn unit_bound_stop(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        scope: &str,
    ) -> Result<Option<StepOutcome>, ControllerError> {
        let scope_task = TaskId(scope.to_string());
        let Some(budget) = self.owner.store.work_budget(&scope_task)? else {
            return Ok(None);
        };
        if budget.state != WorkBudgetState::Open {
            return Ok(None);
        }
        Ok(Some(self.stop_at_work_bound(
            session_id,
            task_id,
            scope,
            WORK_UNIT_BOUND_REACHED,
        )?))
    }

    /// Moves one scope's work row to stopped once. A row another path already
    /// stopped is the state this call wanted, so it is not an error; every
    /// other store refusal propagates.
    fn stop_reached_work_budget(
        &mut self,
        task_id: &TaskId,
        reason: &str,
    ) -> Result<(), ControllerError> {
        match self.owner.store.stop_work_budget(task_id, reason) {
            Ok(_) => Ok(()),
            Err(StoreError::Conflict(ConflictCause::WorkBudgetStopped { .. })) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// The one off gate of the native path (AC-024/REQ-017): an explicit
    /// user `workflow.enabled = false` — or the pause that transition
    /// recorded on this task — refuses the step before its first provider
    /// call, and records the pause once so the interruption is a durable
    /// fact rather than a silent drop. Nothing is disposed and no settled
    /// effect is touched. Only this path is gated: the custom/tool path
    /// never reaches it, so `context.compact`, memory and every tool the
    /// user invokes stay available at off (DEC-011/S-1).
    fn off_gate(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
    ) -> Result<Option<StepOutcome>, ControllerError> {
        let off = !self.off_state.native_dispatch_open();
        if !off && self.owner.store.task_lifecycle(task_id)? != Lifecycle::Paused {
            return Ok(None);
        }
        if off {
            self.owner
                .store
                .pause_for_workflow_off(session_id, task_id)?;
        }
        let snapshot = self.owner.store.snapshot(task_id)?;
        Ok(Some(StepOutcome::Paused { snapshot }))
    }

    /// Resolves the scoped read target. A manual-fallback pick dispatches
    /// the paused attempt; any other fixed option already names the one
    /// permitted read, so no model call is spent on it; only free-text
    /// answers need the model to interpret them.
    /// `Err(Waiting)` is a step outcome, not a controller failure.
    fn resolve_read_target(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        answer: &AnswerSelection,
        preview: Option<&dyn Fn(&str)>,
    ) -> Result<Result<(PathBuf, Option<String>), StepOutcome>, ControllerError> {
        // The manifest freezes the execution world (AC-013): the
        // scope root the request's sources and proofs live in,
        // re-checked at dispatch.
        let world = self.scope_root.display().to_string();
        // A manual-fallback answer naming a served candidate dispatches
        // the paused attempt's frozen manifest through the picked
        // connection — the broker re-runs the current eligibility check
        // before the send, so a candidate that lost eligibility between
        // the question and the answer is refused typed, never sent.
        // The pause is bound to the question that served its candidates:
        // the step runs right after the answer commit, so the task's
        // latest applied row names the fork this answer resolves, and an
        // option id colliding with a stale pause's candidate on a
        // different fork can never spend its frozen manifest.
        let answered = self.owner.store.latest_applied_answer_question(task_id)?;
        if let Some(question) = &answered
            && question.0.starts_with(FILE_SHARE_QUESTION)
        {
            return self.resume_file_share(session_id, task_id, question, answer, preview);
        }
        if let Some(question) = &answered
            && question.0.starts_with(FILE_WRITE_QUESTION)
        {
            return self.resume_file_write(session_id, task_id, question, answer);
        }
        if let Some(question) = &answered
            && question.0.starts_with(PROJECT_CHECK_QUESTION)
        {
            return self.resume_project_check(session_id, task_id, question, answer);
        }
        // The reserved `begin` position is the ordinary first step only when
        // the applied answer named this task's recorded start question. A
        // fallback candidate that happens to be named `begin` keeps its own
        // frozen manifest path below.
        let start_answer = matches!(
            answer,
            AnswerSelection::Option { option_id }
                if option_id.0 == crate::contracts::TASK_START_OPTION
        ) && answered
            .as_ref()
            .is_some_and(|question_id| Question::is_task_start_question(question_id, task_id));
        let chosen = match answer {
            AnswerSelection::Option { option_id } => self
                .paused_attempts
                .get(&task_id.0)
                .filter(|paused| {
                    answered.as_ref() == paused.served_question_id.as_ref()
                        && paused
                            .choice
                            .as_ref()
                            .is_some_and(|choice| choice.candidates.contains(&option_id.0))
                })
                .map(|paused| {
                    (
                        paused.manifest.attempt_id.clone(),
                        option_id.0.clone(),
                        paused.manifest.clone(),
                        paused.share_reads,
                    )
                }),
            AnswerSelection::Custom { .. } => None,
        };
        if let Some((attempt_id, connection, paused_manifest, share_reads)) = chosen {
            let scopes = self.budget_scopes(task_id)?;
            let sent = {
                let mut ledger = crate::state::StoreLedger::new(&mut self.owner.store, scopes);
                self.broker.dispatch_fallback_choice_with_cancel(
                    &mut ledger,
                    &world,
                    &attempt_id,
                    &connection,
                    foreground_signal(self.foreground.as_ref(), task_id),
                )
            };
            if let Some(stopped) =
                self.note_send_outcome(session_id, task_id, &sent, Some(&paused_manifest))?
            {
                return Ok(Err(stopped));
            }
            let reply = match sent {
                Ok(reply) => reply,
                // The substitute never entered a send: a worker's own scope
                // that cannot fund it stops at its unit bound; any other
                // scope leaves the task waiting on the named resolution.
                Err(ModelError::BudgetExhausted { scope }) => {
                    if let Some(outcome) = self.unit_bound_stop(session_id, task_id, &scope)? {
                        return Ok(Err(outcome));
                    }
                    let snapshot = self.owner.store.snapshot(task_id)?;
                    return Ok(Err(StepOutcome::Waiting { snapshot }));
                }
                Err(source) => {
                    if let Some(scope) = work_send_bound_scope(&source) {
                        let outcome = self.stop_at_work_bound(
                            session_id,
                            task_id,
                            &scope,
                            WORK_SEND_BOUND_REACHED,
                        )?;
                        return Ok(Err(outcome));
                    }
                    return Err(source.into());
                }
            };
            self.provider_calls += 1;
            self.paused_attempts.remove(&task_id.0);
            if share_reads
                && let Some(work) = self
                    .foreground
                    .as_mut()
                    .filter(|work| &work.task_id == task_id)
            {
                work.share_reads = true;
                self.record_tui_context(session_id, task_id)?;
            }
            return self.read_target_from_reply(task_id, reply, Some(attempt_id));
        }
        if matches!(answer, AnswerSelection::Option { .. }) && !start_answer {
            // The served question's options are exactly the pause's
            // candidates and the store denies unknown option ids, so an
            // option answer that missed `chosen` was never aimed at the
            // surviving pause — it is dead residue, tombstoned like
            // every sibling settle path so its admission can never
            // replay under a later fork.
            self.tombstone_paused(task_id);
            return Ok(Ok((self.scoped_file.clone(), None)));
        }
        let purpose = self.purpose.clone();
        let target_declared = self.scoped_file.display().to_string();
        // A real under-scope file is named as the read target; a bound scope
        // root is named as a scope hint instead, so the model never reads the
        // directory as a file.
        let target_line = if self.scoped_file.is_file() {
            format!("read {target_declared}")
        } else {
            format!("scope {target_declared}")
        };
        let mut inputs = format!(
            "goal: {}\nanswer: {}\n{}",
            String::from_utf8_lossy(&self.owner.store.goal_bytes(task_id)?),
            answer_text(answer),
            target_line
        );
        // The authorship of the bytes this dispatch carries (AC-009): a
        // tool output, an observation or a model-authored answer freezes
        // as such, so the wire's user channel never reads as a human
        // turn that could move consent.
        let origin = self.owner.store.answer_input_origin(task_id)?;
        let mut config = self.config_for_broker();
        let ordinary = start_answer
            && self
                .foreground
                .as_ref()
                .is_some_and(|work| &work.task_id == task_id);
        if ordinary {
            self.add_tui_context(session_id, task_id, &mut config, &mut inputs)?;
        }
        let facts = self.ranking_facts(task_id, &inputs)?;
        let prepared = match self.take_pending_image(task_id) {
            // The answer carried a typed image: the one image constructor
            // sniffs, bounds, digests and admit it on this same request.
            Some(image) => self
                .broker
                .prepare_vision(&purpose, &config, &world, &inputs, origin, &facts, image),
            None if ordinary => self
                .broker
                .prepare_project_start(&purpose, &config, &world, &inputs, origin, &facts),
            None => self
                .broker
                .prepare_with_facts(&purpose, &config, &world, &inputs, origin, &facts),
        };
        let manifest = match prepared {
            Ok(manifest) => manifest,
            // The scope chain cannot fund one more bound: the ranking refuses
            // before any attempt exists, and the task waits on the named
            // resolution exactly like the dispatch-time refusal.
            Err(ModelError::BudgetExhausted { scope }) => {
                if let Some(outcome) = self.unit_bound_stop(session_id, task_id, &scope)? {
                    return Ok(Err(outcome));
                }
                self.record_budget_wait(
                    session_id,
                    task_id,
                    format!("budget exhausted at scope {scope}; waiting for its resolution"),
                );
                let snapshot = self.owner.store.snapshot(task_id)?;
                return Ok(Err(StepOutcome::Waiting { snapshot }));
            }
            Err(source) => return Err(source.into()),
        };
        if start_answer
            && let Some(work) = self.foreground.as_mut()
            && &work.task_id == task_id
        {
            work.share_reads = true;
        }
        self.retain_pre_effect(&manifest.attempt_id, "first useful offline dispatch")?;
        let scopes = self.budget_scopes(task_id)?;
        let sent = {
            let mut ledger = crate::state::StoreLedger::new(&mut self.owner.store, scopes);
            self.broker.dispatch_with_preview(
                &mut ledger,
                &world,
                &manifest,
                foreground_signal(self.foreground.as_ref(), task_id),
                preview,
            )
        };
        // The refusal is known here, so the admission and its frozen inputs
        // are dropped before the fallible projection refresh can return early.
        let refused_attempt = matches!(sent, Err(ModelError::BudgetExhausted { .. }))
            || sent
                .as_ref()
                .err()
                .and_then(work_send_bound_scope)
                .is_some();
        if refused_attempt {
            self.broker.cancel_attempt(&manifest.attempt_id);
        }
        if let Some(stopped) =
            self.note_send_outcome(session_id, task_id, &sent, Some(&manifest))?
        {
            return Ok(Err(stopped));
        }
        match sent {
            Ok(reply) => {
                self.provider_calls += 1;
                if ordinary
                    && let Some(cancelled) = self.foreground_cancellation(session_id, task_id)?
                {
                    return Ok(Err(cancelled));
                }
                if ordinary {
                    self.record_tui_context(session_id, task_id)?;
                }
                // The send landed: any attempt this task was paused on
                // is superseded — tombstone it so a late retry of its
                // frozen manifest is refused, not resurrected.
                self.tombstone_paused(task_id);
                self.read_target_from_reply(task_id, reply, Some(manifest.attempt_id))
            }
            // The frozen bound did not fit an open scope: a worker's own
            // scope that can never fund it stops at its unit bound; any other
            // scope leaves the task waiting on the named resolution.
            Err(ModelError::BudgetExhausted { scope }) => {
                if let Some(outcome) = self.unit_bound_stop(session_id, task_id, &scope)? {
                    return Ok(Err(outcome));
                }
                let snapshot = self.owner.store.snapshot(task_id)?;
                Ok(Err(StepOutcome::Waiting { snapshot }))
            }
            Err(ModelError::ManualFallbackPending { .. }) => {
                self.pause_on_fallback_choice(session_id, task_id, manifest)
            }
            Err(source) => {
                // A bound filled by an earlier leg of this same dispatch ends
                // the worker terminally: a fallback leg never sends past it.
                if let Some(scope) = work_send_bound_scope(&source) {
                    let outcome = self.stop_at_work_bound(
                        session_id,
                        task_id,
                        &scope,
                        WORK_SEND_BOUND_REACHED,
                    )?;
                    return Ok(Err(outcome));
                }
                // Every other dispatch error leaves the primary's admission
                // live — the task pauses on a still-retryable attempt
                // that no question served, so nothing can answer it
                // into a dispatch.
                self.record_pause(task_id, manifest, None, None);
                Err(source.into())
            }
        }
    }

    /// The task facts `auto` ranks on (AC-096, DEC-013): the recorded
    /// obligations and criteria of the task snapshot, the context estimate over
    /// the frozen inputs, and the scope chain with the units each scope still
    /// holds. The surface scan and the tool modality are undecided here — the
    /// controller owns no impact label, and no recorded row states a tool
    /// surface — so both are unknown, never "no risky surface" or "no tools".
    fn ranking_facts(
        &self,
        task_id: &TaskId,
        inputs: &str,
    ) -> Result<RankingFacts, ControllerError> {
        let snapshot = self.owner.store.snapshot(task_id)?;
        let scope_chain = self.budget_scopes(task_id)?;
        let mut remaining_units = BTreeMap::new();
        for scope in &scope_chain {
            match self.owner.store.budget_status(scope) {
                Ok(status) => {
                    let remaining = status
                        .limit_units
                        .saturating_sub(status.spent)
                        .saturating_sub(status.reserved);
                    remaining_units.insert(scope.clone(), remaining);
                }
                // An unopened scope records no units: unknown, never zero, so
                // it never excludes a candidate it cannot speak for.
                Err(StoreError::NotFound(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(RankingFacts::Recorded(RecordedFacts {
            surfaces: None,
            // No recorded row states a tool modality, so this read step's
            // requested tool surface is not a recorded fact the ranking may
            // match on: it stays unknown until a recorded modality exists.
            tools_required: false,
            context_tokens_estimate: u64::try_from(inputs.chars().count()).unwrap_or(u64::MAX),
            obligations: snapshot.obligations.items.len(),
            criteria: snapshot.criteria.items.len(),
            remaining_units,
            scope_chain,
        }))
    }

    /// Records what one broker send did for the controller's own view
    /// (AC-059, AC-062): a budget refusal becomes the task's named waiting
    /// reason — cleared as soon as a later send gets through — before the
    /// fallible projection refresh runs. The refresh is best-effort: a
    /// delivered reply is never dropped on a store fault, and the fault is
    /// recorded in the boot diagnostics with its cause instead of vanishing.
    fn note_send_outcome(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        sent: &Result<ProviderReply, ModelError>,
        manifest: Option<&RequestManifest>,
    ) -> Result<Option<StepOutcome>, ControllerError> {
        match sent {
            Err(ModelError::BudgetExhausted { scope }) => self.record_budget_wait(
                session_id,
                task_id,
                format!("budget exhausted at scope {scope}; waiting for its resolution"),
            ),
            _ => self.clear_budget_wait(session_id, task_id),
        }
        // The prepared manifest is offered on every outcome: the projection
        // reads the durable row family and stays untouched when nothing
        // landed. On the mixed path an entered primary's row is the landing
        // even though the fallback leg was refused before it sent.
        if let Err(error) = self.refresh_economy(manifest) {
            self.boot_diagnostics
                .push(format!("economy projection refresh failed: {error}"));
        }
        if matches!(
            sent,
            Err(ModelError::AttemptCancelled { .. }
                | ModelError::Provider(ProviderError::Interrupted { .. }))
        ) {
            return self.foreground_cancellation(session_id, task_id);
        }
        Ok(None)
    }

    /// Remembers the broker attempt this task is paused on so a later
    /// cancel tombstones it (EDGE-004); a superseded earlier pause dies
    /// with its replacement — its frozen manifest never replays.
    fn record_pause(
        &mut self,
        task_id: &TaskId,
        manifest: RequestManifest,
        choice: Option<PendingFallback>,
        served_question_id: Option<QuestionId>,
    ) {
        if let Some(previous) = self.paused_attempts.insert(
            task_id.0.clone(),
            PausedAttempt {
                manifest,
                choice,
                served_question_id,
                share_reads: self
                    .foreground
                    .as_ref()
                    .is_some_and(|work| &work.task_id == task_id && work.share_reads),
            },
        ) {
            self.broker.cancel_attempt(&previous.manifest.attempt_id);
        }
    }

    /// The manual-fallback bridge (AC-045, DEC-014): the broker recorded
    /// the pending choice on the failed attempt; this consumes it into a
    /// `question.current` publication — one atomic store write that serves
    /// the candidates and moves the task to waiting — and remembers the
    /// attempt so the answered candidate dispatches and a cancel still
    /// tombstones it.
    fn pause_on_fallback_choice(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        manifest: RequestManifest,
    ) -> Result<Result<(PathBuf, Option<String>), StepOutcome>, ControllerError> {
        let Some(choice) = self.broker.pending_choice(&manifest.attempt_id).cloned() else {
            // dispatch reported the pending state, so the record must
            // exist — a missing one is a broker invariant violation,
            // not a recoverable pause. Tombstone the still-live
            // admission in place so it can never be resurrected.
            self.broker.cancel_attempt(&manifest.attempt_id);
            return Err(ControllerError::Model(ModelError::NoPendingChoice {
                attempt_id: manifest.attempt_id.clone(),
            }));
        };
        let Some(recommended) = choice.candidates.first() else {
            // No surviving candidate means there is no choice to serve:
            // an empty question would wait forever, so the step fails
            // typed instead. The admission stays live and retryable —
            // record the pause so a cancel still tombstones it.
            self.record_pause(task_id, manifest, None, None);
            return Err(ControllerError::Model(ModelError::NoEligibleCandidate {
                purpose: choice.purpose,
                rejected: Vec::new(),
            }));
        };
        let snapshot = self.owner.store.snapshot(task_id)?;
        let question = Question {
            question_id: QuestionId::generate(),
            question_revision: 1,
            task_id: task_id.clone(),
            intent_revision: snapshot.intent_revision,
            // The prompt states the verdict the broker recorded: an unknown
            // primary may already have applied remotely, so every offered
            // pick is a repeat of that effect, not just a fallback.
            prompt: if choice.unknown_outcome {
                "the pinned dispatch ended without a definitive answer; its effect may have applied before the failure — a substitute send repeats it".to_string()
            } else {
                "the pinned dispatch failed; choose the fallback connection".to_string()
            },
            options: choice
                .candidates
                .iter()
                .map(|connection| QuestionOption {
                    option_id: OptionId(connection.clone()),
                    label: connection.clone(),
                    consequences: format!("dispatch the frozen request through {connection}"),
                    availability: Availability::Enabled,
                })
                .collect(),
            recommended_option_id: OptionId(recommended.clone()),
            recommendation_basis: if choice.unknown_outcome {
                "unknown-outcome-repeat: a substitute repeats an effect that may have applied"
            } else {
                "candidates passing the current eligibility check"
            }
            .to_string(),
        };
        // One atomic write: the question lands and the task moves to
        // waiting — on a store error nothing is published, the broker's
        // pending record stays, and the next failed dispatch serves it
        // again.
        self.owner.store.publish_question(session_id, &question)?;
        self.broker.take_pending_choice(&manifest.attempt_id);
        // The pause binds the question it just published: only that
        // question's applied answer may spend the frozen manifest.
        self.record_pause(task_id, manifest, Some(choice), Some(question.question_id));
        Ok(Err(StepOutcome::Waiting {
            snapshot: self.owner.store.snapshot(task_id)?,
        }))
    }

    /// The read target a dispatch reply names: the only permitted action
    /// is the scoped `read_file` call; a reply without one leaves the
    /// task waiting on its intent.
    fn read_target_from_reply(
        &mut self,
        task_id: &TaskId,
        reply: ProviderReply,
        retained_attempt_id: Option<String>,
    ) -> Result<Result<(PathBuf, Option<String>), StepOutcome>, ControllerError> {
        if reply.tool_calls.len() > 1
            && self
                .foreground
                .as_ref()
                .is_some_and(|work| &work.task_id == task_id && work.share_reads)
        {
            return Ok(Err(
                self.refuse_effect(task_id, "use one project tool per response")?
            ));
        }
        let Some(call) = reply.tool_calls.iter().find(|c| c.tool == "read_file") else {
            let direct = reply.tool_calls.is_empty() && !reply.text.trim().is_empty();
            if direct {
                self.owner.store.mark_waiting(task_id)?;
            } else {
                self.owner.store.mark_no_ready(task_id)?;
            }
            let snapshot = self.owner.store.snapshot(task_id)?;
            if direct
                && let Some(work) = self.foreground.as_mut()
                && &work.task_id == task_id
            {
                if let Some(previous) = &mut work.reply {
                    previous.push('\n');
                    previous.push_str(&reply.text);
                } else {
                    work.reply = Some(reply.text);
                }
            }
            return Ok(Err(StepOutcome::Waiting { snapshot }));
        };
        Ok(Ok((
            self.scope_root
                .join(call.path.as_deref().unwrap_or_default()),
            retained_attempt_id,
        )))
    }

    fn add_tui_context(
        &self,
        session: &SessionId,
        task: &TaskId,
        config: &mut crate::config::Config,
        inputs: &mut String,
    ) -> Result<(), ControllerError> {
        use crate::config::{FallbackAssign, ModelAssign};
        let project = crate::commands::tui_project_marker(&self.scope_root);
        if self
            .owner
            .store
            .tui_project_session(&project, Some(session))?
            .is_none()
        {
            return Ok(());
        }
        let resolved = config
            .resolve_purpose(&self.purpose)
            .map_err(ModelError::from)?;
        let connection = match &resolved.model {
            ModelAssign::Fixed(pin) => &pin.connection,
            ModelAssign::Auto { pool: Some(pool) } if pool.len() == 1 => &pool[0],
            ModelAssign::Auto { pool: None } if config.connections.len() == 1 => {
                let Some(connection) = config.connections.keys().next() else {
                    return Ok(());
                };
                connection
            }
            ModelAssign::Auto { .. } | ModelAssign::Inherit => return Ok(()),
        };
        let Some(identity) = self.private_context_recipient(config, connection) else {
            return Ok(());
        };
        let revision = format!("{}:{identity}", self.effective().sources_digest);
        let history = self
            .owner
            .store
            .tui_previous_turns(session, task, &project, &revision, connection)?;
        if !history.is_empty() {
            inputs.push_str("\nEarlier human goals and recorded effects for this conversation: ");
            inputs.push_str(&serde_json::Value::Array(history).to_string());
            config
                .models
                .purposes
                .entry(self.purpose.clone())
                .or_default()
                .fallback = Some(FallbackAssign::Off);
        }
        Ok(())
    }

    fn record_tui_context(
        &mut self,
        session: &SessionId,
        task: &TaskId,
    ) -> Result<(), ControllerError> {
        let project = crate::commands::tui_project_marker(&self.scope_root);
        if self
            .owner
            .store
            .tui_project_session(&project, Some(session))?
            .is_some()
            && let Some(connection) = self.economy().connection.clone()
        {
            let config = self.config_for_broker();
            if let Some(identity) = self.private_context_recipient(&config, &connection) {
                let revision = format!("{}:{identity}", self.effective().sources_digest);
                self.owner
                    .store
                    .record_tui_turn(task, &project, &revision, &connection)?;
            }
        }
        Ok(())
    }

    /// Evidence and the completion guard for a confirmed scoped read. The
    /// observation names the resolved target, not the declared `scoped_file`:
    /// a relative provider path is joined under the bound scope root.
    fn complete_read_with_evidence(
        &mut self,
        read: ConfirmedRead<'_>,
    ) -> Result<StepOutcome, ControllerError> {
        let ConfirmedRead {
            session_id,
            task_id,
            target,
            bytes,
            digest,
            retained_attempt_id,
            effect_attempt,
            grant_id,
            preview,
            auto_reads,
        } = read;
        let observation = format!(
            "read {} bytes from {}; sha256={}",
            bytes.len(),
            target.display(),
            digest
        );
        self.owner.store.insert_evidence_for_task(
            task_id,
            &format!("task:{}", task_id.0),
            &observation,
            digest,
        )?;
        let terminal_attempt_id = retained_attempt_id.unwrap_or(effect_attempt);
        let terminal_boundary_id = crate::verification::terminal_boundary_id(
            &crate::verification::boundary_id(&terminal_attempt_id),
        );
        let terminal = crate::verification::RetainedAttempt {
            attempt_id: terminal_attempt_id.clone(),
            boundary_id: terminal_boundary_id,
            stage: crate::verification::RetainedStage::Terminal,
            cause: observation,
            digest: crate::verification::record_digest(&terminal_attempt_id, "terminal"),
            build_attempt: crate::BUILD_ATTEMPT_ID.to_string(),
            admitted_attempt_id: None,
        };
        self.owner.store.retain_attempt(&terminal)?;
        if self
            .foreground
            .as_ref()
            .is_some_and(|work| &work.task_id == task_id && work.share_reads)
        {
            if self.owner.store.task_is_ui_message(task_id)? {
                return self.auto_share_read(
                    session_id, task_id, target, bytes, digest, grant_id, preview, auto_reads,
                );
            }
            return self.pause_for_file_share(session_id, task_id, target, bytes, digest);
        }
        let snapshot = self.owner.store.complete_if_eligible(session_id, task_id)?;
        Ok(StepOutcome::Completed { snapshot })
    }

    fn pause_for_file_share(
        &mut self,
        session: &SessionId,
        task: &TaskId,
        path: &std::path::Path,
        bytes: &[u8],
        digest: &str,
    ) -> Result<StepOutcome, ControllerError> {
        let (pending, question) = match self.file_share_pending(task, path, bytes, digest)? {
            Ok(pair) => pair,
            Err(outcome) => return Ok(outcome),
        };
        let snapshot = self.owner.store.publish_question(session, &question)?;
        self.file_share = Some(pending);
        Ok(StepOutcome::Waiting { snapshot })
    }

    /// The ordinary-prompt route: the operator's prompt selected this provider
    /// and asked it to work on the project, so project reads are shared with
    /// the same connection without a second card. `/task` keeps the explicit
    /// per-file question in [`Self::pause_for_file_share`].
    #[expect(
        clippy::too_many_arguments,
        reason = "the automatic share carries the read, its grant, the preview sink and the loop bound"
    )]
    fn auto_share_read(
        &mut self,
        session: &SessionId,
        task: &TaskId,
        path: &std::path::Path,
        bytes: &[u8],
        digest: &str,
        grant_id: &str,
        preview: Option<&dyn Fn(&str)>,
        auto_reads: u8,
    ) -> Result<StepOutcome, ControllerError> {
        if auto_reads == 0 {
            return self.refuse_effect(task, "automatic file read limit reached");
        }
        let (share, _) = match self.file_share_pending(task, path, bytes, digest)? {
            Ok(pair) => pair,
            Err(outcome) => return Ok(outcome),
        };
        if self.policy.covers(&share.path) || !self.recipient_current(&share.recipient) {
            return self.refuse_effect(task, "file disclosure recipient or policy changed");
        }
        self.dispatch_shared_read(session, task, share, grant_id, preview, auto_reads)
    }

    /// The one continuation after a read is shared: send the observation to
    /// the model and either offer the next write/check or execute the next
    /// scoped read. The caller's bound makes the recursion finite.
    fn dispatch_shared_read(
        &mut self,
        session: &SessionId,
        task: &TaskId,
        share: PendingFileShare,
        grant_id: &str,
        preview: Option<&dyn Fn(&str)>,
        auto_reads: u8,
    ) -> Result<StepOutcome, ControllerError> {
        let result = self.dispatch_tool_observation(
            session,
            task,
            &share.recipient,
            &share.inputs.to_string(),
            &["read_file", crate::providers::WRITE_FILE_TOOL],
            preview,
        )?;
        let (reply, attempt_id) = match result {
            Ok(result) => result,
            Err(waiting) => return Ok(waiting),
        };
        if let [call] = reply.tool_calls.as_slice()
            && call.tool == crate::providers::WRITE_FILE_TOOL
        {
            return self.offer_file_write(session, task, share, call);
        }
        match self.read_target_from_reply(task, reply, Some(attempt_id))? {
            Ok((target, retained_attempt_id)) => {
                if auto_reads == 0 {
                    return self.refuse_effect(task, "automatic file read limit reached");
                }
                self.execute_read(
                    session,
                    task,
                    target,
                    retained_attempt_id,
                    grant_id,
                    preview,
                    false,
                    auto_reads - 1,
                )
            }
            Err(outcome) => Ok(outcome),
        }
    }

    /// Builds the pending disclosure and its card from the connection that
    /// served the current reply. The gate is shared by the explicit `/task`
    /// card and the ordinary-prompt automatic share, so neither can name a
    /// recipient the other would reject.
    fn file_share_pending(
        &mut self,
        task: &TaskId,
        path: &std::path::Path,
        bytes: &[u8],
        digest: &str,
    ) -> Result<Result<(PendingFileShare, Question), StepOutcome>, ControllerError> {
        let config = self.config_for_broker();
        // The latest served connection is the one the reply came from; the
        // bound profile covers the first dispatch before the economy
        // projection has observed its settlement.
        let selected = self
            .economy()
            .connection
            .clone()
            .or_else(|| self.broker.bound_profile().map(|bound| bound.connection));
        let Some(connection) = selected else {
            return Ok(Err(self.refuse_effect(
                task,
                "file disclosure is unavailable for this connection",
            )?));
        };
        let Some(entry) = config.connections.get(&connection) else {
            return Ok(Err(self.refuse_effect(
                task,
                "file disclosure is unavailable for this connection",
            )?));
        };
        let Some(identity) = self.disclosure_recipient(&config, &connection) else {
            return Ok(Err(self.refuse_effect(
                task,
                "file disclosure requires a verified connection identity",
            )?));
        };
        let endpoint = entry.endpoint.as_str();
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Ok(Err(
                self.refuse_effect(task, "file disclosure requires utf-8")?
            ));
        };
        let display_path = path
            .strip_prefix(&self.scope_root)
            .unwrap_or(path)
            .display();
        let inputs = serde_json::json!({
            "goal": String::from_utf8_lossy(&self.owner.store.goal_bytes(task)?),
            "tool_result": { "tool": "read_file", "path": display_path.to_string(), "text": text },
        });
        let question = Question {
            question_id: QuestionId(format!(
                "{FILE_SHARE_QUESTION}{}",
                crate::contracts::CommandId::generate().0
            )),
            question_revision: 1,
            task_id: task.clone(),
            intent_revision: self.owner.store.snapshot(task)?.intent_revision,
            prompt: format!(
                "Share {display_path} with {connection} at {endpoint}? {} bytes, SHA-256 {digest}",
                bytes.len()
            ),
            options: vec![
                QuestionOption {
                    option_id: OptionId("keep-local".to_string()),
                    label: "Keep local".to_string(),
                    consequences: "The file contents stay in this process.".to_string(),
                    availability: Availability::Enabled,
                },
                QuestionOption {
                    option_id: OptionId(SHARE_ONCE.to_string()),
                    label: "Share once".to_string(),
                    consequences: "Send this read result to the named connection.".to_string(),
                    availability: Availability::Enabled,
                },
            ],
            recommended_option_id: OptionId("keep-local".to_string()),
            recommendation_basis: "File read permission does not authorize disclosure.".to_string(),
        };
        let pending = PendingFileShare {
            question: question.question_id.clone(),
            task: task.clone(),
            path: path.to_path_buf(),
            digest: digest.to_string(),
            recipient: ApprovedRecipient {
                connection: connection.clone(),
                endpoint: endpoint.to_string(),
                config_revision: self.effective().sources_digest.clone(),
                identity,
            },
            inputs,
        };
        Ok(Ok((pending, question)))
    }

    fn resume_file_share(
        &mut self,
        session: &SessionId,
        task: &TaskId,
        question: &QuestionId,
        answer: &AnswerSelection,
        preview: Option<&dyn Fn(&str)>,
    ) -> Result<Result<(PathBuf, Option<String>), StepOutcome>, ControllerError> {
        let Some(share) = self.file_share.take_if(|share| &share.question == question) else {
            return Ok(Err(
                self.refuse_effect(task, "file disclosure approval is stale")?
            ));
        };
        if !matches!(answer, AnswerSelection::Option { option_id } if option_id.0 == SHARE_ONCE) {
            return Ok(Err(self.refuse_effect(
                task,
                "permission denied; file contents kept local",
            )?));
        }
        let Some(work) = self
            .foreground
            .as_mut()
            .filter(|work| &work.task_id == task)
        else {
            return Ok(Err(self.refuse_effect(
                task,
                "file disclosure requires the active terminal",
            )?));
        };
        work.share_reads = true;
        if self.policy.covers(&share.path) || !self.recipient_current(&share.recipient) {
            return Ok(Err(self.refuse_effect(
                task,
                "file disclosure recipient or policy changed",
            )?));
        }
        let result = self.dispatch_tool_observation(
            session,
            task,
            &share.recipient,
            &share.inputs.to_string(),
            &["read_file", crate::providers::WRITE_FILE_TOOL],
            preview,
        )?;
        let (reply, attempt_id) = match result {
            Ok(result) => result,
            Err(waiting) => return Ok(Err(waiting)),
        };
        if let [call] = reply.tool_calls.as_slice()
            && call.tool == crate::providers::WRITE_FILE_TOOL
        {
            return Ok(Err(self.offer_file_write(session, task, share, call)?));
        }
        self.read_target_from_reply(task, reply, Some(attempt_id))
    }

    fn recipient_current(&self, recipient: &ApprovedRecipient) -> bool {
        recipient.config_revision == self.effective().sources_digest
            && self
                .disclosure_recipient(&self.config_for_broker(), &recipient.connection)
                .is_some_and(|identity| identity == recipient.identity)
            && self.policy.decide(
                std::path::Path::new(&recipient.endpoint),
                EffectClass::Egress,
                &crate::policy::AdmissionContext {
                    mode: crate::policy::PermissionMode::Manual,
                    in_grant_scope: false,
                    budget_remaining: false,
                    in_trusted_scope: false,
                    has_checkpoint: false,
                    previously_approved: false,
                    within_declared_bounds: false,
                    dry_run: false,
                },
            ) != crate::policy::ModeDecision::Deny
    }

    fn dispatch_tool_observation(
        &mut self,
        session: &SessionId,
        task: &TaskId,
        recipient: &ApprovedRecipient,
        inputs: &str,
        tools: &[&str],
        preview: Option<&dyn Fn(&str)>,
    ) -> Result<Result<(ProviderReply, String), StepOutcome>, ControllerError> {
        use crate::config::{FallbackAssign, ModelAssign};
        let purpose = self.purpose.clone();
        let mut config = self.config_for_broker();
        let mut model = config
            .resolve_purpose(&purpose)
            .map_err(ModelError::from)?
            .model;
        if !matches!(&model, ModelAssign::Fixed(pin) if pin.connection == recipient.connection) {
            model = ModelAssign::Auto {
                pool: Some(vec![recipient.connection.clone()]),
            };
        }
        let row = config.models.purposes.entry(purpose.clone()).or_default();
        row.model = Some(model);
        row.pool = Some(vec![recipient.connection.clone()]);
        row.fallback = Some(FallbackAssign::Off);
        let world = self.scope_root.display().to_string();
        let facts = self.ranking_facts(task, inputs)?;
        let manifest = self.broker.prepare_call_with_facts(
            &purpose,
            &config,
            &world,
            inputs,
            &crate::model::CallContract {
                instructions: crate::model::PROJECT_RESULT_INSTRUCTIONS,
                tools,
            },
            &facts,
        )?;
        if let Some(cancelled) = self.foreground_cancellation(session, task)? {
            self.broker.cancel_attempt(&manifest.attempt_id);
            return Ok(Err(cancelled));
        }
        self.retain_pre_effect(&manifest.attempt_id, "approved tool continuation")?;
        let scopes = self.budget_scopes(task)?;
        let sent = {
            let mut ledger = crate::state::StoreLedger::new(&mut self.owner.store, scopes);
            self.broker.dispatch_with_preview(
                &mut ledger,
                &world,
                &manifest,
                foreground_signal(self.foreground.as_ref(), task),
                preview,
            )
        };
        if let Some(stopped) = self.note_send_outcome(session, task, &sent, Some(&manifest))? {
            return Ok(Err(stopped));
        }
        let reply = sent?;
        self.provider_calls += 1;
        if let Some(cancelled) = self.foreground_cancellation(session, task)? {
            return Ok(Err(cancelled));
        }
        Ok(Ok((reply, manifest.attempt_id)))
    }

    fn offer_file_write(
        &mut self,
        session: &SessionId,
        task: &TaskId,
        share: PendingFileShare,
        call: &crate::providers::ToolCall,
    ) -> Result<StepOutcome, ControllerError> {
        use sha2::Digest as _;
        let (Some(path), Some(text)) = (&call.path, &call.text) else {
            return self.refuse_effect(task, "invalid file replacement");
        };
        let target = self.scope_root.join(path);
        if target != share.path || self.policy.covers(&target) {
            return self.refuse_effect(
                task,
                "file replacement requires a scoped read of the same path",
            );
        }
        let Ok(identity) = crate::executor::write_target_identity(&self.scope_root, &target) else {
            return self.refuse_effect(task, "file replacement target is unavailable");
        };
        if identity.reuse().is_err() || text.len() > crate::executor::macos::WRITE_MAX_BYTES {
            return self.refuse_effect(task, "file replacement cannot be verified on this target");
        }
        let digest = crate::config::hex(&sha2::Sha256::digest(text.as_bytes()));
        let deny = OptionId("deny".to_string());
        let question = Question {
            question_id: QuestionId(format!(
                "{FILE_WRITE_QUESTION}{}",
                crate::contracts::CommandId::generate().0
            )),
            question_revision: 1,
            task_id: task.clone(),
            intent_revision: self.owner.store.snapshot(task)?.intent_revision,
            prompt: format!(
                "Write {path}? Replace with {} bytes, SHA-256 {digest}",
                text.len()
            ),
            options: vec![
                QuestionOption {
                    option_id: deny.clone(),
                    label: "Deny".to_string(),
                    consequences: "Keep the existing project file.".to_string(),
                    availability: Availability::Enabled,
                },
                QuestionOption {
                    option_id: OptionId(ALLOW_WRITE.to_string()),
                    label: "Allow once".to_string(),
                    consequences: "Apply this exact replacement to the named file.".to_string(),
                    availability: Availability::Enabled,
                },
            ],
            recommended_option_id: deny,
            recommendation_basis: "A replacement requires explicit authorization.".to_string(),
        };
        let snapshot = self.owner.store.publish_question(session, &question)?;
        let original = share
            .inputs
            .pointer("/tool_result/text")
            .and_then(serde_json::Value::as_str);
        let mut summary = format!(
            "Original SHA-256 {}; {} proposed bytes (SHA-256 {digest}).",
            share.digest,
            text.len()
        );
        let preview = match preview::replacement(path, original, text) {
            Ok(diff) => Some(diff),
            Err(reason) => {
                summary.push(' ');
                summary.push_str(reason);
                None
            }
        };
        self.file_write = Some(PendingFileWrite {
            question: question.question_id,
            session: session.clone(),
            summary,
            preview,
            task: task.clone(),
            edit: crate::executor::ProjectEdit {
                identity,
                original_digest: share.digest,
            },
            path: target,
            bytes: text.as_bytes().to_vec(),
            recipient: share.recipient,
        });
        Ok(StepOutcome::Waiting { snapshot })
    }

    fn resume_file_write(
        &mut self,
        session: &SessionId,
        task: &TaskId,
        question: &QuestionId,
        answer: &AnswerSelection,
    ) -> Result<Result<(PathBuf, Option<String>), StepOutcome>, ControllerError> {
        let pending = self
            .file_write
            .take_if(|write| &write.question == question && &write.task == task);
        if !matches!(answer, AnswerSelection::Option { option_id } if option_id.0 == ALLOW_WRITE) {
            return Ok(Err(
                self.refuse_effect(task, "permission denied; file unchanged")?
            ));
        }
        let Some(write) = pending else {
            return Ok(Err(
                self.refuse_effect(task, "file replacement approval is stale")?
            ));
        };
        let Some(cancel) = self
            .foreground
            .as_ref()
            .filter(|work| &work.task_id == task)
            .map(|work| std::sync::Arc::clone(&work.cancel))
        else {
            return Ok(Err(self.refuse_effect(
                task,
                "file replacement requires the active terminal",
            )?));
        };
        if !self.recipient_current(&write.recipient) || self.policy.covers(&write.path) {
            return Ok(Err(self.refuse_effect(
                task,
                "file replacement scope or policy changed",
            )?));
        }
        let applied = self.apply_file_write(task, write.path, write.bytes, &write.edit, &cancel);
        if let Some(cancelled) = self.foreground_cancellation(session, task)? {
            return Ok(Err(cancelled));
        }
        let (detail, path) = applied?;
        let projected = path
            .strip_prefix(&self.scope_root)
            .unwrap_or(&path)
            .display()
            .to_string();
        if !self.recipient_current(&write.recipient) {
            if let Some(work) = self.foreground.as_mut() {
                work.reply = Some(format!(
                    "Written {projected}. Provider continuation blocked by policy."
                ));
            }
            self.owner.store.mark_no_ready(task)?;
            return Ok(Err(StepOutcome::Waiting {
                snapshot: self.owner.store.snapshot(task)?,
            }));
        }
        if let Some(work) = self.foreground.as_mut() {
            work.reply = Some(format!("Written {projected}."));
        }
        let inputs = serde_json::json!({
            "goal": String::from_utf8_lossy(&self.owner.store.goal_bytes(task)?),
            "tool_result": { "tool": "write_file", "path": projected, "detail": detail },
        })
        .to_string();
        match self.dispatch_tool_observation(
            session,
            task,
            &write.recipient,
            &inputs,
            &[crate::providers::RUN_CHECK_TOOL],
            None,
        )? {
            Ok((reply, attempt)) => {
                if let [call] = reply.tool_calls.as_slice()
                    && call.tool == crate::providers::RUN_CHECK_TOOL
                    && let Some(selector) = &call.test
                {
                    return Ok(Err(self.offer_project_check(
                        session,
                        task,
                        write.recipient,
                        selector,
                    )?));
                }
                self.read_target_from_reply(task, reply, Some(attempt))
            }
            Err(waiting) => Ok(Err(waiting)),
        }
    }

    fn apply_file_write(
        &mut self,
        task: &TaskId,
        path: PathBuf,
        bytes: Vec<u8>,
        edit: &crate::executor::ProjectEdit,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<(String, PathBuf), ControllerError> {
        let class = EffectClass::Write;
        let grant = self.policy.grant_once(self.scope_root.clone(), class);
        let result = (|| {
            let scope = path
                .to_str()
                .and_then(|target| crate::policy::preapproval_scope(class, &grant, target))
                .ok_or(ExecutorError::PolicyDenied)?;
            self.owner
                .store
                .record_preapproval(&scope, "terminal", 120)?;
            let request = EffectRequest::Write {
                grant_id: grant.clone(),
                path: path.clone(),
                bytes,
            };
            let mut executor = self.executor();
            let admitted = executor.admit(
                task,
                request,
                crate::policy::PermissionMode::PreapprovedOnly,
            )?;
            if admitted.request.target_path() != path || admitted.request.grant_id() != grant {
                drop(executor);
                self.owner
                    .store
                    .attempt_rejected(&admitted.attempt_id, "write target changed")?;
                return Err(ExecutorError::PolicyDenied.into());
            }
            Ok((
                executor.execute_project_edit(&admitted, edit, cancel)?,
                path,
            ))
        })();
        self.policy.forget_once(&grant);
        result
    }

    fn offer_project_check(
        &mut self,
        session: &SessionId,
        task: &TaskId,
        recipient: ApprovedRecipient,
        selector: &str,
    ) -> Result<StepOutcome, ControllerError> {
        let Some((cargo, cargo_home)) = local_check_toolchain() else {
            return self.refuse_effect(task, "check requires a locally installed Cargo toolchain");
        };
        if !self.scope_root.join("Cargo.toml").is_file() || self.policy.covers(&cargo) {
            return self.refuse_effect(
                task,
                "check requires a Cargo project and an allowed executable",
            );
        }
        let candidate = crate::executor::scoped_workspace_digest(&self.scope_root, &self.policy)
            .map_err(ExecutorError::Check)?;
        let deny = OptionId("deny".to_string());
        let question = Question {
            question_id: QuestionId(format!(
                "{PROJECT_CHECK_QUESTION}{}",
                crate::contracts::CommandId::generate().0
            )),
            question_revision: 1,
            task_id: task.clone(),
            intent_revision: self.owner.store.snapshot(task)?.intent_revision,
            prompt: format!(
                "Run Cargo test {selector} --exact in {} using {}? Library test, locked and offline. Project SHA-256 {candidate}",
                self.scope_root.display(),
                cargo.display()
            ),
            options: vec![
                QuestionOption {
                    option_id: deny.clone(),
                    label: "Deny".to_string(),
                    consequences: "Keep the edit and skip this check.".to_string(),
                    availability: Availability::Enabled,
                },
                QuestionOption {
                    option_id: OptionId(ALLOW_CHECK.to_string()),
                    label: "Allow once".to_string(),
                    consequences: "Run this exact test in a confined project snapshot.".to_string(),
                    availability: Availability::Enabled,
                },
            ],
            recommended_option_id: deny,
            recommendation_basis: "Process execution requires explicit authorization.".to_string(),
        };
        let snapshot = self.owner.store.publish_question(session, &question)?;
        self.project_check = Some(PendingProjectCheck {
            question: question.question_id,
            task: task.clone(),
            cargo,
            cargo_home,
            selector: selector.to_string(),
            candidate,
            recipient,
        });
        Ok(StepOutcome::Waiting { snapshot })
    }

    fn resume_project_check(
        &mut self,
        session: &SessionId,
        task: &TaskId,
        question: &QuestionId,
        answer: &AnswerSelection,
    ) -> Result<Result<(PathBuf, Option<String>), StepOutcome>, ControllerError> {
        let pending = self
            .project_check
            .take_if(|check| &check.question == question && &check.task == task);
        if !matches!(answer, AnswerSelection::Option { option_id } if option_id.0 == ALLOW_CHECK) {
            return Ok(Err(
                self.refuse_effect(task, "permission denied; check not run")?
            ));
        }
        let Some(pending) = pending else {
            return Ok(Err(self.refuse_effect(task, "check approval is stale")?));
        };
        let Some(cancel) = self
            .foreground
            .as_ref()
            .filter(|work| &work.task_id == task)
            .map(|work| std::sync::Arc::clone(&work.cancel))
        else {
            return Ok(Err(
                self.refuse_effect(task, "check requires the active terminal")?
            ));
        };
        if !self.recipient_current(&pending.recipient) {
            return Ok(Err(self.refuse_effect(task, "check configuration changed")?));
        }
        let observed_run = self.run_approved_check(session, &pending, &cancel);
        if let Some(cancelled) = self.foreground_cancellation(session, task)? {
            return Ok(Err(cancelled));
        }
        let run = observed_run?;
        let status = match (run.exit_code, run.signal) {
            (Some(code), _) => format!("exit {code}"),
            (_, Some(signal)) => format!("signal {signal}"),
            (None, None) => "exit unknown".to_string(),
        };
        let observed = format!("Cargo test {}: {status}.", pending.selector);
        let mut output = observed.clone();
        if self.recipient_current(&pending.recipient) {
            let inputs = serde_json::json!({
                "goal": String::from_utf8_lossy(&self.owner.store.goal_bytes(task)?),
                "tool_result": { "tool": "run_check", "exit_code": run.exit_code, "signal": run.signal },
            }).to_string();
            match self.dispatch_tool_observation(
                session,
                task,
                &pending.recipient,
                &inputs,
                &[],
                None,
            ) {
                Ok(Ok((reply, _))) if !reply.text.trim().is_empty() => {
                    output = format!("{observed}\n{}", reply.text);
                }
                Ok(Err(waiting)) => return Ok(Err(waiting)),
                Err(error) => {
                    output = format!(
                        "{observed}\nProvider summary unavailable: {}.",
                        error.error_code().as_str()
                    );
                }
                Ok(Ok(_)) => {}
            }
        }
        if let Some(work) = self.foreground.as_mut() {
            work.reply = Some(output);
        }
        self.owner.store.mark_no_ready(task)?;
        Ok(Err(StepOutcome::Waiting {
            snapshot: self.owner.store.snapshot(task)?,
        }))
    }

    fn run_approved_check(
        &mut self,
        session: &SessionId,
        pending: &PendingProjectCheck,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<crate::executor::CheckRun, ControllerError> {
        use crate::actions::{
            ActionRegistry, ContractBasis, PlanRequest, RequestKind, Surface, SurfaceScan, WorkPart,
        };
        use crate::executor::{CheckTarget, ConfinedCheck};
        let task = &pending.task;
        let handoff = self.check_handoff(task);
        let revision = if handoff.explicit_off() {
            0
        } else {
            let config = self.config_for_broker();
            let criteria = self
                .owner
                .store
                .snapshot(task)?
                .criteria
                .items
                .into_iter()
                .map(|criterion| criterion.id)
                .collect();
            let selection = ActionRegistry::new().select(
                &PlanRequest {
                    task_id: task.clone(),
                    kind: RequestKind::Change,
                    surfaces: SurfaceScan::Known([Surface::Local].into()),
                    contract: ContractBasis::Approved,
                    parts: vec![WorkPart {
                        id: "check".to_string(),
                        criteria,
                        depends_on: Vec::new(),
                        proof: format!(
                            "cargo test --lib --locked --offline -- --exact {}",
                            pending.selector
                        ),
                    }],
                    delegation: None,
                    author: None,
                },
                &[],
                &mut self.action_context(session, &config),
            )?;
            selection.revision
        };
        let read = self
            .policy
            .grant_once(self.scope_root.clone(), EffectClass::Read);
        let exec = self
            .policy
            .grant_once(pending.cargo.clone(), EffectClass::Exec);
        let result = (|| {
            for (class, grant, path) in [
                (EffectClass::Exec, &exec, &pending.cargo),
                (EffectClass::Read, &read, &self.scope_root),
            ] {
                let scope = path
                    .to_str()
                    .and_then(|target| crate::policy::preapproval_scope(class, grant, target))
                    .ok_or(ExecutorError::PolicyDenied)?;
                self.owner
                    .store
                    .record_preapproval(&scope, "terminal", 120)?;
            }
            let check = ConfinedCheck {
                task_id: task.clone(),
                expected_selection_revision: revision,
                project_grant_id: read.clone(),
                project_root: self.scope_root.clone(),
                manifest_rel: PathBuf::from("Cargo.toml"),
                cargo: pending.cargo.clone(),
                cargo_home: pending.cargo_home.clone(),
                target: CheckTarget::Library,
                harness_threads: 1,
                exact_test: pending.selector.clone(),
                expected_phase: "project-check".to_string(),
                expected_assertion_identity: pending.selector.clone(),
                expected_candidate_digest: pending.candidate.clone(),
            };
            let mut executor = self.executor();
            let mut admission = executor.admit_check(
                task,
                EffectRequest::Exec {
                    grant_id: exec.clone(),
                    program: pending.cargo.clone(),
                },
                crate::policy::PermissionMode::PreapprovedOnly,
                &check,
                &handoff,
            )?;
            let run = executor.execute_check(&mut admission, &check, cancel)?;
            self.owner
                .store
                .attempt_confirmed(&admission.admitted().attempt_id)?;
            Ok(run)
        })();
        self.policy.forget_once(&read);
        self.policy.forget_once(&exec);
        result
    }

    fn refuse_effect(
        &mut self,
        task: &TaskId,
        reason: &'static str,
    ) -> Result<StepOutcome, ControllerError> {
        self.owner.store.mark_no_ready(task)?;
        if let Some(work) = self
            .foreground
            .as_mut()
            .filter(|work| &work.task_id == task)
        {
            work.reply = Some(format!("{reason}."));
        }
        Ok(StepOutcome::EffectDenied {
            reason: reason.to_string(),
            snapshot: self.owner.store.snapshot(task)?,
        })
    }

    /// DEC-068 sentinel tail: the frozen answer is the only applicability
    /// input the interim driver has; the sentinel option reports the
    /// evaluation returned unknown/error. Every obligation is marked
    /// unresolved — execution untouched, so this never impersonates the
    /// stale-evidence leg — and the step fails so `scheduler_step`'s Err
    /// arm feeds the supervisor (INV-020: observation only, the
    /// supervisor never dispatches).
    fn fail_applicability(&mut self, task_id: &TaskId) -> Result<(), ControllerError> {
        let obligations: Vec<String> = self
            .owner
            .store
            .snapshot(task_id)?
            .obligations
            .items
            .iter()
            .map(|obligation| obligation.id.clone())
            .collect();
        for obligation_id in obligations {
            self.owner
                .store
                .mark_applicability_unresolved(&obligation_id)?;
        }
        Err(ControllerError::ApplicabilityUnknown)
    }

    fn retain_pre_effect(&mut self, attempt_id: &str, cause: &str) -> Result<(), ControllerError> {
        let pre = crate::verification::RetainedAttempt {
            attempt_id: attempt_id.to_string(),
            boundary_id: crate::verification::boundary_id(attempt_id),
            stage: crate::verification::RetainedStage::PreEffect,
            cause: cause.to_string(),
            digest: crate::verification::record_digest(attempt_id, "pre"),
            build_attempt: crate::BUILD_ATTEMPT_ID.to_string(),
            admitted_attempt_id: None,
        };
        self.owner.store.retain_attempt(&pre)?;
        Ok(())
    }

    /// Runs one granted environment restore for a recorded setup gap.
    /// Every admission or execution failure is retained before it is
    /// returned, and success hands back the original unchanged check.
    ///
    /// # Errors
    /// Returns the typed action, executor, or store error that stopped
    /// preparation after retaining any failure evidence.
    pub fn prepare_environment(
        &mut self,
        session_id: &SessionId,
        input: crate::actions::PrepareEnvironmentInput,
        mode: crate::policy::PermissionMode,
    ) -> Result<PreparedEnvironment, ControllerError> {
        let config = self.config_for_broker();
        let task_id = input.task_id.clone();
        let check_id = input.check_id.clone();
        let outcome = crate::actions::ActionRegistry::new().execute(
            crate::actions::ActionInput::PrepareEnvironment(input),
            &mut self.action_context(session_id, &config),
        )?;
        let crate::actions::ActionOutcome::EnvironmentRequested { restore, original } = outcome
        else {
            return Err(ControllerError::UnexpectedEnvironmentOutcome);
        };
        let pending = crate::verification::assumption_pre_effect(&task_id, &check_id);
        self.owner.store.retain_attempt(&pending)?;
        let request = EffectRequest::Write {
            grant_id: restore.grant_id,
            path: restore.target,
            bytes: restore.replacement,
        };
        let admission = {
            let mut executor = self.executor();
            executor.admit(&task_id, request, mode)
        };
        let admitted = match admission {
            Ok(admitted) => admitted,
            Err(error) => {
                self.retain_environment_failure(&pending, error.error_code().as_str(), None)?;
                return Err(error.into());
            }
        };
        let effect = {
            let mut executor = self.executor();
            executor.execute(&admitted)
        };
        match effect {
            Ok(EffectOutcome::Executed { detail }) => {
                let mut evidence = crate::verification::assumption_restore_outcome(
                    &pending,
                    "environment restore completed",
                    Some(&admitted.attempt_id),
                );
                evidence.digest = crate::verification::record_digest(&evidence.attempt_id, &detail);
                self.owner.store.retain_attempt(&evidence)?;
                Ok(PreparedEnvironment {
                    attempt_id: admitted.attempt_id,
                    original,
                })
            }
            Ok(EffectOutcome::Denied { reason: _ }) => {
                self.retain_environment_failure(
                    &pending,
                    ErrorCode::Denied.as_str(),
                    Some(&admitted.attempt_id),
                )?;
                Err(ControllerError::EnvironmentDenied {
                    reason: "effect denied".to_string(),
                })
            }
            Ok(EffectOutcome::Read { .. }) => {
                self.retain_environment_failure(
                    &pending,
                    ErrorCode::InternalError.as_str(),
                    Some(&admitted.attempt_id),
                )?;
                Err(ControllerError::UnexpectedEnvironmentOutcome)
            }
            Err(error) => {
                let cause = error.owned_cause();
                if let Err(secondary) = self.retain_environment_failure(
                    &pending,
                    cause.as_deref().unwrap_or(error.error_code().as_str()),
                    Some(&admitted.attempt_id),
                ) {
                    return Err(ControllerError::EnvironmentRetention {
                        primary: error,
                        secondary: Box::new(secondary),
                    });
                }
                Err(error.into())
            }
        }
    }

    fn retain_environment_failure(
        &mut self,
        pending: &crate::verification::RetainedAttempt,
        cause: &str,
        admitted_attempt_id: Option<&str>,
    ) -> Result<(), ControllerError> {
        let evidence =
            crate::verification::assumption_restore_outcome(pending, cause, admitted_attempt_id);
        self.owner.store.retain_attempt(&evidence)?;
        Ok(())
    }

    /// Safe reconciliation of an unknown attempt: validates the attempt
    /// exists for this task, is `unknown`, and its detail carries a
    /// parseable `read-performed sha256=` marker. The marker's real digest
    /// drives the evidence and retained record; the bool can never reject a
    /// marker that proves execution, and a settled attempt cannot reconcile
    /// twice.
    pub fn reconcile_unknown(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        attempt_id: &str,
        _executed: bool,
    ) -> Result<TaskSnapshot, StoreError> {
        let record = self
            .owner
            .store
            .attempt_record(attempt_id)?
            .ok_or_else(|| StoreError::missing_attempt(attempt_id))?;
        let (owner_task, state, detail) = record;
        if owner_task != task_id.0 {
            return Err(StoreError::InvalidInput(
                InvalidCause::AttemptTaskMismatch {
                    attempt_id: attempt_id.to_string(),
                    owner_task,
                    expected: task_id.0.clone(),
                },
            ));
        }
        if state != "unknown" {
            return Err(StoreError::Conflict(
                ConflictCause::AttemptNotReconcileable {
                    attempt_id: attempt_id.to_string(),
                    state,
                },
            ));
        }
        let marker = detail
            .as_deref()
            .and_then(read_performed_digest)
            .ok_or_else(|| {
                StoreError::InvalidInput(InvalidCause::MissingReadMarker {
                    attempt_id: attempt_id.to_string(),
                })
            })?;
        // The marker proves execution; the informational bool can never
        // reject it.
        let boundary_id = crate::verification::terminal_boundary_id(
            &crate::verification::boundary_id(attempt_id),
        );
        let terminal = crate::verification::RetainedAttempt {
            attempt_id: attempt_id.to_string(),
            boundary_id,
            stage: crate::verification::RetainedStage::Terminal,
            cause: format!("attempt {attempt_id} reconciled as executed from sha256={marker}"),
            digest: marker.clone(),
            build_attempt: crate::BUILD_ATTEMPT_ID.to_string(),
            admitted_attempt_id: None,
        };
        self.owner.store.retain_attempt(&terminal)?;
        self.owner.store.set_attempt_state(
            attempt_id,
            "confirmed",
            Some(&format!("read-performed sha256={marker}")),
        )?;
        self.owner.store.insert_evidence_for_task(
            task_id,
            &format!("task:{}", task_id.0),
            &format!("reconciled attempt {attempt_id} from sha256={marker}"),
            &marker,
        )?;
        self.owner.store.complete_if_eligible(session_id, task_id)
    }

    /// One bounded scheduler pass over the task tree: pending
    /// notification deliveries drain first — cancellation and other
    /// signals outrank work — then the next admitted node runs exactly
    /// one decision step. A parent with unfinished children never
    /// spends the slot it is about to wait on: it releases the slot
    /// inside this loop before waiting (PROH-002), and the freed slot
    /// admits the next ready node in the same pass. Deliveries can only
    /// ever fail closed: no delivery admits or requeues work by itself,
    /// so a late callback on a cancelled tree is observed and discarded
    /// (AC-012). Every step outcome settles the node: a completed run
    /// completes the node, anything else — denied, no action, unknown,
    /// or a wait with no runnable children — settles it without holding
    /// a slot, and a failed decision step settles the node before its
    /// error propagates. A fresh intent submits a fresh node.
    pub fn scheduler_step(
        &mut self,
        session_id: &SessionId,
    ) -> Result<SchedulerStep, ControllerError> {
        self.scheduler_step_with_preview(session_id, None)
    }

    fn scheduler_step_with_preview(
        &mut self,
        session_id: &SessionId,
        preview: Option<&dyn Fn(&str)>,
    ) -> Result<SchedulerStep, ControllerError> {
        for delivery in self.notifications.drain(SCHEDULER_DRAIN_LIMIT) {
            match delivery {
                Delivery::Event(event) => {
                    self.scheduler.deliver(&event);
                }
                // The queue replaced an overflowed backlog with one
                // marker; admission never depends on delivery history,
                // so the marker observes the loss without acting on it.
                Delivery::ResyncMarker => {}
            }
        }
        let node = loop {
            let Some(node) = self.scheduler.admit_next() else {
                return Ok(SchedulerStep::Idle);
            };
            if matches!(
                self.scheduler.begin_wait(node)?,
                WaitTransition::AlreadySatisfied
            ) {
                break node;
            }
        };
        let context = self.scheduler.node_context(node)?;
        let outcome = match self.run_decision_step_with_preview(
            session_id,
            &context.task,
            &context.answer,
            &context.grant_id,
            false,
            preview,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                // The node settles before the error propagates: a
                // failed decision step must release its slot and
                // reservation, or two of them would stall the tree.
                self.scheduler.settle(node)?;
                // The failed step feeds the same outcome stream
                // (AC-011, DEC-016): the error's typed fingerprint
                // reaches the detectors — an Err never bypasses the
                // feed — and its reaction lands after the node
                // settled, like every other observation.
                let observation = step_error_observation(&context.task, &context.answer, &error);
                if let Some(reaction) = self.supervisor.observe(&self.scheduler, observation) {
                    self.owner.store.record_supervisor_reaction(&reaction)?;
                }
                return Err(error);
            }
        };
        if matches!(outcome, StepOutcome::Completed { .. }) {
            self.clear_budget_wait(session_id, &context.task);
            self.scheduler.complete(node)?;
        } else {
            self.scheduler.settle(node)?;
        }
        // The supervisor reads the same outcome stream the scheduler
        // just settled on (AC-011, DEC-016): every StepOutcome variant
        // feeds its typed observation fingerprint — the only permitted
        // action class is the scoped read, and the frozen answer names
        // the inputs that produced the attempt. The one bounded
        // reaction goes straight to the durable journal — after the
        // node settled, so a journal failure can never strand a
        // running node. The supervisor never dispatches (INV-020):
        // the mapping is observation-only, never a second planner.
        let observation = step_outcome_observation(&context.task, &context.answer, &outcome);
        if let Some(reaction) = self.supervisor.observe(&self.scheduler, observation) {
            self.owner.store.record_supervisor_reaction(&reaction)?;
        }
        Ok(SchedulerStep::Ran {
            node,
            outcome: Box::new(outcome),
        })
    }

    /// Saves the executed plan and its confirmed executor trace (AC-053).
    /// Semantic plan rows remain readable but cannot authorize replay.
    ///
    /// # Errors
    /// The [`crate::procedure::ProcedureError`] refusals of a plan that never
    /// ran, a superseded plan or an empty executed plan.
    pub fn record_procedure_segment(
        &mut self,
        task_id: &TaskId,
    ) -> Result<crate::procedure::SegmentTemplate, ControllerError> {
        Ok(self.owner.store.record_procedure_segment(task_id)?)
    }

    /// One bounded step of a saved segment (AC-053).
    ///
    /// The segment's next step runs through the executor's own admission and
    /// settlement, its result is kept, and the run continues only while the new
    /// snapshot still holds: a fork outside the snapshot, an unresolved effect
    /// or a revoked right stops the remainder, keeps the steps that settled, and
    /// returns the task's snapshot to the normal control path.
    ///
    /// `open` is the caller's answer for a segment that already completed a run:
    /// [`crate::procedure::RunStart::Resume`] refuses it, because every step of a
    /// completed run is an effect that already landed, and only an explicit
    /// [`crate::procedure::RunStart::Fresh`] request runs the segment again.
    ///
    /// # Errors
    /// The store's and the executor's non-stop refusals, and the segment's own
    /// [`crate::procedure::ProcedureError`] (a moved snapshot, an unbound
    /// parameter).
    pub fn run_procedure_step(
        &mut self,
        task_id: &TaskId,
        procedure_id: &str,
        binding: &crate::procedure::SegmentBinding,
        mode: crate::policy::PermissionMode,
        open: crate::procedure::RunStart,
    ) -> Result<SegmentStepOutcome, ControllerError> {
        use crate::procedure::{ProcedureError, SettledStep, StepOutcome, StepStanding, StopCause};
        let segment = self.owner.store.procedure_segment(procedure_id)?;
        if segment.task_id != task_id.0 {
            return Err(ProcedureError::SegmentMissing {
                procedure_id: procedure_id.to_string(),
            }
            .into());
        }
        let live = self.live_segment_snapshot(task_id)?;
        let mut run = self
            .owner
            .store
            .start_procedure_run(&segment, &live, open)?;
        // The step a previous call prepared and did not settle is answered by
        // its own attempt, never by running it again: a step that provably
        // never started is released for its next attempt, one whose effect
        // landed is settled from the ledger, and one that may have landed stops
        // the remainder (PROH-003).
        if let Some(prepared) = self.owner.store.prepared_procedure_step(&run.run_id)? {
            match prepared.standing {
                StepStanding::NotStarted => {
                    self.owner
                        .store
                        .release_unstarted_procedure_step(&run.run_id, prepared.position)?;
                }
                StepStanding::Landed => {
                    run = self
                        .owner
                        .store
                        .settle_procedure_step(&run.run_id, &prepared.settlement())?;
                    if run.state == crate::procedure::RunState::Stopped {
                        return self.receipt_mismatch_outcome(task_id, run);
                    }
                }
                StepStanding::Unresolved => {
                    return self.stop_segment(
                        task_id,
                        &run,
                        StopCause::PreparedStep {
                            position: prepared.position,
                            attempt_id: prepared.attempt_id,
                        },
                    );
                }
            }
        }
        // The new snapshot is re-checked before the step (AC-053): a fork the
        // run's snapshot never held is a material choice the saved segment
        // cannot take on its own, and control returns to the path that already
        // waits on it.
        if live.pending != run.snapshot.pending {
            return self.stop_segment(
                task_id,
                &run,
                StopCause::NewMaterialChoice {
                    pending: live.pending,
                },
            );
        }
        // No-repeat guard, the same one the dispatch decision takes: the newest
        // attempt of this task whose outcome is still unresolved is the durable
        // proof that an effect may have landed, so nothing issues the next one
        // (PROH-003, INV-004).
        if let Some(attempt_id) = self.owner.store.latest_unresolved_attempt(task_id)? {
            return self.stop_segment(task_id, &run, StopCause::UnknownEffect { attempt_id });
        }
        if run.cursor == segment.steps.len() as u64 {
            let run = self.owner.store.complete_procedure_run(&run.run_id)?;
            let snapshot = self.owner.store.snapshot(task_id)?;
            return Ok(SegmentStepOutcome::Completed { run, snapshot });
        }
        for candidate in segment
            .steps
            .iter()
            .filter(|step| step.position > run.cursor)
        {
            let request =
                binding
                    .request(candidate.position)
                    .ok_or(ProcedureError::UnboundParameter {
                        position: candidate.position,
                    })?;
            if !candidate.accepts(request) {
                return Err(ProcedureError::IncompatibleOperation {
                    position: candidate.position,
                }
                .into());
            }
        }
        let step = segment
            .step(run.cursor + 1)
            .ok_or_else(|| ProcedureError::CursorPastSteps {
                procedure_id: segment.procedure_id.clone(),
                cursor: run.cursor,
                steps: u64::try_from(segment.steps.len()).unwrap_or(u64::MAX),
            })?;
        let outcome = {
            let mut executor = self.executor();
            executor.run_segment_step(task_id, &segment, &run, binding, mode)
        };
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                // A failed call proves nothing about the effect: the prepared
                // row's own attempt does, and only a step that provably never
                // started is released for a later attempt (PROH-003).
                self.owner
                    .store
                    .release_unstarted_procedure_step(&run.run_id, step.position)?;
                return Err(error.into());
            }
        };
        let (attempt_id, result) = match outcome {
            StepOutcome::Settled { attempt_id, result } => (attempt_id, result),
            StepOutcome::Stopped(cause) => {
                // A step whose effect was refused ran nothing, so its row is
                // released; a step whose attempt ran keeps its safety record.
                self.owner
                    .store
                    .release_unstarted_procedure_step(&run.run_id, step.position)?;
                return self.stop_segment(task_id, &run, cause);
            }
        };
        let settled = SettledStep {
            position: step.position,
            tool: step.tool.clone(),
            attempt_id,
            result,
        };
        let run = self
            .owner
            .store
            .settle_procedure_step(&run.run_id, &settled)?;
        if run.state == crate::procedure::RunState::Stopped {
            return self.receipt_mismatch_outcome(task_id, run);
        }
        if run.cursor == segment.steps.len() as u64 {
            let run = self.owner.store.complete_procedure_run(&run.run_id)?;
            let snapshot = self.owner.store.snapshot(task_id)?;
            return Ok(SegmentStepOutcome::Completed { run, snapshot });
        }
        Ok(SegmentStepOutcome::Stepped { run, step: settled })
    }

    fn receipt_mismatch_outcome(
        &self,
        task: &TaskId,
        run: crate::procedure::ProcedureRun,
    ) -> Result<SegmentStepOutcome, ControllerError> {
        Ok(SegmentStepOutcome::Stopped {
            cause: crate::procedure::StopCause::ReceiptMismatch {
                position: run.cursor,
            },
            run,
            snapshot: self.owner.store.snapshot(task)?,
        })
    }

    /// The saved segment a task's executed plan names, when this run can start
    /// one (AC-053). The plan revision the task's action resolved is the
    /// segment's key, so a task that never executed a plan — or whose segment
    /// was never saved — keeps the single-step path unchanged. A segment saved
    /// against state this run has moved past is not that segment:
    /// [`crate::procedure::SegmentTemplate::prepare`] refuses it before any
    /// effect (master §12.9), and the task's own step continues instead.
    fn saved_segment(
        &self,
        task_id: &TaskId,
    ) -> Result<Option<crate::procedure::SegmentTemplate>, ControllerError> {
        let Some(plan_revision) = self
            .owner
            .store
            .plan_revisions(task_id)?
            .last()
            .map(|revision| revision.revision)
        else {
            return Ok(None);
        };
        let procedure_id =
            crate::procedure::SegmentTemplate::procedure_id_for(task_id, plan_revision);
        let segment = match self.owner.store.procedure_segment(&procedure_id) {
            Ok(segment) => segment,
            Err(crate::procedure::ProcedureError::SegmentMissing { .. }) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        match segment.prepare(&self.live_segment_snapshot(task_id)?) {
            Ok(()) => Ok(Some(segment)),
            Err(_refused) => Ok(None),
        }
    }

    /// The parameters one run binds into the saved segment come from this run's
    /// own snapshot — the node's scoped read grant and the task's permitted read
    /// target — never from the recording: the saved steps name what ran, the
    /// binding names what this run may do now, and the executor admits every
    /// step again (AC-053, INV-002).
    fn segment_binding(
        &self,
        segment: &crate::procedure::SegmentTemplate,
        grant_id: &str,
    ) -> Option<crate::procedure::SegmentBinding> {
        // This entry point has one live input. Do not collapse distinct source
        // parameters onto it, or substitute a read for another operation.
        if segment
            .steps
            .iter()
            .any(|step| step.operation() != Some(EffectClass::Read) || step.source_input != Some(1))
        {
            return None;
        }
        Some(
            segment
                .steps
                .iter()
                .fold(crate::procedure::SegmentBinding::new(), |binding, step| {
                    binding.bind(
                        step.position,
                        EffectRequest::Read {
                            grant_id: grant_id.to_string(),
                            path: self.scoped_file.clone(),
                        },
                    )
                }),
        )
    }

    /// Runs the remaining steps of a saved segment on this step path (AC-053):
    /// every step enters the executor's own admission and settlement, and the
    /// remainder ends on the first condition the segment honours, so the
    /// completed steps stay stored for the ordinary control path.
    fn run_saved_segment(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        binding: &crate::procedure::SegmentBinding,
        segment: &crate::procedure::SegmentTemplate,
    ) -> Result<StepOutcome, ControllerError> {
        use crate::procedure::{ProcedureError, RunStart};
        let procedure_id = &segment.procedure_id;
        loop {
            // The production step driver still inlines the interim `manual`
            // default (DEC-015) until the Settings surface lands.
            let step = self.run_procedure_step(
                task_id,
                procedure_id,
                binding,
                crate::policy::PermissionMode::Manual,
                RunStart::Resume,
            );
            match step {
                Ok(SegmentStepOutcome::Stepped { .. }) => {}
                Ok(SegmentStepOutcome::Stopped {
                    cause, snapshot, ..
                }) => return Ok(stopped_outcome(cause, snapshot)),
                // Nothing of the segment is left to run — whether this pass
                // settled its last step or an earlier one did — so the task's
                // own completion guard decides what that ends (PROH-003: the
                // steps of a completed run are never issued again).
                Ok(SegmentStepOutcome::Completed { .. })
                | Err(ControllerError::Procedure(ProcedureError::AlreadyCompleted { .. })) => {
                    return Ok(StepOutcome::Completed {
                        snapshot: self.owner.store.complete_if_eligible(session_id, task_id)?,
                    });
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Records the stop, marks the task exactly as the normal path does for that
    /// state, and returns its snapshot.
    fn stop_segment(
        &mut self,
        task_id: &TaskId,
        run: &crate::procedure::ProcedureRun,
        cause: crate::procedure::StopCause,
    ) -> Result<SegmentStepOutcome, ControllerError> {
        let stop = crate::procedure::stop_decision(&cause);
        if matches!(
            cause,
            crate::procedure::StopCause::UnknownEffect { .. }
                | crate::procedure::StopCause::PreparedStep { .. }
        ) {
            // The task's own blocked state and its blocker projection: the same
            // write the unknown-outcome step path already makes.
            self.owner.store.mark_outcome_unknown(task_id)?;
        }
        let run = self.owner.store.stop_procedure_run(&run.run_id, &stop)?;
        let snapshot = self.owner.store.snapshot(task_id)?;
        Ok(SegmentStepOutcome::Stopped {
            run,
            snapshot,
            cause,
        })
    }

    /// The state one saved segment must hold to run now: the live selection and
    /// plan revision, this build's effect tool, and the fork the task waits on.
    fn live_segment_snapshot(
        &self,
        task_id: &TaskId,
    ) -> Result<crate::procedure::SegmentSnapshot, ControllerError> {
        let selection = self.owner.store.plan_selection(task_id)?.ok_or_else(|| {
            crate::procedure::ProcedureError::PlanMissing {
                task_id: task_id.0.clone(),
            }
        })?;
        let plan_revision = self
            .owner
            .store
            .plan_revisions(task_id)?
            .last()
            .map_or(0, |revision| revision.revision);
        let pending = self
            .owner
            .store
            .current_question(task_id)?
            .map(|(question, _)| crate::procedure::PendingFork {
                question_id: question.question_id,
                revision: question.question_revision,
            });
        Ok(crate::procedure::SegmentSnapshot {
            selection_revision: selection.revision,
            plan_revision,
            tool_version: crate::executor::backend().to_string(),
            pending,
        })
    }
}

fn read_performed_digest(detail: &str) -> Option<String> {
    let prefix = "read-performed sha256=";
    let rest = detail.strip_prefix(prefix)?;
    let digest = rest
        .split(|c: char| !c.is_ascii_hexdigit() || c.is_ascii_uppercase())
        .next()
        .unwrap_or_default();
    if digest.len() == 64 {
        Some(digest.to_string())
    } else {
        None
    }
}

fn answer_text(answer: &AnswerSelection) -> String {
    match answer {
        AnswerSelection::Option { option_id } => format!("option:{}", option_id.0),
        AnswerSelection::Custom { text } => text.clone(),
    }
}
