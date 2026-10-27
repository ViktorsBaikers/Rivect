//! Controller: the local reconcile loop between question, broker, executor
//! and evidence. No hidden controller model call: a local check that
//! unblocks the only known admitted action starts it directly, and
//! revocation/cancellation block the next dispatch before any provider
//! effect.

use crate::commands::{PausedAttempt, Runtime};
use crate::contracts::{
    AnswerSelection, Availability, EffectClass, ErrorCode, OptionId, Question, QuestionId,
    QuestionOption, SessionId, TaskId, TaskSnapshot,
};
use crate::executor::{EffectOutcome, EffectRequest, ExecutorError};
use crate::model::{ModelError, PendingFallback, RequestManifest};
use crate::policy::PolicyError;
use crate::resources::{Delivery, OutputSettlement};
use crate::scheduler::{NodeId, SchedulerError, WaitTransition};
use crate::state::{ConflictCause, InvalidCause, StoreError};
use crate::supervisor::{Observation, OperationClass};
use std::path::PathBuf;

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
        | StepOutcome::NoAction { snapshot } => snapshot.clone(),
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
            Self::EnvironmentRetention { .. } => ErrorCode::StorageUnavailable,
            Self::Policy(_) => ErrorCode::Denied,
            Self::Model(ModelError::RequestTooLarge { .. }) => ErrorCode::ContextOverflow,
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
        StepOutcome::Waiting { .. } | StepOutcome::NoAction { .. } => None,
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

impl Runtime {
    pub fn drain_scheduler(&mut self, session_id: &SessionId) -> Result<(), ControllerError> {
        for _ in 0..SCHEDULER_DRAIN_LIMIT {
            match self.scheduler_step(session_id)? {
                SchedulerStep::Idle => return Ok(()),
                SchedulerStep::Ran { .. } => {}
            }
        }
        Ok(())
    }

    /// One decision step for a task whose pending question has been
    /// answered: the broker dispatches the frozen manifest once, the only
    /// permitted action is a scoped read, evidence and the completion guard
    /// close the loop. `crash_after_dispatch` emulates process death after
    /// the durable dispatched record, before effect confirmation.
    pub fn run_decision_step(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        answer: &AnswerSelection,
        grant_id: &str,
        crash_after_dispatch: bool,
    ) -> Result<StepOutcome, ControllerError> {
        if let Some(gated) = self.gate_decision_dispatch(task_id, grant_id)? {
            return Ok(gated);
        }
        if matches!(
            answer,
            AnswerSelection::Option { option_id }
                if option_id.0.as_str() == APPLICABILITY_UNKNOWN_OPTION
        ) {
            self.fail_applicability(task_id)?;
        }
        let (target, retained_attempt_id) =
            match self.resolve_read_target(session_id, task_id, answer)? {
                Ok(pair) => pair,
                Err(waiting) => return Ok(waiting),
            };
        let request = EffectRequest::Read {
            grant_id: grant_id.to_string(),
            path: target,
        };
        let admitted = {
            let mut executor = crate::executor::Executor::new(
                &mut self.policy,
                &mut self.owner.store,
                self.read_worker.as_mut(),
            );
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
        let mut executor = crate::executor::Executor::new(
            &mut self.policy,
            &mut self.owner.store,
            self.read_worker.as_mut(),
        );
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
            Ok(EffectOutcome::Read { bytes, digest }) => self.complete_read_with_evidence(
                session_id,
                task_id,
                &bytes,
                &digest,
                retained_attempt_id,
                effect_attempt,
            ),
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
            SchedulerStep::Ran { node: ran, outcome } if ran == node => {
                Ok(ContinuationOutcome::Resumed {
                    snapshot: Box::new(step_snapshot(&outcome)),
                    context_bytes: context.text.len(),
                })
            }
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
        task_id: &TaskId,
        grant_id: &str,
    ) -> Result<Option<StepOutcome>, ControllerError> {
        if self.owner.store.task_lifecycle(task_id)?.is_terminal() {
            let snapshot = self.owner.store.snapshot(task_id)?;
            return Ok(Some(StepOutcome::NoAction { snapshot }));
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
        let chosen = match answer {
            AnswerSelection::Option { option_id } => {
                let answered = self.owner.store.latest_applied_answer_question(task_id)?;
                self.paused_attempts
                    .get(&task_id.0)
                    .filter(|paused| {
                        answered.is_some()
                            && paused.served_question_id == answered
                            && paused
                                .choice
                                .as_ref()
                                .is_some_and(|choice| choice.candidates.contains(&option_id.0))
                    })
                    .map(|paused| (paused.manifest.attempt_id.clone(), option_id.0.clone()))
            }
            AnswerSelection::Custom { .. } => None,
        };
        if let Some((attempt_id, connection)) = chosen {
            let reply = self
                .broker
                .dispatch_fallback_choice(&world, &attempt_id, &connection)?;
            self.provider_calls += 1;
            self.paused_attempts.remove(&task_id.0);
            return self.read_target_from_reply(task_id, reply, Some(attempt_id));
        }
        if matches!(answer, AnswerSelection::Option { .. }) {
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
        let inputs = format!(
            "goal: {}\nanswer: {}\nread {}",
            String::from_utf8_lossy(&self.owner.store.goal_bytes(task_id)?),
            answer_text(answer),
            self.scoped_file.display()
        );
        let manifest = self
            .broker
            .prepare(&purpose, &self.config_for_broker(), &world, &inputs)?;
        self.retain_pre_effect(&manifest.attempt_id, "first useful offline dispatch")?;
        match self.broker.dispatch(&world, &manifest) {
            Ok(reply) => {
                self.provider_calls += 1;
                // The send landed: any attempt this task was paused on
                // is superseded — tombstone it so a late retry of its
                // frozen manifest is refused, not resurrected.
                self.tombstone_paused(task_id);
                self.read_target_from_reply(task_id, reply, Some(manifest.attempt_id))
            }
            Err(ModelError::ManualFallbackPending { .. }) => {
                self.pause_on_fallback_choice(session_id, task_id, manifest)
            }
            Err(source) => {
                // Every dispatch error leaves the primary's admission
                // live — the task pauses on a still-retryable attempt
                // that no question served, so nothing can answer it
                // into a dispatch.
                self.record_pause(task_id, manifest, None, None);
                Err(source.into())
            }
        }
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
            prompt: "the pinned dispatch failed; choose the fallback connection".to_string(),
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
            recommendation_basis: "candidates passing the current eligibility check".to_string(),
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
        reply: crate::providers::ProviderReply,
        retained_attempt_id: Option<String>,
    ) -> Result<Result<(PathBuf, Option<String>), StepOutcome>, ControllerError> {
        let Some(call) = reply.tool_calls.iter().find(|c| c.tool == "read_file") else {
            self.owner.store.mark_no_ready(task_id)?;
            let snapshot = self.owner.store.snapshot(task_id)?;
            return Ok(Err(StepOutcome::Waiting { snapshot }));
        };
        Ok(Ok((
            self.scope_root
                .join(call.path.as_deref().unwrap_or_default()),
            retained_attempt_id,
        )))
    }

    /// Evidence and the completion guard for a confirmed scoped read.
    /// The observation names `scoped_file`, the dispatch's permitted
    /// action, not the worker target the grant already bound.
    fn complete_read_with_evidence(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        bytes: &[u8],
        digest: &str,
        retained_attempt_id: Option<String>,
        effect_attempt: String,
    ) -> Result<StepOutcome, ControllerError> {
        let observation = format!(
            "read {} bytes from {}; sha256={}",
            bytes.len(),
            self.scoped_file.display(),
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
        let snapshot = self.owner.store.complete_if_eligible(session_id, task_id)?;
        Ok(StepOutcome::Completed { snapshot })
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
            let mut executor = crate::executor::Executor::new(
                &mut self.policy,
                &mut self.owner.store,
                self.read_worker.as_mut(),
            );
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
            let mut executor = crate::executor::Executor::new(
                &mut self.policy,
                &mut self.owner.store,
                self.read_worker.as_mut(),
            );
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
        let outcome = match self.run_decision_step(
            session_id,
            &context.task,
            &context.answer,
            &context.grant_id,
            false,
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
