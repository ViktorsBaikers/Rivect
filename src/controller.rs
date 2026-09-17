//! Controller: the local reconcile loop between question, broker, executor
//! and evidence. No hidden controller model call: a local check that
//! unblocks the only known admitted action starts it directly, and
//! revocation/cancellation block the next dispatch before any provider
//! effect.

use crate::commands::Runtime;
use crate::contracts::{
    AnswerSelection, EffectClass, KNOWN_READY_OPTION, SessionId, TaskId, TaskSnapshot,
};
use crate::executor::{EffectOutcome, EffectRequest, ExecutorError};
use crate::model::ModelError;
use crate::policy::PolicyError;
use crate::resources::Delivery;
use crate::scheduler::{NodeId, SchedulerError, WaitTransition};
use crate::state::{ConflictCause, InvalidCause, StoreError};

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

#[derive(Debug, thiserror::Error)]
pub enum ControllerError {
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
}

/// Mirrors the runtime notification queue capacity: one pass drains at
/// most one full queue, so bounded work never grows with the backlog.
const SCHEDULER_DRAIN_LIMIT: usize = 8;

impl Runtime {
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
        let snapshot = self.owner.store.snapshot(task_id)?;
        if snapshot.lifecycle.is_terminal() {
            return Ok(StepOutcome::NoAction { snapshot });
        }
        // No-repeat guard: any unresolved running/unknown attempt of this
        // task blocks the next decision before a single provider call or
        // worker effect; the caller reconciles or starts a new task.
        if let Some(unresolved) = self.owner.store.latest_unresolved_attempt(task_id)? {
            let snapshot = self.owner.store.snapshot(task_id)?;
            return Ok(StepOutcome::OutcomeUnknown {
                attempt_id: unresolved,
                snapshot,
            });
        }
        // Mutable admission gates before the first provider effect:
        // revocation and task cancellation both deny the dispatch itself.
        self.policy.admit(grant_id, EffectClass::Read)?;
        // Permission-mode consult (DEC-014) on the only permitted action
        // target: an enrolled deny outranks the fixed interim `manual`
        // mode (DEC-015), and any verdict that is not a clear allow —
        // ask included — gates the dispatch read before any provider
        // effect, mirroring the executor's fail-closed rule.
        let dispatch_ctx = crate::executor::admission_context(
            &self.owner.store,
            EffectClass::Read,
            &self.scope_root,
            &self.scoped_file,
        )?;
        let dispatch_verdict =
            self.policy
                .decide(&self.scoped_file, EffectClass::Read, &dispatch_ctx);
        if dispatch_verdict != crate::policy::ModeDecision::Allow {
            let snapshot = self.owner.store.snapshot(task_id)?;
            return Ok(StepOutcome::EffectDenied {
                reason: crate::executor::mode_reason(dispatch_verdict).to_string(),
                snapshot,
            });
        }
        if self.owner.store.task_cancelled(task_id)? {
            let snapshot = self.owner.store.snapshot(task_id)?;
            return Ok(StepOutcome::EffectDenied {
                reason: crate::executor::TASK_CANCELLED.to_string(),
                snapshot,
            });
        }
        self.owner.store.materialize_obligations(task_id)?;
        let known_ready = matches!(
            answer,
            AnswerSelection::Option { option_id }
                if option_id.0.as_str() == KNOWN_READY_OPTION
        );
        let (target, retained_attempt_id) = if known_ready {
            (self.scoped_file.clone(), None)
        } else {
            let purpose = self.purpose.clone();
            let inputs = format!(
                "goal: {}\nanswer: {}\nread {}",
                String::from_utf8_lossy(&self.owner.store.goal_bytes(task_id)?),
                answer_text(answer),
                self.scoped_file.display()
            );
            let manifest = self
                .broker
                .prepare(&purpose, &self.config_for_broker(), &inputs)?;
            self.retain_pre_effect(&manifest.attempt_id, "first useful offline dispatch")?;
            let reply = self.broker.dispatch(&manifest)?;
            self.provider_calls += 1;
            let Some(call) = reply.tool_calls.iter().find(|c| c.tool == "read_file") else {
                self.owner.store.mark_no_ready(task_id)?;
                let snapshot = self.owner.store.snapshot(task_id)?;
                return Ok(StepOutcome::Waiting { snapshot });
            };
            (
                self.scope_root
                    .join(call.path.as_deref().unwrap_or_default()),
                Some(manifest.attempt_id),
            )
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
            executor.admit(task_id, request)?
        };
        let effect_attempt = admitted.attempt_id.clone();
        if known_ready {
            self.retain_pre_effect(&effect_attempt, "known ready admitted read")?;
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
            Ok(EffectOutcome::Read { bytes, digest }) => {
                let observation = format!(
                    "read {} bytes from {}; sha256={}",
                    bytes.len(),
                    self.scoped_file.display(),
                    digest
                );
                let obligation_count = self.owner.store.obligations_count(task_id)?;
                for index in 0..obligation_count {
                    self.owner.store.insert_evidence(
                        task_id,
                        index,
                        &format!("task:{}", task_id.0),
                        &observation,
                        &digest,
                    )?;
                }
                let terminal_attempt_id =
                    retained_attempt_id.unwrap_or_else(|| effect_attempt.clone());
                let terminal_boundary_id = crate::verification::boundary_id(&terminal_attempt_id);
                let terminal = crate::verification::RetainedAttempt {
                    attempt_id: terminal_attempt_id.clone(),
                    boundary_id: terminal_boundary_id,
                    stage: crate::verification::RetainedStage::Terminal,
                    cause: observation,
                    digest: crate::verification::record_digest(&terminal_attempt_id, "terminal"),
                    build_attempt: crate::BUILD_ATTEMPT_ID.to_string(),
                };
                let terminal_json = serde_json::to_string(&terminal)?;
                self.owner
                    .store
                    .retain(&terminal_json, &terminal.boundary_id)?;
                let snapshot = self.owner.store.complete_if_eligible(session_id, task_id)?;
                Ok(StepOutcome::Completed { snapshot })
            }
            Ok(EffectOutcome::Denied { reason }) => {
                let snapshot = self.owner.store.snapshot(task_id)?;
                Ok(StepOutcome::EffectDenied { reason, snapshot })
            }
            Err(err) => Err(err.into()),
        }
    }

    fn retain_pre_effect(&mut self, attempt_id: &str, cause: &str) -> Result<(), ControllerError> {
        let pre = crate::verification::RetainedAttempt {
            attempt_id: attempt_id.to_string(),
            boundary_id: crate::verification::boundary_id(attempt_id),
            stage: crate::verification::RetainedStage::PreEffect,
            cause: cause.to_string(),
            digest: crate::verification::record_digest(attempt_id, "pre"),
            build_attempt: crate::BUILD_ATTEMPT_ID.to_string(),
        };
        let pre_json = serde_json::to_string(&pre)?;
        self.owner.store.retain(&pre_json, &pre.boundary_id)?;
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
        let boundary_id = crate::verification::boundary_id(attempt_id);
        let terminal = crate::verification::RetainedAttempt {
            attempt_id: attempt_id.to_string(),
            boundary_id: boundary_id.clone(),
            stage: crate::verification::RetainedStage::Terminal,
            cause: format!("attempt {attempt_id} reconciled as executed from sha256={marker}"),
            digest: marker.clone(),
            build_attempt: crate::BUILD_ATTEMPT_ID.to_string(),
        };
        self.owner.store.retain(
            &serde_json::to_string(&terminal).unwrap_or_default(),
            &boundary_id,
        )?;
        self.owner.store.set_attempt_state(
            attempt_id,
            "confirmed",
            Some(&format!("read-performed sha256={marker}")),
        )?;
        let count = self.owner.store.obligations_count(task_id)?;
        for index in 0..count {
            self.owner.store.insert_evidence(
                task_id,
                index,
                &format!("task:{}", task_id.0),
                &format!("reconciled attempt {attempt_id} from sha256={marker}"),
                &marker,
            )?;
        }
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
                return Err(error);
            }
        };
        if matches!(outcome, StepOutcome::Completed { .. }) {
            self.scheduler.complete(node)?;
        } else {
            self.scheduler.settle(node)?;
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
