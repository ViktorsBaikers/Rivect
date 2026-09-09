//! Controller: the local reconcile loop between question, broker, executor
//! and evidence. No hidden controller model call: a local check that
//! unblocks the only known admitted action starts it directly, and
//! revocation/cancellation block the next dispatch before any provider
//! effect.

use crate::commands::Runtime;
use crate::contracts::{AnswerSelection, EffectClass, SessionId, TaskId, TaskSnapshot};
use crate::executor::{EffectOutcome, EffectRequest, ExecutorError};
use crate::model::ModelError;
use crate::policy::PolicyError;
use crate::state::{ConflictCause, InvalidCause, StoreError};
use std::path::PathBuf;

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
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

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
        if self.owner.store.task_cancelled(task_id)? {
            let snapshot = self.owner.store.snapshot(task_id)?;
            return Ok(StepOutcome::EffectDenied {
                reason: crate::executor::TASK_CANCELLED.to_string(),
                snapshot,
            });
        }
        self.owner.store.materialize_obligations(task_id)?;
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
        let pre = crate::verification::RetainedAttempt {
            attempt_id: manifest.attempt_id.clone(),
            boundary_id: crate::verification::boundary_id(&manifest.attempt_id),
            stage: crate::verification::RetainedStage::PreEffect,
            cause: "first useful offline dispatch".to_string(),
            digest: crate::verification::record_digest(&manifest.attempt_id, "pre"),
            build_attempt: crate::BUILD_ATTEMPT_ID.to_string(),
        };
        let pre_json = serde_json::to_string(&pre)?;
        self.owner.store.retain(&pre_json, &pre.boundary_id)?;
        let reply = self.broker.dispatch(&manifest)?;
        self.provider_calls += 1;
        let Some(call) = reply.tool_calls.iter().find(|c| c.tool == "read_file") else {
            let snapshot = self.owner.store.snapshot(task_id)?;
            return Ok(StepOutcome::Waiting { snapshot });
        };
        let target: PathBuf = self
            .scope_root
            .join(call.path.as_deref().unwrap_or_default());
        let request = EffectRequest::Read {
            grant_id: grant_id.to_string(),
            path: target,
        };
        let mut executor = crate::executor::Executor::new(
            &mut self.policy,
            &mut self.owner.store,
            self.read_worker.as_mut(),
        );
        let admitted = executor.admit(task_id, request)?;
        let effect_attempt = admitted.attempt_id.clone();
        if crash_after_dispatch {
            // Process death after the effect committed, before the receipt:
            // exactly one real worker read, no confirmation, no evidence.
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
                let terminal = crate::verification::RetainedAttempt {
                    attempt_id: manifest.attempt_id.clone(),
                    boundary_id: pre.boundary_id.clone(),
                    stage: crate::verification::RetainedStage::Terminal,
                    cause: observation,
                    digest: crate::verification::record_digest(&manifest.attempt_id, "terminal"),
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
