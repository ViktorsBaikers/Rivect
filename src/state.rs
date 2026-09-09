//! Task/evidence state owner: SQLite-backed store with revision/CAS
//! commits, outbox events, question durability, command dedupe receipts,
//! the attempt ledger and retained records. One writer, short transactions.

use crate::contracts::{
    AnswerSelection, ArtifactRef, AttachmentId, AttemptId, AttemptRef, AttemptState, Availability,
    Blocker, CommandResult, Criterion, CriterionId, ErrorCode, Event, EventId, EvidenceId,
    Lifecycle, Obligation, ObligationApplicability, ObligationExecution, OptionId, Page, Question,
    QuestionId, QuestionOption, ResumeCondition, SessionId, TaskId, TaskSnapshot,
};
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};
use serde_json::{Value, json};
use sha2::Digest;
use std::path::Path;

mod sql;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum Missing {
    #[error("session {0}")]
    Session(String),
    #[error("task {0}")]
    Task(String),
    #[error("question {0}")]
    Question(String),
    #[error("attempt {0}")]
    Attempt(String),
    #[error("evidence {0}")]
    Evidence(String),
    #[error("obligation")]
    Obligation,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ConflictCause {
    #[error("command {command_id} already recorded with different params")]
    DuplicateCommand { command_id: String },
    #[error("cannot publish a question for a {lifecycle} task")]
    QuestionOnLifecycle { lifecycle: String },
    #[error("a pending question already exists")]
    PendingQuestionExists,
    #[error("question is no longer pending")]
    QuestionNotPending,
    #[error("question revision {expected} is not the current revision {current}")]
    QuestionRevision { expected: u64, current: u64 },
    #[error("terminal task cannot be reopened")]
    TerminalCannotReopen,
    #[error("task revision {expected} is not the current revision {current}")]
    TaskRevision { expected: u64, current: u64 },
    #[error("cursor generation {expected} does not match snapshot generation {current}")]
    CursorGeneration { expected: u64, current: u64 },
    #[error("task is already terminal")]
    TaskAlreadyTerminal,
    #[error(
        "completion rejected: {unsatisfied} unsatisfied, {unresolved} unresolved, {unknown} unknown"
    )]
    CompletionOpen {
        unsatisfied: u64,
        unresolved: u64,
        unknown: u64,
    },
    #[error("completion rejected: {stale} stale evidence")]
    CompletionStale { stale: u64 },
    #[error("attempt {attempt_id} is {state}, not reconcile-able")]
    AttemptNotReconcileable { attempt_id: String, state: String },
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum InvalidCause {
    #[error("goal must be non-empty bounded text")]
    EmptyGoal,
    #[error("unknown option {option_id} for question {question_id}")]
    UnknownOption {
        option_id: String,
        question_id: String,
    },
    #[error("option {option_id} is disabled: {reason}")]
    DisabledOption { option_id: String, reason: String },
    #[error("custom answer must be non-empty")]
    EmptyCustomAnswer,
    #[error("unknown collection {0}")]
    UnknownCollection(String),
    #[error("attempt {attempt_id} belongs to task {owner_task}, not {expected}")]
    AttemptTaskMismatch {
        attempt_id: String,
        owner_task: String,
        expected: String,
    },
    #[error("attempt {attempt_id} carries no read-performed marker")]
    MissingReadMarker { attempt_id: String },
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("not found: {0}")]
    NotFound(#[source] Missing),
    #[error("conflict: {0}")]
    Conflict(#[source] ConflictCause),
    #[error("stale intent: expected {expected}, current {current}")]
    StaleIntent { expected: u64, current: u64 },
    #[error("already terminal")]
    AlreadyTerminal,
    #[error("invalid input: {0}")]
    InvalidInput(#[source] InvalidCause),
    #[error("storage: {0}")]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl StoreError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) => ErrorCode::NotFound,
            Self::Conflict(_) => ErrorCode::Conflict,
            Self::StaleIntent { .. } => ErrorCode::StaleIntent,
            Self::AlreadyTerminal => ErrorCode::AlreadyTerminal,
            Self::InvalidInput(_) => ErrorCode::InvalidInput,
            Self::Storage(_) => ErrorCode::StorageUnavailable,
        }
    }

    pub fn missing_session(id: impl Into<String>) -> Self {
        Self::NotFound(Missing::Session(id.into()))
    }

    pub fn missing_task(id: impl Into<String>) -> Self {
        Self::NotFound(Missing::Task(id.into()))
    }

    pub fn missing_question(id: impl Into<String>) -> Self {
        Self::NotFound(Missing::Question(id.into()))
    }

    pub fn missing_attempt(id: impl Into<String>) -> Self {
        Self::NotFound(Missing::Attempt(id.into()))
    }

    pub fn missing_evidence(id: impl Into<String>) -> Self {
        Self::NotFound(Missing::Evidence(id.into()))
    }

    pub fn missing_obligation() -> Self {
        Self::NotFound(Missing::Obligation)
    }
}

pub type Result<T, E = StoreError> = std::result::Result<T, E>;

fn storage(err: impl std::error::Error + Send + Sync + 'static) -> StoreError {
    StoreError::Storage(Box::new(err))
}

pub struct TaskStore {
    conn: Connection,
}

impl TaskStore {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(storage)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(storage)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(storage)?;
        conn.execute_batch(sql::SCHEMA).map_err(storage)?;
        Ok(Self { conn })
    }

    // ----- sessions -----

    pub fn open_session(
        &mut self,
        bootstrap_id: &str,
        connection_id: &str,
        attach_to: Option<&SessionId>,
    ) -> Result<(SessionId, AttachmentId, u64, bool)> {
        let params_digest = format!(
            "{bootstrap_id}|{connection_id}|attach={}",
            attach_to.is_some()
        );
        let key = format!("{connection_id}|{bootstrap_id}");
        let replay = self
            .conn
            .query_row(sql::BOOTSTRAP_RECEIPT_BY_KEY, params![key], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .map_err(storage)?;
        if let Some(result_json) = replay {
            let value: Value = serde_json::from_str(&result_json).map_err(storage)?;
            let session_id =
                SessionId(value["session_id"].as_str().unwrap_or_default().to_string());
            let attachment_id = AttachmentId(
                value["attachment_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            );
            let generation = value["owner_generation"].as_u64().unwrap_or(1);
            return Ok((session_id, attachment_id, generation, true));
        }
        let session_id = match attach_to {
            Some(id) => {
                let exists: bool = self
                    .conn
                    .query_row(sql::SESSION_EXISTS, params![id.0], |row| row.get(0))
                    .map_err(storage)?;
                if !exists {
                    return Err(StoreError::missing_session(&id.0));
                }
                id.clone()
            }
            None => SessionId::generate(),
        };
        let attachment_id = AttachmentId::generate();
        self.conn
            .execute(
                sql::INSERT_ATTACHMENT,
                params![
                    attachment_id.0,
                    session_id.0,
                    connection_id,
                    bootstrap_id,
                    params_digest
                ],
            )
            .map_err(storage)?;
        let revision: u64 = self
            .conn
            .query_row(sql::NEXT_SESSION_REVISION, params![session_id.0], |row| {
                row.get::<_, i64>(0).map(|v| v as u64)
            })
            .map_err(storage)?;
        if attach_to.is_none() {
            self.conn
                .execute(sql::INSERT_SESSION, params![session_id.0, revision as i64])
                .map_err(storage)?;
        } else {
            self.conn
                .execute(
                    sql::UPDATE_SESSION_REVISION,
                    params![session_id.0, revision as i64],
                )
                .map_err(storage)?;
        }
        let result_json = serde_json::to_string(&json!({
            "session_id": session_id.0,
            "attachment_id": attachment_id.0,
            "owner_generation": 1u64,
        }))
        .map_err(storage)?;
        self.conn
            .execute(
                sql::INSERT_BOOTSTRAP_RECEIPT,
                params![key, attachment_id.0, result_json],
            )
            .map_err(storage)?;
        Ok((session_id, attachment_id, 1, false))
    }

    // ----- events -----

    fn next_cursor(tx: &rusqlite::Transaction<'_>) -> Result<u64> {
        let cursor: u64 = tx
            .query_row(sql::NEXT_EVENT_CURSOR, [], |row| {
                row.get::<_, i64>(0).map(|v| v as u64)
            })
            .map_err(storage)?;
        Ok(cursor)
    }

    fn append_event(
        tx: &rusqlite::Transaction<'_>,
        session_id: &SessionId,
        task_id: Option<&TaskId>,
        aggregate: (&str, u64),
        event_type: &str,
        delta: Value,
        origin: &str,
    ) -> Result<Event> {
        let (aggregate_id, aggregate_revision) = aggregate;
        let cursor = Self::next_cursor(tx)?;
        let event = Event {
            schema_version: 1,
            event_id: EventId::generate(),
            aggregate_id: aggregate_id.to_string(),
            aggregate_revision,
            cursor,
            session_id: session_id.clone(),
            task_id: task_id.cloned(),
            event_type: event_type.to_string(),
            delta,
            origin: origin.to_string(),
        };
        tx.execute(
            sql::INSERT_EVENT,
            params![
                event.event_id.0,
                event.aggregate_id,
                event.aggregate_revision as i64,
                event.cursor as i64,
                event.session_id.0,
                event.task_id.as_ref().map(|id| id.0.clone()),
                event.event_type,
                serde_json::to_string(&event.delta).map_err(storage)?,
                event.origin
            ],
        )
        .map_err(storage)?;
        Ok(event)
    }

    pub fn events_after(
        &self,
        session_id: &SessionId,
        task_id: Option<&TaskId>,
        after: u64,
        limit: u32,
    ) -> Result<Vec<Event>> {
        let (query, args): (&str, Vec<Box<dyn rusqlite::ToSql>>) = if let Some(id) = task_id {
            (
                sql::EVENTS_AFTER_FOR_TASK,
                vec![
                    Box::new(session_id.0.clone()),
                    Box::new(after as i64),
                    Box::new(id.0.clone()),
                    Box::new(limit as i64),
                ],
            )
        } else {
            (
                sql::EVENTS_AFTER,
                vec![
                    Box::new(session_id.0.clone()),
                    Box::new(after as i64),
                    Box::new(limit as i64),
                ],
            )
        };
        let mut stmt = self.conn.prepare(query).map_err(storage)?;
        let rows = stmt
            .query_map(params_from_iter(args.iter()), |row| {
                Ok(Event {
                    schema_version: 1,
                    event_id: EventId(row.get(0)?),
                    aggregate_id: row.get(1)?,
                    aggregate_revision: row.get::<_, i64>(2)? as u64,
                    cursor: row.get::<_, i64>(3)? as u64,
                    session_id: SessionId(row.get(4)?),
                    task_id: row.get::<_, Option<String>>(5)?.map(TaskId),
                    event_type: row.get(6)?,
                    delta: serde_json::from_str(&row.get::<_, String>(7)?).unwrap_or(Value::Null),
                    origin: row.get(8)?,
                })
            })
            .map_err(storage)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(storage)?);
        }
        Ok(out)
    }

    // ----- command dedupe -----

    pub fn receipt(&self, command_id: &str) -> Result<Option<(String, String)>> {
        let row = self
            .conn
            .query_row(sql::RECEIPT_BY_COMMAND, params![command_id], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()
            .map_err(storage)?;
        Ok(row)
    }

    fn record_receipt(
        tx: &rusqlite::Transaction<'_>,
        command_id: &str,
        session_id: &SessionId,
        principal: &str,
        params_digest: &str,
        result: &CommandResult,
    ) -> Result<()> {
        tx.execute(
            sql::INSERT_RECEIPT,
            params![
                command_id,
                session_id.0,
                principal,
                params_digest,
                serde_json::to_string(result).map_err(storage)?
            ],
        )
        .map_err(storage)?;
        Ok(())
    }

    // ----- task lifecycle -----

    pub fn create_task(
        &mut self,
        session_id: &SessionId,
        command_id: &str,
        principal: &str,
        goal: &str,
        contract: (&[String], &[String]),
    ) -> Result<CommandResult> {
        let (criteria, constraints) = contract;
        if goal.is_empty() || goal.len() > crate::contracts::TEXT_MAX_BYTES {
            return Err(StoreError::InvalidInput(InvalidCause::EmptyGoal));
        }
        let params_digest = format!("create|{principal}|{goal}|{}", criteria.join("\u{1}"));
        if let Some((digest, result_json)) = self.receipt(command_id)? {
            if digest != params_digest {
                return Err(StoreError::Conflict(ConflictCause::DuplicateCommand {
                    command_id: command_id.to_string(),
                }));
            }
            let result: CommandResult = serde_json::from_str(&result_json).map_err(storage)?;
            return Ok(result);
        }
        let task_id = TaskId::generate();
        let goal_bytes = goal.as_bytes().to_vec();
        let digest = crate::config::hex(&sha2::Sha256::digest(&goal_bytes));
        let tx = self.conn.transaction().map_err(storage)?;
        tx.execute(
            sql::INSERT_TASK,
            params![
                task_id.0,
                session_id.0,
                goal_bytes,
                digest,
                goal_artifact_id(&task_id),
            ],
        )
        .map_err(storage)?;
        for (position, text) in criteria.iter().enumerate() {
            let criterion_id = CriterionId::generate();
            tx.execute(
                sql::INSERT_CRITERION,
                params![criterion_id.0, task_id.0, position as i64, text],
            )
            .map_err(storage)?;
        }
        for (position, text) in constraints.iter().enumerate() {
            tx.execute(
                sql::INSERT_CONSTRAINT,
                params![task_id.0, position as i64, text],
            )
            .map_err(storage)?;
        }
        tx.execute(sql::TOUCH_EVENT_CURSOR, params![task_id.0])
            .map_err(storage)?;
        Self::append_event(
            &tx,
            session_id,
            Some(&task_id),
            (&task_id.0, 1),
            "task.created",
            json!({ "task_id": task_id.0, "goal_digest": digest }),
            "human",
        )?;
        let snapshot = Self::snapshot_in_tx(&tx, &task_id)?;
        let result = CommandResult {
            status: "accepted".to_string(),
            task_id: task_id.clone(),
            task_revision: snapshot.revision,
            intent_revision: snapshot.intent_revision,
            event_cursor: 1,
            snapshot,
            contract_revision: Some(1),
        };
        Self::record_receipt(
            &tx,
            command_id,
            session_id,
            principal,
            &params_digest,
            &result,
        )?;
        tx.commit().map_err(storage)?;
        Ok(result)
    }

    /// The single question producer (architecture TP-PUBLIC): atomically
    /// stores the pending question and moves the task to `waiting` with a
    /// decision blocker in the same commit.
    pub fn publish_question(
        &mut self,
        session_id: &SessionId,
        question: &Question,
    ) -> Result<TaskSnapshot> {
        let tx = self.conn.transaction().map_err(storage)?;
        let (revision, lifecycle): (u64, String) = tx
            .query_row(
                sql::TASK_REVISION_LIFECYCLE,
                params![question.task_id.0],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get(1)?)),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_task(&question.task_id.0))?;
        if lifecycle != "running" {
            return Err(StoreError::Conflict(ConflictCause::QuestionOnLifecycle {
                lifecycle,
            }));
        }
        let pending: bool = tx
            .query_row(
                sql::PENDING_QUESTION_EXISTS,
                params![question.task_id.0],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if pending {
            return Err(StoreError::Conflict(ConflictCause::PendingQuestionExists));
        }
        tx.execute(
            sql::INSERT_QUESTION,
            params![
                question.question_id.0,
                question.task_id.0,
                question.question_revision as i64,
                question.intent_revision as i64,
                question.prompt,
                serde_json::to_string(question).map_err(storage)?
            ],
        )
        .map_err(storage)?;
        let new_revision = revision + 1;
        tx.execute(
            sql::TASK_SET_WAITING,
            params![question.task_id.0, new_revision as i64],
        )
        .map_err(storage)?;
        Self::append_event(
            &tx,
            session_id,
            Some(&question.task_id),
            (&question.task_id.0, new_revision),
            "question.published",
            json!({ "question_id": question.question_id.0, "question_revision": question.question_revision }),
            "state",
        )?;
        tx.commit().map_err(storage)?;
        self.snapshot(&question.task_id)
    }

    pub fn current_question(&self, task_id: &TaskId) -> Result<Option<(Question, u64)>> {
        let row = self
            .conn
            .query_row(
                sql::CURRENT_QUESTION,
                params![task_id.0, task_id.0],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(storage)?;
        match row {
            None => Ok(None),
            Some((body, revision)) => {
                let question: Question = serde_json::from_str(&body).map_err(storage)?;
                Ok(Some((question, revision as u64)))
            }
        }
    }

    pub fn answer_question(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        question_id: &QuestionId,
        question_revision: u64,
        selection: &AnswerSelection,
        author: &str,
    ) -> Result<CommandResult> {
        let tx = self.conn.transaction().map_err(storage)?;
        let (revision, intent_revision, lifecycle): (u64, u64, String) = tx
            .query_row(sql::TASK_REVISIONS, params![task_id.0], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get(2)?,
                ))
            })
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_task(&task_id.0))?;
        if Lifecycle::from_db(&lifecycle).is_terminal() {
            return Err(StoreError::AlreadyTerminal);
        }
        let (stored_revision, state, body_json): (u64, String, String) = tx
            .query_row(sql::QUESTION_BY_ID, params![question_id.0], |row| {
                Ok((row.get::<_, i64>(0)? as u64, row.get(1)?, row.get(2)?))
            })
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_question(&question_id.0))?;
        if state != "pending" {
            return Err(StoreError::Conflict(ConflictCause::QuestionNotPending));
        }
        if stored_revision != question_revision {
            return Err(StoreError::Conflict(ConflictCause::QuestionRevision {
                expected: question_revision,
                current: stored_revision,
            }));
        }
        let question: Question = serde_json::from_str(&body_json).map_err(storage)?;
        match selection {
            AnswerSelection::Option { option_id } => {
                let Some(option) = question.options.iter().find(|o| o.option_id == *option_id)
                else {
                    return Err(StoreError::InvalidInput(InvalidCause::UnknownOption {
                        option_id: option_id.0.clone(),
                        question_id: question_id.0.clone(),
                    }));
                };
                if let Availability::Disabled { reason } = &option.availability {
                    return Err(StoreError::InvalidInput(InvalidCause::DisabledOption {
                        option_id: option_id.0.clone(),
                        reason: reason.clone(),
                    }));
                }
            }
            AnswerSelection::Custom { text } => {
                if text.trim().is_empty() {
                    return Err(StoreError::InvalidInput(InvalidCause::EmptyCustomAnswer));
                }
            }
        }
        let answer_json = serde_json::to_string(selection).map_err(storage)?;
        tx.execute(
            sql::ANSWER_QUESTION,
            params![question_id.0, answer_json, author],
        )
        .map_err(storage)?;
        let new_revision = revision + 1;
        tx.execute(
            sql::TASK_SET_RUNNING,
            params![task_id.0, new_revision as i64],
        )
        .map_err(storage)?;
        Self::append_event(
            &tx,
            session_id,
            Some(task_id),
            (&task_id.0, new_revision),
            "question.answered",
            json!({ "question_id": question_id.0, "author": author }),
            author,
        )?;
        let snapshot = Self::snapshot_in_tx(&tx, task_id)?;
        tx.commit().map_err(storage)?;
        Ok(CommandResult {
            status: "applied".to_string(),
            task_id: task_id.clone(),
            task_revision: new_revision,
            intent_revision,
            event_cursor: snapshot.event_cursor,
            snapshot,
            contract_revision: None,
        })
    }

    pub fn steer_task(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        expected_intent_revision: u64,
        expected_task_revision: u64,
        instruction: &str,
    ) -> Result<CommandResult> {
        let tx = self.conn.transaction().map_err(storage)?;
        let (revision, intent_revision, lifecycle): (u64, u64, String) = tx
            .query_row(sql::TASK_REVISIONS, params![task_id.0], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get(2)?,
                ))
            })
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_task(&task_id.0))?;
        if Lifecycle::from_db(&lifecycle).is_terminal() {
            return Err(StoreError::Conflict(ConflictCause::TerminalCannotReopen));
        }
        if intent_revision != expected_intent_revision {
            return Err(StoreError::StaleIntent {
                expected: expected_intent_revision,
                current: intent_revision,
            });
        }
        if revision != expected_task_revision {
            return Err(StoreError::Conflict(ConflictCause::TaskRevision {
                expected: expected_task_revision,
                current: revision,
            }));
        }
        let new_revision = revision + 1;
        let new_intent = intent_revision + 1;
        tx.execute(
            sql::UPDATE_INTENT,
            params![task_id.0, new_revision as i64, new_intent as i64],
        )
        .map_err(storage)?;
        Self::append_event(
            &tx,
            session_id,
            Some(task_id),
            (&task_id.0, new_revision),
            "task.steered",
            json!({ "instruction": instruction }),
            "human",
        )?;
        let snapshot = Self::snapshot_in_tx(&tx, task_id)?;
        tx.commit().map_err(storage)?;
        Ok(CommandResult {
            status: "applied".to_string(),
            task_id: task_id.clone(),
            task_revision: new_revision,
            intent_revision: new_intent,
            event_cursor: snapshot.event_cursor,
            snapshot,
            contract_revision: None,
        })
    }

    /// Monotonic control of the current intent. Terminal tasks answer
    /// `already_terminal`; a stale intent is `stale_intent` even then.
    pub fn cancel_task(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        expected_intent_revision: u64,
        reason: Option<&str>,
    ) -> Result<CommandResult> {
        let tx = self.conn.transaction().map_err(storage)?;
        let (revision, intent_revision, lifecycle): (u64, u64, String) = tx
            .query_row(sql::TASK_REVISIONS, params![task_id.0], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get(2)?,
                ))
            })
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_task(&task_id.0))?;
        let terminal = Lifecycle::from_db(&lifecycle).is_terminal();
        if intent_revision != expected_intent_revision {
            return Err(StoreError::StaleIntent {
                expected: expected_intent_revision,
                current: intent_revision,
            });
        }
        let snapshot;
        if terminal {
            snapshot = Self::snapshot_in_tx(&tx, task_id)?;
            tx.commit().map_err(storage)?;
            return Ok(CommandResult {
                status: "already_terminal".to_string(),
                task_id: task_id.clone(),
                task_revision: revision,
                intent_revision,
                event_cursor: snapshot.event_cursor,
                snapshot,
                contract_revision: None,
            });
        }
        tx.execute(sql::CANCEL_TASK, params![task_id.0, (revision + 1) as i64])
            .map_err(storage)?;
        Self::append_event(
            &tx,
            session_id,
            Some(task_id),
            (&task_id.0, revision + 1),
            "task.cancelled",
            json!({ "reason": reason }),
            "human",
        )?;
        snapshot = Self::snapshot_in_tx(&tx, task_id)?;
        tx.commit().map_err(storage)?;
        Ok(CommandResult {
            status: "applied".to_string(),
            task_id: task_id.clone(),
            task_revision: revision + 1,
            intent_revision,
            event_cursor: snapshot.event_cursor,
            snapshot,
            contract_revision: None,
        })
    }

    pub fn task_cancelled(&self, task_id: &TaskId) -> Result<bool> {
        let lifecycle: String = self
            .conn
            .query_row(sql::TASK_LIFECYCLE, params![task_id.0], |row| row.get(0))
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_task(&task_id.0))?;
        Ok(lifecycle == "cancelled")
    }

    // ----- snapshots -----

    fn snapshot_in_tx(tx: &rusqlite::Transaction<'_>, task_id: &TaskId) -> Result<TaskSnapshot> {
        let (
            revision,
            intent_revision,
            contract_revision,
            lifecycle,
            goal_digest,
            artifact_id,
            goal_len,
            event_cursor,
        ): (u64, u64, u64, String, String, String, usize, u64) = tx
            .query_row(sql::SNAPSHOT_TASK, params![task_id.0], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u64,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get::<_, i64>(6)? as usize,
                    row.get::<_, i64>(7)? as u64,
                ))
            })
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_task(&task_id.0))?;
        let mut criteria_stmt = tx.prepare(sql::CRITERIA_FOR_TASK).map_err(storage)?;
        let criteria = criteria_stmt
            .query_map(params![task_id.0], |row| {
                Ok(Criterion {
                    id: CriterionId(row.get(0)?),
                    text: row.get(1)?,
                })
            })
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        let mut constraints_stmt = tx.prepare(sql::CONSTRAINTS_FOR_TASK).map_err(storage)?;
        let constraints = constraints_stmt
            .query_map(params![task_id.0], |row| row.get::<_, String>(0))
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        let mut obligations_stmt = tx.prepare(sql::OBLIGATIONS_FOR_TASK).map_err(storage)?;
        let obligations = obligations_stmt
            .query_map(params![task_id.0], |row| {
                Ok(Obligation {
                    id: row.get(0)?,
                    criterion_refs: vec![CriterionId(row.get(1)?)],
                    applicability: match row.get::<_, String>(2)?.as_str() {
                        "not_applicable" => ObligationApplicability::NotApplicable,
                        "unresolved" => ObligationApplicability::Unresolved,
                        _ => ObligationApplicability::Required,
                    },
                    execution: match row.get::<_, String>(3)?.as_str() {
                        "satisfied" => ObligationExecution::Satisfied,
                        "failed" => ObligationExecution::Failed,
                        "stale" => ObligationExecution::Stale,
                        _ => ObligationExecution::Pending,
                    },
                    basis_refs: Vec::new(),
                })
            })
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        let mut attempts_stmt = tx.prepare(sql::ATTEMPTS_FOR_TASK).map_err(storage)?;
        let attempts = attempts_stmt
            .query_map(params![task_id.0], |row| {
                Ok(AttemptRef {
                    attempt_id: AttemptId(row.get(0)?),
                    action_id: crate::contracts::ActionId(row.get(1)?),
                    effect_class: match row.get::<_, String>(2)?.as_str() {
                        "write" => crate::contracts::EffectClass::Write,
                        "exec" => crate::contracts::EffectClass::Exec,
                        "egress" => crate::contracts::EffectClass::Egress,
                        "model" => crate::contracts::EffectClass::Model,
                        "control" => crate::contracts::EffectClass::Control,
                        _ => crate::contracts::EffectClass::Read,
                    },
                    state: match row.get::<_, String>(3)?.as_str() {
                        "admitted" => AttemptState::Admitted,
                        "running" => AttemptState::Running,
                        "confirmed" => AttemptState::Confirmed,
                        "rejected" => AttemptState::Rejected,
                        "cancel_requested" => AttemptState::CancelRequested,
                        "unknown" => AttemptState::Unknown,
                        _ => AttemptState::Planned,
                    },
                })
            })
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        let blockers = Self::blockers_in_tx(tx, task_id)?;
        Ok(TaskSnapshot {
            task_id: task_id.clone(),
            revision,
            intent_revision,
            lifecycle: Lifecycle::from_db(&lifecycle),
            goal_ref: ArtifactRef {
                id: crate::contracts::ArtifactId(artifact_id),
                digest: goal_digest,
                size_bytes: goal_len as u64,
                media_type: "text/plain;charset=utf-8".to_string(),
                scope: Some(format!("task:{}", task_id.0)),
            },
            contract_revision,
            constraints: Page::new(constraints, revision),
            criteria: Page::new(criteria, revision),
            obligations: Page::new(obligations, revision),
            actions: Page::new(Vec::new(), revision),
            attempts: Page::new(attempts, revision),
            decision_refs: Page::new(Vec::new(), revision),
            event_cursor,
            blockers,
        })
    }

    fn blockers_in_tx(
        tx: &rusqlite::Transaction<'_>,
        task_id: &TaskId,
    ) -> Result<Option<Vec<Blocker>>> {
        let lifecycle: String = tx
            .query_row(sql::TASK_LIFECYCLE, params![task_id.0], |row| row.get(0))
            .map_err(storage)?;
        let mut blockers = Vec::new();
        match lifecycle.as_str() {
            "waiting" => {
                let pending: Option<(String, u64)> = tx
                    .query_row(sql::PENDING_QUESTION, params![task_id.0], |row| {
                        Ok((row.get(0)?, row.get::<_, i64>(1)? as u64))
                    })
                    .optional()
                    .map_err(storage)?;
                if let Some((question_id, revision)) = pending {
                    blockers.push(Blocker {
                        reason: ErrorCode::DependencyBlocked,
                        owner: "state".to_string(),
                        condition: ResumeCondition::Decision {
                            question_id: QuestionId(question_id),
                            revision,
                        },
                    });
                }
            }
            "blocked" => {
                let unresolved: u64 = tx
                    .query_row(sql::UNRESOLVED_OBLIGATIONS, params![task_id.0], |row| {
                        row.get::<_, i64>(0).map(|v| v as u64)
                    })
                    .map_err(storage)?;
                if unresolved > 0 {
                    blockers.push(Blocker {
                        reason: ErrorCode::DependencyBlocked,
                        owner: "state".to_string(),
                        condition: ResumeCondition::Dependency {
                            action_id: crate::contracts::ActionId(format!(
                                "obligations:{unresolved}"
                            )),
                        },
                    });
                }
                let unknown: u64 = tx
                    .query_row(sql::UNKNOWN_ATTEMPTS, params![task_id.0], |row| {
                        row.get::<_, i64>(0).map(|v| v as u64)
                    })
                    .map_err(storage)?;
                if unknown > 0 {
                    blockers.push(Blocker {
                        reason: ErrorCode::OutcomeUnknown,
                        owner: "executor".to_string(),
                        condition: ResumeCondition::Reconciliation {
                            action_id: crate::contracts::ActionId(format!("attempts:{unknown}")),
                        },
                    });
                }
            }
            _ => {}
        }
        if blockers.is_empty() {
            Ok(None)
        } else {
            Ok(Some(blockers))
        }
    }

    pub fn snapshot(&self, task_id: &TaskId) -> Result<TaskSnapshot> {
        let tx = self.conn.unchecked_transaction().map_err(storage)?;
        let snapshot = Self::snapshot_in_tx(&tx, task_id)?;
        Ok(snapshot)
    }

    pub fn task_status_page(
        &self,
        session_id: &SessionId,
    ) -> Result<Page<crate::contracts::TaskStatus>> {
        let mut stmt = self.conn.prepare(sql::TASKS_FOR_SESSION).map_err(storage)?;
        let items = stmt
            .query_map(params![session_id.0], |row| {
                Ok(crate::contracts::TaskStatus {
                    task_id: TaskId(row.get(0)?),
                    task_revision: row.get::<_, i64>(1)? as u64,
                    intent_revision: row.get::<_, i64>(2)? as u64,
                    lifecycle: Lifecycle::from_db(&row.get::<_, String>(3)?),
                })
            })
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        Ok(Page::new(items, 0))
    }

    pub fn collection(
        &self,
        task_id: &TaskId,
        collection: &str,
        cursor_gen: Option<u64>,
    ) -> Result<Page<Value>> {
        let snapshot = self.snapshot(task_id)?;
        if let Some(generation) = cursor_gen
            && generation != snapshot.revision
        {
            return Err(StoreError::Conflict(ConflictCause::CursorGeneration {
                expected: generation,
                current: snapshot.revision,
            }));
        }
        let generation = snapshot.revision;
        let items: Vec<Value> = match collection {
            "criteria" => snapshot
                .criteria
                .items
                .iter()
                .map(|c| json!({ "id": c.id.0, "text": c.text }))
                .collect(),
            "constraints" => snapshot
                .constraints
                .items
                .iter()
                .map(|c| Value::String(c.clone()))
                .collect(),
            "obligations" => snapshot
                .obligations
                .items
                .iter()
                .map(|o| serde_json::to_value(o).unwrap_or(Value::Null))
                .collect(),
            "attempts" => snapshot
                .attempts
                .items
                .iter()
                .map(|a| serde_json::to_value(a).unwrap_or(Value::Null))
                .collect(),
            other => {
                return Err(StoreError::InvalidInput(InvalidCause::UnknownCollection(
                    other.to_string(),
                )));
            }
        };
        Ok(Page::new(items, generation))
    }

    // ----- attempts / effects ledger -----

    pub fn plan_attempt(
        &mut self,
        task_id: &TaskId,
        class: crate::contracts::EffectClass,
        describe: &str,
    ) -> Result<String> {
        let attempt_id = AttemptId::generate().0;
        self.conn
            .execute(
                sql::INSERT_ATTEMPT,
                params![
                    attempt_id,
                    task_id.0,
                    format!("action-{attempt_id}"),
                    format!("{class:?}").to_lowercase(),
                    describe
                ],
            )
            .map_err(storage)?;
        Ok(attempt_id)
    }

    pub fn set_attempt_state(
        &mut self,
        attempt_id: &str,
        state: &str,
        detail: Option<&str>,
    ) -> Result<()> {
        let changed = self
            .conn
            .execute(sql::UPDATE_ATTEMPT, params![attempt_id, state, detail])
            .map_err(storage)?;
        if changed == 0 {
            return Err(StoreError::missing_attempt(attempt_id));
        }
        Ok(())
    }

    pub fn attempt_state(&self, attempt_id: &str) -> Result<Option<String>> {
        let state = self
            .conn
            .query_row(sql::ATTEMPT_STATE, params![attempt_id], |row| row.get(0))
            .optional()
            .map_err(storage)?;
        Ok(state)
    }

    /// (task_id, state, detail) of one attempt; reconcile validates against
    /// this instead of trusting an arbitrary id.
    pub fn attempt_record(
        &self,
        attempt_id: &str,
    ) -> Result<Option<(String, String, Option<String>)>> {
        let record = self
            .conn
            .query_row(sql::ATTEMPT_RECORD, params![attempt_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .optional()
            .map_err(storage)?;
        Ok(record)
    }

    /// The newest unresolved (running or unknown) attempt of a task, if any:
    /// the no-repeat guard for the next dispatch decision.
    pub fn latest_unresolved_attempt(&self, task_id: &TaskId) -> Result<Option<String>> {
        let attempt_id = self
            .conn
            .query_row(sql::LATEST_UNRESOLVED_ATTEMPT, params![task_id.0], |row| {
                row.get(0)
            })
            .optional()
            .map_err(storage)?;
        Ok(attempt_id)
    }

    pub fn attempt_running(&mut self, attempt_id: &str) -> Result<()> {
        self.set_attempt_state(attempt_id, "running", None)
    }

    pub fn attempt_confirmed(&mut self, attempt_id: &str) -> Result<()> {
        self.set_attempt_state(attempt_id, "confirmed", None)
    }

    pub fn attempt_rejected(&mut self, attempt_id: &str, detail: &str) -> Result<()> {
        self.set_attempt_state(attempt_id, "rejected", Some(detail))
    }

    pub fn attempt_unknown(&mut self, attempt_id: &str, detail: &str) -> Result<()> {
        self.set_attempt_state(attempt_id, "unknown", Some(detail))
    }

    pub fn goal_bytes(&self, task_id: &TaskId) -> Result<Vec<u8>> {
        let bytes = self
            .conn
            .query_row(sql::GOAL_BYTES, params![task_id.0], |row| row.get(0))
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_task(&task_id.0))?;
        Ok(bytes)
    }

    pub fn obligations_count(&self, task_id: &TaskId) -> Result<usize> {
        let count = self
            .conn
            .query_row(sql::OBLIGATION_COUNT, params![task_id.0], |row| {
                row.get::<_, i64>(0).map(|v| v as usize)
            })
            .map_err(storage)?;
        Ok(count)
    }

    /// The durable recorded answer for a task: (answer json, author origin).
    pub fn answered_question(&self, task_id: &TaskId) -> Result<Option<(String, String)>> {
        let row = self
            .conn
            .query_row(sql::ANSWERED_QUESTION, params![task_id.0], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            })
            .optional()
            .map_err(storage)?;
        Ok(row.and_then(|(answer, origin)| Some((answer?, origin?))))
    }

    pub fn insert_evidence(
        &mut self,
        task_id: &TaskId,
        obligation_index: usize,
        scope: &str,
        observation: &str,
        digest: &str,
    ) -> Result<String> {
        let obligation_id: String = self
            .conn
            .query_row(
                sql::OBLIGATION_AT_OFFSET,
                params![task_id.0, obligation_index as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(StoreError::missing_obligation)?;
        let evidence_id = EvidenceId::generate().0;
        self.conn
            .execute(
                sql::INSERT_EVIDENCE,
                params![
                    evidence_id,
                    task_id.0,
                    scope,
                    observation,
                    digest,
                    obligation_id
                ],
            )
            .map_err(storage)?;
        self.conn
            .execute(sql::SATISFY_OBLIGATION, params![obligation_id])
            .map_err(storage)?;
        Ok(evidence_id)
    }

    pub fn invalidate_evidence(&mut self, evidence_id: &str) -> Result<String> {
        let obligation_id: String = self
            .conn
            .query_row(sql::STALE_EVIDENCE, params![evidence_id], |row| row.get(0))
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_evidence(evidence_id))?;
        self.conn
            .execute(sql::STALE_OBLIGATION, params![obligation_id])
            .map_err(storage)?;
        let task_id: String = self
            .conn
            .query_row(sql::TASK_ID_FOR_OBLIGATION, params![obligation_id], |row| {
                row.get(0)
            })
            .map_err(storage)?;
        self.conn
            .execute(sql::BLOCK_TASK_NOT_CANCELLED, params![task_id])
            .map_err(storage)?;
        Ok(task_id)
    }

    pub fn evidence_validity(&self, evidence_id: &str) -> Result<Option<String>> {
        let validity = self
            .conn
            .query_row(sql::EVIDENCE_VALIDITY, params![evidence_id], |row| {
                row.get(0)
            })
            .optional()
            .map_err(storage)?;
        Ok(validity)
    }

    /// A dispatch whose receipt was lost blocks the scope until the owner
    /// reconciles it; the snapshot carries an outcome_unknown blocker.
    pub fn mark_outcome_unknown(&mut self, task_id: &TaskId) -> Result<()> {
        self.conn
            .execute(sql::BLOCK_TASK_OPEN, params![task_id.0])
            .map_err(storage)?;
        Ok(())
    }

    /// frame_goal contribution: the accepted receipt carries empty
    pub fn materialize_obligations(&mut self, task_id: &TaskId) -> Result<()> {
        let mut stmt = self
            .conn
            .prepare(sql::MISSING_OBLIGATIONS)
            .map_err(storage)?;
        let missing: Vec<String> = stmt
            .query_map(params![task_id.0], |row| row.get(0))
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        drop(stmt);
        for criterion_id in missing {
            self.conn
                .execute(
                    sql::INSERT_OBLIGATION,
                    params![EvidenceId::generate().0, task_id.0, criterion_id],
                )
                .map_err(storage)?;
        }
        Ok(())
    }

    /// Completion guard (EDGE-001): `completed` requires every criterion's
    /// and no unknown attempt. An empty ready queue never completes a task.
    pub fn complete_if_eligible(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
    ) -> Result<TaskSnapshot> {
        let tx = self.conn.transaction().map_err(storage)?;
        let lifecycle: String = tx
            .query_row(sql::TASK_LIFECYCLE, params![task_id.0], |row| row.get(0))
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_task(&task_id.0))?;
        if Lifecycle::from_db(&lifecycle).is_terminal() {
            return Err(StoreError::Conflict(ConflictCause::TaskAlreadyTerminal));
        }
        let (unsatisfied, unresolved, unknown): (u64, u64, u64) = tx
            .query_row(sql::COMPLETION_COUNTS, params![task_id.0], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u64,
                ))
            })
            .map_err(storage)?;
        if unsatisfied > 0 || unresolved > 0 || unknown > 0 {
            tx.execute(sql::PAUSE_RUNNING_TASK, params![task_id.0])
                .map_err(storage)?;
            Self::snapshot_in_tx(&tx, task_id)?;
            tx.commit().map_err(storage)?;
            return Err(StoreError::Conflict(ConflictCause::CompletionOpen {
                unsatisfied,
                unresolved,
                unknown,
            }));
        }
        let stale: u64 = tx
            .query_row(sql::STALE_EVIDENCE_COUNT, params![task_id.0], |row| {
                row.get::<_, i64>(0).map(|v| v as u64)
            })
            .map_err(storage)?;
        if stale > 0 {
            return Err(StoreError::Conflict(ConflictCause::CompletionStale {
                stale,
            }));
        }
        let revision: u64 = tx
            .query_row(sql::TASK_REVISION, params![task_id.0], |row| {
                row.get::<_, i64>(0).map(|v| v as u64)
            })
            .map_err(storage)?;
        tx.execute(
            sql::COMPLETE_TASK,
            params![task_id.0, (revision + 1) as i64],
        )
        .map_err(storage)?;
        Self::append_event(
            &tx,
            session_id,
            Some(task_id),
            (&task_id.0, revision + 1),
            "task.completed",
            json!({}),
            "state",
        )?;
        let snapshot = Self::snapshot_in_tx(&tx, task_id)?;
        tx.commit().map_err(storage)?;
        Ok(snapshot)
    }

    // ----- retained records -----

    pub fn retain(&mut self, record_json: &str, boundary_id: &str) -> Result<()> {
        self.conn
            .execute(sql::UPSERT_RETAINED, params![boundary_id, record_json])
            .map_err(storage)?;
        Ok(())
    }

    pub fn retained(&self, boundary_id: &str) -> Result<Option<String>> {
        let record = self
            .conn
            .query_row(sql::RETAINED_BY_ID, params![boundary_id], |row| row.get(0))
            .optional()
            .map_err(storage)?;
        Ok(record)
    }
}

impl Lifecycle {
    fn from_db(raw: &str) -> Self {
        match raw {
            "waiting" => Self::Waiting,
            "paused" => Self::Paused,
            "blocked" => Self::Blocked,
            "completed" => Self::Completed,
            "cancelled" => Self::Cancelled,
            _ => Self::Running,
        }
    }
}

fn goal_artifact_id(task_id: &TaskId) -> String {
    format!("goal-{}", task_id.0)
}

const ASK_PROMPT: &str = "Which form should we use?";
const ASK_BRIEF_LABEL: &str = "Brief answer";
const ASK_BRIEF_CONSEQUENCES: &str = "The essentials without a breakdown.";
const ASK_STEPS_LABEL: &str = "Step-by-step";
const ASK_STEPS_CONSEQUENCES: &str = "Sequential steps with an explanation of each.";
const ASK_WORKED_LABEL: &str = "Worked example";
const ASK_WORKED_CONSEQUENCES: &str = "A full example from the given conditions to the result.";
const ASK_COMPARE_LABEL: &str = "Compare options";
const ASK_COMPARE_CONSEQUENCES: &str = "A table of trade-offs.";
const ASK_DIAGRAM_LABEL: &str = "Diagram";
const ASK_DIAGRAM_CONSEQUENCES: &str = "A visual structure diagram.";
const ASK_DIAGRAM_DISABLED: &str = "no useful diagram for this topic";
const ASK_RECOMMENDATION: &str =
    "the request does not need a detailed breakdown; the brief form meets the criterion.";

impl Question {
    pub fn fixture(task_id: &TaskId, intent_revision: u64) -> Self {
        let option = |id: &str, label: &str, consequences: &str, availability: Availability| {
            QuestionOption {
                option_id: OptionId(id.to_string()),
                label: label.to_string(),
                consequences: consequences.to_string(),
                availability,
            }
        };
        Self {
            question_id: QuestionId::generate(),
            question_revision: 1,
            task_id: task_id.clone(),
            intent_revision,
            prompt: ASK_PROMPT.to_string(),
            options: vec![
                option(
                    "brief",
                    ASK_BRIEF_LABEL,
                    ASK_BRIEF_CONSEQUENCES,
                    Availability::Enabled,
                ),
                option(
                    "steps",
                    ASK_STEPS_LABEL,
                    ASK_STEPS_CONSEQUENCES,
                    Availability::Enabled,
                ),
                option(
                    "worked",
                    ASK_WORKED_LABEL,
                    ASK_WORKED_CONSEQUENCES,
                    Availability::Enabled,
                ),
                option(
                    "compare",
                    ASK_COMPARE_LABEL,
                    ASK_COMPARE_CONSEQUENCES,
                    Availability::Enabled,
                ),
                option(
                    "diagram",
                    ASK_DIAGRAM_LABEL,
                    ASK_DIAGRAM_CONSEQUENCES,
                    Availability::Disabled {
                        reason: ASK_DIAGRAM_DISABLED.to_string(),
                    },
                ),
            ],
            recommended_option_id: OptionId("brief".to_string()),
            recommendation_basis: ASK_RECOMMENDATION.to_string(),
        }
    }
}
