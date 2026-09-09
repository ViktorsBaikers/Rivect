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
#[derive(Debug, Clone, PartialEq)]
pub enum StoreError {
    NotFound(String),
    Conflict(String),
    StaleIntent { expected: u64, current: u64 },
    AlreadyTerminal,
    InvalidInput(String),
    Storage(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(what) => write!(f, "not found: {what}"),
            Self::Conflict(why) => write!(f, "conflict: {why}"),
            Self::StaleIntent { expected, current } => {
                write!(f, "stale intent: expected {expected}, current {current}")
            }
            Self::AlreadyTerminal => write!(f, "already terminal"),
            Self::InvalidInput(why) => write!(f, "invalid input: {why}"),
            Self::Storage(why) => write!(f, "storage: {why}"),
        }
    }
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
}

pub type Result<T, E = StoreError> = std::result::Result<T, E>;

fn storage(err: rusqlite::Error) -> StoreError {
    StoreError::Storage(err.to_string())
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
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                session_revision INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attachments (
                attachment_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                connection_id TEXT NOT NULL,
                bootstrap_id TEXT NOT NULL,
                params_digest TEXT NOT NULL,
                state TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS bootstrap_receipts (
                key TEXT PRIMARY KEY,
                attachment_id TEXT NOT NULL,
                result_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                intent_revision INTEGER NOT NULL,
                contract_revision INTEGER NOT NULL,
                lifecycle TEXT NOT NULL,
                goal_bytes BLOB NOT NULL,
                goal_digest TEXT NOT NULL,
                goal_artifact_id TEXT NOT NULL,
                event_cursor INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS criteria (
                criterion_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                position INTEGER NOT NULL,
                text TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS task_constraints (
                task_id TEXT NOT NULL,
                position INTEGER NOT NULL,
                text TEXT NOT NULL,
                PRIMARY KEY (task_id, position)
            );
            CREATE TABLE IF NOT EXISTS obligations (
                obligation_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                criterion_id TEXT NOT NULL,
                applicability TEXT NOT NULL,
                execution TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                scope TEXT NOT NULL,
                observation TEXT NOT NULL,
                digest TEXT NOT NULL,
                validity TEXT NOT NULL,
                obligation_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS questions (
                question_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                intent_revision INTEGER NOT NULL,
                prompt TEXT NOT NULL,
                body_json TEXT NOT NULL,
                state TEXT NOT NULL,
                answer_json TEXT,
                answered_origin TEXT
            );
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                aggregate_id TEXT NOT NULL,
                aggregate_revision INTEGER NOT NULL,
                cursor INTEGER NOT NULL UNIQUE,
                session_id TEXT NOT NULL,
                task_id TEXT,
                event_type TEXT NOT NULL,
                delta_json TEXT NOT NULL,
                origin TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_events_aggregate
                ON events (aggregate_id, aggregate_revision);
            CREATE TABLE IF NOT EXISTS command_receipts (
                command_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                principal TEXT NOT NULL,
                params_digest TEXT NOT NULL,
                result_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attempts (
                attempt_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                effect_class TEXT NOT NULL,
                describe TEXT NOT NULL,
                state TEXT NOT NULL,
                detail TEXT
            );
            CREATE TABLE IF NOT EXISTS retained (
                boundary_id TEXT PRIMARY KEY,
                record_json TEXT NOT NULL
            );",
        )
        .map_err(storage)?;
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
            .query_row(
                "SELECT result_json FROM bootstrap_receipts WHERE key = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(storage)?;
        if let Some(result_json) = replay {
            let value: Value = serde_json::from_str(&result_json)
                .map_err(|err| StoreError::Storage(err.to_string()))?;
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
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM sessions WHERE session_id = ?1)",
                        params![id.0],
                        |row| row.get(0),
                    )
                    .map_err(storage)?;
                if !exists {
                    return Err(StoreError::NotFound(format!("session {}", id.0)));
                }
                id.clone()
            }
            None => SessionId::generate(),
        };
        let attachment_id = AttachmentId::generate();
        self.conn
            .execute(
                "INSERT INTO attachments (attachment_id, session_id, connection_id, bootstrap_id, params_digest, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'attached')",
                params![attachment_id.0, session_id.0, connection_id, bootstrap_id, params_digest],
            )
            .map_err(storage)?;
        let revision: u64 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(session_revision), 0) + 1 FROM sessions WHERE session_id = ?1",
                params![session_id.0],
                |row| row.get::<_, i64>(0).map(|v| v as u64),
            )
            .map_err(storage)?;
        if attach_to.is_none() {
            self.conn
                .execute(
                    "INSERT INTO sessions (session_id, session_revision, created_at)
                     VALUES (?1, ?2, datetime('now'))",
                    params![session_id.0, revision as i64],
                )
                .map_err(storage)?;
        } else {
            self.conn
                .execute(
                    "UPDATE sessions SET session_revision = ?2 WHERE session_id = ?1",
                    params![session_id.0, revision as i64],
                )
                .map_err(storage)?;
        }
        let result_json = serde_json::to_string(&json!({
            "session_id": session_id.0,
            "attachment_id": attachment_id.0,
            "owner_generation": 1u64,
        }))
        .map_err(|err| StoreError::Storage(err.to_string()))?;
        self.conn
            .execute(
                "INSERT INTO bootstrap_receipts (key, attachment_id, result_json) VALUES (?1, ?2, ?3)",
                params![key, attachment_id.0, result_json],
            )
            .map_err(storage)?;
        Ok((session_id, attachment_id, 1, false))
    }

    // ----- events -----

    fn next_cursor(tx: &rusqlite::Transaction<'_>) -> Result<u64> {
        let cursor: u64 = tx
            .query_row(
                "SELECT COALESCE(MAX(cursor), 0) + 1 FROM events",
                [],
                |row| row.get::<_, i64>(0).map(|v| v as u64),
            )
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
            "INSERT INTO events (event_id, aggregate_id, aggregate_revision, cursor, session_id, task_id, event_type, delta_json, origin)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                event.event_id.0,
                event.aggregate_id,
                event.aggregate_revision as i64,
                event.cursor as i64,
                event.session_id.0,
                event.task_id.as_ref().map(|id| id.0.clone()),
                event.event_type,
                serde_json::to_string(&event.delta).map_err(|e| StoreError::Storage(e.to_string()))?,
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
        let mut sql = "SELECT event_id, aggregate_id, aggregate_revision, cursor, session_id, task_id, event_type, delta_json, origin
             FROM events WHERE session_id = ?1 AND cursor > ?2".to_string();
        let mut args: Vec<Box<dyn rusqlite::ToSql>> =
            vec![Box::new(session_id.0.clone()), Box::new(after as i64)];
        if let Some(id) = task_id {
            sql.push_str(" AND task_id = ?3");
            args.push(Box::new(id.0.clone()));
        }
        sql.push_str(" ORDER BY cursor LIMIT ");
        sql.push_str(&limit.to_string());
        let mut stmt = self.conn.prepare(&sql).map_err(storage)?;
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
            .query_row(
                "SELECT params_digest, result_json FROM command_receipts WHERE command_id = ?1",
                params![command_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
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
            "INSERT INTO command_receipts (command_id, session_id, principal, params_digest, result_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                command_id,
                session_id.0,
                principal,
                params_digest,
                serde_json::to_string(result).map_err(|e| StoreError::Storage(e.to_string()))?
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
            return Err(StoreError::InvalidInput(
                "goal must be non-empty bounded text".into(),
            ));
        }
        let params_digest = format!("create|{principal}|{goal}|{}", criteria.join("\u{1}"));
        if let Some((digest, result_json)) = self.receipt(command_id)? {
            if digest != params_digest {
                return Err(StoreError::Conflict(format!(
                    "command {command_id} already recorded with different params"
                )));
            }
            let result: CommandResult = serde_json::from_str(&result_json)
                .map_err(|e| StoreError::Storage(e.to_string()))?;
            return Ok(result);
        }
        let task_id = TaskId::generate();
        let goal_bytes = goal.as_bytes().to_vec();
        let digest = crate::config::hex(&sha2::Sha256::digest(&goal_bytes));
        let tx = self.conn.transaction().map_err(storage)?;
        tx.execute(
            "INSERT INTO tasks (task_id, session_id, revision, intent_revision, contract_revision, lifecycle, goal_bytes, goal_digest, goal_artifact_id, event_cursor)
             VALUES (?1, ?2, 1, 1, 1, 'running', ?3, ?4, ?5, 0)",
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
                "INSERT INTO criteria (criterion_id, task_id, position, text) VALUES (?1, ?2, ?3, ?4)",
                params![criterion_id.0, task_id.0, position as i64, text],
            )
            .map_err(storage)?;
        }
        for (position, text) in constraints.iter().enumerate() {
            tx.execute(
                "INSERT INTO task_constraints (task_id, position, text) VALUES (?1, ?2, ?3)",
                params![task_id.0, position as i64, text],
            )
            .map_err(storage)?;
        }
        tx.execute(
            "UPDATE tasks SET event_cursor = 1 WHERE task_id = ?1",
            params![task_id.0],
        )
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
                "SELECT revision, lifecycle FROM tasks WHERE task_id = ?1",
                params![question.task_id.0],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get(1)?)),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::NotFound(format!("task {}", question.task_id.0)))?;
        if lifecycle != "running" {
            return Err(StoreError::Conflict(format!(
                "cannot publish a question for a {lifecycle} task"
            )));
        }
        let pending: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM questions WHERE task_id = ?1 AND state = 'pending')",
                params![question.task_id.0],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if pending {
            return Err(StoreError::Conflict(
                "a pending question already exists".into(),
            ));
        }
        tx.execute(
            "INSERT INTO questions (question_id, task_id, revision, intent_revision, prompt, body_json, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending')",
            params![
                question.question_id.0,
                question.task_id.0,
                question.question_revision as i64,
                question.intent_revision as i64,
                question.prompt,
                serde_json::to_string(question).map_err(|e| StoreError::Storage(e.to_string()))?
            ],
        )
        .map_err(storage)?;
        let new_revision = revision + 1;
        tx.execute(
            "UPDATE tasks SET revision = ?2, lifecycle = 'waiting', event_cursor = event_cursor + 1 WHERE task_id = ?1",
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
                "SELECT body_json, (SELECT revision FROM tasks WHERE task_id = ?2) FROM questions
                 WHERE task_id = ?2 AND state = 'pending' ORDER BY revision DESC LIMIT 1",
                params![task_id.0, task_id.0],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(storage)?;
        match row {
            None => Ok(None),
            Some((body, revision)) => {
                let question: Question =
                    serde_json::from_str(&body).map_err(|e| StoreError::Storage(e.to_string()))?;
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
            .query_row(
                "SELECT revision, intent_revision, lifecycle FROM tasks WHERE task_id = ?1",
                params![task_id.0],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u64,
                        row.get::<_, i64>(1)? as u64,
                        row.get(2)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::NotFound(format!("task {}", task_id.0)))?;
        if Lifecycle::from_db(&lifecycle).is_terminal() {
            return Err(StoreError::AlreadyTerminal);
        }
        let (stored_revision, state, body_json): (u64, String, String) = tx
            .query_row(
                "SELECT revision, state, body_json FROM questions WHERE question_id = ?1",
                params![question_id.0],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::NotFound(format!("question {}", question_id.0)))?;
        if state != "pending" {
            return Err(StoreError::Conflict("question is no longer pending".into()));
        }
        if stored_revision != question_revision {
            return Err(StoreError::Conflict(format!(
                "question revision {question_revision} is not the current revision {stored_revision}"
            )));
        }
        let question: Question =
            serde_json::from_str(&body_json).map_err(|e| StoreError::Storage(e.to_string()))?;
        match selection {
            AnswerSelection::Option { option_id } => {
                let Some(option) = question.options.iter().find(|o| o.option_id == *option_id)
                else {
                    return Err(StoreError::InvalidInput(format!(
                        "unknown option {} for question {}",
                        option_id.0, question_id.0
                    )));
                };
                if let Availability::Disabled { reason } = &option.availability {
                    return Err(StoreError::InvalidInput(format!(
                        "option {} is disabled: {reason}",
                        option_id.0
                    )));
                }
            }
            AnswerSelection::Custom { text } => {
                if text.trim().is_empty() {
                    return Err(StoreError::InvalidInput(
                        "custom answer must be non-empty".into(),
                    ));
                }
            }
        }
        let answer_json =
            serde_json::to_string(selection).map_err(|e| StoreError::Storage(e.to_string()))?;
        tx.execute(
            "UPDATE questions SET state = 'answered', answer_json = ?2, answered_origin = ?3 WHERE question_id = ?1",
            params![question_id.0, answer_json, author],
        )
        .map_err(storage)?;
        let new_revision = revision + 1;
        tx.execute(
            "UPDATE tasks SET revision = ?2, lifecycle = 'running', event_cursor = event_cursor + 1 WHERE task_id = ?1",
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
            .query_row(
                "SELECT revision, intent_revision, lifecycle FROM tasks WHERE task_id = ?1",
                params![task_id.0],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u64,
                        row.get::<_, i64>(1)? as u64,
                        row.get(2)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::NotFound(format!("task {}", task_id.0)))?;
        if Lifecycle::from_db(&lifecycle).is_terminal() {
            return Err(StoreError::Conflict(
                "terminal task cannot be reopened".into(),
            ));
        }
        if intent_revision != expected_intent_revision {
            return Err(StoreError::StaleIntent {
                expected: expected_intent_revision,
                current: intent_revision,
            });
        }
        if revision != expected_task_revision {
            return Err(StoreError::Conflict(format!(
                "task revision {expected_task_revision} is not the current revision {revision}"
            )));
        }
        let new_revision = revision + 1;
        let new_intent = intent_revision + 1;
        tx.execute(
            "UPDATE tasks SET revision = ?2, intent_revision = ?3, event_cursor = event_cursor + 1 WHERE task_id = ?1",
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
            .query_row(
                "SELECT revision, intent_revision, lifecycle FROM tasks WHERE task_id = ?1",
                params![task_id.0],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u64,
                        row.get::<_, i64>(1)? as u64,
                        row.get(2)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::NotFound(format!("task {}", task_id.0)))?;
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
        tx.execute(
            "UPDATE tasks SET revision = ?2, lifecycle = 'cancelled', event_cursor = event_cursor + 1 WHERE task_id = ?1",
            params![task_id.0, (revision + 1) as i64],
        )
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
            .query_row(
                "SELECT lifecycle FROM tasks WHERE task_id = ?1",
                params![task_id.0],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::NotFound(format!("task {}", task_id.0)))?;
        Ok(lifecycle == "cancelled")
    }

    // ----- snapshots -----

    fn snapshot_in_tx(tx: &rusqlite::Transaction<'_>, task_id: &TaskId) -> Result<TaskSnapshot> {
        let (revision, intent_revision, contract_revision, lifecycle, goal_digest, artifact_id, goal_len, event_cursor): (
            u64,
            u64,
            u64,
            String,
            String,
            String,
            usize,
            u64,
        ) = tx
            .query_row(
                "SELECT revision, intent_revision, contract_revision, lifecycle, goal_digest, goal_artifact_id, LENGTH(goal_bytes), event_cursor
                 FROM tasks WHERE task_id = ?1",
                params![task_id.0],
                |row| {
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
                },
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::NotFound(format!("task {}", task_id.0)))?;
        let mut criteria_stmt = tx
            .prepare("SELECT criterion_id, text FROM criteria WHERE task_id = ?1 ORDER BY position")
            .map_err(storage)?;
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
        let mut constraints_stmt = tx
            .prepare("SELECT text FROM task_constraints WHERE task_id = ?1 ORDER BY position")
            .map_err(storage)?;
        let constraints = constraints_stmt
            .query_map(params![task_id.0], |row| row.get::<_, String>(0))
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        let mut obligations_stmt = tx
            .prepare("SELECT obligation_id, criterion_id, applicability, execution FROM obligations WHERE task_id = ?1")
            .map_err(storage)?;
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
        let mut attempts_stmt = tx
            .prepare("SELECT attempt_id, action_id, effect_class, state FROM attempts WHERE task_id = ?1")
            .map_err(storage)?;
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
            .query_row(
                "SELECT lifecycle FROM tasks WHERE task_id = ?1",
                params![task_id.0],
                |row| row.get(0),
            )
            .map_err(storage)?;
        let mut blockers = Vec::new();
        match lifecycle.as_str() {
            "waiting" => {
                let pending: Option<(String, u64)> = tx
                    .query_row(
                        "SELECT question_id, revision FROM questions WHERE task_id = ?1 AND state = 'pending'
                         ORDER BY revision DESC LIMIT 1",
                        params![task_id.0],
                        |row| Ok((row.get(0)?, row.get::<_, i64>(1)? as u64)),
                    )
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
                    .query_row(
                        "SELECT COUNT(*) FROM obligations WHERE task_id = ?1 AND applicability = 'unresolved'",
                        params![task_id.0],
                        |row| row.get::<_, i64>(0).map(|v| v as u64),
                    )
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
                    .query_row(
                        "SELECT COUNT(*) FROM attempts WHERE task_id = ?1 AND state = 'unknown'",
                        params![task_id.0],
                        |row| row.get::<_, i64>(0).map(|v| v as u64),
                    )
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
        let mut stmt = self
            .conn
            .prepare(
                "SELECT task_id, revision, intent_revision, lifecycle FROM tasks WHERE session_id = ?1 ORDER BY rowid",
            )
            .map_err(storage)?;
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
            return Err(StoreError::Conflict(format!(
                "cursor generation {generation} does not match snapshot generation {}",
                snapshot.revision
            )));
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
                return Err(StoreError::InvalidInput(format!(
                    "unknown collection {other}"
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
                "INSERT INTO attempts (attempt_id, task_id, action_id, effect_class, describe, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'planned')",
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
            .execute(
                "UPDATE attempts SET state = ?2, detail = ?3 WHERE attempt_id = ?1",
                params![attempt_id, state, detail],
            )
            .map_err(storage)?;
        if changed == 0 {
            return Err(StoreError::NotFound(format!("attempt {attempt_id}")));
        }
        Ok(())
    }

    pub fn attempt_state(&self, attempt_id: &str) -> Result<Option<String>> {
        let state = self
            .conn
            .query_row(
                "SELECT state FROM attempts WHERE attempt_id = ?1",
                params![attempt_id],
                |row| row.get(0),
            )
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
            .query_row(
                "SELECT task_id, state, detail FROM attempts WHERE attempt_id = ?1",
                params![attempt_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?;
        Ok(record)
    }

    /// The newest unresolved (running or unknown) attempt of a task, if any:
    /// the no-repeat guard for the next dispatch decision.
    pub fn latest_unresolved_attempt(&self, task_id: &TaskId) -> Result<Option<String>> {
        let attempt_id = self
            .conn
            .query_row(
                "SELECT attempt_id FROM attempts WHERE task_id = ?1 AND state IN ('running', 'unknown')
                 ORDER BY rowid DESC LIMIT 1",
                params![task_id.0],
                |row| row.get(0),
            )
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
            .query_row(
                "SELECT goal_bytes FROM tasks WHERE task_id = ?1",
                params![task_id.0],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::NotFound(format!("task {}", task_id.0)))?;
        Ok(bytes)
    }

    pub fn obligations_count(&self, task_id: &TaskId) -> Result<usize> {
        let count = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM obligations WHERE task_id = ?1",
                params![task_id.0],
                |row| row.get::<_, i64>(0).map(|v| v as usize),
            )
            .map_err(storage)?;
        Ok(count)
    }

    /// The durable recorded answer for a task: (answer json, author origin).
    pub fn answered_question(&self, task_id: &TaskId) -> Result<Option<(String, String)>> {
        let row = self
            .conn
            .query_row(
                "SELECT answer_json, answered_origin FROM questions WHERE task_id = ?1 AND state = 'answered'
                 ORDER BY rowid DESC LIMIT 1",
                params![task_id.0],
                |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, Option<String>>(1)?)),
            )
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
                "SELECT obligation_id FROM obligations WHERE task_id = ?1 ORDER BY rowid LIMIT 1 OFFSET ?2",
                params![task_id.0, obligation_index as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::NotFound("obligation".into()))?;
        let evidence_id = EvidenceId::generate().0;
        self.conn
            .execute(
                "INSERT INTO evidence (evidence_id, task_id, scope, observation, digest, validity, obligation_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'current', ?6)",
                params![evidence_id, task_id.0, scope, observation, digest, obligation_id],
            )
            .map_err(storage)?;
        self.conn
            .execute(
                "UPDATE obligations SET execution = 'satisfied' WHERE obligation_id = ?1",
                params![obligation_id],
            )
            .map_err(storage)?;
        Ok(evidence_id)
    }

    pub fn invalidate_evidence(&mut self, evidence_id: &str) -> Result<String> {
        let obligation_id: String = self
            .conn
            .query_row(
                "UPDATE evidence SET validity = 'stale' WHERE evidence_id = ?1 RETURNING obligation_id",
                params![evidence_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::NotFound(format!("evidence {evidence_id}")))?;
        self.conn
            .execute(
                "UPDATE obligations SET applicability = 'unresolved', execution = 'stale' WHERE obligation_id = ?1",
                params![obligation_id],
            )
            .map_err(storage)?;
        let task_id: String = self
            .conn
            .query_row(
                "SELECT task_id FROM obligations WHERE obligation_id = ?1",
                params![obligation_id],
                |row| row.get(0),
            )
            .map_err(storage)?;
        self.conn
            .execute(
                "UPDATE tasks SET revision = revision + 1, lifecycle = 'blocked', event_cursor = event_cursor + 1
                 WHERE task_id = ?1 AND lifecycle != 'cancelled'",
                params![task_id],
            )
            .map_err(storage)?;
        Ok(task_id)
    }

    pub fn evidence_validity(&self, evidence_id: &str) -> Result<Option<String>> {
        let validity = self
            .conn
            .query_row(
                "SELECT validity FROM evidence WHERE evidence_id = ?1",
                params![evidence_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        Ok(validity)
    }

    /// A dispatch whose receipt was lost blocks the scope until the owner
    /// reconciles it; the snapshot carries an outcome_unknown blocker.
    pub fn mark_outcome_unknown(&mut self, task_id: &TaskId) -> Result<()> {
        self.conn
            .execute(
                "UPDATE tasks SET revision = revision + 1, lifecycle = 'blocked', event_cursor = event_cursor + 1
                 WHERE task_id = ?1 AND lifecycle NOT IN ('completed', 'cancelled')",
                params![task_id.0],
            )
            .map_err(storage)?;
        Ok(())
    }

    /// frame_goal contribution: the accepted receipt carries empty
    pub fn materialize_obligations(&mut self, task_id: &TaskId) -> Result<()> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT criterion_id FROM criteria WHERE task_id = ?1 AND criterion_id NOT IN
                 (SELECT criterion_id FROM obligations WHERE task_id = ?1)",
            )
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
                    "INSERT INTO obligations (obligation_id, task_id, criterion_id, applicability, execution)
                     VALUES (?1, ?2, ?3, 'required', 'pending')",
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
            .query_row(
                "SELECT lifecycle FROM tasks WHERE task_id = ?1",
                params![task_id.0],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::NotFound(format!("task {}", task_id.0)))?;
        if Lifecycle::from_db(&lifecycle).is_terminal() {
            return Err(StoreError::Conflict("task is already terminal".into()));
        }
        let (unsatisfied, unresolved, unknown): (u64, u64, u64) = tx
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM obligations WHERE task_id = ?1 AND execution != 'satisfied'),
                    (SELECT COUNT(*) FROM obligations WHERE task_id = ?1 AND applicability = 'unresolved'),
                    (SELECT COUNT(*) FROM attempts WHERE task_id = ?1 AND state = 'unknown')",
                params![task_id.0],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64, row.get::<_, i64>(2)? as u64)),
            )
            .map_err(storage)?;
        if unsatisfied > 0 || unresolved > 0 || unknown > 0 {
            tx.execute(
                "UPDATE tasks SET lifecycle = 'waiting' WHERE task_id = ?1 AND lifecycle = 'running'",
                params![task_id.0],
            )
            .map_err(storage)?;
            Self::snapshot_in_tx(&tx, task_id)?;
            tx.commit().map_err(storage)?;
            return Err(StoreError::Conflict(format!(
                "completion rejected: {unsatisfied} unsatisfied, {unresolved} unresolved, {unknown} unknown"
            )));
        }
        let stale: u64 = tx
            .query_row(
                "SELECT COUNT(*) FROM evidence e JOIN obligations o ON o.obligation_id = e.obligation_id
                 WHERE o.task_id = ?1 AND e.validity = 'stale'",
                params![task_id.0],
                |row| row.get::<_, i64>(0).map(|v| v as u64),
            )
            .map_err(storage)?;
        if stale > 0 {
            return Err(StoreError::Conflict(format!(
                "completion rejected: {stale} stale evidence"
            )));
        }
        let revision: u64 = tx
            .query_row(
                "SELECT revision FROM tasks WHERE task_id = ?1",
                params![task_id.0],
                |row| row.get::<_, i64>(0).map(|v| v as u64),
            )
            .map_err(storage)?;
        tx.execute(
            "UPDATE tasks SET revision = ?2, lifecycle = 'completed', event_cursor = event_cursor + 1 WHERE task_id = ?1",
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
            .execute(
                "INSERT OR REPLACE INTO retained (boundary_id, record_json) VALUES (?1, ?2)",
                params![boundary_id, record_json],
            )
            .map_err(storage)?;
        Ok(())
    }

    pub fn retained(&self, boundary_id: &str) -> Result<Option<String>> {
        let record = self
            .conn
            .query_row(
                "SELECT record_json FROM retained WHERE boundary_id = ?1",
                params![boundary_id],
                |row| row.get(0),
            )
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
            prompt: "Какую форму использовать?".to_string(),
            options: vec![
                option(
                    "brief",
                    "Краткий ответ",
                    "Самое существенное без разбора.",
                    Availability::Enabled,
                ),
                option(
                    "steps",
                    "Пошаговый разбор",
                    "Последовательные шаги с пояснением каждого.",
                    Availability::Enabled,
                ),
                option(
                    "worked",
                    "Разбор на примере",
                    "Полный пример от условия к результату.",
                    Availability::Enabled,
                ),
                option(
                    "compare",
                    "Сравнение вариантов",
                    "Таблица плюсов и минусов подходов.",
                    Availability::Enabled,
                ),
                option(
                    "diagram",
                    "Схема",
                    "Наглядная схема структуры.",
                    Availability::Disabled {
                        reason: "для этой темы нет полезной схемы".to_string(),
                    },
                ),
            ],
            recommended_option_id: OptionId("brief".to_string()),
            recommendation_basis:
                "запрос не требует детального разбора; краткая форма отвечает критерию.".to_string(),
        }
    }
}
