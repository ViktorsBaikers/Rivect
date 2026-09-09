//! Named SQLite for the state owner. Schema lives in `schema.sql`;
//! statements are constants so CAS/outbox logic is not mixed with DDL.

pub const SCHEMA: &str = include_str!("schema.sql");

pub const BOOTSTRAP_RECEIPT_BY_KEY: &str =
    "SELECT result_json FROM bootstrap_receipts WHERE key = ?1";
pub const SESSION_EXISTS: &str = "SELECT EXISTS(SELECT 1 FROM sessions WHERE session_id = ?1)";
pub const INSERT_ATTACHMENT: &str = "INSERT INTO attachments (attachment_id, session_id, connection_id, bootstrap_id, params_digest, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'attached')";
pub const NEXT_SESSION_REVISION: &str =
    "SELECT COALESCE(MAX(session_revision), 0) + 1 FROM sessions WHERE session_id = ?1";
pub const INSERT_SESSION: &str = "INSERT INTO sessions (session_id, session_revision, created_at)
                     VALUES (?1, ?2, datetime('now'))";
pub const UPDATE_SESSION_REVISION: &str =
    "UPDATE sessions SET session_revision = ?2 WHERE session_id = ?1";
pub const INSERT_BOOTSTRAP_RECEIPT: &str =
    "INSERT INTO bootstrap_receipts (key, attachment_id, result_json) VALUES (?1, ?2, ?3)";
pub const NEXT_EVENT_CURSOR: &str = "SELECT COALESCE(MAX(cursor), 0) + 1 FROM events";
pub const INSERT_EVENT: &str = "INSERT INTO events (event_id, aggregate_id, aggregate_revision, cursor, session_id, task_id, event_type, delta_json, origin)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
pub const EVENTS_AFTER: &str = "SELECT event_id, aggregate_id, aggregate_revision, cursor, session_id, task_id, event_type, delta_json, origin
             FROM events WHERE session_id = ?1 AND cursor > ?2 ORDER BY cursor LIMIT ?3";
pub const EVENTS_AFTER_FOR_TASK: &str = "SELECT event_id, aggregate_id, aggregate_revision, cursor, session_id, task_id, event_type, delta_json, origin
             FROM events WHERE session_id = ?1 AND cursor > ?2 AND task_id = ?3 ORDER BY cursor LIMIT ?4";
pub const RECEIPT_BY_COMMAND: &str =
    "SELECT params_digest, result_json FROM command_receipts WHERE command_id = ?1";
pub const INSERT_RECEIPT: &str =
    "INSERT INTO command_receipts (command_id, session_id, principal, params_digest, result_json)
             VALUES (?1, ?2, ?3, ?4, ?5)";
pub const INSERT_TASK: &str = "INSERT INTO tasks (task_id, session_id, revision, intent_revision, contract_revision, lifecycle, goal_bytes, goal_digest, goal_artifact_id, event_cursor)
             VALUES (?1, ?2, 1, 1, 1, 'running', ?3, ?4, ?5, 0)";
pub const INSERT_CRITERION: &str =
    "INSERT INTO criteria (criterion_id, task_id, position, text) VALUES (?1, ?2, ?3, ?4)";
pub const INSERT_CONSTRAINT: &str =
    "INSERT INTO task_constraints (task_id, position, text) VALUES (?1, ?2, ?3)";
pub const TOUCH_EVENT_CURSOR: &str = "UPDATE tasks SET event_cursor = 1 WHERE task_id = ?1";
pub const TASK_REVISION_LIFECYCLE: &str =
    "SELECT revision, lifecycle FROM tasks WHERE task_id = ?1";
pub const PENDING_QUESTION_EXISTS: &str =
    "SELECT EXISTS(SELECT 1 FROM questions WHERE task_id = ?1 AND state = 'pending')";
pub const INSERT_QUESTION: &str = "INSERT INTO questions (question_id, task_id, revision, intent_revision, prompt, body_json, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending')";
pub const TASK_SET_WAITING: &str = "UPDATE tasks SET revision = ?2, lifecycle = 'waiting', event_cursor = event_cursor + 1 WHERE task_id = ?1";
pub const CURRENT_QUESTION: &str =
    "SELECT body_json, (SELECT revision FROM tasks WHERE task_id = ?2) FROM questions
                 WHERE task_id = ?2 AND state = 'pending' ORDER BY revision DESC LIMIT 1";
pub const TASK_REVISIONS: &str =
    "SELECT revision, intent_revision, lifecycle FROM tasks WHERE task_id = ?1";
pub const QUESTION_BY_ID: &str =
    "SELECT revision, state, body_json FROM questions WHERE question_id = ?1";
pub const ANSWER_QUESTION: &str = "UPDATE questions SET state = 'answered', answer_json = ?2, answered_origin = ?3 WHERE question_id = ?1";
pub const TASK_SET_RUNNING: &str = "UPDATE tasks SET revision = ?2, lifecycle = 'running', event_cursor = event_cursor + 1 WHERE task_id = ?1";
pub const UPDATE_INTENT: &str = "UPDATE tasks SET revision = ?2, intent_revision = ?3, event_cursor = event_cursor + 1 WHERE task_id = ?1";
pub const CANCEL_TASK: &str = "UPDATE tasks SET revision = ?2, lifecycle = 'cancelled', event_cursor = event_cursor + 1 WHERE task_id = ?1";
pub const TASK_LIFECYCLE: &str = "SELECT lifecycle FROM tasks WHERE task_id = ?1";
pub const SNAPSHOT_TASK: &str = "SELECT revision, intent_revision, contract_revision, lifecycle, goal_digest, goal_artifact_id, LENGTH(goal_bytes), event_cursor
                 FROM tasks WHERE task_id = ?1";
pub const CRITERIA_FOR_TASK: &str =
    "SELECT criterion_id, text FROM criteria WHERE task_id = ?1 ORDER BY position";
pub const CONSTRAINTS_FOR_TASK: &str =
    "SELECT text FROM task_constraints WHERE task_id = ?1 ORDER BY position";
pub const OBLIGATIONS_FOR_TASK: &str = "SELECT obligation_id, criterion_id, applicability, execution FROM obligations WHERE task_id = ?1";
pub const ATTEMPTS_FOR_TASK: &str =
    "SELECT attempt_id, action_id, effect_class, state FROM attempts WHERE task_id = ?1";
pub const PENDING_QUESTION: &str =
    "SELECT question_id, revision FROM questions WHERE task_id = ?1 AND state = 'pending'
                         ORDER BY revision DESC LIMIT 1";
pub const UNRESOLVED_OBLIGATIONS: &str =
    "SELECT COUNT(*) FROM obligations WHERE task_id = ?1 AND applicability = 'unresolved'";
pub const UNKNOWN_ATTEMPTS: &str =
    "SELECT COUNT(*) FROM attempts WHERE task_id = ?1 AND state = 'unknown'";
pub const TASKS_FOR_SESSION: &str = "SELECT task_id, revision, intent_revision, lifecycle FROM tasks WHERE session_id = ?1 ORDER BY rowid";
pub const INSERT_ATTEMPT: &str =
    "INSERT INTO attempts (attempt_id, task_id, action_id, effect_class, describe, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'planned')";
pub const UPDATE_ATTEMPT: &str =
    "UPDATE attempts SET state = ?2, detail = ?3 WHERE attempt_id = ?1";
pub const ATTEMPT_STATE: &str = "SELECT state FROM attempts WHERE attempt_id = ?1";
pub const ATTEMPT_RECORD: &str =
    "SELECT task_id, state, detail FROM attempts WHERE attempt_id = ?1";
pub const LATEST_UNRESOLVED_ATTEMPT: &str =
    "SELECT attempt_id FROM attempts WHERE task_id = ?1 AND state IN ('running', 'unknown')
                 ORDER BY rowid DESC LIMIT 1";
pub const GOAL_BYTES: &str = "SELECT goal_bytes FROM tasks WHERE task_id = ?1";
pub const OBLIGATION_COUNT: &str = "SELECT COUNT(*) FROM obligations WHERE task_id = ?1";
pub const ANSWERED_QUESTION: &str =
    "SELECT answer_json, answered_origin FROM questions WHERE task_id = ?1 AND state = 'answered'
                 ORDER BY rowid DESC LIMIT 1";
pub const OBLIGATION_AT_OFFSET: &str =
    "SELECT obligation_id FROM obligations WHERE task_id = ?1 ORDER BY rowid LIMIT 1 OFFSET ?2";
pub const INSERT_EVIDENCE: &str = "INSERT INTO evidence (evidence_id, task_id, scope, observation, digest, validity, obligation_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'current', ?6)";
pub const SATISFY_OBLIGATION: &str =
    "UPDATE obligations SET execution = 'satisfied' WHERE obligation_id = ?1";
pub const STALE_EVIDENCE: &str =
    "UPDATE evidence SET validity = 'stale' WHERE evidence_id = ?1 RETURNING obligation_id";
pub const STALE_OBLIGATION: &str = "UPDATE obligations SET applicability = 'unresolved', execution = 'stale' WHERE obligation_id = ?1";
pub const TASK_ID_FOR_OBLIGATION: &str = "SELECT task_id FROM obligations WHERE obligation_id = ?1";
pub const BLOCK_TASK_NOT_CANCELLED: &str = "UPDATE tasks SET revision = revision + 1, lifecycle = 'blocked', event_cursor = event_cursor + 1
                 WHERE task_id = ?1 AND lifecycle != 'cancelled'";
pub const EVIDENCE_VALIDITY: &str = "SELECT validity FROM evidence WHERE evidence_id = ?1";
pub const BLOCK_TASK_OPEN: &str = "UPDATE tasks SET revision = revision + 1, lifecycle = 'blocked', event_cursor = event_cursor + 1
                 WHERE task_id = ?1 AND lifecycle NOT IN ('completed', 'cancelled')";
pub const MISSING_OBLIGATIONS: &str =
    "SELECT criterion_id FROM criteria WHERE task_id = ?1 AND criterion_id NOT IN
                 (SELECT criterion_id FROM obligations WHERE task_id = ?1)";
pub const INSERT_OBLIGATION: &str =
    "INSERT INTO obligations (obligation_id, task_id, criterion_id, applicability, execution)
                     VALUES (?1, ?2, ?3, 'required', 'pending')";
pub const PAUSE_RUNNING_TASK: &str =
    "UPDATE tasks SET lifecycle = 'waiting' WHERE task_id = ?1 AND lifecycle = 'running'";
pub const STALE_EVIDENCE_COUNT: &str =
    "SELECT COUNT(*) FROM evidence e JOIN obligations o ON o.obligation_id = e.obligation_id
                 WHERE o.task_id = ?1 AND e.validity = 'stale'";
pub const TASK_REVISION: &str = "SELECT revision FROM tasks WHERE task_id = ?1";
pub const COMPLETE_TASK: &str = "UPDATE tasks SET revision = ?2, lifecycle = 'completed', event_cursor = event_cursor + 1 WHERE task_id = ?1";
pub const COMPLETION_COUNTS: &str = "SELECT
                    (SELECT COUNT(*) FROM obligations WHERE task_id = ?1 AND execution != 'satisfied'),
                    (SELECT COUNT(*) FROM obligations WHERE task_id = ?1 AND applicability = 'unresolved'),
                    (SELECT COUNT(*) FROM attempts WHERE task_id = ?1 AND state = 'unknown')";
pub const UPSERT_RETAINED: &str =
    "INSERT OR REPLACE INTO retained (boundary_id, record_json) VALUES (?1, ?2)";
pub const RETAINED_BY_ID: &str = "SELECT record_json FROM retained WHERE boundary_id = ?1";
