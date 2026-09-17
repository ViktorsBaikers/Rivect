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
pub const EVENT_BY_AGGREGATE_REVISION: &str = "SELECT event_id, aggregate_id, aggregate_revision, cursor, session_id, task_id, event_type, delta_json, origin
             FROM events WHERE aggregate_id = ?1 AND aggregate_revision = ?2";
pub const EVENT_COUNT: &str = "SELECT COUNT(*) FROM events";
pub const REPLAY_TODO_PROJECTION: &str =
    "INSERT OR REPLACE INTO todo_projection (task_id, revision, lifecycle)
             SELECT task_id, revision, lifecycle FROM tasks WHERE task_id = ?1";
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
pub const ATTEMPTS_FOR_TASK: &str = "SELECT attempt_id, action_id, effect_class, state FROM attempts WHERE task_id = ?1 ORDER BY rowid";
pub const PENDING_QUESTION: &str =
    "SELECT question_id, revision FROM questions WHERE task_id = ?1 AND state = 'pending'
                         ORDER BY revision DESC LIMIT 1";
pub const UNRESOLVED_OBLIGATIONS: &str =
    "SELECT COUNT(*) FROM obligations WHERE task_id = ?1 AND applicability = 'unresolved'";
pub const UNKNOWN_ATTEMPTS: &str =
    "SELECT COUNT(*) FROM attempts WHERE task_id = ?1 AND state = 'unknown'";
pub const SESSION_GENERATION: &str =
    "SELECT COALESCE(MAX(revision), 0) FROM tasks WHERE session_id = ?1";
pub const TASKS_FOR_SESSION_PAGE: &str = "SELECT task_id, revision, intent_revision, lifecycle FROM tasks WHERE session_id = ?1 ORDER BY rowid LIMIT ?2 OFFSET ?3";
pub const TODO_FOR_SESSION_PAGE: &str = "SELECT tp.task_id, tp.revision, tp.lifecycle FROM todo_projection tp JOIN tasks t ON t.task_id = tp.task_id WHERE t.session_id = ?1 ORDER BY t.rowid LIMIT ?2 OFFSET ?3";
fn task_placeholders(count: usize) -> String {
    (1..=count)
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn pending_questions_for_tasks(count: usize) -> String {
    format!(
        "SELECT q.task_id, q.question_id, q.revision FROM questions q
         WHERE q.task_id IN ({}) AND q.state = 'pending'
           AND q.rowid = (SELECT latest.rowid FROM questions latest
                          WHERE latest.task_id = q.task_id AND latest.state = 'pending'
                          ORDER BY latest.revision DESC LIMIT 1)",
        task_placeholders(count)
    )
}

pub fn unresolved_obligations_for_tasks(count: usize) -> String {
    format!(
        "SELECT task_id, COUNT(*) FROM obligations
         WHERE task_id IN ({}) AND applicability = 'unresolved' GROUP BY task_id",
        task_placeholders(count)
    )
}

pub fn unknown_attempts_for_tasks(count: usize) -> String {
    format!(
        "SELECT task_id, COUNT(*) FROM attempts
         WHERE task_id IN ({}) AND state = 'unknown' GROUP BY task_id",
        task_placeholders(count)
    )
}
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
// The DEC-068 unknown/error-applicability write flips applicability
// alone: STALE_OBLIGATION stays the only writer that touches
// execution, so an evaluation failure never impersonates stale
// evidence.
pub const UNRESOLVED_APPLICABILITY: &str =
    "UPDATE obligations SET applicability = 'unresolved' WHERE obligation_id = ?1";
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
pub const INSERT_SUPERVISOR_REACTION: &str =
    "INSERT INTO supervisor_reactions (task_id, reaction_json) VALUES (?1, ?2)";
pub const SUPERVISOR_REACTIONS_PAGE: &str = "SELECT reaction_json FROM supervisor_reactions WHERE task_id = ?1 ORDER BY id LIMIT ?2 OFFSET ?3";
// Column census for the reaction journal's idempotency step: a
// database created before the `id` append identity (intermediate
// commit 0131781) keeps a two-column table that `ORDER BY id` cannot
// page.
pub const SUPERVISOR_REACTIONS_COLUMNS: &str = "PRAGMA table_info(supervisor_reactions)";
// SQLite cannot ALTER TABLE ... ADD COLUMN a PRIMARY KEY, so the
// id-less journal is rebuilt in one batch: rows copy in rowid order,
// the stale table drops, the rebuilt one takes its name, and the task
// index is recreated with it.
pub const MIGRATE_SUPERVISOR_REACTIONS: &str = "CREATE TABLE supervisor_reactions_migrated (
                    id INTEGER PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    reaction_json TEXT NOT NULL
                ) STRICT;
                INSERT INTO supervisor_reactions_migrated (task_id, reaction_json)
                    SELECT task_id, reaction_json FROM supervisor_reactions ORDER BY rowid;
                DROP TABLE supervisor_reactions;
                ALTER TABLE supervisor_reactions_migrated RENAME TO supervisor_reactions;
                CREATE INDEX IF NOT EXISTS idx_supervisor_reactions_task
                    ON supervisor_reactions (task_id);";
// The admission counter is scoped to the target, not (owner, target):
// every intent competing for one target draws from the same sequence, so
// concurrent intents are totally ordered by admission, never by owner
// spelling (EDGE-009 — a UUID is not an admission order).
pub const NEXT_PUBLICATION_SEQ: &str =
    "SELECT COALESCE(MAX(admission_seq), 0) + 1 FROM config_publications
                 WHERE target = ?1";
pub const INSERT_PUBLICATION: &str = "INSERT INTO config_publications (owner, target, admission_seq, intended_digest, base_digest, identity, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending')";
// Selection order: target (the competition scope), then admission_seq
// (chronology). The journal key stays (owner, target, admission_seq);
// owner breaks ties only for rows journaled before the per-target
// counter — its legacy per-(owner, target) sequence could tie across
// owners. Every row this build writes has a unique (target, admission_seq).
pub const PENDING_PUBLICATIONS: &str =
    "SELECT owner, target, admission_seq, intended_digest, base_digest, identity
                 FROM config_publications WHERE state = 'pending'
                 ORDER BY target, admission_seq, owner";
// Terminal rows stay matchable: the singleflight replay of an
// already-applied intent observes the winner's receipt instead of
// minting a second journal row.
pub const APPLIED_PUBLICATIONS: &str =
    "SELECT owner, target, admission_seq, intended_digest, base_digest, identity
                 FROM config_publications WHERE state = 'applied'
                 ORDER BY target, admission_seq, owner";
pub const COMPLETE_PUBLICATION: &str = "UPDATE config_publications SET state = 'applied'
                 WHERE owner = ?1 AND target = ?2 AND admission_seq = ?3 AND state = 'pending'";
pub const INSERT_PREAPPROVAL: &str =
    "INSERT OR REPLACE INTO preapprovals (scope, granted_by, expires_at)
                 VALUES (?1, ?2, datetime('now', ?3))";
pub const PREAPPROVAL_LIVE: &str =
    "SELECT EXISTS(SELECT 1 FROM preapprovals WHERE scope = ?1 AND expires_at > datetime('now'))";
pub const INSERT_BUDGET_SCOPE: &str =
    "INSERT INTO budget_scopes (scope, limit_units, spent, reserved) VALUES (?1, ?2, 0, 0)";
pub const BUDGET_SCOPE_ROW: &str =
    "SELECT limit_units, spent, reserved FROM budget_scopes WHERE scope = ?1";
// The admission invariant lives in the WHERE clause (INV-022): the
// check and the increment are one statement, so two children racing
// for the last reserveable budget serialize on the write lock and
// exactly one UPDATE matches.
pub const RESERVE_BUDGET: &str = "UPDATE budget_scopes SET reserved = reserved + ?2
                 WHERE scope = ?1 AND spent + reserved + ?2 <= limit_units";
pub const INSERT_BUDGET_RESERVATION: &str =
    "INSERT INTO budget_reservations (reservation_id, scope, bound, state)
                 VALUES (?1, ?2, ?3, 'reserved')";
pub const RESERVATION_EXISTS: &str =
    "SELECT EXISTS(SELECT 1 FROM budget_reservations WHERE reservation_id = ?1)";
pub const BUDGET_RESERVATION_SCOPES: &str =
    "SELECT scope, bound, state FROM budget_reservations WHERE reservation_id = ?1 ORDER BY scope";
pub const CHARGE_BUDGET_SCOPE: &str =
    "UPDATE budget_scopes SET spent = spent + ?2, reserved = reserved - ?3 WHERE scope = ?1";
pub const RELEASE_BUDGET_SCOPE: &str =
    "UPDATE budget_scopes SET reserved = reserved - ?2 WHERE scope = ?1";
pub const SET_BUDGET_RESERVATION_STATE: &str =
    "UPDATE budget_reservations SET state = ?2, charged = ?3 WHERE reservation_id = ?1";
pub const BUDGET_RESERVATION_ROW: &str =
    "SELECT state, bound, charged FROM budget_reservations WHERE reservation_id = ?1 LIMIT 1";
