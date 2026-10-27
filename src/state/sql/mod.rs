//! Named SQLite for the state owner. Schema lives in `schema.sql`;
//! statements are constants so CAS/outbox logic is not mixed with DDL.
//! The one bounded existence read the session switch asks for executes
//! here beside its statement, so the switch never walks a page.
pub const SCHEMA: &str = include_str!("schema.sql");
/// Decision-owned DDL: the append-only answer-attempt journal. Idempotent
/// at open like `SCHEMA`; statement texts stay named below (P-002).
pub const DECISIONS_SCHEMA: &str = include_str!("decisions.sql");
/// Plan-owned DDL: selections, plan obligations, versioned plans, gate
/// holds and plan-owned block marks. Idempotent at open like `SCHEMA`.
pub const PLANS_SCHEMA: &str = include_str!("plans.sql");
/// Index-owned DDL: the versioned snapshot generations and their
/// derived edges. Idempotent at open like `SCHEMA`.
pub const INDEX_SCHEMA: &str = include_str!("index.sql");
/// Assumption-check records with immutable expectations. Idempotent at open.
pub const ASSUMPTIONS_SCHEMA: &str = include_str!("assumptions.sql");

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
pub const PENDING_QUESTION_EXISTS: &str =
    "SELECT EXISTS(SELECT 1 FROM questions WHERE task_id = ?1 AND state = 'pending')";
pub const INSERT_QUESTION: &str = "INSERT INTO questions (question_id, task_id, revision, intent_revision, prompt, body_json, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending')";
pub const TASK_SET_WAITING: &str = "UPDATE tasks SET revision = ?2, lifecycle = 'waiting', event_cursor = event_cursor + 1 WHERE task_id = ?1";
// The pending read is lifecycle-bound: a terminal task cannot own a live
// question, so a stale row left pending beside `completed`/`cancelled`
// (a pre-journal write or a foreign writer) stays invisible instead of
// resurrecting the task's wait on every question.current poll.
pub const CURRENT_QUESTION: &str =
    "SELECT q.body_json, t.revision, t.intent_revision FROM questions q
                 JOIN tasks t ON t.task_id = q.task_id
                 WHERE q.task_id = ?1 AND q.state = 'pending'
                 AND t.lifecycle NOT IN ('completed', 'cancelled')
                 ORDER BY q.revision DESC LIMIT 1";
pub const TASK_REVISIONS: &str =
    "SELECT revision, intent_revision, lifecycle FROM tasks WHERE task_id = ?1";
// A question is addressed by its owning task too: an answer that names
// another task's question id must miss the row, never answer across the
// task boundary. `intent_revision` rides along so a superseded row's
// stale pin reports `stale_intent`, not a generic not-pending conflict.
pub const QUESTION_BY_ID: &str = "SELECT revision, state, body_json, intent_revision FROM questions WHERE question_id = ?1 AND task_id = ?2";
/// A pending row whose intent pin no longer matches the task's live
/// intent is dead: `current_question` hides it and `answer_question`
/// denies it. Superseding keeps the row for audit while freeing the task
/// to publish the fork its live intent actually asks. RETURNING hands
/// back each killed row's id, revision and stale pin so the caller can
/// journal its `question.superseded` event in the same transaction — an
/// `events.read` replay must see the row die, not stay pending forever.
pub const SUPERSEDE_PENDING_QUESTIONS: &str = "UPDATE questions SET state = 'superseded'
                 WHERE task_id = ?1 AND state = 'pending' AND intent_revision != ?2
                 RETURNING question_id, revision, intent_revision";
/// A changed selection supersedes only a question its old plan row waits
/// on; returning the revision lets the caller journal the death atomically.
pub const SUPERSEDE_PLAN_QUESTION: &str = "UPDATE questions SET state = 'superseded'
                 WHERE question_id = ?1 AND task_id = ?2 AND revision = ?3 AND state = 'pending'
                 RETURNING revision";
/// Terminal transitions kill every pending row regardless of its intent
/// pin: the task can never publish the fork a still-live pin was waiting
/// on, so the row dies for the lifecycle, not for a stale pin. The row
/// is kept for audit and RETURNING hands back each killed row's id and
/// revision so its `question.superseded` event journals in the same
/// transaction.
pub const SUPERSEDE_TERMINAL_QUESTIONS: &str = "UPDATE questions SET state = 'superseded'
                 WHERE task_id = ?1 AND state = 'pending'
                 RETURNING question_id, revision";
/// Superseding a pending question ends the task's wait until its current
/// intent or plan selection publishes a replacement.
pub const SUPERSESSION_RESUMES_TASK: &str =
    "UPDATE tasks SET lifecycle = 'running' WHERE task_id = ?1 AND lifecycle = 'waiting'";
pub const ANSWER_QUESTION: &str = "UPDATE questions SET state = 'answered', answer_json = ?2, answered_origin = ?3 WHERE question_id = ?1";
pub const TASK_SET_RUNNING: &str = "UPDATE tasks SET revision = ?2, lifecycle = 'running', event_cursor = event_cursor + 1 WHERE task_id = ?1";
/// One attempt row: `applied` rows ride the answering transaction, denied
/// rows commit on their own so the journal never loses a rejection.
pub const INSERT_ANSWER_ATTEMPT: &str = "INSERT INTO answer_attempts (question_id, task_id, question_revision, selection_json, author, outcome, denial)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
pub const ANSWER_ATTEMPTS_FOR_TASK: &str =
    "SELECT id, question_id, task_id, question_revision, selection_json, author, outcome, denial
             FROM answer_attempts WHERE task_id = ?1 ORDER BY id";
/// The pause-binding read (AC-045): a decision step runs immediately
/// after its answer commit, so the task's newest applied row names the
/// question the step resolves — denied rows answer nothing and stay
/// invisible here.
pub const LATEST_APPLIED_ANSWER: &str =
    "SELECT question_id FROM answer_attempts WHERE task_id = ?1 AND outcome = 'applied'
                 ORDER BY id DESC LIMIT 1";
pub const EVIDENCE_FOR_TASK: &str =
    "SELECT evidence_id, task_id, scope, observation, digest, validity, obligation_id
             FROM evidence WHERE task_id = ?1 ORDER BY rowid";
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
pub const OBLIGATION_IDS_FOR_TASK: &str =
    "SELECT obligation_id FROM obligations WHERE task_id = ?1 ORDER BY rowid";
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
// Plan obligations count toward completion like criterion obligations:
// a required stage or check that never closed keeps the task open
// instead of vanishing from the guard.
pub const COMPLETION_COUNTS: &str = "SELECT
                    (SELECT COUNT(*) FROM obligations WHERE task_id = ?1 AND execution != 'satisfied')
                      + (SELECT COUNT(*) FROM plan_obligations WHERE task_id = ?1 AND execution != 'satisfied'),
                    (SELECT COUNT(*) FROM obligations WHERE task_id = ?1 AND applicability = 'unresolved')
                      + (SELECT COUNT(*) FROM plan_obligations WHERE task_id = ?1 AND applicability = 'unresolved'),
                    (SELECT COUNT(*) FROM attempts WHERE task_id = ?1 AND state = 'unknown')";
pub const ASSUMPTION_TASK_IN_SESSION: &str =
    "SELECT EXISTS(SELECT 1 FROM tasks WHERE session_id = ?1 AND task_id = ?2)";
pub const RECORD_ASSUMPTION_CHECK: &str = "INSERT INTO assumption_checks
                    (session_id, task_id, check_id, expected_result, assertion_digest, record_version, record_json)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                    ON CONFLICT(session_id, task_id, check_id) DO UPDATE SET record_json = excluded.record_json
                    WHERE assumption_checks.expected_result = excluded.expected_result
                      AND assumption_checks.assertion_digest = excluded.assertion_digest
                      AND assumption_checks.record_version = excluded.record_version";
pub const ASSUMPTION_CHECK_BY_ID: &str = "SELECT record_version, record_json FROM assumption_checks
                    WHERE session_id = ?1 AND task_id = ?2 AND check_id = ?3";
pub const INSERT_RETAINED_ONCE: &str = "INSERT INTO retained (boundary_id, record_json) VALUES (?1, ?2) ON CONFLICT(boundary_id) DO NOTHING";
pub const RETAINED_BY_ID: &str = "SELECT record_json FROM retained WHERE boundary_id = ?1";
pub const RETAINED_LATEST_BY_ID: &str = "SELECT record_json FROM retained
                    WHERE boundary_id = ?1 OR boundary_id = ?2
                    ORDER BY CASE boundary_id WHEN ?1 THEN 0 ELSE 1 END
                    LIMIT 1";
/// The dual-key collision read: every row at the direct or the terminal
/// key, so a conflicting row at either key surfaces instead of hiding
/// behind an identical row at the other.
pub const RETAINED_BY_BOTH_KEYS: &str = "SELECT record_json FROM retained
                    WHERE boundary_id = ?1 OR boundary_id = ?2
                    ORDER BY boundary_id";
/// One attempt's own retained check rows in boundary order: the DEC-047
/// recovery settlement predicate reads the durable rows alone. The
/// bounds are the attempt's boundary prefix and its successor (';' is
/// ':' + 1), so the rejection namespace (`ret:check-rejection:…`) and
/// the terminal namespace never intersect the range.
pub const CHECK_RETAINED_ROWS: &str = "SELECT boundary_id, record_json FROM retained
                    WHERE boundary_id BETWEEN ?1 AND ?2
                    ORDER BY boundary_id";
pub const EXISTS_RETAINED: &str = "SELECT EXISTS(SELECT 1 FROM retained WHERE boundary_id = ?1)";
// DEC-048 first-only dispatch claim (#6a): the attempt's task, effect
// class and state, the task's lifecycle, and the existence of the
// attempt's `admit.claim` marker — one statement, one owner operation.
pub const CLAIM_ATTEMPT_READ: &str = "SELECT
                    a.task_id,
                    a.effect_class,
                    a.state,
                    t.lifecycle,
                    EXISTS(SELECT 1 FROM retained WHERE boundary_id = ?2)
                    FROM attempts a JOIN tasks t ON t.task_id = a.task_id
                    WHERE a.attempt_id = ?1";
// DEC-048 claim #9: the conditional planned->running transition.
pub const CLAIM_ATTEMPT_RUNNING: &str = "UPDATE attempts SET state = 'running'
                    WHERE attempt_id = ?1 AND task_id = ?2 AND effect_class = 'exec' AND state = 'planned'";
// DEC-047 recovery reconcile: every attempt whose first-only check
// dispatch claim marker is durable — the whole Runtime-open recovery
// view in one statement. The boundary prefix is bound, never spliced.
pub const CHECK_CLAIMED_ATTEMPTS: &str = "SELECT a.attempt_id FROM attempts a
                    WHERE EXISTS (SELECT 1 FROM retained r
                                  WHERE r.boundary_id = ?1 || a.attempt_id || ':admit.claim')
                    ORDER BY a.rowid";
// DEC-048 claim #1: the actual busy timeout as a typed integer row.
pub const BUSY_TIMEOUT_READ: &str = "PRAGMA busy_timeout";
// DEC-051 healthy close: the two named maintenance statements, in the
// contract order (optimize first, then the truncating checkpoint).
pub const OPTIMIZE: &str = "PRAGMA optimize";
pub const WAL_CHECKPOINT_TRUNCATE: &str = "PRAGMA wal_checkpoint(TRUNCATE)";
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
    "UPDATE budget_scopes SET spent = spent + ?2, reserved = reserved - ?3
                  WHERE scope = ?1 AND reserved >= ?3";
pub const RELEASE_BUDGET_SCOPE: &str =
    "UPDATE budget_scopes SET reserved = reserved - ?2 WHERE scope = ?1";
pub const SET_BUDGET_RESERVATION_STATE: &str =
    "UPDATE budget_reservations SET state = ?2, charged = ?3 WHERE reservation_id = ?1";
pub const BUDGET_RESERVATION_ROW: &str =
    "SELECT state, bound, charged FROM budget_reservations WHERE reservation_id = ?1 LIMIT 1";

// ----- plan selection, plan obligations, plan revisions, gate holds -----

pub const PLAN_SELECTION: &str =
    "SELECT revision, facts_digest, request_kind FROM plan_selections WHERE task_id = ?1";
pub const UPSERT_PLAN_SELECTION: &str =
    "INSERT INTO plan_selections (task_id, revision, facts_digest, request_kind)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (task_id) DO UPDATE SET
                 revision = excluded.revision,
                 facts_digest = excluded.facts_digest,
                 request_kind = excluded.request_kind";
/// Changed facts rewrite the selection's rows wholesale: a row whose
/// need derives from the old facts must never stay satisfied under new
/// ones.
pub const DELETE_PLAN_OBLIGATIONS: &str = "DELETE FROM plan_obligations WHERE task_id = ?1";
pub const INSERT_PLAN_OBLIGATION: &str = "INSERT INTO plan_obligations
                 (task_id, capability, applicability, execution, stage, handler, blocker)
             VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?6)";
pub const PLAN_OBLIGATIONS_FOR_TASK: &str =
    "SELECT capability, applicability, execution, stage, handler, blocker, outcome_json
             FROM plan_obligations WHERE task_id = ?1 ORDER BY rowid";
pub const PLAN_ROW: &str =
    "SELECT applicability, handler FROM plan_obligations WHERE task_id = ?1 AND capability = ?2";
/// A close clears the row's blocker: the row no longer waits on it.
pub const CLOSE_PLAN_ROW: &str =
    "UPDATE plan_obligations SET execution = ?3, outcome_json = ?4, blocker = NULL
                 WHERE task_id = ?1 AND capability = ?2";
pub const BLOCK_PLAN_ROW: &str =
    "UPDATE plan_obligations SET blocker = ?3 WHERE task_id = ?1 AND capability = ?2";
/// Keep an applied fork's question pin after a later blocker replaces `Decision`.
pub const RETAIN_ANSWERED_PLAN_FORK: &str =
    "UPDATE plan_obligations SET outcome_json = ?3 WHERE task_id = ?1 AND capability = ?2";
/// A new plan revision reopens every required row its assessor closed —
/// the verdict on the replaced revision never covers the new one.
pub const REOPEN_PLAN_ROWS_BY_HANDLER: &str =
    "UPDATE plan_obligations SET execution = 'pending', outcome_json = NULL, blocker = NULL
                 WHERE task_id = ?1 AND handler = ?2 AND applicability = 'required'";
/// The DEC-068 applicability write for every plan row of a task:
/// applicability only — execution, outcome and the stored blocker stay,
/// so a verdict, fork or route blocker holds again once the row recovers.
pub const UNRESOLVE_PLAN_ROWS: &str =
    "UPDATE plan_obligations SET applicability = 'unresolved' WHERE task_id = ?1";
/// The PG-4 in-place reset of a row whose applicability recovered under
/// identical facts: applicability only, everything else as stored.
pub const RESET_PLAN_ROW_APPLICABILITY: &str = "UPDATE plan_obligations SET applicability = ?3
                 WHERE task_id = ?1 AND capability = ?2";
pub const NEXT_PLAN_REVISION: &str =
    "SELECT COALESCE(MAX(revision), 0) + 1 FROM plans WHERE task_id = ?1";
pub const INSERT_PLAN_REVISION: &str =
    "INSERT INTO plans (task_id, revision, selection_revision, body_json) VALUES (?1, ?2, ?3, ?4)";
pub const PLAN_REVISIONS_FOR_TASK: &str =
    "SELECT revision, selection_revision, body_json, verdict, assessment_json
             FROM plans WHERE task_id = ?1 ORDER BY revision";
/// The gate's revision conjunct reads only revisions recorded under the
/// current selection: an earlier selection's pass never opens it.
pub const LATEST_PLAN_VERDICT_FOR_SELECTION: &str =
    "SELECT verdict FROM plans WHERE task_id = ?1 AND selection_revision = ?2
                 ORDER BY revision DESC LIMIT 1";
/// A verdict lands only on the task's latest, still-unjudged revision
/// of the current selection: an assessment of a superseded plan must
/// never unblock its replacement.
pub const ASSESS_PLAN_REVISION: &str = "UPDATE plans SET verdict = ?4, assessment_json = ?5
                 WHERE task_id = ?1 AND revision = ?2 AND selection_revision = ?3
                 AND verdict IS NULL
                 AND revision = (SELECT MAX(revision) FROM plans WHERE task_id = ?1)";
pub const PLAN_GATE_HOLD: &str = "SELECT kind FROM plan_gate_holds WHERE task_id = ?1";
pub const UPSERT_PLAN_GATE_HOLD: &str =
    "INSERT INTO plan_gate_holds (task_id, kind) VALUES (?1, ?2)
             ON CONFLICT (task_id) DO UPDATE SET kind = excluded.kind";
pub const DELETE_PLAN_GATE_HOLD: &str = "DELETE FROM plan_gate_holds WHERE task_id = ?1";
pub const MARK_PLAN_BLOCK: &str = "INSERT OR IGNORE INTO plan_blocks (task_id) VALUES (?1)";
pub const CLEAR_PLAN_BLOCK: &str = "DELETE FROM plan_blocks WHERE task_id = ?1";
pub const PLAN_BLOCK_EXISTS: &str = "SELECT EXISTS(SELECT 1 FROM plan_blocks WHERE task_id = ?1)";
pub const PLAN_BLOCK_RUNNING_TASK: &str = "UPDATE tasks SET revision = revision + 1, lifecycle = 'blocked', event_cursor = event_cursor + 1
                 WHERE task_id = ?1 AND lifecycle = 'running'";
pub const PLAN_RELEASE_TASK: &str = "UPDATE tasks SET revision = revision + 1, lifecycle = 'running', event_cursor = event_cursor + 1
                 WHERE task_id = ?1 AND lifecycle = 'blocked'";
/// Every non-plan source that keeps a task from running: an unresolved
/// criterion obligation, an unknown attempt, a pending question.
pub const PLAN_RELEASE_BLOCKING_SOURCES: &str = "SELECT
                    (SELECT COUNT(*) FROM obligations WHERE task_id = ?1 AND applicability = 'unresolved')
                  + (SELECT COUNT(*) FROM attempts WHERE task_id = ?1 AND state = 'unknown')
                  + (SELECT COUNT(*) FROM questions WHERE task_id = ?1 AND state = 'pending')";

/// Plan blockers of a page of tasks in one statement — every row that
/// stores a blocker or waits on its applicability, in selection order,
/// then the task's gate hold — so the status and todo projections never
/// issue a query per task.
pub fn plan_blockers_for_tasks(count: usize) -> String {
    let tasks = task_placeholders(count);
    format!(
        "SELECT task_id, capability, applicability, blocker, kind FROM (
             SELECT task_id, 0 AS source, rowid AS position, capability, applicability, blocker,
                    NULL AS kind
               FROM plan_obligations WHERE task_id IN ({tasks})
                    AND (blocker IS NOT NULL OR applicability = 'unresolved')
             UNION ALL
             SELECT task_id, 1 AS source, 0 AS position, NULL AS capability,
                    NULL AS applicability, NULL AS blocker, kind
               FROM plan_gate_holds WHERE task_id IN ({tasks})
         ) ORDER BY task_id, source, position"
    )
}

// ----- index snapshot generations and their derived edges -----

/// The next generation number. A reserved number is monotonic even
/// after retention prunes the older rows: a `SnapshotId` is never
/// reissued.
pub const NEXT_INDEX_GENERATION: &str =
    "SELECT COALESCE(MAX(generation), 0) + 1 FROM index_generations";
/// A generation is reserved `stale`/`interrupted` and unsealed: a build
/// that never reaches its seal leaves exactly this row, which reads as
/// broken rather than current (INV-007). The stub's coverage is
/// `Partial`, never `Complete`: a reservation has verified nothing, so
/// reporting it as full coverage would be a claim no build ever made.
/// It carries no edges, so its graph is empty — an empty set of rows is
/// not a claim about the project.
pub const RESERVE_INDEX_GENERATION: &str =
    "INSERT INTO index_generations (generation, state, stale_cause, coverage_json, unresolved_json, sealed)
             VALUES (?1, 'stale', 'interrupted',
                     '{\"status\":\"partial\",\"reasons\":[{\"reason\":\"entries_failed\",\"count\":1}]}',
                     '[]', 0)";
pub const SEAL_INDEX_GENERATION: &str =
    "UPDATE index_generations SET state = ?2, stale_cause = ?3, coverage_json = ?4,
             unresolved_json = ?5, sealed = 1
             WHERE generation = ?1";
/// The repair trigger: mark one generation stale with its cause. Only
/// the state columns move — the coverage and unresolved specifiers the
/// build actually observed are kept, because a generation that failed
/// for one reason is still the record of what the other documents
/// showed. A fresh row is marked like any other: observing that the
/// project moved is exactly the case a fresh generation must be marked
/// for, so refusing to mark one would leave the stale bytes served as
/// current. `false` therefore means the number is unknown, nothing
/// else. The supersession below is the narrower statement.
pub const MARK_INDEX_GENERATION_STALE: &str =
    "UPDATE index_generations SET state = ?2, stale_cause = ?3, sealed = 1
             WHERE generation = ?1";
/// The supersession a seal performs in its own transaction: a row that
/// is still fresh stops being current the moment its successor commits.
/// A row that already carries a cause keeps it — `watcher_missed` says
/// more than `superseded` — so only a fresh row is touched.
pub const SUPERSEDE_INDEX_GENERATION: &str =
    "UPDATE index_generations SET state = 'stale', stale_cause = 'superseded', sealed = 1
             WHERE generation = ?1 AND state = 'fresh'";
pub const INDEX_GENERATION_ROW: &str =
    "SELECT state, stale_cause, coverage_json, unresolved_json, sealed FROM index_generations
             WHERE generation = ?1";
pub const LATEST_INDEX_GENERATION: &str =
    "SELECT generation FROM index_generations ORDER BY generation DESC LIMIT 1";
/// The generation an incremental cut carries from and supersedes: the
/// newest one that is not the number being sealed. The number is bound
/// because a seal runs against a row that is already the newest, so the
/// max alone would name the generation being written and every carry
/// would be empty.
pub const PREVIOUS_INDEX_GENERATION: &str =
    "SELECT generation FROM index_generations WHERE generation <> ?1
             ORDER BY generation DESC LIMIT 1";
/// The newest generation's state in one statement, so a report never
/// reads two rows that a concurrent cut could have moved apart.
pub const LATEST_INDEX_STATE: &str =
    "SELECT generation, state, stale_cause, sealed FROM index_generations
             ORDER BY generation DESC LIMIT 1";
/// Rows an incremental cut keeps: the previous generation's edges
/// whose subject document is not among the replaced paths.
pub const INDEX_EDGES_TO_CARRY: &str =
    "SELECT e.from_path, e.from_line, e.from_ignored, e.to_path, e.kind, e.provenance,
            e.version, e.confidence
             FROM index_edges e WHERE e.generation = ?1
               AND e.from_path NOT IN ({})";
pub const INSERT_INDEX_DOCUMENT: &str =
    "INSERT OR REPLACE INTO index_documents (generation, path) VALUES (?1, ?2)";
pub const INDEX_DOCUMENTS_FOR_GENERATION: &str =
    "SELECT path FROM index_documents WHERE generation = ?1 ORDER BY path";
pub const INSERT_INDEX_EDGE: &str =
    "INSERT OR REPLACE INTO index_edges
             (generation, from_path, from_line, from_ignored, to_path, kind, provenance, version, confidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
pub const INDEX_EDGES_FOR_GENERATION: &str =
    "SELECT from_path, from_line, from_ignored, to_path, kind, provenance, version, confidence
             FROM index_edges WHERE generation = ?1 ORDER BY from_path, from_line, to_path";
/// Retention: the newest `keep` generations, their edges included.
/// `keep` is a bound, never a per-event delete.
pub fn prune_index_generations(keep: usize) -> String {
    format!(
        "DELETE FROM index_documents WHERE generation NOT IN (
             SELECT generation FROM index_generations ORDER BY generation DESC LIMIT {keep})
             ;
         DELETE FROM index_edges WHERE generation NOT IN (
             SELECT generation FROM index_generations ORDER BY generation DESC LIMIT {keep})
             ;
         DELETE FROM index_generations WHERE generation NOT IN (
             SELECT generation FROM index_generations ORDER BY generation DESC LIMIT {keep})"
    )
}

/// The session switch's in-flight guard: the oldest task `/new` would leave
/// without a surface. One bounded existence check, never a page — a session
/// past the status page cap still answers for the task it runs.
pub const IN_FLIGHT_TASK: &str = "SELECT task_id FROM tasks WHERE session_id = ?1 AND lifecycle NOT IN ('completed', 'cancelled') ORDER BY rowid LIMIT 1";

impl super::TaskStore {
    /// The task of `session_id` a new conversation would orphan, if any.
    /// The read lives beside its statement: P-002 keeps the SQL here, and
    /// the guard needs the answer without walking pages.
    ///
    /// # Errors
    /// Returns [`super::StoreError::Closed`] when the store is not open and
    /// [`super::StoreError::Storage`] when the query fails.
    pub fn in_flight_task(
        &self,
        session_id: &crate::contracts::SessionId,
    ) -> super::Result<Option<crate::contracts::TaskId>> {
        use rusqlite::OptionalExtension;
        let mut stmt = self
            .conn()?
            .prepare(IN_FLIGHT_TASK)
            .map_err(super::storage)?;
        let task_id = stmt
            .query_row(rusqlite::params![session_id.0], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .map_err(super::storage)?;
        Ok(task_id.map(crate::contracts::TaskId))
    }
}
