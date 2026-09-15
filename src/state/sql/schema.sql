CREATE TABLE IF NOT EXISTS sessions (
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
CREATE INDEX IF NOT EXISTS idx_tasks_session ON tasks (session_id);
-- Covers SESSION_GENERATION's MAX(revision) per session as a covering index;
-- the page statements keep idx_tasks_session for their rowid-ordered scans.
CREATE INDEX IF NOT EXISTS idx_tasks_session_revision
    ON tasks (session_id, revision);
CREATE TABLE IF NOT EXISTS todo_projection (
    task_id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL,
    lifecycle TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS tasks_todo_projection_insert
AFTER INSERT ON tasks
BEGIN
    INSERT OR REPLACE INTO todo_projection (task_id, revision, lifecycle)
    VALUES (NEW.task_id, NEW.revision, NEW.lifecycle);
END;
CREATE TRIGGER IF NOT EXISTS tasks_todo_projection_update
AFTER UPDATE OF revision, lifecycle ON tasks
BEGIN
    INSERT OR REPLACE INTO todo_projection (task_id, revision, lifecycle)
    VALUES (NEW.task_id, NEW.revision, NEW.lifecycle);
END;
-- Backfill only missing projection rows; task triggers maintain current rows, so
-- an existing drift is left for explicit recovery instead of rewritten on every open.
INSERT OR IGNORE INTO todo_projection (task_id, revision, lifecycle)
SELECT task_id, revision, lifecycle
FROM tasks
WHERE NOT EXISTS (
    SELECT 1 FROM todo_projection
    WHERE todo_projection.task_id = tasks.task_id
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
CREATE INDEX IF NOT EXISTS idx_obligations_task_applicability
    ON obligations (task_id, applicability);
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
CREATE INDEX IF NOT EXISTS idx_questions_task_state_revision
    ON questions (task_id, state, revision);
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
CREATE INDEX IF NOT EXISTS idx_attempts_task_state
    ON attempts (task_id, state);
CREATE TABLE IF NOT EXISTS retained (
    boundary_id TEXT PRIMARY KEY,
    record_json TEXT NOT NULL
);
