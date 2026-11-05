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
CREATE TRIGGER IF NOT EXISTS retained_rows_immutable
BEFORE UPDATE ON retained
BEGIN
    SELECT RAISE(ABORT, 'retained rows are immutable');
END;

-- Supervisor reaction journal (INV-027): one append-only row per
-- detector firing; the JSON carries the stall cause and the class
-- limits/cooldown in force when the detector fired. `id` is the
-- stable append identity — firing order never depends on rowid
-- spelling.
CREATE TABLE IF NOT EXISTS supervisor_reactions (
    id INTEGER PRIMARY KEY,
    task_id TEXT NOT NULL,
    reaction_json TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_supervisor_reactions_task
    ON supervisor_reactions (task_id);
-- Config publication journal: append-only intents, receipted by
-- the state transition pending -> applied. `identity` is the target's
-- write identity at staging, lowercase hex: `v2:dev:ino:token` with the
-- reuse token when attested, the legacy `dev:ino` (read as unattested)
-- when not. The managed write is in-place, so a surviving inode
-- attributes intended bytes to our own crashed write; a replaced inode
-- never does.
CREATE TABLE IF NOT EXISTS config_publications (
    owner TEXT NOT NULL,
    target TEXT NOT NULL,
    admission_seq INTEGER NOT NULL,
    intended_digest TEXT NOT NULL,
    base_digest TEXT,
    identity TEXT,
    state TEXT NOT NULL,
    PRIMARY KEY (owner, target, admission_seq)
) STRICT;
-- Limited-grant consents: one live row per scope, renewed by
-- re-grant; read by the permission-mode decision, written by the panel.
CREATE TABLE IF NOT EXISTS preapprovals (
    scope TEXT PRIMARY KEY,
    granted_by TEXT NOT NULL,
    expires_at TEXT NOT NULL
) STRICT;
-- Atomic tree budget ledger (INV-022): one row per budget scope.
CREATE TABLE IF NOT EXISTS budget_scopes (
    scope TEXT PRIMARY KEY,
    limit_units INTEGER NOT NULL,
    spent INTEGER NOT NULL,
    reserved INTEGER NOT NULL
) STRICT;
-- One row per (reservation, scope): a reservation spans every
-- applicable level atomically and resolves exactly once — charged or
-- released — so the same units can never be spent twice. `charged`
-- stays NULL while reserved/released, and NULL on a charged row means
-- the sent cost stayed unknown and the bound was retained.
CREATE TABLE IF NOT EXISTS budget_reservations (
    reservation_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    bound INTEGER NOT NULL,
    state TEXT NOT NULL,
    charged INTEGER,
    PRIMARY KEY (reservation_id, scope)
) STRICT;
CREATE INDEX IF NOT EXISTS idx_budget_reservations_scope
    ON budget_reservations (scope);
-- Durable settlement of every dispatched child attempt (AC-057): the row
-- is written `dispatched` in the same transaction that reserves the bound
-- and closed `settled` in the same transaction that resolves it, so a
-- crash between them leaves exactly one row a reopen reconciles as
-- unknown. Additive and ignored by a build without it: no generation bump.
CREATE TABLE IF NOT EXISTS usage_settlements (
    attempt_id TEXT PRIMARY KEY,
    parent_attempt_id TEXT,
    purpose TEXT NOT NULL,
    connection TEXT NOT NULL,
    ranking_basis TEXT,
    cost_bound INTEGER NOT NULL,
    state TEXT NOT NULL,
    exactness TEXT NOT NULL,
    unknown_reason TEXT,
    wire_retries INTEGER NOT NULL,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    reasoning_tokens INTEGER,
    cache_read_tokens INTEGER,
    cache_write_tokens INTEGER,
    total_tokens INTEGER,
    charged_units INTEGER
) STRICT;
CREATE INDEX IF NOT EXISTS idx_usage_settlements_state
    ON usage_settlements (state);
-- Substitutes are looked up by their failed parent on every dispatch, so
-- the lineage column is indexed instead of scanned.
CREATE INDEX IF NOT EXISTS idx_usage_settlements_parent
    ON usage_settlements (parent_attempt_id);
-- The incremental settlement totals (AC-062): one row updated in the same
-- transaction that settles a send, so a status refresh reads one row
-- instead of aggregating the whole table. `next_rowid` is the monotonic
-- identity the dispatch insert names, so that insert never aggregates the
-- ledger to find its row. Additive and ignored by a build without it: no
-- generation bump.
CREATE TABLE IF NOT EXISTS usage_totals (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    settled_count INTEGER NOT NULL,
    settled_without_total INTEGER NOT NULL,
    total_tokens INTEGER,
    charged_count INTEGER NOT NULL,
    charged_units INTEGER,
    latest_prompt_tokens INTEGER,
    dispatched_count INTEGER NOT NULL,
    next_rowid INTEGER NOT NULL
) STRICT;
-- The row itself is filled by the gated upgrade batch (`USAGE_TOTALS_BACKFILL`)
-- and recomputed by it when the settlement ledger is ahead of `next_rowid`
-- (a build without this table wrote past the counter): the O(1) presence and
-- `MAX(rowid)` reads plus one index-range open-send count per gate keep a
-- current incremental row untouched and an ordinary open from scanning the
-- whole settlement ledger; production startup runs the gate twice.
-- SQLite's `CREATE TRIGGER IF NOT EXISTS` keeps an existing body, so a store
-- first opened by an earlier candidate would keep stale guard text forever.
-- Every settlement guard is therefore dropped and recreated with the current
-- body on open; the historical settled-only delete name is retired too.
DROP TRIGGER IF EXISTS usage_settlements_settled_immutable;
DROP TRIGGER IF EXISTS usage_settlements_settled_undeletable;
DROP TRIGGER IF EXISTS usage_settlements_undeletable;
DROP TRIGGER IF EXISTS usage_settlements_dispatch_only;
DROP TRIGGER IF EXISTS usage_settlements_identity_immutable;
DROP TRIGGER IF EXISTS usage_settlements_rowid_immutable;
DROP TRIGGER IF EXISTS usage_settlements_dispatched_closes_settled;
-- A settled row is immutable: the bins a provider reported are the record,
-- and a second settle of the same attempt would be a second charge.
CREATE TRIGGER usage_settlements_settled_immutable
BEFORE UPDATE ON usage_settlements
WHEN OLD.state = 'settled'
BEGIN
    SELECT RAISE(ABORT, 'settled settlements are immutable');
END;
-- No settlement row is deleted: a dispatched row is the replay identity a
-- reopen reconciles, and a settled row is the charge record. The row's
-- only exit is the dispatched-to-settled close.
CREATE TRIGGER usage_settlements_undeletable
BEFORE DELETE ON usage_settlements
BEGIN
    SELECT RAISE(ABORT, 'settlement rows are immutable');
END;
-- Only the dispatch transaction opens a row, and it opens it `dispatched`.
-- The `EXISTS` arms also refuse `INSERT OR REPLACE` over an existing
-- attempt or row identity: the conflict resolution would delete that row
-- without firing its delete trigger, so the replacement is denied before
-- it can happen. An omitted rowid reads `-1` inside a BEFORE INSERT, so the
-- arm cannot tell that sentinel from a stored `-1`: the product insert
-- names its own positive rowid (floor 1) and this arm covers every stored
-- identity unconditionally.
CREATE TRIGGER usage_settlements_dispatch_only
BEFORE INSERT ON usage_settlements
WHEN NEW.state <> 'dispatched'
   OR EXISTS (SELECT 1 FROM usage_settlements WHERE attempt_id = NEW.attempt_id)
   OR EXISTS (SELECT 1 FROM usage_settlements WHERE rowid = NEW.rowid)
BEGIN
    SELECT RAISE(ABORT, 'settlements are opened dispatched and never replaced');
END;
-- The attempt id is the settlement identity: rewriting it through
-- `UPDATE OR REPLACE` would delete the settled row through the primary-key
-- conflict without firing the delete trigger, so the key never moves.
CREATE TRIGGER usage_settlements_identity_immutable
BEFORE UPDATE OF attempt_id ON usage_settlements
BEGIN
    SELECT RAISE(ABORT, 'settlement attempt ids are immutable');
END;
-- The implicit row identity is immutable too: `rowid` (and its `_rowid_`/
-- `oid` aliases) can collide through the same REPLACE conflict and delete a
-- stored row, so a row never changes its own rowid.
CREATE TRIGGER usage_settlements_rowid_immutable
BEFORE UPDATE ON usage_settlements
WHEN NEW.rowid <> OLD.rowid
BEGIN
    SELECT RAISE(ABORT, 'settlement row identity is immutable');
END;
-- A dispatched row has exactly one exit: it closes `settled`. Rewriting a
-- dispatched row into any other state would reopen an accounted attempt.
CREATE TRIGGER usage_settlements_dispatched_closes_settled
BEFORE UPDATE ON usage_settlements
WHEN OLD.state = 'dispatched' AND NEW.state <> 'settled'
BEGIN
    SELECT RAISE(ABORT, 'a dispatched settlement only closes settled');
END;
-- Bounded work (AC-083a): one row per long-running worker's recorded
-- deadline, settled-send bound and terminal state. The unit bound is the
-- shared ledger's own `budget_scopes` limit for the same task scope and
-- the settled-send count reads `usage_settlements`, so this table keeps no
-- counter of its own. Additive and ignored by a build without it: no
-- generation bump.
CREATE TABLE IF NOT EXISTS work_budgets (
    task_id TEXT PRIMARY KEY,
    deadline_unix_seconds INTEGER NOT NULL,
    send_bound INTEGER NOT NULL,
    state TEXT NOT NULL,
    stop_reason TEXT
) STRICT;
-- Scoped local sharing (AC-083b): one row per observer grant. The token is
-- never stored — `token_digest` is the SHA-256 hex the exchange compares —
-- and `state` is terminal once revoked, expired or failed. Additive and
-- ignored by a build without it: no generation bump.
CREATE TABLE IF NOT EXISTS sharing_grants (
    grant_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    token_digest TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    state TEXT NOT NULL
) STRICT;
