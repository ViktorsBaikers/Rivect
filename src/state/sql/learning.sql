-- Learned definitions (AC-051, REQ-041, P-002): one row per candidate
-- delta with the typed payload and the single fact that must hold for it to
-- apply, plus the corpus verdict a candidate earned. Both tables are
-- additive — no existing table is rewritten — so a rollback drops exactly
-- these and the store's own data is untouched. The procedure tables below
-- ride the same batch: they hold derived records of an executed plan, so a
-- rollback drops them with the definitions they belong to.
--
-- Retention (INV-010): `learning_deltas` is primary evidence. A delta that
-- activated, and the tombstone a rollback leaves, are never pruned; only a
-- never-activated candidate beyond the named window is evicted, and its
-- verdict rows leave with it. `learning_corpus` holds at most one row per
-- case kind, so the verdict set cannot grow without bound.
CREATE TABLE IF NOT EXISTS learning_deltas (
    delta_id TEXT PRIMARY KEY,
    base_version INTEGER NOT NULL,
    scope TEXT NOT NULL,
    instruction TEXT,
    capability TEXT,
    effect TEXT,
    condition_json TEXT,
    evidence TEXT NOT NULL,
    state TEXT NOT NULL,
    version INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_learning_deltas_state
    ON learning_deltas (state);

-- One verdict per case kind: the runner replaces a kind's row when it runs
-- the corpus again, so the newest judgement per kind is the readable one.
CREATE TABLE IF NOT EXISTS learning_corpus (
    delta_id TEXT NOT NULL,
    delta_version INTEGER NOT NULL,
    case_kind TEXT NOT NULL,
    expected TEXT NOT NULL,
    observed TEXT NOT NULL,
    verdict TEXT NOT NULL,
    PRIMARY KEY (delta_id, case_kind)
) STRICT;

-- Verified procedure segments (AC-053, REQ-043, master §12.9): one row per
-- segment derived from an executed plan revision of one selection. `steps`
-- holds the typed steps — each with the tool that performed it and the output
-- it recorded — `stop_conditions` the conditions the run will not run past,
-- and `tool_version`/`schema_version` are re-validated on every run so another
-- sandbox or segment schema is never masked by a past success.
CREATE TABLE IF NOT EXISTS procedure_segments (
    procedure_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    selection_revision INTEGER NOT NULL,
    plan_revision INTEGER NOT NULL,
    schema_version INTEGER NOT NULL,
    tool_version TEXT NOT NULL,
    stop_conditions TEXT NOT NULL,
    steps TEXT NOT NULL
) STRICT;

-- One row per run: `cursor` is the count of steps that settled, so a resume
-- continues after the last settled step and never re-issues it (PROH-003).
-- `snapshot_json` pins the state the segment was started under and `state`
-- moves only through the run's own transitions. A stop records the trigger and
-- the detail it names; the blocker a caller acts on is the task's own
-- projection, never a second identity minted here.
CREATE TABLE IF NOT EXISTS procedure_runs (
    run_id TEXT PRIMARY KEY,
    procedure_id TEXT NOT NULL,
    procedure_version INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    cursor INTEGER NOT NULL,
    step_count INTEGER NOT NULL,
    state TEXT NOT NULL,
    stop_condition TEXT,
    stop_detail TEXT
) STRICT;
CREATE INDEX IF NOT EXISTS idx_procedure_runs_procedure
    ON procedure_runs (procedure_id, procedure_version);

-- The steps of a run. A step row is written `prepared` before its effect and
-- stamped with the attempt that performs it, so the row does not assert on its
-- own that the effect may have landed: the attempt's own state answers that. A
-- row whose attempt never reached the worker is released for the step's next
-- attempt; a row whose attempt ran stays the run's safety record (the remainder
-- does not run past it and a resume does not re-issue it, PROH-003) and is
-- settled from the attempt's own settlement once that outcome is known. Only
-- settled rows carry a result; `cursor` on the run is their highest position.
CREATE TABLE IF NOT EXISTS procedure_run_steps (
    run_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    tool TEXT NOT NULL,
    state TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    result TEXT NOT NULL,
    PRIMARY KEY (run_id, position)
) STRICT;

-- The product base this store serves (AC-054, INV-010a): one row per base
-- version with the digest of the document it was read from. `state` is the
-- cutover's own record — `staged` arrived but has not committed, `active`
-- serves, `retired` was replaced by a committed successor and keeps its row as
-- the previous base that served. The partial index is the backstop for the one
-- invariant the transitions rely on: at most one base serves at a time
-- (PROH-004: a new base never rewrites the installed one in place, so an
-- interruption leaves the previous base serving and the new one staged).
CREATE TABLE IF NOT EXISTS base_state (
    base_version INTEGER PRIMARY KEY,
    digest TEXT NOT NULL,
    state TEXT NOT NULL
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_base_state_active
    ON base_state (state) WHERE state = 'active';

-- The update receipt (REQ-044, DEC-009): one row per persistent asset this
-- build writes, with the location it exists at and the policy the update
-- followed for it. The classifier is one table in the config owner
-- (`UPDATE_ASSETS`), so a receipt can never name an asset this build does not
-- write; the row set is written once per base and re-read as written.
CREATE TABLE IF NOT EXISTS update_receipts (
    base_version INTEGER NOT NULL,
    asset TEXT NOT NULL,
    location TEXT NOT NULL,
    policy TEXT NOT NULL,
    PRIMARY KEY (base_version, asset)
) STRICT;

-- Semantic identity (AC-056, REQ-046, master §12A.9): the versioned
-- `old_id → new_id` rules one product base was released with. A rule belongs to
-- the base it names, so an older mapping never rebinds rows a newer base already
-- moved, and `kind` keeps the action namespace apart from the role namespace:
-- one spelling can be both, and the two experiences move by different rules.
-- `subject` is the experience a split part inherits — only a split carries one,
-- because only a split has to say which part keeps the old binding. Additive
-- like the rest of this batch: a rollback drops the map and the stored rows keep
-- the spelling they were served under.
CREATE TABLE IF NOT EXISTS identity_migrations (
    base_version INTEGER NOT NULL,
    old_id TEXT NOT NULL,
    new_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    rule TEXT NOT NULL,
    subject TEXT,
    PRIMARY KEY (base_version, kind, old_id, new_id)
) STRICT;
