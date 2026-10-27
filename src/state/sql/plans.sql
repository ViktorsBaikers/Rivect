-- Plan-owned state. Additive STRICT tables, idempotent at open like
-- `SCHEMA`; statement texts stay named in `mod.rs` (P-002).
--
-- One versioned selection per task: `revision` moves only when the
-- canonical facts digest changes, so identical facts are idempotent and
-- changed facts rewrite every row they derive. `request_kind` is the
-- kind the plan was selected for — the effect gate reads it back.
CREATE TABLE IF NOT EXISTS plan_selections (
    task_id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL,
    facts_digest TEXT NOT NULL,
    request_kind TEXT NOT NULL
) STRICT;
-- The current selection's obligations, one row per required or
-- unresolved capability. `handler` is the action that may close the row
-- (the capability itself or an allowed equivalent) and stays NULL when
-- this build has none. `blocker` is one serialized `contracts::Blocker`
-- with no CHECK on its condition kind, so a new kind needs no DDL. Only
-- the selection and the row's handler write it; an `unresolved` row
-- projects one `dependency_blocked` in its place and keeps it stored.
-- `stage` marks the plan-phase rows that gate execution; every other row
-- is execution-phase and holds only completion. `outcome_json` is the
-- handler output that closed the row. Kept apart from `obligations` so
-- criterion evidence never satisfies a plan stage by accident.
CREATE TABLE IF NOT EXISTS plan_obligations (
    task_id TEXT NOT NULL,
    capability TEXT NOT NULL,
    applicability TEXT NOT NULL,
    execution TEXT NOT NULL,
    stage INTEGER NOT NULL,
    handler TEXT,
    blocker TEXT,
    outcome_json TEXT,
    PRIMARY KEY (task_id, capability)
) STRICT;
-- Versioned plans: every `plan_work` run appends a revision bound to the
-- selection it was recorded under, so a verdict stays tied to the exact
-- revision it judged and revisions of an earlier selection never gate
-- the current one. `verdict` is the mechanical leg's and stays NULL
-- until that leg judges the revision.
CREATE TABLE IF NOT EXISTS plans (
    task_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    selection_revision INTEGER NOT NULL,
    body_json TEXT NOT NULL,
    verdict TEXT,
    assessment_json TEXT,
    PRIMARY KEY (task_id, revision)
) STRICT;
-- One gate hold per task: a non-read effect refused on a closed gate.
-- The hold lives until a transaction opens the gate.
CREATE TABLE IF NOT EXISTS plan_gate_holds (
    task_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL
) STRICT;
-- Present while the plan itself moved the task `running -> blocked`.
-- Only a plan-owned block is released by plan resolution; every foreign
-- block clears the mark in its own transaction.
CREATE TABLE IF NOT EXISTS plan_blocks (
    task_id TEXT PRIMARY KEY
) STRICT;
