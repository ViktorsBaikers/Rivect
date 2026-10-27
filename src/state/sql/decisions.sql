-- Append-only answer-attempt journal for one versioned question: every
-- accepted or denied answer attempt lands here with its origin and
-- outcome, so a stale, replayed or invalid answer never erases the
-- record of having been tried. `id` is the stable append identity —
-- attempt order never depends on rowid spelling. `outcome` is
-- "applied" or "denied"; `denial` carries the typed denial class for
-- denied rows and stays NULL otherwise.
CREATE TABLE IF NOT EXISTS answer_attempts (
    id INTEGER PRIMARY KEY,
    question_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    question_revision INTEGER NOT NULL,
    selection_json TEXT NOT NULL,
    author TEXT NOT NULL,
    outcome TEXT NOT NULL,
    denial TEXT
) STRICT;
CREATE INDEX IF NOT EXISTS idx_answer_attempts_task
    ON answer_attempts (task_id, id);
