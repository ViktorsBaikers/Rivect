-- The first expected result and assertion digest stay fixed for each check id.
CREATE TABLE IF NOT EXISTS assumption_checks (
    session_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    check_id TEXT NOT NULL CHECK (
        length(check_id) BETWEEN 1 AND 64
        AND check_id NOT GLOB '*[^A-Za-z0-9._-]*'
    ),
    expected_result TEXT NOT NULL CHECK (expected_result IN ('pass', 'fail')),
    assertion_digest TEXT NOT NULL CHECK (
        length(assertion_digest) = 64
        AND assertion_digest NOT GLOB '*[^0-9a-f]*'
    ),
    record_version INTEGER NOT NULL CHECK (record_version = 1),
    record_json TEXT NOT NULL,
    PRIMARY KEY (session_id, task_id, check_id)
) STRICT;
