-- Index snapshot generations (INV-007): one row per derived graph the
-- single writer cut, its freshness state and its coverage. `sealed`
-- stays 0 while a build is in flight, so a writer that died mid-index
-- leaves a row every later read reports `stale` and repairs — a broken
-- generation is never served as current, and never deleted.
CREATE TABLE IF NOT EXISTS index_generations (
    generation INTEGER PRIMARY KEY,
    state TEXT NOT NULL,
    stale_cause TEXT,
    coverage_json TEXT NOT NULL,
    unresolved_json TEXT NOT NULL,
    sealed INTEGER NOT NULL
) STRICT;
-- The derived edges of one generation. `from_line` is the 1-based line
-- the relation was read at, and it is `NOT NULL` on purpose: the
-- derivation reads every edge from a located line, a line-less row is
-- not a shape this producer can emit, and a nullable member of a
-- STRICT primary key is not storable anyway — so the column states the
-- constraint the table already has instead of the schema pretending it
-- could hold NULL. `version` is the subject document's content version
-- at index time, so a row always names the bytes it was derived from.
CREATE TABLE IF NOT EXISTS index_edges (
    generation INTEGER NOT NULL,
    from_path TEXT NOT NULL,
    from_line INTEGER NOT NULL,
    from_ignored INTEGER NOT NULL,
    to_path TEXT NOT NULL,
    kind TEXT NOT NULL,
    provenance TEXT NOT NULL,
    version INTEGER NOT NULL,
    confidence TEXT NOT NULL,
    PRIMARY KEY (generation, from_path, from_line, to_path, kind, provenance)
) STRICT;
CREATE INDEX IF NOT EXISTS idx_index_edges_generation
    ON index_edges (generation);

-- The documents one generation was cut from: its own indexed file set,
-- which is the only record of what the project held at that
-- generation. A later cut compares its enumeration against this set to
-- decide whether a narrowed re-derivation is sound, so a file that
-- appeared or vanished outside the narrowing is caught even when the
-- backend that reported the change coalesced it away.
CREATE TABLE IF NOT EXISTS index_documents (
    generation INTEGER NOT NULL,
    path TEXT NOT NULL,
    PRIMARY KEY (generation, path)
) STRICT;
