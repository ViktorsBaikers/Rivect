//! Durable settlement and economy projection proof: one row per dispatched
//! child attempt across replay and restart, the exact provider bins beside
//! the bound-capped charge, interrupted sends reconciled as unknown, the
//! status surface serving unknown-with-source figures from its cache, and
//! the cache-read rate over a frozen cohort (AC-057, AC-059, AC-062,
//! AC-058 contribution).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/discard conveniences; src/ stays strict (standards §14)"
)]

mod support;

use rivect::actions::{
    ActionRegistry, ContractBasis, PlanRequest, RequestKind, Surface, SurfaceScan,
};
use rivect::config::{
    Config, ConnKind, Connection, EffortAssign, EffortLevel, FixedModel, ModelAssign,
};
use rivect::contracts::AnswerSelection;
use rivect::controller::{SchedulerStep, StepOutcome};
use rivect::learning::{
    FeedbackCause, FeedbackOutcome, FeedbackRecord, FeedbackReward, FeedbackVerdict,
    VersionEvidence,
};
use rivect::model::{Broker, ModelError, RequestManifest, SendContext, SendOutcome, SendTicket};
use rivect::providers::{LoopbackProvider, Provider, ProviderError, ProviderReply};
use rivect::resources::{Exactness, UsageDelta};
use rivect::state::{
    CacheCohort, CacheCohortCounts, CacheRate, ConflictCause, InvalidCause, SettlementState,
    SettlementTotals, StoreError, StoreLedger, TaskStore,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const CONNECTION: &str = "local";
const WORLD: &str = "/world/economy";
const SCOPE_A: &str = "economy-scope-a";
const SCOPE_B: &str = "economy-scope-b";

fn config() -> Config {
    Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\n\
         model = { mode = \"fixed\", connection = \"local\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"high\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("the settlement fixture config validates")
}

fn config_text() -> &'static str {
    "config_version = 1\n\
     [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
     [models.defaults]\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"fixture-model\" }\n\
     effort = { mode = \"fixed\", value = \"high\" }\n\
     fallback = { mode = \"off\" }\n"
}

/// Two local connections: the pairing proof needs a substitute that lands on
/// a connection the prepared manifest never named.
fn pairing_config_text() -> &'static str {
    "config_version = 1\n\
     [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
     [connections.reserve]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11435\"\n\
     [models.defaults]\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"fixture-model\" }\n\
     effort = { mode = \"fixed\", value = \"high\" }\n\
     fallback = { mode = \"off\" }\n"
}

/// Two eligible local connections under `auto` with an auto fallback: a chain
/// that fails on every entry.
fn all_fail_config_text() -> &'static str {
    "config_version = 1\n\
     [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
     [connections.reserve]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11435\"\n\
     [models.defaults]\nmodel = { mode = \"auto\" }\neffort = { mode = \"auto\" }\n\
     fallback = { mode = \"auto\" }\n\
     [models.purposes.main]\nmodel = { mode = \"auto\", pool = [\"local\", \"reserve\"] }\nfallback = { mode = \"auto\", chain = [ { mode = \"fixed\", connection = \"reserve\", model_id = \"reserve-model\" } ] }\n"
}

/// Two local connections where the purpose's fallback chain names `reserve`.
/// A scope sized to one bound lets the entered primary land but refuses the
/// fallback leg.
fn mixed_config_text() -> &'static str {
    "config_version = 1\n\
     [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
     [connections.reserve]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11435\"\n\
     [models.defaults]\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"fixture-model\" }\n\
     effort = { mode = \"fixed\", value = \"high\" }\n\
     fallback = { mode = \"off\" }\n\
     [models.purposes.main]\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"fixture-model\" }\n\
     fallback = { mode = \"auto\", chain = [ { mode = \"fixed\", connection = \"reserve\", model_id = \"reserve-model\" } ] }\n"
}

/// Asserts the five model/effort/purpose/connection fields did not move.
fn assert_same_pairing(before: &Value, after: &Value, label: &str) {
    for key in ["model", "source", "effort", "purpose", "connection"] {
        assert_eq!(after[key], before[key], "{label} keeps {key}");
    }
}

/// A provider that answers with exactly the usage it was handed, so the
/// settlement carries the provider's own bins and nothing inferred. The
/// counter lets a replay proof assert the provider was never called.
struct UsageProvider {
    usage: UsageDelta,
    fail: bool,
    calls: Arc<AtomicU64>,
}

impl UsageProvider {
    fn settled(usage: UsageDelta) -> Self {
        Self::counting(usage, Arc::new(AtomicU64::new(0)))
    }

    /// The same provider over a caller-held counter: the caller keeps the
    /// Arc after the broker owns the provider.
    fn counting(usage: UsageDelta, calls: Arc<AtomicU64>) -> Self {
        Self {
            usage,
            fail: false,
            calls,
        }
    }
}

impl Provider for UsageProvider {
    fn name(&self) -> &'static str {
        "economy-fixture"
    }

    fn serves(&self, connection: &str, entry: &Connection) -> bool {
        connection == CONNECTION && entry.kind == ConnKind::Local
    }

    fn send(&mut self, _manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(ProviderError::ProviderFailed {
                connection: CONNECTION.to_string(),
                reason: "fixture failure".to_string(),
            });
        }
        Ok(ProviderReply {
            text: "fixture answer".to_string(),
            tool_calls: Vec::new(),
            usage: self.usage,
            wire_retries: 0,
        })
    }
}

fn context() -> SendContext {
    SendContext {
        purpose: "main".to_string(),
        connection: CONNECTION.to_string(),
        parent_attempt_id: None,
        ranking_basis: None,
    }
}

fn scopes() -> Vec<String> {
    vec![SCOPE_A.to_string(), SCOPE_B.to_string()]
}

/// One prepared manifest on the fixture broker: the send paths and the
/// store-level settlement legs both start from this frozen request.
fn prepared(broker: &mut Broker) -> RequestManifest {
    broker
        .prepare("main", &config(), WORLD, "goal: settlement")
        .expect("the fixture request prepares")
}

#[test]
fn settled_send_is_one_row_and_a_replay_never_doubles() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-settle-").expect("fixture root");
    let mut store = TaskStore::open(&root.path().join("state.db")).expect("store opens");
    for scope in [SCOPE_A, SCOPE_B] {
        store.open_budget(scope, 10).expect("budget opens");
    }
    let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Exact {
        prompt_tokens: 6,
        completion_tokens: 4,
        total_tokens: 10,
    })));
    let manifest = prepared(&mut broker);
    let bound = manifest.cost_bound;
    assert!(bound > 0, "the bound is a finite unit figure");

    let reply = {
        let mut ledger = StoreLedger::new(&mut store, scopes());
        broker
            .dispatch(&mut ledger, WORLD, &manifest)
            .expect("the send settles")
    };
    assert_eq!(reply.text, "fixture answer");

    let record = store.settlement(&manifest.attempt_id).expect("one row");
    assert_eq!(record.state, SettlementState::Settled);
    assert_eq!(record.parent_attempt_id, None);
    assert_eq!(record.connection, CONNECTION);
    assert_eq!(record.bins.total_tokens, Some(10));
    assert_eq!(record.bins.prompt_tokens, Some(6));
    assert_eq!(record.exactness, Exactness::Exact);
    // The provider reported more than the bound: the row keeps the exact
    // bins and the charge stays capped at the frozen bound.
    assert_eq!(record.charged_units, Some(bound));
    assert!(record.wire_retries == 0);

    // A replayed dispatch is the spent-attempt refusal: no second send.
    let replay = {
        let mut ledger = StoreLedger::new(&mut store, scopes());
        broker.dispatch(&mut ledger, WORLD, &manifest)
    };
    assert!(
        matches!(replay, Err(ModelError::AttemptAlreadyAccounted { .. })),
        "a replayed attempt never sends twice"
    );

    // A second settle of the same attempt is the exactly-once refusal.
    let ticket = SendTicket {
        attempt_id: manifest.attempt_id.clone(),
        cost_bound: bound,
        reserved: true,
    };
    let second = store.finish_send(
        &ticket,
        &SendOutcome::Settled {
            usage: UsageDelta::Unknown,
            wire_retries: 0,
        },
    );
    assert!(
        matches!(
            second,
            Err(StoreError::Conflict(
                ConflictCause::SettlementNotDispatched { .. }
            ))
        ),
        "a settled row never settles twice"
    );

    // One row, one charge at every open scope.
    let totals = store.settlement_totals().expect("totals");
    assert_eq!(totals.settled_count, 1);
    assert_eq!(totals.total_tokens, Some(10));
    for scope in [SCOPE_A, SCOPE_B] {
        let status = store.budget_status(scope).expect("scope status");
        assert_eq!(status.spent, bound, "{scope} charged once");
        assert_eq!(status.reserved, 0, "{scope} holds nothing after the settle");
    }
}

#[test]
fn settlement_reopen_recalculates_the_same_bins() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-reopen-").expect("fixture root");
    let path = root.path().join("state.db");
    let usage = UsageDelta::Legs {
        prompt_tokens: Some(9),
        completion_tokens: Some(3),
        reasoning_tokens: Some(2),
        cache_read_tokens: Some(5),
        cache_write_tokens: Some(1),
        total_tokens: Some(12),
    };
    let (attempt_id, before, totals_before) = {
        let mut store = TaskStore::open(&path).expect("store opens");
        store.open_budget(SCOPE_A, 10).expect("budget opens");
        let mut broker = Broker::new(Box::new(UsageProvider::settled(usage)));
        let manifest = prepared(&mut broker);
        {
            let mut ledger = StoreLedger::new(&mut store, vec![SCOPE_A.to_string()]);
            broker
                .dispatch(&mut ledger, WORLD, &manifest)
                .expect("the send settles");
        }
        let record = store.settlement(&manifest.attempt_id).expect("one row");
        let totals = store.settlement_totals().expect("totals");
        (manifest.attempt_id, record, totals)
    };

    // The bytes a reopened runtime reads back are the same settlement: the
    // bins are recorded, not recomputed from a second source.
    let store = TaskStore::open(&path).expect("store reopens");
    let after = store.settlement(&attempt_id).expect("the row survives");
    assert_eq!(after, before);
    assert_eq!(after.bins.reasoning_tokens, Some(2));
    assert_eq!(after.bins.cache_read_tokens, Some(5));
    assert_eq!(after.bins.cache_write_tokens, Some(1));
    assert_eq!(store.settlement_totals().expect("totals"), totals_before);
}

#[test]
fn interrupted_settle_is_reconciled_on_reopen() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-interrupt-").expect("fixture root");
    let path = root.path().join("state.db");
    let mut store = TaskStore::open(&path).expect("store opens");
    store.open_budget(SCOPE_A, 10).expect("budget opens");
    let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Unknown)));
    let manifest = prepared(&mut broker);
    let ticket = store
        .begin_send(&[SCOPE_A], &context(), &manifest)
        .expect("the send is begun");
    assert!(ticket.reserved);
    let open = store
        .settlement(&manifest.attempt_id)
        .expect("dispatched row");
    assert_eq!(open.state, SettlementState::Dispatched);
    assert_eq!(open.charged_units, None);
    drop(store);

    // A killed process leaves exactly this: one dispatched row and a held
    // reservation. The reopen closes it unknown and charges the bound.
    let mut reopened = TaskStore::open(&path).expect("store reopens");
    assert_eq!(
        reopened
            .settlement(&manifest.attempt_id)
            .expect("the row survived the crash")
            .state,
        SettlementState::Dispatched,
        "the open alone reconciles nothing"
    );
    let reconciled = reopened.reconcile_sends().expect("reconciliation runs");
    assert_eq!(reconciled, 1);
    let settled = reopened
        .settlement(&manifest.attempt_id)
        .expect("the row is closed");
    assert_eq!(settled.state, SettlementState::Settled);
    assert_eq!(settled.exactness, Exactness::Unknown);
    assert_eq!(settled.unknown_reason.as_deref(), Some("interrupted"));
    assert_eq!(settled.bins.total_tokens, None);
    assert_eq!(settled.charged_units, Some(manifest.cost_bound));
    let status = reopened.budget_status(SCOPE_A).expect("scope status");
    assert_eq!(status.spent, manifest.cost_bound, "the bound is retained");
    assert_eq!(status.reserved, 0, "the reservation resolved once");
    // The recovered close lands in the incremental totals exactly once: one
    // settled row without a total, the retained bound as its charge, and no
    // send left open.
    let totals = reopened.settlement_totals().expect("totals");
    assert_eq!(
        totals,
        SettlementTotals {
            settled_count: 1,
            settled_without_total: 1,
            total_tokens: None,
            charged_units: Some(manifest.cost_bound),
            dispatched_count: 0,
            latest_prompt_tokens: None,
        },
        "the reconciled row lands in the incremental totals exactly once"
    );
    assert_eq!(
        reopened
            .reconcile_sends()
            .expect("a second pass is a no-op"),
        0
    );
    assert_eq!(
        reopened.settlement_totals().expect("totals"),
        totals,
        "a second reconciliation pass changes no total"
    );
}

/// An upgrade store carries settlement rows but no incremental totals row:
/// the O(1) presence guard fills it once from the ledger, counts included,
/// and the monotonic identity resumes after the newest stored row.
#[test]
fn missing_totals_row_is_backfilled_once_from_the_settlement_ledger() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-backfill-").expect("fixture root");
    let path = root.path().join("state.db");
    let (charged, measured_total) = {
        let mut store = TaskStore::open(&path).expect("store opens");
        store.open_budget(SCOPE_A, 10).expect("budget opens");
        let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Unknown)));
        let failed = prepared_with(&mut broker, "goal: backfill failed");
        let measured = prepared_with(&mut broker, "goal: backfill measured");
        let charged = failed.cost_bound + measured.cost_bound;
        for (manifest, usage) in [
            (&failed, UsageDelta::Unknown),
            (
                &measured,
                UsageDelta::Exact {
                    prompt_tokens: 6,
                    completion_tokens: 4,
                    total_tokens: 10,
                },
            ),
        ] {
            let ticket = store
                .begin_send(&[SCOPE_A], &context(), manifest)
                .expect("the send begins");
            store
                .finish_send(
                    &ticket,
                    &SendOutcome::Settled {
                        usage,
                        wire_retries: 0,
                    },
                )
                .expect("the send settles");
        }
        (charged, 10u64)
    };
    // The upgrade shape: the ledger rows survive, the incremental row does
    // not — a store written before the additive totals row existed.
    let conn = rusqlite::Connection::open(&path).expect("raw connection");
    conn.execute("DELETE FROM usage_totals", [])
        .expect("totals row removed");
    drop(conn);

    let reopened = TaskStore::open(&path).expect("store reopens");
    let totals = reopened.settlement_totals().expect("totals");
    assert_eq!(totals.settled_count, 2, "both settled rows are counted");
    assert_eq!(
        totals.settled_without_total, 1,
        "only the failed row reported no total"
    );
    assert_eq!(totals.total_tokens, Some(measured_total));
    assert_eq!(totals.charged_units, Some(charged));
    assert_eq!(totals.dispatched_count, 0);
    assert_eq!(
        totals.latest_prompt_tokens,
        Some(6),
        "the newest settled row's prompt is the backfilled figure"
    );
    drop(reopened);
    let conn = rusqlite::Connection::open(&path).expect("raw connection");
    let next_rowid: i64 = conn
        .query_row(
            "SELECT next_rowid FROM usage_totals WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .expect("the backfilled row answers");
    assert_eq!(
        next_rowid, 3,
        "the backfill resumes after the newest stored ledger row"
    );
}

/// A store written before the incremental totals row existed — settlement
/// rows present, `usage_totals` absent, one send interrupted — opens, closes
/// the send unknown at its bound, and lands the exact totals. The pre-commit
/// recovery would write a table this store has not created, so the schema
/// guard must route the open through the post-commit path.
#[test]
fn pre_totals_store_with_an_interrupted_send_opens_and_reconciles() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-pre-totals-").expect("fixture root");
    let runtime_dir = root.path().join("runtime");
    std::fs::create_dir_all(&runtime_dir).expect("runtime dir");
    let db = runtime_dir.join("rivect.db");
    let (attempt_id, bound) = {
        let mut store = TaskStore::open(&db).expect("store opens");
        store.open_budget(SCOPE_A, 10).expect("budget opens");
        let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Unknown)));
        let manifest = prepared_with(&mut broker, "goal: pre-totals interrupted");
        store
            .begin_send(&[SCOPE_A], &context(), &manifest)
            .expect("the send begins");
        (manifest.attempt_id.clone(), manifest.cost_bound)
    };
    // The upgrade shape: the settlement ledger survives, the incremental
    // totals table does not — the store every earlier candidate of this
    // feature wrote.
    let conn = rusqlite::Connection::open(&db).expect("raw connection");
    conn.execute("DROP TABLE usage_totals", [])
        .expect("totals table removed");
    drop(conn);

    let mut world = support::open_world_at(root.path(), Some(config_text()));
    let record = world
        .runtime
        .store()
        .settlement(&attempt_id)
        .expect("the open closes the row");
    assert_eq!(record.state, SettlementState::Settled);
    assert_eq!(record.exactness, Exactness::Unknown);
    assert_eq!(record.unknown_reason.as_deref(), Some("interrupted"));
    assert_eq!(record.charged_units, Some(bound));
    assert_eq!(
        world
            .runtime
            .store()
            .budget_status(SCOPE_A)
            .expect("scope status")
            .spent,
        bound,
        "the interrupted send keeps its bound charged"
    );
    let totals = world.runtime.store().settlement_totals().expect("totals");
    assert_eq!(
        totals,
        SettlementTotals {
            settled_count: 1,
            settled_without_total: 1,
            total_tokens: None,
            charged_units: Some(bound),
            dispatched_count: 0,
            latest_prompt_tokens: None,
        },
        "the interrupted row lands in the newly created totals exactly once"
    );
    assert!(
        world
            .runtime
            .boot_diagnostics
            .iter()
            .any(|line| line.contains("settlement recovery")),
        "the boot line names the recovery: {:?}",
        world.runtime.boot_diagnostics
    );
    {
        let mut writer = world.runtime.store_writer();
        assert_eq!(
            writer.reconcile_sends().expect("a second pass is a no-op"),
            0
        );
    }
    assert_eq!(
        world.runtime.store().settlement_totals().expect("totals"),
        totals,
        "a second reconciliation pass changes no total"
    );
}

/// A foreign build can write settlement rows past the incremental counter
/// and leave no totals row of its own. The next dispatch allocates above
/// every stored identity instead of colliding with it, and its settlement
/// resumes the ledger: a first send after the upgrade succeeds and lands.
#[test]
fn a_foreign_settlement_beyond_the_counter_does_not_wedge_the_next_send() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-foreign-row-").expect("fixture root");
    let path = root.path().join("state.db");
    let first_total = {
        let mut store = TaskStore::open(&path).expect("store opens");
        store.open_budget(SCOPE_A, 10).expect("budget opens");
        let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Unknown)));
        let manifest = prepared_with(&mut broker, "goal: before the foreign row");
        let ticket = store
            .begin_send(&[SCOPE_A], &context(), &manifest)
            .expect("the first send begins");
        store
            .finish_send(
                &ticket,
                &SendOutcome::Settled {
                    usage: UsageDelta::Exact {
                        prompt_tokens: 6,
                        completion_tokens: 4,
                        total_tokens: 10,
                    },
                    wire_retries: 0,
                },
            )
            .expect("the first send settles");
        10u64
    };
    // A foreign build names its own rowid and leaves `next_rowid` behind:
    // the identity the next allocation would hand out is already taken.
    let conn = rusqlite::Connection::open(&path).expect("raw connection");
    conn.execute(
        "INSERT INTO usage_settlements
             (rowid, attempt_id, purpose, connection, cost_bound, state, exactness, wire_retries)
         VALUES (2, 'foreign-attempt', 'main', 'local', 4, 'dispatched', 'unknown', 0)",
        [],
    )
    .expect("the foreign row lands");
    conn.execute(
        "UPDATE usage_settlements SET state = 'settled' WHERE attempt_id = 'foreign-attempt'",
        [],
    )
    .expect("the foreign row closes");
    drop(conn);

    let mut store = TaskStore::open(&path).expect("the upgraded store opens");
    let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Unknown)));
    let manifest = prepared_with(&mut broker, "goal: after the foreign row");
    let ticket = store
        .begin_send(&[SCOPE_A], &context(), &manifest)
        .expect("the allocation resumes above the foreign identity");
    store
        .finish_send(
            &ticket,
            &SendOutcome::Settled {
                usage: UsageDelta::Exact {
                    prompt_tokens: 3,
                    completion_tokens: 2,
                    total_tokens: 5,
                },
                wire_retries: 0,
            },
        )
        .expect("the send settles");
    assert_eq!(
        store
            .settlement(&manifest.attempt_id)
            .expect("the new row")
            .state,
        SettlementState::Settled
    );
    let totals = store.settlement_totals().expect("totals");
    assert_eq!(
        totals.settled_count, 3,
        "the foreign row and the resumed send are both counted"
    );
    assert_eq!(totals.total_tokens, Some(first_total + 5));
    assert_eq!(totals.dispatched_count, 0);
    let conn = rusqlite::Connection::open(&path).expect("raw connection");
    let (rowid, state): (i64, String) = conn
        .query_row(
            "SELECT rowid, state FROM usage_settlements WHERE attempt_id = 'foreign-attempt'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the foreign row survives");
    assert_eq!(
        (rowid, state.as_str()),
        (2, "settled"),
        "the foreign identity is never overwritten"
    );
    let next_rowid: i64 = conn
        .query_row(
            "SELECT next_rowid FROM usage_totals WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .expect("the counter answers");
    assert_eq!(
        next_rowid, 4,
        "the allocation resynchronised past the foreign row"
    );
}

/// A store reverted to a build without the incremental row writes its
/// settlement rows past `next_rowid` and never touches the totals. The open
/// recomputes the record from the ledger before recovery settles the foreign
/// rows, so every settled row is counted, the open count lands on zero and
/// the next identity resumes after the newest row.
#[test]
fn a_reverted_store_recomputes_the_totals_before_reconciling_foreign_rows() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-reverted-").expect("fixture root");
    let runtime_dir = root.path().join("runtime");
    std::fs::create_dir_all(&runtime_dir).expect("runtime dir");
    let db = runtime_dir.join("rivect.db");
    let (first_bound, first_total) = {
        let mut store = TaskStore::open(&db).expect("store opens");
        store.open_budget(SCOPE_A, 10).expect("budget opens");
        let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Unknown)));
        let manifest = prepared_with(&mut broker, "goal: before the revert");
        let ticket = store
            .begin_send(&[SCOPE_A], &context(), &manifest)
            .expect("the send begins");
        store
            .finish_send(
                &ticket,
                &SendOutcome::Settled {
                    usage: UsageDelta::Exact {
                        prompt_tokens: 6,
                        completion_tokens: 4,
                        total_tokens: 10,
                    },
                    wire_retries: 0,
                },
            )
            .expect("the send settles");
        (manifest.cost_bound, 10u64)
    };
    // The reverted shape: the pre-totals build writes rows 2 and 3 and
    // leaves the record at the pre-revert figures, so the ledger is ahead
    // of it. Row 2 is an interrupted send, row 3 a settled one.
    let conn = rusqlite::Connection::open(&db).expect("raw connection");
    conn.execute(
        "INSERT INTO usage_settlements
             (rowid, attempt_id, purpose, connection, cost_bound, state, exactness, wire_retries)
         VALUES (2, 'foreign-interrupted', 'main', 'local', 4, 'dispatched', 'unknown', 0)",
        [],
    )
    .expect("the foreign interrupted row lands");
    conn.execute(
        "INSERT INTO usage_settlements
             (rowid, attempt_id, purpose, connection, cost_bound, state, exactness, wire_retries)
         VALUES (3, 'foreign-settled', 'main', 'local', 3, 'dispatched', 'unknown', 0)",
        [],
    )
    .expect("the foreign settled row lands");
    conn.execute(
        "UPDATE usage_settlements
             SET state = 'settled', exactness = 'exact', prompt_tokens = 5,
                 completion_tokens = 2, total_tokens = 7, charged_units = 3
             WHERE attempt_id = 'foreign-settled'",
        [],
    )
    .expect("the foreign row closes");
    let record: (i64, i64) = conn
        .query_row(
            "SELECT settled_count, next_rowid FROM usage_totals WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the stale record answers");
    assert_eq!(record, (1, 2), "the record predates both foreign rows");
    drop(conn);

    let world = support::open_world_at(root.path(), Some(config_text()));
    assert_eq!(
        world
            .runtime
            .store()
            .settlement_totals()
            .expect("the open repairs the record"),
        SettlementTotals {
            settled_count: 3,
            settled_without_total: 1,
            total_tokens: Some(first_total + 7),
            charged_units: Some(first_bound + 3),
            dispatched_count: 0,
            latest_prompt_tokens: Some(5),
        },
        "the recomputed record counts every settled row and closes the foreign send"
    );
    assert!(
        world
            .runtime
            .boot_diagnostics
            .iter()
            .any(|line| line.contains("settlement recovery")),
        "the boot line names the recovery: {:?}",
        world.runtime.boot_diagnostics
    );
    drop(world);
    let conn = rusqlite::Connection::open(&db).expect("raw connection");
    let next_rowid: i64 = conn
        .query_row(
            "SELECT next_rowid FROM usage_totals WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .expect("the counter answers");
    assert_eq!(
        next_rowid, 4,
        "the record resumes after the newest foreign row"
    );
}

/// A reopen reconciles an older interrupted row after a newer send already
/// settled: the older row reported no prompt, so it never overwrites the
/// newer attempt's measured count in the incremental totals.
#[test]
fn an_older_reconciled_row_keeps_the_newest_measured_prompt() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-prompt-").expect("fixture root");
    let path = root.path().join("state.db");
    let mut store = TaskStore::open(&path).expect("store opens");
    store.open_budget(SCOPE_A, 10).expect("budget opens");
    let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Unknown)));
    let interrupted = prepared_with(&mut broker, "goal: older interrupted");
    let measured = prepared_with(&mut broker, "goal: newer measured");
    let charged = interrupted.cost_bound + measured.cost_bound;
    let _older_ticket = store
        .begin_send(&[SCOPE_A], &context(), &interrupted)
        .expect("the older send begins");
    let newer_ticket = store
        .begin_send(&[SCOPE_A], &context(), &measured)
        .expect("the newer send begins");
    store
        .finish_send(
            &newer_ticket,
            &SendOutcome::Settled {
                usage: UsageDelta::Exact {
                    prompt_tokens: 42,
                    completion_tokens: 8,
                    total_tokens: 50,
                },
                wire_retries: 0,
            },
        )
        .expect("the newer send settles");
    assert_eq!(
        store
            .settlement_totals()
            .expect("totals")
            .latest_prompt_tokens,
        Some(42),
        "the newer measured prompt is the latest settled figure"
    );

    assert_eq!(store.reconcile_sends().expect("reconciliation runs"), 1);
    let totals = store.settlement_totals().expect("totals");
    assert_eq!(
        totals.latest_prompt_tokens,
        Some(42),
        "the older interrupted row reports no prompt and keeps the newer measurement"
    );
    assert_eq!(totals.settled_count, 2);
    assert_eq!(totals.settled_without_total, 1);
    assert_eq!(totals.total_tokens, Some(50));
    assert_eq!(totals.charged_units, Some(charged));
    assert_eq!(totals.dispatched_count, 0);
}

/// A pre-totals build reopens this build's store and closes the allocated
/// row in place: the ledger settles, `next_rowid` still names the next
/// identity and the incremental record keeps counting the send as open. The
/// reopen must see the record behind the ledger and recompute it, or the
/// projection serves an open send and names no settled attempt over a
/// settled ledger.
#[test]
fn a_pre_totals_in_place_settle_is_recomputed_on_reopen() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-in-place-").expect("fixture root");
    let runtime_dir = root.path().join("runtime");
    std::fs::create_dir_all(&runtime_dir).expect("runtime dir");
    let db = runtime_dir.join("rivect.db");
    let (attempt_id, bound) = {
        let mut store = TaskStore::open(&db).expect("store opens");
        store.open_budget(SCOPE_A, 10).expect("budget opens");
        let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Unknown)));
        let manifest = prepared_with(&mut broker, "goal: in-place settle");
        store
            .begin_send(&[SCOPE_A], &context(), &manifest)
            .expect("the send begins");
        (manifest.attempt_id.clone(), manifest.cost_bound)
    };
    // The downgrade shape: the pre-totals build closes the allocated row in
    // place and never touches `usage_totals`, so the counter still names the
    // next identity while the record counts the send as open.
    let conn = rusqlite::Connection::open(&db).expect("raw connection");
    conn.execute(
        "UPDATE usage_settlements
             SET state = 'settled', exactness = 'exact', wire_retries = 0,
                 prompt_tokens = 6, completion_tokens = 4, total_tokens = 10,
                 charged_units = ?1
             WHERE attempt_id = ?2",
        rusqlite::params![i64::try_from(bound).expect("the bound fits"), attempt_id],
    )
    .expect("the downgraded build closes the row in place");
    let record: (i64, i64, i64) = conn
        .query_row(
            "SELECT settled_count, dispatched_count, next_rowid FROM usage_totals WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("the record answers");
    assert_eq!(record, (0, 1, 2), "the downgrade left the record behind");
    drop(conn);

    let mut world = support::open_world_at(root.path(), Some(config_text()));
    let totals = world.runtime.store().settlement_totals().expect("totals");
    assert_eq!(
        totals,
        SettlementTotals {
            settled_count: 1,
            settled_without_total: 0,
            total_tokens: Some(10),
            charged_units: Some(bound),
            dispatched_count: 0,
            latest_prompt_tokens: Some(6),
        },
        "the reopen recomputes the record from the settled ledger"
    );
    let session = world.open_session("bootstrap-economy-in-place");
    let economy = &status(&mut world, &session)["economy"];
    assert_eq!(economy["pending_sends"], json!(0), "no send reads open");
    assert_eq!(economy["settled_tokens"], json!(10));
    assert!(
        !economy["context_source"]
            .as_str()
            .expect("a context source is named")
            .contains("unknown"),
        "the settled row's measurement is served: {economy}"
    );
    assert!(
        world
            .runtime
            .boot_diagnostics
            .iter()
            .all(|line| !line.contains("settlement recovery")),
        "the ledger held no open send, so the boot line claims no recovery: {:?}",
        world.runtime.boot_diagnostics
    );
}

/// Two sends settle out of order: the newer row carries the measurement and
/// the older measured row settles afterwards. The record names the newest
/// settled attempt by rowid, so the late older row never replaces the newer
/// attempt's count.
#[test]
fn an_older_measured_settle_keeps_the_newest_measured_prompt() {
    let root =
        tempfile::TempDir::with_prefix("rivect-economy-prompt-order-").expect("fixture root");
    let path = root.path().join("state.db");
    let mut store = TaskStore::open(&path).expect("store opens");
    store.open_budget(SCOPE_A, 10).expect("budget opens");
    let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Unknown)));
    let older = prepared_with(&mut broker, "goal: older measured");
    let newer = prepared_with(&mut broker, "goal: newer measured");
    let older_ticket = store
        .begin_send(&[SCOPE_A], &context(), &older)
        .expect("the older send begins");
    let newer_ticket = store
        .begin_send(&[SCOPE_A], &context(), &newer)
        .expect("the newer send begins");
    store
        .finish_send(
            &newer_ticket,
            &SendOutcome::Settled {
                usage: UsageDelta::Exact {
                    prompt_tokens: 50,
                    completion_tokens: 4,
                    total_tokens: 54,
                },
                wire_retries: 0,
            },
        )
        .expect("the newer send settles");
    store
        .finish_send(
            &older_ticket,
            &SendOutcome::Settled {
                usage: UsageDelta::Exact {
                    prompt_tokens: 42,
                    completion_tokens: 8,
                    total_tokens: 50,
                },
                wire_retries: 0,
            },
        )
        .expect("the older send settles late");

    let totals = store.settlement_totals().expect("totals");
    assert_eq!(
        totals,
        SettlementTotals {
            settled_count: 2,
            settled_without_total: 0,
            total_tokens: Some(104),
            charged_units: Some(older.cost_bound + newer.cost_bound),
            dispatched_count: 0,
            latest_prompt_tokens: Some(50),
        },
        "the newest settled row keeps its measurement"
    );
}

/// Two measured sends settle in row order: the older row settles first with
/// the larger prompt, the newer row settles second with the smaller one. The
/// record names the newest settled attempt by rowid, so a value-maximum or
/// first-write-wins regression would serve the older figure.
#[test]
fn a_newer_measured_settle_replaces_the_older_measured_prompt() {
    let root =
        tempfile::TempDir::with_prefix("rivect-economy-prompt-newest-").expect("fixture root");
    let path = root.path().join("state.db");
    let mut store = TaskStore::open(&path).expect("store opens");
    store.open_budget(SCOPE_A, 10).expect("budget opens");
    let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Unknown)));
    let older = prepared_with(&mut broker, "goal: older measured");
    let newer = prepared_with(&mut broker, "goal: newer measured");
    let older_ticket = store
        .begin_send(&[SCOPE_A], &context(), &older)
        .expect("the older send begins");
    let newer_ticket = store
        .begin_send(&[SCOPE_A], &context(), &newer)
        .expect("the newer send begins");
    store
        .finish_send(
            &older_ticket,
            &SendOutcome::Settled {
                usage: UsageDelta::Exact {
                    prompt_tokens: 50,
                    completion_tokens: 4,
                    total_tokens: 54,
                },
                wire_retries: 0,
            },
        )
        .expect("the older send settles first");
    store
        .finish_send(
            &newer_ticket,
            &SendOutcome::Settled {
                usage: UsageDelta::Exact {
                    prompt_tokens: 42,
                    completion_tokens: 8,
                    total_tokens: 50,
                },
                wire_retries: 0,
            },
        )
        .expect("the newer send settles second");

    let totals = store.settlement_totals().expect("totals");
    assert_eq!(
        totals,
        SettlementTotals {
            settled_count: 2,
            settled_without_total: 0,
            total_tokens: Some(104),
            charged_units: Some(older.cost_bound + newer.cost_bound),
            dispatched_count: 0,
            latest_prompt_tokens: Some(42),
        },
        "the newer settled row replaces the older prompt even though it is smaller"
    );
}

/// A row this record never counted is reconciled while the open count is
/// already zero: the decrement clamps at zero instead of driving the served
/// ledger negative.
#[test]
fn reconcile_clamps_a_foreign_open_row_at_zero() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-clamp-").expect("fixture root");
    let path = root.path().join("state.db");
    let mut store = TaskStore::open(&path).expect("store opens");
    store.open_budget(SCOPE_A, 10).expect("budget opens");
    let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Unknown)));
    let manifest = prepared_with(&mut broker, "goal: zero clamp");
    store
        .begin_send(&[SCOPE_A], &context(), &manifest)
        .expect("the send begins");
    // The open row was never counted: a foreign write left the record's
    // open count at zero while the ledger holds one dispatched row.
    let conn = rusqlite::Connection::open(&path).expect("raw connection");
    conn.execute(
        "UPDATE usage_totals SET dispatched_count = 0 WHERE id = 1",
        [],
    )
    .expect("the record's open count is zeroed");
    drop(conn);

    assert_eq!(store.reconcile_sends().expect("reconciliation runs"), 1);
    let totals = store.settlement_totals().expect("totals");
    assert_eq!(
        totals,
        SettlementTotals {
            settled_count: 1,
            settled_without_total: 1,
            total_tokens: None,
            charged_units: Some(manifest.cost_bound),
            dispatched_count: 0,
            latest_prompt_tokens: None,
        },
        "the decrement clamps at zero, never below it"
    );
}

/// One settled send through the runtime's own writer, so the status
/// projection reads a row the product wrote.
fn settle_through_runtime(
    world: &mut support::World,
    scope: &str,
    usage: UsageDelta,
) -> RequestManifest {
    world
        .runtime
        .store_writer()
        .open_budget(scope, 10)
        .expect("budget opens");
    let manifest = world
        .runtime
        .broker
        .prepare(
            "main",
            &world.runtime.config_for_broker(),
            WORLD,
            "goal: status",
        )
        .expect("the status request prepares");
    let mut writer = world.runtime.store_writer();
    let ticket = writer
        .begin_send(&[scope], &context(), &manifest)
        .expect("the send begins");
    writer
        .finish_send(
            &ticket,
            &SendOutcome::Settled {
                usage,
                wire_retries: 0,
            },
        )
        .expect("the send settles");
    manifest
}

fn status(world: &mut support::World, session: &rivect::contracts::SessionId) -> Value {
    let response = world.dispatch(&support::corpus_status(session));
    assert!(
        response.get("result").is_some(),
        "runtime.status answers: {response}"
    );
    response["result"].clone()
}

#[test]
fn status_projects_settled_tokens_and_unknown_quota() {
    let mut world = support::open_world("economy-status", Some(config_text()));
    let session = world.open_session("bootstrap-economy-status");
    let manifest = settle_through_runtime(
        &mut world,
        "status-scope",
        UsageDelta::Legs {
            prompt_tokens: Some(8),
            completion_tokens: Some(2),
            reasoning_tokens: Some(1),
            cache_read_tokens: Some(4),
            cache_write_tokens: None,
            total_tokens: Some(10),
        },
    );
    world
        .runtime
        .refresh_economy(Some(&manifest))
        .expect("the projection refreshes");
    let economy = &status(&mut world, &session)["economy"];

    assert_eq!(economy["settled_tokens"], json!(10));
    assert_eq!(
        economy["settled_source"],
        json!("sum of 1 settled attempt's reported totals"),
        "one measured row reads singular possessive: {economy}"
    );
    assert_eq!(economy["charged_units"], json!(manifest.cost_bound));
    // An unreported quota is unknown beside its source — never zero and
    // never unlimited.
    assert_eq!(economy["quota_remaining"], Value::Null);
    assert!(
        economy["quota_source"]
            .as_str()
            .expect("a source is named")
            .contains("unknown"),
        "the quota source names the unknown: {economy}"
    );
    assert_eq!(economy["reset_at"], Value::Null);
}

/// Two measured settlements serve the plural possessive: the source names
/// the lifetime sum, never one row's total.
#[test]
fn status_settled_source_sums_two_measured_attempts() {
    let mut world = support::open_world("economy-two-measured", Some(config_text()));
    let session = world.open_session("bootstrap-economy-two-measured");
    settle_through_runtime(
        &mut world,
        "two-measured-a",
        UsageDelta::Exact {
            prompt_tokens: 6,
            completion_tokens: 4,
            total_tokens: 10,
        },
    );
    let second = settle_through_runtime(
        &mut world,
        "two-measured-b",
        UsageDelta::Exact {
            prompt_tokens: 7,
            completion_tokens: 3,
            total_tokens: 10,
        },
    );
    world
        .runtime
        .refresh_economy(Some(&second))
        .expect("the projection refreshes");
    let economy = &status(&mut world, &session)["economy"];
    assert_eq!(economy["settled_tokens"], json!(20));
    assert_eq!(
        economy["settled_source"],
        json!("sum of 2 settled attempts' reported totals"),
        "two measured rows read plural possessive: {economy}"
    );
}

/// A fresh store has no settled attempt and no charged unit: every absent
/// figure names the unknown it is instead of borrowing a later-branch
/// explanation about a row that does not exist.
#[test]
fn a_fresh_store_names_no_settled_attempt_or_charge() {
    let mut world = support::open_world("economy-fresh", Some(config_text()));
    let session = world.open_session("bootstrap-economy-fresh");
    let economy = &status(&mut world, &session)["economy"];
    assert_eq!(economy["settled_tokens"], Value::Null);
    assert_eq!(
        economy["settled_source"],
        json!("unknown: no settled attempt recorded"),
        "the empty lifetime is unknown, not a sum: {economy}"
    );
    assert_eq!(economy["charged_units"], Value::Null);
    assert_eq!(
        economy["cost_source"],
        json!("unknown: no settled charge recorded"),
        "the empty charge is unknown, not zero: {economy}"
    );
    assert_eq!(economy["context_tokens"], Value::Null);
    assert_eq!(
        economy["context_source"],
        json!("unknown: no settled attempt recorded"),
        "no settled attempt exists to report a prompt: {economy}"
    );
}

/// A send that reserved no budget scope settles uncharged: the projection
/// names the charge unknown, never zero, while the settled row is counted.
#[test]
fn an_uncharged_settled_send_keeps_the_unknown_cost_source() {
    let mut world = support::open_world("economy-unreserved", Some(config_text()));
    let session = world.open_session("bootstrap-economy-unreserved");
    let manifest = world
        .runtime
        .broker
        .prepare(
            "main",
            &world.runtime.config_for_broker(),
            WORLD,
            "goal: status",
        )
        .expect("the status request prepares");
    {
        let mut writer = world.runtime.store_writer();
        let ticket = writer
            .begin_send(&[], &context(), &manifest)
            .expect("the send begins");
        assert!(!ticket.reserved, "no scope is open, so nothing is reserved");
        writer
            .finish_send(
                &ticket,
                &SendOutcome::Settled {
                    usage: UsageDelta::Unknown,
                    wire_retries: 0,
                },
            )
            .expect("the send settles");
    }
    world
        .runtime
        .refresh_economy(Some(&manifest))
        .expect("the projection refreshes");
    let totals = world.runtime.store().settlement_totals().expect("totals");
    assert_eq!(totals.settled_count, 1);
    assert_eq!(totals.charged_units, None, "nothing was charged");
    let economy = &status(&mut world, &session)["economy"];
    assert_eq!(economy["charged_units"], Value::Null);
    assert_eq!(
        economy["cost_source"],
        json!("unknown: no settled charge recorded"),
        "the uncharged send names the unknown charge: {economy}"
    );
}

#[test]
fn settled_totals_stay_partial_when_a_row_reports_no_total() {
    let mut world = support::open_world("economy-partial", Some(config_text()));
    let session = world.open_session("bootstrap-economy-partial");
    let measured = settle_through_runtime(
        &mut world,
        "partial-measured",
        UsageDelta::Exact {
            prompt_tokens: 6,
            completion_tokens: 4,
            total_tokens: 10,
        },
    );
    settle_through_runtime(&mut world, "partial-unknown", UsageDelta::Unknown);
    world
        .runtime
        .refresh_economy(Some(&measured))
        .expect("the projection refreshes");
    let totals = world.runtime.store().settlement_totals().expect("totals");
    assert_eq!(totals.settled_count, 2);
    assert_eq!(totals.settled_without_total, 1);
    assert_eq!(totals.total_tokens, Some(10));
    assert_eq!(
        totals.latest_prompt_tokens, None,
        "the newest settled row reported no prompt, so no older measurement survives"
    );
    let economy = &status(&mut world, &session)["economy"];
    assert_eq!(economy["settled_tokens"], json!(10));
    assert_eq!(economy["settled_without_total"], json!(1));
    let source = economy["settled_source"]
        .as_str()
        .expect("the partial total names its basis");
    assert!(
        source.contains("partial") && source.contains("1 of 2"),
        "a known part is never presented as the whole: {source}"
    );
    assert_eq!(
        economy["context_tokens"],
        Value::Null,
        "occupancy is unknown, never the older measured prompt"
    );
    let context = economy["context_source"]
        .as_str()
        .expect("the occupied context names its basis");
    assert!(
        context.contains("unknown")
            && context.contains("latest settled attempt reported no prompt tokens"),
        "the unknown newest attempt is named: {context}"
    );
}

/// A lifetime whose every settled row reported no total is unknown, not a
/// partial sum: naming it `partial: N of N` would present nothing measured
/// as most of a whole.
#[test]
fn settled_totals_are_unknown_when_no_row_reports_a_total() {
    let mut world = support::open_world("economy-unmeasured", Some(config_text()));
    let session = world.open_session("bootstrap-economy-unmeasured");
    settle_through_runtime(&mut world, "unmeasured-first", UsageDelta::Unknown);
    let second = settle_through_runtime(&mut world, "unmeasured-second", UsageDelta::Unknown);
    world
        .runtime
        .refresh_economy(Some(&second))
        .expect("the projection refreshes");
    let economy = &status(&mut world, &session)["economy"];
    assert_eq!(
        economy["settled_tokens"],
        Value::Null,
        "no row reported a total, so no lifetime sum exists: {economy}"
    );
    assert_eq!(economy["settled_without_total"], json!(2));
    assert_eq!(
        economy["settled_source"],
        json!("unknown: 2 settled attempts reported no total"),
        "an unmeasured lifetime is unknown, not partial: {economy}"
    );
}

#[test]
fn a_single_unmeasured_settled_attempt_reads_unknown_singular() {
    let mut world = support::open_world("economy-unmeasured-one", Some(config_text()));
    let session = world.open_session("bootstrap-economy-unmeasured-one");
    let manifest = settle_through_runtime(&mut world, "unmeasured-one", UsageDelta::Unknown);
    world
        .runtime
        .refresh_economy(Some(&manifest))
        .expect("the projection refreshes");
    let economy = &status(&mut world, &session)["economy"];
    assert_eq!(economy["settled_without_total"], json!(1));
    assert_eq!(
        economy["settled_source"],
        json!("unknown: 1 settled attempt reported no total"),
        "one unmeasured row reads singular: {economy}"
    );
}

#[test]
fn status_unknown_effort_shows_the_sent_setting_and_source() {
    let mut world = support::open_world("economy-effort", Some(config_text()));
    let session = world.open_session("bootstrap-economy-effort");
    let manifest = settle_through_runtime(&mut world, "effort-scope", UsageDelta::Unknown);
    world
        .runtime
        .refresh_economy(Some(&manifest))
        .expect("the projection refreshes");
    let economy = &status(&mut world, &session)["economy"];

    assert_eq!(
        economy["effort"],
        json!("high"),
        "the sent setting is shown"
    );
    assert!(
        economy["effort_source"]
            .as_str()
            .expect("a source is named")
            .contains("sent setting"),
        "the source says the endpoint reports no effective effort: {economy}"
    );
    assert_eq!(economy["purpose"], json!("main"), "the scope is named");
}

#[test]
fn status_keeps_project_and_cwd_visible() {
    let mut world = support::open_world("economy-project", Some(config_text()));
    let session = world.open_session("bootstrap-economy-project");
    let manifest = settle_through_runtime(&mut world, "project-scope", UsageDelta::Unknown);
    world
        .runtime
        .refresh_economy(Some(&manifest))
        .expect("the projection refreshes");
    let economy = &status(&mut world, &session)["economy"];
    assert!(
        !economy["project"].as_str().unwrap_or_default().is_empty(),
        "the project stays visible: {economy}"
    );
    assert!(
        !economy["cwd"].as_str().unwrap_or_default().is_empty(),
        "the cwd stays visible: {economy}"
    );
    // The dock row carries both in the same projection.
    let dock = rivect::ui::task_dock(&status(&mut world, &session));
    let row = dock.last().expect("the economy slot paints last");
    assert!(row.contains("project "), "the row names the project: {row}");
    assert!(row.contains("cwd "), "the row names the cwd: {row}");
}

#[test]
fn context_occupancy_is_not_lifetime_spend() {
    let mut world = support::open_world("economy-occupancy", Some(config_text()));
    let session = world.open_session("bootstrap-economy-occupancy");
    let manifest = settle_through_runtime(
        &mut world,
        "occupancy-scope",
        UsageDelta::Exact {
            prompt_tokens: 5,
            completion_tokens: 5,
            total_tokens: 10,
        },
    );
    world
        .runtime
        .refresh_economy(Some(&manifest))
        .expect("the projection refreshes");
    let economy = &status(&mut world, &session)["economy"];
    // Occupancy is the latest settled attempt's reported prompt tokens; spend
    // is the settled lifetime figure. The two are served apart and never
    // summed, and occupancy is never the request's byte length.
    assert_eq!(economy["context_tokens"], json!(5));
    assert_eq!(economy["settled_tokens"], json!(10));
    assert_ne!(economy["context_tokens"], economy["settled_tokens"]);
    assert_eq!(economy["context_window"], Value::Null);
    assert!(
        economy["context_source"]
            .as_str()
            .expect("a source is named")
            .contains("prompt tokens"),
        "the occupancy source names the reported prompt tokens: {economy}"
    );
}

#[test]
fn status_read_does_not_scan_the_store() {
    let mut world = support::open_world("economy-cache", Some(config_text()));
    let session = world.open_session("bootstrap-economy-cache");
    let manifest = settle_through_runtime(
        &mut world,
        "cache-scope",
        UsageDelta::Exact {
            prompt_tokens: 4,
            completion_tokens: 6,
            total_tokens: 10,
        },
    );
    world
        .runtime
        .refresh_economy(Some(&manifest))
        .expect("the projection refreshes");
    let first = status(&mut world, &session)["economy"].clone();
    assert_eq!(first["settled_tokens"], json!(10));

    // A second settlement lands in the store without a refresh: a status
    // read that scanned the settlement rows would report it.
    settle_through_runtime(
        &mut world,
        "cache-scope-two",
        UsageDelta::Exact {
            prompt_tokens: 7,
            completion_tokens: 3,
            total_tokens: 10,
        },
    );
    let second = status(&mut world, &session)["economy"].clone();
    assert_eq!(
        second, first,
        "the status serves the cached projection, not a fresh store scan"
    );
}

// ----- review-repair legs (w-059-r1) -----

/// The frozen bound of a request whose input needs `units` budget units.
fn inputs_for_bound(units: u64) -> String {
    // one unit per 4096 input bytes, plus one for the request itself.
    "x".repeat(usize::try_from((units - 1) * 4096).expect("fits"))
}

fn prepared_with(broker: &mut Broker, inputs: &str) -> RequestManifest {
    broker
        .prepare("main", &config(), WORLD, inputs)
        .expect("the fixture request prepares")
}

/// A budget refusal reaches the caller as the dedicated model error, never
/// as an opaque ledger wrapper, and the send never entered.
#[test]
fn budget_refusal_is_the_typed_waiting_error() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-budget-").expect("fixture root");
    let mut store = TaskStore::open(&root.path().join("state.db")).expect("store opens");
    store.open_budget(SCOPE_A, 0).expect("budget opens at zero");
    let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Unknown)));
    let manifest = prepared_with(&mut broker, "goal: budget");
    let sent = {
        let mut ledger = StoreLedger::new(&mut store, vec![SCOPE_A.to_string()]);
        broker.dispatch(&mut ledger, WORLD, &manifest)
    };
    match sent {
        Err(ModelError::BudgetExhausted { scope }) => assert_eq!(scope, SCOPE_A),
        other => panic!("a budget refusal stays its own class: {other:?}"),
    }
    assert!(
        matches!(
            store.settlement(&manifest.attempt_id),
            Err(StoreError::NotFound(_))
        ),
        "a refused send never opens a row"
    );
    assert_eq!(store.budget_status(SCOPE_A).expect("scope").reserved, 0);
}

/// An estimate (legs without a total) settles: its bins are kept and the
/// retained bound caps the charge. It can never leave the row dispatched.
#[test]
fn estimate_settles_with_the_retained_bound_and_keeps_its_bins() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-estimate-").expect("fixture root");
    let mut store = TaskStore::open(&root.path().join("state.db")).expect("store opens");
    store.open_budget(SCOPE_A, 10).expect("budget opens");
    let usage = UsageDelta::Legs {
        prompt_tokens: Some(4),
        completion_tokens: Some(2),
        reasoning_tokens: Some(1),
        cache_read_tokens: Some(3),
        cache_write_tokens: None,
        total_tokens: None,
    };
    let mut broker = Broker::new(Box::new(UsageProvider::settled(usage)));
    let manifest = prepared_with(&mut broker, "goal: estimate");
    {
        let mut ledger = StoreLedger::new(&mut store, vec![SCOPE_A.to_string()]);
        broker
            .dispatch(&mut ledger, WORLD, &manifest)
            .expect("the estimate send settles");
    }
    let record = store.settlement(&manifest.attempt_id).expect("row settles");
    assert_eq!(record.state, SettlementState::Settled);
    assert_eq!(record.exactness, Exactness::Estimate);
    assert_eq!(record.bins.prompt_tokens, Some(4));
    assert_eq!(record.bins.reasoning_tokens, Some(1));
    assert_eq!(record.bins.total_tokens, None);
    assert_eq!(record.charged_units, Some(manifest.cost_bound));
    assert_eq!(
        store.settlement_totals().expect("totals").dispatched_count,
        0
    );
}

/// A row begun with no open scope reserved nothing, so its interrupted
/// reconciliation records no charge.
#[test]
fn reconciling_an_unreserved_row_records_no_charge() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-unreserved-").expect("fixture root");
    let path = root.path().join("state.db");
    let attempt = {
        let mut store = TaskStore::open(&path).expect("store opens");
        let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Unknown)));
        let manifest = prepared_with(&mut broker, "goal: semantic");
        store
            .begin_send(&[], &context(), &manifest)
            .expect("the send begins");
        manifest.attempt_id
    };
    let mut reopened = TaskStore::open(&path).expect("store reopens");
    assert_eq!(reopened.reconcile_sends().expect("reconciles"), 1);
    let record = reopened.settlement(&attempt).expect("row settles");
    assert_eq!(record.state, SettlementState::Settled);
    assert_eq!(record.exactness, Exactness::Unknown);
    assert_eq!(record.unknown_reason.as_deref(), Some("interrupted"));
    assert_eq!(
        record.charged_units, None,
        "nothing was reserved, so nothing is charged"
    );
}

/// A replay after restart is refused at both layers: the store's settlement
/// row refuses a second begin typed, and a restarted broker's empty
/// admission table refuses the frozen manifest before any provider call —
/// the durable row stays the exactly-once guard behind the in-memory gate.
#[test]
fn restart_replay_is_refused_and_never_doubles() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-replay-").expect("fixture root");
    let path = root.path().join("state.db");
    let (attempt, totals_before) = {
        let mut store = TaskStore::open(&path).expect("store opens");
        store.open_budget(SCOPE_A, 10).expect("budget opens");
        let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Exact {
            prompt_tokens: 3,
            completion_tokens: 2,
            total_tokens: 5,
        })));
        let manifest = prepared_with(&mut broker, "goal: replay");
        {
            let mut ledger = StoreLedger::new(&mut store, vec![SCOPE_A.to_string()]);
            broker
                .dispatch(&mut ledger, WORLD, &manifest)
                .expect("the send settles");
        }
        (manifest, store.settlement_totals().expect("totals"))
    };
    let mut reopened = TaskStore::open(&path).expect("store reopens");
    let replay = reopened.begin_send(&[SCOPE_A], &context(), &attempt);
    assert!(
        matches!(
            replay,
            Err(StoreError::Conflict(
                ConflictCause::SettlementAlreadyRecorded { .. }
            ))
        ),
        "a restart replay is the typed refusal: {replay:?}"
    );
    assert_eq!(
        reopened.settlement_totals().expect("totals"),
        totals_before,
        "one row and one spend survive the replay"
    );
    let status = reopened.budget_status(SCOPE_A).expect("scope");
    assert_eq!(status.reserved, 0, "the settled reservation is not held");

    // The settlement row is the durable exactly-once guard; the in-memory
    // admission is the earlier layer. A restarted broker holds no admission
    // for the spent attempt, so dispatching the frozen manifest again is
    // refused typed and the provider is never called.
    let calls = Arc::new(AtomicU64::new(0));
    let mut broker = Broker::new(Box::new(UsageProvider::counting(
        UsageDelta::Unknown,
        Arc::clone(&calls),
    )));
    let admission_replay = {
        let mut ledger = StoreLedger::new(&mut reopened, vec![SCOPE_A.to_string()]);
        broker.dispatch(&mut ledger, WORLD, &attempt)
    };
    assert!(
        matches!(admission_replay, Err(ModelError::NoAdmission { .. })),
        "a restarted broker refuses the spent manifest at admission: {admission_replay:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the admission refusal lands before a provider call"
    );
    assert_eq!(
        reopened.settlement_totals().expect("totals"),
        totals_before,
        "the refused replay leaves the settled row and spend unchanged"
    );
}

/// SQLite itself keeps a settled record: a raw delete and both replace
/// shapes abort, and the row, the settled totals and the charged spend stay
/// exactly as the settle left them.
#[test]
fn settled_rows_refuse_raw_delete_and_replace() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-immutable-").expect("fixture root");
    let path = root.path().join("state.db");
    let (attempt_id, totals_before, spent_before) = {
        let mut store = TaskStore::open(&path).expect("store opens");
        store.open_budget(SCOPE_A, 10).expect("budget opens");
        let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Unknown)));
        let manifest = prepared_with(&mut broker, "goal: immutable");
        {
            let mut ledger = StoreLedger::new(&mut store, vec![SCOPE_A.to_string()]);
            broker
                .dispatch(&mut ledger, WORLD, &manifest)
                .expect("the send settles");
        }
        let spent = store.budget_status(SCOPE_A).expect("scope").spent;
        (
            manifest.attempt_id,
            store.settlement_totals().expect("totals"),
            spent,
        )
    };
    let conn = rusqlite::Connection::open(&path).expect("raw connection");
    let deleted = conn.execute(
        "DELETE FROM usage_settlements WHERE attempt_id = ?1",
        rusqlite::params![attempt_id.as_str()],
    );
    expect_abort(deleted, "settlement rows are immutable");
    // A replace carries its own new state: `settled` is refused by the
    // dispatch-only guard, and `dispatched` would also erase the record, so
    // the existing-attempt arm refuses it too.
    for state in ["settled", "dispatched"] {
        let replaced = conn.execute(
            "INSERT OR REPLACE INTO usage_settlements
             (attempt_id, purpose, connection, cost_bound, state, exactness, wire_retries)
             VALUES (?1, 'main', ?2, 0, ?3, 'unknown', 0)",
            rusqlite::params![attempt_id.as_str(), CONNECTION, state],
        );
        expect_abort(
            replaced,
            "settlements are opened dispatched and never replaced",
        );
    }
    // An `UPDATE OR REPLACE` that rewrites the attempt id would delete the
    // settled row through the primary-key conflict: the identity is fixed.
    let identity = conn.execute(
        "UPDATE OR REPLACE usage_settlements SET attempt_id = ?1 WHERE attempt_id = ?2",
        rusqlite::params!["replacement-attempt", attempt_id.as_str()],
    );
    expect_abort(identity, "settlement attempt ids are immutable");
    let bins = conn.execute(
        "UPDATE usage_settlements SET total_tokens = 99 WHERE attempt_id = ?1",
        rusqlite::params![attempt_id.as_str()],
    );
    expect_abort(bins, "settled settlements are immutable");
    drop(conn);
    let store = TaskStore::open(&path).expect("store reopens");
    let record = store.settlement(&attempt_id).expect("the row survives");
    assert_eq!(record.state, SettlementState::Settled);
    assert_eq!(
        store.settlement_totals().expect("totals"),
        totals_before,
        "the refused writes change no settled total"
    );
    assert_eq!(
        store.budget_status(SCOPE_A).expect("scope").spent,
        spent_before,
        "the refused writes release no charged spend"
    );
}

/// Asserts a raw statement aborted with the schema's named guard text, so a
/// renamed guard statement cannot pass as a vacuous error.
fn expect_abort<T>(result: rusqlite::Result<T>, needle: &str) {
    match result {
        Ok(_) => panic!("expected an abort containing `{needle}`"),
        Err(error) => assert!(
            error.to_string().contains(needle),
            "unexpected abort text for `{needle}`: {error}"
        ),
    }
}

/// The guards discriminate every forbidden identity rewrite: a dispatched
/// row A cannot be replaced onto a settled row S (by attempt id or by the
/// implicit rowid), reopened, or deleted, while S stays byte-intact and the
/// ledger totals/spend/reserve do not move.
#[test]
fn settlement_guards_refuse_identity_state_and_delete_rewrites() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-guards-").expect("fixture root");
    let path = root.path().join("state.db");
    let (settled_id, dispatched_id, settled_before, totals_before, spent_before, reserved_before) = {
        let mut store = TaskStore::open(&path).expect("store opens");
        store.open_budget(SCOPE_A, 10).expect("budget opens");
        let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Exact {
            prompt_tokens: 3,
            completion_tokens: 2,
            total_tokens: 5,
        })));
        let settled = prepared_with(&mut broker, "goal: settled guard");
        {
            let mut ledger = StoreLedger::new(&mut store, vec![SCOPE_A.to_string()]);
            broker
                .dispatch(&mut ledger, WORLD, &settled)
                .expect("the first send settles");
        }
        let dispatched = prepared_with(&mut broker, "goal: dispatched guard");
        store
            .begin_send(&[SCOPE_A], &context(), &dispatched)
            .expect("the second send is begun");
        let status = store.budget_status(SCOPE_A).expect("scope");
        let settled_record = store.settlement(&settled.attempt_id).expect("settled row");
        (
            settled.attempt_id,
            dispatched.attempt_id,
            settled_record,
            store.settlement_totals().expect("totals"),
            status.spent,
            status.reserved,
        )
    };
    let conn = rusqlite::Connection::open(&path).expect("raw connection");
    let settled_rowid: i64 = conn
        .query_row(
            "SELECT rowid FROM usage_settlements WHERE attempt_id = ?1",
            rusqlite::params![settled_id.as_str()],
            |row| row.get(0),
        )
        .expect("the settled row carries its identity");
    let replaced = conn.execute(
        "UPDATE OR REPLACE usage_settlements
         SET attempt_id = ?1, state = 'settled'
         WHERE attempt_id = ?2",
        rusqlite::params![settled_id.as_str(), dispatched_id.as_str()],
    );
    expect_abort(replaced, "settlement attempt ids are immutable");
    let rowid_inserted = conn.execute(
        "INSERT OR REPLACE INTO usage_settlements
         (rowid, attempt_id, purpose, connection, cost_bound, state, exactness, wire_retries)
         VALUES (?1, 'replacement-row', 'main', 'local', 0, 'dispatched', 'unknown', 0)",
        rusqlite::params![settled_rowid],
    );
    expect_abort(
        rowid_inserted,
        "settlements are opened dispatched and never replaced",
    );
    let rowid_rewritten = conn.execute(
        "UPDATE OR REPLACE usage_settlements
         SET rowid = ?1, state = 'settled'
         WHERE attempt_id = ?2",
        rusqlite::params![settled_rowid, dispatched_id.as_str()],
    );
    expect_abort(rowid_rewritten, "settlement row identity is immutable");
    let reopened = conn.execute(
        "UPDATE usage_settlements SET state = 'reopened' WHERE attempt_id = ?1",
        rusqlite::params![dispatched_id.as_str()],
    );
    expect_abort(reopened, "a dispatched settlement only closes settled");
    let deleted = conn.execute(
        "DELETE FROM usage_settlements WHERE attempt_id = ?1",
        rusqlite::params![dispatched_id.as_str()],
    );
    expect_abort(deleted, "settlement rows are immutable");
    drop(conn);
    let store = TaskStore::open(&path).expect("store reopens");
    assert_eq!(
        store
            .settlement(&settled_id)
            .expect("the settled row survives"),
        settled_before
    );
    assert_eq!(
        store.settlement_totals().expect("totals"),
        totals_before,
        "the refused writes change no settled total"
    );
    let status = store.budget_status(SCOPE_A).expect("scope");
    assert_eq!(status.spent, spent_before);
    assert_eq!(status.reserved, reserved_before);
}

/// A store first opened by the previous candidate keeps stale trigger bodies
/// unless open replaces them: plant an earlier candidate's INSERT/DELETE
/// bodies, reopen, and both the rowid replace and the dispatched delete must
/// abort. A raw stored `-1` rowid is a real identity: the product names a
/// positive rowid, and a raw replace at `-1` aborts.
#[test]
fn stale_settlement_trigger_bodies_are_replaced_on_open() {
    let root =
        tempfile::TempDir::with_prefix("rivect-economy-stale-triggers-").expect("fixture root");
    let path = root.path().join("state.db");
    TaskStore::open(&path).expect("store opens");
    // A raw explicit rowid -1 is a stored identity, not the implicit
    // sentinel: it is admitted, and the product still names its own
    // positive rowid so a later insert never lands on it.
    {
        let conn = rusqlite::Connection::open(&path).expect("raw connection");
        conn.execute(
            "INSERT INTO usage_settlements
             (rowid, attempt_id, purpose, connection, cost_bound, state, exactness, wire_retries)
             VALUES (-1, 'negative-rowid', 'main', 'local', 0, 'dispatched', 'unknown', 0)",
            [],
        )
        .expect("a raw negative rowid is admitted");
    }
    let (settled_id, dispatched_id, settled_before, totals_before, spent_before) = {
        let mut store = TaskStore::open(&path).expect("store reopens");
        store.open_budget(SCOPE_A, 10).expect("budget opens");
        let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Exact {
            prompt_tokens: 3,
            completion_tokens: 2,
            total_tokens: 5,
        })));
        let settled = prepared_with(&mut broker, "goal: stale settled");
        {
            let mut ledger = StoreLedger::new(&mut store, vec![SCOPE_A.to_string()]);
            broker
                .dispatch(&mut ledger, WORLD, &settled)
                .expect("the first send settles");
        }
        let dispatched = prepared_with(&mut broker, "goal: stale dispatched");
        store
            .begin_send(&[SCOPE_A], &context(), &dispatched)
            .expect("the second send is begun");
        let spent = store.budget_status(SCOPE_A).expect("scope").spent;
        let record = store.settlement(&settled.attempt_id).expect("settled row");
        (
            settled.attempt_id,
            dispatched.attempt_id,
            record,
            store.settlement_totals().expect("totals"),
            spent,
        )
    };
    {
        let conn = rusqlite::Connection::open(&path).expect("raw connection");
        conn.execute_batch(
            "DROP TRIGGER usage_settlements_dispatch_only;
             CREATE TRIGGER usage_settlements_dispatch_only
             BEFORE INSERT ON usage_settlements
             WHEN NEW.state <> 'dispatched'
                OR EXISTS (SELECT 1 FROM usage_settlements WHERE attempt_id = NEW.attempt_id)
             BEGIN
                 SELECT RAISE(ABORT, 'settlements are opened dispatched and never replaced');
             END;
             DROP TRIGGER usage_settlements_undeletable;
             CREATE TRIGGER usage_settlements_settled_undeletable
             BEFORE DELETE ON usage_settlements
             WHEN OLD.state = 'settled'
             BEGIN
                 SELECT RAISE(ABORT, 'settled settlements are immutable');
             END;",
        )
        .expect("the earlier candidate's bodies are planted");
    }
    let store = TaskStore::open(&path).expect("the open reinstalls the current guards");
    drop(store);
    let conn = rusqlite::Connection::open(&path).expect("raw connection");
    let insert_body: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'usage_settlements_dispatch_only'",
            [],
            |row| row.get(0),
        )
        .expect("the insert guard is installed");
    assert!(
        insert_body.contains("NEW.rowid"),
        "the current insert body replaces the stale one: {insert_body}"
    );
    let stale: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name = 'usage_settlements_settled_undeletable'",
            [],
            |row| row.get(0),
        )
        .expect("the old trigger name is retired");
    assert_eq!(stale, 0, "the settled-only delete guard is gone");
    let delete_body: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'usage_settlements_undeletable'",
            [],
            |row| row.get(0),
        )
        .expect("the delete guard is installed");
    assert!(
        !delete_body.contains("WHEN OLD.state"),
        "every settlement row is undeletable: {delete_body}"
    );
    let settled_rowid: i64 = conn
        .query_row(
            "SELECT rowid FROM usage_settlements WHERE attempt_id = ?1",
            rusqlite::params![settled_id.as_str()],
            |row| row.get(0),
        )
        .expect("the settled row carries its identity");
    assert!(
        settled_rowid >= 1,
        "the product names a positive row identity: {settled_rowid}"
    );
    // A raw replace at the stored `-1` identity is a replace of a stored
    // row: the guard's rowid arm is unconditional.
    let negative_replaced = conn.execute(
        "INSERT OR REPLACE INTO usage_settlements
         (rowid, attempt_id, purpose, connection, cost_bound, state, exactness, wire_retries)
         VALUES (-1, 'negative-rowid-replacement', 'main', 'local', 0, 'dispatched', 'unknown', 0)",
        [],
    );
    expect_abort(
        negative_replaced,
        "settlements are opened dispatched and never replaced",
    );
    let inserted = conn.execute(
        "INSERT OR REPLACE INTO usage_settlements
         (rowid, attempt_id, purpose, connection, cost_bound, state, exactness, wire_retries)
         VALUES (?1, 'replacement-row', 'main', 'local', 0, 'dispatched', 'unknown', 0)",
        rusqlite::params![settled_rowid],
    );
    expect_abort(
        inserted,
        "settlements are opened dispatched and never replaced",
    );
    let deleted = conn.execute(
        "DELETE FROM usage_settlements WHERE attempt_id = ?1",
        rusqlite::params![dispatched_id.as_str()],
    );
    expect_abort(deleted, "settlement rows are immutable");
    drop(conn);
    let store = TaskStore::open(&path).expect("store reopens");
    assert_eq!(
        store
            .settlement(&settled_id)
            .expect("the settled row survives"),
        settled_before
    );
    assert_eq!(store.settlement_totals().expect("totals"), totals_before);
    assert_eq!(
        store.budget_status(SCOPE_A).expect("scope").spent,
        spent_before
    );
}

/// A confirmed total below the bound charges exactly the confirmed units.
#[test]
fn below_bound_charge_spends_exactly_the_confirmed_total() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-below-").expect("fixture root");
    let mut store = TaskStore::open(&root.path().join("state.db")).expect("store opens");
    store.open_budget(SCOPE_A, 10).expect("budget opens");
    let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Exact {
        prompt_tokens: 1,
        completion_tokens: 0,
        total_tokens: 1,
    })));
    let manifest = prepared_with(&mut broker, &inputs_for_bound(2));
    assert_eq!(manifest.cost_bound, 2);
    {
        let mut ledger = StoreLedger::new(&mut store, vec![SCOPE_A.to_string()]);
        broker
            .dispatch(&mut ledger, WORLD, &manifest)
            .expect("the send settles");
    }
    let record = store.settlement(&manifest.attempt_id).expect("row");
    assert_eq!(record.charged_units, Some(1));
    assert_eq!(store.budget_status(SCOPE_A).expect("scope").spent, 1);
}

/// Explicit zero and a missing counter stay distinct; a folded reasoning
/// leg is carried as its own bin, never added to the completion count.
#[test]
fn explicit_zero_stays_distinct_and_folded_reasoning_is_not_added() {
    let usage = UsageDelta::Legs {
        prompt_tokens: Some(0),
        completion_tokens: Some(5),
        reasoning_tokens: Some(3),
        cache_read_tokens: Some(2),
        cache_write_tokens: Some(0),
        total_tokens: Some(8),
    };
    let bins = usage.bins();
    assert_eq!(bins.prompt_tokens, Some(0), "a reported zero is a fact");
    assert_eq!(bins.completion_tokens, Some(5), "reasoning is not added");
    assert_eq!(bins.reasoning_tokens, Some(3));
    assert_eq!(bins.cache_read_tokens, Some(2));
    assert_eq!(bins.cache_write_tokens, Some(0));
    assert_eq!(UsageDelta::Unknown.bins().completion_tokens, None);
    assert_ne!(
        usage.bins().completion_tokens,
        UsageDelta::Unknown.bins().completion_tokens
    );
    assert_eq!(usage.exactness(), Exactness::Exact);
    let estimate = UsageDelta::Legs {
        prompt_tokens: None,
        completion_tokens: None,
        reasoning_tokens: None,
        cache_read_tokens: Some(0),
        cache_write_tokens: None,
        total_tokens: None,
    };
    assert_eq!(estimate.exactness(), Exactness::Estimate);

    // The store round-trip keeps a reported zero: the column is NULL only
    // for a missing counter, so a reopened read must not turn `Some(0)` into
    // `None` or invent one where the provider reported none.
    let root = tempfile::TempDir::with_prefix("rivect-economy-zero-").expect("fixture root");
    let path = root.path().join("state.db");
    let attempt = {
        let mut store = TaskStore::open(&path).expect("store opens");
        store.open_budget(SCOPE_A, 10).expect("budget opens");
        let mut broker = Broker::new(Box::new(UsageProvider::settled(usage)));
        let manifest = prepared_with(&mut broker, "goal: zero");
        {
            let mut ledger = StoreLedger::new(&mut store, vec![SCOPE_A.to_string()]);
            broker
                .dispatch(&mut ledger, WORLD, &manifest)
                .expect("the zero leg settles");
        }
        manifest.attempt_id
    };
    let reopened = TaskStore::open(&path).expect("store reopens");
    let record = reopened.settlement(&attempt).expect("the row survives");
    assert_eq!(
        record.bins.prompt_tokens,
        Some(0),
        "a reported zero prompt leg survives the reopen"
    );
    assert_eq!(
        record.bins.cache_write_tokens,
        Some(0),
        "an explicit zero cache leg survives the reopen"
    );
    assert_eq!(record.bins.reasoning_tokens, Some(3));
    assert_eq!(record.bins.completion_tokens, Some(5));
}

/// Runtime open reconciles an interrupted send: the row closes unknown,
/// the bound is charged because a reservation exists, and the boot
/// diagnostics name the recovery.
#[test]
fn open_world_reconciles_an_interrupted_send() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-open-").expect("fixture root");
    let mut world = support::open_world_at(root.path(), Some(config_text()));
    world.open_session("bootstrap-economy-open");
    world
        .runtime
        .store_writer()
        .open_budget("open-scope", 10)
        .expect("budget opens");
    let manifest = world
        .runtime
        .broker
        .prepare(
            "main",
            &world.runtime.config_for_broker(),
            WORLD,
            "goal: open",
        )
        .expect("prepares");
    {
        let mut writer = world.runtime.store_writer();
        writer
            .begin_send(&["open-scope"], &context(), &manifest)
            .expect("the send begins");
    }
    world.reopen();
    let record = world
        .runtime
        .store()
        .settlement(&manifest.attempt_id)
        .expect("the open closes the row");
    assert_eq!(record.state, SettlementState::Settled);
    assert_eq!(record.exactness, Exactness::Unknown);
    assert_eq!(record.unknown_reason.as_deref(), Some("interrupted"));
    assert_eq!(record.charged_units, Some(manifest.cost_bound));
    assert_eq!(
        world
            .runtime
            .store()
            .budget_status("open-scope")
            .expect("scope")
            .spent,
        manifest.cost_bound
    );
    assert!(
        world
            .runtime
            .boot_diagnostics
            .iter()
            .any(|line| line.contains("settlement recovery")),
        "the boot line names the recovery: {:?}",
        world.runtime.boot_diagnostics
    );
    // The runtime's own open reconciliation lands in the incremental totals
    // once, and a second pass over the settled ledger changes nothing.
    let totals = world.runtime.store().settlement_totals().expect("totals");
    assert_eq!(
        totals,
        SettlementTotals {
            settled_count: 1,
            settled_without_total: 1,
            total_tokens: None,
            charged_units: Some(manifest.cost_bound),
            dispatched_count: 0,
            latest_prompt_tokens: None,
        },
        "the open's recovery lands in the incremental totals exactly once"
    );
    {
        let mut writer = world.runtime.store_writer();
        assert_eq!(
            writer.reconcile_sends().expect("a second pass is a no-op"),
            0
        );
    }
    assert_eq!(
        world.runtime.store().settlement_totals().expect("totals"),
        totals,
        "a second reconciliation pass changes no total"
    );
}

/// A store written before the additive settlement table opens and accepts
/// the first send: the recovery passes run after the generation commit, so
/// the DDL exists before the first read. The proof is the added table and
/// its dispatch row, not a reconciliation this fixture has no send for.
#[test]
fn base_schema_store_opens_and_takes_the_first_dispatch_row() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-upgrade-").expect("fixture root");
    let runtime_dir = root.path().join("runtime");
    std::fs::create_dir_all(&runtime_dir).expect("runtime dir");
    let db = runtime_dir.join("rivect.db");
    {
        // A current store, then the settlement table removed: exactly the
        // shape a base-schema store has.
        TaskStore::open(&db).expect("store opens");
        let conn = rusqlite::Connection::open(&db).expect("raw connection");
        conn.execute_batch(
            "DROP TRIGGER IF EXISTS usage_settlements_settled_immutable;
             DROP INDEX IF EXISTS idx_usage_settlements_state;
             DROP TABLE IF EXISTS usage_settlements;",
        )
        .expect("base schema restored");
    }
    let mut world = support::open_world_at(root.path(), Some(config_text()));
    let manifest = world
        .runtime
        .broker
        .prepare(
            "main",
            &world.runtime.config_for_broker(),
            WORLD,
            "goal: upgrade",
        )
        .expect("prepares after the upgrade");
    world
        .runtime
        .store_writer()
        .open_budget("upgrade-scope", 4)
        .expect("budget opens");
    {
        let mut writer = world.runtime.store_writer();
        writer
            .begin_send(&["upgrade-scope"], &context(), &manifest)
            .expect("the additive settlement table exists after the open");
    }
    assert_eq!(
        world
            .runtime
            .store()
            .settlement(&manifest.attempt_id)
            .expect("row")
            .state,
        SettlementState::Dispatched
    );
}

/// The status projection reads the settled totals after a refresh and the
/// same figure survives an owner reopen; occupancy is the latest settled
/// prompt count, and the project is the pinned root.
#[test]
fn status_projection_survives_reopen_and_names_its_sources() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-reopen-status-").expect("fixture");
    let mut world = support::open_world_at(root.path(), Some(config_text()));
    let session = world.open_session("bootstrap-economy-reopen-status");
    let manifest = settle_through_runtime(
        &mut world,
        "reopen-scope",
        UsageDelta::Exact {
            prompt_tokens: 9,
            completion_tokens: 3,
            total_tokens: 12,
        },
    );
    let pinned = root.path().join("project");
    std::fs::create_dir_all(&pinned).expect("the pinned project root exists");
    world.runtime.set_project_root(pinned.clone());
    let canonical = pinned.canonicalize().expect("canonical project root");
    world
        .runtime
        .refresh_economy(Some(&manifest))
        .expect("refreshes");
    let economy = &status(&mut world, &session)["economy"];
    assert_eq!(economy["settled_tokens"], json!(12));
    assert_eq!(economy["context_tokens"], json!(9), "latest prompt count");
    assert!(
        economy["context_source"]
            .as_str()
            .expect("source")
            .contains("prompt tokens"),
        "the occupancy source names the prompt count: {economy}"
    );
    assert_eq!(
        economy["project"].as_str(),
        Some(canonical.display().to_string().as_str()),
        "the project is the canonicalized pinned root, not the data root"
    );
    world.reopen();
    let after = &status(&mut world, &session)["economy"];
    assert_eq!(
        after["settled_tokens"],
        json!(12),
        "the reopen projects the settled total"
    );
}

/// Runs one decision step through the production controller: the answered
/// scheduler node dispatches through the broker's ledger seam, exactly as
/// the loop's step does.
fn drive_step(
    world: &mut support::World,
    session: &rivect::contracts::SessionId,
    task: &rivect::contracts::TaskId,
    grant: &str,
    answer: &str,
) -> Result<SchedulerStep, rivect::controller::ControllerError> {
    world
        .runtime
        .scheduler
        .submit_answered(
            task.clone(),
            AnswerSelection::Custom {
                text: answer.to_string(),
            },
            grant.to_string(),
        )
        .expect("scheduler accepts the node")
        .expect("task outside cancelled subtrees");
    world.runtime.scheduler_step(session)
}

#[test]
fn projection_fault_after_a_delivered_reply_does_not_drop_the_step() {
    let mut world = support::open_world_with(
        "economy-projection-fault",
        Some(config_text()),
        Box::new(UsageProvider::settled(UsageDelta::Exact {
            prompt_tokens: 6,
            completion_tokens: 4,
            total_tokens: 10,
        })),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-economy-fault-marker\n").expect("scoped file");
    world.runtime.purpose = "main".to_string();
    let grant = world.runtime.set_read_scope(scope, file.clone());
    let session = world.open_session("bootstrap-economy-fault");
    let task = world.create_task(&session, "cmd-economy-fault");
    world
        .runtime
        .store_writer()
        .open_budget(&task.0, 10)
        .expect("the task's budget scope opens");
    // A corrupt counter makes the post-send projection refresh fail; the
    // delivered reply must still reach the step after that fault.
    let db = world.runtime.owner().runtime_dir().join("rivect.db");
    let conn = rusqlite::Connection::open(&db).expect("raw connection");
    conn.execute(
        "UPDATE usage_totals SET settled_without_total = -1 WHERE id = 1",
        [],
    )
    .expect("the totals row is poisoned");
    drop(conn);
    let stepped = drive_step(
        &mut world,
        &session,
        &task,
        &grant,
        &format!("read {}", file.display()),
    );
    assert!(
        matches!(stepped, Ok(SchedulerStep::Ran { .. })),
        "the delivered reply still reaches the step: {stepped:?}"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .latest_settlement()
            .expect("the send settled")
            .state,
        SettlementState::Settled,
        "the send's own settlement is durable"
    );
    assert!(
        world
            .runtime
            .boot_diagnostics
            .iter()
            .any(|line| line.contains("economy projection refresh failed")),
        "the failed refresh is recorded with its cause: {:?}",
        world.runtime.boot_diagnostics
    );
}

/// The controller's own refresh, not a test-written row: a real step
/// settles through the broker, the status surface serves the refreshed
/// projection, and a reopen over the same root serves the open-time
/// projection from the store.
#[test]
fn status_economy_serves_a_real_step_and_the_open_time_projection() {
    let mut world = support::open_world_with(
        "economy-step",
        Some(config_text()),
        Box::new(UsageProvider::settled(UsageDelta::Exact {
            prompt_tokens: 6,
            completion_tokens: 4,
            total_tokens: 10,
        })),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-economy-step-marker\n").expect("scoped file");
    world.runtime.purpose = "main".to_string();
    let grant = world.runtime.set_read_scope(scope, file.clone());
    let session = world.open_session("bootstrap-economy-step");
    let task = world.create_task(&session, "cmd-economy-step");
    world
        .runtime
        .store_writer()
        .open_budget(&task.0, 10)
        .expect("the task's budget scope opens");
    let stepped = drive_step(
        &mut world,
        &session,
        &task,
        &grant,
        &format!("read {}", file.display()),
    );
    assert!(
        matches!(stepped, Ok(SchedulerStep::Ran { .. })),
        "the decision step runs: {stepped:?}"
    );
    let settled_row = world
        .runtime
        .store()
        .latest_settlement()
        .expect("the step's send settles one row");
    assert_eq!(settled_row.state, SettlementState::Settled);
    let economy = status(&mut world, &session)["economy"].clone();
    assert_eq!(
        economy["settled_tokens"],
        json!(10),
        "the step's settled total is served: {economy}"
    );
    assert_eq!(
        economy["charged_units"],
        json!(
            settled_row
                .charged_units
                .expect("the settled bound is charged")
        ),
        "the charged bound is the settled units"
    );
    assert_eq!(
        economy["cost_source"],
        json!("the bound is retained unless a reported total is lower"),
        "the served charge source leads with the retained bound: {economy}"
    );
    assert_eq!(economy["pending_sends"], json!(0));
    assert_eq!(economy["context_tokens"], json!(6));

    // The open-time projection is the store's own: a fresh runtime over the
    // same root serves the settled totals without any dispatch.
    let charged = settled_row
        .charged_units
        .expect("the settled bound is charged");
    world.reopen();
    let reopened = status(&mut world, &session)["economy"].clone();
    assert_eq!(
        reopened["settled_tokens"],
        json!(10),
        "the open-time projection reads the settled total: {reopened}"
    );
    assert_eq!(reopened["charged_units"], json!(charged));
    assert_eq!(reopened["pending_sends"], json!(0));
}

/// A pinned send lands, then the next dispatch enters and fails: the
/// served pairing still names the model with the connection that carried
/// it, and a refusal that never landed leaves the whole pairing untouched.
#[test]
fn economy_pairs_a_model_only_with_the_connection_that_carried_it() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-pair-").expect("fixture root");
    let mut world = support::open_world_at(root.path(), Some(pairing_config_text()));
    let session = world.open_session("bootstrap-economy-pair");
    let landed = settle_through_runtime(
        &mut world,
        "pair-scope",
        UsageDelta::Exact {
            prompt_tokens: 4,
            completion_tokens: 1,
            total_tokens: 5,
        },
    );
    world
        .runtime
        .refresh_economy(Some(&landed))
        .expect("the landing refreshes");
    let first = status(&mut world, &session)["economy"].clone();
    assert_eq!(first["model"], json!("fixture-model"));
    assert_eq!(first["connection"], json!(CONNECTION));

    // A dispatch that never landed must leave the whole pairing untouched.
    world
        .runtime
        .refresh_economy(None)
        .expect("the refusal refreshes totals");
    let refused = status(&mut world, &session)["economy"].clone();
    assert_same_pairing(&first, &refused, "the pinned refusal");

    // An entered failure is a landing for its own prepared attempt: the
    // attempt crossed the wire, so the served pair stays truthful.
    let entered = world
        .runtime
        .broker
        .prepare("main", &config(), WORLD, "goal: entered failure")
        .expect("the entered attempt prepares");
    {
        let mut writer = world.runtime.store_writer();
        let ticket = writer
            .begin_send(&["pair-scope"], &context(), &entered)
            .expect("the entered send begins");
        writer
            .finish_send(&ticket, &SendOutcome::Failed { wire_retries: 0 })
            .expect("the entered send settles unknown");
    }
    world
        .runtime
        .refresh_economy(Some(&entered))
        .expect("the entered failure refreshes");
    let after = status(&mut world, &session)["economy"].clone();
    assert_eq!(after["model"], json!("fixture-model"));
    assert_eq!(after["connection"], json!(CONNECTION));
}

/// A fallback substitute is a different attempt even when it reuses the
/// prepared connection: identity is the attempt id, so the prepared model is
/// never served as if it answered. A later reserve landing and a refusal keep
/// the same pairing discipline.
#[test]
fn economy_does_not_report_the_prepared_model_for_a_fallback_landing() {
    let root =
        tempfile::TempDir::with_prefix("rivect-economy-fallback-pair-").expect("fixture root");
    let mut world = support::open_world_at(root.path(), Some(pairing_config_text()));
    let session = world.open_session("bootstrap-economy-fallback-pair");
    world
        .runtime
        .store_writer()
        .open_budget("fallback-pair-scope", 10)
        .expect("the scope opens");
    let prepared = world
        .runtime
        .broker
        .prepare("main", &config(), WORLD, "goal: pinned primary")
        .expect("the primary prepares");
    // Same connection, another model, another attempt: still not the prepared
    // selection.
    let mut same_connection = prepared.clone();
    same_connection.attempt_id = "same-connection-substitute".to_string();
    same_connection.model = ModelAssign::Fixed(FixedModel {
        connection: CONNECTION.to_string(),
        model_id: "same-connection-model".to_string(),
    });
    let same_context = SendContext {
        purpose: "main".to_string(),
        connection: CONNECTION.to_string(),
        parent_attempt_id: Some(prepared.attempt_id.clone()),
        ranking_basis: None,
    };
    {
        let mut writer = world.runtime.store_writer();
        let ticket = writer
            .begin_send(&["fallback-pair-scope"], &same_context, &same_connection)
            .expect("the same-connection substitute begins");
        writer
            .finish_send(
                &ticket,
                &SendOutcome::Settled {
                    usage: UsageDelta::Unknown,
                    wire_retries: 0,
                },
            )
            .expect("the same-connection substitute settles");
    }
    world
        .runtime
        .refresh_economy(Some(&prepared))
        .expect("the same-connection landing refreshes");
    let same = status(&mut world, &session)["economy"].clone();
    assert!(
        same["model"].is_null(),
        "the same connection does not make it the prepared model: {same}"
    );
    assert_eq!(same["connection"], json!(CONNECTION));
    assert!(
        same["source"]
            .as_str()
            .expect("the projection names its source")
            .contains("fallback answered via local"),
        "the source names the answering connection: {same}"
    );
    let mut substitute = prepared.clone();
    substitute.attempt_id = "fallback-substitute-attempt".to_string();
    substitute.model = ModelAssign::Fixed(FixedModel {
        connection: "reserve".to_string(),
        model_id: "fallback-model".to_string(),
    });
    let substitute_context = SendContext {
        purpose: "main".to_string(),
        connection: "reserve".to_string(),
        parent_attempt_id: Some(prepared.attempt_id.clone()),
        ranking_basis: None,
    };
    {
        let mut writer = world.runtime.store_writer();
        let ticket = writer
            .begin_send(&["fallback-pair-scope"], &substitute_context, &substitute)
            .expect("the substitute begins");
        writer
            .finish_send(
                &ticket,
                &SendOutcome::Settled {
                    usage: UsageDelta::Unknown,
                    wire_retries: 0,
                },
            )
            .expect("the substitute settles");
    }
    world
        .runtime
        .refresh_economy(Some(&prepared))
        .expect("the fallback landing refreshes");
    let economy = status(&mut world, &session)["economy"].clone();
    assert!(
        economy["model"].is_null(),
        "a chain entry is not the prepared model: {economy}"
    );
    assert_eq!(economy["connection"], json!("reserve"));
    assert!(
        economy["source"]
            .as_str()
            .expect("the projection names its source")
            .contains("fallback answered via reserve"),
        "the source names the answering connection: {economy}"
    );

    // A budget refusal after the fallback landing changes nothing.
    world
        .runtime
        .refresh_economy(None)
        .expect("the refusal refreshes totals");
    let after = status(&mut world, &session)["economy"].clone();
    assert_same_pairing(&economy, &after, "the fallback refusal");

    // An entered failure prepared on the other connection is its own landing:
    // the pair moves to that connection and its model.
    let mut entered = prepared.clone();
    entered.attempt_id = "entered-reserve-attempt".to_string();
    entered.model = ModelAssign::Fixed(FixedModel {
        connection: "reserve".to_string(),
        model_id: "reserve-model".to_string(),
    });
    let entered_context = SendContext {
        purpose: "main".to_string(),
        connection: "reserve".to_string(),
        parent_attempt_id: None,
        ranking_basis: None,
    };
    {
        let mut writer = world.runtime.store_writer();
        let ticket = writer
            .begin_send(&["fallback-pair-scope"], &entered_context, &entered)
            .expect("the entered send begins");
        writer
            .finish_send(&ticket, &SendOutcome::Failed { wire_retries: 0 })
            .expect("the entered send settles unknown");
    }
    world
        .runtime
        .refresh_economy(Some(&entered))
        .expect("the entered failure refreshes");
    let moved = status(&mut world, &session)["economy"].clone();
    assert_eq!(moved["model"], json!("reserve-model"));
    assert_eq!(moved["connection"], json!("reserve"));
    assert_eq!(moved["source"], json!("fixed pin"));
}

/// Every provider send fails: the fallback row beside the prepared attempt
/// carries no answer, so the served source must not claim one.
struct FailingProvider;

impl Provider for FailingProvider {
    fn name(&self) -> &'static str {
        "failing-fixture"
    }

    fn serves(&self, _connection: &str, entry: &Connection) -> bool {
        entry.kind == ConnKind::Local
    }

    fn send(&mut self, _manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        Err(ProviderError::UnsupportedParameter {
            connection: CONNECTION.to_string(),
            parameter: "fixture-parameter",
            model: "fixture-model".to_string(),
        })
    }
}

#[test]
fn economy_reports_no_fallback_answered_when_every_chain_entry_fails() {
    let mut world = support::open_world_with(
        "economy-all-fail",
        Some(all_fail_config_text()),
        Box::new(FailingProvider),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-economy-all-fail-marker\n").expect("scoped file");
    world.runtime.purpose = "main".to_string();
    let grant = world.runtime.set_read_scope(scope, file.clone());
    let session = world.open_session("bootstrap-economy-all-fail");
    let task = world.create_task(&session, "cmd-economy-all-fail");
    world
        .runtime
        .store_writer()
        .open_budget(&task.0, 10)
        .expect("the task's budget scope opens");
    let sent = drive_step(
        &mut world,
        &session,
        &task,
        &grant,
        &format!("read {}", file.display()),
    );
    assert!(
        sent.is_err(),
        "every chain entry fails, so the step errors: {sent:?}"
    );
    let economy = status(&mut world, &session)["economy"].clone();
    let totals = world
        .runtime
        .store()
        .settlement_totals()
        .expect("settlement totals");
    assert!(
        economy["model"].is_null(),
        "no prepared model is named after a failed chain: {economy}"
    );
    assert_eq!(economy["connection"], json!("reserve"), "totals {totals:?}");
    assert!(
        economy["source"]
            .as_str()
            .expect("the projection names its source")
            .contains("fallback attempted via reserve; no fallback answered"),
        "a failed substitute is not reported as an answer: {economy}"
    );
}

/// The mixed path: the primary enters and fails, then the fallback leg is
/// refused by budget. The served economy names the primary that landed and
/// never the fallback that did not.
#[test]
fn mixed_budget_path_names_the_landed_primary_not_the_refused_fallback() {
    let mut world = support::open_world_with(
        "economy-mixed",
        Some(mixed_config_text()),
        Box::new(FailingProvider),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-economy-mixed-marker\n").expect("scoped file");
    world.runtime.purpose = "main".to_string();
    let grant = world.runtime.set_read_scope(scope.clone(), file.clone());
    let session = world.open_session("bootstrap-economy-mixed");
    let task = world.create_task(&session, "cmd-economy-mixed");
    let answer = format!("read {}", file.display());
    // The controller's own inputs shape gives the frozen bound this scope can
    // fit exactly once.
    let goal = world.runtime.store().goal_bytes(&task).expect("goal bytes");
    let inputs = format!(
        "goal: {}\nanswer: {}\nread {}",
        String::from_utf8_lossy(&goal),
        answer,
        file.display()
    );
    let origin = world
        .runtime
        .store()
        .answer_input_origin(&task)
        .expect("answer origin");
    let config = Config::parse_validated(mixed_config_text()).expect("config validates");
    let mut dry = Broker::new(Box::new(FailingProvider));
    let prepared = dry
        .prepare_authored(
            "main",
            &config,
            &scope.display().to_string(),
            &inputs,
            origin,
        )
        .expect("the dry attempt prepares");
    world
        .runtime
        .store_writer()
        .open_budget(&task.0, prepared.cost_bound)
        .expect("the scope fits exactly one bound");
    let stepped = drive_step(&mut world, &session, &task, &grant, &answer);
    assert!(
        matches!(
            stepped,
            Ok(SchedulerStep::Ran { ref outcome, .. })
                if matches!(**outcome, StepOutcome::Waiting { .. })
        ),
        "the entered primary fails and the fallback waits on budget: {stepped:?}"
    );
    let economy = status(&mut world, &session)["economy"].clone();
    assert_eq!(economy["model"], json!("fixture-model"));
    assert_eq!(economy["connection"], json!(CONNECTION));
    assert_eq!(economy["source"], json!("fixed pin"));
}

/// An open substitute under the prepared attempt is not an answer: the served
/// source says the attempt is unresolved, names its connection, and the cached
/// pending count reports the one open row.
#[test]
fn unresolved_substitute_is_not_reported_as_an_answer() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-unresolved-").expect("fixture root");
    let mut world = support::open_world_at(root.path(), Some(pairing_config_text()));
    let session = world.open_session("bootstrap-economy-unresolved");
    world
        .runtime
        .store_writer()
        .open_budget("unresolved-scope", 10)
        .expect("the scope opens");
    let prepared = world
        .runtime
        .broker
        .prepare("main", &config(), WORLD, "goal: pinned primary")
        .expect("the primary prepares");
    let mut substitute = prepared.clone();
    substitute.attempt_id = "unresolved-substitute".to_string();
    substitute.model = ModelAssign::Fixed(FixedModel {
        connection: "reserve".to_string(),
        model_id: "reserve-model".to_string(),
    });
    let substitute_context = SendContext {
        purpose: "main".to_string(),
        connection: "reserve".to_string(),
        parent_attempt_id: Some(prepared.attempt_id.clone()),
        ranking_basis: None,
    };
    {
        let mut writer = world.runtime.store_writer();
        writer
            .begin_send(&["unresolved-scope"], &substitute_context, &substitute)
            .expect("the substitute stays open");
    }
    world
        .runtime
        .refresh_economy(Some(&prepared))
        .expect("the unresolved landing refreshes");
    let economy = status(&mut world, &session)["economy"].clone();
    assert!(
        economy["model"].is_null(),
        "an open substitute never names a prepared model: {economy}"
    );
    assert_eq!(economy["connection"], json!("reserve"));
    let source = economy["source"]
        .as_str()
        .expect("the projection names its source");
    assert!(
        source.contains("fallback attempt via reserve is unresolved"),
        "the source names the unresolved attempt: {economy}"
    );
    assert!(
        !source.contains("answered via"),
        "an open row is never reported as answered: {economy}"
    );
    assert_eq!(economy["pending_sends"], json!(1));
}

// ----- provider cache evidence (AC-058 contribution) -----

/// The frozen cohort a fixture measures: the attempts a candidate freeze
/// recorded, with the provenance the evidence names.
fn cache_cohort(attempt_ids: Vec<String>, include_cold: bool) -> CacheCohort {
    CacheCohort {
        candidate: "fixture-candidate".to_string(),
        models: vec!["fixture-model".to_string()],
        attempt_ids,
        include_cold,
        frozen_on: "2026-11-04".to_string(),
    }
}

fn economy_status(world: &mut support::World, session: &rivect::contracts::SessionId) -> Value {
    status(world, session)["economy"].clone()
}

/// Asserts the served projection carries the expected pair and a named
/// source fragment, so a test never re-implements the status extraction.
fn assert_served_cache(
    world: &mut support::World,
    session: &rivect::contracts::SessionId,
    rate: Value,
    fragment: &str,
) {
    let economy = economy_status(world, session);
    assert_eq!(economy["cache_rate"], rate);
    let source = economy["cache_source"]
        .as_str()
        .expect("the row names its source");
    assert!(
        source.contains(fragment),
        "expected `{fragment}` in: {source}"
    );
}

/// The exact evidence a measured cohort must produce: the frozen cohort
/// travels with the rate, so a wrong population cannot compare equal.
fn measured(
    cohort: &CacheCohort,
    cache_read_tokens: u64,
    input_tokens: u64,
    (measured, censored, cold_excluded): (u64, u64, u64),
) -> CacheRate {
    CacheRate::Measured {
        cohort: cohort.clone(),
        counts: CacheCohortCounts {
            measured,
            censored,
            cold_excluded,
        },
        cache_read_tokens,
        input_tokens,
    }
}

/// A settled provider cache-read leg is the only hit the rate counts: two
/// requests over identical inputs share one local prefix digest and epoch,
/// yet the row that reported no cache leg stays censored, so a local hash
/// never becomes a provider hit.
#[test]
fn cache_read_rate_uses_settled_bins_and_never_a_local_hash() {
    let mut world = support::open_world("economy-cache-bins", Some(config_text()));
    let session = world.open_session("bootstrap-economy-cache-bins");
    let reported = settle_through_runtime(
        &mut world,
        "cache-bins-warm",
        UsageDelta::Legs {
            prompt_tokens: Some(100),
            completion_tokens: Some(10),
            reasoning_tokens: None,
            cache_read_tokens: Some(300),
            cache_write_tokens: Some(0),
            total_tokens: Some(410),
        },
    );
    let unreported = settle_through_runtime(
        &mut world,
        "cache-bins-local",
        UsageDelta::Exact {
            prompt_tokens: 40,
            completion_tokens: 10,
            total_tokens: 50,
        },
    );
    // The replay is a local fact: the same prefix digest and epoch, and no
    // provider cache figure either way.
    assert_eq!(reported.inputs_digest, unreported.inputs_digest);
    assert_eq!(reported.epoch_id, unreported.epoch_id);

    let frozen = cache_cohort(
        vec![reported.attempt_id.clone(), unreported.attempt_id.clone()],
        false,
    );
    world
        .runtime
        .freeze_cache_cohort(frozen.clone())
        .expect("the freeze measures the cohort");
    let evidence = world
        .runtime
        .store()
        .cache_read_rate(&frozen)
        .expect("the cohort reads");
    assert_eq!(
        evidence,
        measured(&frozen, 300, 400, (1, 1, 0)),
        "only the settled reported leg is summed"
    );
    let economy = economy_status(&mut world, &session);
    assert_eq!(
        economy["cache_rate"],
        json!([300, 400]),
        "the status serves the settled numerator and denominator"
    );
    let source = economy["cache_source"]
        .as_str()
        .expect("the row names its source");
    assert!(source.contains("300 cache-read"), "{source}");
    assert!(source.contains("400 all-input"), "{source}");
    assert!(source.contains("censored 1"), "{source}");
}

/// The denominator is all input — prompt + cache read + cache write — never
/// the provider's own total, which can exclude the cache legs.
#[test]
fn cache_rate_exact_numerator_and_denominator_from_fixtures() {
    let mut world = support::open_world("economy-cache-exact", Some(config_text()));
    let session = world.open_session("bootstrap-economy-cache-exact");
    let first = settle_through_runtime(
        &mut world,
        "cache-exact-a",
        UsageDelta::Legs {
            prompt_tokens: Some(100),
            completion_tokens: Some(10),
            reasoning_tokens: None,
            cache_read_tokens: Some(300),
            cache_write_tokens: Some(100),
            total_tokens: Some(510),
        },
    );
    let second = settle_through_runtime(
        &mut world,
        "cache-exact-b",
        UsageDelta::Legs {
            prompt_tokens: Some(80),
            completion_tokens: Some(20),
            reasoning_tokens: Some(30),
            cache_read_tokens: Some(120),
            cache_write_tokens: Some(0),
            total_tokens: Some(200),
        },
    );
    let frozen = cache_cohort(
        vec![first.attempt_id.clone(), second.attempt_id.clone()],
        false,
    );
    world
        .runtime
        .freeze_cache_cohort(frozen.clone())
        .expect("the freeze measures the cohort");
    let economy = economy_status(&mut world, &session);
    assert_eq!(
        economy["cache_rate"],
        json!([420, 700]),
        "sum(cache read) / sum(prompt + cache read + cache write)"
    );
    // The provider totals sum to 710; they exclude (or count differently)
    // the cache legs and are never the denominator.
    let evidence = world
        .runtime
        .store()
        .cache_read_rate(&frozen)
        .expect("the cohort reads");
    assert_eq!(evidence, measured(&frozen, 420, 700, (2, 0, 0)));
    let source = economy["cache_source"]
        .as_str()
        .expect("the row names its source");
    assert!(source.contains("420 cache-read"), "{source}");
    assert!(source.contains("700 all-input"), "{source}");
    // The observable provenance names the candidate and model set the rate
    // was frozen over, not just the fixture's own helper fields.
    assert!(source.contains("fixture-candidate"), "{source}");
    assert!(source.contains("fixture-model"), "{source}");
    assert!(source.contains("2026-11-04"), "{source}");
    assert!(
        source.contains("prompt + cache read + cache write"),
        "the row defines all input: {source}"
    );

    // A reported zero prompt is exact input when the cache read is
    // positive: the ratio exists and is measured, never unknown.
    let zero_prompt = settle_through_runtime(
        &mut world,
        "cache-exact-zero-prompt",
        UsageDelta::Legs {
            prompt_tokens: Some(0),
            completion_tokens: Some(5),
            reasoning_tokens: None,
            cache_read_tokens: Some(40),
            cache_write_tokens: Some(0),
            total_tokens: Some(45),
        },
    );
    let zero_cohort = cache_cohort(vec![zero_prompt.attempt_id.clone()], false);
    world
        .runtime
        .freeze_cache_cohort(zero_cohort.clone())
        .expect("the zero-prompt cohort measures");
    assert_eq!(
        economy_status(&mut world, &session)["cache_rate"],
        json!([40, 40]),
        "a zero prompt is exact input, not an unknown rate"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .cache_read_rate(&zero_cohort)
            .expect("the zero-prompt cohort reads"),
        measured(&zero_cohort, 40, 40, (1, 0, 0))
    );
}

/// No frozen cohort is `NOT_RUN`; a cohort the store cannot fully record is
/// unknown. Neither ever becomes PASS or a number over a shrunken
/// population.
#[test]
fn cache_rate_unavailable_cohort_is_not_run() {
    let mut world = support::open_world("economy-cache-missing", Some(config_text()));
    let session = world.open_session("bootstrap-economy-cache-missing");
    let absent = economy_status(&mut world, &session);
    assert_eq!(absent["cache_rate"], Value::Null);
    let source = absent["cache_source"]
        .as_str()
        .expect("the row names its source");
    assert!(
        source.contains("NOT_RUN"),
        "the missing cohort is named: {source}"
    );
    assert!(
        !source.contains("PASS"),
        "an absent cohort is not PASS: {source}"
    );

    // A cohort that names a settled attempt and one this store never
    // recorded is refused at freeze: the measured row is not served as if
    // the frozen population were complete, and the status stays NOT_RUN.
    let settled = settle_through_runtime(
        &mut world,
        "cache-missing-settled",
        UsageDelta::Legs {
            prompt_tokens: Some(10),
            completion_tokens: Some(1),
            reasoning_tokens: None,
            cache_read_tokens: Some(5),
            cache_write_tokens: Some(0),
            total_tokens: Some(16),
        },
    );
    let frozen = cache_cohort(
        vec![
            settled.attempt_id.clone(),
            "attempt-never-recorded".to_string(),
        ],
        true,
    );
    let refused = world
        .runtime
        .freeze_cache_cohort(frozen.clone())
        .expect_err("an unrecorded attempt is not a frozen population");
    assert!(
        matches!(
            refused,
            StoreError::InvalidInput(InvalidCause::CacheCohortMissing { attempts: 1 })
        ),
        "the missing attempt is named: {refused:?}"
    );
    let economy = economy_status(&mut world, &session);
    assert_eq!(economy["cache_rate"], Value::Null);
    let source = economy["cache_source"]
        .as_str()
        .expect("the row names its source");
    assert!(
        source.contains("NOT_RUN"),
        "a refused freeze keeps the absent cohort: {source}"
    );
    assert!(
        !source.contains("PASS"),
        "an unavailable cohort is not PASS: {source}"
    );
    assert!(matches!(
        world
            .runtime
            .store()
            .cache_read_rate(&frozen)
            .expect_err("the incomplete cohort refuses"),
        StoreError::InvalidInput(InvalidCause::CacheCohortMissing { attempts: 1 })
    ));

    // Exact zero legs are still a fact, but a measured cohort with no input
    // tokens has no ratio: the status serves unknown, never 0/0.
    let zero = settle_through_runtime(
        &mut world,
        "cache-missing-zero",
        UsageDelta::Legs {
            prompt_tokens: Some(0),
            completion_tokens: Some(0),
            reasoning_tokens: None,
            cache_read_tokens: Some(0),
            cache_write_tokens: Some(0),
            total_tokens: Some(0),
        },
    );
    let zeros = cache_cohort(vec![zero.attempt_id.clone()], true);
    world
        .runtime
        .freeze_cache_cohort(zeros.clone())
        .expect("the zero cohort refreshes as unknown");
    let economy = economy_status(&mut world, &session);
    assert_eq!(economy["cache_rate"], Value::Null);
    let source = economy["cache_source"]
        .as_str()
        .expect("the row names its source");
    assert!(source.contains("no input tokens"), "{source}");
    let evidence = world
        .runtime
        .store()
        .cache_read_rate(&zeros)
        .expect("the zero cohort reads");
    assert!(
        matches!(
            evidence,
            CacheRate::Unknown {
                counts: CacheCohortCounts {
                    measured: 1,
                    censored: 0,
                    cold_excluded: 0,
                },
                ..
            }
        ),
        "the exact zero row is measured, and the ratio is still unknown: {evidence:?}"
    );
}

/// A cohort holding an attempt still in flight is refused at freeze: the
/// population must be a settled set, and a refused freeze leaves the prior
/// rate and its served evidence untouched. The same holds for an empty
/// cohort, and a later refresh keeps serving the prior rate.
#[test]
fn freeze_refuses_an_unsettled_cohort_and_keeps_the_prior_evidence() {
    let mut world = support::open_world("economy-cache-unsettled", Some(config_text()));
    let session = world.open_session("bootstrap-economy-cache-unsettled");
    let settled = settle_through_runtime(
        &mut world,
        "cache-unsettled-settled",
        UsageDelta::Legs {
            prompt_tokens: Some(20),
            completion_tokens: Some(2),
            reasoning_tokens: None,
            cache_read_tokens: Some(10),
            cache_write_tokens: Some(0),
            total_tokens: Some(32),
        },
    );
    world
        .runtime
        .freeze_cache_cohort(cache_cohort(vec![settled.attempt_id.clone()], true))
        .expect("the settled cohort freezes");
    let before = economy_status(&mut world, &session);
    assert_eq!(before["cache_rate"], json!([10, 30]));

    // A started send stays `dispatched` until it settles: it is not a
    // member a frozen rate may sum or classify as censored.
    world
        .runtime
        .store_writer()
        .open_budget("cache-unsettled-scope", 10)
        .expect("the budget scope opens");
    let pending = world
        .runtime
        .broker
        .prepare(
            "main",
            &world.runtime.config_for_broker(),
            WORLD,
            "goal: cache unsettled",
        )
        .expect("the pending attempt prepares");
    {
        let mut writer = world.runtime.store_writer();
        writer
            .begin_send(&["cache-unsettled-scope"], &context(), &pending)
            .expect("the send begins");
    }
    let refused = world
        .runtime
        .freeze_cache_cohort(cache_cohort(
            vec![settled.attempt_id.clone(), pending.attempt_id.clone()],
            true,
        ))
        .expect_err("an unsettled attempt refuses the freeze");
    assert!(
        matches!(
            refused,
            StoreError::InvalidInput(InvalidCause::CacheCohortUnsettled { attempts: 1 })
        ),
        "the unsettled attempt is named: {refused:?}"
    );
    assert_eq!(
        economy_status(&mut world, &session),
        before,
        "a refused freeze serves the previous cohort and snapshot"
    );

    // The stored rate is what a later refresh reads: the poisoned cohort
    // never reached the runtime, so the cached projection cannot show it.
    world
        .runtime
        .refresh_economy(None)
        .expect("a refused freeze leaves a refresh that still succeeds");
    assert_served_cache(&mut world, &session, json!([10, 30]), "fixture-candidate");
    assert_eq!(
        economy_status(&mut world, &session)["cache_source"],
        before["cache_source"],
        "the prior source survives a refresh"
    );

    // An empty cohort is refused before anything is committed.
    let empty = world
        .runtime
        .freeze_cache_cohort(cache_cohort(Vec::new(), true))
        .expect_err("an empty cohort is not a frozen population");
    assert!(
        matches!(
            empty,
            StoreError::InvalidInput(InvalidCause::CacheCohortEmpty)
        ),
        "the empty cohort is named: {empty:?}"
    );
    assert_served_cache(&mut world, &session, json!([10, 30]), "fixture-candidate");
    assert_eq!(
        economy_status(&mut world, &session)["cache_source"],
        before["cache_source"],
        "an empty refusal changes neither rate nor source"
    );
}

/// A cold-inclusive cohort adds the rows that reported an exact zero cache
/// read to the denominator beside the warm rows, and counts the rows whose
/// legs are censored instead of summing them as zero.
#[test]
fn cold_inclusive_cohort_includes_censored_rows() {
    let mut world = support::open_world("economy-cache-cold", Some(config_text()));
    let session = world.open_session("bootstrap-economy-cache-cold");
    let warm = settle_through_runtime(
        &mut world,
        "cache-cold-warm",
        UsageDelta::Legs {
            prompt_tokens: Some(100),
            completion_tokens: Some(10),
            reasoning_tokens: None,
            cache_read_tokens: Some(200),
            cache_write_tokens: Some(0),
            total_tokens: Some(310),
        },
    );
    let cold = settle_through_runtime(
        &mut world,
        "cache-cold-zero",
        UsageDelta::Legs {
            prompt_tokens: Some(50),
            completion_tokens: Some(5),
            reasoning_tokens: None,
            cache_read_tokens: Some(0),
            cache_write_tokens: Some(0),
            total_tokens: Some(55),
        },
    );
    let censored = settle_through_runtime(&mut world, "cache-cold-censored", UsageDelta::Unknown);
    let ids = vec![
        warm.attempt_id.clone(),
        cold.attempt_id.clone(),
        censored.attempt_id.clone(),
    ];
    let inclusive = cache_cohort(ids.clone(), true);
    world
        .runtime
        .freeze_cache_cohort(inclusive.clone())
        .expect("the cold-inclusive cohort measures");
    assert_eq!(
        world
            .runtime
            .store()
            .cache_read_rate(&inclusive)
            .expect("the cohort reads"),
        measured(&inclusive, 200, 350, (2, 1, 0)),
        "the exact zero row joins the denominator; the unknown row is counted, not zero"
    );
    assert_served_cache(
        &mut world,
        &session,
        json!([200, 350]),
        "measured 2, censored 1, cold included",
    );

    // Warm-only keeps the reported zero row out of the warm population; the
    // censored row is still counted, and the excluded cold count reconciles
    // measured + censored + excluded to the three frozen attempts.
    let warm_only = cache_cohort(ids, false);
    world
        .runtime
        .freeze_cache_cohort(warm_only.clone())
        .expect("the warm cohort measures");
    assert_eq!(
        world
            .runtime
            .store()
            .cache_read_rate(&warm_only)
            .expect("the warm cohort reads"),
        measured(&warm_only, 200, 300, (1, 1, 1))
    );
    assert_served_cache(
        &mut world,
        &session,
        json!([200, 300]),
        "measured 1, censored 1, cold excluded 1",
    );
}

/// Folded reasoning is its own bin: it never enters the cache numerator or
/// the input denominator.
#[test]
fn cache_rate_ignores_folded_reasoning() {
    let mut world = support::open_world("economy-cache-reasoning", Some(config_text()));
    let session = world.open_session("bootstrap-economy-cache-reasoning");
    let folded = settle_through_runtime(
        &mut world,
        "cache-reasoning-folded",
        UsageDelta::Legs {
            prompt_tokens: Some(100),
            completion_tokens: Some(10),
            reasoning_tokens: Some(900),
            cache_read_tokens: Some(50),
            cache_write_tokens: Some(0),
            total_tokens: Some(960),
        },
    );
    let cold = settle_through_runtime(
        &mut world,
        "cache-reasoning-cold",
        UsageDelta::Legs {
            prompt_tokens: Some(60),
            completion_tokens: Some(5),
            reasoning_tokens: Some(400),
            cache_read_tokens: Some(0),
            cache_write_tokens: Some(0),
            total_tokens: Some(65),
        },
    );
    assert_eq!(
        world
            .runtime
            .store()
            .settlement(&folded.attempt_id)
            .expect("the folded row settles")
            .bins
            .reasoning_tokens,
        Some(900),
        "the fixture carries the folded reasoning bin"
    );
    let frozen = cache_cohort(
        vec![folded.attempt_id.clone(), cold.attempt_id.clone()],
        true,
    );
    world
        .runtime
        .freeze_cache_cohort(frozen.clone())
        .expect("the cohort measures");
    assert_eq!(
        world
            .runtime
            .store()
            .cache_read_rate(&frozen)
            .expect("the cohort reads"),
        measured(&frozen, 50, 210, (2, 0, 0)),
        "reasoning tokens are neither cache reads nor input"
    );
    let economy = economy_status(&mut world, &session);
    assert_eq!(economy["cache_rate"], json!([50, 210]));
}

/// A cohort past one batch is read in named batches: 900 is a conservative
/// batch under SQLite's 32766-variable ceiling, the 901st attempt is still
/// summed, and the source names the bound.
#[test]
fn cohort_above_the_statement_batch_sums_every_batch() {
    const ROWS: u64 = 901;
    let mut world = support::open_world("economy-cache-batch", Some(config_text()));
    let session = world.open_session("bootstrap-economy-cache-batch");
    let base = world
        .runtime
        .broker
        .prepare(
            "main",
            &world.runtime.config_for_broker(),
            WORLD,
            "goal: cache batch",
        )
        .expect("the batch request prepares");
    let usage = UsageDelta::Legs {
        prompt_tokens: Some(1),
        completion_tokens: Some(0),
        reasoning_tokens: None,
        cache_read_tokens: Some(1),
        cache_write_tokens: Some(0),
        total_tokens: Some(2),
    };
    let mut ids = Vec::with_capacity(usize::try_from(ROWS).expect("fits"));
    {
        let mut writer = world.runtime.store_writer();
        for index in 0..ROWS {
            let mut manifest = base.clone();
            manifest.attempt_id = format!("cache-batch-{index}");
            let ticket = writer
                .begin_send(&[], &context(), &manifest)
                .expect("an unreserved row opens");
            writer
                .finish_send(
                    &ticket,
                    &SendOutcome::Settled {
                        usage,
                        wire_retries: 0,
                    },
                )
                .expect("the row settles");
            ids.push(manifest.attempt_id.clone());
        }
    }
    let frozen = cache_cohort(ids, false);
    world
        .runtime
        .freeze_cache_cohort(frozen.clone())
        .expect("the batch cohort freezes");
    assert_eq!(
        world
            .runtime
            .store()
            .cache_read_rate(&frozen)
            .expect("the batch cohort reads"),
        measured(&frozen, ROWS, ROWS * 2, (ROWS, 0, 0)),
        "every batch is summed"
    );
    assert_served_cache(
        &mut world,
        &session,
        json!([901, 1802]),
        "cohort batches of 900",
    );
}

// ----- AC-052/AC-096: repair attribution and recorded-fact ranking -----

/// Non-secret version evidence for one recorded attempt.
fn feedback_evidence() -> VersionEvidence {
    VersionEvidence {
        build: "rivect 0.1.0".to_string(),
        policy_generation: None,
        base_version: Some(2),
        model: Some("fixture-model".to_string()),
        connection: Some(CONNECTION.to_string()),
    }
}

/// One observed, failed attempt row.
fn feedback_row(attempt_id: &str) -> FeedbackRecord {
    FeedbackRecord {
        attempt_id: attempt_id.to_string(),
        parent_attempt_id: None,
        purpose: "main".to_string(),
        connection: CONNECTION.to_string(),
        model_id: Some("fixture-model".to_string()),
        outcome: FeedbackOutcome::Fail,
        cause: FeedbackCause::None,
        version_evidence: feedback_evidence(),
        repair_of: None,
        verdict: FeedbackVerdict::Fail,
        reward: FeedbackReward::None,
        observed: true,
    }
}

/// The row a late repair appends: its own PASS, its own cost attribution and
/// the attempt it repaired.
fn repair_row(attempt_id: &str, repaired: &str) -> FeedbackRecord {
    FeedbackRecord {
        attempt_id: attempt_id.to_string(),
        outcome: FeedbackOutcome::Pass,
        cause: FeedbackCause::Repair,
        repair_of: Some(repaired.to_string()),
        verdict: FeedbackVerdict::Pass,
        reward: FeedbackReward::Repair,
        ..feedback_row(attempt_id)
    }
}

#[test]
fn feedback_attributes_a_late_repair_to_the_repair() {
    let root = tempfile::TempDir::with_prefix("rivect-economy-repair-").expect("fixture root");
    let mut store = TaskStore::open(&root.path().join("state.db")).expect("store opens");
    store.open_budget(SCOPE_A, 10).expect("budget opens");
    let mut broker = Broker::new(Box::new(UsageProvider::settled(UsageDelta::Exact {
        prompt_tokens: 3,
        completion_tokens: 1,
        total_tokens: 4,
    })));

    // The cheap attempt: one physical send, one settled row, one charge.
    let cheap = prepared(&mut broker);
    let cheap_charge = {
        let mut ledger = StoreLedger::new(&mut store, vec![SCOPE_A.to_string()]);
        broker
            .dispatch(&mut ledger, WORLD, &cheap)
            .expect("the cheap send settles");
        store
            .settlement(&cheap.attempt_id)
            .expect("the cheap row exists")
            .charged_units
            .expect("the cheap bound is charged")
    };

    // The late repair is a second physical attempt whose larger request pays
    // its own bound — the cost is attributed to the repair's own row.
    let repair = broker
        .prepare(
            "main",
            &config(),
            WORLD,
            &format!("goal: repair {}", "x".repeat(4096)),
        )
        .expect("the repair request prepares");
    let repair_charge = {
        let mut ledger = StoreLedger::new(&mut store, vec![SCOPE_A.to_string()]);
        broker
            .dispatch(&mut ledger, WORLD, &repair)
            .expect("the repair send settles");
        store
            .settlement(&repair.attempt_id)
            .expect("the repair row exists")
            .charged_units
            .expect("the repair bound is charged")
    };
    assert_ne!(
        cheap_charge, repair_charge,
        "each attempt pays its own frozen bound"
    );

    let cheap_row = store
        .record_feedback(&feedback_row(&cheap.attempt_id))
        .expect("the cheap result records");
    let repair = store
        .record_feedback(&repair_row(&repair.attempt_id, &cheap.attempt_id))
        .expect("the repair records");

    // The repair attributes itself to the repaired attempt and to its own
    // cost; the cheap result keeps its verdict and carries no repair cost.
    assert_eq!(repair.reward, FeedbackReward::Repair);
    assert_eq!(repair.repair_of.as_deref(), Some(cheap.attempt_id.as_str()));
    assert_eq!(repair.verdict, FeedbackVerdict::Pass);
    assert_eq!(
        store
            .settlement(&repair.attempt_id)
            .expect("the repair row re-reads")
            .charged_units,
        Some(repair_charge)
    );
    let cheap_after = store
        .feedback(&cheap.attempt_id)
        .expect("the cheap row re-reads");
    assert_eq!(cheap_after, cheap_row, "the cheap row is unchanged");
    assert_eq!(cheap_after.verdict, FeedbackVerdict::Fail);
    assert_eq!(cheap_after.reward, FeedbackReward::None);
    assert_eq!(cheap_after.repair_of, None);
    assert_eq!(
        store
            .settlement(&cheap.attempt_id)
            .expect("the cheap row re-reads")
            .charged_units,
        Some(cheap_charge),
        "the repair's cost never moves onto the repaired attempt"
    );
    let repairs = store
        .feedback_repairs(&cheap.attempt_id)
        .expect("the attribution reads");
    assert_eq!(repairs.len(), 1);
    assert_eq!(repairs[0].attempt_id, repair.attempt_id);
}

/// The ranking world: `yolo-auto` records one seed row with a low/high effort
/// ladder, `local` records nothing, and the `main` purpose runs `auto` — so
/// the controller's own facts decide both the model and the level.
fn recorded_config_text() -> &'static str {
    "config_version = 1\n\
     [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
     [connections.yolo-auto]\nkind = \"local\"\nendpoint = \"https://yolo-auto.com/v1\"\n\
     [models.defaults]\nmodel = { mode = \"auto\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"off\" }\n\
     [models.purposes.main]\nmodel = { mode = \"auto\", pool = [\"yolo-auto\"] }\neffort = { mode = \"auto\" }\n"
}

fn recorded_world(tag: &str) -> (support::World, Arc<std::sync::Mutex<Vec<RequestManifest>>>) {
    // The real offline loopback answers, and the wrapper serves the recorded
    // connection and keeps the manifest the provider actually received.
    let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut world = support::open_world_with(
        tag,
        Some(recorded_config_text()),
        Box::new(RankingProvider {
            inner: LoopbackProvider::new(),
            sent: sent.clone(),
        }),
        Box::new(support::PlatformWorker::default()),
    );
    world.runtime.purpose = "main".to_string();
    (world, sent)
}

/// The offline loopback plus one recorded wire log: the ranking world needs a
/// provider that serves the recorded connection and a manifest the test can
/// read back.
struct RankingProvider {
    inner: LoopbackProvider,
    sent: Arc<std::sync::Mutex<Vec<RequestManifest>>>,
}

impl Provider for RankingProvider {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn serves(&self, _connection: &str, _entry: &Connection) -> bool {
        true
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        self.sent.lock().expect("sent lock").push(manifest.clone());
        self.inner.send(manifest)
    }
}

/// One read dispatch through the controller's own path; the provider's
/// received manifest is exactly what the ranking froze.
fn dispatch_read(
    world: &mut support::World,
    sent: &Arc<std::sync::Mutex<Vec<RequestManifest>>>,
    session: &rivect::contracts::SessionId,
    task: &rivect::contracts::TaskId,
) -> RequestManifest {
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-economy-facts-marker\n").expect("scoped file");
    let grant = world.runtime.set_read_scope(scope, file.clone());
    let outcome = world.runtime.run_decision_step(
        session,
        task,
        &support::answer_custom(&format!("read {}", file.display())),
        &grant,
        false,
    );
    match &outcome {
        Ok(_) => {}
        // A task whose selected plan rows are still open refuses completion
        // *after* the send; the dispatch already happened, which is the fact
        // this helper returns.
        Err(rivect::controller::ControllerError::Store(StoreError::Conflict(
            ConflictCause::CompletionOpen { .. },
        ))) => {}
        other => panic!("the controller step runs: {other:?}"),
    }
    sent.lock()
        .expect("sent lock")
        .last()
        .cloned()
        .expect("the broker sent one request")
}

#[test]
fn auto_facts_are_built_from_the_task_snapshot() {
    let (mut world, sent) = recorded_world("economy-facts");
    let session = world.open_session("bootstrap-economy-facts");
    let plain = world.create_task(&session, "cmd-economy-facts-plain");
    let plain = dispatch_read(&mut world, &sent, &session, &plain);
    assert_eq!(
        plain.model,
        ModelAssign::Fixed(FixedModel {
            connection: "yolo-auto".to_string(),
            model_id: "deepseek-flash-v4".to_string(),
        }),
        "the recorded model freezes as a fixed pin"
    );
    assert_eq!(
        plain.effort,
        EffortAssign::Fixed {
            value: EffortLevel::Low
        },
        "one criterion and no obligations ask for the low level"
    );

    // The same purpose and connection on a task whose recorded selection left
    // obligations rank a higher effort: the counts came from the snapshot.
    let selected = world.create_task(&session, "cmd-economy-facts-selected");
    let config = world.runtime.config_for_broker();
    let request = PlanRequest {
        task_id: selected.clone(),
        kind: RequestKind::Audit,
        surfaces: SurfaceScan::Known(BTreeSet::from([Surface::Auth])),
        contract: ContractBasis::Absent,
        parts: Vec::new(),
        delegation: None,
        author: None,
    };
    ActionRegistry::new()
        .select(
            &request,
            &[],
            &mut world.runtime.action_context(&session, &config),
        )
        .expect("the selection records");
    let attested = world
        .runtime
        .store()
        .snapshot(&selected)
        .expect("the snapshot reads")
        .obligations
        .items
        .len();
    assert!(
        attested >= 2,
        "the selected task records at least two obligations: {attested}"
    );
    let ranked = dispatch_read(&mut world, &sent, &session, &selected);
    assert_eq!(ranked.model, plain.model, "the same single recorded model");
    assert_eq!(
        ranked.effort,
        EffortAssign::Fixed {
            value: EffortLevel::High
        },
        "two or more obligations ask for the recorded high level"
    );
}

#[test]
fn auto_explanation_basis_is_settled_and_visible() {
    let (mut world, sent) = recorded_world("economy-basis");
    let session = world.open_session("bootstrap-economy-basis");
    let task = world.create_task(&session, "cmd-economy-basis");
    let manifest = dispatch_read(&mut world, &sent, &session, &task);

    let basis = world
        .runtime
        .store()
        .settlement(&manifest.attempt_id)
        .expect("the send settled one row")
        .ranking_basis
        .expect("the settlement carries the basis");
    assert!(
        basis.contains("yolo-auto/deepseek-flash-v4"),
        "the basis names the pick: {basis}"
    );
    assert!(
        basis.contains("effort low from the default level"),
        "the basis names the effort fact: {basis}"
    );

    // The status serves the same choosing reason the ledger recorded, from
    // the controller's own refresh — no test-written projection.
    let economy = status(&mut world, &session)["economy"].clone();
    assert_eq!(
        economy["ranking_basis"],
        json!(basis),
        "the projection serves the settled basis: {economy}"
    );
    // A ranked model freezes as a fixed assignment, so the served source must
    // name the ranking, never an explicit pin.
    assert_eq!(
        economy["source"],
        json!("auto ranked"),
        "the source names the ranking: {economy}"
    );
    assert_eq!(economy["model"], json!("deepseek-flash-v4"));
}
