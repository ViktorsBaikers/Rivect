//! Durable settlement and economy projection proof: one row per dispatched
//! child attempt across replay and restart, the exact provider bins beside
//! the bound-capped charge, interrupted sends reconciled as unknown, and the
//! status surface serving unknown-with-source figures from its cache
//! (AC-057, AC-059, AC-062).

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

use rivect::config::{Config, ConnKind, Connection, FixedModel, ModelAssign};
use rivect::contracts::AnswerSelection;
use rivect::controller::{SchedulerStep, StepOutcome};
use rivect::model::{Broker, ModelError, RequestManifest, SendContext, SendOutcome, SendTicket};
use rivect::providers::{Provider, ProviderError, ProviderReply};
use rivect::resources::{Exactness, UsageDelta};
use rivect::state::{ConflictCause, SettlementState, StoreError, StoreLedger, TaskStore};
use serde_json::{Value, json};
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
    assert_eq!(
        reopened
            .reconcile_sends()
            .expect("a second pass is a no-op"),
        0
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
        Err(ProviderError::ProviderFailed {
            connection: CONNECTION.to_string(),
            reason: "fixture failure".to_string(),
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
