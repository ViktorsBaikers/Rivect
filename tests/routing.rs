//! Routing proof surface: broker-boundary discriminators. SLICE-011
//! legs — unsupported effort surfaces as a typed rejection on both
//! config carriers, never silently dropped, and the transmitted effort
//! is never called confirmed without provider data (EDGE-006, AC-043).
//! SLICE-013 legs — the sent wire request is exactly the frozen
//! manifest, overflow rejects instead of dropping mandatory parts, a
//! foreign execution world rejects the dispatch, the context epoch
//! replays bytewise until a model switch opens a new one, and pending
//! config/draft never rewrite an in-flight request (EDGE-004, PROH-004).
//! SLICE-012 legs — ineligible candidates are excluded before ranking,
//! a rights loss between ranking and dispatch re-blocks the send, a
//! forged or replayed manifest never dispatches, and every purpose
//! carries purpose, effective assignment/source, admission and exactly
//! one accounting record per physical request through the real offline
//! loopback (EDGE-005, PROH-003, AC-041/044).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/discard conveniences; src/ stays strict (standards §14)"
)]

use rivect::config::{
    Config, ConfigIssue, ConnKind, EffortAssign, EffortLevel, FixedModel, ModelAssign, Stage,
};
use rivect::contracts::MODEL_WIRE_MAX_BYTES;
use rivect::model::{Broker, ModelError, RequestManifest};
use rivect::providers::{LoopbackProvider, Provider, ProviderError, ProviderReply};
use std::sync::{Arc, Mutex};

fn local_fixed_config(effort_toml: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"local\", model_id = \"fixture-model\" }}\n\
         effort = {effort_toml}\n\
         fallback = {{ mode = \"auto\" }}\n"
    )
}

/// Same local-connection fixture with a switchable model id, for the
/// context-epoch and pending-config legs.
fn local_model_config(model_id: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"local\", model_id = \"{model_id}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"auto\" }}\n"
    )
}

/// Owner-side recording double: the offline loopback stays the real
/// provider; this only mirrors what the wire carried, so tests assert
/// the sent record against the frozen manifest.
struct RecordingProvider {
    inner: LoopbackProvider,
    sent: Arc<Mutex<Vec<RequestManifest>>>,
}

impl Provider for RecordingProvider {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        self.sent
            .lock()
            .expect("wire log lock")
            .push(manifest.clone());
        self.inner.send(manifest)
    }
}

fn recording_broker() -> (Broker, Arc<Mutex<Vec<RequestManifest>>>) {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let provider = RecordingProvider {
        inner: LoopbackProvider::new(),
        sent: sent.clone(),
    };
    (Broker::new(Box::new(provider)), sent)
}

/// Everything the provider sees before the inputs separator: the
/// model-visible prefix whose bytewise stability defines the epoch.
fn wire_prefix(wire: &str) -> &str {
    wire.split_once("\n\n").map_or(wire, |(prefix, _)| prefix)
}

#[test]
fn unsupported_effort_surfaces_on_both_carriers_never_drops() {
    // file carrier: the unsupported value is a typed schema rejection,
    // never a coercion or a silent drop
    let file_error = Config::parse_validated(&local_fixed_config(
        "{ mode = \"fixed\", value = \"ultra\" }",
    ))
    .expect_err("the file surface must reject the unsupported effort value");
    assert_eq!(file_error.stage, Stage::Schema);
    assert!(
        matches!(
            &file_error.issue,
            ConfigIssue::UnsupportedEffortValue { value } if value == "ultra"
        ),
        "wrong rejection issue: {file_error}"
    );

    // config.set carrier: the same rejection vocabulary
    let mut config =
        Config::parse_validated(&local_fixed_config("{ mode = \"auto\" }")).expect("valid");
    let wire_error = config
        .set_wire(
            "models.defaults.effort",
            &serde_json::json!({ "mode": "fixed", "value": "ultra" }),
        )
        .expect_err("the config.set surface must surface the unsupported value");
    assert!(
        matches!(
            &wire_error.issue,
            ConfigIssue::UnsupportedEffortValue { value } if value == "ultra"
        ),
        "wrong rejection issue: {wire_error}"
    );
    // the rejection coerces nothing: the retained assignment stays auto
    assert_eq!(
        config.resolve_purpose("main").expect("resolve").effort,
        EffortAssign::Auto
    );
}

#[test]
fn transmitted_effort_is_never_confirmed_without_provider_data() {
    // Each leg runs the full owner-brokered path: prepare freezes the
    // manifest, dispatch round-trips a real ProviderReply through the
    // offline loopback, and only after that reply does effort_explain
    // speak. The loopback carries no applied-effort data, so a
    // transmitted assignment must never surface as confirmed.

    // fixed leg: the resolved level rides the wire request verbatim
    let config = Config::parse_validated(&local_fixed_config(
        "{ mode = \"fixed\", value = \"high\" }",
    ))
    .expect("valid");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let manifest = broker
        .prepare("main", &config, "/world/fixture", "goal: fixture")
        .expect("manifest");
    assert_eq!(
        manifest.effort,
        EffortAssign::Fixed {
            value: EffortLevel::High
        },
        "the transmitted level rides the wire request verbatim"
    );
    let frozen = manifest.clone();
    let reply = broker
        .dispatch("/world/fixture", &manifest)
        .expect("offline dispatch");
    // the loopback really answered: fixture text, no tool calls
    assert!(!reply.text.is_empty(), "dispatch must return a real reply");
    assert!(reply.tool_calls.is_empty());
    assert_eq!(
        manifest, frozen,
        "dispatch never rewrites the frozen manifest"
    );
    let explain = broker.effort_explain(&manifest);
    assert_eq!(explain.transmitted, manifest.effort);
    assert!(
        explain.confirmed.is_none(),
        "a transmitted fixed level must not be called confirmed without provider data"
    );

    // auto leg: same round-trip discipline for the unresolved level
    let auto = Config::parse_validated(&local_fixed_config("{ mode = \"auto\" }")).expect("valid");
    let manifest = broker
        .prepare("main", &auto, "/world/fixture", "goal: fixture")
        .expect("manifest");
    let reply = broker
        .dispatch("/world/fixture", &manifest)
        .expect("offline dispatch");
    assert!(!reply.text.is_empty(), "dispatch must return a real reply");
    assert!(reply.tool_calls.is_empty());
    let explain = broker.effort_explain(&manifest);
    assert_eq!(explain.transmitted, manifest.effort);
    assert_eq!(explain.transmitted, EffortAssign::Auto);
    assert!(
        explain.confirmed.is_none(),
        "an auto assignment stays unconfirmed without provider data"
    );
}

#[test]
fn wire_request_is_the_frozen_manifest_and_overflow_rejects() {
    let config = Config::parse_validated(&local_model_config("fixture-model")).expect("valid");
    let (mut broker, sent) = recording_broker();
    let manifest = broker
        .prepare(
            "main",
            &config,
            "/world/limits",
            "goal: fixture\nread /scope/allowed.txt",
        )
        .expect("manifest");
    // mandatory wire parts are frozen on the manifest, never implied
    assert!(!manifest.instructions.is_empty());
    assert_eq!(manifest.tools, vec!["read_file".to_string()]);
    assert!(manifest.output_reserve > 0, "reserve must be accounted");
    // the wire request is exactly the frozen composition: instructions,
    // tools and inputs all verbatim
    let wire = manifest.wire_bytes();
    assert!(wire.contains(&manifest.instructions));
    assert!(wire.contains("read_file"));
    assert!(wire.contains("read /scope/allowed.txt"));
    let reply = broker
        .dispatch("/world/limits", &manifest)
        .expect("dispatch the fitting request");
    assert!(!reply.text.is_empty());
    assert_eq!(
        sent.lock().expect("wire log lock").last(),
        Some(&manifest),
        "the provider received exactly the frozen manifest"
    );

    // overflow: an inputs block that fits alone but not together with
    // the mandatory instructions, tools and output reserve must be a
    // typed rejection, never a truncation that drops mandatory parts
    let overhead = wire.len() - manifest.inputs.len() + manifest.output_reserve;
    let ignores_reserve = "x".repeat(MODEL_WIRE_MAX_BYTES - overhead + manifest.output_reserve);
    let error = broker
        .prepare("main", &config, "/world/limits", &ignores_reserve)
        .expect_err("a request that fits only without the reserve must reject");
    assert!(
        matches!(error, ModelError::RequestTooLarge { .. }),
        "wrong rejection: {error}"
    );
    // the boundary itself fits: the limit rejects nothing smaller
    let exactly_fits = "x".repeat(MODEL_WIRE_MAX_BYTES - overhead);
    let bounded = broker
        .prepare("main", &config, "/world/limits", &exactly_fits)
        .expect("a request accounting every mandatory part at the limit fits");
    assert_eq!(bounded.inputs.len(), exactly_fits.len());
}

#[test]
fn dispatch_rejects_a_foreign_execution_world() {
    let config = Config::parse_validated(&local_model_config("fixture-model")).expect("valid");
    let (mut broker, sent) = recording_broker();
    let manifest = broker
        .prepare("main", &config, "/world/alpha", "goal: fixture")
        .expect("manifest");
    let mismatch = broker
        .dispatch("/world/beta", &manifest)
        .expect_err("a manifest from another execution world must not be sent");
    assert!(
        matches!(
            &mismatch,
            ModelError::WorldMismatch { frozen, current } if frozen == "/world/alpha"
                && current == "/world/beta"
        ),
        "wrong rejection: {mismatch}"
    );
    assert!(
        sent.lock().expect("wire log lock").is_empty(),
        "the rejected dispatch never reached the provider"
    );
    broker
        .dispatch("/world/alpha", &manifest)
        .expect("the frozen world still dispatches");
    assert_eq!(sent.lock().expect("wire log lock").len(), 1);
}

#[test]
fn epoch_replays_bytewise_and_opens_on_model_switch() {
    let first_config = Config::parse_validated(&local_model_config("model-a")).expect("valid");
    let switched_config = Config::parse_validated(&local_model_config("model-b")).expect("valid");
    let (mut broker, _sent) = recording_broker();

    // input-only change: theme/counter churn never rewrites the
    // model-visible prefix, so the epoch replays bytewise
    let first = broker
        .prepare("main", &first_config, "/world/epoch", "goal: counter 1")
        .expect("manifest");
    let replayed = broker
        .prepare("main", &first_config, "/world/epoch", "goal: counter 2")
        .expect("manifest");
    assert_eq!(first.epoch_id, replayed.epoch_id);
    assert_eq!(first.mutation_reason, None);
    assert_eq!(replayed.mutation_reason, None);
    assert_eq!(
        wire_prefix(&first.wire_bytes()),
        wire_prefix(&replayed.wire_bytes()),
        "an unchanged epoch replays the model-visible prefix byte for byte"
    );

    // model switch opens a new epoch with the recorded reason
    let switched = broker
        .prepare("main", &switched_config, "/world/epoch", "goal: counter 2")
        .expect("manifest");
    assert_ne!(switched.epoch_id, replayed.epoch_id);
    assert_eq!(switched.mutation_reason.as_deref(), Some("model switch"));
    assert_ne!(
        wire_prefix(&switched.wire_bytes()),
        wire_prefix(&replayed.wire_bytes())
    );

    // switching back is another recorded mutation, never a silent replay
    let restored = broker
        .prepare("main", &first_config, "/world/epoch", "goal: counter 2")
        .expect("manifest");
    assert_eq!(restored.epoch_id, first.epoch_id);
    assert_eq!(restored.mutation_reason.as_deref(), Some("model switch"));
}

#[test]
fn pending_config_and_draft_never_rewrite_the_in_flight_request() {
    let first_config = Config::parse_validated(&local_model_config("model-a")).expect("valid");
    let pending_config = Config::parse_validated(&local_model_config("model-b")).expect("valid");
    let (mut broker, sent) = recording_broker();
    let draft_v1 = "goal: fixture\nanswer: draft v1";
    let manifest = broker
        .prepare("main", &first_config, "/world/inflight", draft_v1)
        .expect("manifest");
    let frozen = manifest.clone();

    // the user edits the draft and switches the pending config while
    // the request is in flight; neither object exists yet for the broker
    let _draft_v2 = "goal: fixture\nanswer: draft v2";
    let _pending = &pending_config;
    broker
        .dispatch("/world/inflight", &manifest)
        .expect("the in-flight dispatch completes on the frozen manifest");
    let recorded = sent
        .lock()
        .expect("wire log lock")
        .last()
        .cloned()
        .expect("the wire record exists");
    assert_eq!(
        recorded, frozen,
        "the wire record must match the frozen manifest, not the pending objects"
    );
    assert_eq!(recorded.inputs, draft_v1);
    assert_eq!(
        recorded.model,
        ModelAssign::Fixed(FixedModel {
            connection: "local".to_string(),
            model_id: "model-a".to_string(),
        })
    );

    // the pending draft and config apply to the next request only
    let next = broker
        .prepare(
            "main",
            &pending_config,
            "/world/inflight",
            "goal: fixture\nanswer: draft v2",
        )
        .expect("the next request snapshots the new objects");
    assert_eq!(next.inputs, "goal: fixture\nanswer: draft v2");
    assert_eq!(
        next.model,
        ModelAssign::Fixed(FixedModel {
            connection: "local".to_string(),
            model_id: "model-b".to_string(),
        })
    );
    assert_eq!(next.mutation_reason.as_deref(), Some("model switch"));
    assert_ne!(next.epoch_id, frozen.epoch_id);
}

/// Two local connections plus the live-grant one: the catalogue is
/// wider than any account, so pool/eligible/rights filtering has real
/// candidates to exclude. The learned role pins its own connection.
fn pools_config() -> String {
    "config_version = 1\n\
     [connections.primary]\nkind = \"api_key\"\nendpoint = \"https://api.openai.com/v1\"\ncredential_ref = \"keyring:primary\"\n\
     [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
     [connections.reserve]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11435\"\n\
     [models.defaults]\n\
     model = { mode = \"auto\" }\n\
     effort = { mode = \"auto\" }\n\
     fallback = { mode = \"auto\" }\n\
     [models.purposes.vision]\npool = [\"local\", \"reserve\"]\neligible = [\"reserve\"]\n\
     [models.purposes.compaction]\npool = [\"ghost\", \"local\"]\n\
     [models.purposes.planner]\npool = [\"primary\", \"local\"]\n\
     [models.purposes.live_pin]\nmodel = { mode = \"fixed\", connection = \"primary\", model_id = \"pinned-model\" }\n\
     [models.purposes.embedding]\npool = [\"local\", \"reserve\"]\n\
     [models.purposes.reranker]\npool = [\"local\"]\n\
     [models.purposes.triage_heuristic]\nmodel = { mode = \"fixed\", connection = \"reserve\", model_id = \"learned-model\" }\n"
        .to_string()
}

#[test]
fn ineligible_candidates_are_excluded_before_ranking_and_fail_closed() {
    let config = Config::parse_validated(&pools_config()).expect("valid");

    // per-purpose `eligible` narrows the pool before ranking: pool
    // order would rank local first, the entitlement input excludes it
    let (mut broker, sent) = recording_broker();
    let vision = broker
        .prepare("vision", &config, "/world/pools", "goal: fixture")
        .expect("the entitled candidate ranks");
    let admission = broker
        .admission(&vision.attempt_id)
        .expect("prepare records the admission");
    assert_eq!(admission.connection, "reserve");
    assert_eq!(admission.purpose, "vision");
    assert_eq!(admission.model_source, "models.defaults");

    // catalogue dimension: a pool entry naming no declared connection
    // is not a candidate at all; ranking falls to the known one
    let compaction = broker
        .prepare("compaction", &config, "/world/pools", "goal: fixture")
        .expect("unknown catalogue names never rank");
    assert_eq!(
        broker
            .admission(&compaction.attempt_id)
            .expect("admission")
            .connection,
        "local"
    );

    // live-grant dimension: a non-local connection first in pool order
    // is skipped for a later local one — offline has no grant surface,
    // so primary never reaches the provider or the ranking
    let planner = broker
        .prepare("planner", &config, "/world/pools", "goal: fixture")
        .expect("the offline-usable candidate ranks");
    assert_eq!(
        broker
            .admission(&planner.attempt_id)
            .expect("admission")
            .connection,
        "local"
    );

    // a fixed pin on the live-grant connection keeps the provider's
    // typed rejection, never the ranking's NoEligibleCandidate
    let live_pin = broker
        .prepare("live_pin", &config, "/world/pools", "goal: fixture")
        .expect_err("a fixed live pin needs a grant offline");
    assert!(
        matches!(
            &live_pin,
            ModelError::Provider(ProviderError::LiveGrantRequired {
                kind: ConnKind::ApiKey
            })
        ),
        "wrong rejection: {live_pin}"
    );

    // account dimension: rights narrower than the pool exclude the
    // unentitled candidate before ranking (catalogue ≠ entitlement)
    broker.set_account_rights(&["reserve".to_string()]);
    let embedding = broker
        .prepare("embedding", &config, "/world/pools", "goal: fixture")
        .expect("the account-entitled candidate ranks");
    assert_eq!(
        broker
            .admission(&embedding.attempt_id)
            .expect("admission")
            .connection,
        "reserve"
    );

    // fail closed: a purpose whose every candidate is ineligible gets
    // a typed rejection, never a catalogue-wide ambient fallback — and
    // the failed prepare writes neither an admission nor a provider call
    let admitted_before = broker.admitted_attempts();
    let error = broker
        .prepare("reranker", &config, "/world/pools", "goal: fixture")
        .expect_err("no eligible candidate must fail closed");
    assert!(
        matches!(&error, ModelError::NoEligibleCandidate { purpose } if purpose == "reranker"),
        "wrong rejection: {error}"
    );
    assert_eq!(
        broker.admitted_attempts(),
        admitted_before,
        "a failed prepare writes no admission record"
    );
    assert!(
        sent.lock().expect("wire log lock").is_empty(),
        "an excluded candidate never reaches the provider"
    );

    // a manifest this broker never ranked has no admission record:
    // the dispatch fails closed instead of sending unguarded
    let (mut other, other_sent) = recording_broker();
    let unadmitted = other
        .dispatch("/world/pools", &vision)
        .expect_err("only broker-ranked manifests dispatch");
    assert!(
        matches!(
            &unadmitted,
            ModelError::NoAdmission { attempt_id } if attempt_id == &vision.attempt_id
        ),
        "wrong rejection: {unadmitted}"
    );
    assert!(
        other_sent.lock().expect("wire log lock").is_empty(),
        "the unadmitted dispatch never reached the provider"
    );
}

#[test]
fn rights_loss_between_ranking_and_dispatch_re_blocks_the_send() {
    let config = Config::parse_validated(&pools_config()).expect("valid");
    let (mut broker, sent) = recording_broker();
    broker.set_account_rights(&["local".to_string()]);
    let manifest = broker
        .prepare("main", &config, "/world/rights", "goal: fixture")
        .expect("the entitled candidate ranks");
    assert_eq!(
        broker
            .admission(&manifest.attempt_id)
            .expect("admission")
            .snapshot_version,
        1
    );

    // rights lost between ranking and dispatch: the versioned snapshot
    // moved on, so the send is blocked again before any provider call
    broker.set_account_rights(&["reserve".to_string()]);
    let blocked = broker
        .dispatch("/world/rights", &manifest)
        .expect_err("a stale grant must never ship");
    assert!(
        matches!(
            &blocked,
            ModelError::EligibilityStale {
                attempt_id,
                connection,
                frozen: 1,
                current: 2,
            } if attempt_id == &manifest.attempt_id && connection == "local"
        ),
        "wrong rejection: {blocked}"
    );
    assert!(
        sent.lock().expect("wire log lock").is_empty(),
        "the blocked dispatch never reached the provider"
    );
    assert!(
        broker.accounting_record(&manifest.attempt_id).is_none(),
        "a blocked send is never accounted"
    );

    // restoring the right does not unblock the frozen manifest: the
    // version moved again, so the caller must re-rank, not replay
    broker.set_account_rights(&["local".to_string()]);

    assert_eq!(broker.entitlement_version(), 3);
    let still_stale = broker
        .dispatch("/world/rights", &manifest)
        .expect_err("a changed snapshot stays blocking");
    assert!(
        matches!(
            &still_stale,
            ModelError::EligibilityStale {
                attempt_id,
                connection,
                frozen: 1,
                current: 3,
            } if attempt_id == &manifest.attempt_id && connection == "local"
        ),
        "wrong rejection: {still_stale}"
    );
    assert!(sent.lock().expect("wire log lock").is_empty());

    // a fresh prepare under the current snapshot dispatches again
    let next = broker
        .prepare("main", &config, "/world/rights", "goal: fixture")
        .expect("re-ranking admits the entitled candidate");
    broker
        .dispatch("/world/rights", &next)
        .expect("the re-ranked request sends");
    assert_eq!(sent.lock().expect("wire log lock").len(), 1);
    assert_eq!(
        broker
            .accounting_record(&next.attempt_id)
            .map(|record| (record.connection.as_str(), record.cost_bound)),
        Some(("local", 2)),
        "the accounting names the admitted connection and its frozen bound"
    );
    assert!(
        broker.admission(&next.attempt_id).is_none(),
        "a completed dispatch prunes its admission"
    );
}

#[test]
fn every_purpose_carries_admission_and_single_accounting() {
    let config = Config::parse_validated(&pools_config()).expect("valid");
    let (mut broker, sent) = recording_broker();
    // (purpose, expected admission connection, expected model id):
    // defaults purposes rank the first offline-usable catalogue
    // connection, vision's eligible list admits reserve, and the
    // learned role rides its own fixed pin
    let expected = [
        ("main", "local", None),
        ("child", "local", None),
        ("reviewer", "local", None),
        ("vision", "reserve", None),
        ("compaction", "local", None),
        ("learning", "local", None),
        ("embedding", "local", None),
        ("reranker", "local", None),
        ("triage_heuristic", "reserve", Some("learned-model")),
    ];
    let mut manifests = Vec::new();
    for (purpose, connection, model_id) in expected {
        let manifest = broker
            .prepare(
                purpose,
                &config,
                "/world/purposes",
                &format!("goal: {purpose}"),
            )
            .expect("every purpose resolves through the broker");
        assert_eq!(manifest.purpose, purpose);
        let admission = broker
            .admission(&manifest.attempt_id)
            .expect("every physical request carries an admission");
        assert_eq!(admission.purpose, purpose);
        assert_eq!(admission.connection, connection, "{purpose}");
        assert_eq!(admission.model_id.as_deref(), model_id, "{purpose}");
        assert_eq!(
            admission.model_source,
            if purpose == "triage_heuristic" {
                "models.purposes.triage_heuristic"
            } else {
                "models.defaults"
            },
            "{purpose}"
        );
        // the real offline loopback answers; no fake LLM call exists
        broker
            .dispatch("/world/purposes", &manifest)
            .expect("the brokered dispatch completes");
        let record = broker
            .accounting_record(&manifest.attempt_id)
            .expect("exactly one accounting record per physical request");
        assert_eq!(record.purpose, purpose);
        assert_eq!(record.connection, connection, "{purpose}");
        // tiny fixture inputs: the frozen bound is the request itself
        // plus one unit for its single input slice, so the accounting
        // keeps the admitted bound rather than an invented number
        assert_eq!(record.cost_bound, 2, "{purpose}");
        assert!(
            broker.admission(&manifest.attempt_id).is_none(),
            "a completed dispatch prunes its admission: {purpose}"
        );
        manifests.push(manifest);
    }
    assert_eq!(sent.lock().expect("wire log lock").len(), expected.len());
    assert_eq!(broker.accounted_requests(), expected.len());
    let unique: std::collections::BTreeSet<_> = manifests.iter().map(|m| &m.attempt_id).collect();
    assert_eq!(unique.len(), expected.len(), "one attempt id per request");

    // a replayed ORIGINAL manifest is never a second physical request:
    // its admission is spent, and the accounting map — not a stale
    // admission — answers the replay with the spent single accounting
    let original = &manifests[0];
    let replayed = broker
        .dispatch("/world/purposes", original)
        .expect_err("one physical request per attempt id");
    assert!(
        matches!(
            &replayed,
            ModelError::AttemptAlreadyAccounted { attempt_id } if attempt_id == &original.attempt_id
        ),
        "wrong rejection: {replayed}"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        expected.len(),
        "the rejected replay added no provider call"
    );

    // a forged manifest carrying a real attempt id authorizes nothing:
    // mutated inputs are bytes no ranking saw, rejected before the send
    let pending = broker
        .prepare("main", &config, "/world/purposes", "goal: main")
        .expect("manifest");
    let mut forged = pending.clone();
    forged.inputs = "goal: main\nread /world/purposes/secret".to_string();
    let mismatched = broker
        .dispatch("/world/purposes", &forged)
        .expect_err("only the admitted manifest dispatches");
    assert!(
        matches!(
            &mismatched,
            ModelError::AdmissionMismatch { attempt_id } if attempt_id == &forged.attempt_id
        ),
        "wrong rejection: {mismatched}"
    );
    assert!(
        broker.accounting_record(&pending.attempt_id).is_none(),
        "the forged dispatch is never accounted"
    );

    // the genuine pending manifest still spends its own single request
    broker
        .dispatch("/world/purposes", &pending)
        .expect("the genuine manifest sends");
    let duplicate = broker
        .dispatch("/world/purposes", &pending)
        .expect_err("one physical request per attempt id");
    assert!(
        matches!(
            &duplicate,
            ModelError::AttemptAlreadyAccounted { attempt_id } if attempt_id == &pending.attempt_id
        ),
        "wrong rejection: {duplicate}"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        expected.len() + 1,
        "nine purposes plus one pending manifest — the forged and duplicate replays added none"
    );
    assert_eq!(broker.accounted_requests(), expected.len() + 1);
}
