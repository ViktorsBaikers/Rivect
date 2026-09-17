//! Routing proof surface: broker-boundary discriminators. SLICE-011
//! legs — unsupported effort surfaces as a typed rejection on both
//! config carriers, never silently dropped, and the transmitted effort
//! is never called confirmed without provider data (EDGE-006, AC-043).
//! SLICE-013 legs — the sent wire request is exactly the frozen
//! manifest, overflow rejects instead of dropping mandatory parts, a
//! foreign execution world rejects the dispatch, the context epoch
//! replays bytewise until a model switch opens a new one, and pending
//! config/draft never rewrite an in-flight request (EDGE-004, PROH-004).

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
    Config, ConfigIssue, EffortAssign, EffortLevel, FixedModel, ModelAssign, Stage,
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
