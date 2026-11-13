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
//! SLICE-014 legs — `FallbackAssign::{Auto,Manual,Off}` carry runtime
//! semantics on the one broker: the auto chain walks only candidates
//! passing the current eligibility check, manual records a pending
//! choice that rides the existing question protocol, off never
//! substitutes, a confirmed effect is never replayed, adapter retries
//! spend the shared outer cap, and a cancelled attempt is never
//! resurrected by a retry or a late callback (AC-045/045b, EDGE-004).
//! SLICE-016 leg — the accounting record reflects the provider's
//! reported usage exactly, and an unreported send stays `Unknown`,
//! never a released zero (INV-022/INV-024).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/discard conveniences; src/ stays strict (standards §14)"
)]

use rivect::actions::{
    ActionInput, ActionOutcome, ActionRegistry, BrokerSeam, ContractBasis, PlanRequest,
    RequestKind, Surface, SurfaceScan,
};
use rivect::config::{
    Config, ConfigIssue, ConnKind, EffortAssign, EffortLevel, FixedModel, ModelAssign, Stage,
};
use rivect::contracts::{Availability, MODEL_WIRE_MAX_BYTES, OptionId, Question, QuestionOption};
use rivect::model::{
    Broker, CallContract, CandidateRejection, EpochMutationReason, InputOrigin, ModelError,
    RankingFacts, RecordedFacts, RejectionCause, RequestManifest,
};
use rivect::providers::{
    Dialect, LoopbackProvider, Provider, ProviderError, ProviderReply, TransportCause,
    TransportClass,
};
use rivect::resources::UsageDelta;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

mod support;

fn local_config(model_id: &str, effort_toml: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"local\", model_id = \"{model_id}\" }}\n\
         effort = {effort_toml}\n\
         fallback = {{ mode = \"auto\" }}\n"
    )
}

/// Owner-side recording double: the offline loopback stays the real
/// provider; this only mirrors what the wire carried, so tests assert
/// the sent record against the frozen manifest.
struct RecordingProvider {
    inner: LoopbackProvider,
    sent: Arc<Mutex<Vec<RequestManifest>>>,
    script: Arc<Mutex<VecDeque<Respond>>>,
    inner_attempts: Arc<AtomicU64>,
    inner_retries: u32,
}

/// One scripted send outcome. The adapter's own retries run inside the
/// one physical send — an inner cost the request's shared outer cap
/// already pays for — so they are observable but never a second send.
enum Respond {
    Delegate,
    Fail(ProviderError),
    /// A crafted reply; its `usage` field carries the provider's
    /// physical usage report.
    Reply(ProviderReply),
}

impl Provider for RecordingProvider {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    /// The double's serving rule is its wrapped provider's — the
    /// script decides the reply, not the dialect claim.
    fn serves(&self, connection: &str, entry: &rivect::config::Connection) -> bool {
        self.inner.serves(connection, entry)
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        for _ in 0..self.inner_retries {
            self.inner_attempts.fetch_add(1, Ordering::SeqCst);
        }
        self.sent
            .lock()
            .expect("wire log lock")
            .push(manifest.clone());
        let respond = self
            .script
            .lock()
            .expect("script lock")
            .pop_front()
            .unwrap_or(Respond::Delegate);
        match respond {
            Respond::Fail(error) => Err(error),
            Respond::Delegate => self.inner.send(manifest),
            Respond::Reply(reply) => Ok(reply),
        }
    }
}

fn recording_broker() -> (Broker, Arc<Mutex<Vec<RequestManifest>>>) {
    let (broker, sent, _) = scripted_broker(Vec::new(), 0);
    (broker, sent)
}

fn scripted_broker(
    script: Vec<Respond>,
    inner_retries: u32,
) -> (Broker, Arc<Mutex<Vec<RequestManifest>>>, Arc<AtomicU64>) {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let inner_attempts = Arc::new(AtomicU64::new(0));
    let provider = RecordingProvider {
        inner: LoopbackProvider::new(),
        sent: sent.clone(),
        script: Arc::new(Mutex::new(script.into())),
        inner_attempts: inner_attempts.clone(),
        inner_retries,
    };
    (Broker::new(Box::new(provider)), sent, inner_attempts)
}

/// Fallback corpus: six connections so the auto chain can express a
/// live-grant-denied candidate (`web`), an account-denied one
/// (`denied`), a purpose-shadowed one (`shadowed`), a removed one
/// (`gone`), and the admitted reserve. `web` stays grant-gated through
/// an admitted `keyring:` ref: its binding resolves against `web-lock`,
/// a profile that names no ref, so the credential leg fails without an
/// unsupported store. `purpose_toml` carries the relay purpose's
/// `fallback`/`eligible` lines.
fn fallback_config(purpose_toml: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [connections.reserve]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11435\"\n\
         [profiles.web-lock]\n\
         [connections.web]\nkind = \"api_key\"\nendpoint = \"https://api.example.invalid/v1\"\ncredential_ref = \"keyring:rivect/web\"\nprofile = \"web-lock\"\n\
         [connections.denied]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11436\"\n\
         [connections.shadowed]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11437\"\n\
         [connections.gone]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11438\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"auto\" }}\n\
         [models.purposes.relay]\n\
         model = {{ mode = \"fixed\", connection = \"local\", model_id = \"primary-pin\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         {purpose_toml}"
    )
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
    let file_error = Config::parse_validated(&local_config(
        "fixture-model",
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
    let mut config = Config::parse_validated(&local_config("fixture-model", "{ mode = \"auto\" }"))
        .expect("valid");
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
    let config = Config::parse_validated(&local_config(
        "fixture-model",
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
        .dispatch(&mut rivect::model::NullLedger, "/world/fixture", &manifest)
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
    let auto = Config::parse_validated(&local_config("fixture-model", "{ mode = \"auto\" }"))
        .expect("valid");
    let manifest = broker
        .prepare("main", &auto, "/world/fixture", "goal: fixture")
        .expect("manifest");
    let reply = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/fixture", &manifest)
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
    let config = Config::parse_validated(&local_config(
        "fixture-model",
        "{ mode = \"fixed\", value = \"medium\" }",
    ))
    .expect("valid");
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
        .dispatch(&mut rivect::model::NullLedger, "/world/limits", &manifest)
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
    let config = Config::parse_validated(&local_config(
        "fixture-model",
        "{ mode = \"fixed\", value = \"medium\" }",
    ))
    .expect("valid");
    let (mut broker, sent) = recording_broker();
    let manifest = broker
        .prepare("main", &config, "/world/alpha", "goal: fixture")
        .expect("manifest");
    let mismatch = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/beta", &manifest)
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
        .dispatch(&mut rivect::model::NullLedger, "/world/alpha", &manifest)
        .expect("the frozen world still dispatches");
    assert_eq!(sent.lock().expect("wire log lock").len(), 1);
}

#[test]
fn epoch_replays_bytewise_and_opens_on_model_switch() {
    let first_config = Config::parse_validated(&local_config(
        "model-a",
        "{ mode = \"fixed\", value = \"medium\" }",
    ))
    .expect("valid");
    let switched_config = Config::parse_validated(&local_config(
        "model-b",
        "{ mode = \"fixed\", value = \"medium\" }",
    ))
    .expect("valid");
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
fn epoch_is_bytewise_stable_for_an_irrelevant_tick_p1() {
    let config = Config::parse_validated(&local_config(
        "model-a",
        "{ mode = \"fixed\", value = \"medium\" }",
    ))
    .expect("valid");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));

    // topic and counter churn ride the user channel, after the separator
    let first = broker
        .prepare(
            "main",
            &config,
            "/world/epoch",
            "topic: alpha\ngoal: counter 1",
        )
        .expect("manifest");
    let ticked = broker
        .prepare(
            "main",
            &config,
            "/world/epoch",
            "topic: beta\ngoal: counter 2",
        )
        .expect("manifest");
    assert_ne!(
        first.wire_bytes(),
        ticked.wire_bytes(),
        "the tick really moved the request bytes"
    );
    assert_eq!(
        wire_prefix(&first.wire_bytes()),
        wire_prefix(&ticked.wire_bytes()),
        "an irrelevant tick never rewrites the model-visible envelope"
    );
    assert_eq!(
        first.epoch_id, ticked.epoch_id,
        "an unchanged envelope replays the epoch instead of re-keying it"
    );
    assert_eq!(ticked.mutation_reason, None);
    assert_eq!(
        ticked.epoch_cost, None,
        "an irrelevant tick records no expected rewrite cost"
    );
}

#[test]
fn system_change_opens_its_own_epoch_p2() {
    let config = Config::parse_validated(&local_config(
        "model-a",
        "{ mode = \"fixed\", value = \"medium\" }",
    ))
    .expect("valid");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let baseline = CallContract {
        instructions: "decision core v1",
        tools: &[],
    };
    // the learned instruction delta of INV-009a: same tools, same model,
    // one more system line
    let learned = CallContract {
        instructions: "decision core v1\nprefer the smallest diff",
        tools: &[],
    };

    let first = broker
        .prepare_call("main", &config, "/world/epoch", "goal: fixture", &baseline)
        .expect("manifest");
    assert_eq!(first.mutation_reason, None);
    let changed = broker
        .prepare_call("main", &config, "/world/epoch", "goal: fixture", &learned)
        .expect("manifest");

    assert_eq!(
        first.instructions, "decision core v1",
        "the retired request keeps its own frozen instructions"
    );
    assert_ne!(changed.epoch_id, first.epoch_id);
    assert_eq!(
        changed.mutation_reason.as_deref(),
        Some("system change"),
        "a changed instruction set is a system change, never a model switch"
    );
    let cost = changed
        .epoch_cost
        .expect("a prefix mutation records its expected rewrite cost");
    assert_eq!(cost.reason, EpochMutationReason::SystemChange);
    assert_eq!(
        cost.replaced_part, "instructions",
        "the record names the part the mutation replaces"
    );
    assert_eq!(
        cost.expected_rewrite_bytes,
        wire_prefix(&changed.wire_bytes()).len(),
        "the rewritten cache tail starts at the first envelope part"
    );
}

#[test]
fn tools_change_opens_its_own_epoch_p3() {
    let config = Config::parse_validated(&local_config(
        "model-a",
        "{ mode = \"fixed\", value = \"medium\" }",
    ))
    .expect("valid");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let narrow = CallContract {
        instructions: "decision core v1",
        tools: &[],
    };
    let widened = CallContract {
        instructions: "decision core v1",
        tools: &["read_file"],
    };

    let first = broker
        .prepare_call("main", &config, "/world/epoch", "goal: fixture", &narrow)
        .expect("manifest");
    assert_eq!(first.mutation_reason, None);
    let changed = broker
        .prepare_call("main", &config, "/world/epoch", "goal: fixture", &widened)
        .expect("manifest");

    assert_eq!(changed.instructions, first.instructions);
    assert_ne!(changed.tools, first.tools);
    assert_ne!(changed.epoch_id, first.epoch_id);
    assert_eq!(
        changed.mutation_reason.as_deref(),
        Some("tools change"),
        "a changed tool surface is a tools change, never a model switch"
    );
    let cost = changed
        .epoch_cost
        .expect("a prefix mutation records its expected rewrite cost");
    assert_eq!(cost.reason, EpochMutationReason::ToolsChange);
    assert_eq!(cost.replaced_part, "tools");
    assert_eq!(
        cost.expected_rewrite_bytes,
        format!(
            "tools: read_file\noutput-reserve: {}",
            changed.output_reserve
        )
        .len(),
        "only the envelope tail from the tool surface is rewritten"
    );
}

#[test]
fn model_switch_opens_its_own_epoch_p4() {
    let first_config = Config::parse_validated(&local_config(
        "model-a",
        "{ mode = \"fixed\", value = \"medium\" }",
    ))
    .expect("valid");
    let switched_config = Config::parse_validated(&local_config(
        "model-b",
        "{ mode = \"fixed\", value = \"medium\" }",
    ))
    .expect("valid");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let base = CallContract {
        instructions: "decision core v1",
        tools: &[],
    };
    let widened = CallContract {
        instructions: "decision core v1",
        tools: &["read_file"],
    };

    // one part moves at a time, so each epoch names only its own cause
    let opened = broker
        .prepare_call(
            "main",
            &first_config,
            "/world/epoch",
            "goal: fixture",
            &base,
        )
        .expect("manifest");
    assert_eq!(opened.mutation_reason, None);
    let tools = broker
        .prepare_call(
            "main",
            &first_config,
            "/world/epoch",
            "goal: fixture",
            &widened,
        )
        .expect("manifest");
    let system = broker
        .prepare("main", &first_config, "/world/epoch", "goal: fixture")
        .expect("manifest");
    let switched = broker
        .prepare("main", &switched_config, "/world/epoch", "goal: fixture")
        .expect("manifest");

    assert_eq!(tools.mutation_reason.as_deref(), Some("tools change"));
    assert_eq!(system.mutation_reason.as_deref(), Some("system change"));
    assert_eq!(
        switched.mutation_reason.as_deref(),
        Some("model switch"),
        "only a resolved model change is a model switch"
    );
    let costs = [
        system.epoch_cost.expect("system change cost"),
        tools.epoch_cost.expect("tools change cost"),
        switched.epoch_cost.expect("model switch cost"),
    ];
    let cost = costs[2];
    assert_eq!(cost.reason, EpochMutationReason::ModelSwitch);
    assert_eq!(cost.replaced_part, "model");
    assert!(
        cost.expected_rewrite_bytes > 0
            && cost.expected_rewrite_bytes < wire_prefix(&switched.wire_bytes()).len(),
        "the rewrite starts at the model line, behind the unchanged instructions: {cost:?}"
    );
    // the three causes are distinct records, each naming its own part
    let mut parts: Vec<&str> = costs.iter().map(|cost| cost.replaced_part).collect();
    parts.sort_unstable();
    assert_eq!(parts, vec!["instructions", "model", "tools"]);
    let mut reasons: Vec<String> = costs.iter().map(|cost| cost.reason.to_string()).collect();
    reasons.sort();
    assert_eq!(
        reasons,
        vec!["model switch", "system change", "tools change"]
    );
}

#[test]
fn compaction_is_not_a_prefix_mutation_p5() {
    // Compaction lives in the store and never sees the broker, so this is
    // the guard: the folded history rides the request body while the
    // envelope and its epoch stay byte-identical. A future change that
    // put the history into the envelope turns this case red.
    let mut world =
        support::open_world("epoch-compaction", Some(&support::config_distinct_pools()));
    let session = world.open_session("epoch-compaction");
    let task = world.create_task(&session, "cmd-epoch-compaction");
    // the obligations are the rows evidence is recorded against
    world
        .runtime
        .store_writer()
        .materialize_obligations(&task)
        .expect("obligations");
    let scope = format!("task:{}", task.0);
    for index in 0..4_u8 {
        world
            .runtime
            .store_writer()
            .insert_evidence(
                &task,
                0,
                &scope,
                &format!(
                    "read the scope and reported {}",
                    "a scoped line of the file ".repeat(30)
                ),
                &format!("{index:02x}").repeat(32),
            )
            .expect("evidence row");
    }
    let config = world.runtime.config_for_broker();
    let before = world
        .runtime
        .store()
        .assembled_context(&task)
        .expect("assembled context");
    let first = world
        .runtime
        .broker
        .prepare("backend_task", &config, "/world/epoch", &before.text)
        .expect("manifest");

    let report = world
        .runtime
        .store_writer()
        .force_compaction(&session, &task)
        .expect("forced compaction");
    let after = world
        .runtime
        .store()
        .assembled_context(&task)
        .expect("assembled context");

    assert!(report.folded_records >= 4, "the fold took the records");
    assert!(
        after.history.len() < before.history.len(),
        "the fold really shortened the history: {} -> {}",
        before.history.len(),
        after.history.len()
    );
    assert!(before.text.contains(&before.history));
    let next = world
        .runtime
        .broker
        .prepare("backend_task", &config, "/world/epoch", &after.text)
        .expect("manifest");

    assert_eq!(
        wire_prefix(&first.wire_bytes()),
        wire_prefix(&next.wire_bytes()),
        "a compaction is not a prefix mutation"
    );
    assert_eq!(
        first.epoch_id, next.epoch_id,
        "the replay lineage is never re-keyed by a compaction"
    );
    assert_eq!(next.mutation_reason, None);
    assert_eq!(next.epoch_cost, None, "a non-prefix event costs no rewrite");
    let next_wire = next.wire_bytes();
    let envelope = wire_prefix(&next_wire);
    assert!(
        !envelope.contains(before.history.trim()) && !envelope.contains(after.history.trim()),
        "neither the assembled nor the folded history enters the envelope"
    );
    let first_wire = first.wire_bytes();
    assert!(
        first_wire.contains(before.history.trim()) && next_wire.contains(after.history.trim()),
        "the history rides the request body, which is why the envelope stays stable"
    );
}

#[test]
fn revoked_instruction_is_applied_in_the_next_request_p6() {
    // An applicable instruction is withdrawn between two prepares: the
    // next request carries the instruction set without it even though
    // the provider cache loses the prefix. The retired request keeps its
    // own frozen bytes — the correction applies forward, never backwards.
    let config = Config::parse_validated(&local_config(
        "model-a",
        "{ mode = \"fixed\", value = \"medium\" }",
    ))
    .expect("valid");
    let (mut broker, sent) = recording_broker();
    let mut applicable = vec!["decision core v1", "prefer the smallest diff"];
    let original = applicable.join("\n");
    let before = broker
        .prepare_call(
            "main",
            &config,
            "/world/epoch",
            "goal: fixture",
            &CallContract {
                instructions: &original,
                tools: &[],
            },
        )
        .expect("manifest");

    applicable.retain(|line| !line.contains("smallest diff"));
    let revoked = applicable.join("\n");
    let next = broker
        .prepare_call(
            "main",
            &config,
            "/world/epoch",
            "goal: fixture",
            &CallContract {
                instructions: &revoked,
                tools: &[],
            },
        )
        .expect("manifest");

    assert!(before.instructions.contains("prefer the smallest diff"));
    assert!(
        !next.instructions.contains("prefer the smallest diff"),
        "the revoked instruction is gone from the next request: {}",
        next.instructions
    );
    assert_eq!(
        before.instructions, original,
        "the retired request is never rewritten in place"
    );
    assert_ne!(
        wire_prefix(&before.wire_bytes()),
        wire_prefix(&next.wire_bytes()),
        "the changed instruction bytes open a new envelope"
    );
    assert_ne!(
        next.epoch_id, before.epoch_id,
        "no cached prefix is reused for a revoked instruction"
    );
    assert_eq!(next.mutation_reason.as_deref(), Some("system change"));
    assert!(
        sent.lock().expect("wire log lock").is_empty(),
        "no stale prefix was re-sent"
    );
}

#[test]
fn revoked_right_blocks_the_next_dispatch_p7() {
    let config = Config::parse_validated(&pools_config()).expect("valid");
    let (mut broker, sent) = recording_broker();
    broker.set_account_rights(&["local".to_string()]);
    let frozen = broker
        .prepare("main", &config, "/world/rights", "goal: fixture")
        .expect("the entitled candidate ranks");

    // the grant is revoked between two prepares: no next request is
    // prepared for it, so no reused prefix can carry it forward
    broker.set_account_rights(&[]);
    let refused = broker
        .prepare("main", &config, "/world/rights", "goal: fixture")
        .expect_err("a revoked grant admits no next request");
    assert!(
        matches!(
            &refused,
            ModelError::NoEligibleCandidate { rejected, .. }
                if rejected
                    .iter()
                    .any(|entry| matches!(entry.cause, RejectionCause::NotEntitled))
        ),
        "wrong refusal: {refused}"
    );

    // the frozen prefix is never re-sent either: the dispatch refuses
    // typed instead of replaying bytes the revoked grant authorized
    let blocked = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/rights", &frozen)
        .expect_err("a revoked grant never ships the frozen prefix");
    assert!(
        matches!(
            &blocked,
            ModelError::EligibilityStale {
                attempt_id,
                connection,
                frozen: 1,
                current: 2,
            } if attempt_id == &frozen.attempt_id && connection == "local"
        ),
        "wrong rejection: {blocked}"
    );
    assert!(
        sent.lock().expect("wire log lock").is_empty(),
        "the revoked dispatch never reached the provider"
    );
    assert!(
        broker.accounting_record(&frozen.attempt_id).is_none(),
        "a blocked send is never accounted"
    );
}

#[test]
fn pending_config_and_draft_never_rewrite_the_in_flight_request() {
    let first_config = Config::parse_validated(&local_config(
        "model-a",
        "{ mode = \"fixed\", value = \"medium\" }",
    ))
    .expect("valid");
    let pending_config = Config::parse_validated(&local_config(
        "model-b",
        "{ mode = \"fixed\", value = \"medium\" }",
    ))
    .expect("valid");
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
        .dispatch(&mut rivect::model::NullLedger, "/world/inflight", &manifest)
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
     [profiles.primary-lock]\n\
     [connections.primary]\nkind = \"api_key\"\nendpoint = \"https://api.openai.com/v1\"\ncredential_ref = \"keyring:rivect/primary\"\nprofile = \"primary-lock\"\n\
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
    let ModelError::NoEligibleCandidate { purpose, rejected } = &error else {
        panic!("wrong rejection: {error}")
    };
    assert_eq!(purpose, "reranker");
    assert!(
        matches!(rejected.as_slice(), [CandidateRejection {
            connection,
            cause: RejectionCause::NotEntitled,
        }] if connection == "local"),
        "the ranked refusal names the excluded candidate's cause"
    );
    assert!(
        error
            .to_string()
            .contains("local: outside the account entitlement"),
        "the ranked refusal renders per-candidate causes: {error}"
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
        .dispatch(&mut rivect::model::NullLedger, "/world/pools", &vision)
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
        .dispatch(&mut rivect::model::NullLedger, "/world/rights", &manifest)
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
        .dispatch(&mut rivect::model::NullLedger, "/world/rights", &manifest)
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
        .dispatch(&mut rivect::model::NullLedger, "/world/rights", &next)
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
    println!("ROW A11 ok");
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
            .dispatch(&mut rivect::model::NullLedger, "/world/purposes", &manifest)
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
    let unique: BTreeSet<_> = manifests.iter().map(|m| &m.attempt_id).collect();
    assert_eq!(unique.len(), expected.len(), "one attempt id per request");

    // a replayed ORIGINAL manifest is never a second physical request:
    // its admission is spent, and the accounting map — not a stale
    // admission — answers the replay with the spent single accounting
    let original = &manifests[0];
    let replayed = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/purposes", original)
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
        .dispatch(&mut rivect::model::NullLedger, "/world/purposes", &forged)
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
        .dispatch(&mut rivect::model::NullLedger, "/world/purposes", &pending)
        .expect("the genuine manifest sends");
    let duplicate = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/purposes", &pending)
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

// --- SLICE-014 legs ---------------------------------------------------

/// AC-045: `mode = "auto"` walks only chain entries passing the CURRENT
/// eligibility check — a candidate that fails it never receives the
/// request — and the admitted reserve's physical send freezes the
/// primary's task data byte-for-byte under its own attempt id, model
/// pin and shared reservation.
#[test]
fn fallback_auto_walks_only_admitted_chain_entries_preserving_primary_pins_and_spend() {
    let config = Config::parse_validated(&fallback_config(
        "fallback = { mode = \"auto\", chain = [\
             { mode = \"fixed\", connection = \"web\", model_id = \"web-model\" }, \
             { mode = \"fixed\", connection = \"reserve\", model_id = \"reserve-model\" }] }",
    ))
    .expect("valid");
    let (mut broker, sent, _inner) = scripted_broker(
        vec![
            Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            }),
            Respond::Delegate,
        ],
        0,
    );
    let manifest = broker
        .prepare("relay", &config, "/world/fallback", "goal: relay")
        .expect("manifest");
    assert!(
        matches!(&manifest.model, ModelAssign::Fixed(fixed)
            if fixed.connection == "local" && fixed.model_id == "primary-pin"),
        "the primary pin is the fixed purpose assignment"
    );

    let reply = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/fallback", &manifest)
        .expect("the admitted reserve answers the fallback");
    assert!(!reply.text.is_empty());

    let reserve_attempt = {
        let sent = sent.lock().expect("wire log lock");
        assert_eq!(
            sent.len(),
            2,
            "the egress-ineligible chain head never received a send"
        );
        let (primary, reserve) = (&sent[0], &sent[1]);
        assert_eq!(
            primary, &manifest,
            "the primary send is exactly the frozen manifest"
        );
        // pins and spend preserved: the fallback request carries the
        // primary's task data byte-for-byte under its own attempt id
        // and its own fixed model
        assert_ne!(reserve.attempt_id, primary.attempt_id);
        assert_eq!(
            reserve.model,
            ModelAssign::Fixed(FixedModel {
                connection: "reserve".to_string(),
                model_id: "reserve-model".to_string(),
            })
        );
        assert_eq!(reserve.purpose, primary.purpose);
        assert_eq!(reserve.world, primary.world);
        assert_eq!(reserve.effort, primary.effort);
        assert_eq!(reserve.instructions, primary.instructions);
        assert_eq!(reserve.tools, primary.tools);
        assert_eq!(reserve.output_reserve, primary.output_reserve);
        assert_eq!(reserve.inputs, primary.inputs);
        assert_eq!(reserve.inputs_digest, primary.inputs_digest);
        assert_eq!(reserve.cost_bound, primary.cost_bound);
        assert_eq!(
            reserve.mutation_reason.as_deref(),
            Some("model switch"),
            "a model change opens the new epoch — never a silent rewrite"
        );
        let attempt = reserve.attempt_id.clone();
        drop(sent);
        attempt
    };
    // accounting: exactly one charged physical request, naming the
    // reserve; the failed primary send spent nothing
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&reserve_attempt)
        .expect("the reserve send is accounted");
    assert_eq!(record.connection, "reserve");
    assert_eq!(record.cost_bound, manifest.cost_bound);
    assert!(
        broker.accounting_record(&manifest.attempt_id).is_none(),
        "a failed primary send spends nothing"
    );
    // both admissions are spent: neither can replay
    assert!(broker.admission(&manifest.attempt_id).is_none());
    assert!(broker.admission(&reserve_attempt).is_none());
}

/// AC-045/DEC-014: `mode = "manual"` rides the production question
/// path — the runtime consumes the broker's pending choice into a
/// served `question.current`, the task waits on it, and no substitute
/// dispatches on its own. The answered candidate then sends the frozen
/// manifest's task data through the picked connection under the
/// substitute's own attempt id, and the paused primary's admission is
/// spent with it.
#[test]
fn fallback_manual_surfaces_a_pending_choice_and_dispatches_nothing() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let provider = RecordingProvider {
        inner: LoopbackProvider::new(),
        sent: sent.clone(),
        script: Arc::new(Mutex::new(
            vec![Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            })]
            .into(),
        )),
        inner_attempts: Arc::new(AtomicU64::new(0)),
        inner_retries: 0,
    };
    let mut world = support::open_world_with(
        "manual-fallback",
        Some(&fallback_config("fallback = { mode = \"manual\" }")),
        Box::new(provider),
        Box::new(support::PlatformWorker::default()),
    );
    // the same scoped world the first-task loop drives
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-first-task-marker\n").expect("scoped file");
    world.runtime.purpose = "relay".to_string();
    world.runtime.set_read_scope(scope, file);

    let session = world.open_session("manual-boot");
    let task = world.create_task(&session, "manual-choice");
    let question = world.publish(&session, &task);
    // the fixture answer runs the step: the primary send fails, the
    // manual fallback publishes its own question, the task waits
    let answered = world.dispatch(&support::corpus_answer_custom(
        &session,
        "manual-first",
        &task,
        &question,
        "steps",
        json!(4101),
    ));
    assert!(
        answered.get("error").is_none(),
        "the answer commits and the step pauses: {answered}"
    );

    // the pending choice rides question.current itself — the test never
    // publishes it by hand
    let current = world.dispatch(&support::corpus_question_current(
        &session,
        &task,
        json!(4102),
    ));
    let served = current["result"]["question"].clone();
    assert_eq!(served["task_id"].as_str(), Some(task.0.as_str()));
    let option_ids: Vec<&str> = served["options"]
        .as_array()
        .expect("options")
        .iter()
        .filter_map(|option| option["option_id"].as_str())
        .collect();
    assert_eq!(
        option_ids,
        ["denied", "gone", "reserve", "shadowed"],
        "eligible candidates minus the failed primary"
    );
    let served_question: Question = serde_json::from_value(served).expect("served question parses");
    assert_eq!(
        served_question.prompt, "the pinned dispatch failed; choose the fallback connection",
        "a definitive denial keeps the plain pause"
    );
    assert_eq!(
        served_question.recommendation_basis, "candidates passing the current eligibility check",
        "a definitive denial keeps the plain basis"
    );
    let paused = world
        .runtime
        .paused_attempts
        .get(&task.0)
        .expect("the paused attempt is retained");
    assert!(
        paused
            .choice
            .as_ref()
            .is_some_and(|choice| !choice.unknown_outcome),
        "a definitive denial is not an unknown outcome"
    );

    // a repeated read serves the same pending question — reading never
    // consumes or mutates the pause
    let reread = world.dispatch(&support::corpus_question_current(
        &session,
        &task,
        json!(4104),
    ));
    assert_eq!(
        reread["result"]["question"]["question_id"].as_str(),
        Some(served_question.question_id.0.as_str()),
        "the pending question is stable across reads: {reread}"
    );

    // no substitute dispatched while the choice was pending: one send,
    // nothing accounted, the failed attempt stays admitted
    let paused_attempt = {
        let sent = sent.lock().expect("wire log lock");
        assert_eq!(sent.len(), 1, "manual never dispatches a substitute");
        sent[0].attempt_id.clone()
    };
    assert_eq!(world.runtime.broker.accounted_requests(), 0);
    assert!(
        world.runtime.broker.admission(&paused_attempt).is_some(),
        "the failed attempt stays admitted while the choice is pending"
    );

    // the answered candidate dispatches the frozen manifest's task data
    // through the picked connection under the substitute's own attempt id
    let picked = world.dispatch(&support::corpus_answer_option(
        &session,
        "manual-pick",
        &task,
        &served_question,
        "reserve",
        json!(4103),
    ));
    assert!(
        picked.get("error").is_none(),
        "the pick commits and the step completes: {picked}"
    );
    let substitute_attempt = {
        let sent = sent.lock().expect("wire log lock");
        assert_eq!(sent.len(), 2, "the picked candidate sends once");
        let substitute = &sent[1];
        assert_ne!(
            substitute.attempt_id, paused_attempt,
            "the substitute carries its own attempt id"
        );
        assert_eq!(
            substitute.model,
            ModelAssign::Fixed(FixedModel {
                connection: "reserve".to_string(),
                model_id: "primary-pin".to_string(),
            }),
            "the pinned model survives the substitution on the picked connection"
        );
        assert_eq!(
            substitute.inputs, sent[0].inputs,
            "the frozen task data crosses byte-for-byte"
        );
        substitute.attempt_id.clone()
    };
    // exactly one physical request accounted, naming the picked
    // connection — the failed primary send spent nothing and neither
    // attempt id can replay
    assert_eq!(world.runtime.broker.accounted_requests(), 1);
    let record = world
        .runtime
        .broker
        .accounting_record(&substitute_attempt)
        .expect("the substitute send is accounted");
    assert_eq!(record.connection, "reserve");
    assert!(
        world.runtime.broker.admission(&paused_attempt).is_none(),
        "the paused admission is spent with the substitute"
    );
    assert!(
        !world.runtime.paused_attempts.contains_key(&task.0),
        "the answered pause is consumed"
    );
    // The served economy names the connection that actually answered: the
    // prepared primary's model stays unknown with a source that says so.
    let status = world.dispatch(&support::corpus_status(&session));
    let economy = &status["result"]["economy"];
    assert_eq!(economy["connection"], json!("reserve"));
    assert!(
        economy["model"].is_null(),
        "the unsent primary's model is not named: {economy}"
    );
    assert!(
        economy["source"]
            .as_str()
            .expect("the projection names its source")
            .contains("fallback answered via reserve"),
        "the source names the answering connection: {economy}"
    );

    // a replayed answer is refused typed — the completed task is
    // terminal, the spent question never dispatches a second
    // substitute, and nothing accounts twice
    let replay = world.dispatch(&support::corpus_answer_option(
        &session,
        "manual-replay",
        &task,
        &served_question,
        "reserve",
        json!(4105),
    ));
    assert_eq!(
        replay["error"]["data"]["code"].as_str(),
        Some("already_terminal"),
        "the replayed answer is refused typed: {replay}"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        2,
        "the replay added no send"
    );
    assert_eq!(world.runtime.broker.accounted_requests(), 1);
}

/// AC-045/DEC-014 through the production path: an unknown primary outcome
/// still pauses a manual fallback, and the served question says so — the
/// effect may already have applied, so every offered pick repeats it rather
/// than substituting a request that never ran.
#[test]
fn manual_pause_on_an_unknown_outcome_serves_the_repeat_warning() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let provider = RecordingProvider {
        inner: LoopbackProvider::new(),
        sent: sent.clone(),
        script: Arc::new(Mutex::new(
            vec![Respond::Fail(ProviderError::Transport {
                connection: "local".to_string(),
                cause: TransportCause::Status {
                    status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
                },
            })]
            .into(),
        )),
        inner_attempts: Arc::new(AtomicU64::new(0)),
        inner_retries: 0,
    };
    let mut world = support::open_world_with(
        "manual-unknown",
        Some(&fallback_config("fallback = { mode = \"manual\" }")),
        Box::new(provider),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-first-task-marker\n").expect("scoped file");
    world.runtime.purpose = "relay".to_string();
    world.runtime.set_read_scope(scope, file);

    let session = world.open_session("manual-unknown-boot");
    let task = world.create_task(&session, "manual-unknown-choice");
    let question = world.publish(&session, &task);
    let answered = world.dispatch(&support::corpus_answer_custom(
        &session,
        "manual-unknown-first",
        &task,
        &question,
        "steps",
        json!(4301),
    ));
    assert!(
        answered.get("error").is_none(),
        "the answer commits and the step pauses: {answered}"
    );
    let current = world.dispatch(&support::corpus_question_current(
        &session,
        &task,
        json!(4302),
    ));
    let served_question: Question =
        serde_json::from_value(current["result"]["question"].clone()).expect("served question");
    assert_eq!(
        served_question.prompt,
        "the pinned dispatch ended without a definitive answer; its effect may have applied before the failure — a substitute send repeats it",
        "the unknown pause discloses the repeat: {served_question:?}"
    );
    assert_eq!(
        served_question.recommendation_basis,
        "unknown-outcome-repeat: a substitute repeats an effect that may have applied",
        "the repeat class is machine-readable: {served_question:?}"
    );
    let paused = world
        .runtime
        .paused_attempts
        .get(&task.0)
        .expect("the paused attempt is retained");
    assert!(
        paused
            .choice
            .as_ref()
            .is_some_and(|choice| choice.unknown_outcome),
        "the pause carries the classifier verdict"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        1,
        "manual never dispatches a substitute while the choice waits"
    );
    assert_eq!(
        world.runtime.broker.accounted_requests(),
        0,
        "the paused send spent nothing"
    );
}

/// AC-045/DEC-014 through the production path: a pre-send request-shape
/// refusal raised before the post — here the over-bound replay body —
/// never produced a byte, so the pause keeps the plain prompt and basis
/// and the classifier's `unknown_outcome` stays false: a substitute
/// cannot repeat an effect that never left the client.
#[test]
fn manual_pause_on_an_unsendable_request_keeps_the_plain_basis() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let provider = RecordingProvider {
        inner: LoopbackProvider::new(),
        sent: sent.clone(),
        script: Arc::new(Mutex::new(
            vec![Respond::Fail(ProviderError::UnsendableRequest {
                connection: "local".to_string(),
                reason: format!(
                    "request body of {} bytes exceeds the {} byte wire bound",
                    MODEL_WIRE_MAX_BYTES + 1,
                    MODEL_WIRE_MAX_BYTES
                ),
            })]
            .into(),
        )),
        inner_attempts: Arc::new(AtomicU64::new(0)),
        inner_retries: 0,
    };
    let mut world = support::open_world_with(
        "manual-unsendable",
        Some(&fallback_config("fallback = { mode = \"manual\" }")),
        Box::new(provider),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-first-task-marker\n").expect("scoped file");
    world.runtime.purpose = "relay".to_string();
    world.runtime.set_read_scope(scope, file);

    let session = world.open_session("manual-unsendable-boot");
    let task = world.create_task(&session, "manual-unsendable-choice");
    let question = world.publish(&session, &task);
    let answered = world.dispatch(&support::corpus_answer_custom(
        &session,
        "manual-unsendable-first",
        &task,
        &question,
        "steps",
        json!(4401),
    ));
    assert!(
        answered.get("error").is_none(),
        "the answer commits and the step pauses: {answered}"
    );
    let current = world.dispatch(&support::corpus_question_current(
        &session,
        &task,
        json!(4402),
    ));
    let served_question: Question =
        serde_json::from_value(current["result"]["question"].clone()).expect("served question");
    assert_eq!(
        served_question.prompt, "the pinned dispatch failed; choose the fallback connection",
        "a pre-send refusal keeps the plain pause: {served_question:?}"
    );
    assert_eq!(
        served_question.recommendation_basis, "candidates passing the current eligibility check",
        "a pre-send refusal keeps the plain basis: {served_question:?}"
    );
    let paused = world
        .runtime
        .paused_attempts
        .get(&task.0)
        .expect("the paused attempt is retained");
    assert!(
        paused
            .choice
            .as_ref()
            .is_some_and(|choice| !choice.unknown_outcome),
        "a request that never crossed the wire cannot have applied"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        1,
        "manual never dispatches a substitute while the choice waits"
    );
}

/// AC-045/DEC-014: the adapter's retry marker makes a pause unknown even
/// when the last leg's class alone is a definitive denial — an earlier leg
/// crossed the wire, so the offered picks must repeat the request. A
/// refactor that settles before classifying would read the 400 and pause as
/// a plain refusal.
#[test]
fn manual_pause_on_a_retried_denial_serves_the_repeat_warning() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let provider = RecordingProvider {
        inner: LoopbackProvider::new(),
        sent: sent.clone(),
        script: Arc::new(Mutex::new(
            vec![Respond::Fail(ProviderError::Retried {
                wire_retries: 1,
                source: Box::new(ProviderError::Transport {
                    connection: "local".to_string(),
                    cause: TransportCause::Status {
                        status: reqwest::StatusCode::BAD_REQUEST,
                    },
                }),
            })]
            .into(),
        )),
        inner_attempts: Arc::new(AtomicU64::new(0)),
        inner_retries: 0,
    };
    let mut world = support::open_world_with(
        "manual-retried",
        Some(&fallback_config("fallback = { mode = \"manual\" }")),
        Box::new(provider),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-first-task-marker\n").expect("scoped file");
    world.runtime.purpose = "relay".to_string();
    world.runtime.set_read_scope(scope, file);

    let session = world.open_session("manual-retried-boot");
    let task = world.create_task(&session, "manual-retried-choice");
    let question = world.publish(&session, &task);
    let answered = world.dispatch(&support::corpus_answer_custom(
        &session,
        "manual-retried-first",
        &task,
        &question,
        "steps",
        json!(4401),
    ));
    assert!(
        answered.get("error").is_none(),
        "the answer commits and the step pauses: {answered}"
    );
    let paused = world
        .runtime
        .paused_attempts
        .get(&task.0)
        .expect("the paused attempt is retained");
    assert!(
        paused
            .choice
            .as_ref()
            .is_some_and(|choice| choice.unknown_outcome),
        "a retried denial is an unknown outcome, never a definitive refusal"
    );
    let current = world.dispatch(&support::corpus_question_current(
        &session,
        &task,
        json!(4402),
    ));
    let served_question: Question =
        serde_json::from_value(current["result"]["question"].clone()).expect("served question");
    assert_eq!(
        served_question.prompt,
        "the pinned dispatch ended without a definitive answer; its effect may have applied before the failure — a substitute send repeats it",
        "the retried pause discloses the repeat: {served_question:?}"
    );
    assert_eq!(
        served_question.recommendation_basis,
        "unknown-outcome-repeat: a substitute repeats an effect that may have applied",
        "the retried pause carries the stable repeat token: {served_question:?}"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        1,
        "manual never dispatches a substitute while the choice waits"
    );
}

/// AC-045/DEC-012: a manual pick whose frozen bound no longer fits the
/// task's scope waits on the named budget resolution — the substitute is
/// never sent, the pause stays live, and the status surface serves the
/// reason the refusal recorded.
#[test]
fn budget_refused_manual_pick_waits_and_names_the_gate() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let provider = RecordingProvider {
        inner: LoopbackProvider::new(),
        sent: sent.clone(),
        script: Arc::new(Mutex::new(
            vec![Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            })]
            .into(),
        )),
        inner_attempts: Arc::new(AtomicU64::new(0)),
        inner_retries: 0,
    };
    let mut world = support::open_world_with(
        "manual-budget",
        Some(&fallback_config("fallback = { mode = \"manual\" }")),
        Box::new(provider),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-first-task-marker\n").expect("scoped file");
    world.runtime.purpose = "relay".to_string();
    world.runtime.set_read_scope(scope, file);

    let session = world.open_session("manual-budget-boot");
    let task = world.create_task(&session, "manual-budget-choice");
    let question = world.publish(&session, &task);
    let answered = world.dispatch(&support::corpus_answer_custom(
        &session,
        "manual-budget-first",
        &task,
        &question,
        "steps",
        json!(4201),
    ));
    assert!(
        answered.get("error").is_none(),
        "the answer commits and the step pauses: {answered}"
    );
    let current = world.dispatch(&support::corpus_question_current(
        &session,
        &task,
        json!(4202),
    ));
    let served_question: Question =
        serde_json::from_value(current["result"]["question"].clone()).expect("served question");
    let bound = world
        .runtime
        .paused_attempts
        .get(&task.0)
        .expect("the paused attempt is retained")
        .manifest
        .cost_bound;
    // The scope exists and cannot fit the frozen bound: one unit less than
    // the pick's own reservation.
    world
        .runtime
        .store_writer()
        .open_budget(&task.0, bound.saturating_sub(1))
        .expect("the scope cannot fit the frozen bound");

    let picked = world.dispatch(&support::corpus_answer_option(
        &session,
        "manual-budget-pick",
        &task,
        &served_question,
        "reserve",
        json!(4203),
    ));
    assert!(
        picked.get("error").is_none(),
        "the answer commits and the step waits on the budget: {picked}"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        1,
        "the refused substitute never crosses the wire"
    );
    assert_eq!(
        world.runtime.broker.accounted_requests(),
        0,
        "the refused substitute spends nothing"
    );
    assert!(
        world.runtime.paused_attempts.contains_key(&task.0),
        "the pause stays live on the budget refusal"
    );

    let status = world.dispatch(&support::corpus_status(&session));
    let waiting = status["result"]["budget_waiting"]
        .as_array()
        .expect("the status serves the waiting list");
    let entry = waiting
        .iter()
        .find(|entry| entry["task_id"].as_str() == Some(task.0.as_str()))
        .expect("the status serves the refused task");
    assert!(
        entry["reason"]
            .as_str()
            .expect("the entry names its reason")
            .contains(&task.0),
        "the served reason names the refused scope: {entry}"
    );
}

/// AC-045b: a manual pick is re-checked against the CURRENT eligibility
/// state — a candidate that lost its account rights between the question
/// and the answer is refused typed and never receives the send; the
/// paused attempt stays admitted so a cancel still tombstones it.
#[test]
fn fallback_manual_choice_recheck_blocks_a_candidate_that_lost_eligibility() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let provider = RecordingProvider {
        inner: LoopbackProvider::new(),
        sent: sent.clone(),
        script: Arc::new(Mutex::new(
            vec![Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            })]
            .into(),
        )),
        inner_attempts: Arc::new(AtomicU64::new(0)),
        inner_retries: 0,
    };
    let mut world = support::open_world_with(
        "manual-stale-pick",
        Some(&fallback_config("fallback = { mode = \"manual\" }")),
        Box::new(provider),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-first-task-marker\n").expect("scoped file");
    world.runtime.purpose = "relay".to_string();
    world.runtime.set_read_scope(scope, file);

    let session = world.open_session("manual-stale-boot");
    let task = world.create_task(&session, "manual-stale-choice");
    let question = world.publish(&session, &task);
    let answered = world.dispatch(&support::corpus_answer_custom(
        &session,
        "stale-first",
        &task,
        &question,
        "steps",
        json!(4201),
    ));
    assert!(answered.get("error").is_none());
    let current = world.dispatch(&support::corpus_question_current(
        &session,
        &task,
        json!(4202),
    ));
    let served_question: Question = serde_json::from_value(current["result"]["question"].clone())
        .expect("the pending choice question");
    let paused_attempt = sent.lock().expect("wire log lock")[0].attempt_id.clone();

    // `reserve` loses its account rights after the question is served —
    // the answer still names it, and the dispatch-time re-check refuses
    // the pick typed: the send never happens
    world.runtime.broker.set_account_rights(&[
        "local".to_string(),
        "denied".to_string(),
        "gone".to_string(),
        "shadowed".to_string(),
        "web".to_string(),
    ]);
    let picked = world.dispatch(&support::corpus_answer_option(
        &session,
        "stale-pick",
        &task,
        &served_question,
        "reserve",
        json!(4203),
    ));
    assert_eq!(
        picked["error"]["data"]["code"].as_str(),
        Some("capability_unavailable"),
        "the rejected pick is a typed capability refusal: {picked}"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        1,
        "the ineligible pick never received a send"
    );
    assert_eq!(world.runtime.broker.accounted_requests(), 0);
    assert!(
        world.runtime.broker.admission(&paused_attempt).is_some(),
        "the paused attempt stays admitted after the refused pick"
    );

    // and the surviving pause still tombstones on cancel
    let intent_revision = world
        .runtime
        .store()
        .snapshot(&task)
        .expect("snapshot")
        .intent_revision;
    let cancelled = world.dispatch(
        &json!({
            "jsonrpc": "2.0", "id": 4204, "method": "task.submit",
            "params": {
                "schema_version": 1, "command_id": "stale-cancel",
                "session_id": session.0, "kind": "cancel", "task_id": task.0,
                "expected_intent_revision": intent_revision
            }
        })
        .to_string(),
    );
    assert!(
        cancelled.get("error").is_none(),
        "cancel commits: {cancelled}"
    );
    assert!(
        world.runtime.broker.admission(&paused_attempt).is_none(),
        "the cancel tombstoned the paused attempt"
    );
}

/// EDGE-004 through the production path: a task cancelled while waiting
/// on a manual-fallback choice tombstones its broker attempt — a late
/// dispatch of the frozen manifest is refused, never resurrected — and
/// a task with no outstanding attempt cancels without a tombstone.
#[test]
fn task_cancel_tombstones_the_paused_broker_attempt() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let provider = RecordingProvider {
        inner: LoopbackProvider::new(),
        sent: sent.clone(),
        script: Arc::new(Mutex::new(
            vec![Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            })]
            .into(),
        )),
        inner_attempts: Arc::new(AtomicU64::new(0)),
        inner_retries: 0,
    };
    let mut world = support::open_world_with(
        "manual-cancel",
        Some(&fallback_config("fallback = { mode = \"manual\" }")),
        Box::new(provider),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-first-task-marker\n").expect("scoped file");
    world.runtime.purpose = "relay".to_string();
    world.runtime.set_read_scope(scope, file);

    let session = world.open_session("manual-cancel-boot");
    let task = world.create_task(&session, "manual-cancel-choice");
    let question = world.publish(&session, &task);
    let answered = world.dispatch(&support::corpus_answer_custom(
        &session,
        "cancel-first",
        &task,
        &question,
        "steps",
        json!(4301),
    ));
    assert!(
        answered["error"].is_null(),
        "the answer commits and the step pauses: {answered}"
    );
    let manifest = sent.lock().expect("wire log lock")[0].clone();
    assert!(
        world
            .runtime
            .broker
            .admission(&manifest.attempt_id)
            .is_some(),
        "the choice-pending attempt is still admitted"
    );

    let intent_revision = world
        .runtime
        .store()
        .snapshot(&task)
        .expect("snapshot")
        .intent_revision;
    let cancelled = world.dispatch(
        &json!({
            "jsonrpc": "2.0", "id": 4302, "method": "task.submit",
            "params": {
                "schema_version": 1, "command_id": "cancel-waiting",
                "session_id": session.0, "kind": "cancel", "task_id": task.0,
                "expected_intent_revision": intent_revision
            }
        })
        .to_string(),
    );
    assert!(
        cancelled.get("error").is_none(),
        "cancel commits: {cancelled}"
    );
    assert!(
        world
            .runtime
            .broker
            .admission(&manifest.attempt_id)
            .is_none(),
        "the cancelled task's broker attempt is tombstoned"
    );
    assert!(
        !world.runtime.paused_attempts.contains_key(&task.0),
        "the pause record is consumed with the tombstone"
    );
    let late = world
        .runtime
        .broker
        .dispatch(
            &mut rivect::model::NullLedger,
            &manifest.world.clone(),
            &manifest,
        )
        .expect_err("a late dispatch of the cancelled attempt is refused");
    assert!(
        matches!(&late, ModelError::AttemptCancelled { attempt_id }
            if attempt_id == &manifest.attempt_id),
        "wrong rejection: {late}"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        1,
        "the cancelled attempt never dispatched again"
    );

    // a task that never ran a dispatch holds no pause record: cancel
    // commits without tombstoning anything
    let idle_task = world.create_task(&session, "cancel-idle");
    let idle_revision = world
        .runtime
        .store()
        .snapshot(&idle_task)
        .expect("snapshot")
        .intent_revision;
    let idle = world.dispatch(
        &json!({
            "jsonrpc": "2.0", "id": 4303, "method": "task.submit",
            "params": {
                "schema_version": 1, "command_id": "cancel-idle",
                "session_id": session.0, "kind": "cancel", "task_id": idle_task.0,
                "expected_intent_revision": idle_revision
            }
        })
        .to_string(),
    );
    assert!(
        idle.get("error").is_none(),
        "a task with no outstanding attempt cancels clean: {idle}"
    );
}

/// A steer that lands while a manual-fallback choice is pending
/// supersedes the intent the question and the paused attempt were
/// pinned under: the paused broker admission is tombstoned,
/// `question.current` stops serving the stale record, and an answer
/// naming it — under the stale pin or the live intent — is denied
/// typed and never dispatches the frozen manifest.
#[test]
fn steer_while_a_fallback_choice_is_pending_retires_the_pause_and_question() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let provider = RecordingProvider {
        inner: LoopbackProvider::new(),
        sent: sent.clone(),
        script: Arc::new(Mutex::new(
            vec![Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            })]
            .into(),
        )),
        inner_attempts: Arc::new(AtomicU64::new(0)),
        inner_retries: 0,
    };
    let mut world = support::open_world_with(
        "manual-steer",
        Some(&fallback_config("fallback = { mode = \"manual\" }")),
        Box::new(provider),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-first-task-marker\n").expect("scoped file");
    world.runtime.purpose = "relay".to_string();
    world.runtime.set_read_scope(scope, file);

    let session = world.open_session("manual-steer-boot");
    let task = world.create_task(&session, "manual-steer-choice");
    let question = world.publish(&session, &task);
    let answered = world.dispatch(&support::corpus_answer_custom(
        &session,
        "steer-first",
        &task,
        &question,
        "steps",
        json!(4401),
    ));
    assert!(answered.get("error").is_none());
    let current = world.dispatch(&support::corpus_question_current(
        &session,
        &task,
        json!(4402),
    ));
    let served_question: Question = serde_json::from_value(current["result"]["question"].clone())
        .expect("the pending choice question");
    let paused_attempt = sent.lock().expect("wire log lock")[0].attempt_id.clone();
    assert!(
        world.runtime.broker.admission(&paused_attempt).is_some(),
        "the choice-pending attempt is admitted"
    );

    // the steer commits under the pre-pause revisions and advances the
    // intent the question and the frozen manifest were pinned under
    let snapshot = world.runtime.store().snapshot(&task).expect("snapshot");
    let steered = world.dispatch(&support::corpus_steer(
        &session,
        "steer-mid-choice",
        &task,
        snapshot.intent_revision,
        snapshot.revision,
        json!(4403),
    ));
    assert!(
        steered.get("error").is_none(),
        "steer commits on a waiting task: {steered}"
    );
    let live_intent = steered["result"]["intent_revision"]
        .as_u64()
        .expect("the steer reports the new intent");
    assert_eq!(live_intent, snapshot.intent_revision + 1);

    // the pause record is gone and the broker admission is tombstoned —
    // the frozen manifest has nothing left to dispatch through
    assert!(
        !world.runtime.paused_attempts.contains_key(&task.0),
        "the steer drained the pause record"
    );
    assert!(
        world.runtime.broker.admission(&paused_attempt).is_none(),
        "the steer tombstoned the paused admission"
    );

    // `question.current` retracts the stale record — the answer a client
    // could build from it can no longer be constructed
    let retracted = world.dispatch(&support::corpus_question_current(
        &session,
        &task,
        json!(4404),
    ));
    assert!(
        retracted["result"]["question"].is_null(),
        "the stale question is retracted: {retracted}"
    );

    // the stale-pin answer is denied typed before the store leg — and
    // an answer that quotes the LIVE intent with the stale question id
    // is denied the same way: the question's own intent pin is stale,
    // so neither shape can dispatch the frozen manifest
    let stale = world.dispatch(&support::corpus_answer_option(
        &session,
        "stale-answer",
        &task,
        &served_question,
        "reserve",
        json!(4405),
    ));
    assert_eq!(
        stale["error"]["data"]["code"].as_str(),
        Some("stale_intent"),
        "the stale-pin answer is refused typed: {stale}"
    );
    let live = world.dispatch(
        &json!({
            "jsonrpc": "2.0", "id": 4406, "method": "task.submit",
            "params": {
                "schema_version": 1, "command_id": "live-intent-answer",
                "session_id": session.0, "kind": "answer", "task_id": task.0,
                "expected_intent_revision": live_intent,
                "question_id": served_question.question_id.0,
                "question_revision": served_question.question_revision,
                "selection": { "kind": "option", "option_id": "reserve" }
            }
        })
        .to_string(),
    );
    assert_eq!(
        live["error"]["data"]["code"].as_str(),
        Some("stale_intent"),
        "the live-intent answer to a stale question is refused typed: {live}"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        1,
        "no answer dispatched the frozen manifest"
    );
    assert_eq!(world.runtime.broker.accounted_requests(), 0);
}

/// A dispatch failure under `mode = "off"` leaves a residue pause bound
/// to no served question — it exists so a cancel can tombstone the
/// still-live admission, never to be answered into a send. The next
/// fixed-option answer resolves a different fork: it reads the scoped
/// file directly and drains the residue with it, so the frozen manifest
/// can never replay.
#[test]
fn option_answer_drains_a_choiceless_residue_pause() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let provider = RecordingProvider {
        inner: LoopbackProvider::new(),
        sent: sent.clone(),
        script: Arc::new(Mutex::new(
            vec![Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            })]
            .into(),
        )),
        inner_attempts: Arc::new(AtomicU64::new(0)),
        inner_retries: 0,
    };
    let mut world = support::open_world_with(
        "residue-pause",
        Some(&fallback_config("fallback = { mode = \"off\" }")),
        Box::new(provider),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-first-task-marker\n").expect("scoped file");
    world.runtime.purpose = "relay".to_string();
    world.runtime.set_read_scope(scope, file);

    let session = world.open_session("residue-boot");
    let task = world.create_task(&session, "residue-choice");
    let question = world.publish(&session, &task);
    // `off` reports the provider's own error and substitutes nothing:
    // the step fails, leaving the failed attempt's admission live as a
    // residue pause no question served.
    let failed = world.dispatch(&support::corpus_answer_custom(
        &session,
        "residue-first",
        &task,
        &question,
        "steps",
        json!(4501),
    ));
    assert_eq!(
        failed["error"]["data"]["code"].as_str(),
        Some("denied"),
        "the failed send surfaces typed: {failed}"
    );
    let paused_attempt = sent.lock().expect("wire log lock")[0].attempt_id.clone();
    assert!(
        world
            .runtime
            .paused_attempts
            .get(&task.0)
            .is_some_and(|paused| paused.choice.is_none()),
        "the residue pause carries no served choice"
    );
    assert!(
        world.runtime.broker.admission(&paused_attempt).is_some(),
        "the failed attempt stays admitted while paused"
    );

    // A fixed option on the next fork answers a different question: it
    // resolves the scoped read itself — no send — and drains the
    // residue pause, tombstoning the frozen manifest's admission.
    let next = world.publish(&session, &task);
    let settled = world.dispatch(&support::corpus_answer_option(
        &session,
        "residue-settle",
        &task,
        &next,
        "steps",
        json!(4502),
    ));
    assert!(
        settled["error"].is_null(),
        "the option answer completes the read: {settled}"
    );
    assert_eq!(
        settled["result"]["snapshot"]["lifecycle"].as_str(),
        Some("completed"),
        "the direct read settles the task: {settled}"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        1,
        "the residue pause never dispatched"
    );
    assert_eq!(world.runtime.provider_calls, 0);
    assert!(
        world.runtime.broker.admission(&paused_attempt).is_none(),
        "the settle tombstoned the residue admission"
    );
    assert!(
        !world.runtime.paused_attempts.contains_key(&task.0),
        "the pause record drained with the settle"
    );
    assert_eq!(world.runtime.broker.accounted_requests(), 0);
}

/// A pause answers only to the question that served it. The served
/// choice survives a refused pick; when a different fork then publishes
/// and its answer happens to name the same option id as a served
/// candidate, the frozen manifest must not dispatch — the stale pause
/// is dead residue and settles tombstoned while the task reads the
/// scoped file directly.
#[test]
fn option_answer_on_a_different_fork_never_spends_a_stale_pause() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let provider = RecordingProvider {
        inner: LoopbackProvider::new(),
        sent: sent.clone(),
        script: Arc::new(Mutex::new(
            vec![
                Respond::Fail(ProviderError::UnknownConnection {
                    connection: "local".to_string(),
                }),
                Respond::Delegate,
            ]
            .into(),
        )),
        inner_attempts: Arc::new(AtomicU64::new(0)),
        inner_retries: 0,
    };
    let mut world = support::open_world_with(
        "stale-pause-collision",
        Some(&fallback_config("fallback = { mode = \"manual\" }")),
        Box::new(provider),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-first-task-marker\n").expect("scoped file");
    world.runtime.purpose = "relay".to_string();
    world.runtime.set_read_scope(scope, file);

    let session = world.open_session("collision-boot");
    let task = world.create_task(&session, "collision-choice");
    let question = world.publish(&session, &task);
    let answered = world.dispatch(&support::corpus_answer_custom(
        &session,
        "collision-first",
        &task,
        &question,
        "steps",
        json!(4601),
    ));
    assert!(
        answered["error"].is_null(),
        "the answer commits and the step pauses: {answered}"
    );
    let current = world.dispatch(&support::corpus_question_current(
        &session,
        &task,
        json!(4602),
    ));
    let served_question: Question = serde_json::from_value(current["result"]["question"].clone())
        .expect("the pending choice question");
    let paused_attempt = sent.lock().expect("wire log lock")[0].attempt_id.clone();

    // The pick names a served candidate that lost its account rights —
    // refused typed, and the pause survives for a re-pick.
    world.runtime.broker.set_account_rights(&[
        "local".to_string(),
        "denied".to_string(),
        "gone".to_string(),
        "shadowed".to_string(),
        "web".to_string(),
    ]);
    let refused = world.dispatch(&support::corpus_answer_option(
        &session,
        "collision-refused",
        &task,
        &served_question,
        "reserve",
        json!(4603),
    ));
    assert_eq!(
        refused["error"]["data"]["code"].as_str(),
        Some("capability_unavailable"),
        "the rejected pick is a typed capability refusal: {refused}"
    );
    assert!(
        world.runtime.paused_attempts.contains_key(&task.0),
        "the refused pick keeps the pause for a re-pick"
    );

    // Rights return, then a different fork publishes carrying an option
    // id that collides with a served candidate: answering it must not
    // dispatch the stale pause's frozen manifest.
    world.runtime.broker.set_account_rights(&[
        "local".to_string(),
        "denied".to_string(),
        "gone".to_string(),
        "shadowed".to_string(),
        "web".to_string(),
        "reserve".to_string(),
    ]);
    let mut other = Question::fixture(&task, 1);
    other.options.push(QuestionOption {
        option_id: OptionId("reserve".to_string()),
        label: "reserve".to_string(),
        consequences: "collides with a served candidate id".to_string(),
        availability: Availability::Enabled,
    });
    world
        .runtime
        .store_writer()
        .publish_question(&session, &other)
        .expect("the second fork publishes");
    let settled = world.dispatch(&support::corpus_answer_option(
        &session,
        "collision-settle",
        &task,
        &other,
        "reserve",
        json!(4604),
    ));
    assert!(
        settled["error"].is_null(),
        "the colliding option answer commits and completes: {settled}"
    );
    assert_eq!(
        settled["result"]["snapshot"]["lifecycle"].as_str(),
        Some("completed"),
        "the task read the scoped file directly: {settled}"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        1,
        "the frozen manifest never dispatched"
    );
    assert_eq!(world.runtime.provider_calls, 0);
    assert_eq!(
        world.runtime.broker.accounted_requests(),
        0,
        "nothing was accounted to the stale pause"
    );
    assert!(
        world.runtime.broker.admission(&paused_attempt).is_none(),
        "the settle tombstoned the stale admission"
    );
    assert!(
        !world.runtime.paused_attempts.contains_key(&task.0),
        "the stale pause drained with the settle"
    );
}

/// A free-text answer to the served fallback question spends a fresh
/// dispatch: the successful send supersedes the pause, whose admission
/// is tombstoned so neither attempt id can replay.
#[test]
fn custom_answer_on_the_served_question_supersedes_the_pause() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let provider = RecordingProvider {
        inner: LoopbackProvider::new(),
        sent: sent.clone(),
        script: Arc::new(Mutex::new(
            vec![
                Respond::Fail(ProviderError::UnknownConnection {
                    connection: "local".to_string(),
                }),
                Respond::Delegate,
            ]
            .into(),
        )),
        inner_attempts: Arc::new(AtomicU64::new(0)),
        inner_retries: 0,
    };
    let mut world = support::open_world_with(
        "served-custom",
        Some(&fallback_config("fallback = { mode = \"manual\" }")),
        Box::new(provider),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-first-task-marker\n").expect("scoped file");
    world.runtime.purpose = "relay".to_string();
    world.runtime.set_read_scope(scope, file);

    let session = world.open_session("served-custom-boot");
    let task = world.create_task(&session, "served-custom-choice");
    let question = world.publish(&session, &task);
    let answered = world.dispatch(&support::corpus_answer_custom(
        &session,
        "served-first",
        &task,
        &question,
        "steps",
        json!(4701),
    ));
    assert!(
        answered["error"].is_null(),
        "the answer commits and the step pauses: {answered}"
    );
    let current = world.dispatch(&support::corpus_question_current(
        &session,
        &task,
        json!(4702),
    ));
    let served_question: Question = serde_json::from_value(current["result"]["question"].clone())
        .expect("the pending choice question");
    let paused_attempt = sent.lock().expect("wire log lock")[0].attempt_id.clone();
    assert!(
        world.runtime.broker.admission(&paused_attempt).is_some(),
        "the choice-pending attempt is admitted"
    );

    // Free text on the served question pays a fresh dispatch, and the
    // send supersedes the pause: its admission is tombstoned.
    let custom = world.dispatch(&support::corpus_answer_custom(
        &session,
        "served-pick",
        &task,
        &served_question,
        "read the scoped file",
        json!(4703),
    ));
    assert!(
        custom["error"].is_null(),
        "the custom answer commits and the step completes: {custom}"
    );
    assert_eq!(
        custom["result"]["snapshot"]["lifecycle"].as_str(),
        Some("completed"),
        "the fresh dispatch completed the read: {custom}"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        2,
        "the custom answer dispatched a fresh manifest"
    );
    assert_eq!(world.runtime.provider_calls, 1);
    assert!(
        world.runtime.broker.admission(&paused_attempt).is_none(),
        "the superseding send tombstoned the paused admission"
    );
    assert!(
        !world.runtime.paused_attempts.contains_key(&task.0),
        "the pause record drained with the settle"
    );
}

/// A live pause on a tree that settles unanswered is dead residue: the
/// late answer to the still-pending served question stays durable but
/// grows nothing runnable, and the resume tombstones the paused
/// attempt — its admission cancelled so the frozen manifest can never
/// dispatch — while the settle journals under the state machine's own
/// origin, never the operator's.
#[test]
fn answer_on_a_settled_tree_tombstones_the_live_pause() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let provider = RecordingProvider {
        inner: LoopbackProvider::new(),
        sent: sent.clone(),
        script: Arc::new(Mutex::new(
            vec![Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            })]
            .into(),
        )),
        inner_attempts: Arc::new(AtomicU64::new(0)),
        inner_retries: 0,
    };
    let mut world = support::open_world_with(
        "dead-tree-pause",
        Some(&fallback_config("fallback = { mode = \"manual\" }")),
        Box::new(provider),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-first-task-marker\n").expect("scoped file");
    world.runtime.purpose = "relay".to_string();
    world.runtime.set_read_scope(scope, file);

    let session = world.open_session("dead-tree-pause-boot");
    let task = world.create_task(&session, "dead-tree-pause-choice");
    let question = world.publish(&session, &task);
    let answered = world.dispatch(&support::corpus_answer_custom(
        &session,
        "dead-tree-first",
        &task,
        &question,
        "steps",
        json!(4801),
    ));
    assert!(
        answered["error"].is_null(),
        "the answer commits and the step pauses: {answered}"
    );
    let current = world.dispatch(&support::corpus_question_current(
        &session,
        &task,
        json!(4802),
    ));
    let served_question: Question = serde_json::from_value(current["result"]["question"].clone())
        .expect("the pending choice question");
    let paused_attempt = sent.lock().expect("wire log lock")[0].attempt_id.clone();
    assert!(
        world.runtime.broker.admission(&paused_attempt).is_some(),
        "the choice-pending attempt is admitted"
    );
    assert!(
        world.runtime.paused_attempts.contains_key(&task.0),
        "the pause binds the served question"
    );

    // The tree drains while the served question stays pending — the
    // task row itself is untouched, so the late answer still commits;
    // only the scheduler refuses to grow runnable work for it.
    world
        .runtime
        .scheduler
        .cancel_task_tree(&task)
        .expect("tree cancel drains");

    // The option answer names a served candidate — the pick that would
    // spend the frozen manifest on a live tree. Here the resume finds
    // the tree dead: the answer stays durable, the paused attempt is
    // tombstoned, and the row settles cancelled through the state
    // machine's own seam.
    let late = world.dispatch(&support::corpus_answer_option(
        &session,
        "dead-tree-answer",
        &task,
        &served_question,
        "reserve",
        json!(4803),
    ));
    assert!(
        late["error"].is_null(),
        "the answer on the dead tree still commits: {late}"
    );
    assert_eq!(
        late["result"]["status"], "applied",
        "the answer stays durable: {late}"
    );
    assert_eq!(
        late["result"]["snapshot"]["lifecycle"], "cancelled",
        "the wire response reports the terminal snapshot: {late}"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        1,
        "the dead tree never dispatched the frozen manifest"
    );
    assert_eq!(world.runtime.provider_calls, 0);
    assert!(
        world.runtime.broker.admission(&paused_attempt).is_none(),
        "the settle tombstoned the paused admission"
    );
    assert!(
        !world.runtime.paused_attempts.contains_key(&task.0),
        "the pause record drained with the settle"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .snapshot(&task)
            .expect("snapshot")
            .lifecycle,
        rivect::contracts::Lifecycle::Cancelled,
        "durable state agrees the row settled"
    );
    // Both commits stay durable in commit order: the answer that paused
    // the task and the late answer the dead tree could not spend.
    let attempts = world
        .runtime
        .store()
        .answer_attempts(&task)
        .expect("attempts");
    assert_eq!(attempts.len(), 2);
    assert!(
        attempts
            .iter()
            .all(|attempt| attempt.outcome == rivect::contracts::AnswerAttemptOutcome::Applied),
        "the committed answers stay durable: {attempts:?}"
    );
    let feed = world
        .runtime
        .store()
        .events_after(&session, Some(&task), 0, 100)
        .expect("task feed");
    let kills: Vec<&rivect::contracts::Event> = feed
        .iter()
        .filter(|event| event.event_type == "task.cancelled")
        .collect();
    assert_eq!(kills.len(), 1, "{feed:?}");
    assert!(
        kills[0].delta["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("settled or cancelled")),
        "the settle reason names the dead tree: {:?}",
        kills[0].delta
    );
    assert_eq!(
        kills[0].origin, "state",
        "a scheduler-driven settle must not impersonate the operator: {feed:?}"
    );
}

/// A task that pauses twice keeps only the latest pause: the fresh
/// pending choice serves its own question, the re-pause replaces the
/// record, and the superseded manifest's admission is cancelled with
/// it so the earlier frozen request can never replay beside its
/// successor.
#[test]
fn a_second_pending_fallback_supersedes_the_pause_and_cancels_its_admission() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let provider = RecordingProvider {
        inner: LoopbackProvider::new(),
        sent: sent.clone(),
        script: Arc::new(Mutex::new(
            vec![
                Respond::Fail(ProviderError::UnknownConnection {
                    connection: "local".to_string(),
                }),
                Respond::Fail(ProviderError::UnknownConnection {
                    connection: "local".to_string(),
                }),
            ]
            .into(),
        )),
        inner_attempts: Arc::new(AtomicU64::new(0)),
        inner_retries: 0,
    };
    let mut world = support::open_world_with(
        "re-pause",
        Some(&fallback_config("fallback = { mode = \"manual\" }")),
        Box::new(provider),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-first-task-marker\n").expect("scoped file");
    world.runtime.purpose = "relay".to_string();
    world.runtime.set_read_scope(scope, file);

    let session = world.open_session("re-pause-boot");
    let task = world.create_task(&session, "re-pause-choice");
    let question = world.publish(&session, &task);
    let answered = world.dispatch(&support::corpus_answer_custom(
        &session,
        "re-pause-first",
        &task,
        &question,
        "steps",
        json!(4901),
    ));
    assert!(
        answered["error"].is_null(),
        "the answer commits and the step pauses: {answered}"
    );
    let current = world.dispatch(&support::corpus_question_current(
        &session,
        &task,
        json!(4902),
    ));
    let first_question: Question = serde_json::from_value(current["result"]["question"].clone())
        .expect("the first pending choice question");
    let first_attempt = sent.lock().expect("wire log lock")[0].attempt_id.clone();
    assert!(
        world.runtime.broker.admission(&first_attempt).is_some(),
        "the first choice-pending attempt is admitted"
    );

    // Free text on the served question pays a fresh dispatch that also
    // fails pending: the second choice publishes and the re-pause
    // supersedes — the first manifest's admission must die with its
    // record, never linger spendable beside the successor.
    let reanswered = world.dispatch(&support::corpus_answer_custom(
        &session,
        "re-pause-second",
        &task,
        &first_question,
        "try the reserve connection instead",
        json!(4903),
    ));
    assert!(
        reanswered["error"].is_null(),
        "the second answer commits and pauses again: {reanswered}"
    );
    assert_eq!(
        reanswered["result"]["snapshot"]["lifecycle"].as_str(),
        Some("waiting"),
        "the re-pause waits on the second choice: {reanswered}"
    );
    let second_attempt = sent.lock().expect("wire log lock")[1].attempt_id.clone();
    assert_ne!(
        first_attempt, second_attempt,
        "each dispatch freezes its own manifest"
    );
    assert!(
        world.runtime.broker.admission(&first_attempt).is_none(),
        "the superseded manifest's admission was cancelled with its record"
    );
    assert!(
        world.runtime.broker.admission(&second_attempt).is_some(),
        "the second pause's admission is live for its own pick"
    );

    // The map holds only the successor pause, bound to the question the
    // second pending choice served.
    let current = world.dispatch(&support::corpus_question_current(
        &session,
        &task,
        json!(4904),
    ));
    let second_question: Question = serde_json::from_value(current["result"]["question"].clone())
        .expect("the second pending choice question");
    assert_ne!(
        first_question.question_id, second_question.question_id,
        "the second pending choice serves its own question"
    );
    let paused = world
        .runtime
        .paused_attempts
        .get(&task.0)
        .expect("the re-pause record survives");
    assert_eq!(paused.manifest.attempt_id, second_attempt);
    assert_eq!(paused.served_question_id, Some(second_question.question_id));
    assert_eq!(world.runtime.provider_calls, 0);
    assert_eq!(world.runtime.broker.accounted_requests(), 0);
}

/// AC-045: `mode = "off"` never substitutes — the provider's own error
/// surfaces typed, the task stays paused on its admission, and an
/// operator retry of the same frozen manifest resumes the intent.
#[test]
fn fallback_off_never_substitutes_and_leaves_the_task_paused() {
    let config =
        Config::parse_validated(&fallback_config("fallback = { mode = \"off\" }")).expect("valid");
    let (mut broker, sent, _inner) = scripted_broker(
        vec![
            Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            }),
            Respond::Delegate,
        ],
        0,
    );
    let manifest = broker
        .prepare("relay", &config, "/world/off", "goal: off")
        .expect("manifest");
    let error = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/off", &manifest)
        .expect_err("off never substitutes");
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::UnknownConnection { connection })
                if connection == "local"
        ),
        "off reports the provider's own error: {error}"
    );
    assert!(
        error.to_string().contains("unknown connection local"),
        "the denial names the missing id: {error}"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        1,
        "no substitute was sent"
    );
    assert!(broker.pending_choice(&manifest.attempt_id).is_none());
    assert_eq!(broker.accounted_requests(), 0, "nothing spent");
    assert!(
        broker.admission(&manifest.attempt_id).is_some(),
        "the task stays paused on its admission — the intent survives for a retry"
    );

    // the paused attempt retries the same frozen manifest
    let reply = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/off", &manifest)
        .expect("the paused attempt retries the same manifest");
    assert!(!reply.text.is_empty());
    assert_eq!(sent.lock().expect("wire log lock").len(), 2);
    assert_eq!(broker.accounted_requests(), 1);
}

/// AC-045b: every rejection cause is honored at send time — a candidate
/// that fails the current eligibility check never receives the request,
/// even when it passed at prepare. The check reads the broker's CURRENT
/// view: a connection removed after prepare rejects as unknown.
#[test]
fn fallback_candidate_failing_eligibility_or_egress_never_receives_the_request() {
    let mut config = Config::parse_validated(&fallback_config(
        "eligible = [\"local\", \"reserve\", \"denied\", \"web\", \"gone\", \"vanishing\"]\n\
         fallback = { mode = \"auto\", chain = [\
             { mode = \"fixed\", connection = \"gone\", model_id = \"gone-model\" }, \
             { mode = \"fixed\", connection = \"web\", model_id = \"web-model\" }, \
             { mode = \"fixed\", connection = \"denied\", model_id = \"denied-model\" }, \
             { mode = \"fixed\", connection = \"shadowed\", model_id = \"shadowed-model\" }, \
             { mode = \"fixed\", connection = \"vanishing\", model_id = \"vanishing-model\" }, \
             { mode = \"fixed\", connection = \"reserve\", model_id = \"reserve-model\" }] }\n\
         [connections.vanishing]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11439\"",
    ))
    .expect("valid");
    // `gone` was declared so the chain validates, but the retained
    // config never admitted it — the current check rejects it
    config.connections.remove("gone");

    let (mut broker, sent, _inner) = scripted_broker(
        vec![
            Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            }),
            Respond::Delegate,
        ],
        0,
    );
    // account rights deny `denied`; every other declared connection is
    // entitled
    broker.set_account_rights(&[
        "local".to_string(),
        "reserve".to_string(),
        "web".to_string(),
        "gone".to_string(),
        "shadowed".to_string(),
        "vanishing".to_string(),
    ]);
    let manifest = broker
        .prepare("relay", &config, "/world/eligible", "goal: eligibility")
        .expect("manifest");
    // the current check is live: `vanishing` passes at prepare, then
    // the config edit removes it before dispatch
    let mut edited = config.clone();
    edited.connections.remove("vanishing");
    broker.set_config(&edited);

    broker
        .dispatch(&mut rivect::model::NullLedger, "/world/eligible", &manifest)
        .expect("the admitted reserve answers after every rejection");

    let sent = sent.lock().expect("wire log lock");
    assert_eq!(
        sent.len(),
        2,
        "only the primary and the admitted reserve were sent"
    );
    assert_eq!(sent[0], manifest);
    assert_eq!(
        sent[1].model,
        ModelAssign::Fixed(FixedModel {
            connection: "reserve".to_string(),
            model_id: "reserve-model".to_string(),
        }),
        "every ineligible candidate was skipped without a send"
    );
}

/// EDGE-004 + AC-045: an adapter's inner retries ride inside the one
/// physical send — the shared outer cap is spent once — and a cancelled
/// attempt is never resurrected by a retry or a late callback.
#[test]
fn adapter_inner_retries_spend_the_shared_outer_cap_and_never_resurrect_a_cancelled_attempt() {
    let config = Config::parse_validated(&fallback_config(
        "fallback = { mode = \"auto\", chain = [] }",
    ))
    .expect("valid");
    let (mut broker, sent, inner_attempts) = scripted_broker(vec![Respond::Delegate], 3);
    let manifest = broker
        .prepare("relay", &config, "/world/retry", "goal: shared cap")
        .expect("manifest");
    broker
        .dispatch(&mut rivect::model::NullLedger, "/world/retry", &manifest)
        .expect("dispatch");
    assert_eq!(
        inner_attempts.load(Ordering::SeqCst),
        3,
        "the adapter's three inner tries rode inside one physical send"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        1,
        "inner retries never mint a second physical send"
    );
    assert_eq!(
        broker.accounted_requests(),
        1,
        "the shared outer cap is spent once, not once per inner try"
    );

    // a cancelled attempt is never resurrected by a late callback
    let doomed = broker
        .prepare("relay", &config, "/world/retry", "goal: cancelled")
        .expect("manifest");
    assert!(broker.cancel_attempt(&doomed.attempt_id));
    let late = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/retry", &doomed)
        .expect_err("a cancelled attempt never re-dispatches");
    assert!(
        matches!(&late, ModelError::AttemptCancelled { attempt_id }
            if attempt_id == &doomed.attempt_id),
        "wrong rejection: {late}"
    );
    let again = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/retry", &doomed)
        .expect_err("the cancellation stays authoritative");
    assert!(
        matches!(&again, ModelError::AttemptCancelled { .. }),
        "wrong rejection: {again}"
    );
    assert_eq!(sent.lock().expect("wire log lock").len(), 1);
    assert_eq!(
        inner_attempts.load(Ordering::SeqCst),
        3,
        "the cancelled callback ran no inner retries"
    );
    assert_eq!(broker.accounted_requests(), 1);
}

/// EDGE-004: cancellation is authoritative before any send, clears a
/// pending manual choice, and stays distinct from a spent attempt.
#[test]
fn cancel_then_late_provider_callback_produces_no_new_dispatch_or_effect() {
    let config = Config::parse_validated(&fallback_config("fallback = { mode = \"manual\" }"))
        .expect("valid");
    let (mut broker, sent, _inner) = scripted_broker(
        vec![
            Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            }),
            Respond::Delegate,
        ],
        0,
    );

    // cancel before any send: the admission dies, nothing dispatches
    let manifest = broker
        .prepare("relay", &config, "/world/cancel", "goal: pre-send cancel")
        .expect("manifest");
    assert!(broker.cancel_attempt(&manifest.attempt_id));
    let late = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/cancel", &manifest)
        .expect_err("a cancelled attempt never dispatches");
    assert!(
        matches!(&late, ModelError::AttemptCancelled { attempt_id }
            if attempt_id == &manifest.attempt_id),
        "wrong rejection: {late}"
    );
    assert!(sent.lock().expect("wire log lock").is_empty());
    assert_eq!(broker.accounted_requests(), 0);
    assert!(broker.admission(&manifest.attempt_id).is_none());

    // a failed manual attempt records a pending choice; cancelling the
    // attempt clears it — a late human answer never dispatches
    let manual = broker
        .prepare(
            "relay",
            &config,
            "/world/cancel",
            "goal: pending choice cancel",
        )
        .expect("manifest");
    let pending_error = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/cancel", &manual)
        .expect_err("manual records the choice");
    assert!(matches!(
        &pending_error,
        ModelError::ManualFallbackPending { .. }
    ));
    assert!(broker.pending_choice(&manual.attempt_id).is_some());
    assert!(broker.cancel_attempt(&manual.attempt_id));
    assert!(
        broker.pending_choice(&manual.attempt_id).is_none(),
        "the pending choice dies with its attempt"
    );
    assert_eq!(sent.lock().expect("wire log lock").len(), 1);

    // a completed attempt answers spent, never cancelled
    let done = broker
        .prepare("relay", &config, "/world/cancel", "goal: done")
        .expect("manifest");
    broker
        .dispatch(&mut rivect::model::NullLedger, "/world/cancel", &done)
        .expect("dispatch");
    assert!(
        !broker.cancel_attempt(&done.attempt_id),
        "a spent attempt is not cancelled"
    );
    let replay = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/cancel", &done)
        .expect_err("the spent attempt reports spent, not cancelled");
    assert!(
        matches!(&replay, ModelError::AttemptAlreadyAccounted { attempt_id }
            if attempt_id == &done.attempt_id),
        "wrong rejection: {replay}"
    );
}

/// AC-045: an auto chain whose every entry fails pauses honestly — the
/// typed rejection names each skipped candidate with its cause, in chain
/// order: catalogue removal, the offline live-grant rule, the account
/// entitlement, the per-purpose eligible list, and a candidate that
/// passed the re-check but failed its own send. The intent stays
/// admitted for a retry, and nothing was spent on the rejected entries.
#[test]
fn exhausted_fallback_chain_pauses_honestly_with_intent_effects_and_budget_preserved() {
    let mut config = Config::parse_validated(&fallback_config(
        "eligible = [\"local\", \"gone\", \"web\", \"denied\", \"reserve\"]\n\
         fallback = { mode = \"auto\", chain = [\
             { mode = \"fixed\", connection = \"gone\", model_id = \"gone-model\" }, \
             { mode = \"fixed\", connection = \"web\", model_id = \"web-model\" }, \
             { mode = \"fixed\", connection = \"denied\", model_id = \"denied-model\" }, \
             { mode = \"fixed\", connection = \"shadowed\", model_id = \"shadowed-model\" }, \
             { mode = \"fixed\", connection = \"reserve\", model_id = \"reserve-model\" }] }",
    ))
    .expect("valid");
    // `gone` was declared so the chain validates, then removed — the
    // current check reports it unknown
    config.connections.remove("gone");
    let (mut broker, sent, _inner) = scripted_broker(
        vec![
            Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            }),
            Respond::Fail(ProviderError::UnknownConnection {
                connection: "reserve".to_string(),
            }),
            Respond::Delegate,
        ],
        0,
    );
    // every declared connection holds rights except `denied`
    broker.set_account_rights(&[
        "local".to_string(),
        "gone".to_string(),
        "web".to_string(),
        "shadowed".to_string(),
        "reserve".to_string(),
    ]);
    let manifest = broker
        .prepare(
            "relay",
            &config,
            "/world/exhausted",
            "goal: exhausted chain",
        )
        .expect("manifest");
    let error = broker
        .dispatch(
            &mut rivect::model::NullLedger,
            "/world/exhausted",
            &manifest,
        )
        .expect_err("the exhausted chain pauses instead of dispatching");
    // the rejection vector is exact: every skipped entry in chain order
    // with its typed cause — only `reserve` ever reached a send
    assert!(
        matches!(&error, ModelError::FallbackExhausted {
            attempt_id, purpose, rejected, attempted, ..
        } if attempt_id == &manifest.attempt_id
            && purpose == "relay"
            && attempted == &vec!["reserve".to_string()]
            && matches!(rejected.as_slice(), [
                CandidateRejection {
                    connection: connection_0,
                    cause: RejectionCause::UnknownConnection,
                },
                CandidateRejection {
                    connection: connection_1,
                    cause: RejectionCause::LiveGrantRequired { kind: ConnKind::ApiKey },
                },
                CandidateRejection {
                    connection: connection_2,
                    cause: RejectionCause::NotEntitled,
                },
                CandidateRejection {
                    connection: connection_3,
                    cause: RejectionCause::NotPurposeEligible,
                },
                CandidateRejection {
                    connection: connection_4,
                    cause: RejectionCause::SendFailed(ProviderError::UnknownConnection {
                        connection: connection_5,
                    }),
                },
            ] if connection_0 == "gone" && connection_1 == "web" && connection_2 == "denied" && connection_3 == "shadowed" && connection_4 == "reserve" && connection_5 == "reserve")),
        "wrong rejection: {error}"
    );
    // the display carries the same refusal the typed fields hold:
    // every rejected candidate with its gate, then the attempted sends
    let display = error.to_string();
    assert!(
        display.contains(
            "rejected gone: connection no longer declared, \
             web: api_key connection requires a separate live grant, \
             denied: outside the account entitlement, \
             shadowed: outside the purpose's eligible list, \
             reserve: send failed: provider capability unavailable: model references unknown connection reserve"
        ),
        "the exhausted display names each rejected candidate and its gate: {display}"
    );
    assert!(
        display.contains("attempted reserve"),
        "the exhausted display names the send that ran: {display}"
    );
    // the typed provider cause stays on the error chain — the variant
    // heap-boxes the source so `ModelError` stays small, so the chain node
    // is `Box<ProviderError>` whose payload is still the typed error
    let source = std::error::Error::source(&error)
        .and_then(|source| source.downcast_ref::<Box<ProviderError>>());
    assert!(
        matches!(
            source.map(|boxed| &**boxed),
            Some(ProviderError::UnknownConnection { connection }) if connection == "local"
        ),
        "the primary provider error stays typed on the error chain"
    );

    // intent, effects and budget preserved: the paused attempt stays
    // admitted, only the attempted reserve ever sent — and failed —
    // nothing is accounted
    assert!(broker.admission(&manifest.attempt_id).is_some());
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        2,
        "the primary and the one admitted substitute — nothing else sent"
    );
    assert_eq!(broker.accounted_requests(), 0);
    assert!(broker.pending_choice(&manifest.attempt_id).is_none());

    // an operator retry resumes the same frozen intent
    broker
        .dispatch(
            &mut rivect::model::NullLedger,
            "/world/exhausted",
            &manifest,
        )
        .expect("the paused attempt retries the same manifest");
    assert_eq!(sent.lock().expect("wire log lock").len(), 3);
    assert_eq!(broker.accounted_requests(), 1);

    let request = reqwest::blocking::Client::builder().no_proxy().build().expect("client")
        .get("ftp://fixture-user:fixture-secret@127.0.0.1/private-path?token=fixture-query#fixture-fragment")
        .send().expect_err("the unsupported scheme is refused without network access");
    assert!(request.is_builder());
    let original = ProviderError::Transport {
        connection: "local".to_string(),
        cause: TransportCause::Request {
            source: Arc::new(request.without_url()),
        },
    };
    let (mut broker, sent, _inner) = scripted_broker(
        vec![
            Respond::Fail(original.clone()),
            Respond::Fail(ProviderError::UnknownConnection {
                connection: "reserve".to_string(),
            }),
        ],
        0,
    );
    drop(original);
    broker.set_account_rights(&[
        "local".to_string(),
        "gone".to_string(),
        "web".to_string(),
        "shadowed".to_string(),
        "reserve".to_string(),
    ]);
    let manifest = broker
        .prepare(
            "relay",
            &config,
            "/world/transport-exhausted",
            "goal: retained source",
        )
        .expect("manifest");
    let error = broker
        .dispatch(
            &mut rivect::model::NullLedger,
            "/world/transport-exhausted",
            &manifest,
        )
        .expect_err("the typed transport primary exhausts the same chain");
    let ModelError::FallbackExhausted {
        attempt_id,
        purpose,
        rejected,
        attempted,
        source,
    } = &error
    else {
        panic!("expected exhaustion");
    };
    assert_eq!(attempt_id, &manifest.attempt_id);
    assert_eq!(purpose, "relay");
    assert_eq!(attempted, &["reserve"]);
    assert!(matches!(rejected.as_slice(), [
        CandidateRejection { connection: gone, cause: RejectionCause::UnknownConnection },
        CandidateRejection { connection: web, cause: RejectionCause::LiveGrantRequired { kind: ConnKind::ApiKey } },
        CandidateRejection { connection: denied, cause: RejectionCause::NotEntitled },
        CandidateRejection { connection: shadowed, cause: RejectionCause::NotPurposeEligible },
        CandidateRejection { connection: reserve, cause: RejectionCause::SendFailed(ProviderError::UnknownConnection { connection: failed }) },
    ] if gone == "gone" && web == "web" && denied == "denied" && shadowed == "shadowed" && reserve == "reserve" && failed == "reserve"));
    let ProviderError::Transport { connection, cause } = source.as_ref() else {
        panic!("the primary transport error stays typed");
    };
    assert_eq!(connection, "local");
    assert_eq!(cause.class(), TransportClass::RequestFailure);
    let retained = std::error::Error::source(&error)
        .and_then(|source| source.downcast_ref::<Box<ProviderError>>())
        .expect("the broker retains its primary source");
    let cause = std::error::Error::source(retained.as_ref())
        .and_then(|source| source.downcast_ref::<TransportCause>())
        .expect("the primary retains the transport cause");
    let leaf = std::error::Error::source(cause)
        .and_then(|source| source.downcast_ref::<reqwest::Error>())
        .expect("the broker preserves the concrete request error after original drop");
    assert!(leaf.is_builder());
    assert!(!leaf.is_timeout());
    assert!(leaf.url().is_none());
    assert!(broker.admission(&manifest.attempt_id).is_some());
    assert!(broker.pending_choice(&manifest.attempt_id).is_none());
    assert_eq!(broker.accounted_requests(), 0);
    {
        let sent = sent.lock().expect("wire log lock");
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0], manifest);
        assert_eq!(sent[1].inputs, manifest.inputs);
        assert_eq!(sent[1].instructions, manifest.instructions);
        assert_eq!(
            sent[1].model,
            ModelAssign::Fixed(FixedModel {
                connection: "reserve".to_string(),
                model_id: "reserve-model".to_string()
            })
        );
    }
    let rejection = RejectionCause::SendFailed(source.as_ref().clone());
    let controller = rivect::controller::ControllerError::Model(error);
    assert_eq!(
        controller.error_code(),
        rivect::contracts::ErrorCode::Denied
    );
    let rivect::controller::ControllerError::Model(model) = &controller else {
        panic!("expected model error");
    };
    for rendered in [
        format!("{rejection}"),
        format!("{rejection:?}"),
        format!("{model}"),
        format!("{model:?}"),
        format!("{controller}"),
        format!("{controller:?}"),
    ] {
        for sentinel in [
            "fixture-user",
            "fixture-secret",
            "private-path",
            "fixture-query",
            "fixture-fragment",
        ] {
            assert!(
                !rendered.contains(sentinel),
                "composed diagnostics exposed source material"
            );
        }
    }
    for (model, expected) in [
        (
            ModelError::Config(
                Config::parse_validated("config_version = 0")
                    .expect_err("the unsupported configuration version is rejected"),
            ),
            rivect::contracts::ErrorCode::CapabilityUnavailable,
        ),
        (
            ModelError::Provider(ProviderError::Transport {
                connection: "local".to_string(),
                cause: TransportCause::Status {
                    status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
                },
            }),
            rivect::contracts::ErrorCode::Denied,
        ),
        (
            ModelError::Provider(ProviderError::UnsupportedParameter {
                connection: "local".to_string(),
                parameter: "temperature",
                model: "fixture-chat-model".to_string(),
            }),
            rivect::contracts::ErrorCode::InvalidInput,
        ),
        (
            ModelError::Provider(ProviderError::EndpointRequired {
                connection: "cloudflare-ai-gateway".to_string(),
            }),
            rivect::contracts::ErrorCode::InvalidInput,
        ),
        (
            ModelError::ManualFallbackPending {
                attempt_id: "attempt".to_string(),
                purpose: "relay".to_string(),
            },
            rivect::contracts::ErrorCode::DependencyBlocked,
        ),
        (
            ModelError::ManualChoiceRejected {
                attempt_id: "attempt".to_string(),
                connection: "reserve".to_string(),
                cause: RejectionCause::NotOffered,
            },
            rivect::contracts::ErrorCode::CapabilityUnavailable,
        ),
        (
            ModelError::NoEligibleCandidate {
                purpose: "relay".to_string(),
                rejected: Vec::new(),
            },
            rivect::contracts::ErrorCode::CapabilityUnavailable,
        ),
        (
            ModelError::RequestTooLarge {
                limit: 1,
                actual: 2,
            },
            rivect::contracts::ErrorCode::ContextOverflow,
        ),
    ] {
        assert_eq!(
            rivect::controller::ControllerError::Model(model).error_code(),
            expected
        );
    }

    {
        use rivect::contracts::{AnswerSelection, TaskId};
        use rivect::controller::{ControllerError, step_error_observation};
        use rivect::scheduler::Scheduler;
        use rivect::supervisor::{StallCause, Supervisor, SupervisorPolicy};
        use std::io::{Read, Write};
        use std::sync::mpsc::{RecvTimeoutError, sync_channel};
        use std::time::{Duration, Instant};

        #[derive(Clone, Copy)]
        enum PeerFault {
            RequestTimeout,
            RequestFailure,
            DecodeTimeout,
            DecodeFailure,
            BodyFailure,
        }

        fn capture_peer_error(fault: PeerFault) -> reqwest::Error {
            let peer_bound = Duration::from_millis(3000);
            let teardown_bound = Duration::from_millis(5000);
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.set_nonblocking(true).expect("nonblocking");
            let address = listener.local_addr().expect("address");
            let client = reqwest::blocking::Client::builder()
                .no_proxy()
                .timeout(Duration::from_millis(500))
                .build()
                .unwrap_or_else(|_error| panic!("fixture client construction failed"));
            let (observed_tx, observed_rx) = sync_channel(1);
            let (release_tx, release_rx) = sync_channel(1);
            let peer = std::thread::spawn(move || -> std::io::Result<usize> {
                let started = Instant::now();
                let remaining = || {
                    peer_bound.checked_sub(started.elapsed()).ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "fixture watchdog expired",
                        )
                    })
                };
                let mut stream = loop {
                    remaining()?;
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::yield_now()
                        }
                        Err(error) => return Err(error),
                    }
                };
                // Darwin inherits the listener's nonblocking flag on accept.
                stream.set_nonblocking(false)?;
                let mut headers = Vec::new();
                while !headers.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    stream.set_read_timeout(Some(remaining()?))?;
                    let mut chunk = [0; 1024];
                    let count = stream.read(&mut chunk)?;
                    if count == 0 || headers.len() + count > 64 * 1024 {
                        return Err(std::io::Error::other(
                            "fixture request headers incomplete or oversized",
                        ));
                    }
                    headers.extend_from_slice(&chunk[..count]);
                }
                observed_tx.send(1).map_err(std::io::Error::other)?;
                let response: &[u8] = match fault {
                    PeerFault::RequestTimeout => b"",
                    PeerFault::RequestFailure => b"invalid-http\r\n\r\n",
                    PeerFault::DecodeFailure => b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n{",
                    PeerFault::DecodeTimeout | PeerFault::BodyFailure => {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx"
                    }
                };
                stream.set_write_timeout(Some(remaining()?))?;
                stream.write_all(response)?;
                let stream =
                    if matches!(fault, PeerFault::RequestTimeout | PeerFault::DecodeTimeout) {
                        Some(stream)
                    } else {
                        drop(stream);
                        None
                    };
                match release_rx.recv_timeout(remaining()?) {
                    Ok(()) => {}
                    Err(RecvTimeoutError::Timeout) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "fixture release watchdog expired",
                        ));
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        return Err(std::io::Error::other("fixture release disconnected"));
                    }
                }
                drop(stream);
                let mut requests = 1;
                loop {
                    remaining()?;
                    match listener.accept() {
                        Ok((stream, _)) => {
                            requests += 1;
                            drop(stream);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error),
                    }
                }
                Ok(requests)
            });
            let captured = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match client
                .get(format!("http://{address}/fixture"))
                .send()
            {
                Err(error) => error,
                Ok(response) if matches!(fault, PeerFault::DecodeFailure) => {
                    match response.json::<serde_json::Value>() {
                        Err(error) => error,
                        Ok(_) => panic!("the invalid json response unexpectedly decoded"),
                    }
                }
                Ok(mut response) => {
                    let mut body = Vec::new();
                    match response.read_to_end(&mut body) {
                        Err(error) => match error.into_inner() {
                            Some(inner) => match inner.downcast::<reqwest::Error>() {
                                Ok(error) => *error,
                                Err(_unrecognized_source) => {
                                    panic!("Response::read retained a different source type")
                                }
                            },
                            None => {
                                panic!("Response::read did not retain a concrete reqwest error")
                            }
                        },
                        Ok(_) => panic!("the incomplete response unexpectedly completed"),
                    }
                }
            }));
            drop(client);
            let observed = observed_rx.recv_timeout(peer_bound);
            let released = release_tx.try_send(()).is_ok();
            let teardown_started = Instant::now();
            while !peer.is_finished() && teardown_started.elapsed() < teardown_bound {
                std::thread::yield_now();
            }
            assert!(peer.is_finished(), "fixture teardown watchdog expired");
            let completed = peer
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            let requests =
                completed.unwrap_or_else(|_error| panic!("fixture setup or cleanup failed"));
            assert_eq!(requests, 1, "one physical request reached the fixture");
            assert_eq!(
                observed,
                Ok(1),
                "the complete request reached the peer before its response"
            );
            assert!(released, "fixture received the explicit release");
            captured.unwrap_or_else(|panic| std::panic::resume_unwind(panic))
        }

        let builder = reqwest::blocking::Client::builder()
            .no_proxy()
            .build()
            .unwrap_or_else(|_error| panic!("fixture client construction failed"))
            .get("ftp://127.0.0.1/fixture")
            .send();
        let Err(builder) = builder else {
            panic!("unsupported scheme unexpectedly succeeded");
        };
        assert!(
            builder.is_builder() && !builder.is_timeout(),
            "genuine builder error required"
        );
        let request_timeout = capture_peer_error(PeerFault::RequestTimeout);
        assert!(
            request_timeout.is_request() && request_timeout.is_timeout(),
            "genuine request timeout required"
        );
        let request_failure = capture_peer_error(PeerFault::RequestFailure);
        assert!(
            request_failure.is_request() && !request_failure.is_timeout(),
            "genuine non-timeout request failure required"
        );
        let read_request_timeout = capture_peer_error(PeerFault::RequestTimeout);
        let read_request_failure = capture_peer_error(PeerFault::RequestFailure);
        let decode_timeout = capture_peer_error(PeerFault::DecodeTimeout);
        assert!(
            decode_timeout.is_decode() && decode_timeout.is_timeout(),
            "genuine blocking read decode timeout required"
        );
        let decode_failure = capture_peer_error(PeerFault::DecodeFailure);
        assert!(
            decode_failure.is_decode() && !decode_failure.is_timeout(),
            "genuine non-timeout decode failure required"
        );
        let read_decode_timeout = capture_peer_error(PeerFault::DecodeTimeout);
        let read_decode_failure = capture_peer_error(PeerFault::DecodeFailure);
        let body_failure = capture_peer_error(PeerFault::BodyFailure);
        assert!(
            body_failure.is_body() && !body_failure.is_timeout(),
            "genuine response body failure required"
        );
        let read_body_failure = capture_peer_error(PeerFault::BodyFailure);

        let directory = tempfile::tempdir().expect("private fixture directory");
        let first_io = std::fs::File::open(directory.path().join("first-absent"));
        let second_io = std::fs::File::open(directory.path().join("second-absent"));
        let (Err(first_io), Err(second_io)) = (first_io, second_io) else {
            panic!("the absent fixture files unexpectedly opened");
        };
        assert!(
            directory.close().is_ok(),
            "fixture directory cleanup failed"
        );
        assert!(
            first_io.kind() == std::io::ErrorKind::NotFound && first_io.raw_os_error().is_some()
        );
        assert!(
            second_io.kind() == std::io::ErrorKind::NotFound
                && second_io.raw_os_error() == first_io.raw_os_error()
        );
        let io_code = first_io
            .raw_os_error()
            .expect("filesystem error retained its os code");

        let request = |source: reqwest::Error| ProviderError::Transport {
            connection: "local".to_string(),
            cause: TransportCause::Request {
                source: Arc::new(source.without_url()),
            },
        };
        let read = |source: reqwest::Error| ProviderError::Transport {
            connection: "local".to_string(),
            cause: TransportCause::Read {
                source: Arc::new(std::io::Error::other(source.without_url())),
            },
        };
        // Literal legacy groups are the oracle; neither class() nor diagnostic text selects a group.
        let cases = [
            ("builder", 0, request(builder)),
            ("request timeout", 1, request(request_timeout)),
            ("request failure", 1, request(request_failure)),
            ("read request timeout", 1, read(read_request_timeout)),
            ("read request failure", 1, read(read_request_failure)),
            ("request decode timeout", 2, request(decode_timeout)),
            ("request decode failure", 2, request(decode_failure)),
            ("read decode timeout", 2, read(read_decode_timeout)),
            ("read decode failure", 2, read(read_decode_failure)),
            ("request body failure", 3, request(body_failure)),
            ("read body failure", 3, read(read_body_failure)),
            (
                "deadline 500ms",
                4,
                ProviderError::Transport {
                    connection: "local".to_string(),
                    cause: TransportCause::Deadline {
                        budget: Duration::from_millis(500),
                    },
                },
            ),
            (
                "deadline 1000ms",
                5,
                ProviderError::Transport {
                    connection: "local".to_string(),
                    cause: TransportCause::Deadline {
                        budget: Duration::from_millis(1000),
                    },
                },
            ),
            (
                "status 401",
                6,
                ProviderError::Transport {
                    connection: "local".to_string(),
                    cause: TransportCause::Status {
                        status: reqwest::StatusCode::UNAUTHORIZED,
                    },
                },
            ),
            (
                "status 429",
                7,
                ProviderError::Transport {
                    connection: "local".to_string(),
                    cause: TransportCause::Status {
                        status: reqwest::StatusCode::TOO_MANY_REQUESTS,
                    },
                },
            ),
            (
                "status 503",
                8,
                ProviderError::Transport {
                    connection: "local".to_string(),
                    cause: TransportCause::Status {
                        status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
                    },
                },
            ),
            (
                "first filesystem read",
                9,
                ProviderError::Transport {
                    connection: "local".to_string(),
                    cause: TransportCause::Read {
                        source: Arc::new(first_io),
                    },
                },
            ),
            (
                "second filesystem read",
                9,
                ProviderError::Transport {
                    connection: "local".to_string(),
                    cause: TransportCause::Read {
                        source: Arc::new(second_io),
                    },
                },
            ),
        ];
        let task = TaskId("transport-fingerprint".to_string());
        let answer = AnswerSelection::Custom {
            text: "retry unchanged".to_string(),
        };
        let scheduler = Scheduler::new(2, 4);
        for projection in 0..4 {
            let observations: Vec<_> = cases
                .iter()
                .map(|(_, _, error)| {
                    let model = match projection {
                        0 => ModelError::Provider(error.clone()),
                        1 => ModelError::FallbackExhausted {
                            attempt_id: "attempt".to_string(),
                            purpose: "relay".to_string(),
                            rejected: Vec::new(),
                            attempted: vec!["reserve".to_string()],
                            source: Box::new(error.clone()),
                        },
                        2 => ModelError::FallbackExhausted {
                            attempt_id: "attempt".to_string(),
                            purpose: "relay".to_string(),
                            rejected: vec![
                                CandidateRejection {
                                    connection: "first".to_string(),
                                    cause: RejectionCause::SendFailed(error.clone()),
                                },
                                CandidateRejection {
                                    connection: "second".to_string(),
                                    cause: RejectionCause::NotEntitled,
                                },
                            ],
                            attempted: vec!["first".to_string(), "second".to_string()],
                            source: Box::new(ProviderError::UnknownConnection {
                                connection: "local".to_string(),
                            }),
                        },
                        3 => ModelError::ManualChoiceRejected {
                            attempt_id: "attempt".to_string(),
                            connection: "reserve".to_string(),
                            cause: RejectionCause::SendFailed(error.clone()),
                        },
                        _ => unreachable!(),
                    };
                    let controller = ControllerError::Model(model);
                    assert!(
                        controller.error_code()
                            == if projection == 3 {
                                rivect::contracts::ErrorCode::CapabilityUnavailable
                            } else {
                                rivect::contracts::ErrorCode::Denied
                            }
                    );
                    step_error_observation(&task, &answer, &controller)
                })
                .collect();
            for (left, (left_name, left_group, _)) in cases.iter().enumerate() {
                for (right, (right_name, right_group, _)) in cases.iter().enumerate() {
                    let equivalent = left_group == right_group;
                    assert!(
                        (observations[left].signature.result
                            == observations[right].signature.result)
                            == equivalent,
                        "legacy fingerprint quotient changed: projection {projection}, {left_name} vs {right_name}"
                    );

                    for sequence in [
                        vec![left, left, left],
                        vec![left, right, left],
                        vec![left, right, left, right],
                    ] {
                        let mut supervisor =
                            Supervisor::new(SupervisorPolicy::default()).expect("valid policy");
                        let mut fired = 0;
                        for (index, &case) in sequence.iter().enumerate() {
                            let reaction =
                                supervisor.observe(&scheduler, observations[case].clone());
                            let exact =
                                index == 2 && (sequence == vec![left, left, left] || equivalent);
                            let fuzzy = index == 3 && !equivalent;
                            let expected = match (exact, fuzzy) {
                                (true, _) => Some(StallCause::ExactRepeat {
                                    signature: observations[case].signature.clone(),
                                    repeats: 3,
                                }),
                                (_, true) => Some(StallCause::FuzzyRepeat {
                                    signature: observations[case].signature.clone(),
                                    repeats: 4,
                                }),
                                _ => None,
                            };
                            assert!(
                                reaction.as_ref().map(|reaction| &reaction.cause)
                                    == expected.as_ref(),
                                "the sterile sequence fired the wrong cause or count"
                            );
                            assert!(
                                reaction
                                    .as_ref()
                                    .is_none_or(|reaction| reaction.task == task),
                                "the sterile reaction must retain the task"
                            );
                            fired += usize::from(reaction.is_some());
                        }
                        let expected_count = usize::from(
                            sequence.len() == 4 || equivalent || sequence == vec![left, left, left],
                        );
                        assert_eq!(fired, expected_count);
                        assert_eq!(supervisor.reactions(&task).len(), fired);
                    }
                }
                let context: &[&str] = match *left_group {
                    0 => &["builder"],
                    1 => &["request"],
                    2 => &["decode"],
                    3 => &["body"],
                    4 => &["deadline", "500ms"],
                    5 => &["deadline", "1s"],
                    6 => &["status", "401"],
                    7 => &["status", "429"],
                    8 => &["status", "503"],
                    9 => &["read"],
                    _ => unreachable!(),
                };
                for required in context {
                    assert!(
                        observations[left].signature.result.contains(required),
                        "the composed fingerprint lost its safe typed context"
                    );
                }
                if *left_group == 9 {
                    assert!(
                        observations[left]
                            .signature
                            .result
                            .contains(&io_code.to_string()),
                        "the composed read fingerprint lost its os code"
                    );
                }
                for progress in [
                    observations[left].clone().with_new_inputs(),
                    observations[left].clone().with_heartbeat(),
                    observations[left].clone().with_evidence_growth(1),
                ] {
                    let mut supervisor =
                        Supervisor::new(SupervisorPolicy::default()).expect("valid policy");
                    for observation in [
                        observations[left].clone(),
                        observations[left].clone(),
                        progress,
                        observations[left].clone(),
                        observations[left].clone(),
                    ] {
                        assert!(
                            supervisor.observe(&scheduler, observation).is_none(),
                            "progress must reset the sterile run"
                        );
                    }
                    let reaction = supervisor.observe(&scheduler, observations[left].clone());
                    assert!(
                        matches!(reaction.as_ref(), Some(reaction) if matches!(&reaction.cause,
                    StallCause::ExactRepeat { signature, repeats: 3 } if signature == &observations[left].signature)),
                        "three fresh sterile outcomes must fire exactly once after progress"
                    );
                    assert_eq!(supervisor.reactions(&task).len(), 1);
                }
            }
        }
    }
}

/// AC-045: a candidate that passes the re-check but fails its own send
/// is recorded `SendFailed` and the walk continues in chain order — the
/// later admitted entry answers, the skipped entry never received a
/// send, and every admission returns to the baseline count.
#[test]
fn send_failure_walks_the_admitted_chain_in_order() {
    let config = Config::parse_validated(&fallback_config(
        "eligible = [\"local\", \"reserve\", \"denied\", \"shadowed\"]\n\
         fallback = { mode = \"auto\", chain = [\
             { mode = \"fixed\", connection = \"denied\", model_id = \"denied-model\" }, \
             { mode = \"fixed\", connection = \"reserve\", model_id = \"reserve-model\" }, \
             { mode = \"fixed\", connection = \"shadowed\", model_id = \"shadowed-model\" }] }",
    ))
    .expect("valid");
    let (mut broker, sent, _inner) = scripted_broker(
        vec![
            // the primary send fails, then reserve's admitted substitute
            // fails its own send — the walk continues to shadowed
            Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            }),
            Respond::Fail(ProviderError::UnknownConnection {
                connection: "reserve".to_string(),
            }),
            Respond::Delegate,
        ],
        0,
    );
    // `denied` holds no account rights: the walk skips it before any send
    broker.set_account_rights(&[
        "local".to_string(),
        "reserve".to_string(),
        "shadowed".to_string(),
    ]);
    let manifest = broker
        .prepare("relay", &config, "/world/walk", "goal: walk")
        .expect("manifest");
    assert_eq!(broker.admitted_attempts(), 1, "the prepare admits one");
    let reply = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/walk", &manifest)
        .expect("the walk answers through shadowed");
    assert!(!reply.text.is_empty());

    let shadowed_attempt = {
        let sent = sent.lock().expect("wire log lock");
        assert_eq!(
            sent.len(),
            3,
            "primary, reserve substitute, shadowed substitute — denied never sent"
        );
        assert_eq!(&sent[0], &manifest);
        assert_eq!(
            sent[1].model,
            ModelAssign::Fixed(FixedModel {
                connection: "reserve".to_string(),
                model_id: "reserve-model".to_string(),
            })
        );
        assert_eq!(
            sent[2].model,
            ModelAssign::Fixed(FixedModel {
                connection: "shadowed".to_string(),
                model_id: "shadowed-model".to_string(),
            })
        );
        assert_eq!(sent[1].inputs, sent[0].inputs);
        assert_eq!(sent[2].inputs, sent[0].inputs);
        assert_ne!(sent[1].attempt_id, sent[0].attempt_id);
        assert_ne!(sent[2].attempt_id, sent[1].attempt_id);
        sent[2].attempt_id.clone()
    };
    assert_eq!(broker.accounted_requests(), 1);
    assert_eq!(
        broker
            .accounting_record(&shadowed_attempt)
            .expect("the shadowed send is accounted")
            .connection,
        "shadowed"
    );
    assert_eq!(
        broker.admitted_attempts(),
        0,
        "every admission returns to baseline — the failed substitute left none"
    );
}

/// AC-045: a middle chain entry's 503 leaves its outcome unknown, so the
/// walk ends exactly where the primary gate ends — a later entry could
/// duplicate an effect the failed one may already have applied. The last
/// chain entry never receives a request.
#[test]
fn chain_unknown_outcome_stops_before_the_next_entry() {
    let config = Config::parse_validated(&fallback_config(
        "eligible = [\"local\", \"reserve\", \"shadowed\"]\n\
         fallback = { mode = \"auto\", chain = [\
             { mode = \"fixed\", connection = \"reserve\", model_id = \"reserve-model\" }, \
             { mode = \"fixed\", connection = \"shadowed\", model_id = \"shadowed-model\" }] }",
    ))
    .expect("valid");
    let (mut broker, sent, _inner) = scripted_broker(
        vec![
            Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            }),
            Respond::Fail(ProviderError::Transport {
                connection: "reserve".to_string(),
                cause: TransportCause::Status {
                    status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
                },
            }),
        ],
        0,
    );
    let manifest = broker
        .prepare("relay", &config, "/world/unknown-chain", "goal: chain")
        .expect("manifest");
    assert_eq!(
        broker.admitted_attempts(),
        1,
        "the primary is the only live admission before the walk"
    );
    let error = broker
        .dispatch(
            &mut rivect::model::NullLedger,
            "/world/unknown-chain",
            &manifest,
        )
        .expect_err("the middle entry's 503 is unknown");
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::Transport { connection, cause })
                if connection == "reserve"
                    && matches!(cause.class(), TransportClass::HttpStatus { code: 503 })
        ),
        "the middle entry's typed failure ends the walk: {error}"
    );
    assert_eq!(
        broker.admitted_attempts(),
        1,
        "the abandoned substitute leaves no live admission behind"
    );
    // The substitute's provisional epoch minted for the middle entry rolls
    // back with it: a re-prepare of the same prefix replays the epoch
    // bytewise instead of reporting a phantom model switch.
    let replay = broker
        .prepare("relay", &config, "/world/unknown-chain", "goal: chain")
        .expect("the prefix re-prepares");
    assert!(
        replay.mutation_reason.is_none(),
        "no phantom mutation: {:?}",
        replay.mutation_reason
    );
    assert_eq!(
        replay.epoch_id, manifest.epoch_id,
        "the epoch replays bytewise for the unchanged prefix"
    );
    let sent = sent.lock().expect("wire log lock");
    assert_eq!(
        sent.len(),
        2,
        "the primary and the failing middle entry sent; the last entry never did"
    );
    assert_eq!(
        sent[1].model,
        ModelAssign::Fixed(FixedModel {
            connection: "reserve".to_string(),
            model_id: "reserve-model".to_string(),
        })
    );
}

/// AC-045: a provider failure verdict is emitted only after the response
/// started (a terminal incomplete/cancelled event, a non-STOP finish or a
/// mid-stream error), so its effect may already have applied. The auto
/// walk stops before the chain entry is consulted and never sends a
/// substitute.
#[test]
fn post_output_provider_failure_stops_the_walk_before_the_next_entry() {
    let config = Config::parse_validated(&fallback_config(
        "eligible = [\"local\", \"reserve\"]\n\
         fallback = { mode = \"auto\", chain = [\
             { mode = \"fixed\", connection = \"reserve\", model_id = \"reserve-model\" }] }",
    ))
    .expect("valid");
    let (mut broker, sent, _inner) = scripted_broker(
        vec![Respond::Fail(ProviderError::ProviderFailed {
            connection: "local".to_string(),
            reason: "response.cancelled".to_string(),
        })],
        0,
    );
    let manifest = broker
        .prepare("relay", &config, "/world/post-output-chain", "goal: chain")
        .expect("manifest");
    let error = broker
        .dispatch(
            &mut rivect::model::NullLedger,
            "/world/post-output-chain",
            &manifest,
        )
        .expect_err("a post-output failure is an unknown outcome");
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::ProviderFailed { connection, reason })
                if connection == "local" && reason == "response.cancelled"
        ),
        "the caller meets the failure's own class: {error}"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        1,
        "the primary sent; a substitute would repeat a possibly applied effect"
    );
}

/// AC-045: a pre-send request-shape refusal — the over-bound replay
/// body — is definitive, so the auto walk consults the chain and
/// dispatches the admitted substitute instead of stopping as an
/// unknown outcome would. One physical request is accounted, naming the
/// substitute's connection.
#[test]
fn unsendable_request_walks_the_chain_to_a_definitive_substitute() {
    let config = Config::parse_validated(&fallback_config(
        "eligible = [\"local\", \"reserve\"]\n\
         fallback = { mode = \"auto\", chain = [\
             { mode = \"fixed\", connection = \"reserve\", model_id = \"reserve-model\" }] }",
    ))
    .expect("valid");
    let (mut broker, sent, _inner) = scripted_broker(
        vec![
            Respond::Fail(ProviderError::UnsendableRequest {
                connection: "local".to_string(),
                reason: format!(
                    "request body of {} bytes exceeds the {} byte wire bound",
                    MODEL_WIRE_MAX_BYTES + 1,
                    MODEL_WIRE_MAX_BYTES
                ),
            }),
            Respond::Delegate,
        ],
        0,
    );
    let manifest = broker
        .prepare("relay", &config, "/world/unsendable-chain", "goal: chain")
        .expect("manifest");
    let reply = broker
        .dispatch(
            &mut rivect::model::NullLedger,
            "/world/unsendable-chain",
            &manifest,
        )
        .expect("a definitive pre-send refusal never stops the walk");
    assert!(!reply.text.is_empty());
    let substitute_attempt = {
        let sent = sent.lock().expect("wire log lock");
        assert_eq!(
            sent.len(),
            2,
            "the refused primary and the answering substitute sent"
        );
        assert_eq!(
            sent[1].model,
            ModelAssign::Fixed(FixedModel {
                connection: "reserve".to_string(),
                model_id: "reserve-model".to_string(),
            }),
            "the walk dispatched the chain entry"
        );
        assert_eq!(sent[1].inputs, sent[0].inputs);
        sent[1].attempt_id.clone()
    };
    assert_eq!(broker.accounted_requests(), 1);
    assert_eq!(
        broker
            .accounting_record(&substitute_attempt)
            .expect("the substitute send is accounted")
            .connection,
        "reserve"
    );
    assert_eq!(
        broker.admitted_attempts(),
        0,
        "every admission returns to baseline"
    );
}

/// AC-045: the same post-output failure class under a manual fallback
/// still pauses for the human, and the served question carries the
/// machine-readable repeat token.
#[test]
fn manual_pause_on_a_post_output_failure_serves_the_repeat_warning() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let provider = RecordingProvider {
        inner: LoopbackProvider::new(),
        sent: sent.clone(),
        script: Arc::new(Mutex::new(
            vec![Respond::Fail(ProviderError::ProviderFailed {
                connection: "local".to_string(),
                reason: "finishReason OTHER".to_string(),
            })]
            .into(),
        )),
        inner_attempts: Arc::new(AtomicU64::new(0)),
        inner_retries: 0,
    };
    let mut world = support::open_world_with(
        "manual-post-output",
        Some(&fallback_config("fallback = { mode = \"manual\" }")),
        Box::new(provider),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-first-task-marker\n").expect("scoped file");
    world.runtime.purpose = "relay".to_string();
    world.runtime.set_read_scope(scope, file);

    let session = world.open_session("manual-post-output-boot");
    let task = world.create_task(&session, "manual-post-output-choice");
    let question = world.publish(&session, &task);
    let answered = world.dispatch(&support::corpus_answer_custom(
        &session,
        "manual-post-output-first",
        &task,
        &question,
        "steps",
        json!(4501),
    ));
    assert!(
        answered.get("error").is_none(),
        "the answer commits and the step pauses: {answered}"
    );
    let paused = world
        .runtime
        .paused_attempts
        .get(&task.0)
        .expect("the paused attempt is retained");
    assert!(
        paused
            .choice
            .as_ref()
            .is_some_and(|choice| choice.unknown_outcome),
        "a post-output failure is an unknown outcome"
    );
    let current = world.dispatch(&support::corpus_question_current(
        &session,
        &task,
        json!(4502),
    ));
    let served_question: Question =
        serde_json::from_value(current["result"]["question"].clone()).expect("served question");
    assert_eq!(
        served_question.prompt,
        "the pinned dispatch ended without a definitive answer; its effect may have applied before the failure — a substitute send repeats it",
        "the pause discloses the repeat: {served_question:?}"
    );
    assert_eq!(
        served_question.recommendation_basis,
        "unknown-outcome-repeat: a substitute repeats an effect that may have applied",
        "the repeat class is machine-readable: {served_question:?}"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        1,
        "manual never dispatches a substitute while the choice waits"
    );
}

/// AC-045: an adapter-retried send is one physical child whose first leg
/// may have applied. A definitive denial on the second leg is still an
/// unknown outcome, so the walk stops and the last entry never sends.
#[test]
fn retried_send_failure_stops_the_walk_before_the_next_entry() {
    let config = Config::parse_validated(&fallback_config(
        "eligible = [\"local\", \"reserve\", \"shadowed\"]\n\
         fallback = { mode = \"auto\", chain = [\
             { mode = \"fixed\", connection = \"reserve\", model_id = \"reserve-model\" }, \
             { mode = \"fixed\", connection = \"shadowed\", model_id = \"shadowed-model\" }] }",
    ))
    .expect("valid");
    let (mut broker, sent, _inner) = scripted_broker(
        vec![
            Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            }),
            Respond::Fail(ProviderError::Retried {
                wire_retries: 1,
                source: Box::new(ProviderError::Transport {
                    connection: "reserve".to_string(),
                    cause: TransportCause::Status {
                        status: reqwest::StatusCode::BAD_REQUEST,
                    },
                }),
            }),
        ],
        0,
    );
    let manifest = broker
        .prepare("relay", &config, "/world/retried-chain", "goal: chain")
        .expect("manifest");
    let error = broker
        .dispatch(
            &mut rivect::model::NullLedger,
            "/world/retried-chain",
            &manifest,
        )
        .expect_err("a retried leg's effect is unknown");
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::Transport { connection, cause })
                if connection == "reserve"
                    && matches!(cause.class(), TransportClass::HttpStatus { code: 400 })
        ),
        "the caller meets the last leg's own definitive class: {error}"
    );
    let sent = sent.lock().expect("wire log lock");
    assert_eq!(
        sent.len(),
        2,
        "the primary and the retried middle entry sent; the last entry never did"
    );
}

/// AC-061 adjacency: a failed send never mints an epoch — the
/// substitute's provisional mint rolls back, so a re-prepare of the same
/// prefix replays the epoch instead of reporting a phantom model switch.
#[test]
fn failed_send_leaves_no_phantom_epoch() {
    let config = Config::parse_validated(&fallback_config(
        "fallback = { mode = \"auto\", chain = [\
             { mode = \"fixed\", connection = \"reserve\", model_id = \"reserve-model\" }] }",
    ))
    .expect("valid");
    let (mut broker, _sent, _inner) = scripted_broker(
        vec![
            Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            }),
            Respond::Fail(ProviderError::UnknownConnection {
                connection: "reserve".to_string(),
            }),
        ],
        0,
    );
    let manifest = broker
        .prepare("relay", &config, "/world/epoch", "goal: epoch")
        .expect("manifest");
    let error = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/epoch", &manifest)
        .expect_err("the single-entry chain exhausts");
    assert!(
        matches!(&error, ModelError::FallbackExhausted {
            rejected, attempted, ..
        } if attempted == &vec!["reserve".to_string()]
            && matches!(rejected.as_slice(), [CandidateRejection {
                connection: connection_0,
                cause: RejectionCause::SendFailed(ProviderError::UnknownConnection {
                    connection: connection_1,
                }),
            }] if connection_0 == "reserve" && connection_1 == "reserve")),
        "wrong rejection: {error}"
    );

    // the failed substitute's provisional epoch mint rolled back: a
    // re-prepare of the same prefix replays the epoch bytewise — no
    // phantom "model switch" is reported for a send that never landed
    let replay = broker
        .prepare("relay", &config, "/world/epoch", "goal: epoch")
        .expect("re-prepare");
    assert!(
        replay.mutation_reason.is_none(),
        "no phantom mutation: {:?}",
        replay.mutation_reason
    );
    assert_eq!(
        replay.epoch_id, manifest.epoch_id,
        "the epoch replays bytewise for the unchanged prefix"
    );
    assert!(
        broker.admission(&manifest.attempt_id).is_some(),
        "the failed primary stays admitted for a retry"
    );
    assert_eq!(
        broker.admitted_attempts(),
        2,
        "primary and replay prepare — the dead substitute left none"
    );
}

/// AC-045/AC-061 through the manual path: the broker-side pause pin —
/// not the frozen `Manual` flag alone — gates a substitute dispatch,
/// the pick is confined to the candidates the recorded pause served,
/// and a substitute whose send fails rolls its provisional epoch mint
/// back exactly like the auto walk's: the re-prepare replays the epoch,
/// the dead substitute leaves no admission, and the paused primary
/// stays admitted for the retry that still lands.
#[test]
fn manual_substitute_send_failure_restores_epoch_and_prunes_admission() {
    let config = Config::parse_validated(&fallback_config("fallback = { mode = \"manual\" }"))
        .expect("valid");
    let (mut broker, sent, _inner) = scripted_broker(
        vec![
            // the primary send fails into the pause, the picked
            // substitute's own send fails, the retried pick lands
            Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            }),
            Respond::Fail(ProviderError::UnknownConnection {
                connection: "reserve".to_string(),
            }),
            Respond::Delegate,
        ],
        0,
    );
    let manifest = broker
        .prepare("relay", &config, "/world/manual-epoch", "goal: epoch")
        .expect("manifest");

    // the pause pin is the gate: a Manual admission that never paused
    // refuses the substitute dispatch typed — the flag alone authorizes
    // nothing
    let premature = broker
        .dispatch_fallback_choice(
            &mut rivect::model::NullLedger,
            "/world/manual-epoch",
            &manifest.attempt_id,
            "reserve",
        )
        .expect_err("an un-paused Manual admission has no substitute path");
    assert!(
        matches!(&premature, ModelError::NoPendingChoice { .. }),
        "wrong rejection: {premature}"
    );

    let error = broker
        .dispatch(
            &mut rivect::model::NullLedger,
            "/world/manual-epoch",
            &manifest,
        )
        .expect_err("manual records the pending choice");
    assert!(matches!(&error, ModelError::ManualFallbackPending { .. }));
    // the publish path consumes the pending choice — the surviving pin
    // is what still authorizes the human's pick afterwards
    let pending = broker
        .take_pending_choice(&manifest.attempt_id)
        .expect("the recorded pending choice");
    assert!(pending.candidates.contains(&"reserve".to_string()));

    // the pick is confined to the served set: the just-failed primary
    // is never on it, even while it still passes the live check
    let off_menu = broker
        .dispatch_fallback_choice(
            &mut rivect::model::NullLedger,
            "/world/manual-epoch",
            &manifest.attempt_id,
            "local",
        )
        .expect_err("the failed primary was never served");
    assert!(
        matches!(
            &off_menu,
            ModelError::ManualChoiceRejected {
                cause: RejectionCause::NotOffered,
                ..
            }
        ),
        "wrong rejection: {off_menu}"
    );

    let picked = broker
        .dispatch_fallback_choice(
            &mut rivect::model::NullLedger,
            "/world/manual-epoch",
            &manifest.attempt_id,
            "reserve",
        )
        .expect_err("the substitute's send fails");
    assert!(
        matches!(
            &picked,
            ModelError::Provider(ProviderError::UnknownConnection { connection })
                if connection == "reserve"
        ),
        "wrong rejection: {picked}"
    );
    assert_eq!(sent.lock().expect("wire log lock").len(), 2);

    // the failed substitute's provisional epoch mint rolled back: a
    // re-prepare of the same prefix replays the epoch bytewise — no
    // phantom "model switch" is reported for a send that never landed
    let replay = broker
        .prepare("relay", &config, "/world/manual-epoch", "goal: epoch")
        .expect("re-prepare")
        .clone();
    assert!(
        replay.mutation_reason.is_none(),
        "no phantom mutation: {:?}",
        replay.mutation_reason
    );
    assert_eq!(
        replay.epoch_id, manifest.epoch_id,
        "the epoch replays bytewise for the unchanged prefix"
    );
    assert!(
        broker.admission(&manifest.attempt_id).is_some(),
        "the paused primary stays admitted for a retry"
    );
    assert_eq!(
        broker.admitted_attempts(),
        2,
        "primary and replay prepare — the dead substitute left none"
    );

    // the pause survives a failed substitute: the re-pick lands, the
    // consumed pause clears exactly once, and a later answer is refused
    // typed — the spent primary's id never replays either
    broker
        .dispatch_fallback_choice(
            &mut rivect::model::NullLedger,
            "/world/manual-epoch",
            &manifest.attempt_id,
            "reserve",
        )
        .expect("the retried pick dispatches the substitute");
    let refused = broker
        .dispatch_fallback_choice(
            &mut rivect::model::NullLedger,
            "/world/manual-epoch",
            &manifest.attempt_id,
            "reserve",
        )
        .expect_err("the consumed pause refuses a second substitute");
    assert!(
        matches!(&refused, ModelError::NoAdmission { .. }),
        "wrong rejection: {refused}"
    );
}

/// AC-045 edge: a manual fallback whose pause would serve an empty
/// candidate set can never be answered — the pick must name a served
/// member, so a `paused = {}` pin is a wedge, not a question. The
/// broker reports the exhaustion honestly instead: every evaluated
/// connection's typed cause, no pending choice published, and the
/// failed primary's admission stays live for a retry exactly like an
/// exhausted auto chain's.
#[test]
fn manual_fallback_with_no_servable_candidate_exhausts_instead_of_wedging() {
    let config = Config::parse_validated(&fallback_config(
        "eligible = [\"local\"]\nfallback = { mode = \"manual\" }",
    ))
    .expect("valid");
    let (mut broker, sent, _inner) = scripted_broker(
        vec![Respond::Fail(ProviderError::UnknownConnection {
            connection: "local".to_string(),
        })],
        0,
    );
    let manifest = broker
        .prepare("relay", &config, "/world/wedge", "goal: wedge")
        .expect("manifest");
    let error = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/wedge", &manifest)
        .expect_err("a pause with no servable candidate is exhaustion");
    assert!(
        matches!(&error, ModelError::FallbackExhausted {
            attempt_id, purpose, rejected, attempted, ..
        } if attempt_id == &manifest.attempt_id
            && purpose == "relay"
            && attempted.is_empty()
            && matches!(rejected.as_slice(), [
                CandidateRejection {
                    connection: connection_0,
                    cause: RejectionCause::NotPurposeEligible,
                },
                CandidateRejection {
                    connection: connection_1,
                    cause: RejectionCause::NotPurposeEligible,
                },
                CandidateRejection {
                    connection: connection_2,
                    cause: RejectionCause::NotPurposeEligible,
                },
                CandidateRejection {
                    connection: connection_3,
                    cause: RejectionCause::NotPurposeEligible,
                },
                CandidateRejection {
                    connection: connection_4,
                    cause: RejectionCause::LiveGrantRequired { kind: ConnKind::ApiKey },
                },
            ] if connection_0 == "denied" && connection_1 == "gone" && connection_2 == "reserve" && connection_3 == "shadowed" && connection_4 == "web")),
        "the exhaustion names every evaluated candidate's cause: {error}"
    );
    // no question was ever published — nothing can answer an empty set
    assert!(broker.pending_choice(&manifest.attempt_id).is_none());
    // the failed primary stays admitted for a retry — intent, effects
    // and budget preserved, and only the primary ever sent
    assert!(broker.admission(&manifest.attempt_id).is_some());
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        1,
        "the exhausted manual pause dispatched nothing"
    );
    assert_eq!(broker.accounted_requests(), 0);
}

/// AC-045b: the dispatch-time re-check view refreshes only on a
/// successful prepare — a prepare that fails purpose resolution must not
/// steer the retained view with its caller-supplied config.
#[test]
fn a_failed_prepare_never_rewrites_the_dispatch_recheck_view() {
    let config = Config::parse_validated(&fallback_config("fallback = { mode = \"manual\" }"))
        .expect("valid");
    let (mut broker, _sent, _inner) = scripted_broker(
        vec![Respond::Fail(ProviderError::UnknownConnection {
            connection: "local".to_string(),
        })],
        0,
    );
    let manifest = broker
        .prepare("relay", &config, "/world/view", "goal: view")
        .expect("manifest");
    // a prepare whose purpose cannot resolve fails — the retained view
    // must stay the one this successful prepare observed, not the empty
    // caller config the failure carried
    let failed = broker.prepare("relay", &Config::default(), "/world/view", "goal: x");
    assert!(
        matches!(failed, Err(ModelError::Config(_))),
        "a purpose with no defaults fails typed: {failed:?}"
    );
    let error = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/view", &manifest)
        .expect_err("manual pauses on the failed send");
    assert!(matches!(&error, ModelError::ManualFallbackPending { .. }));
    let pending = broker
        .take_pending_choice(&manifest.attempt_id)
        .expect("the pending choice");
    assert_eq!(
        pending.candidates,
        vec![
            "denied".to_string(),
            "gone".to_string(),
            "reserve".to_string(),
            "shadowed".to_string(),
        ],
        "the retained view still names the real catalogue — the failed \
         prepare's empty config never reached it"
    );
}

/// A broken stream after a confirmed tool effect never replays that
/// effect: the spent attempt rejects the re-send outright, and the
/// fallback continuation is a real loopback answer under the
/// substitute's own attempt — the same frozen inputs re-request the
/// read legitimately while neither spent attempt id can dispatch again.
#[test]
fn stream_broken_after_a_confirmed_tool_effect_never_replays_the_effect() {
    let config = Config::parse_validated(&fallback_config(
        "fallback = { mode = \"auto\", chain = [\
             { mode = \"fixed\", connection = \"reserve\", model_id = \"reserve-model\" }] }",
    ))
    .expect("valid");
    let (mut broker, sent, _inner) = scripted_broker(
        vec![
            // attempt A confirms its tool effect through the loopback
            Respond::Delegate,
            // attempt B's stream breaks on the primary send
            Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            }),
            // the reserve continues the broken stream through the real
            // loopback — nothing about the reply is preconstructed
            Respond::Delegate,
        ],
        0,
    );
    let first = broker
        .prepare(
            "relay",
            &config,
            "/world/stream",
            "goal: fixture\nread /scope/allowed.txt",
        )
        .expect("manifest A");
    let confirmed = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/stream", &first)
        .expect("the first dispatch confirms its tool effect");
    assert_eq!(
        confirmed.tool_calls.len(),
        1,
        "the admitted read effect ran"
    );

    // the stream's re-send of the spent attempt is the replay surface:
    // it can never re-run the confirmed effect
    let replay = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/stream", &first)
        .expect_err("a spent attempt never replays");
    assert!(
        matches!(&replay, ModelError::AttemptAlreadyAccounted { attempt_id }
            if attempt_id == &first.attempt_id),
        "wrong rejection: {replay}"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        1,
        "the replay added no send"
    );

    // the broken follow-on request falls back — the continuation runs
    // the real provider seam: the substitute inherits the frozen inputs
    // byte-for-byte, so the loopback re-derives the read request under
    // the substitute's OWN attempt — a new decision, not a replay of
    // attempt A's confirmed send
    let follow = broker
        .prepare(
            "relay",
            &config,
            "/world/stream",
            "goal: fixture\nread /scope/allowed.txt",
        )
        .expect("manifest B");
    let continued = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/stream", &follow)
        .expect("the reserve continues the broken stream");
    assert_eq!(
        continued.tool_calls.len(),
        1,
        "the continuation re-requests the read under its own attempt"
    );
    let substitute_attempt = {
        let sent = sent.lock().expect("wire log lock");
        assert_eq!(
            sent.len(),
            3,
            "the primary of A, the broken primary of B, the reserve substitute"
        );
        assert_eq!(&sent[0], &first);
        assert_eq!(&sent[1], &follow);
        assert_ne!(sent[2].attempt_id, sent[0].attempt_id);
        assert_ne!(sent[2].attempt_id, sent[1].attempt_id);
        assert_eq!(
            sent[2].inputs, sent[1].inputs,
            "the substitute carries the frozen task data byte-for-byte"
        );
        assert_eq!(
            sent[2].model,
            ModelAssign::Fixed(FixedModel {
                connection: "reserve".to_string(),
                model_id: "reserve-model".to_string(),
            })
        );
        sent[2].attempt_id.clone()
    };
    assert_eq!(
        broker.accounted_requests(),
        2,
        "attempt A and the reserve substitute — the failed send spent nothing"
    );
    assert_eq!(
        broker
            .accounting_record(&substitute_attempt)
            .expect("the substitute send is accounted")
            .connection,
        "reserve"
    );
    // the continuation's attempt is spent too: replaying it is refused
    // like every spent attempt — no id ever replays its accounting
    let substitute_manifest = sent.lock().expect("wire log lock")[2].clone();
    let again = broker
        .dispatch(
            &mut rivect::model::NullLedger,
            "/world/stream",
            &substitute_manifest,
        )
        .expect_err("the spent substitute never replays either");
    assert!(
        matches!(&again, ModelError::AttemptAlreadyAccounted { attempt_id }
            if attempt_id == &substitute_attempt),
        "wrong rejection: {again}"
    );
}

/// INV-022/INV-024: the one accounting record of a physical send
/// reflects exactly the usage the provider reported — a crafted reply
/// usage lands verbatim on the record, and a send that reported none
/// keeps `Unknown` (the retained bound is never released as zero).
/// Usage is consumed through the provider seam exactly once — a second
/// send cannot re-charge the first send's report.
#[test]
fn accounting_record_reflects_provider_reply_usage_exactly_unknown_never_zero() {
    let reported = UsageDelta::Exact {
        prompt_tokens: 11,
        completion_tokens: 7,
        total_tokens: 18,
    };
    let (mut broker, sent, _) = scripted_broker(
        vec![
            Respond::Reply(ProviderReply {
                text: "one".to_string(),
                tool_calls: Vec::new(),
                usage: reported,
                wire_retries: 0,
                dropped_reasoning: 0,
            }),
            Respond::Reply(ProviderReply {
                text: "two".to_string(),
                tool_calls: Vec::new(),
                usage: UsageDelta::Unknown,
                wire_retries: 0,
                dropped_reasoning: 0,
            }),
        ],
        0,
    );
    let config =
        Config::parse_validated(&local_config("m", "{ mode = \"fixed\", value = \"low\" }"))
            .expect("valid");

    let first = broker
        .prepare("main", &config, "/world/usage", "goal: first")
        .expect("first prepares");
    let first_reply = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/usage", &first)
        .expect("the crafted reply dispatches");
    assert_eq!(
        first_reply.usage, reported,
        "the reply carries the provider's report"
    );
    let record = broker
        .accounting_record(&first.attempt_id)
        .expect("the send is accounted once");
    assert_eq!(
        record.usage, reported,
        "the record carries the provider's report verbatim"
    );
    let explain = broker.sent_cost_explain(&first);
    assert_eq!(explain.bound, first.cost_bound);
    assert_eq!(
        explain.confirmed,
        Some(18),
        "the provider's totals confirm the charge"
    );

    let second = broker
        .prepare("main", &config, "/world/usage", "goal: second")
        .expect("second prepares");
    let second_reply = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/usage", &second)
        .expect("the usage-less reply dispatches");
    assert_eq!(
        second_reply.usage,
        UsageDelta::Unknown,
        "a usage-less reply stays unknown at the seam"
    );
    let record = broker
        .accounting_record(&second.attempt_id)
        .expect("the send is accounted once");
    assert_eq!(
        record.usage,
        UsageDelta::Unknown,
        "no report stays unknown — never a fabricated zero"
    );
    let explain = broker.sent_cost_explain(&second);
    assert_eq!(explain.bound, second.cost_bound);
    assert_eq!(explain.confirmed, None, "unknown usage retains the bound");

    // two physical sends, two records, each charged its own usage —
    // the seam consumes a report exactly once.
    assert_eq!(sent.lock().expect("wire log lock").len(), 2);
    assert_eq!(broker.accounted_requests(), 2);
}

/// DEC-013 at the dispatch re-check: a profile-bound api_key
/// connection is usable through the profile's ref — precedence
/// actually reaches eligibility, so the dialect gate is the only
/// denial left — and a post-prepare profile removal re-denies the
/// same candidate as a live grant, proving the credential leg ran.
#[test]
fn profile_bound_credential_reaches_the_dispatch_recheck() {
    let mut config = Config::parse_validated(&fallback_config(
        "fallback = { mode = \"auto\", chain = [\
             { mode = \"fixed\", connection = \"probed\", model_id = \"probed-model\" }] }\n\
         [connections.probed]\nkind = \"api_key\"\nendpoint = \"https://api.example.invalid/v1\"\ncredential_ref = \"keyring:rivect-test/probed\"\nprofile = \"p\"\n\
         [profiles.p]\ncredential_ref = \"keyring:rivect-test/p\"",
    ))
    .expect("valid");
    let (mut broker, sent, _inner) = scripted_broker(
        vec![
            Respond::Fail(ProviderError::UnknownConnection {
                connection: "local".to_string(),
            }),
            Respond::Fail(ProviderError::UnknownConnection {
                connection: "probed".to_string(),
            }),
        ],
        0,
    );
    let manifest = broker
        .prepare(
            "relay",
            &config,
            "/world/profiles",
            "goal: profile precedence",
        )
        .expect("manifest");

    // the profile's ref resolves under DEC-013 precedence, so the
    // candidate passes the credential gate — the dialect gate is the
    // only denial left: no installed adapter serves its class
    let error = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/profiles", &manifest)
        .expect_err("a candidate no adapter serves is skipped");
    assert!(
        matches!(&error, ModelError::FallbackExhausted { rejected, .. }
        if matches!(rejected.as_slice(), [CandidateRejection {
            connection: connection_0,
            cause: RejectionCause::DialectMismatch,
        }] if connection_0 == "probed")),
        "the profile ref reached eligibility: {error}"
    );

    // remove the profile: the same candidate now fails the credential
    // gate itself — precedence, not a blanket api_key denial, decided
    config.profiles.remove("p");
    broker.set_config(&config);
    let error = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/profiles", &manifest)
        .expect_err("the profile-less candidate loses its grant");
    assert!(
        matches!(&error, ModelError::FallbackExhausted { rejected, .. }
        if matches!(rejected.as_slice(), [CandidateRejection {
            connection: connection_0,
            cause: RejectionCause::LiveGrantRequired { kind: ConnKind::ApiKey },
        }] if connection_0 == "probed")),
        "without the profile the credential gate denies: {error}"
    );
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        2,
        "only the two scripted primary sends ran — a rejected candidate never received a request"
    );
    assert_eq!(broker.accounted_requests(), 0);
}

/// A declared id `dialect_for` reserves fails the send gate with the
/// build truth — no installed adapter serves the recorded dialect — a
/// distinct typed denial from an adapter declining an offered id, and
/// the exhausted display carries it per candidate.
#[test]
fn a_reserved_connection_denies_with_the_unserved_dialect_truth() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.openai]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11439\"\n\
         [models.defaults]\nmodel = { mode = \"auto\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n\
         [models.purposes.relay]\n\
         model = { mode = \"fixed\", connection = \"openai\", model_id = \"reserved-model\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let (mut broker, sent, _inner) = scripted_broker(Vec::new(), 0);
    let manifest = broker
        .prepare("relay", &config, "/world/reserved", "goal: reserved")
        .expect("the declared reserved candidate ranks");
    let error = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/reserved", &manifest)
        .expect_err("the reserved id denies before any send");
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::DialectUnserved { connection, dialect })
                if connection == "openai" && *dialect == Dialect::Responses
        ),
        "the denial is the typed build truth: {error}"
    );
    let ModelError::Provider(source) = &error else {
        panic!("expected ModelError::Provider: {error}");
    };
    assert_eq!(
        source.to_string(),
        "connection openai is reserved for dialect responses; no installed adapter serves it in this build",
        "the display carries the honest build truth, not adapter blame"
    );
    assert!(
        sent.lock().expect("wire log lock").is_empty(),
        "the reserved id never reached the wire"
    );
}

/// The native `ollama-chat` dialect's unserved truth (DEC-001): the
/// literal `ollama-cloud` id is reserved by the dialect map, so a
/// dispatch through an adapter that does not serve it denies with the
/// build truth — the display names the recorded dialect, and no byte
/// reaches the wire.
#[test]
fn ollama_cloud_dialect_unserved_display_names_ollama_chat() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.\"ollama-cloud\"]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11439\"\n\
         [models.defaults]\nmodel = { mode = \"auto\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n\
         [models.purposes.relay]\n\
         model = { mode = \"fixed\", connection = \"ollama-cloud\", model_id = \"native-model\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let (mut broker, sent, _inner) = scripted_broker(Vec::new(), 0);
    let manifest = broker
        .prepare(
            "relay",
            &config,
            "/world/native-reserved",
            "goal: native reserved",
        )
        .expect("the declared reserved candidate ranks");
    let error = broker
        .dispatch(
            &mut rivect::model::NullLedger,
            "/world/native-reserved",
            &manifest,
        )
        .expect_err("the reserved native id denies before any send");
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::DialectUnserved { connection, dialect })
                if connection == "ollama-cloud" && *dialect == Dialect::OllamaChat
        ),
        "the denial is the typed build truth: {error}"
    );
    let ModelError::Provider(source) = &error else {
        panic!("expected ModelError::Provider: {error}");
    };
    assert_eq!(
        source.to_string(),
        "connection ollama-cloud is reserved for dialect ollama-chat; no installed adapter serves it in this build",
        "the display names the recorded native dialect"
    );
    assert!(
        sent.lock().expect("wire log lock").is_empty(),
        "the reserved native id never reached the wire"
    );
}

// ----- band-1 connection legs ---------------------------------------------------

/// `coreweave` is a served Chat-Completions id, not a reserved one:
/// the dialect map routes the literal id and the api_key pin is
/// offline-eligible at the binding level — an absent `credential_ref`
/// binding or an undeclared id is the typed denial, never a dispatch.
#[test]
fn coreweave_offline_eligibility_is_binding_level_typed() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.coreweave]\nkind = \"api_key\"\nendpoint = \"https://api.example.invalid/v1\"\ncredential_ref = \"keyring:rivect/cw\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"coreweave\", model_id = \"cw-model\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("coreweave"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    // a bound api_key pin is usable without a separate live grant —
    // eligibility reads the binding, never the store
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "coreweave".to_string(),
        model_id: "cw-model".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a bound api_key pin is usable without a separate live grant"
    );

    // a fixed pin on an undeclared id is the typed unknown-connection
    // denial at eligibility, before any ranking or send
    let undeclared = Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"local\", model_id = \"x\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    let missing = ModelAssign::Fixed(FixedModel {
        connection: "coreweave-missing".to_string(),
        model_id: "x".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &missing,
                &undeclared.connections,
                &undeclared.profiles,
            ),
            Err(ProviderError::UnknownConnection { .. })
        ),
        "an undeclared pin is the typed denial"
    );
}

/// `deepinfra` is a served Chat-Completions id, not a reserved one:
/// the dialect map routes the literal id and the api_key pin is
/// offline-eligible at the binding level — an absent `credential_ref`
/// binding or an undeclared id is the typed denial, never a dispatch.
#[test]
fn deepinfra_offline_eligibility_is_binding_level_typed() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.deepinfra]\nkind = \"api_key\"\nendpoint = \"https://api.example.invalid/v1\"\ncredential_ref = \"keyring:rivect/di\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"deepinfra\", model_id = \"di-model\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("deepinfra"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    // a bound api_key pin is usable without a separate live grant —
    // eligibility reads the binding, never the store
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "deepinfra".to_string(),
        model_id: "di-model".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a bound api_key pin is usable without a separate live grant"
    );

    // a fixed pin on an undeclared id is the typed unknown-connection
    // denial at eligibility, before any ranking or send
    let undeclared = Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"local\", model_id = \"x\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    let missing = ModelAssign::Fixed(FixedModel {
        connection: "deepinfra-missing".to_string(),
        model_id: "x".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &missing,
                &undeclared.connections,
                &undeclared.profiles,
            ),
            Err(ProviderError::UnknownConnection { .. })
        ),
        "an undeclared pin is the typed denial"
    );
}

/// `deepseek` is a served Chat-Completions id, not a reserved one:
/// the dialect map routes the literal id and the api_key pin is
/// offline-eligible at the binding level — an absent `credential_ref`
/// binding or an undeclared id is the typed denial, never a dispatch.
#[test]
fn deepseek_offline_eligibility_is_binding_level_typed() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.deepseek]\nkind = \"api_key\"\nendpoint = \"https://api.example.invalid\"\ncredential_ref = \"keyring:rivect/ds\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"deepseek\", model_id = \"ds-model\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("deepseek"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    // a bound api_key pin is usable without a separate live grant —
    // eligibility reads the binding, never the store
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "deepseek".to_string(),
        model_id: "ds-model".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a bound api_key pin is usable without a separate live grant"
    );

    // a fixed pin on an undeclared id is the typed unknown-connection
    // denial at eligibility, before any ranking or send
    let undeclared = Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"local\", model_id = \"x\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    let missing = ModelAssign::Fixed(FixedModel {
        connection: "deepseek-missing".to_string(),
        model_id: "x".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &missing,
                &undeclared.connections,
                &undeclared.profiles,
            ),
            Err(ProviderError::UnknownConnection { .. })
        ),
        "an undeclared pin is the typed denial"
    );
}

/// `fireworks` is a served Chat-Completions id, not a reserved one:
/// the dialect map routes the literal id and the api_key pin is
/// offline-eligible at the binding level — an absent `credential_ref`
/// binding or an undeclared id is the typed denial, never a dispatch.
#[test]
fn fireworks_offline_eligibility_is_binding_level_typed() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.fireworks]\nkind = \"api_key\"\nendpoint = \"https://api.example.invalid\"\ncredential_ref = \"keyring:rivect/fw\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"fireworks\", model_id = \"fw-model\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("fireworks"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    // a bound api_key pin is usable without a separate live grant —
    // eligibility reads the binding, never the store
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "fireworks".to_string(),
        model_id: "fw-model".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a bound api_key pin is usable without a separate live grant"
    );

    // a fixed pin on an undeclared id is the typed unknown-connection
    // denial at eligibility, before any ranking or send
    let undeclared = Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"local\", model_id = \"x\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    let missing = ModelAssign::Fixed(FixedModel {
        connection: "fireworks-missing".to_string(),
        model_id: "x".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &missing,
                &undeclared.connections,
                &undeclared.profiles,
            ),
            Err(ProviderError::UnknownConnection { .. })
        ),
        "an undeclared pin is the typed denial"
    );
}

/// `firepass` is a served Chat-Completions id, not a reserved one: the
/// dialect map routes the literal id and the api_key pin is
/// offline-eligible at the binding level — an absent `credential_ref`
/// binding or an undeclared id is the typed denial, never a dispatch.
#[test]
fn firepass_offline_eligibility_is_binding_level_typed() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.firepass]\nkind = \"api_key\"\nendpoint = \"https://api.example.invalid\"\ncredential_ref = \"keyring:rivect/fp\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"firepass\", model_id = \"fp-model\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("firepass"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    // a bound api_key pin is usable without a separate live grant —
    // eligibility reads the binding, never the store
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "firepass".to_string(),
        model_id: "fp-model".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a bound api_key pin is usable without a separate live grant"
    );

    // a fixed pin on an undeclared id is the typed unknown-connection
    // denial at eligibility, before any ranking or send
    let undeclared = Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"local\", model_id = \"x\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    let missing = ModelAssign::Fixed(FixedModel {
        connection: "firepass-missing".to_string(),
        model_id: "x".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &missing,
                &undeclared.connections,
                &undeclared.profiles,
            ),
            Err(ProviderError::UnknownConnection { .. })
        ),
        "an undeclared pin is the typed denial"
    );
}

/// `gmi-cloud` is a served Chat-Completions id, not a reserved one: the
/// dialect map routes the literal id and the api_key pin is
/// offline-eligible at the binding level — an undeclared id is the typed
/// denial, never a dispatch.
#[test]
fn gmi_cloud_offline_eligibility_is_binding_level_typed() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.gmi-cloud]\nkind = \"api_key\"\nendpoint = \"https://api.example.invalid\"\ncredential_ref = \"keyring:rivect/gmi\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"gmi-cloud\", model_id = \"gmi-model\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("gmi-cloud"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    // a bound api_key pin is usable without a separate live grant —
    // eligibility reads the binding, never the store
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "gmi-cloud".to_string(),
        model_id: "gmi-model".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a bound api_key pin is usable without a separate live grant"
    );

    // a fixed pin on an undeclared id is the typed unknown-connection
    // denial at eligibility, before any ranking or send
    let undeclared = Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"local\", model_id = \"x\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    let missing = ModelAssign::Fixed(FixedModel {
        connection: "gmi-cloud-missing".to_string(),
        model_id: "x".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &missing,
                &undeclared.connections,
                &undeclared.profiles,
            ),
            Err(ProviderError::UnknownConnection { .. })
        ),
        "an undeclared pin is the typed denial"
    );
}

/// `groq` is a served Chat-Completions id under the recorded
/// env/credential-chain class: the dialect map routes the literal id,
/// and the pin is offline-eligible at the binding level through a
/// profile-bound scoped ref — an undeclared id is the typed denial,
/// never a dispatch.
#[test]
fn groq_offline_eligibility_is_binding_level_typed() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.groq]\nkind = \"api_key\"\nendpoint = \"https://api.example.invalid\"\ncredential_ref = \"keyring:rivect/groq-scope\"\nprofile = \"groq-team\"\n\
         [profiles.groq-team]\ncredential_ref = \"keyring:rivect/groq-team\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"groq\", model_id = \"openai/gpt-oss-120b\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("groq"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    // the profile-bound scoped chain is usable without a separate live
    // grant — eligibility reads the binding, never the store
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "groq".to_string(),
        model_id: "openai/gpt-oss-120b".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a profile-bound credential chain is usable without a separate live grant"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "groq",
    ));

    // a fixed pin on an undeclared id is the typed unknown-connection
    // denial at eligibility, before any ranking or send
    let undeclared = Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"local\", model_id = \"x\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    let missing = ModelAssign::Fixed(FixedModel {
        connection: "groq-missing".to_string(),
        model_id: "x".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &missing,
                &undeclared.connections,
                &undeclared.profiles,
            ),
            Err(ProviderError::UnknownConnection { .. })
        ),
        "an undeclared pin is the typed denial"
    );
}

/// `huggingface` is a served Chat-Completions id under the recorded
/// api-key class: the dialect map routes the literal id, and the pin is
/// offline-eligible at the binding level through a profile-bound scoped
/// ref — an undeclared id is the typed denial, never a dispatch.
#[test]
fn huggingface_offline_eligibility_is_binding_level_typed() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.huggingface]\nkind = \"api_key\"\nendpoint = \"https://api.example.invalid\"\ncredential_ref = \"keyring:rivect/huggingface-scope\"\nprofile = \"huggingface-team\"\n\
         [profiles.huggingface-team]\ncredential_ref = \"keyring:rivect/huggingface-team\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"huggingface\", model_id = \"Qwen/Qwen3-235B-A22B-Thinking-2507\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("huggingface"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "huggingface".to_string(),
        model_id: "Qwen/Qwen3-235B-A22B-Thinking-2507".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a profile-bound credential binding is usable without a separate live grant"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "huggingface",
    ));

    // a fixed pin on an undeclared id is the typed unknown-connection
    // denial at eligibility, before any ranking or send
    let undeclared = Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"local\", model_id = \"x\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    let missing = ModelAssign::Fixed(FixedModel {
        connection: "huggingface-missing".to_string(),
        model_id: "x".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &missing,
                &undeclared.connections,
                &undeclared.profiles,
            ),
            Err(ProviderError::UnknownConnection { .. })
        ),
        "an undeclared pin is the typed denial"
    );
}

/// `kilo` is a served Chat-Completions id under the recorded custom
/// device/key class: the dialect map routes the literal id, and the pin
/// is offline-eligible at the binding level through a profile-bound
/// scoped ref — an undeclared id is the typed denial, never a dispatch.
#[test]
fn kilo_offline_eligibility_is_binding_level_typed() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.kilo]\nkind = \"api_key\"\nendpoint = \"https://api.kilo.ai/api/gateway\"\ncredential_ref = \"keyring:rivect/kilo-scope\"\nprofile = \"kilo-device\"\n\
         [profiles.kilo-device]\ncredential_ref = \"keyring:rivect/kilo-device\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"kilo\", model_id = \"anthropic/claude-opus-4.8\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("kilo"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "kilo".to_string(),
        model_id: "anthropic/claude-opus-4.8".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a profile-bound credential binding is usable without a separate live grant"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "kilo",
    ));

    // a fixed pin on an undeclared id is the typed unknown-connection
    // denial at eligibility, before any ranking or send
    let undeclared = Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"local\", model_id = \"x\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    let missing = ModelAssign::Fixed(FixedModel {
        connection: "kilo-missing".to_string(),
        model_id: "x".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &missing,
                &undeclared.connections,
                &undeclared.profiles,
            ),
            Err(ProviderError::UnknownConnection { .. })
        ),
        "an undeclared pin is the typed denial"
    );
}

/// `litellm` is a served Chat-Completions id under the recorded
/// credential-optional api-key class: the dialect map routes the literal
/// id, and a fixed pin is offline-eligible both on the recorded
/// open-proxy declaration — which binds no `credential_ref` at all — and
/// through a scoped key, while an undeclared id is the typed denial.
#[test]
fn litellm_offline_eligibility_admits_the_open_proxy_binding() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.litellm]\nkind = \"api_key\"\nendpoint = \"https://proxy.example.invalid/v1\"\n\
         [connections.litellm-keyed]\nkind = \"api_key\"\nendpoint = \"https://proxy.example.invalid/v1\"\ncredential_ref = \"keyring:rivect/litellm-scope\"\nprofile = \"litellm-team\"\n\
         [profiles.litellm-team]\ncredential_ref = \"keyring:rivect/litellm-team\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"litellm\", model_id = \"proxy/chat-model\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("litellm"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    assert_eq!(
        config.connections["litellm"].credential_ref, None,
        "the open-proxy row binds no credential"
    );
    let open_proxy = ModelAssign::Fixed(FixedModel {
        connection: "litellm".to_string(),
        model_id: "proxy/chat-model".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&open_proxy, &config.connections, &config.profiles)
            .is_ok(),
        "the recorded open proxy is usable without a live grant"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "litellm",
    ));

    let keyed = ModelAssign::Fixed(FixedModel {
        connection: "litellm-keyed".to_string(),
        model_id: "proxy/chat-model".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&keyed, &config.connections, &config.profiles).is_ok(),
        "a scoped key is usable on the same class"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "litellm-keyed",
    ));

    // a litellm row whose declared binding cannot resolve is the typed
    // live-grant denial at eligibility: the open proxy is the
    // *undeclared* binding, never an unresolvable one
    let unresolvable = Config::parse_validated(
        "config_version = 1\n\
         [connections.litellm]\nkind = \"api_key\"\nendpoint = \"https://proxy.example.invalid/v1\"\nprofile = \"litellm\"\n\
         [profiles.litellm]\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"litellm\", model_id = \"proxy/chat-model\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("a profile-bound row is valid");
    let unresolvable_pin = ModelAssign::Fixed(FixedModel {
        connection: "litellm".to_string(),
        model_id: "proxy/chat-model".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &unresolvable_pin,
                &unresolvable.connections,
                &unresolvable.profiles,
            ),
            Err(ProviderError::LiveGrantRequired {
                kind: ConnKind::ApiKey
            })
        ),
        "a declared binding that cannot resolve is the typed live-grant denial"
    );
    assert!(
        !rivect::providers::offline_usable(
            &unresolvable.connections,
            &unresolvable.profiles,
            "litellm",
        ),
        "only the undeclared binding is the open-proxy form"
    );
}

/// `llama.cpp` is a served Chat-Completions id under the recorded
/// local-endpoint class: the dialect map routes the literal id, and the
/// keyless declaration — which binds no `credential_ref` at all — reads
/// the same absent-binding predicate config admission does, so a fixed
/// pin prepares through the real Broker. The server-key half of the same
/// class stays eligible, and a declared-but-unresolvable binding is the
/// typed live-grant denial rather than a silent keyless fallback.
#[test]
fn llama_cpp_keyless_local_connection_is_offline_eligible() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.\"llama.cpp\"]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:8080\"\n\
         [connections.\"llama.cpp-keyed\"]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:8080\"\ncredential_ref = \"keyring:rivect/llama.cpp-scope\"\nprofile = \"llama-cpp-team\"\n\
         [profiles.llama-cpp-team]\ncredential_ref = \"keyring:rivect/llama-cpp-team\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"llama.cpp\", model_id = \"fixture-gguf-model\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("llama.cpp"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    assert_eq!(
        config.connections["llama.cpp"].credential_ref, None,
        "the keyless local row binds no credential"
    );
    let keyless = ModelAssign::Fixed(FixedModel {
        connection: "llama.cpp".to_string(),
        model_id: "fixture-gguf-model".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&keyless, &config.connections, &config.profiles)
            .is_ok(),
        "the keyless local mode is usable without a live grant"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "llama.cpp",
    ));

    // the eligible-but-unbound connection prepares through the real
    // Broker — eligibility reads the same predicate config admission does
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let manifest = broker
        .prepare("main", &config, "/world/llama", "goal: keyless local")
        .expect("the unbound local connection prepares");
    assert!(
        matches!(&manifest.model, ModelAssign::Fixed(fixed)
            if fixed.connection == "llama.cpp" && fixed.model_id == "fixture-gguf-model"),
        "the prepared manifest pins the local connection and model: {:?}",
        manifest.model
    );

    let keyed = ModelAssign::Fixed(FixedModel {
        connection: "llama.cpp-keyed".to_string(),
        model_id: "fixture-gguf-model".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&keyed, &config.connections, &config.profiles).is_ok(),
        "a scoped server key is usable on the same class"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "llama.cpp-keyed",
    ));

    // a row whose declared binding cannot resolve is the typed
    // live-grant denial at eligibility: the keyless form is the
    // *undeclared* binding, never an unresolvable one
    let unresolvable = Config::parse_validated(
        "config_version = 1\n\
         [connections.\"llama.cpp\"]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:8080\"\nprofile = \"llama.cpp\"\n\
         [profiles.\"llama.cpp\"]\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"llama.cpp\", model_id = \"fixture-gguf-model\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("a profile-bound row is valid");
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &keyless,
                &unresolvable.connections,
                &unresolvable.profiles,
            ),
            Err(ProviderError::LiveGrantRequired {
                kind: ConnKind::ApiKey
            })
        ),
        "a declared binding that cannot resolve is the typed live-grant denial"
    );
    assert!(
        !rivect::providers::offline_usable(
            &unresolvable.connections,
            &unresolvable.profiles,
            "llama.cpp",
        ),
        "only the undeclared binding is the keyless local form"
    );
}

/// `lm-studio` is the second served Chat-Completions id under the
/// recorded local-endpoint class: the dialect map routes the literal id
/// and the keyless declaration — which binds no `credential_ref` at all
/// — reads the same absent-binding predicate config admission does, so a
/// fixed pin prepares through the real Broker. Its own recorded base
/// (`127.0.0.1:1234/v1`, never `llama.cpp`'s `:8080` — EDGE-006) is what
/// the declaration carries, the server-key half stays eligible, and a
/// declared-but-unresolvable binding is the typed live-grant denial.
#[test]
fn lm_studio_keyless_local_connection_is_offline_eligible() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.\"lm-studio\"]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1234/v1\"\n\
         [connections.\"lm-studio-keyed\"]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1234/v1\"\ncredential_ref = \"keyring:rivect/lm-studio-scope\"\nprofile = \"lm-studio-team\"\n\
         [profiles.lm-studio-team]\ncredential_ref = \"keyring:rivect/lm-studio-team\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"lm-studio\", model_id = \"fixture-local-model\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("lm-studio"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    assert_eq!(
        config.connections["lm-studio"].credential_ref, None,
        "the keyless local row binds no credential"
    );
    let keyless = ModelAssign::Fixed(FixedModel {
        connection: "lm-studio".to_string(),
        model_id: "fixture-local-model".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&keyless, &config.connections, &config.profiles)
            .is_ok(),
        "the keyless local mode is usable without a live grant"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "lm-studio",
    ));

    // the eligible-but-unbound connection prepares through the real
    // Broker — eligibility reads the same predicate config admission does
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let manifest = broker
        .prepare("main", &config, "/world/studio", "goal: keyless local")
        .expect("the unbound local connection prepares");
    assert!(
        matches!(&manifest.model, ModelAssign::Fixed(fixed)
            if fixed.connection == "lm-studio" && fixed.model_id == "fixture-local-model"),
        "the prepared manifest pins the local connection and model: {:?}",
        manifest.model
    );

    let keyed = ModelAssign::Fixed(FixedModel {
        connection: "lm-studio-keyed".to_string(),
        model_id: "fixture-local-model".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&keyed, &config.connections, &config.profiles).is_ok(),
        "a scoped server key is usable on the same class"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "lm-studio-keyed",
    ));

    // a row whose declared binding cannot resolve is the typed
    // live-grant denial at eligibility: the keyless form is the
    // *undeclared* binding, never an unresolvable one
    let unresolvable = Config::parse_validated(
        "config_version = 1\n\
         [connections.\"lm-studio\"]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1234/v1\"\nprofile = \"lm-studio\"\n\
         [profiles.\"lm-studio\"]\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"lm-studio\", model_id = \"fixture-local-model\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("a profile-bound row is valid");
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &keyless,
                &unresolvable.connections,
                &unresolvable.profiles,
            ),
            Err(ProviderError::LiveGrantRequired {
                kind: ConnKind::ApiKey
            })
        ),
        "a declared binding that cannot resolve is the typed live-grant denial"
    );
    assert!(
        !rivect::providers::offline_usable(
            &unresolvable.connections,
            &unresolvable.profiles,
            "lm-studio",
        ),
        "only the undeclared binding is the keyless local form"
    );
}

/// `vllm` is a served Chat-Completions id under the recorded local-server
/// class: the dialect map routes the literal id, and the recorded local
/// mode is offline-eligible without a key on both shipped headerless
/// declarations — the unbound `api_key` row and the `local` row — while a
/// scoped server key stays eligible and a declared-but-unresolvable
/// binding keeps the typed live-grant denial rather than a silent keyless
/// fallback.
#[test]
fn vllm_keyless_connection_is_offline_eligible() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.vllm]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:8000/v1\"\n\
         [connections.vllm-local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:8000/v1\"\n\
         [connections.vllm-keyed]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:8000/v1\"\ncredential_ref = \"keyring:rivect/vllm-scope\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"vllm\", model_id = \"Qwen/Qwen3.8-27B\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("vllm"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    assert_eq!(
        config.connections["vllm"].credential_ref, None,
        "the keyless api_key row binds no credential"
    );

    let keyless = ModelAssign::Fixed(FixedModel {
        connection: "vllm".to_string(),
        model_id: "Qwen/Qwen3.8-27B".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&keyless, &config.connections, &config.profiles)
            .is_ok(),
        "the unbound local mode is usable without a live grant"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "vllm",
    ));

    let local = ModelAssign::Fixed(FixedModel {
        connection: "vllm-local".to_string(),
        model_id: "Qwen/Qwen3.8-27B".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&local, &config.connections, &config.profiles).is_ok(),
        "the shipped kind=local headerless form is the same leg"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "vllm-local",
    ));

    // the eligible-but-unbound connection prepares through the real
    // Broker — eligibility reads the same predicate config admission does
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let manifest = broker
        .prepare("main", &config, "/world/vllm", "goal: keyless local")
        .expect("the unbound local connection prepares");
    assert!(
        matches!(&manifest.model, ModelAssign::Fixed(fixed)
            if fixed.connection == "vllm" && fixed.model_id == "Qwen/Qwen3.8-27B"),
        "the prepared manifest pins the local connection and model: {:?}",
        manifest.model
    );

    let keyed = ModelAssign::Fixed(FixedModel {
        connection: "vllm-keyed".to_string(),
        model_id: "Qwen/Qwen3.8-27B".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&keyed, &config.connections, &config.profiles).is_ok(),
        "a scoped server key is usable on the same class"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "vllm-keyed",
    ));

    // a row whose declared binding cannot resolve is the typed live-grant
    // denial at eligibility: the keyless form is the *undeclared* binding,
    // never an unresolvable one
    let unresolvable = Config::parse_validated(
        "config_version = 1\n\
         [connections.vllm]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:8000/v1\"\nprofile = \"vllm\"\n\
         [profiles.vllm]\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"vllm\", model_id = \"Qwen/Qwen3.8-27B\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("a profile-bound row is valid");
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &keyless,
                &unresolvable.connections,
                &unresolvable.profiles,
            ),
            Err(ProviderError::LiveGrantRequired {
                kind: ConnKind::ApiKey
            })
        ),
        "a declared binding that cannot resolve is the typed live-grant denial"
    );
    assert!(
        !rivect::providers::offline_usable(
            &unresolvable.connections,
            &unresolvable.profiles,
            "vllm",
        ),
        "only the undeclared binding is the keyless local form"
    );
}

/// `ollama` is a served Responses id whose credential is optional: the
/// dialect map routes the literal id, and a fixed pin is
/// offline-eligible on both keyless declarations — `api_key` with no
/// binding and `local` — while a bound profile stays eligible and a
/// declared-but-unresolvable binding keeps the typed live-grant denial.
#[test]
fn ollama_keyless_local_connection_is_offline_eligible() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.ollama]\nkind = \"api_key\"\nendpoint = \"\"\n\
         [connections.ollama-local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434/v1\"\n\
         [connections.ollama-keyed]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:11434/v1\"\ncredential_ref = \"keyring:rivect/ol\"\nprofile = \"ollama-team\"\n\
         [profiles.ollama-team]\ncredential_ref = \"keyring:rivect/ollama-team\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"ollama\", model_id = \"llama3.2:3b\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("ollama"),
        Some(Dialect::Responses),
        "the literal id routes to the shared Responses dialect"
    );
    assert_eq!(
        config.connections["ollama"].credential_ref, None,
        "the keyless api_key row binds no credential"
    );

    let keyless = ModelAssign::Fixed(FixedModel {
        connection: "ollama".to_string(),
        model_id: "llama3.2:3b".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&keyless, &config.connections, &config.profiles)
            .is_ok(),
        "the keyless api_key form is usable without a live grant"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "ollama",
    ));

    let local = ModelAssign::Fixed(FixedModel {
        connection: "ollama-local".to_string(),
        model_id: "llama3.2:3b".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&local, &config.connections, &config.profiles).is_ok(),
        "the local declaration is the same keyless leg"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "ollama-local",
    ));

    let keyed = ModelAssign::Fixed(FixedModel {
        connection: "ollama-keyed".to_string(),
        model_id: "llama3.2:3b".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&keyed, &config.connections, &config.profiles).is_ok(),
        "a scoped key is usable on the same class"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "ollama-keyed",
    ));

    // the eligible keyless pin prepares through the real Broker with
    // the literal connection and model frozen
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let manifest = broker
        .prepare("main", &config, "/world/ollama", "goal: local")
        .expect("the keyless ollama pin prepares");
    assert!(
        matches!(&manifest.model, ModelAssign::Fixed(fixed)
            if fixed.connection == "ollama" && fixed.model_id == "llama3.2:3b"),
        "the prepared manifest pins the local connection and model: {:?}",
        manifest.model
    );

    // a declared binding that cannot resolve is the typed live-grant
    // denial at eligibility — only the undeclared binding is keyless
    let unresolvable = Config::parse_validated(
        "config_version = 1\n\
         [connections.ollama]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:11434/v1\"\nprofile = \"ollama\"\n\
         [profiles.ollama]\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"ollama\", model_id = \"llama3.2:3b\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("a profile-bound row is valid");
    let unresolvable_pin = ModelAssign::Fixed(FixedModel {
        connection: "ollama".to_string(),
        model_id: "llama3.2:3b".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &unresolvable_pin,
                &unresolvable.connections,
                &unresolvable.profiles,
            ),
            Err(ProviderError::LiveGrantRequired {
                kind: ConnKind::ApiKey
            })
        ),
        "an unresolvable declared binding is the live-grant denial"
    );
    assert!(
        !rivect::providers::offline_usable(
            &unresolvable.connections,
            &unresolvable.profiles,
            "ollama",
        ),
        "only the undeclared binding is the keyless local form"
    );
}

/// `meta` is a served Responses-dialect id, not a reserved one: the
/// dialect map routes the literal id and the api_key pin is
/// offline-eligible at the binding level — an undeclared id is the
/// typed denial, never a dispatch.
#[test]
fn meta_offline_eligibility_is_binding_level_typed() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.meta]\nkind = \"api_key\"\nendpoint = \"https://api.meta.ai/v1\"\ncredential_ref = \"keyring:rivect/mt\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"meta\", model_id = \"muse-spark-1.1\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("meta"),
        Some(Dialect::Responses),
        "the literal id routes to the shared Responses dialect"
    );
    // a bound api_key pin is usable without a separate live grant —
    // eligibility reads the binding, never the store
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "meta".to_string(),
        model_id: "muse-spark-1.1".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a bound api_key pin is usable without a separate live grant"
    );

    // a fixed pin on an undeclared id is the typed unknown-connection
    // denial at eligibility, before any ranking or send
    let undeclared = Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"local\", model_id = \"x\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    let missing = ModelAssign::Fixed(FixedModel {
        connection: "meta-missing".to_string(),
        model_id: "x".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &missing,
                &undeclared.connections,
                &undeclared.profiles,
            ),
            Err(ProviderError::UnknownConnection { .. })
        ),
        "an undeclared pin is the typed denial"
    );
}

/// `minimax-code` is a served Chat-Completions id under the recorded
/// class-P plan-key cell: the dialect map routes the literal id and the
/// api_key pin is offline-eligible at the binding level — an undeclared
/// id or a declared-but-unresolvable binding is the typed denial, never
/// a dispatch. The recorded contract names no discovery leg, so
/// eligibility is the binding-level proof for this id.
#[test]
fn minimax_code_offline_eligibility_is_binding_level_typed() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.minimax-code]\nkind = \"api_key\"\nendpoint = \"https://api.minimax.io/v1\"\ncredential_ref = \"keyring:rivect/mm\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"minimax-code\", model_id = \"minimax-m2.5\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("minimax-code"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    // a bound api_key pin is usable without a separate live grant —
    // eligibility reads the binding, never the store
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "minimax-code".to_string(),
        model_id: "minimax-m2.5".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a bound api_key pin is usable without a separate live grant"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "minimax-code",
    ));

    // a fixed pin on an undeclared id is the typed unknown-connection
    // denial at eligibility, before any ranking or send
    let undeclared = Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"local\", model_id = \"x\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert!(!rivect::providers::offline_usable(
        &undeclared.connections,
        &undeclared.profiles,
        "minimax-code-missing",
    ));
    let missing = ModelAssign::Fixed(FixedModel {
        connection: "minimax-code-missing".to_string(),
        model_id: "x".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &missing,
                &undeclared.connections,
                &undeclared.profiles,
            ),
            Err(ProviderError::UnknownConnection { .. })
        ),
        "an undeclared pin is the typed denial"
    );

    // a declared binding whose profile ref disagrees with the
    // connection's scope is the typed live-grant denial: the plan key
    // is the *declared* binding, never a mismatched one — and this
    // class requires `credential_ref` at admission, so a declared row
    // can never bind absent
    let mismatched = Config::parse_validated(
        "config_version = 1\n\
         [connections.minimax-code]\nkind = \"api_key\"\nendpoint = \"https://api.minimax.io/v1\"\ncredential_ref = \"keyring:rivect/mm-scope\"\nprofile = \"minimax-team\"\n\
         [profiles.minimax-team]\ncredential_ref = \"keyring:rivect/other\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"minimax-code\", model_id = \"minimax-m2.5\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("a profile-bound row is valid");
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &pin,
                &mismatched.connections,
                &mismatched.profiles,
            ),
            Err(ProviderError::LiveGrantRequired {
                kind: ConnKind::ApiKey
            })
        ),
        "a declared binding that cannot resolve is the typed live-grant denial"
    );
    assert!(
        !rivect::providers::offline_usable(
            &mismatched.connections,
            &mismatched.profiles,
            "minimax-code",
        ),
        "only the resolvable binding is the plan-key form"
    );
}

/// `minimax-code-cn` is a served Chat-Completions id under the
/// recorded class-P CN plan-key cell: the dialect map routes the
/// literal id and the api_key pin is offline-eligible at the binding
/// level — an undeclared id or a declared-but-unresolvable binding is
/// the typed denial, never a dispatch. The recorded contract names no
/// discovery leg, so eligibility is the binding-level proof for this
/// id.
#[test]
fn minimax_code_cn_offline_eligibility_is_binding_level_typed() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.minimax-code-cn]\nkind = \"api_key\"\nendpoint = \"https://api.minimaxi.com/v1\"\ncredential_ref = \"keyring:rivect/mmcn\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"minimax-code-cn\", model_id = \"minimax-m2.5\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("minimax-code-cn"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    // a bound api_key pin is usable without a separate live grant —
    // eligibility reads the binding, never the store
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "minimax-code-cn".to_string(),
        model_id: "minimax-m2.5".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a bound api_key pin is usable without a separate live grant"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "minimax-code-cn",
    ));

    // a fixed pin on an undeclared id is the typed unknown-connection
    // denial at eligibility, before any ranking or send
    let undeclared = Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"local\", model_id = \"x\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert!(!rivect::providers::offline_usable(
        &undeclared.connections,
        &undeclared.profiles,
        "minimax-code-cn-missing",
    ));
    let missing = ModelAssign::Fixed(FixedModel {
        connection: "minimax-code-cn-missing".to_string(),
        model_id: "x".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &missing,
                &undeclared.connections,
                &undeclared.profiles,
            ),
            Err(ProviderError::UnknownConnection { .. })
        ),
        "an undeclared pin is the typed denial"
    );

    // a declared binding whose profile ref disagrees with the
    // connection's scope is the typed live-grant denial: the plan key
    // is the *declared* binding, never a mismatched one — and this
    // class requires `credential_ref` at admission, so a declared row
    // can never bind absent
    let mismatched = Config::parse_validated(
        "config_version = 1\n\
         [connections.minimax-code-cn]\nkind = \"api_key\"\nendpoint = \"https://api.minimaxi.com/v1\"\ncredential_ref = \"keyring:rivect/mmcn-scope\"\nprofile = \"minimax-cn-team\"\n\
         [profiles.minimax-cn-team]\ncredential_ref = \"keyring:rivect/other\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"minimax-code-cn\", model_id = \"minimax-m2.5\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("a profile-bound row is valid");
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &pin,
                &mismatched.connections,
                &mismatched.profiles,
            ),
            Err(ProviderError::LiveGrantRequired {
                kind: ConnKind::ApiKey
            })
        ),
        "a declared binding that cannot resolve is the typed live-grant denial"
    );
    assert!(
        !rivect::providers::offline_usable(
            &mismatched.connections,
            &mismatched.profiles,
            "minimax-code-cn",
        ),
        "only the resolvable binding is the plan-key form"
    );
}

/// `mistral` is a served Chat-Completions id under the recorded
/// env/credential-chain class (DEC-006): the dialect map routes the
/// literal id, and the pin is offline-eligible at the binding level
/// through a profile-bound scoped ref — the same `SecretRef` seam the
/// api-key class binds, traversal staying credential-substrate debt —
/// while an undeclared id or a declared-but-unresolvable binding is
/// the typed denial, never a dispatch.
#[test]
fn mistral_offline_eligibility_is_binding_level_typed() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.mistral]\nkind = \"api_key\"\nendpoint = \"https://api.mistral.ai/v1\"\ncredential_ref = \"keyring:rivect/mistral-scope\"\nprofile = \"mistral-team\"\n\
         [profiles.mistral-team]\ncredential_ref = \"keyring:rivect/mistral-team\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"mistral\", model_id = \"mistral-small-latest\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("mistral"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    // the profile-bound scoped chain is usable without a separate live
    // grant — eligibility reads the binding, never the store
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "mistral".to_string(),
        model_id: "mistral-small-latest".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a profile-bound credential chain is usable without a separate live grant"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "mistral",
    ));

    // a fixed pin on an undeclared id is the typed unknown-connection
    // denial at eligibility, before any ranking or send
    let undeclared = Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"local\", model_id = \"x\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert!(!rivect::providers::offline_usable(
        &undeclared.connections,
        &undeclared.profiles,
        "mistral-missing",
    ));
    let missing = ModelAssign::Fixed(FixedModel {
        connection: "mistral-missing".to_string(),
        model_id: "x".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &missing,
                &undeclared.connections,
                &undeclared.profiles,
            ),
            Err(ProviderError::UnknownConnection { .. })
        ),
        "an undeclared pin is the typed denial"
    );

    // a declared binding whose profile ref disagrees with the
    // connection's scope is the typed live-grant denial: the scoped
    // chain binds the *declared* ref, never a mismatched one — and
    // this class requires `credential_ref` at admission, so a declared
    // row can never bind absent
    let mismatched = Config::parse_validated(
        "config_version = 1\n\
         [connections.mistral]\nkind = \"api_key\"\nendpoint = \"https://api.mistral.ai/v1\"\ncredential_ref = \"keyring:rivect/mistral-scope\"\nprofile = \"mistral-team\"\n\
         [profiles.mistral-team]\ncredential_ref = \"keyring:rivect/other\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"mistral\", model_id = \"mistral-small-latest\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("a profile-bound row is valid");
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &pin,
                &mismatched.connections,
                &mismatched.profiles,
            ),
            Err(ProviderError::LiveGrantRequired {
                kind: ConnKind::ApiKey
            })
        ),
        "a declared binding that cannot resolve is the typed live-grant denial"
    );
    assert!(
        !rivect::providers::offline_usable(
            &mismatched.connections,
            &mismatched.profiles,
            "mistral",
        ),
        "only the resolvable binding is the env-chain form"
    );
}

/// `moonshot` is a served Chat-Completions id under the recorded
/// class-B api-key cell: the dialect map routes the literal id and the
/// api_key pin is offline-eligible at the binding level — an undeclared
/// id or a declared-but-unresolvable binding is the typed denial, never
/// a plaintext or env path (the recorded `KIMI_API_KEY` fallback key
/// name proves neither region nor payment).
#[test]
fn moonshot_offline_eligibility_is_binding_level_typed() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.moonshot]\nkind = \"api_key\"\nendpoint = \"https://api.moonshot.ai/v1\"\ncredential_ref = \"keyring:rivect/ms\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"moonshot\", model_id = \"kimi-k3\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("moonshot"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    // a bound api_key pin is usable without a separate live grant —
    // eligibility reads the binding, never the store
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "moonshot".to_string(),
        model_id: "kimi-k3".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a bound api_key pin is usable without a separate live grant"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "moonshot",
    ));

    // a fixed pin on an undeclared id is the typed unknown-connection
    // denial at eligibility, before any ranking or send
    let undeclared = Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"local\", model_id = \"x\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert!(!rivect::providers::offline_usable(
        &undeclared.connections,
        &undeclared.profiles,
        "moonshot-missing",
    ));
    let missing = ModelAssign::Fixed(FixedModel {
        connection: "moonshot-missing".to_string(),
        model_id: "x".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &missing,
                &undeclared.connections,
                &undeclared.profiles,
            ),
            Err(ProviderError::UnknownConnection { .. })
        ),
        "an undeclared pin is the typed denial"
    );

    // a declared binding whose profile ref disagrees with the
    // connection's scope is the typed live-grant denial: the api key
    // is the *declared* binding, never a mismatched one — and this
    // class requires `credential_ref` at admission, so a declared row
    // can never bind absent
    let mismatched = Config::parse_validated(
        "config_version = 1\n\
         [connections.moonshot]\nkind = \"api_key\"\nendpoint = \"https://api.moonshot.ai/v1\"\ncredential_ref = \"keyring:rivect/ms-scope\"\nprofile = \"moonshot-team\"\n\
         [profiles.moonshot-team]\ncredential_ref = \"keyring:rivect/other\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"moonshot\", model_id = \"kimi-k3\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("a profile-bound row is valid");
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "moonshot".to_string(),
        model_id: "kimi-k3".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &pin,
                &mismatched.connections,
                &mismatched.profiles,
            ),
            Err(ProviderError::LiveGrantRequired {
                kind: ConnKind::ApiKey
            })
        ),
        "a declared binding that cannot resolve is the typed live-grant denial"
    );
    assert!(
        !rivect::providers::offline_usable(
            &mismatched.connections,
            &mismatched.profiles,
            "moonshot",
        ),
        "only the resolvable binding is the api-key form"
    );
}

/// `nanogpt` is a served Chat-Completions id under the recorded
/// class-B api-key cell: the dialect map routes the literal id and the
/// api_key pin is offline-eligible at the binding level — an undeclared
/// id or a declared-but-unresolvable binding is the typed denial, never
/// a plaintext or env path (the recorded `NANO_GPT_API_KEY` key name
/// proves neither region nor payment; the recorded subscription base is
/// a separate configured payment class, never a hidden fallback).
#[test]
fn nanogpt_offline_eligibility_is_binding_level_typed() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.nanogpt]\nkind = \"api_key\"\nendpoint = \"https://nano-gpt.com/api/v1\"\ncredential_ref = \"keyring:rivect/ng\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"nanogpt\", model_id = \"openai/gpt-5.5\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("nanogpt"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    // a bound api_key pin is usable without a separate live grant —
    // eligibility reads the binding, never the store
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "nanogpt".to_string(),
        model_id: "openai/gpt-5.5".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a bound api_key pin is usable without a separate live grant"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "nanogpt",
    ));

    // a fixed pin on an undeclared id is the typed unknown-connection
    // denial at eligibility, before any ranking or send
    let undeclared = Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"local\", model_id = \"x\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert!(!rivect::providers::offline_usable(
        &undeclared.connections,
        &undeclared.profiles,
        "nanogpt-missing",
    ));
    let missing = ModelAssign::Fixed(FixedModel {
        connection: "nanogpt-missing".to_string(),
        model_id: "x".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &missing,
                &undeclared.connections,
                &undeclared.profiles,
            ),
            Err(ProviderError::UnknownConnection { .. })
        ),
        "an undeclared pin is the typed denial"
    );

    // a declared binding whose profile ref disagrees with the
    // connection's scope is the typed live-grant denial: the api key
    // is the *declared* binding, never a mismatched one — and this
    // class requires `credential_ref` at admission, so a declared row
    // can never bind absent
    let mismatched = Config::parse_validated(
        "config_version = 1\n\
         [connections.nanogpt]\nkind = \"api_key\"\nendpoint = \"https://nano-gpt.com/api/v1\"\ncredential_ref = \"keyring:rivect/ng-scope\"\nprofile = \"nanogpt-team\"\n\
         [profiles.nanogpt-team]\ncredential_ref = \"keyring:rivect/other\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"nanogpt\", model_id = \"openai/gpt-5.5\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("a profile-bound row is valid");
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "nanogpt".to_string(),
        model_id: "openai/gpt-5.5".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &pin,
                &mismatched.connections,
                &mismatched.profiles,
            ),
            Err(ProviderError::LiveGrantRequired {
                kind: ConnKind::ApiKey
            })
        ),
        "a declared binding that cannot resolve is the typed live-grant denial"
    );
    assert!(
        !rivect::providers::offline_usable(
            &mismatched.connections,
            &mismatched.profiles,
            "nanogpt",
        ),
        "only the resolvable binding is the api-key form"
    );

    // an api_key declaration that binds no credential is refused at
    // admission: the absent-binding predicate names the open proxy and
    // the local-endpoint class alone (DEC-009), so `nanogpt` can never
    // resolve the keyless form the local ids record
    let unbound = Config::parse_validated(
        "config_version = 1\n\
         [connections.nanogpt]\nkind = \"api_key\"\nendpoint = \"https://nano-gpt.com/api/v1\"\n\
         [models.defaults]\nmodel = { mode = \"auto\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    );
    let Err(error) = unbound else {
        panic!("a cloud api_key declaration without a binding is refused at admission")
    };
    assert!(
        matches!(
            &error.issue,
            ConfigIssue::CredentialRefRequired {
                kind: ConnKind::ApiKey
            }
        ),
        "the absent binding is the local-endpoint predicate's alone: {error}"
    );
}

/// `novita` is a served Chat-Completions id under the recorded
/// class-B api-key cell: the dialect map routes the literal id and the
/// api_key pin is offline-eligible at the binding level — an undeclared
/// id or a declared-but-unresolvable binding is the typed denial, never
/// a plaintext or env path (the recorded `NOVITA_API_KEY` key name
/// proves no entitlement, and the recorded login validates against
/// inference, never payment administration).
#[test]
fn novita_offline_eligibility_is_binding_level_typed() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.novita]\nkind = \"api_key\"\nendpoint = \"https://api.novita.ai/openai/v1\"\ncredential_ref = \"keyring:rivect/nv\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"novita\", model_id = \"moonshotai/kimi-k2.7-code\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("novita"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    // a bound api_key pin is usable without a separate live grant —
    // eligibility reads the binding, never the store
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "novita".to_string(),
        model_id: "moonshotai/kimi-k2.7-code".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a bound api_key pin is usable without a separate live grant"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "novita",
    ));

    // a fixed pin on an undeclared id is the typed unknown-connection
    // denial at eligibility, before any ranking or send
    let undeclared = Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"local\", model_id = \"x\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert!(!rivect::providers::offline_usable(
        &undeclared.connections,
        &undeclared.profiles,
        "novita-missing",
    ));
    let missing = ModelAssign::Fixed(FixedModel {
        connection: "novita-missing".to_string(),
        model_id: "x".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &missing,
                &undeclared.connections,
                &undeclared.profiles,
            ),
            Err(ProviderError::UnknownConnection { .. })
        ),
        "an undeclared pin is the typed denial"
    );

    // a declared binding whose profile ref disagrees with the
    // connection's scope is the typed live-grant denial: the api key
    // is the *declared* binding, never a mismatched one — and this
    // class requires `credential_ref` at admission, so a declared row
    // can never bind absent
    let mismatched = Config::parse_validated(
        "config_version = 1\n\
         [connections.novita]\nkind = \"api_key\"\nendpoint = \"https://api.novita.ai/openai/v1\"\ncredential_ref = \"keyring:rivect/nv-scope\"\nprofile = \"novita-team\"\n\
         [profiles.novita-team]\ncredential_ref = \"keyring:rivect/other\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"novita\", model_id = \"moonshotai/kimi-k2.7-code\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("a profile-bound row is valid");
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "novita".to_string(),
        model_id: "moonshotai/kimi-k2.7-code".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &pin,
                &mismatched.connections,
                &mismatched.profiles,
            ),
            Err(ProviderError::LiveGrantRequired {
                kind: ConnKind::ApiKey
            })
        ),
        "a declared binding that cannot resolve is the typed live-grant denial"
    );
    assert!(
        !rivect::providers::offline_usable(&mismatched.connections, &mismatched.profiles, "novita",),
        "only the resolvable binding is the api-key form"
    );

    // an api_key declaration that binds no credential is refused at
    // admission: the absent-binding predicate names the open proxy and
    // the local-endpoint class alone (DEC-009), so `novita` can never
    // resolve the keyless form the local ids record
    let unbound = Config::parse_validated(
        "config_version = 1\n\
         [connections.novita]\nkind = \"api_key\"\nendpoint = \"https://api.novita.ai/openai/v1\"\n\
         [models.defaults]\nmodel = { mode = \"auto\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    );
    let Err(error) = unbound else {
        panic!("a cloud api_key declaration without a binding is refused at admission")
    };
    assert!(
        matches!(
            &error.issue,
            ConfigIssue::CredentialRefRequired {
                kind: ConnKind::ApiKey
            }
        ),
        "the absent binding is the local-endpoint predicate's alone: {error}"
    );
}

/// `nvidia` is a served Chat-Completions id under the recorded
/// class-B api-key cell: the dialect map routes the literal id and the
/// api_key pin is offline-eligible at the binding level — an undeclared
/// id or a declared-but-unresolvable binding is the typed denial, never
/// a plaintext or env path (the recorded `NVIDIA_API_KEY` key name
/// proves no entitlement, and the recorded login validates optionally
/// against inference, never payment administration). A
/// `subscription`-kind declaration is the live-grant class, never this
/// connection's binding (DEC-010).
#[test]
fn nvidia_offline_eligibility_is_binding_level_typed() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.nvidia]\nkind = \"api_key\"\nendpoint = \"https://integrate.api.nvidia.com/v1\"\ncredential_ref = \"keyring:rivect/nv\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"nvidia\", model_id = \"nvidia/llama-3.1-nemotron-70b-instruct\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("nvidia"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
    // a bound api_key pin is usable without a separate live grant —
    // eligibility reads the binding, never the store
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "nvidia".to_string(),
        model_id: "nvidia/llama-3.1-nemotron-70b-instruct".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a bound api_key pin is usable without a separate live grant"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "nvidia",
    ));

    // a fixed pin on an undeclared id is the typed unknown-connection
    // denial at eligibility, before any ranking or send
    let undeclared = Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"local\", model_id = \"x\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert!(!rivect::providers::offline_usable(
        &undeclared.connections,
        &undeclared.profiles,
        "nvidia-missing",
    ));
    let missing = ModelAssign::Fixed(FixedModel {
        connection: "nvidia-missing".to_string(),
        model_id: "x".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &missing,
                &undeclared.connections,
                &undeclared.profiles,
            ),
            Err(ProviderError::UnknownConnection { .. })
        ),
        "an undeclared pin is the typed denial"
    );

    // a declared binding whose profile ref disagrees with the
    // connection's scope is the typed live-grant denial: the api key
    // is the *declared* binding, never a mismatched one — and this
    // class requires `credential_ref` at admission, so a declared row
    // can never bind absent
    let mismatched = Config::parse_validated(
        "config_version = 1\n\
         [connections.nvidia]\nkind = \"api_key\"\nendpoint = \"https://integrate.api.nvidia.com/v1\"\ncredential_ref = \"keyring:rivect/nv-scope\"\nprofile = \"nvidia-team\"\n\
         [profiles.nvidia-team]\ncredential_ref = \"keyring:rivect/other\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"nvidia\", model_id = \"nvidia/llama-3.1-nemotron-70b-instruct\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("a profile-bound row is valid");
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &pin,
                &mismatched.connections,
                &mismatched.profiles,
            ),
            Err(ProviderError::LiveGrantRequired {
                kind: ConnKind::ApiKey
            })
        ),
        "a declared binding that cannot resolve is the typed live-grant denial"
    );
    assert!(
        !rivect::providers::offline_usable(&mismatched.connections, &mismatched.profiles, "nvidia",),
        "only the resolvable binding is the api-key form"
    );

    // the recorded class is the api_key binding: a subscription-kind
    // declaration stays the live-grant class and is never offline
    // usable (DEC-010)
    let subscription = Config::parse_validated(
        "config_version = 1\n\
         [connections.nvidia]\nkind = \"subscription\"\nendpoint = \"https://integrate.api.nvidia.com/v1\"\ncredential_ref = \"keyring:rivect/nv-plan\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"nvidia\", model_id = \"nvidia/llama-3.1-nemotron-70b-instruct\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("a subscription declaration parses");
    assert!(
        !rivect::providers::offline_usable(
            &subscription.connections,
            &subscription.profiles,
            "nvidia",
        ),
        "a subscription declaration never becomes this api-key binding"
    );
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &pin,
                &subscription.connections,
                &subscription.profiles,
            ),
            Err(ProviderError::LiveGrantRequired {
                kind: ConnKind::Subscription
            })
        ),
        "a subscription declaration is the separate live-grant denial"
    );

    // an api_key declaration that binds no credential is refused at
    // admission: the absent-binding predicate names the open proxy and
    // the local-endpoint class alone (DEC-009), so `nvidia` can never
    // resolve the keyless form the local ids record
    let unbound = Config::parse_validated(
        "config_version = 1\n\
         [connections.nvidia]\nkind = \"api_key\"\nendpoint = \"https://integrate.api.nvidia.com/v1\"\n\
         [models.defaults]\nmodel = { mode = \"auto\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    );
    let Err(error) = unbound else {
        panic!("a cloud api_key declaration without a binding is refused at admission")
    };
    assert!(
        matches!(
            &error.issue,
            ConfigIssue::CredentialRefRequired {
                kind: ConnKind::ApiKey
            }
        ),
        "the absent binding is the local-endpoint predicate's alone: {error}"
    );
}

/// `openrouter` is admitted at ingress without a binding for its keyless
/// catalogue, but it is not send-eligible: the eligibility predicate
/// keeps the open-proxy class alone, so the fixed pin is the typed
/// live-grant denial and the real Broker refuses it at prepare. The same
/// literal id with its scoped binding is send-eligible.
#[test]
fn openrouter_unbound_connection_is_not_send_eligible() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.openrouter]\nkind = \"api_key\"\nendpoint = \"https://openrouter.ai/api/v1\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"openrouter\", model_id = \"vendor/tool-model\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"off\" }\n",
    )
    .expect("the keyless catalogue row is admitted at ingress");
    assert_eq!(
        config.connections["openrouter"].credential_ref, None,
        "the admitted row binds no credential"
    );
    assert_eq!(
        rivect::providers::dialect_for("openrouter"),
        Some(Dialect::Responses),
        "the literal id routes to the shared Responses dialect"
    );

    let pin = ModelAssign::Fixed(FixedModel {
        connection: "openrouter".to_string(),
        model_id: "vendor/tool-model".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles),
            Err(ProviderError::LiveGrantRequired {
                kind: ConnKind::ApiKey
            })
        ),
        "the absent binding is not a send grant"
    );
    assert!(
        !rivect::providers::offline_usable(&config.connections, &config.profiles, "openrouter"),
        "keyless catalogue admission never widens send eligibility"
    );

    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let err = broker
        .prepare("main", &config, "/world/openrouter", "goal: keyless send")
        .expect_err("the unbound pin never prepares");
    assert!(
        matches!(
            err,
            ModelError::Provider(ProviderError::LiveGrantRequired {
                kind: ConnKind::ApiKey
            })
        ),
        "the real admission path refuses it: {err:?}"
    );

    // the same literal id with its scoped binding is send-eligible
    let bound = Config::parse_validated(
        "config_version = 1\n\
         [connections.openrouter]\nkind = \"api_key\"\nendpoint = \"https://openrouter.ai/api/v1\"\ncredential_ref = \"keyring:rivect/openrouter\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"openrouter\", model_id = \"vendor/tool-model\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"off\" }\n",
    )
    .expect("the bound row is admitted");
    assert!(
        rivect::providers::offline_usable(&bound.connections, &bound.profiles, "openrouter"),
        "a bound openrouter row is send-eligible"
    );
}

/// `custom-responses` joins the recorded custom-open absent-binding form
/// (DEC-015/DEC-017): the unbound `api_key` row is admitted at ingress and
/// is offline-eligible, and the widened predicate stays scoped to that
/// literal id — `openrouter` remains catalogue-only, an unbound required
/// `api_key` row is still refused at admission, and the bound custom row
/// keeps its own usability.
#[test]
fn custom_responses_eligibility_does_not_widen_other_ids() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.\"custom-responses\"]\nkind = \"api_key\"\nendpoint = \"https://custom.example.invalid/v1\"\n\
         [connections.\"custom-responses-keyed\"]\nkind = \"api_key\"\nendpoint = \"https://custom.example.invalid/v1\"\ncredential_ref = \"keyring:rivect/custom-responses\"\n\
         [connections.openrouter]\nkind = \"api_key\"\nendpoint = \"https://openrouter.ai/api/v1\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"custom-responses\", model_id = \"fixture-custom-model\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"off\" }\n",
    )
    .expect("the custom-open row is admitted at ingress");
    assert_eq!(
        rivect::providers::dialect_for("custom-responses"),
        Some(Dialect::Responses),
        "the literal id routes to the shared Responses dialect"
    );
    assert_eq!(
        config.connections["custom-responses"].credential_ref, None,
        "the unbound row binds no credential"
    );

    let unbound = ModelAssign::Fixed(FixedModel {
        connection: "custom-responses".to_string(),
        model_id: "fixture-custom-model".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&unbound, &config.connections, &config.profiles)
            .is_ok(),
        "the recorded custom-open form is usable without a live grant"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "custom-responses",
    ));
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let manifest = broker
        .prepare(
            "main",
            &config,
            "/world/custom-responses",
            "goal: custom open",
        )
        .expect("the unbound custom pin prepares");
    assert!(
        matches!(&manifest.model, ModelAssign::Fixed(fixed)
            if fixed.connection == "custom-responses"
                && fixed.model_id == "fixture-custom-model"),
        "the prepared manifest pins the custom connection and model: {:?}",
        manifest.model
    );

    // the catalogue-only id keeps its narrower answer: admission without
    // a binding is not a send grant
    let openrouter = ModelAssign::Fixed(FixedModel {
        connection: "openrouter".to_string(),
        model_id: "vendor/tool-model".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(&openrouter, &config.connections, &config.profiles,),
            Err(ProviderError::LiveGrantRequired {
                kind: ConnKind::ApiKey
            })
        ),
        "openrouter keeps its typed live-grant denial"
    );
    assert!(
        !rivect::providers::offline_usable(&config.connections, &config.profiles, "openrouter"),
        "the custom-open form never widens openrouter's send eligibility"
    );

    // a required sibling id still refuses an unbound declaration at ingress
    let required = Config::parse_validated(
        "config_version = 1\n\
         [connections.deepseek]\nkind = \"api_key\"\nendpoint = \"https://api.deepseek.com\"\n\
         [models.defaults]\nmodel = { mode = \"auto\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    );
    let Err(error) = required else {
        panic!("a required api_key declaration without a binding is refused at admission")
    };
    assert!(
        matches!(
            &error.issue,
            ConfigIssue::CredentialRefRequired {
                kind: ConnKind::ApiKey
            }
        ),
        "the absent binding stays scoped to the custom-open class: {error}"
    );

    // the bound custom row is send-eligible like every scoped binding
    let bound = ModelAssign::Fixed(FixedModel {
        connection: "custom-responses-keyed".to_string(),
        model_id: "fixture-custom-model".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&bound, &config.connections, &config.profiles).is_ok(),
        "the bound custom row stays eligible"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "custom-responses-keyed",
    ));
}

/// `azure` records the Responses dialect on the fixed azure resource path
/// (DEC-003/DEC-004): the literal id routes to the shared codec, never a
/// second adapter.
#[test]
fn azure_routes_to_the_responses_dialect() {
    assert_eq!(
        rivect::providers::dialect_for("azure"),
        Some(Dialect::Responses),
        "the literal id routes to the shared Responses dialect"
    );
}

/// `baseten` records the Chat Completions dialect on the fixed
/// `inference.baseten.co/v1` base (DEC-002/DEC-025): the literal id
/// routes to the shared codec, never a second adapter.
#[test]
fn baseten_routes_to_the_chat_completions_dialect() {
    assert_eq!(
        rivect::providers::dialect_for("baseten"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
}

/// `cerebras` records the Chat Completions dialect on the fixed
/// `api.cerebras.ai/v1` base (DEC-002): the literal id routes to the
/// shared codec, never a second adapter.
#[test]
fn cerebras_routes_to_the_chat_completions_dialect() {
    assert_eq!(
        rivect::providers::dialect_for("cerebras"),
        Some(Dialect::ChatCompletions),
        "the literal id routes to the shared Chat Completions dialect"
    );
}

// ----- AC-040h Pro/Max profile is not an offline inference grant --------

/// The login's scoped subscription credential is a live grant, not an
/// offline inference credential: the scoped `SecretRef` resolves at the
/// credential seam the Messages adapter consumes, while the Broker's
/// unchanged offline gate refuses the pin with the typed live-grant
/// denial and the API-key row keeps its own usability.
#[test]
fn anthropic_subscription_profile_is_not_offline_inference() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.anthropic]\nkind = \"api_key\"\nendpoint = \"https://api.anthropic.com/v1\"\ncredential_ref = \"keyring:rivect/anthropic\"\n\
         [connections.anthropic-subscription]\nkind = \"subscription\"\nendpoint = \"https://api.anthropic.com/v1\"\ncredential_ref = \"keyring:rivect/anthropic-pro-max/anthropic-pro-max\"\nprofile = \"anthropic-pro-max\"\n\
         [profiles.anthropic-pro-max]\ncredential_ref = \"keyring:rivect/anthropic-pro-max/anthropic-pro-max\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"anthropic-subscription\", model_id = \"claude-opus-4-8\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"off\" }\n",
    )
    .expect("the isolated pair parses");
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "anthropic-subscription".to_string(),
        model_id: "claude-opus-4-8".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles),
            Err(ProviderError::LiveGrantRequired {
                kind: ConnKind::Subscription
            })
        ),
        "the subscription profile is the live-grant class"
    );
    assert!(
        !rivect::providers::offline_usable(
            &config.connections,
            &config.profiles,
            "anthropic-subscription",
        ),
        "a subscription profile is never offline-usable inference"
    );
    assert!(
        rivect::providers::offline_usable(&config.connections, &config.profiles, "anthropic"),
        "the api-key row keeps its own usability"
    );

    // The login's scoped ref resolves at the credential seam — the
    // Messages adapter reads the stored access token there — while the
    // Broker's offline gate is not weakened.
    let reference = rivect::providers::resolve_credential(&config, "anthropic-subscription")
        .expect("the login's scoped ref resolves for the adapter seam");
    assert_eq!(reference.profile(), "anthropic-pro-max");

    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let err = broker
        .prepare(
            "main",
            &config,
            "/world/pro-max",
            "goal: subscription inference",
        )
        .expect_err("the subscription pin never prepares");
    assert!(
        matches!(
            err,
            ModelError::Provider(ProviderError::LiveGrantRequired {
                kind: ConnKind::Subscription
            })
        ),
        "the real admission path refuses it: {err:?}"
    );
}

// ----- AC-096/AC-096a: recorded task facts rank `auto` -----

const RANK_WORLD: &str = "/world/ranking";

/// The connections whose recorded catalogue rows the ranking legs read:
/// `deepseek` records three built-in rows (reasoning, a million-token window,
/// per-model USD prices), `groq` records its static floor (price and effort
/// marks), `firepass` records two router ids with no window or price, and
/// `yolo-auto` records one pinned seed row. Every id is declared `local` so
/// eligibility is never the fact a case accidentally measures; `held` is the
/// subscription class no scoped reference makes usable offline.
fn ranking_connections() -> &'static str {
    "config_version = 1\n\
     [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
     [connections.deepseek]\nkind = \"local\"\nendpoint = \"https://api.deepseek.com/v1\"\n\
     [connections.groq]\nkind = \"local\"\nendpoint = \"https://api.groq.com/openai/v1\"\n\
     [connections.firepass]\nkind = \"local\"\nendpoint = \"https://api.fireworks.ai/inference/v1\"\n\
     [connections.yolo-auto]\nkind = \"local\"\nendpoint = \"https://yolo-auto.com/v1\"\n\
     [connections.held]\nkind = \"subscription\"\nendpoint = \"https://subscription.fixture.invalid\"\ncredential_ref = \"keyring:rivect/held\"\n"
}

/// One config with the named purpose pools over the recorded connections.
fn ranking_config_text(purposes: &[(&str, &[&str])], effort: &str) -> String {
    let mut text = format!(
        "{}\n[models.defaults]\nmodel = {{ mode = \"auto\" }}\neffort = {effort}\nfallback = {{ mode = \"off\" }}\n",
        ranking_connections()
    );
    for (name, pool) in purposes {
        let listed = pool
            .iter()
            .map(|connection| format!("\"{connection}\""))
            .collect::<Vec<_>>()
            .join(", ");
        text.push_str(&format!(
            "[models.purposes.{name}]\nmodel = {{ mode = \"auto\", pool = [{listed}] }}\neffort = {effort}\n"
        ));
    }
    text
}

fn ranking_config(purposes: &[(&str, &[&str])], effort: &str) -> Config {
    Config::parse_validated(&ranking_config_text(purposes, effort))
        .expect("the ranking fixture validates")
}

fn single_pool_config(pool: &[&str], effort: &str) -> Config {
    ranking_config(&[("main", pool)], effort)
}

/// The recorded task facts one case ranks on.
fn facts(
    surfaces: Option<&[Surface]>,
    tools_required: bool,
    context_tokens_estimate: u64,
    obligations: usize,
    criteria: usize,
) -> RankingFacts {
    RankingFacts::Recorded(RecordedFacts {
        surfaces: surfaces.map(|labels| labels.iter().copied().collect()),
        tools_required,
        context_tokens_estimate,
        obligations,
        criteria,
        remaining_units: BTreeMap::new(),
        scope_chain: Vec::new(),
    })
}

/// The same facts with one recorded scope holding `remaining` units.
fn with_scope(mut facts: RankingFacts, scope: &str, remaining: u64) -> RankingFacts {
    if let RankingFacts::Recorded(recorded) = &mut facts {
        recorded.scope_chain.push(scope.to_string());
        recorded
            .remaining_units
            .insert(scope.to_string(), remaining);
    }
    facts
}

/// The connection one prepared manifest was admitted on.
fn admitted(broker: &Broker, manifest: &RequestManifest) -> String {
    broker
        .admission(&manifest.attempt_id)
        .expect("the prepare admitted the attempt")
        .connection
        .clone()
}

/// The basis one prepared manifest froze on its admission.
fn basis(broker: &Broker, manifest: &RequestManifest) -> String {
    broker
        .admission(&manifest.attempt_id)
        .expect("the prepare admitted the attempt")
        .ranking_basis
        .clone()
        .expect("the recorded ranking froze a basis")
}

fn fixed(connection: &str, model_id: &str) -> ModelAssign {
    ModelAssign::Fixed(FixedModel {
        connection: connection.to_string(),
        model_id: model_id.to_string(),
    })
}

#[test]
fn auto_ranks_a_tool_task_above_pool_order() {
    let config = single_pool_config(&["firepass", "deepseek"], "{ mode = \"auto\" }");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    // Unknown facts keep the declared order: the pool's first entry wins.
    let declared = broker
        .prepare("main", &config, RANK_WORLD, "goal: tool task")
        .expect("the declared request prepares");
    assert_eq!(admitted(&broker, &declared), "firepass");

    // The tool task's own recorded facts rank the context fit above that
    // order — and an unrecorded tools mark excludes nothing.
    let task = facts(None, true, 10_000, 0, 1);
    let ranked = broker
        .prepare_with_facts(
            "main",
            &config,
            RANK_WORLD,
            "goal: tool task",
            InputOrigin::Human,
            &task,
        )
        .expect("the recorded request prepares");
    assert_eq!(admitted(&broker, &ranked), "deepseek");
    assert_eq!(ranked.model, fixed("deepseek", "deepseek-v4-flash"));
    let decision = basis(&broker, &ranked);
    assert!(
        decision.contains("context fit"),
        "the basis names it: {decision}"
    );
    assert!(
        decision.contains("firepass/"),
        "the basis names the candidate it beat: {decision}"
    );
}

#[test]
fn auto_prefers_the_recorded_fit_for_a_risky_surface() {
    let config = single_pool_config(&["firepass", "groq"], "{ mode = \"auto\" }");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let risky = facts(Some(&[Surface::Auth]), false, 10_000, 0, 1);
    let ranked = broker
        .prepare_with_facts(
            "main",
            &config,
            RANK_WORLD,
            "goal: risk",
            InputOrigin::Human,
            &risky,
        )
        .expect("the risky request prepares");
    assert_eq!(admitted(&broker, &ranked), "groq");
    assert_eq!(ranked.model, fixed("groq", "groq/compound"));
    assert_eq!(
        ranked.effort,
        EffortAssign::Fixed {
            value: EffortLevel::High
        },
        "the risky surface asks for the high floor"
    );
    let decision = basis(&broker, &ranked);
    assert!(
        decision.contains("reasoning fit for risky surface auth"),
        "the basis names the risk fact: {decision}"
    );

    // The same pool without a risk fact decides on the recorded price class.
    let plain = facts(None, false, 10_000, 0, 1);
    let ranked = broker
        .prepare_with_facts(
            "main",
            &config,
            RANK_WORLD,
            "goal: plain",
            InputOrigin::Human,
            &plain,
        )
        .expect("the plain request prepares");
    let plain_basis = basis(&broker, &ranked);
    assert!(
        !plain_basis.contains("reasoning fit"),
        "no risk fact, no reasoning basis: {plain_basis}"
    );
    assert!(
        plain_basis.contains("cheapest known full cost"),
        "the price class decides instead: {plain_basis}"
    );
}

#[test]
fn auto_uses_the_cheapest_known_full_cost_and_unknown_price_is_not_free() {
    let lean = single_pool_config(&["firepass", "groq"], "{ mode = \"auto\" }");
    let reversed = single_pool_config(&["groq", "firepass"], "{ mode = \"auto\" }");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let task = facts(None, false, 10_000, 0, 1);
    for config in [&lean, &reversed] {
        let ranked = broker
            .prepare_with_facts(
                "main",
                config,
                RANK_WORLD,
                "goal: cost",
                InputOrigin::Human,
                &task,
            )
            .expect("the cost request prepares");
        // The cheapest stated full cost wins in both pool orders: an unknown
        // price is never read as free, so a `firepass` row never ranks first
        // by carrying no figure at all.
        assert_eq!(ranked.model, fixed("groq", "groq/compound"));
        assert_eq!(admitted(&broker, &ranked), "groq");
    }
}

#[test]
fn single_candidate_changes_only_effort() {
    let config = single_pool_config(&["yolo-auto"], "{ mode = \"auto\" }");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let declared = broker
        .prepare("main", &config, RANK_WORLD, "goal: single")
        .expect("the declared request prepares");
    assert_eq!(
        declared.effort,
        EffortAssign::Auto,
        "unknown facts keep the resolved effort"
    );

    // One connection records one model: the facts move the effort and add no
    // second model to trial.
    let task = facts(None, false, 4_000, 2, 1);
    let ranked = broker
        .prepare_with_facts(
            "main",
            &config,
            RANK_WORLD,
            "goal: single",
            InputOrigin::Human,
            &task,
        )
        .expect("the recorded request prepares");
    assert_eq!(admitted(&broker, &ranked), "yolo-auto");
    assert_eq!(ranked.model, fixed("yolo-auto", "deepseek-flash-v4"));
    assert_eq!(
        ranked.effort,
        EffortAssign::Fixed {
            value: EffortLevel::High
        },
        "two obligations ask for the recorded high level"
    );
    let decision = basis(&broker, &ranked);
    assert!(
        decision.contains("only eligible connection"),
        "one candidate, no comparison invented: {decision}"
    );
    assert!(
        decision.contains("two or more obligations"),
        "the basis names the effort fact: {decision}"
    );
    assert_eq!(broker.accounted_requests(), 0, "prepare trialled no model");
}

#[test]
fn explicit_pin_is_never_overridden() {
    // The purpose pins a model and a level; the facts would otherwise rank the
    // recorded `deepseek` rows first.
    let config = Config::parse_validated(&format!(
        "{}\n[models.defaults]\nmodel = {{ mode = \"auto\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n[models.purposes.main]\nmodel = {{ mode = \"fixed\", connection = \"local\", model_id = \"pinned-model\" }}\neffort = {{ mode = \"fixed\", value = \"low\" }}\n",
        ranking_connections()
    ))
    .expect("the pinned fixture validates");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let risky = facts(Some(&[Surface::Auth]), true, 2_000_000, 4, 5);
    let ranked = broker
        .prepare_with_facts(
            "main",
            &config,
            RANK_WORLD,
            "goal: pinned",
            InputOrigin::Human,
            &risky,
        )
        .expect("the pinned request prepares");
    assert_eq!(ranked.model, fixed("local", "pinned-model"));
    assert_eq!(
        ranked.effort,
        EffortAssign::Fixed {
            value: EffortLevel::Low
        },
        "the pinned level wins over the risky surface's floor"
    );
    assert_eq!(
        broker
            .admission(&ranked.attempt_id)
            .expect("admission")
            .ranking_basis,
        None,
        "a pin is not a ranking and records no basis"
    );
}

#[test]
fn no_eligible_candidate_denies_typed() {
    let config = single_pool_config(&["held"], "{ mode = \"auto\" }");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    for facts in [
        RankingFacts::unknown(),
        facts(Some(&[Surface::Auth]), true, 1_000, 4, 5),
    ] {
        let refused = broker
            .prepare_with_facts(
                "main",
                &config,
                RANK_WORLD,
                "goal: denied",
                InputOrigin::Human,
                &facts,
            )
            .expect_err("no candidate survives eligibility");
        match refused {
            ModelError::NoEligibleCandidate { purpose, rejected } => {
                assert_eq!(purpose, "main");
                assert!(
                    matches!(
                        rejected.as_slice(),
                        [CandidateRejection {
                            connection,
                            cause: RejectionCause::LiveGrantRequired { .. },
                        }] if connection == "held"
                    ),
                    "the denial names the candidate and its cause: {rejected:?}"
                );
            }
            other => panic!("expected the typed denial, got {other:?}"),
        }
    }
}

#[test]
fn exhausted_scope_excludes_a_candidate() {
    let config = single_pool_config(&["deepseek"], "{ mode = \"auto\" }");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let drained = with_scope(facts(None, false, 1_000, 0, 1), "task:root", 0);
    let refused = broker
        .prepare_with_facts(
            "main",
            &config,
            RANK_WORLD,
            "goal: budget",
            InputOrigin::Human,
            &drained,
        )
        .expect_err("an exhausted scope funds no bound");
    // The refusal is the same typed waiting signal the send raises, and it
    // names the scope that holds nothing: no candidate was ranked at all.
    match refused {
        ModelError::BudgetExhausted { scope } => assert_eq!(scope, "task:root"),
        other => panic!("expected the budget exclusion, got {other:?}"),
    }

    // A scope the facts record nothing about is unknown, never zero.
    let funded = with_scope(facts(None, false, 1_000, 0, 1), "task:root", 5);
    broker
        .prepare_with_facts(
            "main",
            &config,
            RANK_WORLD,
            "goal: budget",
            InputOrigin::Human,
            &funded,
        )
        .expect("a funded scope admits the candidate");
    // A chain entry the facts record nothing about is unknown, never zero.
    let unknown = facts(None, false, 1_000, 0, 1);
    broker
        .prepare_with_facts(
            "main",
            &config,
            RANK_WORLD,
            "goal: budget",
            InputOrigin::Human,
            &unknown,
        )
        .expect("a scope the facts do not record excludes nothing");
}

#[test]
fn unknown_fact_is_distinct_from_a_recorded_miss() {
    // `yolo-auto` records a 131072-token window — below this estimate, so a
    // recorded miss; `local` records nothing — an unknown fact; `deepseek`
    // records a fit. The unknown candidate ranks above the recorded miss.
    let config = single_pool_config(&["yolo-auto", "local", "deepseek"], "{ mode = \"auto\" }");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let task = facts(None, false, 200_000, 0, 1);
    let ranked = broker
        .prepare_with_facts(
            "main",
            &config,
            RANK_WORLD,
            "goal: context",
            InputOrigin::Human,
            &task,
        )
        .expect("the context request prepares");
    assert_eq!(ranked.model, fixed("deepseek", "deepseek-v4-flash"));
    let decision = basis(&broker, &ranked);
    assert!(
        decision.contains("local/unrecorded"),
        "the unknown fact outranks the recorded miss: {decision}"
    );
    assert!(
        !decision.contains("yolo-auto/"),
        "the recorded miss never becomes the runner-up: {decision}"
    );
}

#[test]
fn unrecorded_tools_is_not_a_hard_miss() {
    // Every recorded row here carries `tools == false` — "not recorded", not
    // "unsupported" — so the tool task still has an eligible candidate.
    let config = single_pool_config(&["deepseek"], "{ mode = \"auto\" }");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let task = facts(None, true, 1_000, 0, 1);
    let ranked = broker
        .prepare_with_facts(
            "main",
            &config,
            RANK_WORLD,
            "goal: tools",
            InputOrigin::Human,
            &task,
        )
        .expect("an unrecorded tools mark denies nothing");
    assert_eq!(ranked.model, fixed("deepseek", "deepseek-v4-flash"));
}

#[test]
fn context_preference_does_not_hard_exclude_an_unknown_estimate() {
    // `firepass` records neither a window nor an effort ladder: an unknown
    // estimate (zero), a tool requirement and three criteria demote nothing
    // into a denial, and the unknown effort keeps the resolved assignment.
    let config = single_pool_config(&["firepass"], "{ mode = \"auto\" }");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let task = facts(None, true, 0, 0, 3);
    let ranked = broker
        .prepare_with_facts(
            "main",
            &config,
            RANK_WORLD,
            "goal: unknown estimate",
            InputOrigin::Human,
            &task,
        )
        .expect("an unknown estimate and effort deny nothing");
    assert_eq!(ranked.model, fixed("firepass", "kimi-k2.6-turbo"));
    assert_eq!(
        ranked.effort,
        EffortAssign::Auto,
        "an unrecorded ladder keeps the resolved effort"
    );
}

#[test]
fn known_cost_decides_before_declaration_order() {
    // Both candidates record a fitting window and a known price, and the
    // cheaper one is declared *later*: the basis must name the cost key, never
    // the declared order.
    let config = single_pool_config(&["deepseek", "yolo-auto"], "{ mode = \"auto\" }");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let task = facts(None, false, 1_000, 0, 1);
    let ranked = broker
        .prepare_with_facts(
            "main",
            &config,
            RANK_WORLD,
            "goal: cost order",
            InputOrigin::Human,
            &task,
        )
        .expect("the cost request prepares");
    assert_eq!(ranked.model, fixed("yolo-auto", "deepseek-flash-v4"));
    let decision = basis(&broker, &ranked);
    assert!(
        decision.contains("cheaper known full cost"),
        "the basis names the cost key: {decision}"
    );
    assert!(
        !decision.contains("declared order"),
        "the declared order did not decide: {decision}"
    );
}

#[test]
fn recorded_window_below_the_estimate_demotes_without_denying() {
    // `yolo-auto` records a 131072-token window; this estimate exceeds it, so
    // the row is a recorded miss — demoted, never filtered out of eligibility.
    let alone = single_pool_config(&["yolo-auto"], "{ mode = \"auto\" }");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let task = facts(None, false, 200_000, 0, 1);
    let ranked = broker
        .prepare_with_facts(
            "main",
            &alone,
            RANK_WORLD,
            "goal: miss",
            InputOrigin::Human,
            &task,
        )
        .expect("a recorded miss never denies its candidate");
    assert_eq!(ranked.model, fixed("yolo-auto", "deepseek-flash-v4"));

    // Beside a fitting candidate the same row loses the fit comparison, so the
    // demotion is a ranking fact rather than an exclusion.
    let paired = single_pool_config(&["yolo-auto", "deepseek"], "{ mode = \"auto\" }");
    let ranked = broker
        .prepare_with_facts(
            "main",
            &paired,
            RANK_WORLD,
            "goal: miss",
            InputOrigin::Human,
            &task,
        )
        .expect("the fitting candidate is eligible");
    assert_eq!(ranked.model, fixed("deepseek", "deepseek-v4-flash"));
}

#[test]
fn fitting_window_does_not_demote() {
    // A recorded window equal to the estimate is a fit: a later-declared
    // fitting candidate is not demoted below it, and the known price decides.
    let config = single_pool_config(&["yolo-auto", "deepseek"], "{ mode = \"auto\" }");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let task = facts(None, false, 131_072, 0, 1);
    let ranked = broker
        .prepare_with_facts(
            "main",
            &config,
            RANK_WORLD,
            "goal: boundary",
            InputOrigin::Human,
            &task,
        )
        .expect("a boundary fit is a fit");
    assert_eq!(ranked.model, fixed("yolo-auto", "deepseek-flash-v4"));
    let decision = basis(&broker, &ranked);
    assert!(
        decision.contains("cheaper known full cost"),
        "both fit, so the cost decides: {decision}"
    );
}

#[test]
fn three_criteria_ask_for_the_high_recorded_level() {
    let config = single_pool_config(&["yolo-auto"], "{ mode = \"auto\" }");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let task = facts(None, false, 1_000, 0, 3);
    let ranked = broker
        .prepare_with_facts(
            "main",
            &config,
            RANK_WORLD,
            "goal: criteria",
            InputOrigin::Human,
            &task,
        )
        .expect("the criteria request prepares");
    assert_eq!(
        ranked.effort,
        EffortAssign::Fixed {
            value: EffortLevel::High
        },
        "three criteria ask for the medium floor, and the recorded ladder's smallest fit is high"
    );
    let decision = basis(&broker, &ranked);
    assert!(
        decision.contains("three or more criteria"),
        "the basis names the effort fact: {decision}"
    );
}

#[test]
fn surface_fact_flips_the_winner_not_the_pool() {
    // `yolo-auto` records a 131072-token window below this estimate, so
    // without a risk fact the unknown-fact `firepass` row wins; the risk fact
    // alone flips the pick to the recorded reasoning fit.
    let config = single_pool_config(&["firepass", "yolo-auto"], "{ mode = \"auto\" }");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let plain = facts(None, false, 140_000, 0, 1);
    let ranked = broker
        .prepare_with_facts(
            "main",
            &config,
            RANK_WORLD,
            "goal: surface",
            InputOrigin::Human,
            &plain,
        )
        .expect("the plain request prepares");
    assert_eq!(admitted(&broker, &ranked), "firepass");
    let risky = facts(Some(&[Surface::Auth]), false, 140_000, 0, 1);
    let ranked = broker
        .prepare_with_facts(
            "main",
            &config,
            RANK_WORLD,
            "goal: surface",
            InputOrigin::Human,
            &risky,
        )
        .expect("the risky request prepares");
    assert_eq!(admitted(&broker, &ranked), "yolo-auto");
}

/// Serves every connection and fails the first send only: the fallback leg's
/// substitute then reaches the real loopback, so one physical attempt settles
/// on each side of the chain.
struct FailFirstProvider {
    inner: LoopbackProvider,
    failed: bool,
}

impl Provider for FailFirstProvider {
    fn name(&self) -> &'static str {
        "fail-first"
    }

    fn serves(&self, _connection: &str, _entry: &rivect::config::Connection) -> bool {
        true
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        if !self.failed {
            self.failed = true;
            return Err(ProviderError::UnsupportedParameter {
                connection: "yolo-auto".to_string(),
                parameter: "fixture-parameter",
                model: "fixture-model".to_string(),
            });
        }
        self.inner.send(manifest)
    }
}

#[test]
fn substitute_settles_without_the_primary_basis() {
    // The primary ranks on recorded facts and records its basis; the chain's
    // substitute was chosen by no ranking, so its own row keeps an unknown
    // basis rather than inheriting the primary's explanation.
    let config = Config::parse_validated(&format!(
        "{}\n[models.defaults]\nmodel = {{ mode = \"auto\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"auto\" }}\n[models.purposes.main]\nmodel = {{ mode = \"auto\", pool = [\"yolo-auto\"] }}\nfallback = {{ mode = \"auto\", chain = [ {{ mode = \"fixed\", connection = \"local\", model_id = \"fallback-model\" }} ] }}\n",
        ranking_connections()
    ))
    .expect("the fallback ranking fixture validates");
    let mut broker = Broker::new(Box::new(FailFirstProvider {
        inner: LoopbackProvider::new(),
        failed: false,
    }));
    let root = tempfile::TempDir::with_prefix("rivect-ranking-fallback-").expect("fixture root");
    let mut store =
        rivect::state::TaskStore::open(&root.path().join("state.db")).expect("the store opens");
    store
        .open_budget("ranking-fallback", 10)
        .expect("the scope opens");
    let task = facts(None, false, 1_000, 0, 1);
    let primary = broker
        .prepare_with_facts(
            "main",
            &config,
            RANK_WORLD,
            "goal: fallback",
            InputOrigin::Human,
            &task,
        )
        .expect("the primary prepares");
    let ranked = basis(&broker, &primary);
    {
        let mut ledger =
            rivect::state::StoreLedger::new(&mut store, vec!["ranking-fallback".to_string()]);
        broker
            .dispatch(&mut ledger, RANK_WORLD, &primary)
            .expect("the chain entry answers");
    }
    assert_eq!(
        store
            .settlement(&primary.attempt_id)
            .expect("the primary settled")
            .ranking_basis,
        Some(ranked),
        "the ranked primary keeps its basis"
    );
    let substitute = store
        .settlements_for_parent(&primary.attempt_id)
        .expect("the substitute rows read")
        .pop()
        .expect("the chain entry settled one substitute");
    assert_eq!(
        substitute.ranking_basis, None,
        "no ranking chose the substitute, so it records no basis"
    );
}

#[test]
fn alphabet_and_stage_name_rules_do_not_decide() {
    // Alphabetically and in pool order `deepseek` precedes `groq`; the
    // recorded miss at this estimate ranks `groq` first instead.
    let config = ranking_config(
        &[
            ("planning", &["deepseek", "groq"]),
            ("code", &["deepseek", "groq"]),
        ],
        "{ mode = \"auto\" }",
    );
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let task = facts(None, false, 2_000_000, 0, 1);
    let mut picks = Vec::new();
    for purpose in ["planning", "code"] {
        let ranked = broker
            .prepare_with_facts(
                purpose,
                &config,
                RANK_WORLD,
                "goal: purpose",
                InputOrigin::Human,
                &task,
            )
            .expect("the purpose prepares");
        assert_eq!(ranked.model, fixed("groq", "groq/compound"));
        picks.push(ranked.model);
    }
    assert_eq!(
        picks[0], picks[1],
        "the purpose name decides nothing: the same facts pick the same model"
    );
}

/// The scripted challenge reply: one risk per selected risky surface, read
/// from the manifest inputs so no fixed template can match.
struct ChallengeProvider {
    sent: Arc<Mutex<Vec<RequestManifest>>>,
}

impl Provider for ChallengeProvider {
    fn name(&self) -> &'static str {
        "challenge-fixture"
    }

    fn serves(&self, _connection: &str, _entry: &rivect::config::Connection) -> bool {
        true
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        self.sent.lock().expect("sent lock").push(manifest.clone());
        let inputs: serde_json::Value =
            serde_json::from_str(&manifest.inputs).expect("manifest inputs are json");
        let risks: Vec<serde_json::Value> = inputs["surfaces"]
            .as_array()
            .expect("surfaces")
            .iter()
            .map(|label| json!({ "surface": label, "text": format!("risk on {label}") }))
            .collect();
        Ok(ProviderReply {
            text: json!({ "risks": risks }).to_string(),
            tool_calls: Vec::new(),
            usage: UsageDelta::Unknown,
            wire_retries: 0,
            dropped_reasoning: 0,
        })
    }
}

#[test]
fn action_dispatch_uses_task_facts_for_auto() {
    // A long goal puts the action's context estimate above `yolo-auto`'s
    // recorded window, so without the request's risk fact the unknown-fact
    // `firepass` row wins; the risk fact alone flips the pick to `yolo-auto`.
    let config_toml = ranking_config_text(
        &[
            ("challenge_direction", &["yolo-auto", "firepass"]),
            ("design_contracts", &["yolo-auto", "firepass"]),
        ],
        "{ mode = \"auto\" }",
    );
    let mut world = support::open_world("routing-action-facts", Some(&config_toml));
    let config = world.runtime.config_for_broker();
    let session = world.open_session("action-facts-session");
    // The goal is bounded well below a recorded window, so the estimate is
    // lifted by a wide criterion set: the action's inputs carry all of them.
    let task = submit_wide_task(&mut world, &session, "action-facts-task", 12_000, 12);
    let request = PlanRequest {
        task_id: task.clone(),
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
    let sent = Arc::new(Mutex::new(Vec::new()));
    let mut broker = Broker::new(Box::new(ChallengeProvider { sent: sent.clone() }));
    let outcome = {
        let mut seam = BrokerSeam {
            broker: &mut broker,
            world: RANK_WORLD,
        };
        ActionRegistry::new().execute_with_seam(
            ActionInput::ChallengeDirection(request),
            &mut world.runtime.action_context(&session, &config),
            Some(&mut seam),
        )
    };
    assert!(
        matches!(outcome, Ok(ActionOutcome::Challenged { .. })),
        "the semantic leg answers: {outcome:?}"
    );
    let sent = sent.lock().expect("sent lock").clone();
    assert_eq!(sent.len(), 1, "one physical request");
    assert!(
        sent[0].inputs.chars().count() > 131_072,
        "the action's estimate exceeds the recorded window: {}",
        sent[0].inputs.chars().count()
    );
    assert_eq!(
        sent[0].model,
        fixed("yolo-auto", "deepseek-flash-v4"),
        "the action dispatched the risk-fact pick"
    );

    // The same facts without the request's surface scan pick the other
    // connection: the surface is the fact that decided, not the pool order.
    let snapshot = world
        .runtime
        .store()
        .snapshot(&task)
        .expect("the snapshot reads");
    let plain = RankingFacts::Recorded(RecordedFacts {
        surfaces: None,
        tools_required: false,
        context_tokens_estimate: u64::try_from(sent[0].inputs.chars().count()).unwrap_or(u64::MAX),
        obligations: snapshot.obligations.items.len(),
        criteria: snapshot.criteria.items.len(),
        remaining_units: BTreeMap::new(),
        scope_chain: Vec::new(),
    });
    let mut control = Broker::new(Box::new(LoopbackProvider::new()));
    let plain = control
        .prepare_with_facts(
            "challenge_direction",
            &config,
            RANK_WORLD,
            &sent[0].inputs,
            InputOrigin::Tool,
            &plain,
        )
        .expect("the surface-less control prepares");
    assert_eq!(
        admitted(&control, &plain),
        "firepass",
        "without the surface fact the unknown-fact row wins"
    );
}

/// One task whose contract carries `criteria` criteria of `criterion_len`
/// characters each, so the action's context estimate crosses a recorded
/// window while the goal itself stays inside its own bound.
fn submit_wide_task(
    world: &mut support::World,
    session: &rivect::contracts::SessionId,
    command_id: &str,
    criterion_len: usize,
    criteria: usize,
) -> rivect::contracts::TaskId {
    let items: Vec<String> = (0..criteria)
        .map(|index| format!("{} {index}", "y".repeat(criterion_len)))
        .collect();
    let request = json!({
        "jsonrpc": "2.0", "id": 4, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": command_id, "session_id": session.0,
            "kind": "create",
            "goal": "Bound the recorded surface.",
            "contract": { "criteria": items, "constraints": [] },
            "attachments": []
        }
    });
    let response = world.dispatch(&request);
    rivect::contracts::TaskId(
        response["result"]["task_id"]
            .as_str()
            .unwrap_or_else(|| panic!("task.submit failed: {response}"))
            .to_string(),
    )
}

/// The two codex literals own one recorded dialect and never substitute a
/// sibling id: the adapter refuses a foreign pin before any wire leg, and
/// a configured region stays the typed denial instead of borrowing another
/// endpoint.
#[test]
fn openai_codex_never_falls_back_across_id_or_region() {
    for (id, sibling) in [
        ("openai-codex", "openai-codex-device"),
        ("openai-codex-device", "openai-codex"),
    ] {
        assert_eq!(
            rivect::providers::dialect_for(id),
            Some(Dialect::Responses),
            "{id} records the Responses dialect"
        );
        assert!(
            rivect::providers::routes_for(id).is_empty(),
            "{id} is single-dialect and records no cross-route table"
        );
        let config = Config::parse_validated(&support::codex_provider_config(
            id,
            "http://127.0.0.1:1/backend-api/codex",
        ))
        .expect("the codex config parses");
        let entry = config.connections.get(id).expect("declared").clone();
        let credential = support::codex_stored_credential();
        let store = Arc::new(support::MapStore::seeded(
            rivect::providers::StoreKind::Keychain,
            &[(support::CODEX_REF, credential.as_str())],
        ));
        let built = config.clone();
        let id_owned = id.to_string();
        let provider = std::thread::spawn(move || {
            rivect::providers::openai::OpenAiProvider::new(&built, &id_owned, store)
        })
        .join()
        .expect("the provider thread joins")
        .expect("the codex adapter builds");
        assert!(provider.serves(id, &entry));
        assert!(
            !provider.serves(sibling, &entry),
            "{id} never serves the sibling literal id"
        );

        let mut manifest = {
            let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
            broker
                .prepare("main", &config, "/world/codex", "goal: no fallback")
                .expect("the codex pin prepares")
        };
        manifest.model = ModelAssign::Fixed(FixedModel {
            connection: sibling.to_string(),
            model_id: "gpt-5.2-codex".to_string(),
        });
        let (provider, outcome) = support::send_on_thread(provider, manifest);
        assert!(
            matches!(outcome, Err(ProviderError::DialectMismatch { .. })),
            "a foreign pin never falls back into this adapter: {outcome:?}"
        );
        support::drop_blocking(provider);

        let regional = Config::parse_validated(
            &support::codex_provider_config(id, "http://127.0.0.1:1/backend-api/codex")
                .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
        )
        .expect("the regional config parses");
        let store = Arc::new(support::MapStore::seeded(
            rivect::providers::StoreKind::Keychain,
            &[],
        ));
        let denied = std::thread::spawn(move || {
            rivect::providers::openai::OpenAiProvider::new(&regional, id, store)
        })
        .join()
        .expect("the provider thread joins")
        .expect_err("a configured region never borrows another endpoint");
        assert!(
            matches!(&denied, ProviderError::RegionMismatch { connection, region }
                if connection == id && region == "eu"),
            "the typed region denial: {denied:?}"
        );
    }
}

/// The gateway id owns the Messages dialect and never substitutes a
/// sibling id or a region default: the adapter refuses a foreign pin
/// before any wire leg, and a configured region stays the typed denial.
#[test]
fn vercel_ai_gateway_never_falls_back_across_id_or_region() {
    assert_eq!(
        rivect::providers::dialect_for("vercel-ai-gateway"),
        Some(Dialect::Messages)
    );
    assert!(
        rivect::providers::routes_for("vercel-ai-gateway").is_empty(),
        "the gateway is single-dialect and records no cross-route table"
    );
    let toml = "config_version = 1\n\
         [connections.vercel-ai-gateway]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1/v1\"\ncredential_ref = \"keyring:rivect-test/vercel-ai-gateway\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"vercel-ai-gateway\", model_id = \"anthropic/claude-opus-5\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"off\" }\n";
    let config = Config::parse_validated(toml).expect("the gateway config parses");
    let store = Arc::new(support::MapStore::seeded(
        rivect::providers::StoreKind::Keychain,
        &[(
            "keyring:rivect-test/vercel-ai-gateway",
            "fixture-vercel-key-not-real",
        )],
    ));
    let built = config.clone();
    let provider = std::thread::spawn(move || {
        rivect::providers::anthropic::MessagesProvider::new(&built, "vercel-ai-gateway", store)
    })
    .join()
    .expect("the provider thread joins")
    .expect("the gateway adapter builds");

    let mut manifest = {
        let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
        broker
            .prepare("main", &config, "/world/vercel", "goal: no fallback")
            .expect("the gateway pin prepares")
    };
    manifest.model = ModelAssign::Fixed(FixedModel {
        connection: "anthropic".to_string(),
        model_id: "claude-opus-4-8".to_string(),
    });
    let (provider, outcome) = support::send_on_thread(provider, manifest);
    assert!(
        matches!(outcome, Err(ProviderError::DialectMismatch { .. })),
        "a foreign pin never falls back into this adapter: {outcome:?}"
    );
    support::drop_blocking(provider);

    let regional = Config::parse_validated(
        &toml.replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("the regional config parses");
    let store = Arc::new(support::MapStore::seeded(
        rivect::providers::StoreKind::Keychain,
        &[],
    ));
    let denied = std::thread::spawn(move || {
        rivect::providers::anthropic::MessagesProvider::new(&regional, "vercel-ai-gateway", store)
    })
    .join()
    .expect("the provider thread joins")
    .expect_err("a configured region never borrows another endpoint");
    assert!(
        matches!(&denied, ProviderError::RegionMismatch { connection, region }
            if connection == "vercel-ai-gateway" && region == "eu"),
        "the typed region denial: {denied:?}"
    );
}

/// The operator-configured Messages origin owns no default base and no
/// route table: the adapter refuses a foreign pin before any wire leg, a
/// configured region stays the typed denial, and the empty endpoint names
/// no host at all — a manual id is admitted by the arm, never by a
/// recorded alias table.
#[test]
fn custom_messages_never_falls_back_across_id_or_region() {
    assert_eq!(
        rivect::providers::dialect_for("custom-messages"),
        Some(Dialect::Messages)
    );
    assert!(
        rivect::providers::routes_for("custom-messages").is_empty(),
        "the id records no cross-route table"
    );
    assert_eq!(
        rivect::providers::route_for("custom-messages", "fixture-messages-model"),
        None,
        "a manual id is admitted by the arm, not by a recorded alias table"
    );
    let toml = "config_version = 1\n\
         [connections.custom-messages]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1/v1\"\ncredential_ref = \"keyring:rivect-test/custom-messages\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"custom-messages\", model_id = \"fixture-messages-model\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"off\" }\n";
    let config = Config::parse_validated(toml).expect("the configured origin parses");
    let store = Arc::new(support::MapStore::seeded(
        rivect::providers::StoreKind::Keychain,
        &[(
            "keyring:rivect-test/custom-messages",
            "fixture-messages-key-not-real",
        )],
    ));
    let built = config.clone();
    let provider = std::thread::spawn(move || {
        rivect::providers::anthropic::MessagesProvider::new(&built, "custom-messages", store)
    })
    .join()
    .expect("the provider thread joins")
    .expect("the configured origin builds");

    let mut manifest = {
        let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
        broker
            .prepare(
                "main",
                &config,
                "/world/custom-messages",
                "goal: no fallback",
            )
            .expect("the configured pin prepares")
    };
    manifest.model = ModelAssign::Fixed(FixedModel {
        connection: "anthropic".to_string(),
        model_id: "claude-opus-4-8".to_string(),
    });
    let (provider, outcome) = support::send_on_thread(provider, manifest);
    assert!(
        matches!(outcome, Err(ProviderError::DialectMismatch { .. })),
        "a foreign pin never falls back into this adapter: {outcome:?}"
    );
    support::drop_blocking(provider);

    let regional = Config::parse_validated(
        &toml.replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("the regional config parses");
    let store = Arc::new(support::MapStore::seeded(
        rivect::providers::StoreKind::Keychain,
        &[],
    ));
    let denied = std::thread::spawn(move || {
        rivect::providers::anthropic::MessagesProvider::new(&regional, "custom-messages", store)
    })
    .join()
    .expect("the provider thread joins")
    .expect_err("a configured region never borrows another endpoint");
    assert!(
        matches!(&denied, ProviderError::RegionMismatch { connection, region }
            if connection == "custom-messages" && region == "eu"),
        "the typed region denial: {denied:?}"
    );

    let empty = Config::parse_validated(&toml.replace("http://127.0.0.1:1/v1", "")).expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        rivect::providers::StoreKind::Keychain,
        &[],
    ));
    let denied = std::thread::spawn(move || {
        rivect::providers::anthropic::MessagesProvider::new(&empty, "custom-messages", store)
    })
    .join()
    .expect("the provider thread joins")
    .expect_err("the arm invents no default origin");
    assert!(
        matches!(&denied, ProviderError::EndpointRequired { connection }
            if connection == "custom-messages"),
        "the typed endpoint denial: {denied:?}"
    );
}

/// The `zenmux` route table separates the recorded Chat Completions
/// default from the metadata's Anthropic class with no third route and
/// no cross-route fallback: the Messages arm refuses a default-class
/// model before any wire leg, and the literal default keeps `new` on the
/// Chat Completions codec.
#[test]
fn zenmux_never_falls_back_across_route_or_id() {
    assert_eq!(
        rivect::providers::dialect_for("zenmux"),
        Some(Dialect::ChatCompletions),
        "the literal default is the recorded Chat Completions dialect"
    );
    assert_eq!(
        rivect::providers::routes_for("zenmux"),
        &[Dialect::ChatCompletions, Dialect::Messages],
        "only the recorded two-route table exists"
    );
    for (model, expected) in [
        ("anthropic/claude-opus-4.8", Dialect::Messages),
        ("anthropic/claude-haiku-4.5", Dialect::Messages),
        ("google/gemini-3-pro-preview", Dialect::ChatCompletions),
        ("openai/gpt-6.1-terra", Dialect::ChatCompletions),
        ("claude-opus-4.8", Dialect::ChatCompletions),
        ("fixture/unknown-model", Dialect::ChatCompletions),
    ] {
        assert_eq!(
            rivect::providers::route_for("zenmux", model),
            Some(expected),
            "{model} takes its recorded route"
        );
    }

    let toml = "config_version = 1\n\
         [connections.zenmux]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1/api/v1\"\ncredential_ref = \"keyring:rivect-test/zenmux\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"zenmux\", model_id = \"google/gemini-3-pro-preview\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"off\" }\n";
    let config = Config::parse_validated(toml).expect("the zenmux config parses");
    let store = Arc::new(support::MapStore::seeded(
        rivect::providers::StoreKind::Keychain,
        &[("keyring:rivect-test/zenmux", "fixture-zenmux-key-not-real")],
    ));
    let reference = rivect::providers::SecretRef::parse("keyring:rivect-test/zenmux")
        .expect("the scoped ref parses");
    let built = config.clone();
    let provider = std::thread::spawn(move || {
        rivect::providers::anthropic::MessagesProvider::with_route(
            &built,
            "zenmux",
            store,
            std::time::Duration::from_secs(1),
            rivect::providers::WireAuth::Store(Some(reference)),
        )
    })
    .join()
    .expect("the provider thread joins")
    .expect("the Messages route builds");

    let manifest = {
        let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
        broker
            .prepare("main", &config, "/world/zenmux", "goal: no fallback")
            .expect("the pin prepares")
    };
    let (provider, outcome) = support::send_on_thread(provider, manifest);
    assert!(
        matches!(
            outcome,
            Err(ProviderError::UnsupportedParameter {
                parameter: "model",
                ..
            })
        ),
        "a default-class model never enters the Messages route: {outcome:?}"
    );
    support::drop_blocking(provider);

    let regional = Config::parse_validated(
        &toml.replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("the regional config parses");
    let store = Arc::new(support::MapStore::seeded(
        rivect::providers::StoreKind::Keychain,
        &[],
    ));
    let denied = std::thread::spawn(move || {
        rivect::providers::anthropic::MessagesProvider::with_route(
            &regional,
            "zenmux",
            store,
            std::time::Duration::from_secs(1),
            rivect::providers::WireAuth::Store(None),
        )
    })
    .join()
    .expect("the provider thread joins")
    .expect_err("a configured region never borrows a route");
    assert!(
        matches!(&denied, ProviderError::RegionMismatch { connection, region }
            if connection == "zenmux" && region == "eu"),
        "the typed region denial: {denied:?}"
    );
}

/// A definitive primary denial is the only failure a manual pause may
/// follow. The same-recorded-contract sibling is removed from the served
/// candidates and refused again if a caller names it directly.
struct DefinitiveFailProvider {
    inner: LoopbackProvider,
    failed: bool,
}

impl Provider for DefinitiveFailProvider {
    fn name(&self) -> &'static str {
        "definitive-fail"
    }

    fn serves(&self, _connection: &str, _entry: &rivect::config::Connection) -> bool {
        true
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        if !self.failed {
            self.failed = true;
            return Err(ProviderError::UnsupportedParameter {
                connection: "openai-codex".to_string(),
                parameter: "fixture",
                model: "gpt-5.2-codex".to_string(),
            });
        }
        self.inner.send(manifest)
    }
}

fn codex_manual_config(eligible: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.openai-codex]\nkind = \"api_key\"\nendpoint = \"https://chatgpt.com/backend-api/codex\"\n\
         credential_ref = \"{reference}\"\nprofile = \"openai-codex\"\n\
         [connections.openai-codex-device]\nkind = \"api_key\"\nendpoint = \"https://chatgpt.com/backend-api/codex\"\n\
         credential_ref = \"{reference}\"\nprofile = \"openai-codex\"\n\
         [connections.reserve]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11435\"\n\
         [profiles.openai-codex]\ncredential_ref = \"{reference}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"openai-codex\", model_id = \"gpt-5.2-codex\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\nfallback = {{ mode = \"auto\" }}\n\
         [models.purposes.relay]\n\
         model = {{ mode = \"fixed\", connection = \"openai-codex\", model_id = \"gpt-5.2-codex\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"manual\" }}\neligible = [{eligible}]\n",
        reference = support::CODEX_REF,
    )
}

#[test]
fn manual_fallback_filters_the_same_contract_sibling_from_its_choices() {
    let config = Config::parse_validated(&codex_manual_config(
        "\"openai-codex\", \"openai-codex-device\"",
    ))
    .expect("the manual codex fixture validates");
    let mut broker = Broker::new(Box::new(DefinitiveFailProvider {
        inner: LoopbackProvider::new(),
        failed: false,
    }));
    let manifest = broker
        .prepare(
            "relay",
            &config,
            "/world/codex-manual",
            "goal: manual sibling",
        )
        .expect("the codex pin prepares");
    let outcome = broker.dispatch(
        &mut rivect::model::NullLedger,
        "/world/codex-manual",
        &manifest,
    );
    let Err(error) = outcome else {
        panic!("the empty served set exhausts instead of pausing: {outcome:?}");
    };
    let ModelError::FallbackExhausted {
        rejected,
        attempted,
        ..
    } = error
    else {
        panic!("no servable candidate is the typed exhaustion: {error:?}");
    };
    assert!(
        attempted.is_empty(),
        "the filtered sibling never receives a send: {attempted:?}"
    );
    let sibling = rejected
        .iter()
        .find(|rejection| rejection.connection == "openai-codex-device")
        .expect("the filtered sibling is reported, not dropped silently");
    assert!(
        matches!(sibling.cause, RejectionCause::BlindRetryRefused),
        "the refusal names the same-contract blind retry: {:?}",
        sibling.cause
    );
    assert!(
        rejected
            .iter()
            .any(|rejection| rejection.connection == "reserve"),
        "every evaluated non-primary connection keeps its cause: {rejected:?}"
    );
    assert!(
        broker.pending_choice(&manifest.attempt_id).is_none(),
        "the same-contract sibling is never offered"
    );
}

#[test]
fn manual_pick_of_the_same_contract_sibling_is_refused() {
    let config = Config::parse_validated(&codex_manual_config(
        "\"openai-codex\", \"openai-codex-device\", \"reserve\"",
    ))
    .expect("the manual codex fixture validates");
    let mut broker = Broker::new(Box::new(DefinitiveFailProvider {
        inner: LoopbackProvider::new(),
        failed: false,
    }));
    let manifest = broker
        .prepare("relay", &config, "/world/codex-pick", "goal: manual pick")
        .expect("the codex pin prepares");
    let error = broker
        .dispatch(
            &mut rivect::model::NullLedger,
            "/world/codex-pick",
            &manifest,
        )
        .expect_err("the definitive primary denial pauses");
    assert!(
        matches!(error, ModelError::ManualFallbackPending { .. }),
        "a servable different contract still pauses: {error:?}"
    );
    let choice = broker
        .pending_choice(&manifest.attempt_id)
        .expect("the pause serves its candidates");
    assert!(
        !choice
            .candidates
            .contains(&"openai-codex-device".to_string()),
        "the sibling is filtered from the pause: {choice:?}"
    );
    let picked = broker.dispatch_fallback_choice(
        &mut rivect::model::NullLedger,
        "/world/codex-pick",
        &manifest.attempt_id,
        "openai-codex-device",
    );
    assert!(
        matches!(
            picked,
            Err(ModelError::ManualChoiceRejected {
                cause: RejectionCause::BlindRetryRefused,
                ..
            })
        ),
        "a direct pick is refused by the contract classification: {picked:?}"
    );
}

/// Serves every connection and fails the primary once with an entered 503:
/// the outcome may already have applied remotely, so only the auto walk
/// stops — a manual fallback still asks the human.
struct UnknownOutcomeFailProvider {
    inner: LoopbackProvider,
    failed: bool,
}

impl Provider for UnknownOutcomeFailProvider {
    fn name(&self) -> &'static str {
        "unknown-outcome-fail"
    }

    fn serves(&self, _connection: &str, _entry: &rivect::config::Connection) -> bool {
        true
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        if !self.failed {
            self.failed = true;
            return Err(ProviderError::Transport {
                connection: "openai-codex".to_string(),
                cause: TransportCause::Status {
                    status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
                },
            });
        }
        self.inner.send(manifest)
    }
}

/// AC-045: an entered unknown outcome ends only the auto walk. A manual
/// fallback still pauses for the human — the pending choice rides
/// question.current — and the same-contract sibling stays filtered from the
/// served candidates, so the pause can only be answered by a different
/// recorded contract.
#[test]
fn manual_fallback_still_pauses_on_an_unknown_primary_outcome() {
    let config = Config::parse_validated(&codex_manual_config(
        "\"openai-codex\", \"openai-codex-device\", \"reserve\"",
    ))
    .expect("the manual codex fixture validates");
    let mut broker = Broker::new(Box::new(UnknownOutcomeFailProvider {
        inner: LoopbackProvider::new(),
        failed: false,
    }));
    let manifest = broker
        .prepare(
            "relay",
            &config,
            "/world/codex-unknown",
            "goal: manual unknown",
        )
        .expect("the codex pin prepares");
    let error = broker
        .dispatch(
            &mut rivect::model::NullLedger,
            "/world/codex-unknown",
            &manifest,
        )
        .expect_err("an unknown primary still pauses a manual fallback");
    assert!(
        matches!(error, ModelError::ManualFallbackPending { .. }),
        "the manual pause is the typed outcome, never a provider close: {error:?}"
    );
    let choice = broker
        .pending_choice(&manifest.attempt_id)
        .expect("the pause serves its candidates");
    assert_eq!(
        choice.candidates,
        vec!["reserve".to_string()],
        "the failed primary and its same-contract sibling are never offered: {choice:?}"
    );
    assert!(
        choice.unknown_outcome,
        "an entered 503 is an unknown outcome the pause must disclose: {choice:?}"
    );
    assert!(
        broker.admission(&manifest.attempt_id).is_some(),
        "the paused primary stays admitted for the human's answer"
    );
}

/// One declaration carrying every frozen field: kind, endpoint, credential
/// reference, region and profile all present on the pinned row.
fn frozen_entry_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [profiles.pinned]\ncredential_ref = \"keyring:rivect-test/pinned\"\n\
         [connections.pinned]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\n\
         credential_ref = \"keyring:rivect-test/pinned\"\nregion = \"eu-west-1\"\nprofile = \"pinned\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"pinned\", model_id = \"pinned-model\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// TD-01: the admission freezes the whole connection entry the ranking
/// read — kind, endpoint, credential reference, region and profile — so
/// the dispatch re-check compares the admitted config, never a later
/// document.
#[test]
fn admission_freezes_the_connection_entry_fields() {
    let config = Config::parse_validated(&frozen_entry_config("https://api.example.invalid/v1"))
        .expect("valid");
    let (mut broker, _sent) = recording_broker();
    let manifest = broker
        .prepare(
            "main",
            &config,
            "/world/activation",
            "goal: frozen connection entry",
        )
        .expect("manifest");
    let admission = broker.admission(&manifest.attempt_id).expect("admitted");
    let declared = config.connections.get("pinned").expect("declared");
    assert_eq!(&admission.connection_entry, declared);
    assert_eq!(admission.connection_entry.kind, ConnKind::ApiKey);
    assert_eq!(
        admission.connection_entry.endpoint,
        "https://api.example.invalid/v1"
    );
    assert_eq!(
        admission.connection_entry.credential_ref.as_deref(),
        Some("keyring:rivect-test/pinned")
    );
    assert_eq!(
        admission.connection_entry.region.as_deref(),
        Some("eu-west-1")
    );
    assert_eq!(
        admission.connection_entry.profile.as_deref(),
        Some("pinned")
    );
}

/// TD-01: a differing current view entry denies `ConnectionChanged`
/// before the reservation or any provider call — the admitted request
/// keeps the config it was ranked on.
#[test]
fn a_differing_current_connection_view_denies_changed_before_send() {
    let config = Config::parse_validated(&local_config(
        "fixture-model",
        "{ mode = \"fixed\", value = \"medium\" }",
    ))
    .expect("valid");
    let (mut broker, sent) = recording_broker();
    let manifest = broker
        .prepare(
            "main",
            &config,
            "/world/activation",
            "goal: stale connection view",
        )
        .expect("manifest");

    let mut edited = config.clone();
    let entry = edited.connections.get_mut("local").expect("declared");
    entry.endpoint = "http://127.0.0.1:11435".to_string();
    entry.region = Some("eu-west-1".to_string());
    broker.set_config(&edited);

    let mut ledger = support::CountingLedger::new();
    let error = broker
        .dispatch(&mut ledger, "/world/activation", &manifest)
        .expect_err("the differing entry must deny the admitted request");
    match error {
        ModelError::ConnectionChanged {
            attempt_id,
            connection,
        } => {
            assert_eq!(attempt_id, manifest.attempt_id);
            assert_eq!(connection, "local");
        }
        other => panic!("expected ConnectionChanged, got {other:?}"),
    }
    assert!(
        sent.lock().expect("wire log lock").is_empty(),
        "a denied dispatch never reaches the provider"
    );
    assert_eq!(
        (ledger.begun, ledger.finished),
        (0, 0),
        "a denied dispatch opens no settlement"
    );
    assert_eq!(broker.accounted_requests(), 0);
}

/// TD-01: only the admitted connection's entry is compared — an edit to
/// another view entry never blocks an in-flight request.
#[test]
fn an_unrelated_view_edit_keeps_the_admitted_request_sendable() {
    let config = Config::parse_validated(&local_config(
        "fixture-model",
        "{ mode = \"fixed\", value = \"medium\" }",
    ))
    .expect("valid");
    let (mut broker, sent) = recording_broker();
    let manifest = broker
        .prepare(
            "main",
            &config,
            "/world/activation",
            "goal: unrelated view edit",
        )
        .expect("manifest");

    let mut edited = config.clone();
    edited.connections.insert(
        "later".to_string(),
        rivect::config::Connection {
            kind: ConnKind::Local,
            endpoint: "http://127.0.0.1:11436".to_string(),
            credential_ref: None,
            region: None,
            profile: None,
        },
    );
    broker.set_config(&edited);

    let mut ledger = support::CountingLedger::new();
    let reply = broker
        .dispatch(&mut ledger, "/world/activation", &manifest)
        .expect("the admitted entry is unchanged, so the request still sends");
    assert!(!reply.text.is_empty());
    assert_eq!(
        sent.lock().expect("wire log lock").len(),
        1,
        "the unchanged entry still reaches the provider"
    );
    assert_eq!((ledger.begun, ledger.finished), (1, 1));
}

/// TD-01: every field of the admitted connection entry is frozen, not only
/// the endpoint pair a multi-field edit moves: each single-field mutation —
/// kind, endpoint, credential reference, region, profile — and removal of
/// the admitted entry itself denies `ConnectionChanged` before any
/// reservation, provider call or settlement.
#[test]
fn every_single_frozen_entry_field_and_removal_denies_changed_before_send() {
    type EntryMutation = (&'static str, fn(&mut Config));
    let mutations: [EntryMutation; 6] = [
        ("kind", |config| {
            config.connections.get_mut("pinned").expect("declared").kind = ConnKind::Local;
        }),
        ("endpoint", |config| {
            config
                .connections
                .get_mut("pinned")
                .expect("declared")
                .endpoint = "https://api.example.invalid/v2".to_string();
        }),
        ("credential_ref", |config| {
            config
                .connections
                .get_mut("pinned")
                .expect("declared")
                .credential_ref = Some("keyring:rivect-test/rotated".to_string());
        }),
        ("region", |config| {
            config
                .connections
                .get_mut("pinned")
                .expect("declared")
                .region = Some("us-east-2".to_string());
        }),
        ("profile", |config| {
            config
                .connections
                .get_mut("pinned")
                .expect("declared")
                .profile = Some("rotated".to_string());
        }),
        ("removal", |config| {
            config.connections.remove("pinned");
        }),
    ];
    for (field, mutate) in mutations {
        let config =
            Config::parse_validated(&frozen_entry_config("https://api.example.invalid/v1"))
                .expect("valid");
        let (mut broker, sent) = recording_broker();
        let manifest = broker
            .prepare(
                "main",
                &config,
                "/world/activation",
                "goal: frozen entry field",
            )
            .expect("manifest");
        let mut edited = config.clone();
        mutate(&mut edited);
        broker.set_config(&edited);

        let mut ledger = support::CountingLedger::new();
        let error = broker
            .dispatch(&mut ledger, "/world/activation", &manifest)
            .expect_err("the edited entry must deny the admitted request");
        match error {
            ModelError::ConnectionChanged {
                attempt_id,
                connection,
            } => {
                assert_eq!(attempt_id, manifest.attempt_id, "{field}");
                assert_eq!(connection, "pinned", "{field}");
            }
            other => panic!("expected ConnectionChanged for the {field} edit, got {other:?}"),
        }
        assert!(
            sent.lock().expect("wire log lock").is_empty(),
            "the {field} edit never reaches the provider"
        );
        assert_eq!(
            (ledger.begun, ledger.finished),
            (0, 0),
            "the {field} edit opens no settlement"
        );
        assert_eq!(
            broker.accounted_requests(),
            0,
            "the {field} edit spends nothing"
        );
    }
}

/// TD-01/A2: a profile's own `credential_ref` is the binding the send
/// resolves, so rotating it denies the admitted request even though the
/// connection entry is byte-identical — the frozen credential, not the row,
/// is what an edit to the profile moves.
#[test]
fn a_rotated_profile_credential_denies_changed_before_send() {
    let config = Config::parse_validated(&frozen_entry_config("https://api.example.invalid/v1"))
        .expect("valid");
    let (mut broker, sent) = recording_broker();
    let manifest = broker
        .prepare(
            "main",
            &config,
            "/world/activation",
            "goal: rotated profile credential",
        )
        .expect("manifest");
    let admission = broker.admission(&manifest.attempt_id).expect("admitted");
    assert_eq!(
        admission.credential.as_deref(),
        Some("keyring:rivect-test/pinned"),
        "the ranking's effective credential is frozen on the admission"
    );

    let mut edited = config.clone();
    edited
        .profiles
        .get_mut("pinned")
        .expect("declared")
        .credential_ref = Some("keyring:rivect-test/rotated/pinned".to_string());
    broker.set_config(&edited);
    assert_eq!(
        edited.connections.get("pinned"),
        config.connections.get("pinned"),
        "the connection row is untouched, so only the credential comparison can deny"
    );

    let mut ledger = support::CountingLedger::new();
    let error = broker
        .dispatch(&mut ledger, "/world/activation", &manifest)
        .expect_err("the rotated credential must deny the admitted request");
    match error {
        ModelError::ConnectionChanged {
            attempt_id,
            connection,
        } => {
            assert_eq!(attempt_id, manifest.attempt_id);
            assert_eq!(connection, "pinned");
        }
        other => panic!("expected ConnectionChanged, got {other:?}"),
    }
    assert!(
        sent.lock().expect("wire log lock").is_empty(),
        "the rotated credential never reaches the provider"
    );
    assert_eq!(
        (ledger.begun, ledger.finished),
        (0, 0),
        "the rotated credential opens no settlement"
    );
}

// ----- SLICE-005: Kimi Code routed inference ------------------------------

/// `kimi-code` records the two-protocol route table under the api-key
/// class (the `research/provider-coverage.md` device-code row; DEC-031
/// re-pinned only this roster): the Messages default is its dialect, a
/// bound api-key pin is offline-eligible without a separate live grant,
/// both recorded routes stay declared, and an unresolved binding is the
/// typed live-grant denial — never a plaintext or env path.
#[test]
fn kimi_code_offline_eligibility_is_binding_level_typed() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.kimi-code]\nkind = \"api_key\"\nendpoint = \"https://api.kimi.com/coding/v1\"\ncredential_ref = \"keyring:rivect/kimi-device\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"kimi-code\", model_id = \"kimi-k3\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    assert_eq!(
        rivect::providers::dialect_for("kimi-code"),
        Some(Dialect::Messages),
        "the literal id keeps the recorded Messages default"
    );
    assert_eq!(
        rivect::providers::routes_for("kimi-code"),
        [Dialect::Messages, Dialect::ChatCompletions],
        "the id records both protocols; the model's listing selects one"
    );
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "kimi-code".to_string(),
        model_id: "kimi-k3".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a bound api_key pin is usable without a separate live grant"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "kimi-code",
    ));

    let undeclared = ModelAssign::Fixed(FixedModel {
        connection: "kimi-missing".to_string(),
        model_id: "kimi-k3".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(&undeclared, &config.connections, &config.profiles,),
            Err(ProviderError::UnknownConnection { .. })
        ),
        "an undeclared pin is the typed denial"
    );

    let mismatched = Config::parse_validated(
        "config_version = 1\n\
         [connections.kimi-code]\nkind = \"api_key\"\nendpoint = \"https://api.kimi.com/coding/v1\"\ncredential_ref = \"keyring:rivect/kimi-device\"\nprofile = \"kimi-device\"\n\
         [profiles.kimi-device]\ncredential_ref = \"keyring:rivect/other\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"kimi-code\", model_id = \"kimi-k3\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("a profile-bound row is valid");
    let pin = ModelAssign::Fixed(FixedModel {
        connection: "kimi-code".to_string(),
        model_id: "kimi-k3".to_string(),
    });
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &pin,
                &mismatched.connections,
                &mismatched.profiles,
            ),
            Err(ProviderError::LiveGrantRequired {
                kind: ConnKind::ApiKey
            })
        ),
        "a declared binding that cannot resolve is the typed live-grant denial"
    );
    assert!(
        !rivect::providers::offline_usable(
            &mismatched.connections,
            &mismatched.profiles,
            "kimi-code",
        ),
        "only the resolvable binding is the api-key form"
    );
}

// ----- SLICE-006: Z.AI coding-plan routed inference -----------------------

/// `zai` and `zai-coding-plan` are one recorded backend, not two: both
/// literals resolve the same Messages default and the same two-transport
/// route table, a bound canonical `zai` profile is offline-eligible without
/// a separate live grant, and an unresolved binding keeps the typed
/// live-grant denial.
#[test]
fn zai_aliases_resolve_one_coding_plan_backend() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.zai]\nkind = \"api_key\"\nendpoint = \"https://api.z.ai\"\ncredential_ref = \"keychain:rivect/zai\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"zai\", model_id = \"glm-5.2\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("valid");
    for alias in ["zai", "zai-coding-plan"] {
        assert_eq!(
            rivect::providers::dialect_for(alias),
            Some(Dialect::Messages),
            "{alias} keeps the recorded Messages default"
        );
        assert_eq!(
            rivect::providers::routes_for(alias),
            [Dialect::Messages, Dialect::ChatCompletions],
            "{alias} records exactly the two coding-plan transports"
        );
    }
    assert_eq!(
        rivect::providers::dialect_for("zai"),
        rivect::providers::dialect_for("zai-coding-plan"),
        "the alias is not a second backend"
    );
    assert_eq!(
        rivect::providers::zai::route_for("glm-5.2"),
        Some(Dialect::Messages),
        "the bundled row selects the Messages transport"
    );
    assert_eq!(
        rivect::providers::zai::route_for("glm-5.3-flash"),
        Some(Dialect::ChatCompletions),
        "the bundled row selects the Chat transport"
    );

    let pin = ModelAssign::Fixed(FixedModel {
        connection: "zai".to_string(),
        model_id: "glm-5.2".to_string(),
    });
    assert!(
        rivect::providers::offline_eligible(&pin, &config.connections, &config.profiles).is_ok(),
        "a bound api_key pin is usable without a separate live grant"
    );
    assert!(rivect::providers::offline_usable(
        &config.connections,
        &config.profiles,
        "zai",
    ));

    let mismatched = Config::parse_validated(
        "config_version = 1\n\
         [connections.zai]\nkind = \"api_key\"\nendpoint = \"https://api.z.ai\"\ncredential_ref = \"keychain:rivect/zai\"\n\
         profile = \"zai\"\n\
         [profiles.zai]\ncredential_ref = \"keychain:rivect/other\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"zai\", model_id = \"glm-5.2\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n",
    )
    .expect("a profile-bound row is valid");
    assert!(
        matches!(
            rivect::providers::offline_eligible(
                &pin,
                &mismatched.connections,
                &mismatched.profiles,
            ),
            Err(ProviderError::LiveGrantRequired {
                kind: ConnKind::ApiKey
            })
        ),
        "a declared binding that cannot resolve is the typed live-grant denial"
    );
    assert!(
        !rivect::providers::offline_usable(&mismatched.connections, &mismatched.profiles, "zai",),
        "only the resolvable canonical binding is the api-key form"
    );
}
