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

use rivect::config::{
    Config, ConfigIssue, ConnKind, EffortAssign, EffortLevel, FixedModel, ModelAssign, Stage,
};
use rivect::contracts::{Availability, MODEL_WIRE_MAX_BYTES, OptionId, Question, QuestionOption};
use rivect::model::{
    Broker, CallContract, CandidateRejection, EpochMutationReason, ModelError, RejectionCause,
    RequestManifest,
};
use rivect::providers::{Dialect, LoopbackProvider, Provider, ProviderError, ProviderReply};
use rivect::resources::UsageDelta;
use serde_json::json;
use std::collections::VecDeque;
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
    let auto = Config::parse_validated(&local_config("fixture-model", "{ mode = \"auto\" }"))
        .expect("valid");
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
        .dispatch("/world/rights", &frozen)
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
        .dispatch("/world/fallback", &manifest)
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
        .dispatch(&manifest.world.clone(), &manifest)
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
        .dispatch("/world/off", &manifest)
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
        .dispatch("/world/off", &manifest)
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
        .dispatch("/world/eligible", &manifest)
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
        .dispatch("/world/retry", &manifest)
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
        .dispatch("/world/retry", &doomed)
        .expect_err("a cancelled attempt never re-dispatches");
    assert!(
        matches!(&late, ModelError::AttemptCancelled { attempt_id }
            if attempt_id == &doomed.attempt_id),
        "wrong rejection: {late}"
    );
    let again = broker
        .dispatch("/world/retry", &doomed)
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
        .dispatch("/world/cancel", &manifest)
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
        .dispatch("/world/cancel", &manual)
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
    broker.dispatch("/world/cancel", &done).expect("dispatch");
    assert!(
        !broker.cancel_attempt(&done.attempt_id),
        "a spent attempt is not cancelled"
    );
    let replay = broker
        .dispatch("/world/cancel", &done)
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
        .dispatch("/world/exhausted", &manifest)
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
        .dispatch("/world/exhausted", &manifest)
        .expect("the paused attempt retries the same manifest");
    assert_eq!(sent.lock().expect("wire log lock").len(), 3);
    assert_eq!(broker.accounted_requests(), 1);

    let request = reqwest::blocking::Client::builder().no_proxy().build().expect("client")
        .get("ftp://fixture-user:fixture-secret@127.0.0.1/private-path?token=fixture-query#fixture-fragment")
        .send().expect_err("the unsupported scheme is refused without network access");
    assert!(request.is_builder());
    let original = ProviderError::Transport {
        connection: "local".to_string(),
        cause: rivect::providers::TransportCause::Request {
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
        .dispatch("/world/transport-exhausted", &manifest)
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
    assert_eq!(
        cause.class(),
        rivect::providers::TransportClass::RequestFailure
    );
    let retained = std::error::Error::source(&error)
        .and_then(|source| source.downcast_ref::<Box<ProviderError>>())
        .expect("the broker retains its primary source");
    let cause = std::error::Error::source(retained.as_ref())
        .and_then(|source| source.downcast_ref::<rivect::providers::TransportCause>())
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
                cause: rivect::providers::TransportCause::Status {
                    status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
                },
            }),
            rivect::contracts::ErrorCode::Denied,
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
        use rivect::providers::TransportCause;
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
        .dispatch("/world/walk", &manifest)
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
        .dispatch("/world/epoch", &manifest)
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
        .dispatch_fallback_choice("/world/manual-epoch", &manifest.attempt_id, "reserve")
        .expect_err("an un-paused Manual admission has no substitute path");
    assert!(
        matches!(&premature, ModelError::NoPendingChoice { .. }),
        "wrong rejection: {premature}"
    );

    let error = broker
        .dispatch("/world/manual-epoch", &manifest)
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
        .dispatch_fallback_choice("/world/manual-epoch", &manifest.attempt_id, "local")
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
        .dispatch_fallback_choice("/world/manual-epoch", &manifest.attempt_id, "reserve")
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
        .dispatch_fallback_choice("/world/manual-epoch", &manifest.attempt_id, "reserve")
        .expect("the retried pick dispatches the substitute");
    let refused = broker
        .dispatch_fallback_choice("/world/manual-epoch", &manifest.attempt_id, "reserve")
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
        .dispatch("/world/wedge", &manifest)
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
        .dispatch("/world/view", &manifest)
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
        .dispatch("/world/stream", &first)
        .expect("the first dispatch confirms its tool effect");
    assert_eq!(
        confirmed.tool_calls.len(),
        1,
        "the admitted read effect ran"
    );

    // the stream's re-send of the spent attempt is the replay surface:
    // it can never re-run the confirmed effect
    let replay = broker
        .dispatch("/world/stream", &first)
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
        .dispatch("/world/stream", &follow)
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
        .dispatch("/world/stream", &substitute_manifest)
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
            }),
            Respond::Reply(ProviderReply {
                text: "two".to_string(),
                tool_calls: Vec::new(),
                usage: UsageDelta::Unknown,
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
        .dispatch("/world/usage", &first)
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
        .dispatch("/world/usage", &second)
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
        .dispatch("/world/profiles", &manifest)
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
        .dispatch("/world/profiles", &manifest)
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
        .dispatch("/world/reserved", &manifest)
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
