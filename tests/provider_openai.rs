//! OpenAI provider proof legs (TP-PROVIDER-{CATALOG,AUTH,WIRE,
//! RECOVERY,INSTALLED}::openai): the configured literal `openai`
//! connection returns a verified model outcome through the standard
//! Broker — the real synchronous adapter against the source-derived
//! protocol peer as localhost wiremock fixtures, no OMP, no user
//! adapter, no real host. The SSE legs pin the shared parser's WHATWG
//! §9.2.5–9.2.6 conformance. TP-PROVIDER-INSTALLED::openai stays
//! NOT_RUN — the ignored named case carries that status explicitly.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/discard conveniences; src/ stays strict (standards §14)"
)]

use rivect::config::Config;
use rivect::model::{Broker, ModelError, RequestManifest};
use rivect::providers::openai::OpenAiProvider;
use rivect::providers::sse::{SseError, SseParser};
use rivect::providers::{Provider, ProviderError, StoreKind};
use rivect::resources::UsageDelta;
use serde_json::{Value, json};
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

mod support;

use support::{
    SlowStore, drop_blocking, mount_responses, received_bodies, responses_completed_stream,
    send_on_thread, sse_block,
};

/// The scoped credential ref the `openai` connection binds — a
/// `keyring:` ref resolves to the platform's native class, which the
/// offline store double serves by scope alone.
const CREDENTIAL_REF: &str = "keyring:rivect-test/openai";
/// A sibling scope holding real material while the bound scope stays
/// empty: seeded so a no-secret assertion proves no cross-scope
/// material leaks into a typed denial, never vacuously true.
const NEIGHBOR_REF: &str = "keyring:rivect-test/neighbor";
/// Fixture material — never a real token, only ever sent to localhost.
/// Deliberately not shaped like a provider key so the secret gate and
/// any future scrubbing never see a plausible credential in fixtures.
const SECRET: &str = "fixture-token-not-a-real-credential";

/// The fixture store's class label is never consulted offline — the
/// double resolves by scope; a name keeps the seam honest.
const STORE_KIND: StoreKind = StoreKind::Keychain;

/// One configured `openai` connection pointing at the fixture peer:
/// the api_key auth class resolves a scoped `SecretRef` (DEC-011), the
/// dialect comes from the literal connection id (DEC-007).
fn openai_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.openai]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"openai\", model_id = \"gpt-5.2\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// reqwest's blocking client builds and drops a shell runtime inside
/// `wait::enter` — panicking in any tokio context (debug builds) — so
/// every `OpenAiProvider` construction happens on a plain OS thread.
fn provider_result(
    config: Config,
    connection: String,
    store: Arc<support::MapStore>,
) -> Result<OpenAiProvider, ProviderError> {
    std::thread::spawn(move || OpenAiProvider::new(&config, &connection, store))
        .join()
        .expect("the provider thread joins")
}

fn openai_provider(config: &Config) -> (OpenAiProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let provider = provider_result(config.clone(), "openai".to_string(), store.clone())
        .expect("the openai adapter builds for the literal id");
    (provider, store)
}

/// The configured endpoint is the API base — `/v1` included, like
/// `https://api.openai.com/v1` — and the adapter appends the recorded
/// resource paths.
fn server_uri_v1(server: &MockServer) -> String {
    format!("{}/v1", server.uri())
}

fn received_auth(request: &Request) -> String {
    request
        .headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .expect("the request carried an authorization header")
        .to_string()
}

/// A prepared manifest plus the broker that admitted it — the real
/// admission path, not a constructed manifest.
fn prepared(config: &Config, world: &str, inputs: &str) -> (Broker, RequestManifest) {
    let (provider, _store) = openai_provider(config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", config, world, inputs)
        .expect("the openai pin passes DEC-011 eligibility");
    (broker, manifest)
}

/// One frozen manifest through the real admission path.
fn prepared_manifest(config: &Config) -> RequestManifest {
    let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
    broker
        .prepare("main", config, "/world/openai", "goal: auth leg")
        .expect("the openai pin prepares")
}

/// The blocking provider send runs on a plain OS thread: reqwest's
/// blocking wait panics inside any tokio context — even the blocking
/// pool — and the fixture peer needs this runtime's thread anyway.
fn dispatch(
    mut broker: Broker,
    world: &str,
    manifest: RequestManifest,
) -> (Broker, Result<rivect::providers::ProviderReply, ModelError>) {
    let world = world.to_string();
    std::thread::spawn(move || {
        let outcome = broker.dispatch(&world, &manifest);
        (broker, outcome)
    })
    .join()
    .expect("the dispatch thread joins")
}

// ----- TP-PROVIDER-WIRE::openai -------------------------------------

/// A configured `openai` connection returns a verified model outcome
/// through the standard Broker: prepare admits the api_key pin under
/// DEC-011, the adapter posts exactly the frozen manifest as a
/// Responses request — `store: false`, `stream: true`, pinned model,
/// instructions, tool surface and effort verbatim — the SSE stream
/// validates its terminal, and the one physical send is charged once
/// with the provider's reported usage.
#[tokio::test]
async fn valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "verified outcome text",
            Vec::new(),
            Some(json!({"input_tokens": 11, "output_tokens": 7, "total_tokens": 18})),
        ),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: prove the wire");

    let (broker, outcome) = dispatch(broker, "/world/openai", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified outcome text");
    assert!(reply.tool_calls.is_empty());

    // The wire request is exactly the frozen manifest — and nothing
    // the manifest does not carry.
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request");
    assert_eq!(received_auth(&requests[0]), format!("Bearer {SECRET}"));
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], "gpt-5.2");
    assert_eq!(body["store"], false);
    assert_eq!(body["stream"], true);
    assert_eq!(
        body["include"],
        json!(["reasoning.encrypted_content"]),
        "the replay contract asks for the reasoning artifact verbatim (SRC-019/D-006)"
    );
    assert_eq!(body["instructions"], manifest.instructions);
    assert_eq!(body["reasoning"], json!({"effort": "medium"}));
    assert_eq!(
        body["tools"],
        json!([{ "type": "function", "name": "read_file" }])
    );
    assert_eq!(
        body["input"],
        json!([{
            "role": "user",
            "content": [{ "type": "input_text", "text": manifest.inputs }],
        }])
    );

    // Exactly one accounting record carries the one physical usage
    // report — the bound was 33k-reserved, the provider's 18 tokens
    // are the confirmed charge, and a replayed attempt reports spent.
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "openai");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 11,
            completion_tokens: 7,
            total_tokens: 18,
        }
    );
    let explain = broker.sent_cost_explain(&manifest);
    assert_eq!(explain.bound, manifest.cost_bound);
    assert_eq!(explain.confirmed, Some(18));
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay = broker.dispatch("/world/openai", &manifest);
            (broker, replay)
        })
        .join()
        .expect("the replay thread joins")
    };
    assert!(
        matches!(replay, Err(ModelError::AttemptAlreadyAccounted { .. })),
        "the spent attempt never re-sends: {replay:?}"
    );
    drop_blocking(broker);
}

/// The dialect keys on the literal connection id, never an auth
/// label: a connection id without the recorded Responses source class
/// builds no adapter, and a manifest pinning a different connection
/// id is refused at send.
#[tokio::test]
async fn dialect_is_keyed_on_the_literal_connection_id() {
    let server = MockServer::start().await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = provider_result(config.clone(), "openai-codex".to_string(), store)
        .expect_err("a different literal id is not this dialect");
    assert!(matches!(err, ProviderError::DialectMismatch { .. }));

    let (mut provider, _store) = openai_provider(&config);
    let foreign = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.other]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"other\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let mut manifest = {
        let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
        broker
            .prepare("main", &foreign, "/world/openai", "goal: x")
            .expect("foreign pin prepares")
    };
    let (p, outcome) = send_on_thread(provider, manifest.clone());
    provider = p;
    assert!(
        matches!(outcome, Err(ProviderError::DialectMismatch { .. })),
        "a foreign pin never speaks this dialect: {outcome:?}"
    );
    manifest.model = rivect::config::ModelAssign::Auto { pool: None };
    let (provider, outcome) = send_on_thread(provider, manifest);
    assert!(
        matches!(outcome, Err(ProviderError::UnpinnedModel { .. })),
        "an unpinned assignment names no model for the wire: {outcome:?}"
    );
    drop_blocking(provider);
}

// ----- TP-PROVIDER-CATALOG::openai ----------------------------------

/// `GET /models` filtered to the recorded Responses-capable sample:
/// ids the dialect cannot serve are never offered, and the bearer
/// credential came through the store seam.
#[tokio::test]
async fn provider_catalog_filters_models_to_the_responses_sample() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [
                {"id": "gpt-5.2", "object": "model"},
                {"id": "o3", "object": "model"},
                {"id": "dall-e-3", "object": "model"},
                {"id": "text-embedding-3-large", "object": "model"},
            ],
        })))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = openai_provider(&config);
    let ids = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("the catalog thread joins")
        .expect("the catalog answers");
    assert_eq!(ids, vec!["gpt-5.2".to_string(), "o3".to_string()]);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(received_auth(&requests[0]), format!("Bearer {SECRET}"));
}

/// The listing payload is bounded like the stream: a body past the
/// byte bound is a typed violation, never buffered unbounded.
#[tokio::test]
async fn catalog_payload_over_the_byte_bound_is_a_typed_violation() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            // the bound is 1 MiB — one byte past it trips the read loop
            "x".repeat(1024 * 1024 + 1),
        ))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = openai_provider(&config);
    let outcome = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("the catalog thread joins");
    assert!(
        matches!(outcome, Err(ProviderError::StreamViolation { .. })),
        "an over-bound catalog payload is a typed violation: {outcome:?}"
    );
}

/// The listing reads under the same whole-request deadline: a peer
/// dribbling `/models` byte-by-byte trips the total budget, never
/// parks the call inside a per-read window.
#[tokio::test]
async fn dribbling_catalog_cannot_park_past_the_deadline() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let peer = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n");
            while stream.write_all(b"x").is_ok() {
                std::thread::sleep(Duration::from_millis(30));
            }
        }
    });
    let endpoint = format!("http://{address}/v1");
    let config = Config::parse_validated(&openai_config(&endpoint)).expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let built = config.clone();
    let provider = std::thread::spawn(move || {
        OpenAiProvider::with_deadline(&built, "openai", store, Duration::from_millis(1500))
    })
    .join()
    .expect("the provider thread joins")
    .expect("the adapter builds");

    let began = Instant::now();
    let outcome = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("the catalog thread joins");
    let elapsed = began.elapsed();
    match outcome {
        Err(ProviderError::Transport { reason, .. }) => {
            assert!(
                reason.contains("deadline"),
                "the total deadline is the named cause: {reason}"
            );
        }
        other => panic!("a dribbling peer is a typed transport denial: {other:?}"),
    }
    assert!(
        elapsed < Duration::from_secs(10),
        "the listing ended near its deadline, not the 120s per-read bound: {elapsed:?}"
    );
    peer.join().expect("the drip thread joins");
}

/// AC-046 fail-closed: eligibility says the `openai` pin is usable,
/// but a broker whose only adapter is the local fixture must still
/// deny the send — the provider's own dialect claim is the last
/// gate, and the denial lands before any send or accounting.
#[test]
fn a_pin_no_adapter_serves_is_denied_before_send_or_accounting() {
    let config = Config::parse_validated(&openai_config("http://127.0.0.1:1/v1")).expect("valid");
    let (provider, calls, _manifest) = support::CountingProvider::new();
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/openai", "goal: unserved pin")
        .expect("the openai pin passes DEC-011 eligibility");
    let outcome = broker.dispatch("/world/openai", &manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::DialectUnserved { .. }))
        ),
        "a pin the broker's provider cannot serve is a typed denial: {outcome:?}"
    );
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the provider never saw the request"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a denied send is never accounted"
    );
}

/// AC-046 fail-closed the other way: a connection id `dialect_for`
/// reserves for a live dialect is never fixture-served, whatever kind
/// it declares — `openai` declaring `local` kind gets the typed denial,
/// never a fabricated loopback reply.
#[test]
fn a_reserved_dialect_id_is_never_loopback_served() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.openai]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"openai\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"medium\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let loopback = rivect::providers::LoopbackProvider::new();
    let entry = config.connections.get("openai").expect("declared");
    assert!(
        !loopback.serves("openai", entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );
    let mut broker = Broker::new(Box::new(loopback));
    let manifest = broker
        .prepare("main", &config, "/world/openai", "goal: reserved id")
        .expect("the local-kind pin passes DEC-011 eligibility");
    let outcome = broker.dispatch("/world/openai", &manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::DialectUnserved { .. }))
        ),
        "a dialect-reserved id is denied, never fabricated: {outcome:?}"
    );
}

/// AC-045: an explicit manual pick of a served `openai` candidate
/// reaches the real send — the substitute's single-member auto pool
/// pins the connection, the live catalogue names the model, and the
/// send is attempted instead of deterministically failing
/// `UnpinnedModel` after eligibility already passed.
#[tokio::test]
async fn a_manual_pick_of_an_openai_candidate_reaches_the_real_send() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "gpt-5.2", "object": "model"}],
        })))
        .mount(&server)
        .await;
    mount_responses(
        &server,
        responses_completed_stream(
            "picked outcome",
            Vec::new(),
            Some(json!({"input_tokens": 1, "output_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [connections.openai]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"manual\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let (provider, _store) = openai_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/openai", "goal: pick openai")
        .expect("the auto ranking admits a candidate");
    let attempt_id = manifest.attempt_id.clone();

    // The adapter speaks no `local` dialect: the primary send fails
    // and the manual pause offers the served openai candidate.
    let (mut broker, outcome) = std::thread::spawn(move || {
        let outcome = broker.dispatch("/world/openai", &manifest);
        (broker, outcome)
    })
    .join()
    .expect("the dispatch thread joins");
    assert!(
        matches!(outcome, Err(ModelError::ManualFallbackPending { .. })),
        "the failed primary pauses for the human pick: {outcome:?}"
    );
    let pending = broker
        .pending_choice(&attempt_id)
        .expect("the pause published its candidates");
    assert!(
        pending.candidates.contains(&"openai".to_string()),
        "the served candidate is offered: {:?}",
        pending.candidates
    );

    let (broker, outcome) = std::thread::spawn(move || {
        let outcome = broker.dispatch_fallback_choice("/world/openai", &attempt_id, "openai");
        (broker, outcome)
    })
    .join()
    .expect("the pick thread joins");
    let reply = outcome.expect("the explicit pick sends — never UnpinnedModel");
    assert_eq!(reply.text, "picked outcome");

    // The catalogue lookup resolved the wire model, then the one
    // physical send carried it.
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "the catalogue resolution plus the one physical send"
    );
    let body: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert_eq!(
        body["model"], "gpt-5.2",
        "the live catalogue named the model the pick resolved to"
    );
    drop_blocking(broker);
}

/// The same auto seam on the primary send: `mode = "auto"` ranks the
/// `openai` connection, the dispatch narrows the pool to the winner it
/// picked, and the adapter's catalogue leg names the wire model —
/// `UnpinnedModel` never fires on a send the broker itself routed.
#[tokio::test]
async fn auto_ranked_openai_primary_send_resolves_via_catalog() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [
                {"id": "o3", "object": "model"},
                {"id": "gpt-5.2", "object": "model"},
                {"id": "dall-e-3", "object": "model"},
            ],
        })))
        .mount(&server)
        .await;
    mount_responses(
        &server,
        responses_completed_stream(
            "auto outcome",
            Vec::new(),
            Some(json!({"input_tokens": 2, "output_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.openai]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: auto route");
    assert!(
        matches!(
            manifest.model,
            rivect::config::ModelAssign::Auto { pool: None }
        ),
        "the ranked auto assignment stays un-narrowed on the frozen manifest"
    );

    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    let reply = outcome.expect("the ranked auto send resolves its model");
    assert_eq!(reply.text, "auto outcome");

    // The catalogue leg resolved the wire model, then the one
    // physical send carried the deterministic sorted-first id.
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "the catalogue resolution plus the one physical send"
    );
    assert_eq!(received_auth(&requests[0]), format!("Bearer {SECRET}"));
    let body: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert_eq!(
        body["model"], "gpt-5.2",
        "the catalogue's sorted-first Responses id rode the wire"
    );
    assert_eq!(broker.accounted_requests(), 1);
    drop_blocking(broker);
}

/// DEC-014: the whole-request deadline is one budget over connect,
/// request send and every stream read — a peer that dribbles a byte
/// inside each per-read window can never park a dispatch: only the
/// total elapsed trips the bound, not any single read.
#[tokio::test]
async fn dribbling_peer_cannot_park_the_send_past_the_deadline() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let peer = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n");
            // one byte per tick — every individual read answers inside
            // its own window, so only a total deadline can end this
            while stream.write_all(b"x").is_ok() {
                std::thread::sleep(Duration::from_millis(30));
            }
        }
    });
    let endpoint = format!("http://{address}/v1");
    let config = Config::parse_validated(&openai_config(&endpoint)).expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let built = config.clone();
    let provider = std::thread::spawn(move || {
        OpenAiProvider::with_deadline(&built, "openai", store, Duration::from_millis(1500))
    })
    .join()
    .expect("the provider thread joins")
    .expect("the adapter builds");

    let began = Instant::now();
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let elapsed = began.elapsed();
    match outcome {
        Err(ProviderError::Transport { reason, .. }) => {
            assert!(
                reason.contains("deadline"),
                "the total deadline is the named cause: {reason}"
            );
        }
        other => panic!("a dribbling peer is a typed transport denial: {other:?}"),
    }
    assert!(
        elapsed < Duration::from_secs(10),
        "the send ended near its deadline, not the 120s per-read bound: {elapsed:?}"
    );
    drop_blocking(provider);
    peer.join().expect("the drip thread joins");
}

/// DEC-014: the deadline check stands between the legs that spend the
/// budget and the wire — a credential resolve that consumes the whole
/// budget fails the send typed before one byte crosses, never a post
/// on an expired clock surfacing reqwest's backstop text.
#[tokio::test]
async fn expired_budget_denies_the_send_before_any_wire_leg() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream("never sent", Vec::new(), None),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let deadline = Duration::from_millis(1500);
    let store = Arc::new(SlowStore {
        inner: support::MapStore::seeded(STORE_KIND, &[(CREDENTIAL_REF, SECRET)]),
        // past the deadline — the resolve returns under an expired clock
        delay: deadline + Duration::from_millis(500),
    });
    let built = config.clone();
    let provider = std::thread::spawn(move || {
        OpenAiProvider::with_deadline(&built, "openai", store, deadline)
    })
    .join()
    .expect("the provider thread joins")
    .expect("the adapter builds");

    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    match outcome {
        Err(ProviderError::Transport { reason, .. }) => {
            assert!(
                reason.contains("deadline"),
                "the total deadline is the named cause: {reason}"
            );
        }
        other => panic!("an expired budget is a typed transport denial: {other:?}"),
    }
    let requests = server.received_requests().await.expect("recorded");
    assert!(
        requests.is_empty(),
        "the post never crossed the wire on an expired budget: {requests:?}"
    );
    drop_blocking(provider);
}

/// DEC-014: an already-spent budget denies the credential call before
/// the store seam runs — the deadline check is the only point a spent
/// clock can refuse, because the synchronous resolve behind it cannot
/// be interrupted once it starts.
#[tokio::test]
async fn spent_budget_denies_the_credential_call_before_the_store() {
    let config = Config::parse_validated(&openai_config("https://127.0.0.1:1/v1")).expect("valid");
    // The delay is the wedge marker: had the resolve run, the send
    // could not have returned inside it.
    let store_delay = Duration::from_secs(30);
    let store = Arc::new(SlowStore {
        inner: support::MapStore::seeded(STORE_KIND, &[(CREDENTIAL_REF, SECRET)]),
        delay: store_delay,
    });
    let built = config.clone();
    let provider = std::thread::spawn(move || {
        OpenAiProvider::with_deadline(&built, "openai", store, Duration::ZERO)
    })
    .join()
    .expect("the provider thread joins")
    .expect("the adapter builds");

    let started = Instant::now();
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let elapsed = started.elapsed();
    match outcome {
        Err(ProviderError::Transport { reason, .. }) => {
            assert!(
                reason.contains("deadline"),
                "the spent budget is the named cause: {reason}"
            );
        }
        other => panic!("a spent budget is a typed transport denial: {other:?}"),
    }
    assert!(
        elapsed < store_delay,
        "the denial returned before the store's resolve could: {elapsed:?}"
    );
    drop_blocking(provider);
}

// ----- TP-PROVIDER-AUTH::openai -------------------------------------

/// A marker the 401 fixture's body carries so an error that echoes
/// uncontrolled peer bytes is caught, never vacuously clean.
const BODY_MARKER: &str = "fixture-401-body-marker-never-in-errors";

/// Every leg's denial renders Display and Debug with typed context
/// only — credential material and the peer's response body never
/// appear on either surface.
fn assert_no_secret_or_body(err: &ProviderError) {
    for rendered in [format!("{err}"), format!("{err:?}")] {
        assert!(
            !rendered.contains(SECRET),
            "the credential material never renders: {rendered}"
        );
        assert!(
            !rendered.contains(BODY_MARKER),
            "the peer's response body never renders: {rendered}"
        );
    }
}

/// Wrong credential/profile/region never produce a false success:
/// a configured region outside the dialect's endpoint contract, the
/// profile-bound ref whose scope disagrees with the binding, an
/// absent credential, and a refused bearer each land a typed denial —
/// and none of them, nor any Debug surface the boundary exposes,
/// renders credential material or the peer's body.
#[tokio::test]
async fn wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // region outside the recorded endpoint contract — a sibling scope
    // holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(&openai_config(&server_uri_v1(&server)).replace(
        "kind = \"api_key\"",
        "kind = \"api_key\"\nregion = \"eu-west\"",
    ))
    .expect("valid");
    let err = provider_result(
        regioned,
        "openai".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, SECRET)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "openai");
    assert_eq!(region, "eu-west");
    assert_no_secret_or_body(&err);

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.openai]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"openai\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "openai".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, SECRET)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err);

    // a bound ref with no material at its own scope — the sibling
    // scope's material stays sealed behind the typed denial
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let provider = provider_result(
        config.clone(),
        "openai".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, SECRET)],
        )),
    )
    .expect("binding resolves; the store is read at send");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("no material at the scope is the typed denial");
    assert!(matches!(err, ProviderError::CredentialAbsent { .. }));
    assert_no_secret_or_body(&err);
    drop_blocking(provider);

    // a refused bearer is a typed transport denial — the wire never
    // coerces a wrong credential into success, and the peer's body
    // never enters the error
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    // The fixture 401s any bearer, so the enrolled material is SECRET
    // itself — the only leg that resolves material before the HTTP
    // error, and the assertion must prove that resolved credential is
    // absent from the error, not a different string.
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let provider = provider_result(config.clone(), "openai".to_string(), store).expect("builds");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused bearer is a typed transport denial");
    let ProviderError::Transport { connection, reason } = &err else {
        panic!("a refused bearer is transport: {err}")
    };
    assert_eq!(connection, "openai");
    assert!(
        reason.contains("401"),
        "the status code is the context: {reason}"
    );
    assert_no_secret_or_body(&err);
    drop_blocking(provider);

    // The same boundary on the Debug surfaces the dispatch path
    // exposes: provider, manifest, accounting record, broker and
    // runtime each render without the material the store alone holds.
    let server = MockServer::start().await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let provider =
        provider_result(config.clone(), "openai".to_string(), store).expect("the adapter builds");
    assert!(
        !format!("{provider:?}").contains(SECRET),
        "provider Debug never carries credential material"
    );
    mount_responses(
        &server,
        responses_completed_stream(
            "accounted",
            Vec::new(),
            Some(json!({"input_tokens": 1, "output_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: debug surfaces");
    assert!(
        !format!("{manifest:?}").contains(SECRET),
        "manifest Debug never carries credential material"
    );
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest.clone());
    outcome.expect("the debug-surface send completes");
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert!(
        !format!("{record:?}").contains(SECRET),
        "accounting-record Debug never carries credential material"
    );
    assert!(
        !format!("{broker:?}").contains(SECRET),
        "broker Debug never carries credential material"
    );
    drop_blocking(broker);
    drop_blocking(provider);

    let world = support::open_world("auth-debug", Some(&openai_config(&server_uri_v1(&server))));
    assert!(
        !format!("{:?}", world.runtime).contains(SECRET),
        "runtime Debug never carries credential material"
    );
}

/// Material the store resolves but the dialect cannot use — non-UTF-8
/// bytes can never be a bearer token — is the typed malformed denial
/// at send, and the material itself never enters the error.
#[tokio::test]
async fn non_utf8_credential_material_is_a_typed_malformed_denial() {
    let server = MockServer::start().await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::new(STORE_KIND));
    store.enroll(CREDENTIAL_REF, b"\xff\xfe");
    let provider = provider_result(config.clone(), "openai".to_string(), store)
        .expect("binding resolves; the store is read at send");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("non-utf-8 material is the typed denial");
    let ProviderError::CredentialMalformed { connection } = &err else {
        panic!("non-utf-8 material is malformed, never absent: {err}")
    };
    assert_eq!(connection, "openai");
    assert_no_secret_or_body(&err);
    drop_blocking(provider);
}

// ----- TP-PROVIDER-RECOVERY::openai ---------------------------------

/// A typed denial is recoverable through the same seam: the absent
/// credential denies the first send, enrolling material at the scope
/// admits the retry — no state wedged, no plaintext path taken.
#[tokio::test]
async fn typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "recovered",
            Vec::new(),
            Some(json!({"input_tokens": 2, "output_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "openai".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialAbsent { .. })
    ));

    store.enroll(CREDENTIAL_REF, SECRET.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the enrolled credential admits the retry");
    assert_eq!(reply.text, "recovered");
    drop_blocking(provider);
}

// ----- stream legs ----------------------------------------------------

/// A stream that ends mid output item is never a usable reply — the
/// partial function_call is rejected, nothing executes, and nothing
/// is accounted.
#[tokio::test]
async fn partial_tool_block_never_executes() {
    let server = MockServer::start().await;
    let body = format!(
        "{}{}",
        sse_block(
            "response.output_item.added",
            &json!({"item": {"id": "fc_1", "type": "function_call", "status": "in_progress", "name": "read_file", "arguments": "", "call_id": "call_1"}, "output_index": 0}),
        ),
        sse_block(
            "response.function_call_arguments.delta",
            &json!({"delta": "{\"path\":", "item_id": "fc_1", "output_index": 0}),
        ),
    );
    mount_responses(&server, body).await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: partial tool");

    let (broker, outcome) = dispatch(broker, "/world/openai", manifest.clone());
    let error = outcome.expect_err("a truncated stream is never success");
    assert!(
        matches!(
            error,
            ModelError::Provider(ProviderError::StreamViolation { .. })
        ),
        "a stream ended mid output item is the wire violation: {error}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);
}

/// The stream owes a terminal the dialect can classify: a stream that
/// ends without one, and a `response.completed` carrying an outcome
/// the dialect cannot classify, are both unknown — never success.
#[tokio::test]
async fn unknown_mandatory_terminal_is_not_success() {
    let server = MockServer::start().await;

    // complete items, then silence — no terminal ever arrives
    mount_responses(
        &server,
        format!(
            "{}{}",
            sse_block(
                "response.output_item.added",
                &json!({"item": {"id": "msg_1", "type": "message", "status": "in_progress", "role": "assistant", "content": []}, "output_index": 0}),
            ),
            sse_block(
                "response.output_item.done",
                &json!({"item": {"id": "msg_1", "type": "message", "status": "completed", "role": "assistant", "content": [{"type": "output_text", "text": "hi"}]}, "output_index": 0}),
            ),
        ),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: no terminal");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "EOF without a terminal is the unknown terminal: {outcome:?}"
    );
    drop_blocking(broker);

    // a terminal whose outcome the dialect cannot classify
    let server = MockServer::start().await;
    mount_responses(
        &server,
        sse_block(
            "response.completed",
            &json!({"response": {"id": "resp_1", "status": "concluded", "output": []}}),
        ),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: strange terminal");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "an unclassifiable terminal is not success: {outcome:?}"
    );
    drop_blocking(broker);
}

/// Well-formed output the dialect cannot honour is a typed rejection:
/// a server-side tool kind the request never declared, and a
/// reasoning item with no `encrypted_content` to prove lineage.
#[tokio::test]
async fn incompatible_tools_or_reasoning_is_a_typed_rejection() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "",
            vec![json!({
                "id": "mcp_1", "type": "mcp_call", "name": "server.tool",
                "arguments": "{}", "server_label": "fixture",
            })],
            None,
        ),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: incompatible tool");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(
                ProviderError::IncompatibleOutput { .. }
            ))
        ),
        "an unhonourable output item is a typed rejection: {outcome:?}"
    );
    drop_blocking(broker);

    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "",
            vec![json!({"id": "rs_1", "type": "reasoning", "summary": []})],
            None,
        ),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: bare reasoning");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(
                ProviderError::ReasoningProvenance { .. }
            ))
        ),
        "an artifact with no encrypted_content cannot prove lineage: {outcome:?}"
    );
    drop_blocking(broker);

    // a function_call naming a tool the frozen request never declared
    // is output the dialect cannot honour — never executed
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "",
            vec![json!({
                "id": "fc_1", "type": "function_call", "status": "completed",
                "name": "exec_shell", "arguments": "{\"cmd\": \"ls\"}", "call_id": "call_1",
            })],
            None,
        ),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: undeclared call");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(
                ProviderError::IncompatibleOutput { .. }
            ))
        ),
        "an undeclared tool name is a typed rejection: {outcome:?}"
    );
    drop_blocking(broker);

    // a peer name past the reason bound truncates on the boundary —
    // the diagnostic surface never parks a payload
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "",
            vec![json!({
                "id": "fc_1", "type": "function_call", "status": "completed",
                "name": "x".repeat(2000), "arguments": "{}", "call_id": "call_1",
            })],
            None,
        ),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: oversized name");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    let Err(ModelError::Provider(ProviderError::IncompatibleOutput { reason, .. })) = outcome
    else {
        panic!("the oversized tool name is a typed rejection: {outcome:?}")
    };
    assert_eq!(
        reason.len(),
        1024,
        "the peer name is capped at the reason bound"
    );
    drop_blocking(broker);
}

/// A completed terminal may only carry finished items: a
/// function_call reporting an unfinished status, and a message item
/// carrying no status at all, are truncated content — wire
/// violations, never a usable reply.
#[tokio::test]
async fn incomplete_output_item_in_a_completed_terminal_is_rejected() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "reading",
            vec![json!({
                "id": "fc_1", "type": "function_call", "status": "incomplete",
                "name": "read_file", "arguments": "{\"path\": \"src/lib.rs\"}", "call_id": "call_1",
            })],
            None,
        ),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: unfinished item");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "an unfinished item inside a completed terminal is a violation: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    // a message item with no status label at all is denied the same
    // way — the completed contract requires the finished label
    let server = MockServer::start().await;
    let mut statusless = json!({
        "id": "msg_0", "type": "message", "status": "in_progress", "role": "assistant",
        "content": [{ "type": "output_text", "text": "hi" }],
    });
    statusless.as_object_mut().unwrap().remove("status");
    mount_responses(
        &server,
        responses_completed_stream("hi", vec![statusless], None),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: unlabelled item");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "an unlabelled item inside a completed terminal is a violation: {outcome:?}"
    );
    drop_blocking(broker);
}

/// The remaining terminal and malformed shapes all land as typed
/// rejections: `response.incomplete` and `error` are peer verdicts,
/// a duplicate terminal or malformed payload is a wire violation, an
/// unreadable usage object violates the contract, and a refused
/// connection is a transport failure.
#[tokio::test]
async fn remaining_terminals_and_malformed_wire_shapes_are_typed() {
    // response.incomplete is a peer verdict, never success
    let server = MockServer::start().await;
    mount_responses(
        &server,
        sse_block(
            "response.incomplete",
            &json!({"response": {"id": "resp_1", "status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"}}}),
        ),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: incomplete verdict");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::ProviderFailed { .. }))
        ),
        "an incomplete verdict is a peer failure: {outcome:?}"
    );
    drop_blocking(broker);

    // an error event is a peer failure verdict
    let server = MockServer::start().await;
    mount_responses(
        &server,
        sse_block("error", &json!({"code": "server_error", "message": "boom"})),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: error verdict");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::ProviderFailed { .. }))
        ),
        "an error event is a peer failure: {outcome:?}"
    );
    drop_blocking(broker);

    // a payload-length peer reason is bounded: the cap lands on a UTF-8
    // char boundary, so '€' (3 bytes) cuts at 1023, never mid-codepoint
    let server = MockServer::start().await;
    mount_responses(
        &server,
        sse_block("error", &json!({"message": "€".repeat(400)})),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: oversized reason");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    let Err(ModelError::Provider(ProviderError::ProviderFailed { reason, .. })) = outcome else {
        panic!("the oversized reason is a peer failure: {outcome:?}")
    };
    assert_eq!(
        reason.len(),
        1023,
        "the peer reason is capped on a char boundary"
    );
    drop_blocking(broker);

    // a second terminal after a valid completed one is a wire
    // violation — the stream owes exactly one verdict
    let server = MockServer::start().await;
    mount_responses(
        &server,
        format!(
            "{}{}",
            responses_completed_stream("first", Vec::new(), None),
            sse_block(
                "response.failed",
                &json!({"response": {"id": "resp_2", "status": "failed"}}),
            ),
        ),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: duplicate terminal");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "a duplicate terminal is a wire violation: {outcome:?}"
    );
    drop_blocking(broker);

    // a terminal event whose payload does not parse is a violation
    let server = MockServer::start().await;
    mount_responses(
        &server,
        "event: response.completed\ndata: {broken\n\n".to_string(),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: malformed terminal");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "a malformed terminal payload is a wire violation: {outcome:?}"
    );
    drop_blocking(broker);

    // a usage object whose counters do not read is unreadable, never
    // an estimate
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "counted",
            Vec::new(),
            Some(json!({"input_tokens": "many", "output_tokens": 7, "total_tokens": 7})),
        ),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: unreadable usage");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "an unreadable usage object is a wire violation: {outcome:?}"
    );
    drop_blocking(broker);

    // a refused connection is a transport failure
    let config = Config::parse_validated(&openai_config("http://127.0.0.1:1/v1")).expect("valid");
    let (provider, _store) = openai_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    assert!(
        matches!(outcome, Err(ProviderError::Transport { .. })),
        "a refused connection is transport: {outcome:?}"
    );
    drop_blocking(provider);
}

/// Every malformed sibling shape lands the typed violation: a
/// catalogue payload that is not the `data` listing the contract
/// requires, a completed envelope missing its output set, an item
/// missing its own mandatory field, and a `done` lifecycle event
/// whose `added` never arrived.
#[tokio::test]
async fn malformed_wire_shapes_are_typed_violations() {
    // catalogue legs: GET /models owes the `data` array
    for (name, body) in [
        ("a non-json listing", "not json".to_string()),
        (
            "a listing without the data array",
            "{\"object\": \"list\"}".to_string(),
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let config =
            Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
        let (provider, _store) = openai_provider(&config);
        let outcome = std::thread::spawn(move || provider.catalog())
            .join()
            .expect("the catalog thread joins");
        assert!(
            matches!(outcome, Err(ProviderError::StreamViolation { .. })),
            "{name} is a typed violation: {outcome:?}"
        );
    }

    // stream legs: the completed envelope and its items owe their
    // mandatory fields, and a done event owes its added
    let legs: Vec<(&str, String)> = vec![
        (
            "a completed envelope without output",
            sse_block(
                "response.completed",
                &json!({"response": {"id": "resp_1", "status": "completed"}}),
            ),
        ),
        (
            "an output item without a type",
            responses_completed_stream("", vec![json!({"id": "x_1"})], None),
        ),
        (
            "a message item without content",
            responses_completed_stream(
                "",
                vec![json!({
                    "id": "msg_0", "type": "message", "status": "completed",
                    "role": "assistant",
                })],
                None,
            ),
        ),
        (
            "a function_call without a name",
            responses_completed_stream(
                "",
                vec![json!({
                    "id": "fc_1", "type": "function_call", "status": "completed",
                    "arguments": "{}",
                })],
                None,
            ),
        ),
        (
            "function_call arguments that are not json",
            responses_completed_stream(
                "",
                vec![json!({
                    "id": "fc_1", "type": "function_call", "status": "completed",
                    "name": "read_file", "arguments": "{broken",
                })],
                None,
            ),
        ),
        (
            "function_call arguments that are not an object",
            responses_completed_stream(
                "",
                vec![json!({
                    "id": "fc_1", "type": "function_call", "status": "completed",
                    "name": "read_file", "arguments": "\"x\"",
                })],
                None,
            ),
        ),
        (
            "an output_item.done without its added",
            format!(
                "{}{}",
                sse_block(
                    "response.output_item.done",
                    &json!({"item": {"id": "msg_1", "type": "message", "status": "completed", "role": "assistant", "content": [{"type": "output_text", "text": "x"}]}, "output_index": 0}),
                ),
                sse_block(
                    "response.completed",
                    &json!({"response": {"id": "resp_1", "status": "completed", "output": []}}),
                ),
            ),
        ),
    ];
    for (name, body) in legs {
        let server = MockServer::start().await;
        mount_responses(&server, body).await;
        let config =
            Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
        let (broker, manifest) = prepared(&config, "/world/openai", "goal: malformed");
        let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
        assert!(
            matches!(
                outcome,
                Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
            ),
            "{name} is a typed violation: {outcome:?}"
        );
        assert_eq!(broker.accounted_requests(), 0, "{name} charged nothing");
        drop_blocking(broker);
    }
}

/// A reported `total_tokens` is charged verbatim — 11+7 reported as
/// 25 stays 25, never re-summed — while a usage object that withholds
/// the total is a wire violation, not an estimate.
#[tokio::test]
async fn reported_total_is_charged_verbatim_and_a_missing_total_is_a_violation() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "verbatim",
            Vec::new(),
            Some(json!({"input_tokens": 11, "output_tokens": 7, "total_tokens": 25})),
        ),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: verbatim total");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest.clone());
    outcome.expect("the reported total charges");
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 11,
            completion_tokens: 7,
            total_tokens: 25,
        },
        "the peer's reported total is charged verbatim"
    );
    drop_blocking(broker);

    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "no total",
            Vec::new(),
            Some(json!({"input_tokens": 11, "output_tokens": 7})),
        ),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: missing total");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "a withheld total is a violation, not an estimate: {outcome:?}"
    );
    drop_blocking(broker);
}

/// DEC-012: a reasoning artifact produced under one manifest-bound
/// lineage is foreign to another — never silently dropped, never
/// blindly replayed, always the named provenance error.
#[tokio::test]
async fn foreign_reasoning_blob_rejected() {
    let server = MockServer::start().await;
    let reasoning = json!({
        "id": "rs_1", "type": "reasoning", "summary": [],
        "encrypted_content": "enc-fixture-blob-aaa",
    });
    mount_responses(
        &server,
        responses_completed_stream("ok", vec![reasoning], None),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = openai_provider(&config);
    let mut broker = Broker::new(Box::new(provider));

    // world A's completed turn adopts the artifact into its lineage
    let manifest_a = broker
        .prepare("main", &config, "/world/A", "goal: first")
        .expect("prepare A");
    let (broker, outcome_a) = dispatch(broker, "/world/A", manifest_a);
    outcome_a.expect("world A adopts the artifact");
    let mut broker = broker;

    // the same artifact arriving under world B is foreign — the
    // lineage that produced it does not own this manifest
    let manifest_b = broker
        .prepare("main", &config, "/world/B", "goal: second")
        .expect("prepare B");
    let (broker, outcome_b) = dispatch(broker, "/world/B", manifest_b);
    assert!(
        matches!(
            outcome_b,
            Err(ModelError::Provider(
                ProviderError::ReasoningProvenance { .. }
            ))
        ),
        "a foreign blob is the named provenance error: {outcome_b:?}"
    );
    drop_blocking(broker);
}

/// DEC-012: with `store: false` sent verbatim, the next turn replays
/// the full prior output-item set ahead of the new input — the
/// stateless contract, observable on the wire.
#[tokio::test]
async fn responses_store_false_is_explicit_and_stateless_replay_carries_prior_output_items() {
    let server = MockServer::start().await;
    let reasoning = json!({
        "id": "rs_1", "type": "reasoning", "summary": [],
        "encrypted_content": "enc-fixture-blob-aaa",
    });
    let message = json!({
        "id": "msg_1", "type": "message", "status": "completed", "role": "assistant",
        "content": [{ "type": "output_text", "text": "first answer" }],
    });
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(format!(
                    "{}{}{}",
                    sse_block(
                        "response.output_item.added",
                        &json!({"item": {"id": "msg_1", "type": "message", "status": "in_progress", "role": "assistant", "content": []}, "output_index": 1}),
                    ),
                    sse_block(
                        "response.output_item.done",
                        &json!({"item": message, "output_index": 1}),
                    ),
                    sse_block(
                        "response.completed",
                        &json!({"response": {"id": "resp_1", "status": "completed",
                            "output": [reasoning.clone(), message.clone()],
                            "usage": {"input_tokens": 3, "output_tokens": 2, "total_tokens": 5}}}),
                    ),
                )),
        )
        .expect(2)
        .mount(&server)
        .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = openai_provider(&config);
    let mut broker = Broker::new(Box::new(provider));

    let first = broker
        .prepare("main", &config, "/world/openai", "goal: first turn")
        .expect("prepare turn 1");
    let (broker, reply) = dispatch(broker, "/world/openai", first);
    reply.expect("turn 1 completes");
    let mut broker = broker;

    let second = broker
        .prepare("main", &config, "/world/openai", "goal: second turn")
        .expect("prepare turn 2 — same epoch");
    let (broker, reply) = dispatch(broker, "/world/openai", second.clone());
    reply.expect("turn 2 completes");

    let bodies = received_bodies(&server).await;
    assert_eq!(bodies.len(), 2, "two physical sends");
    assert_eq!(bodies[0]["store"], false, "store:false is sent verbatim");
    assert_eq!(bodies[1]["store"], false);
    assert_eq!(
        bodies[0]["include"],
        json!(["reasoning.encrypted_content"]),
        "every send asks for the reasoning artifact"
    );
    assert_eq!(bodies[1]["include"], json!(["reasoning.encrypted_content"]));
    // turn 2's input is the full prior output set, verbatim, ahead of
    // the new user item — the lineage the artifacts belong to.
    assert_eq!(
        bodies[1]["input"],
        json!([
            reasoning,
            message,
            {
                "role": "user",
                "content": [{ "type": "input_text", "text": second.inputs }],
            }
        ]),
        "the stateless replay carries the full prior output set"
    );
    // each physical send charged its own usage — two records, no
    // double-charge of one send.
    assert_eq!(broker.accounted_requests(), 2);
    drop_blocking(broker);
}

/// A reply that reports no usage keeps the sent cost unknown: the
/// accounting record carries `Unknown`, the explain retains the bound
/// — never a released zero.
#[tokio::test]
async fn unknown_usage_never_releases_the_admission_bound() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream("no usage", Vec::new(), None),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: unknown usage");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest.clone());
    outcome.expect("a usage-less reply still verifies");
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("accounted");
    assert_eq!(record.usage, UsageDelta::Unknown);
    let explain = broker.sent_cost_explain(&manifest);
    assert_eq!(explain.bound, manifest.cost_bound);
    assert_eq!(explain.confirmed, None);
    drop_blocking(broker);
}

/// The provider's own failure verdict is a typed peer error, not a
/// parse failure and not success.
#[tokio::test]
async fn provider_reported_failure_is_a_typed_denial() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        sse_block(
            "response.failed",
            &json!({"response": {"id": "resp_1", "status": "failed",
                "error": {"code": "rate_limit_exceeded", "message": "slow down"}}}),
        ),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: failure");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::ProviderFailed { .. }))
        ),
        "the peer's failure verdict is typed: {outcome:?}"
    );
    drop_blocking(broker);
}

/// A `response.completed` envelope carrying a non-completed status is
/// the peer's own verdict, not a parse error and not success: failed,
/// incomplete and cancelled all land as the typed provider failure.
#[tokio::test]
async fn completed_envelope_with_a_non_completed_status_is_a_peer_verdict() {
    for status in ["failed", "incomplete", "cancelled"] {
        let server = MockServer::start().await;
        mount_responses(
            &server,
            sse_block(
                "response.completed",
                &json!({"response": {"id": "resp_1", "status": status, "output": [],
                    "error": {"code": "server_error", "message": format!("verdict {status}")}}}),
            ),
        )
        .await;
        let config =
            Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
        let (broker, manifest) = prepared(&config, "/world/openai", "goal: envelope verdict");
        let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
        assert!(
            matches!(
                outcome,
                Err(ModelError::Provider(ProviderError::ProviderFailed { .. }))
            ),
            "a {status} envelope status is the typed peer verdict: {outcome:?}"
        );
        drop_blocking(broker);
    }
}

/// D-006: a reasoning item's lifecycle label is forward-compatible
/// surface — the `encrypted_content` blob is the provenance gate, so
/// an unfinished-labelled reasoning item inside a completed envelope
/// still verifies and replays verbatim.
#[tokio::test]
async fn reasoning_item_status_is_not_the_provenance_gate() {
    let server = MockServer::start().await;
    let reasoning = json!({
        "id": "rs_1", "type": "reasoning", "status": "in_progress",
        "summary": [], "encrypted_content": "enc-fixture-blob-aaa",
    });
    mount_responses(
        &server,
        responses_completed_stream("ok", vec![reasoning], None),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: labelled reasoning");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    outcome.expect("a labelled-unfinished reasoning item with its blob verifies");
    drop_blocking(broker);
}

/// A `refusal` content part contributes its text to the reply —
/// forward-compatible surface the dialect carries verbatim.
#[tokio::test]
async fn refusal_content_part_reaches_the_reply_text() {
    let server = MockServer::start().await;
    let refusal_message = json!({
        "id": "msg_0", "type": "message", "status": "completed", "role": "assistant",
        "content": [{ "type": "refusal", "refusal": "cannot do that" }],
    });
    mount_responses(
        &server,
        responses_completed_stream("answer", vec![refusal_message], None),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: refusal part");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    let reply = outcome.expect("the refusal part reply dispatches");
    assert_eq!(
        reply.text, "cannot do thatanswer",
        "the refusal text lands ahead of the output text"
    );
    drop_blocking(broker);
}

/// A completed tool call reaches the reply as a typed `ToolCall` —
/// only a complete, object-arguments function_call item can.
#[tokio::test]
async fn completed_tool_call_reaches_the_reply_typed() {
    let server = MockServer::start().await;
    let call = json!({
        "id": "fc_1", "type": "function_call", "status": "completed",
        "name": "read_file", "arguments": "{\"path\": \"src/lib.rs\"}",
        "call_id": "call_1",
    });
    mount_responses(
        &server,
        responses_completed_stream("reading", vec![call], None),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: tool call");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    let reply = outcome.expect("the tool call reply dispatches");
    assert_eq!(reply.tool_calls.len(), 1);
    assert_eq!(reply.tool_calls[0].tool, "read_file");
    assert_eq!(reply.tool_calls[0].path.as_deref(), Some("src/lib.rs"));
    drop_blocking(broker);
}

/// DEC-012: a blob minted under a retired epoch is a foreign replay
/// under the new one — ownership claims outlive the replay set they
/// retired with, and the retired set never rides the wire again.
#[tokio::test]
async fn retired_epoch_reasoning_blob_is_rejected_not_readopted() {
    let server = MockServer::start().await;
    let reasoning = json!({
        "id": "rs_1", "type": "reasoning", "summary": [],
        "encrypted_content": "enc-fixture-blob-aaa",
    });
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(responses_completed_stream("ok", vec![reasoning], None)),
        )
        .expect(2)
        .mount(&server)
        .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = openai_provider(&config);
    let mut broker = Broker::new(Box::new(provider));

    let first = broker
        .prepare("main", &config, "/world/openai", "goal: first epoch")
        .expect("prepare turn 1");
    let (broker, outcome) = dispatch(broker, "/world/openai", first);
    outcome.expect("turn 1 mints the artifact");
    let mut broker = broker;

    // a model switch opens a new epoch: the retired lineage's blob is
    // no longer a replay of ours — it is foreign
    let switched = Config::parse_validated(
        &openai_config(&server_uri_v1(&server)).replace("gpt-5.2", "gpt-5.1"),
    )
    .expect("valid");
    let second = broker
        .prepare("main", &switched, "/world/openai", "goal: second epoch")
        .expect("prepare turn 2");
    assert_eq!(
        second.mutation_reason.as_deref(),
        Some("model switch"),
        "the model switch minted a new epoch"
    );
    let (broker, outcome) = dispatch(broker, "/world/openai", second.clone());
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(
                ProviderError::ReasoningProvenance { .. }
            ))
        ),
        "a retired-epoch blob is a provenance failure: {outcome:?}"
    );

    // the retired replay set never rode the wire: turn 2's input is
    // only the new user item
    let bodies = received_bodies(&server).await;
    assert_eq!(bodies.len(), 2);
    assert_eq!(
        bodies[1]["input"],
        json!([{
            "role": "user",
            "content": [{ "type": "input_text", "text": second.inputs }],
        }]),
        "the retired lineage replayed nothing"
    );
    drop_blocking(broker);
}

/// A rejected reply commits nothing: after a provenance denial, an
/// incompatible-output denial and a wire violation, the retry under
/// the same epoch replays none of the refused items — the lineage
/// only ever holds validated output.
#[tokio::test]
async fn rejected_output_items_never_join_the_replay_lineage() {
    type DenialLeg = (&'static str, String, fn(&ProviderError) -> bool);
    let legs: Vec<DenialLeg> = vec![
        (
            "a reasoning item without its artifact",
            responses_completed_stream(
                "",
                vec![json!({"id": "rs_1", "type": "reasoning", "summary": []})],
                None,
            ),
            |err| matches!(err, ProviderError::ReasoningProvenance { .. }),
        ),
        (
            "an unhonourable output item",
            responses_completed_stream(
                "",
                vec![json!({
                    "id": "mcp_1", "type": "mcp_call", "name": "server.tool",
                    "arguments": "{}", "server_label": "fixture",
                })],
                None,
            ),
            |err| matches!(err, ProviderError::IncompatibleOutput { .. }),
        ),
        (
            "a malformed output item",
            responses_completed_stream("", vec![json!({"id": "x_1"})], None),
            |err| matches!(err, ProviderError::StreamViolation { .. }),
        ),
    ];
    for (name, refused_body, denies) in legs {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(refused_body),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        mount_responses(
            &server,
            responses_completed_stream("clean answer", Vec::new(), None),
        )
        .await;
        let config =
            Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
        let (provider, _store) = openai_provider(&config);
        let manifest = prepared_manifest(&config);

        let (provider, denied) = send_on_thread(provider, manifest.clone());
        let err = denied.expect_err("the malformed reply is refused");
        assert!(denies(&err), "{name} is refused typed: {err:?}");

        // Same provider, same epoch: the retry replays nothing the
        // refused reply carried — commit happens after validation only.
        let (provider, outcome) = send_on_thread(provider, manifest);
        outcome.expect("the retry under the same epoch completes");
        let bodies = received_bodies(&server).await;
        assert_eq!(bodies.len(), 2, "{name}: the refusal plus the retry");
        assert_eq!(
            bodies[1]["input"],
            json!([{
                "role": "user",
                "content": [{ "type": "input_text", "text": "goal: auth leg" }],
            }]),
            "{name}: the refused items never entered the replay set"
        );
        drop_blocking(provider);
    }
}

/// DEC-012: replay sets are per-epoch — an interleaved send under a
/// non-current epoch replays and mutates only its own set, so a stale
/// commit can never wipe the live epoch's replay context. The last
/// send under the live epoch proves its set survived.
#[tokio::test]
async fn interleaved_epoch_sends_preserve_the_live_epochs_replay_set() {
    let server = MockServer::start().await;
    // the replayed items are the message shapes `completed_stream`
    // emits — the answer text is what discriminates the two epochs
    let epoch_one_message = json!({
        "id": "msg_1", "type": "message", "status": "completed", "role": "assistant",
        "content": [{ "type": "output_text", "text": "epoch-one answer" }],
    });
    let epoch_two_message = json!({
        "id": "msg_1", "type": "message", "status": "completed", "role": "assistant",
        "content": [{ "type": "output_text", "text": "epoch-two answer" }],
    });
    // the first send mints epoch one's set; every later send mints
    // epoch two's — the mounted order makes the first answer distinct
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(responses_completed_stream(
                    "epoch-one answer",
                    Vec::new(),
                    None,
                )),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_responses(
        &server,
        responses_completed_stream("epoch-two answer", Vec::new(), None),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = openai_provider(&config);
    let mut broker = Broker::new(Box::new(provider));

    // epoch one's set commits one item
    let first = broker
        .prepare("main", &config, "/world/openai", "goal: epoch one turn")
        .expect("prepare epoch one");
    let (mut broker, outcome) = dispatch(broker, "/world/openai", first);
    outcome.expect("epoch one's turn commits");

    // the stale manifest is frozen under epoch one — prepared, then
    // held while the context switches
    let stale = broker
        .prepare(
            "main",
            &config,
            "/world/openai",
            "goal: held epoch one send",
        )
        .expect("prepare the held send");

    // a model switch opens epoch two and its turn commits its own set
    let switched = Config::parse_validated(
        &openai_config(&server_uri_v1(&server)).replace("gpt-5.2", "gpt-5.1"),
    )
    .expect("valid");
    let second = broker
        .prepare("main", &switched, "/world/openai", "goal: epoch two turn")
        .expect("prepare epoch two");
    assert_eq!(second.mutation_reason.as_deref(), Some("model switch"));
    let (broker, outcome) = dispatch(broker, "/world/openai", second);
    outcome.expect("epoch two's turn commits");

    // the held send still dispatches under epoch one: its input is
    // epoch one's own replay set, and its commit touches only that set
    let (mut broker, outcome) = dispatch(broker, "/world/openai", stale.clone());
    outcome.expect("the stale-epoch send still verifies");

    // a send under the live epoch replays epoch two's set — a stale
    // commit that clobbered it would leave this input empty
    let third = broker
        .prepare("main", &switched, "/world/openai", "goal: live epoch turn")
        .expect("prepare the live epoch turn");
    assert_eq!(
        third.mutation_reason, None,
        "an unchanged prefix replays the live epoch"
    );
    let (broker, outcome) = dispatch(broker, "/world/openai", third.clone());
    outcome.expect("the live epoch's turn completes");

    let bodies = received_bodies(&server).await;
    assert_eq!(bodies.len(), 4, "four physical sends");
    // the stale send replayed epoch one's set — its own epoch's
    // context, never epoch two's
    assert_eq!(
        bodies[2]["input"],
        json!([
            epoch_one_message,
            {
                "role": "user",
                "content": [{ "type": "input_text", "text": stale.inputs }],
            }
        ]),
        "the interleaved send carried its own epoch's replay set"
    );
    // the live epoch's set survived the stale commit verbatim
    assert_eq!(
        bodies[3]["input"],
        json!([
            epoch_two_message,
            {
                "role": "user",
                "content": [{ "type": "input_text", "text": third.inputs }],
            }
        ]),
        "the live epoch's replay set survived the interleaved commit"
    );
    drop_blocking(broker);
}

/// AC-013/DEC-012: the replayed lineage set rides inside the same
/// wire bound — a serialized request body past the limit is a typed
/// violation before any byte is sent, never a silent truncation.
#[tokio::test]
async fn replay_body_is_bounded_by_the_wire_limit() {
    let server = MockServer::start().await;
    // ~220KB of text per turn: five completed turns grow the lineage's
    // replay set so the sixth request serializes past the 1 MiB bound
    let big = "x".repeat(220 * 1024);
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(responses_completed_stream(&big, Vec::new(), None)),
        )
        .expect(5)
        .mount(&server)
        .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (mut provider, _store) = openai_provider(&config);
    for _ in 0..5 {
        let (p, outcome) = send_on_thread(provider, prepared_manifest(&config));
        provider = p;
        outcome.expect("the turn completes");
    }
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    assert!(
        matches!(outcome, Err(ProviderError::StreamViolation { .. })),
        "an over-bound replay body is a typed violation: {outcome:?}"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        5,
        "the over-bound request never crossed the wire"
    );
    drop_blocking(provider);
}

/// The legs matrix enforces the recorded expected set for `openai`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside this
/// run, and INSTALLED reports NOT_RUN — an omitted leg fails the suite
/// rather than silently absenting.
#[tokio::test]
async fn provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "gpt-5.2", "object": "model"}],
        })))
        .mount(&server)
        .await;
    mount_responses(
        &server,
        responses_completed_stream(
            "matrix",
            Vec::new(),
            Some(json!({"input_tokens": 1, "output_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");

    // CATALOG: the filtered model list answers through the credential
    // seam — the seeded store admits the lookup.
    let (provider, _) = openai_provider(&config);
    let catalog = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("catalog thread joins");
    reported.insert(
        "CATALOG",
        if matches!(catalog, Ok(ref ids) if ids == &["gpt-5.2".to_string()]) {
            "PASS"
        } else {
            "FAIL"
        },
    );

    // AUTH: an empty store denies at send with the typed verdict.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), "openai".to_string(), empty).expect("binding resolves");
    let (provider, denied) = send_on_thread(provider, prepared_manifest(&config));
    reported.insert(
        "AUTH",
        if matches!(denied, Err(ProviderError::CredentialAbsent { .. })) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // WIRE: the full broker dispatch returns the verified outcome.
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: matrix wire");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest);
    reported.insert(
        "WIRE",
        if matches!(&outcome, Ok(reply) if reply.text == "matrix") {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

    // RECOVERY: a typed denial is followed by a successful retry
    // through the same credential seam.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), "openai".to_string(), empty.clone()).expect("resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(CREDENTIAL_REF, SECRET.as_bytes());
    let (provider, retried) = send_on_thread(provider, manifest);
    let recovered = matches!(retried, Ok(ref reply) if reply.text == "matrix");
    reported.insert(
        "RECOVERY",
        if denied_ok && recovered {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // The literal row mirrors the `#[ignore]`d `provider_installed_openai`
    // case below: its ignored count is the explicit NOT_RUN signal this
    // matrix asserts — the row stays a literal so the two cannot drift.
    reported.insert("INSTALLED", "NOT_RUN");

    assert_eq!(
        reported,
        BTreeMap::from([
            ("CATALOG", "PASS"),
            ("AUTH", "PASS"),
            ("WIRE", "PASS"),
            ("RECOVERY", "PASS"),
            ("INSTALLED", "NOT_RUN"),
        ]),
        "every expected leg executed and reported: {reported:?}"
    );
}

// ----- TP-PROVIDER-INSTALLED::openai --------------------------------

/// TP-PROVIDER-INSTALLED::openai = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::openai = NOT_RUN"]
fn provider_installed_openai() {}

// ----- SSE conformance (WHATWG §9.2.5–9.2.6) -------------------------

fn parse_all(chunks: &[&[u8]]) -> Result<Vec<rivect::providers::sse::SseEvent>, SseError> {
    let mut parser = SseParser::new();
    let mut events = Vec::new();
    for chunk in chunks {
        events.extend(parser.feed(chunk)?);
    }
    events.extend(parser.finish()?);
    Ok(events)
}

#[test]
fn sse_split_utf8_codepoint_across_chunks() {
    // '€' is three bytes; the split must not corrupt the line
    let events = parse_all(&[b"data: caf\xe2\x82".as_slice(), b"\xac\n\n".as_slice()])
        .expect("split code point decodes whole");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data, "caf\u{20ac}");
}

#[test]
fn sse_single_leading_bom_stripped() {
    // one leading BOM is removed; a second BOM mid-stream is data
    let events = parse_all(&[
        b"\xef\xbb".as_slice(),
        b"\xbfdata: x\xef\xbb\xbf\n\n".as_slice(),
    ])
    .expect("bom handling");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data, "x\u{feff}");
}

#[test]
fn sse_cr_lf_crlf_line_endings_across_chunk_boundaries() {
    // every terminator form, with CR+LF split across a chunk boundary
    let events = parse_all(&[
        b"data: a\r".as_slice(),
        b"\ndata: b\r\ndata: c\r\n\n".as_slice(),
    ])
    .expect("all line endings");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data, "a\nb\nc");
}

#[test]
fn sse_comment_lines_are_ignored() {
    let events = parse_all(&[b": keepalive\n: another\ndata: x\n\n".as_slice()]).expect("comments");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data, "x");
}

#[test]
fn sse_exactly_one_space_after_colon_removed() {
    let events =
        parse_all(&[b"data:  two\ndata:three\ndata: four\n\n".as_slice()]).expect("one space only");
    assert_eq!(events[0].data, " two\nthree\nfour");
}

#[test]
fn sse_field_without_colon_is_name_with_empty_value() {
    let events = parse_all(&[b"data\n\n".as_slice()]).expect("empty value field");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data, "");
}

#[test]
fn sse_block_without_data_is_not_dispatched() {
    // a data-less block dispatches nothing and its field buffers reset —
    // neither the event type nor the ignored id leaks into the next block
    let events =
        parse_all(&[b"event: ping\nid: 7\n\ndata: next\n\n".as_slice()]).expect("block dropped");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "");
    assert_eq!(events[0].data, "next");
}

#[test]
fn sse_multiline_data_fields_joined_and_final_lf_removed() {
    let events =
        parse_all(&[b"data: one\ndata: two\ndata: three\n\n".as_slice()]).expect("multiline");
    assert_eq!(events[0].data, "one\ntwo\nthree");
}

#[test]
fn sse_reconnection_fields_parse_clean_and_carry_nothing() {
    // `id`/`retry` — including a NUL-carrying id and a non-digit retry —
    // parse as ignored fields: dispatch is undisturbed and no event
    // surface exposes them
    let events = parse_all(&[
        b"id: good\nretry: 250\ndata: a\n\n".as_slice(),
        b"id: ba\0d\nretry: 12x\ndata: b\n\n".as_slice(),
    ])
    .expect("reconnection fields are ignored");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].data, "a");
    assert_eq!(events[1].data, "b");
    // an event is exactly the two buffers a consumer reads — no
    // stream-level field can ride along
    assert_eq!(
        size_of::<rivect::providers::sse::SseEvent>(),
        2 * size_of::<String>(),
        "an event must carry no retained id/retry state"
    );
}

#[test]
fn sse_maximal_id_line_is_not_retained_across_events() {
    // a near-cap id line then many minimal events: the id is parsed and
    // dropped, so the per-event output stays minimal no matter how large
    // the reconnection state the peer sent
    let mut chunk = b"id: ".to_vec();
    chunk.extend(std::iter::repeat_n(b'x', 200 * 1024));
    chunk.extend(b"\n\n");
    let mut parser = SseParser::new();
    assert!(parser.feed(&chunk).expect("id block").is_empty());
    let mut emitted = 0usize;
    let mut payload_bytes = 0usize;
    for _ in 0..256 {
        for event in parser.feed(b"data: x\n\n").expect("minimal event") {
            emitted += 1;
            payload_bytes += event.event.len() + event.data.len();
        }
    }
    parser.finish().expect("clean eof");
    assert_eq!(emitted, 256);
    assert_eq!(
        payload_bytes, 256,
        "the 200KiB id never rode along on a minimal event"
    );
}

#[test]
fn sse_incomplete_block_at_eof_discarded_as_unknown_terminal() {
    // pending data with no terminating blank line never dispatches
    let events = parse_all(&[b"data: pending\n".as_slice()]).expect("eof discard");
    assert!(events.is_empty(), "the incomplete block is discarded");
    // an unterminated partial line is dropped the same way
    let events = parse_all(&[b"data: complete\n\ndata: orphan".as_slice()]).expect("partial tail");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data, "complete");
}

#[test]
fn sse_oversize_input_fails_closed_with_diagnostic() {
    // a line past the bound is a typed overrun, never a silent clamp
    let mut big = b"data: ".to_vec();
    big.extend(std::iter::repeat_n(b'x', 300 * 1024));
    big.extend(b"\n\n");
    let mut parser = SseParser::new();
    let err = parser
        .feed(&big)
        .expect_err("an over-long line fails closed");
    assert!(
        matches!(err, SseError::Overrun { .. }),
        "the bound reports itself: {err}"
    );
    // invalid utf-8 on a complete line fails the same way
    let mut parser = SseParser::new();
    let err = parser
        .feed(b"data: \xff\xfe\n\n")
        .expect_err("invalid utf-8 fails closed");
    assert!(matches!(err, SseError::InvalidUtf8), "got {err}");
}

/// The held-CR edge must not make the line bound chunk-dependent:
/// a line of exactly the cap followed by a split CRLF completes,
/// while one byte more fails under either delivery.
#[test]
fn sse_line_cap_is_chunk_independent() {
    let mut line = b"data: ".to_vec();
    line.extend(std::iter::repeat_n(b'x', 256 * 1024 - 6));
    assert_eq!(line.len(), 256 * 1024);
    let events = parse_all(&[line.as_slice(), b"\r".as_slice(), b"\n\n".as_slice()])
        .expect("the max-size line completes across the split CRLF");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data.len(), 256 * 1024 - 6);

    // one byte past the cap is an overrun under both chunkings
    let mut over = b"data: ".to_vec();
    over.extend(std::iter::repeat_n(b'x', 256 * 1024 - 5));
    let mut parser = SseParser::new();
    let err = parser.feed(&over).expect_err("one byte over fails closed");
    assert!(matches!(err, SseError::Overrun { .. }), "{err}");
    let mut parser = SseParser::new();
    parser.feed(&over[..256 * 1024]).expect("the cap holds");
    let err = parser
        .feed(&over[256 * 1024..])
        .expect_err("the same line split fails closed");
    assert!(matches!(err, SseError::Overrun { .. }), "{err}");
}

/// One event's accumulated `data` carries its own cap: many legal
/// lines overrunning the event bound are a typed overrun, not a
/// truncated event.
#[test]
fn sse_event_data_accumulation_overruns_its_bound() {
    let mut stream = Vec::new();
    for _ in 0..20 {
        stream.extend_from_slice(b"data: ");
        stream.extend(std::iter::repeat_n(b'x', 220 * 1024));
        stream.push(b'\n');
    }
    let mut parser = SseParser::new();
    let err = parser
        .feed(&stream)
        .expect_err("accumulated event data overruns its bound");
    assert!(
        matches!(
            err,
            SseError::Overrun {
                what: "event data",
                ..
            }
        ),
        "the event-data bound reports itself: {err}"
    );
}

/// EOF edges: a partial tail is discarded undecoded (invalid UTF-8
/// never validates — only complete lines decode), a held CR at EOF
/// terminates its line while the incomplete block still discards,
/// and a lone BOM is an empty stream. `finish` is idempotent and the
/// parser stays usable after it.
#[test]
fn sse_eof_edges_and_finish_reuse_are_safe() {
    let events = parse_all(&[b"data: ok\n\npartial \xff\xfe".as_slice()]).expect("partial tail");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data, "ok");

    let events = parse_all(&[b"data: held\r".as_slice()]).expect("held CR at EOF");
    assert!(events.is_empty(), "the unterminated block discards");

    let events = parse_all(&[b"\xef\xbb\xbf".as_slice()]).expect("BOM only");
    assert!(events.is_empty(), "a lone BOM is an empty stream");

    let mut parser = SseParser::new();
    parser.feed(b"data: partial").expect("a held line");
    parser.finish().expect("finish discards the held tail");
    // the scan cursor resets with the buffer: reuse after finish
    // starts from zero, never from the stale cursor
    parser.finish().expect("finish twice must not panic");
    let events = parser.feed(b"data: b\n\n").expect("feed after finish");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data, "b");
}

#[test]
fn sse_cost_is_linear_across_chunk_splits() {
    // the same stream fed byte-by-byte must produce byte-identical
    // events — the scan cursor keeps per-chunk work O(1) regardless
    // of how the input is split
    let stream: Vec<u8> = (0..64)
        .flat_map(|i| format!("data: line-{i}\n\n").into_bytes())
        .collect();
    let whole = parse_all(&[&stream]).expect("whole");
    let bytewise =
        parse_all(&stream.iter().map(std::slice::from_ref).collect::<Vec<_>>()).expect("bytewise");
    assert_eq!(whole, bytewise);
    assert_eq!(whole.len(), 64);
}

#[test]
fn sse_eventsource_stream_defects_10_11_do_not_reproduce() {
    // defect #10 (BOM byte offset): the BOM is stripped only as the
    // stream's leading bytes — one arriving inside a later field value
    // is literal data, never stripped
    let events = parse_all(&[
        b"data: first\n\n".as_slice(),
        b"data: \xef\xbb\xbfsecond\n\n".as_slice(),
    ])
    .expect("mid-stream bom is literal data");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].data, "first");
    assert_eq!(events[1].data, "\u{feff}second");

    // defect #11 (quadratic reparse of the in-progress line): a large
    // line arriving in many small chunks is held byte-wise and
    // decoded once — the cursor never reparses it
    let mut line = b"data: ".to_vec();
    line.extend(std::iter::repeat_n(b'y', 100 * 1024));
    line.extend(b"\n\n");
    let chunks: Vec<&[u8]> = line.chunks(1024).collect();
    let events = parse_all(&chunks).expect("long line in small chunks");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data.len(), 100 * 1024);
}
