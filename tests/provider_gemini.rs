//! Google Gemini provider proof legs (TP-PROVIDER-{CATALOG,AUTH,WIRE,
//! RECOVERY,INSTALLED}::google): the configured literal `google`
//! connection returns a verified model outcome through the standard
//! Broker — the real synchronous adapter against the source-derived
//! `streamGenerateContent` peer as localhost wiremock fixtures, no
//! OMP, no user adapter, no real host. The shared SSE parser's
//! WHATWG §9.2.5–9.2.6 conformance is pinned in provider_openai.rs;
//! this file pins the Gemini dialect surface on top of it.
//! TP-PROVIDER-INSTALLED::google stays NOT_RUN — the ignored named
//! case carries that status explicitly.

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
use rivect::providers::gemini::{
    GOOGLE_PROJECT_BILLED_KEY_TYPE, GOOGLE_STANDARD_KEY_SUNSET, GeminiProvider,
};
use rivect::providers::{CredentialStore, Provider, ProviderError, SecretRef, StoreKind};
use rivect::resources::UsageDelta;
use serde_json::{Value, json};
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

mod support;

/// The scoped credential ref the `google` connection binds — a
/// `keyring:` ref resolves to the platform's native class, which the
/// offline store double serves by scope alone.
const CREDENTIAL_REF: &str = "keyring:rivect-test/google";
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

/// The pinned model id the fixed-pin legs carry.
const MODEL: &str = "gemini-3.1-pro-preview";

/// One configured `google` connection pointing at the fixture peer:
/// the api_key auth class resolves a scoped `SecretRef` (DEC-011), the
/// dialect comes from the literal connection id (DEC-007).
fn gemini_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.google]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"google\", model_id = \"{MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// reqwest's blocking client builds and drops a shell runtime inside
/// `wait::enter` — panicking in any tokio context (debug builds) — so
/// every `GeminiProvider` construction happens on a plain OS thread.
fn provider_result(
    config: Config,
    connection: String,
    store: Arc<support::MapStore>,
) -> Result<GeminiProvider, ProviderError> {
    std::thread::spawn(move || GeminiProvider::new(&config, &connection, store))
        .join()
        .expect("the provider thread joins")
}

fn google_provider(config: &Config) -> (GeminiProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let provider = provider_result(config.clone(), "google".to_string(), store.clone())
        .expect("the google adapter builds for the literal id");
    (provider, store)
}

/// One SSE block on the wire — the Gemini `alt=sse` contract dispatches
/// bare `data:` chunks, one `GenerateContentResponse` each, with no
/// named event fields.
fn data_block(chunk: &Value) -> String {
    format!("data: {chunk}\n\n")
}

/// A Gemini stream: one chunk carrying the streamed parts, then the
/// terminal chunk whose candidate declares the mandatory
/// `finishReason` and whose `usageMetadata` reports the physical
/// charge. The dialect never treats a stream without a finish reason
/// as success.
fn gemini_stream(parts: Vec<Value>, finish_reason: &str, usage: Option<Value>) -> String {
    let mut terminal = json!({
        "candidates": [{
            "content": {"role": "model", "parts": []},
            "finishReason": finish_reason,
            "index": 0,
        }],
    });
    if let Some(usage) = usage {
        terminal["usageMetadata"] = usage;
    }
    format!(
        "{}{}",
        data_block(&json!({
            "candidates": [{
                "content": {"role": "model", "parts": parts},
                "index": 0,
            }],
        })),
        data_block(&terminal),
    )
}

/// A completed stream with text parts and a `STOP` finish.
fn completed_stream(text: &str, extra_parts: Vec<Value>, usage: Option<Value>) -> String {
    let mut parts = extra_parts;
    parts.push(json!({"text": text}));
    gemini_stream(parts, "STOP", usage)
}

/// The configured endpoint is the API base — `/v1beta` included, like
/// `https://generativelanguage.googleapis.com/v1beta` — and the
/// adapter appends the recorded resource paths.
fn server_uri_v1beta(server: &MockServer) -> String {
    format!("{}/v1beta", server.uri())
}

/// The recorded wire path for the pinned fixed model.
fn generate_path(model_id: &str) -> String {
    format!("/v1beta/models/{model_id}:streamGenerateContent")
}

async fn mount_generate(server: &MockServer, body: String) {
    Mock::given(method("POST"))
        .and(path(generate_path(MODEL).as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(server)
        .await;
}

/// The request bodies the fixture peer received, parsed as JSON.
async fn received_bodies(server: &MockServer) -> Vec<Value> {
    server
        .received_requests()
        .await
        .expect("the mock recorded requests")
        .iter()
        .map(|request: &Request| {
            serde_json::from_slice(&request.body).expect("the wire body is json")
        })
        .collect()
}

/// The API-key header the Gemini dialect authenticates with —
/// `x-goog-api-key`, never a bearer token.
fn received_key(request: &Request) -> String {
    request
        .headers
        .get("x-goog-api-key")
        .and_then(|value| value.to_str().ok())
        .expect("the request carried an x-goog-api-key header")
        .to_string()
}

/// A prepared manifest plus the broker that admitted it — the real
/// admission path, not a constructed manifest.
fn prepared(config: &Config, world: &str, inputs: &str) -> (Broker, RequestManifest) {
    let (provider, _store) = google_provider(config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", config, world, inputs)
        .expect("the google pin passes DEC-011 eligibility");
    (broker, manifest)
}

/// One frozen manifest through the real admission path.
fn prepared_manifest(config: &Config) -> RequestManifest {
    let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
    broker
        .prepare("main", config, "/world/google", "goal: auth leg")
        .expect("the google pin prepares")
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

/// reqwest's blocking client owns an internal runtime that must never
/// be dropped inside any tokio context — even the blocking pool — so
/// every broker/provider drop goes to a plain OS thread.
fn drop_blocking<T: Send + 'static>(value: T) {
    std::thread::spawn(move || drop(value))
        .join()
        .expect("the drop thread joins");
}

/// A bare `provider.send` must not run inside any tokio context for
/// the same reason — sends go to a plain OS thread and the provider
/// comes back.
fn send_on_thread(
    mut provider: GeminiProvider,
    manifest: RequestManifest,
) -> (
    GeminiProvider,
    Result<rivect::providers::ProviderReply, ProviderError>,
) {
    std::thread::spawn(move || {
        let outcome = provider.send(&manifest);
        (provider, outcome)
    })
    .join()
    .expect("the send thread joins")
}

/// A store double whose `resolve` parks for a fixed delay before
/// delegating — the seam a credential leg that consumes the send's
/// whole budget is proved through (DEC-014).
struct SlowStore {
    inner: support::MapStore,
    delay: Duration,
}

impl CredentialStore for SlowStore {
    fn kind(&self) -> StoreKind {
        self.inner.kind()
    }

    fn occupied(&self, credential: &SecretRef) -> Result<bool, ProviderError> {
        self.inner.occupied(credential)
    }

    fn entry_accounts(&self, service: &str) -> Result<Vec<String>, ProviderError> {
        self.inner.entry_accounts(service)
    }

    fn login(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        self.inner.login(credential, secret)
    }

    fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
        std::thread::sleep(self.delay);
        self.inner.resolve(credential)
    }

    fn refresh(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        self.inner.refresh(credential, secret)
    }

    fn revoke(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.inner.revoke(credential)
    }

    fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.inner.logout(credential)
    }
}

// ----- TP-PROVIDER-WIRE::google -------------------------------------

/// A configured `google` connection returns a verified model outcome
/// through the standard Broker: prepare admits the api_key pin under
/// DEC-011, the adapter posts exactly the frozen manifest as a
/// `streamGenerateContent` request — contents, systemInstruction, the
/// declared tool surface as functionDeclarations and the pinned effort
/// as thinkingConfig verbatim — the SSE stream validates its
/// finishReason terminal, and the one physical send is charged once
/// with the provider's reported usage.
#[tokio::test]
async fn valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_generate(
        &server,
        completed_stream(
            "verified outcome text",
            Vec::new(),
            Some(json!({"promptTokenCount": 11, "candidatesTokenCount": 7, "totalTokenCount": 18})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: prove the wire");

    let (broker, outcome) = dispatch(broker, "/world/google", manifest.clone());
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
    assert_eq!(received_key(&requests[0]), SECRET);
    assert!(
        requests[0].headers.get("authorization").is_none(),
        "the dialect authenticates with x-goog-api-key alone — no bearer header rides the wire"
    );
    assert_eq!(
        requests[0].url.query(),
        Some("alt=sse"),
        "the recorded streaming selector rides the request"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["contents"],
        json!([{
            "role": "user",
            "parts": [{ "text": manifest.inputs }],
        }])
    );
    if manifest.instructions.is_empty() {
        assert!(
            body.get("systemInstruction").is_none(),
            "no instructions means no systemInstruction member"
        );
    } else {
        assert_eq!(
            body["systemInstruction"],
            json!({"parts": [{ "text": manifest.instructions }]}),
            "the frozen instructions ride the systemInstruction surface"
        );
    }
    assert_eq!(
        body["tools"],
        json!([{ "functionDeclarations": [{ "name": "read_file", "description": "" }] }]),
        "the declared tool surface maps to functionDeclarations verbatim"
    );
    assert_eq!(
        body["generationConfig"],
        json!({ "thinkingConfig": { "thinkingLevel": "MEDIUM" } }),
        "the pinned effort rides the recorded thinkingLevel enum"
    );

    // Exactly one accounting record carries the one physical usage
    // report — the bound was 33k-reserved, the provider's 18 tokens
    // are the confirmed charge, and a replayed attempt reports spent.
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "google");
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
            let replay = broker.dispatch("/world/google", &manifest);
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
/// label: a connection id without the recorded Gemini source class
/// builds no adapter, a manifest pinning a different connection id is
/// refused at send, and an `openai`-pinned manifest through the google
/// broker is a dialect denial before any byte or accounting.
#[tokio::test]
async fn dialect_is_keyed_on_the_literal_connection_id() {
    let server = MockServer::start().await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = provider_result(config.clone(), "google-vertex".to_string(), store)
        .expect_err("a different literal id is not this dialect");
    assert!(matches!(err, ProviderError::DialectMismatch { .. }));

    let (mut provider, _store) = google_provider(&config);
    let foreign = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.other]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"other\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1beta(&server)
    ))
    .expect("valid");
    let mut manifest = {
        let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
        broker
            .prepare("main", &foreign, "/world/google", "goal: x")
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

    // An OpenAI-pinned manifest dispatched through the google broker:
    // eligibility passes the api_key pin, the adapter's own dialect
    // gate denies it before any send or accounting.
    let openai_pinned = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.openai]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"openai\", model_id = \"gpt-5.2\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1beta(&server)
    ))
    .expect("valid");
    let (provider, _store) = google_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare(
            "main",
            &openai_pinned,
            "/world/google",
            "goal: foreign dialect",
        )
        .expect("the openai pin passes DEC-011 eligibility");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::DialectMismatch { .. }))
        ),
        "an openai pin through the google broker is the typed dialect denial: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a denied send is never accounted"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert!(
        requests.is_empty(),
        "the dialect denial never sent: {requests:?}"
    );
    drop_blocking(broker);
}

// ----- TP-PROVIDER-CATALOG::google ----------------------------------

/// `GET /models` merged with the recorded static catalogue: only
/// entries whose `supportedGenerationMethods` admit `generateContent`
/// join — a capability never inferred from the model name — the union
/// deduplicates against the static sample, and the API-key credential
/// came through the store seam.
#[tokio::test]
async fn google_catalog_merges_models_list_and_static_catalog() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "models": [
                {
                    "name": "models/gemini-3.1-pro",
                    "supportedGenerationMethods": ["generateContent"],
                },
                {
                    "name": "models/gemini-2.0-flash",
                    "supportedGenerationMethods": ["generateContent", "countTokens"],
                },
                {
                    "name": "models/text-embedding-004",
                    "supportedGenerationMethods": ["embedContent"],
                },
                {
                    "name": "models/aqa",
                },
            ],
        })))
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (provider, _store) = google_provider(&config);
    let ids = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("the catalog thread joins")
        .expect("the catalog answers");
    assert_eq!(
        ids,
        vec![
            "gemini-2.0-flash".to_string(),
            "gemini-3.1-pro".to_string(),
            "gemini-3.1-pro-preview".to_string(),
            "gemini-3.7-flash".to_string(),
        ],
        "the dynamic listing merged with the recorded static catalogue"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(received_key(&requests[0]), SECRET);
    assert!(
        requests[0].headers.get("authorization").is_none(),
        "the catalogue leg authenticates with x-goog-api-key alone"
    );
}

/// The listing payload is bounded like the stream: a body past the
/// byte bound is a typed violation, never buffered unbounded.
#[tokio::test]
async fn catalog_payload_over_the_byte_bound_is_a_typed_violation() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            // the bound is 1 MiB — one byte past it trips the read loop
            "x".repeat(1024 * 1024 + 1),
        ))
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (provider, _store) = google_provider(&config);
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
    let endpoint = format!("http://{address}/v1beta");
    let config = Config::parse_validated(&gemini_config(&endpoint)).expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let built = config.clone();
    let provider = std::thread::spawn(move || {
        GeminiProvider::with_deadline(&built, "google", store, Duration::from_millis(1500))
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

/// The recorded account predicates for the `google` class hold as
/// data: the API keys this dialect authenticates with are the
/// project-billed "standard" type — never detectable from their
/// material — and upstream's September 2026 sunset rejects every
/// standard key while unrestricted ones are already refused. The
/// constants pin the recorded values so the predicates cannot drift.
#[test]
fn google_project_billed_key_type_and_standard_key_sunset_predicates_hold() {
    assert_eq!(GOOGLE_PROJECT_BILLED_KEY_TYPE, "standard");
    assert_eq!(GOOGLE_STANDARD_KEY_SUNSET, "2026-09");
}

/// AC-046 fail-closed: eligibility says the `google` pin is usable,
/// but a broker whose only adapter is the local fixture must still
/// deny the send — the provider's own dialect claim is the last
/// gate, and the denial lands before any send or accounting.
#[test]
fn a_pin_no_adapter_serves_is_denied_before_send_or_accounting() {
    let config =
        Config::parse_validated(&gemini_config("http://127.0.0.1:1/v1beta")).expect("valid");
    let (provider, calls, _manifest) = support::CountingProvider::new();
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/google", "goal: unserved pin")
        .expect("the google pin passes DEC-011 eligibility");
    let outcome = broker.dispatch("/world/google", &manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::DialectMismatch { .. }))
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
/// it declares — `google` declaring `local` kind gets the typed denial,
/// never a fabricated loopback reply.
#[test]
fn a_reserved_dialect_id_is_never_loopback_served() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.google]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"google\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"medium\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let loopback = rivect::providers::LoopbackProvider::new();
    let entry = config.connections.get("google").expect("declared");
    assert!(
        !loopback.serves("google", entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );
    let mut broker = Broker::new(Box::new(loopback));
    let manifest = broker
        .prepare("main", &config, "/world/google", "goal: reserved id")
        .expect("the local-kind pin passes DEC-011 eligibility");
    let outcome = broker.dispatch("/world/google", &manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::DialectMismatch { .. }))
        ),
        "a dialect-reserved id is denied, never fabricated: {outcome:?}"
    );
}

/// AC-045: an explicit manual pick of a served `google` candidate
/// reaches the real send — the substitute's single-member auto pool
/// pins the connection, the live catalogue names the model, and the
/// send is attempted instead of deterministically failing
/// `UnpinnedModel` after eligibility already passed.
#[tokio::test]
async fn a_manual_pick_of_a_google_candidate_reaches_the_real_send() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "models": [
                {
                    "name": "models/gemini-3.1-pro",
                    "supportedGenerationMethods": ["generateContent"],
                },
            ],
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(generate_path("gemini-3.1-pro").as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(completed_stream(
                    "picked outcome",
                    Vec::new(),
                    Some(
                        json!({"promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 2}),
                    ),
                )),
        )
        .mount(&server)
        .await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.a-local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [connections.google]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"manual\" }}\n",
        server_uri_v1beta(&server)
    ))
    .expect("valid");
    let (provider, _store) = google_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/google", "goal: pick google")
        .expect("the auto ranking admits a candidate");
    let attempt_id = manifest.attempt_id.clone();

    // The adapter speaks no local-fixture dialect: the ranked `a-local`
    // primary send fails and the manual pause offers the served google
    // candidate.
    let (mut broker, outcome) = std::thread::spawn(move || {
        let outcome = broker.dispatch("/world/google", &manifest);
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
        pending.candidates.contains(&"google".to_string()),
        "the served candidate is offered: {:?}",
        pending.candidates
    );

    let (broker, outcome) = std::thread::spawn(move || {
        let outcome = broker.dispatch_fallback_choice("/world/google", &attempt_id, "google");
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
    assert_eq!(
        requests[1].url.path(),
        generate_path("gemini-3.1-pro"),
        "the live catalogue named the model the pick resolved to"
    );
    drop_blocking(broker);
}

/// The same auto seam on the primary send: `mode = "auto"` ranks the
/// `google` connection, the dispatch narrows the pool to the winner it
/// picked, and the adapter's catalogue leg names the wire model —
/// `UnpinnedModel` never fires on a send the broker itself routed.
#[tokio::test]
async fn auto_ranked_google_primary_send_resolves_via_catalog() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "models": [
                {
                    "name": "models/gemini-3.1-pro-preview",
                    "supportedGenerationMethods": ["generateContent"],
                },
                {
                    "name": "models/gemini-3.1-pro",
                    "supportedGenerationMethods": ["generateContent"],
                },
                {
                    "name": "models/text-embedding-004",
                    "supportedGenerationMethods": ["embedContent"],
                },
            ],
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(generate_path("gemini-3.1-pro").as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(completed_stream(
                    "auto outcome",
                    Vec::new(),
                    Some(
                        json!({"promptTokenCount": 2, "candidatesTokenCount": 1, "totalTokenCount": 3}),
                    ),
                )),
        )
        .mount(&server)
        .await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.google]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1beta(&server)
    ))
    .expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: auto route");
    assert!(
        matches!(
            manifest.model,
            rivect::config::ModelAssign::Auto { pool: None }
        ),
        "the ranked auto assignment stays un-narrowed on the frozen manifest"
    );

    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
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
    assert_eq!(received_key(&requests[0]), SECRET);
    assert_eq!(
        requests[1].url.path(),
        generate_path("gemini-3.1-pro"),
        "the catalogue's sorted-first id rode the wire"
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
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("address");
    // serve every connection the transport opens — a reset or retried
    // leg gets the same dribble, never an unanswered socket — until the
    // test releases the flag and the thread joins
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = stop.clone();
    let peer = std::thread::spawn(move || {
        while !flag.load(std::sync::atomic::Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n");
                    // one byte per tick — every individual read answers
                    // inside its own window, so only a total deadline
                    // can end this
                    while stream.write_all(b"x").is_ok()
                        && !flag.load(std::sync::atomic::Ordering::Relaxed)
                    {
                        std::thread::sleep(Duration::from_millis(30));
                    }
                }
                Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    let endpoint = format!("http://{address}/v1beta");
    let config = Config::parse_validated(&gemini_config(&endpoint)).expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let built = config.clone();
    let provider = std::thread::spawn(move || {
        GeminiProvider::with_deadline(&built, "google", store, Duration::from_millis(1500))
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
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    peer.join().expect("the drip thread joins");
}

/// DEC-014: the deadline check stands between the legs that spend the
/// budget and the wire — a credential resolve that consumes the whole
/// budget fails the send typed before one byte crosses, never a post
/// on an expired clock surfacing reqwest's backstop text.
#[tokio::test]
async fn expired_budget_denies_the_send_before_any_wire_leg() {
    let server = MockServer::start().await;
    mount_generate(&server, completed_stream("never sent", Vec::new(), None)).await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let deadline = Duration::from_millis(1500);
    let store = Arc::new(SlowStore {
        inner: support::MapStore::seeded(STORE_KIND, &[(CREDENTIAL_REF, SECRET)]),
        // past the deadline — the resolve returns under an expired clock
        delay: deadline + Duration::from_millis(500),
    });
    let built = config.clone();
    let provider = std::thread::spawn(move || {
        GeminiProvider::with_deadline(&built, "google", store, deadline)
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

// ----- TP-PROVIDER-AUTH::google -------------------------------------

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
/// a configured region outside the dialect's recorded endpoint
/// contract — the `google` class records none — the profile-bound ref
/// whose scope disagrees with the binding, an absent credential, and a
/// refused API key each land a typed denial — and none of them, nor
/// any Debug surface the boundary exposes, renders credential
/// material or the peer's body.
#[tokio::test]
async fn wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // region outside the recorded endpoint contract — the public
    // Gemini API records no configurable region — a sibling scope
    // holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(&gemini_config(&server_uri_v1beta(&server)).replace(
        "kind = \"api_key\"",
        "kind = \"api_key\"\nregion = \"us-central1\"",
    ))
    .expect("valid");
    let err = provider_result(
        regioned,
        "google".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, SECRET)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "google");
    assert_eq!(region, "us-central1");
    assert_no_secret_or_body(&err);

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.google]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"google\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1beta(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "google".to_string(),
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
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let provider = provider_result(
        config.clone(),
        "google".to_string(),
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

    // a refused API key is a typed transport denial — the wire never
    // coerces a wrong credential into success, and the peer's body
    // never enters the error
    Mock::given(method("POST"))
        .and(path(generate_path(MODEL).as_str()))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    // The fixture 401s any key, so the enrolled material is SECRET
    // itself — the only leg that resolves material before the HTTP
    // error, and the assertion must prove that resolved credential is
    // absent from the error, not a different string.
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let provider = provider_result(config.clone(), "google".to_string(), store).expect("builds");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused key is a typed transport denial");
    let ProviderError::Transport { connection, reason } = &err else {
        panic!("a refused key is transport: {err}")
    };
    assert_eq!(connection, "google");
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
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let provider =
        provider_result(config.clone(), "google".to_string(), store).expect("the adapter builds");
    assert!(
        !format!("{provider:?}").contains(SECRET),
        "provider Debug never carries credential material"
    );
    mount_generate(
        &server,
        completed_stream(
            "accounted",
            Vec::new(),
            Some(json!({"promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 2})),
        ),
    )
    .await;
    let (broker, manifest) = prepared(&config, "/world/google", "goal: debug surfaces");
    assert!(
        !format!("{manifest:?}").contains(SECRET),
        "manifest Debug never carries credential material"
    );
    let (broker, outcome) = dispatch(broker, "/world/google", manifest.clone());
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

    let world = support::open_world(
        "auth-debug",
        Some(&gemini_config(&server_uri_v1beta(&server))),
    );
    assert!(
        !format!("{:?}", world.runtime).contains(SECRET),
        "runtime Debug never carries credential material"
    );
}

/// Material the store resolves but the dialect cannot use — non-UTF-8
/// bytes can never be an API-key header — is the typed malformed
/// denial at send, and the material itself never enters the error.
#[tokio::test]
async fn non_utf8_credential_material_is_a_typed_malformed_denial() {
    let server = MockServer::start().await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let store = Arc::new(support::MapStore::new(STORE_KIND));
    store.enroll(CREDENTIAL_REF, b"\xff\xfe");
    let provider = provider_result(config.clone(), "google".to_string(), store)
        .expect("binding resolves; the store is read at send");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("non-utf-8 material is the typed denial");
    let ProviderError::CredentialMalformed { connection } = &err else {
        panic!("non-utf-8 material is malformed, never absent: {err}")
    };
    assert_eq!(connection, "google");
    assert_no_secret_or_body(&err);
    drop_blocking(provider);
}

// ----- TP-PROVIDER-RECOVERY::google ---------------------------------

/// A typed denial is recoverable through the same seam: the absent
/// credential denies the first send, enrolling material at the scope
/// admits the retry — no state wedged, no plaintext path taken.
#[tokio::test]
async fn typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_generate(
        &server,
        completed_stream(
            "recovered",
            Vec::new(),
            Some(json!({"promptTokenCount": 2, "candidatesTokenCount": 1, "totalTokenCount": 3})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "google".to_string(), store.clone())
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

/// A stream that ends mid content is never a usable reply — the
/// streamed functionCall arrived but no finishReason ever did, the
/// partial call is never executed, and nothing is accounted.
#[tokio::test]
async fn partial_tool_block_never_executes() {
    let server = MockServer::start().await;
    mount_generate(
        &server,
        data_block(&json!({
            "candidates": [{
                "content": {"role": "model", "parts": [
                    {"functionCall": {"name": "read_file", "args": {"path": "src/lib.rs"}}},
                ]},
                "index": 0,
            }],
        })),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: partial tool");

    let (broker, outcome) = dispatch(broker, "/world/google", manifest.clone());
    let error = outcome.expect_err("a truncated stream is never success");
    assert!(
        matches!(
            error,
            ModelError::Provider(ProviderError::UnknownTerminal { .. })
        ),
        "a stream ended without a finishReason is the unknown terminal: {error}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);
}

/// The stream owes a finishReason the dialect can classify: a stream
/// that ends without one, and a finishReason the dialect cannot
/// classify, are both unknown — never success.
#[tokio::test]
async fn unknown_mandatory_terminal_is_not_success() {
    let server = MockServer::start().await;

    // complete parts, then silence — no finishReason ever arrives
    mount_generate(
        &server,
        data_block(&json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "hi"}]},
                "index": 0,
            }],
        })),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: no terminal");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "EOF without a finishReason is the unknown terminal: {outcome:?}"
    );
    drop_blocking(broker);

    // a finishReason the dialect cannot classify
    let server = MockServer::start().await;
    mount_generate(
        &server,
        gemini_stream(vec![json!({"text": "hi"})], "CONCLUDED", None),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: strange terminal");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "an unclassifiable finishReason is not success: {outcome:?}"
    );
    drop_blocking(broker);
}

/// Well-formed output the dialect cannot honour is a typed rejection:
/// a part kind outside the recorded text/thought/functionCall surface,
/// a functionCall naming a tool the frozen request never declared, and
/// a pinned effort the recorded `ThinkingLevel` enum cannot carry —
/// the request refuses to send rather than clamping silently.
#[tokio::test]
async fn incompatible_tools_or_reasoning_is_a_typed_rejection() {
    // a server-side part kind the dialect cannot honour
    let server = MockServer::start().await;
    mount_generate(
        &server,
        completed_stream(
            "",
            vec![json!({"executableCode": {"language": "PYTHON", "code": "print(1)"}})],
            None,
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: incompatible part");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(
                ProviderError::IncompatibleOutput { .. }
            ))
        ),
        "an unhonourable part kind is a typed rejection: {outcome:?}"
    );
    drop_blocking(broker);

    // a functionCall naming a tool the frozen request never declared
    // is output the dialect cannot honour — never executed
    let server = MockServer::start().await;
    mount_generate(
        &server,
        completed_stream(
            "",
            vec![json!({"functionCall": {"name": "exec_shell", "args": {"cmd": "ls"}}})],
            None,
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: undeclared call");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
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

    // a pinned effort the recorded ThinkingLevel enum cannot carry is
    // a typed request rejection — never silently clamped to HIGH and
    // never an invented wire spelling
    let server = MockServer::start().await;
    mount_generate(&server, completed_stream("never sent", Vec::new(), None)).await;
    let config = Config::parse_validated(
        &gemini_config(&server_uri_v1beta(&server))
            .replace("value = \"medium\"", "value = \"xhigh\""),
    )
    .expect("valid");
    let (provider, _store) = google_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    assert!(
        matches!(outcome, Err(ProviderError::StreamViolation { .. })),
        "an unrepresentable effort is a typed request rejection: {outcome:?}"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert!(
        requests.is_empty(),
        "the refused effort never sent: {requests:?}"
    );
    drop_blocking(provider);
}

/// The remaining terminal and malformed shapes all land as typed
/// rejections: an error-class `finishReason`, a `promptFeedback`
/// block and a provider `error` verdict are peer failures even when
/// earlier chunks carried valid tool calls, a duplicate finishReason
/// or malformed chunk is a wire violation, an unreadable
/// `usageMetadata` violates the contract, and a refused connection is
/// a transport failure.
#[tokio::test]
async fn remaining_terminals_and_malformed_wire_shapes_are_typed() {
    // a SAFETY finish is the peer's own failure verdict — even though
    // an earlier chunk carried a valid functionCall
    let server = MockServer::start().await;
    mount_generate(
        &server,
        gemini_stream(
            vec![json!({"functionCall": {"name": "read_file", "args": {"path": "src/lib.rs"}}})],
            "SAFETY",
            None,
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: safety verdict");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::ProviderFailed { .. }))
        ),
        "a SAFETY finish is a peer failure, never a tool call: {outcome:?}"
    );
    drop_blocking(broker);

    // a MALFORMED_FUNCTION_CALL finish is a peer failure the same way
    let server = MockServer::start().await;
    mount_generate(
        &server,
        gemini_stream(vec![json!({"text": "x"})], "MALFORMED_FUNCTION_CALL", None),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: malformed call verdict");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::ProviderFailed { .. }))
        ),
        "a MALFORMED_FUNCTION_CALL finish is a peer failure: {outcome:?}"
    );
    drop_blocking(broker);

    // a promptFeedback blockReason is the peer's refusal verdict
    let server = MockServer::start().await;
    mount_generate(
        &server,
        data_block(&json!({
            "promptFeedback": {"blockReason": "SAFETY"},
        })),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: blocked verdict");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::ProviderFailed { .. }))
        ),
        "a prompt block is a peer failure: {outcome:?}"
    );
    drop_blocking(broker);

    // a second finishReason after a valid terminal is a wire
    // violation — the stream owes exactly one verdict
    let server = MockServer::start().await;
    mount_generate(
        &server,
        format!(
            "{}{}",
            completed_stream("first", Vec::new(), None),
            data_block(&json!({
                "candidates": [{"finishReason": "SAFETY", "index": 0}],
            })),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: duplicate terminal");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "a duplicate terminal is a wire violation: {outcome:?}"
    );
    drop_blocking(broker);

    // a chunk whose payload does not parse is a violation
    let server = MockServer::start().await;
    mount_generate(&server, "data: {broken\n\n".to_string()).await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: malformed chunk");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "a malformed chunk is a wire violation: {outcome:?}"
    );
    drop_blocking(broker);

    // a usage object whose counters do not read is unreadable, never
    // an estimate
    let server = MockServer::start().await;
    mount_generate(
        &server,
        completed_stream(
            "counted",
            Vec::new(),
            Some(json!({"promptTokenCount": "many", "candidatesTokenCount": 7, "totalTokenCount": 7})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: unreadable usage");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "an unreadable usage object is a wire violation: {outcome:?}"
    );
    drop_blocking(broker);

    // a refused connection is a transport failure
    let config =
        Config::parse_validated(&gemini_config("http://127.0.0.1:1/v1beta")).expect("valid");
    let (provider, _store) = google_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    assert!(
        matches!(outcome, Err(ProviderError::Transport { .. })),
        "a refused connection is transport: {outcome:?}"
    );
    drop_blocking(provider);
}

/// Every malformed sibling shape lands the typed violation: a
/// non-success listing status, a catalogue payload that is not the
/// `models` listing the contract requires, and the malformed
/// chunk/candidate/part/finishReason shapes the stream contract rules
/// out.
#[tokio::test]
async fn malformed_wire_shapes_are_typed_violations() {
    // a non-success listing status is a typed transport failure —
    // the peer's own code names it, never the uncontrolled body
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (provider, _store) = google_provider(&config);
    let outcome = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("the catalog thread joins");
    assert!(
        matches!(outcome, Err(ProviderError::Transport { .. })),
        "a non-success listing status is a typed transport failure: {outcome:?}"
    );

    // catalogue legs: GET /models owes the `models` array
    for (name, body) in [
        ("a non-json listing", "not json".to_string()),
        (
            "a listing without the models array",
            "{\"object\": \"list\"}".to_string(),
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1beta/models"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let config =
            Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
        let (provider, _store) = google_provider(&config);
        let outcome = std::thread::spawn(move || provider.catalog())
            .join()
            .expect("the catalog thread joins");
        assert!(
            matches!(outcome, Err(ProviderError::StreamViolation { .. })),
            "{name} is a typed violation: {outcome:?}"
        );
    }

    // stream legs: every mandatory shape the chunk contract requires
    let legs: Vec<(&str, String)> = vec![
        ("a chunk that is not an object", "data: 5\n\n".to_string()),
        (
            "a candidates member that is not an array",
            data_block(&json!({"candidates": "x"})),
        ),
        (
            "a candidate that is not an object",
            data_block(&json!({"candidates": [5]})),
        ),
        (
            "a candidate content that is not an object",
            data_block(&json!({"candidates": [{"content": 5}]})),
        ),
        (
            "a candidate content parts member that is not an array",
            data_block(&json!({"candidates": [{"content": {"role": "model", "parts": "x"}}]})),
        ),
        (
            "a part that is not an object",
            data_block(&json!({"candidates": [{"content": {"role": "model", "parts": [5]}}]})),
        ),
        (
            "a text part that is not a string",
            data_block(
                &json!({"candidates": [{"content": {"role": "model", "parts": [{"text": 5}]}}]}),
            ),
        ),
        (
            "a thought marker that is not a boolean",
            data_block(
                &json!({"candidates": [{"content": {"role": "model", "parts": [{"thought": "yes", "text": "x"}]}}]}),
            ),
        ),
        (
            "a thoughtSignature that is not a string",
            data_block(
                &json!({"candidates": [{"content": {"role": "model", "parts": [{"thoughtSignature": 5}]}}]}),
            ),
        ),
        (
            "a functionCall that is not an object",
            data_block(
                &json!({"candidates": [{"content": {"role": "model", "parts": [{"functionCall": "x"}]}}]}),
            ),
        ),
        (
            "a functionCall without a name",
            data_block(
                &json!({"candidates": [{"content": {"role": "model", "parts": [{"functionCall": {"args": {}}}]}}]}),
            ),
        ),
        (
            "functionCall args that are not an object",
            data_block(
                &json!({"candidates": [{"content": {"role": "model", "parts": [{"functionCall": {"name": "read_file", "args": "x"}}]}}]}),
            ),
        ),
        (
            "a finishReason that is not a string",
            data_block(&json!({"candidates": [{"finishReason": 5}]})),
        ),
        (
            "a promptFeedback member that is not an object",
            data_block(&json!({"promptFeedback": "blocked"})),
        ),
        (
            "a promptFeedback blockReason that is not a string",
            data_block(&json!({"promptFeedback": {"blockReason": 5}})),
        ),
    ];
    for (name, body) in legs {
        let server = MockServer::start().await;
        mount_generate(&server, body).await;
        let config =
            Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
        let (broker, manifest) = prepared(&config, "/world/google", "goal: malformed");
        let (broker, outcome) = dispatch(broker, "/world/google", manifest);
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

/// A model id is exactly one URL path segment: a fixed pin carrying
/// `?`, `/`, `%` or an empty id is denied before any byte crosses —
/// never a traversal of the `/models/` collection or a rewrite of the
/// method suffix — and a catalogue name outside the id charset is
/// dropped, so a hostile listing cannot poison the auto pick with an
/// empty id that sorts first.
#[tokio::test]
async fn hostile_model_ids_and_catalog_names_never_reach_the_wire() {
    for hostile in ["a?b=1", "models/../x", "%2e%2e%2fadmin", ""] {
        let server = MockServer::start().await;
        mount_generate(&server, completed_stream("never sent", Vec::new(), None)).await;
        let config = Config::parse_validated(&format!(
            "config_version = 1\n\
             [connections.google]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
             [models.defaults]\n\
             model = {{ mode = \"fixed\", connection = \"google\", model_id = \"{hostile}\" }}\n\
             effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
             fallback = {{ mode = \"off\" }}\n",
            server_uri_v1beta(&server)
        ))
        .expect("valid");
        let (provider, _store) = google_provider(&config);
        let manifest = prepared_manifest(&config);
        let (provider, outcome) = send_on_thread(provider, manifest);
        assert!(
            matches!(outcome, Err(ProviderError::StreamViolation { .. })),
            "model id {hostile:?} is a typed denial before the post: {outcome:?}"
        );
        let requests = server.received_requests().await.expect("recorded");
        assert!(
            requests.is_empty(),
            "model id {hostile:?} never crossed the wire: {requests:?}"
        );
        drop_blocking(provider);
    }

    // `models/` strips to an empty id and `models/../x` carries a
    // traversal — both drop out of the offered set, so only the
    // conforming listing entry and the static catalogue remain.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "models": [
                {
                    "name": "models/",
                    "supportedGenerationMethods": ["generateContent"],
                },
                {
                    "name": "models/../admin",
                    "supportedGenerationMethods": ["generateContent"],
                },
                {
                    "name": "models/has space",
                    "supportedGenerationMethods": ["generateContent"],
                },
                {
                    "name": "models/legit-1.5-flash",
                    "supportedGenerationMethods": ["generateContent"],
                },
            ],
        })))
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (provider, _store) = google_provider(&config);
    let ids = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("the catalog thread joins")
        .expect("the catalog answers");
    assert_eq!(
        ids,
        vec![
            "gemini-3.1-pro".to_string(),
            "gemini-3.1-pro-preview".to_string(),
            "gemini-3.7-flash".to_string(),
            "legit-1.5-flash".to_string(),
        ],
        "hostile names never join the offered set"
    );
}

/// The request never declares `candidateCount`: a chunk carrying more
/// than one candidate, or a candidate whose `index` is not the single
/// slot asked for, is off-contract input — a typed violation, never a
/// silent first-pick — while an empty candidate set terminates nothing
/// and leaves the stream owing a verdict.
#[tokio::test]
async fn candidate_collections_outside_the_single_candidate_contract_are_typed() {
    let legs: Vec<(&str, String)> = vec![
        (
            "a second candidate the request never asked for",
            data_block(&json!({
                "candidates": [
                    {
                        "content": {"role": "model", "parts": [{"text": "a"}]},
                        "index": 0,
                    },
                    {
                        "content": {"role": "model", "parts": [{"text": "b"}]},
                        "finishReason": "STOP",
                        "index": 1,
                    },
                ],
            })),
        ),
        (
            "a candidate index other than the requested slot",
            data_block(&json!({
                "candidates": [{
                    "content": {"role": "model", "parts": [{"text": "x"}]},
                    "index": 1,
                }],
            })),
        ),
    ];
    for (name, body) in legs {
        let server = MockServer::start().await;
        mount_generate(&server, body).await;
        let config =
            Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
        let (broker, manifest) = prepared(&config, "/world/google", "goal: candidate set");
        let (broker, outcome) = dispatch(broker, "/world/google", manifest);
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

    // an empty candidates member adopts nothing and declares no
    // verdict — the stream still owes a finishReason
    let server = MockServer::start().await;
    mount_generate(&server, data_block(&json!({"candidates": []}))).await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: empty candidates");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "an empty candidate set is the unknown terminal: {outcome:?}"
    );
    drop_blocking(broker);
}

/// A candidate arriving after the declared terminal adopts nothing —
/// a post-finishReason part is a typed violation, never a tool call or
/// lineage entry — while the recorded `usageMetadata`-only tail still
/// lands its charge.
#[tokio::test]
async fn post_terminal_content_is_refused_and_a_usage_tail_still_lands() {
    let server = MockServer::start().await;
    mount_generate(
        &server,
        format!(
            "{}{}",
            data_block(&json!({
                "candidates": [{
                    "content": {"role": "model", "parts": [{"text": "done"}]},
                    "finishReason": "STOP",
                    "index": 0,
                }],
            })),
            data_block(&json!({
                "candidates": [{
                    "content": {"role": "model", "parts": [
                        {"functionCall": {"name": "read_file", "args": {"path": "src/lib.rs"}}},
                    ]},
                    "index": 0,
                }],
            })),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: late content");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "content after the terminal is a typed violation, never adopted: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a refused stream charges nothing"
    );
    drop_blocking(broker);

    // the recorded post-terminal shape — usageMetadata alone — lands
    // the stream's last cumulative charge
    let server = MockServer::start().await;
    mount_generate(
        &server,
        format!(
            "{}{}",
            data_block(&json!({
                "candidates": [{
                    "content": {"role": "model", "parts": [{"text": "done"}]},
                    "finishReason": "STOP",
                    "index": 0,
                }],
            })),
            data_block(&json!({
                "usageMetadata": {
                    "promptTokenCount": 5,
                    "candidatesTokenCount": 2,
                    "totalTokenCount": 7,
                },
            })),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: usage tail");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest.clone());
    outcome.expect("a usage-only tail after the terminal is the recorded shape");
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 5,
            completion_tokens: 2,
            total_tokens: 7,
        },
        "the trailing usage report is the charge"
    );
    drop_blocking(broker);
}

/// Every recorded `finishReason` maps to its one terminal class:
/// `STOP`/`MAX_TOKENS` complete — a truncated answer is a valid
/// charge — the recorded failure set is the peer's own verdict, and
/// anything else is unknown, never success.
#[tokio::test]
async fn every_recorded_finish_reason_maps_to_its_terminal_class() {
    enum Verdict {
        Completed,
        Failed,
        Unknown,
    }
    let legs: Vec<(&str, Verdict)> = vec![
        ("STOP", Verdict::Completed),
        ("MAX_TOKENS", Verdict::Completed),
        ("BLOCKLIST", Verdict::Failed),
        ("PROHIBITED_CONTENT", Verdict::Failed),
        ("SPII", Verdict::Failed),
        ("SAFETY", Verdict::Failed),
        ("IMAGE_SAFETY", Verdict::Failed),
        ("IMAGE_PROHIBITED_CONTENT", Verdict::Failed),
        ("IMAGE_RECITATION", Verdict::Failed),
        ("IMAGE_OTHER", Verdict::Failed),
        ("RECITATION", Verdict::Failed),
        ("FINISH_REASON_UNSPECIFIED", Verdict::Failed),
        ("OTHER", Verdict::Failed),
        ("LANGUAGE", Verdict::Failed),
        ("MALFORMED_FUNCTION_CALL", Verdict::Failed),
        ("UNEXPECTED_TOOL_CALL", Verdict::Failed),
        ("NO_IMAGE", Verdict::Failed),
        ("CONCLUDED", Verdict::Unknown),
        ("A_REASON_THE_DIALECT_NEVER_RECORDED", Verdict::Unknown),
    ];
    for (reason, verdict) in legs {
        let server = MockServer::start().await;
        mount_generate(
            &server,
            gemini_stream(vec![json!({"text": "done"})], reason, None),
        )
        .await;
        let config =
            Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
        let (broker, manifest) = prepared(&config, "/world/google", "goal: finish table");
        let (broker, outcome) = dispatch(broker, "/world/google", manifest);
        match verdict {
            Verdict::Completed => {
                let reply =
                    outcome.unwrap_or_else(|err| panic!("{reason} completes the stream: {err:?}"));
                assert_eq!(reply.text, "done", "{reason} keeps the answer");
            }
            Verdict::Failed => {
                assert!(
                    matches!(
                        outcome,
                        Err(ModelError::Provider(ProviderError::ProviderFailed { .. }))
                    ),
                    "{reason} is the peer's failure verdict: {outcome:?}"
                );
            }
            Verdict::Unknown => {
                assert!(
                    matches!(
                        outcome,
                        Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
                    ),
                    "{reason} is unclassifiable, never success: {outcome:?}"
                );
            }
        }
        drop_blocking(broker);
    }
}

/// proto3 JSON elides a zero-valued `candidatesTokenCount`: a usage
/// report without it charges a real zero — the elided field, not an
/// estimate — while a present-but-unreadable counter stays a
/// violation.
#[tokio::test]
async fn an_elided_candidates_token_count_is_a_reported_zero() {
    let server = MockServer::start().await;
    mount_generate(
        &server,
        completed_stream(
            "no candidates tokens",
            Vec::new(),
            Some(json!({"promptTokenCount": 11, "totalTokenCount": 11})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: elided zero");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest.clone());
    outcome.expect("the elided zero still completes");
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 11,
            completion_tokens: 0,
            total_tokens: 11,
        },
        "an absent candidatesTokenCount is the reported zero"
    );
    drop_blocking(broker);

    // only the absent zero elides — a counter the peer did send but
    // that does not read is still malformed
    let server = MockServer::start().await;
    mount_generate(
        &server,
        completed_stream(
            "unreadable counter",
            Vec::new(),
            Some(
                json!({"promptTokenCount": 11, "candidatesTokenCount": "many", "totalTokenCount": 11}),
            ),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: bad counter");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "a present-but-unreadable counter is a violation: {outcome:?}"
    );
    drop_blocking(broker);
}

/// proto3 elides an empty `repeated parts`: a role-only `content`
/// member is the recorded terminal-chunk shape and folds zero parts —
/// upstream's `candidate?.content?.parts` guard reads it the same —
/// while a `content` that is not an object stays malformed.
#[tokio::test]
async fn parts_less_content_folds_empty_and_non_object_content_violates() {
    let server = MockServer::start().await;
    mount_generate(
        &server,
        format!(
            "{}{}",
            data_block(&json!({
                "candidates": [{"content": {"role": "model"}, "index": 0}],
            })),
            data_block(&json!({
                "candidates": [{"finishReason": "STOP", "index": 0}],
            })),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: role only");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    let reply = outcome.expect("a parts-less content folds zero parts");
    assert_eq!(reply.text, "", "nothing streamed, nothing answered");
    drop_blocking(broker);
}

/// A reported `totalTokenCount` is charged verbatim — 11+7 reported as
/// 25 stays 25, never re-summed — while a usage object that withholds
/// the total is a wire violation, not an estimate.
#[tokio::test]
async fn reported_total_is_charged_verbatim_and_a_missing_total_is_a_violation() {
    let server = MockServer::start().await;
    mount_generate(
        &server,
        completed_stream(
            "verbatim",
            Vec::new(),
            Some(json!({"promptTokenCount": 11, "candidatesTokenCount": 7, "totalTokenCount": 25})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: verbatim total");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest.clone());
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
    mount_generate(
        &server,
        completed_stream(
            "no total",
            Vec::new(),
            Some(json!({"promptTokenCount": 11, "candidatesTokenCount": 7})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: missing total");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "a withheld total is a violation, not an estimate: {outcome:?}"
    );
    drop_blocking(broker);
}

/// The provider's own failure verdict — the stream's `error` member —
/// is a typed peer error, not a parse failure and not success. Its
/// reason is the peer's own prose: a `message` field carrying a nested
/// object is structure, never serialized into the reason, while a
/// scalar `code` still renders.
#[tokio::test]
async fn provider_reported_failure_is_a_typed_denial() {
    let server = MockServer::start().await;
    mount_generate(
        &server,
        data_block(&json!({"error": {"code": 429, "message": "quota exceeded", "status": "RESOURCE_EXHAUSTED"}})),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: failure");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::ProviderFailed { .. }))
        ),
        "the peer's failure verdict is typed: {outcome:?}"
    );
    drop_blocking(broker);

    // a `message` field carrying a nested object is skipped — the
    // reason falls to the next populated scalar, never serialized
    // structure
    let server = MockServer::start().await;
    mount_generate(
        &server,
        data_block(
            &json!({"error": {"message": {"nested": "detail"}, "status": "INVALID_ARGUMENT"}}),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: structured reason");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    let Err(ModelError::Provider(ProviderError::ProviderFailed { reason, .. })) = outcome else {
        panic!("the structured error payload is a peer failure: {outcome:?}")
    };
    assert_eq!(reason, "INVALID_ARGUMENT");
    drop_blocking(broker);

    // a scalar code still renders as the reason
    let server = MockServer::start().await;
    mount_generate(&server, data_block(&json!({"error": {"code": 503}}))).await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: scalar reason");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    let Err(ModelError::Provider(ProviderError::ProviderFailed { reason, .. })) = outcome else {
        panic!("the coded error payload is a peer failure: {outcome:?}")
    };
    assert_eq!(reason, "503");
    drop_blocking(broker);
}

/// Thought text is model-internal: a part marked `thought` never joins
/// the visible answer, while a completed `functionCall` reaches the
/// reply as a typed `ToolCall`.
#[tokio::test]
async fn thought_text_is_model_internal_and_a_function_call_is_typed() {
    let server = MockServer::start().await;
    mount_generate(
        &server,
        completed_stream(
            "visible answer",
            vec![
                json!({"thought": true, "text": "internal chain of thought"}),
                json!({"functionCall": {"name": "read_file", "args": {"path": "src/lib.rs"}}}),
            ],
            None,
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: thought and call");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    let reply = outcome.expect("the thought-and-call reply dispatches");
    assert_eq!(
        reply.text, "visible answer",
        "thought text never enters the visible answer"
    );
    assert_eq!(reply.tool_calls.len(), 1);
    assert_eq!(reply.tool_calls[0].tool, "read_file");
    assert_eq!(reply.tool_calls[0].path.as_deref(), Some("src/lib.rs"));
    drop_blocking(broker);

    // `args` is optional on the wire — a functionCall without it lands
    // as a typed call carrying no path
    let server = MockServer::start().await;
    mount_generate(
        &server,
        completed_stream(
            "",
            vec![json!({"functionCall": {"name": "read_file"}})],
            None,
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: argless call");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    let reply = outcome.expect("an args-less functionCall is a typed call");
    assert_eq!(reply.tool_calls.len(), 1);
    assert_eq!(reply.tool_calls[0].tool, "read_file");
    assert_eq!(reply.tool_calls[0].path, None);
    drop_blocking(broker);
}

/// DEC-012: a `thoughtSignature` produced under one manifest-bound
/// lineage is foreign to another — never silently dropped, never
/// blindly replayed, always the named provenance error.
#[tokio::test]
async fn foreign_thought_signature_rejected() {
    let server = MockServer::start().await;
    mount_generate(
        &server,
        completed_stream(
            "ok",
            vec![json!({"text": "reasoned", "thoughtSignature": "sig-fixture-aaa"})],
            None,
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (provider, _store) = google_provider(&config);
    let mut broker = Broker::new(Box::new(provider));

    // world A's completed turn adopts the artifact into its lineage
    let manifest_a = broker
        .prepare("main", &config, "/world/A", "goal: first")
        .expect("prepare A");
    let (broker, outcome_a) = dispatch(broker, "/world/A", manifest_a);
    outcome_a.expect("world A adopts the artifact");
    let mut broker = broker;

    // the same signature arriving under world B is foreign — the
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
        "a foreign signature is the named provenance error: {outcome_b:?}"
    );
    drop_blocking(broker);
}

/// DEC-012: the next turn replays the assembled model turn verbatim —
/// signature-bearing parts preserved as-is — ahead of the new user
/// content. The stateless replay is observable on the wire.
#[tokio::test]
async fn stateless_replay_carries_prior_model_parts_verbatim() {
    let server = MockServer::start().await;
    let turn_parts = vec![
        json!({"thought": true, "text": "internal chain"}),
        json!({"text": "first answer", "thoughtSignature": "sig-fixture-aaa"}),
    ];
    Mock::given(method("POST"))
        .and(path(generate_path(MODEL).as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(gemini_stream(
                    turn_parts.clone(),
                    "STOP",
                    Some(
                        json!({"promptTokenCount": 3, "candidatesTokenCount": 2, "totalTokenCount": 5}),
                    ),
                )),
        )
        .expect(2)
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (provider, _store) = google_provider(&config);
    let mut broker = Broker::new(Box::new(provider));

    let first = broker
        .prepare("main", &config, "/world/google", "goal: first turn")
        .expect("prepare turn 1");
    let (broker, reply) = dispatch(broker, "/world/google", first);
    reply.expect("turn 1 completes");
    let mut broker = broker;

    let second = broker
        .prepare("main", &config, "/world/google", "goal: second turn")
        .expect("prepare turn 2 — same epoch");
    let (broker, reply) = dispatch(broker, "/world/google", second.clone());
    reply.expect("turn 2 completes");

    let bodies = received_bodies(&server).await;
    assert_eq!(bodies.len(), 2, "two physical sends");
    // turn 2's contents are the prior model turn, verbatim — the
    // signature-bearing part preserved as-is, never merged or moved —
    // ahead of the new user content.
    assert_eq!(
        bodies[1]["contents"],
        json!([
            { "role": "model", "parts": turn_parts },
            {
                "role": "user",
                "parts": [{ "text": second.inputs }],
            }
        ]),
        "the stateless replay carries the assembled model turn verbatim"
    );
    // each physical send charged its own usage — two records, no
    // double-charge of one send.
    assert_eq!(broker.accounted_requests(), 2);
    drop_blocking(broker);
}

/// A rejected reply commits nothing: after an incompatible-output
/// denial, a wire violation and a peer failure verdict, the retry
/// under the same epoch replays none of the refused parts — the
/// lineage only ever holds validated output.
#[tokio::test]
async fn rejected_output_never_joins_the_replay_lineage() {
    type DenialLeg = (&'static str, String, fn(&ProviderError) -> bool);
    let legs: Vec<DenialLeg> = vec![
        (
            "an unhonourable part kind",
            completed_stream(
                "",
                vec![json!({"executableCode": {"language": "PYTHON", "code": "x"}})],
                None,
            ),
            |err| matches!(err, ProviderError::IncompatibleOutput { .. }),
        ),
        (
            "a malformed part",
            data_block(
                &json!({"candidates": [{"content": {"role": "model", "parts": [{"text": 5}]}}]}),
            ),
            |err| matches!(err, ProviderError::StreamViolation { .. }),
        ),
        (
            "a peer failure verdict",
            gemini_stream(vec![json!({"text": "x"})], "SAFETY", None),
            |err| matches!(err, ProviderError::ProviderFailed { .. }),
        ),
    ];
    for (name, refused_body, denies) in legs {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(generate_path(MODEL).as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(refused_body),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        mount_generate(&server, completed_stream("clean answer", Vec::new(), None)).await;
        let config =
            Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
        let (provider, _store) = google_provider(&config);
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
            bodies[1]["contents"],
            json!([{
                "role": "user",
                "parts": [{ "text": "goal: auth leg" }],
            }]),
            "{name}: the refused parts never entered the replay set"
        );
        drop_blocking(provider);
    }
}

/// DEC-012: a signature minted under a retired epoch is a foreign
/// replay under the new one — ownership claims outlive the replay set
/// they retired with, and the retired set never rides the wire again.
#[tokio::test]
async fn retired_epoch_signature_is_rejected_not_readopted() {
    let server = MockServer::start().await;
    // both epochs' model paths answer the same signature-bearing
    // stream — the retired epoch's artifact is what turn 2 echoes
    for model in [MODEL, "gemini-3.1-pro"] {
        Mock::given(method("POST"))
            .and(path(generate_path(model).as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(completed_stream(
                        "ok",
                        vec![json!({"text": "reasoned", "thoughtSignature": "sig-fixture-aaa"})],
                        None,
                    )),
            )
            .expect(1)
            .mount(&server)
            .await;
    }
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (provider, _store) = google_provider(&config);
    let mut broker = Broker::new(Box::new(provider));

    let first = broker
        .prepare("main", &config, "/world/google", "goal: first epoch")
        .expect("prepare turn 1");
    let (broker, outcome) = dispatch(broker, "/world/google", first);
    outcome.expect("turn 1 mints the artifact");
    let mut broker = broker;

    // a model switch opens a new epoch: the retired lineage's
    // signature is no longer a replay of ours — it is foreign
    let switched = Config::parse_validated(
        &gemini_config(&server_uri_v1beta(&server)).replace(MODEL, "gemini-3.1-pro"),
    )
    .expect("valid");
    let second = broker
        .prepare("main", &switched, "/world/google", "goal: second epoch")
        .expect("prepare turn 2");
    assert_eq!(
        second.mutation_reason.as_deref(),
        Some("model switch"),
        "the model switch minted a new epoch"
    );
    let (broker, outcome) = dispatch(broker, "/world/google", second.clone());
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(
                ProviderError::ReasoningProvenance { .. }
            ))
        ),
        "a retired-epoch signature is a provenance failure: {outcome:?}"
    );

    // the retired replay set never rode the wire: turn 2's contents
    // are only the new user turn
    let bodies = received_bodies(&server).await;
    assert_eq!(bodies.len(), 2);
    assert_eq!(
        bodies[1]["contents"],
        json!([{
            "role": "user",
            "parts": [{ "text": second.inputs }],
        }]),
        "the retired lineage replayed nothing"
    );
    drop_blocking(broker);
}

/// DEC-012: replay sets are per-epoch — an interleaved send under a
/// non-current epoch replays and mutates only its own set, so a stale
/// commit can never wipe the live epoch's replay context. The last
/// send under the live epoch proves its set survived.
#[tokio::test]
async fn interleaved_epoch_sends_preserve_the_live_epochs_replay_set() {
    let server = MockServer::start().await;
    let epoch_one_parts = vec![json!({"text": "epoch-one answer"})];
    let epoch_two_parts = vec![json!({"text": "epoch-two answer"})];
    // each epoch's sends ride its own pinned model path: the first
    // send on the preview model mints epoch one's set; every later
    // send — on either model path — answers epoch two's parts, and
    // the mounted order makes the first answer distinct
    Mock::given(method("POST"))
        .and(path(generate_path(MODEL).as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(gemini_stream(epoch_one_parts.clone(), "STOP", None)),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    for model in [MODEL, "gemini-3.1-pro"] {
        Mock::given(method("POST"))
            .and(path(generate_path(model).as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(gemini_stream(epoch_two_parts.clone(), "STOP", None)),
            )
            .mount(&server)
            .await;
    }
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (provider, _store) = google_provider(&config);
    let mut broker = Broker::new(Box::new(provider));

    // epoch one's set commits one model turn
    let first = broker
        .prepare("main", &config, "/world/google", "goal: epoch one turn")
        .expect("prepare epoch one");
    let (mut broker, outcome) = dispatch(broker, "/world/google", first);
    outcome.expect("epoch one's turn commits");

    // the stale manifest is frozen under epoch one — prepared, then
    // held while the context switches
    let stale = broker
        .prepare(
            "main",
            &config,
            "/world/google",
            "goal: held epoch one send",
        )
        .expect("prepare the held send");

    // a model switch opens epoch two and its turn commits its own set
    let switched = Config::parse_validated(
        &gemini_config(&server_uri_v1beta(&server)).replace(MODEL, "gemini-3.1-pro"),
    )
    .expect("valid");
    let second = broker
        .prepare("main", &switched, "/world/google", "goal: epoch two turn")
        .expect("prepare epoch two");
    assert_eq!(second.mutation_reason.as_deref(), Some("model switch"));
    let (broker, outcome) = dispatch(broker, "/world/google", second);
    outcome.expect("epoch two's turn commits");

    // the held send still dispatches under epoch one: its contents are
    // epoch one's own replay set, and its commit touches only that set
    let (mut broker, outcome) = dispatch(broker, "/world/google", stale.clone());
    outcome.expect("the stale-epoch send still verifies");

    // a send under the live epoch replays epoch two's set — a stale
    // commit that clobbered it would leave these contents empty
    let third = broker
        .prepare("main", &switched, "/world/google", "goal: live epoch turn")
        .expect("prepare the live epoch turn");
    assert_eq!(
        third.mutation_reason, None,
        "an unchanged prefix replays the live epoch"
    );
    let (broker, outcome) = dispatch(broker, "/world/google", third.clone());
    outcome.expect("the live epoch's turn completes");

    let bodies = received_bodies(&server).await;
    assert_eq!(bodies.len(), 4, "four physical sends");
    // the stale send replayed epoch one's set — its own epoch's
    // context, never epoch two's
    assert_eq!(
        bodies[2]["contents"],
        json!([
            { "role": "model", "parts": epoch_one_parts },
            {
                "role": "user",
                "parts": [{ "text": stale.inputs }],
            }
        ]),
        "the interleaved send carried its own epoch's replay set"
    );
    // the live epoch's set survived the stale commit verbatim
    assert_eq!(
        bodies[3]["contents"],
        json!([
            { "role": "model", "parts": epoch_two_parts },
            {
                "role": "user",
                "parts": [{ "text": third.inputs }],
            }
        ]),
        "the live epoch's replay set survived the interleaved commit"
    );
    drop_blocking(broker);
}

/// A reply that reports no usage keeps the sent cost unknown: the
/// accounting record carries `Unknown`, the explain retains the bound
/// — never a released zero.
#[tokio::test]
async fn unknown_usage_never_releases_the_admission_bound() {
    let server = MockServer::start().await;
    mount_generate(&server, completed_stream("no usage", Vec::new(), None)).await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: unknown usage");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest.clone());
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
        .and(path(generate_path(MODEL).as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(completed_stream(&big, Vec::new(), None)),
        )
        .expect(5)
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (mut provider, _store) = google_provider(&config);
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

/// The legs matrix enforces the recorded expected set for `google`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside this
/// run, and INSTALLED reports NOT_RUN — an omitted leg fails the suite
/// rather than silently absenting.
#[tokio::test]
async fn provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "models": [
                {
                    "name": "models/gemini-3.1-pro",
                    "supportedGenerationMethods": ["generateContent"],
                },
            ],
        })))
        .mount(&server)
        .await;
    mount_generate(
        &server,
        completed_stream(
            "matrix",
            Vec::new(),
            Some(json!({"promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 2})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");

    // CATALOG: the merged model list answers through the credential
    // seam — the seeded store admits the lookup.
    let (provider, _) = google_provider(&config);
    let catalog = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("catalog thread joins");
    reported.insert(
        "CATALOG",
        if matches!(catalog, Ok(ref ids) if ids == &[
            "gemini-3.1-pro".to_string(),
            "gemini-3.1-pro-preview".to_string(),
            "gemini-3.7-flash".to_string(),
        ]) {
            "PASS"
        } else {
            "FAIL"
        },
    );

    // AUTH: an empty store denies at send with the typed verdict.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), "google".to_string(), empty).expect("binding resolves");
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
    let (broker, manifest) = prepared(&config, "/world/google", "goal: matrix wire");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
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
        provider_result(config.clone(), "google".to_string(), empty.clone()).expect("resolves");
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

    // The literal row mirrors the `#[ignore]`d `provider_installed_google`
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

// ----- TP-PROVIDER-INSTALLED::google --------------------------------

/// TP-PROVIDER-INSTALLED::google = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::google = NOT_RUN"]
fn provider_installed_google() {}
