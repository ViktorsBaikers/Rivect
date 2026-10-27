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
use rivect::providers::{Provider, ProviderError, StoreKind, TransportCause, TransportClass};
use rivect::resources::UsageDelta;
use serde_json::{Value, json};
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

mod support;

use support::{SlowStore, drop_blocking, received_bodies, send_on_thread};

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
            Err(ModelError::Provider(ProviderError::DialectUnserved { .. }))
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
    use std::io::Read;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Clone)]
    struct PeerFacts {
        accepts: usize,
        responses: usize,
        valid_requests_before_response: usize,
        drips: usize,
        peek_present: usize,
        peek_unknown: usize,
        header_poll_unknown: usize,
        stage: &'static str,
        io_kind: Option<std::io::ErrorKind>,
        raw_os_error: Option<i32>,
    }
    fn run_catalog_peer(
        listener: std::net::TcpListener,
        stop: &AtomicBool,
        facts: &Mutex<PeerFacts>,
        sockets: &Mutex<Vec<std::net::TcpStream>>,
        fixture_started: Instant,
        multiple_connections: bool,
    ) -> std::io::Result<()> {
        while !stop.load(Ordering::SeqCst) && fixture_started.elapsed() < Duration::from_secs(12) {
            let (mut stream, _) = match listener.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::yield_now();
                    continue;
                }
                Err(error) => return Err(error),
            };
            {
                let mut trace = facts
                    .lock()
                    .map_err(|_poison| std::io::Error::other("fixture trace poisoned"))?;
                trace.accepts += 1;
                trace.stage = "accepted";
            }
            if stop.load(Ordering::SeqCst) {
                break;
            }
            stream.set_nonblocking(true)?;
            {
                let mut registry = sockets
                    .lock()
                    .map_err(|_poison| std::io::Error::other("fixture socket registry poisoned"))?;
                if registry.len() == 16 {
                    return Err(std::io::Error::other("fixture connection bound exceeded"));
                }
                registry.push(stream.try_clone()?);
            }
            let mut probe = [0; 1];
            // One nonblocking peek observes readiness; it never waits for request bytes.
            let present = matches!(stream.peek(&mut probe), Ok(count) if count > 0);
            {
                let mut trace = facts
                    .lock()
                    .map_err(|_poison| std::io::Error::other("fixture trace poisoned"))?;
                trace.peek_present += usize::from(present);
                trace.peek_unknown += usize::from(!present);
                trace.stage = "accepted";
            }

            let mut headers = Vec::new();
            let expected_request = b"GET /v1beta/models HTTP/1.1\r\n";
            loop {
                if stop.load(Ordering::SeqCst) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "fixture stopped before complete request",
                    ));
                }
                if fixture_started.elapsed() >= Duration::from_secs(12) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "fixture request watchdog expired",
                    ));
                }
                let mut chunk = [0; 1024];
                let count = match stream.read(&mut chunk) {
                    Ok(0) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "fixture request headers incomplete",
                        ));
                    }
                    Ok(count) => count,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) =>
                    {
                        facts
                            .lock()
                            .map_err(|_poison| std::io::Error::other("fixture trace poisoned"))?
                            .header_poll_unknown += 1;
                        std::thread::yield_now();
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                if headers.len() + count > 16 * 1024 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "fixture request header bound exceeded",
                    ));
                }
                headers.extend_from_slice(&chunk[..count]);
                if headers.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    if !headers.starts_with(expected_request) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "fixture expected the catalog get target",
                        ));
                    }
                    let mut trace = facts
                        .lock()
                        .map_err(|_poison| std::io::Error::other("fixture trace poisoned"))?;
                    trace.valid_requests_before_response += 1;
                    trace.stage = "valid_request_before_response";
                    drop(trace);
                    break;
                }
            }
            drop(headers);
            let emitted =
                stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n");
            if let Err(error) = emitted {
                let mut trace = facts
                    .lock()
                    .map_err(|_poison| std::io::Error::other("fixture trace poisoned"))?;
                trace.stage = "response_write_failed";
                trace.io_kind = Some(error.kind());
                trace.raw_os_error = error.raw_os_error();
                drop(trace);
                if multiple_connections {
                    continue;
                }
                return Ok(());
            }
            {
                let mut trace = facts
                    .lock()
                    .map_err(|_poison| std::io::Error::other("fixture trace poisoned"))?;
                trace.responses += 1;
                trace.stage = "response_emitted";
            }
            while !stop.load(Ordering::SeqCst)
                && fixture_started.elapsed() < Duration::from_secs(12)
            {
                if let Err(error) = stream.write_all(b"x") {
                    let mut trace = facts
                        .lock()
                        .map_err(|_poison| std::io::Error::other("fixture trace poisoned"))?;
                    trace.stage = "drip_write_failed";
                    trace.io_kind = Some(error.kind());
                    trace.raw_os_error = error.raw_os_error();
                    drop(trace);
                    break;
                }
                {
                    let mut trace = facts
                        .lock()
                        .map_err(|_poison| std::io::Error::other("fixture trace poisoned"))?;
                    trace.drips += 1;
                    trace.stage = "dripping";
                }
                std::thread::sleep(Duration::from_millis(30));
            }
            match stream.shutdown(std::net::Shutdown::Both) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotConnected => {}
                Err(error) => return Err(error),
            }
            if !multiple_connections {
                return Ok(());
            }
        }
        facts
            .lock()
            .map_err(|_poison| std::io::Error::other("fixture trace poisoned"))?
            .stage = if stop.load(Ordering::SeqCst) {
            "stopped"
        } else {
            "watchdog"
        };
        Ok(())
    }
    let facts = Arc::new(Mutex::new(PeerFacts {
        accepts: 0,
        responses: 0,
        valid_requests_before_response: 0,
        drips: 0,
        peek_present: 0,
        peek_unknown: 0,
        header_poll_unknown: 0,
        stage: "waiting",
        io_kind: None,
        raw_os_error: None,
    }));
    let stop = Arc::new(AtomicBool::new(false));
    let sockets = Arc::new(Mutex::new(Vec::<std::net::TcpStream>::new()));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("address");
    let config = Config::parse_validated(&gemini_config(&format!("http://{address}/v1beta")))
        .expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let fixture_started = Instant::now();
    let peer = {
        let stop = Arc::clone(&stop);
        let facts = Arc::clone(&facts);
        let sockets = Arc::clone(&sockets);
        std::thread::Builder::new()
            .spawn(move || -> std::io::Result<()> {
                let multiple_connections = false;
                let outcome = run_catalog_peer(
                    listener,
                    &stop,
                    &facts,
                    &sockets,
                    fixture_started,
                    multiple_connections,
                );
                if let Err(error) = &outcome {
                    let mut trace = facts.lock().unwrap_or_else(|poison| poison.into_inner());
                    trace.stage = "fixture_io_failed";
                    trace.io_kind = Some(error.kind());
                    trace.raw_os_error = error.raw_os_error();
                }
                outcome
            })
            .unwrap_or_else(|_error| panic!("cannot_verify: fixture peer could not start"))
    };
    let client_spawn = std::thread::Builder::new().spawn(move || {
        let provider =
            GeminiProvider::with_deadline(&config, "google", store, Duration::from_millis(1500))?;
        let began = Instant::now();
        let outcome = provider.catalog();
        Ok::<_, ProviderError>((began.elapsed(), outcome))
    });
    let (mut client, spawn_error) = match client_spawn {
        Ok(worker) => (Some(worker), None),
        Err(error) => (None, Some(error.kind())),
    };
    let client_spawned = client.is_some();
    while client.as_ref().is_some_and(|worker| !worker.is_finished())
        && fixture_started.elapsed() < Duration::from_secs(10)
    {
        std::thread::yield_now();
    }
    let mut returned = if client
        .as_ref()
        .is_some_and(std::thread::JoinHandle::is_finished)
    {
        client.take().map(std::thread::JoinHandle::join)
    } else {
        None
    };
    // The caller's bound includes worker setup, provider drop and the completed join.
    let mut caller_elapsed = returned.as_ref().map(|_| fixture_started.elapsed());
    let observed = match &returned {
        Some(Ok(Ok((elapsed, outcome)))) => Some((elapsed, outcome)),
        _ => None,
    };
    let error = match &returned {
        Some(Ok(Ok((_, Err(error))))) | Some(Ok(Err(error))) => Some(error),
        _ => None,
    };
    let variant = match error {
        Some(ProviderError::UnknownConnection { .. }) => "UnknownConnection",
        Some(ProviderError::LiveGrantRequired { .. }) => "LiveGrantRequired",
        Some(ProviderError::StoreUnavailable { .. }) => "StoreUnavailable",
        Some(ProviderError::StoreAmbiguous { .. }) => "StoreAmbiguous",
        Some(ProviderError::CredentialUnresolved { .. }) => "CredentialUnresolved",
        Some(ProviderError::CredentialProfileMismatch { .. }) => "CredentialProfileMismatch",
        Some(ProviderError::CredentialOutsideNamespace { .. }) => "CredentialOutsideNamespace",
        Some(ProviderError::CredentialOccupied { .. }) => "CredentialOccupied",
        Some(ProviderError::CredentialAbsent { .. }) => "CredentialAbsent",
        Some(ProviderError::CredentialMalformed { .. }) => "CredentialMalformed",
        Some(ProviderError::CredentialBaseMismatch { .. }) => "CredentialBaseMismatch",
        Some(ProviderError::DialectMismatch { .. }) => "DialectMismatch",
        Some(ProviderError::DialectUnserved { .. }) => "DialectUnserved",
        Some(ProviderError::UnpinnedModel { .. }) => "UnpinnedModel",
        Some(ProviderError::RegionMismatch { .. }) => "RegionMismatch",
        Some(ProviderError::Transport { .. }) => "Transport",
        Some(ProviderError::ProviderFailed { .. }) => "ProviderFailed",
        Some(ProviderError::UnknownTerminal { .. }) => "UnknownTerminal",
        Some(ProviderError::StreamViolation { .. }) => "StreamViolation",
        Some(ProviderError::IncompatibleOutput { .. }) => "IncompatibleOutput",
        Some(ProviderError::ReasoningProvenance { .. }) => "ReasoningProvenance",
        None => "none",
    };
    let (class, request, io) = match error {
        Some(ProviderError::Transport { cause, .. }) => {
            let (request, io) = match cause {
                TransportCause::Request { source } => (Some(source.as_ref()), None),
                TransportCause::Read { source } => (
                    source
                        .get_ref()
                        .and_then(|inner| inner.downcast_ref::<reqwest::Error>()),
                    Some(source.as_ref()),
                ),
                TransportCause::Deadline { .. } | TransportCause::Status { .. } => (None, None),
            };
            (Some(cause.class()), request, io)
        }
        _ => (None, None, None),
    };
    let class = match class {
        Some(TransportClass::DeadlineExpired) => json!({"kind": "deadline_expired"}),
        Some(TransportClass::Timeout) => json!({"kind": "timeout"}),
        Some(TransportClass::RequestFailure) => json!({"kind": "request_failure"}),
        Some(TransportClass::ReadFailure) => json!({"kind": "read_failure"}),
        Some(TransportClass::HttpStatus { code }) => json!({"kind": "http_status", "code": code}),
        None => Value::Null,
    };
    let snapshot = facts
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone();
    let record = json!({
        "adapter": "google",
        "variant": variant, "class": class,
        "reqwest": request.map(|error| json!({
            "builder": error.is_builder(), "request": error.is_request(), "body": error.is_body(),
            "decode": error.is_decode(), "redirect": error.is_redirect(), "status": error.is_status(),
            "upgrade": error.is_upgrade(), "timeout": error.is_timeout(), "connect": error.is_connect(),
        })),
        "io": io.map(|error| json!({"kind": format!("{:?}", error.kind()), "raw_os_error": error.raw_os_error()})),
        "elapsed_ms": caller_elapsed.map(|elapsed| elapsed.as_millis()),
        "method_elapsed_ms": observed.map(|(elapsed, _)| elapsed.as_millis()),
        "client_return": usize::from(observed.is_some()),
        "worker_completed": usize::from(returned.is_some()),
        "client_spawn_kind": spawn_error.map(|kind| format!("{kind:?}")),
        "client_stage": match &returned { Some(Ok(Ok(_))) => "returned", Some(Ok(Err(_))) => "setup_failed", Some(Err(_)) => "panicked", None if !client_spawned => "spawn_failed", None => "pending" },
        "request_at_first_peek": if snapshot.peek_present > 0 { "present" } else { "unknown" },
        "peer": {
            "accepts": snapshot.accepts, "response_emits": snapshot.responses,
            "valid_requests_before_response": snapshot.valid_requests_before_response, "drips": snapshot.drips,
            "peek_present": snapshot.peek_present, "peek_unknown": snapshot.peek_unknown,
            "header_poll_unknown": snapshot.header_poll_unknown,
            "stage": snapshot.stage, "completed": peer.is_finished(),
            "io_kind": snapshot.io_kind.map(|kind| format!("{kind:?}")),
            "raw_os_error": snapshot.raw_os_error,
        },
        "teardown": "pending",
    }).to_string();
    let record_bounded = record.len() + "RIVECT_CATALOG_DIAG ".len() < 2048;
    let record_written = if record_bounded {
        let mut sink = std::io::stderr().lock();
        sink.write_all(format!("RIVECT_CATALOG_DIAG {record}\n").as_bytes())
            .and_then(|()| sink.flush())
            .is_ok()
    } else {
        false
    };

    fn shutdown_owned(sockets: &Mutex<Vec<std::net::TcpStream>>) -> bool {
        let mut clean = !sockets.is_poisoned();
        let mut sockets = sockets.lock().unwrap_or_else(|poison| poison.into_inner());
        for stream in sockets.iter() {
            clean &= match stream.shutdown(std::net::Shutdown::Both) {
                Ok(()) => true,
                Err(error) => error.kind() == std::io::ErrorKind::NotConnected,
            };
        }
        sockets.clear();
        clean
    }
    stop.store(true, Ordering::SeqCst);
    let mut sockets_closed = shutdown_owned(&sockets);
    while (!peer.is_finished() || client.as_ref().is_some_and(|worker| !worker.is_finished()))
        && fixture_started.elapsed() < Duration::from_secs(15)
    {
        std::thread::yield_now();
    }
    let peer_return = if peer.is_finished() {
        Some(peer.join())
    } else {
        None
    };
    if client
        .as_ref()
        .is_some_and(std::thread::JoinHandle::is_finished)
    {
        returned = client.take().map(std::thread::JoinHandle::join);
        caller_elapsed = returned.as_ref().map(|_| fixture_started.elapsed());
    }
    sockets_closed &= shutdown_owned(&sockets);
    assert!(
        peer_return.is_some() && client.is_none(),
        "cannot_verify: fixture teardown watchdog expired"
    );
    assert!(
        matches!(peer_return, Some(Ok(Ok(())))),
        "cannot_verify: fixture setup or cleanup failed"
    );
    assert!(
        sockets_closed && !facts.is_poisoned(),
        "cannot_verify: fixture resources were not cleanly released"
    );
    assert!(
        record_written,
        "cannot_verify: bounded diagnostic record could not be retained"
    );
    let Some(Ok(Ok((_method_elapsed, outcome)))) = returned else {
        panic!("cannot_verify: catalog setup or worker failed");
    };
    match outcome {
        Err(ProviderError::Transport { cause, .. }) => {
            assert!(
                cause.class() == TransportClass::DeadlineExpired,
                "the total deadline is the named cause: {cause}"
            );
        }
        other => panic!("a dribbling peer is a typed transport denial: {other:?}"),
    }
    let elapsed = caller_elapsed.expect("the complete caller lifecycle was observed");
    assert!(
        elapsed < Duration::from_secs(10),
        "the listing ended near its deadline, not the 120s per-read bound: {elapsed:?}"
    );
    assert!(
        snapshot.accepts > 0
            && snapshot.valid_requests_before_response > 0
            && snapshot.responses > 0
            && snapshot.drips > 0,
        "a deadline success requires a real request, response and drip observed before stop"
    );
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
            Err(ModelError::Provider(ProviderError::DialectUnserved { .. }))
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

/// Real transport failures retain their concrete sources without changing timeout policy.
#[test]
fn transport_timeout_keeps_the_original_source() {
    use std::io::Read;
    use std::sync::mpsc::{RecvTimeoutError, TrySendError, sync_channel};

    let exercise = |response: &'static [u8], hold: bool| {
        let peer_watchdog = Duration::from_millis(3000);
        let teardown_watchdog = Duration::from_millis(5000);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("address");
        let config = Config::parse_validated(&gemini_config(&format!("http://{address}/v1beta")))
            .expect("valid");
        let manifest = prepared_manifest(&config);
        let store = Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(CREDENTIAL_REF, SECRET)],
        ));
        let (observed_tx, observed_rx) = sync_channel(1);
        let (release_tx, release_rx) = sync_channel(1);
        let peer = std::thread::spawn(move || -> std::io::Result<usize> {
            let started = Instant::now();
            let remaining = || {
                peer_watchdog.checked_sub(started.elapsed()).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "fixture watchdog expired")
                })
            };
            let mut stream = loop {
                remaining()?;
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::yield_now();
                    }
                    Err(error) => return Err(error),
                }
            };
            let mut request = Vec::new();
            let mut request_len = None;
            loop {
                stream.set_read_timeout(Some(remaining()?))?;
                let mut chunk = [0; 4096];
                let count = stream.read(&mut chunk)?;
                if count == 0 || request.len() + count > 1024 * 1024 {
                    return Err(std::io::Error::other(
                        "fixture request incomplete or oversized",
                    ));
                }
                request.extend_from_slice(&chunk[..count]);
                if request_len.is_none()
                    && let Some(header_end) =
                        request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                {
                    let headers = std::str::from_utf8(&request[..header_end])
                        .map_err(std::io::Error::other)?;
                    let body_len = headers
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                        .filter(|length| *length <= 1024 * 1024 - header_end - 4)
                        .ok_or_else(|| std::io::Error::other("fixture content length invalid"))?;
                    request_len = Some(header_end + 4 + body_len);
                }
                if request_len == Some(request.len()) {
                    break;
                }
            }
            observed_tx
                .send(request)
                .map_err(|_request_with_credentials| {
                    std::io::Error::other("fixture observer disconnected")
                })?;
            stream.set_write_timeout(Some(remaining()?))?;
            stream.write_all(response)?;
            let stream = if hold {
                Some(stream)
            } else {
                drop(stream);
                None
            };
            // The response's open socket distinguishes request and read stalls from early EOF.
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

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut provider =
                GeminiProvider::with_deadline(&config, "google", store, Duration::from_millis(500))
                    .expect("the adapter builds");
            provider.send(&manifest)
        }));
        let observed = observed_rx.recv_timeout(peer_watchdog);
        let released = match release_tx.try_send(()) {
            Ok(()) => true,
            Err(TrySendError::Disconnected(())) => false,
            Err(TrySendError::Full(())) => false,
        };
        let teardown_started = Instant::now();
        while !peer.is_finished() && teardown_started.elapsed() < teardown_watchdog {
            std::thread::yield_now();
        }
        assert!(peer.is_finished(), "fixture teardown watchdog expired");
        let requests = peer.join().expect("the fixture thread joins");

        let requests = requests.expect("fixture completed within its watchdog");
        assert!(released, "fixture received the explicit release");
        assert_eq!(requests, 1, "one physical request reached the fixture");
        let observed = observed.expect("the fixture observed the complete request");
        assert!(
            observed.starts_with(
                format!("POST {}?alt=sse HTTP/1.1\r\n", generate_path(MODEL)).as_bytes()
            )
        );
        let outcome = outcome.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        let error = outcome.expect_err("the peer returns a transport denial");
        assert!(
            matches!(&error, ProviderError::Transport { connection, .. } if connection == "google")
        );

        error
    };
    let original = exercise(b"", true);
    let error = original.clone();
    drop(original);
    let mut source = std::error::Error::source(&error);
    let mut timeout_preserved = false;
    while let Some(cause) = source {
        if let Some(cause) = cause.downcast_ref::<reqwest::Error>() {
            timeout_preserved = cause.is_timeout();
            break;
        }
        source = cause.source();
    }
    assert!(
        timeout_preserved,
        "the standard error chain retains the concrete reqwest timeout"
    );

    assert_eq!(
        match &error {
            ProviderError::Transport { cause, .. } => cause.class(),
            _ => panic!("expected transport denial"),
        },
        TransportClass::Timeout,
    );
    let ProviderError::Transport {
        cause: TransportCause::Request { source },
        ..
    } = &error
    else {
        panic!("a stalled header is a request failure");
    };
    assert!(source.is_timeout());
    assert!(source.url().is_none());
    let cause = std::error::Error::source(&error).expect("the transport cause is retained");
    let model = ModelError::Provider(error.clone());
    let controller =
        rivect::controller::ControllerError::Model(ModelError::Provider(error.clone()));
    for rendered in [
        format!("{cause}"),
        format!("{cause:?}"),
        format!("{error}"),
        format!("{error:?}"),
        format!("{model}"),
        format!("{model:?}"),
        format!("{controller}"),
        format!("{controller:?}"),
    ] {
        assert!(
            rendered.contains("request"),
            "a request timeout retains its safe request context"
        );
        assert!(
            !rendered.contains(SECRET),
            "credential material stays out of diagnostics"
        );
    }

    for (response, hold, expected, read) in [
        (
            &b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 100\r\n\r\nx"
                [..],
            true,
            TransportClass::Timeout,
            true,
        ),
        (
            &b"invalid-http\r\n\r\n"[..],
            false,
            TransportClass::RequestFailure,
            false,
        ),
        (
            &b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 100\r\n\r\nx"
                [..],
            false,
            TransportClass::ReadFailure,
            true,
        ),
        (
            &b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 17\r\n\r\nhostile-peer-body"[..],
            false,
            TransportClass::HttpStatus { code: 401 },
            false,
        ),
        (
            &b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 17\r\n\r\nhostile-peer-body"[..],
            false,
            TransportClass::HttpStatus { code: 429 },
            false,
        ),
        (
            &b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 17\r\n\r\nhostile-peer-body"[..],
            false,
            TransportClass::HttpStatus { code: 503 },
            false,
        ),
    ] {
        let original = exercise(response, hold);
        let error = original.clone();
        drop(original);
        let ProviderError::Transport { cause, .. } = &error else {
            panic!("expected transport denial");
        };
        assert_eq!(cause.class(), expected);
        use std::error::Error;
        match cause {
            TransportCause::Read { source } => {
                assert!(read);
                let leaf = cause
                    .source()
                    .and_then(|source| source.downcast_ref::<std::io::Error>())
                    .expect("the immediate read source is concrete io::Error");
                assert_eq!(leaf.kind(), source.kind());
                assert_eq!(leaf.raw_os_error(), source.raw_os_error());
                let inner = leaf
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<reqwest::Error>())
                    .expect("the real Response::read retained its reqwest error");
                assert_eq!(inner.is_timeout(), expected == TransportClass::Timeout);
            }
            TransportCause::Request { source } => {
                assert!(!read);
                let leaf = cause
                    .source()
                    .and_then(|source| source.downcast_ref::<reqwest::Error>())
                    .expect("the immediate request source is concrete reqwest::Error");
                assert!(!leaf.is_timeout());
                assert!(!source.is_timeout());
                assert!(leaf.url().is_none());
            }
            TransportCause::Status { status } => {
                assert_eq!(
                    expected,
                    TransportClass::HttpStatus {
                        code: status.as_u16()
                    }
                );
                assert!(cause.source().is_none());
            }
            TransportCause::Deadline { .. } => {
                panic!("the peer failure is not an adapter deadline")
            }
        }
        let model = ModelError::Provider(error.clone());
        let controller =
            rivect::controller::ControllerError::Model(ModelError::Provider(error.clone()));
        for rendered in [
            format!("{cause}"),
            format!("{cause:?}"),
            format!("{error}"),
            format!("{error:?}"),
            format!("{model}"),
            format!("{model:?}"),
            format!("{controller}"),
            format!("{controller:?}"),
        ] {
            let context = if read {
                if hold { "decode" } else { "body" }
            } else if matches!(expected, TransportClass::HttpStatus { .. }) {
                "status"
            } else {
                "request"
            };
            assert!(
                rendered.contains(context),
                "transport diagnostics lost their safe kind context"
            );
            if let TransportClass::HttpStatus { code } = expected {
                assert!(
                    rendered.contains(&code.to_string()),
                    "status diagnostics lost the exact numeric code"
                );
            }
            assert!(
                !rendered.contains(SECRET),
                "credential material stays out of diagnostics"
            );
            assert!(
                !rendered.contains("hostile-peer-body"),
                "peer bodies stay out of diagnostics"
            );
        }
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let config = Config::parse_validated(&gemini_config(&format!(
        "http://{}/v1beta",
        listener.local_addr().expect("address")
    )))
    .expect("valid");
    // An empty store would return CredentialAbsent if the expired-budget guard called it.
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let mut provider = GeminiProvider::with_deadline(&config, "google", store, Duration::ZERO)
        .expect("the adapter builds");
    let outcome = provider.send(&prepared_manifest(&config));
    drop(provider);
    let accepted = listener.accept();
    drop(listener);
    assert!(matches!(
        outcome,
        Err(ProviderError::Transport {
            cause: TransportCause::Deadline {
                budget: Duration::ZERO
            },
            ..
        })
    ));
    assert!(
        matches!(accepted, Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "an expired budget never sends or resolves the empty credential store"
    );

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let config = Config::parse_validated(&gemini_config(&format!(
        "http://{}/v1beta",
        listener.local_addr().expect("address")
    )))
    .expect("valid");
    let store = Arc::new(SlowStore {
        inner: support::MapStore::seeded(STORE_KIND, &[(CREDENTIAL_REF, SECRET)]),
        delay: Duration::from_millis(600),
    });
    let mut provider =
        GeminiProvider::with_deadline(&config, "google", store, Duration::from_millis(500))
            .expect("the adapter builds");
    let outcome = provider.send(&prepared_manifest(&config));
    drop(provider);
    let accepted = listener.accept();
    drop(listener);
    assert!(
        matches!(accepted, Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "credential latency exhausted the budget before any wire leg"
    );
    let error = outcome.expect_err("the exhausted whole-request budget is a typed denial");
    let ProviderError::Transport {
        cause: TransportCause::Deadline { budget },
        ..
    } = &error
    else {
        panic!("the exhausted credential leg retains the whole-request deadline");
    };
    assert_eq!(*budget, Duration::from_millis(500));
    let cause = std::error::Error::source(&error).expect("the deadline cause is retained");
    assert!(cause.source().is_none());
    let model = ModelError::Provider(error.clone());
    let controller =
        rivect::controller::ControllerError::Model(ModelError::Provider(error.clone()));
    for rendered in [
        format!("{cause}"),
        format!("{cause:?}"),
        format!("{error}"),
        format!("{error:?}"),
        format!("{model}"),
        format!("{model:?}"),
        format!("{controller}"),
        format!("{controller:?}"),
    ] {
        assert!(
            rendered.contains("deadline") && rendered.contains("500ms"),
            "deadline diagnostics retain the complete adapter budget"
        );
        assert!(
            !rendered.contains(SECRET),
            "credential material stays out of diagnostics"
        );
    }
}

/// DEC-014: the whole-request deadline is one budget over connect,
/// request send and every stream read — a peer that dribbles a byte
/// inside each per-read window can never park a dispatch: only the
/// total elapsed trips the bound, not any single read.
#[tokio::test]
async fn dribbling_peer_cannot_park_the_send_past_the_deadline() {
    use std::io::{ErrorKind, Read};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::process::{Command, Stdio};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    use std::sync::mpsc::{SyncSender, sync_channel};

    const ADAPTER: &str = "gemini";
    const GUARD: &str = "RIVECT_H009_SEND_CHILD";
    const CHILD_PREFIX: &str = "RIVECT_SEND_CHILD ";
    const CLEAN: &str = "RIVECT_SEND_TEARDOWN clean";
    const TEST: &str = "dribbling_peer_cannot_park_the_send_past_the_deadline";
    const LIMIT: usize = 4;

    #[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Facts {
        accepts: u32,
        complete_post: u32,
        headers: u32,
        body_bytes: u32,
        response_emits: u32,
        drips: u32,
        first_peek: Option<bool>,
        complete_before_response: Option<bool>,
        first_response_before_body: Option<bool>,
        io_kind: Option<IoKind>,
        raw_os_error: Option<i32>,
        fixture_error: bool,
    }
    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    enum ProviderVariant {
        UnknownConnection,
        LiveGrantRequired,
        StoreUnavailable,
        StoreAmbiguous,
        CredentialUnresolved,
        CredentialProfileMismatch,
        CredentialOutsideNamespace,
        CredentialOccupied,
        CredentialAbsent,
        CredentialMalformed,
        CredentialBaseMismatch,
        DialectMismatch,
        DialectUnserved,
        UnpinnedModel,
        RegionMismatch,
        Transport,
        ProviderFailed,
        UnknownTerminal,
        StreamViolation,
        IncompatibleOutput,
        ReasoningProvenance,
    }
    fn provider_variant(error: &ProviderError) -> ProviderVariant {
        match error {
            ProviderError::UnknownConnection { .. } => ProviderVariant::UnknownConnection,
            ProviderError::LiveGrantRequired { .. } => ProviderVariant::LiveGrantRequired,
            ProviderError::StoreUnavailable { .. } => ProviderVariant::StoreUnavailable,
            ProviderError::StoreAmbiguous { .. } => ProviderVariant::StoreAmbiguous,
            ProviderError::CredentialUnresolved { .. } => ProviderVariant::CredentialUnresolved,
            ProviderError::CredentialProfileMismatch { .. } => {
                ProviderVariant::CredentialProfileMismatch
            }
            ProviderError::CredentialOutsideNamespace { .. } => {
                ProviderVariant::CredentialOutsideNamespace
            }
            ProviderError::CredentialOccupied { .. } => ProviderVariant::CredentialOccupied,
            ProviderError::CredentialAbsent { .. } => ProviderVariant::CredentialAbsent,
            ProviderError::CredentialMalformed { .. } => ProviderVariant::CredentialMalformed,
            ProviderError::CredentialBaseMismatch { .. } => ProviderVariant::CredentialBaseMismatch,
            ProviderError::DialectMismatch { .. } => ProviderVariant::DialectMismatch,
            ProviderError::DialectUnserved { .. } => ProviderVariant::DialectUnserved,
            ProviderError::UnpinnedModel { .. } => ProviderVariant::UnpinnedModel,
            ProviderError::RegionMismatch { .. } => ProviderVariant::RegionMismatch,
            ProviderError::Transport { .. } => ProviderVariant::Transport,
            ProviderError::ProviderFailed { .. } => ProviderVariant::ProviderFailed,
            ProviderError::UnknownTerminal { .. } => ProviderVariant::UnknownTerminal,
            ProviderError::StreamViolation { .. } => ProviderVariant::StreamViolation,
            ProviderError::IncompatibleOutput { .. } => ProviderVariant::IncompatibleOutput,
            ProviderError::ReasoningProvenance { .. } => ProviderVariant::ReasoningProvenance,
        }
    }
    #[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
    enum IoKind {
        WouldBlock,
        Interrupted,
        TimedOut,
        UnexpectedEof,
        InvalidData,
        ConnectionReset,
        ConnectionAborted,
        BrokenPipe,
        NotConnected,
        Other,
    }
    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "lowercase")]
    enum Predicate {
        Builder,
        Request,
        Body,
        Decode,
        Redirect,
        Status,
        Upgrade,
        Timeout,
        Connect,
    }
    type RequestFlags = std::collections::BTreeMap<Predicate, bool>;
    #[derive(Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
    enum Variant {
        #[default]
        Pending,
        Setup,
        Transport,
        Other,
    }
    #[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    enum Class {
        DeadlineExpired,
        Timeout,
        RequestFailure,
        ReadFailure,
        HttpStatus,
    }
    #[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Primary {
        variant: Variant,
        provider_variant: Option<ProviderVariant>,
        class: Option<Class>,
        status: Option<u16>,
        reqwest: Option<RequestFlags>,
        read_kind: Option<IoKind>,
        raw_os_error: Option<i32>,
        method_ms: Option<u64>,
    }
    #[derive(serde::Serialize, serde::Deserialize)]
    enum ClientStage {
        Pending,
        Construction,
        Send,
        Drop,
        Joined,
    }
    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Snapshot {
        facts: Facts,
        primary: Primary,
        client_stage: ClientStage,
        caller_ms: Option<u64>,
    }
    fn kind(error: &std::io::Error) -> IoKind {
        match error.kind() {
            ErrorKind::WouldBlock => IoKind::WouldBlock,
            ErrorKind::Interrupted => IoKind::Interrupted,
            ErrorKind::TimedOut => IoKind::TimedOut,
            ErrorKind::UnexpectedEof => IoKind::UnexpectedEof,
            ErrorKind::InvalidData => IoKind::InvalidData,
            ErrorKind::ConnectionReset => IoKind::ConnectionReset,
            ErrorKind::ConnectionAborted => IoKind::ConnectionAborted,
            ErrorKind::BrokenPipe => IoKind::BrokenPipe,
            ErrorKind::NotConnected => IoKind::NotConnected,
            _ => IoKind::Other,
        }
    }
    fn flags(error: &reqwest::Error) -> RequestFlags {
        std::collections::BTreeMap::from([
            (Predicate::Builder, error.is_builder()),
            (Predicate::Request, error.is_request()),
            (Predicate::Body, error.is_body()),
            (Predicate::Decode, error.is_decode()),
            (Predicate::Redirect, error.is_redirect()),
            (Predicate::Status, error.is_status()),
            (Predicate::Upgrade, error.is_upgrade()),
            (Predicate::Timeout, error.is_timeout()),
            (Predicate::Connect, error.is_connect()),
        ])
    }
    fn primary(outcome: Result<rivect::providers::ProviderReply, ProviderError>) -> Primary {
        let mut observed = Primary {
            variant: Variant::Other,
            ..Primary::default()
        };
        observed.provider_variant = outcome.as_ref().err().map(provider_variant);
        if let Err(ProviderError::Transport { cause, .. }) = outcome {
            observed.variant = Variant::Transport;
            observed.class = Some(match cause.class() {
                TransportClass::DeadlineExpired => Class::DeadlineExpired,
                TransportClass::Timeout => Class::Timeout,
                TransportClass::RequestFailure => Class::RequestFailure,
                TransportClass::ReadFailure => Class::ReadFailure,
                TransportClass::HttpStatus { code } => {
                    observed.status = Some(code);
                    Class::HttpStatus
                }
            });
            match cause {
                TransportCause::Request { source } => observed.reqwest = Some(flags(&source)),
                TransportCause::Read { source } => {
                    observed.read_kind = Some(kind(&source));
                    observed.raw_os_error = source.raw_os_error();
                    observed.reqwest = source
                        .get_ref()
                        .and_then(|inner| inner.downcast_ref::<reqwest::Error>())
                        .map(flags);
                }
                TransportCause::Deadline { .. } | TransportCause::Status { .. } => {}
            }
        }
        observed
    }
    fn capture_pipe(
        mut pipe: impl Read,
        sender: SyncSender<(Vec<u8>, bool, bool)>,
        overflow: Arc<AtomicBool>,
    ) -> bool {
        let mut bytes = Vec::with_capacity(8193);
        let mut eof = false;
        let mut failed = false;
        while bytes.len() < 8193 {
            let mut chunk = [0; 1024];
            let remaining = (8193 - bytes.len()).min(chunk.len());
            match pipe.read(&mut chunk[..remaining]) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(count) => bytes.extend_from_slice(&chunk[..count]),
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        if bytes.len() > 8192 {
            overflow.store(true, Ordering::Release);
        }
        // One terminal result per reader; capacity one never waits on another producer.
        sender.send((bytes, eof, failed)).is_ok()
    }

    match std::env::var_os(GUARD) {
        None => {
            let executable = std::env::current_exe()
                .and_then(std::fs::canonicalize)
                .expect("the test executable is canonical");
            let mut command = Command::new(executable);
            command
                .args([
                    TEST,
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                    "--color",
                    "never",
                ])
                .env_clear()
                .env(GUARD, ADAPTER)
                .env("NO_PROXY", "127.0.0.1,localhost")
                .env("no_proxy", "127.0.0.1,localhost")
                .env("RUST_BACKTRACE", "0")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let began = Instant::now();
            let spawned = command.spawn();
            let mut terminal = "normal";
            let mut status = None;
            let mut kill_attempted = false;
            let mut kill_ok = None;
            let mut exit_race_reconciled = false;
            let mut stdout = None;
            let mut stderr = None;
            let mut stdout_joined = false;
            let mut stderr_joined = false;
            let overflow = Arc::new(AtomicBool::new(false));
            let (out_tx, out_rx) = sync_channel(1);
            let (err_tx, err_rx) = sync_channel(1);
            if let Ok(mut child) = spawned {
                let out_reader = child.stdout.take().map(|pipe| {
                    let overflow = overflow.clone();
                    std::thread::Builder::new().spawn(move || capture_pipe(pipe, out_tx, overflow))
                });
                let err_reader = child.stderr.take().map(|pipe| {
                    let overflow = overflow.clone();
                    std::thread::Builder::new().spawn(move || capture_pipe(pipe, err_tx, overflow))
                });
                let mut out_reader = match out_reader {
                    Some(Ok(reader)) => Some(reader),
                    Some(Err(_)) | None => {
                        terminal = "reader_spawn";
                        None
                    }
                };
                let mut err_reader = match err_reader {
                    Some(Ok(reader)) => Some(reader),
                    Some(Err(_)) | None => {
                        terminal = "reader_spawn";
                        None
                    }
                };
                if out_reader.is_none() || err_reader.is_none() {
                    terminal = "reader_spawn";
                }
                loop {
                    if status.is_none() {
                        match child.try_wait() {
                            Ok(observed) => status = observed,
                            Err(_) => terminal = "poll",
                        }
                    }
                    if overflow.load(Ordering::Acquire) {
                        terminal = "overflow";
                    }
                    if began.elapsed() >= Duration::from_secs(25)
                        && status.is_none()
                        && terminal == "normal"
                    {
                        terminal = "watchdog";
                    }
                    if terminal != "normal" && status.is_none() && !kill_attempted {
                        kill_attempted = true;
                        match child.kill() {
                            Ok(()) => kill_ok = Some(true),
                            Err(_) => match child.try_wait() {
                                Ok(Some(observed)) => {
                                    status = Some(observed);
                                    kill_ok = Some(false);
                                    exit_race_reconciled = true;
                                }
                                Ok(None) => {
                                    kill_ok = Some(false);
                                    terminal = "kill_pending";
                                }
                                Err(_) => {
                                    kill_ok = Some(false);
                                    terminal = "kill_poll";
                                }
                            },
                        }
                    }
                    if out_reader
                        .as_ref()
                        .is_some_and(std::thread::JoinHandle::is_finished)
                    {
                        stdout_joined = out_reader
                            .take()
                            .expect("owned output reader")
                            .join()
                            .is_ok_and(|sent| sent);
                        stdout = out_rx.try_recv().ok();
                        if stdout.as_ref().is_none_or(|(_, _, failed)| *failed) {
                            terminal = "stdout_read";
                        }
                    }
                    if err_reader
                        .as_ref()
                        .is_some_and(std::thread::JoinHandle::is_finished)
                    {
                        stderr_joined = err_reader
                            .take()
                            .expect("owned error reader")
                            .join()
                            .is_ok_and(|sent| sent);
                        stderr = err_rx.try_recv().ok();
                        if stderr.as_ref().is_none_or(|(_, _, failed)| *failed) {
                            terminal = "stderr_read";
                        }
                    }
                    if status.is_some() && out_reader.is_none() && err_reader.is_none() {
                        break;
                    }
                    if began.elapsed() >= Duration::from_secs(30) {
                        terminal = "cleanup_pending";
                        break;
                    }
                    std::thread::yield_now();
                }
            } else {
                terminal = "spawn";
            }
            let stdout_eof = stdout
                .as_ref()
                .is_some_and(|(_, eof, failed)| *eof && !failed);
            let stderr_eof = stderr
                .as_ref()
                .is_some_and(|(_, eof, failed)| *eof && !failed);
            let output_text = stdout
                .as_ref()
                .and_then(|(bytes, _, _)| std::str::from_utf8(bytes).ok());
            let error_text = stderr
                .as_ref()
                .and_then(|(bytes, _, _)| std::str::from_utf8(bytes).ok());
            let executed_one = output_text.is_some_and(|text| {
                let results: Vec<_> = text
                    .lines()
                    .filter(|line| line.starts_with("test result: "))
                    .collect();
                results.len() == 1
                    && (results[0].starts_with(
                        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ",
                    ) || results[0].starts_with(
                        "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; ",
                    ))
            });
            let records: Vec<_> = error_text
                .into_iter()
                .flat_map(str::lines)
                .filter_map(|line| line.strip_prefix(CHILD_PREFIX))
                .collect();
            let snapshot = if records.len() == 1 && records[0].len() + CHILD_PREFIX.len() < 2048 {
                serde_json::from_str::<Snapshot>(records[0])
                    .ok()
                    .filter(|record| {
                        let f = &record.facts;
                        f.accepts <= 5
                            && f.complete_post <= 4
                            && f.headers <= 4
                            && f.body_bytes <= 327680
                            && f.response_emits <= 4
                            && f.drips <= 4000
                            && record
                                .primary
                                .status
                                .is_none_or(|s| (100..1000).contains(&s))
                            && record
                                .primary
                                .reqwest
                                .as_ref()
                                .is_none_or(|flags| flags.len() == 9)
                            && record.primary.method_ms.is_none_or(|ms| ms <= 30000)
                            && record.caller_ms.is_none_or(|ms| ms <= 30000)
                    })
            } else {
                None
            };
            let peer_clean = error_text
                .is_some_and(|text| text.lines().filter(|line| *line == CLEAN).count() == 1);
            let cleanup =
                status.is_some() && stdout_joined && stderr_joined && stdout_eof && stderr_eof;
            if snapshot.is_none() && terminal == "normal" {
                terminal = "diagnostic_invalid";
            }
            if !executed_one && terminal == "normal" {
                terminal = "execution_count";
            }
            if !peer_clean && terminal == "normal" {
                terminal = "peer_cleanup";
            }
            let outcome_reason = snapshot.as_ref().map_or("cannot_verify", |snapshot| {
                if snapshot.primary.variant == Variant::Setup {
                    "setup"
                } else if snapshot.primary.variant != Variant::Transport
                    || snapshot.primary.class != Some(Class::DeadlineExpired)
                {
                    "strict_class"
                } else if !snapshot.caller_ms.is_some_and(|elapsed| elapsed < 20000) {
                    "strict_elapsed"
                } else if snapshot.facts.fixture_error
                    || snapshot.facts.complete_post != 1
                    || snapshot.facts.body_bytes == 0
                    || snapshot.facts.response_emits != 1
                    || snapshot.facts.drips == 0
                    || snapshot.facts.complete_before_response != Some(true)
                    || snapshot.facts.first_response_before_body != Some(false)
                {
                    "fixture"
                } else {
                    "strict_pass"
                }
            });
            let record = json!({
                "adapter": ADAPTER, "phase": "fixed", "snapshot": snapshot,
                "child": { "exit": status.and_then(|s| s.code()), "success": status.map(|s| s.success()),
                    "kill_attempted": kill_attempted, "kill_observed": kill_ok,
                    "exit_race_reconciled": exit_race_reconciled, "reaped": status.is_some(),
                    "stdout_join": stdout_joined, "stderr_join": stderr_joined,
                    "stdout_eof": stdout_eof, "stderr_eof": stderr_eof, "executed_one": executed_one },
                "peer": { "stop": if peer_clean { Some(true) } else { None },
                    "shutdown": if peer_clean { Some(true) } else { None },
                    "join": if peer_clean { Some(true) } else { None } },
                "terminal": terminal, "outcome": outcome_reason
            });
            let line = format!("RIVECT_SEND_DIAG {record}\n");
            assert!(line.len() <= 2048, "the safe send diagnostic is bounded");
            let mut sink = std::io::stderr().lock();
            sink.write_all(line.as_bytes())
                .and_then(|()| sink.flush())
                .expect("the safe send diagnostic reaches the parent sink");
            assert!(
                cleanup && terminal == "normal" && peer_clean && executed_one,
                "the isolated send scenario cannot be verified"
            );
            assert!(
                status.is_some_and(|s| s.success()) && outcome_reason == "strict_pass",
                "the isolated send scenario failed its strict oracle"
            );
            return;
        }
        Some(value) => assert!(value == ADAPTER, "the send child guard is adapter-specific"),
    }

    struct PeerState {
        stop: bool,
        sockets: Vec<TcpStream>,
        facts: Facts,
    }
    struct Connection {
        stream: TcpStream,
        request: Vec<u8>,
        header_end: Option<usize>,
        length: Option<usize>,
        complete: bool,
        observed_body: usize,
        response_offset: usize,
        next_drip: Instant,
        closed: bool,
    }
    fn observe_request(
        connection: &mut Connection,
        state: &Arc<Mutex<PeerState>>,
    ) -> std::io::Result<()> {
        let mut chunk = [0; 1024];
        match connection.stream.read(&mut chunk) {
            Ok(0) => {
                connection.closed = true;
                if !connection.request.is_empty() && !connection.complete {
                    return Err(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "incomplete fixture post",
                    ));
                }
                return Ok(());
            }
            Ok(count) => {
                if connection.complete || connection.request.len() + count > 81920 {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "extra or oversized fixture post",
                    ));
                }
                connection.request.extend_from_slice(&chunk[..count]);
            }
            Err(error)
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        if connection.header_end.is_none() {
            if let Some(end) = connection
                .request
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
            {
                let end = end + 4;
                if end > 16384 {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "oversized fixture headers",
                    ));
                }
                let header = std::str::from_utf8(&connection.request[..end])
                    .map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error))?;
                let mut lines = header.split("\r\n");
                if lines.next()
                    != Some(
                        "POST /v1beta/models/gemini-3.1-pro-preview:streamGenerateContent?alt=sse HTTP/1.1",
                    )
                {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "unexpected fixture post target",
                    ));
                }
                let mut lengths = Vec::new();
                let mut content_types = 0;
                for line in lines.filter(|line| !line.is_empty()) {
                    let (name, value) = line.split_once(':').ok_or_else(|| {
                        std::io::Error::new(ErrorKind::InvalidData, "invalid fixture header")
                    })?;
                    if name.eq_ignore_ascii_case("transfer-encoding") {
                        return Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            "ambiguous fixture framing",
                        ));
                    }
                    if name.eq_ignore_ascii_case("content-length") {
                        let value = value.trim();
                        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                            return Err(std::io::Error::new(
                                ErrorKind::InvalidData,
                                "invalid fixture length",
                            ));
                        }
                        lengths.push(
                            value.parse::<usize>().map_err(|error| {
                                std::io::Error::new(ErrorKind::InvalidData, error)
                            })?,
                        );
                    }
                    if name.eq_ignore_ascii_case("content-type") {
                        if value.trim() != "application/json" {
                            return Err(std::io::Error::new(
                                ErrorKind::InvalidData,
                                "invalid fixture content type",
                            ));
                        }
                        content_types += 1;
                    }
                }
                if lengths.len() != 1 || lengths[0] == 0 || lengths[0] > 65536 || content_types != 1
                {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "invalid fixture framing",
                    ));
                }
                connection.header_end = Some(end);
                connection.length = Some(lengths[0]);
                state.lock().expect("peer state").facts.headers += 1;
            } else if connection.request.len() > 16384 {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "oversized fixture headers",
                ));
            }
        }
        if let (Some(end), Some(length)) = (connection.header_end, connection.length) {
            let count = connection.request.len() - end;
            let newly_observed = count.saturating_sub(connection.observed_body);
            state.lock().expect("peer state").facts.body_bytes +=
                u32::try_from(newly_observed).expect("bounded fixture body");
            connection.observed_body = count;
            if count > length {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "extra fixture body",
                ));
            }
            if count == length {
                let body: Value = serde_json::from_slice(&connection.request[end..])
                    .map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error))?;
                if !(body["contents"]
                    == json!([{"role":"user","parts":[{"text":"goal: auth leg"}]}]))
                {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "unexpected fixture json shape",
                    ));
                }
                connection.complete = true;
                let mut state = state.lock().expect("peer state");
                state.facts.complete_post += 1;
                if state.facts.complete_post != 1 {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "duplicate fixture post",
                    ));
                }
            }
        }
        Ok(())
    }
    fn run_peer(listener: TcpListener, state: Arc<Mutex<PeerState>>, began: Instant) {
        let mut connections: Vec<Connection> = Vec::new();
        const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n";
        while began.elapsed() < Duration::from_secs(24) {
            if state.lock().expect("peer state").stop {
                return;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let mut observed = state.lock().expect("peer state");
                    observed.facts.accepts += 1;
                    if observed.stop || connections.len() == LIMIT {
                        if let Err(error) = stream.shutdown(Shutdown::Both) {
                            observed.facts.io_kind = Some(kind(&error));
                            observed.facts.raw_os_error = error.raw_os_error();
                        }
                        observed.facts.fixture_error |= !observed.stop;
                        return;
                    } else {
                        let registered = stream
                            .set_nonblocking(true)
                            .and_then(|()| stream.try_clone());
                        match registered {
                            Ok(owned) => {
                                observed.sockets.push(owned);
                                let mut byte = [0];
                                let present = match stream.peek(&mut byte) {
                                    Ok(count) if count > 0 => Some(true),
                                    Ok(_) => None,
                                    Err(error)
                                        if matches!(
                                            error.kind(),
                                            ErrorKind::WouldBlock | ErrorKind::Interrupted
                                        ) =>
                                    {
                                        None
                                    }
                                    Err(error) => {
                                        observed.facts.io_kind = Some(kind(&error));
                                        observed.facts.raw_os_error = error.raw_os_error();
                                        None
                                    }
                                };
                                if connections.is_empty() {
                                    observed.facts.first_peek = present;
                                }
                                connections.push(Connection {
                                    stream,
                                    request: Vec::new(),
                                    header_end: None,
                                    length: None,
                                    complete: false,
                                    observed_body: 0,
                                    response_offset: 0,
                                    next_drip: Instant::now(),
                                    closed: false,
                                });
                            }
                            Err(error) => {
                                observed.facts.fixture_error = true;
                                observed.facts.io_kind = Some(kind(&error));
                                observed.facts.raw_os_error = error.raw_os_error();
                            }
                        }
                    }
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                Err(error) => {
                    let mut observed = state.lock().expect("peer state");
                    observed.facts.fixture_error = true;
                    observed.facts.io_kind = Some(kind(&error));
                    observed.facts.raw_os_error = error.raw_os_error();
                    drop(observed);
                    return;
                }
            }
            for connection in &mut connections {
                if state.lock().expect("peer state").stop {
                    return;
                }
                if connection.closed {
                    continue;
                }
                let io = (|| -> std::io::Result<()> {
                    observe_request(connection, &state)?;
                    if !connection.complete || connection.closed {
                        return Ok(());
                    }
                    if connection.response_offset < RESPONSE.len() {
                        match connection
                            .stream
                            .write(&RESPONSE[connection.response_offset..])
                        {
                            Ok(0) => {
                                return Err(std::io::Error::new(
                                    ErrorKind::WriteZero,
                                    "fixture response write stopped",
                                ));
                            }
                            Ok(count) => {
                                let mut observed = state.lock().expect("peer state");
                                if connection.response_offset == 0
                                    && observed.facts.complete_before_response.is_none()
                                {
                                    observed.facts.complete_before_response =
                                        Some(connection.complete);
                                    observed.facts.first_response_before_body =
                                        Some(!connection.complete);
                                }
                                connection.response_offset += count;
                                if connection.response_offset == RESPONSE.len() {
                                    observed.facts.response_emits += 1;
                                }
                            }
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    ErrorKind::WouldBlock | ErrorKind::Interrupted
                                ) =>
                            {
                                return Ok(());
                            }
                            Err(error) => return Err(error),
                        }
                        if connection.response_offset < RESPONSE.len() {
                            return Ok(());
                        }
                    }
                    if connection.next_drip <= Instant::now() {
                        match connection.stream.write(b"x") {
                            Ok(1) => {
                                state.lock().expect("peer state").facts.drips += 1;
                                connection.next_drip = Instant::now() + Duration::from_millis(30);
                            }
                            Ok(_) => {
                                return Err(std::io::Error::new(
                                    ErrorKind::WriteZero,
                                    "fixture drip stopped",
                                ));
                            }
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    ErrorKind::WouldBlock | ErrorKind::Interrupted
                                ) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    Ok(())
                })();
                if let Err(error) = io {
                    connection.closed = true;
                    let mut observed = state.lock().expect("peer state");
                    observed.facts.io_kind = Some(kind(&error));
                    observed.facts.raw_os_error = error.raw_os_error();
                    observed.facts.fixture_error |= !matches!(
                        error.kind(),
                        ErrorKind::BrokenPipe
                            | ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                    );
                }
            }
            std::thread::yield_now();
        }
    }
    fn shutdown_owned(state: &Arc<Mutex<PeerState>>) -> bool {
        let mut state = state.lock().expect("peer state");
        state.stop = true;
        let mut clean = true;
        for stream in &state.sockets {
            if let Err(error) = stream.shutdown(Shutdown::Both) {
                clean &= error.kind() == ErrorKind::NotConnected;
            }
        }
        drop(state);
        clean
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("the fixture binds");
    listener
        .set_nonblocking(true)
        .expect("the fixture is nonblocking");
    let address = listener.local_addr().expect("the fixture address is local");
    let endpoint = format!("http://{address}/v1beta");
    let config =
        Config::parse_validated(&gemini_config(&endpoint)).expect("the fixture config is valid");
    let manifest = prepared_manifest(&config);
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let state = Arc::new(Mutex::new(PeerState {
        stop: false,
        sockets: Vec::new(),
        facts: Facts::default(),
    }));
    let stage = Arc::new(AtomicU8::new(0));
    let captured = Arc::new(Mutex::new(Primary::default()));
    let began = Instant::now();
    let peer_state = state.clone();
    let mut peer =
        match std::thread::Builder::new().spawn(move || run_peer(listener, peer_state, began)) {
            Ok(worker) => Some(worker),
            Err(_) => {
                state.lock().expect("peer state").facts.fixture_error = true;
                None
            }
        };
    let client_stage = stage.clone();
    let client_primary = captured.clone();
    let mut client = if peer.is_some() {
        std::thread::Builder::new()
            .spawn(move || {
                client_stage.store(1, Ordering::Release);
                let built = GeminiProvider::with_deadline(
                    &config,
                    "google",
                    store,
                    Duration::from_millis(4000),
                );
                let observed = match built {
                    Ok(mut provider) => {
                        client_stage.store(2, Ordering::Release);
                        let method = Instant::now();
                        let outcome = provider.send(&manifest);
                        let mut observed = primary(outcome);
                        observed.method_ms = Some(
                            u64::try_from(method.elapsed().as_millis())
                                .unwrap_or(30000)
                                .min(30000),
                        );
                        *client_primary.lock().expect("captured primary") = observed.clone();
                        client_stage.store(3, Ordering::Release);
                        drop(provider);
                        observed
                    }
                    Err(error) => {
                        let mut observed = primary(Err(error));
                        observed.variant = Variant::Setup;
                        observed
                    }
                };
                *client_primary.lock().expect("captured primary") = observed.clone();
                observed
            })
            .map(Some)
            .unwrap_or_else(|_| {
                state.lock().expect("peer state").facts.fixture_error = true;
                None
            })
    } else {
        None
    };
    while client.as_ref().is_some_and(|worker| !worker.is_finished())
        && began.elapsed() < Duration::from_secs(20)
    {
        std::thread::yield_now();
    }
    let mut observed = captured.lock().expect("captured primary").clone();
    let mut caller_ms = None;
    let mut client_joined = false;
    if client
        .as_ref()
        .is_some_and(std::thread::JoinHandle::is_finished)
        && let Ok(returned) = client.take().expect("owned client").join()
    {
        observed = returned;
        caller_ms = Some(
            u64::try_from(began.elapsed().as_millis())
                .unwrap_or(30000)
                .min(30000),
        );
        stage.store(4, Ordering::Release);
        client_joined = true;
    }
    let snapshot = Snapshot {
        facts: state.lock().expect("peer state").facts.clone(),
        primary: observed,
        client_stage: match stage.load(Ordering::Acquire) {
            1 => ClientStage::Construction,
            2 => ClientStage::Send,
            3 => ClientStage::Drop,
            4 => ClientStage::Joined,
            _ => ClientStage::Pending,
        },
        caller_ms,
    };
    let line = format!(
        "{CHILD_PREFIX}{}\n",
        serde_json::to_string(&snapshot).expect("typed snapshot serializes")
    );
    let mut sink = std::io::stderr().lock();
    let snapshot_written = line.len() <= 2048
        && sink
            .write_all(line.as_bytes())
            .and_then(|()| sink.flush())
            .is_ok();
    drop(sink);
    let mut shutdown = shutdown_owned(&state);
    while began.elapsed() < Duration::from_secs(24)
        && (peer.as_ref().is_some_and(|worker| !worker.is_finished())
            || client.as_ref().is_some_and(|worker| !worker.is_finished()))
    {
        std::thread::yield_now();
    }
    let mut peer_joined = false;
    if peer
        .as_ref()
        .is_some_and(std::thread::JoinHandle::is_finished)
    {
        peer_joined = peer.take().expect("owned peer").join().is_ok();
    }
    if client
        .as_ref()
        .is_some_and(std::thread::JoinHandle::is_finished)
    {
        client_joined = client.take().expect("owned client").join().is_ok();
    }
    shutdown &= shutdown_owned(&state);
    if peer.is_some() || client.is_some() {
        // Keep ownership until the parent observes process containment.
        loop {
            std::thread::park_timeout(Duration::from_secs(1));
        }
    }
    if shutdown && peer_joined && client_joined {
        let mut sink = std::io::stderr().lock();
        sink.write_all(format!("{CLEAN}\n").as_bytes())
            .and_then(|()| sink.flush())
            .expect("the cleanup token reaches the private parent pipe");
    }
    assert!(
        snapshot_written,
        "the provisional send snapshot is bounded and written"
    );
    assert!(
        snapshot.primary.variant == Variant::Transport,
        "a dribbling peer is a typed transport denial"
    );
    assert!(
        snapshot.primary.class == Some(Class::DeadlineExpired),
        "the total deadline is the named cause"
    );
    assert!(
        snapshot.caller_ms.is_some_and(|elapsed| elapsed < 20000),
        "the send ended near its deadline, including construction drop and join"
    );
    assert!(
        shutdown && peer_joined && client_joined,
        "the send fixture cleanup is observed"
    );
    assert!(
        !snapshot.facts.fixture_error,
        "the physical post fixture is valid"
    );
    assert!(
        snapshot.facts.complete_post == 1
            && snapshot.facts.body_bytes > 0
            && snapshot.facts.response_emits == 1
            && snapshot.facts.drips > 0
            && snapshot.facts.complete_before_response == Some(true)
            && snapshot.facts.first_response_before_body == Some(false),
        "the send exercised exactly one complete physical post and a dribbling response"
    );
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
        Err(ProviderError::Transport { cause, .. }) => {
            assert!(
                cause.class() == TransportClass::DeadlineExpired,
                "the total deadline is the named cause: {cause}"
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
    let config =
        Config::parse_validated(&gemini_config("https://127.0.0.1:1/v1beta")).expect("valid");
    // The delay is the wedge marker: had the resolve run, the send
    // could not have returned inside it.
    let store_delay = Duration::from_secs(30);
    let store = Arc::new(SlowStore {
        inner: support::MapStore::seeded(STORE_KIND, &[(CREDENTIAL_REF, SECRET)]),
        delay: store_delay,
    });
    let built = config.clone();
    let provider = std::thread::spawn(move || {
        GeminiProvider::with_deadline(&built, "google", store, Duration::ZERO)
    })
    .join()
    .expect("the provider thread joins")
    .expect("the adapter builds");

    let started = Instant::now();
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let elapsed = started.elapsed();
    match outcome {
        Err(ProviderError::Transport { cause, .. }) => {
            assert!(
                cause.class() == TransportClass::DeadlineExpired,
                "the spent budget is the named cause: {cause}"
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
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused key is transport: {err}")
    };
    assert_eq!(connection, "google");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
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

    // a peer name past the reason bound truncates on the boundary —
    // the diagnostic surface never parks a payload
    let server = MockServer::start().await;
    mount_generate(
        &server,
        completed_stream(
            "",
            vec![json!({"functionCall": {"name": "x".repeat(2000), "args": {}}})],
            None,
        ),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: oversized name");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
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
/// method suffix — and the denial reason stays bounded however long
/// the hostile id. A catalogue name outside the id charset is
/// dropped, so a hostile listing cannot poison the auto pick with an
/// empty id that sorts first.
#[tokio::test]
async fn hostile_model_ids_and_catalog_names_never_reach_the_wire() {
    // An oversized id is denied on the same leg, and the reason it
    // produces is capped — a hostile pin cannot park an unbounded id
    // in the diagnostic surface.
    let oversized = "a?".repeat(1000);
    for hostile in ["a?b=1", "models/../x", "%2e%2e%2fadmin", "", &oversized] {
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
        let Err(ProviderError::StreamViolation { reason, .. }) = &outcome else {
            panic!("model id {hostile:?} is a typed denial before the post: {outcome:?}")
        };
        assert!(
            reason.len() <= 1024,
            "model id {hostile:?} denial reason stays bounded: {reason:?}"
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

    // a payload-length peer reason is bounded: the cap lands on a UTF-8
    // char boundary, so '€' (3 bytes) cuts at 1023, never mid-codepoint
    let server = MockServer::start().await;
    mount_generate(
        &server,
        data_block(&json!({"error": {"message": "€".repeat(400)}})),
    )
    .await;
    let config =
        Config::parse_validated(&gemini_config(&server_uri_v1beta(&server))).expect("valid");
    let (broker, manifest) = prepared(&config, "/world/google", "goal: oversized reason");
    let (broker, outcome) = dispatch(broker, "/world/google", manifest);
    let Err(ModelError::Provider(ProviderError::ProviderFailed { reason, .. })) = outcome else {
        panic!("the oversized reason is a peer failure: {outcome:?}")
    };
    assert_eq!(
        reason.len(),
        1023,
        "the peer reason is capped on a char boundary"
    );
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
