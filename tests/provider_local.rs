//! Provider proof legs for the ten recorded connection ids of this band
//! — `coreweave`, `deepinfra`, `deepseek`, `firepass`, `fireworks`,
//! `gmi-cloud`, `groq`, `huggingface`, `kilo` and `litellm` (section
//! owned by SLICE-108) — plus the four position-4 ids whose source
//! classes resolve through this offline target
//! (TP-PROVIDER-{CATALOG,AUTH,WIRE,RECOVERY,INSTALLED}::
//! custom-chat-completions, abliteration, aiand, aimlapi): the
//! configured literal `custom-chat-completions` connection returns a
//! verified model outcome through the standard Broker against the
//! source-derived `chat/completions` peer, `abliteration` does the
//! same through the shared SLICE-016 Responses adapter, `aiand` and
//! `aimlapi` through the shared Chat Completions adapter, and each
//! band id through that same shared adapter under its own recorded
//! predicates — no copied codec — as localhost wiremock fixtures, no
//! OMP, no user adapter, no real host. The shared SSE parser's WHATWG
//! §9.2.5–9.2.6 conformance is pinned in provider_openai.rs; this file
//! pins the Chat Completions dialect surface plus the per-connection
//! predicates on top of it.
//! TP-PROVIDER-INSTALLED::<id> stays NOT_RUN — the ignored named cases
//! carry that status explicitly.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/discard conveniences; src/ stays strict (standards §14)"
)]

use rivect::config::{Config, ConfigIssue, EffortLevel};
use rivect::model::{Broker, ModelError, RequestManifest};
use rivect::providers::local::{CatalogModel, ChatCompletionsProvider, ModelPrice};
use rivect::providers::openai::OpenAiProvider;
use rivect::providers::{
    CredentialStore, Provider, ProviderError, SecretRef, StoreKind, TransportCause, TransportClass,
};
use rivect::resources::UsageDelta;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

mod support;

use support::{
    SlowStore, drop_blocking, mount_responses, prepared_with, responses_completed_stream,
    send_on_thread, sse_block,
};

/// The literal connection id this dialect serves.
const CONNECTION: &str = "custom-chat-completions";
/// The scoped credential ref the connection binds — a `keyring:` ref
/// resolves to the platform's native class, which the offline store
/// double serves by scope alone.
const CREDENTIAL_REF: &str = "keyring:rivect-test/custom-chat-completions";
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
const MODEL: &str = "fixture-chat-model";

/// One configured `custom-chat-completions` connection pointing at the
/// fixture peer: the api_key auth class resolves a scoped `SecretRef`
/// (DEC-011), the dialect comes from the literal connection id
/// (DEC-007). The configured endpoint carries the API base's version
/// segment verbatim — `…/v1` like an OpenAI-compatible deployment's
/// own root.
fn local_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.{CONNECTION}]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{CONNECTION}\", model_id = \"{MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// reqwest's blocking client builds and drops a shell runtime inside
/// `wait::enter` — panicking in any tokio context (debug builds) — so
/// every `ChatCompletionsProvider` construction happens on a plain OS
/// thread.
fn provider_result(
    config: Config,
    connection: String,
    store: Arc<support::MapStore>,
) -> Result<ChatCompletionsProvider, ProviderError> {
    std::thread::spawn(move || ChatCompletionsProvider::new(&config, &connection, store))
        .join()
        .expect("the provider thread joins")
}

fn local_provider(config: &Config) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let provider = provider_result(config.clone(), CONNECTION.to_string(), store.clone())
        .expect("the chat-completions adapter builds for the literal id");
    (provider, store)
}

/// One SSE block on the wire — the Chat Completions contract
/// dispatches bare `data:` chunks, one `chat.completion.chunk` each,
/// with no named event fields.
fn data_block(chunk: &Value) -> String {
    format!("data: {chunk}\n\n")
}

/// The `[DONE]` sentinel — the contract's server-agreed stream close.
const DONE_BLOCK: &str = "data: [DONE]\n\n";

/// One content-delta chunk on the single recorded `choices[0]` slot.
fn delta_chunk(delta: Value) -> Value {
    json!({"id": "c1", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": delta, "finish_reason": null}]})
}

/// A finish chunk — empty delta carrying the reason.
fn finish_chunk(reason: &str) -> Value {
    json!({"id": "c1", "choices": [{"index": 0, "delta": {}, "finish_reason": reason}]})
}

/// The trailing usage-only chunk `stream_options.include_usage`
/// requests (recorded shape: empty `choices`, top-level `usage`).
fn usage_chunk(usage: Value) -> Value {
    json!({"id": "c1", "choices": [], "usage": usage})
}

/// A completed stream: the content delta, the `stop` finish, then
/// `[DONE]` — with an optional trailing usage chunk between them.
fn completed_stream(text: &str, usage: Option<Value>) -> String {
    let mut body = data_block(&delta_chunk(json!({"role": "assistant", "content": text})));
    body.push_str(&data_block(&finish_chunk("stop")));
    if let Some(usage) = usage {
        body.push_str(&data_block(&usage_chunk(usage)));
    }
    body.push_str(DONE_BLOCK);
    body
}

/// The configured endpoint is the API base — `/v1` included — and the
/// adapter appends the recorded resource paths.
fn server_uri_v1(server: &MockServer) -> String {
    format!("{}/v1", server.uri())
}

async fn mount_chat(server: &MockServer, body: String) {
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(server)
        .await;
}

async fn mount_models(server: &MockServer, ids: Vec<Value>) {
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"object": "list", "data": ids})),
        )
        .mount(server)
        .await;
}

/// The bearer header the Chat Completions dialect authenticates with.
fn received_auth(request: &Request) -> String {
    request
        .headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .expect("the request carried an authorization header")
        .to_string()
}

/// One frozen manifest through the real admission path.
fn prepared_manifest(config: &Config) -> RequestManifest {
    let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
    broker
        .prepare("main", config, "/world/local", "goal: auth leg")
        .expect("the pin prepares")
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
        let outcome = broker.dispatch(&mut rivect::model::NullLedger, &world, &manifest);
        (broker, outcome)
    })
    .join()
    .expect("the dispatch thread joins")
}

/// A bare `provider.catalog` must not run inside any tokio context for
/// the same reason — lookups go to a plain OS thread and the provider
/// comes back.
fn catalog_on_thread(
    provider: ChatCompletionsProvider,
) -> (
    ChatCompletionsProvider,
    Result<Vec<CatalogModel>, ProviderError>,
) {
    std::thread::spawn(move || {
        let outcome = provider.catalog();
        (provider, outcome)
    })
    .join()
    .expect("the catalog thread joins")
}

/// The offered model ids of a catalogue answer, in order — the id is
/// the wire name the dispatch surface compares.
fn model_ids(models: &[CatalogModel]) -> Vec<&str> {
    models.iter().map(|model| model.id.as_str()).collect()
}

// ----- TP-PROVIDER-WIRE::custom-chat-completions ---------------------

/// A configured `custom-chat-completions` connection returns a
/// verified model outcome through the standard Broker: prepare admits
/// the api_key pin under DEC-011, the adapter posts exactly the frozen
/// manifest as a `chat/completions` request — model, system+user
/// messages, `stream` with `stream_options.include_usage`, the
/// declared tool surface as function tools and the pinned effort as
/// `reasoning_effort` verbatim — the SSE stream validates its
/// finish_reason/`[DONE]` terminal, and the one physical send is
/// charged once with the provider's reported usage.
#[tokio::test]
async fn valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified outcome text",
            Some(json!({"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18})),
        ),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: prove the wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/local", manifest.clone());
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
    assert_eq!(
        requests[0]
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json"),
        "the body rides the recorded json content type"
    );
    assert_eq!(
        requests[0]
            .headers
            .get("accept")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream"),
        "the stream negotiation rides the recorded accept"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(SECRET),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], json!(MODEL));
    assert_eq!(
        body["messages"],
        json!([
            {"role": "system", "content": manifest.instructions},
            {"role": "user", "content": manifest.inputs},
        ]),
        "the frozen instructions and inputs ride the messages verbatim"
    );
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["stream_options"],
        json!({"include_usage": true}),
        "the recorded usage request rides the stream options"
    );
    assert_eq!(
        body["tools"],
        json!([{
            "type": "function",
            "function": {"name": "read_file", "description": "", "parameters": {"type": "object"}},
        }]),
        "the declared tool surface maps to function tools verbatim"
    );
    assert_eq!(
        body["reasoning_effort"],
        json!("medium"),
        "the pinned effort rides the recorded reasoning_effort surface"
    );

    // Exactly one accounting record carries the one physical usage
    // report — the provider's 18 tokens are the confirmed charge, and
    // a replayed attempt reports spent.
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, CONNECTION);
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
            let replay = broker.dispatch(&mut rivect::model::NullLedger, "/world/local", &manifest);
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

/// Members the manifest does not pin never reach the wire: an
/// `Auto`/`Inherit` effort emits no `reasoning_effort` key — the
/// recorded surface exists only for a frozen pin — and empty
/// instructions emit no `system` message.
#[tokio::test]
async fn unpinned_effort_and_empty_instructions_emit_no_wire_members() {
    let server = MockServer::start().await;
    mount_chat(&server, completed_stream("bare", None)).await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = local_provider(&config);
    let base = prepared_manifest(&config);

    // an auto effort is unpinned — no member — and empty instructions
    // emit no system message in the same body
    let mut auto = base.clone();
    auto.effort = rivect::config::EffortAssign::Auto;
    auto.instructions = String::new();
    let inputs = auto.inputs.clone();
    let (provider, outcome) = send_on_thread(provider, auto);
    outcome.expect("the auto-effort send completes");

    // an inherited effort is likewise unpinned
    let mut inherit = base;
    inherit.effort = rivect::config::EffortAssign::Inherit;
    let (provider, outcome) = send_on_thread(provider, inherit);
    outcome.expect("the inherited-effort send completes");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 2, "one send per effort assignment");
    for request in &requests {
        let body: Value = serde_json::from_slice(&request.body).expect("json body");
        assert!(
            body.get("reasoning_effort").is_none(),
            "an unpinned effort emits no reasoning_effort member: {body}"
        );
    }
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["messages"],
        json!([{"role": "user", "content": inputs}]),
        "empty instructions emit no system message"
    );
}

/// The dialect keys on the literal connection id, never an auth
/// label: a connection id without the recorded Chat Completions
/// source class builds no adapter, a manifest pinning a different
/// connection id is refused at send, and an `openai`-pinned manifest
/// through this broker is a dialect denial before any byte or
/// accounting.
#[tokio::test]
async fn dialect_is_keyed_on_the_literal_connection_id() {
    let server = MockServer::start().await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = provider_result(config.clone(), "other-chat".to_string(), store)
        .expect_err("a different literal id is not this dialect");
    assert!(matches!(err, ProviderError::DialectMismatch { .. }));

    let (mut provider, _store) = local_provider(&config);
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
            .prepare("main", &foreign, "/world/local", "goal: x")
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

    // A foreign-dialect pin dispatched through this broker:
    // eligibility passes the api_key pin, the adapter's own dialect
    // gate denies it before any send or accounting.
    let foreign = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.openai]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"openai\", model_id = \"gpt-5.2\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let (provider, _store) = local_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &foreign, "/world/local", "goal: foreign dialect")
        .expect("the foreign pin passes DEC-011 eligibility");
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::DialectUnserved { .. }))
        ),
        "a foreign pin through this broker is the typed dialect denial: {outcome:?}"
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

// ----- TP-PROVIDER-CATALOG::custom-chat-completions ------------------

/// `GET {endpoint}/models` is the configured endpoint's own listing —
/// every `data[]` id with a non-whitespace body is an offered model
/// in sorted order, and the bearer credential came through the store
/// seam.
#[tokio::test]
async fn catalog_lists_the_configured_endpoints_models() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "zeta-9"}),
            json!({"id": "alpha-1"}),
            json!({"id": "alpha-1"}),
            // gateway-style ids carry path characters — the id is a
            // JSON body field, not URL material, so it is admitted
            // verbatim
            json!({"id": "vendor/mid-2"}),
            json!({"id": ""}),
            json!({"owned_by": "nobody"}),
        ],
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = local_provider(&config);
    let models = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("the catalog thread joins")
        .expect("the catalog answers");
    assert_eq!(
        model_ids(&models),
        vec!["alpha-1", "vendor/mid-2", "zeta-9"],
        "the listing's non-empty ids deduplicate and sort"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(received_auth(&requests[0]), format!("Bearer {SECRET}"));
}

/// The listing payload is bounded like the stream: a valid listing
/// past the byte bound is a typed violation, never buffered
/// unbounded.
#[tokio::test]
async fn catalog_payload_over_the_byte_bound_is_a_typed_violation() {
    let server = MockServer::start().await;
    // a *valid* listing padded past the 1 MiB bound — an unparseable
    // body would deny on the JSON arm and never discriminate this one
    let ids: Vec<Value> = (0..60_000)
        .map(|entry| json!({"id": format!("model-{entry}")}))
        .collect();
    let body = json!({"object": "list", "data": ids}).to_string();
    assert!(
        body.len() > 1024 * 1024,
        "the fixture listing exceeds the catalog byte bound: {} bytes",
        body.len()
    );
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = local_provider(&config);
    let outcome = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("the catalog thread joins");
    assert!(
        matches!(outcome, Err(ProviderError::StreamViolation { .. })),
        "an over-bound catalog payload is a typed violation: {outcome:?}"
    );
}

/// A seedless class keeps the typed denial on a failed discovery send
/// (DEC-012): the refused endpoint contributes no offer and this class
/// records no floor to fall back to, so the `Transport` denial stands
/// unchanged rather than a fabricated catalogue.
#[tokio::test]
async fn failed_discovery_send_keeps_the_seedless_typed_denial() {
    let config = Config::parse_validated(&local_config("http://127.0.0.1:1/v1")).expect("valid");
    let (provider, _store) = local_provider(&config);
    let (provider, catalogue) = catalog_on_thread(provider);
    let err = catalogue.expect_err("a seedless class has no floor to answer");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused discovery send is transport: {err}")
    };
    assert_eq!(connection, CONNECTION);
    assert!(
        cause.class() == TransportClass::RequestFailure,
        "the refused connection is the typed request failure: {cause}"
    );
    drop_blocking(provider);
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
            let expected_request = b"GET /v1/models HTTP/1.1\r\n";
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
    let config =
        Config::parse_validated(&local_config(&format!("http://{address}/v1"))).expect("valid");
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
                let multiple_connections = true;
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
        let provider = ChatCompletionsProvider::with_deadline(
            &config,
            CONNECTION,
            store,
            Duration::from_millis(1500),
        )?;
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
        Some(ProviderError::LocalProfileDeclared { .. }) => "LocalProfileDeclared",
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
        Some(ProviderError::EndpointRequired { .. }) => "EndpointRequired",
        Some(ProviderError::Transport { .. }) => "Transport",
        Some(ProviderError::ProviderFailed { .. }) => "ProviderFailed",
        Some(ProviderError::UnknownTerminal { .. }) => "UnknownTerminal",
        Some(ProviderError::StreamViolation { .. }) => "StreamViolation",
        Some(ProviderError::IncompatibleOutput { .. }) => "IncompatibleOutput",
        Some(ProviderError::UnsupportedParameter { .. }) => "UnsupportedParameter",
        Some(ProviderError::ReasoningProvenance { .. }) => "ReasoningProvenance",
        Some(ProviderError::Retried { .. }) => "Retried",
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
        "adapter": CONNECTION,
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

/// AC-046 fail-closed: eligibility says the `custom-chat-completions`
/// pin is usable, but a broker whose only adapter is the local fixture
/// must still deny the send — the provider's own dialect claim is the
/// last gate, and the denial lands before any send or accounting.
#[test]
fn a_pin_no_adapter_serves_is_denied_before_send_or_accounting() {
    let config = Config::parse_validated(&local_config("http://127.0.0.1:1/v1")).expect("valid");
    let (provider, calls, _manifest) = support::CountingProvider::new();
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/local", "goal: unserved pin")
        .expect("the pin passes DEC-011 eligibility");
    let outcome = broker.dispatch(&mut rivect::model::NullLedger, "/world/local", &manifest);
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
/// it declares — `custom-chat-completions` declaring `local` kind gets
/// the typed denial, never a fabricated loopback reply.
#[test]
fn a_reserved_dialect_id_is_never_loopback_served() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.custom-chat-completions]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"custom-chat-completions\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"medium\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let loopback = rivect::providers::LoopbackProvider::new();
    let entry = config.connections.get(CONNECTION).expect("declared");
    assert!(
        !loopback.serves(CONNECTION, entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );
    let mut broker = Broker::new(Box::new(loopback));
    let manifest = broker
        .prepare("main", &config, "/world/local", "goal: reserved id")
        .expect("the local-kind pin passes DEC-011 eligibility");
    let outcome = broker.dispatch(&mut rivect::model::NullLedger, "/world/local", &manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::DialectUnserved { .. }))
        ),
        "a dialect-reserved id is denied, never fabricated: {outcome:?}"
    );
}

/// AC-045: an explicit manual pick of a served
/// `custom-chat-completions` candidate reaches the real send — the
/// substitute's single-member auto pool pins the connection, the live
/// catalogue names the model, and the send is attempted instead of
/// deterministically failing `UnpinnedModel` after eligibility already
/// passed.
#[tokio::test]
async fn a_manual_pick_of_a_candidate_reaches_the_real_send() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "fixture-chat-model"})]).await;
    mount_chat(
        &server,
        completed_stream(
            "picked outcome",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.a-local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [connections.{CONNECTION}]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"manual\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let (provider, _store) = local_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/local", "goal: pick the connection")
        .expect("the auto ranking admits a candidate");
    let attempt_id = manifest.attempt_id.clone();

    // The adapter speaks no local-fixture dialect: the ranked `a-local`
    // primary send fails and the manual pause offers the served
    // candidate.
    let (mut broker, outcome) = std::thread::spawn(move || {
        let outcome = broker.dispatch(&mut rivect::model::NullLedger, "/world/local", &manifest);
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
        pending.candidates.contains(&CONNECTION.to_string()),
        "the served candidate is offered: {:?}",
        pending.candidates
    );

    let (broker, outcome) = std::thread::spawn(move || {
        let outcome = broker.dispatch_fallback_choice(
            &mut rivect::model::NullLedger,
            "/world/local",
            &attempt_id,
            CONNECTION,
        );
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
        "/v1/chat/completions",
        "the live catalogue named the model the pick resolved to"
    );
    let body: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert_eq!(body["model"], json!("fixture-chat-model"));
    drop_blocking(broker);
}

/// The same auto seam on the primary send: `mode = "auto"` ranks the
/// connection, the dispatch narrows the pool to the winner it picked,
/// and the adapter's catalogue leg names the wire model —
/// `UnpinnedModel` never fires on a send the broker itself routed.
#[tokio::test]
async fn auto_ranked_primary_send_resolves_via_catalog() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![json!({"id": "zeta-9"}), json!({"id": "alpha-1"})],
    )
    .await;
    mount_chat(
        &server,
        completed_stream(
            "auto outcome",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.{CONNECTION}]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: auto route",
    );
    assert!(
        matches!(
            manifest.model,
            rivect::config::ModelAssign::Auto { pool: None }
        ),
        "the ranked auto assignment stays un-narrowed on the frozen manifest"
    );

    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
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
    assert_eq!(
        requests[1].url.path(),
        "/v1/chat/completions",
        "the catalogue's sorted-first id rode the wire"
    );
    let body: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert_eq!(body["model"], json!("alpha-1"));
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
        let config =
            Config::parse_validated(&local_config(&format!("http://{address}/v1"))).expect("valid");
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
            let mut provider = ChatCompletionsProvider::with_deadline(
                &config,
                CONNECTION,
                store,
                Duration::from_millis(500),
            )
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
            observed.starts_with(String::from("POST /v1/chat/completions HTTP/1.1\r\n").as_bytes())
        );
        let outcome = outcome.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        let error = outcome.expect_err("the peer returns a transport denial");
        assert!(
            matches!(&error, ProviderError::Transport { connection, .. } if connection == CONNECTION)
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
    let config = Config::parse_validated(&local_config(&format!(
        "http://{}/v1",
        listener.local_addr().expect("address")
    )))
    .expect("valid");
    // An empty store would return CredentialAbsent if the expired-budget guard called it.
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let mut provider =
        ChatCompletionsProvider::with_deadline(&config, CONNECTION, store, Duration::ZERO)
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
    let config = Config::parse_validated(&local_config(&format!(
        "http://{}/v1",
        listener.local_addr().expect("address")
    )))
    .expect("valid");
    let store = Arc::new(SlowStore {
        inner: support::MapStore::seeded(STORE_KIND, &[(CREDENTIAL_REF, SECRET)]),
        delay: Duration::from_millis(600),
    });
    let mut provider = ChatCompletionsProvider::with_deadline(
        &config,
        CONNECTION,
        store,
        Duration::from_millis(500),
    )
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

    const ADAPTER: &str = "local";
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
        LocalProfileDeclared,
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
        EndpointRequired,
        Transport,
        ProviderFailed,
        UnknownTerminal,
        StreamViolation,
        IncompatibleOutput,
        UnsupportedParameter,
        ReasoningProvenance,
        Retried,
    }
    fn provider_variant(error: &ProviderError) -> ProviderVariant {
        match error {
            ProviderError::UnknownConnection { .. } => ProviderVariant::UnknownConnection,
            ProviderError::LiveGrantRequired { .. } => ProviderVariant::LiveGrantRequired,
            ProviderError::StoreUnavailable { .. } => ProviderVariant::StoreUnavailable,
            ProviderError::StoreAmbiguous { .. } => ProviderVariant::StoreAmbiguous,
            ProviderError::CredentialUnresolved { .. } => ProviderVariant::CredentialUnresolved,
            ProviderError::LocalProfileDeclared { .. } => ProviderVariant::LocalProfileDeclared,
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
            ProviderError::EndpointRequired { .. } => ProviderVariant::EndpointRequired,
            ProviderError::Transport { .. } => ProviderVariant::Transport,
            ProviderError::ProviderFailed { .. } => ProviderVariant::ProviderFailed,
            ProviderError::UnknownTerminal { .. } => ProviderVariant::UnknownTerminal,
            ProviderError::StreamViolation { .. } => ProviderVariant::StreamViolation,
            ProviderError::IncompatibleOutput { .. } => ProviderVariant::IncompatibleOutput,
            ProviderError::UnsupportedParameter { .. } => ProviderVariant::UnsupportedParameter,
            ProviderError::ReasoningProvenance { .. } => ProviderVariant::ReasoningProvenance,
            ProviderError::Retried { .. } => ProviderVariant::Retried,
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
                if lines.next() != Some("POST /v1/chat/completions HTTP/1.1") {
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
                if !(body["model"] == "fixture-chat-model"
                    && body["stream"] == true
                    && body["messages"].as_array().is_some_and(|messages| {
                        messages.last() == Some(&json!({"role":"user","content":"goal: auth leg"}))
                    }))
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
    let endpoint = format!("http://{address}/v1");
    let config =
        Config::parse_validated(&local_config(&endpoint)).expect("the fixture config is valid");
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
                let built = ChatCompletionsProvider::with_deadline(
                    &config,
                    CONNECTION,
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
    mount_chat(&server, completed_stream("never sent", None)).await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let deadline = Duration::from_millis(1500);
    let store = Arc::new(SlowStore {
        inner: support::MapStore::seeded(STORE_KIND, &[(CREDENTIAL_REF, SECRET)]),
        // past the deadline — the resolve returns under an expired clock
        delay: deadline + Duration::from_millis(500),
    });
    let built = config.clone();
    let provider = std::thread::spawn(move || {
        ChatCompletionsProvider::with_deadline(&built, CONNECTION, store, deadline)
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
    let config = Config::parse_validated(&local_config("https://127.0.0.1:1/v1")).expect("valid");
    // The delay is the wedge marker: had the resolve run, the send
    // could not have returned inside it.
    let store_delay = Duration::from_secs(30);
    let store = Arc::new(SlowStore {
        inner: support::MapStore::seeded(STORE_KIND, &[(CREDENTIAL_REF, SECRET)]),
        delay: store_delay,
    });
    let built = config.clone();
    let provider = std::thread::spawn(move || {
        ChatCompletionsProvider::with_deadline(&built, CONNECTION, store, Duration::ZERO)
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

/// The serialized request body rides under the same wire bound the
/// manifest's accounted size promised (AC-013) — a body past
/// `MODEL_WIRE_MAX_BYTES` is a typed violation before any byte
/// crosses, never truncated.
#[tokio::test]
async fn request_body_over_the_wire_bound_is_denied_before_any_send() {
    let server = MockServer::start().await;
    mount_chat(&server, completed_stream("never sent", None)).await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = local_provider(&config);
    let mut manifest = prepared_manifest(&config);
    manifest.inputs = "x".repeat(rivect::contracts::MODEL_WIRE_MAX_BYTES);
    let (provider, outcome) = send_on_thread(provider, manifest);
    assert!(
        matches!(outcome, Err(ProviderError::StreamViolation { .. })),
        "an over-bound body is a typed violation: {outcome:?}"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert!(
        requests.is_empty(),
        "the denied body never crossed the wire: {requests:?}"
    );
    drop_blocking(provider);
}

/// `custom-chat-completions` is the one connection id without a fixed
/// host — its egress binds to the explicitly configured endpoint
/// origin, and discovery never escapes it. The catalogue lookup and
/// the send land on the configured origin only while a foreign peer
/// records nothing, and a redirect answer is the typed non-2xx
/// outcome, never followed: the credential-bearing request cannot be
/// pulled off the configured origin.
#[tokio::test]
async fn custom_chat_completions_egress_is_bound_to_the_configured_origin() {
    // The bound arm: the configured origin serves the listing and the
    // send; the foreign peer never sees a byte.
    let server = MockServer::start().await;
    let foreign = MockServer::start().await;
    mount_models(&server, vec![json!({"id": MODEL})]).await;
    mount_chat(&server, completed_stream("bound outcome", None)).await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = local_provider(&config);

    let (provider, catalog) = catalog_on_thread(provider);
    assert_eq!(
        model_ids(&catalog.expect("the configured origin's listing answers")),
        vec![MODEL]
    );
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let reply = outcome.expect("the configured origin's send completes");
    assert_eq!(reply.text, "bound outcome");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 2, "the catalogue lookup plus the one send");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(requests[1].url.path(), "/v1/chat/completions");
    for request in &requests {
        assert_eq!(received_auth(request), format!("Bearer {SECRET}"));
    }
    let foreign_requests = foreign.received_requests().await.expect("recorded");
    assert!(
        foreign_requests.is_empty(),
        "the unconfigured origin never saw a byte: {foreign_requests:?}"
    );

    // The refusal arm: a redirect pointing off-origin is the peer's
    // own non-2xx outcome — never followed, so the bearer and body
    // cannot leak to a foreign host. The decoy successes make a
    // followed redirect a false green the assertions below catch.
    let server = MockServer::start().await;
    let foreign = MockServer::start().await;
    mount_models(&foreign, vec![json!({"id": "decoy-model"})]).await;
    mount_chat(&foreign, completed_stream("decoy outcome", None)).await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/v1/models", foreign.uri())),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/v1/chat/completions", foreign.uri())),
        )
        .mount(&server)
        .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = local_provider(&config);

    let (provider, catalog) = catalog_on_thread(provider);
    match catalog {
        Err(ProviderError::Transport { cause, .. }) => {
            assert!(
                cause.class() == TransportClass::HttpStatus { code: 307 },
                "the refused redirect's own status names the denial: {cause}"
            );
        }
        other => panic!("a redirect answer is a typed transport denial, never a follow: {other:?}"),
    }
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    match outcome {
        Err(ProviderError::Transport { cause, .. }) => {
            assert!(
                cause.class() == TransportClass::HttpStatus { code: 307 },
                "the refused redirect's own status names the denial: {cause}"
            );
        }
        other => panic!("a redirect answer is a typed transport denial, never a follow: {other:?}"),
    }
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "each leg reached the configured origin exactly once"
    );
    let foreign_requests = foreign.received_requests().await.expect("recorded");
    assert!(
        foreign_requests.is_empty(),
        "a redirect never carried a request off-origin: {foreign_requests:?}"
    );
}

// ----- TP-PROVIDER-AUTH::custom-chat-completions ---------------------

/// A marker the 401 fixture's body carries so an error that echoes
/// uncontrolled peer bytes is caught, never vacuously clean.
const BODY_MARKER: &str = "fixture-401-body-marker-never-in-errors";

/// Every leg's denial renders Display and Debug with typed context
/// only — the leg's enrolled credential material and the peer's
/// response body never appear on either surface. The material is
/// scanned in both renderings a leak could take: its lossy string
/// form and the Debug-slice form a `Vec<u8>` field would print.
fn assert_no_secret_or_body(err: &ProviderError, material: &[u8]) {
    for rendered in [format!("{err}"), format!("{err:?}")] {
        for leak in [
            String::from_utf8_lossy(material).into_owned(),
            format!("{material:?}"),
        ] {
            assert!(
                !rendered.contains(&leak),
                "the credential material never renders: {rendered}"
            );
        }
        assert!(
            !rendered.contains(BODY_MARKER),
            "the peer's response body never renders: {rendered}"
        );
    }
}

/// Wrong credential/profile/region never produce a false success:
/// a configured region outside the dialect's recorded endpoint
/// contract — the generic Chat Completions class records none — the
/// profile-bound ref whose scope disagrees with the binding, an absent
/// credential, and a refused bearer token each land a typed denial —
/// and none of them, nor any Debug surface the boundary exposes,
/// renders credential material or the peer's body.
#[tokio::test]
async fn wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // region outside the recorded endpoint contract — the generic
    // class records no configurable region — a sibling scope holds
    // real material so the no-secret assertion proves no cross-scope
    // leak instead of passing vacuously
    let regioned = Config::parse_validated(&local_config(&server_uri_v1(&server)).replace(
        "kind = \"api_key\"",
        "kind = \"api_key\"\nregion = \"eu-1\"",
    ))
    .expect("valid");
    let err = provider_result(
        regioned,
        CONNECTION.to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, SECRET)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, CONNECTION);
    assert_eq!(region, "eu-1");
    assert_no_secret_or_body(&err, SECRET.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.{CONNECTION}]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"{CONNECTION}\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        CONNECTION.to_string(),
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
    assert_no_secret_or_body(&err, SECRET.as_bytes());

    // a bound ref with no material at its own scope — the sibling
    // scope's material stays sealed behind the typed denial
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let provider = provider_result(
        config.clone(),
        CONNECTION.to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, SECRET)],
        )),
    )
    .expect("binding resolves; the store is read at send");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("no material at the scope is the typed denial");
    assert!(matches!(err, ProviderError::CredentialAbsent { .. }));
    assert_no_secret_or_body(&err, SECRET.as_bytes());
    drop_blocking(provider);

    // a refused bearer token is a typed transport denial — the wire
    // never coerces a wrong credential into success, and the peer's
    // body never enters the error
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    // The fixture 401s any token, so the enrolled material is SECRET
    // itself — the only leg that resolves material before the HTTP
    // error, and the assertion must prove that resolved credential is
    // absent from the error, not a different string.
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let provider = provider_result(config.clone(), CONNECTION.to_string(), store).expect("builds");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused token is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused token is transport: {err}")
    };
    assert_eq!(connection, CONNECTION);
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, SECRET.as_bytes());
    drop_blocking(provider);

    // The same boundary on the Debug surfaces the dispatch path
    // exposes: provider, manifest, accounting record, broker and
    // runtime each render without the material the store alone holds.
    let server = MockServer::start().await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let provider =
        provider_result(config.clone(), CONNECTION.to_string(), store).expect("the adapter builds");
    assert!(
        !format!("{provider:?}").contains(SECRET),
        "provider Debug never carries credential material"
    );
    mount_chat(
        &server,
        completed_stream(
            "accounted",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: debug surfaces",
    );
    assert!(
        !format!("{manifest:?}").contains(SECRET),
        "manifest Debug never carries credential material"
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest.clone());
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
        "auth-debug-local",
        Some(&local_config(&server_uri_v1(&server))),
    );
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
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::new(STORE_KIND));
    let material: &[u8] = b"\xff\xfe";
    store.enroll(CREDENTIAL_REF, material);
    let provider = provider_result(config.clone(), CONNECTION.to_string(), store)
        .expect("binding resolves; the store is read at send");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("non-utf-8 material is the typed denial");
    let ProviderError::CredentialMalformed { connection } = &err else {
        panic!("non-utf-8 material is malformed, never absent: {err}")
    };
    assert_eq!(connection, CONNECTION);
    assert_no_secret_or_body(&err, material);
    drop_blocking(provider);
}

// ----- TP-PROVIDER-RECOVERY::custom-chat-completions -----------------

/// A typed denial is recoverable through the same seam: the absent
/// credential denies the first send, enrolling material at the scope
/// admits the retry — no state wedged, no plaintext path taken.
#[tokio::test]
async fn typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), CONNECTION.to_string(), store.clone())
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
/// streamed tool_call fragment arrived but neither finish_reason nor
/// `[DONE]` ever did, the partial call is never executed, and nothing
/// is accounted.
#[tokio::test]
async fn partial_tool_block_never_executes() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        data_block(&delta_chunk(json!({
            "tool_calls": [{
                "index": 0,
                "id": "call_1",
                "type": "function",
                "function": {"name": "read_file", "arguments": "{\"path\":"},
            }],
        }))),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: partial tool",
    );

    let (broker, outcome) = dispatch(broker, "/world/local", manifest.clone());
    let error = outcome.expect_err("a truncated stream is never success");
    assert!(
        matches!(
            error,
            ModelError::Provider(ProviderError::UnknownTerminal { .. })
        ),
        "a stream ended without a finish_reason or [DONE] is the unknown terminal: {error}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);
}

/// The stream owes a terminal the dialect can classify: a stream that
/// ends without finish_reason and without `[DONE]`, and a
/// finish_reason the dialect cannot classify, are both unknown —
/// never success.
#[tokio::test]
async fn unknown_mandatory_terminal_is_not_success() {
    let server = MockServer::start().await;

    // a complete content delta, then silence — no finish_reason and
    // no [DONE] ever arrive
    mount_chat(&server, data_block(&delta_chunk(json!({"content": "hi"})))).await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: no terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "EOF without a terminal is the unknown terminal: {outcome:?}"
    );
    drop_blocking(broker);

    // a finish_reason the dialect cannot classify
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&finish_chunk("concluded_by_host")),
            DONE_BLOCK
        ),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: strange terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "an unclassifiable finish_reason is not success: {outcome:?}"
    );
    drop_blocking(broker);
}

/// Streamed `tool_calls` fragments accumulate into typed calls: two
/// sibling calls routed by `index`, a continuation routed by `id`
/// alone, an unkeyed continuation resuming the last-opened block,
/// `function.arguments` fragments concatenated per call, and a `stop`
/// finish with accumulated calls is still the tool outcome — the
/// recorded promotion.
#[tokio::test]
async fn streamed_tool_calls_accumulate_across_chunks() {
    let server = MockServer::start().await;
    let stream = format!(
        "{}{}{}{}{}{}{}",
        data_block(&delta_chunk(json!({
            "tool_calls": [{
                "index": 0, "id": "call_a", "type": "function",
                "function": {"name": "read_file", "arguments": "{\"pa"},
            }],
        }))),
        // a second sibling call interleaved by index — its object stays
        // open for the unkeyed continuation to close
        data_block(&delta_chunk(json!({
            "tool_calls": [{
                "index": 1, "id": "call_b", "type": "function",
                "function": {"name": "read_file", "arguments": "{\"path\": \"b\""},
            }],
        }))),
        // the first call's argument tail continues it by index, leaving
        // a member open for the id-keyed hop
        data_block(&delta_chunk(json!({
            "tool_calls": [{
                "index": 0,
                "function": {"arguments": "th\": \"src/lib.rs\", \"via\":"},
            }],
        }))),
        // an entry keyed by `id` alone routes to its block wherever it
        // sits — only call_a's open member can take this fragment
        data_block(&delta_chunk(json!({
            "tool_calls": [{"id": "call_a", "function": {"arguments": "\"id\"}"}}],
        }))),
        // an unkeyed continuation resumes the last-opened block — its
        // fragment is the closing brace only the sibling still owed, so
        // a wrong route unbalances whichever object it lands on
        data_block(&delta_chunk(json!({
            "tool_calls": [{"function": {"arguments": "}"}}],
        }))),
        data_block(&finish_chunk("stop")),
        DONE_BLOCK
    );
    mount_chat(&server, stream).await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: accumulate calls",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    let reply = outcome.expect("the accumulated calls dispatch");
    assert_eq!(reply.tool_calls.len(), 2);
    assert_eq!(reply.tool_calls[0].tool, "read_file");
    assert_eq!(reply.tool_calls[0].path.as_deref(), Some("src/lib.rs"));
    assert_eq!(reply.tool_calls[1].tool, "read_file");
    assert_eq!(reply.tool_calls[1].path.as_deref(), Some("b"));
    drop_blocking(broker);
}

/// Streamed tool calls stay under their bounds: a stream opening more
/// blocks than the call bound and a single call's `arguments` past the
/// byte bound are both typed violations — denied, never buffered
/// unbounded — and charge nothing. Each fixture stays completable past
/// the bound so only the bound itself can produce the violation.
#[tokio::test]
async fn streamed_tool_call_bounds_are_typed_violations() {
    // the block bound is 32 — the 33rd opened block trips it
    let server = MockServer::start().await;
    mount_chat(
        &server,
        data_block(&delta_chunk(json!({
            "tool_calls": (0..33)
                .map(|index| json!({
                    "index": index,
                    "id": format!("call_{index}"),
                    "type": "function",
                    "function": {"name": "read_file", "arguments": "{}"},
                }))
                .collect::<Vec<_>>(),
        }))),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: call bound",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "a stream over the tool-call bound is a typed violation: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a denied stream charges nothing"
    );
    drop_blocking(broker);

    // the arguments bound is 1 MiB — one fragment past it trips the
    // concatenation even though the completed text stays valid json
    let server = MockServer::start().await;
    mount_chat(
        &server,
        data_block(&delta_chunk(json!({
            "tool_calls": [{
                "index": 0, "id": "call_1", "type": "function",
                "function": {
                    "name": "read_file",
                    "arguments": format!("{{\"path\": \"{}\"}}", "x".repeat(1024 * 1024)),
                },
            }],
        }))),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: args bound",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "a tool_call's arguments over the byte bound is a typed violation: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a denied stream charges nothing"
    );
    drop_blocking(broker);
}

/// Well-formed output the dialect cannot honour is a typed rejection:
/// a tool_call naming a tool the frozen request never declared and a
/// streamed call whose `type` is not the recorded `function` kind —
/// never executed, never accounted.
#[tokio::test]
async fn incompatible_tool_surface_is_a_typed_rejection() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({
                "tool_calls": [{
                    "index": 0, "id": "call_1", "type": "function",
                    "function": {"name": "exec_shell", "arguments": "{\"cmd\": \"ls\"}"},
                }],
            }))),
            data_block(&finish_chunk("tool_calls")),
            DONE_BLOCK
        ),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: undeclared call",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(
                ProviderError::IncompatibleOutput { .. }
            ))
        ),
        "an undeclared tool name is a typed rejection: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a refused send charges nothing"
    );
    drop_blocking(broker);

    // a non-function tool call kind is output the dialect cannot
    // honour — the same typed rejection
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({
                "tool_calls": [{
                    "index": 0, "id": "call_1", "type": "retrieval",
                    "function": {"name": "read_file", "arguments": "{}"},
                }],
            }))),
            data_block(&finish_chunk("tool_calls")),
            DONE_BLOCK
        ),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: foreign tool kind",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(
                ProviderError::IncompatibleOutput { .. }
            ))
        ),
        "a non-function tool kind is a typed rejection: {outcome:?}"
    );
    drop_blocking(broker);

    // a peer name past the reason bound truncates on the boundary —
    // the diagnostic surface never parks a payload
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({
                "tool_calls": [{
                    "index": 0, "id": "call_1", "type": "function",
                    "function": {"name": "x".repeat(2000), "arguments": "{}"},
                }],
            }))),
            data_block(&finish_chunk("tool_calls")),
            DONE_BLOCK
        ),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: oversized name",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
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

/// The remaining terminal and malformed shapes all land as typed
/// rejections: a `content_filter` finish is the peer's refusal verdict
/// even when earlier chunks carried valid tool calls, an in-band
/// `error` chunk is a peer failure, a duplicate finish_reason is a
/// wire violation, a malformed chunk is a violation, an unreadable
/// `usage` violates the contract, and a refused connection is a
/// transport failure.
#[tokio::test]
async fn remaining_terminals_and_malformed_wire_shapes_are_typed() {
    // a content_filter finish is the peer's own refusal verdict — even
    // though an earlier chunk carried a valid tool call
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({
                "tool_calls": [{
                    "index": 0, "id": "call_1", "type": "function",
                    "function": {"name": "read_file", "arguments": "{\"path\": \"src/lib.rs\"}"},
                }],
            }))),
            data_block(&finish_chunk("content_filter")),
            DONE_BLOCK
        ),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: filtered verdict",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::ProviderFailed { .. }))
        ),
        "a content_filter finish is a peer failure, never a tool call: {outcome:?}"
    );
    drop_blocking(broker);

    // an in-band error chunk is the peer's own failure verdict
    let server = MockServer::start().await;
    mount_chat(
        &server,
        data_block(&json!({"error": {"message": "upstream exploded", "code": 500}})),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: in-band error",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::ProviderFailed { .. }))
        ),
        "an in-band error chunk is a peer failure: {outcome:?}"
    );
    drop_blocking(broker);

    // a second finish_reason after a valid terminal is a wire
    // violation — the stream owes exactly one verdict
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({"content": "first"}))),
            data_block(&finish_chunk("stop")),
            data_block(&finish_chunk("content_filter")),
        ),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: duplicate terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
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
    mount_chat(&server, "data: {broken\n\n".to_string()).await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: malformed chunk",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
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
    mount_chat(
        &server,
        completed_stream(
            "counted",
            Some(json!({"prompt_tokens": "many", "completion_tokens": 7, "total_tokens": 7})),
        ),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: unreadable usage",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "an unreadable usage object is a wire violation: {outcome:?}"
    );
    drop_blocking(broker);

    // a refused connection is a transport failure
    let config = Config::parse_validated(&local_config("http://127.0.0.1:1/v1")).expect("valid");
    let (provider, _store) = local_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    assert!(
        matches!(outcome, Err(ProviderError::Transport { .. })),
        "a refused connection is transport: {outcome:?}"
    );
    drop_blocking(provider);
}

/// Every malformed sibling shape lands the typed violation: a
/// non-success listing status, a catalogue payload that is not the
/// `data` listing the contract requires, and the malformed
/// chunk/choice/delta/tool_calls/finish_reason shapes the stream
/// contract rules out.
#[tokio::test]
async fn malformed_wire_shapes_are_typed_violations() {
    // a non-success listing status is a typed transport failure —
    // the peer's own code names it, never the uncontrolled body
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = local_provider(&config);
    let outcome = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("the catalog thread joins");
    assert!(
        matches!(outcome, Err(ProviderError::Transport { .. })),
        "a non-success listing status is a typed transport failure: {outcome:?}"
    );

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
            Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
        let (provider, _store) = local_provider(&config);
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
            "a choices member that is not an array",
            data_block(&json!({"choices": "x"})),
        ),
        (
            "a second choice the request never asked for",
            data_block(&json!({"choices": [{"index": 0, "delta": {}}, {"index": 1, "delta": {}}]})),
        ),
        (
            "a choice that is not an object",
            data_block(&json!({"choices": [5]})),
        ),
        (
            "a choice index other than the requested slot",
            data_block(&json!({"choices": [{"index": 3, "delta": {}}]})),
        ),
        (
            "a non-delta message member on a streamed choice",
            data_block(
                &json!({"choices": [{"index": 0, "message": {"role": "assistant", "content": "x"}}]}),
            ),
        ),
        (
            "a delta that is not an object",
            data_block(&json!({"choices": [{"index": 0, "delta": 5}]})),
        ),
        (
            "a delta role that is not a string",
            data_block(&delta_chunk(json!({"role": 5}))),
        ),
        (
            "a delta content that is not a string",
            data_block(&delta_chunk(json!({"content": 5}))),
        ),
        (
            "a delta refusal that is not a string",
            data_block(&delta_chunk(json!({"refusal": 5}))),
        ),
        (
            "a delta reasoning member that is not a string",
            data_block(&delta_chunk(json!({"reasoning_content": 5}))),
        ),
        (
            "a delta reasoning_details that is not an array",
            data_block(&delta_chunk(json!({"reasoning_details": "x"}))),
        ),
        (
            "a delta tool_calls that is not an array",
            data_block(&delta_chunk(json!({"tool_calls": "x"}))),
        ),
        (
            "a tool_calls entry that is not an object",
            data_block(&delta_chunk(json!({"tool_calls": [5]}))),
        ),
        (
            "a tool_calls index that is not an integer",
            data_block(&delta_chunk(json!({"tool_calls": [{"index": "0"}]}))),
        ),
        (
            "a tool_calls id that is not a string",
            data_block(&delta_chunk(json!({"tool_calls": [{"index": 0, "id": 5}]}))),
        ),
        (
            "a tool_calls entry type that is not a string",
            data_block(&delta_chunk(
                json!({"tool_calls": [{"index": 0, "type": 5}]}),
            )),
        ),
        (
            "a tool_calls function that is not an object",
            data_block(&delta_chunk(
                json!({"tool_calls": [{"index": 0, "function": "x"}]}),
            )),
        ),
        (
            "a function name that is not a string",
            data_block(&delta_chunk(
                json!({"tool_calls": [{"index": 0, "function": {"name": 5}}]}),
            )),
        ),
        (
            "function arguments that are not a streamed string",
            data_block(&delta_chunk(
                json!({"tool_calls": [{"index": 0, "function": {"name": "read_file", "arguments": {"path": "x"}}}]}),
            )),
        ),
        (
            "a finish_reason that is not a string",
            data_block(&json!({"choices": [{"index": 0, "delta": {}, "finish_reason": 5}]})),
        ),
        (
            "an error member that is not an object or string",
            data_block(&json!({"error": 5})),
        ),
        (
            "a tool_calls batch whose entries cannot be routed",
            data_block(&delta_chunk(
                json!({"tool_calls": [{"function": {"arguments": "a"}}, {"function": {"arguments": "b"}}]}),
            )),
        ),
        (
            "a tool_call block that never carried a function name",
            format!(
                "{}{}{}",
                data_block(&delta_chunk(json!({
                    "tool_calls": [{"index": 0, "function": {"arguments": "{}"}}],
                }))),
                data_block(&finish_chunk("stop")),
                DONE_BLOCK
            ),
        ),
        (
            "a tool_call whose arguments never parse",
            format!(
                "{}{}{}",
                data_block(&delta_chunk(json!({
                    "tool_calls": [{"index": 0, "function": {"name": "read_file", "arguments": "{broken"}}],
                }))),
                data_block(&finish_chunk("stop")),
                DONE_BLOCK
            ),
        ),
        (
            "a tool_call whose arguments are not an object",
            format!(
                "{}{}{}",
                data_block(&delta_chunk(json!({
                    "tool_calls": [{"index": 0, "function": {"name": "read_file", "arguments": "[1]"}}],
                }))),
                data_block(&finish_chunk("stop")),
                DONE_BLOCK
            ),
        ),
        (
            "a tool_call block whose name changed mid-stream",
            format!(
                "{}{}{}{}",
                data_block(&delta_chunk(json!({
                    "tool_calls": [{"index": 0, "function": {"name": "read_file"}}],
                }))),
                data_block(&delta_chunk(json!({
                    "tool_calls": [{"index": 0, "function": {"name": "other_tool"}}],
                }))),
                data_block(&finish_chunk("stop")),
                DONE_BLOCK
            ),
        ),
        (
            "a tool_call block whose id changed mid-stream",
            format!(
                "{}{}{}{}",
                data_block(&delta_chunk(json!({
                    "tool_calls": [{"index": 0, "id": "call_a", "function": {"name": "read_file"}}],
                }))),
                data_block(&delta_chunk(json!({
                    "tool_calls": [{"index": 0, "id": "call_b"}],
                }))),
                data_block(&finish_chunk("stop")),
                DONE_BLOCK
            ),
        ),
        (
            "a tool_call id a sibling block already holds",
            format!(
                "{}{}{}{}{}",
                data_block(&delta_chunk(json!({
                    "tool_calls": [{"index": 0, "id": "call_x", "function": {"name": "read_file"}}],
                }))),
                data_block(&delta_chunk(json!({
                    "tool_calls": [{"index": 1, "id": "call_x", "function": {"name": "read_file"}}],
                }))),
                // an id-only continuation would route to the last
                // holder — the duplicate is denied before arguments
                // can land on the wrong block
                data_block(&delta_chunk(json!({
                    "tool_calls": [{"id": "call_x", "function": {"arguments": "{}"}}],
                }))),
                data_block(&finish_chunk("stop")),
                DONE_BLOCK
            ),
        ),
        (
            "a second [DONE] sentinel",
            format!("{}{}", completed_stream("done", None), DONE_BLOCK),
        ),
        (
            "content after the [DONE] sentinel",
            format!(
                "{}{}{}",
                completed_stream("done", None),
                data_block(&delta_chunk(json!({"content": "late"}))),
                DONE_BLOCK
            ),
        ),
    ];
    for (name, body) in legs {
        let server = MockServer::start().await;
        mount_chat(&server, body).await;
        let config =
            Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
        let (broker, manifest) = prepared_with(
            local_provider(&config),
            &config,
            "/world/local",
            "goal: malformed",
        );
        let (broker, outcome) = dispatch(broker, "/world/local", manifest);
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

/// A choice arriving after the declared terminal adopts nothing —
/// a post-finish_reason delta is a typed violation, never content or
/// a tool call — while the recorded `choices:[]` usage tail still
/// lands its charge.
#[tokio::test]
async fn post_terminal_content_is_refused_and_a_usage_tail_still_lands() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&json!({
                "choices": [{"index": 0, "delta": {"content": "done"}, "finish_reason": "stop"}],
            })),
            data_block(&delta_chunk(json!({
                "tool_calls": [{
                    "index": 0, "function": {"name": "read_file", "arguments": "{}"},
                }],
            }))),
            DONE_BLOCK
        ),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: late content",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
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

    // the recorded post-terminal shape — a `choices:[]` usage chunk —
    // lands the stream's charge
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "done",
            Some(json!({"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7})),
        ),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: usage tail",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest.clone());
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

/// Every recorded `finish_reason` maps to its one terminal class:
/// `stop`/`end` complete, `length`/`max_tokens` complete — a truncated
/// answer is a valid charge — `function_call`/`tool_calls` complete
/// with the accumulated calls, the recorded failure set is the peer's
/// own verdict, and anything else is unknown, never success.
#[tokio::test]
async fn every_recorded_finish_reason_maps_to_its_terminal_class() {
    enum Verdict {
        Completed,
        Failed,
        Unknown,
    }
    let legs: Vec<(&str, Verdict)> = vec![
        ("stop", Verdict::Completed),
        ("end", Verdict::Completed),
        ("length", Verdict::Completed),
        ("max_tokens", Verdict::Completed),
        ("function_call", Verdict::Completed),
        ("tool_calls", Verdict::Completed),
        ("content_filter", Verdict::Failed),
        ("network_error", Verdict::Failed),
        ("error", Verdict::Failed),
        ("insufficient_system_resource", Verdict::Failed),
        ("concluded_by_host", Verdict::Unknown),
        ("a_reason_the_dialect_never_recorded", Verdict::Unknown),
    ];
    for (reason, verdict) in legs {
        let server = MockServer::start().await;
        mount_chat(
            &server,
            format!(
                "{}{}{}",
                data_block(&delta_chunk(json!({"content": "done"}))),
                data_block(&finish_chunk(reason)),
                DONE_BLOCK
            ),
        )
        .await;
        let config =
            Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
        let (broker, manifest) = prepared_with(
            local_provider(&config),
            &config,
            "/world/local",
            "goal: finish table",
        );
        let (broker, outcome) = dispatch(broker, "/world/local", manifest);
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

/// The reported token counters are charged verbatim — 11+7 reported
/// as 25 stays 25, never re-summed — while a usage object that
/// withholds a counter is a wire violation, not an estimate.
#[tokio::test]
async fn reported_usage_is_charged_verbatim_and_a_missing_counter_is_a_violation() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verbatim",
            Some(json!({"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 25})),
        ),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: verbatim total",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest.clone());
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
    mount_chat(
        &server,
        completed_stream(
            "no total",
            Some(json!({"prompt_tokens": 11, "completion_tokens": 7})),
        ),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: missing total",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "a withheld counter is a violation, not an estimate: {outcome:?}"
    );
    drop_blocking(broker);
}

/// No `usage` anywhere in the stream is `UsageDelta::Unknown` — the
/// frozen admission bound stays reserved, never released as a
/// fabricated zero.
#[tokio::test]
async fn unknown_usage_never_releases_the_admission_bound() {
    let server = MockServer::start().await;
    mount_chat(&server, completed_stream("unmetered", None)).await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: unknown usage",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest.clone());
    outcome.expect("the unmetered send completes");
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.usage, UsageDelta::Unknown);
    let explain = broker.sent_cost_explain(&manifest);
    assert_eq!(explain.bound, manifest.cost_bound);
    assert_eq!(
        explain.confirmed, None,
        "an unknown cost stays at the bound"
    );
    drop_blocking(broker);
}

/// The recorded close needs exactly one terminal: `[DONE]` alone is
/// the server-agreed stop for hosts that never send a finish_reason,
/// and a declared finish_reason completes at EOF without the sentinel
/// — while EOF with neither stays the unknown terminal.
#[tokio::test]
async fn declared_terminal_or_done_sentinel_closes_the_stream() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}",
            data_block(&delta_chunk(json!({"content": "server closed"}))),
            DONE_BLOCK
        ),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: done only",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    let reply = outcome.expect("[DONE] alone is the server-agreed completion");
    assert_eq!(reply.text, "server closed");
    assert_eq!(reply.usage, UsageDelta::Unknown);
    drop_blocking(broker);

    // a declared finish_reason at EOF — the sentinel never arrives —
    // completes on the recorded verdict alone
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}",
            data_block(&delta_chunk(json!({"content": "declared close"}))),
            data_block(&finish_chunk("stop")),
        ),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: finish only",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    let reply = outcome.expect("a declared terminal completes without the sentinel");
    assert_eq!(reply.text, "declared close");
    drop_blocking(broker);
}

/// The provider's own failure verdict — the stream's `error` member —
/// is a typed peer error, not a parse failure and not success. Its
/// reason is the peer's own prose: a `message` field carrying a nested
/// object is structure, never serialized into the reason, while a
/// scalar `code` still renders — and the flat `{"message": "…"}`
/// shape some hosts send is the same verdict.
#[tokio::test]
async fn provider_reported_failure_is_a_typed_denial() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        data_block(&json!({"error": {"code": 429, "message": "quota exceeded"}})),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: failure",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
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
    mount_chat(
        &server,
        data_block(&json!({"error": {"message": {"nested": "detail"}, "code": "rate_limited"}})),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: structured reason",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    let Err(ModelError::Provider(ProviderError::ProviderFailed { reason, .. })) = outcome else {
        panic!("the structured error payload is a peer failure: {outcome:?}")
    };
    assert_eq!(reason, "rate_limited");
    drop_blocking(broker);

    // a scalar code still renders as the reason
    let server = MockServer::start().await;
    mount_chat(&server, data_block(&json!({"error": {"code": 503}}))).await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: scalar reason",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    let Err(ModelError::Provider(ProviderError::ProviderFailed { reason, .. })) = outcome else {
        panic!("the coded error payload is a peer failure: {outcome:?}")
    };
    assert_eq!(reason, "503");
    drop_blocking(broker);

    // the flat `{"message": "…"}` error shape is the same verdict
    let server = MockServer::start().await;
    mount_chat(&server, data_block(&json!({"message": "model not loaded"}))).await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: flat error",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    let Err(ModelError::Provider(ProviderError::ProviderFailed { reason, .. })) = outcome else {
        panic!("the flat error payload is a peer failure: {outcome:?}")
    };
    assert_eq!(reason, "model not loaded");
    drop_blocking(broker);

    // an `error` member carrying a bare string is the same verdict —
    // the string is the reason verbatim
    let server = MockServer::start().await;
    mount_chat(&server, data_block(&json!({"error": "boom"}))).await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: string error",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    let Err(ModelError::Provider(ProviderError::ProviderFailed { reason, .. })) = outcome else {
        panic!("the string error payload is a peer failure: {outcome:?}")
    };
    assert_eq!(reason, "boom");
    drop_blocking(broker);

    // a payload-length peer reason is bounded: the cap lands on a UTF-8
    // char boundary, so '€' (3 bytes) cuts at 1023, never mid-codepoint
    let server = MockServer::start().await;
    mount_chat(
        &server,
        data_block(&json!({"error": {"message": "€".repeat(400)}})),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: oversized reason",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
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

/// The recorded `if (data.error)` / `if (data.message)` guards treat a
/// falsy member as absent: `{"error": false}`, `{"error": 0}`,
/// `{"error": ""}` and `{"message": null}` carry no verdict — the
/// stream runs on to its terminal untouched.
#[tokio::test]
async fn falsy_error_and_message_members_carry_no_verdict() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}{}{}{}{}",
            data_block(&json!({"error": false})),
            data_block(&json!({"error": 0})),
            data_block(&json!({"error": ""})),
            data_block(&json!({"message": null})),
            data_block(&delta_chunk(json!({"content": "carried"}))),
            data_block(&finish_chunk("stop")),
            DONE_BLOCK
        ),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: falsy members",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    let reply = outcome.expect("falsy verdict members are ignored");
    assert_eq!(reply.text, "carried");
    drop_blocking(broker);
}

/// Thinking surface is model-internal: `reasoning_content`,
/// `reasoning`/`reasoning_text` and `refusal` deltas are consumed as
/// progress but never join the visible answer, and `reasoning_details`
/// carries no replay contract in this dialect — observed, never
/// adopted.
#[tokio::test]
async fn reasoning_and_refusal_deltas_never_join_the_answer() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}{}",
            data_block(&delta_chunk(json!({
                "reasoning_content": "internal chain of thought",
            }))),
            data_block(&delta_chunk(json!({
                "reasoning": "more thinking",
                "reasoning_text": "still thinking",
                "reasoning_details": [{"type": "reasoning.encrypted", "id": "x", "data": "blob"}],
                "refusal": "cannot help",
            }))),
            data_block(&delta_chunk(json!({"content": "visible answer"}))),
            data_block(&finish_chunk("stop")),
        ),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: thinking surface",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    let reply = outcome.expect("the thinking-and-answer reply dispatches");
    assert_eq!(
        reply.text, "visible answer",
        "reasoning and refusal surface never enters the visible answer"
    );
    assert!(reply.tool_calls.is_empty());
    drop_blocking(broker);
}

/// The legs matrix enforces the recorded expected set for
/// `custom-chat-completions`: CATALOG, AUTH, WIRE and RECOVERY each
/// execute and report inside this run, and INSTALLED reports NOT_RUN —
/// an omitted leg fails the suite rather than silently absenting.
#[tokio::test]
async fn provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "fixture-chat-model"})]).await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");

    // CATALOG: the endpoint's own listing answers through the
    // credential seam — the seeded store admits the lookup.
    let (provider, _) = local_provider(&config);
    let catalog = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("catalog thread joins");
    reported.insert(
        "CATALOG",
        if matches!(catalog, Ok(ref models) if model_ids(models) == ["fixture-chat-model"]) {
            "PASS"
        } else {
            "FAIL"
        },
    );

    // AUTH: an empty store denies at send with the typed verdict.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), CONNECTION.to_string(), empty).expect("binding resolves");
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
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
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
        provider_result(config.clone(), CONNECTION.to_string(), empty.clone()).expect("resolves");
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

    // The literal row mirrors the `#[ignore]`d
    // `provider_installed_custom_chat_completions` case below: its
    // ignored count is the explicit NOT_RUN signal this matrix asserts
    // — the row stays a literal so the two cannot drift.
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

// ----- TP-PROVIDER-INSTALLED::custom-chat-completions ----------------

/// TP-PROVIDER-INSTALLED::custom-chat-completions = NOT_RUN: the
/// installed-provider proof is a live-environment leg this offline
/// slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::custom-chat-completions = NOT_RUN"]
fn provider_installed_custom_chat_completions() {}

// ----- abliteration -----------------------------------------------------
//
// The `abliteration` connection's proof legs (HZN-008 class A): the
// shared Responses adapter serves the literal id — no copied codec —
// under the connection's own recorded predicates. `/models` is
// authoritative, with the static source seed merging on top as the
// offer floor (its recorded rationale — offering models before a live
// key exists — stays upstream's); every offered model is
// reasoning-forced (the recorded
// mapper marks even unseeded ids `reasoning: true`), so a pinned
// effort rides the reasoning surface on any catalogue id; and the
// recorded peer compat marks the gateway as never returning encrypted
// reasoning items (`include-encrypted-reasoning #false`), so the
// replay include is never requested.

/// The scoped credential ref the `abliteration` connection binds.
const ABLITERATION_REF: &str = "keyring:rivect-test/abliteration";

/// The pinned model id the fixed-pin `abliteration` legs carry — one
/// of the recorded static-seed ids (HZN-008).
const ABLITERATION_MODEL: &str = "abliterated-model";

/// One configured `abliteration` connection pointing at the fixture
/// peer: the api_key auth class resolves a scoped `SecretRef`
/// (DEC-011), the dialect comes from the literal connection id
/// (DEC-007), and the endpoint carries the API base's `/v1` segment
/// verbatim — like the recorded default `api.abliteration.ai/v1`.
fn abliteration_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.abliteration]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{ABLITERATION_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"abliteration\", model_id = \"{ABLITERATION_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The same construction seam as `provider_result`, over the shared
/// Responses adapter: reqwest's blocking client still builds on a
/// plain OS thread, and the literal id decides the dialect.
fn abliteration_provider_result(
    config: Config,
    connection: String,
    store: Arc<support::MapStore>,
) -> Result<OpenAiProvider, ProviderError> {
    std::thread::spawn(move || OpenAiProvider::new(&config, &connection, store))
        .join()
        .expect("the provider thread joins")
}

fn abliteration_provider(config: &Config) -> (OpenAiProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(ABLITERATION_REF, SECRET)],
    ));
    let provider =
        abliteration_provider_result(config.clone(), "abliteration".to_string(), store.clone())
            .expect("the shared adapter builds for the abliteration id");
    (provider, store)
}

// ----- TP-PROVIDER-WIRE::abliteration ----------------------------------

/// A configured `abliteration` connection returns a verified model
/// outcome through the standard Broker: prepare admits the api_key
/// pin under DEC-011, the shared adapter posts exactly the frozen
/// manifest as a Responses request — `store: false`, `stream: true`,
/// pinned model, instructions, tool surface and pinned effort
/// verbatim, and no `include` member, since the recorded peer compat
/// marks the gateway as never returning encrypted reasoning items —
/// the SSE stream validates its terminal, and the one physical send
/// is charged once with the provider's reported usage.
#[tokio::test]
async fn abliteration_valid_control_yields_one_outcome_and_one_physical_usage() {
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
    let config =
        Config::parse_validated(&abliteration_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        abliteration_provider(&config),
        &config,
        "/world/abliteration",
        "goal: prove the wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/abliteration", manifest.clone());
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
    assert_eq!(
        requests[0]
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json"),
        "the body rides the recorded json content type"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(SECRET),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], ABLITERATION_MODEL);
    assert_eq!(body["store"], false);
    assert_eq!(body["stream"], true);
    assert!(
        body.get("include").is_none(),
        "the recorded gateway never returns encrypted reasoning items — the artifact include is never requested: {body}"
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
    // report — the provider's 18 tokens are the confirmed charge, and
    // a replayed attempt reports spent.
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "abliteration");
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
            let replay = broker.dispatch(
                &mut rivect::model::NullLedger,
                "/world/abliteration",
                &manifest,
            );
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
/// label: an id without the recorded Responses class builds no
/// adapter, a manifest pinning a different connection id is refused
/// at send, and `dialect_for` reserving `abliteration` means the id
/// is never fixture-served even when it declares `local` kind.
#[test]
fn abliteration_dialect_is_keyed_on_the_literal_connection_id() {
    let config =
        Config::parse_validated(&abliteration_config("http://127.0.0.1:1/v1")).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = abliteration_provider_result(config.clone(), "abliteration-pro".to_string(), store)
        .expect_err("a different literal id is not this dialect");
    assert!(matches!(err, ProviderError::DialectMismatch { .. }));

    // a dialect-reserved id is never fixture-served whatever kind it
    // declares — `abliteration` pinned `local` keeps the typed denial
    let local = Config::parse_validated(
        "config_version = 1\n\
         [connections.abliteration]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"abliteration\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"medium\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let loopback = rivect::providers::LoopbackProvider::new();
    let entry = local.connections.get("abliteration").expect("declared");
    assert!(
        !loopback.serves("abliteration", entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );

    // a manifest pinning a different connection id is refused at send
    let (provider, _store) = abliteration_provider(&config);
    let foreign = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.other]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1/v1\"\ncredential_ref = \"{ABLITERATION_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"other\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let manifest = {
        let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
        broker
            .prepare("main", &foreign, "/world/abliteration", "goal: x")
            .expect("foreign pin prepares")
    };
    let (provider, outcome) = send_on_thread(provider, manifest);
    assert!(
        matches!(outcome, Err(ProviderError::DialectMismatch { .. })),
        "a foreign pin never speaks this dialect: {outcome:?}"
    );
    drop_blocking(provider);
}

// ----- TP-PROVIDER-CATALOG::abliteration -------------------------------

/// `GET /models` is authoritative for `abliteration` (HZN-008): every
/// `data[]` id with a non-empty body is offered — never filtered
/// to a sample — the recorded static seed merges on top as the offer
/// floor (its recorded rationale — offering models before a live key
/// exists — stays upstream's), the union deduplicates and sorts, and
/// the bearer credential came through the store seam.
#[tokio::test]
async fn abliteration_catalog_is_the_authoritative_listing_over_the_static_seed() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "unseeded-future-model"}),
            // a seed id already listed deduplicates rather than doubling
            json!({"id": "abliterated-model-large"}),
            json!({"id": ""}),
            json!({"owned_by": "nobody"}),
        ],
    )
    .await;
    let config =
        Config::parse_validated(&abliteration_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = abliteration_provider(&config);
    let ids = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("the catalog thread joins")
        .expect("the catalog answers");
    assert_eq!(
        ids,
        vec![
            "abliterated-model".to_string(),
            "abliterated-model-large".to_string(),
            "abliterated-model-large-v2".to_string(),
            "unseeded-future-model".to_string(),
        ],
        "the authoritative listing and the static seed merge, sorted and deduplicated"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(received_auth(&requests[0]), format!("Bearer {SECRET}"));
}

/// The recorded `abliteration` reasoning predicates bind from the
/// catalogue through the dispatch to the wire: every offered model —
/// a static-seed id or an id only `/models` ever named — is
/// reasoning-forced (the recorded mapper marks even unseeded ids
/// `reasoning: true`), so a pinned effort rides the reasoning
/// surface verbatim on any of them, and because the recorded peer
/// compat marks the gateway as never returning encrypted reasoning
/// items (`include-encrypted-reasoning #false`), no `include` member
/// is emitted. The dialect's other recorded id keeps its own
/// predicates — the suppression binds the literal `abliteration` id,
/// never the shared Responses dialect.
#[tokio::test]
async fn abliteration_forced_reasoning_models_are_bound_to_their_source_predicates() {
    // Catalogue → dispatch: an auto-ranked send's catalogue leg
    // resolves the wire model. The discovered id sorts before the
    // static seed, so it is the pick — and being reasoning-forced is
    // a model predicate, not a seed membership, so the discovered id
    // still carries the effort dial while the artifact include stays
    // off.
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "a-unseeded-model"})]).await;
    mount_responses(
        &server,
        responses_completed_stream("forced", Vec::new(), None),
    )
    .await;
    let auto = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.abliteration]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{ABLITERATION_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"fixed\", value = \"high\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let (broker, manifest) = prepared_with(
        abliteration_provider(&auto),
        &auto,
        "/world/abliteration",
        "goal: forced reasoning",
    );
    let (broker, outcome) = dispatch(broker, "/world/abliteration", manifest);
    outcome.expect("the auto send resolves through the catalogue");
    drop_blocking(broker);
    let requests = server.received_requests().await.expect("recorded");
    let send = requests
        .iter()
        .find(|request| request.url.path() == "/v1/responses")
        .expect("the send crossed the wire");
    let body: Value = serde_json::from_slice(&send.body).expect("json body");
    assert_eq!(
        body["model"], "a-unseeded-model",
        "the discovered id the catalogue offered rides the wire"
    );
    assert_eq!(
        body["reasoning"],
        json!({"effort": "high"}),
        "an unseeded model still carries the reasoning dial — the forced predicate is not seed-bound"
    );
    assert!(
        body.get("include").is_none(),
        "the recorded peer never returns encrypted reasoning items: {body}"
    );

    // A fixed pin on a static-seed id carries the same surface, and
    // an unpinned effort declares no level — reasoning stays
    // intrinsic to the model, the wire asks for nothing extra.
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream("seeded", Vec::new(), None),
    )
    .await;
    let config =
        Config::parse_validated(&abliteration_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = abliteration_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    outcome.expect("the seed-pin send completes");
    let mut unpinned = prepared_manifest(&config);
    unpinned.effort = rivect::config::EffortAssign::Auto;
    let (provider, outcome) = send_on_thread(provider, unpinned);
    outcome.expect("the unpinned send completes");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 2, "the two fixture sends");
    let pinned: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(pinned["model"], ABLITERATION_MODEL);
    assert_eq!(
        pinned["reasoning"],
        json!({"effort": "medium"}),
        "the pinned effort rides the reasoning surface verbatim"
    );
    assert!(pinned.get("include").is_none());
    let bare: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert!(
        bare.get("reasoning").is_none(),
        "an unpinned effort declares no level — the wire injects none: {bare}"
    );
    assert!(bare.get("include").is_none());

    // The non-forced arm: `openai` keeps its own recorded predicates —
    // the suppression binds the literal `abliteration` id, never the
    // shared dialect.
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream("openai", Vec::new(), None),
    )
    .await;
    let openai = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.openai]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{ABLITERATION_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"openai\", model_id = \"gpt-5.2\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(ABLITERATION_REF, SECRET)],
    ));
    let provider = abliteration_provider_result(openai.clone(), "openai".to_string(), store)
        .expect("the shared adapter builds for openai too");
    let manifest = {
        let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
        broker
            .prepare("main", &openai, "/world/abliteration", "goal: openai arm")
            .expect("the openai pin prepares")
    };
    let (provider, outcome) = send_on_thread(provider, manifest);
    outcome.expect("the openai send completes");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["include"],
        json!(["reasoning.encrypted_content"]),
        "the artifact include stays on for the dialect's other id — the predicate binds the literal id"
    );
}

/// A `response.completed` carrying a blobless reasoning item next to
/// the message is the recorded peer's normal shape: the send verifies
/// with its exact text and one usage record, and the item is never
/// adopted into the lineage — a follow-up send under the same epoch
/// replays the message item but carries no `type:"reasoning"` input
/// item.
#[tokio::test]
async fn abliteration_blobless_reasoning_item_is_dropped_from_the_replay() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "reasoned answer",
            vec![json!({"id": "rs_1", "type": "reasoning", "summary": []})],
            Some(json!({"input_tokens": 3, "output_tokens": 2, "total_tokens": 5})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&abliteration_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = abliteration_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let first = broker
        .prepare("main", &config, "/world/abliteration", "goal: first turn")
        .expect("prepare turn 1");
    let (broker, outcome) = dispatch(broker, "/world/abliteration", first);
    let reply = outcome.expect("a blobless reasoning item is the peer's normal shape");
    assert_eq!(reply.text, "reasoned answer");
    assert!(reply.tool_calls.is_empty());
    assert_eq!(
        broker.accounted_requests(),
        1,
        "the one send is charged once"
    );
    let mut broker = broker;

    // Same epoch: turn 2's replayed input carries the adopted message
    // item ahead of the new user item — the dropped reasoning item is
    // absent from the wire.
    let second = broker
        .prepare("main", &config, "/world/abliteration", "goal: second turn")
        .expect("prepare turn 2 — same epoch");
    let (broker, outcome) = dispatch(broker, "/world/abliteration", second.clone());
    outcome.expect("turn 2 completes");
    assert_eq!(broker.accounted_requests(), 2);
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 2, "two physical sends");
    let replayed: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert_eq!(
        replayed["input"],
        json!([
            {
                "id": "msg_1", "type": "message", "status": "completed", "role": "assistant",
                "content": [{ "type": "output_text", "text": "reasoned answer" }],
            },
            {
                "role": "user",
                "content": [{ "type": "input_text", "text": second.inputs }],
            }
        ]),
        "the blobless reasoning item never joined the lineage — the replay carries only the adopted message item"
    );
}

/// The recorded compat's `stream-idle-timeout-ms 0` holds by
/// construction: the read loop runs no per-read idle watchdog, so a
/// peer answering in spaced fragments — each gap a real idle stretch
/// like a long reasoning turn — still completes under the one
/// whole-call deadline instead of tripping an idle denial.
#[tokio::test]
async fn abliteration_stream_gaps_inside_the_deadline_still_complete() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("address");
    let body = responses_completed_stream(
        "paced answer",
        Vec::new(),
        Some(json!({"input_tokens": 1, "output_tokens": 1, "total_tokens": 2})),
    );
    // serve every connection the transport opens the same spaced
    // fragments — a reset or retried leg gets the same answer — until
    // the test releases the flag and the thread joins
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = stop.clone();
    let peer = std::thread::spawn(move || {
        while !flag.load(std::sync::atomic::Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // drain the request before answering: closing a
                    // socket that still holds unread request bytes
                    // RSTs the connection and can race the reply out
                    // of the client's buffer
                    if stream
                        .set_read_timeout(Some(Duration::from_millis(150)))
                        .is_ok()
                    {
                        let mut sink = [0u8; 8192];
                        while matches!(stream.read(&mut sink), Ok(read) if read > 0) {}
                    }
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    for piece in body.as_bytes().chunks(64) {
                        if stream.write_all(piece).is_err()
                            || flag.load(std::sync::atomic::Ordering::Relaxed)
                        {
                            break;
                        }
                        // the real gap between fragments — the idle
                        // stretch a per-read watchdog would trip on
                        std::thread::sleep(Duration::from_millis(60));
                    }
                }
                Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    let endpoint = format!("http://{address}/v1");
    let config = Config::parse_validated(&abliteration_config(&endpoint)).expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(ABLITERATION_REF, SECRET)],
    ));
    let built = config.clone();
    let provider = std::thread::spawn(move || {
        OpenAiProvider::with_deadline(&built, "abliteration", store, Duration::from_millis(1500))
    })
    .join()
    .expect("the provider thread joins")
    .expect("the adapter builds");

    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let reply = outcome.expect("idle gaps inside the whole-call deadline still complete");
    assert_eq!(reply.text, "paced answer");
    drop_blocking(provider);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    peer.join().expect("the peer thread joins");
}

// ----- TP-PROVIDER-AUTH::abliteration ----------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `abliteration`: a configured region — the recorded contract names
/// none, so global data placement is never asserted — the
/// profile-bound ref whose scope disagrees with the binding, an
/// absent credential and a refused bearer token each land a typed
/// denial, and none of them, nor any Debug surface the boundary
/// exposes, renders credential material or the peer's body.
#[tokio::test]
async fn abliteration_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets()
{
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(&abliteration_config(&server_uri_v1(&server)).replace(
        "kind = \"api_key\"",
        "kind = \"api_key\"\nregion = \"eu-1\"",
    ))
    .expect("valid");
    let err = abliteration_provider_result(
        regioned,
        "abliteration".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, SECRET)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "abliteration");
    assert_eq!(region, "eu-1");
    assert_no_secret_or_body(&err, SECRET.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.abliteration]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"abliteration\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = abliteration_provider_result(
        mismatched,
        "abliteration".to_string(),
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
    assert_no_secret_or_body(&err, SECRET.as_bytes());

    // a bound ref with no material at its own scope — the sibling
    // scope's material stays sealed behind the typed denial
    let config =
        Config::parse_validated(&abliteration_config(&server_uri_v1(&server))).expect("valid");
    let provider = abliteration_provider_result(
        config.clone(),
        "abliteration".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, SECRET)],
        )),
    )
    .expect("binding resolves; the store is read at send");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("no material at the scope is the typed denial");
    assert!(matches!(err, ProviderError::CredentialAbsent { .. }));
    assert_no_secret_or_body(&err, SECRET.as_bytes());
    drop_blocking(provider);

    // a refused bearer token is a typed transport denial — the wire
    // never coerces a wrong credential into success, and the peer's
    // body never enters the error
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(ABLITERATION_REF, SECRET)],
    ));
    let provider = abliteration_provider_result(config.clone(), "abliteration".to_string(), store)
        .expect("builds");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused token is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused token is transport: {err}")
    };
    assert_eq!(connection, "abliteration");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, SECRET.as_bytes());
    drop_blocking(provider);

    // The same boundary on the Debug surfaces the dispatch path
    // exposes: provider, manifest, accounting record, broker and
    // runtime each render without the material the store alone holds.
    let server = MockServer::start().await;
    let config =
        Config::parse_validated(&abliteration_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(ABLITERATION_REF, SECRET)],
    ));
    let provider = abliteration_provider_result(config.clone(), "abliteration".to_string(), store)
        .expect("the adapter builds");
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
    let (broker, manifest) = prepared_with(
        abliteration_provider(&config),
        &config,
        "/world/abliteration",
        "goal: debug surfaces",
    );
    assert!(
        !format!("{manifest:?}").contains(SECRET),
        "manifest Debug never carries credential material"
    );
    let (broker, outcome) = dispatch(broker, "/world/abliteration", manifest.clone());
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
        "auth-debug-abliteration",
        Some(&abliteration_config(&server_uri_v1(&server))),
    );
    assert!(
        !format!("{:?}", world.runtime).contains(SECRET),
        "runtime Debug never carries credential material"
    );
}

// ----- TP-PROVIDER-RECOVERY::abliteration ------------------------------

/// A typed denial is recoverable through the same seam: the absent
/// credential denies the first send, enrolling material at the scope
/// admits the retry — no state wedged, no plaintext path taken.
#[tokio::test]
async fn abliteration_typed_denial_recovers_through_the_same_credential_seam() {
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
    let config =
        Config::parse_validated(&abliteration_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        abliteration_provider_result(config.clone(), "abliteration".to_string(), store.clone())
            .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialAbsent { .. })
    ));

    store.enroll(ABLITERATION_REF, SECRET.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the enrolled credential admits the retry");
    assert_eq!(reply.text, "recovered");
    drop_blocking(provider);
}

/// The failure legs never produce a false success or a usage record:
/// a stream ending mid `function_call` item is a partial-tool
/// violation, an EOF without a terminal is the unknown terminal, a
/// `function_call` naming a tool the frozen request never declared is
/// incompatible output, and a reasoning item carrying
/// `encrypted_content` is the provenance denial — the recorded
/// gateway never returns encrypted reasoning items, so any present
/// member, whatever its value, is off-contract foreign material. The
/// peer's normal blobless
/// reasoning item is not a failure leg at all: it is tolerated —
/// dropped from the lineage, the reply unaffected, the one send
/// charged once.
#[tokio::test]
async fn abliteration_stream_rejections_stay_typed_and_charge_nothing() {
    // a stream ended mid `function_call` item — a partial tool call
    // is never a usable one
    let server = MockServer::start().await;
    mount_responses(
        &server,
        sse_block(
            "response.output_item.added",
            &json!({"item": {"id": "call_1", "type": "function_call", "status": "in_progress", "name": "read_file", "arguments": ""}, "output_index": 0}),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&abliteration_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        abliteration_provider(&config),
        &config,
        "/world/abliteration",
        "goal: partial item",
    );
    let (broker, outcome) = dispatch(broker, "/world/abliteration", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "a stream ended mid output item is a typed violation: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a denied stream charges nothing"
    );
    drop_blocking(broker);

    // a stream that ends without a terminal event is the unknown
    // terminal — never success
    let server = MockServer::start().await;
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
    let config =
        Config::parse_validated(&abliteration_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        abliteration_provider(&config),
        &config,
        "/world/abliteration",
        "goal: no terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/abliteration", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "EOF without a terminal is the unknown terminal: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    // a completed `function_call` naming a tool the frozen request
    // never declared is incompatible output — never executed
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "ignored",
            vec![json!({
                "id": "call_1", "type": "function_call", "status": "completed",
                "name": "exec_shell", "arguments": "{}",
            })],
            None,
        ),
    )
    .await;
    let config =
        Config::parse_validated(&abliteration_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        abliteration_provider(&config),
        &config,
        "/world/abliteration",
        "goal: undeclared call",
    );
    let (broker, outcome) = dispatch(broker, "/world/abliteration", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(
                ProviderError::IncompatibleOutput { .. }
            ))
        ),
        "an undeclared tool name is a typed rejection: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    // a blobless reasoning item is the recorded peer's normal shape —
    // every model reasons intrinsically and none returns the artifact:
    // the item is tolerated — dropped from the lineage rather than
    // adopted — the reply is unaffected and the one send charges once
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "answered",
            vec![json!({"id": "rs_1", "type": "reasoning", "summary": []})],
            Some(json!({"input_tokens": 2, "output_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&abliteration_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        abliteration_provider(&config),
        &config,
        "/world/abliteration",
        "goal: blobless reasoning",
    );
    let (broker, outcome) = dispatch(broker, "/world/abliteration", manifest);
    let reply = outcome.expect("a blobless reasoning item is the peer's normal shape");
    assert_eq!(reply.text, "answered");
    assert!(reply.tool_calls.is_empty());
    assert_eq!(
        broker.accounted_requests(),
        1,
        "the tolerated item still charges the one send"
    );
    drop_blocking(broker);

    // a reasoning item carrying `encrypted_content` is off-contract
    // foreign material where the recorded peer never returns one —
    // the DEC-012 provenance denial, refused and never adopted
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "ignored",
            vec![json!({"id": "rs_1", "type": "reasoning", "summary": [], "encrypted_content": "enc-foreign-blob"})],
            None,
        ),
    )
    .await;
    let config =
        Config::parse_validated(&abliteration_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        abliteration_provider(&config),
        &config,
        "/world/abliteration",
        "goal: foreign artifact",
    );
    let (broker, outcome) = dispatch(broker, "/world/abliteration", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(
                ProviderError::ReasoningProvenance { .. }
            ))
        ),
        "a reasoning item carrying an artifact the peer never returns is the provenance denial: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    // the denial keys on the member's presence, not its value —
    // upstream types `encrypted_content` `string | null`, and a
    // carried `null` is the same off-contract foreign material,
    // never a tolerated blobless shape
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "ignored",
            vec![json!({"id": "rs_1", "type": "reasoning", "summary": [], "encrypted_content": null})],
            None,
        ),
    )
    .await;
    let config =
        Config::parse_validated(&abliteration_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        abliteration_provider(&config),
        &config,
        "/world/abliteration",
        "goal: null artifact member",
    );
    let (broker, outcome) = dispatch(broker, "/world/abliteration", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(
                ProviderError::ReasoningProvenance { .. }
            ))
        ),
        "a reasoning item carrying `encrypted_content: null` is still the provenance denial: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    // a non-string `encrypted_content` is equally present — the
    // member exists off-contract, so the denial never waits on the
    // value parsing as a string
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "ignored",
            vec![
                json!({"id": "rs_1", "type": "reasoning", "summary": [], "encrypted_content": 42}),
            ],
            None,
        ),
    )
    .await;
    let config =
        Config::parse_validated(&abliteration_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        abliteration_provider(&config),
        &config,
        "/world/abliteration",
        "goal: non-string artifact member",
    );
    let (broker, outcome) = dispatch(broker, "/world/abliteration", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(
                ProviderError::ReasoningProvenance { .. }
            ))
        ),
        "a reasoning item carrying a non-string `encrypted_content` is still the provenance denial: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);
}

/// The legs matrix enforces the recorded expected set for
/// `abliteration`: CATALOG, AUTH, WIRE and RECOVERY each execute and
/// report inside this run, and INSTALLED reports NOT_RUN — an
/// omitted leg fails the suite rather than silently absenting.
#[tokio::test]
async fn abliteration_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "abliterated-model"})]).await;
    mount_responses(
        &server,
        responses_completed_stream(
            "matrix",
            Vec::new(),
            Some(json!({"input_tokens": 1, "output_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&abliteration_config(&server_uri_v1(&server))).expect("valid");

    // CATALOG: the authoritative listing plus the static seed answer
    // through the credential seam.
    let (provider, _) = abliteration_provider(&config);
    let catalog = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("catalog thread joins");
    reported.insert(
        "CATALOG",
        if matches!(catalog, Ok(ref ids) if ids == &[
            "abliterated-model".to_string(),
            "abliterated-model-large".to_string(),
            "abliterated-model-large-v2".to_string(),
        ]) {
            "PASS"
        } else {
            "FAIL"
        },
    );

    // AUTH: an empty store denies at send with the typed verdict.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = abliteration_provider_result(config.clone(), "abliteration".to_string(), empty)
        .expect("binding resolves");
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
    let (broker, manifest) = prepared_with(
        abliteration_provider(&config),
        &config,
        "/world/abliteration",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/abliteration", manifest);
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
        abliteration_provider_result(config.clone(), "abliteration".to_string(), empty.clone())
            .expect("resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(ABLITERATION_REF, SECRET.as_bytes());
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

    // The literal row mirrors the `#[ignore]`d
    // `provider_installed_abliteration` case below: its ignored count
    // is the explicit NOT_RUN signal this matrix asserts — the row
    // stays a literal so the two cannot drift.
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

// ----- TP-PROVIDER-INSTALLED::abliteration ----------------------------

/// TP-PROVIDER-INSTALLED::abliteration = NOT_RUN: the
/// installed-provider proof is a live-environment leg this offline
/// slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::abliteration = NOT_RUN"]
fn provider_installed_abliteration() {}

// ----- aiand ---------------------------------------------------------------
//
// The `aiand` connection's proof legs (HZN-008 class A): the shared
// Chat Completions adapter serves the literal id — no copied codec —
// under the connection's own recorded predicates. The configured
// endpoint normalizes onto the recorded `/v1` API root
// (`normalizeAiandBaseUrl`: a bare configured base gains the `/v1`
// tail, an empty one resolves to `api.aiand.com/v1`); the org-scoped
// `/models` listing is authoritative, with the recorded static seed
// merging on top as the offer floor (its recorded rationale —
// offering models before a live key exists — stays upstream's, while
// the listing alone states a model's metadata); and every listed
// entry runs the recorded capability/effort/currency transform — a
// model whose stated price carries an unrecognized or missing
// billing currency stays `ModelPrice::Unknown`, never a coerced
// zero, never a silent USD default.

/// The scoped credential ref the `aiand` connection binds.
const AIAND_REF: &str = "keyring:rivect-test/aiand";

/// The pinned model id the fixed-pin `aiand` legs carry — the
/// recorded `defaultModel` of the bundled static seed.
const AIAND_MODEL: &str = "moonshotai/kimi-k2.7-code";

/// The recorded static-seed ids in catalogue order — the sorted
/// union the offer floor contributes.
const AIAND_SEED_IDS: [&str; 9] = [
    "deepseek-ai/deepseek-v4-flash",
    "deepseek-ai/deepseek-v4-pro",
    "google/gemma-4-31b-it",
    "moonshotai/kimi-k2.6",
    "moonshotai/kimi-k2.7-code",
    "openai/gpt-oss-120b",
    "qwen/qwen3.6-27b",
    "zai-org/glm-5.1",
    "zai-org/glm-5.2",
];

/// One configured `aiand` connection pointing at the fixture peer:
/// the api_key auth class resolves a scoped `SecretRef` (DEC-011),
/// the dialect comes from the literal connection id (DEC-007), and
/// the endpoint carries the API base's `/v1` segment verbatim — like
/// the recorded default `api.aiand.com/v1`.
fn aiand_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.aiand]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{AIAND_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"aiand\", model_id = \"{AIAND_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The same construction seam as `provider_result`, over the shared
/// Chat Completions adapter: reqwest's blocking client still builds
/// on a plain OS thread, and the literal id decides the dialect.
fn aiand_provider_result(
    config: Config,
    connection: String,
    store: Arc<support::MapStore>,
) -> Result<ChatCompletionsProvider, ProviderError> {
    std::thread::spawn(move || ChatCompletionsProvider::new(&config, &connection, store))
        .join()
        .expect("the provider thread joins")
}

fn aiand_provider(config: &Config) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(AIAND_REF, SECRET)],
    ));
    let provider = aiand_provider_result(config.clone(), "aiand".to_string(), store.clone())
        .expect("the shared adapter builds for the aiand id");
    (provider, store)
}

// ----- TP-PROVIDER-WIRE::aiand ---------------------------------------------

/// A configured `aiand` connection returns a verified model outcome
/// through the standard Broker: prepare admits the api_key pin under
/// DEC-011, the shared adapter posts exactly the frozen manifest as a
/// `chat/completions` request — pinned model, system+user messages,
/// `stream` with `stream_options.include_usage`, the declared tool
/// surface as function tools and the pinned effort as
/// `reasoning_effort` verbatim — the SSE stream validates its
/// finish_reason/`[DONE]` terminal, and the one physical send is
/// charged once with the provider's reported usage.
#[tokio::test]
async fn aiand_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified outcome text",
            Some(json!({"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18})),
        ),
    )
    .await;
    let config = Config::parse_validated(&aiand_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        aiand_provider(&config),
        &config,
        "/world/aiand",
        "goal: prove the wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/aiand", manifest.clone());
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
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(SECRET),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], json!(AIAND_MODEL));
    assert_eq!(
        body["messages"],
        json!([
            {"role": "system", "content": manifest.instructions},
            {"role": "user", "content": manifest.inputs},
        ]),
        "the frozen instructions and inputs ride the messages verbatim"
    );
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["stream_options"],
        json!({"include_usage": true}),
        "the recorded usage request rides the stream options"
    );
    assert_eq!(
        body["reasoning_effort"],
        json!("medium"),
        "the pinned effort rides the recorded reasoning_effort surface"
    );

    // Exactly one accounting record carries the one physical usage
    // report — the provider's 18 tokens are the confirmed charge, and
    // a replayed attempt reports spent.
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "aiand");
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
            let replay = broker.dispatch(&mut rivect::model::NullLedger, "/world/aiand", &manifest);
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
/// label: an id without the recorded Chat Completions class builds no
/// adapter — a Chat-Completions-classed id is reserved for its own
/// named contract arm — `dialect_for` reserving `aiand` means the id
/// is never fixture-served even when it declares `local` kind, and a
/// manifest pinning a different connection id is refused at send.
#[test]
fn aiand_dialect_is_keyed_on_the_literal_connection_id() {
    let config = Config::parse_validated(&aiand_config("http://127.0.0.1:1/v1")).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = aiand_provider_result(config.clone(), "aiand-pro".to_string(), store)
        .expect_err("a different literal id is not this dialect");
    assert!(matches!(err, ProviderError::DialectMismatch { .. }));

    // a dialect-reserved id is never fixture-served whatever kind it
    // declares — `aiand` pinned `local` keeps the typed denial
    let local = Config::parse_validated(
        "config_version = 1\n\
         [connections.aiand]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"aiand\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"medium\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let loopback = rivect::providers::LoopbackProvider::new();
    let entry = local.connections.get("aiand").expect("declared");
    assert!(
        !loopback.serves("aiand", entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );

    // a manifest pinning a different connection id is refused at send
    let (provider, _store) = aiand_provider(&config);
    let foreign = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.other]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1/v1\"\ncredential_ref = \"{AIAND_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"other\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let manifest = {
        let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
        broker
            .prepare("main", &foreign, "/world/aiand", "goal: x")
            .expect("foreign pin prepares")
    };
    let (provider, outcome) = send_on_thread(provider, manifest);
    assert!(
        matches!(outcome, Err(ProviderError::DialectMismatch { .. })),
        "a foreign pin never speaks this dialect: {outcome:?}"
    );
    drop_blocking(provider);
}

// ----- TP-PROVIDER-CATALOG::aiand -------------------------------------------

/// `GET /models` is the authoritative org-scoped listing for `aiand`
/// (HZN-008): the configured endpoint normalizes onto the recorded
/// `/v1` API root — a bare configured origin gains the version tail —
/// every `data[]` id with a non-whitespace body is offered, the
/// recorded static seed merges on top as the offer floor, the union
/// deduplicates and sorts, every listed entry runs the recorded
/// capability/effort/currency transform, and the bearer credential
/// came through the store seam. The generic arm keeps the verbatim
/// endpoint rule — the normalization binds the literal `aiand` id,
/// never the shared dialect.
#[tokio::test]
async fn aiand_catalog_is_the_authoritative_org_listing_over_the_static_seed() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({
                "id": "unseeded-org-model",
                "description": "the org's own listing entry",
                "capabilities": ["reasoning", "vision"],
                "reasoning_efforts": ["low", "medium", "high", "max"],
                "reasoning_effort_default": "medium",
                "context_window": 262144,
                "currency": "usd",
                "input_per_1m": "0.75",
                "output_per_1m": "3.5",
            }),
            // a seed id already listed deduplicates rather than
            // doubling — and the listing's entry keeps its transform:
            // the stated USD price is the discriminating surface the
            // seed stub's empty `Unknown` loses to
            json!({
                "id": "qwen/qwen3.6-27b",
                "currency": "usd",
                "input_per_1m": "9",
                "output_per_1m": "27",
            }),
            // the transform's negative arms: a declared default lands
            // only as a declared level — one absent from the ladder
            // drops, the unmappable `max` never lands — and an entry
            // without the reasoning capability maps no effort surface
            json!({
                "id": "default-outside-ladder",
                "capabilities": ["reasoning"],
                "reasoning_efforts": ["low", "medium"],
                "reasoning_effort_default": "high",
            }),
            json!({
                "id": "efforts-without-reasoning",
                "reasoning_efforts": ["low", "high"],
            }),
            json!({
                "id": "unmapped-effort-default",
                "capabilities": ["reasoning"],
                "reasoning_efforts": ["low", "high"],
                "reasoning_effort_default": "max",
            }),
            json!({"id": ""}),
            json!({"owned_by": "nobody"}),
        ],
    )
    .await;
    // a bare origin — no `/v1` tail — proves the recorded endpoint
    // normalization: the lookup still lands on `/v1/models`
    let config = Config::parse_validated(&aiand_config(&server.uri())).expect("valid");
    let (provider, _store) = aiand_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the org listing answers");
    drop_blocking(provider);
    let mut expected: Vec<&str> = AIAND_SEED_IDS.to_vec();
    expected.extend([
        "unseeded-org-model",
        "default-outside-ladder",
        "efforts-without-reasoning",
        "unmapped-effort-default",
    ]);
    expected.sort_unstable();
    assert_eq!(
        model_ids(&models),
        expected,
        "the authoritative org listing and the static seed merge, sorted and deduplicated"
    );
    // the listed entry carries the recorded transform: reasoning and
    // vision capabilities, the effort ladder with the unmapped `max`
    // wire value dropped, the declared default only as a declared
    // level, the context window, and the stated USD price
    let listed = models
        .iter()
        .find(|model| model.id == "unseeded-org-model")
        .expect("the listed model is offered");
    assert_eq!(
        listed,
        &CatalogModel {
            id: "unseeded-org-model".to_string(),
            reasoning: true,
            vision: true,
            tools: false,
            efforts: vec![EffortLevel::Low, EffortLevel::Medium, EffortLevel::High],
            effort_default: Some(EffortLevel::Medium),
            context_window: Some(262144),
            max_output_tokens: None,
            price: ModelPrice::Usd {
                input_per_1m: 0.75,
                output_per_1m: 3.5,
            },
        }
    );
    // the transform's negative arms land too: the declared default
    // survives only as a declared level — `high` absent from the
    // ladder drops, the unmappable `max` never lands — and an entry
    // without the reasoning capability ignores `reasoning_efforts`
    let model = |id: &str| {
        models
            .iter()
            .find(|model| model.id == id)
            .unwrap_or_else(|| panic!("{id} is offered"))
    };
    assert_eq!(
        model("default-outside-ladder"),
        &CatalogModel {
            id: "default-outside-ladder".to_string(),
            reasoning: true,
            efforts: vec![EffortLevel::Low, EffortLevel::Medium],
            ..CatalogModel::default()
        },
        "a default the ladder does not declare drops"
    );
    assert_eq!(
        model("efforts-without-reasoning"),
        &CatalogModel {
            id: "efforts-without-reasoning".to_string(),
            ..CatalogModel::default()
        },
        "a non-reasoning entry maps no effort surface"
    );
    assert_eq!(
        model("unmapped-effort-default"),
        &CatalogModel {
            id: "unmapped-effort-default".to_string(),
            reasoning: true,
            efforts: vec![EffortLevel::Low, EffortLevel::High],
            ..CatalogModel::default()
        },
        "the recorded `max` has no landing level — default included"
    );
    // a seed id the listing restated carries the listing's transform
    // — here the stated USD price is the discriminating leg that a
    // reversed seed-over-listing merge would lose — while a seed id
    // the listing omitted still offers with the empty surface: the
    // seed never states metadata the listing did not
    assert_eq!(
        model("qwen/qwen3.6-27b"),
        &CatalogModel {
            id: "qwen/qwen3.6-27b".to_string(),
            price: ModelPrice::Usd {
                input_per_1m: 9.0,
                output_per_1m: 27.0,
            },
            ..CatalogModel::default()
        },
        "the listed entry's transform wins the seed collision"
    );
    assert_eq!(
        model(AIAND_MODEL),
        &CatalogModel {
            id: AIAND_MODEL.to_string(),
            ..CatalogModel::default()
        },
        "a seed id the listing omitted carries the empty surface"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests[0].url.path(),
        "/v1/models",
        "the bare configured origin normalized onto the /v1 root"
    );
    assert_eq!(received_auth(&requests[0]), format!("Bearer {SECRET}"));

    // the generic arm keeps the verbatim endpoint rule: the same bare
    // origin serves its listing at `/models`, never normalized —
    // the predicate binds the literal `aiand` id, not the dialect
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"object": "list", "data": [{"id": "plain"}]})),
        )
        .mount(&server)
        .await;
    let generic = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.custom-chat-completions]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"custom-chat-completions\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server.uri()
    ))
    .expect("valid");
    let (provider, _store) = local_provider(&generic);
    let (provider, catalog) = catalog_on_thread(provider);
    assert_eq!(
        model_ids(&catalog.expect("the generic listing answers")),
        vec!["plain"]
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests[0].url.path(),
        "/models",
        "the generic arm hits the configured origin verbatim"
    );
}

/// An empty configured endpoint resolves the recorded default host —
/// `normalizeAiandBaseUrl`'s empty arm (`AIAND_DEFAULT_BASE_URL`):
/// the schema admits the empty string, and whitespace-only shares
/// the arm under the rule's trim. Offline pin: the adapter's `Debug`
/// surface reports the resolved endpoint, so the arm is proved
/// without one byte toward `api.aiand.com` — the host the bearer
/// credential would egress to.
#[test]
fn aiand_empty_endpoint_resolves_the_recorded_default_host() {
    for endpoint in ["", "   "] {
        let config =
            Config::parse_validated(&aiand_config(endpoint)).expect("an empty endpoint is valid");
        let (provider, _store) = aiand_provider(&config);
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"https://api.aiand.com/v1\""),
            "endpoint {endpoint:?} resolved to the recorded default host: {debug}"
        );
        drop_blocking(provider);
    }
}

/// The recorded currency rule (`mapAiandCost`): the org's billing
/// currency decides whether a stated price lands — only a `usd`
/// entry's figures carry onto the surface, a stated zero included,
/// while every other currency, a missing member or an unreadable
/// shape stays `ModelPrice::Unknown`: never coerced to a zero the
/// accounting could release, never defaulted to USD.
#[tokio::test]
async fn aiand_unknown_currency_stays_unknown_never_zero() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            // a stated USD price lands verbatim — a stated zero too:
            // a free model's 0 is a real figure, not an unknown
            json!({"id": "priced-usd", "currency": "usd", "input_per_1m": "0.15", "output_per_1m": "0.25"}),
            json!({"id": "free-usd", "currency": "usd", "input_per_1m": "0", "output_per_1m": "0"}),
            // a currency the org bills that is not USD — upstream
            // zeroes it; here it stays unknown
            json!({"id": "priced-jpy", "currency": "jpy", "input_per_1m": "20", "output_per_1m": "40"}),
            json!({"id": "priced-credits", "currency": "credits", "input_per_1m": "1", "output_per_1m": "2"}),
            json!({"id": "no-currency", "input_per_1m": "0.5", "output_per_1m": "0.5"}),
            json!({"id": "odd-currency", "currency": 42, "input_per_1m": "1", "output_per_1m": "1"}),
        ],
    )
    .await;
    let config = Config::parse_validated(&aiand_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = aiand_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the listing answers");
    drop_blocking(provider);

    let price = |id: &str| {
        models
            .iter()
            .find(|model| model.id == id)
            .unwrap_or_else(|| panic!("{id} is offered"))
            .price
    };
    assert_eq!(
        price("priced-usd"),
        ModelPrice::Usd {
            input_per_1m: 0.15,
            output_per_1m: 0.25,
        },
        "a usd entry's stated figures land verbatim"
    );
    assert_eq!(
        price("free-usd"),
        ModelPrice::Usd {
            input_per_1m: 0.0,
            output_per_1m: 0.0,
        },
        "a stated zero under usd is a real figure, never mistaken for unknown"
    );
    for id in [
        "priced-jpy",
        "priced-credits",
        "no-currency",
        "odd-currency",
    ] {
        assert_eq!(
            price(id),
            ModelPrice::Unknown,
            "{id}: an unrecognized or missing currency stays unknown — never a coerced zero"
        );
    }
}

// ----- TP-PROVIDER-AUTH::aiand ----------------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `aiand`: a configured region — the recorded contract names none —
/// the profile-bound ref whose scope disagrees with the binding, an
/// absent credential and a refused bearer token each land a typed
/// denial, and none of them, nor any Debug surface the boundary
/// exposes, renders credential material or the peer's body.
#[tokio::test]
async fn aiand_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(&aiand_config(&server_uri_v1(&server)).replace(
        "kind = \"api_key\"",
        "kind = \"api_key\"\nregion = \"eu-1\"",
    ))
    .expect("valid");
    let err = aiand_provider_result(
        regioned,
        "aiand".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, SECRET)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "aiand");
    assert_eq!(region, "eu-1");
    assert_no_secret_or_body(&err, SECRET.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.aiand]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"aiand\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = aiand_provider_result(
        mismatched,
        "aiand".to_string(),
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
    assert_no_secret_or_body(&err, SECRET.as_bytes());

    // a bound ref with no material at its own scope — the sibling
    // scope's material stays sealed behind the typed denial
    let config = Config::parse_validated(&aiand_config(&server_uri_v1(&server))).expect("valid");
    let provider = aiand_provider_result(
        config.clone(),
        "aiand".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, SECRET)],
        )),
    )
    .expect("binding resolves; the store is read at send");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("no material at the scope is the typed denial");
    assert!(matches!(err, ProviderError::CredentialAbsent { .. }));
    assert_no_secret_or_body(&err, SECRET.as_bytes());
    drop_blocking(provider);

    // a refused bearer token is a typed transport denial — the wire
    // never coerces a wrong credential into success, and the peer's
    // body never enters the error
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(AIAND_REF, SECRET)],
    ));
    let provider =
        aiand_provider_result(config.clone(), "aiand".to_string(), store).expect("builds");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused token is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused token is transport: {err}")
    };
    assert_eq!(connection, "aiand");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, SECRET.as_bytes());
    drop_blocking(provider);

    // The same boundary on the Debug surfaces the dispatch path
    // exposes: provider, manifest, accounting record, broker and
    // runtime each render without the material the store alone holds.
    let server = MockServer::start().await;
    let config = Config::parse_validated(&aiand_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(AIAND_REF, SECRET)],
    ));
    let provider = aiand_provider_result(config.clone(), "aiand".to_string(), store)
        .expect("the adapter builds");
    assert!(
        !format!("{provider:?}").contains(SECRET),
        "provider Debug never carries credential material"
    );
    mount_chat(
        &server,
        completed_stream(
            "accounted",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let (broker, manifest) = prepared_with(
        aiand_provider(&config),
        &config,
        "/world/aiand",
        "goal: debug surfaces",
    );
    assert!(
        !format!("{manifest:?}").contains(SECRET),
        "manifest Debug never carries credential material"
    );
    let (broker, outcome) = dispatch(broker, "/world/aiand", manifest.clone());
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
        "auth-debug-aiand",
        Some(&aiand_config(&server_uri_v1(&server))),
    );
    assert!(
        !format!("{:?}", world.runtime).contains(SECRET),
        "runtime Debug never carries credential material"
    );
}

// ----- TP-PROVIDER-RECOVERY::aiand ------------------------------------------

/// A typed denial is recoverable through the same seam: the absent
/// credential denies the first send, enrolling material at the scope
/// admits the retry — no state wedged, no plaintext path taken.
#[tokio::test]
async fn aiand_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config = Config::parse_validated(&aiand_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = aiand_provider_result(config.clone(), "aiand".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialAbsent { .. })
    ));

    store.enroll(AIAND_REF, SECRET.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the enrolled credential admits the retry");
    assert_eq!(reply.text, "recovered");
    drop_blocking(provider);
}

/// The auto-pick catalogue leg rides the merged catalogue: the
/// dispatch narrows the pool to the `aiand` winner and the shared
/// adapter resolves the deterministic sorted-first id of the
/// authoritative-listing-over-seed union as the wire model.
#[tokio::test]
async fn aiand_auto_pick_resolves_through_the_merged_catalog() {
    let server = MockServer::start().await;
    // a discovered id that sorts before the seed floor is the pick —
    // the catalogue names the model, never the config
    mount_models(&server, vec![json!({"id": "a-unlisted-org-model"})]).await;
    mount_chat(&server, completed_stream("auto pick", None)).await;
    let auto = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.aiand]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{AIAND_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let (broker, manifest) = prepared_with(
        aiand_provider(&auto),
        &auto,
        "/world/aiand",
        "goal: auto pick",
    );
    let (broker, outcome) = dispatch(broker, "/world/aiand", manifest);
    outcome.expect("the auto send resolves through the catalogue");
    drop_blocking(broker);
    let requests = server.received_requests().await.expect("recorded");
    let send = requests
        .iter()
        .find(|request| request.url.path() == "/v1/chat/completions")
        .expect("the send crossed the wire");
    let body: Value = serde_json::from_slice(&send.body).expect("json body");
    assert_eq!(
        body["model"], "a-unlisted-org-model",
        "the sorted-first id of the merged catalogue rides the wire"
    );

    // and the floor itself: a listing naming nothing usable still
    // offers the seed — the sorted-first seed id is the pick
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"owned_by": "nobody"})]).await;
    mount_chat(&server, completed_stream("seed pick", None)).await;
    let auto = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.aiand]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{AIAND_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let (broker, manifest) = prepared_with(
        aiand_provider(&auto),
        &auto,
        "/world/aiand",
        "goal: seed pick",
    );
    let (broker, outcome) = dispatch(broker, "/world/aiand", manifest);
    outcome.expect("the seed floor still offers a model");
    drop_blocking(broker);
    let requests = server.received_requests().await.expect("recorded");
    let send = requests
        .iter()
        .find(|request| request.url.path() == "/v1/chat/completions")
        .expect("the send crossed the wire");
    let body: Value = serde_json::from_slice(&send.body).expect("json body");
    assert_eq!(
        body["model"], "deepseek-ai/deepseek-v4-flash",
        "the sorted-first seed id is the floor's offer"
    );
}

/// The legs matrix enforces the recorded expected set for `aiand`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside
/// this run, and INSTALLED reports NOT_RUN — an omitted leg fails the
/// suite rather than silently absenting.
#[tokio::test]
async fn aiand_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": AIAND_MODEL})]).await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&aiand_config(&server_uri_v1(&server))).expect("valid");

    // CATALOG: the org listing plus the static seed answer through
    // the credential seam — the seed's own id listed deduplicates
    // into the floor.
    let (provider, _) = aiand_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if matches!(catalog, Ok(ref models) if model_ids(models) == AIAND_SEED_IDS) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: an empty store denies at send with the typed verdict.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = aiand_provider_result(config.clone(), "aiand".to_string(), empty)
        .expect("binding resolves");
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
    let (broker, manifest) = prepared_with(
        aiand_provider(&config),
        &config,
        "/world/aiand",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/aiand", manifest);
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
    let provider = aiand_provider_result(config.clone(), "aiand".to_string(), empty.clone())
        .expect("resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(AIAND_REF, SECRET.as_bytes());
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

    // The literal row mirrors the `#[ignore]`d
    // `provider_installed_aiand` case below: its ignored count is the
    // explicit NOT_RUN signal this matrix asserts — the row stays a
    // literal so the two cannot drift.
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

// ----- TP-PROVIDER-INSTALLED::aiand ------------------------------------------

/// TP-PROVIDER-INSTALLED::aiand = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::aiand = NOT_RUN"]
fn provider_installed_aiand() {}

// ----- aimlapi ---------------------------------------------------------------
//
// The `aimlapi` connection's proof legs (HZN-008 class A): the shared
// Chat Completions adapter serves the literal id — no copied codec —
// under the connection's own recorded predicates
// (`aimlApiModelManagerOptions`, openai-compat.ts §6.4). The
// configured endpoint is the API base verbatim under the recorded
// `normalizeBaseUrl` — trimmed, a single trailing slash stripped —
// and an empty one resolves the recorded default
// `api.aimlapi.com/v1`, the `config?.baseUrl ?? defaultBaseUrl` absent
// case our required `endpoint` field expresses as the empty string.
// The `/models` listing is authoritative (`dynamicModelsAuthoritative`)
// and passes the recorded chat-id filter
// (`isLikelyAimlApiChatModelId` — the provider's `exclude-models`
// roster drops the media/embedding SKUs the chat surface cannot
// serve); an admitted id lands the defaults surface alone, since
// `mapWithBundledReference` reads listing fields only through a
// bundled reference index this adapter does not carry. All keys share
// one account balance per the recorded contract — an account-level
// fact with no listing field and no balance endpoint, so the adapter
// never reads one and never spends a second egress leg on it.

/// The scoped credential ref the `aimlapi` connection binds.
const AIMLAPI_REF: &str = "keyring:rivect-test/aimlapi";

/// The pinned model id the fixed-pin `aimlapi` legs carry — the
/// recorded `defaultModel` of the catalogue descriptors.
const AIMLAPI_MODEL: &str = "gpt-5.5-2026-04-23";

/// One configured `aimlapi` connection pointing at the fixture peer:
/// the api_key auth class resolves a scoped `SecretRef` (DEC-011), the
/// dialect comes from the literal connection id (DEC-007), and the
/// endpoint carries the API base verbatim — the recorded
/// `api.aimlapi.com/v1` carries its `/v1` segment the same way.
fn aimlapi_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.aimlapi]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{AIMLAPI_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"aimlapi\", model_id = \"{AIMLAPI_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn aimlapi_provider(config: &Config) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(AIMLAPI_REF, SECRET)],
    ));
    let provider = provider_result(config.clone(), "aimlapi".to_string(), store.clone())
        .expect("the shared adapter builds for the aimlapi id");
    (provider, store)
}

// ----- TP-PROVIDER-WIRE::aimlapi --------------------------------------------

/// A configured `aimlapi` connection returns a verified model outcome
/// through the standard Broker: prepare admits the api_key pin under
/// DEC-011, the shared adapter posts exactly the frozen manifest as a
/// `chat/completions` request — pinned model, system+user messages,
/// `stream` with `stream_options.include_usage`, the declared tool
/// surface as function tools and the pinned effort as
/// `reasoning_effort` verbatim — the SSE stream validates its
/// finish_reason/`[DONE]` terminal, and the one physical send is
/// charged once with the provider's reported usage.
#[tokio::test]
async fn aimlapi_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified outcome text",
            Some(json!({"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18})),
        ),
    )
    .await;
    let config = Config::parse_validated(&aimlapi_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        aimlapi_provider(&config),
        &config,
        "/world/aimlapi",
        "goal: prove the wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/aimlapi", manifest.clone());
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
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(SECRET),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], json!(AIMLAPI_MODEL));
    assert_eq!(
        body["messages"],
        json!([
            {"role": "system", "content": manifest.instructions},
            {"role": "user", "content": manifest.inputs},
        ]),
        "the frozen instructions and inputs ride the messages verbatim"
    );
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["stream_options"],
        json!({"include_usage": true}),
        "the recorded usage request rides the stream options"
    );
    assert_eq!(
        body["tools"],
        json!([{
            "type": "function",
            "function": {"name": "read_file", "description": "", "parameters": {"type": "object"}},
        }]),
        "the declared tool surface maps to function tools verbatim"
    );
    assert_eq!(
        body["reasoning_effort"],
        json!("medium"),
        "the pinned effort rides the recorded reasoning_effort surface"
    );

    // Exactly one accounting record carries the one physical usage
    // report — the provider's 18 tokens are the confirmed charge, and
    // a replayed attempt reports spent.
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "aimlapi");
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
            let replay =
                broker.dispatch(&mut rivect::model::NullLedger, "/world/aimlapi", &manifest);
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
/// label: an id without the recorded Chat Completions class builds no
/// adapter — a Chat-Completions-classed id is reserved for its own
/// named contract arm — `dialect_for` reserving `aimlapi` means the
/// id is never fixture-served even when it declares `local` kind, and
/// a manifest pinning a different connection id is refused at send.
#[test]
fn aimlapi_dialect_is_keyed_on_the_literal_connection_id() {
    let config = Config::parse_validated(&aimlapi_config("http://127.0.0.1:1/v1")).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = provider_result(config.clone(), "aimlapi-pro".to_string(), store)
        .expect_err("a different literal id is not this dialect");
    assert!(matches!(err, ProviderError::DialectMismatch { .. }));

    // a dialect-reserved id is never fixture-served whatever kind it
    // declares — `aimlapi` pinned `local` keeps the typed denial
    let local = Config::parse_validated(
        "config_version = 1\n\
         [connections.aimlapi]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"aimlapi\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"medium\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let loopback = rivect::providers::LoopbackProvider::new();
    let entry = local.connections.get("aimlapi").expect("declared");
    assert!(
        !loopback.serves("aimlapi", entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );

    // a manifest pinning a different connection id is refused at send
    let (provider, _store) = aimlapi_provider(&config);
    let foreign = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.other]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1/v1\"\ncredential_ref = \"{AIMLAPI_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"other\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let manifest = {
        let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
        broker
            .prepare("main", &foreign, "/world/aimlapi", "goal: x")
            .expect("foreign pin prepares")
    };
    let (provider, outcome) = send_on_thread(provider, manifest);
    assert!(
        matches!(outcome, Err(ProviderError::DialectMismatch { .. })),
        "a foreign pin never speaks this dialect: {outcome:?}"
    );
    drop_blocking(provider);
}

// ----- TP-PROVIDER-CATALOG::aimlapi -----------------------------------------

/// `GET /models` is the authoritative listing for `aimlapi`
/// (`dynamicModelsAuthoritative`, no recorded static seed): the
/// configured endpoint is the API base verbatim under the recorded
/// `normalizeBaseUrl` — never normalized onto a `/v1` root the way
/// `aiand`'s arm records — and every listed entry passes the recorded
/// chat-id filter before offer. `isLikelyAimlApiChatModelId`
/// normalizes (trim, lowercase), rejects empty, and drops the ids the
/// provider's `exclude-models` roster names — token matches on
/// `[^a-z0-9]+` segments, substring matches — while an admitted id
/// lands the defaults surface alone: `mapWithBundledReference` reads
/// the entry's name/limits only through a bundled reference index
/// this adapter does not carry, so neither a stated price nor the
/// account's shared balance — an account-level fact the listing never
/// carries — lands as a field.
#[tokio::test]
async fn aimlapi_models_listing_filters_chat_models_and_shares_account_balance() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            // chat ids — admitted, offered verbatim
            json!({"id": AIMLAPI_MODEL}),
            json!({"id": "openai/gpt-5.5-mini"}),
            // token-roster exclusions: the media/embedding SKUs the
            // chat surface cannot serve — `audio`, `embed`,
            // `embedding`, `embeddings`, `i2i`, `i2v`, `image`,
            // `speech`, `t2i`, `t2v`, `tts`, `video` as whole
            // `[^a-z0-9]+` segments — one id pins each member
            json!({"id": "openai/tts-1"}),
            json!({"id": "x/speech-1"}),
            json!({"id": "openai/text-embedding-3-large"}),
            json!({"id": "x/embed-1"}),
            json!({"id": "x/embeddings-1"}),
            json!({"id": "stabilityai/sdxl-t2i"}),
            json!({"id": "x/i2i"}),
            json!({"id": "aiml/video-kling-i2v"}),
            json!({"id": "x/t2v"}),
            json!({"id": "assemblyai/audio-sense"}),
            json!({"id": "google/image-gen-4"}),
            // substring-roster exclusions: `dall-e`, `dalle`, `flux`,
            // `imagen`, `sora`, `veo`, `whisper` anywhere in the id
            json!({"id": "openai/dall-e-3"}),
            json!({"id": "x/dalle-mini"}),
            json!({"id": "black-forest-labs/flux-1.1-pro"}),
            json!({"id": "google/imagen-4"}),
            json!({"id": "openai/sora-2"}),
            json!({"id": "google/veo-3"}),
            json!({"id": "openai/whisper-1"}),
            // the roster's bounded tokens keep chat ids from
            // false-matching on plain substrings: `embedded` is not the
            // `embed`/`embedding` token and no substring covers it
            json!({"id": "vendor/embedded-chat-7b"}),
            // normalization is recorded inside the predicate: a
            // spaced, uppercased media id still fails the filter
            json!({"id": "  OpenAI/WHISPER-2  "}),
            // the shared account balance is an account-level fact the
            // listing never carries: fields naming a balance, a
            // currency, per-model prices or limits are not a surface
            // this dialect reads — none of them lands
            json!({
                "id": "priced-chat",
                "balance": "12.50",
                "currency": "usd",
                "input_per_1m": "1",
                "output_per_1m": "2",
                "context_length": 262144,
            }),
            // a raw-empty or whitespace-only id drops at
            // `catalog_entry`'s shared trim rule, and an entry with no
            // id drops too — none of them reaches the pool
            json!({"id": ""}),
            json!({"id": "   "}),
            json!({"owned_by": "nobody"}),
        ],
    )
    .await;
    let config = Config::parse_validated(&aimlapi_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = aimlapi_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the filtered listing answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        vec![
            AIMLAPI_MODEL,
            "openai/gpt-5.5-mini",
            "priced-chat",
            "vendor/embedded-chat-7b",
        ],
        "the authoritative listing filters to chat ids, sorted"
    );
    // every admitted id lands the defaults surface — price stays
    // `Unknown`, no field the listing stated is adopted: the shared
    // account balance has no landing spot and is never invented
    for id in [
        AIMLAPI_MODEL,
        "openai/gpt-5.5-mini",
        "priced-chat",
        "vendor/embedded-chat-7b",
    ] {
        assert_eq!(
            models.iter().find(|model| model.id == id),
            Some(&CatalogModel {
                id: id.to_string(),
                ..CatalogModel::default()
            }),
            "{id}: the listing states the id alone — balance and metadata stay unread"
        );
    }
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "the listing leg is the only egress — no balance endpoint is consulted"
    );
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(received_auth(&requests[0]), format!("Bearer {SECRET}"));

    // the configured endpoint is verbatim, never normalized onto a
    // `/v1` root the way `aiand`'s recorded rule does: a bare origin
    // serves its listing at `/models`, and a single trailing slash is
    // the recorded strip
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"object": "list", "data": [{"id": "plain-chat"}]})),
        )
        .mount(&server)
        .await;
    let bare = Config::parse_validated(&aimlapi_config(&server.uri())).expect("valid");
    let (provider, _store) = aimlapi_provider(&bare);
    let (provider, catalog) = catalog_on_thread(provider);
    assert_eq!(
        model_ids(&catalog.expect("the bare-origin listing answers")),
        vec!["plain-chat"]
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests[0].url.path(),
        "/models",
        "the aimlapi arm hits the configured origin verbatim"
    );

    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "trailing-chat"})]).await;
    let slashed =
        Config::parse_validated(&aimlapi_config(&format!("{}/v1/", server.uri()))).expect("valid");
    let (provider, _store) = aimlapi_provider(&slashed);
    let (provider, catalog) = catalog_on_thread(provider);
    assert_eq!(
        model_ids(&catalog.expect("the slashed-origin listing answers")),
        vec!["trailing-chat"]
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests[0].url.path(),
        "/v1/models",
        "one trailing slash is stripped — the recorded normalizeBaseUrl"
    );
}

/// An empty configured endpoint resolves the recorded default host —
/// the `config?.baseUrl ?? defaultBaseUrl` absent arm, which our
/// required `endpoint` field expresses as the empty string, and
/// whitespace-only shares the arm under the recorded `normalizeBaseUrl`
/// trim. Offline pin: the adapter's `Debug` surface reports the
/// resolved endpoint, so the arm is proved without one byte toward
/// `api.aimlapi.com` — the host the bearer credential would egress to.
#[test]
fn aimlapi_empty_endpoint_resolves_the_recorded_default_host() {
    for endpoint in ["", "   "] {
        let config =
            Config::parse_validated(&aimlapi_config(endpoint)).expect("an empty endpoint is valid");
        let (provider, _store) = aimlapi_provider(&config);
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"https://api.aimlapi.com/v1\""),
            "endpoint {endpoint:?} resolved to the recorded default host: {debug}"
        );
        drop_blocking(provider);
    }
}

// ----- TP-PROVIDER-AUTH::aimlapi --------------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `aimlapi`: a configured region — the recorded contract names none —
/// the profile-bound ref whose scope disagrees with the binding, an
/// absent credential and a refused bearer token each land a typed
/// denial, and none of them, nor any Debug surface the boundary
/// exposes, renders credential material or the peer's body.
#[tokio::test]
async fn aimlapi_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(&aimlapi_config(&server_uri_v1(&server)).replace(
        "kind = \"api_key\"",
        "kind = \"api_key\"\nregion = \"eu-1\"",
    ))
    .expect("valid");
    let err = provider_result(
        regioned,
        "aimlapi".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, SECRET)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "aimlapi");
    assert_eq!(region, "eu-1");
    assert_no_secret_or_body(&err, SECRET.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.aimlapi]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"aimlapi\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "aimlapi".to_string(),
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
    assert_no_secret_or_body(&err, SECRET.as_bytes());

    // a bound ref with no material at its own scope — the sibling
    // scope's material stays sealed behind the typed denial
    let config = Config::parse_validated(&aimlapi_config(&server_uri_v1(&server))).expect("valid");
    let provider = provider_result(
        config.clone(),
        "aimlapi".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, SECRET)],
        )),
    )
    .expect("binding resolves; the store is read at send");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("no material at the scope is the typed denial");
    assert!(matches!(err, ProviderError::CredentialAbsent { .. }));
    assert_no_secret_or_body(&err, SECRET.as_bytes());
    drop_blocking(provider);

    // a refused bearer token is a typed transport denial — the wire
    // never coerces a wrong credential into success, and the peer's
    // body never enters the error
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(AIMLAPI_REF, SECRET)],
    ));
    let provider = provider_result(config.clone(), "aimlapi".to_string(), store).expect("builds");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused token is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused token is transport: {err}")
    };
    assert_eq!(connection, "aimlapi");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, SECRET.as_bytes());
    drop_blocking(provider);

    // The same boundary on the Debug surfaces the dispatch path
    // exposes: provider, manifest, accounting record, broker and
    // runtime each render without the material the store alone holds.
    let server = MockServer::start().await;
    let config = Config::parse_validated(&aimlapi_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(AIMLAPI_REF, SECRET)],
    ));
    let provider =
        provider_result(config.clone(), "aimlapi".to_string(), store).expect("the adapter builds");
    assert!(
        !format!("{provider:?}").contains(SECRET),
        "provider Debug never carries credential material"
    );
    mount_chat(
        &server,
        completed_stream(
            "accounted",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let (broker, manifest) = prepared_with(
        aimlapi_provider(&config),
        &config,
        "/world/aimlapi",
        "goal: debug surfaces",
    );
    assert!(
        !format!("{manifest:?}").contains(SECRET),
        "manifest Debug never carries credential material"
    );
    let (broker, outcome) = dispatch(broker, "/world/aimlapi", manifest.clone());
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
        "auth-debug-aimlapi",
        Some(&aimlapi_config(&server_uri_v1(&server))),
    );
    assert!(
        !format!("{:?}", world.runtime).contains(SECRET),
        "runtime Debug never carries credential material"
    );
}

// ----- TP-PROVIDER-RECOVERY::aimlapi ----------------------------------------

/// A typed denial is recoverable through the same seam: the absent
/// credential denies the first send, enrolling material at the scope
/// admits the retry — no state wedged, no plaintext path taken.
#[tokio::test]
async fn aimlapi_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config = Config::parse_validated(&aimlapi_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "aimlapi".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialAbsent { .. })
    ));

    store.enroll(AIMLAPI_REF, SECRET.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the enrolled credential admits the retry");
    assert_eq!(reply.text, "recovered");
    drop_blocking(provider);
}

/// The auto-pick catalogue leg rides the filtered catalogue: the
/// dispatch narrows the pool to the `aimlapi` winner and the shared
/// adapter resolves the deterministic sorted-first id of the filtered
/// listing as the wire model — a listing whose every id the roster
/// excludes names no model, and the send denies unpinned rather than
/// offering a non-chat id.
#[tokio::test]
async fn aimlapi_auto_pick_resolves_through_the_filtered_catalog() {
    let server = MockServer::start().await;
    // a rostered id sorts ahead of the admitted id yet never enters
    // the pick — the filtered listing alone names the wire model, so
    // the leg proves filter-before-pick rather than ordering luck
    mount_models(
        &server,
        vec![
            json!({"id": "0-media/whisper-1"}),
            json!({"id": "a-listed-chat-model"}),
        ],
    )
    .await;
    mount_chat(&server, completed_stream("auto pick", None)).await;
    let auto = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.aimlapi]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{AIMLAPI_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let (broker, manifest) = prepared_with(
        aimlapi_provider(&auto),
        &auto,
        "/world/aimlapi",
        "goal: auto pick",
    );
    let (broker, outcome) = dispatch(broker, "/world/aimlapi", manifest);
    outcome.expect("the auto send resolves through the catalogue");
    drop_blocking(broker);
    let requests = server.received_requests().await.expect("recorded");
    let send = requests
        .iter()
        .find(|request| request.url.path() == "/v1/chat/completions")
        .expect("the send crossed the wire");
    let body: Value = serde_json::from_slice(&send.body).expect("json body");
    assert_eq!(
        body["model"], "a-listed-chat-model",
        "the sorted-first filtered id rides the wire"
    );

    // a listing whose every id is rostered names no model — the send
    // denies unpinned, and the chat endpoint is never reached
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "openai/whisper-1"})]).await;
    mount_chat(&server, completed_stream("unreachable", None)).await;
    let auto = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.aimlapi]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{AIMLAPI_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let (broker, manifest) = prepared_with(
        aimlapi_provider(&auto),
        &auto,
        "/world/aimlapi",
        "goal: empty pick",
    );
    let (broker, outcome) = dispatch(broker, "/world/aimlapi", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnpinnedModel { .. }))
        ),
        "a fully filtered listing denies unpinned: {outcome:?}"
    );
    drop_blocking(broker);
    let requests = server.received_requests().await.expect("recorded");
    assert!(
        requests
            .iter()
            .all(|request| request.url.path() != "/v1/chat/completions"),
        "no send crosses the wire without a model the filter admitted"
    );
}

/// The legs matrix enforces the recorded expected set for `aimlapi`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside
/// this run, and INSTALLED reports NOT_RUN — an omitted leg fails the
/// suite rather than silently absenting.
#[tokio::test]
async fn aimlapi_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": AIMLAPI_MODEL})]).await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&aimlapi_config(&server_uri_v1(&server))).expect("valid");

    // CATALOG: the filtered authoritative listing answers through the
    // credential seam — no seed merges, the listed id is the offer.
    let (provider, _) = aimlapi_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if matches!(catalog, Ok(ref models) if model_ids(models) == [AIMLAPI_MODEL]) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: an empty store denies at send with the typed verdict.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), "aimlapi".to_string(), empty).expect("binding resolves");
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
    let (broker, manifest) = prepared_with(
        aimlapi_provider(&config),
        &config,
        "/world/aimlapi",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/aimlapi", manifest);
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
        provider_result(config.clone(), "aimlapi".to_string(), empty.clone()).expect("resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(AIMLAPI_REF, SECRET.as_bytes());
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

    // The literal row mirrors the `#[ignore]`d
    // `provider_installed_aimlapi` case below: its ignored count is
    // the explicit NOT_RUN signal this matrix asserts — the row stays
    // a literal so the two cannot drift.
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

// ----- TP-PROVIDER-INSTALLED::aimlapi ----------------------------------------

/// TP-PROVIDER-INSTALLED::aimlapi = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::aimlapi = NOT_RUN"]
fn provider_installed_aimlapi() {}

// ----- alibaba-coding-plan ----------------------------------------------------
//
// The `alibaba-coding-plan` connection's proof legs (HZN-008 class
// P): the shared Chat Completions adapter serves the literal id —
// no copied codec — under its own recorded predicates
// (`alibabaCodingPlanModelManagerOptions`, `loginAlibabaCodingPlan`).
// The configured `endpoint` carries the region choice: the recorded
// international `coding-intl.dashscope.aliyuncs.com/v1`, the China
// `coding.dashscope.aliyuncs.com/v1`, or an explicitly configured
// custom origin — an empty one resolves the recorded international
// default (`config?.baseUrl ?? defaultBaseUrl`), and a configured
// `region` is denied: the contract names none. The catalogue is the
// recorded fixed allowed-model list alone — the plan's model surface
// is static, so no `/models` leg ever runs and no credential is
// consulted. The credential follows the recorded `api-key-format
// "structured"` rule (`alibabaCodingPlanAuth`): the only shape the
// recorded login writes is a JSON `{"token": …, "enterpriseUrl": …}`
// whose `token` bears the wire and whose `enterpriseUrl` — the base
// the key was enrolled and validated against — must equal the
// connection's configured base. A bare key or a token-only blob is
// unbound material the recorded flow never produces — attributable
// to no base — and denies as malformed; the recorded `apiEndpoint`
// steering field is never followed either — the configured endpoint
// alone decides egress. The bearer always carries the recorded
// plan-key grammar (`sk-sp-…`): a PAYG `sk-…` is a different product
// that never serves these bases, and every class or base mismatch
// denies before any wire leg reaches the wrong host.

/// The scoped credential ref the `alibaba-coding-plan` connection
/// binds.
const ALIBABA_CP_REF: &str = "keyring:rivect-test/alibaba-coding-plan";

/// Fixture plan-key material — the recorded `sk-sp-…` grammar, never
/// a real credential, only ever sent to localhost.
const PLAN_KEY: &str = "sk-sp-fixture-plan-key";

/// Fixture PAYG material — the recorded `sk-…` non-plan grammar —
/// the wrong credential class on every plan base.
const PAYG_KEY: &str = "sk-fixture-payg-key";

/// The recorded international and China plan endpoints — credential
/// enrollment literals only: they ride the stored material, and no
/// configured endpoint ever names a real host offline.
const PLAN_INTL_BASE: &str = "https://coding-intl.dashscope.aliyuncs.com/v1";
const PLAN_CN_BASE: &str = "https://coding.dashscope.aliyuncs.com/v1";

/// The recorded PAYG product endpoint — a different base class the
/// plan connection never serves.
const PAYG_BASE: &str = "https://dashscope.aliyuncs.com/compatible-mode/v1";

/// The pinned model id the fixed-pin legs carry — the recorded
/// `defaultModel` of the catalogue descriptors.
const ALIBABA_CP_MODEL: &str = "qwen3.7-plus";

/// The recorded allowed-model list's ids in catalogue order — the
/// static surface `catalog` answers.
const ALIBABA_CP_MODEL_IDS: [&str; 10] = [
    "MiniMax-M2.5",
    "glm-4.7",
    "glm-5",
    "kimi-k2.5",
    "qwen3-coder-next",
    "qwen3-coder-plus",
    "qwen3-max-2026-01-23",
    "qwen3.5-plus",
    "qwen3.6-plus",
    "qwen3.7-plus",
];

/// One configured `alibaba-coding-plan` connection pointing at the
/// fixture peer: the api_key auth class resolves a scoped `SecretRef`
/// (DEC-011), the dialect comes from the literal connection id
/// (DEC-007), and the endpoint carries the API base verbatim — the
/// region choice rides it, like the recorded bases' own `/v1` roots.
fn alibaba_cp_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.alibaba-coding-plan]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{ALIBABA_CP_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"alibaba-coding-plan\", model_id = \"{ALIBABA_CP_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The recorded structured credential (`api-key-format
/// "structured"`): the enrolled base rides beside the token.
fn plan_credential(token: &str, enrolled_base: &str) -> String {
    json!({"token": token, "enterpriseUrl": enrolled_base}).to_string()
}

fn alibaba_cp_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(ALIBABA_CP_REF, material)],
    ));
    let provider = provider_result(
        config.clone(),
        "alibaba-coding-plan".to_string(),
        store.clone(),
    )
    .expect("the shared adapter builds for the alibaba-coding-plan id");
    (provider, store)
}

/// The `alibaba-coding-plan` provider over the structured credential
/// enrolled for this connection's own configured base — the only
/// shape the recorded login writes.
fn enrolled_alibaba_cp_provider(
    config: &Config,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let enrolled = &config
        .connections
        .get("alibaba-coding-plan")
        .expect("the alibaba-coding-plan connection is declared")
        .endpoint;
    alibaba_cp_provider(config, &plan_credential(PLAN_KEY, enrolled))
}

// ----- TP-PROVIDER-WIRE::alibaba-coding-plan ----------------------------------

/// A configured `alibaba-coding-plan` connection returns a verified
/// model outcome through the standard Broker: prepare admits the
/// api_key pin under DEC-011, the recorded structured credential
/// unwraps to its bearer token — the enrolled `enterpriseUrl`
/// matching the configured base — and the shared adapter posts
/// exactly the frozen manifest as a `chat/completions` request —
/// pinned model, system+user messages, `stream` with
/// `stream_options.include_usage` and the pinned effort as
/// `reasoning_effort` verbatim — the SSE stream validates its
/// finish_reason/`[DONE]` terminal, and the one physical send is
/// charged once with the provider's reported usage.
#[tokio::test]
async fn alibaba_coding_plan_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified outcome text",
            Some(json!({"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&alibaba_cp_config(&base)).expect("valid");
    // the recorded structured credential: `token` bears the wire and
    // `enterpriseUrl` confirms the enrolled base is the configured one
    let (provider, _store) = alibaba_cp_provider(&config, &plan_credential(PLAN_KEY, &base));
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/alibaba-cp", "goal: prove the wire")
        .expect("the alibaba-coding-plan pin passes DEC-011 eligibility");

    let (broker, outcome) = dispatch(broker, "/world/alibaba-cp", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified outcome text");
    assert!(reply.tool_calls.is_empty());

    // The wire request is exactly the frozen manifest — and nothing
    // the manifest does not carry; the catalogue never opens a leg.
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {PLAN_KEY}"),
        "the structured credential's token bears the wire — never the JSON blob"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(PLAN_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], json!(ALIBABA_CP_MODEL));
    assert_eq!(
        body["messages"],
        json!([
            {"role": "system", "content": manifest.instructions},
            {"role": "user", "content": manifest.inputs},
        ]),
        "the frozen instructions and inputs ride the messages verbatim"
    );
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["stream_options"],
        json!({"include_usage": true}),
        "the recorded usage request rides the stream options"
    );
    assert_eq!(
        body["reasoning_effort"],
        json!("medium"),
        "the pinned effort rides the recorded reasoning_effort surface"
    );

    // Exactly one accounting record carries the one physical usage
    // report — the provider's 18 tokens are the confirmed charge, and
    // a replayed attempt reports spent.
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "alibaba-coding-plan");
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
            let replay = broker.dispatch(
                &mut rivect::model::NullLedger,
                "/world/alibaba-cp",
                &manifest,
            );
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
/// label: an id without the recorded Chat Completions class builds
/// no adapter — a Chat-Completions-classed id is reserved for its
/// own named contract arm — `dialect_for` reserving
/// `alibaba-coding-plan` means the id is never fixture-served even
/// when it declares `local` kind, and a manifest pinning a different
/// connection id is refused at send.
#[test]
fn alibaba_coding_plan_dialect_is_keyed_on_the_literal_connection_id() {
    let config =
        Config::parse_validated(&alibaba_cp_config("http://127.0.0.1:1/v1")).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = provider_result(config.clone(), "alibaba-coding-plan-pro".to_string(), store)
        .expect_err("a different literal id is not this dialect");
    assert!(matches!(err, ProviderError::DialectMismatch { .. }));

    // a dialect-reserved id is never fixture-served whatever kind it
    // declares — `alibaba-coding-plan` pinned `local` keeps the typed
    // denial
    let local = Config::parse_validated(
        "config_version = 1\n\
         [connections.alibaba-coding-plan]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"alibaba-coding-plan\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"medium\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let loopback = rivect::providers::LoopbackProvider::new();
    let entry = local
        .connections
        .get("alibaba-coding-plan")
        .expect("declared");
    assert!(
        !loopback.serves("alibaba-coding-plan", entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );

    // a manifest pinning a different connection id is refused at send —
    // the bound credential is well-formed so the denial is the dialect's,
    // never the credential seam's
    let (provider, _store) =
        alibaba_cp_provider(&config, &plan_credential(PLAN_KEY, "http://127.0.0.1:1/v1"));
    let foreign = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.other]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1/v1\"\ncredential_ref = \"{ALIBABA_CP_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"other\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let manifest = {
        let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
        broker
            .prepare("main", &foreign, "/world/alibaba-cp", "goal: x")
            .expect("foreign pin prepares")
    };
    let (provider, outcome) = send_on_thread(provider, manifest);
    assert!(
        matches!(outcome, Err(ProviderError::DialectMismatch { .. })),
        "a foreign pin never speaks this dialect: {outcome:?}"
    );
    drop_blocking(provider);
}

// ----- TP-PROVIDER-CATALOG::alibaba-coding-plan --------------------------------

/// The `alibaba-coding-plan` catalogue is the recorded fixed
/// allowed-model list alone (HZN-008 class P): the plan's model
/// surface is static — the lookup opens no `/models` leg and
/// resolves no credential, so an empty store still answers — and
/// the listed entries carry their recorded surface: the vision
/// marks the allowlist states, nothing more.
#[tokio::test]
async fn alibaba_coding_plan_catalog_is_the_recorded_allowlist_without_a_wire_leg() {
    let server = MockServer::start().await;
    let config =
        Config::parse_validated(&alibaba_cp_config(&server_uri_v1(&server))).expect("valid");
    // an empty store proves the lookup consults no credential — the
    // static list is the whole catalogue
    let provider = provider_result(
        config.clone(),
        "alibaba-coding-plan".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("the adapter builds");
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the allowlist answers with no credential at all");
    drop_blocking(provider);
    // the whole catalogue pinned row for row — the recorded vision
    // marks land on the three marked entries and every other field of
    // every row stays at its unstated default
    let row = |id: &str, vision: bool| CatalogModel {
        id: id.to_string(),
        reasoning: false,
        vision,
        tools: false,
        efforts: vec![],
        effort_default: None,
        context_window: None,
        max_output_tokens: None,
        price: ModelPrice::Unknown,
    };
    assert_eq!(
        models,
        vec![
            row("MiniMax-M2.5", false),
            row("glm-4.7", false),
            row("glm-5", false),
            row("kimi-k2.5", true),
            row("qwen3-coder-next", false),
            row("qwen3-coder-plus", false),
            row("qwen3-max-2026-01-23", false),
            row("qwen3.5-plus", false),
            row("qwen3.6-plus", true),
            row("qwen3.7-plus", true),
        ],
        "the recorded allowed-model list answers sorted, every field pinned"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert!(
        requests.is_empty(),
        "a static catalogue never opens a wire leg"
    );
}

/// An empty configured endpoint resolves the recorded international
/// default — the `config?.baseUrl ?? defaultBaseUrl` absent arm our
/// required `endpoint` field expresses as the empty string, and
/// whitespace-only shares the arm under the recorded trim. Offline
/// pin: the adapter's `Debug` surface reports the resolved endpoint,
/// so the arm is proved without one byte toward
/// `coding-intl.dashscope.aliyuncs.com` — the host the bearer
/// credential would egress to.
#[test]
fn alibaba_coding_plan_empty_endpoint_resolves_the_recorded_intl_default() {
    for endpoint in ["", "   "] {
        let config = Config::parse_validated(&alibaba_cp_config(endpoint))
            .expect("an empty endpoint is valid");
        let (provider, _store) =
            alibaba_cp_provider(&config, &plan_credential(PLAN_KEY, PLAN_INTL_BASE));
        let debug = format!("{provider:?}");
        assert!(
            debug.contains(&format!("endpoint: \"{PLAN_INTL_BASE}\"")),
            "endpoint {endpoint:?} resolved to the recorded default: {debug}"
        );
        drop_blocking(provider);
    }
}

/// The auto-pick catalogue leg resolves the deterministic
/// sorted-first id of the recorded allowlist as the wire model —
/// with no `/models` leg: the send's catalogue lookup is the static
/// list, so exactly one request crosses the wire.
#[tokio::test]
async fn alibaba_coding_plan_auto_pick_resolves_through_the_static_allowlist() {
    let server = MockServer::start().await;
    mount_chat(&server, completed_stream("auto pick", None)).await;
    let auto = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.alibaba-coding-plan]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{ALIBABA_CP_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_alibaba_cp_provider(&auto),
        &auto,
        "/world/alibaba-cp",
        "goal: auto pick",
    );
    let (broker, outcome) = dispatch(broker, "/world/alibaba-cp", manifest);
    outcome.expect("the auto send resolves through the allowlist");
    drop_blocking(broker);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "no /models leg — the allowlist is static"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"], "MiniMax-M2.5",
        "the sorted-first allowlist id rides the wire"
    );
}

// ----- TP-PROVIDER-AUTH::alibaba-coding-plan -----------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `alibaba-coding-plan`: a configured `region` — the recorded
/// contract carries the region choice on the endpoint and names no
/// `region` field — the profile-bound ref whose scope disagrees with
/// the binding, an absent credential, a structured credential with
/// no usable `token` and a refused bearer token each land a typed
/// denial, and none of them, nor any Debug surface the boundary
/// exposes, renders credential material or the peer's body.
#[tokio::test]
async fn alibaba_coding_plan_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets()
 {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &alibaba_cp_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"cn\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "alibaba-coding-plan".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, PLAN_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "alibaba-coding-plan");
    assert_eq!(region, "cn");
    assert_no_secret_or_body(&err, PLAN_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.alibaba-coding-plan]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"alibaba-coding-plan\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "alibaba-coding-plan".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, PLAN_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, PLAN_KEY.as_bytes());

    // a bound ref with no material at its own scope — the sibling
    // scope's material stays sealed behind the typed denial
    let config =
        Config::parse_validated(&alibaba_cp_config(&server_uri_v1(&server))).expect("valid");
    let provider = provider_result(
        config.clone(),
        "alibaba-coding-plan".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, PLAN_KEY)],
        )),
    )
    .expect("binding resolves; the store is read at send");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("no material at the scope is the typed denial");
    assert!(matches!(err, ProviderError::CredentialAbsent { .. }));
    assert_no_secret_or_body(&err, PLAN_KEY.as_bytes());
    drop_blocking(provider);

    // a structured credential whose `token` is unusable is malformed —
    // the JSON blob is never sent as the bearer
    let blob = "{\"enterpriseUrl\": \"https://elsewhere.example.com/v1\"}";
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(ALIBABA_CP_REF, blob)],
    ));
    let provider = provider_result(config.clone(), "alibaba-coding-plan".to_string(), store)
        .expect("binding resolves");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a structured credential without a token is malformed");
    assert!(matches!(err, ProviderError::CredentialMalformed { .. }));
    assert_no_secret_or_body(&err, blob.as_bytes());
    drop_blocking(provider);

    // a refused bearer token is a typed transport denial — the wire
    // never coerces a wrong credential into success, and the peer's
    // body never enters the error
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let (provider, _store) =
        alibaba_cp_provider(&config, &plan_credential(PLAN_KEY, &server_uri_v1(&server)));
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused token is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused token is transport: {err}")
    };
    assert_eq!(connection, "alibaba-coding-plan");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, PLAN_KEY.as_bytes());
    drop_blocking(provider);

    // The same boundary on the Debug surfaces the dispatch path
    // exposes: provider, manifest, accounting record, broker and
    // runtime each render without the material the store alone holds.
    let server = MockServer::start().await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&alibaba_cp_config(&base)).expect("valid");
    let material = plan_credential(PLAN_KEY, &base);
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(ALIBABA_CP_REF, &material)],
    ));
    let provider = provider_result(config.clone(), "alibaba-coding-plan".to_string(), store)
        .expect("the adapter builds");
    assert!(
        !format!("{provider:?}").contains(PLAN_KEY),
        "provider Debug never carries credential material"
    );
    mount_chat(
        &server,
        completed_stream(
            "accounted",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let (broker, manifest) = {
        let (provider, _store) = alibaba_cp_provider(&config, &material);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/alibaba-cp", "goal: debug surfaces")
            .expect("the pin passes DEC-011 eligibility");
        (broker, manifest)
    };
    assert!(
        !format!("{manifest:?}").contains(PLAN_KEY),
        "manifest Debug never carries credential material"
    );
    let (broker, outcome) = dispatch(broker, "/world/alibaba-cp", manifest.clone());
    outcome.expect("the debug-surface send completes");
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert!(
        !format!("{record:?}").contains(PLAN_KEY),
        "accounting-record Debug never carries credential material"
    );
    assert!(
        !format!("{broker:?}").contains(PLAN_KEY),
        "broker Debug never carries credential material"
    );
    drop_blocking(broker);
    drop_blocking(provider);

    let world = support::open_world(
        "auth-debug-alibaba-cp",
        Some(&alibaba_cp_config(&server_uri_v1(&server))),
    );
    assert!(
        !format!("{:?}", world.runtime).contains(PLAN_KEY),
        "runtime Debug never carries credential material"
    );
}

/// The typed denial one credential/base pairing lands: every matrix
/// row declares its variant so a wrong-class denial can never pass as
/// the expected one. `BaseMismatch` carries the enrolled base the
/// error reports — the canonical egress rendering of the credential's
/// `enterpriseUrl`, never the raw store bytes.
#[derive(Debug)]
enum PlanDeny {
    Malformed,
    BaseMismatch(String),
}

/// The recorded non-interchangeability predicate (HZN-008 class P):
/// a key enrolled for one base class — international, China or a
/// custom origin — can never serve another, and a PAYG key serves
/// none of them. The enrolled base rides the recorded structured
/// credential's `enterpriseUrl` and must equal the connection's
/// configured endpoint; every mismatch or foreign-class credential
/// lands a typed denial before any wire leg — zero requests reach
/// any mock. A bare plan key, a token-only blob, an `apiEndpoint`
/// steering field without `enterpriseUrl`, or a structured credential
/// with an unusable field is unbound material the recorded login
/// never writes — attributable to no base and malformed on every one.
#[tokio::test]
async fn alibaba_coding_plan_intl_cn_custom_and_payg_keys_are_not_interchangeable() {
    // Three stand-in bases — distinct mock origins: a denied send
    // that still egressed would be observed, and no configured
    // endpoint ever names a real host. The recorded base literals
    // appear only inside credential material — they ride the store,
    // never a socket.
    let intl = MockServer::start().await;
    let cn = MockServer::start().await;
    let custom = MockServer::start().await;
    let intl_base = server_uri_v1(&intl);
    let cn_base = server_uri_v1(&cn);
    let custom_base = server_uri_v1(&custom);
    let bases: [(&str, &String, &MockServer); 3] = [
        ("intl", &intl_base, &intl),
        ("cn", &cn_base, &cn),
        ("custom", &custom_base, &custom),
    ];

    // (credential material, the only base it may serve, the typed
    // denial every other pairing lands): a denied send never reaches
    // a socket — the enrolled host included
    let credentials: [(&str, String, PlanDeny); 19] = [
        // keys enrolled for each base class serve that base alone
        (
            "intl",
            plan_credential(PLAN_KEY, &intl_base),
            PlanDeny::BaseMismatch(intl_base.clone()),
        ),
        (
            "cn",
            plan_credential(PLAN_KEY, &cn_base),
            PlanDeny::BaseMismatch(cn_base.clone()),
        ),
        (
            "custom",
            plan_credential(PLAN_KEY, &custom_base),
            PlanDeny::BaseMismatch(custom_base.clone()),
        ),
        // the real recorded base literals are classes of their own —
        // a credential enrolled at the real intl or CN endpoint is
        // not a mock's credential either
        (
            "none",
            plan_credential(PLAN_KEY, PLAN_INTL_BASE),
            PlanDeny::BaseMismatch(PLAN_INTL_BASE.to_string()),
        ),
        (
            "none",
            plan_credential(PLAN_KEY, PLAN_CN_BASE),
            PlanDeny::BaseMismatch(PLAN_CN_BASE.to_string()),
        ),
        // a key enrolled at an unrelated origin serves none of them
        (
            "none",
            plan_credential(PLAN_KEY, "https://elsewhere.example.com/v1"),
            PlanDeny::BaseMismatch("https://elsewhere.example.com/v1".to_string()),
        ),
        // an `apiEndpoint` steering field naming the configured intl
        // base never rescues a foreign enrolled base — the steering
        // field is never a second enrolled-base source
        (
            "none",
            json!({"token": PLAN_KEY, "enterpriseUrl": "https://elsewhere.example.com/v1", "apiEndpoint": intl_base.as_str()})
                .to_string(),
            PlanDeny::BaseMismatch("https://elsewhere.example.com/v1".to_string()),
        ),
        // PAYG keys — the recorded `sk-…` non-plan grammar — are a
        // different product on every plan base, structured or bare,
        // even when the enrolled field names the right base
        (
            "none",
            plan_credential(PAYG_KEY, PAYG_BASE),
            PlanDeny::Malformed,
        ),
        (
            "none",
            plan_credential(PAYG_KEY, &intl_base),
            PlanDeny::Malformed,
        ),
        ("none", PAYG_KEY.to_string(), PlanDeny::Malformed),
        // unbound material the recorded login never writes — a bare
        // key, a token-only blob, an `apiEndpoint` steering field
        // without `enterpriseUrl`: attributable to no base
        ("none", PLAN_KEY.to_string(), PlanDeny::Malformed),
        (
            "none",
            json!({"token": PLAN_KEY}).to_string(),
            PlanDeny::Malformed,
        ),
        (
            "none",
            json!({"token": PLAN_KEY, "apiEndpoint": cn_base.as_str()}).to_string(),
            PlanDeny::Malformed,
        ),
        // malformed structured material never reaches a socket either
        ("none", "{\"token\": 42}".to_string(), PlanDeny::Malformed),
        ("none", "{not-json".to_string(), PlanDeny::Malformed),
        (
            "none",
            json!({"token": PLAN_KEY, "enterpriseUrl": ""}).to_string(),
            PlanDeny::Malformed,
        ),
        (
            "none",
            json!({"token": PLAN_KEY, "enterpriseUrl": null}).to_string(),
            PlanDeny::Malformed,
        ),
        (
            "none",
            json!({"token": PLAN_KEY, "enterpriseUrl": 42}).to_string(),
            PlanDeny::Malformed,
        ),
        // the recorded ingress normalization: a trailing slash on the
        // enrolled base still matches the configured one
        (
            "intl",
            plan_credential(PLAN_KEY, &format!("{intl_base}/")),
            PlanDeny::BaseMismatch(intl_base.clone()),
        ),
    ];

    // every deny pairing first, while no mock has seen a request —
    // a wrong credential never reaches a socket, enrolled host
    // included
    for (serves, material, deny) in &credentials {
        for (base_label, base, _server) in &bases {
            if serves == base_label {
                continue;
            }
            let config = Config::parse_validated(&alibaba_cp_config(base)).expect("valid");
            let store = Arc::new(support::MapStore::seeded(
                STORE_KIND,
                &[(ALIBABA_CP_REF, material.as_str())],
            ));
            let provider =
                provider_result(config.clone(), "alibaba-coding-plan".to_string(), store)
                    .expect("binding resolves");
            let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
            let err = outcome.expect_err("a wrong-base or wrong-class credential denies");
            match (deny, &err) {
                (PlanDeny::Malformed, ProviderError::CredentialMalformed { connection }) => {
                    assert_eq!(connection, "alibaba-coding-plan");
                }
                (
                    PlanDeny::BaseMismatch(enrolled),
                    ProviderError::CredentialBaseMismatch {
                        connection,
                        enrolled: reported,
                    },
                ) => {
                    assert_eq!(connection, "alibaba-coding-plan");
                    assert_eq!(
                        reported, enrolled,
                        "the denial reports the credential's own enrolled base"
                    );
                }
                _ => panic!(
                    "{serves}-enrolled credential on {base_label} base denies as {deny:?}: {err}"
                ),
            }
            assert_no_secret_or_body(&err, PLAN_KEY.as_bytes());
            assert_no_secret_or_body(&err, PAYG_KEY.as_bytes());
            drop_blocking(provider);
            for (_, _, server) in &bases {
                assert!(
                    server
                        .received_requests()
                        .await
                        .expect("recorded")
                        .is_empty(),
                    "no wire leg left the denied send — the enrolled host included"
                );
            }
        }
    }

    // the serve pairings: each enrolled key on its own base — the
    // enrolled base equals the configured one
    for (label, server) in [("intl", &intl), ("cn", &cn), ("custom", &custom)] {
        mount_chat(server, completed_stream(&format!("served-{label}"), None)).await;
    }
    for (serves, material, _deny) in &credentials {
        for (base_label, base, server) in &bases {
            if serves != base_label {
                continue;
            }
            let config = Config::parse_validated(&alibaba_cp_config(base)).expect("valid");
            let store = Arc::new(support::MapStore::seeded(
                STORE_KIND,
                &[(ALIBABA_CP_REF, material.as_str())],
            ));
            let provider =
                provider_result(config.clone(), "alibaba-coding-plan".to_string(), store)
                    .expect("binding resolves");
            let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
            let reply = outcome.unwrap_or_else(|err| {
                panic!("{serves}-enrolled credential serves the {base_label} base: {err}")
            });
            assert_eq!(reply.text, format!("served-{base_label}"));
            drop_blocking(provider);
            let requests = server.received_requests().await.expect("recorded");
            let last = requests.last().expect("the serve crossed the wire");
            assert_eq!(
                received_auth(last),
                format!("Bearer {PLAN_KEY}"),
                "the unwrapped plan token bears the wire"
            );
        }
    }

    // exactly the serve legs crossed the wire — each enrolled key on
    // its own base plus intl's extra trailing-slash enrolled leg —
    // and every denial left none
    for (label, _, server) in &bases {
        let expected = if label == &"intl" { 2 } else { 1 };
        let requests = server.received_requests().await.expect("recorded");
        assert_eq!(
            requests.len(),
            expected,
            "the serve legs alone egressed on the {label} base"
        );
    }
    // Let the mock servers' in-flight handler tasks drain before the
    // servers drop: `MockServer::drop` verifies through a futures
    // `block_on` that cannot drive this runtime, so a handler still
    // holding the state write lock would park the teardown forever.
    tokio::task::yield_now().await;
}

/// `apiEndpoint` is the recorded credential's steering field, not
/// this adapter's: a structured credential carrying it beside a
/// matching `enterpriseUrl` still serves the configured base alone —
/// the steering field is never read, so an `apiEndpoint` naming a
/// different origin redirects no egress.
#[tokio::test]
async fn alibaba_coding_plan_api_endpoint_field_never_steers_egress() {
    let intl = MockServer::start().await;
    let cn = MockServer::start().await;
    mount_chat(&intl, completed_stream("served-intl", None)).await;
    let intl_base = server_uri_v1(&intl);
    let config = Config::parse_validated(&alibaba_cp_config(&intl_base)).expect("valid");
    // the steering field names the China mock while `enterpriseUrl`
    // binds the configured intl base — the credential serves the
    // configured base alone
    let material = json!({
        "token": PLAN_KEY,
        "apiEndpoint": server_uri_v1(&cn),
        "enterpriseUrl": intl_base,
    })
    .to_string();
    let (provider, _store) = alibaba_cp_provider(&config, &material);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let reply = outcome.expect("the bound credential serves the configured base");
    assert_eq!(reply.text, "served-intl");
    drop_blocking(provider);
    let requests = intl.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the configured intl base served");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {PLAN_KEY}"),
        "the unwrapped plan token bears the wire"
    );
    assert!(
        cn.received_requests().await.expect("recorded").is_empty(),
        "the apiEndpoint-named origin never saw a request"
    );
    tokio::task::yield_now().await;
}

/// The configured side of the binding takes the same recorded ingress
/// normalization: an `endpoint` carrying a trailing slash resolves to
/// the same base the credential enrolled, and the request path never
/// doubles the slash.
#[tokio::test]
async fn alibaba_coding_plan_configured_trailing_slash_binds_the_same_base() {
    let server = MockServer::start().await;
    mount_chat(&server, completed_stream("slashed", None)).await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&alibaba_cp_config(&format!("{base}/"))).expect("valid");
    let (provider, _store) = alibaba_cp_provider(&config, &plan_credential(PLAN_KEY, &base));
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    outcome.expect("the normalized configured base binds the enrolled credential");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].url.path(),
        "/v1/chat/completions",
        "the resolved base carries no doubled slash"
    );
    tokio::task::yield_now().await;
}

/// A `CredentialBaseMismatch` reports the enrolled base in the
/// canonical egress form — the same rendering consent and journal
/// surfaces use — so store content carrying userinfo or a query
/// never reaches the diagnostic.
#[tokio::test]
async fn alibaba_coding_plan_base_mismatch_redacts_enrolled_url_parts() {
    let server = MockServer::start().await;
    let config =
        Config::parse_validated(&alibaba_cp_config(&server_uri_v1(&server))).expect("valid");
    let material = json!({
        "token": PLAN_KEY,
        "enterpriseUrl": "https://user:pw@host.invalid/v1?x=1",
    })
    .to_string();
    let (provider, _store) = alibaba_cp_provider(&config, &material);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a foreign enrolled base denies");
    let ProviderError::CredentialBaseMismatch {
        connection,
        enrolled,
    } = &err
    else {
        panic!("the foreign enrolled base is the typed mismatch: {err}")
    };
    assert_eq!(connection, "alibaba-coding-plan");
    assert_eq!(
        enrolled, "https://host.invalid/v1",
        "the reported enrolled base drops userinfo and query"
    );
    let rendered = err.to_string();
    for secret_part in ["user", "pw", "x=1"] {
        assert!(
            !rendered.contains(secret_part),
            "the enrolled base's {secret_part:?} never renders: {rendered}"
        );
    }
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "no wire leg left the denied send"
    );
    tokio::task::yield_now().await;
}

// ----- TP-PROVIDER-RECOVERY::alibaba-coding-plan -------------------------------

/// A typed denial is recoverable through the same seam: the absent
/// credential denies the first send, enrolling a plan key at the
/// scope admits the retry — no state wedged, no plaintext path
/// taken.
#[tokio::test]
async fn alibaba_coding_plan_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&alibaba_cp_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(
        config.clone(),
        "alibaba-coding-plan".to_string(),
        store.clone(),
    )
    .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialAbsent { .. })
    ));

    store.enroll(
        ALIBABA_CP_REF,
        plan_credential(PLAN_KEY, &server_uri_v1(&server)).as_bytes(),
    );
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the enrolled credential admits the retry");
    assert_eq!(reply.text, "recovered");
    drop_blocking(provider);
}

/// The legs matrix enforces the recorded expected set for
/// `alibaba-coding-plan`: CATALOG, AUTH, WIRE and RECOVERY each
/// execute and report inside this run, and INSTALLED reports
/// NOT_RUN — an omitted leg fails the suite rather than silently
/// absenting.
#[tokio::test]
async fn alibaba_coding_plan_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&alibaba_cp_config(&server_uri_v1(&server))).expect("valid");

    // CATALOG: the static allowlist answers with no credential and
    // no wire leg — the empty store proves both.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "alibaba-coding-plan".to_string(), empty)
        .expect("the adapter builds");
    let (provider, catalog) = catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if matches!(catalog, Ok(ref models) if model_ids(models) == ALIBABA_CP_MODEL_IDS) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: an empty store denies at send with the typed verdict.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "alibaba-coding-plan".to_string(), empty)
        .expect("binding resolves");
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
    let (broker, manifest) = prepared_with(
        enrolled_alibaba_cp_provider(&config),
        &config,
        "/world/alibaba-cp",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/alibaba-cp", manifest);
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
    let provider = provider_result(
        config.clone(),
        "alibaba-coding-plan".to_string(),
        empty.clone(),
    )
    .expect("resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(
        ALIBABA_CP_REF,
        plan_credential(PLAN_KEY, &server_uri_v1(&server)).as_bytes(),
    );
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

    // The literal row mirrors the `#[ignore]`d
    // `provider_installed_alibaba_coding_plan` case below: its
    // ignored count is the explicit NOT_RUN signal this matrix
    // asserts — the row stays a literal so the two cannot drift.
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

// ----- TP-PROVIDER-INSTALLED::alibaba-coding-plan ------------------------------

/// TP-PROVIDER-INSTALLED::alibaba-coding-plan = NOT_RUN: the
/// installed-provider proof is a live-environment leg this offline
/// slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::alibaba-coding-plan = NOT_RUN"]
fn provider_installed_alibaba_coding_plan() {}

// ----- alibaba-token-plan -----------------------------------------------------
//
// The `alibaba-token-plan` connection's proof legs (HZN-008 class
// P): the shared Chat Completions adapter serves the literal id —
// no copied codec — under its own recorded predicates
// (`alibabaTokenPlanModelManagerOptions`, `loginAlibabaTokenPlan`,
// `parseAlibabaTokenPlanCredential`). The configured `endpoint`
// carries the region choice — the recorded international
// `token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1`,
// the China `token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1`,
// or an explicitly configured custom origin — an empty one resolves
// the recorded international default (`credential?.baseUrl ??
// config?.baseUrl ?? ALIBABA_TOKEN_PLAN_BASE_URL`'s configured arm),
// and a configured `region` is denied: the contract names none. The
// catalogue is the configured region's own authoritative `/models`
// listing (`dynamicModelsAuthoritative` — the discovered set alone,
// never unioned with the recorded static fallback) under the
// recorded exclusion prefixes — the ASR/image/embedding SKUs the
// chat picker cannot route — each admitted id landing the defaults
// surface: the recorded reference and limits hydration is the
// enrichment layer this adapter does not carry, the same boundary
// `aimlapi` applies. The credential follows
// `parseAlibabaTokenPlanCredential`: a bare `sk-…` token, or the
// JSON `{"token": …, "cookie": …, "baseUrl": …}` — `baseUrl` is the
// region base the key authenticates against, the recorded
// international default when absent, and must equal the
// connection's configured endpoint: keys are region-locked (#6682),
// so a key recorded for one base never serves another. The optional
// `cookie` member is the separately admitted quota credential the
// recorded login pastes by hand — validated for shape and dropped:
// no wire leg reads it and no extraction path exists.

/// The scoped credential ref the `alibaba-token-plan` connection
/// binds.
const ALIBABA_TP_REF: &str = "keyring:rivect-test/alibaba-token-plan";

/// Fixture token-plan material — the recorded `sk-…` grammar
/// (`TOKEN_PATTERN`), never a real credential, only ever sent to
/// localhost.
const TOKEN_PLAN_KEY: &str = "sk-tp-fixture-key";

/// The recorded international and China token-plan endpoints —
/// credential `baseUrl` literals only: they ride the stored
/// material, and no configured endpoint ever names a real host
/// offline.
const TOKEN_PLAN_INTL_BASE: &str =
    "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1";
const TOKEN_PLAN_CN_BASE: &str =
    "https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1";

/// The pinned model id the fixed-pin legs carry — the recorded
/// `defaultModel` of the catalogue descriptors.
const ALIBABA_TP_MODEL: &str = "qwen3.7-plus";

/// Fixture quota-cookie material — the recorded optional member's
/// `name=value` shape, never a real Cookie header, only ever
/// asserted absent from the wire.
const QUOTA_COOKIE: &str = "fixture_quota=never-on-the-wire; session=fixture";

/// Distinctive quota-cookie material one denied credential carries —
/// the pin that no diagnostic surface ever renders it, complementing
/// the wire-absence legs.
const QUOTA_COOKIE_XYZ: &str = "diag_quota=QUOTA_COOKIE_XYZ";

/// One configured `alibaba-token-plan` connection pointing at the
/// fixture peer: the api_key auth class resolves a scoped `SecretRef`
/// (DEC-011), the dialect comes from the literal connection id
/// (DEC-007), and the endpoint carries the API base verbatim — the
/// region choice rides it, like the recorded bases' own
/// `compatible-mode/v1` roots.
fn alibaba_tp_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.alibaba-token-plan]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{ALIBABA_TP_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"alibaba-token-plan\", model_id = \"{ALIBABA_TP_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The recorded structured credential
/// (`parseAlibabaTokenPlanCredential`'s JSON shape): `token` bears
/// the wire and `baseUrl` is the region base the key was enrolled
/// and validated against.
fn token_plan_credential(token: &str, enrolled_base: &str) -> String {
    json!({"token": token, "baseUrl": enrolled_base}).to_string()
}

fn alibaba_tp_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(ALIBABA_TP_REF, material)],
    ));
    let provider = provider_result(
        config.clone(),
        "alibaba-token-plan".to_string(),
        store.clone(),
    )
    .expect("the shared adapter builds for the alibaba-token-plan id");
    (provider, store)
}

/// The `alibaba-token-plan` provider over the structured credential
/// enrolled for this connection's own configured base — the shape the
/// recorded login writes for a region diverging from the default.
fn enrolled_alibaba_tp_provider(
    config: &Config,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let enrolled = &config
        .connections
        .get("alibaba-token-plan")
        .expect("the alibaba-token-plan connection is declared")
        .endpoint;
    alibaba_tp_provider(config, &token_plan_credential(TOKEN_PLAN_KEY, enrolled))
}

// ----- TP-PROVIDER-WIRE::alibaba-token-plan -----------------------------------

/// A configured `alibaba-token-plan` connection returns a verified
/// model outcome through the standard Broker: prepare admits the
/// api_key pin under DEC-011, the recorded structured credential
/// unwraps to its bearer token — the enrolled `baseUrl` matching the
/// configured base — and the shared adapter posts exactly the frozen
/// manifest as a `chat/completions` request — pinned model,
/// system+user messages, `stream` with `stream_options.include_usage`
/// and the pinned effort as `reasoning_effort` verbatim — the SSE
/// stream validates its finish_reason/`[DONE]` terminal, and the one
/// physical send is charged once with the provider's reported usage.
#[tokio::test]
async fn alibaba_token_plan_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified outcome text",
            Some(json!({"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&alibaba_tp_config(&base)).expect("valid");
    // the recorded structured credential: `token` bears the wire and
    // `baseUrl` confirms the enrolled region is the configured one
    let (provider, _store) =
        alibaba_tp_provider(&config, &token_plan_credential(TOKEN_PLAN_KEY, &base));
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/alibaba-tp", "goal: prove the wire")
        .expect("the alibaba-token-plan pin passes DEC-011 eligibility");

    let (broker, outcome) = dispatch(broker, "/world/alibaba-tp", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified outcome text");
    assert!(reply.tool_calls.is_empty());

    // The wire request is exactly the frozen manifest — and nothing
    // the manifest does not carry; a fixed pin opens no catalogue leg.
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {TOKEN_PLAN_KEY}"),
        "the structured credential's token bears the wire — never the JSON blob"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(TOKEN_PLAN_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], json!(ALIBABA_TP_MODEL));
    assert_eq!(
        body["messages"],
        json!([
            {"role": "system", "content": manifest.instructions},
            {"role": "user", "content": manifest.inputs},
        ]),
        "the frozen instructions and inputs ride the messages verbatim"
    );
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["stream_options"],
        json!({"include_usage": true}),
        "the recorded usage request rides the stream options"
    );
    assert_eq!(
        body["reasoning_effort"],
        json!("medium"),
        "the pinned effort rides the recorded reasoning_effort surface"
    );

    // Exactly one accounting record carries the one physical usage
    // report — the provider's 18 tokens are the confirmed charge, and
    // a replayed attempt reports spent.
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "alibaba-token-plan");
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
            let replay = broker.dispatch(
                &mut rivect::model::NullLedger,
                "/world/alibaba-tp",
                &manifest,
            );
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
/// label: an id without the recorded Chat Completions class builds
/// no adapter — a Chat-Completions-classed id is reserved for its
/// own named contract arm — `dialect_for` reserving
/// `alibaba-token-plan` means the id is never fixture-served even
/// when it declares `local` kind, and a manifest pinning a different
/// connection id is refused at send.
#[test]
fn alibaba_token_plan_dialect_is_keyed_on_the_literal_connection_id() {
    let config =
        Config::parse_validated(&alibaba_tp_config("http://127.0.0.1:1/v1")).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = provider_result(config.clone(), "alibaba-token-plan-pro".to_string(), store)
        .expect_err("a different literal id is not this dialect");
    assert!(matches!(err, ProviderError::DialectMismatch { .. }));

    // a dialect-reserved id is never fixture-served whatever kind it
    // declares — `alibaba-token-plan` pinned `local` keeps the typed
    // denial
    let local = Config::parse_validated(
        "config_version = 1\n\
         [connections.alibaba-token-plan]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"alibaba-token-plan\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"medium\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let loopback = rivect::providers::LoopbackProvider::new();
    let entry = local
        .connections
        .get("alibaba-token-plan")
        .expect("declared");
    assert!(
        !loopback.serves("alibaba-token-plan", entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );

    // a manifest pinning a different connection id is refused at send —
    // the bound credential is well-formed so the denial is the dialect's,
    // never the credential seam's
    let (provider, _store) = alibaba_tp_provider(
        &config,
        &token_plan_credential(TOKEN_PLAN_KEY, "http://127.0.0.1:1/v1"),
    );
    let foreign = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.other]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1/v1\"\ncredential_ref = \"{ALIBABA_TP_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"other\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let manifest = {
        let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
        broker
            .prepare("main", &foreign, "/world/alibaba-tp", "goal: x")
            .expect("foreign pin prepares")
    };
    let (provider, outcome) = send_on_thread(provider, manifest);
    assert!(
        matches!(outcome, Err(ProviderError::DialectMismatch { .. })),
        "a foreign pin never speaks this dialect: {outcome:?}"
    );
    drop_blocking(provider);
}

// ----- TP-PROVIDER-CATALOG::alibaba-token-plan ---------------------------------

/// The `alibaba-token-plan` catalogue is the configured region's own
/// authoritative `/models` listing (HZN-008 class P —
/// `dynamicModelsAuthoritative`): the lookup resolves the structured
/// credential — its enrolled `baseUrl` bound to the configured base —
/// and opens the one `GET {endpoint}/models` leg under the bearer;
/// every admitted id is an offer under the recorded chat-id filter
/// (`isAlibabaTokenPlanChatModelId` — the `exclude-models` prefix
/// roster drops the ASR/image/embedding SKUs the chat picker cannot
/// route) and lands the defaults surface: the recorded reference and
/// limits hydration is the enrichment layer this adapter does not
/// carry, the same boundary `aimlapi` applies.
#[tokio::test]
async fn alibaba_token_plan_catalog_is_the_region_bound_authoritative_listing() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            // chat ids — admitted, offered verbatim
            json!({"id": ALIBABA_TP_MODEL}),
            json!({"id": "deepseek-v4-flash"}),
            json!({"id": "glm-5.1"}),
            // the recorded `exclude-models` prefix roster — the ASR,
            // image and embedding SKUs the chat picker cannot route
            json!({"id": "fun-asr-plus"}),
            json!({"id": "happyhorse-v1"}),
            json!({"id": "qwen-audio-asr"}),
            json!({"id": "qwen-image-2.5"}),
            json!({"id": "text-embedding-v4"}),
            json!({"id": "wan2.7-t2v"}),
            // the match runs on the normalized id — a spaced,
            // uppercased media id still fails the filter
            json!({"id": "  QWEN-IMAGE-3  "}),
            // a near miss: the roster is prefixes, not substrings —
            // `qwen-image` inside an id that does not start with it
            // still offers
            json!({"id": "vendor/qwen-image-captioner"}),
            // fields the listing may state are not a surface this
            // dialect reads — none of them lands
            json!({
                "id": "priced-chat",
                "context_window": 262144,
                "input": ["text", "image"],
            }),
            // empty or absent ids can never name a model
            json!({"id": ""}),
            json!({"id": "   "}),
            json!({"owned_by": "nobody"}),
        ],
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&alibaba_tp_config(&base)).expect("valid");
    let (provider, _store) =
        alibaba_tp_provider(&config, &token_plan_credential(TOKEN_PLAN_KEY, &base));
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the region's authoritative listing answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        vec![
            "deepseek-v4-flash",
            "glm-5.1",
            "priced-chat",
            ALIBABA_TP_MODEL,
            "vendor/qwen-image-captioner",
        ],
        "the authoritative listing filters to chat ids, sorted"
    );
    // every admitted id lands the defaults surface — a stated context
    // window or modality list is never adopted
    for model in &models {
        assert_eq!(
            model,
            &CatalogModel {
                id: model.id.clone(),
                ..CatalogModel::default()
            },
            "{}: the listing states the id alone",
            model.id
        );
    }
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "the listing leg is the only egress — no other endpoint is consulted"
    );
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {TOKEN_PLAN_KEY}"),
        "the unwrapped token bears the discovery leg"
    );
}

/// An empty configured endpoint resolves the recorded international
/// default — the `config?.baseUrl ?? ALIBABA_TOKEN_PLAN_BASE_URL`
/// absent arm our required `endpoint` field expresses as the empty
/// string, and whitespace-only shares the arm under the recorded
/// trim. Offline pin: the adapter's `Debug` surface reports the
/// resolved endpoint, so the arm is proved without one byte toward
/// `token-plan.ap-southeast-1.maas.aliyuncs.com` — the host the
/// bearer credential would egress to.
#[test]
fn alibaba_token_plan_empty_endpoint_resolves_the_recorded_intl_default() {
    for endpoint in ["", "   "] {
        let config = Config::parse_validated(&alibaba_tp_config(endpoint))
            .expect("an empty endpoint is valid");
        let (provider, _store) = alibaba_tp_provider(
            &config,
            &token_plan_credential(TOKEN_PLAN_KEY, TOKEN_PLAN_INTL_BASE),
        );
        let debug = format!("{provider:?}");
        assert!(
            debug.contains(&format!("endpoint: \"{TOKEN_PLAN_INTL_BASE}\"")),
            "endpoint {endpoint:?} resolved to the recorded default: {debug}"
        );
        drop_blocking(provider);
    }
}

/// The auto-pick catalogue leg rides the filtered listing: the
/// dispatch narrows the pool to the `alibaba-token-plan` member and
/// the shared adapter resolves the deterministic sorted-first
/// admitted id as the wire model — a listing whose every id the
/// roster excludes names no model, and the send denies unpinned
/// rather than offering a non-chat id.
#[tokio::test]
async fn alibaba_token_plan_auto_pick_resolves_through_the_authoritative_catalog() {
    let server = MockServer::start().await;
    // a rostered SKU sorts ahead of every admitted id yet never
    // enters the pick — the filtered listing alone names the wire
    // model, so the leg proves filter-before-pick rather than
    // ordering luck
    mount_models(
        &server,
        vec![
            json!({"id": "fun-asr-9-ultra"}),
            json!({"id": "qwen3.7-plus"}),
            json!({"id": "qwen3.8-flash"}),
        ],
    )
    .await;
    mount_chat(&server, completed_stream("auto pick", None)).await;
    let auto = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.alibaba-token-plan]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{ALIBABA_TP_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_alibaba_tp_provider(&auto),
        &auto,
        "/world/alibaba-tp",
        "goal: auto pick",
    );
    let (broker, outcome) = dispatch(broker, "/world/alibaba-tp", manifest);
    outcome.expect("the auto send resolves through the catalogue");
    drop_blocking(broker);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "the auto pick spends the one listing leg plus the send"
    );
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {TOKEN_PLAN_KEY}"),
        "the discovery leg bears the unwrapped token"
    );
    let send = requests
        .iter()
        .find(|request| request.url.path() == "/v1/chat/completions")
        .expect("the send crossed the wire");
    let body: Value = serde_json::from_slice(&send.body).expect("json body");
    assert_eq!(
        body["model"], "qwen3.7-plus",
        "the sorted-first admitted id rides the wire"
    );

    // a listing whose every id is rostered names no model — the send
    // denies unpinned, and the chat endpoint is never reached
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "qwen-image-2.5"})]).await;
    mount_chat(&server, completed_stream("unreachable", None)).await;
    let auto = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.alibaba-token-plan]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{ALIBABA_TP_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_alibaba_tp_provider(&auto),
        &auto,
        "/world/alibaba-tp",
        "goal: empty pick",
    );
    let (broker, outcome) = dispatch(broker, "/world/alibaba-tp", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnpinnedModel { .. }))
        ),
        "a fully filtered listing denies unpinned: {outcome:?}"
    );
    drop_blocking(broker);
    let requests = server.received_requests().await.expect("recorded");
    assert!(
        requests
            .iter()
            .all(|request| request.url.path() != "/v1/chat/completions"),
        "no send crosses the wire without a model the filter admitted"
    );
}

// ----- TP-PROVIDER-AUTH::alibaba-token-plan ------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `alibaba-token-plan`: a configured `region` — the recorded
/// contract carries the region choice on the endpoint and names no
/// `region` field — the profile-bound ref whose scope disagrees with
/// the binding, an absent credential, a structured credential with
/// no usable `token` and a refused bearer token each land a typed
/// denial, and none of them, nor any Debug surface the boundary
/// exposes, renders credential material or the peer's body.
#[tokio::test]
async fn alibaba_token_plan_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets()
 {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &alibaba_tp_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"cn\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "alibaba-token-plan".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, TOKEN_PLAN_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "alibaba-token-plan");
    assert_eq!(region, "cn");
    assert_no_secret_or_body(&err, TOKEN_PLAN_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.alibaba-token-plan]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"alibaba-token-plan\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "alibaba-token-plan".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, TOKEN_PLAN_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, TOKEN_PLAN_KEY.as_bytes());

    // a bound ref with no material at its own scope — the sibling
    // scope's material stays sealed behind the typed denial
    let config =
        Config::parse_validated(&alibaba_tp_config(&server_uri_v1(&server))).expect("valid");
    let provider = provider_result(
        config.clone(),
        "alibaba-token-plan".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, TOKEN_PLAN_KEY)],
        )),
    )
    .expect("binding resolves; the store is read at send");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("no material at the scope is the typed denial");
    assert!(matches!(err, ProviderError::CredentialAbsent { .. }));
    assert_no_secret_or_body(&err, TOKEN_PLAN_KEY.as_bytes());
    drop_blocking(provider);

    // a structured credential whose `token` is unusable is malformed —
    // the JSON blob is never sent as the bearer
    let blob = "{\"baseUrl\": \"https://elsewhere.example.com/v1\"}";
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(ALIBABA_TP_REF, blob)],
    ));
    let provider = provider_result(config.clone(), "alibaba-token-plan".to_string(), store)
        .expect("binding resolves");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a structured credential without a token is malformed");
    assert!(matches!(err, ProviderError::CredentialMalformed { .. }));
    assert_no_secret_or_body(&err, blob.as_bytes());
    drop_blocking(provider);

    // a refused bearer token is a typed transport denial — the wire
    // never coerces a wrong credential into success, and the peer's
    // body never enters the error
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let (provider, _store) = alibaba_tp_provider(
        &config,
        &token_plan_credential(TOKEN_PLAN_KEY, &server_uri_v1(&server)),
    );
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused token is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused token is transport: {err}")
    };
    assert_eq!(connection, "alibaba-token-plan");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, TOKEN_PLAN_KEY.as_bytes());
    drop_blocking(provider);

    // The same boundary on the Debug surfaces the dispatch path
    // exposes: provider, manifest, accounting record, broker and
    // runtime each render without the material the store alone holds.
    let server = MockServer::start().await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&alibaba_tp_config(&base)).expect("valid");
    let material = token_plan_credential(TOKEN_PLAN_KEY, &base);
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(ALIBABA_TP_REF, &material)],
    ));
    let provider = provider_result(config.clone(), "alibaba-token-plan".to_string(), store)
        .expect("the adapter builds");
    assert!(
        !format!("{provider:?}").contains(TOKEN_PLAN_KEY),
        "provider Debug never carries credential material"
    );
    mount_chat(
        &server,
        completed_stream(
            "accounted",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let (broker, manifest) = {
        let (provider, _store) = alibaba_tp_provider(&config, &material);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/alibaba-tp", "goal: debug surfaces")
            .expect("the pin passes DEC-011 eligibility");
        (broker, manifest)
    };
    assert!(
        !format!("{manifest:?}").contains(TOKEN_PLAN_KEY),
        "manifest Debug never carries credential material"
    );
    let (broker, outcome) = dispatch(broker, "/world/alibaba-tp", manifest.clone());
    outcome.expect("the debug-surface send completes");
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert!(
        !format!("{record:?}").contains(TOKEN_PLAN_KEY),
        "accounting-record Debug never carries credential material"
    );
    assert!(
        !format!("{broker:?}").contains(TOKEN_PLAN_KEY),
        "broker Debug never carries credential material"
    );
    drop_blocking(broker);
    drop_blocking(provider);

    let world = support::open_world(
        "auth-debug-alibaba-tp",
        Some(&alibaba_tp_config(&server_uri_v1(&server))),
    );
    assert!(
        !format!("{:?}", world.runtime).contains(TOKEN_PLAN_KEY),
        "runtime Debug never carries credential material"
    );
}

/// The recorded non-interchangeability predicate (HZN-008 class P):
/// a key enrolled for one region — international, China or a custom
/// origin — can never serve another, because the credential's
/// `baseUrl` is the region base the key authenticates against and
/// must equal the connection's configured endpoint; every mismatch
/// or foreign-grammar credential lands a typed denial before any
/// wire leg — zero requests reach any mock. A bare `sk-…` token or a
/// blob without `baseUrl` records the absent case — the default
/// international endpoint — so it is the intl class credential and
/// binds that base alone; material the recorded parse never produces
/// — a non-`sk-…` token, a non-string member — is malformed on every
/// base.
#[tokio::test]
async fn alibaba_token_plan_enrolled_bases_are_not_interchangeable() {
    // Three stand-in bases — distinct mock origins: a denied send
    // that still egressed would be observed, and no configured
    // endpoint ever names a real host. The recorded base literals
    // appear only inside credential material — they ride the store,
    // never a socket.
    let intl = MockServer::start().await;
    let cn = MockServer::start().await;
    let custom = MockServer::start().await;
    let intl_base = server_uri_v1(&intl);
    let cn_base = server_uri_v1(&cn);
    let custom_base = server_uri_v1(&custom);
    let bases: [(&str, &String, &MockServer); 3] = [
        ("intl", &intl_base, &intl),
        ("cn", &cn_base, &cn),
        ("custom", &custom_base, &custom),
    ];

    // (credential material, the only base it may serve, the typed
    // denial every other pairing lands): a denied send never reaches
    // a socket — the enrolled host included
    let credentials: [(&str, String, PlanDeny); 25] = [
        // keys enrolled for each base class serve that base alone
        (
            "intl",
            token_plan_credential(TOKEN_PLAN_KEY, &intl_base),
            PlanDeny::BaseMismatch(intl_base.clone()),
        ),
        (
            "cn",
            token_plan_credential(TOKEN_PLAN_KEY, &cn_base),
            PlanDeny::BaseMismatch(cn_base.clone()),
        ),
        (
            "custom",
            token_plan_credential(TOKEN_PLAN_KEY, &custom_base),
            PlanDeny::BaseMismatch(custom_base.clone()),
        ),
        // the real recorded base literals are classes of their own —
        // a credential enrolled at the real intl or CN endpoint is
        // not a mock's credential either
        (
            "none",
            token_plan_credential(TOKEN_PLAN_KEY, TOKEN_PLAN_INTL_BASE),
            PlanDeny::BaseMismatch(TOKEN_PLAN_INTL_BASE.to_string()),
        ),
        (
            "none",
            token_plan_credential(TOKEN_PLAN_KEY, TOKEN_PLAN_CN_BASE),
            PlanDeny::BaseMismatch(TOKEN_PLAN_CN_BASE.to_string()),
        ),
        // a key enrolled at an unrelated origin serves none of them
        (
            "none",
            token_plan_credential(TOKEN_PLAN_KEY, "https://elsewhere.example.com/v1"),
            PlanDeny::BaseMismatch("https://elsewhere.example.com/v1".to_string()),
        ),
        // the recorded absent case: a bare `sk-…` token or a blob
        // without `baseUrl` is enrolled for the default international
        // endpoint — it is the intl class credential on every other
        // configured base
        (
            "none",
            TOKEN_PLAN_KEY.to_string(),
            PlanDeny::BaseMismatch(TOKEN_PLAN_INTL_BASE.to_string()),
        ),
        (
            "none",
            json!({"token": TOKEN_PLAN_KEY}).to_string(),
            PlanDeny::BaseMismatch(TOKEN_PLAN_INTL_BASE.to_string()),
        ),
        (
            "none",
            json!({"token": TOKEN_PLAN_KEY, "baseUrl": ""}).to_string(),
            PlanDeny::BaseMismatch(TOKEN_PLAN_INTL_BASE.to_string()),
        ),
        // the separately admitted quota `cookie` never alters the
        // binding — this blob records no base, so it is intl-enrolled
        (
            "none",
            json!({"token": TOKEN_PLAN_KEY, "cookie": QUOTA_COOKIE}).to_string(),
            PlanDeny::BaseMismatch(TOKEN_PLAN_INTL_BASE.to_string()),
        ),
        // …and never reaches a diagnostic: this blob denies on a
        // foreign enrolled base, and the deny loop scans both
        // renderings for the distinctive cookie material
        (
            "none",
            json!({"token": TOKEN_PLAN_KEY, "cookie": QUOTA_COOKIE_XYZ, "baseUrl": "https://elsewhere.example.com/v1"})
                .to_string(),
            PlanDeny::BaseMismatch("https://elsewhere.example.com/v1".to_string()),
        ),
        // material the recorded parse never produces — malformed on
        // every base, enrolled host included: a present-but-empty
        // store blob is malformed, never absent
        ("none", String::new(), PlanDeny::Malformed),
        ("none", "   ".to_string(), PlanDeny::Malformed),
        (
            "none",
            "fixture-token-not-a-real-credential".to_string(),
            PlanDeny::Malformed,
        ),
        // the recorded key grammar's reject arms — an empty core,
        // more than two pad characters, `=` inside the core: a
        // cookie-shaped blob is never a token
        ("none", "sk-".to_string(), PlanDeny::Malformed),
        ("none", "sk-abc===".to_string(), PlanDeny::Malformed),
        ("none", "sk-a=b".to_string(), PlanDeny::Malformed),
        ("none", "{\"token\": 42}".to_string(), PlanDeny::Malformed),
        ("none", "{not-json".to_string(), PlanDeny::Malformed),
        (
            "none",
            json!({"token": "fixture-token-not-a-real-credential", "baseUrl": intl_base.as_str()})
                .to_string(),
            PlanDeny::Malformed,
        ),
        (
            "none",
            json!({"token": TOKEN_PLAN_KEY, "baseUrl": null}).to_string(),
            PlanDeny::Malformed,
        ),
        (
            "none",
            json!({"token": TOKEN_PLAN_KEY, "baseUrl": 42}).to_string(),
            PlanDeny::Malformed,
        ),
        (
            "none",
            json!({"token": TOKEN_PLAN_KEY, "cookie": 42, "baseUrl": intl_base.as_str()})
                .to_string(),
            PlanDeny::Malformed,
        ),
        (
            "none",
            json!({"token": TOKEN_PLAN_KEY, "cookie": null, "baseUrl": intl_base.as_str()})
                .to_string(),
            PlanDeny::Malformed,
        ),
        // the recorded ingress normalization: a trailing slash on the
        // enrolled base still matches the configured one
        (
            "intl",
            token_plan_credential(TOKEN_PLAN_KEY, &format!("{intl_base}/")),
            PlanDeny::BaseMismatch(intl_base.clone()),
        ),
    ];

    // every deny pairing first, while no mock has seen a request —
    // a wrong credential never reaches a socket, enrolled host
    // included
    for (serves, material, deny) in &credentials {
        for (base_label, base, _server) in &bases {
            if serves == base_label {
                continue;
            }
            let config = Config::parse_validated(&alibaba_tp_config(base)).expect("valid");
            let store = Arc::new(support::MapStore::seeded(
                STORE_KIND,
                &[(ALIBABA_TP_REF, material.as_str())],
            ));
            let provider = provider_result(config.clone(), "alibaba-token-plan".to_string(), store)
                .expect("binding resolves");
            let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
            let err = outcome.expect_err("a wrong-base or wrong-grammar credential denies");
            match (deny, &err) {
                (PlanDeny::Malformed, ProviderError::CredentialMalformed { connection }) => {
                    assert_eq!(connection, "alibaba-token-plan");
                }
                (
                    PlanDeny::BaseMismatch(enrolled),
                    ProviderError::CredentialBaseMismatch {
                        connection,
                        enrolled: reported,
                    },
                ) => {
                    assert_eq!(connection, "alibaba-token-plan");
                    assert_eq!(
                        reported, enrolled,
                        "the denial reports the credential's own enrolled base"
                    );
                }
                _ => panic!(
                    "{serves}-enrolled credential on {base_label} base denies as {deny:?}: {err}"
                ),
            }
            assert_no_secret_or_body(&err, TOKEN_PLAN_KEY.as_bytes());
            // a denied credential's `cookie` member never reaches a
            // diagnostic — Display or Debug — at any granularity
            for rendered in [format!("{err}"), format!("{err:?}")] {
                for marker in [QUOTA_COOKIE_XYZ, "diag_quota", "QUOTA_COOKIE_XYZ"] {
                    assert!(
                        !rendered.contains(marker),
                        "the quota cookie never renders: {rendered}"
                    );
                }
            }
            drop_blocking(provider);
            for (_, _, server) in &bases {
                assert!(
                    server
                        .received_requests()
                        .await
                        .expect("recorded")
                        .is_empty(),
                    "no wire leg left the denied send — the enrolled host included"
                );
            }
        }
    }

    // the serve pairings: each enrolled key on its own base — the
    // enrolled base equals the configured one
    for (label, server) in [("intl", &intl), ("cn", &cn), ("custom", &custom)] {
        mount_chat(server, completed_stream(&format!("served-{label}"), None)).await;
    }
    for (serves, material, _deny) in &credentials {
        for (base_label, base, server) in &bases {
            if serves != base_label {
                continue;
            }
            let config = Config::parse_validated(&alibaba_tp_config(base)).expect("valid");
            let store = Arc::new(support::MapStore::seeded(
                STORE_KIND,
                &[(ALIBABA_TP_REF, material.as_str())],
            ));
            let provider = provider_result(config.clone(), "alibaba-token-plan".to_string(), store)
                .expect("binding resolves");
            let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
            let reply = outcome.unwrap_or_else(|err| {
                panic!("{serves}-enrolled credential serves the {base_label} base: {err}")
            });
            assert_eq!(reply.text, format!("served-{base_label}"));
            drop_blocking(provider);
            let requests = server.received_requests().await.expect("recorded");
            let last = requests.last().expect("the serve crossed the wire");
            assert_eq!(
                received_auth(last),
                format!("Bearer {TOKEN_PLAN_KEY}"),
                "the unwrapped plan token bears the wire"
            );
        }
    }

    // exactly the serve legs crossed the wire — each enrolled key on
    // its own base plus intl's extra trailing-slash enrolled leg —
    // and every denial left none
    for (label, _, server) in &bases {
        let expected = if label == &"intl" { 2 } else { 1 };
        let requests = server.received_requests().await.expect("recorded");
        assert_eq!(
            requests.len(),
            expected,
            "the serve legs alone egressed on the {label} base"
        );
    }
    // Let the mock servers' in-flight handler tasks drain before the
    // servers drop: `MockServer::drop` verifies through a futures
    // `block_on` that cannot drive this runtime, so a handler still
    // holding the state write lock would park the teardown forever.
    tokio::task::yield_now().await;
}

/// A `CredentialBaseMismatch` reports the enrolled base in the
/// canonical egress form — the same rendering consent and journal
/// surfaces use — so store content carrying userinfo or a query
/// never reaches the diagnostic.
#[tokio::test]
async fn alibaba_token_plan_base_mismatch_redacts_enrolled_url_parts() {
    let server = MockServer::start().await;
    let config =
        Config::parse_validated(&alibaba_tp_config(&server_uri_v1(&server))).expect("valid");
    let material = json!({
        "token": TOKEN_PLAN_KEY,
        "baseUrl": "https://user:pw@host.invalid/v1?x=1",
    })
    .to_string();
    let (provider, _store) = alibaba_tp_provider(&config, &material);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a foreign enrolled base denies");
    let ProviderError::CredentialBaseMismatch {
        connection,
        enrolled,
    } = &err
    else {
        panic!("the foreign enrolled base is the typed mismatch: {err}")
    };
    assert_eq!(connection, "alibaba-token-plan");
    assert_eq!(
        enrolled, "https://host.invalid/v1",
        "the reported enrolled base drops userinfo and query"
    );
    let rendered = err.to_string();
    for secret_part in ["user", "pw", "x=1"] {
        assert!(
            !rendered.contains(secret_part),
            "the enrolled base's {secret_part:?} never renders: {rendered}"
        );
    }
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "no wire leg left the denied send"
    );
    tokio::task::yield_now().await;
}

/// The headline discriminator, both clauses. Region-bound catalogue:
/// a credential enrolled for the configured base discovers the
/// listing there, while one enrolled for a foreign region is denied
/// before any wire leg — the discovery endpoint is never borrowed
/// from store material, so a credential's own `baseUrl` cannot steer
/// egress to its recorded host either. Optional quota cookie: the
/// recorded `cookie` member is the separately admitted capability the
/// login pastes by hand for a usage API this adapter has no leg for —
/// the parse admits its shape, then drops it: no `Cookie` header, no
/// request part and no Debug surface ever carries the material, and
/// no browser/DevTools extraction path exists to produce it.
#[tokio::test]
async fn alibaba_token_plan_region_bound_catalog_and_optional_quota_cookie_is_never_auto_extracted()
{
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": ALIBABA_TP_MODEL}),
            json!({"id": "qwen-audio-asr"}),
        ],
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&alibaba_tp_config(&base)).expect("valid");
    // the full recorded credential shape — token, the enrolled region
    // base and the pasted quota cookie
    let material = json!({
        "token": TOKEN_PLAN_KEY,
        "cookie": QUOTA_COOKIE,
        "baseUrl": base,
    })
    .to_string();

    // region-bound: the catalogue leg discovers the configured
    // region's own listing under the bound credential
    let (provider, _store) = alibaba_tp_provider(&config, &material);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the region-bound listing answers");
    assert_eq!(
        model_ids(&models),
        vec![ALIBABA_TP_MODEL],
        "the filtered authoritative listing"
    );
    drop_blocking(provider);

    // a credential enrolled for the recorded CN endpoint binds no
    // catalogue on this configured base — the region mismatch is
    // typed before any wire leg, and no request ever reaches the
    // credential's recorded host: the configured endpoint alone
    // decides egress
    let (provider, _store) = alibaba_tp_provider(
        &config,
        &token_plan_credential(TOKEN_PLAN_KEY, TOKEN_PLAN_CN_BASE),
    );
    let (provider, denied) = catalog_on_thread(provider);
    let err = denied.expect_err("a foreign-enrolled credential binds no catalogue");
    let ProviderError::CredentialBaseMismatch {
        connection,
        enrolled,
    } = &err
    else {
        panic!("the foreign region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "alibaba-token-plan");
    assert_eq!(enrolled, TOKEN_PLAN_CN_BASE);
    drop_blocking(provider);

    // the quota cookie never reaches the wire: the send under the
    // cookie-bearing credential carries the bearer alone — no
    // `Cookie` header, no cookie material in any request part
    mount_chat(&server, completed_stream("wired", None)).await;
    let (provider, _store) = alibaba_tp_provider(&config, &material);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    outcome.expect("the cookie-bearing credential serves its own base");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "the models leg and the send leg alone crossed"
    );
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(requests[1].url.path(), "/v1/chat/completions");
    for request in &requests {
        assert!(
            request.headers.get("cookie").is_none(),
            "no Cookie header ever rides a leg: {:?}",
            request.headers
        );
        assert_eq!(
            received_auth(request),
            format!("Bearer {TOKEN_PLAN_KEY}"),
            "the unwrapped token bears every leg — never the JSON blob"
        );
        let rendered = format!(
            "{}{:?}",
            request.url,
            String::from_utf8_lossy(&request.body)
        );
        for marker in [QUOTA_COOKIE, "fixture_quota", "session=fixture"] {
            assert!(
                !rendered.contains(marker),
                "no part of the quota cookie reaches the wire: {marker}"
            );
        }
        for value in request.headers.values() {
            let value = value.to_str().expect("header values are ascii");
            for marker in [QUOTA_COOKIE, "fixture_quota", "session=fixture"] {
                assert!(
                    !value.contains(marker),
                    "no header carries the quota cookie: {marker}"
                );
            }
        }
    }
}

/// The configured side of the binding takes the same recorded ingress
/// normalization: an `endpoint` carrying a trailing slash resolves to
/// the same base the credential enrolled, and the request path never
/// doubles the slash.
#[tokio::test]
async fn alibaba_token_plan_configured_trailing_slash_binds_the_same_base() {
    let server = MockServer::start().await;
    mount_chat(&server, completed_stream("slashed", None)).await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&alibaba_tp_config(&format!("{base}/"))).expect("valid");
    let (provider, _store) =
        alibaba_tp_provider(&config, &token_plan_credential(TOKEN_PLAN_KEY, &base));
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    outcome.expect("the normalized configured base binds the enrolled credential");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].url.path(),
        "/v1/chat/completions",
        "the resolved base carries no doubled slash"
    );
    tokio::task::yield_now().await;
}

// ----- TP-PROVIDER-RECOVERY::alibaba-token-plan --------------------------------

/// A typed denial is recoverable through the same seam: the absent
/// credential denies the first send, enrolling a plan key at the
/// scope admits the retry — no state wedged, no plaintext path
/// taken.
#[tokio::test]
async fn alibaba_token_plan_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&alibaba_tp_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(
        config.clone(),
        "alibaba-token-plan".to_string(),
        store.clone(),
    )
    .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialAbsent { .. })
    ));

    store.enroll(
        ALIBABA_TP_REF,
        token_plan_credential(TOKEN_PLAN_KEY, &server_uri_v1(&server)).as_bytes(),
    );
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the enrolled credential admits the retry");
    assert_eq!(reply.text, "recovered");
    drop_blocking(provider);
}

/// The legs matrix enforces the recorded expected set for
/// `alibaba-token-plan`: CATALOG, AUTH, WIRE and RECOVERY each
/// execute and report inside this run, and INSTALLED reports
/// NOT_RUN — an omitted leg fails the suite rather than silently
/// absenting.
#[tokio::test]
async fn alibaba_token_plan_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": ALIBABA_TP_MODEL}),
            json!({"id": "text-embedding-v4"}),
        ],
    )
    .await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&alibaba_tp_config(&base)).expect("valid");

    // CATALOG: the region's authoritative `/models` listing answers
    // under the bound credential — filtered to the admitted ids.
    let (provider, _store) =
        alibaba_tp_provider(&config, &token_plan_credential(TOKEN_PLAN_KEY, &base));
    let (provider, catalog) = catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if matches!(catalog, Ok(ref models) if model_ids(models) == [ALIBABA_TP_MODEL]) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: an empty store denies at send with the typed verdict.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "alibaba-token-plan".to_string(), empty)
        .expect("binding resolves");
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
    let (broker, manifest) = prepared_with(
        enrolled_alibaba_tp_provider(&config),
        &config,
        "/world/alibaba-tp",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/alibaba-tp", manifest);
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
    let provider = provider_result(
        config.clone(),
        "alibaba-token-plan".to_string(),
        empty.clone(),
    )
    .expect("resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(
        ALIBABA_TP_REF,
        token_plan_credential(TOKEN_PLAN_KEY, &server_uri_v1(&server)).as_bytes(),
    );
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

    // The literal row mirrors the `#[ignore]`d
    // `provider_installed_alibaba_token_plan` case below: its ignored
    // count is the explicit NOT_RUN signal this matrix asserts — the
    // row stays a literal so the two cannot drift.
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

// ----- TP-PROVIDER-INSTALLED::alibaba-token-plan -------------------------------

/// TP-PROVIDER-INSTALLED::alibaba-token-plan = NOT_RUN: the
/// installed-provider proof is a live-environment leg this offline
/// slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::alibaba-token-plan = NOT_RUN"]
fn provider_installed_alibaba_token_plan() {}

// ----- coreweave -------------------------------------------------------------
//
// The `coreweave` connection's proof legs (HZN-008 class A): the
// shared Chat Completions adapter serves the literal id — no copied
// codec — under its own recorded predicates (`Rivect/key +
// OpenAI-Project`, wire/coreweave.ts). The configured `endpoint`
// carries the API base verbatim — an empty one resolves the recorded
// `api.inference.wandb.ai/v1` default (`config?.baseUrl ??
// defaultBaseUrl`'s absent arm), and a configured `region` is denied:
// the contract names none. The catalogue is the configured base's
// own authoritative `/models` listing and ids-only offers: team and
// project spend and geography stay recorded account data, never
// synthesized catalog metadata. The credential slot holds the scoped
// `{"key": …, "OpenAI-Project": "<team>/<project>"}` JSON — Rivect's
// translated store form of the recorded `api-key` login, whose
// `OpenAI-Project` header hook resolves from the environment, a
// channel the transport has none of: the `key` is the bearer and the
// `OpenAI-Project` becomes the header (the recorded surface resolves
// that scope before any fetch and fails closed without it). The bare
// pasted key is login input the credential substrate resolves into
// that stored form, never store material here, so material outside
// the scoped shape — a bare key, a key-only blob, an empty member,
// JSON that is not an object with both members — denies before any
// wire leg.

/// The scoped credential ref the `coreweave` connection binds.
const COREWEAVE_REF: &str = "keyring:rivect-test/coreweave";

/// Fixture coreweave key material — never a real credential, only
/// ever sent to localhost.
const COREWEAVE_KEY: &str = "fixture-coreweave-key";

/// The recorded `<team>/<project>` scope the `OpenAI-Project` header
/// carries.
const COREWEAVE_PROJECT: &str = "fixture-team/fixture-project";

/// The pinned model id the fixed-pin legs carry.
const COREWEAVE_MODEL: &str = "fixture-cw-model";

/// One configured `coreweave` connection pointing at the fixture
/// peer: the api_key auth class resolves a scoped `SecretRef`
/// (DEC-011), the dialect comes from the literal connection id
/// (DEC-007), and the endpoint carries the API base verbatim.
fn coreweave_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.coreweave]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{COREWEAVE_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"coreweave\", model_id = \"{COREWEAVE_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The scoped `{"key": …, "OpenAI-Project": "<team>/<project>"}` JSON —
/// Rivect's translated store form of the recorded `api-key` login; the
/// bare pasted key is login input the credential substrate resolves,
/// never store material.
fn coreweave_credential(key: &str, project: &str) -> String {
    json!({"key": key, "OpenAI-Project": project}).to_string()
}

fn coreweave_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(COREWEAVE_REF, material)],
    ));
    let provider = provider_result(config.clone(), "coreweave".to_string(), store.clone())
        .expect("the shared adapter builds for the coreweave id");
    (provider, store)
}

/// The `coreweave` provider over the recorded scoped credential —
/// the documented `key` plus `OpenAI-Project` form.
fn enrolled_coreweave_provider(
    config: &Config,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    coreweave_provider(
        config,
        &coreweave_credential(COREWEAVE_KEY, COREWEAVE_PROJECT),
    )
}

/// The `OpenAI-Project` scope header a scoped `coreweave` credential
/// carries.
fn received_project(request: &Request) -> String {
    request
        .headers
        .get("openai-project")
        .and_then(|value| value.to_str().ok())
        .expect("the request carried an openai-project header")
        .to_string()
}

// ----- TP-PROVIDER-WIRE::coreweave ---------------------------------------------

/// A configured `coreweave` connection returns a verified model
/// outcome through the standard Broker: prepare admits the api_key
/// pin under DEC-011, the scoped store material bears the wire —
/// `Authorization: Bearer` with the recorded `OpenAI-Project` scope
/// header, resolved by the login before the store — and the
/// shared adapter posts exactly the frozen manifest as a
/// `chat/completions` request — pinned model, system+user messages,
/// `stream` with `stream_options.include_usage` and the pinned effort
/// as `reasoning_effort` verbatim — the SSE stream validates its
/// finish_reason/`[DONE]` terminal, and the one physical send is
/// charged once with the provider's reported usage.
#[tokio::test]
async fn coreweave_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified outcome text",
            Some(json!({"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&coreweave_config(&base)).expect("valid");
    let (provider, _store) = enrolled_coreweave_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/coreweave", "goal: prove the wire")
        .expect("the coreweave pin passes DEC-011 eligibility");

    let (broker, outcome) = dispatch(broker, "/world/coreweave", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified outcome text");
    assert!(reply.tool_calls.is_empty());

    // The wire request is exactly the frozen manifest — and nothing
    // the manifest does not carry; a fixed pin opens no catalogue leg.
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {COREWEAVE_KEY}"),
        "the scoped material's `key` bears the wire verbatim"
    );
    assert_eq!(
        received_project(&requests[0]),
        COREWEAVE_PROJECT,
        "the scoped material's `OpenAI-Project` rides every leg"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(COREWEAVE_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], json!(COREWEAVE_MODEL));
    assert_eq!(
        body["messages"],
        json!([
            {"role": "system", "content": manifest.instructions},
            {"role": "user", "content": manifest.inputs},
        ]),
        "the frozen instructions and inputs ride the messages verbatim"
    );
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["stream_options"],
        json!({"include_usage": true}),
        "the recorded usage request rides the stream options"
    );
    assert_eq!(
        body["reasoning_effort"],
        json!("medium"),
        "the pinned effort rides the recorded reasoning_effort surface"
    );

    // Exactly one accounting record carries the one physical usage
    // report — the provider's 18 tokens are the confirmed charge, and
    // a replayed attempt reports spent.
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "coreweave");
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
            let replay = broker.dispatch(
                &mut rivect::model::NullLedger,
                "/world/coreweave",
                &manifest,
            );
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

/// Hostile stream input is never a false success for `coreweave`: a
/// stream ended mid `tool_calls` fragment — a partial call that never
/// executes — and a finish_reason the dialect cannot classify are both
/// the unknown terminal, and a rejected send charges nothing.
#[tokio::test]
async fn coreweave_adverse_wire_input_never_reports_success() {
    // a complete content delta plus an unterminated tool-call
    // fragment, then EOF — no finish_reason and no [DONE]
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&delta_chunk(json!({
                "tool_calls": [{
                    "index": 0,
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": "{\"path\":"},
                }],
            }))),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&coreweave_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_coreweave_provider(&config),
        &config,
        "/world/coreweave",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/coreweave", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "EOF mid tool call is the unknown terminal — never a usable call: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);

    // a finish_reason the dialect cannot classify is unknown, never
    // success
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&finish_chunk("mystery")),
            DONE_BLOCK
        ),
    )
    .await;
    let config =
        Config::parse_validated(&coreweave_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_coreweave_provider(&config),
        &config,
        "/world/coreweave",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/coreweave", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "an unclassifiable terminal is the unknown terminal: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);
}

/// The dialect keys on the literal connection id, never an auth
/// label: an id without the recorded Chat Completions class builds
/// no adapter — a Chat-Completions-classed id is reserved for its
/// own named contract arm — `dialect_for` reserving `coreweave`
/// means the id is never fixture-served even when it declares
/// `local` kind, and a manifest pinning a different connection id is
/// refused at send.
#[test]
fn coreweave_dialect_is_keyed_on_the_literal_connection_id() {
    assert_eq!(
        rivect::providers::dialect_for("coreweave"),
        Some(rivect::providers::Dialect::ChatCompletions),
        "the literal id binds the shared Chat Completions dialect"
    );
    let config =
        Config::parse_validated(&coreweave_config("http://127.0.0.1:1/v1")).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = provider_result(config.clone(), "coreweave-pro".to_string(), store)
        .expect_err("a different literal id is not this dialect");
    assert!(matches!(err, ProviderError::DialectMismatch { .. }));

    // a dialect-reserved id is never fixture-served whatever kind it
    // declares — `coreweave` pinned `local` keeps the typed denial
    let local = Config::parse_validated(
        "config_version = 1\n\
         [connections.coreweave]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"coreweave\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"medium\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let loopback = rivect::providers::LoopbackProvider::new();
    let entry = local.connections.get("coreweave").expect("declared");
    assert!(
        !loopback.serves("coreweave", entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );

    // a manifest pinning a different connection id is refused at send —
    // the bound credential is well-formed so the denial is the dialect's,
    // never the credential seam's
    let (provider, _store) = enrolled_coreweave_provider(&config);
    let foreign = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.other]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1/v1\"\ncredential_ref = \"{COREWEAVE_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"other\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let manifest = {
        let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
        broker
            .prepare("main", &foreign, "/world/coreweave", "goal: x")
            .expect("foreign pin prepares")
    };
    let (provider, outcome) = send_on_thread(provider, manifest);
    assert!(
        matches!(outcome, Err(ProviderError::DialectMismatch { .. })),
        "a foreign pin never speaks this dialect: {outcome:?}"
    );
    drop_blocking(provider);
}

// ----- TP-PROVIDER-CATALOG::coreweave ------------------------------------------

/// The `coreweave` catalogue is the configured base's own
/// authoritative `/models` listing (HZN-008 class A): the lookup
/// resolves the scoped credential — `key` bearer plus its
/// `OpenAI-Project` header on the one `GET {endpoint}/models` leg —
/// and every `id` with a non-whitespace body is an offer landing the
/// ids-only surface: team and project spend and geography stay
/// recorded account data, never synthesized catalog metadata.
#[tokio::test]
async fn coreweave_catalog_is_the_authoritative_ids_only_listing() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "cw-chat-large"}),
            json!({"id": COREWEAVE_MODEL}),
            // fields the listing may state are account or deployment
            // data — spend, team, region — never a surface this
            // dialect reads: none of them lands
            json!({
                "id": "priced-chat",
                "context_window": 262144,
                "owned_by": "fixture-team",
                "region": "eu-west",
            }),
            // only a non-whitespace id offers — an empty, absent or
            // whitespace-only id can never name a model
            json!({"id": ""}),
            json!({"id": "   "}),
            json!({"owned_by": "nobody"}),
        ],
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&coreweave_config(&base)).expect("valid");
    let (provider, _store) = enrolled_coreweave_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the authoritative listing answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        vec!["cw-chat-large", COREWEAVE_MODEL, "priced-chat"],
        "the authoritative listing answers every usable id verbatim, sorted"
    );
    assert!(
        !models.iter().any(|model| model.id.trim().is_empty()),
        "a whitespace-only id names no model: {:?}",
        model_ids(&models)
    );
    // every admitted id lands the ids-only surface — a stated context
    // window, owner or region is never adopted
    for model in &models {
        assert_eq!(
            model,
            &CatalogModel {
                id: model.id.clone(),
                ..CatalogModel::default()
            },
            "{}: the listing states the id alone",
            model.id
        );
    }
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "the listing leg is the only egress — no other endpoint is consulted"
    );
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {COREWEAVE_KEY}"),
        "the credential's `key` bears the discovery leg"
    );
    assert_eq!(
        received_project(&requests[0]),
        COREWEAVE_PROJECT,
        "the scope header rides the catalogue leg like every other leg"
    );
}

/// An empty configured endpoint resolves the recorded default —
/// the `config?.baseUrl ?? defaultBaseUrl` absent arm our required
/// `endpoint` field expresses as the empty string, and
/// whitespace-only shares the arm under the recorded trim. Offline
/// pin: the adapter's `Debug` surface reports the resolved endpoint,
/// so the arm is proved without one byte toward
/// `api.inference.wandb.ai` — the host the scoped credential would
/// egress to.
#[test]
fn coreweave_empty_endpoint_resolves_the_recorded_default() {
    for endpoint in ["", "   "] {
        let config = Config::parse_validated(&coreweave_config(endpoint))
            .expect("an empty endpoint is valid");
        let (provider, _store) = enrolled_coreweave_provider(&config);
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"https://api.inference.wandb.ai/v1\""),
            "endpoint {endpoint:?} resolved to the recorded default: {debug}"
        );
        drop_blocking(provider);
    }
}

/// The auto-pick catalogue leg rides the authoritative listing: the
/// dispatch narrows the pool to the `coreweave` member and the shared
/// adapter resolves the deterministic sorted-first id as the wire
/// model.
#[tokio::test]
async fn coreweave_auto_pick_resolves_through_the_authoritative_catalog() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![json!({"id": "zz-late"}), json!({"id": "aa-first"})],
    )
    .await;
    mount_chat(
        &server,
        completed_stream(
            "auto picked",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.coreweave]\nkind = \"api_key\"\nendpoint = \"{base}\"\ncredential_ref = \"{COREWEAVE_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\", pool = [\"coreweave\"] }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let (provider, _store) = enrolled_coreweave_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/coreweave", "goal: auto pick")
        .expect("the single-member pool pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/coreweave", manifest);
    let reply = outcome.expect("the auto pick dispatches");
    assert_eq!(reply.text, "auto picked");
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "the catalogue leg and the send are the only egress"
    );
    let body: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert_eq!(
        body["model"],
        json!("aa-first"),
        "the deterministic sorted-first id names the wire model"
    );
}

// ----- TP-PROVIDER-AUTH::coreweave ---------------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `coreweave`: a configured `region` — the recorded contract names
/// none — the profile-bound ref whose scope disagrees with the
/// binding, an absent credential, credential material outside the
/// scoped store shape and a refused bearer token each land a typed
/// denial, and none of them, nor any Debug surface the boundary
/// exposes, renders credential material or the peer's body.
#[tokio::test]
async fn coreweave_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &coreweave_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "coreweave".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, COREWEAVE_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "coreweave");
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, COREWEAVE_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.coreweave]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"coreweave\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "coreweave".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, COREWEAVE_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, COREWEAVE_KEY.as_bytes());

    // a bound ref with no material at its own scope — the sibling
    // scope's material stays sealed behind the typed denial
    let config =
        Config::parse_validated(&coreweave_config(&server_uri_v1(&server))).expect("valid");
    let provider = provider_result(
        config.clone(),
        "coreweave".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, COREWEAVE_KEY)],
        )),
    )
    .expect("binding resolves; the store is read at send");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("no material at the scope is the typed denial");
    assert!(matches!(err, ProviderError::CredentialAbsent { .. }));
    assert_no_secret_or_body(&err, COREWEAVE_KEY.as_bytes());
    drop_blocking(provider);

    // material outside the scoped store shape is the recorded
    // fail-closed: the recorded bare paste key — login input the
    // credential substrate resolves, never store material — a
    // key-only blob, an empty scope member, an empty or
    // whitespace-only key, an object naming no `key`, a JSON body
    // of the wrong shape — a quoted string, an array — and
    // structure-looking material that does not parse: a truncated
    // object, a BOM-prefixed scoped blob, a single-quoted shell blob,
    // and the bare paste wrapped the same ways — each denies
    // malformed before any wire leg — zero requests reach the mock
    for material in [
        COREWEAVE_KEY.to_string(),
        json!({"key": COREWEAVE_KEY}).to_string(),
        json!({"key": COREWEAVE_KEY, "OpenAI-Project": "  "}).to_string(),
        json!({"key": "", "OpenAI-Project": COREWEAVE_PROJECT}).to_string(),
        json!({"key": "  ", "OpenAI-Project": COREWEAVE_PROJECT}).to_string(),
        json!({"OpenAI-Project": COREWEAVE_PROJECT}).to_string(),
        json!("\"quoted-json-string\"").to_string(),
        json!([COREWEAVE_KEY]).to_string(),
        "{\"key\": \"sk-live\",".to_string(),
        "[1".to_string(),
        "\"sk-live".to_string(),
        format!(
            "\u{feff}{}",
            coreweave_credential(COREWEAVE_KEY, COREWEAVE_PROJECT)
        ),
        format!(
            "'{}'",
            coreweave_credential(COREWEAVE_KEY, COREWEAVE_PROJECT)
        ),
        format!("\u{feff}{COREWEAVE_KEY}"),
        format!("'{COREWEAVE_KEY}'"),
    ] {
        let (provider, _store) = coreweave_provider(&config, &material);
        let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
        let err = outcome
            .expect_err("material outside the scoped store shape denies before any wire leg");
        assert!(
            matches!(err, ProviderError::CredentialMalformed { .. }),
            "material outside the scoped store shape is the typed malformed denial: {err}"
        );
        assert_no_secret_or_body(&err, material.as_bytes());
        drop_blocking(provider);
    }
    // empty and whitespace-only material names no key at all
    for material in ["", "   "] {
        let (provider, _store) = coreweave_provider(&config, material);
        let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
        let err = outcome.expect_err("empty material denies before any wire leg");
        assert!(
            matches!(err, ProviderError::CredentialMalformed { .. }),
            "empty material is the typed malformed denial: {err}"
        );
        drop_blocking(provider);
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "material outside the scoped store shape never reached the wire"
    );

    // a refused bearer token is a typed transport denial — the wire
    // never coerces a wrong credential into success, and the peer's
    // body never enters the error
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let (provider, _store) = enrolled_coreweave_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused token is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused token is transport: {err}")
    };
    assert_eq!(connection, "coreweave");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, COREWEAVE_KEY.as_bytes());
    drop_blocking(provider);

    // The same boundary on the Debug surfaces the dispatch path
    // exposes: provider, manifest, accounting record, broker and
    // runtime each render without the material the store alone holds.
    let server = MockServer::start().await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&coreweave_config(&base)).expect("valid");
    let material = coreweave_credential(COREWEAVE_KEY, COREWEAVE_PROJECT);
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(COREWEAVE_REF, &material)],
    ));
    let provider = provider_result(config.clone(), "coreweave".to_string(), store)
        .expect("the adapter builds");
    assert!(
        !format!("{provider:?}").contains(COREWEAVE_KEY),
        "provider Debug never carries credential material"
    );
    assert!(
        !format!("{provider:?}").contains(COREWEAVE_PROJECT),
        "provider Debug never carries the scope member — store material too"
    );
    mount_chat(
        &server,
        completed_stream(
            "accounted",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let (broker, manifest) = {
        let (provider, _store) = coreweave_provider(&config, &material);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/coreweave", "goal: debug surfaces")
            .expect("the pin passes DEC-011 eligibility");
        (broker, manifest)
    };
    assert!(
        !format!("{manifest:?}").contains(COREWEAVE_KEY),
        "manifest Debug never carries credential material"
    );
    let (broker, outcome) = dispatch(broker, "/world/coreweave", manifest.clone());
    outcome.expect("the debug-surface send completes");
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert!(
        !format!("{record:?}").contains(COREWEAVE_KEY),
        "accounting-record Debug never carries credential material"
    );
    assert!(
        !format!("{broker:?}").contains(COREWEAVE_KEY),
        "broker Debug never carries credential material"
    );
    drop_blocking(broker);
    drop_blocking(provider);

    let world = support::open_world(
        "auth-debug-coreweave",
        Some(&coreweave_config(&server_uri_v1(&server))),
    );
    assert!(
        !format!("{:?}", world.runtime).contains(COREWEAVE_KEY),
        "runtime Debug never carries credential material"
    );
}

/// A `/models` HTTP 200 is never entitlement (INV-010) for
/// `coreweave`: with the scoped key enrolled the fixed pin still rides
/// only its request leg, and a listing answering the pinned id neither
/// stands in for the credential nor admits the send — the unmounted
/// `chat/completions` peer answers the typed transport denial while the
/// 200 listing is never consulted.
#[tokio::test]
async fn coreweave_models_http_200_is_never_entitlement() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": COREWEAVE_MODEL})]).await;
    let config =
        Config::parse_validated(&coreweave_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_coreweave_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a 200 catalogue never releases the pin");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the unmounted request leg is the typed transport denial: {err:?}");
    };
    assert_eq!(connection, "coreweave");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 404 },
        "the request leg answers the peer's status, never a listing-granted success: {cause}"
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "only the request leg runs — the 200 listing releases no entitlement"
    );
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_project(&requests[0]),
        COREWEAVE_PROJECT,
        "the scope header rides the one request leg"
    );
}

// ----- TP-PROVIDER-RECOVERY::coreweave -----------------------------------------

/// A typed denial is recoverable through the same seam: the absent
/// credential denies the first send, enrolling the scoped material at
/// the scope admits the retry — no state wedged, no plaintext path
/// taken.
#[tokio::test]
async fn coreweave_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&coreweave_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "coreweave".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialAbsent { .. })
    ));

    store.enroll(
        COREWEAVE_REF,
        coreweave_credential(COREWEAVE_KEY, COREWEAVE_PROJECT).as_bytes(),
    );
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the enrolled credential admits the retry");
    assert_eq!(reply.text, "recovered");
    drop_blocking(provider);
}

/// The legs matrix enforces the recorded expected set for
/// `coreweave`: CATALOG, AUTH, WIRE and RECOVERY each execute and
/// report inside this run, and INSTALLED reports NOT_RUN — an
/// omitted leg fails the suite rather than silently absenting.
#[tokio::test]
async fn coreweave_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "matrix"})]).await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&coreweave_config(&server_uri_v1(&server))).expect("valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the authoritative `/models` listing is the offer.
    let (provider, _store) = enrolled_coreweave_provider(&config);
    let (provider, listed) = catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if model_ids(&listed.expect("catalog answers")) == ["matrix"] {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: an absent credential denies typed before any leg.
    let absent = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), "coreweave".to_string(), absent).expect("binding resolves");
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
    let (broker, manifest) = {
        let (provider, _store) = enrolled_coreweave_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/coreweave", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
    let (broker, outcome) = dispatch(broker, "/world/coreweave", manifest);
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
    let provider = provider_result(config.clone(), "coreweave".to_string(), empty.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(
        COREWEAVE_REF,
        coreweave_credential(COREWEAVE_KEY, COREWEAVE_PROJECT).as_bytes(),
    );
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

    // The literal row mirrors the `#[ignore]`d
    // `provider_installed_coreweave` case below: its ignored count is
    // the explicit NOT_RUN signal this matrix asserts — the row stays
    // a literal so the two cannot drift.
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

// ----- TP-PROVIDER-INSTALLED::coreweave -----------------------------------------

/// TP-PROVIDER-INSTALLED::coreweave = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::coreweave = NOT_RUN"]
fn provider_installed_coreweave() {}

// ----- deepinfra -------------------------------------------------------------
//
// The `deepinfra` connection's proof legs (HZN-008 class A): the
// shared Chat Completions adapter serves the literal id — no copied
// codec — under its own recorded predicates (`Rivect/key`,
// `deepinfraModelManagerOptions` + `auth/deepinfra.kdl`). The
// configured `endpoint` carries the API base verbatim — an empty one
// resolves the recorded `api.deepinfra.com/v1/openai` default
// (`config?.baseUrl ?? DEEPINFRA_BASE_URL`'s absent arm), and a
// configured `region` is denied: the contract names none. The
// catalogue is the configured base's own authoritative chat-model
// `/models` listing and ids-only offers: the listing is public
// metadata, never an authentication surface — the recorded validate
// leg exercises `chat/completions`, not `/models` — and service-tier
// and flex surcharges stay recorded billing metadata the ids-only
// surface never synthesizes into a price. The credential is the
// recorded plain `key` bearer; material that is not UTF-8 text
// denies malformed before any wire leg.

/// The scoped credential ref the `deepinfra` connection binds.
const DEEPINFRA_REF: &str = "keyring:rivect-test/deepinfra";

/// Fixture deepinfra key material — never a real credential, only
/// ever sent to localhost.
const DEEPINFRA_KEY: &str = "fixture-deepinfra-key";

/// The pinned model id the fixed-pin legs carry.
const DEEPINFRA_MODEL: &str = "fixture-di-model";

/// One configured `deepinfra` connection pointing at the fixture
/// peer: the api_key auth class resolves a scoped `SecretRef`
/// (DEC-011), the dialect comes from the literal connection id
/// (DEC-007), and the endpoint carries the API base verbatim.
fn deepinfra_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.deepinfra]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{DEEPINFRA_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"deepinfra\", model_id = \"{DEEPINFRA_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn deepinfra_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(DEEPINFRA_REF, material)],
    ));
    let provider = provider_result(config.clone(), "deepinfra".to_string(), store.clone())
        .expect("the shared adapter builds for the deepinfra id");
    (provider, store)
}

/// The `deepinfra` provider over the recorded enrolled credential.
fn enrolled_deepinfra_provider(
    config: &Config,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    deepinfra_provider(config, DEEPINFRA_KEY)
}

// ----- TP-PROVIDER-WIRE::deepinfra ---------------------------------------------

/// A configured `deepinfra` connection returns a verified model
/// outcome through the standard Broker: prepare admits the api_key
/// pin under DEC-011, the plain bearer credential rides the
/// `Authorization` header — no scope member, no body copy — and the
/// shared adapter posts exactly the frozen manifest as a
/// `chat/completions` request — pinned model, system+user messages,
/// `stream` with `stream_options.include_usage` and the pinned effort
/// as `reasoning_effort` verbatim — the SSE stream validates its
/// finish_reason/`[DONE]` terminal, and the one physical send is
/// charged once with the provider's reported usage.
#[tokio::test]
async fn deepinfra_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified outcome text",
            Some(json!({"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&deepinfra_config(&base)).expect("valid");
    let (provider, _store) = enrolled_deepinfra_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/deepinfra", "goal: prove the wire")
        .expect("the deepinfra pin passes DEC-011 eligibility");

    let (broker, outcome) = dispatch(broker, "/world/deepinfra", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified outcome text");
    assert!(reply.tool_calls.is_empty());

    // The wire request is exactly the frozen manifest — and nothing
    // the manifest does not carry; a fixed pin opens no catalogue leg.
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {DEEPINFRA_KEY}"),
        "the plain key material bears the wire verbatim"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(DEEPINFRA_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], json!(DEEPINFRA_MODEL));
    assert_eq!(
        body["messages"],
        json!([
            {"role": "system", "content": manifest.instructions},
            {"role": "user", "content": manifest.inputs},
        ]),
        "the frozen instructions and inputs ride the messages verbatim"
    );
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["stream_options"],
        json!({"include_usage": true}),
        "the recorded usage request rides the stream options"
    );
    assert_eq!(
        body["reasoning_effort"],
        json!("medium"),
        "the pinned effort rides the recorded reasoning_effort surface"
    );

    // Exactly one accounting record carries the one physical usage
    // report — the provider's 18 tokens are the confirmed charge, and
    // a replayed attempt reports spent.
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "deepinfra");
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
            let replay = broker.dispatch(
                &mut rivect::model::NullLedger,
                "/world/deepinfra",
                &manifest,
            );
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
/// label: an id without the recorded Chat Completions class builds
/// no adapter — a Chat-Completions-classed id is reserved for its
/// own named contract arm — `dialect_for` reserving `deepinfra`
/// means the id is never fixture-served even when it declares
/// `local` kind, and a manifest pinning a different connection id is
/// refused at send.
#[test]
fn deepinfra_dialect_is_keyed_on_the_literal_connection_id() {
    assert_eq!(
        rivect::providers::dialect_for("deepinfra"),
        Some(rivect::providers::Dialect::ChatCompletions),
        "the literal id binds the shared Chat Completions dialect"
    );
    let config =
        Config::parse_validated(&deepinfra_config("http://127.0.0.1:1/v1")).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = provider_result(config.clone(), "deepinfra-pro".to_string(), store)
        .expect_err("a different literal id is not this dialect");
    assert!(matches!(err, ProviderError::DialectMismatch { .. }));

    // a dialect-reserved id is never fixture-served whatever kind it
    // declares — `deepinfra` pinned `local` keeps the typed denial
    let local = Config::parse_validated(
        "config_version = 1\n\
         [connections.deepinfra]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"deepinfra\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"medium\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let loopback = rivect::providers::LoopbackProvider::new();
    let entry = local.connections.get("deepinfra").expect("declared");
    assert!(
        !loopback.serves("deepinfra", entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );

    // a manifest pinning a different connection id is refused at send —
    // the bound credential is well-formed so the denial is the dialect's,
    // never the credential seam's
    let (provider, _store) = enrolled_deepinfra_provider(&config);
    let foreign = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.other]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1/v1\"\ncredential_ref = \"{DEEPINFRA_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"other\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let manifest = {
        let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
        broker
            .prepare("main", &foreign, "/world/deepinfra", "goal: x")
            .expect("foreign pin prepares")
    };
    let (provider, outcome) = send_on_thread(provider, manifest);
    assert!(
        matches!(outcome, Err(ProviderError::DialectMismatch { .. })),
        "a foreign pin never speaks this dialect: {outcome:?}"
    );
    drop_blocking(provider);
}

/// Hostile stream input is never a false success: a stream ended mid
/// `tool_calls` fragment — a partial call that never executes — and a
/// finish_reason the dialect cannot classify are both the unknown
/// terminal, and a rejected send charges nothing.
#[tokio::test]
async fn deepinfra_adverse_wire_input_never_reports_success() {
    // a complete content delta plus an unterminated tool-call
    // fragment, then EOF — no finish_reason and no [DONE]
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&delta_chunk(json!({
                "tool_calls": [{
                    "index": 0,
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": "{\"path\":"},
                }],
            }))),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&deepinfra_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_deepinfra_provider(&config),
        &config,
        "/world/deepinfra",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/deepinfra", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "EOF mid tool call is the unknown terminal — never a usable call: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);

    // a finish_reason the dialect cannot classify is unknown, never
    // success
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&finish_chunk("mystery")),
            DONE_BLOCK
        ),
    )
    .await;
    let config =
        Config::parse_validated(&deepinfra_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_deepinfra_provider(&config),
        &config,
        "/world/deepinfra",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/deepinfra", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "an unclassifiable terminal is the unknown terminal: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);
}

// ----- TP-PROVIDER-CATALOG::deepinfra ------------------------------------------

/// The `deepinfra` catalogue is the configured base's own
/// authoritative chat-model `/models` listing (HZN-008 class A): the
/// lookup resolves the plain bearer credential on the one
/// `GET {endpoint}/models` leg and every `id` with a non-whitespace
/// body is an offer landing the ids-only surface — a listing entry's
/// metadata, tags, prices and context length stay recorded upstream
/// data, never synthesized catalog fields; service-tier and flex
/// surcharges stay distinguished metadata, never a price.
#[tokio::test]
async fn deepinfra_catalog_is_the_authoritative_ids_only_listing() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "fixture-org/di-chat-large"}),
            json!({"id": DEEPINFRA_MODEL}),
            // the recorded listing can attach per-model metadata —
            // tags, limits, prices — under `filter=with_meta`: none
            // of it is catalog surface, and the recorded
            // service-tier/flex surcharges never synthesize a price
            json!({
                "id": "priced-chat",
                "metadata": {
                    "tags": ["chat", "reasoning"],
                    "context_length": 128000,
                    "prices": {"input": 0.3, "output": 0.5},
                },
                "service_tier": {"priority": {"surcharge": 0.5}, "flex": {"discount": 0.2}},
            }),
            // the listing is the authoritative chat-model surface:
            // `catalog_entry`'s shared trim rule drops an empty or
            // whitespace-only id, so the fixture offers no such model
            json!({"id": ""}),
            json!({"metadata": {}}),
        ],
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&deepinfra_config(&base)).expect("valid");
    let (provider, _store) = enrolled_deepinfra_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the authoritative listing answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        vec![DEEPINFRA_MODEL, "fixture-org/di-chat-large", "priced-chat"],
        "the authoritative chat-model listing offers the ids it names, sorted"
    );
    // every admitted id lands the ids-only surface — stated metadata,
    // tags, prices and tier/flex surcharges are never adopted
    for model in &models {
        assert_eq!(
            model,
            &CatalogModel {
                id: model.id.clone(),
                ..CatalogModel::default()
            },
            "{}: the listing states the id alone",
            model.id
        );
    }
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "the listing leg is the only egress — no other endpoint is consulted"
    );
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {DEEPINFRA_KEY}"),
        "the plain key bears the discovery leg"
    );
}

/// An empty configured endpoint resolves the recorded default —
/// the `config?.baseUrl ?? DEEPINFRA_BASE_URL` absent arm our
/// required `endpoint` field expresses as the empty string, and
/// whitespace-only shares the arm under the recorded trim. Offline
/// pin: the adapter's `Debug` surface reports the resolved endpoint,
/// so the arm is proved without one byte toward
/// `api.deepinfra.com`.
#[test]
fn deepinfra_empty_endpoint_resolves_the_recorded_default() {
    for endpoint in ["", "   "] {
        let config = Config::parse_validated(&deepinfra_config(endpoint))
            .expect("an empty endpoint is valid");
        let (provider, _store) = enrolled_deepinfra_provider(&config);
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"https://api.deepinfra.com/v1/openai\""),
            "endpoint {endpoint:?} resolved to the recorded default: {debug}"
        );
        drop_blocking(provider);
    }
}

/// The auto-pick catalogue leg rides the authoritative listing: the
/// dispatch narrows the pool to the `deepinfra` member and the shared
/// adapter resolves the deterministic sorted-first id as the wire
/// model.
#[tokio::test]
async fn deepinfra_auto_pick_resolves_through_the_authoritative_catalog() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "fixture-org/zz-late"}),
            json!({"id": "fixture-org/aa-first"}),
        ],
    )
    .await;
    mount_chat(
        &server,
        completed_stream(
            "auto picked",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.deepinfra]\nkind = \"api_key\"\nendpoint = \"{base}\"\ncredential_ref = \"{DEEPINFRA_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\", pool = [\"deepinfra\"] }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let (provider, _store) = enrolled_deepinfra_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/deepinfra", "goal: auto pick")
        .expect("the single-member pool pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/deepinfra", manifest);
    let reply = outcome.expect("the auto pick dispatches");
    assert_eq!(reply.text, "auto picked");
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "the catalogue leg and the send are the only egress"
    );
    let body: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert_eq!(
        body["model"],
        json!("fixture-org/aa-first"),
        "the deterministic sorted-first id names the wire model"
    );
}

// ----- TP-PROVIDER-AUTH::deepinfra ---------------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `deepinfra`: a configured `region` — the recorded contract names
/// none — the profile-bound ref whose scope disagrees with the
/// binding, an absent credential, credential material that is not
/// UTF-8 text and a refused bearer token each land a typed denial,
/// and none of them, nor any Debug surface the boundary exposes,
/// renders credential material or the peer's body.
#[tokio::test]
async fn deepinfra_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &deepinfra_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "deepinfra".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, DEEPINFRA_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "deepinfra");
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, DEEPINFRA_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.deepinfra]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"deepinfra\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "deepinfra".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, DEEPINFRA_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, DEEPINFRA_KEY.as_bytes());

    // a bound ref with no material at its own scope — the sibling
    // scope's material stays sealed behind the typed denial
    let config =
        Config::parse_validated(&deepinfra_config(&server_uri_v1(&server))).expect("valid");
    let provider = provider_result(
        config.clone(),
        "deepinfra".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, DEEPINFRA_KEY)],
        )),
    )
    .expect("binding resolves; the store is read at send");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("no material at the scope is the typed denial");
    assert!(matches!(err, ProviderError::CredentialAbsent { .. }));
    assert_no_secret_or_body(&err, DEEPINFRA_KEY.as_bytes());
    drop_blocking(provider);

    // material that is not UTF-8 text cannot be a bearer token: the
    // typed malformed denial lands before any wire leg — zero
    // requests reach the mock
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    store.enroll(DEEPINFRA_REF, &[0xFF, 0xFE, 0xFD]);
    let provider =
        provider_result(config.clone(), "deepinfra".to_string(), store).expect("binding resolves");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("non-text material denies before any wire leg");
    assert!(
        matches!(err, ProviderError::CredentialMalformed { .. }),
        "non-UTF-8 material is the typed malformed denial: {err}"
    );
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "denied credentials never reached the wire"
    );

    // a refused bearer token is a typed transport denial — the wire
    // never coerces a wrong credential into success, and the peer's
    // body never enters the error
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let (provider, _store) = enrolled_deepinfra_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused token is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused token is transport: {err}")
    };
    assert_eq!(connection, "deepinfra");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, DEEPINFRA_KEY.as_bytes());
    drop_blocking(provider);

    // The same boundary on the Debug surfaces the dispatch path
    // exposes: provider, manifest, accounting record, broker and
    // runtime each render without the material the store alone holds.
    let server = MockServer::start().await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&deepinfra_config(&base)).expect("valid");
    let provider = provider_result(
        config.clone(),
        "deepinfra".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(DEEPINFRA_REF, DEEPINFRA_KEY)],
        )),
    )
    .expect("the adapter builds");
    assert!(
        !format!("{provider:?}").contains(DEEPINFRA_KEY),
        "provider Debug never carries credential material"
    );
    mount_chat(
        &server,
        completed_stream(
            "accounted",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let (broker, manifest) = {
        let (provider, _store) = enrolled_deepinfra_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/deepinfra", "goal: debug surfaces")
            .expect("the pin passes DEC-011 eligibility");
        (broker, manifest)
    };
    assert!(
        !format!("{manifest:?}").contains(DEEPINFRA_KEY),
        "manifest Debug never carries credential material"
    );
    let (broker, outcome) = dispatch(broker, "/world/deepinfra", manifest.clone());
    outcome.expect("the debug-surface send completes");
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert!(
        !format!("{record:?}").contains(DEEPINFRA_KEY),
        "accounting-record Debug never carries credential material"
    );
    assert!(
        !format!("{broker:?}").contains(DEEPINFRA_KEY),
        "broker Debug never carries credential material"
    );
    drop_blocking(broker);
    drop_blocking(provider);

    let world = support::open_world(
        "auth-debug-deepinfra",
        Some(&deepinfra_config(&server_uri_v1(&server))),
    );
    assert!(
        !format!("{:?}", world.runtime).contains(DEEPINFRA_KEY),
        "runtime Debug never carries credential material"
    );
}

/// The public catalogue is never an authentication surface
/// (auth/deepinfra.kdl — `/models` is public and would accept any
/// string as a key, so the recorded validate leg exercises
/// `chat/completions`): a fixture `GET /models` answering 200 with an
/// arbitrary roster proves nothing about entitlement — with the key
/// enrolled the fixed pin still rides only its request leg, and the
/// unmounted `chat/completions` peer answers the typed transport
/// denial while the 200 listing is never consulted.
#[tokio::test]
async fn deepinfra_public_catalog_listing_is_never_entitlement() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": DEEPINFRA_MODEL})]).await;
    let config =
        Config::parse_validated(&deepinfra_config(&server_uri_v1(&server))).expect("valid");
    let provider = provider_result(
        config.clone(),
        "deepinfra".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(DEEPINFRA_REF, DEEPINFRA_KEY)],
        )),
    )
    .expect("the enrolled binding resolves");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a 200 catalogue never releases the pin");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the unmounted request leg is the typed transport denial: {err:?}");
    };
    assert_eq!(connection, "deepinfra");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 404 },
        "the request leg answers the peer's status, never a listing-granted success: {cause}"
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "only the request leg runs — the 200 listing releases no entitlement"
    );
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
}

// ----- TP-PROVIDER-RECOVERY::deepinfra -----------------------------------------

/// A typed denial is recoverable through the same seam: the absent
/// credential denies the first send, enrolling the material at the
/// scope admits the retry — no state wedged, no plaintext path
/// taken.
#[tokio::test]
async fn deepinfra_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&deepinfra_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "deepinfra".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialAbsent { .. })
    ));

    store.enroll(DEEPINFRA_REF, DEEPINFRA_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the enrolled credential admits the retry");
    assert_eq!(reply.text, "recovered");
    drop_blocking(provider);
}

/// The legs matrix enforces the recorded expected set for
/// `deepinfra`: CATALOG, AUTH, WIRE and RECOVERY each execute and
/// report inside this run, and INSTALLED reports NOT_RUN — an
/// omitted leg fails the suite rather than silently absenting.
#[tokio::test]
async fn deepinfra_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "matrix"})]).await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&deepinfra_config(&server_uri_v1(&server))).expect("valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the authoritative `/models` listing is the offer.
    let (provider, _store) = enrolled_deepinfra_provider(&config);
    let (provider, listed) = catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if model_ids(&listed.expect("catalog answers")) == ["matrix"] {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: an absent credential denies typed before any leg.
    let absent = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), "deepinfra".to_string(), absent).expect("binding resolves");
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
    let (broker, manifest) = {
        let (provider, _store) = enrolled_deepinfra_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/deepinfra", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
    let (broker, outcome) = dispatch(broker, "/world/deepinfra", manifest);
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
    let provider = provider_result(config.clone(), "deepinfra".to_string(), empty.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(DEEPINFRA_REF, DEEPINFRA_KEY.as_bytes());
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

    // The literal row mirrors the `#[ignore]`d
    // `provider_installed_deepinfra` case below: its ignored count is
    // the explicit NOT_RUN signal this matrix asserts — the row stays
    // a literal so the two cannot drift.
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

// ----- TP-PROVIDER-INSTALLED::deepinfra -----------------------------------------

/// TP-PROVIDER-INSTALLED::deepinfra = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::deepinfra = NOT_RUN"]
fn provider_installed_deepinfra() {}

// ----- deepseek --------------------------------------------------------------

// The `deepseek` connection's proof legs (HZN-008 class A): the
// shared Chat Completions adapter serves the literal id — no copied
// codec — under its own recorded predicates (`Rivect/key`,
// `deepseekModelManagerOptions` + `auth/deepseek.kdl`). The
// configured `endpoint` carries the API base verbatim — an empty one
// resolves the recorded `api.deepseek.com` default
// (`config?.baseUrl ?? defaultBaseUrl`'s absent arm), and a
// configured `region` is denied: the contract names none. The
// catalogue is the configured base's own authoritative `/models`
// listing gated by the recorded built-in roster — a built-in id
// offers with its recorded native-reasoning surface; a benchmark or
// legacy id the listing carries is never offered — and the seed is
// the offer floor: a built-in offers even when the listing omits it.
// The credential is the recorded plain `key` bearer; material that
// is not UTF-8 text denies malformed before any wire leg; the
// recorded per-model USD prices carry onto the offered surface while
// the prepaid balance stays an account fact.

/// The scoped credential ref the `deepseek` connection binds.
const DEEPSEEK_REF: &str = "keyring:rivect-test/deepseek";

/// Fixture deepseek key material — never a real credential, only
/// ever sent to localhost.
const DEEPSEEK_KEY: &str = "fixture-deepseek-key";

/// The pinned model id the fixed-pin legs carry — a recorded
/// built-in, so the pin is one the catalogue could itself offer.
const DEEPSEEK_MODEL: &str = "deepseek-v4-flash";

/// The recorded built-in ids, sorted — the whole offered universe
/// this connection may name, listing or seed alike.
const DEEPSEEK_BUILTIN_IDS: [&str; 3] = [
    "deepseek-v4-flash",
    "deepseek-v4-flash-vision-exp",
    "deepseek-v4-pro",
];

/// The recorded surface of one built-in as an independent expected
/// snapshot: the reasoning mark, the `vision-exp` image-input mark,
/// the recorded effort ladder, the million-token window and the
/// per-model USD price.
fn deepseek_expected_model(id: &str) -> CatalogModel {
    let (vision, input_per_1m, output_per_1m) = match id {
        "deepseek-v4-flash" => (false, 0.14, 0.28),
        "deepseek-v4-flash-vision-exp" => (true, 0.14, 0.28),
        "deepseek-v4-pro" => (false, 0.435, 0.87),
        other => panic!("{other} is not a recorded deepseek built-in"),
    };
    CatalogModel {
        id: id.to_string(),
        reasoning: true,
        vision,
        efforts: vec![EffortLevel::Low, EffortLevel::High],
        context_window: Some(1_000_000),
        price: ModelPrice::Usd {
            input_per_1m,
            output_per_1m,
        },
        ..CatalogModel::default()
    }
}

/// One configured `deepseek` connection pointing at the fixture
/// peer: the api_key auth class resolves a scoped `SecretRef`
/// (DEC-011), the dialect comes from the literal connection id
/// (DEC-007), and the endpoint carries the API base verbatim.
fn deepseek_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.deepseek]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{DEEPSEEK_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"deepseek\", model_id = \"{DEEPSEEK_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn deepseek_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(DEEPSEEK_REF, material)],
    ));
    let provider = provider_result(config.clone(), "deepseek".to_string(), store.clone())
        .expect("the shared adapter builds for the deepseek id");
    (provider, store)
}

/// The `deepseek` provider over the recorded enrolled credential.
fn enrolled_deepseek_provider(
    config: &Config,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    deepseek_provider(config, DEEPSEEK_KEY)
}

// ----- TP-PROVIDER-WIRE::deepseek ---------------------------------------------

/// A configured `deepseek` connection returns a verified model
/// outcome through the standard Broker: prepare admits the api_key
/// pin under DEC-011, the plain bearer credential rides the
/// `Authorization` header — no scope member, no body copy — and the
/// shared adapter posts exactly the frozen manifest as a
/// `chat/completions` request — pinned model, system+user messages,
/// `stream` with `stream_options.include_usage` and the pinned effort
/// as `reasoning_effort` verbatim — the SSE stream validates its
/// finish_reason/`[DONE]` terminal, and the one physical send is
/// charged once with the provider's reported usage.
#[tokio::test]
async fn deepseek_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified outcome text",
            Some(json!({"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&deepseek_config(&base)).expect("valid");
    let (provider, _store) = enrolled_deepseek_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/deepseek", "goal: prove the wire")
        .expect("the deepseek pin passes DEC-011 eligibility");

    let (broker, outcome) = dispatch(broker, "/world/deepseek", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified outcome text");
    assert!(reply.tool_calls.is_empty());

    // The wire request is exactly the frozen manifest — and nothing
    // the manifest does not carry; a fixed pin opens no catalogue leg.
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {DEEPSEEK_KEY}"),
        "the plain key material bears the wire verbatim"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(DEEPSEEK_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], json!(DEEPSEEK_MODEL));
    assert_eq!(
        body["messages"],
        json!([
            {"role": "system", "content": manifest.instructions},
            {"role": "user", "content": manifest.inputs},
        ]),
        "the frozen instructions and inputs ride the messages verbatim"
    );
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["stream_options"],
        json!({"include_usage": true}),
        "the recorded usage request rides the stream options"
    );
    assert_eq!(
        body["reasoning_effort"],
        json!("medium"),
        "the pinned effort rides the recorded reasoning_effort surface"
    );

    // Exactly one accounting record carries the one physical usage
    // report — the provider's 18 tokens are the confirmed charge, and
    // a replayed attempt reports spent.
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "deepseek");
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
            let replay =
                broker.dispatch(&mut rivect::model::NullLedger, "/world/deepseek", &manifest);
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
/// label: an id without the recorded Chat Completions class builds
/// no adapter — a Chat-Completions-classed id is reserved for its
/// own named contract arm — `dialect_for` reserving `deepseek`
/// means the id is never fixture-served even when it declares
/// `local` kind, and a manifest pinning a different connection id is
/// refused at send.
#[test]
fn deepseek_dialect_is_keyed_on_the_literal_connection_id() {
    assert_eq!(
        rivect::providers::dialect_for("deepseek"),
        Some(rivect::providers::Dialect::ChatCompletions),
        "the literal id binds the shared Chat Completions dialect"
    );
    let config = Config::parse_validated(&deepseek_config("http://127.0.0.1:1/v1")).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = provider_result(config.clone(), "deepseek-pro".to_string(), store)
        .expect_err("a different literal id is not this dialect");
    assert!(matches!(err, ProviderError::DialectMismatch { .. }));

    // a dialect-reserved id is never fixture-served whatever kind it
    // declares — `deepseek` pinned `local` keeps the typed denial
    let local = Config::parse_validated(
        "config_version = 1\n\
         [connections.deepseek]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"deepseek\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"medium\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let loopback = rivect::providers::LoopbackProvider::new();
    let entry = local.connections.get("deepseek").expect("declared");
    assert!(
        !loopback.serves("deepseek", entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );

    // a manifest pinning a different connection id is refused at send —
    // the bound credential is well-formed so the denial is the dialect's,
    // never the credential seam's
    let (provider, _store) = enrolled_deepseek_provider(&config);
    let foreign = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.other]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1/v1\"\ncredential_ref = \"{DEEPSEEK_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"other\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let manifest = {
        let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
        broker
            .prepare("main", &foreign, "/world/deepseek", "goal: x")
            .expect("foreign pin prepares")
    };
    let (provider, outcome) = send_on_thread(provider, manifest);
    assert!(
        matches!(outcome, Err(ProviderError::DialectMismatch { .. })),
        "a foreign pin never speaks this dialect: {outcome:?}"
    );
    drop_blocking(provider);
}

/// Hostile stream input is never a false success: a stream ended mid
/// `tool_calls` fragment — a partial call that never executes — and a
/// finish_reason the dialect cannot classify are both the unknown
/// terminal, a streamed call whose `type` is not the recorded
/// `function` kind and a `reasoning_content` member that is not a
/// string are typed rejections, and a rejected send charges nothing.
#[tokio::test]
async fn deepseek_adverse_wire_input_never_reports_success() {
    // a complete content delta plus an unterminated tool-call
    // fragment, then EOF — no finish_reason and no [DONE]
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&delta_chunk(json!({
                "tool_calls": [{
                    "index": 0,
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": "{\"path\":"},
                }],
            }))),
        ),
    )
    .await;
    let config = Config::parse_validated(&deepseek_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_deepseek_provider(&config),
        &config,
        "/world/deepseek",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/deepseek", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "EOF mid tool call is the unknown terminal — never a usable call: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);

    // a finish_reason the dialect cannot classify is unknown, never
    // success
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&finish_chunk("mystery")),
            DONE_BLOCK
        ),
    )
    .await;
    let config = Config::parse_validated(&deepseek_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_deepseek_provider(&config),
        &config,
        "/world/deepseek",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/deepseek", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "an unclassifiable terminal is the unknown terminal: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);

    // a non-function tool call kind is output the dialect cannot
    // honour — the same typed rejection, never executed
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({
                "tool_calls": [{
                    "index": 0, "id": "call_1", "type": "retrieval",
                    "function": {"name": "read_file", "arguments": "{}"},
                }],
            }))),
            data_block(&finish_chunk("tool_calls")),
            DONE_BLOCK
        ),
    )
    .await;
    let config = Config::parse_validated(&deepseek_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_deepseek_provider(&config),
        &config,
        "/world/deepseek",
        "goal: foreign tool kind",
    );
    let (broker, outcome) = dispatch(broker, "/world/deepseek", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(
                ProviderError::IncompatibleOutput { .. }
            ))
        ),
        "a non-function tool kind is a typed rejection: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a refused send charges nothing"
    );
    drop_blocking(broker);

    // a `reasoning_content` member that is not a string is hostile
    // reasoning input — a typed wire violation, never progress
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({"reasoning_content": 5}))),
            data_block(&finish_chunk("stop")),
            DONE_BLOCK
        ),
    )
    .await;
    let config = Config::parse_validated(&deepseek_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_deepseek_provider(&config),
        &config,
        "/world/deepseek",
        "goal: malformed reasoning",
    );
    let (broker, outcome) = dispatch(broker, "/world/deepseek", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "a non-string reasoning member is a typed violation: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a denied stream charges nothing"
    );
    drop_blocking(broker);
}

// ----- TP-PROVIDER-CATALOG::deepseek ------------------------------------------

/// The `deepseek` catalogue is the configured base's own
/// authoritative `/models` listing under the recorded built-in
/// transform (HZN-008 class A): the lookup resolves the plain bearer
/// credential on the one `GET {endpoint}/models` leg, and every
/// listed built-in id lands its recorded surface — the reasoning
/// mark with the native effort ladder (the bundled `max` names no
/// level our enum carries and never maps onto a lower one), the
/// image-input mark, the context window and the recorded per-model
/// USD prices — while the prepaid balance stays an account fact.
#[tokio::test]
async fn deepseek_catalog_lists_the_recorded_builtin_surface() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "deepseek-v4-pro"}),
            json!({"id": DEEPSEEK_MODEL}),
            json!({"id": "deepseek-v4-flash-vision-exp"}),
            // an empty or absent id can never name a model — and a
            // listed benchmark id is never offered whatever the
            // listing states
            json!({"id": ""}),
            json!({"metadata": {}}),
        ],
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&deepseek_config(&base)).expect("valid");
    let (provider, _store) = enrolled_deepseek_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the authoritative listing answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        DEEPSEEK_BUILTIN_IDS,
        "the listing offers the recorded built-in roster, sorted"
    );
    let model = |id: &str| {
        models
            .iter()
            .find(|model| model.id == id)
            .unwrap_or_else(|| panic!("{id} is offered"))
    };
    assert_eq!(
        model("deepseek-v4-flash"),
        &deepseek_expected_model("deepseek-v4-flash"),
        "a built-in lands the recorded native-reasoning surface with its recorded USD price"
    );
    assert_eq!(
        model("deepseek-v4-flash-vision-exp"),
        &deepseek_expected_model("deepseek-v4-flash-vision-exp"),
        "the vision build carries its image-input mark and the recorded flash price"
    );
    assert_eq!(
        model("deepseek-v4-pro"),
        &deepseek_expected_model("deepseek-v4-pro"),
        "the pro built-in carries the recorded reasoning surface and its own recorded price"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "the listing leg is the only egress — no other endpoint is consulted"
    );
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {DEEPSEEK_KEY}"),
        "the plain key bears the discovery leg"
    );
}

/// A benchmark or legacy id the listing carries is never offered
/// (HZN-008 class A): the built-in roster is the whole offered
/// universe — `deepseek-chat`, `deepseek-reasoner` and every
/// non-roster id filter out of the catalogue, and the recorded seed
/// floor still offers the built-ins the listing omitted.
#[tokio::test]
async fn deepseek_benchmark_ids_are_never_offered_as_models() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "deepseek-chat"}),
            json!({"id": "deepseek-reasoner"}),
            json!({"id": "deepseek-r1"}),
            // a gateway-style or arbitrary listed id is no more
            // offered — the roster, not the listing shape, decides
            json!({"id": "fixture-org/aaa-benchmark"}),
        ],
    )
    .await;
    let config = Config::parse_validated(&deepseek_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_deepseek_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the listing answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        DEEPSEEK_BUILTIN_IDS,
        "only the recorded built-in roster offers — every benchmark and foreign id is filtered"
    );
    for offered in &models {
        assert!(
            DEEPSEEK_BUILTIN_IDS.contains(&offered.id.as_str()),
            "a non-built-in id can never land: {}",
            offered.id
        );
    }
}

/// A built-in the authoritative listing omits still offers through
/// the seed floor — and the seed carries the same recorded transform
/// surface as the listing arm, not a bare id-only stub: the
/// reasoning mark and ladder, the `vision-exp` image-input mark,
/// the million-token window and the recorded per-model USD prices
/// land on every seeded offer.
#[tokio::test]
async fn deepseek_seed_floor_carries_the_full_recorded_surface() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            // benchmark ids the roster never names — the whole offer
            // below is the seed's, never a listed entry's
            json!({"id": "deepseek-chat"}),
            json!({"id": "deepseek-reasoner"}),
        ],
    )
    .await;
    let config = Config::parse_validated(&deepseek_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_deepseek_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the listing answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        DEEPSEEK_BUILTIN_IDS,
        "the seed floor offers the built-ins the listing omitted"
    );
    let model = |id: &str| {
        models
            .iter()
            .find(|model| model.id == id)
            .unwrap_or_else(|| panic!("{id} is offered"))
    };
    assert_eq!(
        model("deepseek-v4-flash"),
        &deepseek_expected_model("deepseek-v4-flash"),
        "a seed-only offer carries the recorded surface — the discriminating leg a bare-stub seed arm would lose"
    );
    assert_eq!(
        model("deepseek-v4-flash-vision-exp"),
        &deepseek_expected_model("deepseek-v4-flash-vision-exp"),
        "the seed-only vision build carries its image-input mark and price"
    );
    assert_eq!(
        model("deepseek-v4-pro"),
        &deepseek_expected_model("deepseek-v4-pro"),
        "the seed-only pro build carries its own recorded price"
    );
}

/// The `deepseek` reasoning surface this band proves: every built-in
/// offer carries its catalogue reasoning mark over the recorded
/// effort ladder, the pinned effort rides the `reasoning_effort`
/// member verbatim, and a native `reasoning_content` fragment never
/// joins the visible answer — the stream completes carrying only its
/// `content`. The recorded `thinking` body member that disables
/// reasoning on a non-reasoner request is not sent here; it is
/// deferred as `D5` to the first recorded-request body carrying it.
#[tokio::test]
async fn deepseek_native_reasoning_rules_are_preserved() {
    // the catalogue surface: a built-in declares reasoning over the
    // recorded ladder — the unmappable `max` level drops rather than
    // coercing to a lower one — and the recorded USD price carries
    // while the prepaid balance stays an account fact
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": DEEPSEEK_MODEL})]).await;
    let config = Config::parse_validated(&deepseek_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_deepseek_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the listing answers");
    drop_blocking(provider);
    let built = models
        .iter()
        .find(|model| model.id == DEEPSEEK_MODEL)
        .expect("the built-in offers");
    assert!(built.reasoning, "the native reasoning surface binds");
    assert_eq!(
        built.efforts,
        vec![EffortLevel::Low, EffortLevel::High],
        "the recorded ladder lands without the unmappable max level"
    );
    assert_eq!(
        built.price,
        ModelPrice::Usd {
            input_per_1m: 0.14,
            output_per_1m: 0.28,
        },
        "the recorded per-model USD price carries"
    );

    // the wire surface: the pinned effort rides verbatim and a
    // native `reasoning_content` fragment never joins the visible
    // answer — the stream completes with its content alone; the
    // recorded `thinking` body member stays unsent here (deferred as
    // `D5`)
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}",
            data_block(&delta_chunk(json!({
                "reasoning_content": "internal chain of thought",
            }))),
            completed_stream(
                "reasoned answer",
                Some(json!({"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5})),
            ),
        ),
    )
    .await;
    let config = Config::parse_validated(&deepseek_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_deepseek_provider(&config),
        &config,
        "/world/deepseek",
        "goal: reasoning stream",
    );
    let (broker, outcome) = dispatch(broker, "/world/deepseek", manifest);
    let reply = outcome.expect("the reasoning stream completes");
    assert_eq!(
        reply.text, "reasoned answer",
        "the reasoning fragment never joins the visible answer"
    );
    let requests = server.received_requests().await.expect("recorded");
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["reasoning_effort"],
        json!("medium"),
        // verbatim send is the recorded band convention every prior id
        // keeps — `classes/deepseek.kdl` folds medium/xhigh to high,
        // but the wire carries what the pin declared
        "the pinned effort rides the reasoning surface verbatim"
    );
    assert!(
        body.get("thinking").is_none(),
        "the recorded thinking body member is unsent (D5): {body}"
    );
    drop_blocking(broker);
}

/// An empty configured endpoint resolves the recorded default —
/// the `config?.baseUrl ?? defaultBaseUrl` absent arm our
/// required `endpoint` field expresses as the empty string, and
/// whitespace-only shares the arm under the recorded trim. Offline
/// pin: the adapter's `Debug` surface reports the resolved endpoint,
/// so the arm is proved without one byte toward
/// `api.deepseek.com`.
#[test]
fn deepseek_empty_endpoint_resolves_the_recorded_default() {
    for endpoint in ["", "   "] {
        let config = Config::parse_validated(&deepseek_config(endpoint))
            .expect("an empty endpoint is valid");
        let (provider, _store) = enrolled_deepseek_provider(&config);
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"https://api.deepseek.com\""),
            "endpoint {endpoint:?} resolved to the recorded default: {debug}"
        );
        drop_blocking(provider);
    }
}

/// The auto-pick catalogue leg rides the authoritative listing under
/// the built-in gate: a listed benchmark id can never become the
/// wire model — the dispatch narrows the pool to the `deepseek`
/// member and the shared adapter resolves the deterministic
/// sorted-first built-in.
#[tokio::test]
async fn deepseek_auto_pick_resolves_through_the_authoritative_catalog() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            // would sort first if admitted — the built-in gate keeps
            // it out of the offer set entirely
            json!({"id": "aaa-benchmark"}),
            json!({"id": "deepseek-v4-pro"}),
        ],
    )
    .await;
    mount_chat(
        &server,
        completed_stream(
            "auto picked",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.deepseek]\nkind = \"api_key\"\nendpoint = \"{base}\"\ncredential_ref = \"{DEEPSEEK_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\", pool = [\"deepseek\"] }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let (provider, _store) = enrolled_deepseek_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/deepseek", "goal: auto pick")
        .expect("the single-member pool pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/deepseek", manifest);
    let reply = outcome.expect("the auto pick dispatches");
    assert_eq!(reply.text, "auto picked");
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "the catalogue leg and the send are the only egress"
    );
    let body: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert_eq!(
        body["model"],
        json!("deepseek-v4-flash"),
        "the sorted-first built-in names the wire model — a benchmark id never picks"
    );
}

// ----- TP-PROVIDER-AUTH::deepseek ---------------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `deepseek`: a configured `region` — the recorded contract names
/// none — the profile-bound ref whose scope disagrees with the
/// binding, an absent credential, credential material that is not
/// UTF-8 text and a refused bearer token each land a typed denial,
/// and none of them, nor any Debug surface the boundary exposes,
/// renders credential material or the peer's body.
#[tokio::test]
async fn deepseek_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &deepseek_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "deepseek".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, DEEPSEEK_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "deepseek");
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, DEEPSEEK_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.deepseek]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"deepseek\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "deepseek".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, DEEPSEEK_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, DEEPSEEK_KEY.as_bytes());

    // a bound ref with no material at its own scope — the sibling
    // scope's material stays sealed behind the typed denial
    let config = Config::parse_validated(&deepseek_config(&server_uri_v1(&server))).expect("valid");
    let provider = provider_result(
        config.clone(),
        "deepseek".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, DEEPSEEK_KEY)],
        )),
    )
    .expect("binding resolves; the store is read at send");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("no material at the scope is the typed denial");
    assert!(matches!(err, ProviderError::CredentialAbsent { .. }));
    assert_no_secret_or_body(&err, DEEPSEEK_KEY.as_bytes());
    drop_blocking(provider);

    // material that is not UTF-8 text cannot be a bearer token: the
    // typed malformed denial lands before any wire leg — zero
    // requests reach the mock
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    store.enroll(DEEPSEEK_REF, &[0xFF, 0xFE, 0xFD]);
    let provider =
        provider_result(config.clone(), "deepseek".to_string(), store).expect("binding resolves");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("non-text material denies before any wire leg");
    assert!(
        matches!(err, ProviderError::CredentialMalformed { .. }),
        "non-UTF-8 material is the typed malformed denial: {err}"
    );
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "denied credentials never reached the wire"
    );

    // a refused bearer token is a typed transport denial — the wire
    // never coerces a wrong credential into success, and the peer's
    // body never enters the error
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let (provider, _store) = enrolled_deepseek_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused token is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused token is transport: {err}")
    };
    assert_eq!(connection, "deepseek");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, DEEPSEEK_KEY.as_bytes());
    drop_blocking(provider);

    // The same boundary on the Debug surfaces the dispatch path
    // exposes: provider, manifest, accounting record, broker and
    // runtime each render without the material the store alone holds.
    let server = MockServer::start().await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&deepseek_config(&base)).expect("valid");
    let provider = provider_result(
        config.clone(),
        "deepseek".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(DEEPSEEK_REF, DEEPSEEK_KEY)],
        )),
    )
    .expect("the adapter builds");
    assert!(
        !format!("{provider:?}").contains(DEEPSEEK_KEY),
        "provider Debug never carries credential material"
    );
    mount_chat(
        &server,
        completed_stream(
            "accounted",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let (broker, manifest) = {
        let (provider, _store) = enrolled_deepseek_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/deepseek", "goal: debug surfaces")
            .expect("the pin passes DEC-011 eligibility");
        (broker, manifest)
    };
    assert!(
        !format!("{manifest:?}").contains(DEEPSEEK_KEY),
        "manifest Debug never carries credential material"
    );
    let (broker, outcome) = dispatch(broker, "/world/deepseek", manifest.clone());
    outcome.expect("the debug-surface send completes");
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert!(
        !format!("{record:?}").contains(DEEPSEEK_KEY),
        "accounting-record Debug never carries credential material"
    );
    assert!(
        !format!("{broker:?}").contains(DEEPSEEK_KEY),
        "broker Debug never carries credential material"
    );
    drop_blocking(broker);
    drop_blocking(provider);

    let world = support::open_world(
        "auth-debug-deepseek",
        Some(&deepseek_config(&server_uri_v1(&server))),
    );
    assert!(
        !format!("{:?}", world.runtime).contains(DEEPSEEK_KEY),
        "runtime Debug never carries credential material"
    );
}

/// A `/models` HTTP 200 is never entitlement (INV-010): the recorded
/// validate leg exercises `chat/completions`, so a fixture listing
/// answering an arbitrary roster proves nothing — with the key
/// enrolled the fixed pin still rides only its request leg, and the
/// unmounted `chat/completions` peer answers the typed transport
/// denial while the 200 listing is never consulted.
#[tokio::test]
async fn deepseek_models_http_200_is_never_entitlement() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": DEEPSEEK_MODEL})]).await;
    let config = Config::parse_validated(&deepseek_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_deepseek_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a 200 catalogue never releases the pin");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the unmounted request leg is the typed transport denial: {err:?}");
    };
    assert_eq!(connection, "deepseek");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 404 },
        "the request leg answers the peer's status, never a listing-granted success: {cause}"
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "only the request leg runs — the 200 listing releases no entitlement"
    );
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
}

// ----- TP-PROVIDER-RECOVERY::deepseek -----------------------------------------

/// A typed denial is recoverable through the same seam: the absent
/// credential denies the first send, enrolling the material at the
/// scope admits the retry — no state wedged, no plaintext path
/// taken.
#[tokio::test]
async fn deepseek_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config = Config::parse_validated(&deepseek_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "deepseek".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialAbsent { .. })
    ));

    store.enroll(DEEPSEEK_REF, DEEPSEEK_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the enrolled credential admits the retry");
    assert_eq!(reply.text, "recovered");
    drop_blocking(provider);
}

/// The legs matrix enforces the recorded expected set for
/// `deepseek`: CATALOG, AUTH, WIRE and RECOVERY each execute and
/// report inside this run, and INSTALLED reports NOT_RUN — an
/// omitted leg fails the suite rather than silently absenting.
#[tokio::test]
async fn deepseek_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "matrix"})]).await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&deepseek_config(&server_uri_v1(&server))).expect("valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the listing's non-built-in id filters out — the
    // built-in seed floor alone is the offer.
    let (provider, _store) = enrolled_deepseek_provider(&config);
    let (provider, listed) = catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if model_ids(&listed.expect("catalog answers")) == DEEPSEEK_BUILTIN_IDS {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: an absent credential denies typed before any leg.
    let absent = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), "deepseek".to_string(), absent).expect("binding resolves");
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
    let (broker, manifest) = {
        let (provider, _store) = enrolled_deepseek_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/deepseek", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
    let (broker, outcome) = dispatch(broker, "/world/deepseek", manifest);
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
    let provider = provider_result(config.clone(), "deepseek".to_string(), empty.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(DEEPSEEK_REF, DEEPSEEK_KEY.as_bytes());
    let (provider, retried) = send_on_thread(provider, manifest);
    let recovered = matches!(&retried, Ok(reply) if reply.text == "matrix");
    reported.insert(
        "RECOVERY",
        if denied_ok && recovered {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // The literal row mirrors the `#[ignore]`d
    // `provider_installed_deepseek` case below: its ignored count is
    // the explicit NOT_RUN signal this matrix asserts — the row stays
    // a literal so the two cannot drift.
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

// ----- TP-PROVIDER-INSTALLED::deepseek ----------------------------------------

/// TP-PROVIDER-INSTALLED::deepseek = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::deepseek = NOT_RUN"]
fn provider_installed_deepseek() {}
// ----- fireworks --------------------------------------------------------------

// The `fireworks` connection's proof legs (HZN-008 class A): the
// shared Chat Completions adapter serves the literal id — no copied
// codec — under its own recorded predicates (`Rivect/key`,
// `fireworksModelManagerOptions`, `providers/fireworks.kdl` +
// `auth/fireworks.kdl`, commit `0133f7ff52d3859944b4fd4ccf3852df7fbf1b54`).
// The configured `endpoint` carries the API base verbatim — an empty
// one resolves the recorded `api.fireworks.ai/inference/v1` default
// (`config?.baseUrl ?? defaultBaseUrl`'s absent arm), and a
// configured `region` is denied: the contract names none. The
// catalogue is the configured base's own request-model `/models`
// listing — the `/v1/accounts/fireworks/models` management API is
// never a model source — under the recorded serverless/fast
// chat-model predicates: an `accounts/fireworks/models/` wire id
// normalizes to its public form (`p` version separator folded back
// to `.`), an id still carrying a reserved `accounts/fireworks/`
// prefix is dropped (router ids are serving paths, never models
// this connection offers), and the recorded Fast seed floors the
// offer — Fast router variants the listing never surfaces. The
// request body sends the recorded wire-model-id dispatch:
// `accounts/fireworks/models/<id>` — `accounts/fireworks/routers/
// <id>` for a `*-fast` id — with the `p` version separator. The
// credential is the recorded plain `key` bearer; material that is
// not UTF-8 text denies malformed before any wire leg; the recorded
// per-model USD prices carry onto the offered surface — a stated
// zero is a real figure — and the pinned rows' cache figures stay
// uncarried: `ModelPrice` holds input/output alone.

/// The scoped credential ref the `fireworks` connection binds.
const FIREWORKS_REF: &str = "keyring:rivect-test/fireworks";

/// Fixture fireworks key material — never a real credential, only
/// ever sent to localhost.
const FIREWORKS_KEY: &str = "fixture-fireworks-key";

/// The pinned model id the fixed-pin legs carry — a recorded
/// bundled row, so the pin is one the catalogue could itself offer.
const FIREWORKS_MODEL: &str = "kimi-k2.7-code";

/// The recorded Fast seed ids, sorted — the offer floor the listing
/// never surfaces: every seeded id wires under the recorded
/// `wire-model-id-mode "firepass"` router dispatch.
const FIREWORKS_FAST_SEED_IDS: [&str; 4] = [
    "glm-5.1-fast",
    "glm-5.2-fast",
    "kimi-k2.6-fast",
    "kimi-k2.7-code-fast",
];

/// The recorded Fast seed's price as an independent expected
/// snapshot: id and USD input/output per 1M tokens.
fn fireworks_expected_fast_prices() -> [(&'static str, f64, f64); 4] {
    [
        ("glm-5.1-fast", 2.8, 8.8),
        ("glm-5.2-fast", 2.1, 6.6),
        ("kimi-k2.6-fast", 2.0, 8.0),
        ("kimi-k2.7-code-fast", 1.9, 8.0),
    ]
}

/// One configured `fireworks` connection pointing at the fixture
/// peer: the api_key auth class resolves a scoped `SecretRef`
/// (DEC-011), the dialect comes from the literal connection id
/// (DEC-007), and the endpoint carries the API base verbatim.
fn fireworks_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.fireworks]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{FIREWORKS_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"fireworks\", model_id = \"{FIREWORKS_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn fireworks_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(FIREWORKS_REF, material)],
    ));
    let provider = provider_result(config.clone(), "fireworks".to_string(), store.clone())
        .expect("the shared adapter builds for the fireworks id");
    (provider, store)
}

/// The `fireworks` provider over the recorded enrolled credential.
fn enrolled_fireworks_provider(
    config: &Config,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    fireworks_provider(config, FIREWORKS_KEY)
}

// ----- TP-PROVIDER-WIRE::fireworks --------------------------------------------

/// A configured `fireworks` connection returns a verified model
/// outcome through the standard Broker: prepare admits the api_key
/// pin under DEC-011, the plain bearer credential rides the
/// `Authorization` header — no scope member, no body copy — and the
/// shared adapter posts exactly the frozen manifest as a
/// `chat/completions` request — the pinned public id translated
/// under the recorded `wire-model-id-mode` dispatch into
/// `accounts/fireworks/models/<id>` (the digit-adjacent `.` in
/// `kimi-k2.7-code` folds to `p`), system+user
/// messages, `stream` with `stream_options.include_usage` and the
/// pinned effort as `reasoning_effort` verbatim — the SSE stream
/// validates its finish_reason/`[DONE]` terminal, and the one
/// physical send is charged once with the provider's reported usage.
#[tokio::test]
async fn fireworks_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified outcome text",
            Some(json!({"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&fireworks_config(&base)).expect("valid");
    let (provider, _store) = enrolled_fireworks_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/fireworks", "goal: prove the wire")
        .expect("the fireworks pin passes DEC-011 eligibility");

    let (broker, outcome) = dispatch(broker, "/world/fireworks", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified outcome text");
    assert!(reply.tool_calls.is_empty());

    // The wire request is exactly the frozen manifest — and nothing
    // the manifest does not carry; a fixed pin opens no catalogue leg.
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {FIREWORKS_KEY}"),
        "the plain key material bears the wire verbatim"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(FIREWORKS_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"],
        json!("accounts/fireworks/models/kimi-k2p7-code"),
        "the pinned public id translates under the recorded wire-model-id dispatch — the p separator folded"
    );
    assert_eq!(
        body["messages"],
        json!([
            {"role": "system", "content": manifest.instructions},
            {"role": "user", "content": manifest.inputs},
        ]),
        "the frozen instructions and inputs ride the messages verbatim"
    );
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["stream_options"],
        json!({"include_usage": true}),
        "the recorded usage request rides the stream options"
    );
    assert_eq!(
        body["reasoning_effort"],
        json!("medium"),
        "the pinned effort rides the recorded reasoning_effort surface"
    );

    // Exactly one accounting record carries the one physical usage
    // report — the provider's 18 tokens are the confirmed charge, and
    // a replayed attempt reports spent.
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "fireworks");
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
            let replay = broker.dispatch(
                &mut rivect::model::NullLedger,
                "/world/fireworks",
                &manifest,
            );
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

/// Hostile stream input is never a false success for `fireworks`: a
/// stream ended mid `tool_calls` fragment — a partial call that never
/// executes — and a finish_reason the dialect cannot classify are both
/// the unknown terminal, and a rejected send charges nothing.
#[tokio::test]
async fn fireworks_adverse_wire_input_never_reports_success() {
    // a complete content delta plus an unterminated tool-call
    // fragment, then EOF — no finish_reason and no [DONE]
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&delta_chunk(json!({
                "tool_calls": [{
                    "index": 0,
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": "{\"path\":"},
                }],
            }))),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&fireworks_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_fireworks_provider(&config),
        &config,
        "/world/fireworks",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/fireworks", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "EOF mid tool call is the unknown terminal — never a usable call: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);

    // a finish_reason the dialect cannot classify is unknown, never
    // success
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&finish_chunk("mystery")),
            DONE_BLOCK
        ),
    )
    .await;
    let config =
        Config::parse_validated(&fireworks_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_fireworks_provider(&config),
        &config,
        "/world/fireworks",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/fireworks", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "an unclassifiable terminal is the unknown terminal: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);
}

/// The recorded `wire-model-id-mode "firepass"` dispatch: a `*-fast`
/// pin sends the router wire form `accounts/fireworks/routers/<id>`
/// — the Fast serving path is a router, never a models/ id — while
/// the models wire prefix stays for the base ids. A digit-adjacent
/// `.` folds to `p` and a `p` between digits in the listing id folds
/// back — the translation is the recorded round-trip.
#[tokio::test]
async fn fireworks_fast_pin_sends_the_recorded_router_wire_form() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "fast outcome",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(
        &fireworks_config(&base).replace(FIREWORKS_MODEL, "kimi-k2.6-fast"),
    )
    .expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_fireworks_provider(&config),
        &config,
        "/world/fireworks",
        "goal: fast wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/fireworks", manifest);
    let reply = outcome.expect("the fast pin dispatches");
    assert_eq!(reply.text, "fast outcome");
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "one physical request — no catalogue leg");
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"],
        json!("accounts/fireworks/routers/kimi-k2p6-fast"),
        "a *-fast pin rides the recorded router wire form — never the models/ prefix"
    );
}

/// The recorded wire-model-id dispatch strips whichever wire prefix a
/// pin already carries before re-prefixing it: `routers/` exactly
/// when the stripped id ends `-fast`, `models/` otherwise, so no pin
/// stacks a second prefix and a prefix that disagrees with the id is
/// replaced by the serving path the id names.
#[tokio::test]
async fn fireworks_router_form_pin_round_trips_the_recorded_wire_form() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "router form outcome",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    for (pinned, expected) in [
        (
            "accounts/fireworks/routers/kimi-k2p6-fast",
            "accounts/fireworks/routers/kimi-k2p6-fast",
        ),
        (
            "accounts/fireworks/models/kimi-k2p7-code",
            "accounts/fireworks/models/kimi-k2p7-code",
        ),
        (
            "accounts/fireworks/routers/kimi-k2p6-turbo",
            "accounts/fireworks/models/kimi-k2p6-turbo",
        ),
        (
            "accounts/fireworks/models/kimi-k2.6-fast",
            "accounts/fireworks/routers/kimi-k2p6-fast",
        ),
    ] {
        let config =
            Config::parse_validated(&fireworks_config(&base).replace(FIREWORKS_MODEL, pinned))
                .expect("valid");
        let (broker, manifest) = prepared_with(
            enrolled_fireworks_provider(&config),
            &config,
            "/world/fireworks",
            "goal: router wire",
        );
        let (broker, outcome) = dispatch(broker, "/world/fireworks", manifest);
        outcome.expect("the router-form pin dispatches");
        drop_blocking(broker);

        let requests = server.received_requests().await.expect("recorded");
        let body: Value =
            serde_json::from_slice(&requests[requests.len() - 1].body).expect("json body");
        assert_eq!(
            body["model"],
            json!(expected),
            "a {pinned} pin lands the serving-path wire form — routers/ for a *-fast id, models/ otherwise"
        );
    }
}

/// The dialect keys on the literal connection id, never an auth
/// label: an id without the recorded Chat Completions class builds
/// no adapter — a Chat-Completions-classed id is reserved for its
/// own named contract arm — `dialect_for` reserving `fireworks`
/// means the id is never fixture-served even when it declares
/// `local` kind, and a manifest pinning a different connection id is
/// refused at send.
#[test]
fn fireworks_dialect_is_keyed_on_the_literal_connection_id() {
    assert_eq!(
        rivect::providers::dialect_for("fireworks"),
        Some(rivect::providers::Dialect::ChatCompletions),
        "the literal id binds the shared Chat Completions dialect"
    );
    let config =
        Config::parse_validated(&fireworks_config("http://127.0.0.1:1/v1")).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = provider_result(config.clone(), "fireworks-plus".to_string(), store)
        .expect_err("a different literal id is not this dialect");
    assert!(matches!(err, ProviderError::DialectMismatch { .. }));

    // a dialect-reserved id is never fixture-served whatever kind it
    // declares — `fireworks` pinned `local` keeps the typed denial
    let local = Config::parse_validated(
        "config_version = 1\n\
         [connections.fireworks]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"fireworks\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"medium\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let loopback = rivect::providers::LoopbackProvider::new();
    let entry = local.connections.get("fireworks").expect("declared");
    assert!(
        !loopback.serves("fireworks", entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );

    // a manifest pinning a different connection id is refused at send —
    // the bound credential is well-formed so the denial is the dialect's,
    // never the credential seam's
    let (provider, _store) = enrolled_fireworks_provider(&config);
    let foreign = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.other]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1/v1\"\ncredential_ref = \"{FIREWORKS_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"other\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let manifest = {
        let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
        broker
            .prepare("main", &foreign, "/world/fireworks", "goal: x")
            .expect("foreign pin prepares")
    };
    let (provider, outcome) = send_on_thread(provider, manifest);
    assert!(
        matches!(outcome, Err(ProviderError::DialectMismatch { .. })),
        "a foreign pin never speaks this dialect: {outcome:?}"
    );
    drop_blocking(provider);
}

// ----- TP-PROVIDER-CATALOG::fireworks -----------------------------------------

/// The `fireworks` catalogue is the configured base's own
/// request-model `/models` listing under the recorded
/// serverless/fast transform (HZN-008 class A): the lookup resolves
/// the plain bearer credential on the one `GET {endpoint}/models`
/// leg, a listed `accounts/fireworks/models/` wire id normalizes to
/// its public form — the `p` separator between digits folds back to
/// `.` — an id still carrying a reserved `accounts/fireworks/`
/// prefix is dropped as a serving path, and every admitted id lands
/// the recorded per-model USD price the pinned row states (a stated
/// zero is a real figure, an unbundled id stays `Unknown`).
#[tokio::test]
async fn fireworks_catalog_lists_the_recorded_request_model_surface() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "accounts/fireworks/models/kimi-k2p7-code"}),
            // a listed fast id the seed does not name — the listing
            // leg alone must offer it under its public form
            json!({"id": "accounts/fireworks/models/glm-5p3-flash-fast"}),
            json!({"id": "deepseek-v4-pro"}),
            json!({"id": "flux-1-schnell-fp8"}),
            json!({"id": "unbundled-fixture-model"}),
            // an empty or absent id can never name a model — and a
            // listed router id is a serving path, never offered
            json!({"id": ""}),
            json!({"metadata": {}}),
            json!({"id": "accounts/fireworks/routers/kimi-k2p6-turbo"}),
        ],
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&fireworks_config(&base)).expect("valid");
    let (provider, _store) = enrolled_fireworks_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the request-model listing answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        [
            "deepseek-v4-pro",
            "flux-1-schnell-fp8",
            "glm-5.1-fast",
            "glm-5.2-fast",
            "glm-5.3-flash-fast",
            "kimi-k2.6-fast",
            "kimi-k2.7-code",
            "kimi-k2.7-code-fast",
            "unbundled-fixture-model",
        ],
        "the listing offers the normalized public ids plus the Fast seed floor — a router id never offers"
    );
    let model = |id: &str| {
        models
            .iter()
            .find(|model| model.id == id)
            .unwrap_or_else(|| panic!("{id} is offered"))
    };
    assert_eq!(
        model("kimi-k2.7-code"),
        &CatalogModel {
            id: "kimi-k2.7-code".to_string(),
            price: ModelPrice::Usd {
                input_per_1m: 0.67,
                output_per_1m: 3.4,
            },
            ..CatalogModel::default()
        },
        "a bundled id lands its public form and recorded USD price — the p separator folded back"
    );
    assert_eq!(
        model("flux-1-schnell-fp8"),
        &CatalogModel {
            id: "flux-1-schnell-fp8".to_string(),
            price: ModelPrice::Usd {
                input_per_1m: 0.0,
                output_per_1m: 0.0,
            },
            ..CatalogModel::default()
        },
        "a stated zero is a real figure — a free SKU, never the unknown state"
    );
    assert_eq!(
        model("unbundled-fixture-model"),
        &CatalogModel {
            id: "unbundled-fixture-model".to_string(),
            ..CatalogModel::default()
        },
        "an id the pinned rows do not name keeps the unknown price, never a borrowed figure"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "the listing leg is the only egress — the management API is never consulted"
    );
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {FIREWORKS_KEY}"),
        "the plain key bears the discovery leg"
    );
}

/// The `/v1/accounts/fireworks/models` management API is never a
/// model source (DEC-025, EDGE fireworks row): the catalogue is the
/// configured base's own request-model `/models` listing, and the
/// recorded serverless/fast predicates gate admission — a listing
/// entry still carrying a reserved `accounts/fireworks/` prefix is
/// dropped, a public id offers through the transform, and no leg
/// ever touches the account-scoped management path.
#[tokio::test]
async fn fireworks_management_api_is_never_a_model_source() {
    let server = MockServer::start().await;
    // the management API is not mounted — any call toward
    // /v1/accounts/fireworks/models would answer 404 and the lookup
    // would fail rather than harvest a management page
    mount_models(
        &server,
        vec![
            json!({"id": "accounts/fireworks/models/glm-5p2"}),
            json!({"id": "accounts/fireworks/routers/managed-thing"}),
        ],
    )
    .await;
    let config =
        Config::parse_validated(&fireworks_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_fireworks_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the request-model listing answers");
    drop_blocking(provider);
    assert!(
        models.iter().any(|model| model.id == "glm-5.2"),
        "a wire-prefixed id normalizes to its public form: {}",
        model_ids(&models).join(", ")
    );
    assert!(
        !models.iter().any(|model| model.id.contains("routers")),
        "a listed router id is a serving path — never a model offer"
    );
    let requests = server.received_requests().await.expect("recorded");
    for request in &requests {
        assert!(
            !request.url.path().starts_with("/v1/accounts/"),
            "the management API is never a model source: {}",
            request.url.path()
        );
    }
    assert_eq!(requests.len(), 1, "one request-model listing leg");
    assert_eq!(requests[0].url.path(), "/v1/models");
}

/// The recorded Fast seed floors the offer (HZN-008 class A): Fast
/// router variants never appear in the serverless list, so the seed
/// ids offer even when the listing omits them — and every seeded
/// offer carries the recorded surface the transform lands, the
/// recorded variant USD price included, never a bare id-only stub.
#[tokio::test]
async fn fireworks_seed_floor_carries_the_full_recorded_surface() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            // a base id the listing states — the whole Fast offer
            // below is the seed's, never a listed entry's
            json!({"id": "deepseek-v4-flash"}),
        ],
    )
    .await;
    let config =
        Config::parse_validated(&fireworks_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_fireworks_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the listing answers");
    drop_blocking(provider);
    let model = |id: &str| {
        models
            .iter()
            .find(|model| model.id == id)
            .unwrap_or_else(|| panic!("{id} is offered"))
    };
    for (id, input_per_1m, output_per_1m) in fireworks_expected_fast_prices() {
        assert_eq!(
            model(id),
            &CatalogModel {
                id: id.to_string(),
                price: ModelPrice::Usd {
                    input_per_1m,
                    output_per_1m,
                },
                ..CatalogModel::default()
            },
            "a seed-only Fast offer carries the recorded variant price — the discriminating leg a bare-stub seed arm would lose"
        );
    }
    assert!(
        FIREWORKS_FAST_SEED_IDS
            .iter()
            .all(|id| models.iter().any(|model| &model.id == id)),
        "every recorded Fast seed id offers through the floor"
    );
}

/// The recorded serverless/fast predicates gate the listing (DEC-025
/// row wording): the `models/` wire prefix strips to the public id,
/// a `p` version separator folds back to `.`, a `*-fast` public id
/// is a router serving path offered as such — never under the
/// models/ wire prefix — and an id still carrying the reserved
/// `accounts/fireworks/` prefix drops as a non-model serving path.
#[tokio::test]
async fn fireworks_serverless_fast_predicates_filter_the_listing() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "accounts/fireworks/models/glm-5p3-flash-fast"}),
            json!({"id": "accounts/fireworks/routers/kimi-k2p6-turbo"}),
            json!({"id": "accounts/fireworks/other-namespace/thing"}),
        ],
    )
    .await;
    let config =
        Config::parse_validated(&fireworks_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_fireworks_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the listing answers");
    drop_blocking(provider);
    let listed_fast = models
        .iter()
        .find(|model| model.id == "glm-5.3-flash-fast")
        .unwrap_or_else(|| panic!("a listed fast id the seed never names offers"));
    assert_eq!(
        listed_fast.price,
        ModelPrice::Unknown,
        "an unshipped fast variant keeps the unknown price — a prefix-matching row never lends glm-5.3-flash its figure"
    );
    for listed in [
        "accounts/fireworks/routers/kimi-k2p6-turbo",
        "accounts/fireworks/other-namespace/thing",
    ] {
        assert!(
            !models.iter().any(|model| model.id == listed),
            "a reserved-prefix id is dropped as a serving path: {listed}"
        );
    }
    assert!(
        !models.iter().any(|model| model.id.starts_with("accounts/")),
        "no reserved-prefix form lands on the offer surface"
    );
}

/// An empty configured endpoint resolves the recorded default —
/// the `config?.baseUrl ?? defaultBaseUrl` absent arm our
/// required `endpoint` field expresses as the empty string, and
/// whitespace-only shares the arm under the recorded trim. Offline
/// pin: the adapter's `Debug` surface reports the resolved endpoint,
/// so the arm is proved without one byte toward
/// `api.fireworks.ai`.
#[test]
fn fireworks_empty_endpoint_resolves_the_recorded_default() {
    for endpoint in ["", "   "] {
        let config = Config::parse_validated(&fireworks_config(endpoint))
            .expect("an empty endpoint is valid");
        let (provider, _store) = enrolled_fireworks_provider(&config);
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"https://api.fireworks.ai/inference/v1\""),
            "endpoint {endpoint:?} resolved to the recorded default: {debug}"
        );
        drop_blocking(provider);
    }
}

/// The auto-pick catalogue leg rides the request-model listing under
/// the recorded transform: a listed serving-path id can never become
/// the wire model — the dispatch narrows the pool to the `fireworks`
/// member, the shared adapter resolves the deterministic
/// sorted-first offer, and the send translates it under the recorded
/// wire-model-id dispatch.
#[tokio::test]
async fn fireworks_auto_pick_resolves_through_the_request_model_catalog() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            // would sort first if admitted — the transform keeps it
            // out of the offer set entirely
            json!({"id": "accounts/fireworks/routers/aaa-path"}),
            json!({"id": "deepseek-v4-pro"}),
        ],
    )
    .await;
    mount_chat(
        &server,
        completed_stream(
            "auto picked",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.fireworks]\nkind = \"api_key\"\nendpoint = \"{base}\"\ncredential_ref = \"{FIREWORKS_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\", pool = [\"fireworks\"] }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let (provider, _store) = enrolled_fireworks_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/fireworks", "goal: auto pick")
        .expect("the single-member pool pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/fireworks", manifest);
    let reply = outcome.expect("the auto pick dispatches");
    assert_eq!(reply.text, "auto picked");
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "the catalogue leg and the send are the only egress"
    );
    let body: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert_eq!(
        body["model"],
        json!("accounts/fireworks/models/deepseek-v4-pro"),
        "the sorted-first offer names the wire model under the recorded dispatch — a serving path never picks"
    );
}

// ----- TP-PROVIDER-AUTH::fireworks --------------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `fireworks`: a configured `region` — the recorded contract names
/// none — the profile-bound ref whose scope disagrees with the
/// binding, an absent credential, credential material that is not
/// UTF-8 text and a refused bearer token each land a typed denial,
/// and none of them, nor any Debug surface the boundary exposes,
/// renders credential material or the peer's body.
#[tokio::test]
async fn fireworks_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &fireworks_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "fireworks".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, FIREWORKS_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "fireworks");
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, FIREWORKS_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.fireworks]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"fireworks\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "fireworks".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, FIREWORKS_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, FIREWORKS_KEY.as_bytes());

    // a bound ref with no material at its own scope — the sibling
    // scope's material stays sealed behind the typed denial
    let config =
        Config::parse_validated(&fireworks_config(&server_uri_v1(&server))).expect("valid");
    let provider = provider_result(
        config.clone(),
        "fireworks".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, FIREWORKS_KEY)],
        )),
    )
    .expect("binding resolves; the store is read at send");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("no material at the scope is the typed denial");
    assert!(matches!(err, ProviderError::CredentialAbsent { .. }));
    assert_no_secret_or_body(&err, FIREWORKS_KEY.as_bytes());
    drop_blocking(provider);

    // material that is not UTF-8 text cannot be a bearer token: the
    // typed malformed denial lands before any wire leg — zero
    // requests reach the mock
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    store.enroll(FIREWORKS_REF, &[0xFF, 0xFE, 0xFD]);
    let provider =
        provider_result(config.clone(), "fireworks".to_string(), store).expect("binding resolves");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("non-text material denies before any wire leg");
    assert!(
        matches!(err, ProviderError::CredentialMalformed { .. }),
        "non-UTF-8 material is the typed malformed denial: {err}"
    );
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "denied credentials never reached the wire"
    );

    // a refused bearer token is a typed transport denial — the wire
    // never coerces a wrong credential into success, and the peer's
    // body never enters the error
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let (provider, _store) = enrolled_fireworks_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused token is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused token is transport: {err}")
    };
    assert_eq!(connection, "fireworks");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, FIREWORKS_KEY.as_bytes());
    drop_blocking(provider);

    // The same boundary on the Debug surfaces the dispatch path
    // exposes: provider, manifest, accounting record, broker and
    // runtime each render without the material the store alone holds.
    let server = MockServer::start().await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&fireworks_config(&base)).expect("valid");
    let provider = provider_result(
        config.clone(),
        "fireworks".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(FIREWORKS_REF, FIREWORKS_KEY)],
        )),
    )
    .expect("the adapter builds");
    assert!(
        !format!("{provider:?}").contains(FIREWORKS_KEY),
        "provider Debug never carries credential material"
    );
    mount_chat(
        &server,
        completed_stream(
            "accounted",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let (broker, manifest) = {
        let (provider, _store) = enrolled_fireworks_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/fireworks", "goal: debug surfaces")
            .expect("the pin passes DEC-011 eligibility");
        (broker, manifest)
    };
    assert!(
        !format!("{manifest:?}").contains(FIREWORKS_KEY),
        "manifest Debug never carries credential material"
    );
    let (broker, outcome) = dispatch(broker, "/world/fireworks", manifest.clone());
    outcome.expect("the debug-surface send completes");
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert!(
        !format!("{record:?}").contains(FIREWORKS_KEY),
        "accounting-record Debug never carries credential material"
    );
    assert!(
        !format!("{broker:?}").contains(FIREWORKS_KEY),
        "broker Debug never carries credential material"
    );
    drop_blocking(broker);
    drop_blocking(provider);

    let world = support::open_world(
        "auth-debug-fireworks",
        Some(&fireworks_config(&server_uri_v1(&server))),
    );
    assert!(
        !format!("{:?}", world.runtime).contains(FIREWORKS_KEY),
        "runtime Debug never carries credential material"
    );
}

/// A `/models` HTTP 200 is never entitlement (INV-010): with the key
/// enrolled the fixed pin still rides only its request leg, and a
/// listing answering arbitrary ids neither stands in for the
/// credential nor admits the send — the unmounted `chat/completions`
/// peer answers the typed transport denial while the 200 listing is
/// never consulted.
#[tokio::test]
async fn fireworks_models_http_200_is_never_entitlement() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": FIREWORKS_MODEL})]).await;
    let config =
        Config::parse_validated(&fireworks_config(&server_uri_v1(&server))).expect("valid");
    let provider = provider_result(
        config.clone(),
        "fireworks".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(FIREWORKS_REF, FIREWORKS_KEY)],
        )),
    )
    .expect("the enrolled binding resolves");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a 200 catalogue never releases the pin");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the unmounted request leg is the typed transport denial: {err:?}");
    };
    assert_eq!(connection, "fireworks");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 404 },
        "the request leg answers the peer's status, never a listing-granted success: {cause}"
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "only the request leg runs — the 200 listing releases no entitlement"
    );
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
}

// ----- TP-PROVIDER-RECOVERY::fireworks ----------------------------------------

/// A typed denial is recoverable through the same seam: the absent
/// credential denies the first send, enrolling the material at the
/// scope admits the retry — no state wedged, no plaintext path
/// taken.
#[tokio::test]
async fn fireworks_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&fireworks_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "fireworks".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialAbsent { .. })
    ));

    store.enroll(FIREWORKS_REF, FIREWORKS_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the enrolled credential admits the retry");
    assert_eq!(reply.text, "recovered");
    drop_blocking(provider);
}

/// The legs matrix enforces the recorded expected set for
/// `fireworks`: CATALOG, AUTH, WIRE and RECOVERY each execute and
/// report inside this run, and INSTALLED reports NOT_RUN — an
/// omitted leg fails the suite rather than silently absenting.
#[tokio::test]
async fn fireworks_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "deepseek-v4-flash"})]).await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&fireworks_config(&server_uri_v1(&server))).expect("valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the listing's base id plus the recorded Fast seed
    // floor is the offer — a serving path can never name a model.
    let (provider, _store) = enrolled_fireworks_provider(&config);
    let (provider, listed) = catalog_on_thread(provider);
    let listed = listed.expect("catalog answers");
    let offered = model_ids(&listed);
    reported.insert(
        "CATALOG",
        if offered.contains(&"deepseek-v4-flash")
            && FIREWORKS_FAST_SEED_IDS
                .iter()
                .all(|id| offered.contains(id))
        {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: an absent credential denies typed before any leg.
    let absent = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), "fireworks".to_string(), absent).expect("binding resolves");
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
    let (broker, manifest) = {
        let (provider, _store) = enrolled_fireworks_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/fireworks", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
    let (broker, outcome) = dispatch(broker, "/world/fireworks", manifest);
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
    let provider = provider_result(config.clone(), "fireworks".to_string(), empty.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(FIREWORKS_REF, FIREWORKS_KEY.as_bytes());
    let (provider, retried) = send_on_thread(provider, manifest);
    let recovered = matches!(&retried, Ok(reply) if reply.text == "matrix");
    reported.insert(
        "RECOVERY",
        if denied_ok && recovered {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // The literal row mirrors the `#[ignore]`d
    // `provider_installed_fireworks` case below: its ignored count is
    // the explicit NOT_RUN signal this matrix asserts — the row stays
    // a literal so the two cannot drift.
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

// ----- TP-PROVIDER-INSTALLED::fireworks ---------------------------------------

/// TP-PROVIDER-INSTALLED::fireworks = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::fireworks = NOT_RUN"]
fn provider_installed_fireworks() {}

// ----- firepass ---------------------------------------------------------------

// The `firepass` connection's proof legs (HZN-008 class P): the shared
// Chat Completions adapter serves the literal id — no copied codec —
// under its own recorded predicates (`auth/firepass.kdl`,
// `firepassModelManagerOptions`, commit
// `0133f7ff52d3859944b4fd4ccf3852df7fbf1b54`). The configured
// `endpoint` carries the API base verbatim — an empty one resolves the
// same recorded `api.fireworks.ai/inference/v1` default `fireworks`
// serves, under this connection's own contract — and admission
// discriminates by connection id, never by host. The catalogue is the
// recorded static router list alone: the `fpk_…` key authorizes no
// `/models` lookup, so no discovery leg exists and a listing answer
// proves no access. The credential is the dedicated `fpk_` pass key —
// a Fireworks account key on the shared host denies malformed before
// any wire leg. The request body sends every pin on the
// `accounts/fireworks/routers/` serving path with the `p` version
// separator, so the pinned `kimi-k2.6-turbo` router and the documented
// `kimi-k3-fast` id keep their own wire identities rather than folding
// into one. The class records no per-model price, so no offer claims a
// figure.

/// The scoped credential ref the `firepass` connection binds.
const FIREPASS_REF: &str = "keyring:rivect-test/firepass";

/// Fixture Fire Pass key material — never a real credential, only ever
/// sent to localhost.
const FIREPASS_KEY: &str = "fpk_fixture-firepass-key";

/// The pinned model id the fixed-pin legs carry — the pinned source's
/// recorded router identity, so the pin is one the catalogue offers.
const FIREPASS_MODEL: &str = "kimi-k2.6-turbo";

/// One configured `firepass` connection pointing at the fixture peer:
/// the api_key auth class resolves a scoped `SecretRef` (DEC-011), the
/// dialect comes from the literal connection id (DEC-007), and the
/// endpoint carries the API base verbatim.
fn firepass_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.firepass]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{FIREPASS_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"firepass\", model_id = \"{FIREPASS_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn firepass_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(FIREPASS_REF, material)],
    ));
    let provider = provider_result(config.clone(), "firepass".to_string(), store.clone())
        .expect("the shared adapter builds for the firepass id");
    (provider, store)
}

/// The `firepass` provider over the recorded enrolled pass key.
fn enrolled_firepass_provider(
    config: &Config,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    firepass_provider(config, FIREPASS_KEY)
}

// ----- TP-PROVIDER-WIRE::firepass ---------------------------------------------

/// A configured `firepass` connection returns a verified model
/// outcome through the standard Broker: prepare admits the api_key
/// pin under DEC-011, the `fpk_` pass key rides the `Authorization`
/// header and never the body, and the shared adapter posts exactly the
/// frozen manifest as a `chat/completions` request — the pinned
/// `kimi-k2.6-turbo` translated under the recorded router wire
/// dispatch into `accounts/fireworks/routers/kimi-k2p6-turbo` (the
/// digit-adjacent `.` folds to `p`), system+user messages, `stream`
/// with `stream_options.include_usage` and the pinned effort as
/// `reasoning_effort` verbatim — the SSE stream validates its
/// finish_reason/`[DONE]` terminal, the one physical send is charged
/// once with the provider's reported usage, and the spent attempt
/// never re-sends.
#[tokio::test]
async fn firepass_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified firepass outcome",
            Some(json!({"prompt_tokens": 9, "completion_tokens": 4, "total_tokens": 13})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&firepass_config(&base)).expect("valid");
    let (provider, _store) = enrolled_firepass_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/firepass", "goal: prove the wire")
        .expect("the firepass pin passes DEC-011 eligibility");

    let (broker, outcome) = dispatch(broker, "/world/firepass", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified firepass outcome");
    assert!(reply.tool_calls.is_empty());

    // The wire request is exactly the frozen manifest — and nothing
    // the manifest does not carry; a fixed pin opens no catalogue leg.
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {FIREPASS_KEY}"),
        "the pass key bears the wire verbatim"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(FIREPASS_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"],
        json!("accounts/fireworks/routers/kimi-k2p6-turbo"),
        "the pinned public router id translates into the recorded router wire form"
    );
    assert_eq!(
        body["messages"],
        json!([
            {"role": "system", "content": manifest.instructions},
            {"role": "user", "content": manifest.inputs},
        ]),
        "the frozen instructions and inputs ride the messages verbatim"
    );
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["stream_options"],
        json!({"include_usage": true}),
        "the recorded usage request rides the stream options"
    );
    assert_eq!(
        body["reasoning_effort"],
        json!("medium"),
        "the pinned effort rides the recorded reasoning_effort surface"
    );

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "firepass");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 9,
            completion_tokens: 4,
            total_tokens: 13,
        }
    );
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay =
                broker.dispatch(&mut rivect::model::NullLedger, "/world/firepass", &manifest);
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

/// Hostile stream input is never a false success for `firepass`: a
/// stream ended mid `tool_calls` fragment — a partial call that never
/// executes — and a finish_reason the dialect cannot classify are both
/// the unknown terminal, and a rejected send charges nothing.
#[tokio::test]
async fn firepass_adverse_wire_input_never_reports_success() {
    // a complete content delta plus an unterminated tool-call
    // fragment, then EOF — no finish_reason and no [DONE]
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&delta_chunk(json!({
                "tool_calls": [{
                    "index": 0,
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": "{\"path\":"},
                }],
            }))),
        ),
    )
    .await;
    let config = Config::parse_validated(&firepass_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_firepass_provider(&config),
        &config,
        "/world/firepass",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/firepass", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "EOF mid tool call is the unknown terminal — never a usable call: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);

    // a finish_reason the dialect cannot classify is unknown, never
    // success
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&finish_chunk("mystery")),
            DONE_BLOCK
        ),
    )
    .await;
    let config = Config::parse_validated(&firepass_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_firepass_provider(&config),
        &config,
        "/world/firepass",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/firepass", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "an unclassifiable terminal is the unknown terminal: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);
}

// ----- TP-PROVIDER-AUTH::firepass ---------------------------------------------

/// The recorded `fpk_` key grammar gates the `firepass` credential:
/// the recorded `fpk_…` form is admitted and bears a real send, while
/// a Fireworks account key on the shared `api.fireworks.ai` host — and
/// a bare `fpk_` prefix that carries no key — deny `CredentialMalformed`
/// typed before any wire leg, and the denied material never enters the
/// error's Display or Debug.
#[tokio::test]
async fn firepass_fpk_grammar_denies_a_non_fpk_key() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "admitted",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&firepass_config(&base)).expect("valid");

    // the recorded pass-key form is admitted
    let (provider, _store) = enrolled_firepass_provider(&config);
    let (provider, admitted) = send_on_thread(provider, prepared_manifest(&config));
    admitted.expect("the recorded fpk_ key is the connection's own credential");
    drop_blocking(provider);

    // a Fireworks account key and a bare prefix are unbound material
    // for this connection: typed denial, zero further wire legs
    for material in [FIREWORKS_KEY, "fpk_"] {
        let (provider, _store) = firepass_provider(&config, material);
        let (provider, denied) = send_on_thread(provider, prepared_manifest(&config));
        let err = denied.expect_err("material outside the pass-key grammar denies");
        assert!(
            matches!(err, ProviderError::CredentialMalformed { .. }),
            "the grammar denial is typed: {err}"
        );
        assert_no_secret_or_body(&err, material.as_bytes());
        drop_blocking(provider);
    }
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        1,
        "only the admitted send reached the wire — the denials landed before any leg"
    );
}

/// Wrong credential/profile/region never produce a false success for
/// `firepass`, through the same shared construction its siblings use:
/// a configured `region` — the recorded contract names none — denies
/// `RegionMismatch` with the connection context, a profile-bound ref
/// whose scope disagrees with the binding denies
/// `CredentialProfileMismatch`, and a refused pass key lands the typed
/// transport denial carrying the peer's status alone — no error, nor
/// the offered credential material or the peer's body, reaches
/// Display or Debug.
#[tokio::test]
async fn firepass_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &firepass_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "firepass".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, FIREPASS_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "firepass");
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, FIREPASS_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.firepass]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"firepass\", model_id = \"{FIREPASS_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "firepass".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, FIREPASS_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, FIREPASS_KEY.as_bytes());

    // a refused pass key is a typed transport denial — the wire never
    // coerces a wrong credential into success, the peer's body never
    // enters the error, and the request carried the pass key
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&firepass_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_firepass_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused pass key is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused pass key is transport: {err}")
    };
    assert_eq!(connection, "firepass");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, FIREPASS_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {FIREPASS_KEY}"),
        "the admitted grammar reached the wire — the denial is the peer's status"
    );
}

/// `firepass` and `fireworks` resolve the same `api.fireworks.ai`
/// host under their own connections: the recorded default endpoint
/// resolves for each literal id, the Fireworks account key is admitted
/// as `fireworks`' plain bearer and denied as `firepass`' pass key, and
/// a manifest pinning the other connection is refused by the literal-id
/// send gate, never by host matching.
#[tokio::test]
async fn firepass_and_fireworks_share_a_host_but_not_a_connection() {
    // the same host resolves for both ids from the recorded default
    for (config, id) in [
        (firepass_config(""), "firepass"),
        (fireworks_config(""), "fireworks"),
    ] {
        let config = Config::parse_validated(&config).expect("an empty endpoint is valid");
        let provider = provider_result(
            config,
            id.to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the adapter builds");
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"https://api.fireworks.ai/inference/v1\""),
            "the {id} connection resolves the shared recorded host: {debug}"
        );
        drop_blocking(provider);
    }

    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "shared host",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);

    // the Fireworks bearer is admitted on its own connection ...
    let fireworks = Config::parse_validated(&fireworks_config(&base)).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_fireworks_provider(&fireworks),
        &fireworks,
        "/world/fireworks",
        "goal: shared host",
    );
    let (broker, outcome) = dispatch(broker, "/world/fireworks", manifest);
    outcome.expect("the fireworks bearer is its own connection's credential");
    drop_blocking(broker);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "one fireworks send reaches the wire");

    // ... and denied on `firepass`, the same host's other connection
    let firepass = Config::parse_validated(&firepass_config(&base)).expect("valid");
    let (provider, _store) = firepass_provider(&firepass, FIREWORKS_KEY);
    let (provider, denied) = send_on_thread(provider, prepared_manifest(&firepass));
    let err = denied.expect_err("the fireworks key is unbound material for firepass");
    assert!(
        matches!(err, ProviderError::CredentialMalformed { .. }),
        "the shared host never shares a credential grammar: {err}"
    );
    assert_no_secret_or_body(&err, FIREWORKS_KEY.as_bytes());
    drop_blocking(provider);

    // a pin naming the other connection is refused by the literal id,
    // never admitted because the host agrees
    let (provider, _store) = enrolled_firepass_provider(&firepass);
    let foreign = prepared_manifest(&fireworks);
    let (provider, refused) = send_on_thread(provider, foreign);
    assert!(
        matches!(refused, Err(ProviderError::DialectMismatch { .. })),
        "the firepass adapter never serves a fireworks pin: {refused:?}"
    );
    drop_blocking(provider);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        1,
        "the denied key and the foreign pin both stopped before any wire leg"
    );
}

/// The recorded router-identity divergence is carried, not folded: the
/// static catalogue offers the pinned source's `kimi-k2.6-turbo` and
/// the documented `kimi-k3-fast` as two distinct router identities,
/// and each pin wires its own `accounts/fireworks/routers/` form —
/// neither id is rewritten to the other, so the accountability for
/// which router a pass key covers stays visible at both the offer and
/// the wire.
#[tokio::test]
async fn firepass_k3_fast_k2p6_divergence_is_preserved() {
    let config = Config::parse_validated(&firepass_config("http://127.0.0.1:1/v1")).expect("valid");
    let (provider, _store) = enrolled_firepass_provider(&config);
    let (provider, catalogue) = catalog_on_thread(provider);
    let models = catalogue.expect("the static router catalogue answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        [FIREPASS_MODEL, "kimi-k3-fast"],
        "both recorded router identities are offered as distinct entries"
    );
    for model in &models {
        assert_eq!(
            model.price,
            ModelPrice::Unknown,
            "{} carries no recorded firepass price — a borrowed fireworks figure would red here",
            model.id
        );
        assert!(
            !model.vision,
            "{} carries no recorded firepass vision mark",
            model.id
        );
        assert!(
            !model.reasoning,
            "{} carries no recorded firepass reasoning mark",
            model.id
        );
    }

    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "router identity",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    for (pinned, expected) in [
        (
            "kimi-k2.6-turbo",
            "accounts/fireworks/routers/kimi-k2p6-turbo",
        ),
        ("kimi-k3-fast", "accounts/fireworks/routers/kimi-k3-fast"),
        (
            "accounts/fireworks/routers/kimi-k2p6-turbo",
            "accounts/fireworks/routers/kimi-k2p6-turbo",
        ),
    ] {
        let config =
            Config::parse_validated(&firepass_config(&base).replace(FIREPASS_MODEL, pinned))
                .expect("valid");
        let (broker, manifest) = prepared_with(
            enrolled_firepass_provider(&config),
            &config,
            "/world/firepass",
            "goal: router identity",
        );
        let (broker, outcome) = dispatch(broker, "/world/firepass", manifest);
        outcome.expect("the router pin dispatches");
        drop_blocking(broker);

        let requests = server.received_requests().await.expect("recorded");
        let body: Value =
            serde_json::from_slice(&requests[requests.len() - 1].body).expect("json body");
        assert_eq!(
            body["model"],
            json!(expected),
            "a {pinned} pin wires its own router form — the ids never fold onto one another"
        );
    }
}

/// A `/models` HTTP 200 is never entitlement for `firepass`: the
/// recorded `fpk_…` key does not authorize the listing, so the
/// catalogue answers the static router list with no wire leg at all,
/// and a fixture listing naming an unrelated roster neither joins the
/// offer set nor stands in for the credential — without enrolled
/// material the send denies `CredentialAbsent` typed before any leg.
#[tokio::test]
async fn firepass_models_listing_is_not_entitlement() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "accounts/fireworks/models/kimi-k3"}),
            json!({"id": "listed-entitlement-claim"}),
        ],
    )
    .await;
    let config = Config::parse_validated(&firepass_config(&server_uri_v1(&server))).expect("valid");

    let (provider, _store) = enrolled_firepass_provider(&config);
    let (provider, catalogue) = catalog_on_thread(provider);
    let models = catalogue.expect("the static router catalogue answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        [FIREPASS_MODEL, "kimi-k3-fast"],
        "the static router list alone is the offer — the 200 listing adds nothing"
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "no discovery leg exists: the listing was never consulted"
    );

    let provider = provider_result(
        config.clone(),
        "firepass".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("binding resolves; the store is read at send");
    let (provider, denied) = send_on_thread(provider, prepared_manifest(&config));
    assert!(
        matches!(denied, Err(ProviderError::CredentialAbsent { .. })),
        "a 200 catalogue never stands in for the pass key: {denied:?}"
    );
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the credential denial lands before any leg"
    );
}

// ----- TP-PROVIDER-RECOVERY::firepass -----------------------------------------

/// A typed denial is recoverable through the same seam: material
/// outside the pass-key grammar denies the first send, enrolling the
/// recorded `fpk_` key at the scope admits the retry — no state
/// wedged, no plaintext path taken.
#[tokio::test]
async fn firepass_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config = Config::parse_validated(&firepass_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(FIREPASS_REF, FIREWORKS_KEY)],
    ));
    let provider = provider_result(config.clone(), "firepass".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialMalformed { .. })
    ));

    store.enroll(FIREPASS_REF, FIREPASS_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the recorded pass key admits the retry");
    assert_eq!(reply.text, "recovered");
    drop_blocking(provider);
}

/// The legs matrix enforces the recorded expected set for `firepass`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside
/// this run, and INSTALLED reports NOT_RUN — an omitted leg fails the
/// suite rather than silently absenting.
#[tokio::test]
async fn firepass_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&firepass_config(&server_uri_v1(&server))).expect("valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the static router list is the whole offer, and no
    // entry borrows a price or capability mark the class never
    // records — a borrowed fireworks figure fails the row.
    let (provider, _store) = enrolled_firepass_provider(&config);
    let (provider, listed) = catalog_on_thread(provider);
    let listed = listed.expect("catalog answers");
    reported.insert(
        "CATALOG",
        if model_ids(&listed) == [FIREPASS_MODEL, "kimi-k3-fast"]
            && listed.iter().all(|model| {
                model.price == ModelPrice::Unknown && !model.vision && !model.reasoning
            })
        {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: a key outside the recorded pass-key grammar denies typed
    // before any leg.
    let provider = provider_result(
        config.clone(),
        "firepass".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(FIREPASS_REF, FIREWORKS_KEY)],
        )),
    )
    .expect("binding resolves");
    let (provider, denied) = send_on_thread(provider, prepared_manifest(&config));
    reported.insert(
        "AUTH",
        if matches!(denied, Err(ProviderError::CredentialMalformed { .. })) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // WIRE: the full broker dispatch returns the verified outcome.
    let (broker, manifest) = {
        let (provider, _store) = enrolled_firepass_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/firepass", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
    let (broker, outcome) = dispatch(broker, "/world/firepass", manifest);
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
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(FIREPASS_REF, FIREWORKS_KEY)],
    ));
    let provider = provider_result(config.clone(), "firepass".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialMalformed { .. }));
    store.enroll(FIREPASS_REF, FIREPASS_KEY.as_bytes());
    let (provider, retried) = send_on_thread(provider, manifest);
    let recovered = matches!(&retried, Ok(reply) if reply.text == "matrix");
    reported.insert(
        "RECOVERY",
        if denied_ok && recovered {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // The row restates the `#[ignore]`d `provider_installed_firepass`
    // case's status, as its sibling matrices do: the ignored count is
    // the explicit NOT_RUN signal, and this literal keeps that row
    // visible inside the executed set.
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

// ----- TP-PROVIDER-INSTALLED::firepass ----------------------------------------

/// TP-PROVIDER-INSTALLED::firepass = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::firepass = NOT_RUN"]
fn provider_installed_firepass() {}

// ----- gmi-cloud ---------------------------------------------------------------

// The `gmi-cloud` connection's proof legs (HZN-008 class A): the shared
// Chat Completions adapter serves the literal id — no copied codec —
// under its own recorded predicates (DEC-025 row: `Rivect/key` →
// `api.gmi-serving.com/v1`). The configured `endpoint` carries the API
// base verbatim — an empty one resolves the recorded
// `api.gmi-serving.com/v1` default — and a configured `region` is
// denied: the contract names none. The catalogue is the configured
// base's own authoritative `/models` listing, and every listing row's
// bare id is offered exactly as served: no vendor namespace is added,
// stripped or otherwise rewritten. The credential is the recorded plain
// bearer. The class records no per-model price, so an offered id keeps
// `ModelPrice::Unknown` — no figure is borrowed from another
// connection's price table.

/// The scoped credential ref the `gmi-cloud` connection binds.
const GMI_REF: &str = "keyring:rivect-test/gmi-cloud";

/// Fixture gmi-cloud key material — never a real credential, only ever
/// sent to localhost.
const GMI_KEY: &str = "fixture-gmi-cloud-key";

/// The pinned model id the fixed-pin legs carry.
const GMI_MODEL: &str = "fixture-gmi-chat";

/// One configured `gmi-cloud` connection pointing at the fixture peer:
/// the api_key auth class resolves a scoped `SecretRef` (DEC-011), the
/// dialect comes from the literal connection id (DEC-007), and the
/// endpoint carries the API base verbatim.
fn gmi_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.gmi-cloud]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{GMI_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"gmi-cloud\", model_id = \"{GMI_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn gmi_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(GMI_REF, material)],
    ));
    let provider = provider_result(config.clone(), "gmi-cloud".to_string(), store.clone())
        .expect("the shared adapter builds for the gmi-cloud id");
    (provider, store)
}

/// The `gmi-cloud` provider over the recorded enrolled credential.
fn enrolled_gmi_provider(config: &Config) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    gmi_provider(config, GMI_KEY)
}

// ----- TP-PROVIDER-WIRE::gmi-cloud ---------------------------------------------

/// A configured `gmi-cloud` connection returns a verified model
/// outcome through the standard Broker: prepare admits the api_key pin
/// under DEC-011, the plain bearer credential rides the
/// `Authorization` header — no scope member, no body copy — and the
/// shared adapter posts exactly the frozen manifest as a
/// `chat/completions` request — the pinned bare id verbatim, system+user
/// messages, `stream` with `stream_options.include_usage` and the
/// pinned effort as `reasoning_effort` verbatim — the SSE stream
/// validates its finish_reason/`[DONE]` terminal, and the one physical
/// send is charged once with the provider's reported usage.
#[tokio::test]
async fn gmi_cloud_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified gmi outcome",
            Some(json!({"prompt_tokens": 6, "completion_tokens": 3, "total_tokens": 9})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&gmi_config(&base)).expect("valid");
    let (provider, _store) = enrolled_gmi_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/gmi", "goal: prove the wire")
        .expect("the gmi-cloud pin passes DEC-011 eligibility");

    let (broker, outcome) = dispatch(broker, "/world/gmi", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified gmi outcome");
    assert!(reply.tool_calls.is_empty());

    // The wire request is exactly the frozen manifest — and nothing
    // the manifest does not carry; a fixed pin opens no catalogue leg.
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {GMI_KEY}"),
        "the plain key material bears the wire verbatim"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(GMI_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"],
        json!(GMI_MODEL),
        "the bare id rides the wire exactly as pinned"
    );
    assert_eq!(
        body["messages"],
        json!([
            {"role": "system", "content": manifest.instructions},
            {"role": "user", "content": manifest.inputs},
        ]),
        "the frozen instructions and inputs ride the messages verbatim"
    );
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["stream_options"],
        json!({"include_usage": true}),
        "the recorded usage request rides the stream options"
    );
    assert_eq!(
        body["reasoning_effort"],
        json!("medium"),
        "the pinned effort rides the recorded reasoning_effort surface"
    );

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "gmi-cloud");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 6,
            completion_tokens: 3,
            total_tokens: 9,
        }
    );
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay = broker.dispatch(&mut rivect::model::NullLedger, "/world/gmi", &manifest);
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

/// Hostile stream input is never a false success: a stream ended mid
/// `tool_calls` fragment — a partial call that never executes — and a
/// finish_reason the dialect cannot classify are both the unknown
/// terminal, and a rejected send charges nothing.
#[tokio::test]
async fn gmi_cloud_adverse_wire_input_never_reports_success() {
    // a complete content delta plus an unterminated tool-call
    // fragment, then EOF — no finish_reason and no [DONE]
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&delta_chunk(json!({
                "tool_calls": [{
                    "index": 0,
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": "{\"path\":"},
                }],
            }))),
        ),
    )
    .await;
    let config = Config::parse_validated(&gmi_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_gmi_provider(&config),
        &config,
        "/world/gmi",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/gmi", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "EOF mid tool call is the unknown terminal — never a usable call: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);

    // a finish_reason the dialect cannot classify is unknown, never
    // success
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&finish_chunk("mystery")),
            DONE_BLOCK
        ),
    )
    .await;
    let config = Config::parse_validated(&gmi_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_gmi_provider(&config),
        &config,
        "/world/gmi",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/gmi", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "an unclassifiable terminal is the unknown terminal: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);
}

// ----- TP-PROVIDER-CATALOG::gmi-cloud ------------------------------------------

/// The `gmi-cloud` catalogue is the configured base's own authoritative
/// `/models` listing (HZN-008 class A): the lookup resolves the plain
/// bearer credential on the one `GET {endpoint}/models` leg, every
/// `id` with a non-whitespace body is offered exactly as served — a
/// bare id gains no vendor namespace, a namespaced id keeps its own
/// form, and the listing's attached metadata is never adopted —
/// while an empty, absent or whitespace-only id can never name a
/// model.
#[tokio::test]
async fn gmi_bare_id_rows_are_offered_verbatim() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": GMI_MODEL}),
            json!({"id": "fixture-org/gmi-chat-large"}),
            // the listing can attach per-model metadata — none of it
            // is catalog surface this class records
            json!({"id": "gmi-priced-chat", "metadata": {"context_length": 131072}}),
            // a flat aiand-shaped row: the recorded `IdsOnly` transform
            // reads no member, so this entry lands the default surface.
            // An `Aiand` swap would adopt every member here and red the
            // default-surface assertions below.
            json!({
                "id": "gmi-flat-aiand-shape",
                "currency": "usd",
                "input_per_1m": 0.3,
                "output_per_1m": 0.5,
                "capabilities": ["reasoning", "vision"],
                "context_window": 131072,
            }),
            // only a non-whitespace id offers — an empty, absent or
            // whitespace-only id can never name a model
            json!({"id": ""}),
            json!({"id": "  "}),
            json!({"metadata": {}}),
        ],
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&gmi_config(&base)).expect("valid");
    let (provider, _store) = enrolled_gmi_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the authoritative listing answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        vec![
            GMI_MODEL,
            "fixture-org/gmi-chat-large",
            "gmi-flat-aiand-shape",
            "gmi-priced-chat",
        ],
        "every usable listing id is offered exactly as served, sorted — never namespaced or rewritten"
    );
    // The flat aiand-shaped row lands the default surface: `IdsOnly`
    // reads no currency, price, capability or window member, so an
    // `Aiand` swap reds on the first line here.
    let flat = models
        .iter()
        .find(|model| model.id == "gmi-flat-aiand-shape")
        .expect("the flat aiand-shaped row is offered");
    assert_eq!(
        flat.price,
        ModelPrice::Unknown,
        "a listing-stated figure is never adopted — the class records no price"
    );
    assert!(!flat.vision, "no image-input mark is read from the listing");
    assert!(
        !flat.reasoning,
        "no reasoning mark is read from the listing"
    );
    assert!(
        flat.efforts.is_empty(),
        "no effort ladder is read from the listing"
    );
    assert!(
        flat.effort_default.is_none(),
        "no default effort is read from the listing"
    );
    assert_eq!(
        flat.context_window, None,
        "no context window is read from the listing"
    );
    for model in &models {
        assert_eq!(
            model,
            &CatalogModel {
                id: model.id.clone(),
                ..CatalogModel::default()
            },
            "{}: the listing states the id alone",
            model.id
        );
    }
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the listing leg is the only egress");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {GMI_KEY}"),
        "the plain key bears the discovery leg"
    );
}

/// A `gmi-cloud` offer never borrows a price (DEC-025 row, AC-040e):
/// the listing states ids only, so every offered id keeps
/// `ModelPrice::Unknown` and carries no vision or reasoning mark — a
/// listed id a sibling class's recorded table prices (`deepseek-v4-pro`,
/// `kimi-k2.7-code`, `glm-5.1-fast`) included — and neither the seed
/// floor nor the Fast ids of another connection join this offer set.
#[tokio::test]
async fn gmi_unknown_price_stays_unknown_never_borrowed() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            // ids sibling classes' recorded price rows state figures for
            json!({"id": "deepseek-v4-pro"}),
            json!({"id": "kimi-k2.7-code"}),
            json!({"id": "glm-5.1-fast"}),
            json!({"id": "fixture-unrecorded-model"}),
        ],
    )
    .await;
    let config = Config::parse_validated(&gmi_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_gmi_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the listing answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        vec![
            "deepseek-v4-pro",
            "fixture-unrecorded-model",
            "glm-5.1-fast",
            "kimi-k2.7-code",
        ],
        "the listing's ids are the whole offer — no sibling seed id joins it"
    );
    for model in &models {
        assert_eq!(
            model,
            &CatalogModel {
                id: model.id.clone(),
                ..CatalogModel::default()
            },
            "{} keeps the unknown price and no capability mark — a sibling table's figure would red here",
            model.id
        );
    }
}

/// An empty configured endpoint resolves the recorded default —
/// the `config?.baseUrl ?? defaultBaseUrl` absent arm our required
/// `endpoint` field expresses as the empty string, and whitespace-only
/// shares the arm under the recorded trim. Offline pin: the adapter's
/// `Debug` surface reports the resolved endpoint, so the arm is proved
/// without one byte toward `api.gmi-serving.com`.
#[test]
fn gmi_cloud_empty_endpoint_resolves_the_recorded_default() {
    for endpoint in ["", "   "] {
        let config =
            Config::parse_validated(&gmi_config(endpoint)).expect("an empty endpoint is valid");
        let (provider, _store) = enrolled_gmi_provider(&config);
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"https://api.gmi-serving.com/v1\""),
            "endpoint {endpoint:?} resolved to the recorded default: {debug}"
        );
        drop_blocking(provider);
    }
}

/// The auto-pick catalogue leg rides the authoritative listing: the
/// dispatch narrows the pool to the `gmi-cloud` member, the shared
/// adapter resolves the deterministic sorted-first listed id, and the
/// send carries that bare id verbatim — the listing's own row, never a
/// namespaced or otherwise rewritten form.
#[tokio::test]
async fn gmi_cloud_auto_pick_resolves_through_the_authoritative_catalog() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "fixture-zz-late"}),
            json!({"id": "fixture-aa-first"}),
        ],
    )
    .await;
    mount_chat(
        &server,
        completed_stream(
            "auto picked",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.gmi-cloud]\nkind = \"api_key\"\nendpoint = \"{base}\"\ncredential_ref = \"{GMI_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\", pool = [\"gmi-cloud\"] }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let (provider, _store) = enrolled_gmi_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/gmi", "goal: auto pick")
        .expect("the single-member pool pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/gmi", manifest);
    let reply = outcome.expect("the auto pick dispatches");
    assert_eq!(reply.text, "auto picked");
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "the catalogue leg and the send are the only egress"
    );
    let body: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert_eq!(
        body["model"],
        json!("fixture-aa-first"),
        "the sorted-first listed id names the wire model verbatim"
    );
}

// ----- TP-PROVIDER-AUTH::gmi-cloud ---------------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `gmi-cloud`, through the same shared construction its siblings use:
/// a configured `region` — the recorded contract names none — denies
/// `RegionMismatch` with the connection context, a profile-bound ref
/// whose scope disagrees with the binding denies
/// `CredentialProfileMismatch`, and a refused bearer lands the typed
/// transport denial carrying the peer's status alone — no error, nor
/// the offered credential material or the peer's body, reaches Display
/// or Debug.
#[tokio::test]
async fn gmi_cloud_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &gmi_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "gmi-cloud".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, GMI_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "gmi-cloud");
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, GMI_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.gmi-cloud]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"gmi-cloud\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "gmi-cloud".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, GMI_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, GMI_KEY.as_bytes());

    // a refused bearer is a typed transport denial — the wire never
    // coerces a wrong credential into success, the peer's body never
    // enters the error, and the request carried the bearer
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&gmi_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_gmi_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused bearer is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused bearer is transport: {err}")
    };
    assert_eq!(connection, "gmi-cloud");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, GMI_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {GMI_KEY}"),
        "the admitted bearer reached the wire — the denial is the peer's status"
    );
}

/// A `/models` HTTP 200 is never entitlement (INV-010) for `gmi-cloud`:
/// with the key enrolled the fixed pin still rides only its request
/// leg, and a listing answering arbitrary ids neither stands in for the
/// credential nor admits the send — the unmounted `chat/completions`
/// peer answers the typed transport denial while the 200 listing is
/// never consulted.
#[tokio::test]
async fn gmi_cloud_models_http_200_is_never_entitlement() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": GMI_MODEL})]).await;
    let config = Config::parse_validated(&gmi_config(&server_uri_v1(&server))).expect("valid");
    let provider = provider_result(
        config.clone(),
        "gmi-cloud".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[(GMI_REF, GMI_KEY)])),
    )
    .expect("the enrolled binding resolves");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a 200 catalogue never releases the pin");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the unmounted request leg is the typed transport denial: {err:?}");
    };
    assert_eq!(connection, "gmi-cloud");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 404 },
        "the request leg answers the peer's status, never a listing-granted success: {cause}"
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "only the request leg runs — the 200 listing releases no entitlement"
    );
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
}

// ----- TP-PROVIDER-RECOVERY::gmi-cloud -----------------------------------------

/// A typed denial is recoverable through the same seam: the absent
/// credential denies the first send, enrolling the material at the
/// scope admits the retry — no state wedged, no plaintext path taken.
#[tokio::test]
async fn gmi_cloud_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config = Config::parse_validated(&gmi_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "gmi-cloud".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialAbsent { .. })
    ));

    store.enroll(GMI_REF, GMI_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the enrolled credential admits the retry");
    assert_eq!(reply.text, "recovered");
    drop_blocking(provider);
}

/// The legs matrix enforces the recorded expected set for `gmi-cloud`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside this
/// run, and INSTALLED reports NOT_RUN — an omitted leg fails the suite
/// rather than silently absenting.
#[tokio::test]
async fn gmi_cloud_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": GMI_MODEL})]).await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&gmi_config(&server_uri_v1(&server))).expect("valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the listing's bare id is the whole offer, and no entry
    // borrows a price or capability mark the class never records.
    let (provider, _store) = enrolled_gmi_provider(&config);
    let (provider, listed) = catalog_on_thread(provider);
    let listed = listed.expect("catalog answers");
    reported.insert(
        "CATALOG",
        if model_ids(&listed) == [GMI_MODEL]
            && listed.iter().all(|model| {
                model.price == ModelPrice::Unknown && !model.vision && !model.reasoning
            })
        {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: an absent credential denies typed before any leg.
    let provider = provider_result(
        config.clone(),
        "gmi-cloud".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("binding resolves");
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
    let (broker, manifest) = {
        let (provider, _store) = enrolled_gmi_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/gmi", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
    let (broker, outcome) = dispatch(broker, "/world/gmi", manifest);
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
    let provider = provider_result(config.clone(), "gmi-cloud".to_string(), empty.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(GMI_REF, GMI_KEY.as_bytes());
    let (provider, retried) = send_on_thread(provider, manifest);
    let recovered = matches!(&retried, Ok(reply) if reply.text == "matrix");
    reported.insert(
        "RECOVERY",
        if denied_ok && recovered {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // The row restates the `#[ignore]`d `provider_installed_gmi_cloud`
    // case's status, as its sibling matrices do.
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

// ----- TP-PROVIDER-INSTALLED::gmi-cloud ----------------------------------------

/// TP-PROVIDER-INSTALLED::gmi-cloud = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::gmi-cloud = NOT_RUN"]
fn provider_installed_gmi_cloud() {}

// ----- groq --------------------------------------------------------------------

// The `groq` connection's proof legs (HZN-008 class A): the shared Chat
// Completions adapter serves the literal id — no copied codec — under
// its own recorded predicates (DEC-025 row: `Rivect/key` →
// `api.groq.com/openai/v1`, static and reference model data plus a
// non-authoritative list, unsupported parameters and per-model effort).
// The configured `endpoint` carries the API base verbatim — an empty one
// resolves the recorded `api.groq.com/openai/v1` default — and a
// configured `region` is denied: the contract names none. The catalogue
// merges the recorded static and benchmark floor over the provider's
// non-authoritative `/models` list: a listed foreign id is offered with
// no recorded surface, a listed recorded id keeps the floor's surface,
// and a `/models` HTTP 200 never proves entitlement. The auth class is
// the recorded env/credential chain: an `env:`-spelled reference is
// refused at ingress, and the stored binding resolves through the scoped
// `SecretRef` seam under DEC-013 profile precedence. A pinned
// `reasoning_effort` a model's recorded ladder does not carry is a
// rejected parameter — a typed denial before any wire leg, never a
// silently dropped body field.

/// The scoped credential ref the `groq` connection binds.
const GROQ_REF: &str = "keyring:rivect-test/groq";

/// Fixture groq key material — never a real credential, only ever sent
/// to localhost.
const GROQ_KEY: &str = "fixture-groq-key";

/// The pinned model id the fixed-pin legs carry — a recorded reasoning
/// build carrying the `low`/`medium`/`high` effort ladder.
const GROQ_MODEL: &str = "openai/gpt-oss-120b";

/// Recorded reasoning builds that discriminate the per-model effort
/// predicate: the systems ladder carries `xhigh`, the R1 distill carries
/// `high` alone.
const GROQ_COMPOUND: &str = "groq/compound";
const GROQ_R1: &str = "deepseek-r1-distill-llama-70b";

/// A recorded non-reasoning build: no effort ladder.
const GROQ_PLAIN: &str = "gemma2-9b-it";

/// One configured `groq` connection pointing at the fixture peer: the
/// api_key auth class resolves a scoped `SecretRef` (DEC-011), the
/// dialect comes from the literal connection id (DEC-007), and the
/// endpoint carries the API base verbatim.
fn groq_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.groq]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{GROQ_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"groq\", model_id = \"{GROQ_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// A `groq` config pinning a specific model and effort.
fn groq_pin_config(endpoint: &str, model: &str, effort: &str) -> String {
    groq_config(endpoint)
        .replace(GROQ_MODEL, model)
        .replace("value = \"medium\"", &format!("value = \"{effort}\""))
}

fn groq_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(GROQ_REF, material)],
    ));
    let provider = provider_result(config.clone(), "groq".to_string(), store.clone())
        .expect("the shared adapter builds for the groq id");
    (provider, store)
}

/// The `groq` provider over the recorded enrolled credential.
fn enrolled_groq_provider(config: &Config) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    groq_provider(config, GROQ_KEY)
}

// ----- TP-PROVIDER-WIRE::groq --------------------------------------------------

/// A configured `groq` connection returns a verified model outcome
/// through the standard Broker: prepare admits the api_key pin under
/// DEC-011, the plain bearer credential rides the `Authorization`
/// header — no scope member, no body copy — and the shared adapter posts
/// exactly the frozen manifest as a `chat/completions` request — the
/// pinned id verbatim, system+user messages, `stream` with
/// `stream_options.include_usage` and the pinned effort as
/// `reasoning_effort` verbatim — the SSE stream validates its
/// finish_reason/`[DONE]` terminal, the one physical send is charged
/// once with the provider's reported usage, and the spent attempt never
/// re-sends.
#[tokio::test]
async fn groq_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified groq outcome",
            Some(json!({"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&groq_config(&base)).expect("valid");
    let (provider, _store) = enrolled_groq_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/groq", "goal: prove the wire")
        .expect("the groq pin passes DEC-011 eligibility");

    let (broker, outcome) = dispatch(broker, "/world/groq", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified groq outcome");
    assert!(reply.tool_calls.is_empty());

    // The wire request is exactly the frozen manifest — and nothing the
    // manifest does not carry; a fixed pin opens no catalogue leg.
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {GROQ_KEY}"),
        "the plain key material bears the wire verbatim"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(GROQ_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"],
        json!(GROQ_MODEL),
        "the recorded id rides the wire verbatim"
    );
    assert_eq!(
        body["messages"],
        json!([
            {"role": "system", "content": manifest.instructions},
            {"role": "user", "content": manifest.inputs},
        ]),
        "the frozen instructions and inputs ride the messages verbatim"
    );
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["stream_options"],
        json!({"include_usage": true}),
        "the recorded usage request rides the stream options"
    );
    assert_eq!(
        body["reasoning_effort"],
        json!("medium"),
        "the pinned effort rides the recorded reasoning_effort surface"
    );

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "groq");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 7,
            completion_tokens: 3,
            total_tokens: 10,
        }
    );
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay = broker.dispatch(&mut rivect::model::NullLedger, "/world/groq", &manifest);
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

/// Hostile stream input is never a false success for `groq`: a stream
/// ended mid `tool_calls` fragment — a partial call that never executes
/// — and a finish_reason the dialect cannot classify are both the
/// unknown terminal, and a rejected send charges nothing.
#[tokio::test]
async fn groq_adverse_wire_input_never_reports_success() {
    // a complete content delta plus an unterminated tool-call fragment,
    // then EOF — no finish_reason and no [DONE]
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&delta_chunk(json!({
                "tool_calls": [{
                    "index": 0,
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": "{\"path\":"},
                }],
            }))),
        ),
    )
    .await;
    let config = Config::parse_validated(&groq_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_groq_provider(&config),
        &config,
        "/world/groq",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/groq", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "EOF mid tool call is the unknown terminal — never a usable call: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);

    // a finish_reason the dialect cannot classify is unknown, never
    // success
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&finish_chunk("mystery")),
            DONE_BLOCK
        ),
    )
    .await;
    let config = Config::parse_validated(&groq_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_groq_provider(&config),
        &config,
        "/world/groq",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/groq", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "an unclassifiable terminal is the unknown terminal: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);
}

/// A parameter the `groq` class records as rejected is denied, never
/// dropped: a pinned `reasoning_effort` the pinned model's recorded
/// ladder does not carry — a non-reasoning build, or a level outside the
/// build's ladder — yields the typed `UnsupportedParameter` denial
/// naming the connection, parameter and model before any wire leg, so no
/// request is ever posted with a silently stripped body. The admitted
/// control posts the parameter verbatim, proving the gate denies rather
/// than removes.
#[tokio::test]
async fn groq_unsupported_parameters_are_denied_not_dropped() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "admitted",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);

    for (model, effort) in [(GROQ_PLAIN, "medium"), (GROQ_MODEL, "xhigh")] {
        let config =
            Config::parse_validated(&groq_pin_config(&base, model, effort)).expect("valid");
        let (provider, _store) = enrolled_groq_provider(&config);
        let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
        let err = outcome.expect_err("the unrecorded level is a rejected parameter");
        match &err {
            ProviderError::UnsupportedParameter {
                connection,
                parameter,
                model: named,
            } => {
                assert_eq!(connection, "groq");
                assert_eq!(*parameter, "reasoning_effort");
                assert_eq!(named, model);
            }
            other => panic!("the rejection is typed and names the parameter: {other:?}"),
        }
        assert_no_secret_or_body(&err, GROQ_KEY.as_bytes());
        drop_blocking(provider);
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "a rejected parameter never reaches the wire — no stripped body is posted"
    );

    // the admitted pin still carries the parameter: the gate denies, it
    // does not drop
    let config = Config::parse_validated(&groq_config(&base)).expect("valid");
    let (provider, _store) = enrolled_groq_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    outcome.expect("the recorded level is admitted");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "only the admitted send reached the wire");
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["reasoning_effort"],
        json!("medium"),
        "the admitted parameter rides the body verbatim"
    );
}

// ----- TP-PROVIDER-CATALOG::groq -----------------------------------------------

/// The pinned `groq` rows as an independent expected snapshot: id,
/// image-input mark, recorded effort ladder, and USD input/output per
/// 1M tokens.
fn groq_expected_rows() -> Vec<(&'static str, bool, Vec<EffortLevel>, f64, f64)> {
    vec![
        (
            "deepseek-r1-distill-llama-70b",
            false,
            vec![EffortLevel::High],
            0.75,
            0.99,
        ),
        ("gemma2-9b-it", false, vec![], 0.2, 0.2),
        (
            "groq/compound",
            false,
            vec![
                EffortLevel::Minimal,
                EffortLevel::Low,
                EffortLevel::Medium,
                EffortLevel::High,
                EffortLevel::Xhigh,
            ],
            0.0,
            0.0,
        ),
        (
            "groq/compound-mini",
            false,
            vec![
                EffortLevel::Minimal,
                EffortLevel::Low,
                EffortLevel::Medium,
                EffortLevel::High,
                EffortLevel::Xhigh,
            ],
            0.0,
            0.0,
        ),
        ("llama-3.1-8b-instant", false, vec![], 0.05, 0.08),
        ("llama-3.3-70b-versatile", false, vec![], 0.59, 0.79),
        ("llama3-70b-8192", false, vec![], 0.59, 0.79),
        ("llama3-8b-8192", false, vec![], 0.05, 0.08),
        (
            "meta-llama/llama-4-maverick-17b-128e-instruct",
            true,
            vec![],
            0.2,
            0.6,
        ),
        (
            "meta-llama/llama-4-scout-17b-16e-instruct",
            true,
            vec![],
            0.11,
            0.34,
        ),
        ("mistral-saba-24b", false, vec![], 0.79, 0.79),
        ("moonshotai/kimi-k2-instruct", false, vec![], 1.0, 3.0),
        ("moonshotai/kimi-k2-instruct-0905", false, vec![], 1.0, 3.0),
        (
            "openai/gpt-oss-120b",
            false,
            vec![EffortLevel::Low, EffortLevel::Medium, EffortLevel::High],
            0.15,
            0.6,
        ),
        (
            "openai/gpt-oss-20b",
            false,
            vec![EffortLevel::Low, EffortLevel::Medium, EffortLevel::High],
            0.075,
            0.3,
        ),
        (
            "openai/gpt-oss-safeguard-20b",
            false,
            vec![EffortLevel::Low, EffortLevel::Medium, EffortLevel::High],
            0.075,
            0.3,
        ),
        (
            "qwen-qwq-32b",
            false,
            vec![
                EffortLevel::Minimal,
                EffortLevel::Low,
                EffortLevel::Medium,
                EffortLevel::High,
            ],
            0.29,
            0.39,
        ),
        ("qwen/qwen3-32b", false, vec![], 0.29, 0.59),
        (
            "qwen/qwen3.6-27b",
            true,
            vec![
                EffortLevel::Minimal,
                EffortLevel::Low,
                EffortLevel::Medium,
                EffortLevel::High,
            ],
            0.6,
            3.0,
        ),
        (
            "qwen/qwen3.8-27b",
            true,
            vec![
                EffortLevel::Minimal,
                EffortLevel::Low,
                EffortLevel::Medium,
                EffortLevel::High,
            ],
            0.8,
            4.0,
        ),
    ]
}

/// The `groq` catalogue merges the recorded static and benchmark floor
/// over the provider's non-authoritative `/models` list (HZN-008 class
/// A): the lookup resolves the plain bearer on one `GET {endpoint}/models`
/// leg, a listed foreign id is offered exactly as served with no
/// recorded surface — never a borrowed price — a listed recorded id
/// does not duplicate its seeded row, and every seeded row keeps its
/// recorded reasoning mark, effort ladder, vision mark and USD price.
#[tokio::test]
async fn groq_non_authoritative_listing_merges_offers_without_entitlement() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "foreign-listed-chat"}),
            // a listed id the static floor already carries
            json!({"id": GROQ_MODEL}),
            // an empty id never names a model
            json!({"id": ""}),
        ],
    )
    .await;
    let config = Config::parse_validated(&groq_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_groq_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the catalogue answers");
    drop_blocking(provider);

    let expected = groq_expected_rows();
    assert_eq!(
        models.len(),
        expected.len() + 1,
        "the static floor unions the foreign listed id: {:?}",
        model_ids(&models)
    );
    for (id, vision, efforts, input_per_1m, output_per_1m) in &expected {
        let model = models
            .iter()
            .find(|model| model.id == *id)
            .unwrap_or_else(|| panic!("{id} is offered"));
        assert_eq!(model.vision, *vision, "{id}: image-input mark");
        assert_eq!(model.efforts, *efforts, "{id}: recorded effort ladder");
        assert_eq!(
            model.reasoning,
            !efforts.is_empty(),
            "{id}: reasoning follows the recorded ladder"
        );
        assert_eq!(
            model.price,
            ModelPrice::Usd {
                input_per_1m: *input_per_1m,
                output_per_1m: *output_per_1m,
            },
            "{id}: recorded USD price"
        );
        assert_eq!(model.context_window, None, "{id}: no window is carried");
        assert_eq!(
            model.effort_default, None,
            "{id}: no default effort is carried"
        );
    }
    assert_eq!(
        models.iter().filter(|model| model.id == GROQ_MODEL).count(),
        1,
        "a listed recorded id deduplicates against its seeded row"
    );

    let foreign = models
        .iter()
        .find(|model| model.id == "foreign-listed-chat")
        .expect("a listed foreign id is offered");
    assert_eq!(
        foreign,
        &CatalogModel {
            id: "foreign-listed-chat".to_string(),
            ..CatalogModel::default()
        },
        "a foreign id carries no borrowed price, effort or vision surface"
    );

    let mut sorted = model_ids(&models);
    sorted.sort_unstable();
    assert_eq!(
        model_ids(&models),
        sorted,
        "the merged offer is deterministic sorted order"
    );

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "one discovery leg — a cloud listing opens no native probe"
    );
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert!(
        !request_paths(&requests).contains(&LM_STUDIO_NATIVE_PATH),
        "the lm-studio native probe stays on its own connection"
    );
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {GROQ_KEY}"),
        "the plain key bears the discovery leg"
    );
}

/// The auto-pick leg rides the non-authoritative listing under the
/// record's auto semantic: the dispatch narrows the pool to the `groq`
/// member, the merged catalogue is sorted deterministically, and the
/// sorted-first **listed** id — a foreign id the static floor does not
/// carry — names the wire model verbatim, in the inverted order the
/// peer answered.
#[tokio::test]
async fn groq_auto_pick_resolves_through_the_non_authoritative_listing() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "zz-listed-late"}),
            json!({"id": "aaa-listed-first"}),
        ],
    )
    .await;
    mount_chat(
        &server,
        completed_stream(
            "auto picked",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.groq]\nkind = \"api_key\"\nendpoint = \"{base}\"\ncredential_ref = \"{GROQ_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\", pool = [\"groq\"] }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let (provider, _store) = enrolled_groq_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/groq", "goal: auto pick")
        .expect("the single-member pool pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/groq", manifest);
    let reply = outcome.expect("the auto pick dispatches");
    assert_eq!(reply.text, "auto picked");
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "the catalogue leg and the send are the only egress"
    );
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(requests[1].url.path(), "/v1/chat/completions");
    let body: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert_eq!(
        body["model"],
        json!("aaa-listed-first"),
        "the sorted-first listed id names the wire model verbatim"
    );
}

/// The recorded effort predicate applies per model, not per connection:
/// on the one `groq` connection, `xhigh` is admitted for the systems
/// build and denied for the `gpt-oss` build, while `high` is admitted for
/// both; the R1 distill admits `high` and denies `low`. The catalogue
/// carries the same per-model ladders.
#[tokio::test]
async fn groq_per_model_effort_predicates_apply() {
    let server = MockServer::start().await;
    mount_models(&server, vec![]).await;
    mount_chat(
        &server,
        completed_stream(
            "per model",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);

    for (model, effort, admitted) in [
        (GROQ_COMPOUND, "xhigh", true),
        (GROQ_MODEL, "xhigh", false),
        (GROQ_MODEL, "high", true),
        (GROQ_R1, "low", false),
        (GROQ_R1, "high", true),
    ] {
        let config =
            Config::parse_validated(&groq_pin_config(&base, model, effort)).expect("valid");
        let (provider, _store) = enrolled_groq_provider(&config);
        let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
        if admitted {
            outcome.expect("the recorded level is admitted");
        } else {
            assert!(
                matches!(outcome, Err(ProviderError::UnsupportedParameter { .. })),
                "a {model} pin at {effort} is outside its recorded ladder: {outcome:?}"
            );
        }
        drop_blocking(provider);
        if admitted {
            let requests = server.received_requests().await.expect("recorded");
            let body: Value =
                serde_json::from_slice(&requests[requests.len() - 1].body).expect("json body");
            assert_eq!(
                body["model"],
                json!(model),
                "the admitted pin names its own model"
            );
            assert_eq!(body["reasoning_effort"], json!(effort));
        }
    }

    let config = Config::parse_validated(&groq_config(&base)).expect("valid");
    let (provider, _store) = enrolled_groq_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the merged catalogue answers");
    drop_blocking(provider);
    let ladder = |id: &str| {
        models
            .iter()
            .find(|model| model.id == id)
            .map(|model| model.efforts.clone())
            .expect("the pinned model is offered")
    };
    assert_eq!(
        ladder(GROQ_COMPOUND),
        vec![
            EffortLevel::Minimal,
            EffortLevel::Low,
            EffortLevel::Medium,
            EffortLevel::High,
            EffortLevel::Xhigh,
        ]
    );
    assert_eq!(
        ladder(GROQ_MODEL),
        vec![EffortLevel::Low, EffortLevel::Medium, EffortLevel::High],
        "the same connection offers a different ladder per model"
    );
}

/// An auto pick that resolves the sorted-first recorded id while the
/// effort is pinned is the same per-model predicate, not a
/// connection-wide exception: the discovery leg merges the floor, the
/// deterministic pick is the R1 distill build — whose recorded ladder is
/// `high` alone — and a pinned `medium` is therefore a rejected
/// parameter, denied typed before the chat leg exists.
#[tokio::test]
async fn groq_auto_pick_with_a_pinned_effort_denies_the_short_ladder_seed() {
    let server = MockServer::start().await;
    // a listed id sorting after the seeded R1 build
    mount_models(&server, vec![json!({"id": "zz-foreign-listed"})]).await;
    mount_chat(
        &server,
        completed_stream(
            "never sent",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.groq]\nkind = \"api_key\"\nendpoint = \"{base}\"\ncredential_ref = \"{GROQ_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\", pool = [\"groq\"] }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let (provider, _store) = enrolled_groq_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("the sorted-first build does not carry the pinned level");
    match &err {
        ProviderError::UnsupportedParameter {
            connection,
            parameter,
            model,
        } => {
            assert_eq!(connection, "groq");
            assert_eq!(*parameter, "reasoning_effort");
            assert_eq!(model, GROQ_R1);
        }
        other => panic!("the auto pick denies the unrecorded level typed: {other:?}"),
    }
    assert_no_secret_or_body(&err, GROQ_KEY.as_bytes());
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "only the discovery leg runs — the denied parameter never reaches the chat leg"
    );
    assert_eq!(requests[0].url.path(), "/v1/models");
}

/// An empty configured endpoint resolves the recorded default — the
/// `config?.baseUrl ?? defaultBaseUrl` absent arm our required `endpoint`
/// field expresses as the empty string, and whitespace-only shares the
/// arm under the recorded trim. Offline pin: the adapter's `Debug`
/// surface reports the resolved endpoint, so the arm is proved without
/// one byte toward `api.groq.com`.
#[test]
fn groq_empty_endpoint_resolves_the_recorded_default() {
    for endpoint in ["", "   "] {
        let config =
            Config::parse_validated(&groq_config(endpoint)).expect("an empty endpoint is valid");
        let (provider, _store) = enrolled_groq_provider(&config);
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"https://api.groq.com/openai/v1\""),
            "endpoint {endpoint:?} resolved to the recorded default: {debug}"
        );
        drop_blocking(provider);
    }
}

// ----- TP-PROVIDER-AUTH::groq --------------------------------------------------

/// The recorded env/credential-chain auth class resolves through the
/// scoped `SecretRef` seam and never through an env spelling or a
/// plaintext fallback: an `env:GROQ_API_KEY` reference is refused at
/// config ingress with the typed store refusal that never echoes the
/// value, and on a connection that binds both the connection ref and a
/// profile, DEC-013 precedence sends the profile's scoped material —
/// the connection-scope key never bears the wire.
#[tokio::test]
async fn groq_env_chain_resolves_through_the_scoped_secret_ref_seam() {
    // the recorded env spelling is not an admitted store class
    let env_spelled = groq_config("http://127.0.0.1:1/v1").replace(
        &format!("credential_ref = \"{GROQ_REF}\""),
        "credential_ref = \"env:GROQ_API_KEY\"",
    );
    let Err(error) = Config::parse_validated(&env_spelled) else {
        panic!("an env-spelled credential reference is refused at ingress")
    };
    assert!(
        matches!(
            &error.issue,
            ConfigIssue::UnsupportedCredentialStore { store } if store.as_str() == "env"
        ),
        "the refusal names the refused store class: {error}"
    );
    assert!(
        !error.to_string().contains("env:GROQ_API_KEY"),
        "the refusal never echoes the credential value: {error}"
    );

    // a stored profile binding wins over the connection's own ref — the
    // chain resolves scoped store material, not a dummy local key
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "chained",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.groq]\nkind = \"api_key\"\nendpoint = \"{base}\"\ncredential_ref = \"keyring:rivect-test/groq-connection\"\nprofile = \"groq-chain\"\n\
         [profiles.groq-chain]\ncredential_ref = \"keyring:rivect-test/groq-chain\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"groq\", model_id = \"{GROQ_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[
            (
                "keyring:rivect-test/groq-connection",
                "fixture-connection-scope",
            ),
            ("keyring:rivect-test/groq-chain", GROQ_KEY),
        ],
    ));
    let provider = provider_result(config.clone(), "groq".to_string(), store.clone())
        .expect("the chained binding resolves");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    outcome.expect("the profile-bound credential admits the send");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {GROQ_KEY}"),
        "the profile's scoped material bears the wire"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains("fixture-connection-scope"),
        "the connection-scope material never reaches the wire"
    );
}

/// Wrong credential/profile/region never produce a false success for
/// `groq`, through the same shared construction its siblings use: a
/// configured `region` — the recorded contract names none — denies
/// `RegionMismatch` with the connection context, and a profile-bound ref
/// whose scope disagrees with the binding denies
/// `CredentialProfileMismatch`; both deny before the store is read. A
/// refused bearer lands the typed transport denial carrying the peer's
/// status alone, and on that arm — the one that resolves and sends the
/// material — neither the offered credential nor the peer's body reaches
/// Display or Debug.
#[tokio::test]
async fn groq_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — before any
    // credential resolution
    let regioned = Config::parse_validated(
        &groq_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "groq".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "groq");
    assert_eq!(region, "eu");

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.groq]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"groq\", model_id = \"{GROQ_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "groq".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));

    // a refused bearer is a typed transport denial — the wire never
    // coerces a wrong credential into success, the peer's body never
    // enters the error, and the request carried the bearer
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&groq_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_groq_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused bearer is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused bearer is transport: {err}")
    };
    assert_eq!(connection, "groq");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, GROQ_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {GROQ_KEY}"),
        "the admitted bearer reached the wire — the denial is the peer's status"
    );
}

/// A `/models` HTTP 200 contributes ids but confers no entitlement
/// (INV-010) for `groq`: the catalogue offers the listed foreign id
/// beside the recorded floor, yet with the key enrolled the fixed pin
/// still rides only its request leg — the unmounted `chat/completions`
/// peer answers the typed transport denial, so the 200 listing never
/// releases a send or a credential.
#[tokio::test]
async fn groq_models_http_200_is_never_entitlement() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![json!({"id": "listed-foreign-entitlement-claim"})],
    )
    .await;
    let config = Config::parse_validated(&groq_config(&server_uri_v1(&server))).expect("valid");

    let (provider, _store) = enrolled_groq_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the merged catalogue answers");
    drop_blocking(provider);
    assert!(
        model_ids(&models).contains(&"listed-foreign-entitlement-claim"),
        "the 200 listing contributes its id"
    );
    assert_eq!(models.len(), 21, "the listing adds ids, never surface");
    let discovery = server.received_requests().await.expect("recorded");
    assert_eq!(discovery.len(), 1, "the catalogue reads the listing once");
    assert_eq!(discovery[0].url.path(), "/v1/models");

    let (provider, _store) = enrolled_groq_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a 200 catalogue never releases the pin");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the unmounted request leg is the typed transport denial: {err:?}");
    };
    assert_eq!(connection, "groq");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 404 },
        "the request leg answers the peer's status, never a listing-granted success: {cause}"
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "the discovery leg plus the request leg — the 200 listing adds nothing"
    );
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(requests[1].url.path(), "/v1/chat/completions");
}

// ----- TP-PROVIDER-RECOVERY::groq ----------------------------------------------

/// A typed denial is recoverable through the same seam: the absent
/// credential denies the first send, enrolling the material at the
/// scope admits the retry — no state wedged, no plaintext path taken.
#[tokio::test]
async fn groq_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config = Config::parse_validated(&groq_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "groq".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialAbsent { .. })
    ));

    store.enroll(GROQ_REF, GROQ_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the enrolled credential admits the retry");
    assert_eq!(reply.text, "recovered");
    drop_blocking(provider);
}

/// The legs matrix enforces the recorded expected set for `groq`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside this
/// run, and INSTALLED reports NOT_RUN — an omitted leg fails the suite
/// rather than silently absenting.
#[tokio::test]
async fn groq_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "foreign-listed-chat"}),
            json!({"id": GROQ_MODEL}),
        ],
    )
    .await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&groq_config(&server_uri_v1(&server))).expect("valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the non-authoritative listing contributes the foreign id
    // while the recorded floor keeps its reasoning/effort surface, and
    // the one discovery leg is the only request so far.
    let (provider, _store) = enrolled_groq_provider(&config);
    let (provider, listed) = catalog_on_thread(provider);
    let listed = listed.expect("catalog answers");
    let discovery = server.received_requests().await.expect("recorded");
    reported.insert(
        "CATALOG",
        if listed.len() == 21
            && listed.iter().any(|model| model.id == "foreign-listed-chat")
            && listed
                .iter()
                .any(|model| model.id == GROQ_MODEL && model.reasoning && !model.efforts.is_empty())
            && discovery.len() == 1
            && discovery[0].url.path() == "/v1/models"
        {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: an absent credential denies typed before any leg.
    let provider = provider_result(
        config.clone(),
        "groq".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("binding resolves");
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
    let (broker, manifest) = {
        let (provider, _store) = enrolled_groq_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/groq", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
    let (broker, outcome) = dispatch(broker, "/world/groq", manifest);
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
    let provider = provider_result(config.clone(), "groq".to_string(), empty.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(GROQ_REF, GROQ_KEY.as_bytes());
    let (provider, retried) = send_on_thread(provider, manifest);
    let recovered = matches!(&retried, Ok(reply) if reply.text == "matrix");
    reported.insert(
        "RECOVERY",
        if denied_ok && recovered {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // The row restates the `#[ignore]`d `provider_installed_groq`
    // case's status, as its sibling matrices do.
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

// ----- TP-PROVIDER-INSTALLED::groq ---------------------------------------------

/// TP-PROVIDER-INSTALLED::groq = NOT_RUN: the installed-provider proof
/// is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::groq = NOT_RUN"]
fn provider_installed_groq() {}

// ----- huggingface -------------------------------------------------------------

// The `huggingface` connection's proof legs (HZN-008 class A): the
// shared Chat Completions adapter serves the literal id — no copied
// codec — under its own recorded predicates (DEC-025 row: a
// fine-grained model-request token → `router.huggingface.co/v1`,
// `/models` listing). The configured `endpoint` carries the API base
// verbatim — an empty one resolves the recorded
// `router.huggingface.co/v1` default — and a configured `region` is
// denied: the contract names none. The recorded T1 static-bearer-chat
// cell makes the bundled `huggingface` rows the model universe and the
// key-gated `/models` answer a non-authoritative supplement: the static
// floor offers every bundled id even when the listing omits it, and the
// floor's reference descriptors (cost/vision/context) stay uncarried —
// this class offers ids only. Listed ids ride the catalogue and the
// wire verbatim, the `provider/model` routing suffix included: the
// adapter never strips a namespace, folds a suffix or re-prefixes one.
// The credential is the recorded fine-grained model-request token; its
// `hf_…` grammar is the account/org billing form, so material of
// another class — a provider-signed key that would bill at the provider
// (BYOK), a structured blob — denies typed before any wire leg rather
// than being forwarded under an inferred billing mode.

/// The scoped credential ref the `huggingface` connection binds.
const HUGGINGFACE_REF: &str = "keyring:rivect-test/huggingface";

/// Fixture fine-grained model-request token — never a real credential,
/// only ever sent to localhost.
const HUGGINGFACE_KEY: &str = "hf_fixture-huggingface-model-request-token";

/// Provider-signed material of another billing class: a BYOK key would
/// bill the request at the provider, not through the token's account or
/// org.
const HUGGINGFACE_BYOK_KEY: &str = "sk-fixture-provider-issued-key";

/// The pinned namespaced model id the fixed-pin legs carry.
const HUGGINGFACE_MODEL: &str = "Qwen/Qwen3-235B-A22B-Thinking-2507";

/// A namespaced id carrying the recorded `:provider` routing suffix —
/// the form the catalogue and the wire must carry unchanged.
const HUGGINGFACE_ROUTED: &str = "deepseek-ai/DeepSeek-V3.1:novita";

/// One configured `huggingface` connection pointing at the fixture
/// peer: the api_key auth class resolves a scoped `SecretRef`
/// (DEC-011), the dialect comes from the literal connection id
/// (DEC-007), and the endpoint carries the API base verbatim.
fn huggingface_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.huggingface]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{HUGGINGFACE_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"huggingface\", model_id = \"{HUGGINGFACE_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn huggingface_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(HUGGINGFACE_REF, material)],
    ));
    let provider = provider_result(config.clone(), "huggingface".to_string(), store.clone())
        .expect("the shared adapter builds for the huggingface id");
    (provider, store)
}

/// The `huggingface` provider over the recorded token class.
fn enrolled_huggingface_provider(
    config: &Config,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    huggingface_provider(config, HUGGINGFACE_KEY)
}

// ----- TP-PROVIDER-WIRE::huggingface -------------------------------------------

/// A configured `huggingface` connection returns a verified model
/// outcome through the standard Broker: prepare admits the api_key pin
/// under DEC-011, the token bears the `Authorization` header verbatim —
/// never the body — the shared adapter posts exactly the frozen manifest
/// as a `chat/completions` request, the SSE stream validates its
/// finish_reason/`[DONE]` terminal, the one physical send is charged
/// once with the provider's reported usage, and the spent attempt never
/// re-sends.
#[tokio::test]
async fn huggingface_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified huggingface outcome",
            Some(json!({"prompt_tokens": 9, "completion_tokens": 4, "total_tokens": 13})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&huggingface_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_huggingface_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare(
            "main",
            &config,
            "/world/huggingface",
            "goal: prove the wire",
        )
        .expect("the huggingface pin passes DEC-011 eligibility");

    let (broker, outcome) = dispatch(broker, "/world/huggingface", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified huggingface outcome");
    assert!(reply.tool_calls.is_empty());

    // A fixed pin opens no catalogue leg: the request is the one send.
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {HUGGINGFACE_KEY}"),
        "the recorded token bears the wire verbatim"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(HUGGINGFACE_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"],
        json!(HUGGINGFACE_MODEL),
        "the pinned id rides the wire verbatim"
    );
    assert_eq!(
        body["messages"],
        json!([
            {"role": "system", "content": manifest.instructions},
            {"role": "user", "content": manifest.inputs},
        ]),
        "the frozen instructions and inputs ride the messages verbatim"
    );
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["stream_options"],
        json!({"include_usage": true}),
        "the recorded usage request rides the stream options"
    );

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "huggingface");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 9,
            completion_tokens: 4,
            total_tokens: 13,
        }
    );
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay = broker.dispatch(
                &mut rivect::model::NullLedger,
                "/world/huggingface",
                &manifest,
            );
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

/// Hostile stream input is never a false success for `huggingface`: a
/// stream ended mid `tool_calls` fragment — a partial call that never
/// executes — and a finish_reason the dialect cannot classify are both
/// the unknown terminal, and a rejected send charges nothing.
#[tokio::test]
async fn huggingface_adverse_wire_input_never_reports_success() {
    // a complete content delta plus an unterminated tool-call fragment,
    // then EOF — no finish_reason and no [DONE]
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&delta_chunk(json!({
                "tool_calls": [{
                    "index": 0,
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": "{\"path\":"},
                }],
            }))),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&huggingface_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_huggingface_provider(&config),
        &config,
        "/world/huggingface",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/huggingface", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "EOF mid tool call is the unknown terminal — never a usable call: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);

    // a finish_reason the dialect cannot classify is unknown, never
    // success
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&finish_chunk("mystery")),
            DONE_BLOCK,
        ),
    )
    .await;
    let config =
        Config::parse_validated(&huggingface_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_huggingface_provider(&config),
        &config,
        "/world/huggingface",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/huggingface", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "an unclassifiable terminal is the unknown terminal: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);
}

/// The recorded `provider/model` routing suffix is preserved: a listed
/// namespaced id and a listed id carrying the `:provider` suffix are
/// offered exactly as served, and the pinned routed id names the wire
/// model verbatim — never stripped to its bare model name, folded or
/// re-prefixed by this adapter.
#[tokio::test]
async fn huggingface_provider_model_routing_suffix_is_preserved() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": HUGGINGFACE_MODEL}),
            json!({"id": HUGGINGFACE_ROUTED}),
        ],
    )
    .await;
    mount_chat(
        &server,
        completed_stream(
            "routed",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);

    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.huggingface]\nkind = \"api_key\"\nendpoint = \"{base}\"\ncredential_ref = \"{HUGGINGFACE_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"huggingface\", model_id = \"{HUGGINGFACE_ROUTED}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");

    // the catalogue carries both routing forms unchanged — the static
    // bundled floor plus the one routed listed id
    let (provider, _store) = enrolled_huggingface_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the listing answers");
    drop_blocking(provider);
    let ids = model_ids(&models);
    assert_eq!(
        ids.len(),
        73,
        "the static bundled floor plus the routed listing id: {ids:?}"
    );
    assert!(
        ids.contains(&HUGGINGFACE_MODEL) && ids.contains(&HUGGINGFACE_ROUTED),
        "the namespaced ids ride the catalogue verbatim in sorted order: {ids:?}"
    );

    // the pinned routed id names the wire model verbatim
    let (provider, _store) = enrolled_huggingface_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    outcome.expect("the routed pin dispatches");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 2, "the discovery leg and the send");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(requests[1].url.path(), "/v1/chat/completions");
    let body: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert_eq!(
        body["model"],
        json!(HUGGINGFACE_ROUTED),
        "the namespace and the routing suffix ride the wire untouched"
    );
}

/// The recorded billing distinction is explicit in the credential path,
/// never inferred: the fine-grained model-request token — the recorded
/// account/org billing form — bears the wire, while provider-signed
/// material (a BYOK key) and a structured blob deny `CredentialMalformed`
/// on the send and on the catalogue leg, opening no wire leg at all, so
/// neither billing mode is ever inferred from the other.
#[tokio::test]
async fn huggingface_account_org_and_byok_billing_are_explicit_never_implicit() {
    // the recorded token class is the account/org form: it sends
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "account billed",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&huggingface_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_huggingface_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    outcome.expect("the recorded token class admits the send");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {HUGGINGFACE_KEY}"),
        "the recorded token bears the wire"
    );

    // the other billing class denies typed on both legs, before any wire
    // request exists
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": HUGGINGFACE_MODEL})]).await;
    let config =
        Config::parse_validated(&huggingface_config(&server_uri_v1(&server))).expect("valid");
    for material in [
        HUGGINGFACE_BYOK_KEY,
        "{\"token\": \"hf_fixture-structured-blob\"}",
    ] {
        let (provider, _store) = huggingface_provider(&config, material);
        let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
        let err = outcome.expect_err("material of another billing class denies");
        assert!(
            matches!(err, ProviderError::CredentialMalformed { .. }),
            "the denial is the typed malformed credential: {err:?}"
        );
        assert_no_secret_or_body(&err, material.as_bytes());
        drop_blocking(provider);

        let (provider, _store) = huggingface_provider(&config, material);
        let (provider, catalog) = catalog_on_thread(provider);
        let err = catalog.expect_err("the catalogue leg denies the same material");
        assert!(matches!(err, ProviderError::CredentialMalformed { .. }));
        assert_no_secret_or_body(&err, material.as_bytes());
        drop_blocking(provider);
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "material of another billing class never reaches the wire"
    );
}

/// The recorded token grammar requires a non-empty body: material that
/// is the `hf_` prefix alone, or the prefix followed only by
/// whitespace, names no token — `CredentialMalformed` on the send and on
/// the catalogue leg, with no wire request opened on either path.
#[tokio::test]
async fn huggingface_bare_token_prefix_denies_before_any_wire_leg() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": HUGGINGFACE_MODEL})]).await;
    let config =
        Config::parse_validated(&huggingface_config(&server_uri_v1(&server))).expect("valid");
    for material in ["hf_", "hf_   "] {
        let (provider, _store) = huggingface_provider(&config, material);
        let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
        let err = outcome.expect_err("the bare prefix names no token");
        assert!(
            matches!(err, ProviderError::CredentialMalformed { .. }),
            "the bare prefix is the typed malformed credential: {err:?}"
        );
        assert_no_secret_or_body(&err, material.as_bytes());
        drop_blocking(provider);

        let (provider, _store) = huggingface_provider(&config, material);
        let (provider, catalog) = catalog_on_thread(provider);
        let err = catalog.expect_err("the catalogue leg denies the bare prefix");
        assert!(matches!(err, ProviderError::CredentialMalformed { .. }));
        assert_no_secret_or_body(&err, material.as_bytes());
        drop_blocking(provider);
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the bare prefix never reaches the wire"
    );
}

/// An empty configured endpoint resolves the recorded default — the
/// `config?.baseUrl ?? defaultBaseUrl` absent arm our required `endpoint`
/// field expresses as the empty string, and whitespace-only shares the
/// arm under the recorded trim. Offline pin: the adapter's `Debug`
/// surface reports the resolved endpoint, so the arm is proved without
/// one byte toward `router.huggingface.co`.
#[test]
fn huggingface_empty_endpoint_resolves_the_recorded_default() {
    for endpoint in ["", "   "] {
        let config = Config::parse_validated(&huggingface_config(endpoint))
            .expect("an empty endpoint is valid");
        let (provider, _store) = enrolled_huggingface_provider(&config);
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"https://router.huggingface.co/v1\""),
            "endpoint {endpoint:?} resolved to the recorded default: {debug}"
        );
        drop_blocking(provider);
    }
}

// ----- TP-PROVIDER-AUTH::huggingface -------------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `huggingface`, through the same shared construction its siblings
/// use: a configured `region` — the recorded contract names none —
/// denies `RegionMismatch` with the connection context, and a
/// profile-bound ref whose scope disagrees with the binding denies
/// `CredentialProfileMismatch`; both deny before the store is read. A
/// refused bearer lands the typed transport denial carrying the peer's
/// status alone, and on that arm — the one that resolves and sends the
/// material — neither the offered credential nor the peer's body
/// reaches Display or Debug.
#[tokio::test]
async fn huggingface_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets()
{
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — before any
    // credential resolution
    let regioned = Config::parse_validated(
        &huggingface_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "huggingface".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "huggingface");
    assert_eq!(region, "eu");

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.huggingface]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"huggingface\", model_id = \"{HUGGINGFACE_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "huggingface".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));

    // a refused bearer is a typed transport denial — the wire never
    // coerces a wrong credential into success, the peer's body never
    // enters the error, and the request carried the bearer
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&huggingface_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_huggingface_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused bearer is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused bearer is transport: {err}")
    };
    assert_eq!(connection, "huggingface");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, HUGGINGFACE_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {HUGGINGFACE_KEY}"),
        "the admitted bearer reached the wire — the denial is the peer's status"
    );
}

/// A `/models` HTTP 200 contributes ids but confers no entitlement
/// (INV-010) for `huggingface`: the catalogue offers the listed id
/// beside the static bundled floor, yet with the token enrolled the
/// fixed pin's send still posts its own pinned model — never the
/// listed id as a substitute — and the unmounted `chat/completions`
/// peer answers the typed transport denial, so a 200 listing neither
/// rewrites the wire model nor admits the request.
#[tokio::test]
async fn huggingface_models_http_200_is_never_entitlement() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "org/listed-entitlement-claim"})]).await;
    let config =
        Config::parse_validated(&huggingface_config(&server_uri_v1(&server))).expect("valid");

    let (provider, _store) = enrolled_huggingface_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the listing answers");
    drop_blocking(provider);
    assert_eq!(
        models.len(),
        73,
        "the static floor plus the listed id: {:?}",
        model_ids(&models)
    );
    assert!(
        model_ids(&models).contains(&"org/listed-entitlement-claim"),
        "the 200 listing contributes its id"
    );
    let discovery = server.received_requests().await.expect("recorded");
    assert_eq!(discovery.len(), 1, "the catalogue reads the listing once");
    assert_eq!(discovery[0].url.path(), "/v1/models");

    let (provider, _store) = enrolled_huggingface_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a 200 catalogue never releases the pin");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the unmounted request leg is the typed transport denial: {err:?}");
    };
    assert_eq!(connection, "huggingface");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 404 },
        "the request leg answers the peer's status, never a listing-granted success: {cause}"
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "the discovery leg plus the request leg — the 200 listing adds nothing"
    );
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(requests[1].url.path(), "/v1/chat/completions");
    let body: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert_eq!(
        body["model"],
        json!(HUGGINGFACE_MODEL),
        "the pinned model rides the wire — a listed id never substitutes it"
    );
}

// ----- TP-PROVIDER-CATALOG::huggingface ----------------------------------------

/// The pinned bundled floor as an independent expected snapshot: the 72
/// ids the recorded T1 static-bearer-chat cell bundles for
/// `huggingface`, in sorted order. This is a self-consistency control,
/// not source proof — the pinned OMP snapshot is not vendored in this
/// workspace, so the list pins what this adapter's seed must offer, not
/// that upstream still records it.
fn huggingface_expected_floor() -> Vec<&'static str> {
    vec![
        "MiniMaxAI/MiniMax-M2",
        "MiniMaxAI/MiniMax-M2.1",
        "MiniMaxAI/MiniMax-M2.5",
        "MiniMaxAI/MiniMax-M2.7",
        "MiniMaxAI/MiniMax-M3",
        "Qwen/Qwen2.5-Coder-32B-Instruct",
        "Qwen/Qwen3-235B-A22B",
        "Qwen/Qwen3-235B-A22B-Instruct-2507",
        "Qwen/Qwen3-235B-A22B-Thinking-2507",
        "Qwen/Qwen3-30B-A3B",
        "Qwen/Qwen3-32B",
        "Qwen/Qwen3-Coder-30B-A3B-Instruct",
        "Qwen/Qwen3-Coder-480B-A35B-Instruct",
        "Qwen/Qwen3-Coder-Next",
        "Qwen/Qwen3-Next-80B-A3B-Instruct",
        "Qwen/Qwen3-Next-80B-A3B-Thinking",
        "Qwen/Qwen3-VL-235B-A22B-Instruct",
        "Qwen/Qwen3-VL-235B-A22B-Thinking",
        "Qwen/Qwen3.5-122B-A10B",
        "Qwen/Qwen3.5-27B",
        "Qwen/Qwen3.5-35B-A3B",
        "Qwen/Qwen3.5-397B-A17B",
        "Qwen/Qwen3.5-9B",
        "Qwen/Qwen3.6-27B",
        "Qwen/Qwen3.6-35B-A3B",
        "Qwen/Qwen3.8-2.4T-A95B",
        "Qwen/Qwen3.8-27B",
        "XiaomiMiMo/MiMo-V2-Flash",
        "XiaomiMiMo/MiMo-V2.5",
        "XiaomiMiMo/MiMo-V2.5-Pro",
        "deepseek-ai/DeepSeek-R1",
        "deepseek-ai/DeepSeek-R1-0528",
        "deepseek-ai/DeepSeek-V3",
        "deepseek-ai/DeepSeek-V3-0324",
        "deepseek-ai/DeepSeek-V3.1",
        "deepseek-ai/DeepSeek-V3.2",
        "deepseek-ai/DeepSeek-V4-Flash",
        "deepseek-ai/DeepSeek-V4-Flash-0731",
        "deepseek-ai/DeepSeek-V4-Flash-Vision-Exp",
        "deepseek-ai/DeepSeek-V4-Pro",
        "deepseek-ai/DeepSeek-V4-Pro-0813",
        "google/gemma-4-26B-A4B-it",
        "google/gemma-4-31B-it",
        "meta-llama/Llama-3.1-8B-Instruct",
        "meta-llama/Llama-3.3-70B-Instruct",
        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "moonshotai/Kimi-K2-Instruct",
        "moonshotai/Kimi-K2-Instruct-0905",
        "moonshotai/Kimi-K2-Thinking",
        "moonshotai/Kimi-K2.5",
        "moonshotai/Kimi-K2.6",
        "moonshotai/Kimi-K2.7-Code",
        "moonshotai/Kimi-K3",
        "openai/gpt-oss-120b",
        "openai/gpt-oss-20b",
        "stepfun-ai/Step-3.5-Flash",
        "stepfun-ai/Step-3.7-Flash",
        "tencent/Hy3",
        "thinkingmachines/Inkling",
        "thinkingmachines/Inkling-Small",
        "zai-org/GLM-4.5",
        "zai-org/GLM-4.5-Air",
        "zai-org/GLM-4.5V",
        "zai-org/GLM-4.6",
        "zai-org/GLM-4.6V-Flash",
        "zai-org/GLM-4.7",
        "zai-org/GLM-4.7-Flash",
        "zai-org/GLM-5",
        "zai-org/GLM-5.1",
        "zai-org/GLM-5.2",
        "zai-org/GLM-5.3",
        "zai-org/GLM-5.3-Flash",
    ]
}

/// The recorded T1 static-bearer-chat cell makes the bundled rows the
/// model universe: an empty `/models` answer leaves the static floor
/// intact — every bundled id offered ids-only in deterministic sorted
/// order — while the key-gated listing stays a non-authoritative
/// supplement the floor never depends on. The offered set is compared
/// against the pinned 72-id snapshot as a self-consistency control, so a
/// mistyped, swapped or dropped seed id cannot stay green.
#[tokio::test]
async fn huggingface_static_floor_survives_an_empty_listing() {
    use std::collections::BTreeSet;
    let server = MockServer::start().await;
    mount_models(&server, vec![]).await;
    let config =
        Config::parse_validated(&huggingface_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_huggingface_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the empty listing answers");
    drop_blocking(provider);

    let ids = model_ids(&models);
    let offered: BTreeSet<&str> = ids.iter().copied().collect();
    let expected: BTreeSet<&str> = huggingface_expected_floor().into_iter().collect();
    assert_eq!(
        offered, expected,
        "the floor offers exactly the pinned bundled row set"
    );
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "the floor answers in sorted order");
    assert!(
        models.iter().all(|model| model.price == ModelPrice::Unknown
            && !model.vision
            && !model.reasoning
            && model.efforts.is_empty()
            && model.effort_default.is_none()
            && model.context_window.is_none()),
        "the bundled reference descriptors stay uncarried"
    );

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "the empty listing is still the one discovery leg"
    );
    assert_eq!(requests[0].url.path(), "/v1/models");
}

/// One seeded class in the failed-listing cohort: the connection id,
/// its fixture config, its enrolled provider and its recorded floor.
type SeededFloorClass = (
    &'static str,
    fn(&str) -> String,
    fn(&Config) -> (ChatCompletionsProvider, Arc<support::MapStore>),
    Vec<String>,
);

/// The recorded surface a seeded class's floor carries on a failed
/// listing: the floor is the recorded offer, not an id-only stub, so
/// the capability and price pins a successful answer would have
/// supplied still land.
fn seeded_floor_surface(connection: &str, models: &[CatalogModel]) {
    let model = |id: &str| {
        models
            .iter()
            .find(|model| model.id == id)
            .unwrap_or_else(|| panic!("{connection}: {id} offers through the floor"))
    };
    match connection {
        "deepseek" => assert_eq!(
            model(DEEPSEEK_MODEL),
            &deepseek_expected_model(DEEPSEEK_MODEL),
            "deepseek: the recorded surface rides the floor"
        ),
        "fireworks" => {
            for (id, input_per_1m, output_per_1m) in fireworks_expected_fast_prices() {
                assert_eq!(
                    model(id),
                    &CatalogModel {
                        id: id.to_string(),
                        price: ModelPrice::Usd {
                            input_per_1m,
                            output_per_1m,
                        },
                        ..CatalogModel::default()
                    },
                    "fireworks: the recorded variant price rides the floor"
                );
            }
        }
        "groq" => {
            for (id, _vision, efforts, input_per_1m, output_per_1m) in groq_expected_rows() {
                let offered = model(id);
                assert_eq!(
                    offered.efforts, efforts,
                    "groq: the recorded effort ladder rides the floor"
                );
                assert_eq!(
                    offered.price,
                    ModelPrice::Usd {
                        input_per_1m,
                        output_per_1m,
                    },
                    "groq: the recorded price rides the floor"
                );
            }
        }
        "aiand" => assert!(
            models.iter().all(|model| model.price == ModelPrice::Unknown
                && !model.vision
                && !model.reasoning
                && model.efforts.is_empty()
                && model.effort_default.is_none()
                && model.context_window.is_none()),
            "aiand: the ids-only floor carries no borrowed surface"
        ),
        "huggingface" => assert!(
            models
                .iter()
                .all(|model| model.price == ModelPrice::Unknown && model.efforts.is_empty()),
            "huggingface: the ids-only floor carries no borrowed surface"
        ),
        other => panic!("{other} is not a seeded floor class"),
    }
}

/// The recorded seed is the offer floor, so a listing that answered
/// nothing usable still offers it: a 5xx, a non-JSON body, an
/// oversized body and a 200 without a `data` array each answer the
/// recorded floor alone, and a refused endpoint — no answer at all —
/// answers it too: every seeded class keeps its recorded universe, in
/// deterministic sorted order, and the failed answer contributes no
/// offer of its own.
#[tokio::test]
async fn seeded_classes_offer_the_recorded_floor_on_a_failed_listing() {
    // a listed id the failed 5xx answer carries: the floor offers it
    // only if the failure had been admitted as a catalogue answer
    const FAILED_ANSWER_ID: &str = "failed-answer-entitlement-claim";

    fn sorted(ids: &[&str]) -> Vec<String> {
        let mut ids: Vec<String> = ids.iter().map(|id| (*id).to_string()).collect();
        ids.sort_unstable();
        ids
    }

    let groq_rows = groq_expected_rows();
    let groq_ids: Vec<&str> = groq_rows.iter().map(|row| row.0).collect();
    let huggingface_ids = huggingface_expected_floor();
    let classes: [SeededFloorClass; 5] = [
        (
            "deepseek",
            deepseek_config,
            enrolled_deepseek_provider,
            sorted(&DEEPSEEK_BUILTIN_IDS),
        ),
        (
            "fireworks",
            fireworks_config,
            enrolled_fireworks_provider,
            sorted(&FIREWORKS_FAST_SEED_IDS),
        ),
        (
            "groq",
            groq_config,
            enrolled_groq_provider,
            sorted(&groq_ids),
        ),
        (
            "huggingface",
            huggingface_config,
            enrolled_huggingface_provider,
            sorted(&huggingface_ids),
        ),
        (
            "aiand",
            aiand_config,
            aiand_provider,
            sorted(&AIAND_SEED_IDS),
        ),
    ];
    let oversized = json!({
        "object": "list",
        "data": vec![json!({"id": "x".repeat(4096)}); 300],
    })
    .to_string();
    assert!(
        oversized.len() > 1024 * 1024,
        "the fixture listing exceeds the catalog byte bound: {} bytes",
        oversized.len()
    );
    for (answer, template) in [
        (
            "a 5xx answer",
            Some(ResponseTemplate::new(503).set_body_json(json!({
                "object": "list",
                "data": [{"id": FAILED_ANSWER_ID}],
            }))),
        ),
        (
            "a non-JSON body",
            Some(ResponseTemplate::new(200).set_body_string("not json")),
        ),
        (
            "an oversized body",
            Some(ResponseTemplate::new(200).set_body_string(oversized.clone())),
        ),
        (
            "a 200 without a data array",
            Some(ResponseTemplate::new(200).set_body_json(json!({"object": "list"}))),
        ),
        // no answer at all: the connection is refused before a status
        ("a refused endpoint", None),
    ] {
        for (connection, config_for, provider_for, floor) in &classes {
            let (endpoint, server) = match &template {
                Some(template) => {
                    let server = MockServer::start().await;
                    Mock::given(method("GET"))
                        .and(path("/v1/models"))
                        .respond_with(template.clone())
                        .mount(&server)
                        .await;
                    (server_uri_v1(&server), Some(server))
                }
                None => ("http://127.0.0.1:1/v1".to_string(), None),
            };
            let config = Config::parse_validated(&config_for(&endpoint)).expect("valid");
            let (provider, _store) = provider_for(&config);
            let (provider, catalog) = catalog_on_thread(provider);
            let models = catalog.unwrap_or_else(|err| {
                panic!("{connection} on {answer}: the recorded floor answers: {err:?}")
            });
            drop_blocking(provider);
            let ids = model_ids(&models);
            assert_eq!(
                ids, *floor,
                "{connection} on {answer}: the recorded floor alone offers, sorted"
            );
            assert!(
                !ids.contains(&FAILED_ANSWER_ID),
                "{connection} on {answer}: the failed answer contributes no offer"
            );
            seeded_floor_surface(connection, &models);
            if let Some(server) = server {
                let requests = server.received_requests().await.expect("recorded");
                assert_eq!(
                    requests.len(),
                    1,
                    "{connection} on {answer}: the failed listing is the one discovery leg"
                );
                assert_eq!(requests[0].url.path(), "/v1/models");
            }
        }
    }
}

/// A spent whole-call budget is never an answer: a seeded class whose
/// discovery stalls past the deadline re-raises the typed `Transport`
/// deadline denial instead of substituting the recorded floor, whether
/// the late answer would have been a listing body or a failure status
/// (DEC-012, INV-004).
#[tokio::test]
async fn seeded_class_keeps_the_deadline_denial_never_the_floor() {
    // The peer answers 1700 ms in — later than the adapter's 1500 ms
    // budget but well inside the client's 3000 ms backstop — so the
    // adapter's own guard, not the reqwest timeout, raises the named
    // deadline. A status that lands after the budget is no answer
    // either: the 503 must not become the recorded floor.
    for (answer, template) in [
        (
            "a late 200 listing",
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(1700))
                .set_body_json(json!({
                    "object": "list",
                    "data": [{"id": "floor-claim"}],
                })),
        ),
        (
            "a late 503 status",
            ResponseTemplate::new(503).set_delay(Duration::from_millis(1700)),
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(template)
            .mount(&server)
            .await;
        let config =
            Config::parse_validated(&deepseek_config(&server_uri_v1(&server))).expect("valid");
        let store = Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(DEEPSEEK_REF, DEEPSEEK_KEY)],
        ));
        let provider = {
            let config = config.clone();
            std::thread::spawn(move || {
                ChatCompletionsProvider::with_deadline(
                    &config,
                    "deepseek",
                    store,
                    Duration::from_millis(1500),
                )
            })
            .join()
            .expect("the provider thread joins")
            .expect("the shared adapter builds for the deepseek id")
        };
        let (provider, catalogue) = catalog_on_thread(provider);
        let err = catalogue.expect_err("a spent budget never answers the recorded floor");
        let ProviderError::Transport { connection, cause } = &err else {
            panic!("{answer}: the deadline is a typed transport denial: {err}")
        };
        assert_eq!(connection, "deepseek");
        assert!(
            cause.class() == TransportClass::DeadlineExpired,
            "{answer}: the expired whole-call budget is the named deadline: {cause}"
        );
        drop_blocking(provider);
    }
}

/// A seeded class whose discovery peer answers headers inside the
/// budget but dribbles the body past it keeps the typed deadline, never
/// the recorded floor (DEC-012, INV-004): the body read spends the same
/// whole-call budget the status branch does.
#[tokio::test]
async fn seeded_class_mid_body_deadline_denies_never_the_floor() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("address");
    let stop = Arc::new(AtomicBool::new(false));
    let answered_headers = Arc::new(AtomicBool::new(false));
    let drips = Arc::new(AtomicUsize::new(0));
    let peer = {
        let stop = Arc::clone(&stop);
        let answered_headers = Arc::clone(&answered_headers);
        let drips = Arc::clone(&drips);
        std::thread::spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(accepted) => break accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::yield_now();
                    }
                    Err(error) => return Err(error),
                }
            };
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            let mut headers = Vec::new();
            let mut chunk = [0u8; 1024];
            while !headers.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let read = stream.read(&mut chunk)?;
                if read == 0 {
                    return Ok(());
                }
                headers.extend_from_slice(&chunk[..read]);
            }
            // Headers answer inside the budget; the body then dribbles
            // so only the whole-call clock can end the read.
            stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n")?;
            answered_headers.store(true, Ordering::SeqCst);
            let started = Instant::now();
            while !stop.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(10) {
                match stream.write_all(b"x") {
                    Ok(()) => {
                        drips.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::BrokenPipe
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                        ) =>
                    {
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
                std::thread::sleep(Duration::from_millis(30));
            }
            Ok(())
        })
    };

    let endpoint = format!("http://{address}/v1");
    let config = Config::parse_validated(&deepseek_config(&endpoint)).expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(DEEPSEEK_REF, DEEPSEEK_KEY)],
    ));
    let provider = std::thread::spawn(move || {
        ChatCompletionsProvider::with_deadline(
            &config,
            "deepseek",
            store,
            Duration::from_millis(1500),
        )
    })
    .join()
    .expect("the provider thread joins")
    .expect("the shared adapter builds for the deepseek id");
    let (provider, catalogue) = catalog_on_thread(provider);
    let err = catalogue.expect_err("a dribbled body never answers the recorded floor");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a spent body read is a typed transport deadline: {err}")
    };
    assert_eq!(connection, "deepseek");
    assert!(
        cause.class() == TransportClass::DeadlineExpired,
        "the dribbled body spends the whole-call budget: {cause}"
    );
    drop_blocking(provider);
    stop.store(true, Ordering::SeqCst);
    assert!(
        answered_headers.load(Ordering::SeqCst),
        "the peer answered headers inside the budget"
    );
    assert!(
        drips.load(Ordering::SeqCst) > 0,
        "the body was dribbling when the budget expired"
    );
    peer.join()
        .expect("the fixture peer thread joins")
        .expect("the fixture peer ends cleanly");
}

/// The `huggingface` catalogue merges the recorded static bundled floor
/// with the configured endpoint's own `/models` listing (T1 cell): every
/// `data[]` id with a non-whitespace body is offered exactly as served
/// beside the bundled ids, a listed id the floor already carries does
/// not duplicate, and an empty id never names a model. The floor's
/// reference descriptors (cost/vision/context, reasoning/effort) stay
/// uncarried — this class offers ids only — so every offer keeps
/// [`ModelPrice::Unknown`] and an empty capability surface, in
/// deterministic sorted order. The union is
/// compared against the pinned snapshot plus the listed id as a
/// self-consistency control, not source proof.
#[tokio::test]
async fn huggingface_listing_offers_ids_with_no_recorded_surface() {
    use std::collections::BTreeSet;
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": HUGGINGFACE_ROUTED}),
            json!({"id": ""}),
            json!({"id": HUGGINGFACE_MODEL}),
        ],
    )
    .await;
    let config =
        Config::parse_validated(&huggingface_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_huggingface_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the listing answers");
    drop_blocking(provider);

    let ids = model_ids(&models);
    let offered: BTreeSet<&str> = ids.iter().copied().collect();
    let mut floor = huggingface_expected_floor();
    floor.push(HUGGINGFACE_ROUTED);
    let expected: BTreeSet<&str> = floor.into_iter().collect();
    assert_eq!(
        offered, expected,
        "the merge offers exactly the pinned floor plus the routed listed id"
    );
    assert_eq!(
        ids.iter().filter(|id| **id == HUGGINGFACE_MODEL).count(),
        1,
        "a listed id the floor carries does not duplicate its seeded row"
    );
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(
        ids, sorted,
        "the merged offer is deterministic sorted order"
    );
    assert!(
        models.iter().all(|model| model.price == ModelPrice::Unknown
            && !model.vision
            && !model.reasoning
            && model.efforts.is_empty()
            && model.effort_default.is_none()
            && model.context_window.is_none()),
        "no bundled reference descriptor is carried onto an offer"
    );

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "one discovery leg");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {HUGGINGFACE_KEY}"),
        "the token bears the discovery leg"
    );
}

/// The auto pick rides the merged catalogue under the record's auto
/// semantic: the dispatch narrows the pool to the `huggingface` member,
/// the merged offer is sorted deterministically, and the sorted-first
/// offer is a **listed** routed id that sorts ahead of every bundled
/// floor id — the wire body then names that id verbatim, namespace and
/// `:provider` suffix untouched, in the inverted order the peer answered.
#[tokio::test]
async fn huggingface_auto_pick_resolves_through_the_listing() {
    const ROUTED_FIRST: &str = "AAA-org/AAA-chat:novita";
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "zz-late/zz-model"}),
            json!({"id": ROUTED_FIRST}),
        ],
    )
    .await;
    mount_chat(
        &server,
        completed_stream(
            "auto picked",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.huggingface]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{HUGGINGFACE_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\", pool = [\"huggingface\"] }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let (provider, _store) = enrolled_huggingface_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/huggingface", "goal: auto pick")
        .expect("the single-member pool pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/huggingface", manifest);
    let reply = outcome.expect("the auto pick dispatches");
    assert_eq!(reply.text, "auto picked");
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "the catalogue leg and the send are the only egress"
    );
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(requests[1].url.path(), "/v1/chat/completions");
    let body: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert_eq!(
        body["model"],
        json!(ROUTED_FIRST),
        "the sorted-first listed routed id names the wire model verbatim"
    );
}

// ----- TP-PROVIDER-RECOVERY::huggingface ---------------------------------------

/// A typed denial is recoverable through the same seam: the absent
/// credential denies the first send, enrolling the material at the
/// scope admits the retry — no state wedged, no plaintext path taken.
#[tokio::test]
async fn huggingface_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&huggingface_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "huggingface".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialAbsent { .. })
    ));

    store.enroll(HUGGINGFACE_REF, HUGGINGFACE_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the enrolled credential admits the retry");
    assert_eq!(reply.text, "recovered");
    drop_blocking(provider);
}

/// The legs matrix enforces the recorded expected set for
/// `huggingface`: CATALOG, AUTH, WIRE and RECOVERY each execute and
/// report inside this run, and INSTALLED reports NOT_RUN — an omitted
/// leg fails the suite rather than silently absenting.
#[tokio::test]
async fn huggingface_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "org/listed-foreign"}),
            json!({"id": HUGGINGFACE_MODEL}),
        ],
    )
    .await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&huggingface_config(&server_uri_v1(&server))).expect("valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the listing contributes both ids verbatim, each carrying
    // no recorded surface, and the one discovery leg is the only
    // request so far.
    let (provider, _store) = enrolled_huggingface_provider(&config);
    let (provider, listed) = catalog_on_thread(provider);
    let listed = listed.expect("catalog answers");
    let discovery = server.received_requests().await.expect("recorded");
    reported.insert(
        "CATALOG",
        if listed.len() == 73
            && listed.iter().any(|model| {
                model.id == HUGGINGFACE_MODEL
                    && model.price == ModelPrice::Unknown
                    && !model.vision
                    && !model.reasoning
            })
            && listed.iter().any(|model| {
                model.id == "org/listed-foreign"
                    && model.price == ModelPrice::Unknown
                    && model.efforts.is_empty()
            })
            && discovery.len() == 1
            && discovery[0].url.path() == "/v1/models"
        {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: an absent credential denies typed before any leg.
    let provider = provider_result(
        config.clone(),
        "huggingface".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("binding resolves");
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
    let (broker, manifest) = {
        let (provider, _store) = enrolled_huggingface_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/huggingface", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
    let (broker, outcome) = dispatch(broker, "/world/huggingface", manifest);
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
    let provider = provider_result(config.clone(), "huggingface".to_string(), empty.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(HUGGINGFACE_REF, HUGGINGFACE_KEY.as_bytes());
    let (provider, retried) = send_on_thread(provider, manifest);
    let recovered = matches!(&retried, Ok(reply) if reply.text == "matrix");
    reported.insert(
        "RECOVERY",
        if denied_ok && recovered {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // The row restates the `#[ignore]`d `provider_installed_huggingface`
    // case's status, as its sibling matrices do.
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

// ----- TP-PROVIDER-INSTALLED::huggingface --------------------------------------

/// TP-PROVIDER-INSTALLED::huggingface = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::huggingface = NOT_RUN"]
fn provider_installed_huggingface() {}

// ----- kilo --------------------------------------------------------------------

// The `kilo` connection's proof legs (HZN-008 class P): the shared Chat
// Completions adapter serves the literal id — no copied codec — under
// its own recorded predicates (`auth/kilo.kdl` `login "custom"`,
// `kiloModelManagerOptions`, descriptor `defaultModel`, commit
// `0133f7ff52d3859944b4fd4ccf3852df7fbf1b54`). The configured
// `endpoint` carries the API base verbatim — an empty one resolves the
// recorded `api.kilo.ai/api/gateway` default — and a configured `region`
// is denied: the contract names none. The recorded discovery is
// credential-optional (`catalogDiscovery.allowUnauthenticated`): a
// keyless `/models` answer contributes its offers over the recorded
// default row as the floor, an empty answer leaves the floor standing,
// and the `Authorization` header rides only when the store resolves
// material — no catalogue answer confers paid entitlement, since every
// send resolves the profile first. The pinned roster (`models.json`) is
// not vendored in this slice, so an offer carries no transcribed price
// or SKU-bearing row and keeps `ModelPrice::Unknown`. The credential is
// the recorded custom device/key profile: the device login's opaque
// token or the recorded key rides the gateway bearer, and material
// naming no token denies typed before any wire leg.

/// The scoped credential ref the `kilo` connection binds.
const KILO_REF: &str = "keyring:rivect-test/kilo";

/// Fixture gateway bearer — never a real credential, only ever sent to
/// localhost.
const KILO_KEY: &str = "fixture-kilo-gateway-token";

/// The recorded floor row the fixed-pin legs carry — the pinned
/// descriptor's `defaultModel`, so the pin is one the catalogue offers.
const KILO_MODEL: &str = "anthropic/claude-opus-4.8";

/// A free-tier gateway row (`:free` tag, the recorded unauthenticated
/// availability): a keyless `/models` answer contributes it as an offer,
/// which never becomes paid entitlement.
const KILO_FREE_MODEL: &str = "z-ai/glm-5:free";

/// One configured `kilo` connection pointing at the fixture peer: the
/// recorded custom class binds the explicit profile through a scoped
/// `SecretRef` (the same DEC-011 seam every class uses), the dialect
/// comes from the literal connection id (DEC-007), and the endpoint
/// carries the API base verbatim.
fn kilo_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.kilo]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{KILO_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"kilo\", model_id = \"{KILO_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn kilo_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(KILO_REF, material)],
    ));
    let provider = provider_result(config.clone(), "kilo".to_string(), store.clone())
        .expect("the shared adapter builds for the kilo id");
    (provider, store)
}

/// A `kilo` config whose credential arrives through the recorded
/// explicit profile binding — `connections.kilo.profile` naming
/// `profiles.kilo`, whose ref is the scope the store holds. The
/// connection's own ref points at an unseeded scope, so only the
/// profile precedence can resolve the material.
fn kilo_profiled_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.kilo]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"keyring:rivect-test/kilo-scope\"\nprofile = \"kilo\"\n\
         [profiles.kilo]\ncredential_ref = \"{KILO_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"kilo\", model_id = \"{KILO_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The `kilo` provider over the recorded enrolled profile material.
fn enrolled_kilo_provider(config: &Config) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    kilo_provider(config, KILO_KEY)
}

// ----- TP-PROVIDER-WIRE::kilo --------------------------------------------------

/// A configured `kilo` connection returns a verified model outcome
/// through the standard Broker: prepare admits the api_key pin under
/// DEC-011, the profile's opaque token bears the `Authorization` header
/// verbatim — never the body — and the shared adapter posts exactly the
/// frozen manifest as a `chat/completions` request: the recorded row's
/// id verbatim, system+user messages, `stream` with
/// `stream_options.include_usage` and the pinned effort as
/// `reasoning_effort`. The SSE stream validates its
/// finish_reason/`[DONE]` terminal, the one physical send is charged
/// once with the provider's reported usage, and the spent attempt never
/// re-sends.
#[tokio::test]
async fn kilo_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified kilo outcome",
            Some(json!({"prompt_tokens": 9, "completion_tokens": 4, "total_tokens": 13})),
        ),
    )
    .await;
    let config = Config::parse_validated(&kilo_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_kilo_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/kilo", "goal: prove the wire")
        .expect("the kilo pin passes DEC-011 eligibility");

    let (broker, outcome) = dispatch(broker, "/world/kilo", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified kilo outcome");
    assert!(reply.tool_calls.is_empty());

    // A fixed pin opens no catalogue leg: the request is the one send.
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {KILO_KEY}"),
        "the recorded profile material bears the wire verbatim"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(KILO_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"],
        json!(KILO_MODEL),
        "the pinned recorded row rides the wire verbatim"
    );
    assert_eq!(
        body["messages"],
        json!([
            {"role": "system", "content": manifest.instructions},
            {"role": "user", "content": manifest.inputs},
        ]),
        "the frozen instructions and inputs ride the messages verbatim"
    );
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["stream_options"],
        json!({"include_usage": true}),
        "the recorded usage request rides the stream options"
    );
    assert_eq!(
        body["reasoning_effort"],
        json!("medium"),
        "the pinned effort rides the recorded reasoning_effort surface"
    );

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "kilo");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 9,
            completion_tokens: 4,
            total_tokens: 13,
        }
    );
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay = broker.dispatch(&mut rivect::model::NullLedger, "/world/kilo", &manifest);
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

/// Hostile stream input is never a false success for `kilo`: a stream
/// ended mid `tool_calls` fragment — a partial call that never executes —
/// and a finish_reason the dialect cannot classify are both the unknown
/// terminal, and a rejected send charges nothing.
#[tokio::test]
async fn kilo_adverse_wire_input_never_reports_success() {
    // a complete content delta plus an unterminated tool-call fragment,
    // then EOF — no finish_reason and no [DONE]
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&delta_chunk(json!({
                "tool_calls": [{
                    "index": 0,
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": "{\"path\":"},
                }],
            }))),
        ),
    )
    .await;
    let config = Config::parse_validated(&kilo_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_kilo_provider(&config),
        &config,
        "/world/kilo",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/kilo", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "EOF mid tool call is the unknown terminal — never a usable call: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);

    // a finish_reason the dialect cannot classify is unknown, never
    // success
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&finish_chunk("mystery")),
            DONE_BLOCK,
        ),
    )
    .await;
    let config = Config::parse_validated(&kilo_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_kilo_provider(&config),
        &config,
        "/world/kilo",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/kilo", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "an unclassifiable terminal is the unknown terminal: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);
}

/// An empty configured endpoint resolves the recorded default — the
/// `config?.baseUrl ?? "https://api.kilo.ai/api/gateway"` absent arm our
/// required `endpoint` field expresses as the empty string, and
/// whitespace-only shares the arm under the recorded trim. Offline pin:
/// the adapter's `Debug` surface reports the resolved endpoint, so the
/// arm is proved without one byte toward `api.kilo.ai`.
#[test]
fn kilo_empty_endpoint_resolves_the_recorded_default() {
    for endpoint in ["", "   "] {
        let config =
            Config::parse_validated(&kilo_config(endpoint)).expect("an empty endpoint is valid");
        let (provider, _store) = enrolled_kilo_provider(&config);
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"https://api.kilo.ai/api/gateway\""),
            "endpoint {endpoint:?} resolved to the recorded default: {debug}"
        );
        drop_blocking(provider);
    }
}

// ----- TP-PROVIDER-AUTH::kilo --------------------------------------------------

/// The recorded custom device/key profile binds for `kilo`: the
/// credential arrives through `connections.kilo.profile`'s named
/// profile — the connection's own ref points at a scope the store never
/// holds, so only the profile precedence resolves the material — and
/// that material is the gateway bearer, surrounding whitespace trimmed
/// and the trimmed token verbatim on the wire. Material naming no token
/// (empty or whitespace only) denies `CredentialMalformed` before any
/// wire leg, on the catalogue leg as well as the send: resolved-but-
/// unusable material is not the recorded keyless form.
#[tokio::test]
async fn kilo_explicit_device_key_profile_binds() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "profile bound",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&kilo_profiled_config(&server_uri_v1(&server))).expect("valid");

    // the enrolled profile material — the opaque device token or key
    // form — bears the wire, trimmed
    for (material, expected) in [
        (KILO_KEY, KILO_KEY),
        ("  fixture-kilo-device-token  ", "fixture-kilo-device-token"),
    ] {
        let (provider, _store) = kilo_provider(&config, material);
        let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
        outcome.expect("the enrolled profile material is the connection's credential");
        drop_blocking(provider);
        let requests = server.received_requests().await.expect("recorded");
        assert_eq!(
            received_auth(requests.last().expect("the send was recorded")),
            format!("Bearer {expected}"),
            "the trimmed profile material bears the gateway wire"
        );
    }

    // material naming no token is unenrolled for this class: typed
    // denial, zero further wire legs — the keyless catalogue form is
    // the absent binding alone, never unusable material
    for material in ["", "   "] {
        let (provider, _store) = kilo_provider(&config, material);
        let (provider, denied) = send_on_thread(provider, prepared_manifest(&config));
        let err = denied.expect_err("material naming no token denies");
        assert!(
            matches!(err, ProviderError::CredentialMalformed { .. }),
            "the grammar denial is typed: {err}"
        );
        drop_blocking(provider);

        let (provider, _store) = kilo_provider(&config, material);
        let (provider, catalogue) = catalog_on_thread(provider);
        let err = catalogue.expect_err("unusable material has no keyless fallback");
        assert!(
            matches!(err, ProviderError::CredentialMalformed { .. }),
            "the catalogue leg denies the same material: {err}"
        );
        drop_blocking(provider);
    }
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        2,
        "only the two admitted profile sends reached the wire — the denials landed before any leg"
    );
}

/// Wrong credential/profile/region never produce a false success for
/// `kilo`, through the same shared construction its siblings use: a
/// configured `region` — the recorded contract names none — denies
/// `RegionMismatch` with the connection context, a profile-bound ref
/// whose scope disagrees with the binding denies
/// `CredentialProfileMismatch`, and a refused bearer lands the typed
/// transport denial carrying the peer's status alone — no error, nor
/// the offered credential material or the peer's body, reaches Display
/// or Debug.
#[tokio::test]
async fn kilo_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored. The sibling scope
    // is seeded for parity with the landed sibling legs; this arm and
    // the profile arm below deny before the store is read, so the
    // no-secret assertion there is not the discriminating observation —
    // the 401 arm at the end is where material resolves and renders.
    let regioned = Config::parse_validated(
        &kilo_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "kilo".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, KILO_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "kilo");
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, KILO_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.kilo]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"kilo\", model_id = \"{KILO_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "kilo".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, KILO_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, KILO_KEY.as_bytes());

    // a refused bearer is a typed transport denial — the wire never
    // coerces a wrong credential into success, the peer's body never
    // enters the error, and the request carried the bearer
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&kilo_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_kilo_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused bearer is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused bearer is transport: {err}")
    };
    assert_eq!(connection, "kilo");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, KILO_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {KILO_KEY}"),
        "the admitted bearer reached the wire — the denial is the peer's status"
    );
}

/// The recorded discovery is credential-optional, and that is no paid
/// entitlement for `kilo` (AC-040e, INV-010): with no credential
/// enrolled a keyless `/models` answer contributes its rows over the
/// recorded default row as the floor — the request carries no
/// `Authorization` header — an empty answer leaves the floor standing,
/// and the same absent credential denies a paid send `CredentialAbsent`
/// before any leg, so a keyless or free catalogue never pays for a
/// request.
#[tokio::test]
async fn kilo_free_no_key_catalog_is_not_paid_entitlement() {
    // a keyless answer contributes its own rows over the floor
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": KILO_FREE_MODEL})]).await;
    let config = Config::parse_validated(&kilo_config(&server_uri_v1(&server))).expect("valid");
    let provider = provider_result(
        config.clone(),
        "kilo".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("binding resolves; the catalogue is credential-optional");
    let (provider, catalogue) = catalog_on_thread(provider);
    let models = catalogue.expect("the keyless answer merges over the floor");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        [KILO_MODEL, KILO_FREE_MODEL],
        "the keyless answer's rows join the recorded floor in sorted order: {:?}",
        model_ids(&models)
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the keyless catalogue is one leg");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert!(
        requests[0].headers.get("authorization").is_none(),
        "no credential resolved, so the discovery leg carries no Authorization header"
    );

    // an empty answer keeps the floor standing
    let server = MockServer::start().await;
    mount_models(&server, vec![]).await;
    let config = Config::parse_validated(&kilo_config(&server_uri_v1(&server))).expect("valid");
    let provider = provider_result(
        config.clone(),
        "kilo".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("binding resolves; the catalogue is credential-optional");
    let (provider, catalogue) = catalog_on_thread(provider);
    let models = catalogue.expect("the empty answer still answers the floor");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        [KILO_MODEL],
        "the recorded floor survives an empty listing: {:?}",
        model_ids(&models)
    );

    // the keyless catalogue is no credential: a paid send denies typed
    // and opens no further leg
    let provider = provider_result(
        config.clone(),
        "kilo".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("binding resolves; the store is read at send");
    let (provider, denied) = send_on_thread(provider, prepared_manifest(&config));
    assert!(
        matches!(denied, Err(ProviderError::CredentialAbsent { .. })),
        "free availability never stands in for the explicit profile: {denied:?}"
    );
    drop_blocking(provider);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        1,
        "the credential denial lands before any send leg"
    );
}

/// The typed outage every [`UnavailableStore`] call answers.
fn unavailable_store() -> ProviderError {
    ProviderError::StoreUnavailable {
        store: STORE_KIND,
        reason: "fixture store unavailable".to_string(),
    }
}

/// A store double whose every call is the named outage — never the
/// absent-scope answer the keyless discovery form tolerates.
struct UnavailableStore;

impl CredentialStore for UnavailableStore {
    fn kind(&self) -> StoreKind {
        STORE_KIND
    }

    fn occupied(&self, _credential: &SecretRef) -> Result<bool, ProviderError> {
        Err(unavailable_store())
    }

    fn entry_accounts(&self, _service: &str) -> Result<Vec<String>, ProviderError> {
        Err(unavailable_store())
    }

    fn login(&self, _credential: &SecretRef, _secret: &[u8]) -> Result<(), ProviderError> {
        Err(unavailable_store())
    }

    fn resolve(&self, _credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
        Err(unavailable_store())
    }

    fn refresh(&self, _credential: &SecretRef, _secret: &[u8]) -> Result<(), ProviderError> {
        Err(unavailable_store())
    }

    fn revoke(&self, _credential: &SecretRef) -> Result<(), ProviderError> {
        Err(unavailable_store())
    }

    fn logout(&self, _credential: &SecretRef) -> Result<(), ProviderError> {
        Err(unavailable_store())
    }
}

/// A store outage is not the recorded keyless form: the credential-
/// optional discovery resolves `None` only for an absent scope, so a
/// `StoreUnavailable` answer surfaces as that typed error and opens no
/// request — an outage is never read as an unenrolled profile.
#[tokio::test]
async fn kilo_store_outage_is_not_the_keyless_form() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": KILO_FREE_MODEL})]).await;
    let config = Config::parse_validated(&kilo_config(&server_uri_v1(&server))).expect("valid");
    let provider = {
        let config = config.clone();
        std::thread::spawn(move || {
            ChatCompletionsProvider::new(&config, "kilo", Arc::new(UnavailableStore))
        })
        .join()
        .expect("the provider thread joins")
        .expect("the shared adapter builds for the kilo id")
    };
    let (provider, catalogue) = catalog_on_thread(provider);
    let err = catalogue.expect_err("a store outage is a typed denial, never a keyless answer");
    assert!(
        matches!(
            &err,
            ProviderError::StoreUnavailable { store, .. } if *store == STORE_KIND
        ),
        "the outage surfaces as the typed store error: {err}"
    );
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the store denial lands before any wire leg"
    );
}

/// A `/models` HTTP 200 is never entitlement for `kilo`: the keyed
/// listing contributes its rows as offers — merged over the recorded
/// floor in sorted order, on one discovery leg whose header carries the
/// enrolled bearer — yet the fixed pin's send still posts its own
/// recorded model, never a listed id as a substitute, and the answer
/// itself releases no request.
#[tokio::test]
async fn kilo_models_listing_is_not_entitlement() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": KILO_FREE_MODEL}),
            json!({"id": "listed-entitlement-claim"}),
        ],
    )
    .await;
    mount_chat(
        &server,
        completed_stream(
            "listing is no grant",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&kilo_config(&server_uri_v1(&server))).expect("valid");

    let (provider, _store) = enrolled_kilo_provider(&config);
    let (provider, catalogue) = catalog_on_thread(provider);
    let models = catalogue.expect("the listing answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        [KILO_MODEL, "listed-entitlement-claim", KILO_FREE_MODEL],
        "the listed rows join the recorded floor in sorted order: {:?}",
        model_ids(&models)
    );
    let discovery = server.received_requests().await.expect("recorded");
    assert_eq!(discovery.len(), 1, "the catalogue opens one discovery leg");
    assert_eq!(discovery[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&discovery[0]),
        format!("Bearer {KILO_KEY}"),
        "resolved material rides the discovery header"
    );

    let (broker, manifest) = prepared_with(
        enrolled_kilo_provider(&config),
        &config,
        "/world/kilo",
        "goal: listing is no grant",
    );
    let (broker, outcome) = dispatch(broker, "/world/kilo", manifest);
    outcome.expect("the pinned model dispatches");
    drop_blocking(broker);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "the discovery leg then the chat request — a 200 listing releases no third leg"
    );
    assert_eq!(requests[1].url.path(), "/v1/chat/completions");
    let body: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert_eq!(
        body["model"],
        json!(KILO_MODEL),
        "a listed row never substitutes the pinned recorded model"
    );
}

// ----- TP-PROVIDER-CATALOG::kilo ------------------------------------------------

/// A failed listing leaves the recorded floor standing for `kilo`
/// (DEC-012): the recorded default row is a catalogue floor, not the
/// answer's offer, so a 503 contributes no offer and takes none away.
#[tokio::test]
async fn kilo_failed_listing_answers_the_recorded_floor() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({
            "object": "list",
            "data": [{"id": "failed-answer-entitlement-claim"}],
        })))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&kilo_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_kilo_provider(&config);
    let (provider, catalogue) = catalog_on_thread(provider);
    let models = catalogue.expect("the recorded floor answers the failed listing");
    drop_blocking(provider);
    let ids = model_ids(&models);
    assert_eq!(
        ids,
        [KILO_MODEL],
        "the recorded floor alone offers on a failed listing: {ids:?}"
    );
    assert!(
        !ids.contains(&"failed-answer-entitlement-claim"),
        "the failed answer contributes no offer"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "the failed listing is the one discovery leg"
    );
}

/// No borrowed price or SKU-bearing row lands on a `kilo` offer
/// (AC-040e): the offers are the recorded floor row, the pinned roster
/// is not vendored here, and the class carries no price row or
/// capability descriptor — so every offer keeps `ModelPrice::Unknown`
/// and an empty capability surface. A figure transcribed from another
/// class, a fabricated subscription price, or a row carrying a
/// SKU-bearing surface lands here as a red.
#[tokio::test]
async fn kilo_no_subscription_sku_is_invented() {
    let server = MockServer::start().await;
    mount_models(&server, vec![]).await;
    let config = Config::parse_validated(&kilo_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_kilo_provider(&config);
    let (provider, catalogue) = catalog_on_thread(provider);
    let models = catalogue.expect("the recorded floor answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        [KILO_MODEL],
        "the offers are the recorded floor row alone"
    );
    for model in &models {
        assert_eq!(
            model.price,
            ModelPrice::Unknown,
            "{} carries no vendored price row — a borrowed figure or a fabricated subscription price would red here",
            model.id
        );
        assert!(
            !model.vision && !model.reasoning,
            "{} carries no recorded capability mark",
            model.id
        );
        assert!(
            model.efforts.is_empty()
                && model.effort_default.is_none()
                && model.context_window.is_none(),
            "{} carries no recorded effort or window surface",
            model.id
        );
    }
}

// ----- TP-PROVIDER-RECOVERY::kilo -----------------------------------------------

/// A typed denial is recoverable through the same seam: material naming
/// no token denies the first send, enrolling the recorded bearer at the
/// scope admits the retry — no state wedged, no plaintext path taken.
#[tokio::test]
async fn kilo_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config = Config::parse_validated(&kilo_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[(KILO_REF, "")]));
    let provider = provider_result(config.clone(), "kilo".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialMalformed { .. })
    ));

    store.enroll(KILO_REF, KILO_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the enrolled bearer admits the retry");
    assert_eq!(reply.text, "recovered");
    drop_blocking(provider);
}

/// The legs matrix enforces the recorded expected set for `kilo`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside this
/// run, and INSTALLED reports NOT_RUN. The matrix is a self-check: a leg
/// that reports `FAIL` here reds the suite, while a deleted case is
/// caught by the gate's exact-name chain, not by this row.
#[tokio::test]
async fn kilo_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": KILO_FREE_MODEL})]).await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&kilo_config(&server_uri_v1(&server))).expect("valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the keyless-eligible listing contributes its row over
    // the recorded floor, each offer carrying no price or capability
    // mark this slice carries no vendored row for.
    let (provider, _store) = enrolled_kilo_provider(&config);
    let (provider, listed) = catalog_on_thread(provider);
    let listed = listed.expect("catalog answers");
    reported.insert(
        "CATALOG",
        if model_ids(&listed) == [KILO_MODEL, KILO_FREE_MODEL]
            && listed.iter().all(|model| {
                model.price == ModelPrice::Unknown && !model.vision && !model.reasoning
            })
        {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: material naming no token denies typed before any leg.
    let (provider, _store) = kilo_provider(&config, "");
    let (provider, denied) = send_on_thread(provider, prepared_manifest(&config));
    reported.insert(
        "AUTH",
        if matches!(denied, Err(ProviderError::CredentialMalformed { .. })) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // WIRE: the full broker dispatch returns the verified outcome.
    let (broker, manifest) = {
        let (provider, _store) = enrolled_kilo_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/kilo", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
    let (broker, outcome) = dispatch(broker, "/world/kilo", manifest);
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
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[(KILO_REF, "")]));
    let provider = provider_result(config.clone(), "kilo".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialMalformed { .. }));
    store.enroll(KILO_REF, KILO_KEY.as_bytes());
    let (provider, retried) = send_on_thread(provider, manifest);
    let recovered = matches!(&retried, Ok(reply) if reply.text == "matrix");
    reported.insert(
        "RECOVERY",
        if denied_ok && recovered {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // The row restates the `#[ignore]`d `provider_installed_kilo`
    // case's status, as its sibling matrices do.
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

// ----- TP-PROVIDER-INSTALLED::kilo ----------------------------------------------

/// TP-PROVIDER-INSTALLED::kilo = NOT_RUN: the installed-provider proof
/// is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::kilo = NOT_RUN"]
fn provider_installed_kilo() {}

// ----- litellm -----------------------------------------------------------------

// The `litellm` connection's proof legs (HZN-008 class B — the
// configured-proxy cell): the shared Chat Completions adapter serves the
// literal id under its own recorded predicates. The proxy base is
// user-configured — the recorded default is
// `LITELLM_BASE_URL ?? http://localhost:4000/v1`, and our required
// `endpoint` field means a base must be configured, so the default is
// never substituted: an empty configured base resolves empty and no
// localhost or built-in catalogue exists. The recorded discovery is
// the proxy's own management metadata first — four paths under one
// bounded phase — with the recorded fall-through to `/models`
// (DEC-025, DRIFT-010). The recorded credential arm is the open proxy:
// an undeclared binding rides headerless on every leg, a declared
// binding that cannot resolve denies typed, and a scoped key bears the
// wire. A `/models` 200 is never entitlement; a metadata answer's
// capability, window and per-1M price ride the offer, while a `/models`
// fall-through row carries its id alone and keeps `ModelPrice::Unknown`.

/// The scoped credential ref a keyed `litellm` connection binds.
const LITELLM_REF: &str = "keyring:rivect-test/litellm";

/// Fixture proxy key — never a real credential, only ever sent to
/// localhost.
const LITELLM_KEY: &str = "fixture-litellm-proxy-key";

/// The pinned manual model id the fixed-pin legs carry: a proxy model id
/// is the operator's own naming, never a recorded catalogue row.
const LITELLM_MODEL: &str = "proxy/chat-model";

/// A model id the fixture peer's `/models` answer offers.
const LITELLM_LISTED: &str = "proxy/listed-model";

/// The profile-only binding the recorded class admits: a connection
/// naming `profile` and no own ref, so the profile's scope is the
/// binding.
const LITELLM_PROFILE_REF: &str = "keyring:rivect-test/litellm-team";

/// The material the profile's scope holds — the key the proxy login
/// pastes.
const LITELLM_PROFILE_KEY: &str = "fixture-litellm-team-key";

/// The rich metadata row the fixture's management answer carries: the
/// id from `model_group`, and the capability marks, window and per-token
/// prices from its `model_info` object — the pinned fetcher's shape.
fn litellm_rich_entry(model_group: &str) -> Value {
    json!({
        "model_group": model_group,
        "model_info": {
            "max_input_tokens": 1000,
            "max_output_tokens": 500,
            "supports_vision": true,
            "supports_reasoning": true,
            "input_cost_per_token": 0.000003,
            "output_cost_per_token": 0.000010,
        },
    })
}

/// Mount one management-metadata form at `request_path` with the body.
async fn mount_metadata(server: &MockServer, request_path: &str, body: Value) {
    Mock::given(method("GET"))
        .and(path(request_path))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

/// The request paths the fixture peer recorded, in order.
fn request_paths(requests: &[Request]) -> Vec<&str> {
    requests.iter().map(|request| request.url.path()).collect()
}

/// One configured `litellm` connection pointing at the fixture peer,
/// carrying no `credential_ref` — the recorded open-proxy form.
fn litellm_open_proxy_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.litellm]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"litellm\", model_id = \"{LITELLM_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The same connection with a scoped key enrolled — the recorded
/// authenticated form of the one class.
fn litellm_config(endpoint: &str) -> String {
    litellm_open_proxy_config(endpoint).replace(
        "endpoint = \"",
        &format!("credential_ref = \"{LITELLM_REF}\"\nendpoint = \""),
    )
}

fn litellm_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(LITELLM_REF, material)],
    ));
    let provider = provider_result(config.clone(), "litellm".to_string(), store.clone())
        .expect("the shared adapter builds for the litellm id");
    (provider, store)
}

/// The `litellm` provider over the recorded scoped key.
fn enrolled_litellm_provider(config: &Config) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    litellm_provider(config, LITELLM_KEY)
}

/// The `litellm` provider over the recorded open-proxy form: no
/// credential is bound, so the store is never consulted.
fn open_proxy_litellm_provider(config: &Config) -> ChatCompletionsProvider {
    provider_result(
        config.clone(),
        "litellm".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("an unbound declaration is the recorded open-proxy form")
}

// ----- TP-PROVIDER-AUTH::litellm ------------------------------------------------

/// The recorded open proxy is an admitted path for `litellm`, never a
/// dummy key: a declaration binding no `credential_ref` passes DEC-011
/// eligibility, the send reaches the peer with no `Authorization`
/// header at all, the frozen manifest rides as the one physical request,
/// its reply is charged once, and the catalogue lookup over the same
/// form probes the four recorded management paths headerless and takes
/// the recorded `/models` fall-through — neither leg carries a bearer
/// the declaration never bound.
#[tokio::test]
async fn litellm_open_proxy_without_key_is_admitted() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "open proxy outcome",
            Some(json!({"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5})),
        ),
    )
    .await;
    mount_models(&server, vec![json!({"id": LITELLM_LISTED})]).await;
    let config = Config::parse_validated(&litellm_open_proxy_config(&server_uri_v1(&server)))
        .expect("valid");
    assert_eq!(
        config.connections["litellm"].credential_ref, None,
        "the open-proxy row binds no credential — never a materialized dummy"
    );

    let (broker, manifest) = prepared_with(
        (
            open_proxy_litellm_provider(&config),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        ),
        &config,
        "/world/litellm",
        "goal: open proxy",
    );
    let (broker, outcome) = dispatch(broker, "/world/litellm", manifest.clone());
    let reply = outcome.expect("the open-proxy pin is admitted and dispatched");
    assert_eq!(reply.text, "open proxy outcome");
    assert_eq!(
        broker.accounted_requests(),
        1,
        "one physical send is charged once"
    );
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "litellm");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 3,
            completion_tokens: 2,
            total_tokens: 5,
        }
    );
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "a fixed pin opens no catalogue leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert!(
        requests[0].headers.get("authorization").is_none(),
        "no binding means no Authorization header — never a dummy key"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], json!(LITELLM_MODEL));

    // the same form reads the configured base's discovery headerless:
    // no management metadata is mounted, so the class takes the
    // recorded fall-through to `/models`
    let (provider, catalogue) = catalog_on_thread(open_proxy_litellm_provider(&config));
    let models = catalogue.expect("the open-proxy catalogue answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        [LITELLM_LISTED],
        "the fall-through listing is the offer surface: no seed floor, no invented catalogue"
    );
    for model in &models {
        assert_eq!(
            model.price,
            ModelPrice::Unknown,
            "{} carries no recorded price row",
            model.id
        );
        assert!(
            !model.vision && !model.reasoning && model.efforts.is_empty(),
            "{} carries no recorded capability surface",
            model.id
        );
    }
    let requests = server.received_requests().await.expect("recorded");
    let paths = request_paths(&requests);
    assert_eq!(
        paths,
        [
            "/v1/chat/completions",
            "/model_group/info",
            "/v2/model/info",
            "/model/info",
            "/v1/model/info",
            "/v1/models",
        ],
        "the send, then the four recorded metadata probes, then the fall-through"
    );
    assert!(
        requests[1..]
            .iter()
            .all(|request| request.headers.get("authorization").is_none()),
        "the open-proxy discovery carries no Authorization header on any leg"
    );
}

/// A scoped key on the same class is the recorded authenticated form for
/// `litellm`: the store material bears the discovery leg and the send,
/// the pinned model rides the wire verbatim, and one reply is one
/// physical usage.
#[tokio::test]
async fn litellm_scoped_key_sends_bearer() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": LITELLM_LISTED})]).await;
    mount_chat(
        &server,
        completed_stream(
            "keyed proxy outcome",
            Some(json!({"prompt_tokens": 4, "completion_tokens": 1, "total_tokens": 5})),
        ),
    )
    .await;
    let config = Config::parse_validated(&litellm_config(&server_uri_v1(&server))).expect("valid");

    let (provider, _store) = enrolled_litellm_provider(&config);
    let (provider, catalogue) = catalog_on_thread(provider);
    let models = catalogue.expect("the keyed catalogue answers");
    drop_blocking(provider);
    assert_eq!(model_ids(&models), [LITELLM_LISTED]);

    let (broker, manifest) = prepared_with(
        enrolled_litellm_provider(&config),
        &config,
        "/world/litellm",
        "goal: scoped key",
    );
    let (broker, outcome) = dispatch(broker, "/world/litellm", manifest.clone());
    let reply = outcome.expect("the scoped-key pin dispatches");
    assert_eq!(reply.text, "keyed proxy outcome");
    assert_eq!(broker.accounted_requests(), 1);
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    let paths = request_paths(&requests);
    assert_eq!(
        paths,
        [
            "/model_group/info",
            "/v2/model/info",
            "/model/info",
            "/v1/model/info",
            "/v1/models",
            "/v1/chat/completions",
        ],
        "the discovery legs then the chat request"
    );
    assert!(
        requests
            .iter()
            .all(|request| { received_auth(request) == format!("Bearer {LITELLM_KEY}") }),
        "the enrolled key bears every leg of the same class"
    );
    let body: Value = serde_json::from_slice(&requests[5].body).expect("json body");
    assert_eq!(
        body["model"],
        json!(LITELLM_MODEL),
        "the pinned proxy model id rides the wire verbatim"
    );
}

/// The recorded open-proxy class admits a declaration that binds only a
/// profile: `connections.litellm` names `profile = "litellm-team"` and
/// no own `credential_ref`, so the profile's scope is the binding and
/// its material is the bearer the send must carry. A resolution that
/// ignored the profile — treating the row as unbound — would send
/// headerless here, so the header itself is the discriminating
/// observation.
#[tokio::test]
async fn litellm_profile_only_binding_reaches_the_wire() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "profile bound",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4})),
        ),
    )
    .await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.litellm]\nkind = \"api_key\"\nendpoint = \"{}\"\nprofile = \"litellm-team\"\n\
         [profiles.litellm-team]\ncredential_ref = \"{LITELLM_PROFILE_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"litellm\", model_id = \"{LITELLM_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("a profile-only declaration is the recorded binding form");
    assert_eq!(
        config.connections["litellm"].credential_ref, None,
        "the row binds only its profile"
    );
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(LITELLM_PROFILE_REF, LITELLM_PROFILE_KEY)],
    ));
    let provider = provider_result(config.clone(), "litellm".to_string(), store)
        .expect("the profile binding resolves");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let reply = outcome.expect("the profile key admits the send");
    assert_eq!(reply.text, "profile bound");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "a fixed pin opens no discovery leg");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {LITELLM_PROFILE_KEY}"),
        "the profile's material is the wire bearer"
    );
}

/// The open proxy is the absent *binding*, never an absent scope: a
/// connection that does bind a `credential_ref` whose store holds
/// nothing is a configured-but-missing key and denies
/// `CredentialAbsent` on both legs — the catalogue read as well as the
/// send, exactly like every other keyed class, because this class's
/// catalogue is the recorded `Listing` and the keyless tolerance
/// belongs to `kilo`'s discovery form alone. A keyless send would be a
/// fabricated credential, and a headerless catalogue answer would be a
/// silent fall-back the record never names.
#[tokio::test]
async fn litellm_bound_scope_without_material_is_not_the_open_proxy() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": LITELLM_LISTED})]).await;
    mount_metadata(
        &server,
        "/model_group/info",
        json!({"data": [litellm_rich_entry(LITELLM_LISTED)]}),
    )
    .await;
    mount_chat(
        &server,
        completed_stream(
            "unreachable",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&litellm_config(&server_uri_v1(&server))).expect("valid");

    let provider = provider_result(
        config.clone(),
        "litellm".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("the binding resolves; the store is read per leg");
    let (provider, denied) = send_on_thread(provider, prepared_manifest(&config));
    assert!(
        matches!(denied, Err(ProviderError::CredentialAbsent { .. })),
        "a bound scope with no material is not the open proxy: {denied:?}"
    );
    drop_blocking(provider);

    let provider = provider_result(
        config.clone(),
        "litellm".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("binding resolves");
    let (provider, catalogue) = catalog_on_thread(provider);
    let err = catalogue.expect_err("the catalogue denies the same absent material");
    assert!(
        matches!(err, ProviderError::CredentialAbsent { .. }),
        "the catalogue leg is the recorded Listing, never the keyless form: {err}"
    );
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "both denies land before any wire leg"
    );
}

// ----- TP-PROVIDER-CATALOG::litellm ---------------------------------------------

/// The recorded discovery order for `litellm`: the proxy's management
/// metadata is asked first — the four recorded paths in order, appended
/// to the configured base minus its `/v1` — and an answer there is the
/// whole catalogue, so `/models` is never asked. The rich shape rides
/// the offer: the id from `model_group`, the capability marks, the
/// window and the per-token price scaled to per-1M. A form the proxy
/// does not expose (404) is skipped and the walk keeps its order; when
/// every form is absent the class takes the recorded fall-through to
/// `/models`; and a refused form takes the fall-through at once rather
/// than probing the rest.
#[tokio::test]
async fn litellm_management_metadata_precedes_the_models_listing() {
    // (1) the leading form answers: no `/models` leg at all
    let server = MockServer::start().await;
    mount_metadata(
        &server,
        "/model_group/info",
        json!({"data": [litellm_rich_entry("proxy/rich-model")]}),
    )
    .await;
    mount_models(&server, vec![json!({"id": LITELLM_LISTED})]).await;
    let config = Config::parse_validated(&litellm_open_proxy_config(&server_uri_v1(&server)))
        .expect("valid");
    let (provider, catalogue) = catalog_on_thread(open_proxy_litellm_provider(&config));
    let models = catalogue.expect("the metadata answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        ["proxy/rich-model"],
        "the metadata id is the offer — the listing never adds a row here"
    );
    let model = &models[0];
    assert_eq!(
        model.context_window,
        Some(1000),
        "the metadata's input window rides the offer"
    );
    assert_eq!(
        model.max_output_tokens, None,
        "the recorded output cap stays uncarried — the metadata maps the input window alone"
    );
    assert!(
        model.vision && model.reasoning,
        "the metadata's capability marks ride the offer"
    );
    assert_eq!(
        model.price,
        ModelPrice::Usd {
            input_per_1m: 3.0,
            output_per_1m: 10.0,
        },
        "the per-token figures scale to per-1M USD"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        request_paths(&requests),
        ["/model_group/info"],
        "the first answering form is the whole discovery"
    );

    // (2) earlier forms absent: the walk keeps the recorded order and
    // the late form still owns the offer
    let server = MockServer::start().await;
    mount_metadata(
        &server,
        "/v1/model/info",
        json!({"data": [litellm_rich_entry("proxy/late-form-model")]}),
    )
    .await;
    let config = Config::parse_validated(&litellm_open_proxy_config(&server_uri_v1(&server)))
        .expect("valid");
    let (provider, catalogue) = catalog_on_thread(open_proxy_litellm_provider(&config));
    let models = catalogue.expect("the late form answers");
    drop_blocking(provider);
    assert_eq!(model_ids(&models), ["proxy/late-form-model"]);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        request_paths(&requests),
        [
            "/model_group/info",
            "/v2/model/info",
            "/model/info",
            "/v1/model/info",
        ],
        "each absent form is skipped in the recorded order"
    );

    // (3) every form absent: the recorded fall-through to `/models`
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": LITELLM_LISTED})]).await;
    let config = Config::parse_validated(&litellm_open_proxy_config(&server_uri_v1(&server)))
        .expect("valid");
    let (provider, catalogue) = catalog_on_thread(open_proxy_litellm_provider(&config));
    let models = catalogue.expect("the fall-through listing answers");
    drop_blocking(provider);
    assert_eq!(model_ids(&models), [LITELLM_LISTED]);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        request_paths(&requests),
        [
            "/model_group/info",
            "/v2/model/info",
            "/model/info",
            "/v1/model/info",
            "/v1/models",
        ],
        "the absent metadata phase falls through once"
    );

    // (4) a refused form takes the fall-through immediately
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/model_group/info"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    mount_models(&server, vec![json!({"id": LITELLM_LISTED})]).await;
    let config = Config::parse_validated(&litellm_open_proxy_config(&server_uri_v1(&server)))
        .expect("valid");
    let (provider, catalogue) = catalog_on_thread(open_proxy_litellm_provider(&config));
    let models = catalogue.expect("a refused form is the typed fall-through");
    drop_blocking(provider);
    assert_eq!(model_ids(&models), [LITELLM_LISTED]);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        request_paths(&requests),
        ["/model_group/info", "/v1/models"],
        "a refusal ends the metadata phase instead of probing the rest"
    );

    // (5) a served set survives a later form's failure: the first form
    // answers, the second fails, and the offers are kept — the catalogue
    // never falls through to `/models`
    let server = MockServer::start().await;
    mount_metadata(
        &server,
        "/model_group/info",
        json!({"data": [{"model_group": "proxy/served-then-failed"}]}),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/v2/model/info"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    mount_models(&server, vec![json!({"id": LITELLM_LISTED})]).await;
    let config = Config::parse_validated(&litellm_open_proxy_config(&server_uri_v1(&server)))
        .expect("valid");
    let (provider, catalogue) = catalog_on_thread(open_proxy_litellm_provider(&config));
    let models = catalogue.expect("the served set survives the later failure");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        ["proxy/served-then-failed"],
        "a later form's failure never discards the offers already served"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        request_paths(&requests),
        ["/model_group/info", "/v2/model/info"],
        "the failing form ends the walk, and no `/models` leg follows a served set"
    );

    // (6) a later form whose body exceeds the catalogue byte bound is the
    // unreadable case: the walk ends and the served set is kept
    let server = MockServer::start().await;
    mount_metadata(
        &server,
        "/model_group/info",
        json!({"data": [{"model_group": "proxy/served-then-oversize"}]}),
    )
    .await;
    // one byte past the catalogue bound (1 MiB) in a well-formed body
    let oversize = format!(
        "{{\"data\": [{{\"model_group\": \"{}\"}}]}}",
        "a".repeat(1024 * 1024 + 16)
    );
    Mock::given(method("GET"))
        .and(path("/v2/model/info"))
        .respond_with(ResponseTemplate::new(200).set_body_string(oversize))
        .mount(&server)
        .await;
    mount_models(&server, vec![json!({"id": LITELLM_LISTED})]).await;
    let config = Config::parse_validated(&litellm_open_proxy_config(&server_uri_v1(&server)))
        .expect("valid");
    let (provider, catalogue) = catalog_on_thread(open_proxy_litellm_provider(&config));
    let models = catalogue.expect("the served set survives the unreadable form");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        ["proxy/served-then-oversize"],
        "an over-bound body ends the walk without discarding the served set"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        request_paths(&requests),
        ["/model_group/info", "/v2/model/info"],
        "the over-bound form is read as far as its bound and no further leg follows"
    );
}

/// The recorded enrichment semantics: the first answering form owns the
/// offered id set, a later form only fills the gaps that set leaves —
/// never overwriting a value already stated — and the walk stops as soon
/// as every offer states its window and price. A foreign id a later form
/// carries is never added: the first answer's set is the catalogue. The
/// marks and prices one form states survive the next form that states
/// none of them, while the window every earlier form left unstated is
/// filled from the form that states it.
#[tokio::test]
async fn litellm_metadata_merges_into_the_served_set_and_stops_when_complete() {
    let server = MockServer::start().await;
    // the leading form owns the id set and states nothing else, so the
    // walk continues
    mount_metadata(
        &server,
        "/model_group/info",
        json!({"data": [{"model_group": "proxy/enriched"}]}),
    )
    .await;
    // this form fills the marks and the prices but no window, beside an id
    // the leading form never offered, so the walk continues
    mount_metadata(
        &server,
        "/v2/model/info",
        json!({"data": [
            {
                "model_group": "proxy/enriched",
                "model_info": {
                    "supports_vision": true,
                    "supports_reasoning": true,
                    "input_cost_per_token": 0.000003,
                    "output_cost_per_token": 0.000010,
                },
            },
            litellm_rich_entry("proxy/foreign"),
        ]}),
    )
    .await;
    // this form states only the window: every mark and price it omits must
    // survive from the form that stated them, and the window fills
    mount_metadata(
        &server,
        "/model/info",
        json!({"data": [
            {
                "model_group": "proxy/enriched",
                "model_info": {"max_input_tokens": 2000},
            },
        ]}),
    )
    .await;
    mount_models(&server, vec![json!({"id": LITELLM_LISTED})]).await;
    let config = Config::parse_validated(&litellm_open_proxy_config(&server_uri_v1(&server)))
        .expect("valid");
    let (provider, catalogue) = catalog_on_thread(open_proxy_litellm_provider(&config));
    let models = catalogue.expect("the metadata answers");
    drop_blocking(provider);

    assert_eq!(
        model_ids(&models),
        ["proxy/enriched"],
        "the first form's id set is the catalogue — the foreign id is absent"
    );
    let model = &models[0];
    assert_eq!(
        model.context_window,
        Some(2000),
        "the window every earlier form left unstated is filled from the form that states it"
    );
    assert_eq!(
        model.price,
        ModelPrice::Usd {
            input_per_1m: 3.0,
            output_per_1m: 10.0,
        },
        "the price one form stated survives a later form that omits it"
    );
    assert!(
        model.reasoning,
        "the reasoning mark one form stated survives a later form that omits it"
    );
    assert!(
        model.vision,
        "the vision mark one form stated survives a later form that omits it"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        request_paths(&requests),
        ["/model_group/info", "/v2/model/info", "/model/info"],
        "the completed set stops the walk — no further form and no `/models`"
    );
}

/// The recorded placeholder filter: a sentinel group carrying no
/// metadata is the proxy's placeholder, never an offer, while a
/// different sentinel naming real metadata is served. The bare
/// placeholder's own id is distinct from every served id, so dropping
/// the filter changes the offered set.
#[tokio::test]
async fn litellm_metadata_drops_a_bare_sentinel_placeholder() {
    let server = MockServer::start().await;
    mount_metadata(
        &server,
        "/model_group/info",
        json!({"data": [
            {"model_group": "all-team-models", "model_info": {"max_input_tokens": 1000}},
            {"model_group": "all-proxy-models"},
            {"model_group": "no-default-models", "supports_vision": true},
        ]}),
    )
    .await;
    mount_models(&server, vec![json!({"id": LITELLM_LISTED})]).await;
    let config = Config::parse_validated(&litellm_open_proxy_config(&server_uri_v1(&server)))
        .expect("valid");
    let (provider, catalogue) = catalog_on_thread(open_proxy_litellm_provider(&config));
    let models = catalogue.expect("the metadata answers");
    drop_blocking(provider);

    assert_eq!(
        model_ids(&models),
        ["all-team-models", "no-default-models"],
        "only the rows carrying metadata are offered — the bare placeholder is absent"
    );
    assert_eq!(
        models[0].context_window,
        Some(1000),
        "the stated window rides the served sentinel id"
    );
    assert!(
        models[1].vision,
        "a stated capability keeps a sentinel-named row a real offer"
    );
    assert!(
        !model_ids(&models).contains(&LITELLM_LISTED),
        "a served metadata set never falls through to `/models`"
    );

    // a form whose every row is a placeholder serves nothing, so it is
    // not a complete answer: the walk continues to the next form, whose
    // real row is served — the class never falls through to `/models`
    let server = MockServer::start().await;
    mount_metadata(
        &server,
        "/model_group/info",
        json!({"data": [{"model_group": "all-proxy-models"}]}),
    )
    .await;
    mount_metadata(
        &server,
        "/v2/model/info",
        json!({"data": [litellm_rich_entry("proxy/later-form-row")]}),
    )
    .await;
    mount_models(&server, vec![json!({"id": LITELLM_LISTED})]).await;
    let config = Config::parse_validated(&litellm_open_proxy_config(&server_uri_v1(&server)))
        .expect("valid");
    let (provider, catalogue) = catalog_on_thread(open_proxy_litellm_provider(&config));
    let models = catalogue.expect("the later form answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        ["proxy/later-form-row"],
        "an all-placeholder form keeps the walk alive for the next form's offers"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        request_paths(&requests),
        ["/model_group/info", "/v2/model/info"],
        "the placeholder-only form is not a complete answer"
    );
}

/// One lookup against a peer whose leading metadata form answers
/// `response`: the offers and the request paths the peer recorded.
async fn litellm_lookup_over(response: ResponseTemplate) -> (Vec<CatalogModel>, Vec<String>) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/model_group/info"))
        .respond_with(response)
        .mount(&server)
        .await;
    mount_models(&server, vec![json!({"id": LITELLM_LISTED})]).await;
    let config = Config::parse_validated(&litellm_open_proxy_config(&server_uri_v1(&server)))
        .expect("valid");
    let (provider, catalogue) = catalog_on_thread(open_proxy_litellm_provider(&config));
    let models = catalogue.expect("the catalogue answers");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    (
        models,
        request_paths(&requests)
            .into_iter()
            .map(str::to_string)
            .collect(),
    )
}

/// One lookup against a peer whose leading metadata form answers the
/// `payload` as a successful JSON body.
async fn litellm_lookup_over_json(payload: Value) -> (Vec<CatalogModel>, Vec<String>) {
    litellm_lookup_over(ResponseTemplate::new(200).set_body_json(payload)).await
}

/// The recorded metadata payload shape variants and the recorded
/// fall-through causes. A bare array, the `models` and `result`
/// wrappers all carry entries; the id falls back through
/// `model_name`→`id`→`litellm_params.model` when `model_group` is
/// absent; a one-sided cost stays `ModelPrice::Unknown`. A 5xx, a
/// non-JSON body, an empty entry list and an unknown wrapper all end the
/// phase without offers, so the class takes the recorded `/models`
/// fall-through.
#[tokio::test]
async fn litellm_metadata_shape_variants_and_fall_through_causes() {
    // the bare-array payload
    let (models, paths) =
        litellm_lookup_over_json(json!([litellm_rich_entry("proxy/array-model")])).await;
    assert_eq!(model_ids(&models), ["proxy/array-model"]);
    assert_eq!(paths, ["/model_group/info"]);

    // the `models` and `result` wrappers
    for (wrapper, id) in [
        ("models", "proxy/models-wrapper"),
        ("result", "proxy/result-wrapper"),
    ] {
        let (models, paths) =
            litellm_lookup_over_json(json!({ wrapper: [litellm_rich_entry(id)] })).await;
        assert_eq!(
            model_ids(&models),
            [id],
            "the {wrapper} wrapper carries entries"
        );
        assert_eq!(paths, ["/model_group/info"]);
    }

    // the recorded id fallbacks, each row stating its window and price
    let mut by_name = litellm_rich_entry("");
    by_name["model_name"] = json!("proxy/name-model");
    by_name
        .as_object_mut()
        .expect("fixture object")
        .remove("model_group");
    let mut by_id = litellm_rich_entry("");
    by_id["id"] = json!("proxy/id-model");
    by_id
        .as_object_mut()
        .expect("fixture object")
        .remove("model_group");
    let mut by_params = litellm_rich_entry("");
    by_params["litellm_params"] = json!({"model": "proxy/params-model"});
    by_params
        .as_object_mut()
        .expect("fixture object")
        .remove("model_group");
    let (models, _) = litellm_lookup_over_json(json!({"data": [by_name, by_id, by_params]})).await;
    assert_eq!(
        model_ids(&models),
        ["proxy/id-model", "proxy/name-model", "proxy/params-model"],
        "each recorded id fallback names its offer, in sorted order"
    );

    // a one-sided cost stays unknown, and the incomplete set keeps the
    // recorded walk alive (every later form absent)
    let (models, paths) = litellm_lookup_over_json(json!({"data": [{
        "model_group": "proxy/one-sided",
        "model_info": {"max_input_tokens": 10, "input_cost_per_token": 0.001},
    }]}))
    .await;
    assert_eq!(model_ids(&models), ["proxy/one-sided"]);
    assert_eq!(
        models[0].price,
        ModelPrice::Unknown,
        "a cost stating one leg alone is never half a price"
    );
    assert_eq!(
        paths,
        [
            "/model_group/info",
            "/v2/model/info",
            "/model/info",
            "/v1/model/info",
        ],
        "an incomplete served set keeps the walk alive"
    );

    // the fall-through causes: a served-nothing phase answers `/models`
    for (label, response, expected_paths) in [
        (
            "a 5xx form",
            ResponseTemplate::new(500),
            vec!["/model_group/info", "/v1/models"],
        ),
        (
            "a non-JSON body",
            ResponseTemplate::new(200).set_body_string("not json"),
            vec!["/model_group/info", "/v1/models"],
        ),
        (
            "an empty entry list",
            ResponseTemplate::new(200).set_body_json(json!({"data": []})),
            vec![
                "/model_group/info",
                "/v2/model/info",
                "/model/info",
                "/v1/model/info",
                "/v1/models",
            ],
        ),
        (
            "an unknown wrapper",
            ResponseTemplate::new(200)
                .set_body_json(json!({"entries": [litellm_rich_entry("proxy/unwrapped")]})),
            vec![
                "/model_group/info",
                "/v2/model/info",
                "/model/info",
                "/v1/model/info",
                "/v1/models",
            ],
        ),
    ] {
        let (models, paths) = litellm_lookup_over(response).await;
        assert_eq!(
            model_ids(&models),
            [LITELLM_LISTED],
            "{label} falls through to the listing"
        );
        assert_eq!(
            paths, expected_paths,
            "{label} takes the recorded fall-through"
        );
    }
}

/// A spent whole-call budget bounds the catalogue path: the leading
/// metadata probe is issued under the remaining budget and the delayed
/// form cannot answer inside it, so the walk ends without offers. The
/// typed `DeadlineExpired` is raised by the guard before the fall-through
/// `/models` leg — the catalogue leg is a request too — so exactly the
/// one bounded probe reaches the wire and no `/models` request follows.
#[tokio::test]
async fn litellm_metadata_never_probes_past_a_spent_budget() {
    let server = MockServer::start().await;
    // the leading form answers well past the constrained budget
    Mock::given(method("GET"))
        .and(path("/model_group/info"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(2))
                .set_body_json(json!({"data": [litellm_rich_entry("proxy/slow-model")]})),
        )
        .mount(&server)
        .await;
    mount_models(&server, vec![json!({"id": LITELLM_LISTED})]).await;
    let config = Config::parse_validated(&litellm_open_proxy_config(&server_uri_v1(&server)))
        .expect("valid");
    let provider = {
        let config = config.clone();
        std::thread::spawn(move || {
            ChatCompletionsProvider::with_deadline(
                &config,
                "litellm",
                Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
                Duration::from_millis(250),
            )
        })
        .join()
        .expect("the provider thread joins")
        .expect("the shared adapter builds for the litellm id")
    };
    // The blocking lookup runs on the blocking pool so the fixture peer's
    // runtime stays free to record and answer the probe.
    let (provider, catalogue) = tokio::task::spawn_blocking(move || {
        let outcome = provider.catalog();
        (provider, outcome)
    })
    .await
    .expect("the lookup task joins");
    let err = catalogue.expect_err("a spent budget is the typed deadline");
    assert!(
        matches!(&err, ProviderError::Transport { cause, .. }
            if cause.class() == TransportClass::DeadlineExpired),
        "the expired whole-call budget is the typed deadline: {err}"
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        request_paths(&requests),
        ["/model_group/info"],
        "exactly the one bounded probe reached the wire — no later probe and no `/models` leg"
    );
}

/// `litellm` substitutes no default host: the recorded default
/// (`LITELLM_BASE_URL ?? http://localhost:4000/v1`) needs a
/// configured base, and our required `endpoint` field means one is
/// always configured — an empty configured base resolves empty rather
/// than the recorded default, so no localhost catalogue is invented
/// and the lookup over it denies typed instead of reaching any host,
/// while a peer's empty listing offers nothing (the class records no
/// seed floor). The resolved endpoint is read from the adapter's
/// `Debug` surface, and the denial is pinned to the *URL-construction*
/// class: a substituted default host would answer a connection or
/// status failure instead, so a mere `Transport` variant would not
/// discriminate the invented host.
#[test]
fn litellm_no_localhost_catalog_is_invented() {
    use std::error::Error as _;
    for endpoint in ["", "   "] {
        let config = Config::parse_validated(&litellm_open_proxy_config(endpoint))
            .expect("an empty endpoint is valid");
        let provider = open_proxy_litellm_provider(&config);
        let debug = format!("{provider:?}");
        assert!(
            debug.contains(&format!("endpoint: \"{endpoint}\"")),
            "endpoint {endpoint:?} resolved no substituted host: {debug}"
        );
        assert!(
            !debug.contains("localhost") && !debug.contains("127.0.0.1"),
            "no localhost catalogue host is invented: {debug}"
        );
        let (provider, catalogue) = catalog_on_thread(provider);
        let err = catalogue.expect_err("an absent base opens no leg");
        let ProviderError::Transport { connection, cause } = &err else {
            panic!("the absent base is transport: {err}")
        };
        assert_eq!(connection, "litellm");
        assert!(
            cause.class() == TransportClass::RequestFailure,
            "no request was attempted: {cause}"
        );
        let request = cause
            .source()
            .and_then(|source| source.downcast_ref::<reqwest::Error>())
            .expect("the retained reqwest source");
        assert!(
            request.is_builder(),
            "the absent base fails URL construction — never a substituted host: {cause}"
        );
        drop_blocking(provider);
    }
}

/// The one catalogue scope this adapter has is the configured endpoint,
/// and this adapter holds no cache of its own: the same adapter asked
/// twice issues both lookups — five legs each, the four metadata probes
/// then the fall-through listing — and a provider configured for
/// another endpoint answers that endpoint's own listing. The recorded
/// rich-model cache lives in the upstream client layer keyed by the
/// base; nothing here is carried across bases, so an invented cache or
/// a shared catalogue would red this leg.
#[tokio::test]
async fn litellm_cache_is_scoped_to_the_endpoint() {
    let first = MockServer::start().await;
    mount_models(&first, vec![json!({"id": "first-endpoint-model"})]).await;
    let second = MockServer::start().await;
    mount_models(&second, vec![json!({"id": "second-endpoint-model"})]).await;

    let config =
        Config::parse_validated(&litellm_open_proxy_config(&server_uri_v1(&first))).expect("valid");
    let provider = open_proxy_litellm_provider(&config);
    let (provider, first_lookup) = catalog_on_thread(provider);
    let (provider, second_lookup) = catalog_on_thread(provider);
    drop_blocking(provider);
    for lookup in [first_lookup, second_lookup] {
        let models = lookup.expect("the configured base answers");
        assert_eq!(
            model_ids(&models),
            ["first-endpoint-model"],
            "each lookup reads the configured base, never a cached answer"
        );
    }
    assert_eq!(
        first.received_requests().await.expect("recorded").len(),
        10,
        "the one adapter asked twice issues both lookups against its base"
    );

    let config = Config::parse_validated(&litellm_open_proxy_config(&server_uri_v1(&second)))
        .expect("valid");
    let (provider, catalogue) = catalog_on_thread(open_proxy_litellm_provider(&config));
    let models = catalogue.expect("the second base answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        ["second-endpoint-model"],
        "the answer follows the configured endpoint — nothing is carried across bases"
    );
    assert_eq!(
        second.received_requests().await.expect("recorded").len(),
        5,
        "the second endpoint got its one lookup"
    );
    assert_eq!(
        first.received_requests().await.expect("recorded").len(),
        10,
        "the first endpoint saw no further leg"
    );
}

// ----- TP-PROVIDER-WIRE::litellm ------------------------------------------------

/// Hostile stream input is never a false success for `litellm`: a
/// stream ended mid `tool_calls` fragment — a partial call that never
/// executes — and a finish_reason the dialect cannot classify are both
/// the unknown terminal, and a rejected send charges nothing.
#[tokio::test]
async fn litellm_adverse_wire_input_never_reports_success() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&delta_chunk(json!({
                "tool_calls": [{
                    "index": 0,
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": "{\"path\":"},
                }],
            }))),
        ),
    )
    .await;
    let config = Config::parse_validated(&litellm_open_proxy_config(&server_uri_v1(&server)))
        .expect("valid");
    let (broker, manifest) = prepared_with(
        (
            open_proxy_litellm_provider(&config),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        ),
        &config,
        "/world/litellm",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/litellm", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "EOF mid tool call is the unknown terminal: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&finish_chunk("mystery")),
            DONE_BLOCK,
        ),
    )
    .await;
    let config = Config::parse_validated(&litellm_open_proxy_config(&server_uri_v1(&server)))
        .expect("valid");
    let (broker, manifest) = prepared_with(
        (
            open_proxy_litellm_provider(&config),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        ),
        &config,
        "/world/litellm",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/litellm", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "an unclassifiable terminal is the unknown terminal: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);
}

/// Wrong credential/profile/region never produce a false success for
/// `litellm`, through the same shared construction its siblings use: a
/// configured `region` — the recorded contract names none — denies
/// `RegionMismatch` with the connection context, and a profile-bound ref
/// whose scope disagrees with the binding denies
/// `CredentialProfileMismatch`; both deny before the store is read, so
/// neither arm renders material at all. A refused bearer then lands the
/// typed transport denial carrying the peer's status alone, and on that
/// arm — the one that resolves and sends the material — neither the
/// offered credential nor the peer's body reaches Display or Debug.
#[tokio::test]
async fn litellm_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    let regioned = Config::parse_validated(
        &litellm_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "litellm".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "litellm");
    assert_eq!(region, "eu");

    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.litellm]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"litellm\", model_id = \"{LITELLM_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "litellm".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&litellm_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_litellm_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused bearer is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused bearer is transport: {err}")
    };
    assert_eq!(connection, "litellm");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, LITELLM_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {LITELLM_KEY}"),
        "the admitted bearer reached the wire — the denial is the peer's status"
    );
}

/// A `/models` HTTP 200 is never entitlement for `litellm` (INV-010):
/// with the key enrolled the catalogue offers the listed id beside
/// nothing else, yet the fixed pin's send still posts its own model —
/// never the listed id as a substitute — and the unmounted
/// `chat/completions` peer answers the typed transport denial, so a 200
/// listing neither rewrites the wire model nor admits the request.
#[tokio::test]
async fn litellm_models_listing_is_not_entitlement() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "listed-entitlement-claim"})]).await;
    let config = Config::parse_validated(&litellm_config(&server_uri_v1(&server))).expect("valid");

    let (provider, _store) = enrolled_litellm_provider(&config);
    let (provider, catalogue) = catalog_on_thread(provider);
    let models = catalogue.expect("the listing answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        ["listed-entitlement-claim"],
        "the listed id is the whole offer — an answer confers no row beyond it"
    );
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        5,
        "the four metadata probes fall through to the one listing leg"
    );

    let (provider, _store) = enrolled_litellm_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a 200 catalogue never releases the pin");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the unmounted request leg is the typed transport denial: {err:?}");
    };
    assert_eq!(connection, "litellm");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 404 },
        "the request leg answers the peer's status: {cause}"
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 6, "the discovery legs plus the request leg");
    assert_eq!(requests[4].url.path(), "/v1/models");
    assert_eq!(requests[5].url.path(), "/v1/chat/completions");
    let body: Value = serde_json::from_slice(&requests[5].body).expect("json body");
    assert_eq!(
        body["model"],
        json!(LITELLM_MODEL),
        "the pinned model rides the wire — a listed id never substitutes it"
    );
}

/// The auto pick rides the configured base's listing under the record's
/// auto semantic: the dispatch narrows the pool to the `litellm`
/// member, the offer is sorted deterministically, and the sorted-first
/// listed id — ahead of a later-sorting sibling in the peer's inverted
/// order — names the wire model verbatim, on the headerless open-proxy
/// form.
#[tokio::test]
async fn litellm_auto_pick_resolves_through_the_listing() {
    const FIRST_IN_SORT_ORDER: &str = "aaa-proxy-model";
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "zzz-proxy-model"}),
            json!({"id": FIRST_IN_SORT_ORDER}),
        ],
    )
    .await;
    mount_chat(
        &server,
        completed_stream(
            "auto picked",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.litellm]\nkind = \"api_key\"\nendpoint = \"{}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\", pool = [\"litellm\"] }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let mut broker = Broker::new(Box::new(open_proxy_litellm_provider(&config)));
    let manifest = broker
        .prepare("main", &config, "/world/litellm", "goal: auto pick")
        .expect("the single-member pool pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/litellm", manifest);
    let reply = outcome.expect("the auto pick dispatches");
    assert_eq!(reply.text, "auto picked");
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    let paths = request_paths(&requests);
    assert_eq!(
        paths,
        [
            "/model_group/info",
            "/v2/model/info",
            "/model/info",
            "/v1/model/info",
            "/v1/models",
            "/v1/chat/completions",
        ],
        "the discovery legs and then the send"
    );
    assert!(
        requests[..5]
            .iter()
            .all(|request| request.headers.get("authorization").is_none()),
        "the open-proxy discovery carries no header"
    );
    let body: Value = serde_json::from_slice(&requests[5].body).expect("json body");
    assert_eq!(
        body["model"],
        json!(FIRST_IN_SORT_ORDER),
        "the sorted-first listed id names the wire model verbatim"
    );
    assert!(
        requests[5].headers.get("authorization").is_none(),
        "the open-proxy send carries no header"
    );
}

// ----- TP-PROVIDER-RECOVERY::litellm --------------------------------------------

/// A typed denial is recoverable through the same seam: material the
/// store resolves but the class cannot use — non-UTF-8 bytes can never be
/// a bearer token — denies `CredentialMalformed` on the first send, and
/// enrolling the recorded key at the same scope admits the retry with
/// that bearer. No state is wedged and no plaintext path is taken.
#[tokio::test]
async fn litellm_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config = Config::parse_validated(&litellm_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    store.enroll(LITELLM_REF, &[0xff, 0xfe]);
    let provider =
        provider_result(config.clone(), "litellm".to_string(), store.clone()).expect("binding");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialMalformed { .. })
    ));

    store.enroll(LITELLM_REF, LITELLM_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the enrolled key admits the retry");
    assert_eq!(reply.text, "recovered");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "the denial opened no leg; the retry is one send"
    );
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {LITELLM_KEY}"),
        "the recovered material bears the wire"
    );
}

/// The open-proxy arm carries the proxy's own key verbatim, so a
/// declared binding that resolves to empty or whitespace-only material
/// names no key at all: the send denies `CredentialMalformed` before any
/// leg rather than riding an empty `Authorization` value the recorded
/// login never writes.
#[tokio::test]
async fn litellm_open_proxy_empty_material_denies_before_any_leg() {
    let server = MockServer::start().await;
    let config = Config::parse_validated(&litellm_config(&server_uri_v1(&server))).expect("valid");
    for material in ["", "   "] {
        let (provider, _store) = litellm_provider(&config, material);
        let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
        let err = outcome.expect_err("material naming no key never sends");
        let ProviderError::CredentialMalformed { connection } = &err else {
            panic!("empty material is the typed malformed denial: {err:?}");
        };
        assert_eq!(connection, "litellm");
        drop_blocking(provider);
        assert!(
            server
                .received_requests()
                .await
                .expect("recorded")
                .is_empty(),
            "the denial lands before any leg — no headerless or empty-bearer request"
        );
    }
}

/// The legs matrix enforces the recorded expected set for `litellm`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside this
/// run, and INSTALLED reports NOT_RUN — an omitted leg fails the suite
/// rather than silently absenting.
#[tokio::test]
async fn litellm_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": LITELLM_LISTED})]).await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&litellm_config(&server_uri_v1(&server))).expect("valid");
    let open = Config::parse_validated(&litellm_open_proxy_config(&server_uri_v1(&server)))
        .expect("the open-proxy row is valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the configured base's listing is the whole offer surface
    // — no seed floor — and no offer carries a price or capability
    // mark the class does not record.
    let (provider, _store) = enrolled_litellm_provider(&config);
    let (provider, catalogue) = catalog_on_thread(provider);
    let listed = catalogue.expect("catalog answers");
    reported.insert(
        "CATALOG",
        if model_ids(&listed) == [LITELLM_LISTED]
            && listed.iter().all(|model| {
                model.price == ModelPrice::Unknown
                    && !model.vision
                    && !model.reasoning
                    && model.efforts.is_empty()
            })
        {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: the one class carries both recorded forms — the scoped key
    // bears the chat request, the unbound declaration sends headerless.
    let (provider, _store) = enrolled_litellm_provider(&config);
    let (provider, keyed_outcome) = send_on_thread(provider, prepared_manifest(&config));
    let keyed_ok = keyed_outcome.is_ok();
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    let keyed_bearer = requests.last().is_some_and(|request| {
        request.headers.get("authorization").is_some_and(|value| {
            value
                .to_str()
                .is_ok_and(|header| header == format!("Bearer {LITELLM_KEY}"))
        })
    });
    let (provider, headerless_outcome) =
        send_on_thread(open_proxy_litellm_provider(&open), prepared_manifest(&open));
    let headerless_ok = headerless_outcome.is_ok();
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    let headerless_absent = requests
        .last()
        .is_some_and(|request| request.headers.get("authorization").is_none());
    reported.insert(
        "AUTH",
        if keyed_ok && keyed_bearer && headerless_ok && headerless_absent {
            "PASS"
        } else {
            "FAIL"
        },
    );

    // WIRE: the full broker dispatch over the recorded open-proxy form
    // returns the verified outcome.
    let (broker, manifest) = {
        let mut broker = Broker::new(Box::new(open_proxy_litellm_provider(&open)));
        let manifest = broker
            .prepare("main", &open, "/world/litellm", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
    let (broker, outcome) = dispatch(broker, "/world/litellm", manifest);
    reported.insert(
        "WIRE",
        if matches!(&outcome, Ok(reply) if reply.text == "matrix") {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

    // RECOVERY: unusable material denies typed, and the recorded key at
    // the same scope admits the retry.
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    store.enroll(LITELLM_REF, &[0xff, 0xfe]);
    let provider =
        provider_result(config.clone(), "litellm".to_string(), store.clone()).expect("binding");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialMalformed { .. }));
    store.enroll(LITELLM_REF, LITELLM_KEY.as_bytes());
    let (provider, retried) = send_on_thread(provider, manifest);
    let recovered = matches!(&retried, Ok(reply) if reply.text == "matrix");
    reported.insert(
        "RECOVERY",
        if denied_ok && recovered {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

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

// ----- TP-PROVIDER-INSTALLED::litellm -------------------------------------------

/// TP-PROVIDER-INSTALLED::litellm = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::litellm = NOT_RUN"]
fn provider_installed_litellm() {}

// Band-2 tests keep their root names; the split restores the duplicate scanner's per-file coverage.
include!("provider_local/band2.rs");

// Band-3 tests keep their root names; the split restores the duplicate scanner's per-file coverage.
include!("provider_local/band3.rs");
include!("provider_local/band4.rs");
include!("provider_local/band5.rs");

/// `prompt_tokens_details.cached_tokens` and
/// `completion_tokens_details.reasoning_tokens` ride as their own legs; the
/// completion bin keeps the folded reasoning (AC-057).
#[tokio::test]
async fn chat_completion_detail_legs_are_carried() {
    let server = MockServer::start().await;
    let config = Config::parse_validated(&local_config(&server_uri_v1(&server))).expect("valid");
    mount_chat(
        &server,
        completed_stream(
            "cached",
            Some(json!({
                "prompt_tokens": 5,
                "completion_tokens": 7,
                "total_tokens": 12,
                "prompt_tokens_details": { "cached_tokens": 3 },
                "completion_tokens_details": { "reasoning_tokens": 2 },
            })),
        ),
    )
    .await;
    let (broker, manifest) = prepared_with(
        local_provider(&config),
        &config,
        "/world/local",
        "goal: detail legs",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest.clone());
    outcome.expect("the detailed send completes");
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(
        record.usage,
        UsageDelta::Legs {
            prompt_tokens: Some(5),
            completion_tokens: Some(7),
            reasoning_tokens: Some(2),
            cache_read_tokens: Some(3),
            cache_write_tokens: None,
            total_tokens: Some(12),
        }
    );
}
