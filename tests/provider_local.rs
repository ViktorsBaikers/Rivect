//! Provider proof legs for three literal connection ids whose source
//! classes resolve through this offline target
//! (TP-PROVIDER-{CATALOG,AUTH,WIRE,RECOVERY,INSTALLED}::
//! custom-chat-completions, abliteration, aiand): the configured
//! literal `custom-chat-completions` connection returns a verified
//! model outcome through the standard Broker against the
//! source-derived `chat/completions` peer, `abliteration` does the
//! same through the shared SLICE-016 Responses adapter, and `aiand`
//! through the shared Chat Completions adapter — no copied codec —
//! as localhost wiremock fixtures, no OMP, no user adapter, no real
//! host. The shared SSE parser's WHATWG §9.2.5–9.2.6 conformance is
//! pinned in provider_openai.rs; this file pins the Chat Completions
//! dialect surface plus the abliteration and aiand per-connection
//! predicates on top of it. TP-PROVIDER-INSTALLED::<id> stays
//! NOT_RUN — the ignored named cases carry that status explicitly.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/discard conveniences; src/ stays strict (standards §14)"
)]

use rivect::config::{Config, EffortLevel};
use rivect::model::{Broker, ModelError, RequestManifest};
use rivect::providers::local::{CatalogModel, ChatCompletionsProvider, ModelPrice};
use rivect::providers::openai::OpenAiProvider;
use rivect::providers::{CredentialStore, Provider, ProviderError, SecretRef, StoreKind};
use rivect::resources::UsageDelta;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

mod support;

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

/// A prepared manifest plus the broker that admitted it — the real
/// admission path, not a constructed manifest.
fn prepared(config: &Config, world: &str, inputs: &str) -> (Broker, RequestManifest) {
    let (provider, _store) = local_provider(config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", config, world, inputs)
        .expect("the custom-chat-completions pin passes DEC-011 eligibility");
    (broker, manifest)
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
/// comes back. Generic over the dialect adapter: the send seam is
/// the `Provider` trait's, not one implementation's.
fn send_on_thread<P: Provider + 'static>(
    mut provider: P,
    manifest: RequestManifest,
) -> (P, Result<rivect::providers::ProviderReply, ProviderError>) {
    std::thread::spawn(move || {
        let outcome = provider.send(&manifest);
        (provider, outcome)
    })
    .join()
    .expect("the send thread joins")
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: prove the wire");

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
            let replay = broker.dispatch("/world/local", &manifest);
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
            Err(ModelError::Provider(ProviderError::DialectMismatch { .. }))
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
/// every non-empty `data[].id` is an offered model in sorted order,
/// and the bearer credential came through the store seam.
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

/// The listing reads under the same whole-request deadline: a peer
/// dribbling `/models` byte-by-byte trips the total budget, never
/// parks the call inside a per-read window.
#[tokio::test]
async fn dribbling_catalog_cannot_park_past_the_deadline() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("address");
    // serve every connection the transport opens — a reset or retried
    // leg gets the same dribble, never an unanswered socket — until the
    // test releases the flag and the thread joins; a connect that never
    // arrives fails the assertions instead of hanging this peer
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = stop.clone();
    let peer = std::thread::spawn(move || {
        while !flag.load(std::sync::atomic::Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n");
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
    let endpoint = format!("http://{address}/v1");
    let config = Config::parse_validated(&local_config(&endpoint)).expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let built = config.clone();
    let provider = std::thread::spawn(move || {
        ChatCompletionsProvider::with_deadline(
            &built,
            CONNECTION,
            store,
            Duration::from_millis(1500),
        )
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
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    peer.join().expect("the drip thread joins");
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
    let outcome = broker.dispatch("/world/local", &manifest);
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
    let outcome = broker.dispatch("/world/local", &manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::DialectMismatch { .. }))
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
        let outcome = broker.dispatch("/world/local", &manifest);
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
        let outcome = broker.dispatch_fallback_choice("/world/local", &attempt_id, CONNECTION);
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: auto route");
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
    let endpoint = format!("http://{address}/v1");
    let config = Config::parse_validated(&local_config(&endpoint)).expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let built = config.clone();
    let provider = std::thread::spawn(move || {
        ChatCompletionsProvider::with_deadline(
            &built,
            CONNECTION,
            store,
            Duration::from_millis(1500),
        )
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
        Err(ProviderError::Transport { reason, .. }) => {
            assert!(
                reason.contains("307"),
                "the refused redirect's own status names the denial: {reason}"
            );
        }
        other => panic!("a redirect answer is a typed transport denial, never a follow: {other:?}"),
    }
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    match outcome {
        Err(ProviderError::Transport { reason, .. }) => {
            assert!(
                reason.contains("307"),
                "the refused redirect's own status names the denial: {reason}"
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
    let ProviderError::Transport { connection, reason } = &err else {
        panic!("a refused token is transport: {err}")
    };
    assert_eq!(connection, CONNECTION);
    assert!(
        reason.contains("401"),
        "the status code is the context: {reason}"
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: debug surfaces");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: partial tool");

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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: no terminal");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: strange terminal");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: accumulate calls");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: call bound");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: args bound");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: undeclared call");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: foreign tool kind");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: filtered verdict");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: in-band error");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: duplicate terminal");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: malformed chunk");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: unreadable usage");
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
        let (broker, manifest) = prepared(&config, "/world/local", "goal: malformed");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: late content");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: usage tail");
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
        let (broker, manifest) = prepared(&config, "/world/local", "goal: finish table");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: verbatim total");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: missing total");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: unknown usage");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: done only");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: finish only");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: failure");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: structured reason");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: scalar reason");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: flat error");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: string error");
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    let Err(ModelError::Provider(ProviderError::ProviderFailed { reason, .. })) = outcome else {
        panic!("the string error payload is a peer failure: {outcome:?}")
    };
    assert_eq!(reason, "boom");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: falsy members");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: thinking surface");
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
    let (broker, manifest) = prepared(&config, "/world/local", "goal: matrix wire");
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

/// One named SSE block on the Responses wire — the event-tagged
/// framing provider_openai.rs pins.
fn sse_block(event: &str, data: &Value) -> String {
    format!("event: {event}\ndata: {data}\n\n")
}

/// A completed Responses stream: an in-progress message item, a text
/// delta, the done item, any extra output items, then the mandatory
/// `response.completed` terminal carrying the full output set and
/// usage.
fn responses_completed_stream(text: &str, extra_items: Vec<Value>, usage: Option<Value>) -> String {
    let message = json!({
        "id": "msg_1",
        "type": "message",
        "status": "completed",
        "role": "assistant",
        "content": [{ "type": "output_text", "text": text }],
    });
    let mut output = extra_items;
    output.push(message.clone());
    let mut response = json!({
        "id": "resp_1",
        "status": "completed",
        "output": output,
    });
    if let Some(usage) = usage {
        response["usage"] = usage;
    }
    format!(
        "{}{}{}{}",
        sse_block(
            "response.output_item.added",
            &json!({"item": {"id": "msg_1", "type": "message", "status": "in_progress", "role": "assistant", "content": []}, "output_index": 0}),
        ),
        sse_block(
            "response.output_text.delta",
            &json!({"delta": text, "item_id": "msg_1", "output_index": 0, "content_index": 0}),
        ),
        sse_block(
            "response.output_item.done",
            &json!({"item": message, "output_index": 0}),
        ),
        sse_block("response.completed", &json!({"response": response})),
    )
}

async fn mount_responses(server: &MockServer, body: String) {
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(server)
        .await;
}

/// A prepared manifest plus the broker that admitted it — the real
/// admission path for the `abliteration` pin.
fn prepared_abliteration(config: &Config, world: &str, inputs: &str) -> (Broker, RequestManifest) {
    let (provider, _store) = abliteration_provider(config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", config, world, inputs)
        .expect("the abliteration pin passes DEC-011 eligibility");
    (broker, manifest)
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
    let (broker, manifest) =
        prepared_abliteration(&config, "/world/abliteration", "goal: prove the wire");

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
            let replay = broker.dispatch("/world/abliteration", &manifest);
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
/// non-empty `data[].id` is offered — never filtered to a sample —
/// the recorded static seed merges on top as the offer floor (its
/// recorded rationale — offering models before a live key exists —
/// stays upstream's), the union deduplicates and sorts, and the
/// bearer credential came through the store seam.
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
    let (broker, manifest) =
        prepared_abliteration(&auto, "/world/abliteration", "goal: forced reasoning");
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
    let ProviderError::Transport { connection, reason } = &err else {
        panic!("a refused token is transport: {err}")
    };
    assert_eq!(connection, "abliteration");
    assert!(
        reason.contains("401"),
        "the status code is the context: {reason}"
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
    let (broker, manifest) =
        prepared_abliteration(&config, "/world/abliteration", "goal: debug surfaces");
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
    let (broker, manifest) =
        prepared_abliteration(&config, "/world/abliteration", "goal: partial item");
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
    let (broker, manifest) =
        prepared_abliteration(&config, "/world/abliteration", "goal: no terminal");
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
    let (broker, manifest) =
        prepared_abliteration(&config, "/world/abliteration", "goal: undeclared call");
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
    let (broker, manifest) =
        prepared_abliteration(&config, "/world/abliteration", "goal: blobless reasoning");
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
    let (broker, manifest) =
        prepared_abliteration(&config, "/world/abliteration", "goal: foreign artifact");
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
    let (broker, manifest) =
        prepared_abliteration(&config, "/world/abliteration", "goal: null artifact member");
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
    let (broker, manifest) = prepared_abliteration(
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
    let (broker, manifest) =
        prepared_abliteration(&config, "/world/abliteration", "goal: matrix wire");
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

/// A prepared manifest plus the broker that admitted it — the real
/// admission path for the `aiand` pin.
fn prepared_aiand(config: &Config, world: &str, inputs: &str) -> (Broker, RequestManifest) {
    let (provider, _store) = aiand_provider(config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", config, world, inputs)
        .expect("the aiand pin passes DEC-011 eligibility");
    (broker, manifest)
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
    let (broker, manifest) = prepared_aiand(&config, "/world/aiand", "goal: prove the wire");

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
            let replay = broker.dispatch("/world/aiand", &manifest);
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
/// every non-empty `data[].id` is offered, the recorded static seed
/// merges on top as the offer floor, the union deduplicates and
/// sorts, every listed entry runs the recorded
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
            efforts: vec![EffortLevel::Low, EffortLevel::Medium, EffortLevel::High],
            effort_default: Some(EffortLevel::Medium),
            context_window: Some(262144),
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
    let ProviderError::Transport { connection, reason } = &err else {
        panic!("a refused token is transport: {err}")
    };
    assert_eq!(connection, "aiand");
    assert!(
        reason.contains("401"),
        "the status code is the context: {reason}"
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
    let (broker, manifest) = prepared_aiand(&config, "/world/aiand", "goal: debug surfaces");
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
    let (broker, manifest) = prepared_aiand(&auto, "/world/aiand", "goal: auto pick");
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
    let (broker, manifest) = prepared_aiand(&auto, "/world/aiand", "goal: seed pick");
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
    let (broker, manifest) = prepared_aiand(&config, "/world/aiand", "goal: matrix wire");
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
