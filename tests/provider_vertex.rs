//! Vertex dual-class proof (AC-004, T4): the configured literal
//! `google-vertex` connection returns one verified outcome through the
//! standard Broker, and the wire class comes from the pinned model's
//! recorded catalogue `api` owner — never from the model-name family or
//! the credential form. A `google-vertex` row rides the publisher
//! `streamGenerateContent` resource (API-key `publishers/google` form or
//! ADC `projects/.../publishers/google` form), an `anthropic-messages` row
//! rides the regional `streamRawPredict` resource (model in the URL,
//! `anthropic_version` in the body, betas in the body, no `/v1/messages`),
//! and a row outside the two native classes denies typed before any post.
//! The request and stream codecs are the extracted Gemini and Messages
//! seams, not copies — `tests/provider_gemini.rs` and
//! `tests/provider_anthropic.rs` stay the extraction control.
//!
//! The ADC leg consumes the producer artifact: the login path writes the
//! canonical `VertexCredential` bytes and the adapter reads them back
//! through `vertex_login::read` before the actual Broker dispatch.
//!
//! TP-PROVIDER-INSTALLED::google-vertex stays NOT_RUN — the ignored named
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
use rivect::providers::gemini::GeminiProvider;
use rivect::providers::vertex::VertexProvider;
use rivect::providers::vertex_login::{self, AdcEndpoints, AdcSources};
use rivect::providers::{Dialect, ProviderError, ProviderReply, StoreKind, dialect_for};
use rivect::resources::UsageDelta;
use rivect::state::{SettlementState, StoreLedger, TaskStore};
use serde_json::json;
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

mod support;

use support::{
    CountingLedger, MapStore, drop_blocking, prepared_with, received_bodies, send_on_thread,
    sse_block,
};

/// The literal connection id this adapter serves.
const VERTEX: &str = "google-vertex";
/// The scoped credential ref the connection binds.
const CREDENTIAL_REF: &str = "keyring:rivect-test/google-vertex";
/// A sibling scope holding real material while the bound scope stays
/// empty: seeded so a no-secret assertion proves no cross-scope leak.
const NEIGHBOR_REF: &str = "keyring:rivect-test/neighbor";
/// Fixture material, never a real credential, only ever sent to
/// localhost.
const API_KEY: &str = "fixture-vertex-api-key-not-real";
const NEIGHBOR_SECRET: &str = "fixture-neighbor-secret-not-real";
const ADC_TOKEN: &str = "fixture-vertex-adc-token-not-real";
const STORE_KIND: StoreKind = StoreKind::Keychain;

/// The two pinned models, one per native class.
const GEMINI_MODEL: &str = "gemini-3.1-pro-preview";
const MESSAGES_MODEL: &str = "claude-sonnet-4-5";

const PROJECT: &str = "rvct-proj";
const LOCATION: &str = "us-central1";

/// The body-only protocol version the `streamRawPredict` resource
/// records; the `anthropic-version` header stays the Messages dialect's.
const VERTEX_VERSION: &str = "vertex-2023-10-16";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const THINKING_BETA: &str = "thinking-binding-controls-2026-08-01";

const INPUTS: &str = "goal: prove the vertex wire";

/// One configured `google-vertex` connection pointing at the fixture
/// peer: the api_key auth class resolves a scoped `SecretRef` (DEC-011),
/// the dialect comes from the literal connection id (DEC-007), and the
/// effort assignment is the caller's — a pinned level rides the Gemini
/// class's `thinkingConfig` and has no surface on the Messages class.
fn vertex_config(endpoint: &str, model: &str, effort: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.{VERTEX}]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{VERTEX}\", model_id = \"{model}\" }}\n\
         effort = {effort}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

const PINNED_EFFORT: &str = "{ mode = \"fixed\", value = \"medium\" }";
const AUTO_EFFORT: &str = "{ mode = \"auto\" }";

/// The producer's canonical stored bytes: the artifact `vertex_login`
/// publishes, written here so a unit leg can pin the adapter side alone.
fn adc_artifact(project: &str, location: &str) -> String {
    json!({
        "source": "metadata",
        "project": project,
        "location": location,
        "access_token": ADC_TOKEN,
        "expires_at": 4_102_444_800_u64,
    })
    .to_string()
}

/// reqwest's blocking client builds and drops a shell runtime inside
/// `wait::enter` — panicking in any tokio context (debug builds) — so
/// every `VertexProvider` construction happens on a plain OS thread.
fn provider_result(config: Config, store: Arc<MapStore>) -> Result<VertexProvider, ProviderError> {
    std::thread::spawn(move || VertexProvider::new(&config, VERTEX, store))
        .join()
        .expect("the provider thread joins")
}

fn vertex_provider(config: &Config, material: &str) -> (VertexProvider, Arc<MapStore>) {
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, material), (NEIGHBOR_REF, NEIGHBOR_SECRET)],
    ));
    let provider = provider_result(config.clone(), store.clone())
        .expect("the vertex adapter builds for the literal id");
    (provider, store)
}

/// One frozen manifest through the real admission path.
fn prepared_manifest(config: &Config) -> RequestManifest {
    let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
    broker
        .prepare("main", config, "/world/vertex", "goal: auth leg")
        .expect("the vertex pin prepares")
}

/// The blocking provider send runs on a plain OS thread: reqwest's
/// blocking wait panics inside any tokio context, and the fixture peer
/// needs this runtime's thread anyway.
fn dispatch(
    mut broker: Broker,
    world: &str,
    manifest: RequestManifest,
) -> (Broker, Result<ProviderReply, ModelError>) {
    let world = world.to_string();
    std::thread::spawn(move || {
        let outcome = broker.dispatch(&mut rivect::model::NullLedger, &world, &manifest);
        (broker, outcome)
    })
    .join()
    .expect("the dispatch thread joins")
}

/// The same frozen dispatch with a counting ledger: a denial's settlement
/// row and accounting record are observable.
fn dispatch_counted(
    mut broker: Broker,
    world: &str,
    manifest: RequestManifest,
) -> (Broker, CountingLedger, Result<ProviderReply, ModelError>) {
    let world = world.to_string();
    std::thread::spawn(move || {
        let mut ledger = CountingLedger::new();
        let outcome = broker.dispatch(&mut ledger, &world, &manifest);
        (broker, ledger, outcome)
    })
    .join()
    .expect("the dispatch thread joins")
}

/// A pre-send denial opens and closes one settlement row, fails it, and
/// writes no accounting record.
fn assert_denied_settles_without_accounting(broker: &Broker, ledger: &CountingLedger) {
    assert_eq!(ledger.begun, 1, "the entered send opens one settlement row");
    assert_eq!(ledger.finished, 1, "the denial closes the row it opened");
    assert_eq!(ledger.failed, 1, "the row settles as failed");
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a denial opens no accounting record"
    );
}

/// One SSE response on the recorded resource path.
async fn mount_stream(server: &MockServer, resource: &str, body: String) {
    Mock::given(method("POST"))
        .and(path(resource))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(server)
        .await;
}

/// The publisher class's completed stream: one chunk with the parts, then
/// the terminal candidate carrying `finishReason` and `usageMetadata`.
fn gemini_completed(text: &str, prompt: u64, completion: u64) -> String {
    format!(
        "data: {}\n\ndata: {}\n\n",
        json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": text}]},
                "index": 0,
            }],
        }),
        json!({
            "candidates": [{
                "content": {"role": "model", "parts": []},
                "finishReason": "STOP",
                "index": 0,
            }],
            "usageMetadata": {
                "promptTokenCount": prompt,
                "candidatesTokenCount": completion,
                "totalTokenCount": prompt + completion,
            },
        }),
    )
}

/// The Anthropic class's completed stream: `message_stop` is the only
/// terminal, and both usage legs arrive.
fn messages_completed(text: &str, prompt: u64, completion: u64) -> String {
    [
        sse_block(
            "message_start",
            &json!({"type": "message_start", "message": {"usage": {"input_tokens": prompt}}}),
        ),
        sse_block(
            "content_block_start",
            &json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            }),
        ),
        sse_block(
            "content_block_delta",
            &json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": text},
            }),
        ),
        sse_block(
            "content_block_stop",
            &json!({"type": "content_block_stop", "index": 0}),
        ),
        sse_block(
            "message_delta",
            &json!({
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn"},
                "usage": {"output_tokens": completion},
            }),
        ),
        sse_block("message_stop", &json!({"type": "message_stop"})),
    ]
    .concat()
}

fn header<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
}

/// The publisher resource path for the pinned Gemini model.
fn publisher_path(model: &str) -> String {
    format!("/v1/publishers/google/models/{model}:streamGenerateContent")
}

/// The ADC publisher resource path for the pinned Gemini model.
fn adc_publisher_path(project: &str, location: &str, model: &str) -> String {
    format!(
        "/v1/projects/{project}/locations/{location}/publishers/google/models/{model}:streamGenerateContent"
    )
}

/// The regional Anthropic resource path for the pinned Messages model.
fn messages_path(project: &str, location: &str, model: &str) -> String {
    format!(
        "/v1/projects/{project}/locations/{location}/publishers/anthropic/models/{model}:streamRawPredict"
    )
}

// ----- class dispatch -------------------------------------------------

/// Both recorded classes over both credential forms: the API-key and ADC
/// publisher forms differ in resource path and auth header, the Messages
/// form posts the regional resource with the model in the URL, the body
/// version, no `/v1/messages`, and the suppressed context/effort
/// surfaces — each leg returns one verified outcome from one request.
#[tokio::test]
async fn class_dispatch_uses_the_recorded_class_per_credential_form() {
    assert_eq!(dialect_for(VERTEX), Some(Dialect::Vertex));
    assert_eq!(Dialect::Vertex.to_string(), "vertex");

    // The API-key publisher form.
    let keyed = MockServer::start().await;
    mount_stream(
        &keyed,
        &publisher_path(GEMINI_MODEL),
        gemini_completed("keyed answer", 11, 7),
    )
    .await;
    let config = Config::parse_validated(&vertex_config(&keyed.uri(), GEMINI_MODEL, PINNED_EFFORT))
        .expect("valid");
    let (provider, store) = vertex_provider(&config, API_KEY);
    let rendered = format!("{provider:?}");
    for secret in [API_KEY, ADC_TOKEN, NEIGHBOR_SECRET] {
        assert!(
            !rendered.contains(secret),
            "the adapter Debug never carries credential material"
        );
    }
    let (broker, manifest) = prepared_with((provider, store), &config, "/world/vertex", INPUTS);
    let instructions = manifest.instructions.clone();
    let (broker, outcome) = dispatch(broker, "/world/vertex", manifest);
    let reply = outcome.expect("the keyed publisher send succeeds");
    drop_blocking(broker);
    assert_eq!(reply.text, "keyed answer");
    assert_eq!(
        reply.usage,
        UsageDelta::from_reported(11, 7, 18, None, None, None),
        "the publisher's usageMetadata is charged verbatim"
    );

    let requests = keyed.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "one physical request per entered send");
    assert_eq!(requests[0].url.path(), publisher_path(GEMINI_MODEL));
    assert_eq!(
        requests[0].url.query(),
        Some("alt=sse"),
        "the publisher resource streams sse"
    );
    assert_eq!(header(&requests[0], "x-goog-api-key"), Some(API_KEY));
    assert_eq!(header(&requests[0], "authorization"), None);
    let keyed_bodies = received_bodies(&keyed).await;
    let body = &keyed_bodies[0];
    assert_eq!(body["contents"][0]["role"], json!("user"));
    assert_eq!(body["contents"][0]["parts"][0]["text"], json!(INPUTS));
    assert_eq!(
        body["systemInstruction"],
        json!({"parts": [{"text": instructions}]}),
        "the frozen instructions ride the systemInstruction member verbatim"
    );
    assert_eq!(
        body["generationConfig"]["thinkingConfig"]["thinkingLevel"],
        json!("MEDIUM"),
        "the pinned effort is the recorded thinking level"
    );
    assert_eq!(
        body["tools"][0]["functionDeclarations"][0]["name"],
        json!("read_file"),
        "the declared tool surface rides functionDeclarations"
    );

    // The ADC publisher form: same class, project/location resource and
    // a bearer instead of a key.
    let adc = MockServer::start().await;
    mount_stream(
        &adc,
        &adc_publisher_path(PROJECT, LOCATION, GEMINI_MODEL),
        gemini_completed("adc answer", 3, 2),
    )
    .await;
    let config = Config::parse_validated(&vertex_config(&adc.uri(), GEMINI_MODEL, AUTO_EFFORT))
        .expect("valid");
    let (broker, manifest) = prepared_with(
        vertex_provider(&config, &adc_artifact(PROJECT, LOCATION)),
        &config,
        "/world/vertex",
        INPUTS,
    );
    let (broker, outcome) = dispatch(broker, "/world/vertex", manifest);
    outcome.expect("the ADC publisher send succeeds");
    drop_blocking(broker);
    let requests = adc.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].url.path(),
        adc_publisher_path(PROJECT, LOCATION, GEMINI_MODEL)
    );
    assert_eq!(
        header(&requests[0], "authorization"),
        Some(format!("Bearer {ADC_TOKEN}").as_str())
    );
    assert_eq!(header(&requests[0], "x-goog-api-key"), None);

    // The Messages class: the regional streamRawPredict resource.
    let messages = MockServer::start().await;
    mount_stream(
        &messages,
        &messages_path(PROJECT, LOCATION, MESSAGES_MODEL),
        messages_completed("messages answer", 4, 3),
    )
    .await;
    let config = Config::parse_validated(&vertex_config(
        &messages.uri(),
        MESSAGES_MODEL,
        PINNED_EFFORT,
    ))
    .expect("valid");
    let (broker, manifest) = prepared_with(
        vertex_provider(&config, &adc_artifact(PROJECT, LOCATION)),
        &config,
        "/world/vertex",
        INPUTS,
    );
    let (broker, outcome) = dispatch(broker, "/world/vertex", manifest);
    let reply = outcome.expect("the messages resource send succeeds");
    drop_blocking(broker);
    assert_eq!(reply.text, "messages answer");
    assert_eq!(
        reply.usage,
        UsageDelta::from_reported(4, 3, 7, None, None, None)
    );

    let requests = messages.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(
        request.url.path(),
        messages_path(PROJECT, LOCATION, MESSAGES_MODEL),
        "the model rides the resource path"
    );
    assert!(
        !request.url.as_str().contains("/v1/messages"),
        "the standalone messages path never appears: {}",
        request.url
    );
    assert_eq!(
        header(request, "authorization"),
        Some(format!("Bearer {ADC_TOKEN}").as_str())
    );
    assert_eq!(header(request, "x-goog-api-key"), None);
    assert_eq!(
        header(request, "anthropic-version"),
        Some(ANTHROPIC_VERSION),
        "the Messages version header is unchanged"
    );
    assert_eq!(header(request, "anthropic-beta"), None);
    let messages_bodies = received_bodies(&messages).await;
    let body = &messages_bodies[0];
    assert_eq!(
        body.get("model"),
        None,
        "streamRawPredict names the model in the URL only"
    );
    assert_eq!(body["anthropic_version"], json!(VERTEX_VERSION));
    assert_eq!(body["max_tokens"], json!(8192));
    assert_eq!(body["stream"], json!(true));
    assert_eq!(body["messages"][0]["role"], json!("user"));
    assert_eq!(body["messages"][0]["content"], json!(INPUTS));
    assert_eq!(
        body["tools"][0]["input_schema"]["type"],
        json!("object"),
        "the declared tool surface rides input_schema"
    );
    // No manifest carrier produces the effort/context surface on this
    // resource, so this is an absence guard over that whole surface: a
    // future body addition — including an effort smuggled under
    // `thinking` or the Gemini `generationConfig` — reds it.
    for suppressed in [
        "context_management",
        "output_config",
        "betas",
        "anthropic_beta",
        "thinking",
        "generationConfig",
    ] {
        assert_eq!(
            body.get(suppressed),
            None,
            "the messages resource projection never carries {suppressed}"
        );
    }
    for secret in [API_KEY, ADC_TOKEN, NEIGHBOR_SECRET] {
        let rendered = format!("{body}");
        assert!(
            !rendered.contains(secret),
            "the wire body never carries credential material"
        );
    }
}

// ----- producer artifact ----------------------------------------------

/// The ADC leg consumes the producer: the login path writes the canonical
/// `VertexCredential` bytes at the scoped ref, the adapter reads them back
/// through `vertex_login::read`, and the actual Broker dispatch settles
/// exactly one accounting record for the one entered send.
#[tokio::test]
async fn vertex_adapter_consumes_the_producer_artifact() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": ADC_TOKEN,
            "expires_in": 3600,
        })))
        .mount(&server)
        .await;
    mount_stream(
        &server,
        &messages_path(PROJECT, LOCATION, MESSAGES_MODEL),
        messages_completed("producer answer", 5, 4),
    )
    .await;
    let config =
        Config::parse_validated(&vertex_config(&server.uri(), MESSAGES_MODEL, AUTO_EFFORT))
            .expect("valid");
    let store = Arc::new(MapStore::new(STORE_KIND));
    let sources = AdcSources {
        gac_file: None,
        user_adc_file: None,
        project: Some(PROJECT.to_string()),
        location: Some(LOCATION.to_string()),
        raw_env_token: false,
        endpoints: AdcEndpoints {
            token: format!("{}/token", server.uri()),
            metadata: format!("{}/metadata", server.uri()),
            iam: format!("{}/iam", server.uri()),
        },
    };
    let root = tempfile::TempDir::with_prefix("rivect-vertex-settlement-").expect("fixture root");
    let db = root.path().join("state.db");
    let store_for_thread = Arc::clone(&store);
    let (store, attempt, outcome) = std::thread::spawn(move || {
        let profile = vertex_login::login(&config, VERTEX, &sources, store_for_thread.as_ref())
            .expect("the ADC producer publishes the canonical profile");
        assert_eq!(profile, "google-vertex");
        let reference = rivect::providers::SecretRef::parse(CREDENTIAL_REF).expect("scoped ref");
        let artifact = vertex_login::read(store_for_thread.as_ref(), &reference)
            .expect("the adapter reads the producer's own bytes");
        assert_eq!(artifact.project(), PROJECT);
        assert_eq!(artifact.location(), LOCATION);
        assert!(
            !format!("{artifact:?}").contains(ADC_TOKEN),
            "the artifact's Debug redacts the token"
        );
        let mut state = TaskStore::open(&db).expect("store opens");
        state.open_budget("vertex-scope", 10).expect("budget opens");
        let store_handle: Arc<dyn rivect::providers::CredentialStore> = store_for_thread.clone();
        let provider = VertexProvider::new(&config, VERTEX, store_handle)
            .expect("the adapter builds from the published profile");
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/vertex", INPUTS)
            .expect("the pin prepares");
        let attempt = manifest.attempt_id.clone();
        let mut ledger = StoreLedger::new(&mut state, vec!["vertex-scope".to_string()]);
        let outcome = broker.dispatch(&mut ledger, "/world/vertex", &manifest);
        (state, attempt, outcome)
    })
    .join()
    .expect("the producer thread joins");
    outcome.expect("the producer-backed send settles");

    let totals = store.settlement_totals().expect("totals");
    assert_eq!(
        totals.settled_count, 1,
        "one accounting record per entered send"
    );
    let row = store.settlement(&attempt).expect("the row settles");
    assert_eq!(row.state, SettlementState::Settled);
    assert_eq!(row.bins.total_tokens, Some(9));

    let requests = server.received_requests().await.expect("recorded");
    let sends: Vec<&Request> = requests
        .iter()
        .filter(|request| request.method.as_str() == "POST")
        .collect();
    assert_eq!(sends.len(), 1, "one physical request");
    assert_eq!(
        header(sends[0], "authorization"),
        Some(format!("Bearer {ADC_TOKEN}").as_str())
    );
    assert_eq!(
        sends[0].url.path(),
        messages_path(PROJECT, LOCATION, MESSAGES_MODEL)
    );
}

/// The publisher class settles exactly one accounting record for one
/// entered send — the per-class counterpart of the Messages leg.
#[tokio::test]
async fn publisher_class_settles_one_record() {
    let server = MockServer::start().await;
    mount_stream(
        &server,
        &adc_publisher_path(PROJECT, LOCATION, GEMINI_MODEL),
        gemini_completed("publisher answer", 5, 4),
    )
    .await;
    let config = Config::parse_validated(&vertex_config(&server.uri(), GEMINI_MODEL, AUTO_EFFORT))
        .expect("valid");
    let (provider, _store) = vertex_provider(&config, &adc_artifact(PROJECT, LOCATION));
    let root = tempfile::TempDir::with_prefix("rivect-vertex-settlement-").expect("fixture root");
    let db = root.path().join("state.db");
    let (state, attempt, outcome) = std::thread::spawn(move || {
        let mut state = TaskStore::open(&db).expect("store opens");
        state.open_budget("vertex-scope", 10).expect("budget opens");
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/vertex", INPUTS)
            .expect("the pin prepares");
        let attempt = manifest.attempt_id.clone();
        let mut ledger = StoreLedger::new(&mut state, vec!["vertex-scope".to_string()]);
        let outcome = broker.dispatch(&mut ledger, "/world/vertex", &manifest);
        (state, attempt, outcome)
    })
    .join()
    .expect("the dispatch thread joins");
    outcome.expect("the publisher-backed send settles");

    let totals = state.settlement_totals().expect("totals");
    assert_eq!(
        totals.settled_count, 1,
        "one accounting record per entered send"
    );
    let row = state.settlement(&attempt).expect("the row settles");
    assert_eq!(row.state, SettlementState::Settled);
    assert_eq!(row.bins.total_tokens, Some(9));

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "one physical request");
    assert_eq!(
        header(&requests[0], "authorization"),
        Some(format!("Bearer {ADC_TOKEN}").as_str())
    );
}

// ----- class resolution -----------------------------------------------

/// Only the two recorded catalogue owners select a native class: an id
/// outside the closed table and a row whose owner is the upstream
/// `openai-completions` third class both deny `ModelClassUnresolved`
/// before any post, and the family-shaped ids never infer a class.
#[tokio::test]
async fn unknown_or_third_class_model_denies_before_the_post() {
    let server = MockServer::start().await;
    for model in [
        "mystery-model",
        "meta/llama-3.3-70b-instruct-maas",
        "claude-9-absent",
        "gemini-9-absent",
    ] {
        let config = Config::parse_validated(&vertex_config(&server.uri(), model, AUTO_EFFORT))
            .expect("valid");
        let (broker, manifest) = prepared_with(
            vertex_provider(&config, &adc_artifact(PROJECT, LOCATION)),
            &config,
            "/world/vertex",
            INPUTS,
        );
        let (broker, ledger, outcome) = dispatch_counted(broker, "/world/vertex", manifest);
        match outcome {
            Err(ModelError::Provider(ProviderError::ModelClassUnresolved {
                connection,
                model: denied,
            })) => {
                assert_eq!(connection, VERTEX);
                assert_eq!(denied, model);
            }
            other => panic!("{model} must deny its class before the post: {other:?}"),
        }
        assert_denied_settles_without_accounting(&broker, &ledger);
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "a class denial sends zero requests"
    );
}

/// The Messages class addresses a project and location, so the API-key
/// form cannot serve it: the denial is typed and lands before the post.
#[tokio::test]
async fn api_key_form_cannot_serve_the_messages_class() {
    let server = MockServer::start().await;
    let config =
        Config::parse_validated(&vertex_config(&server.uri(), MESSAGES_MODEL, AUTO_EFFORT))
            .expect("valid");
    let (broker, manifest) = prepared_with(
        vertex_provider(&config, API_KEY),
        &config,
        "/world/vertex",
        INPUTS,
    );
    let (broker, ledger, outcome) = dispatch_counted(broker, "/world/vertex", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(
                ProviderError::CredentialMalformed { .. }
            ))
        ),
        "the API-key form has no project/location resource: {outcome:?}"
    );
    assert_denied_settles_without_accounting(&broker, &ledger);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the credential-form denial sends zero requests"
    );
}

/// The dual-class adapter refuses an auto assignment typed: the lexical
/// pick of the mixed-class table could resolve a class the resolved
/// credential form cannot serve, so no class is guessed before the post.
#[tokio::test]
async fn auto_assignment_denies_typed_before_the_post() {
    let server = MockServer::start().await;
    let config = format!(
        "config_version = 1\n\
         [connections.{VERTEX}]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\", pool = [\"{VERTEX}\"] }}\n\
         effort = {AUTO_EFFORT}\n\
         fallback = {{ mode = \"off\" }}\n",
        endpoint = server.uri(),
    );
    let config = Config::parse_validated(&config).expect("valid");
    let (broker, manifest) = prepared_with(
        vertex_provider(&config, API_KEY),
        &config,
        "/world/vertex",
        INPUTS,
    );
    let (broker, ledger, outcome) = dispatch_counted(broker, "/world/vertex", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnpinnedModel { .. }))
        ),
        "an auto assignment has no pinned class: {outcome:?}"
    );
    assert_denied_settles_without_accounting(&broker, &ledger);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the auto denial sends zero requests"
    );
}

/// Stored material that is neither the ADC artifact nor a valid API key
/// denies typed before the post: the key form never guesses a credential.
#[tokio::test]
async fn malformed_api_key_denies_before_the_post() {
    let server = MockServer::start().await;
    let config = Config::parse_validated(&vertex_config(&server.uri(), GEMINI_MODEL, AUTO_EFFORT))
        .expect("valid");
    for material in ["", "not a valid/key"] {
        let (broker, manifest) = prepared_with(
            vertex_provider(&config, material),
            &config,
            "/world/vertex",
            INPUTS,
        );
        let (broker, ledger, outcome) = dispatch_counted(broker, "/world/vertex", manifest);
        assert!(
            matches!(
                outcome,
                Err(ModelError::Provider(
                    ProviderError::CredentialMalformed { .. }
                ))
            ),
            "{material:?} is not usable reference material: {outcome:?}"
        );
        assert_denied_settles_without_accounting(&broker, &ledger);
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the malformed-key denial sends zero requests"
    );
}

/// A project is path material and is percent-escaped: a value carrying a
/// separator or traversal token stays one encoded segment instead of
/// rewriting the resource path.
#[tokio::test]
async fn project_and_location_are_escaped_in_the_resource_path() {
    let server = MockServer::start().await;
    let escaped = "acme%2F..%2Fother";
    mount_stream(
        &server,
        &messages_path(escaped, LOCATION, MESSAGES_MODEL),
        messages_completed("escaped answer", 1, 1),
    )
    .await;
    let config =
        Config::parse_validated(&vertex_config(&server.uri(), MESSAGES_MODEL, AUTO_EFFORT))
            .expect("valid");
    let (broker, manifest) = prepared_with(
        vertex_provider(&config, &adc_artifact("acme/../other", LOCATION)),
        &config,
        "/world/vertex",
        INPUTS,
    );
    let (_broker, outcome) = dispatch(broker, "/world/vertex", manifest);
    outcome.expect("the escaped resource path reaches the peer");
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].url.path(),
        messages_path(escaped, LOCATION, MESSAGES_MODEL)
    );
}

/// A project must be one resource-path segment: an empty value or a dot
/// segment would be resolved away by the URL parser, so both native
/// classes deny typed before any post.
#[tokio::test]
async fn dot_or_empty_project_denies_before_the_post() {
    let server = MockServer::start().await;
    for model in [GEMINI_MODEL, MESSAGES_MODEL] {
        for project in ["", ".", ".."] {
            let config = Config::parse_validated(&vertex_config(&server.uri(), model, AUTO_EFFORT))
                .expect("valid");
            let (broker, manifest) = prepared_with(
                vertex_provider(&config, &adc_artifact(project, LOCATION)),
                &config,
                "/world/vertex",
                INPUTS,
            );
            let (broker, ledger, outcome) = dispatch_counted(broker, "/world/vertex", manifest);
            assert!(
                matches!(
                    outcome,
                    Err(ModelError::Provider(
                        ProviderError::UnsendableRequest { .. }
                    ))
                ),
                "{model} with project {project:?} denies its path segment: {outcome:?}"
            );
            assert_denied_settles_without_accounting(&broker, &ledger);
        }
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "a project-path denial sends zero requests"
    );
}

/// A location that could rewrite the regional host denies typed before
/// the post; a configured region is the same denial at build time.
#[tokio::test]
async fn bad_location_or_configured_region_denies_typed() {
    let server = MockServer::start().await;
    let config =
        Config::parse_validated(&vertex_config(&server.uri(), MESSAGES_MODEL, AUTO_EFFORT))
            .expect("valid");
    let (broker, manifest) = prepared_with(
        vertex_provider(&config, &adc_artifact(PROJECT, "EU/1")),
        &config,
        "/world/vertex",
        INPUTS,
    );
    let (broker, ledger, outcome) = dispatch_counted(broker, "/world/vertex", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::RegionMismatch { .. }))
        ),
        "a location outside the host-label charset denies: {outcome:?}"
    );
    assert_denied_settles_without_accounting(&broker, &ledger);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the location denial sends zero requests"
    );

    let region = format!(
        "config_version = 1\n\
         [connections.{VERTEX}]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\nregion = \"{LOCATION}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{VERTEX}\", model_id = \"{MESSAGES_MODEL}\" }}\n\
         effort = {AUTO_EFFORT}\n\
         fallback = {{ mode = \"off\" }}\n",
        endpoint = server.uri(),
    );
    let config = Config::parse_validated(&region).expect("valid");
    let store = Arc::new(MapStore::new(STORE_KIND));
    let error =
        provider_result(config, store).expect_err("a configured region is not this binding");
    assert!(matches!(error, ProviderError::RegionMismatch { .. }));
}

/// The dialect keys on the literal connection id: another adapter refuses
/// `google-vertex`, and this adapter refuses every other id.
#[test]
fn dialect_is_keyed_on_the_literal_connection_id() {
    let config = Config::parse_validated(&vertex_config(
        "https://aiplatform.googleapis.com",
        GEMINI_MODEL,
        AUTO_EFFORT,
    ))
    .expect("valid");
    let store = Arc::new(MapStore::seeded(STORE_KIND, &[(CREDENTIAL_REF, API_KEY)]));
    let error = std::thread::spawn({
        let config = config.clone();
        let store = Arc::clone(&store);
        move || GeminiProvider::new(&config, VERTEX, store)
    })
    .join()
    .expect("thread joins")
    .expect_err("the Gemini adapter refuses the vertex literal");
    assert!(matches!(error, ProviderError::DialectMismatch { .. }));

    let error = std::thread::spawn({
        let config = config.clone();
        let store = Arc::clone(&store);
        move || VertexProvider::new(&config, "google", store)
    })
    .join()
    .expect("thread joins")
    .expect_err("the vertex adapter refuses another literal");
    assert!(matches!(error, ProviderError::DialectMismatch { .. }));
}

/// The recorded beta rides the Vertex body: a mutated epoch asks for the
/// drop policy, the body carries `anthropic_beta`, and no
/// `anthropic-beta` header ever rides the resource.
#[tokio::test]
async fn betas_ride_the_messages_body_never_the_header() {
    let server = MockServer::start().await;
    mount_stream(
        &server,
        &messages_path(PROJECT, LOCATION, MESSAGES_MODEL),
        messages_completed("after mutation", 2, 1),
    )
    .await;
    let config =
        Config::parse_validated(&vertex_config(&server.uri(), MESSAGES_MODEL, AUTO_EFFORT))
            .expect("valid");
    let (provider, _store) = vertex_provider(&config, &adc_artifact(PROJECT, LOCATION));
    let mut manifest = prepared_manifest(&config);
    manifest.epoch_id = "epoch-vertex".to_string();
    manifest.mutation_reason = Some("instructions".to_string());
    let (provider, outcome) = send_on_thread(provider, manifest);
    outcome.expect("the mutated send succeeds");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        header(&requests[0], "anthropic-beta"),
        None,
        "the resource carries betas in the body only"
    );
    let beta_bodies = received_bodies(&server).await;
    let body = &beta_bodies[0];
    assert_eq!(body["anthropic_beta"], json!([THINKING_BETA]));
    assert_eq!(
        body["thinking"]["block_binding"]["prefix_mismatch_behavior"],
        json!("drop_block"),
        "the recorded drop policy still rides the body"
    );
    assert_eq!(body["anthropic_version"], json!(VERTEX_VERSION));
}

/// A truncated stream is never success: the publisher class owes a
/// classifiable `finishReason`, and the Messages class owes
/// `message_stop`.
#[tokio::test]
async fn truncated_streams_are_never_success() {
    let server = MockServer::start().await;
    let partial_gemini = format!(
        "data: {}\n\n",
        json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "partial"}]},
                "index": 0,
            }],
        }),
    );
    mount_stream(
        &server,
        &adc_publisher_path(PROJECT, LOCATION, GEMINI_MODEL),
        partial_gemini,
    )
    .await;
    let partial_messages = [
        sse_block(
            "message_start",
            &json!({"type": "message_start", "message": {"usage": {"input_tokens": 1}}}),
        ),
        sse_block(
            "content_block_start",
            &json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            }),
        ),
        sse_block(
            "content_block_delta",
            &json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "partial"},
            }),
        ),
        sse_block(
            "content_block_stop",
            &json!({"type": "content_block_stop", "index": 0}),
        ),
    ]
    .concat();
    mount_stream(
        &server,
        &messages_path(PROJECT, LOCATION, MESSAGES_MODEL),
        partial_messages,
    )
    .await;

    for model in [GEMINI_MODEL, MESSAGES_MODEL] {
        let config = Config::parse_validated(&vertex_config(&server.uri(), model, AUTO_EFFORT))
            .expect("valid");
        let (broker, manifest) = prepared_with(
            vertex_provider(&config, &adc_artifact(PROJECT, LOCATION)),
            &config,
            "/world/vertex",
            INPUTS,
        );
        let (_broker, outcome) = dispatch(broker, "/world/vertex", manifest);
        assert!(
            matches!(
                outcome,
                Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
            ),
            "{model} owes a classifiable terminal: {outcome:?}"
        );
    }
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        2,
        "each entered send crossed the wire exactly once"
    );
}

/// TP-PROVIDER-INSTALLED::google-vertex = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::google-vertex = NOT_RUN"]
fn provider_installed_google_vertex() {}
