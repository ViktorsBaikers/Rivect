//! OpenAI Responses-dialect provider proof legs (TP-PROVIDER-{CATALOG,
//! AUTH,WIRE,RECOVERY,INSTALLED}::{openai,abliteration,meta,ollama,openrouter,
//! sakana,custom-responses,openai-codex,openai-codex-device}):
//! the configured literal Responses connections each return a verified
//! model outcome through the standard Broker — the real synchronous
//! adapter against the source-derived protocol peer as localhost
//! wiremock fixtures, no OMP, no user adapter, no real host. `ollama`
//! is the credential-optional local class whose catalogue carries the
//! bounded native discovery overlay; `openrouter` is the catalogue-only
//! keyless class behind the recorded paste-key form; `custom-responses`
//! records the operator-configured custom origin with an absent-binding
//! headerless form. The SSE legs pin
//! the shared parser's WHATWG §9.2.5–9.2.6 conformance.
//! TP-PROVIDER-INSTALLED::{openai,meta,ollama,openrouter,sakana,custom-responses,
//! openai-codex} stays NOT_RUN — the ignored named cases carry that status
//! explicitly, and `openai-codex::class-002` WebSocket stays NOT_RUN (DEC-017).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/discard conveniences; src/ stays strict (standards §14)"
)]

use rivect::config::{Config, ConnKind, EffortLevel};
use rivect::model::{Broker, ModelError, RejectionCause, RequestManifest};
use rivect::providers::local::ChatCompletionsProvider;
use rivect::providers::openai::OpenAiProvider;
use rivect::providers::sse::{SseError, SseParser};
use rivect::providers::{
    CatalogModel, Dialect, ModelPrice, Provider, ProviderError, ProviderReply, StoreKind,
    TransportCause, TransportClass,
};
use rivect::resources::UsageDelta;
use serde_json::{Value, json};
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

mod support;

use support::{
    SlowStore, drop_blocking, mount_responses, prepared_with, received_bodies,
    responses_completed_stream, send_on_thread, sse_block,
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
) -> (Broker, Result<ProviderReply, ModelError>) {
    let world = world.to_string();
    std::thread::spawn(move || {
        let outcome = broker.dispatch(&mut rivect::model::NullLedger, &world, &manifest);
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
            let replay =
                broker.dispatch(&mut rivect::model::NullLedger, "/world/openai", &manifest);
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
    let err = provider_result(config.clone(), "google-vertex".to_string(), store)
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

// ----- TP-PROVIDER-CATALOG::shared record (DEC-007) -----------------

/// Both catalogue surfaces of one Responses provider, on a plain OS
/// thread: the client's shell runtime cannot be built inside a tokio
/// context, and the provider comes back for a blocking drop.
fn catalogue_surfaces(
    provider: OpenAiProvider,
) -> (OpenAiProvider, Vec<String>, Vec<CatalogModel>) {
    std::thread::spawn(move || {
        let ids = provider.catalog().expect("the id-only catalogue answers");
        let models = provider.catalog_models().expect("the rich sibling answers");
        (provider, ids, models)
    })
    .join()
    .expect("the catalog thread joins")
}

/// The id-only surface stays byte-for-byte the same and the rich
/// sibling is additive: the same sorted ids, and one shared record per
/// id whose metadata is still the default — per-id entry rules stay
/// uncarried.
fn assert_id_only_surface(provider: OpenAiProvider, expected: &[&str]) {
    let (provider, ids, models) = catalogue_surfaces(provider);
    drop_blocking(provider);
    let expected_ids: Vec<String> = expected.iter().map(|id| (*id).to_string()).collect();
    assert_eq!(
        ids, expected_ids,
        "the id-only catalogue surface is unchanged"
    );
    let expected_models: Vec<CatalogModel> = expected
        .iter()
        .map(|id| CatalogModel {
            id: (*id).to_string(),
            ..CatalogModel::default()
        })
        .collect();
    assert_eq!(
        models, expected_models,
        "the rich sibling adds the shared record with the existing ids and default metadata"
    );
    assert!(
        models.iter().all(|model| model.max_output_tokens.is_none()),
        "no entry rule states a maximum-output cap"
    );
}

/// Every record carries its id alone: the literal id's catalogue rule
/// left the shared metadata at its default.
fn assert_default_records(models: &[CatalogModel]) {
    for model in models {
        assert_eq!(
            model,
            &CatalogModel {
                id: model.id.clone(),
                ..CatalogModel::default()
            },
            "`{}` keeps the default record — no entry rule",
            model.id
        );
    }
}

/// The rich catalogue mirrors the id-only answer for every Responses
/// id: `openai` keeps its filtered sample, `abliteration` and `meta`
/// keep their authoritative listing plus static seed, and the new
/// shared record adds no metadata beyond the id.
#[tokio::test]
async fn responses_catalogue_keeps_the_id_only_surface() {
    // openai: the recorded sample filters and sorts the listing.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"id": "o3"},
                {"id": "dall-e-3"},
                {"id": "gpt-5.2"},
            ],
        })))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = openai_provider(&config);
    assert_id_only_surface(provider, &["gpt-5.2", "o3"]);

    // abliteration: the authoritative listing merges the static seed.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.abliteration]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"abliteration\", model_id = \"abliterated-model\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let provider = provider_result(config, "abliteration".to_string(), store)
        .expect("the shared adapter builds for the abliteration id");
    assert_id_only_surface(
        provider,
        &[
            "abliterated-model",
            "abliterated-model-large",
            "abliterated-model-large-v2",
        ],
    );

    // meta: the authoritative listing merges the static Muse floor.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&meta_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = meta_provider(&config);
    assert_id_only_surface(provider, &META_FLOOR);
}

/// The rich catalogue carries each Responses id's recorded entry rule:
/// `ollama` maps the native metadata onto the offers its own listing
/// named, while `openai`, `abliteration` and `meta` carry the default
/// record for every id and never probe the native overlay. The gate is
/// the literal `ollama` id, so a widened gate shows up as a
/// `/api/tags` request on a connection that records no native
/// discovery.
#[tokio::test]
async fn responses_catalogue_carries_the_recorded_entry_rule() {
    // ollama: the entry rule rides the listed offers, and an id the
    // native probe never answered for stays at the default.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "enriched"}, {"id": "listing-only"}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .and(body_partial_json(json!({"model": "enriched"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "capabilities": ["thinking", "vision"],
            "num_ctx": 4096,
        })))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&ollama_config(&server_uri_v1(&server))).expect("valid");
    let models = ollama_catalog(ollama_provider(&config).0);
    assert_eq!(
        models,
        vec![
            CatalogModel {
                id: "enriched".to_string(),
                reasoning: true,
                vision: true,
                context_window: Some(4096),
                max_output_tokens: Some(8_192),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "listing-only".to_string(),
                ..CatalogModel::default()
            },
        ],
        "the native entry rule rides the listed offers only"
    );

    // openai: the sample filter plus the default record, no native probe.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "gpt-5.2"}, {"id": "dall-e-3"}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    let (provider, ids, models) = catalogue_surfaces(openai_provider(&config).0);
    drop_blocking(provider);
    assert_eq!(ids, vec!["gpt-5.2".to_string()]);
    assert_default_records(&models);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        count_path(&requests, "/api/tags"),
        0,
        "`openai` records no native discovery — the overlay never runs"
    );

    // abliteration: the static floor plus the default record, no
    // native probe.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.abliteration]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"abliteration\", model_id = \"abliterated-model\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, SECRET)],
    ));
    let provider = provider_result(config, "abliteration".to_string(), store)
        .expect("the shared adapter builds for the abliteration id");
    let (provider, ids, models) = catalogue_surfaces(provider);
    drop_blocking(provider);
    assert_eq!(
        ids,
        vec![
            "abliterated-model".to_string(),
            "abliterated-model-large".to_string(),
            "abliterated-model-large-v2".to_string(),
        ],
        "the authoritative floor keeps its ids and the default record"
    );
    assert_default_records(&models);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        count_path(&requests, "/api/tags"),
        0,
        "`abliteration` records no native discovery — the overlay never runs"
    );

    // meta: the static floor plus the default record, no native probe.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&meta_config(&server_uri_v1(&server))).expect("valid");
    let (provider, ids, models) = catalogue_surfaces(meta_provider(&config).0);
    drop_blocking(provider);
    assert_eq!(ids.len(), META_FLOOR.len());
    assert_default_records(&models);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        count_path(&requests, "/api/tags"),
        0,
        "`meta` records no native discovery — the overlay never runs"
    );
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

/// The rich catalogue's denials are the same typed errors the id-only
/// surface reports: both read the one listing leg, so an over-bound
/// payload denies `catalog_models()` exactly as `catalog()` denies it —
/// never a second, differently-typed failure path.
#[tokio::test]
async fn catalogue_models_denies_with_the_same_typed_error_as_catalog() {
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
    let (provider, models, ids) = std::thread::spawn(move || {
        let models = provider.catalog_models();
        let ids = provider.catalog();
        (provider, models, ids)
    })
    .join()
    .expect("the catalog thread joins");
    drop_blocking(provider);

    let models = models.expect_err("an over-bound listing denies the rich catalogue");
    let ids = ids.expect_err("the id-only surface denies the same payload");
    let (
        ProviderError::StreamViolation {
            connection: models_connection,
            reason: models_reason,
        },
        ProviderError::StreamViolation {
            connection: ids_connection,
            reason: ids_reason,
        },
    ) = (&models, &ids)
    else {
        panic!("both surfaces land the payload violation: {models:?} / {ids:?}");
    };
    assert_eq!(models_connection, ids_connection);
    assert_eq!(models_reason, ids_reason);
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
        Config::parse_validated(&openai_config(&format!("http://{address}/v1"))).expect("valid");
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
            OpenAiProvider::with_deadline(&config, "openai", store, Duration::from_millis(1500))?;
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
        Some(ProviderError::UnsupportedCredentialClass { .. }) => "UnsupportedCredentialClass",
        Some(ProviderError::CredentialBaseMismatch { .. }) => "CredentialBaseMismatch",
        Some(ProviderError::DialectMismatch { .. }) => "DialectMismatch",
        Some(ProviderError::DialectUnserved { .. }) => "DialectUnserved",
        Some(ProviderError::ExternalBlocked { .. }) => "ExternalBlocked",
        Some(ProviderError::ModelClassUnresolved { .. }) => "ModelClassUnresolved",
        Some(ProviderError::UnpinnedModel { .. }) => "UnpinnedModel",
        Some(ProviderError::RegionMismatch { .. }) => "RegionMismatch",
        Some(ProviderError::EndpointRequired { .. }) => "EndpointRequired",
        Some(ProviderError::Transport { .. }) => "Transport",
        Some(ProviderError::ProviderFailed { .. }) => "ProviderFailed",
        Some(ProviderError::UnknownTerminal { .. }) => "UnknownTerminal",
        Some(ProviderError::StreamViolation { .. }) => "StreamViolation",
        Some(ProviderError::IncompatibleOutput { .. }) => "IncompatibleOutput",
        Some(ProviderError::UnsupportedParameter { .. }) => "UnsupportedParameter",
        Some(ProviderError::UnsendableRequest { .. }) => "UnsendableRequest",
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
        "adapter": "openai",
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
    let outcome = broker.dispatch(&mut rivect::model::NullLedger, "/world/openai", &manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::DialectUnserved { .. }))
        ),
        "a pin the broker's provider cannot serve is a typed denial: {outcome:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
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
    let outcome = broker.dispatch(&mut rivect::model::NullLedger, "/world/openai", &manifest);
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
        let outcome = broker.dispatch(&mut rivect::model::NullLedger, "/world/openai", &manifest);
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
        let outcome = broker.dispatch_fallback_choice(
            &mut rivect::model::NullLedger,
            "/world/openai",
            &attempt_id,
            "openai",
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
        let config = Config::parse_validated(&openai_config(&format!("http://{address}/v1")))
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
            // Darwin inherits the listener's nonblocking flag on accept.
            stream.set_nonblocking(false)?;
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
                OpenAiProvider::with_deadline(&config, "openai", store, Duration::from_millis(500))
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
        assert!(observed.starts_with(String::from("POST /v1/responses HTTP/1.1\r\n").as_bytes()));
        let outcome = outcome.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        let error = outcome.expect_err("the peer returns a transport denial");
        assert!(
            matches!(&error, ProviderError::Transport { connection, .. } if connection == "openai")
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
    let config = Config::parse_validated(&openai_config(&format!(
        "http://{}/v1",
        listener.local_addr().expect("address")
    )))
    .expect("valid");
    // An empty store would return CredentialAbsent if the expired-budget guard called it.
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let mut provider = OpenAiProvider::with_deadline(&config, "openai", store, Duration::ZERO)
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
    let config = Config::parse_validated(&openai_config(&format!(
        "http://{}/v1",
        listener.local_addr().expect("address")
    )))
    .expect("valid");
    let store = Arc::new(SlowStore {
        inner: support::MapStore::seeded(STORE_KIND, &[(CREDENTIAL_REF, SECRET)]),
        delay: Duration::from_millis(600),
    });
    let mut provider =
        OpenAiProvider::with_deadline(&config, "openai", store, Duration::from_millis(500))
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

    const ADAPTER: &str = "openai";
    const GUARD: &str = "RIVECT_H009_SEND_CHILD";
    const CHILD_PREFIX: &str = "RIVECT_SEND_CHILD ";
    const CLEAN: &str = "RIVECT_SEND_TEARDOWN clean";
    const TEST: &str = "dribbling_peer_cannot_park_the_send_past_the_deadline";
    const LIMIT: usize = 1;

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
        UnsupportedCredentialClass,
        CredentialBaseMismatch,
        DialectMismatch,
        DialectUnserved,
        ExternalBlocked,
        ModelClassUnresolved,
        UnpinnedModel,
        RegionMismatch,
        EndpointRequired,
        Transport,
        ProviderFailed,
        UnknownTerminal,
        StreamViolation,
        IncompatibleOutput,
        UnsupportedParameter,
        UnsendableRequest,
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
            ProviderError::UnsupportedCredentialClass { .. } => {
                ProviderVariant::UnsupportedCredentialClass
            }
            ProviderError::CredentialBaseMismatch { .. } => ProviderVariant::CredentialBaseMismatch,
            ProviderError::DialectMismatch { .. } => ProviderVariant::DialectMismatch,
            ProviderError::DialectUnserved { .. } => ProviderVariant::DialectUnserved,
            ProviderError::ExternalBlocked { .. } => ProviderVariant::ExternalBlocked,
            ProviderError::ModelClassUnresolved { .. } => ProviderVariant::ModelClassUnresolved,
            ProviderError::UnpinnedModel { .. } => ProviderVariant::UnpinnedModel,
            ProviderError::RegionMismatch { .. } => ProviderVariant::RegionMismatch,
            ProviderError::EndpointRequired { .. } => ProviderVariant::EndpointRequired,
            ProviderError::Transport { .. } => ProviderVariant::Transport,
            ProviderError::ProviderFailed { .. } => ProviderVariant::ProviderFailed,
            ProviderError::UnknownTerminal { .. } => ProviderVariant::UnknownTerminal,
            ProviderError::StreamViolation { .. } => ProviderVariant::StreamViolation,
            ProviderError::IncompatibleOutput { .. } => ProviderVariant::IncompatibleOutput,
            ProviderError::UnsupportedParameter { .. } => ProviderVariant::UnsupportedParameter,
            ProviderError::UnsendableRequest { .. } => ProviderVariant::UnsendableRequest,
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
    fn primary(outcome: Result<ProviderReply, ProviderError>) -> Primary {
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
                if lines.next() != Some("POST /v1/responses HTTP/1.1") {
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
                if !(body["model"] == "gpt-5.2"
                    && body["stream"] == true
                    && body["input"]
                        == json!([{"role":"user","content":[{"type":"input_text","text":"goal: auth leg"}]}]))
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
        Config::parse_validated(&openai_config(&endpoint)).expect("the fixture config is valid");
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
                let built = OpenAiProvider::with_deadline(
                    &config,
                    "openai",
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
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused bearer is transport: {err}")
    };
    assert_eq!(connection, "openai");
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

/// A `local` declaration of the shipped `openai` id that binds a
/// `profile` is the same contradiction: the kind says local endpoint
/// while the profile reaches real material. The adapter names the
/// contradictory profile binding before any credential resolution, so
/// the seeded key is never read and no wire leg runs.
#[tokio::test]
async fn openai_local_profile_declaration_never_sends() {
    let server = MockServer::start().await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.openai]\nkind = \"local\"\nendpoint = \"{}\"\nprofile = \"p1\"\n\
         [profiles.p1]\ncredential_ref = \"keyring:rivect-test/p1\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"openai\", model_id = \"gpt-5.2\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\nfallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("the contradictory declaration is admitted at ingress");
    assert_eq!(config.connections["openai"].profile.as_deref(), Some("p1"));

    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[("keyring:rivect-test/p1", SECRET)],
    ));
    let err = provider_result(config, "openai".to_string(), store)
        .expect_err("the local declaration never resolves the profile's material");
    match &err {
        ProviderError::LocalProfileDeclared { connection } => {
            assert_eq!(connection, "openai");
            let rendered = err.to_string();
            assert!(
                rendered.contains("profile") && rendered.contains("openai"),
                "the denial names the profile member and the connection: {rendered}"
            );
        }
        other => panic!("the local profile form is the named profile denial, not {other:?}"),
    }
    assert_no_secret_or_body(&err);

    let requests = server.received_requests().await.expect("recorded");
    assert!(requests.is_empty(), "no wire leg ran: {requests:?}");
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
/// refusal before any byte is sent, never a silent truncation.
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
        matches!(outcome, Err(ProviderError::UnsendableRequest { .. })),
        "an over-bound replay body is a typed refusal: {outcome:?}"
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

// ----- meta -------------------------------------------------------------
//
// The `meta` connection's proof legs (HZN-008 class B, the band's only
// Responses id, EDGE-008): the shared Responses adapter serves the
// literal id over the recorded `api.meta.ai/v1` base — no copied codec
// — under the connection's own recorded predicates. `/models` is
// authoritative and merges the static Muse roster as the offer floor:
// an empty listing still answers the floor, while a failed listing is
// a typed denial — this owner carries no `floor_or` twin, the
// divergence is asserted rather than assumed. The record names an
// excluded-id filter but never its contents, so no roster exclusion is
// asserted; the recorded `x-api-version: 1.0.0` transport header has
// no seam on this adapter and stays a bounded residual (HZN-005). The
// record states no encrypted reasoning artifact for the id, so the
// request never asks for the include, and the Standard-or-Contributor
// payment predicate is stated by the model id itself, never chosen
// silently.

/// The scoped credential ref the `meta` connection binds.
const META_REF: &str = "keyring:rivect-test/meta";

/// The pinned model id the fixed-pin `meta` legs carry — one of the
/// recorded static Muse roster ids (HZN-008).
const META_MODEL: &str = "muse-spark-1.3";

/// The recorded static Muse roster the `meta` catalogue merges as the
/// offer floor, in the sorted order the adapter returns.
const META_FLOOR: [&str; 5] = [
    "muse-spark-1.1",
    "muse-spark-1.2",
    "muse-spark-1.2-contributor",
    "muse-spark-1.3",
    "muse-spark-1.3-contributor",
];

/// One configured `meta` connection pointing at the fixture peer: the
/// api_key auth class resolves a scoped `SecretRef`, the dialect comes
/// from the literal connection id, and the endpoint carries the API
/// base's `/v1` segment verbatim — like the recorded `api.meta.ai/v1`.
fn meta_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.meta]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{META_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"meta\", model_id = \"{META_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn meta_provider(config: &Config) -> (OpenAiProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[(META_REF, SECRET)]));
    let provider = provider_result(config.clone(), "meta".to_string(), store.clone())
        .expect("the shared adapter builds for the meta id");
    (provider, store)
}

// ----- TP-PROVIDER-WIRE::meta --------------------------------------

/// A configured `meta` connection returns a verified model outcome
/// through the standard Broker: prepare admits the api_key pin, the
/// shared adapter posts exactly the frozen manifest as a Responses
/// request — `store: false`, `stream: true`, pinned model,
/// instructions, tool surface and pinned effort verbatim, and no
/// `include` member, since the record states no encrypted reasoning
/// artifact for the id — the SSE stream validates its terminal, and
/// the one physical send is charged once with the provider's reported
/// usage.
#[tokio::test]
async fn meta_valid_control_yields_one_outcome_and_one_physical_usage() {
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
    let config = Config::parse_validated(&meta_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        meta_provider(&config),
        &config,
        "/world/meta",
        "goal: prove the wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/meta", manifest.clone());
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
    assert_eq!(body["model"], META_MODEL);
    assert_eq!(body["store"], false);
    assert_eq!(body["stream"], true);
    assert!(
        body.get("include").is_none(),
        "the record states no encrypted reasoning artifact for the id — the include is never requested: {body}"
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
    assert_eq!(record.connection, "meta");
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
            let replay = broker.dispatch(&mut rivect::model::NullLedger, "/world/meta", &manifest);
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
/// adapter, the Chat-Completions adapter refuses `meta` outright —
/// the same id, the same store, still a dialect mismatch, never a
/// served connection (EDGE-008) — a manifest pinning a different
/// connection id is refused at send, and `dialect_for` reserving
/// `meta` means the id is never fixture-served even when it declares
/// `local` kind.
#[test]
fn meta_dialect_is_keyed_on_the_literal_connection_id() {
    let config = Config::parse_validated(&meta_config("http://127.0.0.1:1/v1")).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = provider_result(config.clone(), "meta-plus".to_string(), store)
        .expect_err("a different literal id is not this dialect");
    assert!(matches!(err, ProviderError::DialectMismatch { .. }));

    // the Chat-Completions adapter refuses the same id — `meta` rides
    // the Responses dialect, never the other way
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let built = config.clone();
    let err = std::thread::spawn(move || ChatCompletionsProvider::new(&built, "meta", store))
        .join()
        .expect("the provider thread joins")
        .expect_err("the CC adapter refuses the Responses id");
    assert!(
        matches!(err, ProviderError::DialectMismatch { .. }),
        "a CC arm for `meta` is a dialect mismatch, not a served connection"
    );

    // a dialect-reserved id is never fixture-served whatever kind it
    // declares — `meta` pinned `local` keeps the typed denial
    let local = Config::parse_validated(
        "config_version = 1\n\
         [connections.meta]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"meta\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"medium\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let loopback = rivect::providers::LoopbackProvider::new();
    let entry = local.connections.get("meta").expect("declared");
    assert!(
        !loopback.serves("meta", entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );

    // a manifest pinning a different connection id is refused at send
    let (provider, _store) = meta_provider(&config);
    let foreign = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.other]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1/v1\"\ncredential_ref = \"{META_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"other\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let manifest = {
        let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
        broker
            .prepare("main", &foreign, "/world/meta", "goal: x")
            .expect("foreign pin prepares")
    };
    let (provider, outcome) = send_on_thread(provider, manifest);
    assert!(
        matches!(outcome, Err(ProviderError::DialectMismatch { .. })),
        "a foreign pin never speaks this dialect: {outcome:?}"
    );
    drop_blocking(provider);
}

// ----- TP-PROVIDER-CATALOG::meta ------------------------------------

/// `/models` is authoritative for `meta` (HZN-008): every `data[]` id
/// with a non-empty body is offered, and the recorded static Muse
/// roster merges on top as the offer floor — an empty-`data` 200
/// listing still answers the floor alone, the union deduplicates and
/// sorts, and the bearer credential came through the store seam.
#[tokio::test]
async fn meta_static_floor_survives_an_empty_listing() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [],
        })))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&meta_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = meta_provider(&config);
    let ids = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("the catalog thread joins")
        .expect("an empty listing still answers the recorded floor");
    assert_eq!(
        ids,
        META_FLOOR
            .iter()
            .map(|id| (*id).to_string())
            .collect::<Vec<_>>(),
        "the static Muse roster survives an empty listing"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(received_auth(&requests[0]), format!("Bearer {SECRET}"));

    // a populated listing merges its own ids with the floor — the
    // floor is additive, never a replacement for the listing
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [
                {"id": "muse-spark-2.0"},
                {"id": "muse-spark-1.3"},
                {"id": ""},
                {"owned_by": "nobody"},
            ],
        })))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&meta_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = meta_provider(&config);
    let ids = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("the catalog thread joins")
        .expect("the populated listing answers");
    let mut expected: Vec<String> = META_FLOOR.iter().map(|id| (*id).to_string()).collect();
    expected.push("muse-spark-2.0".to_string());
    expected.sort();
    assert_eq!(
        ids, expected,
        "the authoritative listing and the static roster merge, sorted and deduplicated"
    );
}

/// A non-success `/models` status is the typed transport denial for
/// `meta` — this owner carries no `floor_or` twin, so a failed listing
/// answers no floor: the divergence from the CC adapter's seeded
/// fallback is asserted rather than assumed.
#[tokio::test]
async fn meta_failed_listing_denies_typed_without_a_floor() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&meta_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = meta_provider(&config);
    let outcome = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("the catalog thread joins");
    let ProviderError::Transport { connection, cause } =
        &outcome.expect_err("a failed listing denies typed — never a silent floor")
    else {
        unreachable!("the failed listing's denial is transport-typed")
    };
    assert_eq!(connection, "meta");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 503 },
        "the listing's own status is the denial's context: {cause}"
    );
}

/// A `/models` HTTP 200 is never entitlement (INV-010) for `meta`:
/// with the scoped key enrolled the fixed pin still rides only its
/// request leg, and a listing answering the pinned id neither stands
/// in for the credential nor admits the send — the unmounted
/// `/v1/responses` peer answers the typed transport denial while the
/// 200 listing is never consulted.
#[tokio::test]
async fn meta_models_http_200_is_never_entitlement() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": META_MODEL}],
        })))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&meta_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = meta_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a 200 catalogue never releases the pin");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the unmounted request leg is the typed transport denial: {err:?}");
    };
    assert_eq!(connection, "meta");
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
    assert_eq!(requests[0].url.path(), "/v1/responses");
}

/// The request never carries an `include` member (DEC-013): the record
/// states no encrypted reasoning artifact for `meta`, so the request
/// asks for none — and the dialect's other recorded ids keep their own
/// predicates: `openai`'s recorded include still rides its own request,
/// because the suppression binds the literal `meta` id, never the
/// shared Responses dialect.
#[tokio::test]
async fn meta_request_carries_no_reasoning_artifact_include() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream("answered", Vec::new(), None),
    )
    .await;
    let config = Config::parse_validated(&meta_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = meta_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    outcome.expect("the meta send completes");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert!(
        body.get("include").is_none(),
        "the record states no encrypted reasoning artifact — the request asks for none: {body}"
    );

    // the non-suppressed arm: `openai` keeps its own recorded
    // predicate — the artifact include stays on for the dialect's
    // other id
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream("openai", Vec::new(), None),
    )
    .await;
    let openai = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.openai]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{META_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"openai\", model_id = \"gpt-5.2\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[(META_REF, SECRET)]));
    let provider = provider_result(openai.clone(), "openai".to_string(), store)
        .expect("the shared adapter builds for openai too");
    let manifest = {
        let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
        broker
            .prepare("main", &openai, "/world/meta", "goal: openai arm")
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

// ----- TP-PROVIDER-AUTH::meta ---------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `meta`: a configured region — the recorded contract names none —
/// the profile-bound ref whose scope disagrees with the binding, an
/// absent credential and a refused bearer token each land a typed
/// denial, and none of them, nor any Debug surface the boundary
/// exposes, renders credential material or the peer's body.
#[tokio::test]
async fn meta_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(&meta_config(&server_uri_v1(&server)).replace(
        "kind = \"api_key\"",
        "kind = \"api_key\"\nregion = \"eu-1\"",
    ))
    .expect("valid");
    let err = provider_result(
        regioned,
        "meta".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, SECRET)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "meta");
    assert_eq!(region, "eu-1");
    assert_no_secret_or_body(&err);

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.meta]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"meta\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "meta".to_string(),
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
    let config = Config::parse_validated(&meta_config(&server_uri_v1(&server))).expect("valid");
    let provider = provider_result(
        config.clone(),
        "meta".to_string(),
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
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[(META_REF, SECRET)]));
    let provider = provider_result(config.clone(), "meta".to_string(), store).expect("builds");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused token is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused token is transport: {err}")
    };
    assert_eq!(connection, "meta");
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
    let config = Config::parse_validated(&meta_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[(META_REF, SECRET)]));
    let provider =
        provider_result(config.clone(), "meta".to_string(), store).expect("the adapter builds");
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
        meta_provider(&config),
        &config,
        "/world/meta",
        "goal: debug surfaces",
    );
    assert!(
        !format!("{manifest:?}").contains(SECRET),
        "manifest Debug never carries credential material"
    );
    let (broker, outcome) = dispatch(broker, "/world/meta", manifest.clone());
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
        "auth-debug-meta",
        Some(&meta_config(&server_uri_v1(&server))),
    );
    assert!(
        !format!("{:?}", world.runtime).contains(SECRET),
        "runtime Debug never carries credential material"
    );
}

// ----- TP-PROVIDER-RECOVERY::meta ------------------------------------

/// A typed denial is recoverable through the same seam: the absent
/// credential denies the first send, enrolling material at the scope
/// admits the retry — no state wedged, no plaintext path taken.
#[tokio::test]
async fn meta_typed_denial_recovers_through_the_same_credential_seam() {
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
    let config = Config::parse_validated(&meta_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "meta".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialAbsent { .. })
    ));

    store.enroll(META_REF, SECRET.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the enrolled credential admits the retry");
    assert_eq!(reply.text, "recovered");
    drop_blocking(provider);
}

/// Adverse wire input never reports success: a stream ending mid
/// `function_call` item is a partial-tool violation, an EOF without a
/// terminal is the unknown terminal, a `function_call` naming a tool
/// the frozen request never declared is incompatible output, and a
/// reasoning item carrying `encrypted_content` is the provenance
/// denial — the record states no artifact for the id, so any present
/// member, whatever its value, is off-contract foreign material. The
/// peer's normal blobless reasoning item is not a failure leg at all:
/// it is tolerated — dropped from the lineage, the reply unaffected,
/// the one send charged once.
#[tokio::test]
async fn meta_adverse_wire_input_never_reports_success() {
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
    let config = Config::parse_validated(&meta_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        meta_provider(&config),
        &config,
        "/world/meta",
        "goal: partial item",
    );
    let (broker, outcome) = dispatch(broker, "/world/meta", manifest);
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
    let config = Config::parse_validated(&meta_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        meta_provider(&config),
        &config,
        "/world/meta",
        "goal: no terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/meta", manifest);
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
    let config = Config::parse_validated(&meta_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        meta_provider(&config),
        &config,
        "/world/meta",
        "goal: undeclared call",
    );
    let (broker, outcome) = dispatch(broker, "/world/meta", manifest);
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

    // a blobless reasoning item is the recorded peer's tolerated
    // shape — the record states no artifact for the id: the item is
    // dropped from the lineage rather than adopted, the reply is
    // unaffected and the one send charges once
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
    let config = Config::parse_validated(&meta_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        meta_provider(&config),
        &config,
        "/world/meta",
        "goal: blobless reasoning",
    );
    let (broker, outcome) = dispatch(broker, "/world/meta", manifest);
    let reply = outcome.expect("a blobless reasoning item is the peer's tolerated shape");
    assert_eq!(reply.text, "answered");
    assert!(reply.tool_calls.is_empty());
    assert_eq!(
        broker.accounted_requests(),
        1,
        "the tolerated item still charges the one send"
    );
    drop_blocking(broker);

    // a reasoning item carrying `encrypted_content` is off-contract
    // foreign material where the record states none — the provenance
    // denial, refused and never adopted
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
    let config = Config::parse_validated(&meta_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        meta_provider(&config),
        &config,
        "/world/meta",
        "goal: foreign artifact",
    );
    let (broker, outcome) = dispatch(broker, "/world/meta", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(
                ProviderError::ReasoningProvenance { .. }
            ))
        ),
        "a reasoning item carrying an artifact the record never states is the provenance denial: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);
}

/// The legs matrix enforces the recorded expected set for `meta`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside this
/// run, and INSTALLED reports NOT_RUN — an omitted leg fails the suite
/// rather than silently absenting.
#[tokio::test]
async fn meta_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "muse-spark-1.3"}],
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
    let config = Config::parse_validated(&meta_config(&server_uri_v1(&server))).expect("valid");

    // CATALOG: the authoritative listing plus the static Muse floor
    // answer through the credential seam.
    let (provider, _) = meta_provider(&config);
    let catalog = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("catalog thread joins");
    reported.insert(
        "CATALOG",
        if matches!(catalog, Ok(ref ids) if ids == &META_FLOOR.iter().map(|id| (*id).to_string()).collect::<Vec<_>>()) {
            "PASS"
        } else {
            "FAIL"
        },
    );

    // AUTH: an empty store denies at send with the typed verdict.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), "meta".to_string(), empty).expect("binding resolves");
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
        meta_provider(&config),
        &config,
        "/world/meta",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/meta", manifest);
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
        provider_result(config.clone(), "meta".to_string(), empty.clone()).expect("resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(META_REF, SECRET.as_bytes());
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
    // `provider_installed_meta` case below: its ignored count is the
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

// ----- TP-PROVIDER-INSTALLED::meta ----------------------------------

/// TP-PROVIDER-INSTALLED::meta = NOT_RUN: the installed-provider proof
/// is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::meta = NOT_RUN"]
fn provider_installed_meta() {}

// ----- ollama ------------------------------------------------------------
//
// The local `ollama` id records the OpenAI Responses surface under its
// `/v1` base with an optional credential and a bounded native discovery
// overlay (DEC-009/DEC-011/DEC-012). The configured base serves both the
// listing and the inference leg; `/models` is the offer set, while the
// unauthenticated native `/api/tags` + `/api/show` chain only enriches
// ids the listing already named — it never adds an offer, never runs
// past 32 ids or one 250 ms advisory phase, and a failed probe leaves
// the listing-only entry.

const OLLAMA_REF: &str = "keyring:rivect-test/ollama";

const OLLAMA_MODEL: &str = "llama3.2:3b";

/// One keyless `api_key` declaration for `ollama` — the adopted
/// absent-binding form; no `credential_ref` member.
fn ollama_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.ollama]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"ollama\", model_id = \"{OLLAMA_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The same declaration with a scoped binding — the optional class's
/// authenticated half.
fn ollama_bound_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.ollama]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{OLLAMA_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"ollama\", model_id = \"{OLLAMA_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The class's recorded `local` declaration — the second keyless form,
/// carrying no credential at all.
fn ollama_local_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.ollama]\nkind = \"local\"\nendpoint = \"{endpoint}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"ollama\", model_id = \"{OLLAMA_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn ollama_provider(config: &Config) -> (OpenAiProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "ollama".to_string(), store.clone())
        .expect("the shared adapter builds for the keyless ollama id");
    (provider, store)
}

/// The same adapter under an explicit whole-call deadline, so the
/// advisory overlay's share of the budget is exercised deterministically.
fn ollama_provider_with_deadline(
    config: &Config,
    deadline: Duration,
) -> (OpenAiProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let handle = Arc::clone(&store);
    let config = config.clone();
    let provider = std::thread::spawn(move || {
        OpenAiProvider::with_deadline(&config, "ollama", handle, deadline)
    })
    .join()
    .expect("the provider thread joins")
    .expect("the shared adapter builds under the short deadline");
    (provider, store)
}

fn ollama_bound_provider(config: &Config) -> (OpenAiProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(OLLAMA_REF, SECRET)],
    ));
    let provider = provider_result(config.clone(), "ollama".to_string(), store.clone())
        .expect("the shared adapter builds for the bound ollama id");
    (provider, store)
}

/// The rich catalogue result on a plain OS thread: the blocking client
/// cannot be built or dropped inside a tokio context, and the provider
/// comes back for a blocking drop.
fn ollama_catalog_result(
    provider: OpenAiProvider,
) -> (OpenAiProvider, Result<Vec<CatalogModel>, ProviderError>) {
    std::thread::spawn(move || {
        let outcome = provider.catalog_models();
        (provider, outcome)
    })
    .join()
    .expect("the catalog thread joins")
}

/// The rich catalogue on a plain OS thread: the blocking client cannot
/// be dropped inside a tokio context.
fn ollama_catalog(provider: OpenAiProvider) -> Vec<CatalogModel> {
    let (provider, outcome) = ollama_catalog_result(provider);
    drop_blocking(provider);
    outcome.expect("the ollama catalogue answers")
}

/// A catalogue that spends its whole-call budget either denies the
/// typed deadline or answers inside it: a late listing-only answer is
/// exactly the unbounded overlay the shared budget exists to prevent.
fn assert_catalogue_inside_the_deadline(
    outcome: Result<Vec<CatalogModel>, ProviderError>,
    elapsed: Duration,
    deadline: Duration,
) {
    match outcome {
        Err(ProviderError::Transport {
            cause: TransportCause::Deadline { budget },
            ..
        }) => assert_eq!(budget, deadline, "the denial names the whole-call budget"),
        Ok(models) => assert!(
            elapsed < deadline,
            "a catalogue must answer inside its {deadline:?} budget, not after {elapsed:?}: {} offers",
            models.len()
        ),
        Err(other) => panic!("a stalled native peer is the typed deadline, not {other:?}"),
    }
}

fn request_paths(requests: &[Request]) -> Vec<&str> {
    requests
        .iter()
        .map(|request| request.url.path())
        .collect::<Vec<_>>()
}

fn count_path(requests: &[Request], path: &str) -> usize {
    requests
        .iter()
        .filter(|request| request.url.path() == path)
        .count()
}

// ----- TP-PROVIDER-WIRE::ollama -------------------------------------

/// A configured `ollama` connection returns a verified model outcome
/// through the standard Broker: prepare admits the keyless local pin,
/// the shared adapter posts the frozen manifest as a Responses request
/// under the configured `/v1` base — no `Authorization` header, since
/// the absent binding is the recorded unauthenticated form — and the
/// one physical send is charged exactly once with the reported usage.
#[tokio::test]
async fn ollama_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "verified local outcome",
            Vec::new(),
            Some(json!({"input_tokens": 13, "output_tokens": 5, "total_tokens": 18})),
        ),
    )
    .await;
    let config = Config::parse_validated(&ollama_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        ollama_provider(&config),
        &config,
        "/world/ollama",
        "goal: prove the local wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/ollama", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified local outcome");
    assert!(reply.tool_calls.is_empty());

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request");
    assert_eq!(requests[0].url.path(), "/v1/responses");
    assert!(
        requests[0].headers.get("authorization").is_none(),
        "the absent binding sends no Authorization header — never a fabricated key"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], OLLAMA_MODEL);
    assert_eq!(body["store"], false);
    assert_eq!(body["stream"], true);
    assert!(
        body.get("include").is_none(),
        "the local peer returns no encrypted reasoning artifact — the include is never requested: {body}"
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

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "ollama");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 13,
            completion_tokens: 5,
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
                broker.dispatch(&mut rivect::model::NullLedger, "/world/ollama", &manifest);
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

// ----- TP-PROVIDER-CATALOG::ollama ----------------------------------

/// The keyless discovery leg sends no credential on either the
/// configured `/models` listing or the unauthenticated native probes:
/// no header exists to fabricate, and the listing's ids are the offers.
#[tokio::test]
async fn ollama_keyless_listing_omits_the_authorization_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [
                {"id": "qwen3:8b", "object": "model"},
                {"id": OLLAMA_MODEL, "object": "model"},
            ],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "models": [{"name": OLLAMA_MODEL, "model": OLLAMA_MODEL}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&ollama_config(&server_uri_v1(&server))).expect("valid");
    let models = ollama_catalog(ollama_provider(&config).0);
    assert_eq!(
        models
            .iter()
            .map(|model| model.id.as_str())
            .collect::<Vec<_>>(),
        vec![OLLAMA_MODEL, "qwen3:8b"],
        "the listing is the offer set, sorted"
    );

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(count_path(&requests, "/v1/models"), 1);
    assert_eq!(count_path(&requests, "/api/tags"), 1);
    assert_eq!(count_path(&requests, "/api/show"), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.headers.get("authorization").is_none()),
        "no leg fabricates an Authorization header for the keyless form: {:?}",
        request_paths(&requests)
    );
}

/// The bound form resolves its scoped key for the listing and the send
/// (`Authorization: Bearer`), while the native discovery probes stay
/// unauthenticated — the recorded native base never receives the key.
#[tokio::test]
async fn ollama_bound_key_sends_the_bearer() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": OLLAMA_MODEL}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    mount_responses(
        &server,
        responses_completed_stream("bound local outcome", Vec::new(), None),
    )
    .await;
    let config =
        Config::parse_validated(&ollama_bound_config(&server_uri_v1(&server))).expect("valid");
    let models = ollama_catalog(ollama_bound_provider(&config).0);
    assert_eq!(models.len(), 1);
    let (provider, _store) = ollama_bound_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    outcome.expect("the bound send completes");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    let bearer = format!("Bearer {SECRET}");
    for request in &requests {
        let auth = request.headers.get("authorization");
        match request.url.path() {
            "/v1/models" => assert_eq!(
                auth.and_then(|value| value.to_str().ok()),
                Some(bearer.as_str()),
                "the listing carries the scoped bearer"
            ),
            "/v1/responses" => assert_eq!(
                auth.and_then(|value| value.to_str().ok()),
                Some(bearer.as_str()),
                "the send carries the scoped bearer"
            ),
            "/api/tags" | "/api/show" => assert!(
                auth.is_none(),
                "the native discovery probe is unauthenticated: {}",
                request.url.path()
            ),
            other => panic!("unexpected request path {other}"),
        }
    }
}

/// Native metadata enriches only ids the listing already offered:
/// `/api/tags` naming an id the listing omitted never adds an offer,
/// `capabilities` maps thinking/vision, and the first positive context
/// key follows `model_info.*.context_length`, then `num_ctx`, then
/// `context_window`.
#[tokio::test]
async fn ollama_native_metadata_enriches_listing_offers_only() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [
                {"id": "alpha"},
                {"id": "beta"},
                {"id": "num-ctx"},
                {"id": "window"},
                {"id": "zero-first"},
            ],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "models": [{"name": "gamma"}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .and(body_partial_json(json!({"model": "alpha"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "capabilities": ["completion", "thinking", "vision"],
            "model_info": {"llama.context_length": 4096},
            "num_ctx": 2048,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .and(body_partial_json(json!({"model": "num-ctx"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "num_ctx": 2048,
            "context_window": 1024,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .and(body_partial_json(json!({"model": "window"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "context_window": 3072,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .and(body_partial_json(json!({"model": "zero-first"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "model_info": {"a.context_length": 0, "b.context_length": 4096},
            "num_ctx": 2048,
        })))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&ollama_config(&server_uri_v1(&server))).expect("valid");
    let models = ollama_catalog(ollama_provider(&config).0);

    assert_eq!(
        models
            .iter()
            .map(|model| model.id.as_str())
            .collect::<Vec<_>>(),
        vec!["alpha", "beta", "num-ctx", "window", "zero-first"],
        "a native-only id is never offered"
    );
    let alpha = &models[0];
    assert!(alpha.reasoning, "`thinking` capability maps to reasoning");
    assert!(alpha.vision, "`vision` capability maps to vision");
    assert_eq!(
        alpha.context_window,
        Some(4096),
        "model_info.*.context_length outranks num_ctx"
    );
    assert_eq!(alpha.max_output_tokens, Some(8192));
    assert_eq!(
        models[1],
        CatalogModel {
            id: "beta".to_string(),
            ..CatalogModel::default()
        },
        "an id the native probe cannot enrich stays listing-only"
    );
    assert_eq!(
        models[2].context_window,
        Some(2048),
        "num_ctx outranks context_window"
    );
    assert_eq!(
        models[3].context_window,
        Some(3072),
        "context_window is the last recorded key"
    );
    assert_eq!(
        models[4].context_window,
        Some(4096),
        "the first positive model_info key wins — a zero never masks the next"
    );

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(count_path(&requests, "/v1/models"), 1);
    assert_eq!(count_path(&requests, "/api/tags"), 1);
    assert_eq!(count_path(&requests, "/api/show"), 5);
    assert!(
        request_paths(&requests)
            .iter()
            .all(|path| *path != "/v1/api/tags"),
        "the native base carries no trailing /v1"
    );
}

/// A failed native probe is non-fatal: a `/api/tags` failure skips the
/// show fanout entirely, and a failing `/api/show` leaves that id
/// listing-only — the catalogue still answers its `/models` offers.
#[tokio::test]
async fn ollama_native_metadata_failures_are_non_fatal() {
    // the tags leg fails: no show runs and the listing stands alone
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "alpha"}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&ollama_config(&server_uri_v1(&server))).expect("valid");
    let models = ollama_catalog(ollama_provider(&config).0);
    assert_eq!(
        models,
        vec![CatalogModel {
            id: "alpha".to_string(),
            ..CatalogModel::default()
        }],
        "a failed tags leg leaves the listing-only entry"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(count_path(&requests, "/api/show"), 0);

    // the show leg fails per id: the entry stays listing-only
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "alpha"}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&ollama_config(&server_uri_v1(&server))).expect("valid");
    let models = ollama_catalog(ollama_provider(&config).0);
    assert_eq!(
        models,
        vec![CatalogModel {
            id: "alpha".to_string(),
            ..CatalogModel::default()
        }],
        "a failed show leaves the listing-only entry"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(count_path(&requests, "/api/show"), 1);

    // a malformed show payload is the same non-fatal probe failure
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "alpha"}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&ollama_config(&server_uri_v1(&server))).expect("valid");
    let models = ollama_catalog(ollama_provider(&config).0);
    assert_eq!(
        models,
        vec![CatalogModel {
            id: "alpha".to_string(),
            ..CatalogModel::default()
        }],
        "an unreadable show payload is never an enrichment"
    );

    // a show body past the catalogue byte bound is a read-loop error,
    // not an enrichment and not a catalogue denial
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "alpha"}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(1024 * 1024 + 1)))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&ollama_config(&server_uri_v1(&server))).expect("valid");
    let models = ollama_catalog(ollama_provider(&config).0);
    assert_eq!(
        models,
        vec![CatalogModel {
            id: "alpha".to_string(),
            ..CatalogModel::default()
        }],
        "an over-bound show body is never an enrichment"
    );
}

/// The advisory phase is bounded twice, deterministically: a fast peer
/// still probes at most 32 listed ids, and a stalled native peer under
/// a short whole-call deadline never yields a catalogue past that
/// deadline — the typed deadline denial (or an answer inside the
/// deadline), never the unbounded listing-only answer a phase with its
/// own clock would produce.
#[tokio::test]
async fn ollama_native_metadata_phase_budget_bounds_the_fanout() {
    // at most 32 ids are probed even when the listing offers more
    let server = MockServer::start().await;
    let ids: Vec<Value> = (0..40)
        .map(|index| json!({"id": format!("model-{index:02}")}))
        .collect();
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": ids})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&ollama_config(&server_uri_v1(&server))).expect("valid");
    let models = ollama_catalog(ollama_provider(&config).0);
    assert_eq!(models.len(), 40, "every listing offer stands");
    let requests = server.received_requests().await.expect("recorded");
    let shows = count_path(&requests, "/api/show");
    assert_eq!(
        shows, 32,
        "a 40-id listing probes exactly the leading 32, got {shows}"
    );

    // a stalled `/api/tags` peer spends the whole call's remainder: the
    // catalogue answers the typed deadline, never a late listing-only
    // answer the recorded 250 ms advisory phase would have produced
    let deadline = Duration::from_millis(250);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": [{"id": "slow"}]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(1))
                .set_body_json(json!({"models": []})),
        )
        .mount(&server)
        .await;
    let config = Config::parse_validated(&ollama_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = ollama_provider_with_deadline(&config, deadline);
    let started = Instant::now();
    let (provider, outcome) = ollama_catalog_result(provider);
    let elapsed = started.elapsed();
    drop_blocking(provider);
    assert_catalogue_inside_the_deadline(outcome, elapsed, deadline);

    // the same bound on the show fanout: a fast tags leg followed by a
    // stalled first probe still answers inside the call's deadline
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "slow-show"}, {"id": "next"}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(1))
                .set_body_json(json!({})),
        )
        .mount(&server)
        .await;
    let config = Config::parse_validated(&ollama_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = ollama_provider_with_deadline(&config, deadline);
    let started = Instant::now();
    let (provider, outcome) = ollama_catalog_result(provider);
    let elapsed = started.elapsed();
    drop_blocking(provider);
    assert_catalogue_inside_the_deadline(outcome, elapsed, deadline);
}

/// The 250 ms advisory phase is a bound of its own, not whatever the
/// whole-call budget leaves: under a long whole-call deadline a peer
/// whose `/api/tags` answers after one second still leaves every entry
/// listing-only and fans out no `/api/show` — a phase riding the
/// whole-call clock would have spent that second, probed the ids and
/// enriched the record.
#[tokio::test]
async fn ollama_native_phase_budget_is_shorter_than_the_whole_call_deadline() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "slow-tags"}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(1))
                .set_body_json(json!({"models": [{"name": "slow-tags"}]})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "capabilities": ["thinking", "vision"],
            "model_info": {"slow.context_length": 65536},
        })))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&ollama_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = ollama_provider_with_deadline(&config, Duration::from_secs(5));
    let started = Instant::now();
    let models = ollama_catalog(provider);
    let elapsed = started.elapsed();
    // No clock seam records the phase timeout itself, so the clipped
    // one-second peer is the only observable discriminator: the 250 ms
    // phase answers near its budget, while a phase riding the
    // whole-call deadline would spend the full second.
    assert!(
        elapsed < Duration::from_millis(900),
        "the 250 ms phase clips the one-second tags peer, got {elapsed:?}"
    );
    assert_eq!(
        models,
        vec![CatalogModel {
            id: "slow-tags".to_string(),
            ..CatalogModel::default()
        }],
        "the expired phase leaves the listing-only record, never the late enrichment"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(count_path(&requests, "/api/tags"), 1);
    assert_eq!(
        count_path(&requests, "/api/show"),
        0,
        "an expired phase never fans the show probes out"
    );
}

/// The phase's 250 ms clock is a total, never a per-request reset: two
/// sorted ids under a long whole-call deadline each face a `/api/show`
/// that answers after 150 ms, so the first probe spends the phase's
/// bulk and the second is clipped to the remainder and times out — the
/// first entry enriched, the second listing-only. A per-request reset
/// would hand the second probe a fresh 250 ms and enrich both.
#[tokio::test]
async fn ollama_native_probe_clip_is_the_phase_total_not_a_per_request_reset() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "beta"}, {"id": "alpha"}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(150))
                .set_body_json(json!({
                    "capabilities": ["thinking", "vision"],
                    "model_info": {"qwen.context_length": 4096},
                })),
        )
        .mount(&server)
        .await;
    let config = Config::parse_validated(&ollama_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = ollama_provider_with_deadline(&config, Duration::from_secs(5));
    let models = ollama_catalog(provider);
    assert_eq!(
        models,
        vec![
            CatalogModel {
                id: "alpha".to_string(),
                reasoning: true,
                vision: true,
                context_window: Some(4096),
                max_output_tokens: Some(8192),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "beta".to_string(),
                ..CatalogModel::default()
            },
        ],
        "the second probe never gets a fresh phase clock"
    );
}

/// Defaults apply when the native metadata answers without a context
/// key: 128000 context and 8192 max output, with the capability marks
/// still derived from `capabilities`.
#[tokio::test]
async fn ollama_default_context_and_max_apply_when_absent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "solo"}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "capabilities": [],
            "model_info": {"solo.context_length": 0},
        })))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&ollama_config(&server_uri_v1(&server))).expect("valid");
    let models = ollama_catalog(ollama_provider(&config).0);
    assert_eq!(
        models,
        vec![CatalogModel {
            id: "solo".to_string(),
            reasoning: false,
            vision: false,
            context_window: Some(128_000),
            max_output_tokens: Some(8_192),
            ..CatalogModel::default()
        }],
        "a zero context is not positive; the recorded defaults apply"
    );
}

/// The configured base is the API base for both legs under this
/// adapter's normalization: the declaration is trimmed of whitespace
/// and of every trailing slash, so a whitespace-padded value reaches
/// the resolved base rather than a malformed URL — listing, inference
/// and the native probes all land there. The native base is one
/// trailing `/v1` stripped, never a re-inferred suffix. The
/// empty-after-trim arm resolves the recorded local default on the
/// resolution rule itself (`src/providers/openai.rs`), since the
/// recorded default host is a live local server this offline suite
/// never contacts.
#[tokio::test]
async fn ollama_configured_base_applies_to_listing_and_inference() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": OLLAMA_MODEL}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    mount_responses(
        &server,
        responses_completed_stream("configured base", Vec::new(), None),
    )
    .await;
    let padded = format!("  {}/  ", server_uri_v1(&server));
    let config = Config::parse_validated(&ollama_config(&padded)).expect("valid");
    let models = ollama_catalog(ollama_provider(&config).0);
    assert_eq!(models.len(), 1);
    let (provider, _store) = ollama_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    outcome.expect("the configured base serves inference");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(count_path(&requests, "/v1/models"), 1);
    assert_eq!(count_path(&requests, "/v1/responses"), 1);
    assert_eq!(count_path(&requests, "/api/tags"), 1);
    assert_eq!(count_path(&requests, "/api/show"), 1);
    assert_eq!(
        count_path(&requests, "/v1/api/tags"),
        0,
        "the native base strips exactly one trailing /v1"
    );
}

/// The recorded `local` declaration is the same keyless leg on the
/// Responses surface: the shared adapter builds for the literal id,
/// claims to serve it, and both legs — the `/models` listing and the
/// `/responses` send — reach the configured base with no
/// `Authorization` header at all.
#[tokio::test]
async fn ollama_local_kind_form_serves_both_legs_without_a_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": OLLAMA_MODEL}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    mount_responses(
        &server,
        responses_completed_stream("local kind outcome", Vec::new(), None),
    )
    .await;
    let config = Config::parse_validated(&ollama_local_config(&server_uri_v1(&server)))
        .expect("the local declaration is admitted");
    assert_eq!(config.connections["ollama"].kind, ConnKind::Local);

    let (provider, _store) = ollama_provider(&config);
    assert!(
        provider.serves("ollama", &config.connections["ollama"]),
        "the adapter claims the literal id it was built for"
    );
    assert!(
        !provider.serves("openai", &config.connections["ollama"]),
        "and only that id — a sibling pin is a dialect it does not speak"
    );
    let models = ollama_catalog(provider);
    assert_eq!(
        models,
        vec![CatalogModel {
            id: OLLAMA_MODEL.to_string(),
            context_window: Some(128_000),
            max_output_tokens: Some(8_192),
            ..CatalogModel::default()
        }],
        "the local form lists its offers through the same seam, overlay included"
    );

    let (provider, _store) = ollama_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    outcome.expect("the local-kind send completes");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(count_path(&requests, "/v1/models"), 1);
    assert_eq!(count_path(&requests, "/v1/responses"), 1);
    assert!(
        requests
            .iter()
            .all(|request| request.headers.get("authorization").is_none()),
        "the local declaration binds no credential, so no leg fabricates a header: {:?}",
        request_paths(&requests)
    );
}

/// A `local` declaration of `ollama` that also binds a `profile` is
/// contradictory: the kind names a locally served endpoint while the
/// profile reaches real material. The adapter names the contradictory
/// profile binding before any credential resolution, so the seeded key
/// is never read and no wire leg runs (DEC-009/DEC-010).
#[tokio::test]
async fn ollama_local_profile_declaration_never_sends() {
    let server = MockServer::start().await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.ollama]\nkind = \"local\"\nendpoint = \"{}\"\nprofile = \"p1\"\n\
         [profiles.p1]\ncredential_ref = \"keyring:rivect-test/p1\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"ollama\", model_id = \"{OLLAMA_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\nfallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("the contradictory declaration is admitted at ingress");
    assert_eq!(config.connections["ollama"].profile.as_deref(), Some("p1"));

    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[("keyring:rivect-test/p1", SECRET)],
    ));
    let err = provider_result(config, "ollama".to_string(), store)
        .expect_err("the local declaration never resolves the profile's material");
    match &err {
        ProviderError::LocalProfileDeclared { connection } => {
            assert_eq!(connection, "ollama");
            let rendered = err.to_string();
            assert!(
                rendered.contains("profile") && rendered.contains("ollama"),
                "the denial names the profile member and the connection: {rendered}"
            );
        }
        other => panic!("the local profile form is the named profile denial, not {other:?}"),
    }
    assert!(
        !format!("{err} {err:?}").contains(SECRET),
        "the denial never renders the seeded material: {err}"
    );

    let requests = server.received_requests().await.expect("recorded");
    assert!(requests.is_empty(), "no wire leg ran: {requests:?}");
}

/// The optional-credential class still denies a configured region: the
/// recorded endpoint contract names none, so the build is the typed
/// mismatch before any wire leg and the denial renders no material.
#[tokio::test]
async fn ollama_configured_region_denies_before_any_wire() {
    let server = MockServer::start().await;
    let config = Config::parse_validated(
        &ollama_bound_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(OLLAMA_REF, SECRET)],
    ));
    let err = provider_result(config, "ollama".to_string(), store)
        .expect_err("a configured region is denied, never ignored");
    assert!(
        matches!(&err, ProviderError::RegionMismatch { connection, region }
            if connection == "ollama" && region == "eu"),
        "a configured region is the typed mismatch: {err}"
    );
    assert_no_secret_or_body(&err);

    let requests = server.received_requests().await.expect("recorded");
    assert!(
        requests.is_empty(),
        "the denial lands before any wire leg: {requests:?}"
    );
}

/// A typed negative control for the local Responses surface: a partial
/// tool item, an EOF without a terminal, and an unclassifiable terminal
/// status each deny typed and account nothing.
#[tokio::test]
async fn ollama_adverse_wire_input_never_reports_success() {
    // a stream ending mid output item is a typed violation
    let server = MockServer::start().await;
    mount_responses(
        &server,
        sse_block(
            "response.output_item.added",
            &json!({"item": {"id": "call_1", "type": "function_call", "status": "in_progress", "name": "read_file", "arguments": ""}, "output_index": 0}),
        ),
    )
    .await;
    let config = Config::parse_validated(&ollama_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        ollama_provider(&config),
        &config,
        "/world/ollama",
        "goal: partial item",
    );
    let (broker, outcome) = dispatch(broker, "/world/ollama", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "a stream ended mid output item is a typed violation: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    // EOF without a terminal is the unknown terminal
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
    let config = Config::parse_validated(&ollama_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        ollama_provider(&config),
        &config,
        "/world/ollama",
        "goal: no terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/ollama", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "EOF without a terminal is never success: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    // a completed terminal whose status the dialect cannot classify
    let server = MockServer::start().await;
    mount_responses(
        &server,
        sse_block(
            "response.completed",
            &json!({"response": {"status": "esoteric", "output": []}}),
        ),
    )
    .await;
    let config = Config::parse_validated(&ollama_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        ollama_provider(&config),
        &config,
        "/world/ollama",
        "goal: unknown status",
    );
    let (broker, outcome) = dispatch(broker, "/world/ollama", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "an unclassifiable terminal status is never success: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);
}

/// The dialect keys on the literal connection id, never an auth label:
/// `ollama` records the Responses surface, an unreserved sibling builds
/// no adapter, the Chat-Completions adapter refuses `ollama`, and a
/// `local` declaration of the reserved literal is never fixture-served.
#[test]
fn ollama_dialect_is_keyed_on_the_literal_connection_id() {
    assert_eq!(
        rivect::providers::dialect_for("ollama"),
        Some(Dialect::Responses),
        "the literal id records the Responses dialect"
    );
    let config = Config::parse_validated(&ollama_config("http://127.0.0.1:1/v1")).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = provider_result(config.clone(), "ollama-cloud".to_string(), store)
        .expect_err("a different literal id is not this dialect");
    assert!(matches!(err, ProviderError::DialectMismatch { .. }));

    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let built = config.clone();
    let err = std::thread::spawn(move || ChatCompletionsProvider::new(&built, "ollama", store))
        .join()
        .expect("the provider thread joins")
        .expect_err("the CC adapter refuses the Responses id");
    assert!(
        matches!(err, ProviderError::DialectMismatch { .. }),
        "a CC arm for `ollama` is a dialect mismatch, not a served connection"
    );

    let local = Config::parse_validated(
        "config_version = 1\n\
         [connections.ollama]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434/v1\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"ollama\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"medium\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let loopback = rivect::providers::LoopbackProvider::new();
    let entry = local.connections.get("ollama").expect("declared");
    assert!(
        !loopback.serves("ollama", entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );
}

/// The legs matrix enforces the recorded expected set for `ollama`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside this
/// run, and INSTALLED reports NOT_RUN.
#[tokio::test]
async fn ollama_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": OLLAMA_MODEL}],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
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
    let config = Config::parse_validated(&ollama_config(&server_uri_v1(&server))).expect("valid");

    // CATALOG: the listing plus the bounded native overlay.
    let models = ollama_catalog(ollama_provider(&config).0);
    reported.insert(
        "CATALOG",
        if models
            .iter()
            .map(|model| model.id.as_str())
            .eq(std::iter::once(OLLAMA_MODEL))
        {
            "PASS"
        } else {
            "FAIL"
        },
    );

    // AUTH: a bound ref with no store material denies typed.
    let bound =
        Config::parse_validated(&ollama_bound_config(&server_uri_v1(&server))).expect("valid");
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(bound.clone(), "ollama".to_string(), empty).expect("binding resolves");
    let (provider, denied) = send_on_thread(provider, prepared_manifest(&bound));
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
        ollama_provider(&config),
        &config,
        "/world/ollama",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/ollama", manifest);
    reported.insert(
        "WIRE",
        if matches!(&outcome, Ok(reply) if reply.text == "matrix") {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

    // RECOVERY: the typed denial is followed by a successful retry
    // through the same credential seam.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(bound.clone(), "ollama".to_string(), empty.clone()).expect("resolves");
    let manifest = prepared_manifest(&bound);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(OLLAMA_REF, SECRET.as_bytes());
    let (provider, retried) = send_on_thread(provider, manifest);
    let recovered = matches!(retried, Ok(reply) if reply.text == "matrix");
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

// ----- TP-PROVIDER-INSTALLED::ollama --------------------------------

/// TP-PROVIDER-INSTALLED::ollama = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::ollama = NOT_RUN"]
fn provider_installed_ollama() {}

// ----- openrouter --------------------------------------------------------
//
// `openrouter` records the OpenAI Responses transport behind the
// paste-key form (DEC-003): an empty configured endpoint resolves
// `https://openrouter.ai/api/v1`, the keyless `GET /models` lists only
// tool-capable entries and maps their recorded surfaces (DEC-010), and
// an unbound send denies before any wire leg even though the same
// declaration lists keylessly. `models` HTTP 200 is never entitlement.

const OPENROUTER_REF: &str = "keyring:rivect-test/openrouter";

const OPENROUTER_MODEL: &str = "vendor/tool-model";

/// Fixture paste-key material — shaped like the recorded `sk-or-…` form,
/// never a real credential, only ever sent to localhost.
const OPENROUTER_SECRET: &str = "sk-or-fixture-paste-key";

/// One keyless `api_key` declaration for `openrouter` — the adopted
/// absent-binding form; no `credential_ref` member.
fn openrouter_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.openrouter]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"openrouter\", model_id = \"{OPENROUTER_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The same declaration with a scoped binding — the paste-key half.
fn openrouter_bound_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.openrouter]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{OPENROUTER_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"openrouter\", model_id = \"{OPENROUTER_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn openrouter_provider(config: &Config) -> (OpenAiProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "openrouter".to_string(), store.clone())
        .expect("the shared adapter builds for the keyless openrouter id");
    (provider, store)
}

fn openrouter_bound_provider(config: &Config) -> (OpenAiProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(OPENROUTER_REF, OPENROUTER_SECRET)],
    ));
    let provider = provider_result(config.clone(), "openrouter".to_string(), store.clone())
        .expect("the shared adapter builds for the bound openrouter id");
    (provider, store)
}

/// The rich catalogue on a plain OS thread: the blocking client cannot
/// be dropped inside a tokio context.
fn openrouter_catalog(provider: OpenAiProvider) -> Vec<CatalogModel> {
    let (provider, outcome) = std::thread::spawn(move || {
        let outcome = provider.catalog_models();
        (provider, outcome)
    })
    .join()
    .expect("the catalog thread joins");
    drop_blocking(provider);
    outcome.expect("the openrouter catalogue answers")
}

// ----- TP-PROVIDER-WIRE::openrouter ---------------------------------

/// A configured `openrouter` connection returns a verified model
/// outcome through the standard Broker: prepare admits the bound pin,
/// the shared adapter posts exactly the frozen manifest as a Responses
/// request — `store: false`, `stream: true`, pinned model,
/// instructions, tool surface and pinned effort verbatim, no
/// unrecorded reasoning artifact — the SSE stream validates its
/// terminal, and the one physical send is charged once with the
/// provider's reported usage.
#[tokio::test]
async fn openrouter_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "verified openrouter outcome",
            Vec::new(),
            Some(json!({"input_tokens": 17, "output_tokens": 6, "total_tokens": 23})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&openrouter_bound_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        openrouter_bound_provider(&config),
        &config,
        "/world/openrouter",
        "goal: prove the openrouter wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/openrouter", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified openrouter outcome");
    assert!(reply.tool_calls.is_empty());

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request");
    assert_eq!(requests[0].url.path(), "/v1/responses");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {OPENROUTER_SECRET}")
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], OPENROUTER_MODEL);
    assert_eq!(body["store"], false);
    assert_eq!(body["stream"], true);
    assert!(
        body.get("include").is_none(),
        "the record states no replay artifact — the include is never requested: {body}"
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

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "openrouter");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 17,
            completion_tokens: 6,
            total_tokens: 23,
        }
    );
    let explain = broker.sent_cost_explain(&manifest);
    assert_eq!(explain.bound, manifest.cost_bound);
    assert_eq!(explain.confirmed, Some(23));
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay = broker.dispatch(
                &mut rivect::model::NullLedger,
                "/world/openrouter",
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

// ----- TP-PROVIDER-CATALOG::openrouter ------------------------------

/// The keyless `GET /models` filters to entries whose
/// `supported_parameters` declares `tools`: an entry without the
/// capability is never offered — nor is a non-string id or a
/// non-array parameter list — the listing is sorted, and no credential
/// header rides the unbound request.
#[tokio::test]
async fn openrouter_catalog_filters_to_tool_capable_entries() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"id": "vendor/tools", "supported_parameters": ["tools", "reasoning"]},
                {"id": "vendor/text-only", "supported_parameters": ["temperature", "top_p"]},
                {"id": "vendor/absent-parameters"},
                {"id": "vendor/tools-again", "supported_parameters": ["tools"]},
                {"id": "", "supported_parameters": ["tools"]},
                {"id": 7, "supported_parameters": ["tools"]},
                {"id": "vendor/non-array", "supported_parameters": "tools"},
                {"id": "vendor/non-string", "supported_parameters": [7, null]},
                {"id": "vendor/mixed", "supported_parameters": [7, "tools"]},
            ],
        })))
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&openrouter_config(&server_uri_v1(&server))).expect("valid");
    let models = openrouter_catalog(openrouter_provider(&config).0);
    assert_eq!(
        models
            .iter()
            .map(|model| model.id.as_str())
            .collect::<Vec<_>>(),
        vec!["vendor/mixed", "vendor/tools", "vendor/tools-again"],
        "only tool-capable, non-empty string ids are offered, sorted"
    );

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1);
    assert!(
        requests
            .iter()
            .all(|request| request.headers.get("authorization").is_none()),
        "the keyless listing fabricates no Authorization header"
    );
}

/// The surviving entry's own surfaces map onto the shared record:
/// `reasoning` from `supported_parameters`, `vision` from
/// `architecture.input_modalities`, `context_length`, the top
/// provider's `max_completion_tokens`, and the per-token USD pricing
/// scaled to 1M. A JSON number is admitted like the decimal string,
/// while an absent, non-numeric, negative or partial pair is not a
/// figure — the listing never supplies a default.
#[tokio::test]
async fn openrouter_catalog_maps_reasoning_context_and_price() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "id": "vendor/rich",
                    "supported_parameters": ["tools", "reasoning"],
                    "architecture": {"input_modalities": ["text", "image"]},
                    "context_length": 128000,
                    "top_provider": {"max_completion_tokens": 16384},
                    "pricing": {"prompt": "0.0000025", "completion": "0.00001"},
                },
                {
                    "id": "vendor/invalid",
                    "supported_parameters": ["tools"],
                    "architecture": {"input_modalities": ["text"]},
                    "context_length": 0,
                    "top_provider": {"max_completion_tokens": null},
                    "pricing": {"prompt": "not-a-price", "completion": "0.00001"},
                },
                {
                    "id": "vendor/numeric-price",
                    "supported_parameters": ["tools"],
                    "pricing": {"prompt": 0.000001, "completion": 0.000002},
                },
                {
                    "id": "vendor/negative-price",
                    "supported_parameters": ["tools"],
                    "pricing": {"prompt": "-0.000001", "completion": "0.000002"},
                },
                {
                    "id": "vendor/partial-price",
                    "supported_parameters": ["tools"],
                    "pricing": {"prompt": "0.000001"},
                },
                {
                    "id": "vendor/nan-price",
                    "supported_parameters": ["tools"],
                    "pricing": {"prompt": "NaN", "completion": "0.000001"},
                },
                {
                    "id": "vendor/infinite-price",
                    "supported_parameters": ["tools"],
                    "pricing": {"prompt": "0.000001", "completion": "inf"},
                },
                {
                    "id": "vendor/overflow-price",
                    "supported_parameters": ["tools"],
                    "pricing": {"prompt": "1e303", "completion": "0.000001"},
                },
                {"id": "vendor/absent", "supported_parameters": ["tools"]},
            ],
        })))
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&openrouter_config(&server_uri_v1(&server))).expect("valid");
    let models = openrouter_catalog(openrouter_provider(&config).0);
    assert_eq!(
        models
            .iter()
            .map(|model| model.id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "vendor/absent",
            "vendor/infinite-price",
            "vendor/invalid",
            "vendor/nan-price",
            "vendor/negative-price",
            "vendor/numeric-price",
            "vendor/overflow-price",
            "vendor/partial-price",
            "vendor/rich",
        ],
        "every tool-capable entry offers, in sorted order"
    );
    let offered = |id: &str| {
        models
            .iter()
            .find(|model| model.id == id)
            .expect("the fixture entry is offered")
    };
    let id_only = |id: &str| CatalogModel {
        id: id.to_string(),
        ..CatalogModel::default()
    };

    let rich = offered("vendor/rich");
    assert!(rich.reasoning, "`reasoning` is a declared parameter");
    assert!(rich.vision, "`image` is a declared input modality");
    assert_eq!(rich.context_window, Some(128_000));
    assert_eq!(rich.max_output_tokens, Some(16_384));
    let ModelPrice::Usd {
        input_per_1m,
        output_per_1m,
    } = rich.price
    else {
        panic!(
            "the stated per-token pair maps to a USD price: {:?}",
            rich.price
        );
    };
    assert!(
        (input_per_1m - 2.5).abs() < 1e-9,
        "2.5e-6 per token is 2.5 per 1M, got {input_per_1m}"
    );
    assert!(
        (output_per_1m - 10.0).abs() < 1e-9,
        "1e-5 per token is 10 per 1M, got {output_per_1m}"
    );

    let ModelPrice::Usd {
        input_per_1m,
        output_per_1m,
    } = offered("vendor/numeric-price").price
    else {
        panic!("the JSON-number pair is a price");
    };
    assert!(
        (input_per_1m - 1.0).abs() < 1e-9 && (output_per_1m - 2.0).abs() < 1e-9,
        "1e-6 and 2e-6 per token are 1 and 2 per 1M, got {input_per_1m}/{output_per_1m}"
    );

    assert_eq!(
        offered("vendor/invalid"),
        &id_only("vendor/invalid"),
        "an invalid context/max/price pair stays empty and unknown"
    );
    for id in [
        "vendor/negative-price",
        "vendor/partial-price",
        "vendor/nan-price",
        "vendor/infinite-price",
    ] {
        assert_eq!(
            offered(id),
            &id_only(id),
            "a negative, partial or non-finite pair releases no figure"
        );
    }
    assert_eq!(
        offered("vendor/overflow-price"),
        &id_only("vendor/overflow-price"),
        "a finite per-token figure whose 1M scale is not finite releases no price"
    );
    assert_eq!(
        offered("vendor/absent"),
        &id_only("vendor/absent"),
        "absent surfaces are never defaulted to a figure"
    );
}

/// The keyless catalogue requests no credential material: a sibling
/// scope holding real material never reaches the request and no header
/// is fabricated, while the tool-capable listing still answers.
#[tokio::test]
async fn openrouter_keyless_listing_never_requests_material() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": OPENROUTER_MODEL, "supported_parameters": ["tools"]}],
        })))
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&openrouter_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(NEIGHBOR_REF, OPENROUTER_SECRET)],
    ));
    let provider = provider_result(config, "openrouter".to_string(), store)
        .expect("the keyless adapter builds");
    let models = openrouter_catalog(provider);
    assert_eq!(
        models
            .iter()
            .map(|model| model.id.as_str())
            .collect::<Vec<_>>(),
        vec![OPENROUTER_MODEL],
        "the unbound listing answers its offers"
    );

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].headers.get("authorization").is_none(),
        "the keyless catalogue requests no material — never a fabricated key"
    );
}

/// A bound `openrouter` declaration sends the paste key as the
/// catalogue bearer: the keyless form is the absent binding, never a
/// blanket no-header rule.
#[tokio::test]
async fn openrouter_bound_listing_carries_the_paste_key_bearer() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": OPENROUTER_MODEL, "supported_parameters": ["tools"]}],
        })))
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&openrouter_bound_config(&server_uri_v1(&server))).expect("valid");
    let models = openrouter_catalog(openrouter_bound_provider(&config).0);
    assert_eq!(
        models
            .iter()
            .map(|model| model.id.as_str())
            .collect::<Vec<_>>(),
        vec![OPENROUTER_MODEL],
        "the bound listing answers its offers"
    );

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {OPENROUTER_SECRET}"),
        "the bound catalogue carries its paste key as the bearer"
    );
}

/// A keyless declaration is catalogue-only (DEC-010): the unbound send
/// denies typed before any wire leg and issues neither a catalogue GET
/// nor a POST.
#[tokio::test]
async fn openrouter_keyless_send_denies_without_a_binding() {
    let server = MockServer::start().await;
    let config =
        Config::parse_validated(&openrouter_config(&server_uri_v1(&server))).expect("valid");
    // The frozen pin is the same one the bound form would send; only
    // the declaration the adapter was built from is keyless.
    let bound =
        Config::parse_validated(&openrouter_bound_config(&server_uri_v1(&server))).expect("valid");
    let manifest = prepared_manifest(&bound);
    let (provider, _store) = openrouter_provider(&config);
    let (provider, outcome) = send_on_thread(provider, manifest);
    match outcome.expect_err("the unbound send denies") {
        ProviderError::CredentialUnresolved {
            connection,
            scope,
            cause,
        } => {
            assert_eq!(connection, "openrouter");
            assert_eq!(scope, "connections.openrouter.credential_ref");
            assert!(cause.is_none(), "the unbound declaration named no ref");
        }
        other => panic!("the unbound send is the typed unresolved denial, not {other:?}"),
    }
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert!(
        requests.is_empty(),
        "the denial lands before any wire leg: {requests:?}"
    );
}

/// An `openrouter` declaration of `kind = "local"` is the reserved
/// dialect id, not the fixture class (DEC-010): ingress admits the form
/// and ranking may keep it, but the adapter denies
/// `CredentialUnresolved` by declaration kind at build — neither the
/// catalogue GET nor the POST runs.
#[tokio::test]
async fn openrouter_local_declaration_never_sends() {
    let server = MockServer::start().await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.openrouter]\nkind = \"local\"\nendpoint = \"{}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"openrouter\", model_id = \"{OPENROUTER_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\nfallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("the local declaration is admitted at ingress");
    assert_eq!(config.connections["openrouter"].kind, ConnKind::Local);
    assert!(
        rivect::providers::offline_usable(&config.connections, &config.profiles, "openrouter"),
        "the local class ranks like any local row"
    );

    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = provider_result(config, "openrouter".to_string(), store)
        .expect_err("the reserved dialect id builds no adapter");
    match &err {
        ProviderError::CredentialUnresolved {
            connection,
            scope,
            cause,
        } => {
            assert_eq!(connection, "openrouter");
            assert_eq!(scope, "connections.openrouter.kind");
            assert!(cause.is_none(), "the declaration bound no credential");
        }
        other => panic!("the local declaration is the typed unresolved denial, not {other:?}"),
    }

    let requests = server.received_requests().await.expect("recorded");
    assert!(requests.is_empty(), "no wire leg ran: {requests:?}");
}

/// A `local` declaration of the reserved literal that binds a `profile`
/// is contradictory: the kind says local endpoint while the profile
/// reaches real `sk-or-…` material. The adapter names the contradictory
/// profile binding before any credential resolution, so the seeded key
/// is never read and no wire leg runs.
#[tokio::test]
async fn openrouter_local_profile_declaration_never_sends() {
    let server = MockServer::start().await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.openrouter]\nkind = \"local\"\nendpoint = \"{}\"\nprofile = \"p1\"\n\
         [profiles.p1]\ncredential_ref = \"keyring:rivect-test/p1\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"openrouter\", model_id = \"{OPENROUTER_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\nfallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("the contradictory declaration is admitted at ingress");
    assert_eq!(
        config.connections["openrouter"].profile.as_deref(),
        Some("p1")
    );

    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[("keyring:rivect-test/p1", OPENROUTER_SECRET)],
    ));
    let err = provider_result(config, "openrouter".to_string(), store)
        .expect_err("the local declaration never resolves the profile's material");
    match &err {
        ProviderError::LocalProfileDeclared { connection } => {
            assert_eq!(connection, "openrouter");
            let rendered = err.to_string();
            assert!(
                rendered.contains("profile") && rendered.contains("openrouter"),
                "the denial names the profile member and the connection: {rendered}"
            );
        }
        other => panic!("the local profile form is the named profile denial, not {other:?}"),
    }
    assert!(
        !format!("{err} {err:?}").contains(OPENROUTER_SECRET),
        "the denial never renders the seeded material: {err}"
    );

    let requests = server.received_requests().await.expect("recorded");
    assert!(requests.is_empty(), "no wire leg ran: {requests:?}");
}

/// The profile binding's trailing scope segment is the binding itself
/// (DEC-013): a ref whose scope names another profile denies
/// `CredentialProfileMismatch` at build, renders no seeded material
/// and never reaches the wire.
#[tokio::test]
async fn openrouter_profile_mismatch_never_sends() {
    let server = MockServer::start().await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.openrouter]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"openrouter\", model_id = \"{OPENROUTER_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\nfallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(OPENROUTER_REF, OPENROUTER_SECRET)],
    ));
    let err = provider_result(config, "openrouter".to_string(), store)
        .expect_err("a divergent scope is a profile mismatch");
    assert!(
        matches!(
            &err,
            ProviderError::CredentialProfileMismatch { connection, profile }
                if connection == "openrouter" && profile == "work"
        ),
        "a divergent scope is the typed profile mismatch: {err:?}"
    );
    // This path denies at build, before the store is read, so no
    // seeded material can reach the render; redaction is proven on the
    // resolving 401 leg instead.

    let requests = server.received_requests().await.expect("recorded");
    assert!(
        requests.is_empty(),
        "the denial lands before any wire leg: {requests:?}"
    );
}

/// A `/models` HTTP 200 is never entitlement: the listing genuinely
/// answers the pinned id, yet the send rides only its request leg and
/// the unmounted peer's status is the typed denial — the 200 answer
/// releases nothing.
#[tokio::test]
async fn openrouter_models_http_200_is_never_entitlement() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": OPENROUTER_MODEL, "supported_parameters": ["tools"]}],
        })))
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&openrouter_bound_config(&server_uri_v1(&server))).expect("valid");
    let models = openrouter_catalog(openrouter_bound_provider(&config).0);
    assert_eq!(
        models
            .iter()
            .map(|model| model.id.as_str())
            .collect::<Vec<_>>(),
        vec![OPENROUTER_MODEL],
        "the 200 listing answers the pinned id"
    );

    let (provider, _store) = openrouter_bound_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a 200 catalogue never releases the pin");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the unmounted request leg is the typed transport denial: {err:?}");
    };
    assert_eq!(connection, "openrouter");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 404 },
        "the request leg answers the peer's status, never a listing-granted success: {cause}"
    );
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        request_paths(&requests),
        vec!["/v1/models", "/v1/responses"],
        "the listing leg plus the request leg — the 200 grants no send"
    );
}

/// A typed negative control for the openrouter Responses surface: a
/// partial tool item, an EOF without a terminal and an unclassifiable
/// terminal status each deny typed and account nothing; a refused
/// bearer is the typed status denial and renders no secret.
#[tokio::test]
async fn openrouter_adverse_wire_input_never_reports_success() {
    // a stream ending mid output item is a typed violation
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
        Config::parse_validated(&openrouter_bound_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        openrouter_bound_provider(&config),
        &config,
        "/world/openrouter",
        "goal: partial item",
    );
    let (broker, outcome) = dispatch(broker, "/world/openrouter", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "a stream ended mid output item is a typed violation: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    // EOF without a terminal is the unknown terminal
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
        Config::parse_validated(&openrouter_bound_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        openrouter_bound_provider(&config),
        &config,
        "/world/openrouter",
        "goal: no terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/openrouter", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "EOF without a terminal is never success: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    // a completed terminal whose status the dialect cannot classify
    let server = MockServer::start().await;
    mount_responses(
        &server,
        sse_block(
            "response.completed",
            &json!({"response": {"status": "esoteric", "output": []}}),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&openrouter_bound_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        openrouter_bound_provider(&config),
        &config,
        "/world/openrouter",
        "goal: unknown status",
    );
    let (broker, outcome) = dispatch(broker, "/world/openrouter", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "an unclassifiable terminal status is never success: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    // a refused bearer is the typed status denial, and the error renders
    // neither the credential nor the peer's body
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(
            ResponseTemplate::new(401).set_body_string("fixture-401-body-marker-never-in-errors"),
        )
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&openrouter_bound_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        openrouter_bound_provider(&config),
        &config,
        "/world/openrouter",
        "goal: refused bearer",
    );
    let (broker, outcome) = dispatch(broker, "/world/openrouter", manifest);
    let err = outcome.expect_err("a refused bearer is never success");
    assert_eq!(broker.accounted_requests(), 0);
    let rendered = format!("{err} {err:?}");
    assert!(
        !rendered.contains(OPENROUTER_SECRET),
        "the denial renders no credential material: {rendered}"
    );
    assert!(
        !rendered.contains("fixture-401-body-marker-never-in-errors"),
        "the denial renders no peer body: {rendered}"
    );
    let ModelError::Provider(ProviderError::Transport { connection, cause }) = &err else {
        panic!("the refused bearer is the typed transport denial: {err:?}");
    };
    assert_eq!(connection, "openrouter");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the peer's own status is the denial's context: {cause}"
    );
    drop_blocking(broker);
}

/// The dialect keys on the literal connection id, never an auth label:
/// `openrouter` records the Responses surface, an unrouted sibling
/// builds no adapter, the Chat-Completions adapter refuses
/// `openrouter`, a `local` declaration of the reserved literal is never
/// fixture-served, and a configured region is the typed denial.
#[test]
fn openrouter_dialect_is_keyed_on_the_literal_connection_id() {
    assert_eq!(
        rivect::providers::dialect_for("openrouter"),
        Some(Dialect::Responses),
        "the literal id records the Responses dialect"
    );
    let config =
        Config::parse_validated(&openrouter_bound_config("http://127.0.0.1:1/v1")).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = provider_result(config.clone(), "google-vertex".to_string(), store)
        .expect_err("a different literal id is not this dialect");
    assert!(matches!(err, ProviderError::DialectMismatch { .. }));

    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let built = config.clone();
    let err = std::thread::spawn(move || ChatCompletionsProvider::new(&built, "openrouter", store))
        .join()
        .expect("the provider thread joins")
        .expect_err("the CC adapter refuses the Responses id");
    assert!(
        matches!(err, ProviderError::DialectMismatch { .. }),
        "a CC arm for `openrouter` is a dialect mismatch, not a served connection"
    );

    let local = Config::parse_validated(
        "config_version = 1\n\
         [connections.openrouter]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1/v1\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"openrouter\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"medium\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let loopback = rivect::providers::LoopbackProvider::new();
    let entry = local.connections.get("openrouter").expect("declared");
    assert!(
        !loopback.serves("openrouter", entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );

    // a configured region is outside the recorded endpoint contract
    let regional = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.openrouter]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1/v1\"\ncredential_ref = \"{OPENROUTER_REF}\"\nregion = \"eu\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"openrouter\", model_id = \"{OPENROUTER_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = provider_result(regional, "openrouter".to_string(), store)
        .expect_err("a configured region is never silently ignored");
    assert!(
        matches!(&err, ProviderError::RegionMismatch { connection, region }
            if connection == "openrouter" && region == "eu"),
        "a configured region is the typed denial: {err:?}"
    );
}

/// The legs matrix enforces the recorded expected set for `openrouter`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside this
/// run, and INSTALLED reports NOT_RUN.
#[tokio::test]
async fn openrouter_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": OPENROUTER_MODEL, "supported_parameters": ["tools"]}],
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
    let config =
        Config::parse_validated(&openrouter_bound_config(&server_uri_v1(&server))).expect("valid");
    let keyless =
        Config::parse_validated(&openrouter_config(&server_uri_v1(&server))).expect("valid");

    // CATALOG: the keyless listing answers its tool-capable offers.
    let models = openrouter_catalog(openrouter_provider(&keyless).0);
    reported.insert(
        "CATALOG",
        if models
            .iter()
            .map(|model| model.id.as_str())
            .eq(std::iter::once(OPENROUTER_MODEL))
        {
            "PASS"
        } else {
            "FAIL"
        },
    );

    // AUTH: a bound ref with no store material denies typed.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), "openrouter".to_string(), empty.clone()).expect("resolves");
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
        openrouter_bound_provider(&config),
        &config,
        "/world/openrouter",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/openrouter", manifest);
    reported.insert(
        "WIRE",
        if matches!(&outcome, Ok(reply) if reply.text == "matrix") {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

    // RECOVERY: the typed denial is followed by a successful retry
    // through the same credential seam.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), "openrouter".to_string(), empty.clone()).expect("resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(OPENROUTER_REF, OPENROUTER_SECRET.as_bytes());
    let (provider, retried) = send_on_thread(provider, manifest);
    let recovered = matches!(retried, Ok(reply) if reply.text == "matrix");
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

// ----- TP-PROVIDER-INSTALLED::openrouter ----------------------------

/// TP-PROVIDER-INSTALLED::openrouter = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::openrouter = NOT_RUN"]
fn provider_installed_openrouter() {}

// ----- sakana -------------------------------------------------------------
//
// `sakana` records the OpenAI Responses transport over a key-gated
// authoritative `GET /models` listing (DEC-004): an empty configured
// endpoint resolves `https://api.sakana.ai/v1`, the listing alone names
// offers — the recorded in-source Fugu entries are mapping references,
// never a roster — and a `fugu*` id maps the one representable
// reasoning level (`max` is outside the shared vocabulary, DEC-008).
// The recorded request-side clamp is upstream-only (D3), so this
// adapter carries no such field.

const SAKANA_REF: &str = "keyring:rivect-test/sakana";

const SAKANA_MODEL: &str = "fugu-ultra";

/// Fixture key material — never a real credential, only ever sent to
/// localhost.
const SAKANA_SECRET: &str = "fixture-sakana-key";

/// One configured `sakana` connection pointing at the fixture peer:
/// the api_key class resolves a scoped `SecretRef`, and the dialect
/// comes from the literal connection id (DEC-004).
fn sakana_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.sakana]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{SAKANA_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"sakana\", model_id = \"{SAKANA_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn sakana_provider(config: &Config) -> (OpenAiProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(SAKANA_REF, SAKANA_SECRET)],
    ));
    let provider = provider_result(config.clone(), "sakana".to_string(), store.clone())
        .expect("the shared adapter builds for the sakana id");
    (provider, store)
}

/// The rich catalogue on a plain OS thread: the blocking client cannot
/// be dropped inside a tokio context.
fn sakana_catalog(provider: OpenAiProvider) -> Vec<CatalogModel> {
    let (provider, outcome) = std::thread::spawn(move || {
        let outcome = provider.catalog_models();
        (provider, outcome)
    })
    .join()
    .expect("the catalog thread joins");
    drop_blocking(provider);
    outcome.expect("the sakana catalogue answers")
}

// ----- TP-PROVIDER-WIRE::sakana -------------------------------------

/// A configured `sakana` connection returns a verified model outcome
/// through the standard Broker: prepare admits the bound pin, the
/// shared adapter posts exactly the frozen manifest as a Responses
/// request — `store: false`, `stream: true`, pinned model,
/// instructions, tool surface and pinned effort verbatim, no
/// unrecorded reasoning artifact — the SSE stream validates its
/// terminal, and the one physical send is charged once with the
/// provider's reported usage.
#[tokio::test]
async fn sakana_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "verified sakana outcome",
            Vec::new(),
            Some(json!({"input_tokens": 19, "output_tokens": 7, "total_tokens": 26})),
        ),
    )
    .await;
    let config = Config::parse_validated(&sakana_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        sakana_provider(&config),
        &config,
        "/world/sakana",
        "goal: prove the sakana wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/sakana", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified sakana outcome");
    assert!(reply.tool_calls.is_empty());

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request");
    assert_eq!(requests[0].url.path(), "/v1/responses");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {SAKANA_SECRET}")
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], SAKANA_MODEL);
    assert_eq!(body["store"], false);
    assert_eq!(body["stream"], true);
    assert!(
        body.get("include").is_none(),
        "the record states no replay artifact — the include is never requested: {body}"
    );
    assert!(
        body.get("max_output_tokens").is_none(),
        "the recorded request-side clamp is upstream-only — no token cap rides the request: {body}"
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

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "sakana");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 19,
            completion_tokens: 7,
            total_tokens: 26,
        }
    );
    let explain = broker.sent_cost_explain(&manifest);
    assert_eq!(explain.bound, manifest.cost_bound);
    assert_eq!(explain.confirmed, Some(26));
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay =
                broker.dispatch(&mut rivect::model::NullLedger, "/world/sakana", &manifest);
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

// ----- TP-PROVIDER-CATALOG::sakana ----------------------------------

/// The key-gated `GET /models` listing is the whole catalogue
/// (DEC-004): the bound bearer rides the one listing leg, every
/// non-empty string id offers in sorted order — a malformed entry
/// never invents one and a repeated id offers once — an empty answer
/// has no floor to fall back to, and a failed answer keeps the leg's
/// typed denial.
#[tokio::test]
async fn sakana_catalog_is_the_keyed_authoritative_listing() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"id": "sakana-beta"},
                {"id": "sakana-alpha"},
                {"id": "sakana-alpha"},
                {"id": ""},
                {"owned_by": "nobody"},
                {"id": 7},
            ],
        })))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&sakana_config(&server_uri_v1(&server))).expect("valid");
    let models = sakana_catalog(sakana_provider(&config).0);
    assert_eq!(
        models
            .iter()
            .map(|model| model.id.as_str())
            .collect::<Vec<_>>(),
        vec!["sakana-alpha", "sakana-beta"],
        "the authoritative listing names the offers, sorted and deduplicated"
    );

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the keyed listing is the one leg");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {SAKANA_SECRET}"),
        "the listing runs only under the resolved material"
    );

    // an empty `data` answer is a real answer with no offers — the
    // recorded Fugu entries are mapping references, never a floor
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&sakana_config(&server_uri_v1(&server))).expect("valid");
    let models = sakana_catalog(sakana_provider(&config).0);
    assert!(
        models.is_empty(),
        "an empty listing has no floor to fall back to: {:?}",
        models
            .iter()
            .map(|model| model.id.as_str())
            .collect::<Vec<_>>()
    );

    // a failed listing is the leg's typed denial — no floor answers
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&sakana_config(&server_uri_v1(&server))).expect("valid");
    let provider = sakana_provider(&config).0;
    let (provider, outcome) = std::thread::spawn(move || {
        let outcome = provider.catalog_models();
        (provider, outcome)
    })
    .join()
    .expect("the catalog thread joins");
    let err = outcome.expect_err("a failed listing has no floor to answer");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the failed listing is the typed transport denial: {err:?}")
    };
    assert_eq!(connection, "sakana");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 503 },
        "the failed listing keeps its typed denial: {cause}"
    );
    drop_blocking(provider);
}

/// The listing is key-gated (DEC-004, AC-040e): a bound ref with no
/// material at its scope denies the catalogue typed before any wire
/// leg, so an unauthenticated caller never receives offers.
#[tokio::test]
async fn sakana_catalog_without_material_denies_before_any_wire() {
    let server = MockServer::start().await;
    let config = Config::parse_validated(&sakana_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config, "sakana".to_string(), store)
        .expect("the binding resolves; the store is read at the listing");
    let (provider, outcome) = std::thread::spawn(move || {
        let outcome = provider.catalog_models();
        (provider, outcome)
    })
    .join()
    .expect("the catalog thread joins");
    let err = outcome.expect_err("an absent scope is never a listing");
    assert!(
        matches!(&err, ProviderError::CredentialAbsent { scope } if scope == "rivect-test/sakana"),
        "the absent scope is the typed credential denial: {err:?}"
    );
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the denial lands before any wire leg"
    );
}

/// The recorded in-source Fugu entries are mapping references, never
/// offers (DEC-004): the catalogue is exactly the listing's ids — no
/// Fugu reference is seeded — while every offered `fugu*` id maps the
/// recorded reasoning ladder to its single representable level (`max`
/// is outside the shared vocabulary, DEC-008). Vision comes from the
/// entry's declared capabilities, the stated limits land only when
/// positive — zero or negative never becomes a figure — and no chat
/// capability filters an entry.
#[tokio::test]
async fn sakana_fugu_entries_are_mapping_references_not_offers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "id": "fugu-ultra",
                    "capabilities": ["completion", "vision"],
                    "context_length": 200000,
                    "max_completion_tokens": 32768,
                },
                {"id": "fugu-mini"},
                {"id": "fugu-zero", "context_length": 0, "max_completion_tokens": -1},
                {"id": "sakana-text", "capabilities": ["completion", "vision"]},
                {"id": "plain", "capabilities": ["completion"]},
                {"id": ""},
                {"id": 7},
            ],
        })))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&sakana_config(&server_uri_v1(&server))).expect("valid");
    let models = sakana_catalog(sakana_provider(&config).0);
    assert_eq!(
        models,
        vec![
            CatalogModel {
                id: "fugu-mini".to_string(),
                reasoning: true,
                efforts: vec![EffortLevel::High],
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "fugu-ultra".to_string(),
                reasoning: true,
                vision: true,
                efforts: vec![EffortLevel::High],
                context_window: Some(200_000),
                max_output_tokens: Some(32_768),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "fugu-zero".to_string(),
                reasoning: true,
                efforts: vec![EffortLevel::High],
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "plain".to_string(),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "sakana-text".to_string(),
                vision: true,
                ..CatalogModel::default()
            },
        ],
        "the listing alone names offers; a `fugu*` id maps high only and capabilities carry vision"
    );
}

/// The configured base is the API base for both legs under this
/// adapter's normalization: the declaration is trimmed of whitespace
/// and of every trailing slash, and the resolved base serves the
/// listing and the inference POST alike. The empty-after-trim arm
/// resolves the recorded `https://api.sakana.ai/v1` default on the
/// resolution rule itself (`src/providers/openai.rs`), since that host
/// is a live peer this offline suite never contacts.
#[tokio::test]
async fn sakana_configured_base_applies_to_listing_and_inference() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": SAKANA_MODEL}],
        })))
        .mount(&server)
        .await;
    mount_responses(
        &server,
        responses_completed_stream("configured base", Vec::new(), None),
    )
    .await;
    let padded = format!("  {}/  ", server_uri_v1(&server));
    let config = Config::parse_validated(&sakana_config(&padded)).expect("valid");
    let models = sakana_catalog(sakana_provider(&config).0);
    assert_eq!(
        models
            .iter()
            .map(|model| model.id.as_str())
            .collect::<Vec<_>>(),
        vec![SAKANA_MODEL],
        "the configured base serves the listing"
    );
    let (provider, _store) = sakana_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    outcome.expect("the configured base serves inference");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(count_path(&requests, "/v1/models"), 1);
    assert_eq!(count_path(&requests, "/v1/responses"), 1);
}

// ----- TP-PROVIDER-AUTH/ADVERSE::sakana -----------------------------

/// A typed negative control for the sakana Responses surface: a partial
/// tool item, an EOF without a terminal, and an unclassifiable terminal
/// status each deny typed and account nothing; a resolver with no
/// material at the bound scope denies `CredentialAbsent`; and a refused
/// bearer is the typed status denial that renders neither the
/// credential nor the peer's body.
#[tokio::test]
async fn sakana_adverse_wire_input_never_reports_success() {
    // a stream ending mid output item is a typed violation
    let server = MockServer::start().await;
    mount_responses(
        &server,
        sse_block(
            "response.output_item.added",
            &json!({"item": {"id": "call_1", "type": "function_call", "status": "in_progress", "name": "read_file", "arguments": ""}, "output_index": 0}),
        ),
    )
    .await;
    let config = Config::parse_validated(&sakana_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        sakana_provider(&config),
        &config,
        "/world/sakana",
        "goal: partial item",
    );
    let (broker, outcome) = dispatch(broker, "/world/sakana", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "a stream ended mid output item is a typed violation: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    // EOF without a terminal is the unknown terminal
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
    let config = Config::parse_validated(&sakana_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        sakana_provider(&config),
        &config,
        "/world/sakana",
        "goal: no terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/sakana", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "EOF without a terminal is never success: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    // a completed terminal whose status the dialect cannot classify
    let server = MockServer::start().await;
    mount_responses(
        &server,
        sse_block(
            "response.completed",
            &json!({"response": {"status": "esoteric", "output": []}}),
        ),
    )
    .await;
    let config = Config::parse_validated(&sakana_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        sakana_provider(&config),
        &config,
        "/world/sakana",
        "goal: unknown status",
    );
    let (broker, outcome) = dispatch(broker, "/world/sakana", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "an unclassifiable terminal status is never success: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    // a bound ref with no material at its scope denies before any wire
    // leg — the sibling scope's material stays sealed behind the denial
    let server = MockServer::start().await;
    let config = Config::parse_validated(&sakana_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(NEIGHBOR_REF, SAKANA_SECRET)],
    ));
    let provider = provider_result(config.clone(), "sakana".to_string(), store)
        .expect("the binding resolves; the store is read at send");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("an absent scope is never success");
    assert!(
        matches!(&err, ProviderError::CredentialAbsent { scope } if scope == "rivect-test/sakana"),
        "the absent scope is the typed credential denial: {err:?}"
    );
    let rendered = format!("{err} {err:?}");
    assert!(
        !rendered.contains(SAKANA_SECRET),
        "the denial renders no credential material: {rendered}"
    );
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the denial lands before any wire leg"
    );

    // a refused bearer is the typed status denial, and the error renders
    // neither the credential nor the peer's body
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(ResponseTemplate::new(401).set_body_string(BODY_MARKER))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&sakana_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        sakana_provider(&config),
        &config,
        "/world/sakana",
        "goal: refused bearer",
    );
    let (broker, outcome) = dispatch(broker, "/world/sakana", manifest);
    let err = outcome.expect_err("a refused bearer is never success");
    assert_eq!(broker.accounted_requests(), 0);
    let ModelError::Provider(provider_err) = &err else {
        panic!("the refused bearer is the typed transport denial: {err:?}");
    };
    assert_no_secret_or_body(provider_err);
    let rendered = format!("{err} {err:?}");
    assert!(
        !rendered.contains(SAKANA_SECRET),
        "the denial renders no credential material: {rendered}"
    );
    let ProviderError::Transport { connection, cause } = provider_err else {
        panic!("the refused bearer is the typed transport denial: {err:?}");
    };
    assert_eq!(connection, "sakana");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the peer's own status is the denial's context: {cause}"
    );
    drop_blocking(broker);
}

/// The dialect keys on the literal connection id, never an auth label:
/// `sakana` records the Responses surface, an unrouted sibling builds
/// no adapter, the Chat-Completions adapter refuses `sakana`, a `local`
/// declaration of the reserved literal is never fixture-served, and a
/// configured region is the typed denial.
#[test]
fn sakana_dialect_is_keyed_on_the_literal_connection_id() {
    assert_eq!(
        rivect::providers::dialect_for("sakana"),
        Some(Dialect::Responses),
        "the literal id records the Responses dialect"
    );
    let config = Config::parse_validated(&sakana_config("http://127.0.0.1:1/v1")).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = provider_result(config.clone(), "google-vertex".to_string(), store)
        .expect_err("a different literal id is not this dialect");
    assert!(matches!(err, ProviderError::DialectMismatch { .. }));

    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let built = config.clone();
    let err = std::thread::spawn(move || ChatCompletionsProvider::new(&built, "sakana", store))
        .join()
        .expect("the provider thread joins")
        .expect_err("the CC adapter refuses the Responses id");
    assert!(
        matches!(err, ProviderError::DialectMismatch { .. }),
        "a CC arm for `sakana` is a dialect mismatch, not a served connection"
    );

    let local = Config::parse_validated(
        "config_version = 1\n\
         [connections.sakana]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1/v1\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"sakana\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"medium\" }\n\
         fallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let loopback = rivect::providers::LoopbackProvider::new();
    let entry = local.connections.get("sakana").expect("declared");
    assert!(
        !loopback.serves("sakana", entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );

    // a configured region is outside the recorded endpoint contract
    let regional = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.sakana]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1/v1\"\ncredential_ref = \"{SAKANA_REF}\"\nregion = \"eu\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"sakana\", model_id = \"{SAKANA_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = provider_result(regional, "sakana".to_string(), store)
        .expect_err("a configured region is never silently ignored");
    assert!(
        matches!(&err, ProviderError::RegionMismatch { connection, region }
            if connection == "sakana" && region == "eu"),
        "a configured region is the typed denial: {err:?}"
    );
}

/// The legs matrix enforces the recorded expected set for `sakana`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside
/// this run, and INSTALLED reports NOT_RUN.
#[tokio::test]
async fn sakana_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": SAKANA_MODEL}],
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
    let config = Config::parse_validated(&sakana_config(&server_uri_v1(&server))).expect("valid");

    // CATALOG: the keyed listing answers its offers.
    let models = sakana_catalog(sakana_provider(&config).0);
    reported.insert(
        "CATALOG",
        if models
            .iter()
            .map(|model| model.id.as_str())
            .eq(std::iter::once(SAKANA_MODEL))
        {
            "PASS"
        } else {
            "FAIL"
        },
    );

    // AUTH: a bound ref with no store material denies typed.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), "sakana".to_string(), empty.clone()).expect("resolves");
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
        sakana_provider(&config),
        &config,
        "/world/sakana",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/sakana", manifest);
    reported.insert(
        "WIRE",
        if matches!(&outcome, Ok(reply) if reply.text == "matrix") {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

    // RECOVERY: the typed denial is followed by a successful retry
    // through the same credential seam.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), "sakana".to_string(), empty.clone()).expect("resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(SAKANA_REF, SAKANA_SECRET.as_bytes());
    let (provider, retried) = send_on_thread(provider, manifest);
    let recovered = matches!(retried, Ok(reply) if reply.text == "matrix");
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

// ----- TP-PROVIDER-INSTALLED::sakana --------------------------------

/// TP-PROVIDER-INSTALLED::sakana = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::sakana = NOT_RUN"]
fn provider_installed_sakana() {}

// ----- custom-responses --------------------------------------------------
//
// `custom-responses` records the OpenAI Responses transport over an
// operator-configured origin (DEC-015): no default base exists, an empty
// endpoint denies before the wire, `/models` is the model source while a
// pinned manual id still sends when the listing fails, and an absent
// credential binding rides the recorded custom-open headerless form.

const CUSTOM_RESPONSES_REF: &str = "keyring:rivect-test/custom-responses";

const CUSTOM_RESPONSES_MODEL: &str = "custom-fixture-model";

/// Fixture key material — never a real credential, only ever sent to
/// localhost.
const CUSTOM_RESPONSES_SECRET: &str = "fixture-custom-responses-key";

/// One configured `custom-responses` connection pointing at the fixture
/// peer: the api_key class resolves a scoped `SecretRef`, and the
/// dialect comes from the literal connection id (DEC-015).
fn custom_responses_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.\"custom-responses\"]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{CUSTOM_RESPONSES_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"custom-responses\", model_id = \"{CUSTOM_RESPONSES_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The recorded custom-open form: the same origin and pin with no
/// `credential_ref` member at all.
fn custom_responses_unbound_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.\"custom-responses\"]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"custom-responses\", model_id = \"{CUSTOM_RESPONSES_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The listing is the model source in the auto form: no fixed pin names
/// the wire model until the catalogue leg answers.
fn custom_responses_auto_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.\"custom-responses\"]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{CUSTOM_RESPONSES_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn custom_responses_provider(config: &Config) -> (OpenAiProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CUSTOM_RESPONSES_REF, CUSTOM_RESPONSES_SECRET)],
    ));
    let provider = provider_result(
        config.clone(),
        "custom-responses".to_string(),
        store.clone(),
    )
    .expect("the shared adapter builds for the custom-responses id");
    (provider, store)
}

fn custom_responses_unbound_provider(config: &Config) -> (OpenAiProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::new(STORE_KIND));
    let provider = provider_result(
        config.clone(),
        "custom-responses".to_string(),
        store.clone(),
    )
    .expect("the absent binding builds headerless");
    (provider, store)
}

/// The rich catalogue on a plain OS thread: the blocking client cannot
/// be dropped inside a tokio context.
fn custom_responses_catalog(provider: OpenAiProvider) -> Vec<CatalogModel> {
    let (provider, outcome) = std::thread::spawn(move || {
        let outcome = provider.catalog_models();
        (provider, outcome)
    })
    .join()
    .expect("the catalog thread joins");
    drop_blocking(provider);
    outcome.expect("the custom-responses catalogue answers")
}

/// The same adapter under an explicit whole-call deadline, so the budget
/// is exercised deterministically.
fn custom_responses_provider_with_deadline(config: &Config, deadline: Duration) -> OpenAiProvider {
    let config = config.clone();
    std::thread::spawn(move || {
        let store = Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(CUSTOM_RESPONSES_REF, CUSTOM_RESPONSES_SECRET)],
        ));
        OpenAiProvider::with_deadline(&config, "custom-responses", store, deadline)
    })
    .join()
    .expect("the provider thread joins")
    .expect("the adapter builds under the explicit deadline")
}

/// Every denial renders Display and Debug with typed context only — the
/// fixture material and the peer's response body never appear on either.
fn assert_custom_denial_clean(err: &ProviderError) {
    for rendered in [format!("{err}"), format!("{err:?}")] {
        assert!(
            !rendered.contains(CUSTOM_RESPONSES_SECRET),
            "the credential material never renders: {rendered}"
        );
        assert!(
            !rendered.contains(BODY_MARKER),
            "the peer's response body never renders: {rendered}"
        );
    }
}

// ----- TP-PROVIDER-WIRE::custom-responses ---------------------------

/// A configured `custom-responses` connection returns a verified model
/// outcome through the standard Broker: prepare admits the bound pin, the
/// shared adapter posts exactly the frozen manifest as a Responses
/// request — `store: false`, `stream: true`, pinned model, instructions,
/// tool surface and pinned effort verbatim — the SSE stream validates its
/// terminal, and the one physical send is charged once with the provider's
/// reported usage.
#[tokio::test]
async fn custom_responses_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "verified custom outcome",
            Vec::new(),
            Some(json!({"input_tokens": 17, "output_tokens": 5, "total_tokens": 22})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&custom_responses_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        custom_responses_provider(&config),
        &config,
        "/world/custom-responses",
        "goal: prove the custom wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/custom-responses", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified custom outcome");
    assert!(reply.tool_calls.is_empty());

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request");
    assert_eq!(requests[0].url.path(), "/v1/responses");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {CUSTOM_RESPONSES_SECRET}")
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], CUSTOM_RESPONSES_MODEL);
    assert_eq!(body["store"], false);
    assert_eq!(body["stream"], true);
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

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "custom-responses");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 17,
            completion_tokens: 5,
            total_tokens: 22,
        }
    );
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay = broker.dispatch(
                &mut rivect::model::NullLedger,
                "/world/custom-responses",
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

// ----- TP-PROVIDER-AUTH::custom-responses ---------------------------

/// The origin is operator-configured (DEC-015): an empty endpoint is the
/// typed `EndpointRequired` denial before the credential seam or any wire
/// leg, while a configured origin builds and posts exactly once. The
/// empty store pins the ordering: the endpoint gate answers before the
/// credential seam, so no stored material participates in this denial.
#[tokio::test]
async fn custom_responses_requires_a_configured_endpoint() {
    let server = MockServer::start().await;
    let config = Config::parse_validated(&custom_responses_config("")).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = provider_result(config, "custom-responses".to_string(), store)
        .expect_err("an empty origin is denied");
    assert!(
        matches!(&err, ProviderError::EndpointRequired { connection }
            if connection == "custom-responses"),
        "the empty origin is the typed denial, never a credential outcome: {err}"
    );
    assert_eq!(
        err.to_string(),
        "connection custom-responses requires a configured endpoint"
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the denial lands before any wire leg"
    );

    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "configured origin",
            Vec::new(),
            Some(json!({"input_tokens": 1, "output_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&custom_responses_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        custom_responses_provider(&config),
        &config,
        "/world/custom-responses",
        "goal: configured origin",
    );
    let (broker, outcome) = dispatch(broker, "/world/custom-responses", manifest);
    outcome.expect("the configured origin sends once");
    assert_eq!(server.received_requests().await.expect("recorded").len(), 1);
    drop_blocking(broker);
}

/// The absent binding is the recorded custom-open form (DEC-015): the
/// unbound `api_key` declaration is admitted at ingress, both legs reach
/// the configured origin, and neither carries an `Authorization` header —
/// never a fabricated bearer.
#[tokio::test]
async fn custom_responses_absent_binding_is_admitted_and_headerless() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": CUSTOM_RESPONSES_MODEL}],
        })))
        .mount(&server)
        .await;
    mount_responses(
        &server,
        responses_completed_stream(
            "headerless outcome",
            Vec::new(),
            Some(json!({"input_tokens": 3, "output_tokens": 2, "total_tokens": 5})),
        ),
    )
    .await;
    let config = Config::parse_validated(&custom_responses_unbound_config(&server_uri_v1(&server)))
        .expect("the recorded custom-open form is admitted");
    assert_eq!(
        config.connections["custom-responses"].credential_ref, None,
        "the unbound row binds no credential"
    );

    let models = custom_responses_catalog(custom_responses_unbound_provider(&config).0);
    assert_eq!(
        models
            .iter()
            .map(|model| model.id.as_str())
            .collect::<Vec<_>>(),
        vec![CUSTOM_RESPONSES_MODEL],
        "the listing serves the keyless custom open form"
    );

    let (broker, manifest) = prepared_with(
        custom_responses_unbound_provider(&config),
        &config,
        "/world/custom-responses",
        "goal: headerless custom open",
    );
    let (broker, outcome) = dispatch(broker, "/world/custom-responses", manifest);
    outcome.expect("the absent binding sends headerless");
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded both legs");
    assert_eq!(requests.len(), 2, "the listing plus the one send");
    for request in &requests {
        assert!(
            request.headers.get("authorization").is_none(),
            "the absent binding sends no Authorization header on {}",
            request.url.path()
        );
    }
    assert_eq!(broker.accounted_requests(), 1);
    drop_blocking(broker);
}

// ----- TP-PROVIDER-WIRE::custom-responses (request shape) -----------

/// `store: false` and `stream: true` are unconditional, and the tool
/// surface is exactly the frozen manifest's function tools: the recorded
/// custom-open peer gets no hosted-tool authority and no replay artifact
/// include.
#[tokio::test]
async fn custom_responses_sends_store_false_and_never_a_hosted_tool() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "shape outcome",
            Vec::new(),
            Some(json!({"input_tokens": 1, "output_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&custom_responses_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        custom_responses_provider(&config),
        &config,
        "/world/custom-responses",
        "goal: request shape",
    );
    let (broker, outcome) = dispatch(broker, "/world/custom-responses", manifest);
    outcome.expect("the shape control sends");

    let bodies = received_bodies(&server).await;
    assert_eq!(bodies.len(), 1);
    let body = &bodies[0];
    assert_eq!(body["store"], false, "store:false is unconditional");
    assert_eq!(body["stream"], true, "stream:true is unconditional");
    assert!(
        body.get("include").is_none(),
        "the record states no replay artifact for the id: {body}"
    );
    assert_eq!(
        body["tools"],
        json!([{ "type": "function", "name": "read_file" }]),
        "only the frozen manifest's function tools ride the request"
    );
    let tools = body["tools"].as_array().expect("the tools array");
    assert!(
        tools.iter().all(|tool| tool["type"] == "function"),
        "no hosted tool kind is ever sent: {body}"
    );
    drop_blocking(broker);
}

// ----- TP-PROVIDER-CATALOG::custom-responses ------------------------

/// `/models` is the authoritative listing (DEC-015): every non-empty id
/// offers once in sorted order with no seeded floor and no chat filter,
/// the bound bearer rides the one listing leg, and an auto assignment
/// takes its wire model from that listing.
#[tokio::test]
async fn custom_responses_catalog_is_the_authoritative_listing() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"id": "custom-beta"},
                {"id": "custom-alpha"},
                {"id": "custom-alpha"},
                {"id": ""},
                {"owned_by": "nobody"},
                {"id": 7},
            ],
        })))
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&custom_responses_config(&server_uri_v1(&server))).expect("valid");
    let models = custom_responses_catalog(custom_responses_provider(&config).0);
    assert_eq!(
        models
            .iter()
            .map(|model| model.id.as_str())
            .collect::<Vec<_>>(),
        vec!["custom-alpha", "custom-beta"],
        "the authoritative listing names the offers, sorted and deduplicated"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the listing is the one catalogue leg");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {CUSTOM_RESPONSES_SECRET}")
    );

    // an empty listing is a real answer with no offers — the id records
    // no seeded floor
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&custom_responses_config(&server_uri_v1(&server))).expect("valid");
    let models = custom_responses_catalog(custom_responses_provider(&config).0);
    assert!(
        models.is_empty(),
        "an empty listing has no floor to fall back to: {:?}",
        models
            .iter()
            .map(|model| model.id.as_str())
            .collect::<Vec<_>>()
    );

    // the auto send resolves its wire model from the same listing
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "custom-zeta"}, {"id": "custom-alpha"}],
        })))
        .mount(&server)
        .await;
    mount_responses(
        &server,
        responses_completed_stream(
            "listing resolved",
            Vec::new(),
            Some(json!({"input_tokens": 1, "output_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&custom_responses_auto_config(&server_uri_v1(&server)))
        .expect("valid");
    let (broker, manifest) = prepared_with(
        custom_responses_provider(&config),
        &config,
        "/world/custom-responses",
        "goal: listing is the model source",
    );
    let (broker, outcome) = dispatch(broker, "/world/custom-responses", manifest);
    let reply = outcome.expect("the auto send resolves its model");
    assert_eq!(reply.text, "listing resolved");
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        request_paths(&requests),
        vec!["/v1/models", "/v1/responses"],
        "the catalogue resolution then the one physical send"
    );
    let body: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert_eq!(
        body["model"], "custom-alpha",
        "the listing's sorted-first id rode the wire"
    );
    drop_blocking(broker);
}

/// A failed listing denies only where the listing is the model source: a
/// pinned manual id still sends without consulting it (DEC-015).
#[tokio::test]
async fn custom_responses_manual_model_sends_when_the_listing_fails() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .mount(&server)
        .await;
    mount_responses(
        &server,
        responses_completed_stream(
            "manual model outcome",
            Vec::new(),
            Some(json!({"input_tokens": 2, "output_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&custom_responses_config(&server_uri_v1(&server))).expect("valid");

    // the listing itself is the typed denial — the failed source
    let (provider, denied) = {
        let provider = custom_responses_provider(&config).0;
        std::thread::spawn(move || {
            let outcome = provider.catalog_models();
            (provider, outcome)
        })
        .join()
        .expect("the catalog thread joins")
    };
    let ProviderError::Transport { connection, cause } = denied.expect_err("the listing fails")
    else {
        panic!("a failed listing is the typed transport denial");
    };
    assert_eq!(connection, "custom-responses");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 503 },
        "the failed listing keeps its status: {cause}"
    );
    drop_blocking(provider);

    // the pinned manual id still sends against a peer whose listing
    // fails, and never opens that listing leg
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .mount(&server)
        .await;
    mount_responses(
        &server,
        responses_completed_stream(
            "manual model outcome",
            Vec::new(),
            Some(json!({"input_tokens": 2, "output_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&custom_responses_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        custom_responses_provider(&config),
        &config,
        "/world/custom-responses",
        "goal: manual model",
    );
    let (broker, outcome) = dispatch(broker, "/world/custom-responses", manifest);
    let reply = outcome.expect("the pinned manual id sends");
    assert_eq!(reply.text, "manual model outcome");
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        request_paths(&requests),
        vec!["/v1/responses"],
        "a pinned manual model never consults the failed listing"
    );
    drop_blocking(broker);
}

// ----- TP-PROVIDER-AUTH::custom-responses ---------------------------

/// Wrong credential/profile/region never produce a false success for
/// `custom-responses`: a configured region — the recorded contract names
/// none — the profile-bound ref whose scope disagrees with the binding, an
/// absent credential and a refused bearer each land a typed denial, and
/// none renders credential material or the peer's body.
#[tokio::test]
async fn custom_responses_wrong_credential_profile_or_region_denies_without_secrets() {
    let server = MockServer::start().await;

    // a configured region is denied, never ignored
    let regioned =
        Config::parse_validated(&custom_responses_config(&server_uri_v1(&server)).replace(
            "kind = \"api_key\"",
            "kind = \"api_key\"\nregion = \"eu-1\"",
        ))
        .expect("valid");
    let err = provider_result(
        regioned,
        "custom-responses".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, SECRET)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    assert!(
        matches!(&err, ProviderError::RegionMismatch { connection, region }
            if connection == "custom-responses" && region == "eu-1"),
        "a configured region is the typed mismatch: {err}"
    );
    assert_custom_denial_clean(&err);

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.\"custom-responses\"]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"custom-responses\", model_id = \"x\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "custom-responses".to_string(),
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
    assert_custom_denial_clean(&err);

    // a bound ref with no material at its own scope
    let config =
        Config::parse_validated(&custom_responses_config(&server_uri_v1(&server))).expect("valid");
    let provider = provider_result(
        config.clone(),
        "custom-responses".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, SECRET)],
        )),
    )
    .expect("binding resolves; the store is read at send");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("no material at the scope is the typed denial");
    assert!(matches!(err, ProviderError::CredentialAbsent { .. }));
    assert_custom_denial_clean(&err);
    drop_blocking(provider);

    // a refused bearer token is a typed transport denial, never success
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(CUSTOM_RESPONSES_REF, CUSTOM_RESPONSES_SECRET)],
    ));
    let provider = provider_result(config.clone(), "custom-responses".to_string(), store)
        .expect("the adapter builds");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused token is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused token is transport: {err}")
    };
    assert_eq!(connection, "custom-responses");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_custom_denial_clean(&err);
    drop_blocking(provider);
}

// ----- TP-PROVIDER-RECOVERY::custom-responses -----------------------

/// A partial tool block and an unknown terminal never report success: a
/// stream ended mid function_call is the wire violation, and a stream
/// whose completed envelope carries an unclassifiable status is the
/// unknown terminal.
#[tokio::test]
async fn custom_responses_rejects_partial_tool_block_and_unknown_terminal() {
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
    let config =
        Config::parse_validated(&custom_responses_config(&server_uri_v1(&server))).expect("valid");
    let (provider, outcome) = send_on_thread(
        custom_responses_provider(&config).0,
        prepared_manifest(&config),
    );
    let error = outcome.expect_err("a truncated stream is never success");
    assert!(
        matches!(error, ProviderError::StreamViolation { .. }),
        "a stream ended mid output item is the wire violation: {error}"
    );
    drop_blocking(provider);

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
    let config =
        Config::parse_validated(&custom_responses_config(&server_uri_v1(&server))).expect("valid");
    let (provider, outcome) = send_on_thread(
        custom_responses_provider(&config).0,
        prepared_manifest(&config),
    );
    let error = outcome.expect_err("an unclassifiable terminal is never success");
    assert!(
        matches!(error, ProviderError::UnknownTerminal { .. }),
        "an unclassifiable terminal is the unknown terminal: {error}"
    );
    drop_blocking(provider);
}

/// Well-formed output the dialect cannot honour is a typed rejection: a
/// server-side tool kind the frozen function surface never declared, and a
/// reasoning artifact the recorded custom-open peer never returns.
#[tokio::test]
async fn custom_responses_rejects_incompatible_tools_or_reasoning() {
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
    let config =
        Config::parse_validated(&custom_responses_config(&server_uri_v1(&server))).expect("valid");
    let (provider, outcome) = send_on_thread(
        custom_responses_provider(&config).0,
        prepared_manifest(&config),
    );
    let error = outcome.expect_err("an unhonourable hosted tool is never success");
    assert!(
        matches!(error, ProviderError::IncompatibleOutput { .. }),
        "an unhonourable output item is a typed rejection: {error}"
    );
    drop_blocking(provider);

    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "",
            vec![json!({
                "id": "rs_1", "type": "reasoning", "summary": [],
                "encrypted_content": "opaque-artifact-the-record-never-returns",
            })],
            None,
        ),
    )
    .await;
    let config =
        Config::parse_validated(&custom_responses_config(&server_uri_v1(&server))).expect("valid");
    let (provider, outcome) = send_on_thread(
        custom_responses_provider(&config).0,
        prepared_manifest(&config),
    );
    let error = outcome.expect_err("an off-contract artifact cannot be accepted");
    assert!(
        matches!(error, ProviderError::ReasoningProvenance { .. }),
        "a reasoning artifact the recorded peer never returns is the provenance denial: {error}"
    );
    drop_blocking(provider);
}

/// A non-success status is the typed transport denial: the status code
/// alone is the diagnostic, nothing is accounted, and no status opens a
/// second request.
#[tokio::test]
async fn custom_responses_non_success_status_denies() {
    for status in [400_u16, 429, 500] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .respond_with(ResponseTemplate::new(status).set_body_string("peer failure body"))
            .mount(&server)
            .await;
        let config = Config::parse_validated(&custom_responses_config(&server_uri_v1(&server)))
            .expect("valid");
        let (broker, manifest) = prepared_with(
            custom_responses_provider(&config),
            &config,
            "/world/custom-responses",
            "goal: non-success",
        );
        let (broker, outcome) = dispatch(broker, "/world/custom-responses", manifest);
        let Err(ModelError::Provider(ProviderError::Transport { cause, .. })) = outcome else {
            panic!("status {status} is a typed transport denial: {outcome:?}");
        };
        assert_eq!(
            cause.class(),
            TransportClass::HttpStatus { code: status },
            "the status code alone is the diagnostic"
        );
        assert_eq!(broker.accounted_requests(), 0);
        drop_blocking(broker);
        assert_eq!(
            server.received_requests().await.expect("recorded").len(),
            1,
            "a non-success status is never retried"
        );
    }
}

/// The whole-send deadline denies typed and never opens a second request.
#[tokio::test]
async fn custom_responses_short_deadline_denies_without_a_second_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(responses_completed_stream("late", Vec::new(), None))
                .set_delay(Duration::from_millis(600)),
        )
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&custom_responses_config(&server_uri_v1(&server))).expect("valid");
    let deadline = Duration::from_millis(400);
    let provider = custom_responses_provider_with_deadline(&config, deadline);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let error = outcome.expect_err("the expired budget denies");
    assert!(
        matches!(
            error,
            ProviderError::Transport {
                cause: TransportCause::Deadline { budget },
                ..
            } if budget == deadline
        ),
        "the adapter's own deadline is the denial: {error:?}"
    );
    drop_blocking(provider);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        1,
        "an expired budget never opens a second request"
    );
}

/// The legs matrix enforces the recorded expected set for
/// `custom-responses`: CATALOG, AUTH, WIRE and RECOVERY each execute and
/// report inside this run, and INSTALLED reports NOT_RUN.
#[tokio::test]
async fn custom_responses_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": CUSTOM_RESPONSES_MODEL}],
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
    let config =
        Config::parse_validated(&custom_responses_config(&server_uri_v1(&server))).expect("valid");

    // CATALOG: the authoritative listing answers its offers.
    let models = custom_responses_catalog(custom_responses_provider(&config).0);
    reported.insert(
        "CATALOG",
        if models
            .iter()
            .map(|model| model.id.as_str())
            .eq(std::iter::once(CUSTOM_RESPONSES_MODEL))
        {
            "PASS"
        } else {
            "FAIL"
        },
    );

    // AUTH: a bound ref with no store material denies typed.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "custom-responses".to_string(), empty)
        .expect("the binding resolves; the store is read at send");
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
        custom_responses_provider(&config),
        &config,
        "/world/custom-responses",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/custom-responses", manifest);
    reported.insert(
        "WIRE",
        if matches!(&outcome, Ok(reply) if reply.text == "matrix") {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

    // RECOVERY: the typed denial is followed by a successful retry
    // through the same credential seam.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(
        config.clone(),
        "custom-responses".to_string(),
        empty.clone(),
    )
    .expect("the binding resolves; the store is read at send");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(CUSTOM_RESPONSES_REF, CUSTOM_RESPONSES_SECRET.as_bytes());
    let (provider, retried) = send_on_thread(provider, manifest);
    let recovered = matches!(retried, Ok(reply) if reply.text == "matrix");
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

// ----- TP-PROVIDER-INSTALLED::custom-responses ----------------------

/// TP-PROVIDER-INSTALLED::custom-responses = NOT_RUN: the
/// installed-provider proof is a live-environment leg this offline slice
/// never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::custom-responses = NOT_RUN"]
fn provider_installed_custom_responses() {}

// ----- openai-codex (AC-040i / AC-046f) ------------------------------
//
// The canonical `openai-codex` connection and its device alias select the
// one Responses contract: the scoped credential is the login module's
// stored JSON, the bearer is its access token, and the account-scoped
// ChatGPT listing is filtered by the closed recorded route table. The
// device alias is transport identity, never a second backend.

fn codex_uri(server: &MockServer) -> String {
    format!("{}/backend-api/codex", server.uri())
}

fn codex_provider(config: &Config, connection: &str) -> (OpenAiProvider, Arc<support::MapStore>) {
    let credential = support::codex_stored_credential();
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(support::CODEX_REF, credential.as_str())],
    ));
    let provider = provider_result(config.clone(), connection.to_string(), store.clone())
        .expect("the codex adapter builds for the literal id");
    (provider, store)
}

async fn mount_codex_responses(server: &MockServer, body: String) {
    Mock::given(method("POST"))
        .and(path("/backend-api/codex/responses"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(server)
        .await;
}

async fn mount_codex_models(server: &MockServer, data: Value) {
    Mock::given(method("GET"))
        .and(path("/backend-api/codex/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": data })))
        .mount(server)
        .await;
}

fn codex_request_header(request: &Request, name: &str) -> String {
    request
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("the request carried no {name} header"))
        .to_string()
}

fn codex_bearer() -> String {
    format!(
        "Bearer {}",
        support::codex_access_token(support::CODEX_WORKSPACE, support::CODEX_EMAIL, "plus")
    )
}

/// A chain-spanning provider double: codex literals delegate to the real
/// adapter, while a different contract answers the fixture failure. Every
/// send records its connection, so a test can prove which entries were
/// attempted.
struct ChainProvider {
    codex: OpenAiProvider,
    served: Vec<&'static str>,
    sent: Arc<Mutex<Vec<String>>>,
}

impl ChainProvider {
    fn new(config: &Config, served: &[&'static str]) -> (Self, Arc<Mutex<Vec<String>>>) {
        let (codex, _store) = codex_provider(config, "openai-codex");
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                codex,
                served: served.to_vec(),
                sent: Arc::clone(&sent),
            },
            sent,
        )
    }
}

/// The connection one frozen manifest names; the broker narrows an auto
/// pool to its chosen member before the provider sees it.
fn manifest_connection(manifest: &RequestManifest) -> String {
    match &manifest.model {
        rivect::config::ModelAssign::Fixed(fixed) => fixed.connection.clone(),
        rivect::config::ModelAssign::Auto { pool: Some(pool) } => {
            pool.first().cloned().unwrap_or_default()
        }
        _ => String::new(),
    }
}

impl Provider for ChainProvider {
    fn name(&self) -> &'static str {
        "chain-fixture"
    }

    fn serves(&self, connection: &str, _entry: &rivect::config::Connection) -> bool {
        self.served.contains(&connection)
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        let connection = manifest_connection(manifest);
        self.sent
            .lock()
            .expect("send log lock")
            .push(connection.clone());
        if matches!(connection.as_str(), "openai-codex" | "openai-codex-device") {
            return self.codex.send(manifest);
        }
        Err(ProviderError::UnsupportedParameter {
            connection,
            parameter: "fixture",
            model: "fixture-model".to_string(),
        })
    }
}

/// One scripted loopback peer that writes the SSE body in tiny chunks with
/// a pause between them, so the cuts land inside UTF-8, JSON, SSE lines
/// and the tool block's arguments. The connection count proves one
/// physical send.
fn fragmented_codex_peer() -> (String, Arc<AtomicUsize>, std::thread::JoinHandle<()>) {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("the fixture peer binds a loopback port");
    let address = listener.local_addr().expect("the fixture address");
    let connections = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&connections);
    let message = json!({
        "id": "msg_1",
        "type": "message",
        "status": "completed",
        "role": "assistant",
        "content": [{ "type": "output_text", "text": "héllo ✓" }],
    });
    let call = json!({
        "id": "fc_1",
        "type": "function_call",
        "status": "completed",
        "name": "read_file",
        "arguments": "{\"path\":\"/tmp/fixture\"}",
    });
    let terminal_usage = json!({"input_tokens": 5, "output_tokens": 3, "total_tokens": 8});
    let repeated_usage = json!({"input_tokens": 99, "output_tokens": 99, "total_tokens": 198});
    let body = format!(
        "{}{}{}{}{}{}{}",
        sse_block(
            "response.output_item.added",
            &json!({
                "item": {"id": "msg_1", "type": "message", "status": "in_progress", "role": "assistant", "content": []},
                "output_index": 0,
            }),
        ),
        sse_block(
            "response.output_text.delta",
            &json!({
                "delta": "héllo ✓",
                "item_id": "msg_1",
                "output_index": 0,
                "content_index": 0,
            }),
        ),
        sse_block(
            "response.output_item.done",
            &json!({"item": message.clone(), "output_index": 0}),
        ),
        sse_block(
            "response.output_item.added",
            &json!({
                "item": {"id": "fc_1", "type": "function_call", "status": "in_progress", "name": "read_file", "arguments": ""},
                "output_index": 1,
            }),
        ),
        sse_block(
            "response.output_item.done",
            &json!({"item": call.clone(), "output_index": 1}),
        ),
        sse_block(
            "response.in_progress",
            &json!({"response": {"status": "in_progress"}, "usage": repeated_usage.clone()}),
        ),
        sse_block(
            "response.completed",
            &json!({
                "response": {
                    "id": "resp_1",
                    "status": "completed",
                    "output": [message, call],
                    "usage": terminal_usage,
                },
            }),
        ),
    );
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the fixture peer accepts");
        count.fetch_add(1, Ordering::SeqCst);
        support::read_fixture_request(&mut stream);
        let head =
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n";
        stream.write_all(head.as_bytes()).expect("the fixture head");
        let bytes = body.as_bytes();
        let sizes = [1usize, 2, 3, 5, 8, 13, 21];
        let mut offset = 0;
        let mut step = 0;
        while offset < bytes.len() {
            let len = sizes[step % sizes.len()].min(bytes.len() - offset);
            stream
                .write_all(&bytes[offset..offset + len])
                .expect("the fixture fragment");
            stream.flush().expect("the fixture flushes");
            offset += len;
            step += 1;
            std::thread::sleep(Duration::from_millis(2));
        }
    });
    (codex_uri_at(address), connections, handle)
}

fn codex_uri_at(address: std::net::SocketAddr) -> String {
    format!("http://{address}/backend-api/codex")
}

/// A valid control yields exactly one outcome and one physical usage: the
/// scoped credential's access token is the bearer, its workspace scopes
/// the request, and a replay of the spent attempt sends nothing.
#[tokio::test]
async fn openai_codex_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_codex_responses(
        &server,
        responses_completed_stream(
            "codex outcome",
            Vec::new(),
            Some(json!({"input_tokens": 5, "output_tokens": 3, "total_tokens": 8})),
        ),
    )
    .await;
    let config = Config::parse_validated(&support::codex_provider_config(
        "openai-codex",
        &codex_uri(&server),
    ))
    .expect("the codex config parses");
    let (provider, _store) = codex_provider(&config, "openai-codex");
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/codex", "goal: codex wire")
        .expect("the codex pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/codex", manifest.clone());
    let reply = outcome.expect("the codex control answers");
    assert_eq!(reply.text, "codex outcome");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 5,
            completion_tokens: 3,
            total_tokens: 8,
        }
    );
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "openai-codex");
    assert_eq!(record.usage, reply.usage);

    let requests = server.received_requests().await.expect("the mock recorded");
    assert_eq!(requests.len(), 1, "one physical request");
    assert_eq!(received_auth(&requests[0]), codex_bearer());
    assert_eq!(
        codex_request_header(&requests[0], "chatgpt-account-id"),
        support::CODEX_WORKSPACE,
        "the recorded workspace scopes the request"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], "gpt-5.2-codex");
    assert_eq!(body["store"], false);
    assert_eq!(body["stream"], true);
    assert_eq!(
        body["include"],
        json!(["reasoning.encrypted_content"]),
        "the shared Responses replay contract asks for the artifact"
    );

    let manifest = manifest.clone();
    let (broker, replay) = std::thread::spawn(move || {
        let mut broker = broker;
        let replay = broker.dispatch(&mut rivect::model::NullLedger, "/world/codex", &manifest);
        (broker, replay)
    })
    .join()
    .expect("the replay thread joins");
    assert!(
        matches!(replay, Err(ModelError::AttemptAlreadyAccounted { .. })),
        "the spent attempt never re-sends: {replay:?}"
    );
    drop_blocking(broker);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        1,
        "the replay opened no second physical request"
    );
}

/// The account-scoped ChatGPT listing is the discovery leg: it carries the
/// scoped bearer and workspace, and only the closed recorded route ids
/// offer — an HTTP 200 naming an unrecorded id grants nothing.
#[tokio::test]
async fn openai_codex_catalog_is_the_account_workspace_discovery() {
    let server = MockServer::start().await;
    mount_codex_models(
        &server,
        json!([
            {"id": "gpt-5.2-codex"},
            {"id": "gpt-5-codex"},
            {"id": "gpt-5.2"},
            {"id": "o3"},
            {"id": ""},
        ]),
    )
    .await;
    let config = Config::parse_validated(&support::codex_provider_config(
        "openai-codex",
        &codex_uri(&server),
    ))
    .expect("the codex config parses");
    let (provider, _store) = codex_provider(&config, "openai-codex");
    let ids = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("the catalogue thread joins")
        .expect("the account listing answers");
    assert_eq!(
        ids,
        vec!["gpt-5-codex".to_string(), "gpt-5.2-codex".to_string()],
        "only the recorded route ids offer"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "one listing leg");
    assert_eq!(requests[0].url.path(), "/backend-api/codex/models");
    assert_eq!(received_auth(&requests[0]), codex_bearer());
    assert_eq!(
        codex_request_header(&requests[0], "chatgpt-account-id"),
        support::CODEX_WORKSPACE
    );

    // A 200 listing naming only ids outside the recorded route offers
    // nothing: the answer is discovery input, never entitlement.
    let server = MockServer::start().await;
    mount_codex_models(&server, json!([{"id": "gpt-5.2"}, {"id": "o3"}])).await;
    let config = Config::parse_validated(&support::codex_provider_config(
        "openai-codex",
        &codex_uri(&server),
    ))
    .expect("the codex config parses");
    let (provider, _store) = codex_provider(&config, "openai-codex");
    let ids = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("the catalogue thread joins")
        .expect("the listing answers");
    assert!(
        ids.is_empty(),
        "an HTTP 200 listing outside the recorded route offers nothing"
    );
}

/// The device alias selects the same contract: one Responses arm, one
/// credential profile, and a wire request indistinguishable from the
/// canonical id's apart from its literal connection.
#[tokio::test]
async fn openai_codex_device_alias_selects_the_same_contract() {
    assert_eq!(
        rivect::providers::dialect_for("openai-codex-device"),
        Some(Dialect::Responses),
        "the alias records the Responses dialect"
    );
    let server = MockServer::start().await;
    mount_codex_responses(
        &server,
        responses_completed_stream(
            "alias outcome",
            Vec::new(),
            Some(json!({"input_tokens": 2, "output_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config = Config::parse_validated(&support::codex_provider_config(
        "openai-codex-device",
        &codex_uri(&server),
    ))
    .expect("the alias config parses");
    let (provider, _store) = codex_provider(&config, "openai-codex-device");
    let entry = config
        .connections
        .get("openai-codex-device")
        .expect("the alias is declared");
    assert!(provider.serves("openai-codex-device", entry));
    assert!(
        !provider.serves("openai-codex", entry),
        "the alias adapter serves its own literal id"
    );
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/codex", "goal: alias wire")
        .expect("the alias pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/codex", manifest.clone());
    let reply = outcome.expect("the alias control answers");
    assert_eq!(reply.text, "alias outcome");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 2,
            completion_tokens: 1,
            total_tokens: 3,
        }
    );
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the alias send is accounted");
    assert_eq!(
        record.connection, "openai-codex-device",
        "the accounting names the alias literal"
    );
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/backend-api/codex/responses");
    assert_eq!(received_auth(&requests[0]), codex_bearer());
    assert_eq!(
        codex_request_header(&requests[0], "chatgpt-account-id"),
        support::CODEX_WORKSPACE,
        "the alias carries the same account scope"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], "gpt-5.2-codex");
}

/// Wrong credential material, profile binding, region or origin each deny
/// typed before a false success, and the denial never renders the secret.
#[tokio::test]
async fn openai_codex_wrong_credential_profile_or_region_denies_without_secrets() {
    let endpoint = "http://127.0.0.1:1/backend-api/codex";

    // A configured region has no recorded Codex contract.
    let regional = Config::parse_validated(
        &support::codex_provider_config("openai-codex", endpoint)
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let denied = provider_result(regional, "openai-codex".to_string(), store)
        .expect_err("a configured region denies");
    assert!(
        matches!(&denied, ProviderError::RegionMismatch { connection, region }
            if connection == "openai-codex" && region == "eu"),
        "the typed region denial: {denied:?}"
    );

    // The profile binding's scope segment is the binding: a divergent
    // profile denies at build, before any material resolves.
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.openai-codex]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\n\
         credential_ref = \"{reference}\"\nprofile = \"codex-neighbor\"\n\
         [profiles.openai-codex]\ncredential_ref = \"{reference}\"\n\
         [profiles.codex-neighbor]\ncredential_ref = \"{reference}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"openai-codex\", model_id = \"gpt-5.2-codex\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\nfallback = {{ mode = \"off\" }}\n",
        reference = support::CODEX_REF,
    ))
    .expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let denied = provider_result(mismatched, "openai-codex".to_string(), store)
        .expect_err("a divergent profile binding denies");
    assert!(
        matches!(&denied, ProviderError::CredentialProfileMismatch { connection, profile }
            if connection == "openai-codex" && profile == "codex-neighbor"),
        "the typed profile denial: {denied:?}"
    );

    // An empty origin is the typed endpoint denial before the wire.
    let empty = Config::parse_validated(&support::codex_provider_config("openai-codex", ""))
        .expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let denied = provider_result(empty, "openai-codex".to_string(), store)
        .expect_err("an empty origin denies");
    assert!(
        matches!(&denied, ProviderError::EndpointRequired { connection }
            if connection == "openai-codex"),
        "the typed endpoint denial: {denied:?}"
    );

    // Material that is not the stored Codex credential JSON denies at
    // send, and the material never enters the error.
    let server = MockServer::start().await;
    let config = Config::parse_validated(&support::codex_provider_config(
        "openai-codex",
        &codex_uri(&server),
    ))
    .expect("valid");
    let malformed = "fixture-codex-material-not-a-credential";
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(support::CODEX_REF, malformed)],
    ));
    let provider = provider_result(config.clone(), "openai-codex".to_string(), store)
        .expect("the binding resolves; the store is read at send");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("foreign material is never a codex bearer");
    assert!(
        matches!(&err, ProviderError::CredentialMalformed { connection }
            if connection == "openai-codex"),
        "the typed malformed denial: {err:?}"
    );
    let rendered = format!("{err} {err:?}");
    assert!(
        !rendered.contains(malformed),
        "the denial renders no credential material: {rendered}"
    );
    drop_blocking(provider);

    // A valid credential shape with a blank access token is the same
    // malformed denial: no empty bearer reaches the wire.
    for access_token in ["", "   "] {
        let credential = support::codex_stored_credential_with_token(access_token);
        let store = Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(support::CODEX_REF, credential.as_str())],
        ));
        let provider = provider_result(config.clone(), "openai-codex".to_string(), store)
            .expect("the binding resolves; the store is read at send");
        let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
        assert!(
            matches!(&outcome, Err(ProviderError::CredentialMalformed { connection })
                if connection == "openai-codex"),
            "a blank access token is the typed malformed denial: {outcome:?}"
        );
        drop_blocking(provider);
    }

    // An absent scope is the typed absent denial, never an empty bearer.
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "openai-codex".to_string(), store)
        .expect("the binding resolves; the store is read at send");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    assert!(
        matches!(&outcome, Err(ProviderError::CredentialAbsent { scope })
            if scope == "rivect-test/openai-codex"),
        "the absent scope is typed: {outcome:?}"
    );
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "every credential denial landed before any wire leg"
    );
}

/// A partial tool block and an unknown terminal deny typed: an unfinished
/// function_call is never executed and an unclassifiable terminal is never
/// success.
#[tokio::test]
async fn openai_codex_rejects_partial_tool_block_and_unknown_terminal() {
    let server = MockServer::start().await;
    mount_codex_responses(
        &server,
        sse_block(
            "response.completed",
            &json!({
                "response": {
                    "id": "resp_1",
                    "status": "completed",
                    "output": [{
                        "id": "fc_1",
                        "type": "function_call",
                        "status": "in_progress",
                        "name": "read_file",
                        "arguments": "{\"path\":\"/tmp/fixture\"}",
                    }],
                    "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
                },
            }),
        ),
    )
    .await;
    let config = Config::parse_validated(&support::codex_provider_config(
        "openai-codex",
        &codex_uri(&server),
    ))
    .expect("valid");
    let (provider, _store) = codex_provider(&config, "openai-codex");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    assert!(
        matches!(outcome, Err(ProviderError::StreamViolation { .. })),
        "an unfinished function_call never becomes a reply: {outcome:?}"
    );
    drop_blocking(provider);

    let server = MockServer::start().await;
    mount_codex_responses(
        &server,
        sse_block(
            "response.completed",
            &json!({"response": {"id": "resp_1", "status": "concluded", "output": []}}),
        ),
    )
    .await;
    let config = Config::parse_validated(&support::codex_provider_config(
        "openai-codex",
        &codex_uri(&server),
    ))
    .expect("valid");
    let (provider, _store) = codex_provider(&config, "openai-codex");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    assert!(
        matches!(outcome, Err(ProviderError::UnknownTerminal { .. })),
        "an unclassifiable terminal is never success: {outcome:?}"
    );
    drop_blocking(provider);
}

/// Chunked delivery inside UTF-8, JSON, SSE and the tool block reassembles
/// to one outcome; the repeated usage report charges once, and the spent
/// attempt never opens a second request.
#[tokio::test]
async fn openai_codex_stream_fragmentation_and_repeated_usage_never_duplicates() {
    let (endpoint, connections, peer) = fragmented_codex_peer();
    let config =
        Config::parse_validated(&support::codex_provider_config("openai-codex", &endpoint))
            .expect("valid");
    let (provider, _store) = codex_provider(&config, "openai-codex");
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/codex", "goal: fragmented")
        .expect("the codex pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/codex", manifest.clone());
    let reply = outcome.expect("the fragmented stream reassembles");
    assert_eq!(reply.text, "héllo ✓");
    assert_eq!(
        reply.tool_calls,
        vec![rivect::providers::ToolCall {
            tool: "read_file".to_string(),
            path: Some("/tmp/fixture".to_string()),
        }]
    );
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 5,
            completion_tokens: 3,
            total_tokens: 8,
        },
        "the repeated usage report is charged once"
    );
    assert_eq!(broker.accounted_requests(), 1);
    assert_eq!(connections.load(Ordering::SeqCst), 1, "one physical send");

    let replay_manifest = manifest.clone();
    let (broker, replay) = std::thread::spawn(move || {
        let mut broker = broker;
        let replay = broker.dispatch(
            &mut rivect::model::NullLedger,
            "/world/codex",
            &replay_manifest,
        );
        (broker, replay)
    })
    .join()
    .expect("the replay thread joins");
    assert!(
        matches!(replay, Err(ModelError::AttemptAlreadyAccounted { .. })),
        "the confirmed data is never duplicated: {replay:?}"
    );
    drop_blocking(broker);
    peer.join().expect("the fixture peer joins");
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "the replay opened no second connection"
    );
}

/// A stream without a classifiable terminal is unknown, never success.
#[tokio::test]
async fn openai_codex_stream_without_terminal_denies() {
    let server = MockServer::start().await;
    mount_codex_responses(
        &server,
        sse_block(
            "response.created",
            &json!({"response": {"id": "resp_1", "status": "in_progress"}}),
        ),
    )
    .await;
    let config = Config::parse_validated(&support::codex_provider_config(
        "openai-codex",
        &codex_uri(&server),
    ))
    .expect("valid");
    let (provider, _store) = codex_provider(&config, "openai-codex");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    assert!(
        matches!(outcome, Err(ProviderError::UnknownTerminal { .. })),
        "an EOF without a terminal is never success: {outcome:?}"
    );
    drop_blocking(provider);
}

/// An unknown remote outcome is never retried blindly: the peer's failure
/// status denies typed, nothing is accounted, and only one request runs.
#[tokio::test]
async fn openai_codex_unknown_outcome_is_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/backend-api/codex/responses"))
        .respond_with(ResponseTemplate::new(503).set_body_string("peer failure body"))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&support::codex_provider_config(
        "openai-codex",
        &codex_uri(&server),
    ))
    .expect("valid");
    let (provider, _store) = codex_provider(&config, "openai-codex");
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/codex", "goal: unknown outcome")
        .expect("the codex pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/codex", manifest);
    let Err(ModelError::Provider(ProviderError::Transport { cause, .. })) = outcome else {
        panic!("the peer's status is the typed transport denial: {outcome:?}");
    };
    assert_eq!(cause.class(), TransportClass::HttpStatus { code: 503 });
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        1,
        "an unknown outcome is never retried blindly"
    );
}

/// A pinned model outside the closed recorded route denies typed before
/// the wire — the account listing never widens what this contract serves.
#[tokio::test]
async fn openai_codex_model_outside_the_recorded_route_denies() {
    for connection in ["openai-codex", "openai-codex-device"] {
        let server = MockServer::start().await;
        let config = Config::parse_validated(&format!(
            "config_version = 1\n\
             [connections.{connection}]\nkind = \"api_key\"\nendpoint = \"{}\"\n\
             credential_ref = \"{}\"\nprofile = \"openai-codex\"\n\
             [profiles.openai-codex]\ncredential_ref = \"{}\"\n\
             [models.defaults]\n\
             model = {{ mode = \"fixed\", connection = \"{connection}\", model_id = \"gpt-5.2\" }}\n\
             effort = {{ mode = \"fixed\", value = \"medium\" }}\nfallback = {{ mode = \"off\" }}\n",
            codex_uri(&server),
            support::CODEX_REF,
            support::CODEX_REF,
        ))
        .expect("valid");
        let (provider, _store) = codex_provider(&config, connection);
        let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
        let err = outcome.expect_err("a model outside the recorded route denies");
        assert!(
            matches!(&err, ProviderError::UnsupportedParameter { connection: denied, parameter, model }
                if denied == connection && *parameter == "model" && model == "gpt-5.2"),
            "the closed-route denial is typed for {connection}: {err:?}"
        );
        drop_blocking(provider);
        assert!(
            server
                .received_requests()
                .await
                .expect("recorded")
                .is_empty(),
            "the denial for {connection} lands before any wire leg"
        );
    }
}

/// A same-contract alias cannot slip past after its canonical entry was
/// attempted and failed: every failed connection in the walk is a refusal
/// source, so only the first codex entry crosses the wire.
#[tokio::test]
async fn openai_codex_chain_refuses_every_sibling_after_an_attempted_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/backend-api/codex/responses"))
        .respond_with(ResponseTemplate::new(401).set_body_string("peer failure body"))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.primary]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1/primary\"\n\
         [connections.openai-codex]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\n\
         credential_ref = \"{reference}\"\nprofile = \"openai-codex\"\n\
         [connections.openai-codex-device]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\n\
         credential_ref = \"{reference}\"\nprofile = \"openai-codex\"\n\
         [profiles.openai-codex]\ncredential_ref = \"{reference}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"primary\", model_id = \"fixture-primary\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"auto\", chain = [\
             {{ mode = \"fixed\", connection = \"openai-codex\", model_id = \"gpt-5.2-codex\" }}, \
             {{ mode = \"fixed\", connection = \"openai-codex-device\", model_id = \"gpt-5.2-codex\" }}] }}\n",
        endpoint = codex_uri(&server),
        reference = support::CODEX_REF,
    ))
    .expect("valid");
    let (provider, sent) =
        ChainProvider::new(&config, &["primary", "openai-codex", "openai-codex-device"]);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/codex", "goal: chain refusal")
        .expect("the chain config prepares");
    let (broker, outcome) = dispatch(broker, "/world/codex", manifest);
    let Err(ModelError::FallbackExhausted {
        rejected,
        attempted,
        ..
    }) = outcome
    else {
        panic!("the chain exhausts: {outcome:?}");
    };
    assert_eq!(
        attempted,
        vec!["openai-codex".to_string()],
        "only the first codex entry was attempted"
    );
    assert_eq!(rejected.len(), 2, "the attempted entry and the refusal");
    assert!(
        matches!(rejected[0].cause, RejectionCause::SendFailed(_)),
        "the first codex entry's own failure is retained: {:?}",
        rejected[0].cause
    );
    assert_eq!(rejected[1].connection, "openai-codex-device");
    assert!(
        matches!(rejected[1].cause, RejectionCause::BlindRetryRefused),
        "the alias is refused after its canonical entry failed: {:?}",
        rejected[1].cause
    );
    drop_blocking(broker);
    assert_eq!(
        *sent.lock().expect("send log lock"),
        vec!["primary".to_string(), "openai-codex".to_string()],
        "the alias never reached the provider"
    );
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        1,
        "the alias opened no second request"
    );
}

/// A different contract after a same-contract refusal is still attempted:
/// the walk continues past the refusal instead of ending the chain.
#[tokio::test]
async fn openai_codex_chain_continues_past_a_same_contract_refusal() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/backend-api/codex/responses"))
        .respond_with(ResponseTemplate::new(401).set_body_string("peer failure body"))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.openai-codex]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\n\
         credential_ref = \"{reference}\"\nprofile = \"openai-codex\"\n\
         [connections.openai-codex-device]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\n\
         credential_ref = \"{reference}\"\nprofile = \"openai-codex\"\n\
         [connections.reserve]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1/reserve\"\n\
         [profiles.openai-codex]\ncredential_ref = \"{reference}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"openai-codex\", model_id = \"gpt-5.2-codex\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"auto\", chain = [\
             {{ mode = \"fixed\", connection = \"openai-codex-device\", model_id = \"gpt-5.2-codex\" }}, \
             {{ mode = \"fixed\", connection = \"reserve\", model_id = \"fixture-reserve\" }}] }}\n",
        endpoint = codex_uri(&server),
        reference = support::CODEX_REF,
    ))
    .expect("valid");
    let (provider, sent) =
        ChainProvider::new(&config, &["openai-codex", "openai-codex-device", "reserve"]);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/codex", "goal: chain continuation")
        .expect("the chain config prepares");
    let (broker, outcome) = dispatch(broker, "/world/codex", manifest);
    let Err(ModelError::FallbackExhausted {
        rejected,
        attempted,
        ..
    }) = outcome
    else {
        panic!("the chain exhausts after the reserve fails: {outcome:?}");
    };
    assert_eq!(rejected.len(), 2);
    assert_eq!(rejected[0].connection, "openai-codex-device");
    assert!(
        matches!(rejected[0].cause, RejectionCause::BlindRetryRefused),
        "the alias is refused: {:?}",
        rejected[0].cause
    );
    assert_eq!(rejected[1].connection, "reserve");
    assert!(
        matches!(rejected[1].cause, RejectionCause::SendFailed(_)),
        "the different contract was attempted and failed: {:?}",
        rejected[1].cause
    );
    assert_eq!(
        attempted,
        vec!["reserve".to_string()],
        "the walk continued past the refusal"
    );
    drop_blocking(broker);
    assert_eq!(
        *sent.lock().expect("send log lock"),
        vec!["openai-codex".to_string(), "reserve".to_string()],
        "primary plus the different-contract entry"
    );
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        1,
        "the refusal and reserve opened no codex request"
    );
}

/// The account scope is recorded, never invented: a credential without
/// `account_id` sends both legs successfully and carries no
/// `chatgpt-account-id` header.
#[tokio::test]
async fn openai_codex_account_absent_sends_without_scope_header() {
    let server = MockServer::start().await;
    mount_codex_models(&server, json!([{"id": "gpt-5.2-codex"}])).await;
    mount_codex_responses(
        &server,
        responses_completed_stream(
            "unscoped outcome",
            Vec::new(),
            Some(json!({"input_tokens": 2, "output_tokens": 3, "total_tokens": 5})),
        ),
    )
    .await;
    let config = Config::parse_validated(&support::codex_provider_config(
        "openai-codex",
        &codex_uri(&server),
    ))
    .expect("valid");
    let credential = support::codex_stored_credential_without_account();
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(support::CODEX_REF, credential.as_str())],
    ));
    let provider = provider_result(config.clone(), "openai-codex".to_string(), store)
        .expect("the adapter builds");
    let (provider, catalogue) = std::thread::spawn(move || {
        let catalogue = provider.catalog();
        (provider, catalogue)
    })
    .join()
    .expect("the catalogue thread joins");
    assert_eq!(
        catalogue.expect("the unscoped catalogue answers"),
        vec!["gpt-5.2-codex".to_string()]
    );
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/codex", "goal: unscoped")
        .expect("the codex pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/codex", manifest.clone());
    let reply = outcome.expect("the unscoped send answers");
    assert_eq!(reply.text, "unscoped outcome");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 2,
            completion_tokens: 3,
            total_tokens: 5,
        }
    );
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the unscoped send is accounted");
    assert_eq!(record.connection, "openai-codex");
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 2, "one catalogue and one inference leg");
    for request in &requests {
        assert_eq!(received_auth(request), codex_bearer());
        assert!(
            request.headers.get("chatgpt-account-id").is_none(),
            "an absent workspace claim sends no account header on {}",
            request.url.path()
        );
    }
}

// ----- TP-PROVIDER-INSTALLED::openai-codex --------------------------

/// TP-PROVIDER-INSTALLED::openai-codex = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs, and
/// `openai-codex::class-002` WebSocket stays NOT_RUN (DEC-017).
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::openai-codex = NOT_RUN; openai-codex::class-002 WebSocket = NOT_RUN (DEC-017)"]
fn provider_installed_openai_codex() {}

/// An entered unknown outcome ends the auto chain before any candidate is
/// consulted: the primary's own typed failure is the outcome, no substitute
/// send is attempted — not even onto the other Codex id — and only the
/// failed primary crossed the wire.
#[tokio::test]
async fn openai_codex_unknown_outcome_chain_on_same_contract_is_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/backend-api/codex/responses"))
        .respond_with(ResponseTemplate::new(503).set_body_string("peer failure body"))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.openai-codex]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\n\
         credential_ref = \"{reference}\"\nprofile = \"openai-codex\"\n\
         [connections.openai-codex-device]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\n\
         credential_ref = \"{reference}\"\nprofile = \"openai-codex\"\n\
         [profiles.openai-codex]\ncredential_ref = \"{reference}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"openai-codex\", model_id = \"gpt-5.2-codex\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"auto\", chain = [{{ mode = \"fixed\", connection = \"openai-codex-device\", model_id = \"gpt-5.2-codex\" }}] }}\n",
        endpoint = codex_uri(&server),
        reference = support::CODEX_REF,
    ))
    .expect("valid");
    let (provider, _store) = codex_provider(&config, "openai-codex");
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/codex", "goal: no blind fallback")
        .expect("the codex pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/codex", manifest);
    // An entered unknown outcome ends the chain before any candidate is
    // consulted: a 503 may already have applied, so no substitute may run.
    let Err(ModelError::Provider(ProviderError::Transport { connection, cause })) = outcome else {
        panic!("the primary's unknown outcome is the typed outcome: {outcome:?}");
    };
    assert_eq!(connection, "openai-codex");
    assert_eq!(
        cause.class(),
        TransportClass::HttpStatus { code: 503 },
        "the primary's own unknown outcome is retained"
    );
    drop_blocking(broker);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        1,
        "only the failed primary crossed the wire"
    );
}

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

/// Cached prompt and folded reasoning details ride as their own legs
/// (AC-057), with the completion bin unchanged.
#[tokio::test]
async fn response_usage_detail_legs_are_carried() {
    let server = MockServer::start().await;
    let config = Config::parse_validated(&openai_config(&server_uri_v1(&server))).expect("valid");
    mount_responses(
        &server,
        responses_completed_stream(
            "cached",
            Vec::new(),
            Some(json!({
                "input_tokens": 5,
                "output_tokens": 7,
                "total_tokens": 12,
                "input_tokens_details": { "cached_tokens": 3 },
                "output_tokens_details": { "reasoning_tokens": 2 },
            })),
        ),
    )
    .await;
    let (broker, manifest) = prepared(&config, "/world/openai", "goal: detail legs");
    let (broker, outcome) = dispatch(broker, "/world/openai", manifest.clone());
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
