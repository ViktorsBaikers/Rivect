//! Offline GitHub Copilot CAPI proof: the three recorded route families,
//! the credential-derived base and CAPI identity, the closed 44-id
//! table, the catalogue filter, the producer round trip, and the denial
//! legs. One loopback wiremock peer per leg; no live GitHub account or
//! request.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/discard conveniences and block-wise fixture assembly; src/ stays strict (standards §14)"
)]

use rivect::config::{Config, ModelAssign};
use rivect::model::{
    Broker, CandidateRejection, ModelError, NullLedger, RejectionCause, RequestManifest,
};
use rivect::providers::anthropic::MessagesProvider;
use rivect::providers::copilot::CopilotProvider;
use rivect::providers::copilot_login::{self, Advance, DeviceEndpoints};
use rivect::providers::local::ChatCompletionsProvider;
use rivect::providers::openai::OpenAiProvider;
use rivect::providers::routed::RoutedProvider;
use rivect::providers::{
    CredentialStore, Dialect, LoopbackProvider, Provider, ProviderError, ProviderReply, StoreKind,
    TransportClass, dialect_for, resolve_credential, route_for, routes_for,
};
use rivect::resources::UsageDelta;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{method, path as path_matcher};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

mod support;

/// Print one offline receipt marker for a provider trial.
fn emit_provider_row(trial: &str, provider: &str) {
    println!(
        "ROW {} ok",
        rivect::verification::provider_case(trial, provider)
    );
}

use support::{MapStore, drop_blocking, prepared_with, responses_completed_stream, sse_block};

const CONNECTION: &str = "github-copilot";
const REF: &str = "keyring:rivect-test/github-copilot";
const FALLBACK_CONNECTION: &str = "openai";
const FALLBACK_REF: &str = "keyring:rivect-test/openai";
const STORE_KIND: StoreKind = StoreKind::Keychain;
const TOKEN: &str = "fixture-copilot-token-not-real";
/// A sentinel standing in for material a diagnostic must never echo.
const MARKER: &str = "fixture-secret-marker-4c1d";
const WORLD: &str = "/world/github-copilot";
const MESSAGES_MODEL: &str = "claude-opus-4.6";
const RESPONSES_MODEL: &str = "gpt-5.2";
const CHAT_MODEL: &str = "gpt-4o";
const OUTSIDE_MODEL: &str = "claude-mythos-9";
const MESSAGES_PATH: &str = "/v1/messages";
const RESPONSES_PATH: &str = "/responses";
const CHAT_PATH: &str = "/chat/completions";
const MODELS_PATH: &str = "/models";

/// The CAPI identity the recorded provider contract requires on every
/// catalogue and wire leg.
const CAPI_HEADERS: [(&str, &str); 6] = [
    ("user-agent", "copilot/1.0.82"),
    ("editor-version", "copilot/1.0.82"),
    ("copilot-integration-id", "copilot-developer-cli"),
    ("copilot-harness-id", "copilot-sdk"),
    ("openai-intent", "conversation-agent"),
    ("x-github-api-version", "2026-08-01"),
];

fn copilot_config(model: &str) -> Config {
    let document = format!(
        "config_version = 1\n\
         [connections.{CONNECTION}]\n\
         kind = \"api_key\"\n\
         endpoint = \"\"\n\
         credential_ref = \"{REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{CONNECTION}\", model_id = \"{model}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    );
    Config::parse_validated(&document).expect("the copilot fixture config validates")
}

fn stored_credential(token: &str) -> String {
    json!({ "token": token, "expires_at": 4_102_444_800_u64 }).to_string()
}

/// The same pin under a configured region, which the owner refuses.
fn region_config() -> Config {
    let document = format!(
        "config_version = 1\n\
         [connections.{CONNECTION}]\n\
         kind = \"api_key\"\n\
         endpoint = \"\"\n\
         credential_ref = \"{REF}\"\n\
         region = \"eu-west-1\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{CONNECTION}\", model_id = \"{CHAT_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    );
    Config::parse_validated(&document).expect("the region fixture config validates")
}

/// A `local` declaration for the id, optionally carrying the
/// contradictory profile member the build gate names first.
fn local_config(profile: Option<&str>) -> Config {
    let binding = match profile {
        Some(name) => {
            format!("profile = \"{name}\"\n[profiles.{name}]\ncredential_ref = \"{REF}\"\n")
        }
        None => String::new(),
    };
    let document = format!(
        "config_version = 1\n\
         [connections.{CONNECTION}]\n\
         kind = \"local\"\n\
         endpoint = \"\"\n\
         {binding}\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{CONNECTION}\", model_id = \"{CHAT_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    );
    Config::parse_validated(&document).expect("the local-declaration fixture config validates")
}

/// The pin with an auto chain entry naming a second offline-eligible
/// connection whose endpoint is the reserve peer.
fn fallback_config(reserve_base: &str) -> Config {
    let document = format!(
        "config_version = 1\n\
         [connections.{CONNECTION}]\n\
         kind = \"api_key\"\n\
         endpoint = \"\"\n\
         credential_ref = \"{REF}\"\n\
         [connections.{FALLBACK_CONNECTION}]\n\
         kind = \"api_key\"\n\
         endpoint = \"{reserve_base}\"\n\
         credential_ref = \"{FALLBACK_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{CONNECTION}\", model_id = \"{CHAT_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"auto\", chain = [{{ mode = \"fixed\", connection = \"{FALLBACK_CONNECTION}\", model_id = \"{RESPONSES_MODEL}\" }}] }}\n"
    );
    Config::parse_validated(&document).expect("the fallback fixture config validates")
}

fn stored_credential_with_endpoint(token: &str, endpoint: &str) -> String {
    json!({
        "token": token,
        "api_endpoint": endpoint,
        "expires_at": 4_102_444_800_u64,
    })
    .to_string()
}

fn stored_credential_with_enterprise(token: &str, enterprise: &str) -> String {
    json!({
        "token": token,
        "enterprise_url": enterprise,
        "expires_at": 4_102_444_800_u64,
    })
    .to_string()
}

fn fixture_provider(
    config: &Config,
    material: &str,
    base_override: Option<String>,
) -> (CopilotProvider, Arc<MapStore>) {
    let store = Arc::new(MapStore::seeded(STORE_KIND, &[(REF, material)]));
    let provider = provider_from_store(config, Arc::clone(&store), base_override);
    (provider, store)
}

fn provider_from_store(
    config: &Config,
    store: Arc<MapStore>,
    base_override: Option<String>,
) -> CopilotProvider {
    provider_result(config, store, base_override).expect("the copilot adapter builds")
}

fn provider_result(
    config: &Config,
    store: Arc<MapStore>,
    base_override: Option<String>,
) -> Result<CopilotProvider, ProviderError> {
    let config = config.clone();
    std::thread::spawn(move || {
        CopilotProvider::with_base_override(
            &config,
            CONNECTION,
            store,
            Duration::from_secs(5),
            base_override,
        )
    })
    .join()
    .expect("the provider thread joins")
}

fn prepare_with_provider(
    config: &Config,
    (provider, store): (CopilotProvider, Arc<MapStore>),
    world: &str,
) -> (Broker, RequestManifest) {
    prepared_with(
        (provider, store),
        config,
        world,
        "goal: prove the copilot wire",
    )
}

fn dispatch(
    mut broker: Broker,
    world: &str,
    manifest: RequestManifest,
) -> (Broker, Result<ProviderReply, ModelError>) {
    let world = world.to_string();
    std::thread::spawn(move || {
        let outcome = broker.dispatch(&mut NullLedger, &world, &manifest);
        (broker, outcome)
    })
    .join()
    .expect("the dispatch thread joins")
}

fn provider_denial(outcome: Result<ProviderReply, ModelError>) -> ProviderError {
    match outcome {
        Err(ModelError::Provider(error)) => error,
        Err(other) => panic!("expected a provider denial, got {other:?}"),
        Ok(reply) => panic!("expected a denial, got a reply: {reply:?}"),
    }
}

fn denial_status(error: &ProviderError) -> u16 {
    let ProviderError::Transport { cause, .. } = error else {
        panic!("expected a transport denial, got {error:?}");
    };
    match cause.class() {
        TransportClass::HttpStatus { code } => code,
        other => panic!("expected an http status, got {other:?}"),
    }
}

/// One fixture send that must deny: the provider error plus the broker
/// that would have accounted the request.
fn denied_dispatch(
    config: &Config,
    material: &str,
    base_override: Option<String>,
) -> (Broker, ProviderError) {
    let (provider, store) = fixture_provider(config, material, base_override);
    let (broker, prepared) = prepare_with_provider(config, (provider, store), WORLD);
    let (broker, outcome) = dispatch(broker, WORLD, prepared);
    (broker, provider_denial(outcome))
}

fn header<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
}

fn assert_capi_headers(request: &Request) {
    for (name, value) in CAPI_HEADERS {
        assert_eq!(header(request, name), Some(value), "{name}");
    }
}

fn assert_capi_auth(request: &Request) {
    let expected = format!("Bearer {TOKEN}");
    assert_eq!(header(request, "authorization"), Some(expected.as_str()));
}

fn data_block(chunk: &Value) -> String {
    format!("data: {chunk}\n\n")
}

fn messages_start(input_tokens: u64) -> String {
    sse_block(
        "message_start",
        &json!({
            "type": "message_start",
            "message": {
                "id": "msg_copilot",
                "type": "message",
                "role": "assistant",
                "content": [],
                "usage": {"input_tokens": input_tokens, "output_tokens": 1},
            },
        }),
    )
}

fn messages_text_stream(text: &str, input_tokens: u64, output_tokens: u64) -> String {
    format!(
        "{}{}{}{}{}{}",
        messages_start(input_tokens),
        sse_block(
            "content_block_start",
            &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ),
        sse_block(
            "content_block_delta",
            &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}}),
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
                "usage": {"output_tokens": output_tokens},
            }),
        ),
        sse_block("message_stop", &json!({"type": "message_stop"})),
    )
}

fn messages_partial_tool_stream() -> String {
    format!(
        "{}{}{}{}{}",
        messages_start(1),
        sse_block(
            "content_block_start",
            &json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "tool-1",
                    "name": "read_file",
                    "input": {},
                },
            }),
        ),
        sse_block(
            "content_block_delta",
            &json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": "{\"path\":\"a"},
            }),
        ),
        sse_block(
            "message_delta",
            &json!({
                "type": "message_delta",
                "delta": {"stop_reason": "tool_use"},
                "usage": {"output_tokens": 1},
            }),
        ),
        sse_block("message_stop", &json!({"type": "message_stop"})),
    )
}

fn chat_stream(text: &str, usage: Option<Value>) -> String {
    let mut body = data_block(
        &json!({"id": "c1", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": null}]}),
    );
    body.push_str(&data_block(
        &json!({"id": "c1", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}),
    ));
    if let Some(usage) = usage {
        body.push_str(&data_block(
            &json!({"id": "c1", "choices": [], "usage": usage}),
        ));
    }
    body.push_str("data: [DONE]\n\n");
    body
}

fn chat_unknown_terminal() -> String {
    format!(
        "{}{}{}",
        data_block(
            &json!({"id": "c1", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"role": "assistant", "content": "unfinished"}, "finish_reason": null}]}),
        ),
        data_block(
            &json!({"id": "c1", "choices": [{"index": 0, "delta": {}, "finish_reason": "mystery"}]}),
        ),
        "data: [DONE]\n\n",
    )
}

async fn mount_sse(server: &MockServer, route: &str, body: String) {
    Mock::given(method("POST"))
        .and(path_matcher(route))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(server)
        .await;
}

async fn mount_models(server: &MockServer, ids: &[&str]) {
    let data: Vec<Value> = ids.iter().map(|id| json!({ "id": id })).collect();
    Mock::given(method("GET"))
        .and(path_matcher(MODELS_PATH))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"object": "list", "data": data})),
        )
        .mount(server)
        .await;
}

fn records_path(requests: &[Request], route: &str) {
    assert_eq!(requests.len(), 1, "one physical request");
    assert_eq!(requests[0].url.path(), route);
}

#[tokio::test]
async fn copilot_messages_path_yields_one_outcome_and_one_physical_usage() {
    emit_provider_row("WIRE", "github-copilot");
    let server = MockServer::start().await;
    mount_sse(
        &server,
        MESSAGES_PATH,
        messages_text_stream("copilot messages", 2, 3),
    )
    .await;
    let config = copilot_config(MESSAGES_MODEL);
    let (provider, store) =
        fixture_provider(&config, &stored_credential(TOKEN), Some(server.uri()));
    let (broker, prepared) = prepare_with_provider(&config, (provider, store), WORLD);

    let (broker, outcome) = dispatch(broker, WORLD, prepared.clone());
    let reply = outcome.expect("the Messages route answers");
    assert_eq!(reply.text, "copilot messages");
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
        .accounting_record(&prepared.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, CONNECTION);
    assert_eq!(record.usage, reply.usage);

    let requests = server.received_requests().await.expect("recorded");
    records_path(&requests, MESSAGES_PATH);
    assert_capi_auth(&requests[0]);
    assert_capi_headers(&requests[0]);
    assert_eq!(
        header(&requests[0], "anthropic-version"),
        Some("2023-06-01")
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], json!(MESSAGES_MODEL));
    drop_blocking(broker);
}

/// A one-member auto pool naming the CAPI connection resolves the closed
/// table's sorted-first id and yields one outcome with one usage.
#[tokio::test]
async fn copilot_auto_picks_the_sorted_first_closed_table_row() {
    let server = MockServer::start().await;
    mount_sse(
        &server,
        MESSAGES_PATH,
        messages_text_stream("copilot auto", 1, 2),
    )
    .await;
    let config = copilot_config(MESSAGES_MODEL);
    let (mut provider, _store) =
        fixture_provider(&config, &stored_credential(TOKEN), Some(server.uri()));
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let mut prepared = broker
        .prepare("main", &config, WORLD, "goal: resolve the auto pin")
        .expect("the auto fixture prepares");
    prepared.model = ModelAssign::Auto {
        pool: Some(vec![CONNECTION.to_string()]),
    };
    drop(broker);

    let reply = tokio::task::spawn_blocking(move || provider.send(&prepared))
        .await
        .expect("the blocking send joins")
        .expect("the auto pin sends");
    assert_eq!(reply.text, "copilot auto");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 1,
            completion_tokens: 2,
            total_tokens: 3,
        }
    );

    let requests = server.received_requests().await.expect("recorded");
    records_path(&requests, MESSAGES_PATH);
    assert_capi_auth(&requests[0]);
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], json!("claude-fable-5"));
}

#[tokio::test]
async fn copilot_responses_path_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    let stream = responses_completed_stream(
        "copilot responses",
        Vec::new(),
        Some(json!({"input_tokens": 4, "output_tokens": 5, "total_tokens": 9})),
    );
    mount_sse(&server, RESPONSES_PATH, stream).await;
    let config = copilot_config(RESPONSES_MODEL);
    let (provider, store) =
        fixture_provider(&config, &stored_credential(TOKEN), Some(server.uri()));
    let (broker, prepared) = prepare_with_provider(&config, (provider, store), WORLD);

    let (broker, outcome) = dispatch(broker, WORLD, prepared.clone());
    let reply = outcome.expect("the Responses route answers");
    assert_eq!(reply.text, "copilot responses");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 4,
            completion_tokens: 5,
            total_tokens: 9,
        }
    );
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&prepared.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, CONNECTION);
    assert_eq!(record.usage, reply.usage);

    let requests = server.received_requests().await.expect("recorded");
    records_path(&requests, RESPONSES_PATH);
    assert_capi_auth(&requests[0]);
    assert_capi_headers(&requests[0]);
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], json!(RESPONSES_MODEL));
    drop_blocking(broker);
}

#[tokio::test]
async fn copilot_chat_completions_path_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_sse(
        &server,
        CHAT_PATH,
        chat_stream(
            "copilot chat",
            Some(json!({"prompt_tokens": 9, "completion_tokens": 4, "total_tokens": 13})),
        ),
    )
    .await;
    let config = copilot_config(CHAT_MODEL);
    let (provider, store) =
        fixture_provider(&config, &stored_credential(TOKEN), Some(server.uri()));
    let (broker, prepared) = prepare_with_provider(&config, (provider, store), WORLD);

    let (broker, outcome) = dispatch(broker, WORLD, prepared.clone());
    let reply = outcome.expect("the Chat Completions default answers");
    assert_eq!(reply.text, "copilot chat");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 9,
            completion_tokens: 4,
            total_tokens: 13,
        }
    );
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&prepared.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, CONNECTION);
    assert_eq!(record.usage, reply.usage);

    let requests = server.received_requests().await.expect("recorded");
    records_path(&requests, CHAT_PATH);
    assert_capi_auth(&requests[0]);
    assert_capi_headers(&requests[0]);
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], json!(CHAT_MODEL));
    drop_blocking(broker);
}

/// Every leg carries the managed CAPI identity: the `/models` catalogue
/// and each route's inference post.
#[tokio::test]
async fn copilot_identity_headers_ride_every_leg() {
    let catalogue = MockServer::start().await;
    mount_models(&catalogue, &[MESSAGES_MODEL, RESPONSES_MODEL, CHAT_MODEL]).await;
    let config = copilot_config(CHAT_MODEL);
    let (provider, _store) =
        fixture_provider(&config, &stored_credential(TOKEN), Some(catalogue.uri()));
    let models = std::thread::spawn(move || provider.catalog_models())
        .join()
        .expect("the catalogue thread joins")
        .expect("the catalogue answers");
    assert_eq!(models.len(), 3);
    let requests = catalogue.received_requests().await.expect("recorded");
    records_path(&requests, MODELS_PATH);
    assert_capi_auth(&requests[0]);
    assert_capi_headers(&requests[0]);

    for (model, route, stream) in [
        (
            MESSAGES_MODEL,
            MESSAGES_PATH,
            messages_text_stream("identity messages", 1, 1),
        ),
        (
            RESPONSES_MODEL,
            RESPONSES_PATH,
            responses_completed_stream("identity responses", Vec::new(), None),
        ),
        (CHAT_MODEL, CHAT_PATH, chat_stream("identity chat", None)),
    ] {
        let server = MockServer::start().await;
        mount_sse(&server, route, stream).await;
        let config = copilot_config(model);
        let (provider, store) =
            fixture_provider(&config, &stored_credential(TOKEN), Some(server.uri()));
        let (broker, prepared) = prepare_with_provider(&config, (provider, store), WORLD);
        let (broker, outcome) = dispatch(broker, WORLD, prepared);
        outcome.expect("the leg answers");
        assert_eq!(
            broker.accounted_requests(),
            1,
            "each route leg is accounted exactly once"
        );
        let requests = server.received_requests().await.expect("recorded");
        records_path(&requests, route);
        assert_capi_auth(&requests[0]);
        assert_capi_headers(&requests[0]);
        drop_blocking(broker);
    }
}

#[tokio::test]
async fn copilot_catalog_filters_to_the_closed_table_and_route() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        &[
            "grok-4.5",
            "gpt-5.2",
            "claude-mythos-9",
            "gpt-4o",
            "claude-opus-4.6",
            "gpt-6-preview",
            "gpt-4o",
            "llama-3",
        ],
    )
    .await;
    let config = copilot_config(CHAT_MODEL);
    let (provider, _store) =
        fixture_provider(&config, &stored_credential(TOKEN), Some(server.uri()));
    let models = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("the catalogue thread joins")
        .expect("the catalogue answers");
    assert_eq!(
        models,
        ["claude-opus-4.6", "gpt-4o", "gpt-5.2", "grok-4.5"].map(String::from),
        "outside-table ids are not offers and duplicates collapse"
    );
    let requests = server.received_requests().await.expect("recorded");
    records_path(&requests, MODELS_PATH);
    assert_capi_auth(&requests[0]);
    assert_capi_headers(&requests[0]);
}

/// The producer's canonical profile is what the provider consumes: the
/// device flow writes the snake_case JSON, and the provider resolves
/// that same scoped profile, its public base and its token.
#[tokio::test]
async fn copilot_stored_credential_round_trips_from_the_producer() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_matcher("/login/device/code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_code": "fixture-device-code",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 900,
            "interval": 5,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_matcher("/login/oauth/access_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": TOKEN,
            "token_type": "bearer",
            "scope": "read:user",
        })))
        .mount(&server)
        .await;
    let config = copilot_config(CHAT_MODEL);
    let store = Arc::new(MapStore::seeded(STORE_KIND, &[]));
    let producer_config = config.clone();
    let producer_store = Arc::clone(&store);
    let endpoints = DeviceEndpoints {
        device_code: format!("{}/login/device/code", server.uri()),
        access_token: format!("{}/login/oauth/access_token", server.uri()),
    };
    let advance = std::thread::spawn(move || {
        let mut session =
            copilot_login::begin_device("", endpoints).expect("the device leg starts");
        copilot_login::advance(
            &producer_config,
            CONNECTION,
            &mut session,
            producer_store.as_ref(),
        )
    })
    .join()
    .expect("the producer thread joins")
    .expect("the device grant completes");
    assert!(matches!(advance, Advance::Complete(_)), "{advance:?}");

    let reference = resolve_credential(&config, CONNECTION).expect("the scoped ref resolves");
    let credential = copilot_login::read_credential(store.as_ref(), &reference)
        .expect("the producer profile parses");
    assert_eq!(credential.token(), TOKEN);
    assert_eq!(credential.enterprise_url(), None);
    assert_eq!(credential.api_endpoint(), None);
    assert!(credential.expires_at() > 0);
    let debug = format!("{credential:?}");
    assert!(
        !debug.contains(TOKEN),
        "the profile Debug redacts its token"
    );

    let raw = store
        .resolve(&reference)
        .expect("the stored profile material resolves");
    let profile: Value = serde_json::from_slice(&raw).expect("the profile is json");
    assert_eq!(profile["token"], json!(TOKEN));
    assert!(profile.get("expires_at").is_some(), "{profile}");
    assert!(profile.get("expiresAt").is_none(), "{profile}");

    let prod_config = config.clone();
    let prod_store = Arc::clone(&store);
    let public_base = std::thread::spawn(move || {
        CopilotProvider::new(&prod_config, CONNECTION, prod_store)
            .expect("the provider builds on the producer profile")
            .resolved_base()
    })
    .join()
    .expect("the base thread joins")
    .expect("the public base resolves");
    assert_eq!(public_base, "https://api.githubcopilot.com");

    mount_sse(&server, CHAT_PATH, chat_stream("producer round trip", None)).await;
    let provider = provider_from_store(&config, Arc::clone(&store), Some(server.uri()));
    let (provider, store) = (provider, store);
    let (broker, prepared) = prepare_with_provider(&config, (provider, store), WORLD);
    let (broker, outcome) = dispatch(broker, WORLD, prepared.clone());
    let reply = outcome.expect("the producer profile drives the wire");
    assert_eq!(reply.text, "producer round trip");
    assert_eq!(broker.accounted_requests(), 1);
    let requests = server.received_requests().await.expect("recorded");
    let wire = requests
        .iter()
        .filter(|request| request.url.path() == CHAT_PATH)
        .count();
    assert_eq!(wire, 1, "one inference leg");
    drop_blocking(broker);
}

#[tokio::test]
async fn copilot_model_outside_the_closed_table_denies() {
    assert_eq!(dialect_for(CONNECTION), Some(Dialect::ChatCompletions));
    assert_eq!(
        routes_for(CONNECTION),
        [
            Dialect::Messages,
            Dialect::ChatCompletions,
            Dialect::Responses
        ]
    );
    assert_eq!(
        route_for(CONNECTION, MESSAGES_MODEL),
        Some(Dialect::Messages)
    );
    assert_eq!(
        route_for(CONNECTION, RESPONSES_MODEL),
        Some(Dialect::Responses)
    );
    assert_eq!(
        route_for(CONNECTION, CHAT_MODEL),
        Some(Dialect::ChatCompletions)
    );
    assert_eq!(route_for(CONNECTION, "gpt-6-preview"), None);
    assert_eq!(route_for(CONNECTION, OUTSIDE_MODEL), None);

    let server = MockServer::start().await;
    let config = copilot_config(OUTSIDE_MODEL);
    let (provider, store) =
        fixture_provider(&config, &stored_credential(TOKEN), Some(server.uri()));
    let (broker, prepared) = prepare_with_provider(&config, (provider, store), WORLD);
    let (broker, outcome) = dispatch(broker, WORLD, prepared);
    let error = provider_denial(outcome);
    match error {
        ProviderError::UnsupportedParameter {
            connection,
            parameter,
            model,
        } => {
            assert_eq!(connection, CONNECTION);
            assert_eq!(parameter, "model");
            assert_eq!(model, OUTSIDE_MODEL);
        }
        other => panic!("expected the closed-table denial, got {other:?}"),
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the closed table denies before any wire leg"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);
}

#[tokio::test]
async fn copilot_wrong_credential_or_origin_denies_without_secrets() {
    emit_provider_row("AUTH", "github-copilot");
    let server = MockServer::start().await;
    let config = copilot_config(CHAT_MODEL);

    // Valid credential origins resolve first: the enrolled https endpoint
    // wins and the enterprise host folds onto its CAPI name.
    let (provider, _store) = fixture_provider(
        &config,
        &stored_credential_with_endpoint(TOKEN, "https://copilot-api.enterprise.example/"),
        None,
    );
    let base = std::thread::spawn(move || provider.resolved_base())
        .join()
        .expect("the base thread joins")
        .expect("the enrolled endpoint is the base");
    assert_eq!(base, "https://copilot-api.enterprise.example");
    let (provider, _store) = fixture_provider(
        &config,
        &stored_credential_with_enterprise(TOKEN, "ghe.example.com"),
        None,
    );
    let base = std::thread::spawn(move || provider.resolved_base())
        .join()
        .expect("the base thread joins")
        .expect("the enterprise host resolves");
    assert_eq!(base, "https://copilot-api.ghe.example.com");

    let (provider, store) = fixture_provider(
        &config,
        r#"{"enterprise_url":"fixture-secret-marker-4c1d","expires_at":4102444800}"#,
        Some(server.uri()),
    );
    let (broker, prepared) = prepare_with_provider(&config, (provider, store), WORLD);
    let (broker, outcome) = dispatch(broker, WORLD, prepared);
    let error = provider_denial(outcome);
    assert!(
        matches!(error, ProviderError::CredentialMalformed { .. }),
        "{error:?}"
    );
    let text = format!("{error} {error:?}");
    assert!(!text.contains(MARKER), "{text}");
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    let (broker, error) = denied_dispatch(
        &config,
        &stored_credential_with_endpoint(TOKEN, &server.uri()),
        None,
    );
    assert!(
        matches!(error, ProviderError::CredentialBaseMismatch { .. }),
        "{error:?}"
    );
    let text = format!("{error} {error:?}");
    assert!(!text.contains(TOKEN), "{text}");
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    // A refused endpoint renders only its safe half: a bare non-URL
    // value shows the fixed marker, and a URL shows scheme+host+port —
    // never the path, query or userinfo that could carry a secret.
    let (broker, error) = denied_dispatch(
        &config,
        &stored_credential_with_endpoint(TOKEN, MARKER),
        None,
    );
    let ProviderError::CredentialBaseMismatch { enrolled, .. } = &error else {
        panic!("a bare endpoint value is refused: {error:?}");
    };
    assert_eq!(enrolled, "<unparsed endpoint>");
    let text = format!("{error} {error:?}");
    assert!(!text.contains(MARKER), "{text}");
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    let marked = format!("https://api.example.com/{MARKER}?probe=1");
    let (broker, error) = denied_dispatch(
        &config,
        &stored_credential_with_endpoint(TOKEN, &marked),
        None,
    );
    let ProviderError::CredentialBaseMismatch { enrolled, .. } = &error else {
        panic!("the query-carrying endpoint is refused: {error:?}");
    };
    assert_eq!(enrolled, "https://api.example.com");
    let text = format!("{error} {error:?}");
    assert!(!text.contains(MARKER), "{text}");
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    let config_for_build = config.clone();
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(REF, stored_credential(TOKEN).as_str())],
    ));
    let refused = std::thread::spawn(move || {
        CopilotProvider::with_base_override(
            &config_for_build,
            CONNECTION,
            store,
            Duration::from_secs(5),
            Some("https://api.githubcopilot.com".to_string()),
        )
    })
    .join()
    .expect("the build thread joins");
    assert!(matches!(
        refused,
        Err(ProviderError::UnsendableRequest { .. })
    ));
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "no denial leg opens a request"
    );
}

#[tokio::test]
async fn copilot_permanent_auth_denial_is_not_retried() {
    for status in [401_u16, 403] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_matcher(MESSAGES_PATH))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        let config = copilot_config(MESSAGES_MODEL);
        let (provider, store) =
            fixture_provider(&config, &stored_credential(TOKEN), Some(server.uri()));
        let (broker, prepared) = prepare_with_provider(&config, (provider, store), WORLD);
        let (broker, outcome) = dispatch(broker, WORLD, prepared);
        let error = provider_denial(outcome);
        assert_eq!(denial_status(&error), status);
        assert_eq!(broker.accounted_requests(), 0);
        let text = format!("{error} {error:?}");
        assert!(!text.contains(TOKEN), "{text}");
        let requests = server.received_requests().await.expect("recorded");
        assert_eq!(requests.len(), 1, "status {status}: no retry");
        assert_eq!(requests[0].url.path(), MESSAGES_PATH);
        drop_blocking(broker);
    }
}

#[tokio::test]
async fn copilot_rate_limit_is_bounded_without_cross_id_fallback() {
    emit_provider_row("RECOVERY", "github-copilot");
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_matcher(CHAT_PATH))
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;
    let config = copilot_config(CHAT_MODEL);
    let (provider, store) =
        fixture_provider(&config, &stored_credential(TOKEN), Some(server.uri()));
    let (broker, prepared) = prepare_with_provider(&config, (provider, store), WORLD);
    let (broker, outcome) = dispatch(broker, WORLD, prepared);
    let error = provider_denial(outcome);
    assert_eq!(denial_status(&error), 429);
    assert_eq!(broker.accounted_requests(), 0);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the rate limit is not retried");
    assert_eq!(requests[0].url.path(), CHAT_PATH);
    drop_blocking(broker);
}

#[tokio::test]
async fn copilot_partial_tool_block_and_unknown_terminal_deny() {
    let partial_server = MockServer::start().await;
    mount_sse(
        &partial_server,
        MESSAGES_PATH,
        messages_partial_tool_stream(),
    )
    .await;
    let config = copilot_config(MESSAGES_MODEL);
    let (provider, store) = fixture_provider(
        &config,
        &stored_credential(TOKEN),
        Some(partial_server.uri()),
    );
    let (broker, prepared) = prepare_with_provider(&config, (provider, store), WORLD);
    let (broker, outcome) = dispatch(broker, WORLD, prepared);
    let error = provider_denial(outcome);
    assert!(
        matches!(error, ProviderError::StreamViolation { .. }),
        "{error:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    assert_eq!(
        partial_server
            .received_requests()
            .await
            .expect("recorded")
            .len(),
        1
    );
    drop_blocking(broker);

    let terminal_server = MockServer::start().await;
    mount_sse(&terminal_server, CHAT_PATH, chat_unknown_terminal()).await;
    let config = copilot_config(CHAT_MODEL);
    let (provider, store) = fixture_provider(
        &config,
        &stored_credential(TOKEN),
        Some(terminal_server.uri()),
    );
    let (broker, prepared) = prepare_with_provider(&config, (provider, store), WORLD);
    let (broker, outcome) = dispatch(broker, WORLD, prepared);
    let error = provider_denial(outcome);
    assert!(
        matches!(error, ProviderError::UnknownTerminal { .. }),
        "{error:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    let requests = terminal_server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the unknown terminal is not retried");
    assert_eq!(requests[0].url.path(), CHAT_PATH);
    drop_blocking(broker);
}

#[tokio::test]
async fn copilot_direct_codec_construction_is_refused() {
    let server = MockServer::start().await;
    let config = copilot_config(MESSAGES_MODEL);
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(REF, stored_credential(TOKEN).as_str())],
    ));
    let (messages, responses, chat, routed) = {
        let config = config.clone();
        let store: Arc<dyn CredentialStore> = Arc::<MapStore>::clone(&store);
        std::thread::spawn(move || {
            (
                MessagesProvider::new(&config, CONNECTION, Arc::clone(&store)),
                OpenAiProvider::new(&config, CONNECTION, Arc::clone(&store)),
                ChatCompletionsProvider::new(&config, CONNECTION, Arc::clone(&store)),
                RoutedProvider::new(&config, CONNECTION, store),
            )
        })
        .join()
        .expect("the build thread joins")
    };
    assert!(
        matches!(messages, Err(ProviderError::DialectMismatch { .. })),
        "the Messages codec must refuse the owner's id"
    );
    assert!(
        matches!(responses, Err(ProviderError::DialectMismatch { .. })),
        "the Responses codec must refuse the owner's id"
    );
    assert!(
        matches!(chat, Err(ProviderError::DialectMismatch { .. })),
        "the Chat Completions codec must refuse the owner's id"
    );
    assert!(
        matches!(routed, Err(ProviderError::DialectMismatch { .. })),
        "the routed codec must refuse the owner's id"
    );
    let reversed = {
        let config = config.clone();
        let store: Arc<dyn CredentialStore> = Arc::<MapStore>::clone(&store);
        std::thread::spawn(move || CopilotProvider::new(&config, "openai", store))
            .join()
            .expect("the reverse-id thread joins")
    };
    assert!(
        matches!(reversed, Err(ProviderError::DialectMismatch { .. })),
        "the owner refuses to serve another connection's id"
    );
    let owner = {
        let config = config.clone();
        let store: Arc<dyn CredentialStore> = store;
        std::thread::spawn(move || CopilotProvider::new(&config, CONNECTION, store))
            .join()
            .expect("the owner thread joins")
    };
    assert!(owner.is_ok(), "the Copilot owner is the only builder");
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "construction opens no wire leg"
    );
}

/// The owner's build gates: a configured region, a `local` declaration
/// (with or without the contradictory profile member), and another id
/// all deny typed before the credential resolves or a wire leg opens.
#[tokio::test]
async fn copilot_owner_gates_deny_before_the_credential() {
    let server = MockServer::start().await;

    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(REF, stored_credential(TOKEN).as_str())],
    ));
    let refused = provider_result(&region_config(), store, Some(server.uri()));
    assert!(
        matches!(
            refused,
            Err(ProviderError::RegionMismatch { ref connection, .. }) if connection == CONNECTION
        ),
        "a configured region denies typed: {refused:?}"
    );

    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(REF, stored_credential(TOKEN).as_str())],
    ));
    let refused = provider_result(
        &local_config(Some("copilot-profile")),
        store,
        Some(server.uri()),
    );
    assert!(
        matches!(
            refused,
            Err(ProviderError::LocalProfileDeclared { ref connection }) if connection == CONNECTION
        ),
        "a local declaration binding a profile denies typed: {refused:?}"
    );

    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(REF, stored_credential(TOKEN).as_str())],
    ));
    let refused = provider_result(&local_config(None), store, Some(server.uri()));
    assert!(
        matches!(
            refused,
            Err(ProviderError::CredentialUnresolved { ref connection, ref scope, .. })
                if connection == CONNECTION && scope == "connections.github-copilot.kind"
        ),
        "a local declaration denies typed: {refused:?}"
    );

    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "no build gate opens a wire leg"
    );
}

/// The owner's material gates: blank stored material (either form), a
/// credential-named base with userinfo, a query, a fragment or a loopback
/// host, and an empty store all deny typed with zero requests and zero
/// accounting.
#[tokio::test]
async fn copilot_material_gates_deny_before_the_wire() {
    let server = MockServer::start().await;
    let config = copilot_config(CHAT_MODEL);

    for material in [stored_credential("   "), "  ".to_string()] {
        let (broker, error) = denied_dispatch(&config, &material, Some(server.uri()));
        assert!(
            matches!(error, ProviderError::CredentialMalformed { .. }),
            "blank material denies typed: {error:?}"
        );
        assert_eq!(broker.accounted_requests(), 0);
        drop_blocking(broker);
    }

    for (endpoint, secret) in [
        ("https://user:fixture-pass@api.example.com", "fixture-pass"),
        (
            "https://api.example.com/v1?access_token=fixture-query",
            "fixture-query",
        ),
        (
            "https://api.example.com/v1#fixture-fragment",
            "fixture-fragment",
        ),
    ] {
        let material = stored_credential_with_endpoint(TOKEN, endpoint);
        let (broker, error) = denied_dispatch(&config, &material, None);
        assert!(
            matches!(error, ProviderError::CredentialBaseMismatch { .. }),
            "{endpoint} denies typed: {error:?}"
        );
        let text = format!("{error} {error:?}");
        assert!(!text.contains(secret), "{endpoint}: {text}");
        assert_eq!(broker.accounted_requests(), 0);
        drop_blocking(broker);
    }

    for endpoint in [
        "https://[::1]",
        "https://copilot-api.localhost",
        "https://127.0.0.2",
    ] {
        let material = stored_credential_with_endpoint(TOKEN, endpoint);
        let (broker, error) = denied_dispatch(&config, &material, None);
        assert!(
            matches!(error, ProviderError::CredentialBaseMismatch { .. }),
            "{endpoint} denies typed: {error:?}"
        );
        assert_eq!(broker.accounted_requests(), 0);
        drop_blocking(broker);
    }

    let store = Arc::new(MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_from_store(&config, Arc::clone(&store), Some(server.uri()));
    let (broker, prepared) = prepare_with_provider(&config, (provider, store), WORLD);
    let (broker, outcome) = dispatch(broker, WORLD, prepared);
    let error = provider_denial(outcome);
    assert!(
        matches!(error, ProviderError::CredentialAbsent { .. }),
        "an empty store denies typed: {error:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "material denials open no wire leg"
    );
}

/// The recorded raw-token form is a first-class stored material: a
/// trimmed non-JSON byte string is the bearer, resolving the public CAPI
/// base like the JSON profile does.
#[tokio::test]
async fn copilot_raw_token_material_is_the_bearer() {
    let config = copilot_config(CHAT_MODEL);
    let (provider, _store) = fixture_provider(&config, TOKEN, None);
    let base = std::thread::spawn(move || provider.resolved_base())
        .join()
        .expect("the base thread joins")
        .expect("the raw token resolves the public base");
    assert_eq!(base, "https://api.githubcopilot.com");

    let server = MockServer::start().await;
    mount_sse(&server, CHAT_PATH, chat_stream("raw token", None)).await;
    let (provider, store) = fixture_provider(&config, TOKEN, Some(server.uri()));
    let (broker, prepared) = prepare_with_provider(&config, (provider, store), WORLD);
    let (broker, outcome) = dispatch(broker, WORLD, prepared);
    let reply = outcome.expect("a raw stored token rides the wire");
    assert_eq!(reply.text, "raw token");
    assert_eq!(broker.accounted_requests(), 1);
    let requests = server.received_requests().await.expect("recorded");
    records_path(&requests, CHAT_PATH);
    assert_capi_auth(&requests[0]);
    assert_capi_headers(&requests[0]);
    drop_blocking(broker);
}

/// The catalogue filter is fed the whole recorded table: every 44 rows
/// is a routed offer, so the listing returns exactly them, sorted.
#[tokio::test]
async fn copilot_catalog_serves_every_routed_table_row() {
    const ROWS: [&str; 44] = [
        "claude-fable-5",
        "claude-haiku-4.5",
        "claude-opus-4.5",
        "claude-opus-4.6",
        "claude-opus-4.7",
        "claude-opus-4.8",
        "claude-opus-5",
        "claude-sonnet-4",
        "claude-sonnet-4.5",
        "claude-sonnet-4.6",
        "claude-sonnet-5",
        "gemini-2.5-pro",
        "gemini-3-flash-preview",
        "gemini-3-pro-preview",
        "gemini-3.1-pro-preview",
        "gemini-3.5-flash",
        "gemini-3.6-flash",
        "gemini-3.7-flash",
        "gpt-4.1",
        "gpt-4o",
        "gpt-5",
        "gpt-5-mini",
        "gpt-5.1",
        "gpt-5.1-codex",
        "gpt-5.1-codex-max",
        "gpt-5.1-codex-mini",
        "gpt-5.2",
        "gpt-5.2-codex",
        "gpt-5.3-codex",
        "gpt-5.4",
        "gpt-5.4-mini",
        "gpt-5.4-nano",
        "gpt-5.5",
        "gpt-5.6-luna",
        "gpt-5.6-sol",
        "gpt-5.6-terra",
        "grok-4.5",
        "grok-4.6",
        "grok-code-fast-1",
        "kimi-k2.7-code",
        "kimi-k3",
        "mai-code-1-flash-picker",
        "mai-code-1.1-flash",
        "raptor-mini",
    ];
    let server = MockServer::start().await;
    mount_models(&server, &ROWS).await;
    let config = copilot_config(CHAT_MODEL);
    let (provider, _store) =
        fixture_provider(&config, &stored_credential(TOKEN), Some(server.uri()));
    let models = std::thread::spawn(move || provider.catalog())
        .join()
        .expect("the catalogue thread joins")
        .expect("the catalogue answers");
    let mut expected: Vec<String> = ROWS.iter().map(|id| (*id).to_string()).collect();
    expected.sort();
    assert_eq!(models.len(), 44);
    assert_eq!(models, expected, "every routed table row is offered");
}

/// A rate-limited primary never hands its request to another connection:
/// the auto chain's entry is rejected at the pre-send gates, so the
/// reserve peer sees no request and no attempt is accounted.
#[tokio::test]
async fn copilot_rate_limit_never_reaches_the_fallback() {
    let primary = MockServer::start().await;
    let reserve = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_matcher(CHAT_PATH))
        .respond_with(ResponseTemplate::new(429))
        .mount(&primary)
        .await;
    let config = fallback_config(&format!("{}/v1", reserve.uri()));
    let (provider, store) =
        fixture_provider(&config, &stored_credential(TOKEN), Some(primary.uri()));
    let (broker, prepared) = prepare_with_provider(&config, (provider, store), WORLD);
    let (broker, outcome) = dispatch(broker, WORLD, prepared);
    // This proves the adapter's own denial leg leaves the reserve untouched;
    // the configured Broker chain policy is a separate seam (DEC-024).
    let error = outcome.expect_err("the rate limit exhausts the chain");
    let ModelError::FallbackExhausted {
        rejected,
        attempted,
        source,
        ..
    } = error
    else {
        panic!("expected the fallback walk, got {error:?}");
    };
    assert_eq!(denial_status(source.as_ref()), 429);
    assert!(
        attempted.is_empty(),
        "no substitute was dispatched: {attempted:?}"
    );
    assert!(
        matches!(
            rejected.as_slice(),
            [CandidateRejection {
                connection,
                cause: RejectionCause::DialectUnserved { .. },
            }] if connection == FALLBACK_CONNECTION
        ),
        "the unserved reserve is rejected before a send: {rejected:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    let requests = primary.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the rate limit is not retried");
    assert_eq!(requests[0].url.path(), CHAT_PATH);
    assert!(
        reserve
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the reserve peer never receives the rate-limited request"
    );
    drop_blocking(broker);
}
