//! Offline Messages proof for the literal `anthropic` connection
//! (TP-PROVIDER-{CATALOG,AUTH,WIRE,RECOVERY}::anthropic): the configured
//! api-key pin returns one verified outcome and one physical usage
//! through the standard Broker against a localhost `wiremock` peer, the
//! keyed catalogue excludes the recorded snapshots, the auth headers are
//! exactly `x-api-key` + `anthropic-version`, and adverse wire input —
//! a partial tool block, an unknown terminal, a stream without
//! `message_stop`, a non-success status or an expired budget — never
//! reports success. Preserved thinking is replayed bytewise inside its
//! lineage and follows the recorded drop/strip policies.
//!
//! TP-PROVIDER-INSTALLED::anthropic stays NOT_RUN — the ignored named
//! case carries that status explicitly.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    clippy::format_in_format_args,
    reason = "test code keeps unwrap/expect/panic/discard conveniences and block-wise fixture assembly; src/ stays strict (standards §14)"
)]

use rivect::config::{Config, ConfigIssue, EffortLevel, FixedModel, ModelAssign};
use rivect::model::{Broker, ModelError, RequestManifest};
use rivect::providers::anthropic::{MESSAGES_MAX_TOKENS, MessagesProvider};
use rivect::providers::routed::RoutedProvider;
use rivect::providers::{
    CatalogModel, Dialect, ProviderError, ProviderReply, SecretRef, StoreKind, TransportCause,
    TransportClass, WireAuth, dialect_for, route_for, routes_for,
};
use rivect::resources::{Exactness, UsageDelta};
use rivect::state::{SettlementState, StoreLedger, TaskStore};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

mod support;

use support::{MapStore, SlowStore, drop_blocking, prepared_with, send_on_thread, sse_block};

/// The literal connection id this dialect serves.
const CONNECTION: &str = "anthropic";
/// The scoped credential ref the connection binds.
const CREDENTIAL_REF: &str = "keyring:rivect-test/anthropic";
/// A sibling scope holding real material while the bound scope stays
/// empty: seeded so a no-secret assertion proves no cross-scope leak.
const NEIGHBOR_REF: &str = "keyring:rivect-test/neighbor";
/// Fixture material, never a real credential, only sent to localhost.
const SECRET: &str = "fixture-api-key-not-a-real-credential";
const NEIGHBOR_SECRET: &str = "fixture-neighbor-secret-not-real";
const STORE_KIND: StoreKind = StoreKind::Keychain;
const MODEL: &str = "claude-opus-4-8";
const THINKING: &str = "plan the answer";
const SIGNATURE: &str = "sig-fixture-thinking-binding";

/// The literal `umans` connection id this Messages arm serves.
const UMANS: &str = "umans";
/// The scoped credential ref the `umans` connection binds.
const UMANS_CREDENTIAL_REF: &str = "keyring:rivect-test/umans";
/// The pinned `umans` fixture model, never a real roster id.
const UMANS_MODEL: &str = "umans-fixture-model";

/// The literal `minimax` connection id this Messages arm serves.
const MINIMAX: &str = "minimax";
/// The scoped credential ref the `minimax` connection binds.
const MINIMAX_CREDENTIAL_REF: &str = "keyring:rivect-test/minimax";
/// The pinned `minimax` M-series model.
const MINIMAX_MODEL: &str = "MiniMax-M2.7";
/// The recorded M-series offer set in the catalogue's deterministic order.
const MINIMAX_ALLOWLIST: &[&str] = &[
    "MiniMax-M2",
    "MiniMax-M2.1",
    "MiniMax-M2.1-highspeed",
    "MiniMax-M2.5",
    "MiniMax-M2.5-highspeed",
    "MiniMax-M2.7",
    "MiniMax-M2.7-highspeed",
    "MiniMax-M3",
];

/// The literal `cloudflare-ai-gateway` connection id.
const CLOUDFLARE: &str = "cloudflare-ai-gateway";
/// The scoped credential ref the `cloudflare-ai-gateway` connection binds.
const CLOUDFLARE_CREDENTIAL_REF: &str = "keyring:rivect-test/cloudflare-ai-gateway";
/// The recorded static seed; the wire model keeps its upstream prefix.
const CLOUDFLARE_MODEL: &str = "anthropic/claude-opus-4-8";
/// The configured native proxy base path the fixture serves.
const CLOUDFLARE_BASE_PATH: &str = "/v1/account/gateway/anthropic";
/// The inference path the configured base carries.
const CLOUDFLARE_MESSAGES_PATH: &str = "/v1/account/gateway/anthropic/v1/messages";

/// The literal `vercel-ai-gateway` connection id.
const VERCEL: &str = "vercel-ai-gateway";
/// The scoped credential ref the gateway connection binds.
const VERCEL_CREDENTIAL_REF: &str = "keyring:rivect-test/vercel-ai-gateway";
/// A listed row carrying the recorded `tool-use` tag.
const VERCEL_MODEL: &str = "anthropic/claude-opus-5";
/// A listed row without the marker; a pin to it never sends.
const VERCEL_UNMARKED_MODEL: &str = "openai/text-embedding-4";
/// The gateway path inference posts to under the recorded root.
const VERCEL_MESSAGES_PATH: &str = "/v1/messages";
/// The keyed catalogue path the marker is read from.
const VERCEL_MODELS_PATH: &str = "/v1/models";

fn anthropic_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.{CONNECTION}]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{CONNECTION}\", model_id = \"{MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The configured endpoint carries the API base — `/v1` included — the
/// same shape the CLI/config ingress accepts.
fn server_uri_v1(server: &MockServer) -> String {
    format!("{}/v1", server.uri())
}

fn umans_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.{UMANS}]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{UMANS_CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{UMANS}\", model_id = \"{UMANS_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn minimax_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.{MINIMAX}]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{MINIMAX_CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{MINIMAX}\", model_id = \"{MINIMAX_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The configured base is the complete native proxy base — account and
/// gateway included — and inference appends `/v1/messages`.
fn cloudflare_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.{CLOUDFLARE}]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{CLOUDFLARE_CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{CLOUDFLARE}\", model_id = \"{CLOUDFLARE_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn cloudflare_endpoint(server: &MockServer) -> String {
    format!("{}{CLOUDFLARE_BASE_PATH}", server.uri())
}

/// The recorded gateway root is the configured base; inference appends
/// `/v1/messages` and the marker read appends `/v1/models`.
fn vercel_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.{VERCEL}]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{VERCEL_CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{VERCEL}\", model_id = \"{VERCEL_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The same gateway row under the one-connection auto pool.
fn vercel_auto_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.{VERCEL}]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{VERCEL_CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\", pool = [\"{VERCEL}\"] }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// reqwest's blocking client panics inside a tokio context, so every
/// provider build and send runs on a plain OS thread.
fn provider_result(
    config: Config,
    connection: String,
    store: Arc<MapStore>,
) -> Result<MessagesProvider, ProviderError> {
    std::thread::spawn(move || MessagesProvider::new(&config, &connection, store))
        .join()
        .expect("the provider thread joins")
}

fn provider_with_deadline(
    config: &Config,
    store: Arc<MapStore>,
    deadline: Duration,
) -> MessagesProvider {
    let config = config.clone();
    std::thread::spawn(move || {
        MessagesProvider::with_deadline(&config, CONNECTION, store, deadline)
    })
    .join()
    .expect("the provider thread joins")
    .expect("the adapter builds")
}

fn anthropic_provider(config: &Config) -> (MessagesProvider, Arc<MapStore>) {
    let store = Arc::new(MapStore::seeded(STORE_KIND, &[(CREDENTIAL_REF, SECRET)]));
    let provider = provider_result(config.clone(), CONNECTION.to_string(), store.clone())
        .expect("the Messages adapter builds for the literal id");
    (provider, store)
}

fn umans_provider(config: &Config) -> (MessagesProvider, Arc<MapStore>) {
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(UMANS_CREDENTIAL_REF, SECRET)],
    ));
    let provider = provider_result(config.clone(), UMANS.to_string(), store.clone())
        .expect("the Messages adapter builds for the literal id");
    (provider, store)
}

fn umans_with_deadline(config: &Config, deadline: Duration) -> MessagesProvider {
    let config = config.clone();
    std::thread::spawn(move || {
        let store = Arc::new(MapStore::seeded(
            STORE_KIND,
            &[(UMANS_CREDENTIAL_REF, SECRET)],
        ));
        MessagesProvider::with_deadline(&config, UMANS, store, deadline)
    })
    .join()
    .expect("the provider thread joins")
    .expect("the adapter builds")
}

fn minimax_provider(config: &Config) -> (MessagesProvider, Arc<MapStore>) {
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(MINIMAX_CREDENTIAL_REF, SECRET)],
    ));
    let provider = provider_result(config.clone(), MINIMAX.to_string(), store.clone())
        .expect("the Messages adapter builds for the literal id");
    (provider, store)
}

fn minimax_with_deadline(config: &Config, deadline: Duration) -> MessagesProvider {
    let config = config.clone();
    std::thread::spawn(move || {
        let store = Arc::new(MapStore::seeded(
            STORE_KIND,
            &[(MINIMAX_CREDENTIAL_REF, SECRET)],
        ));
        MessagesProvider::with_deadline(&config, MINIMAX, store, deadline)
    })
    .join()
    .expect("the provider thread joins")
    .expect("the adapter builds")
}

fn cloudflare_provider(config: &Config) -> (MessagesProvider, Arc<MapStore>) {
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(CLOUDFLARE_CREDENTIAL_REF, SECRET)],
    ));
    let provider = provider_result(config.clone(), CLOUDFLARE.to_string(), store.clone())
        .expect("the Messages adapter builds for the literal id");
    (provider, store)
}

fn cloudflare_with_deadline(config: &Config, deadline: Duration) -> MessagesProvider {
    let config = config.clone();
    std::thread::spawn(move || {
        let store = Arc::new(MapStore::seeded(
            STORE_KIND,
            &[(CLOUDFLARE_CREDENTIAL_REF, SECRET)],
        ));
        MessagesProvider::with_deadline(&config, CLOUDFLARE, store, deadline)
    })
    .join()
    .expect("the provider thread joins")
    .expect("the adapter builds")
}

fn vercel_provider(config: &Config) -> (MessagesProvider, Arc<MapStore>) {
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(VERCEL_CREDENTIAL_REF, SECRET)],
    ));
    let provider = provider_result(config.clone(), VERCEL.to_string(), store.clone())
        .expect("the Messages adapter builds for the literal id");
    (provider, store)
}

fn prepared_manifest(config: &Config) -> RequestManifest {
    prepared_manifest_at(config, "/world/anthropic")
}

fn prepared_manifest_at(config: &Config, world: &str) -> RequestManifest {
    prepared_manifest_for(config, "main", world)
}

/// One prepared manifest under an explicit purpose and world: the
/// thinking lineage keys on `(world, purpose, epoch)`, so a case that
/// varies either needs its own prepare.
fn prepared_manifest_for(config: &Config, purpose: &str, world: &str) -> RequestManifest {
    let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
    broker
        .prepare(purpose, config, world, "goal: messages wire")
        .expect("the pin prepares")
}

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

fn catalog_on_thread(
    provider: MessagesProvider,
) -> (MessagesProvider, Result<Vec<String>, ProviderError>) {
    std::thread::spawn(move || {
        let outcome = provider.catalog();
        (provider, outcome)
    })
    .join()
    .expect("the catalog thread joins")
}

fn catalog_models_on_thread(
    provider: MessagesProvider,
) -> (MessagesProvider, Result<Vec<CatalogModel>, ProviderError>) {
    std::thread::spawn(move || {
        let outcome = provider.catalog_models();
        (provider, outcome)
    })
    .join()
    .expect("the catalog thread joins")
}

async fn mount_messages(server: &MockServer, body: String) {
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(server)
        .await;
}

async fn mount_messages_once(server: &MockServer, body: String) {
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .up_to_n_times(1)
        .mount(server)
        .await;
}

/// The gateway's native proxy base carries its own `/v1/<account>/<gateway>`
/// prefix before the Messages path the configured base appends.
async fn mount_cloudflare_messages(server: &MockServer, body: String) {
    Mock::given(method("POST"))
        .and(path(CLOUDFLARE_MESSAGES_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(server)
        .await;
}

async fn mount_vercel_messages(server: &MockServer, body: String) {
    Mock::given(method("POST"))
        .and(path(VERCEL_MESSAGES_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(server)
        .await;
}

/// One keyed `/v1/models` row: only the `tags` marker matters to this arm.
fn vercel_row(id: &str, tags: &[&str]) -> Value {
    json!({"id": id, "object": "model", "type": "language", "tags": tags})
}

/// The one keyed `/v1/models` mount: every caller supplies its own rows.
async fn mount_keyed_models(server: &MockServer, rows: &[Value]) {
    Mock::given(method("GET"))
        .and(path(VERCEL_MODELS_PATH))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"object": "list", "data": rows})),
        )
        .mount(server)
        .await;
}

async fn mount_models(server: &MockServer, ids: &[&str]) {
    let rows: Vec<Value> = ids.iter().map(|id| json!({"id": id})).collect();
    mount_keyed_models(server, &rows).await;
}

async fn mount_models_info(server: &MockServer, body: Value) {
    Mock::given(method("GET"))
        .and(path("/models/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

fn message_start(input_tokens: u64) -> String {
    sse_block(
        "message_start",
        &json!({
            "type": "message_start",
            "message": {
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "content": [],
                "usage": {"input_tokens": input_tokens, "output_tokens": 1},
            },
        }),
    )
}

fn text_stream(text: &str, input_tokens: u64, output_tokens: u64) -> String {
    format!(
        "{}{}{}{}{}{}",
        message_start(input_tokens),
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

/// A stream minting one replayable thinking block before its text.
fn thinking_stream(text: &str) -> String {
    thinking_stream_with(text, THINKING, SIGNATURE)
}

fn thinking_stream_with(text: &str, thinking: &str, signature: &str) -> String {
    format!(
        "{}{}{}{}{}{}{}{}{}",
        message_start(5),
        sse_block(
            "content_block_start",
            &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": ""}}),
        ),
        sse_block(
            "content_block_delta",
            &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": thinking}}),
        ),
        sse_block(
            "content_block_delta",
            &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": signature}}),
        ),
        sse_block(
            "content_block_stop",
            &json!({"type": "content_block_stop", "index": 0}),
        ),
        sse_block(
            "content_block_start",
            &json!({"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}}),
        ),
        sse_block(
            "content_block_delta",
            &json!({"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": text}}),
        ),
        sse_block(
            "content_block_stop",
            &json!({"type": "content_block_stop", "index": 1}),
        ),
        format!(
            "{}{}",
            sse_block(
                "message_delta",
                &json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 7}}),
            ),
            sse_block("message_stop", &json!({"type": "message_stop"})),
        ),
    )
}

/// A stream whose `message_start` reports a dropped replayed block.
fn mutated_stream(transformation: &str) -> String {
    format!(
        "{}{}{}{}{}",
        sse_block(
            "message_start",
            &json!({
                "type": "message_start",
                "message": {
                    "id": "msg_2",
                    "type": "message",
                    "role": "assistant",
                    "content": [],
                    "usage": {"input_tokens": 9, "output_tokens": 1},
                    "input_transformations": [{"type": transformation}],
                },
            }),
        ),
        sse_block(
            "content_block_start",
            &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ),
        sse_block(
            "content_block_delta",
            &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "dropped"}}),
        ),
        sse_block(
            "content_block_stop",
            &json!({"type": "content_block_stop", "index": 0}),
        ),
        format!(
            "{}{}",
            sse_block(
                "message_delta",
                &json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 3}}),
            ),
            sse_block("message_stop", &json!({"type": "message_stop"})),
        ),
    )
}

fn thinking_block() -> Value {
    thinking_block_with(THINKING, SIGNATURE)
}

fn thinking_block_with(thinking: &str, signature: &str) -> Value {
    json!({"type": "thinking", "thinking": thinking, "signature": signature})
}

fn header<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
}

fn body_of(request: &Request) -> Value {
    serde_json::from_slice(&request.body).expect("the wire body is json")
}

// ----- TP-PROVIDER-WIRE::anthropic ------------------------------------

/// A configured `anthropic` connection returns one verified outcome and
/// exactly one accounted usage through the standard Broker: one POST,
/// the recorded auth pair, top-level `system`, mandatory `max_tokens`,
/// the declared tools with `input_schema`, and usage from the cumulative
/// `message_delta`.
#[tokio::test]
async fn anthropic_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("verified outcome text", 11, 7)).await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        anthropic_provider(&config),
        &config,
        "/world/anthropic",
        "goal: prove the wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/anthropic", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified outcome text");
    assert!(reply.tool_calls.is_empty());
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 11,
            completion_tokens: 7,
            total_tokens: 18,
        }
    );

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request");
    assert_eq!(header(&requests[0], "x-api-key"), Some(SECRET));
    assert_eq!(
        header(&requests[0], "anthropic-version"),
        Some("2023-06-01")
    );
    assert_eq!(header(&requests[0], "authorization"), None);
    assert_eq!(header(&requests[0], "anthropic-beta"), None);
    let body = body_of(&requests[0]);
    assert_eq!(body["model"], json!(MODEL));
    assert_eq!(body["system"], json!(manifest.instructions));
    assert_eq!(body["max_tokens"], json!(MESSAGES_MAX_TOKENS));
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["messages"],
        json!([{"role": "user", "content": manifest.inputs}]),
        "the system instructions are top-level, never a message role"
    );
    assert_eq!(
        body["tools"],
        json!([{
            "name": "read_file",
            "description": "",
            "input_schema": {"type": "object"},
        }]),
        "the declared client tool carries the Messages input_schema"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(SECRET),
        "credential material rides the header, never the body"
    );

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
    assert_eq!(broker.sent_cost_explain(&manifest).confirmed, Some(18));
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay = broker.dispatch(
                &mut rivect::model::NullLedger,
                "/world/anthropic",
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

// ----- TP-PROVIDER-CATALOG::anthropic ---------------------------------

#[tokio::test]
async fn anthropic_catalog_is_the_keyed_listing() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        &["claude-sonnet-4-5", "claude-opus-4-8", "claude-haiku-4-5"],
    )
    .await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);

    let (provider, catalog) = catalog_on_thread(provider);
    assert_eq!(
        catalog.expect("the keyed listing answers"),
        ["claude-haiku-4-5", "claude-opus-4-8", "claude-sonnet-4-5"],
        "the listing's own ids answer in deterministic sorted order"
    );
    drop_blocking(provider);

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the listing");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(header(&requests[0], "x-api-key"), Some(SECRET));
    assert_eq!(
        header(&requests[0], "anthropic-version"),
        Some("2023-06-01")
    );
    assert_eq!(header(&requests[0], "authorization"), None);
}

#[tokio::test]
async fn anthropic_catalog_excludes_the_recorded_snapshots() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        &[
            "claude-3-5-haiku-20241022",
            "claude-3-5-haiku-latest",
            "claude-3-7-sonnet-20250219",
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229",
            "claude-opus-4-8",
        ],
    )
    .await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);

    let (provider, catalog) = catalog_on_thread(provider);
    assert_eq!(
        catalog.expect("the keyed listing answers"),
        ["claude-opus-4-8"],
        "the recorded snapshot families are never offered"
    );
    drop_blocking(provider);
}

// ----- TP-PROVIDER-AUTH::anthropic ------------------------------------

/// The `anthropic` id declared as the recorded subscription form: the
/// stored material is the login module's credential JSON.
const SUBSCRIPTION_REF: &str = "keyring:rivect-test/anthropic-subscription";
const SUBSCRIPTION_ACCESS: &str = "fixture-subscription-access-not-real";
const SUBSCRIPTION_REFRESH: &str = "fixture-subscription-refresh-not-real";

fn anthropic_subscription_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.{CONNECTION}]\nkind = \"subscription\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{SUBSCRIPTION_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{CONNECTION}\", model_id = \"{MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The stored subscription credential's JSON form: only the access token
/// may reach the wire, never the refresh token or the envelope.
fn subscription_material() -> String {
    json!({
        "access_token": SUBSCRIPTION_ACCESS,
        "refresh_token": SUBSCRIPTION_REFRESH,
        "expires_at": 1_900_000_000_u64,
        "organization_id": "org-fixture",
    })
    .to_string()
}

#[tokio::test]
async fn anthropic_subscription_sends_the_access_token_as_bearer() {
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("subscribed", 1, 1)).await;
    let config = Config::parse_validated(&anthropic_subscription_config(&server_uri_v1(&server)))
        .expect("valid");
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(SUBSCRIPTION_REF, &subscription_material())],
    ));
    // The frozen manifest is prepared under the sibling api-key row: the
    // subscription kind is never offline-inference eligible, while the
    // send only needs the same literal connection id.
    let manifest_config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let manifest = prepared_manifest(&manifest_config);
    let provider = provider_result(config, CONNECTION.to_string(), store)
        .expect("the subscription adapter builds");

    let (provider, outcome) = send_on_thread(provider, manifest);
    outcome.expect("the subscription send succeeds");
    drop_blocking(provider);

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1);
    let access_bearer = format!("Bearer {SUBSCRIPTION_ACCESS}");
    assert_eq!(
        header(&requests[0], "authorization"),
        Some(access_bearer.as_str()),
        "the stored access token rides Authorization: Bearer"
    );
    assert_eq!(
        header(&requests[0], "x-api-key"),
        None,
        "the subscription form never sends x-api-key"
    );
    assert!(
        !requests[0].headers.iter().any(|(_name, value)| value
            .to_str()
            .is_ok_and(|value| value.contains(SUBSCRIPTION_REFRESH))),
        "the refresh token never enters a wire header"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(SUBSCRIPTION_REFRESH),
        "the refresh token never enters the wire body"
    );
}

#[tokio::test]
async fn anthropic_auth_sends_x_api_key_and_version_only() {
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("auth", 1, 1)).await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);
    let manifest = prepared_manifest(&config);

    let (provider, outcome) = send_on_thread(provider, manifest);
    outcome.expect("the auth control sends");
    drop_blocking(provider);

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1);
    let anthropic_headers: BTreeSet<&str> = requests[0]
        .headers
        .keys()
        .map(|name| name.as_str())
        .filter(|name| name.starts_with("anthropic-"))
        .collect();
    assert_eq!(
        anthropic_headers,
        BTreeSet::from(["anthropic-version"]),
        "the only credential-class header is the mandatory version"
    );
    assert_eq!(header(&requests[0], "x-api-key"), Some(SECRET));
    assert_eq!(header(&requests[0], "authorization"), None);
}

#[tokio::test]
async fn anthropic_wrong_credential_profile_or_region_denies_without_secrets() {
    // a configured region names no recorded contract — typed denial at build
    let region_config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.{CONNECTION}]\nkind = \"api_key\"\nendpoint = \"https://api.anthropic.com/v1\"\nregion = \"eu\"\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"{CONNECTION}\", model_id = \"{MODEL}\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the region config parses");
    let empty = Arc::new(MapStore::seeded(STORE_KIND, &[]));
    let region = provider_result(region_config, CONNECTION.to_string(), empty)
        .expect_err("a configured region denies");
    assert!(matches!(
        &region,
        ProviderError::RegionMismatch { connection, region }
            if connection == CONNECTION && region == "eu"
    ));

    // a profile-bound ref whose scope names another profile cannot bind
    let profile_config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.{CONNECTION}]\nkind = \"api_key\"\nendpoint = \"https://api.anthropic.com/v1\"\ncredential_ref = \"{CREDENTIAL_REF}\"\nprofile = \"anthropic-work\"\n\
         [profiles.anthropic-work]\ncredential_ref = \"keyring:rivect-test/another-profile\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"{CONNECTION}\", model_id = \"{MODEL}\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the profile config parses");
    let profile = provider_result(
        profile_config,
        CONNECTION.to_string(),
        Arc::new(MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a divergent profile scope denies");
    assert!(matches!(
        &profile,
        ProviderError::CredentialProfileMismatch { connection, profile }
            if connection == CONNECTION && profile == "anthropic-work"
    ));

    // a profile entry binding no credential is unresolved before any store call
    let absent_config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.{CONNECTION}]\nkind = \"api_key\"\nendpoint = \"https://api.anthropic.com/v1\"\ncredential_ref = \"{CREDENTIAL_REF}\"\nprofile = \"empty-profile\"\n\
         [profiles.empty-profile]\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"{CONNECTION}\", model_id = \"{MODEL}\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the empty-profile config parses");
    let unresolved = provider_result(
        absent_config,
        CONNECTION.to_string(),
        Arc::new(MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("an empty profile binding denies");
    assert!(matches!(
        &unresolved,
        ProviderError::CredentialUnresolved { connection, .. } if connection == CONNECTION
    ));

    // an empty bound scope denies at send without reaching the wire and
    // without leaking the neighbour's material
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("never reached", 1, 1)).await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(NEIGHBOR_REF, NEIGHBOR_SECRET)],
    ));
    let provider =
        provider_result(config.clone(), CONNECTION.to_string(), store).expect("binding resolves");
    let (provider, denied) = send_on_thread(provider, prepared_manifest(&config));
    let error = denied.expect_err("the empty scope denies");
    assert!(matches!(error, ProviderError::CredentialAbsent { .. }));
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(
            !rendered.contains(NEIGHBOR_SECRET) && !rendered.contains(SECRET),
            "diagnostics stay secret-free: {rendered}"
        );
    }
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("the mock recorded")
            .is_empty(),
        "the denial lands before the wire"
    );
}

// ----- TP-PROVIDER-RECOVERY::anthropic --------------------------------

#[tokio::test]
async fn anthropic_rejects_partial_tool_block_and_unknown_terminal() {
    // partial tool JSON at the block stop is a typed violation
    let server = MockServer::start().await;
    mount_messages(
        &server,
        format!(
            "{}{}{}{}{}{}",
            message_start(3),
            sse_block(
                "content_block_start",
                &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {}}}),
            ),
            sse_block(
                "content_block_delta",
                &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "{\"path\":"}}),
            ),
            sse_block(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 0}),
            ),
            sse_block(
                "message_delta",
                &json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 2}}),
            ),
            sse_block("message_stop", &json!({"type": "message_stop"})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    assert!(
        matches!(outcome, Err(ProviderError::StreamViolation { .. })),
        "a partial tool block never becomes a reply: {outcome:?}"
    );
    drop_blocking(provider);

    // a terminal the dialect cannot classify is never success
    let server = MockServer::start().await;
    mount_messages(
        &server,
        format!(
            "{}{}{}{}",
            message_start(3),
            sse_block(
                "content_block_start",
                &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            ),
            sse_block(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 0}),
            ),
            format!(
                "{}{}",
                sse_block(
                    "message_delta",
                    &json!({"type": "message_delta", "delta": {"stop_reason": "teleport"}, "usage": {"output_tokens": 1}}),
                ),
                sse_block("message_stop", &json!({"type": "message_stop"})),
            ),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    assert!(
        matches!(outcome, Err(ProviderError::UnknownTerminal { .. })),
        "an unknown stop reason is an unknown terminal: {outcome:?}"
    );
    drop_blocking(provider);
}

#[tokio::test]
async fn anthropic_stream_without_message_stop_denies() {
    let server = MockServer::start().await;
    let mut body = text_stream("looks complete", 4, 2);
    body.truncate(
        body.rfind("event: message_stop")
            .expect("the terminal exists"),
    );
    mount_messages(&server, body).await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        anthropic_provider(&config),
        &config,
        "/world/anthropic",
        "goal: missing terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/anthropic", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "EOF without message_stop is never success: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0, "nothing is accounted");
    drop_blocking(broker);
}

#[tokio::test]
async fn anthropic_non_success_status_denies() {
    for status in [400_u16, 429, 500] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(status).set_body_string("peer failure body"))
            .mount(&server)
            .await;
        let config =
            Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
        let (broker, manifest) = prepared_with(
            anthropic_provider(&config),
            &config,
            "/world/anthropic",
            "goal: non-success",
        );
        let (broker, outcome) = dispatch(broker, "/world/anthropic", manifest);
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
            "a non-signature failure is never retried"
        );
    }
}

#[tokio::test]
async fn anthropic_short_deadline_denies_without_a_second_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(text_stream("late", 1, 1))
                .set_delay(Duration::from_millis(600)),
        )
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(MapStore::seeded(STORE_KIND, &[(CREDENTIAL_REF, SECRET)]));
    let deadline = Duration::from_millis(400);
    let provider = provider_with_deadline(&config, store, deadline);
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

#[tokio::test]
async fn anthropic_request_uses_top_level_system_and_max_tokens() {
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("wire", 1, 1)).await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);
    let manifest = prepared_manifest(&config);
    let (provider, outcome) = send_on_thread(provider, manifest.clone());
    outcome.expect("the wire control sends");
    drop_blocking(provider);

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    let body = body_of(&requests[0]);
    assert_eq!(body["system"], json!(manifest.instructions));
    assert_eq!(body["max_tokens"], json!(MESSAGES_MAX_TOKENS));
    assert_eq!(
        body["max_tokens"],
        json!(8192),
        "the recorded adapter budget is the literal 8192"
    );
    assert_eq!(body["stream"], json!(true));
    assert!(
        body["thinking"].is_null(),
        "an unchanged epoch asks no drop policy"
    );
    assert_eq!(
        body["messages"],
        json!([{"role": "user", "content": manifest.inputs}])
    );
    assert!(
        body["messages"]
            .as_array()
            .expect("messages is an array")
            .iter()
            .all(|message| message["role"] != json!("system")),
        "system is never a message role"
    );
    assert_eq!(header(&requests[0], "anthropic-beta"), None);
}

#[tokio::test]
async fn anthropic_usage_stays_unknown_without_both_counts() {
    let server = MockServer::start().await;
    mount_messages(
        &server,
        format!(
            "{}{}{}{}{}",
            message_start(5),
            sse_block(
                "content_block_start",
                &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            ),
            sse_block(
                "content_block_delta",
                &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "no usage"}}),
            ),
            sse_block(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 0}),
            ),
            format!(
                "{}{}",
                sse_block(
                    "message_delta",
                    &json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}}),
                ),
                sse_block("message_stop", &json!({"type": "message_stop"})),
            ),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let reply = outcome.expect("the count-less stream still answers");
    assert_eq!(reply.text, "no usage");
    assert_eq!(
        reply.usage,
        UsageDelta::Unknown,
        "a missing output count stays unknown, never an estimate"
    );
    drop_blocking(provider);
}

#[tokio::test]
async fn anthropic_pinned_effort_denies_not_dropped() {
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("never reached", 1, 1)).await;
    let config = Config::parse_validated(&anthropic_config(&server_uri_v1(&server)).replace(
        "effort = { mode = \"auto\" }",
        "effort = { mode = \"fixed\", value = \"high\" }",
    ))
    .expect("valid");
    let (broker, manifest) = prepared_with(
        anthropic_provider(&config),
        &config,
        "/world/anthropic",
        "goal: pinned effort",
    );
    let (broker, outcome) = dispatch(broker, "/world/anthropic", manifest);
    let error = match outcome {
        Err(ModelError::Provider(error)) => error,
        other => panic!("a pinned effort is a typed denial: {other:?}"),
    };
    let ProviderError::UnsupportedParameter {
        connection,
        parameter,
        model,
    } = error
    else {
        panic!("expected the typed unsupported parameter");
    };
    assert_eq!(connection, CONNECTION);
    assert_eq!(parameter, "effort");
    assert_eq!(model, MODEL);
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the denial lands before any wire leg"
    );
}

#[tokio::test]
async fn anthropic_incompatible_tool_pin_denies() {
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("never reached", 1, 1)).await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);
    let mut manifest = prepared_manifest(&config);
    manifest.tools = vec!["read file".to_string()];
    let (provider, outcome) = send_on_thread(provider, manifest);
    let ProviderError::UnsupportedParameter {
        parameter, model, ..
    } = outcome.expect_err("a tool name outside the grammar denies")
    else {
        panic!("expected the typed tool denial");
    };
    assert_eq!(parameter, "tools");
    assert_eq!(model, MODEL);
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

// ----- preserved thinking (REQ-039) -----------------------------------

#[tokio::test]
async fn anthropic_epoch_replay_bytewise() {
    let server = MockServer::start().await;
    mount_messages_once(&server, thinking_stream("captured")).await;
    mount_messages(&server, text_stream("replayed", 5, 7)).await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);

    let mut first = prepared_manifest(&config);
    first.epoch_id = "epoch-one".to_string();
    let (provider, outcome) = send_on_thread(provider, first);
    outcome.expect("the capture send succeeds");
    let mut second = prepared_manifest(&config);
    second.epoch_id = "epoch-one".to_string();
    let inputs = second.inputs.clone();
    let (provider, outcome) = send_on_thread(provider, second);
    assert_eq!(provider.dropped_reasoning(), 0);
    outcome.expect("the replay send succeeds");
    drop_blocking(provider);

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded both sends");
    assert_eq!(requests.len(), 2);
    let body = body_of(&requests[1]);
    assert_eq!(header(&requests[1], "anthropic-beta"), None);
    assert_eq!(
        body["messages"],
        json!([
            {"role": "assistant", "content": [thinking_block()]},
            {"role": "user", "content": inputs},
        ]),
        "the captured thinking block is replayed bytewise in its epoch"
    );
}

#[tokio::test]
async fn anthropic_lineage_key_binds_world_and_purpose() {
    let server = MockServer::start().await;
    mount_messages_once(&server, thinking_stream("captured")).await;
    mount_messages(&server, text_stream("outside the key", 5, 7)).await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);

    let mut captured = prepared_manifest_at(&config, "/world/a");
    captured.epoch_id = "epoch-lineage".to_string();
    let (provider, outcome) = send_on_thread(provider, captured);
    outcome.expect("the capture send succeeds");

    // The same epoch in another world is another conversation.
    let mut other_world = prepared_manifest_at(&config, "/world/b");
    other_world.epoch_id = "epoch-lineage".to_string();
    let (provider, outcome) = send_on_thread(provider, other_world);
    outcome.expect("the other-world send succeeds");

    // The same world and epoch under another purpose is another
    // conversation too.
    let mut other_purpose = prepared_manifest_for(&config, "planner", "/world/a");
    other_purpose.epoch_id = "epoch-lineage".to_string();
    let (provider, outcome) = send_on_thread(provider, other_purpose);
    outcome.expect("the other-purpose send succeeds");

    // Only the full key replays the captured block.
    let mut replay = prepared_manifest_at(&config, "/world/a");
    replay.epoch_id = "epoch-lineage".to_string();
    let inputs = replay.inputs.clone();
    let (provider, outcome) = send_on_thread(provider, replay);
    assert_eq!(provider.dropped_reasoning(), 0);
    outcome.expect("the same lineage replays");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 4);
    for request in &requests[1..3] {
        assert!(
            body_of(request)["messages"]
                .as_array()
                .expect("messages is an array")
                .iter()
                .all(|message| message["role"] != json!("assistant")),
            "a send outside the lineage key never replays the block"
        );
    }
    assert_eq!(
        body_of(&requests[3])["messages"],
        json!([
            {"role": "assistant", "content": [thinking_block()]},
            {"role": "user", "content": inputs},
        ]),
        "the captured block replays only inside its own world/purpose/epoch"
    );
}

#[tokio::test]
async fn anthropic_mutated_epoch_drop_block() {
    let server = MockServer::start().await;
    mount_messages_once(&server, thinking_stream("captured")).await;
    mount_messages_once(&server, mutated_stream("prefix_binding_mismatch")).await;
    mount_messages(&server, text_stream("after mutation", 1, 1)).await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);

    let mut first = prepared_manifest(&config);
    first.epoch_id = "epoch-two".to_string();
    let (provider, outcome) = send_on_thread(provider, first);
    outcome.expect("the capture send succeeds");
    let mut mutated = prepared_manifest(&config);
    mutated.epoch_id = "epoch-two".to_string();
    mutated.mutation_reason = Some("instructions".to_string());
    let (provider, outcome) = send_on_thread(provider, mutated);
    outcome.expect("the mutated send succeeds");
    assert_eq!(
        provider.dropped_reasoning(),
        1,
        "the peer's input_transformations count the dropped reasoning"
    );
    let mut after = prepared_manifest(&config);
    after.epoch_id = "epoch-two".to_string();
    let (provider, outcome) = send_on_thread(provider, after);
    outcome.expect("the post-mutation send succeeds");
    drop_blocking(provider);

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the sends");
    assert_eq!(requests.len(), 3);
    let mutated = body_of(&requests[1]);
    assert_eq!(
        header(&requests[1], "anthropic-beta"),
        Some("thinking-binding-controls-2026-08-01")
    );
    assert_eq!(
        mutated["thinking"]["block_binding"]["prefix_mismatch_behavior"],
        json!("drop_block")
    );
    assert!(
        mutated["messages"]
            .as_array()
            .expect("messages is an array")
            .iter()
            .all(|message| message["role"] != json!("assistant")),
        "a mutated epoch never replays the stale set"
    );
    let after = body_of(&requests[2]);
    assert!(after["thinking"].is_null());
    assert!(
        after["messages"]
            .as_array()
            .expect("messages is an array")
            .iter()
            .all(|message| message["role"] != json!("assistant")),
        "the dropped set is not silently kept for the next send"
    );
}

#[tokio::test]
async fn anthropic_signature_400_permanent() {
    // one strip-retry, then the same permanent 400 is a typed denial
    let server = MockServer::start().await;
    mount_messages_once(&server, thinking_stream("captured")).await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(400).set_body_string(
                "Invalid signature: thinking block bound to a different conversation",
            ),
        )
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);
    let mut first = prepared_manifest(&config);
    first.epoch_id = "epoch-three".to_string();
    let (provider, outcome) = send_on_thread(provider, first);
    outcome.expect("the capture send succeeds");
    let mut second = prepared_manifest(&config);
    second.epoch_id = "epoch-three".to_string();
    let (provider, outcome) = send_on_thread(provider, second);
    let error = outcome.expect_err("the permanent signature error denies");
    match error {
        ProviderError::Retried {
            wire_retries,
            source,
        } => {
            assert_eq!(wire_retries, 1, "the corrected retry is counted");
            assert!(matches!(
                *source,
                ProviderError::Transport {
                    cause: TransportCause::Status { .. },
                    ..
                }
            ));
        }
        other => panic!("the permanent signature error keeps its class: {other:?}"),
    }
    let mut third = prepared_manifest(&config);
    third.epoch_id = "epoch-three".to_string();
    let (provider, outcome) = send_on_thread(provider, third);
    let error = outcome.expect_err("the cleared lineage still denies without a retry");
    assert!(matches!(
        error,
        ProviderError::Transport {
            cause: TransportCause::Status { .. },
            ..
        }
    ));
    drop_blocking(provider);
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the sends");
    assert_eq!(
        requests.len(),
        4,
        "capture, replay, exactly one stripped retry, then one clean attempt"
    );
    let retry = body_of(&requests[2]);
    assert!(
        retry["messages"]
            .as_array()
            .expect("messages is an array")
            .iter()
            .all(|message| message["role"] != json!("assistant")),
        "the retry strips the replayed thinking blocks"
    );
    assert!(
        body_of(&requests[3])["messages"]
            .as_array()
            .expect("messages is an array")
            .iter()
            .all(|message| message["role"] != json!("assistant")),
        "a permanently invalid lineage is never replayed by a later send"
    );

    // a successful stripped retry is the only second request
    let server = MockServer::start().await;
    mount_messages_once(&server, thinking_stream("captured")).await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(body_string_contains(SIGNATURE))
        .respond_with(
            ResponseTemplate::new(400).set_body_string(
                "Invalid signature: thinking block bound to a different conversation",
            ),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_messages(&server, text_stream("retried", 5, 7)).await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);
    let mut first = prepared_manifest(&config);
    first.epoch_id = "epoch-four".to_string();
    let (provider, outcome) = send_on_thread(provider, first);
    outcome.expect("the capture send succeeds");
    let mut second = prepared_manifest(&config);
    second.epoch_id = "epoch-four".to_string();
    let (provider, outcome) = send_on_thread(provider, second);
    assert_eq!(
        outcome.expect("the stripped retry succeeds").text,
        "retried"
    );
    drop_blocking(provider);
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the sends");
    assert_eq!(requests.len(), 3);
    assert!(
        body_of(&requests[2])["messages"]
            .as_array()
            .expect("messages is an array")
            .iter()
            .all(|message| message["role"] != json!("assistant"))
    );
}

#[tokio::test]
async fn wire_retry_is_recorded_and_not_a_second_child() {
    // One physical child attempt answers after the adapter's own stripped
    // retry: the reply carries the retry count, the settlement carries it
    // beside the answering leg's bins, and no second child is opened.
    let server = MockServer::start().await;
    mount_messages_once(&server, thinking_stream("captured")).await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(body_string_contains(SIGNATURE))
        .respond_with(
            ResponseTemplate::new(400).set_body_string(
                "Invalid signature: thinking block bound to a different conversation",
            ),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_messages(&server, text_stream("retried", 5, 7)).await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);
    let root = tempfile::TempDir::with_prefix("rivect-retry-settlement-").expect("fixture root");
    let db = root.path().join("state.db");
    let (broker, outcome, attempts) = std::thread::spawn(move || {
        let mut store = TaskStore::open(&db).expect("store opens");
        store.open_budget("retry-scope", 10).expect("budget opens");
        let mut broker = Broker::new(Box::new(provider));
        let mut attempts = Vec::new();
        for _ in 0..2 {
            let manifest = broker
                .prepare("main", &config, "/world/anthropic", "goal: retry")
                .expect("the pin prepares");
            attempts.push(manifest.attempt_id.clone());
            let mut ledger = StoreLedger::new(&mut store, vec!["retry-scope".to_string()]);
            broker
                .dispatch(&mut ledger, "/world/anthropic", &manifest)
                .expect("the send settles");
        }
        (broker, store, attempts)
    })
    .join()
    .expect("the settlement thread joins");
    drop(broker);
    let totals = outcome.settlement_totals().expect("totals");
    assert_eq!(
        totals.settled_count, 2,
        "one row per dispatched child attempt"
    );
    assert_eq!(
        totals.dispatched_count, 0,
        "the retry never leaves a second open row"
    );
    let capture = outcome
        .settlement(&attempts[0])
        .expect("the capture row settles");
    let retried = outcome
        .settlement(&attempts[1])
        .expect("the retried row settles");
    assert_eq!(capture.wire_retries, 0, "the plain send carries no retry");
    assert_eq!(
        retried.wire_retries, 1,
        "the adapter's correction is recorded"
    );
    assert_eq!(
        retried.bins.total_tokens,
        Some(12),
        "only the answering leg's usage settles"
    );
    assert_eq!(
        retried.bins.prompt_tokens,
        Some(5),
        "the answering leg's reported prompt count settles"
    );
    assert_eq!(
        retried.exactness,
        Exactness::Exact,
        "the answering leg settles exact, not an inferred unknown"
    );
    assert_eq!(
        retried.unknown_reason, None,
        "an answered retry carries no unknown marker"
    );
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the sends");
    assert_eq!(
        requests.len(),
        3,
        "capture, one signature-rejected replay, one stripped retry — never a second child"
    );
    drop_blocking(outcome);
}

#[tokio::test]
async fn failed_stripped_retry_settles_with_the_retry_count() {
    // The capture send seeds the lineage; every later replay is rejected as
    // a permanent signature failure, so the adapter's one stripped retry is
    // its second crossed leg — and that leg fails too. The entered send must
    // settle with the count of the retry it made, not zero.
    let server = MockServer::start().await;
    mount_messages_once(&server, thinking_stream("captured")).await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(body_string_contains(SIGNATURE))
        .respond_with(
            ResponseTemplate::new(400).set_body_string(
                "Invalid signature: thinking block bound to a different conversation",
            ),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(400).set_body_string(
                "Invalid signature: thinking block bound to a different conversation",
            ),
        )
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);
    let root = tempfile::TempDir::with_prefix("rivect-retry-failure-").expect("fixture root");
    let db = root.path().join("state.db");
    let (store, attempt, cost_bound, failed) = std::thread::spawn(move || {
        let mut store = TaskStore::open(&db).expect("store opens");
        store
            .open_budget("retry-failure-scope", 10)
            .expect("budget opens");
        let mut broker = Broker::new(Box::new(provider));
        let capture = broker
            .prepare("main", &config, "/world/anthropic", "goal: retry failure")
            .expect("the capture prepares");
        {
            let mut ledger = StoreLedger::new(&mut store, vec!["retry-failure-scope".to_string()]);
            broker
                .dispatch(&mut ledger, "/world/anthropic", &capture)
                .expect("the capture settles");
        }
        let retried = broker
            .prepare("main", &config, "/world/anthropic", "goal: retry failure")
            .expect("the retried send prepares");
        let failed = {
            let mut ledger = StoreLedger::new(&mut store, vec!["retry-failure-scope".to_string()]);
            broker.dispatch(&mut ledger, "/world/anthropic", &retried)
        };
        (store, retried.attempt_id, retried.cost_bound, failed)
    })
    .join()
    .expect("the settlement thread joins");
    assert!(
        matches!(
            &failed,
            Err(ModelError::Provider(ProviderError::Transport {
                cause: TransportCause::Status { .. },
                ..
            }))
        ),
        "the failure keeps its typed class through the broker: {failed:?}"
    );
    let row = store
        .settlement(&attempt)
        .expect("the entered failure settles");
    assert_eq!(row.state, SettlementState::Settled);
    assert_eq!(
        row.wire_retries, 1,
        "the corrected retry is recorded beside the failure"
    );
    assert_eq!(row.unknown_reason.as_deref(), Some("send failed"));
    assert_eq!(
        row.bins.total_tokens, None,
        "a failed retry reports no usage, never zero"
    );
    assert_eq!(
        row.charged_units,
        Some(cost_bound),
        "the failed send retains the frozen bound captured from its manifest"
    );
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the sends");
    assert_eq!(
        requests.len(),
        3,
        "capture, rejected replay, failed stripped retry"
    );
}

/// One scripted Messages peer for the corrected-retry POST failure: the
/// capture answers the thinking stream, the replay is a permanent
/// signature refusal, and the corrected retry's POST is dropped before a
/// response — its transport error is the second crossed leg.
fn retry_post_failure_peer() -> (String, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("fixture peer binds");
    let address = listener.local_addr().expect("fixture address");
    let handle = std::thread::spawn(move || {
        for attempt in 0..3 {
            let (mut stream, _) = listener.accept().expect("fixture peer accepts");
            read_fixture_request(&mut stream);
            let response = match attempt {
                0 => {
                    let body = thinking_stream("captured");
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                }
                1 => {
                    let body =
                        "Invalid signature: thinking block bound to a different conversation";
                    format!(
                        "HTTP/1.1 400 Bad Request\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                }
                _ => {
                    drop(stream);
                    continue;
                }
            };
            stream
                .write_all(response.as_bytes())
                .expect("fixture response");
        }
    });
    (format!("http://{address}/v1"), handle)
}

/// Consumes one fixture request's head and stated body so the peer only
/// answers after the client finished writing it.
fn read_fixture_request(stream: &mut std::net::TcpStream) {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).expect("fixture request read");
        if read == 0 {
            return;
        }
        bytes.extend_from_slice(&chunk[..read]);
        let Some(head_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let head = String::from_utf8_lossy(&bytes[..head_end]);
        let length = head
            .lines()
            .find_map(|line| {
                let lower = line.to_ascii_lowercase();
                let value = lower.strip_prefix("content-length:")?.trim();
                value.parse::<usize>().ok()
            })
            .unwrap_or(0);
        if bytes.len() >= head_end + 4 + length {
            return;
        }
    }
}

#[tokio::test]
async fn failed_retry_post_settles_with_the_retry_count() {
    // The capture seeds the lineage; the replay is refused as a permanent
    // signature failure; the corrected retry's POST itself fails at the
    // transport, so the entered send must still settle the one retry.
    let (endpoint, peer) = retry_post_failure_peer();
    let config = Config::parse_validated(&anthropic_config(&endpoint)).expect("valid");
    let (provider, _store) = anthropic_provider(&config);
    let root = tempfile::TempDir::with_prefix("rivect-retry-post-failure-").expect("fixture root");
    let db = root.path().join("state.db");
    let (store, attempt, cost_bound, failed) = std::thread::spawn(move || {
        let mut store = TaskStore::open(&db).expect("store opens");
        store
            .open_budget("retry-post-scope", 10)
            .expect("budget opens");
        let mut broker = Broker::new(Box::new(provider));
        let capture = broker
            .prepare("main", &config, "/world/anthropic", "goal: retry post")
            .expect("the capture prepares");
        {
            let mut ledger = StoreLedger::new(&mut store, vec!["retry-post-scope".to_string()]);
            broker
                .dispatch(&mut ledger, "/world/anthropic", &capture)
                .expect("the capture settles");
        }
        let retried = broker
            .prepare("main", &config, "/world/anthropic", "goal: retry post")
            .expect("the retried send prepares");
        let failed = {
            let mut ledger = StoreLedger::new(&mut store, vec!["retry-post-scope".to_string()]);
            broker.dispatch(&mut ledger, "/world/anthropic", &retried)
        };
        (store, retried.attempt_id, retried.cost_bound, failed)
    })
    .join()
    .expect("the settlement thread joins");
    assert!(
        matches!(
            &failed,
            Err(ModelError::Provider(ProviderError::Transport { .. }))
        ),
        "the retry POST failure keeps its typed class: {failed:?}"
    );
    let row = store
        .settlement(&attempt)
        .expect("the entered failure settles");
    assert_eq!(row.state, SettlementState::Settled);
    assert_eq!(
        row.wire_retries, 1,
        "the failed corrected POST is the second crossed leg"
    );
    assert_eq!(row.exactness, Exactness::Unknown);
    assert_eq!(row.unknown_reason.as_deref(), Some("send failed"));
    assert_eq!(row.charged_units, Some(cost_bound));
    peer.join().expect("fixture peer finishes");
}

#[tokio::test]
async fn deadline_while_reading_the_refusable_400_settles_uncounted() {
    // The signature-refused replay's 400 body is delayed past the whole-send
    // deadline, so the deadline trips while reading that body and the corrected
    // retry leg is never built or posted. The refused attempt settles with the
    // typed deadline class and no crossed-leg count.
    //
    // The corrected leg's own `check_deadline`/`wire_body` checks are
    // defensive: from the HTTP seam the first leg's body read already enforces
    // the shared clock, so only this reachable uncounted path is exercised.
    let server = MockServer::start().await;
    mount_messages_once(&server, thinking_stream("captured")).await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_delay(Duration::from_millis(1500))
                .set_body_string(
                    "Invalid signature: thinking block bound to a different conversation",
                ),
        )
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(MapStore::seeded(STORE_KIND, &[(CREDENTIAL_REF, SECRET)]));
    let deadline = Duration::from_millis(1000);
    let provider = provider_with_deadline(&config, store, deadline);
    let root = tempfile::TempDir::with_prefix("rivect-retry-deadline-").expect("fixture root");
    let db = root.path().join("state.db");
    let (store, attempt, cost_bound, failed) = std::thread::spawn(move || {
        let mut store = TaskStore::open(&db).expect("store opens");
        store
            .open_budget("retry-deadline-scope", 10)
            .expect("budget opens");
        let mut broker = Broker::new(Box::new(provider));
        let capture = broker
            .prepare("main", &config, "/world/anthropic", "goal: retry deadline")
            .expect("the capture prepares");
        {
            let mut ledger = StoreLedger::new(&mut store, vec!["retry-deadline-scope".to_string()]);
            broker
                .dispatch(&mut ledger, "/world/anthropic", &capture)
                .expect("the capture settles");
        }
        let retried = broker
            .prepare("main", &config, "/world/anthropic", "goal: retry deadline")
            .expect("the retried send prepares");
        let failed = {
            let mut ledger = StoreLedger::new(&mut store, vec!["retry-deadline-scope".to_string()]);
            broker.dispatch(&mut ledger, "/world/anthropic", &retried)
        };
        (store, retried.attempt_id, retried.cost_bound, failed)
    })
    .join()
    .expect("the settlement thread joins");
    match &failed {
        Err(ModelError::Provider(ProviderError::Transport {
            cause: TransportCause::Deadline { budget },
            ..
        })) => assert_eq!(*budget, deadline, "the typed deadline is the send budget"),
        other => panic!("the deadline keeps its typed class: {other:?}"),
    }
    let row = store
        .settlement(&attempt)
        .expect("the entered failure settles");
    assert_eq!(row.state, SettlementState::Settled);
    assert_eq!(
        row.wire_retries, 0,
        "a retry refused by the deadline never crossed the wire"
    );
    assert_eq!(row.exactness, Exactness::Unknown);
    assert_eq!(row.unknown_reason.as_deref(), Some("send failed"));
    assert_eq!(row.charged_units, Some(cost_bound));
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the sends");
    assert_eq!(
        requests.len(),
        2,
        "capture and the refused replay; the corrected retry never posts"
    );
}

#[tokio::test]
async fn anthropic_model_switch_binding() {
    let server = MockServer::start().await;
    mount_messages_once(&server, thinking_stream("captured")).await;
    mount_messages(&server, mutated_stream("model_binding_mismatch")).await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);
    let mut first = prepared_manifest(&config);
    first.epoch_id = "epoch-five".to_string();
    let (provider, outcome) = send_on_thread(provider, first);
    outcome.expect("the capture send succeeds");
    let mut switched = prepared_manifest(&config);
    switched.epoch_id = "epoch-five".to_string();
    switched.model = ModelAssign::Fixed(FixedModel {
        connection: CONNECTION.to_string(),
        model_id: "claude-sonnet-4-5".to_string(),
    });
    let (provider, outcome) = send_on_thread(provider, switched);
    outcome.expect("the switched-model send succeeds");
    assert_eq!(provider.dropped_reasoning(), 1);
    drop_blocking(provider);

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the sends");
    let body = body_of(&requests[1]);
    assert_eq!(
        header(&requests[1], "anthropic-beta"),
        Some("thinking-binding-controls-2026-08-01")
    );
    assert_eq!(
        body["thinking"]["block_binding"]["prefix_mismatch_behavior"],
        json!("drop_block")
    );
    assert!(
        body["messages"]
            .as_array()
            .expect("messages is an array")
            .iter()
            .all(|message| message["role"] != json!("assistant")),
        "a block minted by another model is never replayed"
    );
}

#[tokio::test]
async fn foreign_reasoning_blob_rejected() {
    let server = MockServer::start().await;
    mount_messages_once(
        &server,
        thinking_stream_with("epoch a", "epoch a plan", "sig-epoch-a"),
    )
    .await;
    mount_messages_once(
        &server,
        thinking_stream_with("epoch b", "epoch b plan", "sig-epoch-b"),
    )
    .await;
    mount_messages(&server, text_stream("epoch b replay", 5, 7)).await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);

    let mut first = prepared_manifest(&config);
    first.epoch_id = "epoch-a".to_string();
    let (provider, outcome) = send_on_thread(provider, first);
    outcome.expect("epoch a captures");
    let mut second = prepared_manifest(&config);
    second.epoch_id = "epoch-b".to_string();
    let (provider, outcome) = send_on_thread(provider, second);
    outcome.expect("epoch b captures");
    let mut third = prepared_manifest(&config);
    third.epoch_id = "epoch-b".to_string();
    let (provider, outcome) = send_on_thread(provider, third);
    outcome.expect("epoch b replays");
    drop_blocking(provider);

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the sends");
    let body = body_of(&requests[2]);
    let assistant = body["messages"]
        .as_array()
        .expect("messages is an array")
        .iter()
        .find(|message| message["role"] == json!("assistant"))
        .expect("the epoch-b assistant block replays");
    assert_eq!(
        assistant["content"],
        json!([thinking_block_with("epoch b plan", "sig-epoch-b")]),
        "only the send's own lineage block is replayed"
    );
    assert!(
        !String::from_utf8_lossy(&requests[2].body).contains("sig-epoch-a"),
        "a foreign lineage's block never enters the replay"
    );
}

// ----- legs matrix ----------------------------------------------------

#[tokio::test]
async fn anthropic_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    // CATALOG
    let catalog_server = MockServer::start().await;
    mount_models(&catalog_server, &["claude-opus-4-8"]).await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&catalog_server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if matches!(&catalog, Ok(ids) if ids == &["claude-opus-4-8".to_string()]) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("matrix", 1, 1)).await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), CONNECTION.to_string(), store).expect("binding resolves");
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

    // WIRE
    let (broker, manifest) = prepared_with(
        anthropic_provider(&config),
        &config,
        "/world/anthropic",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/anthropic", manifest);
    reported.insert(
        "WIRE",
        if matches!(&outcome, Ok(reply) if reply.text == "matrix") {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

    // RECOVERY
    let recovery_server = MockServer::start().await;
    let mut truncated = text_stream("looks complete", 1, 1);
    truncated.truncate(
        truncated
            .rfind("event: message_stop")
            .expect("the terminal exists"),
    );
    mount_messages(&recovery_server, truncated).await;
    let recovery_config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&recovery_server)))
            .expect("valid");
    let (provider, _store) = anthropic_provider(&recovery_config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&recovery_config));
    reported.insert(
        "RECOVERY",
        if matches!(outcome, Err(ProviderError::UnknownTerminal { .. })) {
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

// ----- recorded dialect defaults and the concrete WireAuth seam ------

#[test]
fn dialect_defaults_carry_the_recorded_messages_and_cc_ids() {
    assert_eq!(dialect_for("anthropic"), Some(Dialect::Messages));
    assert_eq!(dialect_for("minimax"), Some(Dialect::Messages));
    assert_eq!(dialect_for("umans"), Some(Dialect::Messages));
    assert_eq!(
        dialect_for("cloudflare-ai-gateway"),
        Some(Dialect::Messages)
    );
    assert_eq!(dialect_for("vercel-ai-gateway"), Some(Dialect::Messages));
    assert_eq!(dialect_for("gitlab-duo"), Some(Dialect::ChatCompletions));
    assert_eq!(dialect_for("opencode-go"), Some(Dialect::ChatCompletions));
    assert_eq!(dialect_for("opencode-zen"), Some(Dialect::ChatCompletions));

    // a reserved id without a Messages contract arm denies at build
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.opencode-zen]\nkind = \"api_key\"\nendpoint = \"https://opencode.ai/zen\"\ncredential_ref = \"keyring:rivect-test/opencode-zen\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"opencode-zen\", model_id = \"claude-opus-4-8\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"off\" }\n",
    )
    .expect("valid");
    let denied = provider_result(
        config,
        "opencode-zen".to_string(),
        Arc::new(MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a Messages-owner build denies an id without its contract arm");
    assert!(matches!(denied, ProviderError::DialectMismatch { .. }));
}

#[test]
fn wire_auth_debug_redacts_resolved_material() {
    let resolved = WireAuth::Resolved {
        token: "fixture-resolved-token-not-real".to_string(),
        headers: std::collections::BTreeMap::from([(
            "x-gitlab-token".to_string(),
            "fixture-header-value-not-real".to_string(),
        )]),
    };
    let rendered = format!("{resolved:?}");
    assert!(!rendered.contains("fixture-resolved-token-not-real"));
    assert!(!rendered.contains("fixture-header-value-not-real"));
    assert!(!rendered.contains("x-gitlab-token"));

    let reference =
        SecretRef::parse("keyring:rivect-test/anthropic").expect("the fixture ref is scoped");
    let stored = WireAuth::Store(Some(reference));
    let rendered = format!("{stored:?}");
    assert!(rendered.contains("keyring:rivect-test/anthropic"));
}

// ----- TP-PROVIDER-INSTALLED::anthropic -------------------------------

/// The peer's `cache_read_input_tokens`/`cache_creation_input_tokens` ride
/// as their own legs; the completion bin keeps the cumulative output count
/// (AC-057).
#[tokio::test]
async fn message_start_cache_legs_are_carried() {
    let server = MockServer::start().await;
    let body = format!(
        "{}{}{}{}{}{}",
        sse_block(
            "message_start",
            &json!({
                "type": "message_start",
                "message": {
                    "id": "msg_1",
                    "type": "message",
                    "role": "assistant",
                    "content": [],
                    "usage": {
                        "input_tokens": 5,
                        "output_tokens": 1,
                        "cache_read_input_tokens": 3,
                        "cache_creation_input_tokens": 2,
                    },
                },
            }),
        ),
        sse_block(
            "content_block_start",
            &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ),
        sse_block(
            "content_block_delta",
            &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "cached"}}),
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
                "usage": {"output_tokens": 7},
            }),
        ),
        sse_block("message_stop", &json!({"type": "message_stop"})),
    );
    mount_messages(&server, body).await;
    let config =
        Config::parse_validated(&anthropic_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = anthropic_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/anthropic", "goal: cache legs")
        .expect("the pin prepares");
    let attempt_id = manifest.attempt_id.clone();
    let (broker, outcome) = std::thread::spawn(move || {
        let mut ledger = rivect::model::NullLedger;
        let outcome = broker.dispatch(&mut ledger, "/world/anthropic", &manifest);
        (broker, outcome)
    })
    .join()
    .expect("the send thread joins");
    outcome.expect("the cached send completes");
    let record = broker
        .accounting_record(&attempt_id)
        .expect("the send is accounted");
    assert_eq!(
        record.usage,
        UsageDelta::Legs {
            prompt_tokens: Some(5),
            completion_tokens: Some(7),
            reasoning_tokens: None,
            cache_read_tokens: Some(3),
            cache_write_tokens: Some(2),
            total_tokens: Some(12),
        }
    );
}

/// TP-PROVIDER-INSTALLED::anthropic = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::anthropic = NOT_RUN"]
fn provider_installed_anthropic() {}

// ----- TP-PROVIDER-{CATALOG,AUTH,WIRE,RECOVERY}::umans ----------------

/// A configured `umans` connection returns one verified outcome and
/// exactly one accounted usage: the configured base is stripped of its
/// trailing `/v1` and the inference path re-appends the version segment.
#[tokio::test]
async fn umans_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("umans outcome", 13, 5)).await;
    let config = Config::parse_validated(&umans_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        umans_provider(&config),
        &config,
        "/world/umans",
        "goal: prove the umans wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/umans", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "umans outcome");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 13,
            completion_tokens: 5,
            total_tokens: 18,
        }
    );

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request");
    assert_eq!(
        requests[0].url.path(),
        "/v1/messages",
        "the stripped base carries the inference path"
    );
    assert_eq!(header(&requests[0], "x-api-key"), Some(SECRET));
    assert_eq!(
        header(&requests[0], "anthropic-version"),
        Some("2023-06-01")
    );
    assert_eq!(header(&requests[0], "authorization"), None);
    let body = body_of(&requests[0]);
    assert_eq!(body["model"], json!(UMANS_MODEL));
    assert_eq!(body["system"], json!(manifest.instructions));
    assert_eq!(body["max_tokens"], json!(MESSAGES_MAX_TOKENS));
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["messages"],
        json!([{"role": "user", "content": manifest.inputs}])
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(SECRET),
        "credential material rides the header, never the body"
    );

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, UMANS);
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 13,
            completion_tokens: 5,
            total_tokens: 18,
        }
    );
    drop_blocking(broker);
}

#[tokio::test]
async fn umans_catalog_reads_models_info_capabilities() {
    let server = MockServer::start().await;
    mount_models_info(
        &server,
        json!({
            "umans-fixture-lite": {
                "capabilities": {
                    "supports_vision": false,
                    "supports_tools": false,
                    "reasoning": {"supported": false, "levels": ["high"]},
                },
                "context_window": "128000",
                "max_completion_tokens": 0,
            },
            "umans-fixture-pro": {
                "name": "Umans Fixture Pro",
                "display_name": "Fixture Pro",
                "capabilities": {
                    "supports_vision": true,
                    "supports_tools": true,
                    "reasoning": {
                        "supported": true,
                        "levels": ["low", "medium", "high", "max", "unknown"],
                    },
                },
                "context_window": 200_000,
                "max_completion_tokens": 64_000,
            },
        }),
    )
    .await;
    let config = Config::parse_validated(&umans_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = umans_provider(&config);

    let (provider, catalog) = catalog_models_on_thread(provider);
    let models = catalog.expect("the object-keyed listing answers");
    assert_eq!(
        models
            .iter()
            .map(|model| model.id.as_str())
            .collect::<Vec<_>>(),
        ["umans-fixture-lite", "umans-fixture-pro"],
        "the listing's own keys answer in deterministic sorted order"
    );
    let lite = &models[0];
    assert!(!lite.reasoning, "a false supported mark is no reasoning");
    assert!(!lite.vision);
    assert!(
        !lite.tools,
        "a false supports_tools mark is no tool surface"
    );
    assert!(
        lite.efforts.is_empty(),
        "levels without a supported reasoning mark are no dial"
    );
    assert_eq!(lite.context_window, Some(128_000));
    assert_eq!(
        lite.max_output_tokens, None,
        "a stated zero output cap stays absent"
    );
    let pro = &models[1];
    assert!(pro.reasoning);
    assert!(pro.vision);
    assert!(
        pro.tools,
        "a literal true supports_tools maps the tool mark"
    );
    assert_eq!(
        pro.efforts,
        [EffortLevel::Low, EffortLevel::Medium, EffortLevel::High],
        "only representable levels land; max and unknown never coerce"
    );
    assert_eq!(pro.context_window, Some(200_000));
    assert_eq!(pro.max_output_tokens, Some(64_000));
    drop_blocking(provider);

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the listing");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].url.path(),
        "/models/info",
        "the configured trailing /v1 is stripped and /models/info is the recorded route"
    );
    assert_eq!(header(&requests[0], "x-api-key"), Some(SECRET));
    assert_eq!(
        header(&requests[0], "anthropic-version"),
        Some("2023-06-01")
    );
    assert_eq!(header(&requests[0], "authorization"), None);
}

#[tokio::test]
async fn umans_models_info_is_object_keyed_and_via_handoff_is_not_vision() {
    let server = MockServer::start().await;
    mount_models_info(
        &server,
        json!({
            "model-handoff": {
                "id": "decoy-id",
                "capabilities": {
                    "supports_vision": "via-handoff",
                    "reasoning": {"supported": true, "levels": ["high"]},
                },
            },
            "model-vision": {"capabilities": {"supports_vision": true}},
            "model-text": {"capabilities": {"supports_vision": false}},
        }),
    )
    .await;
    let config = Config::parse_validated(&umans_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = umans_provider(&config);

    let (provider, catalog) = catalog_models_on_thread(provider);
    let models = catalog.expect("the object-keyed listing answers");
    let ids: Vec<&str> = models.iter().map(|model| model.id.as_str()).collect();
    assert_eq!(
        ids,
        ["model-handoff", "model-text", "model-vision"],
        "the object key is the model id, never a value field"
    );
    let handoff = models
        .iter()
        .find(|model| model.id == "model-handoff")
        .expect("the handoff entry answers");
    assert!(
        !handoff.vision,
        "the via-handoff string sentinel never marks vision"
    );
    assert!(handoff.reasoning);
    let text = models
        .iter()
        .find(|model| model.id == "model-text")
        .expect("the text entry answers");
    assert!(!text.vision);
    let vision = models
        .iter()
        .find(|model| model.id == "model-vision")
        .expect("the vision entry answers");
    assert!(vision.vision, "only a literal true marks vision");
    drop_blocking(provider);
}

#[tokio::test]
async fn umans_failed_models_info_denies_without_a_fabricated_floor() {
    // a non-success listing is a typed denial, never an empty offer set
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models/info"))
        .respond_with(ResponseTemplate::new(503).set_body_string("listing unavailable"))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&umans_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = umans_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let error = catalog.expect_err("a failed listing denies");
    assert!(
        matches!(
            &error,
            ProviderError::Transport {
                cause,
                ..
            } if cause.class() == TransportClass::HttpStatus { code: 503 }
        ),
        "the failed listing keeps its typed transport denial: {error:?}"
    );
    drop_blocking(provider);
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the listing");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/models/info");

    // a payload that is not the object form denies instead of inventing ids
    let server = MockServer::start().await;
    mount_models_info(&server, json!([{"id": "umans-fixture-model"}])).await;
    let config = Config::parse_validated(&umans_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = umans_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let error = catalog.expect_err("a non-object listing denies");
    assert!(
        matches!(error, ProviderError::StreamViolation { .. }),
        "a non-object listing is a typed shape violation: {error:?}"
    );
    drop_blocking(provider);
}

#[tokio::test]
async fn umans_wrong_credential_profile_or_region_denies_without_secrets() {
    // a configured region names no recorded contract — typed denial at build
    let region_config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.{UMANS}]\nkind = \"api_key\"\nendpoint = \"https://api.code.umans.ai/v1\"\nregion = \"eu\"\ncredential_ref = \"{UMANS_CREDENTIAL_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"{UMANS}\", model_id = \"{UMANS_MODEL}\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the region config parses");
    let region = provider_result(
        region_config,
        UMANS.to_string(),
        Arc::new(MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a configured region denies");
    assert!(matches!(
        &region,
        ProviderError::RegionMismatch { connection, region }
            if connection == UMANS && region == "eu"
    ));

    // a profile-bound ref whose scope names another profile cannot bind
    let profile_config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.{UMANS}]\nkind = \"api_key\"\nendpoint = \"https://api.code.umans.ai/v1\"\ncredential_ref = \"{UMANS_CREDENTIAL_REF}\"\nprofile = \"umans-work\"\n\
         [profiles.umans-work]\ncredential_ref = \"keyring:rivect-test/another-profile\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"{UMANS}\", model_id = \"{UMANS_MODEL}\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the profile config parses");
    let profile = provider_result(
        profile_config,
        UMANS.to_string(),
        Arc::new(MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a divergent profile scope denies");
    assert!(matches!(
        &profile,
        ProviderError::CredentialProfileMismatch { connection, profile }
            if connection == UMANS && profile == "umans-work"
    ));

    // an empty bound scope denies at send without reaching the wire and
    // without leaking the neighbour's material
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("never reached", 1, 1)).await;
    let config = Config::parse_validated(&umans_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(NEIGHBOR_REF, NEIGHBOR_SECRET)],
    ));
    let provider =
        provider_result(config.clone(), UMANS.to_string(), store).expect("binding resolves");
    let (provider, denied) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/umans"));
    let error = denied.expect_err("the empty scope denies");
    assert!(matches!(error, ProviderError::CredentialAbsent { .. }));
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(
            !rendered.contains(NEIGHBOR_SECRET) && !rendered.contains(SECRET),
            "diagnostics stay secret-free: {rendered}"
        );
    }
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("the mock recorded")
            .is_empty(),
        "the denial lands before the wire"
    );
}

#[tokio::test]
async fn umans_rejects_partial_tool_block_and_unknown_terminal() {
    // partial tool JSON at the block stop is a typed violation
    let server = MockServer::start().await;
    mount_messages(
        &server,
        format!(
            "{}{}{}{}{}{}",
            message_start(3),
            sse_block(
                "content_block_start",
                &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {}}}),
            ),
            sse_block(
                "content_block_delta",
                &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "{\"path\":"}}),
            ),
            sse_block(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 0}),
            ),
            sse_block(
                "message_delta",
                &json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 2}}),
            ),
            sse_block("message_stop", &json!({"type": "message_stop"})),
        ),
    )
    .await;
    let config = Config::parse_validated(&umans_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = umans_provider(&config);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/umans"));
    assert!(
        matches!(outcome, Err(ProviderError::StreamViolation { .. })),
        "a partial tool block never becomes a reply: {outcome:?}"
    );
    drop_blocking(provider);

    // a terminal the dialect cannot classify is never success
    let server = MockServer::start().await;
    mount_messages(
        &server,
        format!(
            "{}{}{}{}",
            message_start(3),
            sse_block(
                "content_block_start",
                &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            ),
            sse_block(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 0}),
            ),
            format!(
                "{}{}",
                sse_block(
                    "message_delta",
                    &json!({"type": "message_delta", "delta": {"stop_reason": "teleport"}, "usage": {"output_tokens": 1}}),
                ),
                sse_block("message_stop", &json!({"type": "message_stop"})),
            ),
        ),
    )
    .await;
    let config = Config::parse_validated(&umans_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = umans_provider(&config);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/umans"));
    assert!(
        matches!(outcome, Err(ProviderError::UnknownTerminal { .. })),
        "an unknown stop reason is an unknown terminal: {outcome:?}"
    );
    drop_blocking(provider);
}

#[tokio::test]
async fn umans_rejects_incompatible_tools_or_reasoning() {
    // a pinned effort has no recorded Messages dial
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("never reached", 1, 1)).await;
    let config = Config::parse_validated(&umans_config(&server_uri_v1(&server)).replace(
        "effort = { mode = \"auto\" }",
        "effort = { mode = \"fixed\", value = \"high\" }",
    ))
    .expect("valid");
    let (provider, _store) = umans_provider(&config);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/umans"));
    let ProviderError::UnsupportedParameter {
        connection,
        parameter,
        model,
    } = outcome.expect_err("a pinned effort denies")
    else {
        panic!("expected the typed unsupported parameter");
    };
    assert_eq!(connection, UMANS);
    assert_eq!(parameter, "effort");
    assert_eq!(model, UMANS_MODEL);
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the reasoning denial lands before any wire leg"
    );

    // a tool name outside the Messages grammar has no constructible tool
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("never reached", 1, 1)).await;
    let config = Config::parse_validated(&umans_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = umans_provider(&config);
    let mut manifest = prepared_manifest_at(&config, "/world/umans");
    manifest.tools = vec!["read file".to_string()];
    let (provider, outcome) = send_on_thread(provider, manifest);
    let ProviderError::UnsupportedParameter {
        parameter, model, ..
    } = outcome.expect_err("a tool name outside the grammar denies")
    else {
        panic!("expected the typed tool denial");
    };
    assert_eq!(parameter, "tools");
    assert_eq!(model, UMANS_MODEL);
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the tool denial lands before any wire leg"
    );
}

#[tokio::test]
async fn umans_non_success_status_denies() {
    for status in [400_u16, 429, 500] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(status).set_body_string("peer failure body"))
            .mount(&server)
            .await;
        let config =
            Config::parse_validated(&umans_config(&server_uri_v1(&server))).expect("valid");
        let (broker, manifest) = prepared_with(
            umans_provider(&config),
            &config,
            "/world/umans",
            "goal: non-success",
        );
        let (broker, outcome) = dispatch(broker, "/world/umans", manifest);
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
            "a non-signature failure is never retried"
        );
    }
}

#[tokio::test]
async fn umans_short_deadline_denies_without_a_second_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(text_stream("late", 1, 1))
                .set_delay(Duration::from_millis(600)),
        )
        .mount(&server)
        .await;
    let config = Config::parse_validated(&umans_config(&server_uri_v1(&server))).expect("valid");
    let deadline = Duration::from_millis(400);
    let provider = umans_with_deadline(&config, deadline);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/umans"));
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

#[tokio::test]
async fn umans_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    // CATALOG
    let catalog_server = MockServer::start().await;
    mount_models_info(
        &catalog_server,
        json!({
            "umans-fixture-model": {
                "capabilities": {
                    "supports_vision": true,
                    "reasoning": {"supported": true, "levels": ["high"]},
                },
                "context_window": 200_000,
                "max_completion_tokens": 64_000,
            },
        }),
    )
    .await;
    let config =
        Config::parse_validated(&umans_config(&server_uri_v1(&catalog_server))).expect("valid");
    let (provider, _store) = umans_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if matches!(&catalog, Ok(ids) if ids == &[UMANS_MODEL.to_string()]) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("matrix", 1, 1)).await;
    let config = Config::parse_validated(&umans_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), UMANS.to_string(), store).expect("binding resolves");
    let (provider, denied) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/umans"));
    reported.insert(
        "AUTH",
        if matches!(denied, Err(ProviderError::CredentialAbsent { .. })) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // WIRE
    let (broker, manifest) = prepared_with(
        umans_provider(&config),
        &config,
        "/world/umans",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/umans", manifest);
    reported.insert(
        "WIRE",
        if matches!(&outcome, Ok(reply) if reply.text == "matrix") {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

    // RECOVERY
    let recovery_server = MockServer::start().await;
    let mut truncated = text_stream("looks complete", 1, 1);
    truncated.truncate(
        truncated
            .rfind("event: message_stop")
            .expect("the terminal exists"),
    );
    mount_messages(&recovery_server, truncated).await;
    let recovery_config =
        Config::parse_validated(&umans_config(&server_uri_v1(&recovery_server))).expect("valid");
    let (provider, _store) = umans_provider(&recovery_config);
    let (provider, outcome) = send_on_thread(
        provider,
        prepared_manifest_at(&recovery_config, "/world/umans"),
    );
    reported.insert(
        "RECOVERY",
        if matches!(outcome, Err(ProviderError::UnknownTerminal { .. })) {
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

// ----- TP-PROVIDER-INSTALLED::umans -----------------------------------

/// TP-PROVIDER-INSTALLED::umans = NOT_RUN: the installed-provider proof
/// is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::umans = NOT_RUN"]
fn provider_installed_umans() {}

// ----- TP-PROVIDER-{CATALOG,AUTH,WIRE,RECOVERY}::minimax --------------

/// A configured `minimax` connection returns one verified outcome and
/// exactly one accounted usage: the recorded base is used verbatim and
/// the inference path appends `/v1/messages`.
#[tokio::test]
async fn minimax_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("minimax outcome", 13, 5)).await;
    let config = Config::parse_validated(&minimax_config(&server.uri())).expect("valid");
    let (broker, manifest) = prepared_with(
        minimax_provider(&config),
        &config,
        "/world/minimax",
        "goal: prove the minimax wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/minimax", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "minimax outcome");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 13,
            completion_tokens: 5,
            total_tokens: 18,
        }
    );

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request");
    assert_eq!(
        requests[0].url.path(),
        "/v1/messages",
        "the verbatim base carries the inference path"
    );
    assert_eq!(header(&requests[0], "x-api-key"), Some(SECRET));
    assert_eq!(
        header(&requests[0], "anthropic-version"),
        Some("2023-06-01")
    );
    assert_eq!(header(&requests[0], "authorization"), None);
    let body = body_of(&requests[0]);
    assert_eq!(body["model"], json!(MINIMAX_MODEL));
    assert_eq!(body["system"], json!(manifest.instructions));
    assert_eq!(body["max_tokens"], json!(MESSAGES_MAX_TOKENS));
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["messages"],
        json!([{"role": "user", "content": manifest.inputs}])
    );
    for field in [
        "service_tier",
        "top_k",
        "stop_sequences",
        "mcp_servers",
        "context_management",
        "container",
    ] {
        assert!(
            body[field].is_null(),
            "{field} has no manifest carrier and is never constructed"
        );
    }
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(SECRET),
        "credential material rides the header, never the body"
    );

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, MINIMAX);
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 13,
            completion_tokens: 5,
            total_tokens: 18,
        }
    );
    drop_blocking(broker);
}

#[tokio::test]
async fn minimax_catalog_is_the_recorded_m_series_allowlist() {
    let server = MockServer::start().await;
    let config = Config::parse_validated(&minimax_config(&server.uri())).expect("valid");
    let (provider, _store) = minimax_provider(&config);

    let (provider, catalog) = catalog_on_thread(provider);
    assert_eq!(
        catalog.expect("the static M-series allowlist answers"),
        MINIMAX_ALLOWLIST,
        "the recorded M-series set is the whole catalogue"
    );
    drop_blocking(provider);

    assert!(
        server
            .received_requests()
            .await
            .expect("the mock recorded")
            .is_empty(),
        "the allowlist has no discovery leg"
    );
}

#[tokio::test]
async fn static_catalogues_answer_with_an_empty_store() {
    // The static arms return their recorded offer set without resolving
    // a credential: an empty store must not deny the catalogue.
    let config = Config::parse_validated(&minimax_config("https://api.minimax.io/anthropic"))
        .expect("valid");
    let provider = provider_result(
        config,
        MINIMAX.to_string(),
        Arc::new(MapStore::new(STORE_KIND)),
    )
    .expect("the static arm builds");
    let (provider, catalog) = catalog_on_thread(provider);
    assert_eq!(
        catalog.expect("the allowlist answers without store material"),
        MINIMAX_ALLOWLIST,
        "the minimax offer set is static"
    );
    drop_blocking(provider);

    let config = Config::parse_validated(&cloudflare_config("https://gateway.example.invalid"))
        .expect("valid");
    let provider = provider_result(
        config,
        CLOUDFLARE.to_string(),
        Arc::new(MapStore::new(STORE_KIND)),
    )
    .expect("the static arm builds");
    let (provider, catalog) = catalog_on_thread(provider);
    assert_eq!(
        catalog.expect("the seed answers without store material"),
        [CLOUDFLARE_MODEL],
        "the cloudflare offer set is static"
    );
    drop_blocking(provider);
}

#[tokio::test]
async fn minimax_non_m_series_model_is_not_offered() {
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("never reached", 1, 1)).await;
    let config = Config::parse_validated(&minimax_config(&server.uri())).expect("valid");
    let (provider, _store) = minimax_provider(&config);

    let (provider, catalog) = catalog_on_thread(provider);
    let ids = catalog.expect("the static allowlist answers");
    assert!(
        !ids.iter().any(|id| id == "abab6.5-chat"),
        "a non-M id is never offered"
    );

    let mut manifest = prepared_manifest_at(&config, "/world/minimax");
    manifest.model = ModelAssign::Fixed(FixedModel {
        connection: MINIMAX.to_string(),
        model_id: "abab6.5-chat".to_string(),
    });
    let (provider, outcome) = send_on_thread(provider, manifest);
    let ProviderError::UnsupportedParameter {
        connection,
        parameter,
        model,
    } = outcome.expect_err("a non-M id is never sent")
    else {
        panic!("expected the typed model denial");
    };
    assert_eq!(connection, MINIMAX);
    assert_eq!(parameter, "model");
    assert_eq!(model, "abab6.5-chat");
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

#[tokio::test]
async fn minimax_wrong_credential_profile_or_region_denies_without_secrets() {
    // a configured region names no recorded contract — typed denial at build
    let region_config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.{MINIMAX}]\nkind = \"api_key\"\nendpoint = \"https://api.minimax.io/anthropic\"\nregion = \"eu\"\ncredential_ref = \"{MINIMAX_CREDENTIAL_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"{MINIMAX}\", model_id = \"{MINIMAX_MODEL}\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the region config parses");
    let region = provider_result(
        region_config,
        MINIMAX.to_string(),
        Arc::new(MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a configured region denies");
    assert!(matches!(
        &region,
        ProviderError::RegionMismatch { connection, region }
            if connection == MINIMAX && region == "eu"
    ));

    // a profile-bound ref whose scope names another profile cannot bind
    let profile_config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.{MINIMAX}]\nkind = \"api_key\"\nendpoint = \"https://api.minimax.io/anthropic\"\ncredential_ref = \"{MINIMAX_CREDENTIAL_REF}\"\nprofile = \"minimax-work\"\n\
         [profiles.minimax-work]\ncredential_ref = \"keyring:rivect-test/another-profile\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"{MINIMAX}\", model_id = \"{MINIMAX_MODEL}\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the profile config parses");
    let profile = provider_result(
        profile_config,
        MINIMAX.to_string(),
        Arc::new(MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a divergent profile scope denies");
    assert!(matches!(
        &profile,
        ProviderError::CredentialProfileMismatch { connection, profile }
            if connection == MINIMAX && profile == "minimax-work"
    ));

    // an empty bound scope denies at send without reaching the wire and
    // without leaking the neighbour's material
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("never reached", 1, 1)).await;
    let config = Config::parse_validated(&minimax_config(&server.uri())).expect("valid");
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(NEIGHBOR_REF, NEIGHBOR_SECRET)],
    ));
    let provider =
        provider_result(config.clone(), MINIMAX.to_string(), store).expect("binding resolves");
    let (provider, denied) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/minimax"));
    let error = denied.expect_err("the empty scope denies");
    assert!(matches!(error, ProviderError::CredentialAbsent { .. }));
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(
            !rendered.contains(NEIGHBOR_SECRET) && !rendered.contains(SECRET),
            "diagnostics stay secret-free: {rendered}"
        );
    }
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("the mock recorded")
            .is_empty(),
        "the denial lands before the wire"
    );
}

#[tokio::test]
async fn minimax_rejects_partial_tool_block_and_unknown_terminal() {
    // partial tool JSON at the block stop is a typed violation
    let server = MockServer::start().await;
    mount_messages(
        &server,
        format!(
            "{}{}{}{}{}{}",
            message_start(3),
            sse_block(
                "content_block_start",
                &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {}}}),
            ),
            sse_block(
                "content_block_delta",
                &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "{\"path\":"}}),
            ),
            sse_block(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 0}),
            ),
            sse_block(
                "message_delta",
                &json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 2}}),
            ),
            sse_block("message_stop", &json!({"type": "message_stop"})),
        ),
    )
    .await;
    let config = Config::parse_validated(&minimax_config(&server.uri())).expect("valid");
    let (provider, _store) = minimax_provider(&config);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/minimax"));
    assert!(
        matches!(outcome, Err(ProviderError::StreamViolation { .. })),
        "a partial tool block never becomes a reply: {outcome:?}"
    );
    drop_blocking(provider);

    // a terminal the dialect cannot classify is never success
    let server = MockServer::start().await;
    mount_messages(
        &server,
        format!(
            "{}{}{}{}",
            message_start(3),
            sse_block(
                "content_block_start",
                &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            ),
            sse_block(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 0}),
            ),
            format!(
                "{}{}",
                sse_block(
                    "message_delta",
                    &json!({"type": "message_delta", "delta": {"stop_reason": "teleport"}, "usage": {"output_tokens": 1}}),
                ),
                sse_block("message_stop", &json!({"type": "message_stop"})),
            ),
        ),
    )
    .await;
    let config = Config::parse_validated(&minimax_config(&server.uri())).expect("valid");
    let (provider, _store) = minimax_provider(&config);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/minimax"));
    assert!(
        matches!(outcome, Err(ProviderError::UnknownTerminal { .. })),
        "an unknown stop reason is an unknown terminal: {outcome:?}"
    );
    drop_blocking(provider);
}

#[tokio::test]
async fn minimax_rejects_incompatible_tools_or_reasoning() {
    // a pinned effort has no recorded Messages dial
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("never reached", 1, 1)).await;
    let config = Config::parse_validated(&minimax_config(&server.uri()).replace(
        "effort = { mode = \"auto\" }",
        "effort = { mode = \"fixed\", value = \"high\" }",
    ))
    .expect("valid");
    let (provider, _store) = minimax_provider(&config);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/minimax"));
    let ProviderError::UnsupportedParameter {
        connection,
        parameter,
        model,
    } = outcome.expect_err("a pinned effort denies")
    else {
        panic!("expected the typed unsupported parameter");
    };
    assert_eq!(connection, MINIMAX);
    assert_eq!(parameter, "effort");
    assert_eq!(model, MINIMAX_MODEL);
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the reasoning denial lands before any wire leg"
    );

    // a tool name outside the Messages grammar has no constructible tool
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("never reached", 1, 1)).await;
    let config = Config::parse_validated(&minimax_config(&server.uri())).expect("valid");
    let (provider, _store) = minimax_provider(&config);
    let mut manifest = prepared_manifest_at(&config, "/world/minimax");
    manifest.tools = vec!["read file".to_string()];
    let (provider, outcome) = send_on_thread(provider, manifest);
    let ProviderError::UnsupportedParameter {
        parameter, model, ..
    } = outcome.expect_err("a tool name outside the grammar denies")
    else {
        panic!("expected the typed tool denial");
    };
    assert_eq!(parameter, "tools");
    assert_eq!(model, MINIMAX_MODEL);
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the tool denial lands before any wire leg"
    );
}

#[tokio::test]
async fn minimax_non_success_status_denies() {
    for status in [400_u16, 429, 500] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(status).set_body_string("peer failure body"))
            .mount(&server)
            .await;
        let config = Config::parse_validated(&minimax_config(&server.uri())).expect("valid");
        let (broker, manifest) = prepared_with(
            minimax_provider(&config),
            &config,
            "/world/minimax",
            "goal: non-success",
        );
        let (broker, outcome) = dispatch(broker, "/world/minimax", manifest);
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
            "a non-signature failure is never retried"
        );
    }
}

#[tokio::test]
async fn minimax_short_deadline_denies_without_a_second_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(text_stream("late", 1, 1))
                .set_delay(Duration::from_millis(600)),
        )
        .mount(&server)
        .await;
    let config = Config::parse_validated(&minimax_config(&server.uri())).expect("valid");
    let deadline = Duration::from_millis(400);
    let provider = minimax_with_deadline(&config, deadline);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/minimax"));
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

#[tokio::test]
async fn minimax_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    // CATALOG
    let catalog_server = MockServer::start().await;
    let config = Config::parse_validated(&minimax_config(&catalog_server.uri())).expect("valid");
    let (provider, _store) = minimax_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if matches!(&catalog, Ok(ids) if ids == MINIMAX_ALLOWLIST) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH
    let server = MockServer::start().await;
    mount_messages(&server, text_stream("matrix", 1, 1)).await;
    let config = Config::parse_validated(&minimax_config(&server.uri())).expect("valid");
    let store = Arc::new(MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), MINIMAX.to_string(), store).expect("binding resolves");
    let (provider, denied) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/minimax"));
    reported.insert(
        "AUTH",
        if matches!(denied, Err(ProviderError::CredentialAbsent { .. })) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // WIRE
    let (broker, manifest) = prepared_with(
        minimax_provider(&config),
        &config,
        "/world/minimax",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/minimax", manifest);
    reported.insert(
        "WIRE",
        if matches!(&outcome, Ok(reply) if reply.text == "matrix") {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

    // RECOVERY
    let recovery_server = MockServer::start().await;
    let mut truncated = text_stream("looks complete", 1, 1);
    truncated.truncate(
        truncated
            .rfind("event: message_stop")
            .expect("the terminal exists"),
    );
    mount_messages(&recovery_server, truncated).await;
    let recovery_config =
        Config::parse_validated(&minimax_config(&recovery_server.uri())).expect("valid");
    let (provider, _store) = minimax_provider(&recovery_config);
    let (provider, outcome) = send_on_thread(
        provider,
        prepared_manifest_at(&recovery_config, "/world/minimax"),
    );
    reported.insert(
        "RECOVERY",
        if matches!(outcome, Err(ProviderError::UnknownTerminal { .. })) {
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

// ----- TP-PROVIDER-INSTALLED::minimax ---------------------------------

/// TP-PROVIDER-INSTALLED::minimax = NOT_RUN: the installed-provider proof
/// is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::minimax = NOT_RUN"]
fn provider_installed_minimax() {}

// ----- TP-PROVIDER-{CATALOG,AUTH,WIRE,RECOVERY}::cloudflare-ai-gateway

/// A configured `cloudflare-ai-gateway` connection returns one verified
/// outcome and exactly one accounted usage through the standard Broker:
/// the configured base is the complete native proxy base, inference
/// appends `/v1/messages`, the wire model keeps its `anthropic/` prefix,
/// and the token rides `cf-aig-authorization` alone.
#[tokio::test]
async fn cloudflare_ai_gateway_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_cloudflare_messages(&server, text_stream("gateway outcome", 13, 5)).await;
    let config =
        Config::parse_validated(&cloudflare_config(&cloudflare_endpoint(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        cloudflare_provider(&config),
        &config,
        "/world/cloudflare",
        "goal: prove the gateway wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/cloudflare", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "gateway outcome");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 13,
            completion_tokens: 5,
            total_tokens: 18,
        }
    );

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request");
    assert_eq!(requests[0].url.path(), CLOUDFLARE_MESSAGES_PATH);
    let bearer = format!("Bearer {SECRET}");
    assert_eq!(
        header(&requests[0], "cf-aig-authorization"),
        Some(bearer.as_str())
    );
    assert_eq!(header(&requests[0], "authorization"), None);
    assert_eq!(header(&requests[0], "x-api-key"), None);
    assert_eq!(
        header(&requests[0], "anthropic-version"),
        Some("2023-06-01")
    );
    let body = body_of(&requests[0]);
    assert_eq!(
        body["model"],
        json!(CLOUDFLARE_MODEL),
        "the wire model keeps its upstream provider prefix"
    );
    assert_eq!(body["system"], json!(manifest.instructions));
    assert_eq!(body["max_tokens"], json!(MESSAGES_MAX_TOKENS));
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["messages"],
        json!([{"role": "user", "content": manifest.inputs}])
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(SECRET),
        "credential material rides the header, never the body"
    );

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, CLOUDFLARE);
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 13,
            completion_tokens: 5,
            total_tokens: 18,
        }
    );
    drop_blocking(broker);
}

#[tokio::test]
async fn cloudflare_ai_gateway_requires_a_configured_account_gateway_base() {
    // account and gateway are operator data, so an empty endpoint has no
    // recorded base to send to and never falls back to a default host
    let config = Config::parse_validated(&cloudflare_config("   "))
        .expect("the empty sentinel is a valid ingress value");
    let denied = provider_result(
        config,
        CLOUDFLARE.to_string(),
        Arc::new(MapStore::seeded(
            STORE_KIND,
            &[(CLOUDFLARE_CREDENTIAL_REF, SECRET)],
        )),
    )
    .expect_err("a configured base is required");
    assert!(matches!(
        &denied,
        ProviderError::EndpointRequired { connection } if connection == CLOUDFLARE
    ));
    assert!(
        format!("{denied}").contains(CLOUDFLARE),
        "the denial names the connection"
    );
}

#[tokio::test]
async fn cloudflare_ai_gateway_token_rides_cf_aig_authorization_only() {
    let server = MockServer::start().await;
    mount_cloudflare_messages(&server, text_stream("auth", 1, 1)).await;
    let config =
        Config::parse_validated(&cloudflare_config(&cloudflare_endpoint(&server))).expect("valid");
    let (provider, _store) = cloudflare_provider(&config);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/cloudflare"));
    assert!(
        outcome.is_ok(),
        "the single-header form serves: {outcome:?}"
    );
    drop_blocking(provider);

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1);
    let bearer = format!("Bearer {SECRET}");
    assert_eq!(
        header(&requests[0], "cf-aig-authorization"),
        Some(bearer.as_str()),
        "the Run-permission token rides its own header"
    );
    assert_eq!(
        header(&requests[0], "authorization"),
        None,
        "cf-aig-authorization is never a second Authorization"
    );
    assert_eq!(
        header(&requests[0], "x-api-key"),
        None,
        "the native proxy address carries no api-key header"
    );
    assert_eq!(
        header(&requests[0], "anthropic-version"),
        Some("2023-06-01")
    );
    assert!(!String::from_utf8_lossy(&requests[0].body).contains(SECRET));
}

#[tokio::test]
async fn cloudflare_ai_gateway_rejects_a_non_anthropic_model() {
    let server = MockServer::start().await;
    mount_cloudflare_messages(&server, text_stream("never reached", 1, 1)).await;
    let config =
        Config::parse_validated(&cloudflare_config(&cloudflare_endpoint(&server))).expect("valid");

    // the static seed is the whole catalogue and opens no listing leg
    let (provider, _store) = cloudflare_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    assert_eq!(
        catalog.expect("the static seed answers"),
        [CLOUDFLARE_MODEL],
        "the recorded seed is the whole catalogue"
    );
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("the mock recorded")
            .is_empty(),
        "the static seed opens no discovery leg"
    );

    // a model outside the recorded `anthropic/` route family never sends
    let (provider, _store) = cloudflare_provider(&config);
    let mut manifest = prepared_manifest_at(&config, "/world/cloudflare");
    manifest.model = ModelAssign::Fixed(FixedModel {
        connection: CLOUDFLARE.to_string(),
        model_id: "openai/gpt-5".to_string(),
    });
    let (provider, outcome) = send_on_thread(provider, manifest);
    let ProviderError::UnsupportedParameter {
        connection,
        parameter,
        model,
    } = outcome.expect_err("a non-Anthropic route denies")
    else {
        panic!("expected the typed model denial");
    };
    assert_eq!(connection, CLOUDFLARE);
    assert_eq!(parameter, "model");
    assert_eq!(model, "openai/gpt-5");
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

#[tokio::test]
async fn cloudflare_ai_gateway_wrong_credential_profile_or_region_denies_without_secrets() {
    // a configured region names no recorded contract — typed denial at build
    let region_config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.{CLOUDFLARE}]\nkind = \"api_key\"\nendpoint = \"https://gateway.ai.cloudflare.com/v1/account/gateway/anthropic\"\nregion = \"eu\"\ncredential_ref = \"{CLOUDFLARE_CREDENTIAL_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"{CLOUDFLARE}\", model_id = \"{CLOUDFLARE_MODEL}\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the region config parses");
    let region = provider_result(
        region_config,
        CLOUDFLARE.to_string(),
        Arc::new(MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a configured region denies");
    assert!(matches!(
        &region,
        ProviderError::RegionMismatch { connection, region }
            if connection == CLOUDFLARE && region == "eu"
    ));

    // a profile-bound ref whose scope names another profile cannot bind
    let profile_config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.{CLOUDFLARE}]\nkind = \"api_key\"\nendpoint = \"https://gateway.ai.cloudflare.com/v1/account/gateway/anthropic\"\ncredential_ref = \"{CLOUDFLARE_CREDENTIAL_REF}\"\nprofile = \"cloudflare-work\"\n\
         [profiles.cloudflare-work]\ncredential_ref = \"keyring:rivect-test/another-profile\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"{CLOUDFLARE}\", model_id = \"{CLOUDFLARE_MODEL}\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the profile config parses");
    let profile = provider_result(
        profile_config,
        CLOUDFLARE.to_string(),
        Arc::new(MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a divergent profile scope denies");
    assert!(matches!(
        &profile,
        ProviderError::CredentialProfileMismatch { connection, profile }
            if connection == CLOUDFLARE && profile == "cloudflare-work"
    ));

    // an empty bound scope denies at send without reaching the wire and
    // without leaking the neighbour's material
    let server = MockServer::start().await;
    mount_cloudflare_messages(&server, text_stream("never reached", 1, 1)).await;
    let config =
        Config::parse_validated(&cloudflare_config(&cloudflare_endpoint(&server))).expect("valid");
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(NEIGHBOR_REF, NEIGHBOR_SECRET)],
    ));
    let provider =
        provider_result(config.clone(), CLOUDFLARE.to_string(), store).expect("binding resolves");
    let (provider, denied) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/cloudflare"));
    let error = denied.expect_err("the empty scope denies");
    assert!(matches!(error, ProviderError::CredentialAbsent { .. }));
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(
            !rendered.contains(NEIGHBOR_SECRET) && !rendered.contains(SECRET),
            "diagnostics stay secret-free: {rendered}"
        );
    }
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("the mock recorded")
            .is_empty(),
        "the denial lands before the wire"
    );
}

#[tokio::test]
async fn cloudflare_ai_gateway_rejects_partial_tool_block_and_unknown_terminal() {
    // partial tool JSON at the block stop is a typed violation
    let server = MockServer::start().await;
    mount_cloudflare_messages(
        &server,
        format!(
            "{}{}{}{}{}{}",
            message_start(3),
            sse_block(
                "content_block_start",
                &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {}}}),
            ),
            sse_block(
                "content_block_delta",
                &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "{\"path\":"}}),
            ),
            sse_block(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 0}),
            ),
            sse_block(
                "message_delta",
                &json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 2}}),
            ),
            sse_block("message_stop", &json!({"type": "message_stop"})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&cloudflare_config(&cloudflare_endpoint(&server))).expect("valid");
    let (provider, _store) = cloudflare_provider(&config);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/cloudflare"));
    assert!(
        matches!(outcome, Err(ProviderError::StreamViolation { .. })),
        "a partial tool block never becomes a reply: {outcome:?}"
    );
    drop_blocking(provider);

    // a terminal the dialect cannot classify is never success
    let server = MockServer::start().await;
    mount_cloudflare_messages(
        &server,
        format!(
            "{}{}{}{}",
            message_start(3),
            sse_block(
                "content_block_start",
                &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            ),
            sse_block(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 0}),
            ),
            format!(
                "{}{}",
                sse_block(
                    "message_delta",
                    &json!({"type": "message_delta", "delta": {"stop_reason": "teleport"}, "usage": {"output_tokens": 1}}),
                ),
                sse_block("message_stop", &json!({"type": "message_stop"})),
            ),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&cloudflare_config(&cloudflare_endpoint(&server))).expect("valid");
    let (provider, _store) = cloudflare_provider(&config);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/cloudflare"));
    assert!(
        matches!(outcome, Err(ProviderError::UnknownTerminal { .. })),
        "an unknown stop reason is an unknown terminal: {outcome:?}"
    );
    drop_blocking(provider);
}

#[tokio::test]
async fn cloudflare_ai_gateway_rejects_incompatible_tools_or_reasoning() {
    // a pinned effort has no recorded Messages dial
    let server = MockServer::start().await;
    mount_cloudflare_messages(&server, text_stream("never reached", 1, 1)).await;
    let config =
        Config::parse_validated(&cloudflare_config(&cloudflare_endpoint(&server)).replace(
            "effort = { mode = \"auto\" }",
            "effort = { mode = \"fixed\", value = \"high\" }",
        ))
        .expect("valid");
    let (provider, _store) = cloudflare_provider(&config);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/cloudflare"));
    let ProviderError::UnsupportedParameter {
        connection,
        parameter,
        model,
    } = outcome.expect_err("a pinned effort denies")
    else {
        panic!("expected the typed unsupported parameter");
    };
    assert_eq!(connection, CLOUDFLARE);
    assert_eq!(parameter, "effort");
    assert_eq!(model, CLOUDFLARE_MODEL);
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the reasoning denial lands before any wire leg"
    );

    // a tool name outside the Messages grammar has no constructible tool
    let server = MockServer::start().await;
    mount_cloudflare_messages(&server, text_stream("never reached", 1, 1)).await;
    let config =
        Config::parse_validated(&cloudflare_config(&cloudflare_endpoint(&server))).expect("valid");
    let (provider, _store) = cloudflare_provider(&config);
    let mut manifest = prepared_manifest_at(&config, "/world/cloudflare");
    manifest.tools = vec!["read file".to_string()];
    let (provider, outcome) = send_on_thread(provider, manifest);
    let ProviderError::UnsupportedParameter {
        parameter, model, ..
    } = outcome.expect_err("a tool name outside the grammar denies")
    else {
        panic!("expected the typed tool denial");
    };
    assert_eq!(parameter, "tools");
    assert_eq!(model, CLOUDFLARE_MODEL);
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the tool denial lands before any wire leg"
    );
}

#[tokio::test]
async fn cloudflare_ai_gateway_non_success_status_denies() {
    for status in [400_u16, 429, 500] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(CLOUDFLARE_MESSAGES_PATH))
            .respond_with(ResponseTemplate::new(status).set_body_string("peer failure body"))
            .mount(&server)
            .await;
        let config = Config::parse_validated(&cloudflare_config(&cloudflare_endpoint(&server)))
            .expect("valid");
        let (broker, manifest) = prepared_with(
            cloudflare_provider(&config),
            &config,
            "/world/cloudflare",
            "goal: non-success",
        );
        let (broker, outcome) = dispatch(broker, "/world/cloudflare", manifest);
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
            "a non-signature failure is never retried"
        );
    }
}

#[tokio::test]
async fn cloudflare_ai_gateway_short_deadline_denies_without_a_second_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(CLOUDFLARE_MESSAGES_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(text_stream("late", 1, 1))
                .set_delay(Duration::from_millis(600)),
        )
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&cloudflare_config(&cloudflare_endpoint(&server))).expect("valid");
    let deadline = Duration::from_millis(400);
    let provider = cloudflare_with_deadline(&config, deadline);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/cloudflare"));
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

#[tokio::test]
async fn cloudflare_ai_gateway_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    // CATALOG
    let catalog_server = MockServer::start().await;
    let config = Config::parse_validated(&cloudflare_config(&cloudflare_endpoint(&catalog_server)))
        .expect("valid");
    let (provider, _store) = cloudflare_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if matches!(catalog, Ok(ids) if ids == [CLOUDFLARE_MODEL]) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH
    let server = MockServer::start().await;
    mount_cloudflare_messages(&server, text_stream("matrix", 1, 1)).await;
    let config =
        Config::parse_validated(&cloudflare_config(&cloudflare_endpoint(&server))).expect("valid");
    let store = Arc::new(MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), CLOUDFLARE.to_string(), store).expect("binding resolves");
    let (provider, denied) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/cloudflare"));
    reported.insert(
        "AUTH",
        if matches!(denied, Err(ProviderError::CredentialAbsent { .. })) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // WIRE
    let (broker, manifest) = prepared_with(
        cloudflare_provider(&config),
        &config,
        "/world/cloudflare",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/cloudflare", manifest);
    reported.insert(
        "WIRE",
        if matches!(&outcome, Ok(reply) if reply.text == "matrix") {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

    // RECOVERY
    let recovery_server = MockServer::start().await;
    let mut truncated = text_stream("looks complete", 1, 1);
    truncated.truncate(
        truncated
            .rfind("event: message_stop")
            .expect("the terminal exists"),
    );
    mount_cloudflare_messages(&recovery_server, truncated).await;
    let recovery_config =
        Config::parse_validated(&cloudflare_config(&cloudflare_endpoint(&recovery_server)))
            .expect("valid");
    let (provider, _store) = cloudflare_provider(&recovery_config);
    let (provider, outcome) = send_on_thread(
        provider,
        prepared_manifest_at(&recovery_config, "/world/cloudflare"),
    );
    reported.insert(
        "RECOVERY",
        if matches!(outcome, Err(ProviderError::UnknownTerminal { .. })) {
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

// ----- TP-PROVIDER-INSTALLED::cloudflare-ai-gateway -------------------

/// TP-PROVIDER-INSTALLED::cloudflare-ai-gateway = NOT_RUN: the
/// installed-provider proof is a live-environment leg this offline slice
/// never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::cloudflare-ai-gateway = NOT_RUN"]
fn provider_installed_cloudflare_ai_gateway() {}

// ----- TP-PROVIDER-{CATALOG,AUTH,WIRE,RECOVERY}::vercel-ai-gateway ---

fn count_path(requests: &[Request], path: &str) -> usize {
    requests
        .iter()
        .filter(|request| request.url.path() == path)
        .count()
}

/// A configured `vercel-ai-gateway` connection returns one verified
/// outcome and exactly one accounted usage through the standard Broker:
/// the configured root is the Messages base, inference appends
/// `/v1/messages`, the gateway key rides `Authorization: Bearer`, and the
/// marker read is the only other physical request.
#[tokio::test]
async fn vercel_ai_gateway_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_keyed_models(
        &server,
        &[vercel_row(VERCEL_MODEL, &["file-input", "tool-use"])],
    )
    .await;
    mount_vercel_messages(&server, text_stream("gateway outcome", 13, 5)).await;
    let config = Config::parse_validated(&vercel_config(&server.uri())).expect("valid");
    let (broker, manifest) = prepared_with(
        vercel_provider(&config),
        &config,
        "/world/vercel",
        "goal: prove the gateway wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/vercel", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "gateway outcome");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 13,
            completion_tokens: 5,
            total_tokens: 18,
        }
    );

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(
        count_path(&requests, VERCEL_MESSAGES_PATH),
        1,
        "one physical Messages request"
    );
    assert_eq!(
        count_path(&requests, VERCEL_MODELS_PATH),
        1,
        "the marker guard reads the listing once"
    );
    let post = requests
        .iter()
        .find(|request| request.url.path() == VERCEL_MESSAGES_PATH)
        .expect("the Messages request is recorded");
    let bearer = format!("Bearer {SECRET}");
    assert_eq!(header(post, "authorization"), Some(bearer.as_str()));
    assert_eq!(header(post, "x-api-key"), None);
    assert_eq!(header(post, "anthropic-version"), Some("2023-06-01"));
    let body = body_of(post);
    assert_eq!(body["model"], json!(VERCEL_MODEL));
    assert_eq!(body["system"], json!(manifest.instructions));
    assert_eq!(body["max_tokens"], json!(MESSAGES_MAX_TOKENS));
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["messages"],
        json!([{"role": "user", "content": manifest.inputs}])
    );
    assert!(
        !String::from_utf8_lossy(&post.body).contains(SECRET),
        "credential material rides the header, never the body"
    );

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, VERCEL);
    assert_eq!(record.usage, reply.usage);
    drop_blocking(broker);
}

/// The catalogue is the keyed `/v1/models` listing's `tool-use` rows: a
/// row whose `tags` omit the recorded marker, or carry no `tags` at all,
/// is not offered, and the marker records the tool surface.
#[tokio::test]
async fn vercel_ai_gateway_catalog_requires_the_tool_use_marker() {
    let server = MockServer::start().await;
    mount_keyed_models(
        &server,
        &[
            vercel_row(VERCEL_UNMARKED_MODEL, &["embedding"]),
            vercel_row(VERCEL_MODEL, &["file-input", "tool-use"]),
            json!({"id": "anthropic/claude-sonnet-5.5", "object": "model", "type": "language"}),
        ],
    )
    .await;
    let config = Config::parse_validated(&vercel_config(&server.uri())).expect("valid");
    let (provider, _store) = vercel_provider(&config);
    let (provider, catalog) = catalog_models_on_thread(provider);
    let models = catalog.expect("the marker-filtered listing answers");
    let offered: Vec<&str> = models.iter().map(|model| model.id.as_str()).collect();
    assert_eq!(offered, [VERCEL_MODEL], "only the tagged row is offered");
    assert!(models[0].tools, "the marker is the recorded tool surface");
    drop_blocking(provider);
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the listing");
    assert_eq!(count_path(&requests, VERCEL_MODELS_PATH), 1);
    let listing = requests
        .iter()
        .find(|request| request.url.path() == VERCEL_MODELS_PATH)
        .expect("the listing request is recorded");
    let bearer = format!("Bearer {SECRET}");
    assert_eq!(
        header(listing, "authorization"),
        Some(bearer.as_str()),
        "the gateway key authenticates the marker read"
    );
    assert_eq!(header(listing, "x-api-key"), None);
    assert_eq!(header(listing, "anthropic-version"), Some("2023-06-01"));
}

/// A pin outside the tagged table is a closed-table denial: the marked row
/// is offered beside it, so the denial discriminates the marker from mere
/// absence, and no Messages request reaches the peer.
#[tokio::test]
async fn vercel_ai_gateway_model_without_the_marker_denies() {
    let server = MockServer::start().await;
    mount_keyed_models(
        &server,
        &[
            vercel_row(VERCEL_MODEL, &["tool-use"]),
            vercel_row(VERCEL_UNMARKED_MODEL, &["embedding"]),
        ],
    )
    .await;
    mount_vercel_messages(&server, text_stream("never reached", 1, 1)).await;
    let config = Config::parse_validated(&vercel_config(&server.uri())).expect("valid");
    let (provider, _store) = vercel_provider(&config);
    let mut manifest = prepared_manifest_at(&config, "/world/vercel");
    manifest.model = ModelAssign::Fixed(FixedModel {
        connection: VERCEL.to_string(),
        model_id: VERCEL_UNMARKED_MODEL.to_string(),
    });
    let (provider, outcome) = send_on_thread(provider, manifest);
    let ProviderError::UnsupportedParameter {
        connection,
        parameter,
        model,
    } = outcome.expect_err("a model without the marker denies")
    else {
        panic!("expected the typed closed-table denial");
    };
    assert_eq!(connection, VERCEL);
    assert_eq!(parameter, "model");
    assert_eq!(model, VERCEL_UNMARKED_MODEL);
    drop_blocking(provider);
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the marker read");
    assert_eq!(
        count_path(&requests, VERCEL_MESSAGES_PATH),
        0,
        "the closed-table denial sends no inference request"
    );
    assert_eq!(count_path(&requests, VERCEL_MODELS_PATH), 1);
}

/// An auto pin over the one gateway connection resolves its wire model from
/// the same marker listing the admission uses: one listing read and one
/// Messages request, never a second read.
#[tokio::test]
async fn vercel_ai_gateway_auto_pin_reads_one_listing_and_one_messages_request() {
    let server = MockServer::start().await;
    mount_keyed_models(&server, &[vercel_row(VERCEL_MODEL, &["tool-use"])]).await;
    mount_vercel_messages(&server, text_stream("auto outcome", 7, 2)).await;
    let config = Config::parse_validated(&vercel_auto_config(&server.uri())).expect("valid");
    let (broker, manifest) = prepared_with(
        vercel_provider(&config),
        &config,
        "/world/vercel",
        "goal: auto pin",
    );
    let (broker, outcome) = dispatch(broker, "/world/vercel", manifest);
    let reply = outcome.expect("the auto pin resolves the tagged model");
    assert_eq!(reply.text, "auto outcome");

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(
        count_path(&requests, VERCEL_MODELS_PATH),
        1,
        "the one listing read resolves and admits the auto pin"
    );
    assert_eq!(
        count_path(&requests, VERCEL_MESSAGES_PATH),
        1,
        "one physical send"
    );
    let post = requests
        .iter()
        .find(|request| request.url.path() == VERCEL_MESSAGES_PATH)
        .expect("the Messages request is recorded");
    assert_eq!(
        body_of(post)["model"],
        json!(VERCEL_MODEL),
        "the first tagged row is the wire model"
    );
    drop_blocking(broker);
}

#[tokio::test]
async fn vercel_ai_gateway_wrong_credential_profile_region_or_origin_denies_without_secrets() {
    // a configured region names no recorded contract — typed denial at build
    let region_config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.{VERCEL}]\nkind = \"api_key\"\nendpoint = \"https://ai-gateway.vercel.sh\"\nregion = \"eu\"\ncredential_ref = \"{VERCEL_CREDENTIAL_REF}\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"{VERCEL}\", model_id = \"{VERCEL_MODEL}\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the region config parses");
    let region = provider_result(
        region_config,
        VERCEL.to_string(),
        Arc::new(MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a configured region denies");
    assert!(matches!(
        &region,
        ProviderError::RegionMismatch { connection, region }
            if connection == VERCEL && region == "eu"
    ));

    // a profile-bound ref whose scope names another profile cannot bind
    let profile_config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.{VERCEL}]\nkind = \"api_key\"\nendpoint = \"https://ai-gateway.vercel.sh\"\ncredential_ref = \"{VERCEL_CREDENTIAL_REF}\"\nprofile = \"vercel-work\"\n\
         [profiles.vercel-work]\ncredential_ref = \"keyring:rivect-test/another-profile\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"{VERCEL}\", model_id = \"{VERCEL_MODEL}\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the profile config parses");
    let profile = provider_result(
        profile_config,
        VERCEL.to_string(),
        Arc::new(MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a divergent profile scope denies");
    assert!(matches!(
        &profile,
        ProviderError::CredentialProfileMismatch { connection, profile }
            if connection == VERCEL && profile == "vercel-work"
    ));

    // a non-loopback http origin and a userinfo-bearing origin both leave
    // the endpoint trust boundary; neither echoes its value
    for origin in [
        "http://gateway.example.com/v1",
        "https://key:fixture-origin-material@gateway.example.com",
    ] {
        let refused = Config::parse_validated(&vercel_config(origin))
            .expect_err("the origin is outside the trust boundary");
        assert!(matches!(&refused.issue, ConfigIssue::EndpointNotAllowed));
        assert!(
            !refused.to_string().contains("fixture-origin-material"),
            "the refusal never echoes the origin's userinfo: {refused}"
        );
    }

    // an empty bound scope denies at send without reaching the wire and
    // without leaking the neighbour's material
    let server = MockServer::start().await;
    mount_keyed_models(&server, &[vercel_row(VERCEL_MODEL, &["tool-use"])]).await;
    mount_vercel_messages(&server, text_stream("never reached", 1, 1)).await;
    let config = Config::parse_validated(&vercel_config(&server.uri())).expect("valid");
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(NEIGHBOR_REF, NEIGHBOR_SECRET)],
    ));
    let provider =
        provider_result(config.clone(), VERCEL.to_string(), store).expect("binding resolves");
    let (provider, denied) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/vercel"));
    let error = denied.expect_err("the empty scope denies");
    assert!(matches!(error, ProviderError::CredentialAbsent { .. }));
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(
            !rendered.contains(NEIGHBOR_SECRET) && !rendered.contains(SECRET),
            "diagnostics stay secret-free: {rendered}"
        );
    }
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("the mock recorded")
            .is_empty(),
        "the denial lands before the marker read and the wire"
    );
}

#[tokio::test]
async fn vercel_ai_gateway_rejects_partial_tool_block_and_unknown_terminal() {
    // partial tool JSON at the block stop is a typed violation
    let server = MockServer::start().await;
    mount_keyed_models(&server, &[vercel_row(VERCEL_MODEL, &["tool-use"])]).await;
    mount_vercel_messages(
        &server,
        format!(
            "{}{}{}{}{}{}",
            message_start(3),
            sse_block(
                "content_block_start",
                &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {}}}),
            ),
            sse_block(
                "content_block_delta",
                &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "{\"path\":"}}),
            ),
            sse_block(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 0}),
            ),
            sse_block(
                "message_delta",
                &json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 2}}),
            ),
            sse_block("message_stop", &json!({"type": "message_stop"})),
        ),
    )
    .await;
    let config = Config::parse_validated(&vercel_config(&server.uri())).expect("valid");
    let (provider, _store) = vercel_provider(&config);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/vercel"));
    assert!(
        matches!(outcome, Err(ProviderError::StreamViolation { .. })),
        "a partial tool block never becomes a reply: {outcome:?}"
    );
    drop_blocking(provider);

    // a terminal the dialect cannot classify is never success
    let server = MockServer::start().await;
    mount_keyed_models(&server, &[vercel_row(VERCEL_MODEL, &["tool-use"])]).await;
    mount_vercel_messages(
        &server,
        format!(
            "{}{}{}{}",
            message_start(3),
            sse_block(
                "content_block_start",
                &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            ),
            sse_block(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 0}),
            ),
            format!(
                "{}{}",
                sse_block(
                    "message_delta",
                    &json!({"type": "message_delta", "delta": {"stop_reason": "teleport"}, "usage": {"output_tokens": 1}}),
                ),
                sse_block("message_stop", &json!({"type": "message_stop"})),
            ),
        ),
    )
    .await;
    let config = Config::parse_validated(&vercel_config(&server.uri())).expect("valid");
    let (provider, _store) = vercel_provider(&config);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/vercel"));
    assert!(
        matches!(outcome, Err(ProviderError::UnknownTerminal { .. })),
        "an unknown stop reason is an unknown terminal: {outcome:?}"
    );
    drop_blocking(provider);
}

/// A pinned effort and an unconstructible tool name are local denials on
/// every assignment: both land before the marker listing is read, so the
/// peer sees no request at all and the typed `UnsupportedParameter` names
/// the parameter. An auto pin has no resolved model yet and admits under
/// its assignment spelling.
#[tokio::test]
async fn vercel_ai_gateway_rejects_incompatible_tools_or_reasoning() {
    // a pinned effort has no recorded Messages dial
    let server = MockServer::start().await;
    let config = Config::parse_validated(&vercel_config(&server.uri()).replace(
        "effort = { mode = \"auto\" }",
        "effort = { mode = \"fixed\", value = \"high\" }",
    ))
    .expect("valid");
    let (provider, _store) = vercel_provider(&config);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/vercel"));
    let ProviderError::UnsupportedParameter {
        connection,
        parameter,
        model,
    } = outcome.expect_err("a pinned effort denies")
    else {
        panic!("expected the typed unsupported parameter");
    };
    assert_eq!(connection, VERCEL);
    assert_eq!(parameter, "effort");
    assert_eq!(model, VERCEL_MODEL);
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the reasoning denial lands before the marker read and the wire"
    );

    // a tool name outside the Messages grammar has no constructible tool
    let server = MockServer::start().await;
    let config = Config::parse_validated(&vercel_config(&server.uri())).expect("valid");
    let (provider, _store) = vercel_provider(&config);
    let mut manifest = prepared_manifest_at(&config, "/world/vercel");
    manifest.tools = vec!["read file".to_string()];
    let (provider, outcome) = send_on_thread(provider, manifest);
    let ProviderError::UnsupportedParameter {
        parameter, model, ..
    } = outcome.expect_err("a tool name outside the grammar denies")
    else {
        panic!("expected the typed tool denial");
    };
    assert_eq!(parameter, "tools");
    assert_eq!(model, VERCEL_MODEL);
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the tool denial lands before the marker read and the wire"
    );

    // an auto pin has no resolved model yet: the pinned effort still
    // denies before the listing read, under the assignment spelling
    let server = MockServer::start().await;
    let config = Config::parse_validated(&vercel_auto_config(&server.uri()).replace(
        "effort = { mode = \"auto\" }",
        "effort = { mode = \"fixed\", value = \"high\" }",
    ))
    .expect("valid");
    let (provider, _store) = vercel_provider(&config);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/vercel"));
    let ProviderError::UnsupportedParameter {
        connection,
        parameter,
        model,
    } = outcome.expect_err("a pinned effort denies on an auto pin")
    else {
        panic!("expected the typed unsupported parameter");
    };
    assert_eq!(connection, VERCEL);
    assert_eq!(parameter, "effort");
    assert_eq!(model, "auto");
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the auto effort denial lands before the listing read"
    );

    // the same auto pin with an unconstructible tool name
    let server = MockServer::start().await;
    let config = Config::parse_validated(&vercel_auto_config(&server.uri())).expect("valid");
    let (provider, _store) = vercel_provider(&config);
    let mut manifest = prepared_manifest_at(&config, "/world/vercel");
    manifest.tools = vec!["read file".to_string()];
    let (provider, outcome) = send_on_thread(provider, manifest);
    let ProviderError::UnsupportedParameter {
        parameter, model, ..
    } = outcome.expect_err("a tool name outside the grammar denies on an auto pin")
    else {
        panic!("expected the typed tool denial");
    };
    assert_eq!(parameter, "tools");
    assert_eq!(model, "auto");
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the auto tool denial lands before the listing read"
    );
}

/// One scripted gateway peer: the marker listing answers the guard's GET,
/// then the Messages stream is written in tiny chunks so the cuts land
/// inside UTF-8, JSON, SSE lines and the tool block's arguments. The
/// counted POSTs prove one physical send.
fn fragmented_vercel_peer() -> (String, Arc<AtomicUsize>, std::thread::JoinHandle<()>) {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("the fixture peer binds a loopback port");
    let address = listener.local_addr().expect("the fixture address");
    let posts = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&posts);
    let body = format!(
        "{}{}{}{}{}{}{}{}{}",
        message_start(5),
        sse_block(
            "content_block_start",
            &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ),
        sse_block(
            "content_block_delta",
            &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "héllo ✓"}}),
        ),
        sse_block(
            "content_block_stop",
            &json!({"type": "content_block_stop", "index": 0}),
        ),
        sse_block(
            "content_block_start",
            &json!({"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {}}}),
        ),
        sse_block(
            "content_block_delta",
            &json!({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "{\"path\":\"/tmp/fixture\"}"}}),
        ),
        sse_block(
            "content_block_stop",
            &json!({"type": "content_block_stop", "index": 1}),
        ),
        sse_block(
            "message_delta",
            &json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 3}}),
        ),
        format!(
            "{}{}",
            sse_block(
                "message_delta",
                &json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 3}}),
            ),
            sse_block("message_stop", &json!({"type": "message_stop"})),
        ),
    );
    let handle = std::thread::spawn(move || {
        for request in 0..2 {
            let (mut stream, _) = listener.accept().expect("the fixture peer accepts");
            read_fixture_request(&mut stream);
            if request == 0 {
                let listing = serde_json::to_string(
                    &json!({"object": "list", "data": [vercel_row(VERCEL_MODEL, &["tool-use"])]}),
                )
                .expect("the fixture listing serializes");
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    listing.len()
                );
                stream.write_all(head.as_bytes()).expect("the fixture head");
                stream
                    .write_all(listing.as_bytes())
                    .expect("the fixture listing");
                continue;
            }
            count.fetch_add(1, Ordering::SeqCst);
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
        }
    });
    (format!("http://{address}/v1"), posts, handle)
}

/// Chunked delivery inside UTF-8, JSON, SSE and the tool block reassembles
/// to one outcome; the repeated usage report is charged once, and the
/// spent attempt never opens a second request.
#[tokio::test]
async fn vercel_ai_gateway_stream_fragmentation_and_repeated_usage_never_duplicates() {
    let (endpoint, posts, peer) = fragmented_vercel_peer();
    let config = Config::parse_validated(&vercel_config(&endpoint)).expect("valid");
    let (provider, _store) = vercel_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/vercel", "goal: fragmented")
        .expect("the gateway pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/vercel", manifest.clone());
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

    let replay_manifest = manifest.clone();
    let (broker, replay) = std::thread::spawn(move || {
        let mut broker = broker;
        let replay = broker.dispatch(
            &mut rivect::model::NullLedger,
            "/world/vercel",
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
    assert_eq!(posts.load(Ordering::SeqCst), 1, "one physical send");
}

/// An unknown remote outcome is never retried blindly: the peer's failure
/// status denies typed, nothing is accounted, and only one Messages
/// request runs.
#[tokio::test]
async fn vercel_ai_gateway_unknown_outcome_is_not_retried() {
    let server = MockServer::start().await;
    mount_keyed_models(&server, &[vercel_row(VERCEL_MODEL, &["tool-use"])]).await;
    Mock::given(method("POST"))
        .and(path(VERCEL_MESSAGES_PATH))
        .respond_with(ResponseTemplate::new(503).set_body_string("peer failure body"))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&vercel_config(&server.uri())).expect("valid");
    let (provider, _store) = vercel_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/vercel", "goal: unknown outcome")
        .expect("the gateway pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/vercel", manifest);
    let Err(ModelError::Provider(ProviderError::Transport { cause, .. })) = outcome else {
        panic!("the peer's status is the typed transport denial: {outcome:?}");
    };
    assert_eq!(cause.class(), TransportClass::HttpStatus { code: 503 });
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(
        count_path(&requests, VERCEL_MESSAGES_PATH),
        1,
        "an unknown outcome is never retried blindly"
    );
}

// ----- TP-PROVIDER-INSTALLED::vercel-ai-gateway -----------------------

/// TP-PROVIDER-INSTALLED::vercel-ai-gateway = NOT_RUN: the
/// installed-provider proof is a live-environment leg this offline slice
/// never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::vercel-ai-gateway = NOT_RUN"]
fn provider_installed_vercel_ai_gateway() {}

// ----- TP-PROVIDER-{CATALOG,AUTH,WIRE,RECOVERY}::gitlab-duo ----------

/// The literal routed id under proof.
const GITLAB: &str = "gitlab-duo";
/// The scoped credential ref the connection binds.
const GITLAB_CREDENTIAL_REF: &str = "keyring:rivect-test/gitlab-duo";
/// Fixture PAT/OAuth material, never a real credential.
const GITLAB_PAT: &str = "fixture-gitlab-pat-not-a-real-credential";
/// The exchange's short-lived token, distinct from the PAT.
const GITLAB_ACCESS_TOKEN: &str = "fixture-direct-access-token-not-real";
/// The Messages alias and its recorded `upstreamModelId`.
const GITLAB_MESSAGES_MODEL: &str = "duo-chat-opus-4-6";
const GITLAB_MESSAGES_UPSTREAM: &str = "claude-opus-4-6";
/// The Responses alias its route carries.
const GITLAB_RESPONSES_MODEL: &str = "duo-chat-gpt-5-codex";
/// The Chat Completions alias its route carries.
const GITLAB_COMPLETIONS_MODEL: &str = "duo-chat-gpt-5-2";
const GITLAB_COMPLETIONS_UPSTREAM: &str = "gpt-5.2-2025-12-11";
/// The exchange's recorded method/path/body.
const GITLAB_EXCHANGE_PATH: &str = "/api/v4/ai/third_party_agents/direct_access";
/// The fixed proxy paths the routed owner appends to its origin.
const GITLAB_MESSAGES_PROXY_PATH: &str = "/ai/v1/proxy/anthropic/v1/messages";
const GITLAB_RESPONSES_PROXY_PATH: &str = "/ai/v1/proxy/openai/v1/responses";
const GITLAB_CHAT_PROXY_PATH: &str = "/ai/v1/proxy/openai/v1/chat/completions";

fn gitlab_config(endpoint: &str, model: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.{GITLAB}]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{GITLAB_CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{GITLAB}\", model_id = \"{model}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn routed_with(
    config: &Config,
    store: Arc<MapStore>,
    deadline: Duration,
    origin: Option<String>,
) -> RoutedProvider {
    let config = config.clone();
    std::thread::spawn(move || {
        RoutedProvider::with_proxy_origin(&config, GITLAB, store, deadline, origin)
    })
    .join()
    .expect("the provider thread joins")
    .expect("the routed adapter builds")
}

fn gitlab_provider(config: &Config, origin: &str) -> (RoutedProvider, Arc<MapStore>) {
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(GITLAB_CREDENTIAL_REF, GITLAB_PAT)],
    ));
    let provider = routed_with(
        config,
        Arc::clone(&store),
        Duration::from_secs(10),
        Some(origin.to_string()),
    );
    (provider, store)
}

async fn mount_gitlab_exchange(server: &MockServer, body: Value) {
    Mock::given(method("POST"))
        .and(path(GITLAB_EXCHANGE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

async fn mount_gitlab_exchange_ok(server: &MockServer) {
    mount_gitlab_exchange(
        server,
        json!({
            "token": GITLAB_ACCESS_TOKEN,
            "headers": {"x-gitlab-token": "fixture-gitlab-forwarded"},
        }),
    )
    .await;
}

async fn mount_proxy(server: &MockServer, proxy_path: &str, body: String) {
    Mock::given(method("POST"))
        .and(path(proxy_path))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(server)
        .await;
}

fn sse_data(chunk: &Value) -> String {
    format!("data: {chunk}\n\n")
}

fn cc_completed_stream(text: &str, usage: Value) -> String {
    let mut body = sse_data(&json!({
        "id": "c1",
        "object": "chat.completion.chunk",
        "choices": [{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": null}],
    }));
    body.push_str(&sse_data(&json!({
        "id": "c1",
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
    })));
    body.push_str(&sse_data(
        &json!({"id": "c1", "choices": [], "usage": usage}),
    ));
    body.push_str("data: [DONE]\n\n");
    body
}

fn responses_stream(text: &str, usage: Value) -> String {
    support::responses_completed_stream(text, Vec::new(), Some(usage))
}

#[tokio::test]
async fn gitlab_duo_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_gitlab_exchange_ok(&server).await;
    mount_proxy(
        &server,
        GITLAB_MESSAGES_PROXY_PATH,
        text_stream("gitlab outcome", 9, 4),
    )
    .await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_MESSAGES_MODEL))
        .expect("valid");
    let (broker, manifest) = prepared_with(
        gitlab_provider(&config, &server.uri()),
        &config,
        "/world/gitlab",
        "goal: prove the gitlab wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/gitlab", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "gitlab outcome");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 9,
            completion_tokens: 4,
            total_tokens: 13,
        }
    );

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 2, "one exchange and one proxy request");
    assert_eq!(requests[0].url.path(), GITLAB_EXCHANGE_PATH);
    assert_eq!(requests[1].url.path(), GITLAB_MESSAGES_PROXY_PATH);
    let body = body_of(&requests[1]);
    assert_eq!(body["model"], json!(GITLAB_MESSAGES_UPSTREAM));
    assert_eq!(
        header(&requests[1], "anthropic-version"),
        Some("2023-06-01")
    );
    assert_eq!(header(&requests[1], "x-api-key"), None);

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, GITLAB);
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 9,
            completion_tokens: 4,
            total_tokens: 13,
        }
    );
    drop_blocking(broker);
}

#[tokio::test]
async fn gitlab_duo_exchanges_direct_access_before_the_proxy_leg() {
    let server = MockServer::start().await;
    mount_gitlab_exchange_ok(&server).await;
    mount_proxy(
        &server,
        GITLAB_MESSAGES_PROXY_PATH,
        text_stream("ordered", 1, 1),
    )
    .await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_MESSAGES_MODEL))
        .expect("valid");
    let (provider, _store) = gitlab_provider(&config, &server.uri());
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/gitlab"));
    outcome.expect("the exchange and proxy both answer");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests
            .iter()
            .map(|request| request.url.path())
            .collect::<Vec<_>>(),
        [GITLAB_EXCHANGE_PATH, GITLAB_MESSAGES_PROXY_PATH],
        "the exchange is the first leg"
    );
    let exchange = body_of(&requests[0]);
    assert_eq!(
        exchange,
        json!({"feature_flags": {"DuoAgentPlatformNext": true}})
    );
    let pat_bearer = format!("Bearer {GITLAB_PAT}");
    assert_eq!(
        header(&requests[0], "authorization"),
        Some(pat_bearer.as_str())
    );
}

#[tokio::test]
async fn gitlab_duo_requires_token_and_headers_and_forwards_only_x_gitlab_headers() {
    // A returned authorization/host header never overrides the proxy's own.
    let server = MockServer::start().await;
    mount_gitlab_exchange(
        &server,
        json!({
            "token": GITLAB_ACCESS_TOKEN,
            "headers": {
                "x-gitlab-token": "fixture-forwarded-value",
                "authorization": "Bearer attacker",
                "host": "attacker.example",
                "x-other": "never-forwarded",
            },
        }),
    )
    .await;
    mount_proxy(
        &server,
        GITLAB_MESSAGES_PROXY_PATH,
        text_stream("forwarded", 1, 1),
    )
    .await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_MESSAGES_MODEL))
        .expect("valid");
    let (provider, _store) = gitlab_provider(&config, &server.uri());
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/gitlab"));
    outcome.expect("the proxy leg answers");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    let proxy = &requests[1];
    assert_eq!(
        header(proxy, "x-gitlab-token"),
        Some("fixture-forwarded-value")
    );
    let token_bearer = format!("Bearer {GITLAB_ACCESS_TOKEN}");
    assert_eq!(
        header(proxy, "authorization"),
        Some(token_bearer.as_str()),
        "a returned authorization header never overrides the proxy bearer"
    );
    assert_ne!(header(proxy, "host"), Some("attacker.example"));
    assert_eq!(header(proxy, "x-other"), None);

    // Both required exchange members are mandatory, and a stated member
    // outside its recorded shape is the same typed denial.
    for body in [
        json!({"headers": {}}),
        json!({"token": GITLAB_ACCESS_TOKEN}),
        json!({"token": "", "headers": {}}),
        json!({"token": GITLAB_ACCESS_TOKEN, "headers": "not-an-object"}),
    ] {
        let server = MockServer::start().await;
        mount_gitlab_exchange(&server, body).await;
        mount_proxy(
            &server,
            GITLAB_MESSAGES_PROXY_PATH,
            text_stream("never reached", 1, 1),
        )
        .await;
        let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_MESSAGES_MODEL))
            .expect("valid");
        let (provider, _store) = gitlab_provider(&config, &server.uri());
        let (provider, outcome) =
            send_on_thread(provider, prepared_manifest_at(&config, "/world/gitlab"));
        assert!(
            matches!(outcome, Err(ProviderError::StreamViolation { .. })),
            "an incomplete exchange envelope denies: {outcome:?}"
        );
        drop_blocking(provider);
        assert_eq!(
            server.received_requests().await.expect("recorded").len(),
            1,
            "an incomplete exchange never opens the proxy leg"
        );
    }
}

#[tokio::test]
async fn gitlab_duo_forwards_x_gitlab_headers_and_bearer_on_every_proxy_path() {
    let token_bearer = format!("Bearer {GITLAB_ACCESS_TOKEN}");
    for (model, proxy_path, stream) in [
        (
            GITLAB_MESSAGES_MODEL,
            GITLAB_MESSAGES_PROXY_PATH,
            text_stream("messages leg", 1, 1),
        ),
        (
            GITLAB_RESPONSES_MODEL,
            GITLAB_RESPONSES_PROXY_PATH,
            responses_stream(
                "responses leg",
                json!({"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}),
            ),
        ),
        (
            GITLAB_COMPLETIONS_MODEL,
            GITLAB_CHAT_PROXY_PATH,
            cc_completed_stream(
                "cc leg",
                json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}),
            ),
        ),
    ] {
        let server = MockServer::start().await;
        mount_gitlab_exchange(
            &server,
            json!({
                "token": GITLAB_ACCESS_TOKEN,
                "headers": {
                    "x-gitlab-token": "fixture-forwarded-value",
                    "authorization": "Bearer attacker",
                    "x-other": "never-forwarded",
                },
            }),
        )
        .await;
        mount_proxy(&server, proxy_path, stream).await;
        let config = Config::parse_validated(&gitlab_config(&server.uri(), model)).expect("valid");
        let (provider, _store) = gitlab_provider(&config, &server.uri());
        let (provider, outcome) =
            send_on_thread(provider, prepared_manifest_at(&config, "/world/gitlab"));
        outcome.expect("the proxy leg answers");
        drop_blocking(provider);

        let requests = server.received_requests().await.expect("recorded");
        assert_eq!(requests.len(), 2, "{model}: one exchange and one proxy leg");
        let proxy = &requests[1];
        assert_eq!(proxy.url.path(), proxy_path, "{model}");
        assert_eq!(
            header(proxy, "x-gitlab-token"),
            Some("fixture-forwarded-value"),
            "{model}: the recorded forwarded header rides"
        );
        assert_eq!(
            header(proxy, "authorization"),
            Some(token_bearer.as_str()),
            "{model}: the exchanged token is the proxy bearer"
        );
        assert_eq!(header(proxy, "x-other"), None, "{model}");
    }
}

#[tokio::test]
async fn gitlab_duo_proxy_bearer_is_the_short_lived_token_not_the_pat() {
    let server = MockServer::start().await;
    mount_gitlab_exchange_ok(&server).await;
    mount_proxy(
        &server,
        GITLAB_MESSAGES_PROXY_PATH,
        text_stream("distinct", 1, 1),
    )
    .await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_MESSAGES_MODEL))
        .expect("valid");
    let (provider, _store) = gitlab_provider(&config, &server.uri());
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/gitlab"));
    outcome.expect("the proxy leg answers");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    let pat_bearer = format!("Bearer {GITLAB_PAT}");
    let token_bearer = format!("Bearer {GITLAB_ACCESS_TOKEN}");
    assert_eq!(
        header(&requests[0], "authorization"),
        Some(pat_bearer.as_str())
    );
    assert_eq!(
        header(&requests[1], "authorization"),
        Some(token_bearer.as_str())
    );
    assert_ne!(
        header(&requests[1], "authorization"),
        Some(pat_bearer.as_str()),
        "the PAT never reaches the proxy leg"
    );
}

#[tokio::test]
async fn gitlab_duo_exchange_failure_denies_without_a_proxy_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(GITLAB_EXCHANGE_PATH))
        .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
        .mount(&server)
        .await;
    mount_proxy(
        &server,
        GITLAB_MESSAGES_PROXY_PATH,
        text_stream("never reached", 1, 1),
    )
    .await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_MESSAGES_MODEL))
        .expect("valid");
    let (broker, manifest) = prepared_with(
        gitlab_provider(&config, &server.uri()),
        &config,
        "/world/gitlab",
        "goal: exchange failure",
    );
    let (broker, outcome) = dispatch(broker, "/world/gitlab", manifest);
    let Err(ModelError::Provider(ProviderError::Transport { cause, .. })) = outcome else {
        panic!("the exchange failure is a typed transport denial: {outcome:?}");
    };
    assert_eq!(
        cause.class(),
        TransportClass::HttpStatus { code: 403 },
        "the status code alone is the diagnostic"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "only the exchange was attempted");
    assert_eq!(requests[0].url.path(), GITLAB_EXCHANGE_PATH);
}

#[tokio::test]
async fn gitlab_duo_alias_outside_the_recorded_table_denies() {
    let server = MockServer::start().await;
    mount_gitlab_exchange_ok(&server).await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), "duo-chat-unknown-9"))
        .expect("valid");
    let (provider, _store) = gitlab_provider(&config, &server.uri());
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/gitlab"));
    let ProviderError::UnsupportedParameter {
        connection,
        parameter,
        model,
    } = outcome.expect_err("an alias outside the table denies")
    else {
        panic!("expected the typed model denial");
    };
    assert_eq!(connection, GITLAB);
    assert_eq!(parameter, "model");
    assert_eq!(model, "duo-chat-unknown-9");
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the closed-set denial lands before any wire leg"
    );
}

#[tokio::test]
async fn gitlab_duo_routes_each_alias_to_its_recorded_dialect() {
    for (alias, dialect) in [
        ("duo-chat-opus-4-6", Dialect::Messages),
        ("duo-chat-sonnet-4-6", Dialect::Messages),
        ("duo-chat-opus-4-5", Dialect::Messages),
        ("duo-chat-sonnet-4-5", Dialect::Messages),
        ("duo-chat-haiku-4-5", Dialect::Messages),
        ("duo-chat-gpt-5-1", Dialect::ChatCompletions),
        ("duo-chat-gpt-5-2", Dialect::ChatCompletions),
        ("duo-chat-gpt-5-mini", Dialect::ChatCompletions),
        ("duo-chat-gpt-5-codex", Dialect::Responses),
        ("duo-chat-gpt-5-2-codex", Dialect::Responses),
    ] {
        assert_eq!(route_for(GITLAB, alias), Some(dialect), "{alias}");
    }
    assert_eq!(route_for(GITLAB, "duo-chat-unknown-9"), None);
    assert_eq!(
        routes_for(GITLAB),
        [
            Dialect::Messages,
            Dialect::Responses,
            Dialect::ChatCompletions
        ]
    );

    // Responses route
    let server = MockServer::start().await;
    mount_gitlab_exchange_ok(&server).await;
    mount_proxy(
        &server,
        GITLAB_RESPONSES_PROXY_PATH,
        responses_stream(
            "gitlab responses",
            json!({"input_tokens": 2, "output_tokens": 3, "total_tokens": 5}),
        ),
    )
    .await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_RESPONSES_MODEL))
        .expect("valid");
    let (provider, _store) = gitlab_provider(&config, &server.uri());
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/gitlab"));
    let reply = outcome.expect("the Responses route answers");
    assert_eq!(reply.text, "gitlab responses");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests[1].url.path(), GITLAB_RESPONSES_PROXY_PATH);
    assert_eq!(body_of(&requests[1])["model"], json!("gpt-5-codex"));

    // Chat Completions route
    let server = MockServer::start().await;
    mount_gitlab_exchange_ok(&server).await;
    mount_proxy(
        &server,
        GITLAB_CHAT_PROXY_PATH,
        cc_completed_stream(
            "gitlab cc",
            json!({"prompt_tokens": 4, "completion_tokens": 5, "total_tokens": 9}),
        ),
    )
    .await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_COMPLETIONS_MODEL))
        .expect("valid");
    let (provider, _store) = gitlab_provider(&config, &server.uri());
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/gitlab"));
    let reply = outcome.expect("the CC route answers");
    assert_eq!(reply.text, "gitlab cc");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 4,
            completion_tokens: 5,
            total_tokens: 9,
        }
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests[1].url.path(), GITLAB_CHAT_PROXY_PATH);
    assert_eq!(
        body_of(&requests[1])["model"],
        json!(GITLAB_COMPLETIONS_UPSTREAM)
    );
}

#[tokio::test]
async fn gitlab_duo_translates_every_alias_to_its_upstream_on_the_wire() {
    for (alias, upstream, proxy_path, stream) in [
        (
            "duo-chat-opus-4-6",
            "claude-opus-4-6",
            GITLAB_MESSAGES_PROXY_PATH,
            text_stream("alias messages", 1, 1),
        ),
        (
            "duo-chat-sonnet-4-6",
            "claude-sonnet-4-6",
            GITLAB_MESSAGES_PROXY_PATH,
            text_stream("alias messages", 1, 1),
        ),
        (
            "duo-chat-opus-4-5",
            "claude-opus-4-5-20251101",
            GITLAB_MESSAGES_PROXY_PATH,
            text_stream("alias messages", 1, 1),
        ),
        (
            "duo-chat-sonnet-4-5",
            "claude-sonnet-4-5-20250929",
            GITLAB_MESSAGES_PROXY_PATH,
            text_stream("alias messages", 1, 1),
        ),
        (
            "duo-chat-haiku-4-5",
            "claude-haiku-4-5-20251001",
            GITLAB_MESSAGES_PROXY_PATH,
            text_stream("alias messages", 1, 1),
        ),
        (
            "duo-chat-gpt-5-1",
            "gpt-5.1-2025-11-13",
            GITLAB_CHAT_PROXY_PATH,
            cc_completed_stream(
                "alias cc",
                json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}),
            ),
        ),
        (
            "duo-chat-gpt-5-2",
            GITLAB_COMPLETIONS_UPSTREAM,
            GITLAB_CHAT_PROXY_PATH,
            cc_completed_stream(
                "alias cc",
                json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}),
            ),
        ),
        (
            "duo-chat-gpt-5-mini",
            "gpt-5-mini-2025-08-07",
            GITLAB_CHAT_PROXY_PATH,
            cc_completed_stream(
                "alias cc",
                json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}),
            ),
        ),
        (
            "duo-chat-gpt-5-codex",
            "gpt-5-codex",
            GITLAB_RESPONSES_PROXY_PATH,
            responses_stream(
                "alias responses",
                json!({"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}),
            ),
        ),
        (
            "duo-chat-gpt-5-2-codex",
            "gpt-5.2-codex",
            GITLAB_RESPONSES_PROXY_PATH,
            responses_stream(
                "alias responses",
                json!({"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}),
            ),
        ),
    ] {
        let server = MockServer::start().await;
        mount_gitlab_exchange_ok(&server).await;
        mount_proxy(&server, proxy_path, stream).await;
        let config = Config::parse_validated(&gitlab_config(&server.uri(), alias)).expect("valid");
        let (provider, _store) = gitlab_provider(&config, &server.uri());
        let (provider, outcome) =
            send_on_thread(provider, prepared_manifest_at(&config, "/world/gitlab"));
        outcome.expect("the alias route answers");
        drop_blocking(provider);

        let requests = server.received_requests().await.expect("recorded");
        assert_eq!(requests.len(), 2, "{alias}");
        assert_eq!(requests[1].url.path(), proxy_path, "{alias}");
        assert_eq!(
            body_of(&requests[1])["model"],
            json!(upstream),
            "{alias} is translated to its recorded upstreamModelId"
        );
    }
}

#[tokio::test]
async fn gitlab_duo_catalogue_is_the_alias_table_without_a_wire_request() {
    let server = MockServer::start().await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_MESSAGES_MODEL))
        .expect("valid");
    let (provider, _store) = gitlab_provider(&config, &server.uri());
    let (provider, catalog) = std::thread::spawn(move || {
        let outcome = provider.catalog();
        (provider, outcome)
    })
    .join()
    .expect("the catalogue thread joins");
    assert_eq!(
        catalog.expect("the alias table is the catalogue"),
        [
            "duo-chat-gpt-5-1",
            "duo-chat-gpt-5-2",
            "duo-chat-gpt-5-2-codex",
            "duo-chat-gpt-5-codex",
            "duo-chat-gpt-5-mini",
            "duo-chat-haiku-4-5",
            "duo-chat-opus-4-5",
            "duo-chat-opus-4-6",
            "duo-chat-sonnet-4-5",
            "duo-chat-sonnet-4-6",
        ]
        .map(String::from)
    );
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the static alias table opens no wire leg"
    );
}

#[test]
fn routed_route_constructor_rejects_a_dialect_outside_routes_for() {
    let config = Config::parse_validated(&minimax_config("https://api.minimax.io/anthropic"))
        .expect("valid");
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(MINIMAX_CREDENTIAL_REF, SECRET)],
    ));
    let denied = std::thread::spawn(move || {
        MessagesProvider::with_route(
            &config,
            MINIMAX,
            store,
            Duration::from_secs(1),
            WireAuth::Store(None),
        )
    })
    .join()
    .expect("the provider thread joins")
    .expect_err("a single-dialect id has no Messages route");
    assert!(
        matches!(denied, ProviderError::DialectMismatch { .. }),
        "the route gate denies a dialect outside routes_for: {denied:?}"
    );
    assert!(routes_for("anthropic").is_empty());
}

/// A routed id declared `local` applies the sibling adapters' gates: a
/// profile binding is the contradictory half, and a credential binding
/// the routed id cannot serve is the unresolved denial — both before the
/// credential seam or any wire leg.
#[test]
fn routed_constructor_applies_the_local_declaration_gates() {
    use rivect::config::ConnKind;

    let profiled = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.{GITLAB}]\nkind = \"local\"\nendpoint = \"https://gitlab.com\"\nprofile = \"pinned\"\n\
         [profiles.pinned]\ncredential_ref = \"keyring:rivect-test/gitlab-duo/pinned\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{GITLAB}\", model_id = \"{GITLAB_MESSAGES_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let store = Arc::new(MapStore::new(STORE_KIND));
    let denied = std::thread::spawn(move || {
        RoutedProvider::with_deadline(&profiled, GITLAB, store, Duration::from_secs(1))
    })
    .join()
    .expect("the provider thread joins")
    .expect_err("a local declaration with a profile denies");
    assert!(
        matches!(denied, ProviderError::LocalProfileDeclared { .. }),
        "the local/profile contradiction is typed: {denied:?}"
    );

    let mut bound =
        Config::parse_validated(&gitlab_config("https://gitlab.com", GITLAB_MESSAGES_MODEL))
            .expect("valid");
    bound
        .connections
        .get_mut(GITLAB)
        .expect("the declaration")
        .kind = ConnKind::Local;
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(GITLAB_CREDENTIAL_REF, GITLAB_PAT)],
    ));
    let denied = std::thread::spawn(move || {
        RoutedProvider::with_deadline(&bound, GITLAB, store, Duration::from_secs(1))
    })
    .join()
    .expect("the provider thread joins")
    .expect_err("a local declaration outside the absent-binding classes denies");
    assert!(
        matches!(denied, ProviderError::CredentialUnresolved { .. }),
        "a local routed declaration never resolves a credential: {denied:?}"
    );
}

#[tokio::test]
async fn gitlab_duo_wrong_credential_profile_or_region_denies_without_secrets() {
    // A configured region has no recorded GitLab contract.
    let config = Config::parse_validated(
        &gitlab_config("https://gitlab.com", GITLAB_MESSAGES_MODEL)
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(GITLAB_CREDENTIAL_REF, GITLAB_PAT)],
    ));
    let denied = std::thread::spawn(move || {
        RoutedProvider::with_proxy_origin(
            &config,
            GITLAB,
            store,
            Duration::from_secs(1),
            Some("http://127.0.0.1:9".to_string()),
        )
    })
    .join()
    .expect("the provider thread joins")
    .expect_err("a configured region denies");
    let ProviderError::RegionMismatch { connection, .. } = denied else {
        panic!("expected the typed region denial: {denied:?}");
    };
    assert_eq!(connection, GITLAB);

    // An absent scoped credential denies before the exchange.
    let server = MockServer::start().await;
    mount_gitlab_exchange_ok(&server).await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_MESSAGES_MODEL))
        .expect("valid");
    let store = Arc::new(MapStore::seeded(STORE_KIND, &[]));
    let provider = routed_with(&config, store, Duration::from_secs(2), Some(server.uri()));
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/gitlab"));
    assert!(
        matches!(outcome, Err(ProviderError::CredentialAbsent { .. })),
        "absent material denies at the scoped seam: {outcome:?}"
    );
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "no wire leg opens without material"
    );
}

#[tokio::test]
async fn gitlab_duo_rejects_partial_tool_block_and_unknown_terminal() {
    let exchange_server = MockServer::start().await;
    mount_gitlab_exchange_ok(&exchange_server).await;

    // partial tool JSON at the block stop is a typed violation
    let partial = format!(
        "{}{}{}{}{}{}",
        message_start(3),
        sse_block(
            "content_block_start",
            &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {}}}),
        ),
        sse_block(
            "content_block_delta",
            &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "{\"path\":"}}),
        ),
        sse_block(
            "content_block_stop",
            &json!({"type": "content_block_stop", "index": 0}),
        ),
        sse_block(
            "message_delta",
            &json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 2}}),
        ),
        sse_block("message_stop", &json!({"type": "message_stop"})),
    );
    let server = MockServer::start().await;
    mount_gitlab_exchange_ok(&server).await;
    mount_proxy(&server, GITLAB_MESSAGES_PROXY_PATH, partial).await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_MESSAGES_MODEL))
        .expect("valid");
    let (provider, _store) = gitlab_provider(&config, &server.uri());
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/gitlab"));
    assert!(
        matches!(outcome, Err(ProviderError::StreamViolation { .. })),
        "a partial tool block never becomes a reply: {outcome:?}"
    );
    drop_blocking(provider);

    // an unknown terminal is never success
    let server = MockServer::start().await;
    mount_gitlab_exchange_ok(&server).await;
    mount_proxy(
        &server,
        GITLAB_MESSAGES_PROXY_PATH,
        format!(
            "{}{}{}{}",
            message_start(3),
            sse_block(
                "content_block_start",
                &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            ),
            sse_block(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 0}),
            ),
            format!(
                "{}{}",
                sse_block(
                    "message_delta",
                    &json!({"type": "message_delta", "delta": {"stop_reason": "teleport"}, "usage": {"output_tokens": 1}}),
                ),
                sse_block("message_stop", &json!({"type": "message_stop"})),
            ),
        ),
    )
    .await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_MESSAGES_MODEL))
        .expect("valid");
    let (provider, _store) = gitlab_provider(&config, &server.uri());
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/gitlab"));
    assert!(
        matches!(outcome, Err(ProviderError::UnknownTerminal { .. })),
        "an unknown stop reason is an unknown terminal: {outcome:?}"
    );
    drop_blocking(provider);
}

#[tokio::test]
async fn gitlab_duo_rejects_incompatible_tools_or_reasoning() {
    // a pinned effort has no recorded Messages dial
    let server = MockServer::start().await;
    mount_gitlab_exchange_ok(&server).await;
    mount_proxy(
        &server,
        GITLAB_MESSAGES_PROXY_PATH,
        text_stream("never reached", 1, 1),
    )
    .await;
    let config = Config::parse_validated(
        &gitlab_config(&server.uri(), GITLAB_MESSAGES_MODEL).replace(
            "effort = { mode = \"auto\" }",
            "effort = { mode = \"fixed\", value = \"high\" }",
        ),
    )
    .expect("valid");
    let (provider, _store) = gitlab_provider(&config, &server.uri());
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/gitlab"));
    let ProviderError::UnsupportedParameter {
        connection,
        parameter,
        model,
    } = outcome.expect_err("a pinned effort denies")
    else {
        panic!("expected the typed effort denial");
    };
    assert_eq!(connection, GITLAB);
    assert_eq!(parameter, "effort");
    assert_eq!(model, GITLAB_MESSAGES_UPSTREAM);
    drop_blocking(provider);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        1,
        "the effort denial lands before the proxy leg"
    );

    // a tool name outside the Messages grammar has no constructible tool
    let server = MockServer::start().await;
    mount_gitlab_exchange_ok(&server).await;
    mount_proxy(
        &server,
        GITLAB_MESSAGES_PROXY_PATH,
        text_stream("never reached", 1, 1),
    )
    .await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_MESSAGES_MODEL))
        .expect("valid");
    let (provider, _store) = gitlab_provider(&config, &server.uri());
    let mut manifest = prepared_manifest_at(&config, "/world/gitlab");
    manifest.tools = vec!["read file".to_string()];
    let (provider, outcome) = send_on_thread(provider, manifest);
    let ProviderError::UnsupportedParameter {
        parameter, model, ..
    } = outcome.expect_err("a tool name outside the grammar denies")
    else {
        panic!("expected the typed tool denial");
    };
    assert_eq!(parameter, "tools");
    assert_eq!(model, GITLAB_MESSAGES_UPSTREAM);
    drop_blocking(provider);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        1,
        "the tool denial lands before the proxy leg"
    );
}

#[tokio::test]
async fn gitlab_duo_non_success_status_denies() {
    let server = MockServer::start().await;
    mount_gitlab_exchange_ok(&server).await;
    Mock::given(method("POST"))
        .and(path(GITLAB_MESSAGES_PROXY_PATH))
        .respond_with(ResponseTemplate::new(500).set_body_string("peer failure body"))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_MESSAGES_MODEL))
        .expect("valid");
    let (broker, manifest) = prepared_with(
        gitlab_provider(&config, &server.uri()),
        &config,
        "/world/gitlab",
        "goal: non-success",
    );
    let (broker, outcome) = dispatch(broker, "/world/gitlab", manifest);
    let Err(ModelError::Provider(ProviderError::Transport { cause, .. })) = outcome else {
        panic!("a non-success proxy status is a typed denial: {outcome:?}");
    };
    assert_eq!(
        cause.class(),
        TransportClass::HttpStatus { code: 500 },
        "the status code alone is the diagnostic"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        2,
        "the exchange and the refused proxy leg"
    );
}

#[tokio::test]
async fn gitlab_duo_short_deadline_denies_without_a_proxy_leg() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(GITLAB_EXCHANGE_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"token": GITLAB_ACCESS_TOKEN, "headers": {}}))
                .set_delay(Duration::from_millis(600)),
        )
        .mount(&server)
        .await;
    mount_proxy(
        &server,
        GITLAB_MESSAGES_PROXY_PATH,
        text_stream("never reached", 1, 1),
    )
    .await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_MESSAGES_MODEL))
        .expect("valid");
    let deadline = Duration::from_millis(400);
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(GITLAB_CREDENTIAL_REF, GITLAB_PAT)],
    ));
    let provider = routed_with(&config, store, deadline, Some(server.uri()));
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/gitlab"));
    let error = outcome.expect_err("the expired budget denies");
    assert!(
        matches!(
            error,
            ProviderError::Transport {
                cause: TransportCause::Deadline { budget },
                ..
            } if budget == deadline
        ),
        "the shared deadline is the denial: {error:?}"
    );
    drop_blocking(provider);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        1,
        "the expired exchange budget never opens the proxy leg"
    );
}

#[test]
fn routed_proxy_origin_rejects_a_non_loopback_host() {
    let config =
        Config::parse_validated(&gitlab_config("https://gitlab.com", GITLAB_MESSAGES_MODEL))
            .expect("valid");
    for origin in [
        "https://cloud.gitlab.com",
        "https://gitlab.com",
        "http://example.com",
        // Userinfo never impersonates the host it precedes.
        "http://127.0.0.1:9@evil.example",
        // A proxy origin carries no path, query or fragment.
        "http://127.0.0.1:9/prefix",
        "http://127.0.0.1:9?query=1",
        "http://127.0.0.1:9#fragment",
    ] {
        let store = Arc::new(MapStore::seeded(
            STORE_KIND,
            &[(GITLAB_CREDENTIAL_REF, GITLAB_PAT)],
        ));
        let config = config.clone();
        let origin = origin.to_string();
        let denied = std::thread::spawn(move || {
            RoutedProvider::with_proxy_origin(
                &config,
                GITLAB,
                store,
                Duration::from_secs(1),
                Some(origin),
            )
        })
        .join()
        .expect("the provider thread joins")
        .expect_err("a non-loopback override denies");
        assert!(
            matches!(denied, ProviderError::EndpointRequired { .. }),
            "the override never falls back silently: {denied:?}"
        );
    }
    // The loopback origin itself is admitted and canonicalized.
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(GITLAB_CREDENTIAL_REF, GITLAB_PAT)],
    ));
    RoutedProvider::with_proxy_origin(
        &config,
        GITLAB,
        store,
        Duration::from_secs(1),
        Some("http://127.0.0.1:9/".to_string()),
    )
    .expect("the loopback origin is admitted");
}

#[tokio::test]
async fn gitlab_duo_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    // CATALOG: the fixed alias table, no wire leg.
    let server = MockServer::start().await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_MESSAGES_MODEL))
        .expect("valid");
    let (provider, _store) = gitlab_provider(&config, &server.uri());
    let (provider, catalog) = std::thread::spawn(move || {
        let outcome = provider.catalog();
        (provider, outcome)
    })
    .join()
    .expect("the catalog thread joins");
    let expected = [
        "duo-chat-gpt-5-1",
        "duo-chat-gpt-5-2",
        "duo-chat-gpt-5-2-codex",
        "duo-chat-gpt-5-codex",
        "duo-chat-gpt-5-mini",
        "duo-chat-haiku-4-5",
        "duo-chat-opus-4-5",
        "duo-chat-opus-4-6",
        "duo-chat-sonnet-4-5",
        "duo-chat-sonnet-4-6",
    ];
    reported.insert(
        "CATALOG",
        if matches!(&catalog, Ok(ids) if ids == &expected.map(String::from)) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: absent material denies at the scoped seam.
    let server = MockServer::start().await;
    mount_gitlab_exchange_ok(&server).await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_MESSAGES_MODEL))
        .expect("valid");
    let provider = routed_with(
        &config,
        Arc::new(MapStore::seeded(STORE_KIND, &[])),
        Duration::from_secs(2),
        Some(server.uri()),
    );
    let (provider, denied) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/gitlab"));
    reported.insert(
        "AUTH",
        if matches!(denied, Err(ProviderError::CredentialAbsent { .. })) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // WIRE
    let server = MockServer::start().await;
    mount_gitlab_exchange_ok(&server).await;
    mount_proxy(
        &server,
        GITLAB_MESSAGES_PROXY_PATH,
        text_stream("matrix", 1, 1),
    )
    .await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_MESSAGES_MODEL))
        .expect("valid");
    let (broker, manifest) = prepared_with(
        gitlab_provider(&config, &server.uri()),
        &config,
        "/world/gitlab",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/gitlab", manifest);
    reported.insert(
        "WIRE",
        if matches!(&outcome, Ok(reply) if reply.text == "matrix") {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

    // RECOVERY
    let server = MockServer::start().await;
    mount_gitlab_exchange_ok(&server).await;
    let mut truncated = text_stream("looks complete", 1, 1);
    truncated.truncate(
        truncated
            .rfind("event: message_stop")
            .expect("the terminal exists"),
    );
    mount_proxy(&server, GITLAB_MESSAGES_PROXY_PATH, truncated).await;
    let config = Config::parse_validated(&gitlab_config(&server.uri(), GITLAB_MESSAGES_MODEL))
        .expect("valid");
    let (provider, _store) = gitlab_provider(&config, &server.uri());
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/gitlab"));
    reported.insert(
        "RECOVERY",
        if matches!(outcome, Err(ProviderError::UnknownTerminal { .. })) {
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

// ----- TP-PROVIDER-INSTALLED::gitlab-duo -----------------------------

/// TP-PROVIDER-INSTALLED::gitlab-duo = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::gitlab-duo = NOT_RUN"]
fn provider_installed_gitlab_duo() {}

// ----- TP-PROVIDER-{CATALOG,AUTH,WIRE,RECOVERY}::opencode-zen --------

/// The literal routed id under proof.
const ZEN: &str = "opencode-zen";
/// The scoped credential ref the connection binds.
const ZEN_CREDENTIAL_REF: &str = "keyring:rivect-test/opencode-zen";
/// The Messages-family model.
const ZEN_MESSAGES_MODEL: &str = "claude-sonnet-4-5";
/// The Responses-family model.
const ZEN_RESPONSES_MODEL: &str = "muse-spark-1.3-contributor-free";
/// The recorded Chat Completions exact.
const ZEN_CC_MODEL: &str = "minimax-m3-free";
/// The Gemini-family model.
const ZEN_GEMINI_MODEL: &str = "gemini-3.1-pro";
/// An id matching no recorded override — it rides the CC default.
const ZEN_UNKNOWN_MODEL: &str = "deepseek-v4-flash";
const ZEN_MESSAGES_PATH: &str = "/v1/messages";
const ZEN_RESPONSES_PATH: &str = "/v1/responses";
const ZEN_CC_PATH: &str = "/v1/chat/completions";

fn zen_config(endpoint: &str, model: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.{ZEN}]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{ZEN_CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{ZEN}\", model_id = \"{model}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn zen_with(config: &Config, store: Arc<MapStore>, deadline: Duration) -> RoutedProvider {
    let config = config.clone();
    std::thread::spawn(move || RoutedProvider::with_deadline(&config, ZEN, store, deadline))
        .join()
        .expect("the provider thread joins")
        .expect("the routed adapter builds")
}

fn zen_provider(config: &Config, deadline: Duration) -> (RoutedProvider, Arc<MapStore>) {
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(ZEN_CREDENTIAL_REF, SECRET)],
    ));
    (zen_with(config, Arc::clone(&store), deadline), store)
}

async fn mount_zen_models(server: &MockServer, ids: &[&str]) {
    let data: Vec<Value> = ids.iter().map(|id| json!({"id": id})).collect();
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": data})))
        .mount(server)
        .await;
}

async fn mount_zen_post(server: &MockServer, wire_path: &str, body: String) {
    Mock::given(method("POST"))
        .and(path(wire_path))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(server)
        .await;
}

fn zen_gemini_path(model: &str) -> String {
    format!("/v1/models/{model}:streamGenerateContent")
}

fn zen_gemini_stream(text: &str, prompt_tokens: u64, completion_tokens: u64) -> String {
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
                "promptTokenCount": prompt_tokens,
                "candidatesTokenCount": completion_tokens,
                "totalTokenCount": prompt_tokens + completion_tokens,
            },
        }),
    )
}

/// The attribution session a wire leg carries, derived from the frozen
/// world exactly as the routed owner derives it.
fn zen_session(world: &str) -> String {
    support::sha256_hex(world.as_bytes())
        .chars()
        .take(16)
        .collect()
}

#[tokio::test]
async fn opencode_zen_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_zen_post(
        &server,
        ZEN_CC_PATH,
        cc_completed_stream(
            "zen outcome",
            json!({"prompt_tokens": 9, "completion_tokens": 4, "total_tokens": 13}),
        ),
    )
    .await;
    let config = Config::parse_validated(&zen_config(&server.uri(), ZEN_CC_MODEL)).expect("valid");
    let (broker, manifest) = prepared_with(
        zen_provider(&config, Duration::from_secs(10)),
        &config,
        "/world/opencode-zen",
        "goal: prove the zen wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/opencode-zen", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "zen outcome");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 9,
            completion_tokens: 4,
            total_tokens: 13,
        }
    );

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "one physical request");
    assert_eq!(requests[0].url.path(), ZEN_CC_PATH);
    assert_eq!(body_of(&requests[0])["model"], json!(ZEN_CC_MODEL));

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, ZEN);
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 9,
            completion_tokens: 4,
            total_tokens: 13,
        }
    );
    drop_blocking(broker);
}

#[tokio::test]
async fn opencode_zen_catalog_offers_the_recorded_routes() {
    assert_eq!(
        routes_for(ZEN),
        [
            Dialect::ChatCompletions,
            Dialect::Messages,
            Dialect::Responses,
            Dialect::Gemini
        ]
    );
    for (model, dialect) in [
        ("claude-sonnet-4-5", Dialect::Messages),
        ("claude-opus-4-6", Dialect::Messages),
        ("qwen-3-coder", Dialect::Messages),
        ("qwen3.6-plus", Dialect::ChatCompletions),
        ("gpt-5.2", Dialect::Responses),
        ("grok-4", Dialect::Responses),
        ("muse-spark-1.3-contributor-free", Dialect::Responses),
        ("muse-spark-1.2", Dialect::Responses),
        ("minimax-m3", Dialect::ChatCompletions),
        ("minimax-m3-free", Dialect::ChatCompletions),
        ("gemini-3.1-pro", Dialect::Gemini),
        ("deepseek-v4-flash", Dialect::ChatCompletions),
    ] {
        assert_eq!(route_for(ZEN, model), Some(dialect), "{model}");
    }
    assert_eq!(
        route_for("gitlab-duo", "duo-chat-unknown-9"),
        None,
        "the closed GitLab table keeps its denial"
    );

    let server = MockServer::start().await;
    mount_zen_models(
        &server,
        &[
            "claude-sonnet-4-5",
            "gemini-3.1-pro",
            "minimax-m3-free",
            "muse-spark-1.3-contributor-free",
            "qwen3.6-plus",
            "deepseek-v4-flash",
        ],
    )
    .await;
    let config = Config::parse_validated(&zen_config(&server.uri(), ZEN_CC_MODEL)).expect("valid");
    let (provider, _store) = zen_provider(&config, Duration::from_secs(5));
    let (provider, catalog) = std::thread::spawn(move || {
        let outcome = provider.catalog();
        (provider, outcome)
    })
    .join()
    .expect("the catalog thread joins");
    assert_eq!(
        catalog.expect("the listed ids are the catalogue"),
        [
            "claude-sonnet-4-5",
            "deepseek-v4-flash",
            "gemini-3.1-pro",
            "minimax-m3-free",
            "muse-spark-1.3-contributor-free",
            "qwen3.6-plus",
        ]
        .map(String::from)
    );
    drop_blocking(provider);

    // The listing is the source: its failure denies typed.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(500).set_body_string("listing failure"))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&zen_config(&server.uri(), ZEN_CC_MODEL)).expect("valid");
    let (provider, _store) = zen_provider(&config, Duration::from_secs(5));
    let (provider, catalog) = std::thread::spawn(move || {
        let outcome = provider.catalog();
        (provider, outcome)
    })
    .join()
    .expect("the catalog thread joins");
    assert!(
        matches!(&catalog, Err(ProviderError::Transport { .. })),
        "a failed listing denies where the listing is the source"
    );
    let Err(ProviderError::Transport { cause, .. }) = catalog else {
        panic!("expected the typed listing denial");
    };
    assert_eq!(cause.class(), TransportClass::HttpStatus { code: 500 });
    drop_blocking(provider);
}

#[tokio::test]
async fn opencode_zen_messages_responses_cc_and_gemini_dispatch() {
    // Messages override
    let server = MockServer::start().await;
    mount_zen_post(
        &server,
        ZEN_MESSAGES_PATH,
        text_stream("zen messages", 2, 3),
    )
    .await;
    let config =
        Config::parse_validated(&zen_config(&server.uri(), ZEN_MESSAGES_MODEL)).expect("valid");
    let (provider, _store) = zen_provider(&config, Duration::from_secs(5));
    let (provider, outcome) = send_on_thread(
        provider,
        prepared_manifest_at(&config, "/world/opencode-zen"),
    );
    let reply = outcome.expect("the Messages route answers");
    assert_eq!(reply.text, "zen messages");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), ZEN_MESSAGES_PATH);
    assert_eq!(body_of(&requests[0])["model"], json!(ZEN_MESSAGES_MODEL));

    // Responses override
    let server = MockServer::start().await;
    mount_zen_post(
        &server,
        ZEN_RESPONSES_PATH,
        responses_stream(
            "zen responses",
            json!({"input_tokens": 4, "output_tokens": 5, "total_tokens": 9}),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&zen_config(&server.uri(), ZEN_RESPONSES_MODEL)).expect("valid");
    let (provider, _store) = zen_provider(&config, Duration::from_secs(5));
    let (provider, outcome) = send_on_thread(
        provider,
        prepared_manifest_at(&config, "/world/opencode-zen"),
    );
    let reply = outcome.expect("the Responses route answers");
    assert_eq!(reply.text, "zen responses");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 4,
            completion_tokens: 5,
            total_tokens: 9,
        }
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests[0].url.path(), ZEN_RESPONSES_PATH);
    assert_eq!(body_of(&requests[0])["model"], json!(ZEN_RESPONSES_MODEL));

    // Chat Completions exact
    let server = MockServer::start().await;
    mount_zen_post(
        &server,
        ZEN_CC_PATH,
        cc_completed_stream(
            "zen cc",
            json!({"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}),
        ),
    )
    .await;
    let config = Config::parse_validated(&zen_config(&server.uri(), ZEN_CC_MODEL)).expect("valid");
    let (provider, _store) = zen_provider(&config, Duration::from_secs(5));
    let (provider, outcome) = send_on_thread(
        provider,
        prepared_manifest_at(&config, "/world/opencode-zen"),
    );
    let reply = outcome.expect("the CC route answers");
    assert_eq!(reply.text, "zen cc");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests[0].url.path(), ZEN_CC_PATH);
    assert_eq!(body_of(&requests[0])["model"], json!(ZEN_CC_MODEL));

    // Gemini route
    let server = MockServer::start().await;
    mount_zen_post(
        &server,
        &zen_gemini_path(ZEN_GEMINI_MODEL),
        zen_gemini_stream("zen gemini", 6, 2),
    )
    .await;
    let config =
        Config::parse_validated(&zen_config(&server.uri(), ZEN_GEMINI_MODEL)).expect("valid");
    let (provider, _store) = zen_provider(&config, Duration::from_secs(5));
    let (provider, outcome) = send_on_thread(
        provider,
        prepared_manifest_at(&config, "/world/opencode-zen"),
    );
    let reply = outcome.expect("the Gemini route answers");
    assert_eq!(reply.text, "zen gemini");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 6,
            completion_tokens: 2,
            total_tokens: 8,
        }
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests[0].url.path(), zen_gemini_path(ZEN_GEMINI_MODEL));
    assert_eq!(
        requests[0].url.query(),
        Some("alt=sse"),
        "the Gemini route carries its recorded query"
    );
    assert_eq!(
        header(&requests[0], "x-goog-api-key"),
        Some(SECRET),
        "the recorded Gemini route carries the resolved key here"
    );
    assert_eq!(
        header(&requests[0], "authorization"),
        None,
        "the Gemini leg is never a bearer leg"
    );
    assert_eq!(
        header(&requests[0], "user-agent"),
        Some(format!("rivect/{}", env!("CARGO_PKG_VERSION")).as_str())
    );
    assert_eq!(
        header(&requests[0], "x-opencode-session"),
        Some(zen_session("/world/opencode-zen").as_str())
    );

    // The recorded Responses family: a GPT or Grok id posts /responses.
    for model in ["gpt-5.2", "grok-4"] {
        let server = MockServer::start().await;
        mount_zen_post(
            &server,
            ZEN_RESPONSES_PATH,
            responses_stream(
                "zen responses family",
                json!({"input_tokens": 3, "output_tokens": 2, "total_tokens": 5}),
            ),
        )
        .await;
        let config = Config::parse_validated(&zen_config(&server.uri(), model)).expect("valid");
        let (provider, _store) = zen_provider(&config, Duration::from_secs(5));
        let (provider, outcome) = send_on_thread(
            provider,
            prepared_manifest_at(&config, "/world/opencode-zen"),
        );
        outcome.expect("the Responses family answers");
        drop_blocking(provider);
        let requests = server.received_requests().await.expect("recorded");
        assert_eq!(requests.len(), 1, "{model}");
        assert_eq!(requests[0].url.path(), ZEN_RESPONSES_PATH, "{model}");
        assert_eq!(body_of(&requests[0])["model"], json!(model));
    }
}

#[tokio::test]
async fn opencode_zen_unknown_model_uses_the_recorded_cc_default() {
    assert_eq!(
        route_for(ZEN, ZEN_UNKNOWN_MODEL),
        Some(Dialect::ChatCompletions)
    );
    let server = MockServer::start().await;
    mount_zen_post(
        &server,
        ZEN_CC_PATH,
        cc_completed_stream(
            "zen default",
            json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&zen_config(&server.uri(), ZEN_UNKNOWN_MODEL)).expect("valid");
    let (provider, _store) = zen_provider(&config, Duration::from_secs(5));
    let (provider, outcome) = send_on_thread(
        provider,
        prepared_manifest_at(&config, "/world/opencode-zen"),
    );
    let reply = outcome.expect("the unknown id rides the CC default");
    assert_eq!(reply.text, "zen default");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), ZEN_CC_PATH);
    assert_eq!(body_of(&requests[0])["model"], json!(ZEN_UNKNOWN_MODEL));
}

#[tokio::test]
async fn opencode_zen_auth_and_attribution_headers() {
    let server = MockServer::start().await;
    mount_zen_models(&server, &[ZEN_CC_MODEL]).await;
    mount_zen_post(&server, ZEN_MESSAGES_PATH, text_stream("attributed", 1, 1)).await;
    let config =
        Config::parse_validated(&zen_config(&server.uri(), ZEN_MESSAGES_MODEL)).expect("valid");
    let (provider, _store) = zen_provider(&config, Duration::from_secs(5));
    let (provider, catalog) = std::thread::spawn(move || {
        let outcome = provider.catalog();
        (provider, outcome)
    })
    .join()
    .expect("the catalog thread joins");
    catalog.expect("the catalogue answers");
    let (provider, outcome) = send_on_thread(
        provider,
        prepared_manifest_at(&config, "/world/opencode-zen"),
    );
    outcome.expect("the wire leg answers");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 2, "the catalogue and the wire leg");
    let expected_agent = format!("rivect/{}", env!("CARGO_PKG_VERSION"));
    let expected_session = zen_session("/world/opencode-zen");
    for request in &requests {
        assert_eq!(header(request, "user-agent"), Some(expected_agent.as_str()));
        let session = header(request, "x-opencode-session").expect("attributed session");
        assert_eq!(session.len(), 16, "a truncated digest: {session}");
        assert!(
            session.chars().all(|c| c.is_ascii_hexdigit()),
            "the session is hex: {session}"
        );
        let bearer = format!("Bearer {SECRET}");
        assert_eq!(
            header(request, "authorization"),
            Some(bearer.as_str()),
            "the scoped key is the bearer on every leg"
        );
    }
    assert_eq!(
        header(&requests[1], "x-opencode-session"),
        Some(expected_session.as_str()),
        "the wire leg seeds the session from the frozen world"
    );
    assert_eq!(header(&requests[1], "x-api-key"), None);
    assert_eq!(
        header(&requests[1], "anthropic-version"),
        Some("2023-06-01")
    );

    // The catalogue session is stable across calls.
    let first = header(&requests[0], "x-opencode-session").expect("attributed");
    let server = MockServer::start().await;
    mount_zen_models(&server, &[ZEN_CC_MODEL]).await;
    let config = Config::parse_validated(&zen_config(&server.uri(), ZEN_CC_MODEL)).expect("valid");
    let (provider, _store) = zen_provider(&config, Duration::from_secs(5));
    let (provider, catalog) = std::thread::spawn(move || {
        let outcome = provider.catalog();
        (provider, outcome)
    })
    .join()
    .expect("the catalog thread joins");
    catalog.expect("the catalogue answers");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        header(&requests[0], "x-opencode-session"),
        Some(first),
        "the catalogue session is stable"
    );
}

#[tokio::test]
async fn opencode_zen_responses_and_cc_legs_carry_bearer_and_attribution() {
    // The recorded Responses family is `muse-spark-*`; a `gpt-*` id
    // rides the recorded CC default (DEC-018), so the override legs here
    // are the recorded family and the recorded CC exact.
    const ZEN_CC_EXACT: &str = "minimax-m3";
    let server = MockServer::start().await;
    mount_zen_post(
        &server,
        ZEN_MESSAGES_PATH,
        text_stream("zen messages", 1, 1),
    )
    .await;
    mount_zen_post(
        &server,
        ZEN_RESPONSES_PATH,
        responses_stream(
            "zen responses",
            json!({"input_tokens": 4, "output_tokens": 5, "total_tokens": 9}),
        ),
    )
    .await;
    mount_zen_post(
        &server,
        ZEN_CC_PATH,
        cc_completed_stream(
            "zen cc",
            json!({"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}),
        ),
    )
    .await;

    let expected_agent = format!("rivect/{}", env!("CARGO_PKG_VERSION"));
    let expected_session = zen_session("/world/opencode-zen");
    let bearer = format!("Bearer {SECRET}");
    for (model, wire_path, text) in [
        (ZEN_MESSAGES_MODEL, ZEN_MESSAGES_PATH, "zen messages"),
        (ZEN_RESPONSES_MODEL, ZEN_RESPONSES_PATH, "zen responses"),
        (ZEN_CC_EXACT, ZEN_CC_PATH, "zen cc"),
    ] {
        let config = Config::parse_validated(&zen_config(&server.uri(), model)).expect("valid");
        let (provider, _store) = zen_provider(&config, Duration::from_secs(5));
        let (provider, outcome) = send_on_thread(
            provider,
            prepared_manifest_at(&config, "/world/opencode-zen"),
        );
        let reply = outcome.expect("the route answers");
        assert_eq!(reply.text, text, "{model}");
        drop_blocking(provider);

        let requests = server.received_requests().await.expect("recorded");
        let request = requests.last().expect("the leg was recorded");
        assert_eq!(request.url.path(), wire_path, "{model}");
        assert_eq!(
            header(request, "authorization"),
            Some(bearer.as_str()),
            "{model} carries the scoped key as bearer"
        );
        assert_eq!(header(request, "x-api-key"), None, "{model}");
        assert_eq!(
            header(request, "user-agent"),
            Some(expected_agent.as_str()),
            "{model}"
        );
        assert_eq!(
            header(request, "x-opencode-session"),
            Some(expected_session.as_str()),
            "{model} carries the same stable session"
        );
    }
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 3, "one physical request per leg");
}

#[tokio::test]
async fn opencode_zen_wrong_credential_profile_or_region_denies_without_secrets() {
    // A configured region has no recorded Zen contract.
    let config = Config::parse_validated(
        &zen_config("https://opencode.ai/zen", ZEN_CC_MODEL)
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let store = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(ZEN_CREDENTIAL_REF, SECRET)],
    ));
    let denied = std::thread::spawn(move || {
        RoutedProvider::with_deadline(&config, ZEN, store, Duration::from_secs(1))
    })
    .join()
    .expect("the provider thread joins")
    .expect_err("a configured region denies");
    let ProviderError::RegionMismatch { connection, .. } = denied else {
        panic!("expected the typed region denial: {denied:?}");
    };
    assert_eq!(connection, ZEN);

    // An absent scoped credential denies before any wire leg.
    let server = MockServer::start().await;
    mount_zen_post(
        &server,
        ZEN_CC_PATH,
        cc_completed_stream(
            "never reached",
            json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}),
        ),
    )
    .await;
    let config = Config::parse_validated(&zen_config(&server.uri(), ZEN_CC_MODEL)).expect("valid");
    let provider = zen_with(
        &config,
        Arc::new(MapStore::seeded(STORE_KIND, &[])),
        Duration::from_secs(2),
    );
    let (provider, outcome) = send_on_thread(
        provider,
        prepared_manifest_at(&config, "/world/opencode-zen"),
    );
    assert!(
        matches!(outcome, Err(ProviderError::CredentialAbsent { .. })),
        "absent material denies at the scoped seam: {outcome:?}"
    );
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "no wire leg opens without material"
    );
}

#[tokio::test]
async fn opencode_zen_rejects_partial_tool_block_and_unknown_terminal() {
    // A partial tool JSON at the block stop never becomes a reply.
    let partial = format!(
        "{}{}{}{}{}{}",
        message_start(3),
        sse_block(
            "content_block_start",
            &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {}}}),
        ),
        sse_block(
            "content_block_delta",
            &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "{\"path\":"}}),
        ),
        sse_block(
            "content_block_stop",
            &json!({"type": "content_block_stop", "index": 0}),
        ),
        sse_block(
            "message_delta",
            &json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 2}}),
        ),
        sse_block("message_stop", &json!({"type": "message_stop"})),
    );
    let server = MockServer::start().await;
    mount_zen_post(&server, ZEN_MESSAGES_PATH, partial).await;
    let config =
        Config::parse_validated(&zen_config(&server.uri(), ZEN_MESSAGES_MODEL)).expect("valid");
    let (provider, _store) = zen_provider(&config, Duration::from_secs(5));
    let (provider, outcome) = send_on_thread(
        provider,
        prepared_manifest_at(&config, "/world/opencode-zen"),
    );
    assert!(
        matches!(outcome, Err(ProviderError::StreamViolation { .. })),
        "a partial tool block never becomes a reply: {outcome:?}"
    );
    drop_blocking(provider);

    // An unknown terminal is never success.
    let server = MockServer::start().await;
    mount_zen_post(
        &server,
        ZEN_MESSAGES_PATH,
        format!(
            "{}{}{}{}{}",
            message_start(3),
            sse_block(
                "content_block_start",
                &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            ),
            sse_block(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 0}),
            ),
            sse_block(
                "message_delta",
                &json!({"type": "message_delta", "delta": {"stop_reason": "teleport"}, "usage": {"output_tokens": 1}}),
            ),
            sse_block("message_stop", &json!({"type": "message_stop"})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&zen_config(&server.uri(), ZEN_MESSAGES_MODEL)).expect("valid");
    let (provider, _store) = zen_provider(&config, Duration::from_secs(5));
    let (provider, outcome) = send_on_thread(
        provider,
        prepared_manifest_at(&config, "/world/opencode-zen"),
    );
    assert!(
        matches!(outcome, Err(ProviderError::UnknownTerminal { .. })),
        "an unknown stop reason is an unknown terminal: {outcome:?}"
    );
    drop_blocking(provider);
}

#[tokio::test]
async fn opencode_zen_rejects_incompatible_tools_or_reasoning() {
    // A pinned effort has no recorded Messages dial.
    let server = MockServer::start().await;
    mount_zen_post(
        &server,
        ZEN_MESSAGES_PATH,
        text_stream("never reached", 1, 1),
    )
    .await;
    let config = Config::parse_validated(&zen_config(&server.uri(), ZEN_MESSAGES_MODEL).replace(
        "effort = { mode = \"auto\" }",
        "effort = { mode = \"fixed\", value = \"high\" }",
    ))
    .expect("valid");
    let (provider, _store) = zen_provider(&config, Duration::from_secs(5));
    let (provider, outcome) = send_on_thread(
        provider,
        prepared_manifest_at(&config, "/world/opencode-zen"),
    );
    let ProviderError::UnsupportedParameter {
        connection,
        parameter,
        model,
    } = outcome.expect_err("a pinned effort denies")
    else {
        panic!("expected the typed effort denial");
    };
    assert_eq!(connection, ZEN);
    assert_eq!(parameter, "effort");
    assert_eq!(model, ZEN_MESSAGES_MODEL);
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the effort denial lands before any wire leg"
    );

    // A tool name outside the Messages grammar has no constructible tool.
    let server = MockServer::start().await;
    mount_zen_post(
        &server,
        ZEN_MESSAGES_PATH,
        text_stream("never reached", 1, 1),
    )
    .await;
    let config =
        Config::parse_validated(&zen_config(&server.uri(), ZEN_MESSAGES_MODEL)).expect("valid");
    let (provider, _store) = zen_provider(&config, Duration::from_secs(5));
    let mut manifest = prepared_manifest_at(&config, "/world/opencode-zen");
    manifest.tools = vec!["read file".to_string()];
    let (provider, outcome) = send_on_thread(provider, manifest);
    let ProviderError::UnsupportedParameter { parameter, .. } =
        outcome.expect_err("a tool name outside the grammar denies")
    else {
        panic!("expected the typed tool denial");
    };
    assert_eq!(parameter, "tools");
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the tool denial lands before any wire leg"
    );
}

#[tokio::test]
async fn opencode_zen_non_success_status_denies() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(ZEN_CC_PATH))
        .respond_with(ResponseTemplate::new(500).set_body_string("peer failure body"))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&zen_config(&server.uri(), ZEN_CC_MODEL)).expect("valid");
    let (broker, manifest) = prepared_with(
        zen_provider(&config, Duration::from_secs(5)),
        &config,
        "/world/opencode-zen",
        "goal: non-success",
    );
    let (broker, outcome) = dispatch(broker, "/world/opencode-zen", manifest);
    let Err(ModelError::Provider(ProviderError::Transport { cause, .. })) = outcome else {
        panic!("a non-success status is a typed denial: {outcome:?}");
    };
    assert_eq!(
        cause.class(),
        TransportClass::HttpStatus { code: 500 },
        "the status code alone is the diagnostic"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);
    assert_eq!(server.received_requests().await.expect("recorded").len(), 1);
}

#[tokio::test]
async fn opencode_zen_short_deadline_denies_without_a_second_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(ZEN_CC_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(cc_completed_stream(
                    "too late",
                    json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}),
                ))
                .set_delay(Duration::from_millis(400)),
        )
        .mount(&server)
        .await;
    let config = Config::parse_validated(&zen_config(&server.uri(), ZEN_CC_MODEL)).expect("valid");
    let deadline = Duration::from_millis(250);
    let provider = zen_with(
        &config,
        Arc::new(MapStore::seeded(
            STORE_KIND,
            &[(ZEN_CREDENTIAL_REF, SECRET)],
        )),
        deadline,
    );
    let (provider, outcome) = send_on_thread(
        provider,
        prepared_manifest_at(&config, "/world/opencode-zen"),
    );
    let error = outcome.expect_err("the expired budget denies");
    let ProviderError::Transport {
        cause: TransportCause::Deadline { budget },
        ..
    } = error
    else {
        panic!("the shared deadline is the denial: {error:?}");
    };
    assert!(
        !budget.is_zero() && budget <= deadline,
        "the codec inherits the send's remaining budget, not a fresh one: {budget:?}"
    );
    drop_blocking(provider);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        1,
        "the expired budget never opens a second request"
    );
}

#[tokio::test]
async fn opencode_zen_auto_pin_shares_one_clock_across_catalogue_and_wire() {
    let server = MockServer::start().await;
    mount_zen_models(&server, &[ZEN_CC_MODEL]).await;
    mount_zen_post(
        &server,
        ZEN_CC_PATH,
        cc_completed_stream(
            "never reached",
            json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}),
        ),
    )
    .await;
    let mut config =
        Config::parse_validated(&zen_config(&server.uri(), ZEN_CC_MODEL)).expect("valid");
    config
        .models
        .defaults
        .as_mut()
        .expect("models.defaults")
        .model = ModelAssign::Auto {
        pool: Some(vec![ZEN.to_string()]),
    };
    // A credential read that spends the whole budget: the auto catalogue
    // leg and the wire leg must then both inherit the spent clock.
    let store = Arc::new(SlowStore {
        inner: MapStore::seeded(STORE_KIND, &[(ZEN_CREDENTIAL_REF, SECRET)]),
        delay: Duration::from_millis(300),
    });
    let thread_config = config.clone();
    let deadline = Duration::from_millis(100);
    let provider = std::thread::spawn(move || {
        RoutedProvider::with_deadline(&thread_config, ZEN, store, deadline)
            .expect("the routed adapter builds")
    })
    .join()
    .expect("the provider thread joins");
    let (provider, outcome) = send_on_thread(
        provider,
        prepared_manifest_at(&config, "/world/opencode-zen"),
    );
    let error = outcome.expect_err("the spent clock denies the auto send");
    assert!(
        matches!(
            error,
            ProviderError::Transport {
                cause: TransportCause::Deadline { budget },
                ..
            } if budget == deadline
        ),
        "the one send clock is the denial: {error:?}"
    );
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "neither the auto catalogue leg nor the wire leg opens a request"
    );
}

#[tokio::test]
async fn opencode_zen_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    // CATALOG: the one listing filtered by the route table.
    let server = MockServer::start().await;
    mount_zen_models(&server, &["claude-sonnet-4-5", "gemini-3.1-pro"]).await;
    let config = Config::parse_validated(&zen_config(&server.uri(), ZEN_CC_MODEL)).expect("valid");
    let (provider, _store) = zen_provider(&config, Duration::from_secs(5));
    let (provider, catalog) = std::thread::spawn(move || {
        let outcome = provider.catalog();
        (provider, outcome)
    })
    .join()
    .expect("the catalog thread joins");
    reported.insert(
        "CATALOG",
        if matches!(&catalog, Ok(ids) if ids == &["claude-sonnet-4-5", "gemini-3.1-pro"].map(String::from))
        {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: absent material denies at the scoped seam.
    let server = MockServer::start().await;
    mount_zen_post(&server, ZEN_CC_PATH, text_stream("never reached", 1, 1)).await;
    let config = Config::parse_validated(&zen_config(&server.uri(), ZEN_CC_MODEL)).expect("valid");
    let provider = zen_with(
        &config,
        Arc::new(MapStore::seeded(STORE_KIND, &[])),
        Duration::from_secs(2),
    );
    let (provider, denied) = send_on_thread(
        provider,
        prepared_manifest_at(&config, "/world/opencode-zen"),
    );
    reported.insert(
        "AUTH",
        if matches!(denied, Err(ProviderError::CredentialAbsent { .. })) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // WIRE
    let server = MockServer::start().await;
    mount_zen_post(&server, ZEN_MESSAGES_PATH, text_stream("matrix", 1, 1)).await;
    let config =
        Config::parse_validated(&zen_config(&server.uri(), ZEN_MESSAGES_MODEL)).expect("valid");
    let (broker, manifest) = prepared_with(
        zen_provider(&config, Duration::from_secs(5)),
        &config,
        "/world/opencode-zen",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/opencode-zen", manifest);
    reported.insert(
        "WIRE",
        if matches!(&outcome, Ok(reply) if reply.text == "matrix") {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

    // RECOVERY: a stream without its terminal is never success.
    let server = MockServer::start().await;
    let mut truncated = text_stream("looks complete", 1, 1);
    truncated.truncate(
        truncated
            .rfind("event: message_stop")
            .expect("the terminal exists"),
    );
    mount_zen_post(&server, ZEN_MESSAGES_PATH, truncated).await;
    let config =
        Config::parse_validated(&zen_config(&server.uri(), ZEN_MESSAGES_MODEL)).expect("valid");
    let (provider, _store) = zen_provider(&config, Duration::from_secs(5));
    let (provider, outcome) = send_on_thread(
        provider,
        prepared_manifest_at(&config, "/world/opencode-zen"),
    );
    reported.insert(
        "RECOVERY",
        if matches!(outcome, Err(ProviderError::UnknownTerminal { .. })) {
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

// ----- TP-PROVIDER-INSTALLED::opencode-zen ---------------------------

/// TP-PROVIDER-INSTALLED::opencode-zen = NOT_RUN: the
/// installed-provider proof is a live-environment leg this offline
/// slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::opencode-zen = NOT_RUN"]
fn provider_installed_opencode_zen() {}

// ----- TP-PROVIDER-{CATALOG,AUTH,WIRE,RECOVERY}::zenmux ---------------

/// The literal `zenmux` connection id.
const ZENMUX: &str = "zenmux";
/// The scoped credential ref the connection binds.
const ZENMUX_CREDENTIAL_REF: &str = "keyring:rivect-test/zenmux";
/// An id the authoritative metadata classes as Anthropic.
const ZENMUX_ANTHROPIC_MODEL: &str = "anthropic/claude-opus-4.8";
/// An id the metadata keeps on the recorded Chat Completions default.
const ZENMUX_CC_MODEL: &str = "google/gemini-3-pro-preview";
/// The recorded Messages mirror of the Chat Completions root.
const ZENMUX_MESSAGES_PATH: &str = "/api/anthropic/v1/messages";
/// The Chat Completions path the Messages arm never posts to.
const ZENMUX_CC_PATH: &str = "/api/v1/chat/completions";

fn zenmux_config(endpoint: &str, model: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.zenmux]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{ZENMUX_CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"zenmux\", model_id = \"{model}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The configured endpoint carries the recorded Chat Completions root;
/// the Messages arm derives its mirror from the same base.
fn zenmux_uri(server: &MockServer) -> String {
    format!("{}/api/v1", server.uri())
}

fn zenmux_store() -> Arc<MapStore> {
    Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(ZENMUX_CREDENTIAL_REF, SECRET)],
    ))
}

/// The Messages arm is built through the route constructor: the literal
/// default is Chat Completions, so the route table is the gate.
fn zenmux_provider(config: &Config) -> (MessagesProvider, Arc<MapStore>) {
    let store = zenmux_store();
    let reference = SecretRef::parse(ZENMUX_CREDENTIAL_REF).expect("the scoped ref parses");
    let built = config.clone();
    let provider = std::thread::spawn(move || {
        MessagesProvider::with_route(
            &built,
            ZENMUX,
            store.clone(),
            Duration::from_secs(30),
            WireAuth::Store(Some(reference)),
        )
    })
    .join()
    .expect("the provider thread joins")
    .expect("the Messages route builds for zenmux");
    (provider, zenmux_store())
}

fn zenmux_provider_with_auth(
    config: &Config,
    auth: WireAuth,
) -> Result<MessagesProvider, ProviderError> {
    let built = config.clone();
    std::thread::spawn(move || {
        MessagesProvider::with_route(
            &built,
            ZENMUX,
            Arc::new(MapStore::seeded(STORE_KIND, &[])),
            Duration::from_secs(30),
            auth,
        )
    })
    .join()
    .expect("the provider thread joins")
}

fn zenmux_routed(config: &Config) -> RoutedProvider {
    let built = config.clone();
    std::thread::spawn(move || RoutedProvider::new(&built, ZENMUX, zenmux_store()))
        .join()
        .expect("the provider thread joins")
        .expect("the routed owner builds for zenmux")
}

async fn mount_zenmux_messages(server: &MockServer, body: String) {
    Mock::given(method("POST"))
        .and(path(ZENMUX_MESSAGES_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(server)
        .await;
}

/// The authoritative metadata's Anthropic class takes the recorded
/// Messages route: the routed owner resolves the model class, derives the
/// `/api/anthropic` mirror from the configured Chat Completions root, and
/// sends one Messages envelope with the plain key — never a Chat
/// Completions request for the same pin.
#[tokio::test]
async fn zenmux_anthropic_class_model_takes_the_messages_route() {
    assert_eq!(dialect_for(ZENMUX), Some(Dialect::ChatCompletions));
    assert_eq!(
        routes_for(ZENMUX),
        &[Dialect::ChatCompletions, Dialect::Messages]
    );
    assert_eq!(
        route_for(ZENMUX, ZENMUX_ANTHROPIC_MODEL),
        Some(Dialect::Messages)
    );
    assert_eq!(
        route_for(ZENMUX, ZENMUX_CC_MODEL),
        Some(Dialect::ChatCompletions)
    );

    let server = MockServer::start().await;
    mount_zenmux_messages(&server, text_stream("zenmux messages outcome", 13, 5)).await;
    let config =
        Config::parse_validated(&zenmux_config(&zenmux_uri(&server), ZENMUX_ANTHROPIC_MODEL))
            .expect("valid");
    let provider = zenmux_routed(&config);
    let (broker, manifest) = prepared_with(
        (provider, zenmux_store()),
        &config,
        "/world/zenmux",
        "goal: zenmux messages route",
    );
    let (broker, outcome) = dispatch(broker, "/world/zenmux", manifest.clone());
    let reply = outcome.expect("the Anthropic class rides Messages");
    assert_eq!(reply.text, "zenmux messages outcome");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 13,
            completion_tokens: 5,
            total_tokens: 18,
        }
    );
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the Messages send is accounted once");
    assert_eq!(record.connection, ZENMUX);
    assert_eq!(record.usage, reply.usage);
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(count_path(&requests, ZENMUX_MESSAGES_PATH), 1);
    assert_eq!(
        count_path(&requests, ZENMUX_CC_PATH),
        0,
        "the Anthropic class never falls back to the default route"
    );
    let post = requests
        .iter()
        .find(|request| request.url.path() == ZENMUX_MESSAGES_PATH)
        .expect("the Messages request is recorded");
    let bearer = format!("Bearer {SECRET}");
    assert_eq!(header(post, "authorization"), Some(bearer.as_str()));
    assert_eq!(header(post, "anthropic-version"), Some("2023-06-01"));
    assert_eq!(header(post, "x-api-key"), None);
    let body = body_of(post);
    assert_eq!(body["model"], json!(ZENMUX_ANTHROPIC_MODEL));
    assert_eq!(body["system"], json!(manifest.instructions));
    assert_eq!(body["max_tokens"], json!(MESSAGES_MAX_TOKENS));
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["messages"],
        json!([{"role": "user", "content": manifest.inputs}])
    );
    assert!(
        !String::from_utf8_lossy(&post.body).contains(SECRET),
        "the key rides the header, never the body"
    );

    // the empty endpoint resolves the recorded Messages mirror; a
    // configured Messages root folds onto the same fixed pair
    let unset = Config::parse_validated(&zenmux_config("", ZENMUX_ANTHROPIC_MODEL)).expect("valid");
    let provider = zenmux_provider_with_auth(&unset, WireAuth::Store(None))
        .expect("the route constructor builds with the default base");
    let debug = format!("{provider:?}");
    assert!(
        debug.contains("endpoint: \"https://zenmux.ai/api/anthropic\""),
        "an empty endpoint resolves the recorded Messages mirror: {debug}"
    );
    drop_blocking(provider);

    let pair = Config::parse_validated(&zenmux_config(
        &format!("{}/api/anthropic", server.uri()),
        ZENMUX_ANTHROPIC_MODEL,
    ))
    .expect("valid");
    let provider = zenmux_provider_with_auth(&pair, WireAuth::Store(None))
        .expect("the Messages root folds onto the fixed pair");
    assert!(
        format!("{provider:?}").contains(&format!("endpoint: \"{}/api/anthropic\"", server.uri())),
        "the configured Messages root is the same base"
    );
    drop_blocking(provider);
}

/// The recorded default class never crosses into Messages: a Chat
/// Completions-class id — listed or unrecorded — is denied typed before
/// the wire, while the literal construction gate keeps `new` on the
/// recorded default.
#[tokio::test]
async fn zenmux_unrecorded_class_never_enters_the_messages_route() {
    for model in [ZENMUX_CC_MODEL, "fixture/unknown-model", "claude-opus-4.8"] {
        assert_eq!(
            route_for(ZENMUX, model),
            Some(Dialect::ChatCompletions),
            "{model} rides the recorded default"
        );
    }

    let server = MockServer::start().await;
    let config = Config::parse_validated(&zenmux_config(&zenmux_uri(&server), ZENMUX_CC_MODEL))
        .expect("valid");
    let (broker, manifest) = prepared_with(
        zenmux_provider(&config),
        &config,
        "/world/zenmux",
        "goal: default class denial",
    );
    let (broker, outcome) = dispatch(broker, "/world/zenmux", manifest);
    let ProviderError::UnsupportedParameter {
        connection,
        parameter,
        model,
    } = (match outcome {
        Err(ModelError::Provider(error)) => error,
        other => panic!("the default class denies typed: {other:?}"),
    })
    else {
        panic!("expected the typed model denial");
    };
    assert_eq!(connection, ZENMUX);
    assert_eq!(parameter, "model");
    assert_eq!(model, ZENMUX_CC_MODEL);
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the denial lands before any wire leg"
    );

    // the literal default is Chat Completions, so `new` cannot build the
    // Messages arm without the route table gate
    let denied = std::thread::spawn(move || MessagesProvider::new(&config, ZENMUX, zenmux_store()))
        .join()
        .expect("the provider thread joins")
        .expect_err("a Messages build without a route denies");
    assert!(matches!(denied, ProviderError::DialectMismatch { .. }));
}

/// Wrong credential, region or origin never produce a false success for
/// `zenmux`: a configured region denies at build, an origin outside the
/// trust boundary is refused at ingress, an absent scope denies before
/// any wire leg, a refused key lands the typed transport denial, and no
/// denial renders the material or body.
#[tokio::test]
async fn zenmux_wrong_credential_region_or_origin_denies_without_secrets() {
    let server = MockServer::start().await;

    // a configured region names no recorded contract
    let regional = Config::parse_validated(
        &zenmux_config(&zenmux_uri(&server), ZENMUX_ANTHROPIC_MODEL)
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let denied = std::thread::spawn(move || {
        MessagesProvider::with_route(
            &regional,
            ZENMUX,
            zenmux_store(),
            Duration::from_secs(1),
            WireAuth::Store(None),
        )
    })
    .join()
    .expect("the provider thread joins")
    .expect_err("a configured region denies");
    assert!(
        matches!(&denied, ProviderError::RegionMismatch { connection, region }
        if connection == ZENMUX && region == "eu")
    );

    // origins outside the trust boundary are refused at ingress, and the
    // refusal never echoes the userinfo
    for origin in [
        "http://gateway.example.com/api/v1",
        "https://key:fixture-origin-material@gateway.example.com",
    ] {
        let refused = Config::parse_validated(&zenmux_config(origin, ZENMUX_ANTHROPIC_MODEL))
            .expect_err("the origin is outside the trust boundary");
        assert!(matches!(&refused.issue, ConfigIssue::EndpointNotAllowed));
        assert!(
            !refused.to_string().contains("fixture-origin-material"),
            "the refusal never echoes the origin's userinfo: {refused}"
        );
    }

    // a bound-but-empty scope denies at send without reaching the wire
    let config =
        Config::parse_validated(&zenmux_config(&zenmux_uri(&server), ZENMUX_ANTHROPIC_MODEL))
            .expect("valid");
    let provider = zenmux_provider_with_auth(&config, WireAuth::Store(None))
        .expect("the route constructor builds");
    let (provider, denied) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/zenmux"));
    let error = denied.expect_err("the empty scope denies");
    assert!(matches!(error, ProviderError::CredentialUnresolved { .. }));
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(
            !rendered.contains(SECRET) && !rendered.contains(NEIGHBOR_SECRET),
            "diagnostics stay secret-free: {rendered}"
        );
    }
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the denial lands before the wire"
    );

    // a refused key is the typed transport denial carrying only the status
    Mock::given(method("POST"))
        .and(path(ZENMUX_MESSAGES_PATH))
        .respond_with(ResponseTemplate::new(401).set_body_string("fixture-401-body-marker"))
        .mount(&server)
        .await;
    let (provider, _store) = zenmux_provider(&config);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/zenmux"));
    let err = outcome.expect_err("a refused key is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused key is transport: {err}")
    };
    assert_eq!(connection, ZENMUX);
    assert!(cause.class() == TransportClass::HttpStatus { code: 401 });
    assert!(!err.to_string().contains(SECRET));
    assert!(!err.to_string().contains("fixture-401-body-marker"));
    drop_blocking(provider);
}

/// The Messages catalogue is the authoritative `/api/v1/models` metadata
/// read on the pair's Chat Completions root, filtered to the recorded
/// class: the unrecorded `/api/anthropic/v1/models` surface is never
/// contacted, and a default-class row is not offered here.
#[tokio::test]
async fn zenmux_catalog_is_the_authoritative_metadata_on_the_messages_arm() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [
                {
                    "id": ZENMUX_ANTHROPIC_MODEL,
                    "owned_by": "anthropic",
                    "input_modalities": ["text", "image"],
                    "capabilities": {"reasoning": true},
                    "context_length": 200_000,
                    "max_completion_tokens": 32_000,
                    "pricings": {
                        "prompt": [{"value": 5.0, "unit": "perMTokens", "currency": "USD"}],
                        "completion": [{"value": 25.0, "unit": "perMTokens", "currency": "USD"}],
                    },
                },
                {"id": ZENMUX_CC_MODEL, "owned_by": "google"},
            ],
        })))
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&zenmux_config(&zenmux_uri(&server), ZENMUX_ANTHROPIC_MODEL))
            .expect("valid");
    let (provider, _store) = zenmux_provider(&config);
    let (provider, catalog) = catalog_models_on_thread(provider);
    let models = catalog.expect("the authoritative metadata answers");
    assert_eq!(
        models,
        vec![CatalogModel {
            id: ZENMUX_ANTHROPIC_MODEL.to_string(),
            reasoning: true,
            vision: true,
            context_window: Some(200_000),
            max_output_tokens: Some(32_000),
            price: rivect::providers::local::ModelPrice::Usd {
                input_per_1m: 5.0,
                output_per_1m: 25.0,
            },
            ..CatalogModel::default()
        }],
        "the class filter keeps the metadata's Anthropic row alone"
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(count_path(&requests, "/api/v1/models"), 1);
    assert_eq!(
        count_path(&requests, "/api/anthropic/v1/models"),
        0,
        "the unrecorded Messages listing is never contacted"
    );
}

/// Hostile Messages input never reports success for `zenmux`: a partial
/// tool block is the typed violation, an unclassifiable stop reason the
/// unknown terminal, and a repeated usage report one charge — every
/// rejection accounts nothing.
#[tokio::test]
async fn zenmux_rejects_partial_tool_block_unknown_terminal_and_repeated_usage() {
    // partial tool JSON at the block stop
    let server = MockServer::start().await;
    mount_zenmux_messages(
        &server,
        format!(
            "{}{}{}{}{}",
            message_start(3),
            sse_block(
                "content_block_start",
                &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {}}}),
            ),
            sse_block(
                "content_block_delta",
                &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "{\"path\":"}}),
            ),
            sse_block(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 0}),
            ),
            format!(
                "{}{}",
                sse_block(
                    "message_delta",
                    &json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 2}}),
                ),
                sse_block("message_stop", &json!({"type": "message_stop"})),
            ),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&zenmux_config(&zenmux_uri(&server), ZENMUX_ANTHROPIC_MODEL))
            .expect("valid");
    let (provider, _store) = zenmux_provider(&config);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/zenmux"));
    assert!(
        matches!(outcome, Err(ProviderError::StreamViolation { .. })),
        "a partial tool block never becomes a reply: {outcome:?}"
    );
    drop_blocking(provider);

    // a stop reason the dialect cannot classify
    let server = MockServer::start().await;
    mount_zenmux_messages(
        &server,
        format!(
            "{}{}{}{}",
            message_start(3),
            sse_block(
                "content_block_start",
                &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            ),
            sse_block(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 0}),
            ),
            format!(
                "{}{}",
                sse_block(
                    "message_delta",
                    &json!({"type": "message_delta", "delta": {"stop_reason": "teleport"}, "usage": {"output_tokens": 1}}),
                ),
                sse_block("message_stop", &json!({"type": "message_stop"})),
            ),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&zenmux_config(&zenmux_uri(&server), ZENMUX_ANTHROPIC_MODEL))
            .expect("valid");
    let (provider, _store) = zenmux_provider(&config);
    let (provider, outcome) =
        send_on_thread(provider, prepared_manifest_at(&config, "/world/zenmux"));
    assert!(
        matches!(outcome, Err(ProviderError::UnknownTerminal { .. })),
        "an unknown stop reason is an unknown terminal: {outcome:?}"
    );
    drop_blocking(provider);

    // the usage report repeated with the same figures is one charge
    let server = MockServer::start().await;
    mount_zenmux_messages(
        &server,
        format!(
            "{}{}{}{}{}",
            message_start(4),
            sse_block(
                "content_block_start",
                &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            ),
            sse_block(
                "content_block_delta",
                &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "once"}}),
            ),
            sse_block(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 0}),
            ),
            format!(
                "{}{}{}",
                sse_block(
                    "message_delta",
                    &json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 2}}),
                ),
                sse_block(
                    "message_delta",
                    &json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 2}}),
                ),
                sse_block("message_stop", &json!({"type": "message_stop"})),
            ),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&zenmux_config(&zenmux_uri(&server), ZENMUX_ANTHROPIC_MODEL))
            .expect("valid");
    let (broker, manifest) = prepared_with(
        zenmux_provider(&config),
        &config,
        "/world/zenmux",
        "goal: repeated usage",
    );
    let (broker, outcome) = dispatch(broker, "/world/zenmux", manifest.clone());
    let reply = outcome.expect("the repeated report is one charge");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 4,
            completion_tokens: 2,
            total_tokens: 6,
        }
    );
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted once");
    assert_eq!(record.usage, reply.usage);
    drop_blocking(broker);
}
