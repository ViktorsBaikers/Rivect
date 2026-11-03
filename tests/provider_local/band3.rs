// ----- shared catalogue vocabulary (DEC-007) ------------------------------------

/// The shared catalogue record carries the maximum-output carrier:
/// a stated cap survives the value surface unchanged, an unstated one
/// stays `None`, and `providers.rs` re-exports this same record and
/// its price rather than defining a second copy.
#[test]
fn catalogue_vocabulary_carries_max_output_tokens() {
    use rivect::providers::{CatalogModel as SharedCatalogModel, ModelPrice as SharedModelPrice};

    let entry: SharedCatalogModel = CatalogModel {
        id: "carrier-model".to_string(),
        context_window: Some(262144),
        max_output_tokens: Some(65536),
        price: ModelPrice::Usd {
            input_per_1m: 0.15,
            output_per_1m: 0.6,
        },
        ..CatalogModel::default()
    };
    assert_eq!(
        entry.max_output_tokens,
        Some(65536),
        "the stated maximum-output cap survives the record"
    );
    assert_eq!(
        CatalogModel::default().max_output_tokens,
        None,
        "an unstated maximum-output cap is the default"
    );
    let price: SharedModelPrice = entry.price;
    assert_eq!(
        price,
        ModelPrice::Usd {
            input_per_1m: 0.15,
            output_per_1m: 0.6,
        },
        "the re-exported price names the same record"
    );
}

/// The recorded seed floor keeps every entry byte-for-byte: an empty
/// listing still answers the built-in roster with the same id, vision,
/// effort ladder, context window and price, and the new maximum-output
/// carrier stays `None` because no built-in row states a cap.
#[tokio::test]
async fn existing_catalogue_seeds_keep_their_entries() {
    let server = MockServer::start().await;
    mount_models(&server, vec![]).await;
    let config = Config::parse_validated(&deepseek_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_deepseek_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the recorded seed answers an empty listing");
    drop_blocking(provider);

    let expected: Vec<CatalogModel> = DEEPSEEK_BUILTIN_IDS
        .iter()
        .map(|id| deepseek_expected_model(id))
        .collect();
    assert_eq!(
        models, expected,
        "the seed keeps every recorded id, vision, effort, context and price"
    );
}

// ----- ollama-cloud ------------------------------------------------------------
//
// The `ollama-cloud` connection's proof legs (DEC-001/DEC-018): the native
// `ollama-chat` dialect posts `{base}/api/chat` as newline-delimited JSON
// (never SSE), the catalogue is the key-gated `{base}/api/tags` listing
// enriched by a bounded `/api/show` overlay (DEC-012), and the listing
// ladder retries a retryable status at 2/5/10 s while a send never retries
// (DEC-013). The credential is required — no keyless path exists
// (PROH-010) — and the request carries one system turn and one user turn
// with no history (DEC-015).

use rivect::providers::ToolCall;
use rivect::providers::ollama_cloud::OllamaCloudProvider;
use wiremock::matchers::body_partial_json;

/// The literal connection id this dialect serves.
const OLLAMA_CLOUD: &str = "ollama-cloud";

/// The scoped credential ref the connection binds.
const OLLAMA_CLOUD_REF: &str = "keyring:rivect-test/ollama-cloud";

/// The pinned model id the fixed-pin legs carry.
const OLLAMA_CLOUD_MODEL: &str = "gpt-oss:120b";

/// One configured `ollama-cloud` connection pointing at the fixture
/// peer: the api_key auth class resolves a scoped `SecretRef`
/// (DEC-011), and the literal id decides the native dialect.
fn ollama_cloud_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.\"ollama-cloud\"]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{OLLAMA_CLOUD_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"ollama-cloud\", model_id = \"{OLLAMA_CLOUD_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The native adapter builds on a plain OS thread: reqwest's blocking
/// client owns a shell runtime that must never be dropped inside a
/// tokio context.
fn ollama_cloud_provider_result(
    config: Config,
    connection: String,
    store: Arc<support::MapStore>,
) -> Result<OllamaCloudProvider, ProviderError> {
    std::thread::spawn(move || OllamaCloudProvider::new(&config, &connection, store))
        .join()
        .expect("the provider thread joins")
}

fn ollama_cloud_provider(config: &Config) -> (OllamaCloudProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(OLLAMA_CLOUD_REF, SECRET)],
    ));
    let provider =
        ollama_cloud_provider_result(config.clone(), OLLAMA_CLOUD.to_string(), store.clone())
            .expect("the native adapter builds for the ollama-cloud id");
    (provider, store)
}

/// The same adapter under a pinned whole-call deadline — the budget the
/// ladder and the stream legs share.
fn ollama_cloud_provider_with_deadline(
    config: &Config,
    deadline: Duration,
) -> (OllamaCloudProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(OLLAMA_CLOUD_REF, SECRET)],
    ));
    let provider = std::thread::spawn({
        let config = config.clone();
        let store = store.clone();
        move || OllamaCloudProvider::with_deadline(&config, OLLAMA_CLOUD, store, deadline)
    })
    .join()
    .expect("the provider thread joins")
    .expect("the native adapter builds under the pinned deadline");
    (provider, store)
}

fn ollama_cloud_catalog_result(
    provider: OllamaCloudProvider,
) -> (
    OllamaCloudProvider,
    Result<Vec<CatalogModel>, ProviderError>,
) {
    std::thread::spawn(move || {
        let outcome = provider.catalog();
        (provider, outcome)
    })
    .join()
    .expect("the catalog thread joins")
}

fn ollama_cloud_catalog(provider: OllamaCloudProvider) -> Vec<CatalogModel> {
    let (provider, outcome) = ollama_cloud_catalog_result(provider);
    drop_blocking(provider);
    outcome.expect("the ollama-cloud catalogue answers")
}

/// One native JSONL frame — the recorded newline delimiter.
fn jsonl_frame(frame: &Value) -> String {
    format!("{frame}\n")
}

/// A streamed content frame carrying one assistant delta.
fn jsonl_content(text: &str) -> String {
    jsonl_frame(&json!({
        "message": { "role": "assistant", "content": text },
        "done": false,
    }))
}

/// The `done` chunk carrying the recorded reason and counters.
fn jsonl_done(reason: &str, prompt: u64, completion: u64) -> String {
    jsonl_frame(&json!({
        "message": { "role": "assistant", "content": "" },
        "done": true,
        "done_reason": reason,
        "prompt_eval_count": prompt,
        "eval_count": completion,
    }))
}

async fn mount_ollama_cloud_chat(server: &MockServer, body: String) {
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(server)
        .await;
}

async fn mount_ollama_cloud_tags(server: &MockServer, body: Value) {
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

async fn mount_ollama_cloud_show(server: &MockServer, id: &str, body: Value) {
    mount_ollama_cloud_show_response(server, id, ResponseTemplate::new(200).set_body_json(body))
        .await;
}

/// The same probe answering an arbitrary response — the adverse
/// catalogue legs pin the non-success and malformed shapes.
async fn mount_ollama_cloud_show_response(
    server: &MockServer,
    id: &str,
    response: ResponseTemplate,
) {
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .and(body_partial_json(json!({ "model": id })))
        .respond_with(response)
        .mount(server)
        .await;
}

/// How many recorded requests targeted one path.
fn count_path(requests: &[Request], path: &str) -> usize {
    requests
        .iter()
        .filter(|request| request.url.path() == path)
        .count()
}

/// One native outcome through the real Broker: the configured endpoint
/// carries the recorded `/api` suffix, the adapter strips exactly one
/// before its resource paths, one physical POST answers the JSONL
/// stream, and the `done` chunk's counters are the one accounted usage.
#[tokio::test]
async fn ollama_cloud_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    let stream = format!(
        "{}{}{}",
        jsonl_content("verified native outcome"),
        jsonl_frame(&json!({
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "function": {
                        "name": "read_file",
                        "arguments": { "path": "/world/ollama-cloud/target.txt" },
                    },
                }],
            },
            "done": false,
        })),
        jsonl_done("stop", 13, 5),
    );
    mount_ollama_cloud_chat(&server, stream).await;
    let config =
        Config::parse_validated(&ollama_cloud_config(&format!("  {}/api/  ", server.uri())))
            .expect("valid");
    let (broker, manifest) = prepared_with(
        ollama_cloud_provider(&config),
        &config,
        "/world/ollama-cloud",
        "goal: prove the native wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/ollama-cloud", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified native outcome");
    assert_eq!(
        reply.tool_calls,
        vec![ToolCall {
            tool: "read_file".to_string(),
            path: Some("/world/ollama-cloud/target.txt".to_string()),
        }],
        "the streamed tool call is the typed call"
    );

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request, no send retry");
    assert_eq!(
        requests[0].url.path(),
        "/api/chat",
        "exactly one /api is stripped from the configured base"
    );
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
    assert_eq!(body["model"], json!(OLLAMA_CLOUD_MODEL));
    assert_eq!(body["stream"], json!(true));
    assert_eq!(
        body["messages"],
        json!([
            { "role": "system", "content": manifest.instructions },
            { "role": "user", "content": manifest.inputs },
        ]),
        "the frozen instructions and inputs ride one system and one user turn"
    );
    assert_eq!(
        body["tool_choice"],
        json!("auto"),
        "declared tools ride the recorded auto choice"
    );
    assert_eq!(
        body["think"],
        json!("medium"),
        "the pinned effort rides the recorded native think member"
    );

    // Exactly one accounting record carries the one physical usage
    // report — the `done` chunk's counters sum to the confirmed charge.
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, OLLAMA_CLOUD);
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 13,
            completion_tokens: 5,
            total_tokens: 18,
        }
    );
    let explain = broker.sent_cost_explain(&manifest);
    assert_eq!(explain.confirmed, Some(18));
    drop_blocking(broker);
}

/// The frozen effort is never dropped (AC-040d): a fixed level rides the
/// recorded native `think` member under its own pinned name, and an
/// auto assignment omits the member rather than inventing a level.
#[tokio::test]
async fn ollama_cloud_pinned_effort_rides_the_think_member() {
    let server = MockServer::start().await;
    mount_ollama_cloud_chat(
        &server,
        format!("{}{}", jsonl_content("effort"), jsonl_done("stop", 1, 1)),
    )
    .await;
    let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");
    let (provider, _store) = ollama_cloud_provider(&config);

    let pinned = prepared_manifest(&config);
    assert_eq!(
        pinned.effort,
        rivect::config::EffortAssign::Fixed {
            value: EffortLevel::Medium
        },
        "the fixture pins the recorded medium level"
    );
    let (provider, outcome) = send_on_thread(provider, pinned);
    outcome.expect("the pinned-effort send answers");
    let mut auto = prepared_manifest(&config);
    auto.effort = rivect::config::EffortAssign::Auto;
    let (provider, outcome) = send_on_thread(provider, auto);
    outcome.expect("the auto-effort send answers");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 2, "one physical POST per manifest");
    let pinned: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        pinned["think"],
        json!("medium"),
        "the fixed level rides the native think member verbatim"
    );
    let auto: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert!(
        auto.get("think").is_none(),
        "an auto assignment never fabricates a level"
    );
}

/// A level outside the peer's recorded low/medium/high vocabulary is
/// still transmitted under its pinned name — never coerced onto a lower
/// level — so the peer's rejection is the typed status denial with
/// nothing accounted.
#[tokio::test]
async fn ollama_cloud_effort_beyond_the_native_vocabulary_denies_typed() {
    const EFFORT_REJECTION: &str = "peer-rejects-the-think-level";
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .and(body_partial_json(json!({ "think": "xhigh" })))
        .respond_with(ResponseTemplate::new(400).set_body_string(EFFORT_REJECTION))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");
    let (provider, _store) = ollama_cloud_provider(&config);
    let mut manifest = prepared_manifest(&config);
    manifest.effort = rivect::config::EffortAssign::Fixed {
        value: EffortLevel::Xhigh,
    };

    let (provider, outcome) = send_on_thread(provider, manifest);
    drop_blocking(provider);
    let error = outcome.expect_err("a rejected effort level never reports success");
    assert!(
        matches!(
            &error,
            ProviderError::Transport {
                connection,
                cause: TransportCause::Status { status },
            } if connection == OLLAMA_CLOUD && status.as_u16() == 400
        ),
        "the peer rejection is the typed status denial: {error}"
    );
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(
            !rendered.contains(EFFORT_REJECTION),
            "the peer body never enters diagnostics: {rendered}"
        );
        assert!(
            !rendered.contains(SECRET),
            "diagnostics never carry credential material: {rendered}"
        );
    }
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "one physical POST, no send retry");
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["think"],
        json!("xhigh"),
        "the pinned level crosses the wire under its own name"
    );
}

/// The `/api/chat` non-success branch is the typed status denial: one
/// physical POST, nothing accounted, and the peer's body never renders.
#[tokio::test]
async fn ollama_cloud_chat_non_success_status_denies_without_accounting() {
    const DENIAL_MARKER: &str = "peer-denial-marker";
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(401).set_body_string(DENIAL_MARKER))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");
    let (broker, manifest) = prepared_with(
        ollama_cloud_provider(&config),
        &config,
        "/world/oc-status",
        "goal: non-success chat status",
    );

    let (broker, outcome) = dispatch(broker, "/world/oc-status", manifest);
    let error = outcome.expect_err("a non-success chat status never reports success");
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::Transport {
                connection,
                cause: TransportCause::Status { status },
            }) if connection == OLLAMA_CLOUD && status.as_u16() == 401
        ),
        "the non-success status is the typed transport status: {error}"
    );
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(
            !rendered.contains(DENIAL_MARKER),
            "the peer body never enters diagnostics: {rendered}"
        );
        assert!(
            !rendered.contains(SECRET),
            "diagnostics never carry credential material: {rendered}"
        );
    }
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(count_path(&requests, "/api/chat"), 1, "one physical POST");
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a denied send is never accounted"
    );
    drop_blocking(broker);
}

/// A stream cut mid frame is never success: the JSONL framing needs the
/// newline that closes a frame, and a truncated tail is a typed wire
/// violation with nothing accounted.
#[tokio::test]
async fn ollama_cloud_jsonl_partial_frame_never_reports_success() {
    let server = MockServer::start().await;
    let stream = format!(
        "{}{{\"message\":{{\"content\":\"trunc",
        jsonl_content("partial")
    );
    mount_ollama_cloud_chat(&server, stream).await;
    let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");
    let (broker, manifest) = prepared_with(
        ollama_cloud_provider(&config),
        &config,
        "/world/oc-partial",
        "goal: partial frame",
    );

    let (broker, outcome) = dispatch(broker, "/world/oc-partial", manifest);
    let error = outcome.expect_err("a partial frame never reports success");
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::StreamViolation { connection, reason })
                if connection == OLLAMA_CLOUD && reason == "stream ended mid jsonl frame"
        ),
        "the partial frame is the typed mid-frame violation: {error}"
    );
    assert_eq!(broker.accounted_requests(), 0, "nothing is accounted");
    drop_blocking(broker);
}

/// A `done` reason the dialect cannot classify is never success.
#[tokio::test]
async fn ollama_cloud_unknown_done_reason_never_reports_success() {
    let server = MockServer::start().await;
    mount_ollama_cloud_chat(
        &server,
        format!("{}{}", jsonl_content("maybe"), jsonl_done("safety", 1, 1)),
    )
    .await;
    let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");
    let (broker, manifest) = prepared_with(
        ollama_cloud_provider(&config),
        &config,
        "/world/oc-unknown",
        "goal: unknown terminal",
    );

    let (broker, outcome) = dispatch(broker, "/world/oc-unknown", manifest);
    let error = outcome.expect_err("an unclassifiable done reason is never success");
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::UnknownTerminal { connection })
                if connection == OLLAMA_CLOUD
        ),
        "the unknown reason is the typed unknown terminal: {error}"
    );
    assert_eq!(broker.accounted_requests(), 0, "nothing is accounted");
    drop_blocking(broker);
}

/// The recorded `load` reason is the peer's own failure verdict — a
/// typed provider failure, never a completion.
#[tokio::test]
async fn ollama_cloud_load_reason_is_a_typed_provider_failure() {
    let server = MockServer::start().await;
    mount_ollama_cloud_chat(
        &server,
        format!("{}{}", jsonl_content("loading"), jsonl_done("load", 1, 1)),
    )
    .await;
    let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");
    let (broker, manifest) = prepared_with(
        ollama_cloud_provider(&config),
        &config,
        "/world/oc-load",
        "goal: load reason",
    );

    let (broker, outcome) = dispatch(broker, "/world/oc-load", manifest);
    let error = outcome.expect_err("the load verdict is never success");
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::ProviderFailed { connection, reason })
                if connection == OLLAMA_CLOUD && reason.contains("load")
        ),
        "the load verdict is a typed provider failure: {error}"
    );
    assert_eq!(broker.accounted_requests(), 0, "nothing is accounted");
    drop_blocking(broker);
}

/// A well-formed mid-stream `error` frame is the peer's own failure —
/// the carried reason surfaces, never a success.
#[tokio::test]
async fn ollama_cloud_mid_stream_error_is_a_typed_failure() {
    let server = MockServer::start().await;
    mount_ollama_cloud_chat(
        &server,
        format!(
            "{}{}",
            jsonl_content("partial"),
            jsonl_frame(&json!({
                "error": { "message": "native peer refused the turn" },
            })),
        ),
    )
    .await;
    let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");
    let (broker, manifest) = prepared_with(
        ollama_cloud_provider(&config),
        &config,
        "/world/oc-error",
        "goal: mid-stream error",
    );

    let (broker, outcome) = dispatch(broker, "/world/oc-error", manifest);
    let error = outcome.expect_err("a mid-stream error is never success");
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::ProviderFailed { connection, reason })
                if connection == OLLAMA_CLOUD
                    && reason == "native peer refused the turn"
        ),
        "the frame's own reason is the typed failure: {error}"
    );
    assert_eq!(broker.accounted_requests(), 0, "nothing is accounted");
    drop_blocking(broker);
}

/// The `done` chunk's counters are the physical usage: both halves sum
/// to the total, one record charges it, and the spent attempt never
/// re-sends.
#[tokio::test]
async fn ollama_cloud_usage_from_done_chunk_is_charged_once() {
    let server = MockServer::start().await;
    mount_ollama_cloud_chat(
        &server,
        format!(
            "{}{}",
            jsonl_content("metered"),
            jsonl_done("length", 21, 34)
        ),
    )
    .await;
    let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");
    let (broker, manifest) = prepared_with(
        ollama_cloud_provider(&config),
        &config,
        "/world/oc-usage",
        "goal: usage leg",
    );

    let (broker, outcome) = dispatch(broker, "/world/oc-usage", manifest.clone());
    let reply = outcome.expect("the metered send answers");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 21,
            completion_tokens: 34,
            total_tokens: 55,
        },
        "the done counters sum to the reported total"
    );
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 21,
            completion_tokens: 34,
            total_tokens: 55,
        }
    );
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay = broker.dispatch("/world/oc-usage", &manifest);
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
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        count_path(&requests, "/api/chat"),
        1,
        "the replay denial issues no second physical POST"
    );
}

/// The `done` frame's optional members: an absent `done_reason`
/// completes, and absent counters leave the physical usage `Unknown` —
/// never an estimate.
#[tokio::test]
async fn ollama_cloud_done_frame_carries_what_it_reports() {
    let cases = [
        (
            "no reason",
            jsonl_frame(&json!({
                "message": { "role": "assistant", "content": "no reason" },
                "done": true,
                "prompt_eval_count": 2,
                "eval_count": 3,
            })),
            UsageDelta::Exact {
                prompt_tokens: 2,
                completion_tokens: 3,
                total_tokens: 5,
            },
        ),
        (
            "no counters",
            jsonl_frame(&json!({
                "message": { "role": "assistant", "content": "no counters" },
                "done": true,
                "done_reason": "stop",
            })),
            UsageDelta::Unknown,
        ),
    ];
    for (label, stream, expected) in cases {
        let server = MockServer::start().await;
        mount_ollama_cloud_chat(&server, stream).await;
        let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");
        let (broker, manifest) = prepared_with(
            ollama_cloud_provider(&config),
            &config,
            "/world/oc-done",
            "goal: optional done members",
        );
        let (broker, outcome) = dispatch(broker, "/world/oc-done", manifest.clone());
        let reply =
            outcome.unwrap_or_else(|error| panic!("{label}: the done frame completes: {error}"));
        assert_eq!(
            reply.usage, expected,
            "{label}: the done counters are the only usage source"
        );
        assert_eq!(broker.accounted_requests(), 1, "{label}: one physical usage");
        let record = broker
            .accounting_record(&manifest.attempt_id)
            .expect("the send is accounted");
        assert_eq!(
            record.usage, expected,
            "{label}: the record carries the reported usage"
        );
        drop_blocking(broker);
    }
}

/// The native class has no keyless path: the api_key ingress refuses an
/// unbound declaration, and a local-kind declaration the ingress admits
/// still fails the adapter build before any wire leg (PROH-010).
#[tokio::test]
async fn ollama_cloud_keyless_send_denies_before_any_request() {
    let keyless = format!(
        "config_version = 1\n\
         [connections.\"ollama-cloud\"]\nkind = \"api_key\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"ollama-cloud\", model_id = \"{OLLAMA_CLOUD_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    );
    let error = Config::parse_validated(&keyless).expect_err("a keyless api_key row is refused");
    assert!(
        matches!(
            &error.issue,
            ConfigIssue::CredentialRefRequired { kind }
                if *kind == rivect::config::ConnKind::ApiKey
        ),
        "the ingress denial names the missing binding: {error}"
    );

    // The ingress admits the `local` kind, but the native class still
    // requires its bearer: the adapter build denies before any request.
    let server = MockServer::start().await;
    mount_ollama_cloud_chat(&server, jsonl_done("stop", 1, 1)).await;
    mount_ollama_cloud_tags(&server, json!({ "models": [] })).await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.\"ollama-cloud\"]\nkind = \"local\"\nendpoint = \"{}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"ollama-cloud\", model_id = \"{OLLAMA_CLOUD_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n",
        server.uri()
    ))
    .expect("the local declaration is admitted");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let error = ollama_cloud_provider_result(config, OLLAMA_CLOUD.to_string(), store)
        .expect_err("the native class requires its binding");
    assert!(
        matches!(error, ProviderError::CredentialUnresolved { .. }),
        "the build denial is the typed unresolved binding: {error}"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert!(
        requests.is_empty(),
        "no keyless path ever reaches the wire: {} requests",
        requests.len()
    );
}

/// The listing ladder recovers from one retryable status at the first
/// recorded 2 s rung: one successful listing, one show fanout, and no
/// chat POST from the retry — a later send still issues exactly one
/// physical POST (DEC-013). Both recorded retryable codes take the same
/// path.
#[tokio::test]
async fn ollama_cloud_tags_retry_recovers_with_one_listing() {
    for status in [503u16, 429u16] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(status))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        // The one successful listing — the retryable answer above is
        // served exactly once, so this mock proves the recovery.
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "models": [{ "name": "retry-model", "model": "retry-model" }],
            })))
            .expect(1)
            .mount(&server)
            .await;
        mount_ollama_cloud_show(
            &server,
            "retry-model",
            json!({ "capabilities": ["completion"] }),
        )
        .await;
        mount_ollama_cloud_chat(
            &server,
            format!(
                "{}{}",
                jsonl_content("after retry"),
                jsonl_done("stop", 3, 4)
            ),
        )
        .await;
        let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");

        let started = Instant::now();
        let models = ollama_cloud_catalog(ollama_cloud_provider(&config).0);
        let elapsed = started.elapsed();
        assert_eq!(
            model_ids(&models),
            vec!["retry-model"],
            "{status}: the recovered listing is the offer set"
        );
        assert!(
            (Duration::from_secs(2)..Duration::from_secs(4)).contains(&elapsed),
            "{status}: the first rung is the recorded 2 s wait, got {elapsed:?}"
        );

        let requests = server.received_requests().await.expect("recorded");
        assert_eq!(
            count_path(&requests, "/api/tags"),
            2,
            "{status}: one retryable answer, then one successful listing"
        );
        assert_eq!(
            count_path(&requests, "/api/show"),
            1,
            "{status}: the successful listing fans out once"
        );
        assert_eq!(
            count_path(&requests, "/api/chat"),
            0,
            "{status}: the ladder is listing-only"
        );

        let (provider, _store) = ollama_cloud_provider(&config);
        let manifest = prepared_manifest(&config);
        let (provider, outcome) = send_on_thread(provider, manifest);
        assert_eq!(outcome.expect("the send answers").text, "after retry");
        drop_blocking(provider);
        let requests = server.received_requests().await.expect("recorded");
        assert_eq!(
            count_path(&requests, "/api/chat"),
            1,
            "{status}: one physical POST, no send retry"
        );
    }
}

/// A ladder rung that cannot finish inside the whole-call budget is the
/// typed deadline denial — no offer is invented, no show fanout runs,
/// the 17 s ladder is never slept, and each recorded retryable code
/// takes the same path.
#[tokio::test]
async fn ollama_cloud_tags_retry_then_denies_without_a_floor() {
    for status in [503u16, 429u16] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(status))
            .expect(1)
            .mount(&server)
            .await;
        let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");
        let (provider, _store) =
            ollama_cloud_provider_with_deadline(&config, Duration::from_millis(500));

        let started = Instant::now();
        let (provider, outcome) = ollama_cloud_catalog_result(provider);
        let elapsed = started.elapsed();
        drop_blocking(provider);
        let error = outcome.expect_err("a retry that cannot finish inside the budget denies");
        assert!(
            matches!(
                &error,
                ProviderError::Transport {
                    connection,
                    cause: TransportCause::Deadline { .. },
                } if connection == OLLAMA_CLOUD
            ),
            "{status}: the denial is the typed deadline: {error}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "{status}: the first rung is never slept when it cannot fit, got {elapsed:?}"
        );

        let requests = server.received_requests().await.expect("recorded");
        assert_eq!(
            count_path(&requests, "/api/tags"),
            1,
            "{status}: one listing attempt, never a slept rung"
        );
        assert_eq!(
            count_path(&requests, "/api/show"),
            0,
            "{status}: a denied listing never fans out"
        );
        assert_eq!(count_path(&requests, "/api/chat"), 0, "{status}: no send");
    }
}

/// A non-retryable listing denial and a malformed listing payload are
/// each the typed denial with no offers, no show fanout and no chat POST
/// — an unreadable listing never seeds a catalogue.
#[tokio::test]
async fn ollama_cloud_tags_denials_offer_nothing() {
    // A non-retryable status is the typed transport status.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;
    let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");
    let (provider, _store) = ollama_cloud_provider(&config);
    let (provider, outcome) = ollama_cloud_catalog_result(provider);
    drop_blocking(provider);
    let error = outcome.expect_err("a denied listing never answers a catalogue");
    assert!(
        matches!(
            &error,
            ProviderError::Transport {
                connection,
                cause: TransportCause::Status { status },
            } if connection == OLLAMA_CLOUD && status.as_u16() == 401
        ),
        "the non-retryable listing denial is the typed status: {error}"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        count_path(&requests, "/api/tags"),
        1,
        "a non-retryable status is never retried"
    );
    assert_eq!(count_path(&requests, "/api/show"), 0, "no offers, no fanout");
    assert_eq!(count_path(&requests, "/api/chat"), 0);

    // Both malformed listing shapes are the typed wire violation.
    for (body, denied) in [
        ("not json".to_string(), "tags payload is not json"),
        ("{}".to_string(), "tags payload carries no models array"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;
        let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");
        let (provider, _store) = ollama_cloud_provider(&config);
        let (provider, outcome) = ollama_cloud_catalog_result(provider);
        drop_blocking(provider);
        let error = outcome.expect_err("a malformed listing never answers a catalogue");
        assert!(
            matches!(
                &error,
                ProviderError::StreamViolation { connection, reason }
                    if connection == OLLAMA_CLOUD && reason == denied
            ),
            "{denied}: the listing shape is the typed violation: {error}"
        );
        let requests = server.received_requests().await.expect("recorded");
        assert_eq!(
            count_path(&requests, "/api/show"),
            0,
            "{denied}: no offers, no fanout"
        );
    }
}

/// The request carries no conversation history: exactly one system turn
/// and one user turn, no assistant member, and no request-side
/// max-token field (DEC-015).
#[tokio::test]
async fn ollama_cloud_request_carries_no_history() {
    let server = MockServer::start().await;
    mount_ollama_cloud_chat(
        &server,
        format!("{}{}", jsonl_content("history"), jsonl_done("stop", 1, 1)),
    )
    .await;
    let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");
    let (provider, _store) = ollama_cloud_provider(&config);
    let manifest = prepared_manifest(&config);
    let (provider, outcome) = send_on_thread(provider, manifest.clone());
    assert_eq!(outcome.expect("the send answers").text, "history");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["messages"],
        json!([
            { "role": "system", "content": manifest.instructions },
            { "role": "user", "content": manifest.inputs },
        ]),
        "exactly one system turn and one user turn"
    );
    let messages = body["messages"].as_array().expect("messages array");
    assert!(
        messages
            .iter()
            .all(|message| message["role"] != json!("assistant")),
        "no assistant history member rides the request"
    );
    assert!(body.get("history").is_none(), "no history carrier exists");
    for member in ["num_predict", "max_tokens", "options"] {
        assert!(
            body.get(member).is_none(),
            "the request carries no {member} member"
        );
    }
}

/// Declared tools ride `tool_choice: "auto"`; a request with no declared
/// tool surface carries neither member (DEC-015/D12).
#[tokio::test]
async fn ollama_cloud_tools_ride_auto_choice() {
    let server = MockServer::start().await;
    mount_ollama_cloud_chat(
        &server,
        format!("{}{}", jsonl_content("tools"), jsonl_done("stop", 1, 1)),
    )
    .await;
    let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");
    let (provider, _store) = ollama_cloud_provider(&config);

    let with_tools = prepared_manifest(&config);
    assert_eq!(
        with_tools.tools,
        vec!["read_file".to_string()],
        "the frozen manifest carries the declared surface"
    );
    let (provider, outcome) = send_on_thread(provider, with_tools);
    outcome.expect("the tooled send answers");
    let mut bare = prepared_manifest(&config);
    bare.tools.clear();
    let (provider, outcome) = send_on_thread(provider, bare);
    outcome.expect("the bare send answers");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 2, "one physical POST per manifest");
    let tooled: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        tooled["tools"],
        json!([{ "type": "function", "function": { "name": "read_file" } }]),
        "the declared tool surface rides verbatim"
    );
    assert_eq!(
        tooled["tool_choice"],
        json!("auto"),
        "the recorded auto choice rides the tools"
    );
    let bare: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert!(
        bare.get("tools").is_none(),
        "no tools member without a declared surface"
    );
    assert!(
        bare.get("tool_choice").is_none(),
        "no tool_choice without tools"
    );
}

/// One enriched entry in the exact shape the recorded mapping states.
fn ollama_cloud_entry(
    id: &str,
    reasoning: bool,
    vision: bool,
    efforts: Vec<EffortLevel>,
    context_window: u64,
    max_output_tokens: u64,
) -> CatalogModel {
    CatalogModel {
        id: id.to_string(),
        reasoning,
        vision,
        efforts,
        effort_default: None,
        context_window: Some(context_window),
        max_output_tokens: Some(max_output_tokens),
        price: ModelPrice::Unknown,
    }
}

/// The catalogue maps the recorded fields exactly: `capabilities` →
/// reasoning/vision, the first positive context key with the 128000
/// default, the per-id max-output figure, the GLM ≥5.2 single-high
/// ladder against the `minimal…high` default, and no chat filter.
#[tokio::test]
async fn ollama_cloud_catalog_maps_the_recorded_fields() {
    let server = MockServer::start().await;
    mount_ollama_cloud_tags(
        &server,
        json!({
            "models": [
                { "name": "deepseek-v4-flash" },
                { "name": "deepseek-v4-pro" },
                { "name": "embed-only" },
                { "name": "glm-5.1" },
                { "name": "glm-5.2" },
                { "name": "plain-chat" },
                { "name": "window-order" },
            ],
        }),
    )
    .await;
    mount_ollama_cloud_show(
        &server,
        "deepseek-v4-flash",
        json!({
            "capabilities": ["completion", "thinking"],
            "model_info": { "deepseek.context_length": 1000000 },
        }),
    )
    .await;
    mount_ollama_cloud_show(
        &server,
        "deepseek-v4-pro",
        json!({
            "capabilities": ["thinking"],
            "num_ctx": 65536,
        }),
    )
    .await;
    mount_ollama_cloud_show(
        &server,
        "embed-only",
        json!({ "capabilities": ["embedding"] }),
    )
    .await;
    mount_ollama_cloud_show(
        &server,
        "glm-5.1",
        json!({
            "capabilities": ["thinking"],
            "context_window": 131072,
        }),
    )
    .await;
    mount_ollama_cloud_show(
        &server,
        "glm-5.2",
        json!({
            "capabilities": ["thinking", "vision"],
            "model_info": { "zai.context_length": 200000 },
        }),
    )
    .await;
    mount_ollama_cloud_show(
        &server,
        "plain-chat",
        json!({ "capabilities": ["completion"] }),
    )
    .await;
    mount_ollama_cloud_show(
        &server,
        "window-order",
        json!({ "model_info": { "a.context_length": 0, "b.context_length": 4096 } }),
    )
    .await;
    let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");

    let models = ollama_cloud_catalog(ollama_cloud_provider(&config).0);
    let ladder = vec![
        EffortLevel::Minimal,
        EffortLevel::Low,
        EffortLevel::Medium,
        EffortLevel::High,
    ];
    let expected = vec![
        ollama_cloud_entry(
            "deepseek-v4-flash",
            true,
            false,
            ladder.clone(),
            1_000_000,
            65_536,
        ),
        ollama_cloud_entry(
            "deepseek-v4-pro",
            true,
            false,
            ladder.clone(),
            65_536,
            65_536,
        ),
        ollama_cloud_entry("embed-only", false, false, Vec::new(), 128_000, 8_192),
        ollama_cloud_entry("glm-5.1", true, false, ladder, 131_072, 8_192),
        ollama_cloud_entry(
            "glm-5.2",
            true,
            true,
            vec![EffortLevel::High],
            200_000,
            8_192,
        ),
        ollama_cloud_entry("plain-chat", false, false, Vec::new(), 128_000, 8_192),
        ollama_cloud_entry("window-order", false, false, Vec::new(), 4_096, 4_096),
    ];
    assert_eq!(
        models, expected,
        "every recorded field maps exactly, and no chat filter drops an id"
    );

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(count_path(&requests, "/api/tags"), 1);
    assert_eq!(
        count_path(&requests, "/api/show"),
        7,
        "every listed id is probed once"
    );
    for request in &requests {
        assert_eq!(
            received_auth(request),
            format!("Bearer {SECRET}"),
            "every catalogue request is key-gated: {}",
            request.url.path()
        );
    }
}

/// The `/api/show` fanout is bounded: at most 32 listed ids are probed,
/// and a slow peer spends the advisory phase so the entries stay
/// listing-only inside it — never a late enriched catalogue.
#[tokio::test]
async fn ollama_cloud_show_fanout_phase_budget_bounds_the_roster() {
    // 40 listed ids: the listing offers all of them, the phase probes
    // only the leading 32.
    let server = MockServer::start().await;
    let ids: Vec<Value> = (0..40)
        .map(|index| json!({ "name": format!("model-{index:02}") }))
        .collect();
    mount_ollama_cloud_tags(&server, json!({ "models": ids })).await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");

    let models = ollama_cloud_catalog(ollama_cloud_provider(&config).0);
    assert_eq!(models.len(), 40, "the listing is the offer set");
    let requests = server.received_requests().await.expect("recorded");
    let shows = count_path(&requests, "/api/show");
    assert!(
        shows <= 32,
        "the probe fanout never passes 32 listed ids, got {shows}"
    );

    // A slow `/api/show` peer spends the advisory phase: the catalogue
    // still answers its listing, every entry stays listing-only, and
    // the phase never waits for the peer.
    let server = MockServer::start().await;
    mount_ollama_cloud_tags(
        &server,
        json!({ "models": [{ "name": "slow-a" }, { "name": "slow-b" }] }),
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(1))
                .set_body_json(json!({
                    "capabilities": ["thinking", "vision"],
                    "model_info": { "slow.context_length": 65536 },
                })),
        )
        .mount(&server)
        .await;
    let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");

    let started = Instant::now();
    let models = ollama_cloud_catalog(ollama_cloud_provider(&config).0);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "the advisory phase ends well before the slow peer, got {elapsed:?}"
    );
    assert_eq!(model_ids(&models), vec!["slow-a", "slow-b"]);
    assert!(
        models.iter().all(|model| model.context_window.is_none()
            && model.max_output_tokens.is_none()
            && model.efforts.is_empty()),
        "an expired phase leaves listing-only entries: {models:?}"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        count_path(&requests, "/api/show"),
        1,
        "the expired phase never fans out further"
    );
}

/// Every `/api/show` failure is non-fatal (DEC-012): a non-success
/// status, a malformed body, a non-object body and a body past the
/// catalogue byte bound each leave the catalogue `Ok` with that id's
/// listing-only surface.
#[tokio::test]
async fn ollama_cloud_show_failures_leave_listing_only_entries() {
    let server = MockServer::start().await;
    mount_ollama_cloud_tags(
        &server,
        json!({
            "models": [
                { "name": "show-500" },
                { "name": "show-bad-json" },
                { "name": "show-array" },
                { "name": "show-huge" },
            ],
        }),
    )
    .await;
    mount_ollama_cloud_show_response(
        &server,
        "show-500",
        ResponseTemplate::new(500).set_body_string("peer-failure-marker"),
    )
    .await;
    mount_ollama_cloud_show_response(
        &server,
        "show-bad-json",
        ResponseTemplate::new(200).set_body_string("not json"),
    )
    .await;
    mount_ollama_cloud_show_response(
        &server,
        "show-array",
        ResponseTemplate::new(200).set_body_json(json!([1, 2])),
    )
    .await;
    // Past the shared catalogue byte bound: the read denies, and the
    // advisory overlay treats it like every other failed probe.
    mount_ollama_cloud_show_response(
        &server,
        "show-huge",
        ResponseTemplate::new(200).set_body_json(json!({ "pad": "x".repeat(1024 * 1024 + 1) })),
    )
    .await;
    let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");

    let models = ollama_cloud_catalog(ollama_cloud_provider(&config).0);
    assert_eq!(
        model_ids(&models),
        vec!["show-500", "show-array", "show-bad-json", "show-huge"],
        "a failed probe never drops or replaces a listed id"
    );
    assert!(
        models.iter().all(|model| model.context_window.is_none()
            && model.max_output_tokens.is_none()
            && !model.reasoning
            && !model.vision
            && model.efforts.is_empty()),
        "every failed probe leaves that entry listing-only: {models:?}"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        count_path(&requests, "/api/show"),
        4,
        "every listed id is probed once"
    );
}

/// The advisory phase is one total clip, not a per-request reset: two
/// listed ids whose `/api/show` answers each take 150 ms share the
/// 250 ms phase, so the first enriches and the second is clipped — a
/// per-request clock would enrich both.
#[tokio::test]
async fn ollama_cloud_show_phase_clips_the_second_probe() {
    let server = MockServer::start().await;
    mount_ollama_cloud_tags(
        &server,
        json!({ "models": [{ "name": "clip-a" }, { "name": "clip-b" }] }),
    )
    .await;
    for id in ["clip-a", "clip-b"] {
        Mock::given(method("POST"))
            .and(path("/api/show"))
            .and(body_partial_json(json!({ "model": id })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(150))
                    .set_body_json(json!({
                        "capabilities": ["thinking"],
                        "model_info": { "clip.context_length": 65536 },
                    })),
            )
            .mount(&server)
            .await;
    }
    let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");

    let models = ollama_cloud_catalog(ollama_cloud_provider(&config).0);
    assert_eq!(model_ids(&models), vec!["clip-a", "clip-b"]);
    let first = &models[0];
    assert_eq!(
        first.context_window,
        Some(65_536),
        "the first probe fits the phase"
    );
    assert_eq!(first.max_output_tokens, Some(8_192));
    assert!(first.reasoning);
    let second = &models[1];
    assert!(
        second.context_window.is_none()
            && second.max_output_tokens.is_none()
            && !second.reasoning
            && second.efforts.is_empty(),
        "the phase clips the second probe: {second:?}"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        count_path(&requests, "/api/show"),
        2,
        "both listed ids are attempted, the second under the phase remainder"
    );
}

/// The Broker's auto assignment narrows to this connection's pool of
/// one, and the adapter resolves the deterministic sorted-first listed
/// id as the wire model — the recorded auto semantic, never a config
/// pin and never an unlisted id.
#[tokio::test]
async fn ollama_cloud_auto_pick_resolves_the_sorted_first_listed_id() {
    let server = MockServer::start().await;
    mount_ollama_cloud_tags(
        &server,
        json!({ "models": [{ "name": "zeta-model" }, { "name": "alpha-model" }] }),
    )
    .await;
    mount_ollama_cloud_chat(
        &server,
        format!("{}{}", jsonl_content("auto"), jsonl_done("stop", 1, 1)),
    )
    .await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.\"ollama-cloud\"]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{OLLAMA_CLOUD_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n",
        server.uri()
    ))
    .expect("valid");
    let (broker, manifest) = prepared_with(
        ollama_cloud_provider(&config),
        &config,
        "/world/oc-auto",
        "goal: auto pick",
    );

    let (broker, outcome) = dispatch(broker, "/world/oc-auto", manifest);
    assert_eq!(outcome.expect("the auto pick dispatches").text, "auto");
    let requests = server.received_requests().await.expect("recorded");
    let chat: Vec<&Request> = requests
        .iter()
        .filter(|request| request.url.path() == "/api/chat")
        .collect();
    assert_eq!(chat.len(), 1, "one physical POST");
    let body: Value = serde_json::from_slice(&chat[0].body).expect("json body");
    assert_eq!(
        body["model"],
        json!("alpha-model"),
        "the sorted-first listed id is the wire model"
    );
    drop_blocking(broker);
}

/// An empty listing leaves the auto assignment unpinnable: the recorded
/// auto pick has no id to name, so the send is the typed
/// [`ProviderError::UnpinnedModel`] denial with no chat POST and nothing
/// accounted.
#[tokio::test]
async fn ollama_cloud_auto_pick_denies_on_an_empty_listing() {
    let server = MockServer::start().await;
    mount_ollama_cloud_tags(&server, json!({ "models": [] })).await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.\"ollama-cloud\"]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{OLLAMA_CLOUD_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n",
        server.uri()
    ))
    .expect("valid");
    let (broker, manifest) = prepared_with(
        ollama_cloud_provider(&config),
        &config,
        "/world/oc-auto-empty",
        "goal: empty auto listing",
    );

    let (broker, outcome) = dispatch(broker, "/world/oc-auto-empty", manifest);
    let error = outcome.expect_err("an empty listing never pins a model");
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::UnpinnedModel { connection })
                if connection == OLLAMA_CLOUD
        ),
        "the empty listing is the typed unpinned denial: {error}"
    );
    assert_eq!(broker.accounted_requests(), 0, "nothing is accounted");
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(count_path(&requests, "/api/tags"), 1, "one listing leg");
    assert_eq!(
        count_path(&requests, "/api/chat"),
        0,
        "an invented model never reaches the wire"
    );
    drop_blocking(broker);
}

/// The native dialect is keyed on the literal connection id: the map
/// reserves `ollama-cloud`, the sibling adapters refuse it, the native
/// adapter refuses every sibling id, and loopback never serves it.
#[test]
fn ollama_cloud_dialect_is_keyed_on_the_literal_connection_id() {
    assert_eq!(
        rivect::providers::dialect_for(OLLAMA_CLOUD),
        Some(rivect::providers::Dialect::OllamaChat)
    );
    assert_eq!(
        rivect::providers::Dialect::OllamaChat.to_string(),
        "ollama-chat"
    );
    let config = Config::parse_validated(&ollama_cloud_config("http://127.0.0.1:1"))
        .expect("the fixture config is valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));

    // The sibling adapters refuse the native id.
    let err = provider_result(config.clone(), OLLAMA_CLOUD.to_string(), store.clone())
        .expect_err("the Chat Completions adapter refuses the native id");
    assert!(
        matches!(err, ProviderError::DialectMismatch { .. }),
        "the CC adapter refuses the native id: {err}"
    );
    let err = std::thread::spawn({
        let config = config.clone();
        let store = store.clone();
        move || OpenAiProvider::new(&config, OLLAMA_CLOUD, store)
    })
    .join()
    .expect("the provider thread joins")
    .expect_err("the Responses adapter refuses the native id");
    assert!(
        matches!(err, ProviderError::DialectMismatch { .. }),
        "the Responses adapter refuses the native id: {err}"
    );

    // The native adapter refuses every sibling id.
    for id in ["ollama", "openai", "deepseek", "google"] {
        let err = ollama_cloud_provider_result(config.clone(), id.to_string(), store.clone())
            .expect_err("a sibling id is not the native dialect");
        assert!(
            matches!(err, ProviderError::DialectMismatch { .. }),
            "{id} is refused typed: {err}"
        );
    }

    // A configured region is denied — never silently ignored.
    let regional = Config::parse_validated(&ollama_cloud_config("https://ollama.com").replace(
        "credential_ref = \"",
        "region = \"eu\"\ncredential_ref = \"",
    ))
    .expect("a configured region is a valid declaration");
    let err = ollama_cloud_provider_result(
        regional,
        OLLAMA_CLOUD.to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a configured region is outside the native endpoint contract");
    assert!(
        matches!(err, ProviderError::RegionMismatch { .. }),
        "the region denial is typed: {err}"
    );

    // Loopback never serves the reserved id.
    let local = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.\"ollama-cloud\"]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"ollama-cloud\", model_id = \"{OLLAMA_CLOUD_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the local declaration is admitted");
    let entry = local.connections.get(OLLAMA_CLOUD).expect("declared");
    let loopback = rivect::providers::LoopbackProvider::new();
    assert!(
        !loopback.serves(OLLAMA_CLOUD, entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );

    // The native adapter serves only its own literal id.
    let (provider, _store) = ollama_cloud_provider(&config);
    let entry = config.connections.get(OLLAMA_CLOUD).expect("declared");
    assert!(provider.serves(OLLAMA_CLOUD, entry));
    assert!(!provider.serves("ollama", entry));
    drop_blocking(provider);
}

/// One adverse stream through the real Broker: the outcome must be the
/// typed denial and nothing may be accounted.
async fn ollama_cloud_adverse_denial(stream: String) -> (ModelError, usize) {
    let server = MockServer::start().await;
    mount_ollama_cloud_chat(&server, stream).await;
    let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");
    let (broker, manifest) = prepared_with(
        ollama_cloud_provider(&config),
        &config,
        "/world/oc-adverse",
        "goal: adverse wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/oc-adverse", manifest);
    let error = outcome.expect_err("adverse wire input never reports success");
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(
            !rendered.contains(SECRET),
            "diagnostics never carry credential material: {rendered}"
        );
    }
    let accounted = broker.accounted_requests();
    drop_blocking(broker);
    (error, accounted)
}

/// Adverse wire input never reports success: a non-JSON frame, a
/// non-object frame, an oversized frame, an over-bound tool-call set and
/// a tool call the frozen request never declared are each a typed denial
/// with nothing accounted. Each malformed stream still carries a valid
/// terminal afterwards, so ignoring the defect would show success.
#[tokio::test]
async fn ollama_cloud_adverse_wire_input_never_reports_success() {
    // A frame that is not JSON at all, followed by a valid terminal.
    let (error, accounted) = ollama_cloud_adverse_denial(format!(
        "{}\nnot json\n{}",
        jsonl_content("text"),
        jsonl_done("stop", 1, 1)
    ))
    .await;
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::StreamViolation { connection, reason })
                if connection == OLLAMA_CLOUD && reason == "jsonl frame is not json"
        ),
        "a non-JSON frame is the typed parse violation the terminal cannot mask: {error}"
    );
    assert_eq!(accounted, 0);

    // A well-formed frame that is not an object.
    let (error, accounted) = ollama_cloud_adverse_denial(format!(
        "{}\n[1, 2]\n{}",
        jsonl_content("text"),
        jsonl_done("stop", 1, 1)
    ))
    .await;
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::StreamViolation { connection, reason })
                if connection == OLLAMA_CLOUD && reason == "jsonl frame is not an object"
        ),
        "a non-object frame is the typed shape violation: {error}"
    );
    assert_eq!(accounted, 0);

    // A frame past the recorded byte bound, with a valid terminal after.
    let oversized = format!(
        "{}\n{}",
        "x".repeat(1024 * 1024 + 1),
        jsonl_done("stop", 1, 1)
    );
    let (error, accounted) = ollama_cloud_adverse_denial(oversized).await;
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::StreamViolation { connection, reason })
                if connection == OLLAMA_CLOUD && reason == "jsonl frame exceeds the byte bound"
        ),
        "an oversized frame is the typed byte-bound violation: {error}"
    );
    assert_eq!(accounted, 0);

    // One frame carrying more tool calls than the shared bound.
    let calls: Vec<Value> = (0..33)
        .map(|_| {
            json!({
                "function": {
                    "name": "read_file",
                    "arguments": { "path": "/world/oc-adverse/over.txt" },
                },
            })
        })
        .collect();
    let (error, accounted) = ollama_cloud_adverse_denial(format!(
        "{}{}",
        jsonl_frame(&json!({
            "message": { "role": "assistant", "content": "", "tool_calls": calls },
            "done": false,
        })),
        jsonl_done("tool_calls", 1, 1)
    ))
    .await;
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::StreamViolation { connection, reason })
                if connection == OLLAMA_CLOUD
                    && reason == "stream carried more tool calls than the bound"
        ),
        "a 33-call frame is the typed tool-call bound violation: {error}"
    );
    assert_eq!(accounted, 0);

    // A tool call the frozen request never declared is never executed.
    let (error, accounted) = ollama_cloud_adverse_denial(format!(
        "{}{}{}",
        jsonl_content("tools"),
        jsonl_frame(&json!({
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "function": {
                        "name": "write_file",
                        "arguments": { "path": "/world/oc-adverse/out.txt" },
                    },
                }],
            },
            "done": false,
        })),
        jsonl_done("tool_calls", 2, 2),
    ))
    .await;
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::IncompatibleOutput { connection, .. })
                if connection == OLLAMA_CLOUD
        ),
        "an undeclared tool call is a typed rejection: {error}"
    );
    assert_eq!(accounted, 0);
}

/// A stalled peer past the whole-call deadline is the typed deadline
/// denial: the adapter's own budget check ends the send before the
/// client backstop, and nothing is accounted.
#[tokio::test]
async fn ollama_cloud_send_deadline_expiry_is_a_typed_denial() {
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the stalled peer");
    let address = listener.local_addr().expect("peer address");
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the send connects");
        let mut scratch = [0u8; 8192];
        let _read = stream.read(&mut scratch);
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: close\r\n\r\n",
            )
            .expect("the response headers");
        stream
            .write_all(
                jsonl_frame(&json!({
                    "message": { "role": "assistant", "content": "stalled" },
                    "done": false,
                }))
                .as_bytes(),
            )
            .expect("the first frame");
        // Dribble bytes so every read returns and only the total clock
        // can end the stream; the client closes at the deadline.
        for _ in 0..20 {
            if stream.write_all(b" ").is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    let config =
        Config::parse_validated(&ollama_cloud_config(&format!("http://{address}"))).expect("valid");
    let (broker, manifest) = prepared_with(
        ollama_cloud_provider_with_deadline(&config, Duration::from_millis(200)),
        &config,
        "/world/oc-deadline",
        "goal: stalled peer",
    );
    let started = Instant::now();
    let (broker, outcome) = dispatch(broker, "/world/oc-deadline", manifest);
    let elapsed = started.elapsed();
    peer.join().expect("the stalled peer ends");

    let error = outcome.expect_err("a stalled peer never reports success");
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::Transport {
                connection,
                cause: TransportCause::Deadline { .. },
            }) if connection == OLLAMA_CLOUD
        ),
        "the denial is the adapter's typed deadline: {error}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "the budget, not the client backstop, ends the send, got {elapsed:?}"
    );
    assert_eq!(broker.accounted_requests(), 0, "nothing is accounted");
    drop_blocking(broker);
}

/// The legs matrix enforces the recorded expected set for
/// `ollama-cloud`: CATALOG, AUTH, WIRE and RECOVERY each execute and
/// report inside this run, and INSTALLED reports NOT_RUN.
#[tokio::test]
async fn ollama_cloud_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    mount_ollama_cloud_tags(
        &server,
        json!({ "models": [{ "name": OLLAMA_CLOUD_MODEL }] }),
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/api/show"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    mount_ollama_cloud_chat(
        &server,
        format!("{}{}", jsonl_content("matrix"), jsonl_done("stop", 1, 1)),
    )
    .await;
    let config = Config::parse_validated(&ollama_cloud_config(&server.uri())).expect("valid");

    // CATALOG: the listing plus the bounded native overlay.
    let models = ollama_cloud_catalog(ollama_cloud_provider(&config).0);
    reported.insert(
        "CATALOG",
        if model_ids(&models) == vec![OLLAMA_CLOUD_MODEL] {
            "PASS"
        } else {
            "FAIL"
        },
    );

    // AUTH: a bound ref with no store material denies typed.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        ollama_cloud_provider_result(config.clone(), OLLAMA_CLOUD.to_string(), empty.clone())
            .expect("the binding resolves");
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
        ollama_cloud_provider(&config),
        &config,
        "/world/ollama-cloud",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/ollama-cloud", manifest);
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
    let provider =
        ollama_cloud_provider_result(config.clone(), OLLAMA_CLOUD.to_string(), empty.clone())
            .expect("the binding resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(OLLAMA_CLOUD_REF, SECRET.as_bytes());
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

// ----- TP-PROVIDER-INSTALLED::ollama-cloud --------------------------------

/// TP-PROVIDER-INSTALLED::ollama-cloud = NOT_RUN: the
/// installed-provider proof is a live-environment leg this offline
/// slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::ollama-cloud = NOT_RUN"]
fn provider_installed_ollama_cloud() {}

// ----- qianfan ---------------------------------------------------------------

// The `qianfan` connection's proof legs (HZN-008 class B — the api-key
// cell): the shared Chat Completions adapter serves the literal id — no
// copied codec — under its own recorded predicates. The configured
// `endpoint` carries the API base verbatim, an empty one resolves the
// recorded `https://qianfan.baidubce.com/v2` default, and a configured
// `region` is denied: the contract names none. The api-key class gates
// the `/models` listing on resolved material, the listing is the whole
// catalogue — no seed, no fallback floor — and its `data[]` rows carry
// the id plus `context_length` and `max_completion_tokens` when present.
// The recorded `deepseek-v3.2` default is a catalogue hint, never a
// seeded offer and never a ranking: the auto pick stays sorted-first
// (DEC-014/D11).

/// The literal connection id this class serves.
const QIANFAN: &str = "qianfan";

/// The scoped credential ref the connection binds.
const QIANFAN_REF: &str = "keyring:rivect-test/qianfan";

/// Fixture `qianfan` key material — never a real credential, only ever
/// sent to localhost.
const QIANFAN_KEY: &str = "fixture-qianfan-key";

/// The pinned model id the fixed-pin legs carry — a listed id.
const QIANFAN_MODEL: &str = "deepseek-v3.2";

/// One configured `qianfan` connection pointing at the fixture peer:
/// the api_key auth class resolves a scoped `SecretRef` (DEC-011), the
/// dialect comes from the literal connection id (DEC-007), and the
/// endpoint carries the API base verbatim.
fn qianfan_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.qianfan]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{QIANFAN_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"qianfan\", model_id = \"{QIANFAN_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"high\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The recorded `/v2` API root over the fixture peer.
fn qianfan_uri(server: &MockServer) -> String {
    format!("{}/v2", server.uri())
}

fn qianfan_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(QIANFAN_REF, material)],
    ));
    let provider = provider_result(config.clone(), QIANFAN.to_string(), store.clone())
        .expect("the shared adapter builds for the qianfan id");
    (provider, store)
}

/// The `qianfan` provider over the recorded enrolled key.
fn enrolled_qianfan_provider(config: &Config) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    qianfan_provider(config, QIANFAN_KEY)
}

async fn mount_qianfan_chat(server: &MockServer, body: String) {
    Mock::given(method("POST"))
        .and(path("/v2/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(server)
        .await;
}

async fn mount_qianfan_models(server: &MockServer, entries: Vec<Value>) {
    Mock::given(method("GET"))
        .and(path("/v2/models"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"object": "list", "data": entries})),
        )
        .mount(server)
        .await;
}

// ----- TP-PROVIDER-WIRE::qianfan ---------------------------------------------

/// A configured `qianfan` connection returns a verified model outcome
/// through the standard Broker: prepare admits the api_key pin under
/// DEC-011, the scoped material rides the `Authorization` header —
/// never the body — and the shared adapter posts exactly the frozen
/// manifest as a `chat/completions` request — the pinned model id
/// verbatim, system+user messages, `stream` with
/// `stream_options.include_usage` and the pinned effort as
/// `reasoning_effort` verbatim — the SSE stream validates its
/// finish_reason/`[DONE]` terminal, the one physical send is charged
/// once with the provider's reported usage, and the spent attempt
/// never re-sends.
#[tokio::test]
async fn qianfan_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_qianfan_chat(
        &server,
        completed_stream(
            "verified qianfan outcome",
            Some(json!({"prompt_tokens": 9, "completion_tokens": 4, "total_tokens": 13})),
        ),
    )
    .await;
    let config = Config::parse_validated(&qianfan_config(&qianfan_uri(&server))).expect("valid");
    let (provider, _store) = enrolled_qianfan_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/qianfan", "goal: prove the wire")
        .expect("the qianfan pin passes eligibility");

    let (broker, outcome) = dispatch(broker, "/world/qianfan", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified qianfan outcome");
    assert!(reply.tool_calls.is_empty());

    // The wire request is exactly the frozen manifest — a fixed pin
    // opens no catalogue leg.
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v2/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {QIANFAN_KEY}"),
        "the plain key material bears the wire verbatim"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(QIANFAN_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"], QIANFAN_MODEL,
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
    assert_eq!(
        body["reasoning_effort"],
        json!("high"),
        "the pinned effort rides the recorded reasoning_effort surface"
    );

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, QIANFAN);
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
            let replay = broker.dispatch("/world/qianfan", &manifest);
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

// ----- TP-PROVIDER-CATALOG::qianfan ------------------------------------------

/// The `qianfan` catalogue maps the recorded generic fields: every
/// `data[]` id is an offer, and an entry's `context_length` and
/// `max_completion_tokens` land on their own carriers when stated — an
/// absent key stays `None` (no default figure), never borrowed from the
/// other field. The configured base wins under the recorded trim, so
/// the route is the `/v2` root the contract names.
#[tokio::test]
async fn qianfan_catalog_maps_the_recorded_fields() {
    let server = MockServer::start().await;
    mount_qianfan_models(
        &server,
        vec![
            json!({"id": "qianfan-both", "context_length": 131072, "max_completion_tokens": 8192}),
            json!({"id": "qianfan-context-only", "context_length": 32768}),
            json!({"id": "qianfan-max-only", "max_completion_tokens": 4096}),
        ],
    )
    .await;
    let config = Config::parse_validated(&qianfan_config(&format!("  {}/v2/  ", server.uri())))
        .expect("valid");
    let (provider, _store) = enrolled_qianfan_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the keyed catalogue answers");
    drop_blocking(provider);

    assert_eq!(
        models,
        vec![
            CatalogModel {
                id: "qianfan-both".to_string(),
                context_window: Some(131072),
                max_output_tokens: Some(8192),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "qianfan-context-only".to_string(),
                context_window: Some(32768),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "qianfan-max-only".to_string(),
                max_output_tokens: Some(4096),
                ..CatalogModel::default()
            },
        ],
        "each stated limit lands on its own carrier and an absent one stays None"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the keyed listing is the one leg");
    assert_eq!(
        requests[0].url.path(),
        "/v2/models",
        "the configured base wins, trailing slashes trimmed"
    );
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {QIANFAN_KEY}"),
        "the listing runs only under the resolved material"
    );
}

/// The key-gated listing is the whole catalogue: an absent scope denies
/// `CredentialAbsent` before any request, an empty answer offers nothing —
/// the recorded `deepseek-v3.2` default is a hint, never a seeded floor —
/// and a failed answer keeps the leg's typed denial. No floor answers in
/// either case.
#[tokio::test]
async fn qianfan_catalog_is_the_keyed_listing_without_a_floor() {
    // an absent scope denies before any request — the listing never
    // runs keyless, even where a `/models` answer would serve rows
    let server = MockServer::start().await;
    mount_qianfan_models(&server, vec![json!({"id": QIANFAN_MODEL})]).await;
    let config = Config::parse_validated(&qianfan_config(&qianfan_uri(&server))).expect("valid");
    let (provider, denied) = catalog_on_thread(
        provider_result(
            config,
            QIANFAN.to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the binding resolves"),
    );
    assert!(
        matches!(denied, Err(ProviderError::CredentialAbsent { .. })),
        "the keyless listing denies before the wire: {denied:?}"
    );
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the keyless lookup opened no listing leg"
    );

    // an empty `data` answer is a real answer with no offers — the
    // recorded default is a hint, so no seed fills it
    let server = MockServer::start().await;
    mount_qianfan_models(&server, vec![]).await;
    let config = Config::parse_validated(&qianfan_config(&qianfan_uri(&server))).expect("valid");
    let (provider, _store) = enrolled_qianfan_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("an empty listing still answers");
    drop_blocking(provider);
    assert!(
        models.is_empty(),
        "an empty listing has no floor to fall back to: {:?}",
        model_ids(&models)
    );

    // a failed listing is the leg's typed denial — no floor answers
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/models"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&qianfan_config(&qianfan_uri(&server))).expect("valid");
    let (provider, _store) = enrolled_qianfan_provider(&config);
    let (provider, failed) = catalog_on_thread(provider);
    let err = failed.expect_err("a failed listing has no floor to answer");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the failed listing is the typed transport denial: {err:?}")
    };
    assert_eq!(connection, QIANFAN);
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 503 },
        "the failed listing keeps its typed denial: {cause}"
    );
    drop_blocking(provider);
}

/// The auto pick is the uniform sorted-first listed id: the recorded
/// `deepseek-v3.2` default rides the listing without outranking it, and
/// no unlisted id becomes an offer — the send names the sorted-first
/// id verbatim.
#[tokio::test]
async fn qianfan_auto_pick_is_the_sorted_first_listed_id() {
    let server = MockServer::start().await;
    mount_qianfan_models(
        &server,
        vec![
            json!({"id": "zzz-last"}),
            json!({"id": QIANFAN_MODEL}),
            json!({"id": "aardvark-first"}),
        ],
    )
    .await;
    mount_qianfan_chat(
        &server,
        completed_stream(
            "auto picked",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.qianfan]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"{QIANFAN_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\", pool = [\"qianfan\"] }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        qianfan_uri(&server)
    ))
    .expect("valid");
    let (provider, _store) = enrolled_qianfan_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/qianfan", "goal: auto pick")
        .expect("the single-member pool pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/qianfan", manifest);
    let reply = outcome.expect("the auto pick dispatches");
    assert_eq!(reply.text, "auto picked");
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "the catalogue leg and the send are the only egress"
    );
    assert_eq!(requests[0].url.path(), "/v2/models");
    assert_eq!(requests[1].url.path(), "/v2/chat/completions");
    let body: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert_eq!(
        body["model"],
        json!("aardvark-first"),
        "the sorted-first listed id names the wire model — the recorded default never outranks it"
    );
}

/// Hostile stream input never reports success for `qianfan`: a stream
/// ended mid `tool_calls` fragment — a partial call that never executes —
/// and a finish_reason the dialect cannot classify are each the unknown
/// terminal, and a rejected send charges nothing.
#[tokio::test]
async fn qianfan_adverse_wire_input_never_reports_success() {
    // a complete content delta plus an unterminated tool-call
    // fragment, then EOF — no finish_reason and no [DONE]
    let server = MockServer::start().await;
    mount_qianfan_chat(
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
    let config = Config::parse_validated(&qianfan_config(&qianfan_uri(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_qianfan_provider(&config),
        &config,
        "/world/qianfan",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/qianfan", manifest);
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
    mount_qianfan_chat(
        &server,
        format!(
            "{}{}{}",
            data_block(&delta_chunk(json!({"content": "hi"}))),
            data_block(&finish_chunk("mystery")),
            DONE_BLOCK
        ),
    )
    .await;
    let config = Config::parse_validated(&qianfan_config(&qianfan_uri(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_qianfan_provider(&config),
        &config,
        "/world/qianfan",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/qianfan", manifest);
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

// ----- TP-PROVIDER-AUTH::qianfan ---------------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `qianfan`, through the same shared construction its siblings use: a
/// configured `region` — the recorded contract names none — denies
/// `RegionMismatch` with the connection context, a profile-bound ref
/// whose scope disagrees with the binding denies
/// `CredentialProfileMismatch`, and a refused key lands the typed
/// transport denial carrying the peer's status alone — no error, nor
/// the offered credential material or the peer's body, reaches Display
/// or Debug.
#[tokio::test]
async fn qianfan_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &qianfan_config(&qianfan_uri(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        QIANFAN.to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, QIANFAN_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, QIANFAN);
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, QIANFAN_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.qianfan]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"qianfan\", model_id = \"{QIANFAN_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"high\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        qianfan_uri(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        QIANFAN.to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, QIANFAN_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, QIANFAN_KEY.as_bytes());

    // a refused key is a typed transport denial: the wire never
    // coerces a wrong credential into success, the peer's body never
    // enters the error, and the request carried the bearer
    Mock::given(method("POST"))
        .and(path("/v2/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&qianfan_config(&qianfan_uri(&server))).expect("valid");
    let (provider, _store) = enrolled_qianfan_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused key is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused key is transport: {err}")
    };
    assert_eq!(connection, QIANFAN);
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, QIANFAN_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(requests[0].url.path(), "/v2/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {QIANFAN_KEY}"),
        "the admitted bearer reached the wire — the denial is the peer's status"
    );
}

// ----- TP-PROVIDER-DIALECT::qianfan ------------------------------------------

/// The dialect is keyed on the literal connection id: the map routes
/// `qianfan` to the shared Chat Completions dialect, the Responses
/// adapter refuses it, the Chat Completions adapter refuses a Responses
/// and a native sibling id, and loopback never serves the reserved id.
/// An empty endpoint resolves the recorded base.
#[test]
fn qianfan_dialect_is_keyed_on_the_literal_connection_id() {
    assert_eq!(
        rivect::providers::dialect_for(QIANFAN),
        Some(rivect::providers::Dialect::ChatCompletions)
    );

    // the required endpoint's empty string resolves the recorded base —
    // proved on the adapter's `Debug` surface, no byte toward the host
    let config = Config::parse_validated(&qianfan_config("")).expect("the fixture config is valid");
    let provider = provider_result(
        config.clone(),
        QIANFAN.to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("the shared adapter builds for the qianfan id");
    let debug = format!("{provider:?}");
    assert!(
        debug.contains("endpoint: \"https://qianfan.baidubce.com/v2\""),
        "an empty endpoint resolves the recorded base: {debug}"
    );
    drop_blocking(provider);

    // the Responses adapter refuses the Chat Completions id
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let err = std::thread::spawn({
        let config = config.clone();
        let store = store.clone();
        move || OpenAiProvider::new(&config, QIANFAN, store)
    })
    .join()
    .expect("the provider thread joins")
    .expect_err("the Responses adapter refuses the Chat Completions id");
    assert!(
        matches!(err, ProviderError::DialectMismatch { .. }),
        "the Responses adapter refuses the id: {err}"
    );

    // the Chat Completions adapter refuses every sibling id
    for id in ["openrouter", "ollama-cloud", "google"] {
        let err = provider_result(config.clone(), id.to_string(), store.clone())
            .expect_err("a sibling id is not this contract");
        assert!(
            matches!(err, ProviderError::DialectMismatch { .. }),
            "{id} is refused typed: {err}"
        );
    }

    // loopback never serves the reserved id
    let local = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.qianfan]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"qianfan\", model_id = \"{QIANFAN_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the local declaration is admitted");
    let entry = local.connections.get(QIANFAN).expect("declared");
    let loopback = rivect::providers::LoopbackProvider::new();
    assert!(
        !loopback.serves(QIANFAN, entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );

    // the adapter serves only its own literal id
    let (provider, _store) = enrolled_qianfan_provider(&config);
    let entry = config.connections.get(QIANFAN).expect("declared");
    assert!(provider.serves(QIANFAN, entry));
    assert!(!provider.serves("deepseek", entry));
    drop_blocking(provider);
}

// ----- TP-PROVIDER-MATRIX::qianfan -------------------------------------------

/// The legs matrix enforces the recorded expected set for `qianfan`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside this
/// run, and INSTALLED reports NOT_RUN.
#[tokio::test]
async fn qianfan_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    mount_qianfan_models(
        &server,
        vec![
            json!({"id": QIANFAN_MODEL, "context_length": 131072, "max_completion_tokens": 8192}),
        ],
    )
    .await;
    mount_qianfan_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&qianfan_config(&qianfan_uri(&server))).expect("valid");

    // CATALOG: the keyed listing under the generic metadata transform.
    let (provider, _store) = enrolled_qianfan_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if matches!(&catalog, Ok(models) if model_ids(models) == vec![QIANFAN_MODEL]) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: a bound ref with no store material denies typed.
    let empty = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), QIANFAN.to_string(), empty.clone())
        .expect("the binding resolves");
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
        enrolled_qianfan_provider(&config),
        &config,
        "/world/qianfan",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/qianfan", manifest);
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
    let provider = provider_result(config.clone(), QIANFAN.to_string(), empty.clone())
        .expect("the binding resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    empty.enroll(QIANFAN_REF, QIANFAN_KEY.as_bytes());
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

// ----- TP-PROVIDER-INSTALLED::qianfan ----------------------------------------

/// TP-PROVIDER-INSTALLED::qianfan = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::qianfan = NOT_RUN"]
fn provider_installed_qianfan() {}
