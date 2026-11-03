// ----- vllm ------------------------------------------------------------------

// The `vllm` connection's proof legs (HZN-008 class B — the local-server
// cell): the shared Chat Completions adapter serves the literal id — no
// copied codec — under its own recorded predicates. The configured
// `endpoint` carries the API base verbatim, an empty one resolves the
// recorded `http://127.0.0.1:8000/v1` default — its own host, never
// `llama.cpp`'s `:8080` or `lm-studio`'s `:1234` (EDGE-006) — and a
// configured `region` is denied: the contract names none. The recorded
// local mode serves with or without a server key: the unbound
// `kind = "api_key"` declaration (DEC-003) and the shipped optional-binding
// `kind = "local"` declaration both ride headerless, a scoped key rides as
// the bearer, and a bound-but-unresolvable record denies typed. The
// configured base's `/models` listing is the whole catalogue: `max_model_len`
// maps the context window, a Qwen `major.minor` ≥ 3.8 id carries the
// display-only reasoning mark, and the listing states no effort ladder — a
// pinned effort denies typed rather than being dropped at the send seam.

/// The literal connection id this class serves.
const VLLM: &str = "vllm";

/// The scoped credential ref the bound declarations carry.
const VLLM_REF: &str = "keyring:rivect-test/vllm";

/// Fixture `vllm` server-key material — never a real credential, only ever
/// sent to localhost.
const VLLM_KEY: &str = "fixture-vllm-server-key";

/// The pinned model id the fixed-pin legs carry — a listed id.
const VLLM_MODEL: &str = "Qwen/Qwen3.8-27B";

/// One unbound `vllm` connection pointing at the fixture peer: the
/// recorded absent-binding form under `kind = "api_key"` — no
/// `credential_ref`, no dummy key — with auto effort so no pinned ladder
/// is exercised on the wire.
fn vllm_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.vllm]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"vllm\", model_id = \"{VLLM_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The bound half of the same class: a scoped server key the store must
/// resolve before the bearer bears the wire.
fn vllm_bound_config(endpoint: &str) -> String {
    vllm_config(endpoint).replace(
        "[connections.vllm]\nkind = \"api_key\"",
        &format!("[connections.vllm]\nkind = \"api_key\"\ncredential_ref = \"{VLLM_REF}\""),
    )
}

/// The shipped optional-binding `kind = "local"` form: the same headerless
/// local server row, carrying no credential by grammar.
fn vllm_local_config(endpoint: &str) -> String {
    vllm_config(endpoint).replace("kind = \"api_key\"", "kind = \"local\"")
}

/// The adapter over an explicit store — the seam the recovery leg enrolls
/// into after its typed denial.
fn vllm_provider_with(
    config: &Config,
    store: Arc<support::MapStore>,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let provider = provider_result(config.clone(), VLLM.to_string(), store.clone())
        .expect("the shared adapter builds for the vllm id");
    (provider, store)
}

/// The adapter over a store seeded with the recorded server key.
fn vllm_provider(
    config: &Config,
    material: Option<&str>,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = match material {
        None => Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        Some(material) => Arc::new(support::MapStore::seeded(STORE_KIND, &[(VLLM_REF, material)])),
    };
    vllm_provider_with(config, store)
}

/// The absent-binding form's wire proof: no `Authorization` header at all,
/// never an empty or dummy bearer.
fn assert_headerless(request: &Request) {
    assert!(
        request.headers.get("authorization").is_none(),
        "the absent-binding form carries no authorization header"
    );
}

// ----- TP-PROVIDER-WIRE::vllm ------------------------------------------------

/// A configured `vllm` connection returns a verified model outcome through
/// the standard Broker: the unbound `api_key` declaration and the shipped
/// `kind = "local"` declaration each prepare offline and post exactly the
/// frozen manifest as a `chat/completions` request — headerless, model id
/// verbatim, system+user messages, `stream` with
/// `stream_options.include_usage`, auto effort emitting no
/// `reasoning_effort` member — the SSE stream validates its terminal, and
/// the one physical send is charged once with the provider's reported usage.
#[tokio::test]
async fn vllm_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified vllm outcome",
            Some(json!({"prompt_tokens": 9, "completion_tokens": 4, "total_tokens": 13})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&vllm_config(&server_uri_v1(&server))).expect("valid");
    assert_eq!(
        config.connections[VLLM].credential_ref, None,
        "the recorded absent-binding form binds no credential"
    );
    let (provider, _store) = vllm_provider(&config, None);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/vllm", "goal: prove the wire")
        .expect("the unbound vllm pin passes eligibility");

    let (broker, outcome) = dispatch(broker, "/world/vllm", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified vllm outcome");
    assert!(reply.tool_calls.is_empty());

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_headerless(&requests[0]);
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"], VLLM_MODEL,
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
    assert!(
        body.get("reasoning_effort").is_none(),
        "auto effort emits no reasoning_effort member"
    );

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, VLLM);
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 9,
            completion_tokens: 4,
            total_tokens: 13,
        }
    );
    drop_blocking(broker);

    // the shipped optional-binding `kind = "local"` form is the same
    // headerless local server row
    let server = MockServer::start().await;
    mount_chat(&server, completed_stream("local vllm outcome", None)).await;
    let config =
        Config::parse_validated(&vllm_local_config(&server_uri_v1(&server))).expect("valid");
    assert_eq!(config.connections[VLLM].kind, rivect::config::ConnKind::Local);
    let (provider, _store) = vllm_provider(&config, None);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/vllm-local", "goal: local form")
        .expect("the local declaration prepares");
    let (broker, outcome) = dispatch(broker, "/world/vllm-local", manifest);
    let reply = outcome.expect("the local declaration dispatches");
    assert_eq!(reply.text, "local vllm outcome");
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "the local form opens one send leg");
    assert_headerless(&requests[0]);
    assert_eq!(broker.accounted_requests(), 1);
    drop_blocking(broker);
}

/// The bound server-key half of the same class: the resolved key rides the
/// `Authorization` header — never the body — while a bound declaration the
/// store cannot resolve denies `CredentialAbsent` before any wire leg,
/// never a silent fallback to the headerless form.
#[tokio::test]
async fn vllm_bound_key_rides_as_bearer() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified bound vllm outcome",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&vllm_bound_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        vllm_provider(&config, Some(VLLM_KEY)),
        &config,
        "/world/vllm",
        "goal: bound wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/vllm", manifest);
    let reply = outcome.expect("the bound key dispatches");
    assert_eq!(reply.text, "verified bound vllm outcome");

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {VLLM_KEY}"),
        "the resolved server key bears the wire"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(VLLM_KEY),
        "credential material rides the authorization header, never the body"
    );
    assert_eq!(broker.accounted_requests(), 1);
    drop_blocking(broker);

    // a bound-but-unresolvable record is the typed denial, not the
    // headerless form
    let server = MockServer::start().await;
    let config =
        Config::parse_validated(&vllm_bound_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = vllm_provider(&config, None);
    let (provider, denied) = send_on_thread(provider, prepared_manifest(&config));
    let err = denied.expect_err("an unresolvable binding never falls back to headerless");
    assert!(
        matches!(err, ProviderError::CredentialAbsent { .. }),
        "the unresolved binding is the typed denial: {err}"
    );
    assert_no_secret_or_body(&err, VLLM_KEY.as_bytes());
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the denied send opened no wire leg"
    );
}

// ----- TP-PROVIDER-CATALOG::vllm ---------------------------------------------

/// The configured local base's own `/models` listing is the whole
/// catalogue: vLLM's `max_model_len` maps the context window as a positive
/// count (absent or zero stays `None`, never the shared `context_length`),
/// and the display-only reasoning mark follows the recorded Qwen
/// `major.minor` ≥ 3.8 predicate — case-insensitive, a bare major marks
/// nothing. The unbound declaration lists headerless; no seed floor is
/// invented.
#[tokio::test]
async fn vllm_catalog_maps_max_model_len_and_qwen_reasoning() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "Qwen/Qwen2.5-7B-Instruct", "context_length": 8192}),
            json!({"id": "Qwen/Qwen3.5-27B", "max_model_len": 32768}),
            json!({"id": "Qwen/Qwen3.8-27B", "max_model_len": 131072}),
            json!({"id": "Qwen3-32B", "max_model_len": 4096}),
            json!({"id": "meta-llama/Llama-3.1-8B-Instruct"}),
            json!({"id": "qwen3.8-2.4T-A95B", "max_model_len": 0}),
        ],
    )
    .await;
    let config =
        Config::parse_validated(&vllm_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = vllm_provider(&config, None);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the headerless catalogue answers");
    drop_blocking(provider);

    assert_eq!(
        models,
        vec![
            CatalogModel {
                id: "Qwen/Qwen2.5-7B-Instruct".to_string(),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "Qwen/Qwen3.5-27B".to_string(),
                context_window: Some(32768),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "Qwen/Qwen3.8-27B".to_string(),
                reasoning: true,
                context_window: Some(131072),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "Qwen3-32B".to_string(),
                context_window: Some(4096),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "meta-llama/Llama-3.1-8B-Instruct".to_string(),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "qwen3.8-2.4T-A95B".to_string(),
                reasoning: true,
                ..CatalogModel::default()
            },
        ],
        "max_model_len maps the window; only a Qwen major.minor ≥ 3.8 marks reasoning"
    );

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the listing");
    assert_eq!(requests.len(), 1, "the listing is the one catalogue leg");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_headerless(&requests[0]);
}

/// A pinned effort is a parameter the `vllm` contract rejects for every
/// model — the listing that could state the chat-template surface is not
/// visible at the send seam — so the denial lands typed before the body
/// exists: never a request carrying a silently dropped `reasoning_effort`.
#[tokio::test]
async fn vllm_pinned_effort_denies_not_dropped() {
    let server = MockServer::start().await;
    mount_chat(&server, completed_stream("never reached", None)).await;
    let config = Config::parse_validated(
        &vllm_config(&server_uri_v1(&server))
            .replace("effort = { mode = \"auto\" }", "effort = { mode = \"fixed\", value = \"high\" }"),
    )
    .expect("valid");
    let (broker, manifest) = prepared_with(
        vllm_provider(&config, None),
        &config,
        "/world/vllm",
        "goal: pinned effort",
    );
    let (broker, outcome) = dispatch(broker, "/world/vllm", manifest);
    let err = match outcome {
        Err(ModelError::Provider(err)) => err,
        other => panic!("the pinned effort is a typed denial, not a reply: {other:?}"),
    };
    let ProviderError::UnsupportedParameter {
        connection,
        parameter,
        model,
    } = &err
    else {
        panic!("the pinned effort is the typed unsupported parameter: {err:?}")
    };
    assert_eq!(connection, VLLM);
    assert_eq!(*parameter, "reasoning_effort");
    assert_eq!(model, VLLM_MODEL);
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected parameter charges nothing"
    );
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

// ----- TP-PROVIDER-AUTH::vllm ------------------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `vllm`: a configured `region` — the recorded contract names none —
/// denies `RegionMismatch` with the connection context, a profile-bound ref
/// whose scope disagrees with the binding denies
/// `CredentialProfileMismatch`, and a refused key lands the typed transport
/// denial carrying the peer's status alone — no error, nor the offered
/// credential material or the peer's body, reaches Display or Debug.
#[tokio::test]
async fn vllm_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &vllm_config(&server_uri_v1(&server)).replace(
            "kind = \"api_key\"",
            "kind = \"api_key\"\nregion = \"eu\"",
        ),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        VLLM.to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, VLLM_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, VLLM);
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, VLLM_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.vllm]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"vllm\", model_id = \"{VLLM_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        VLLM.to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, VLLM_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, VLLM_KEY.as_bytes());

    // a refused key is a typed transport denial: the wire never coerces a
    // wrong credential into success, and the request carried the bearer
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&vllm_bound_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = vllm_provider(&config, Some(VLLM_KEY));
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused key is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused key is transport: {err}")
    };
    assert_eq!(connection, VLLM);
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, VLLM_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {VLLM_KEY}"),
        "the admitted bearer reached the wire — the denial is the peer's status"
    );
}

// ----- TP-PROVIDER-RECOVERY::vllm --------------------------------------------

/// Hostile stream input never reports success for `vllm`: a stream ended
/// mid `tool_calls` fragment — a partial call that never executes — and a
/// finish_reason the dialect cannot classify are each the unknown terminal,
/// and a rejected send charges nothing.
#[tokio::test]
async fn vllm_rejects_partial_tool_block_and_unknown_terminal() {
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
        Config::parse_validated(&vllm_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        vllm_provider(&config, None),
        &config,
        "/world/vllm",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/vllm", manifest);
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

    // a finish_reason the dialect cannot classify is unknown, never success
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
        Config::parse_validated(&vllm_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        vllm_provider(&config, None),
        &config,
        "/world/vllm",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/vllm", manifest);
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

/// The recorded OpenProxy recovery: a bound scope the store cannot resolve
/// denies `CredentialAbsent` with nothing sent and nothing accounted;
/// enrolling the scoped key and building again yields one verified outcome
/// and exactly one accounted physical request.
#[tokio::test]
async fn vllm_typed_denial_recovers_after_correct_binding() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered vllm outcome",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&vllm_bound_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));

    let (broker, manifest) = prepared_with(
        vllm_provider_with(&config, Arc::clone(&store)),
        &config,
        "/world/vllm",
        "goal: recovery",
    );
    let (broker, denied) = dispatch(broker, "/world/vllm", manifest);
    assert!(
        matches!(
            denied,
            Err(ModelError::Provider(ProviderError::CredentialAbsent { .. }))
        ),
        "the unresolved binding denies typed: {denied:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "the denial charges nothing"
    );
    drop_blocking(broker);

    store.enroll(VLLM_REF, VLLM_KEY.as_bytes());
    let (broker, manifest) = prepared_with(
        vllm_provider_with(&config, Arc::clone(&store)),
        &config,
        "/world/vllm",
        "goal: recovery",
    );
    let (broker, outcome) = dispatch(broker, "/world/vllm", manifest);
    let reply = outcome.expect("the corrected binding dispatches");
    assert_eq!(reply.text, "recovered vllm outcome");
    assert_eq!(broker.accounted_requests(), 1);
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "only the corrected send reached the wire");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {VLLM_KEY}"),
        "the corrected binding bears the wire"
    );
}

// ----- TP-PROVIDER-DIALECT::vllm ---------------------------------------------

/// The dialect is keyed on the literal connection id: the map routes `vllm`
/// to the shared Chat Completions dialect, an empty endpoint resolves its
/// own recorded local base — never the `llama.cpp` or `lm-studio` default
/// (EDGE-006) — and loopback never serves the reserved id.
#[test]
fn vllm_default_base_is_its_own_recorded_host() {
    assert_eq!(
        rivect::providers::dialect_for(VLLM),
        Some(rivect::providers::Dialect::ChatCompletions)
    );

    // the required endpoint's empty string resolves the recorded base —
    // proved on the adapter's `Debug` surface, no byte toward the host
    let config =
        Config::parse_validated(&vllm_config("")).expect("the fixture config is valid");
    let provider = provider_result(
        config.clone(),
        VLLM.to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("the shared adapter builds for the vllm id");
    let debug = format!("{provider:?}");
    assert!(
        debug.contains("endpoint: \"http://127.0.0.1:8000/v1\""),
        "an empty endpoint resolves the recorded base: {debug}"
    );
    assert!(
        !debug.contains("127.0.0.1:8080") && !debug.contains("127.0.0.1:1234"),
        "vllm never borrows a sibling local default: {debug}"
    );
    drop_blocking(provider);

    // the sibling local class still resolves its own base: the defaults
    // are per literal id, not inherited across the local-endpoint class
    let llama = Config::parse_validated(
        "config_version = 1\n\
         [connections.\"llama.cpp\"]\nkind = \"api_key\"\nendpoint = \"\"\n\
         [models.defaults]\nmodel = { mode = \"fixed\", connection = \"llama.cpp\", model_id = \"fixture-gguf-model\" }\n\
         effort = { mode = \"auto\" }\nfallback = { mode = \"off\" }\n",
    )
    .expect("the llama.cpp fixture config is valid");
    let llama_provider = provider_result(
        llama,
        "llama.cpp".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("the shared adapter builds for the llama.cpp id");
    let llama_debug = format!("{llama_provider:?}");
    assert!(
        llama_debug.contains("endpoint: \"http://127.0.0.1:8080\""),
        "llama.cpp keeps its own recorded base: {llama_debug}"
    );
    assert!(
        !llama_debug.contains("127.0.0.1:8000"),
        "llama.cpp never borrows vllm's base: {llama_debug}"
    );
    drop_blocking(llama_provider);

    // loopback never serves the reserved id
    let local = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.vllm]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"vllm\", model_id = \"{VLLM_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the local declaration is admitted");
    let entry = local.connections.get(VLLM).expect("declared");
    let loopback = rivect::providers::LoopbackProvider::new();
    assert!(
        !loopback.serves(VLLM, entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );
}

// ----- TP-PROVIDER-MATRIX::vllm ----------------------------------------------

/// The legs matrix enforces the recorded expected set for `vllm`: CATALOG,
/// AUTH, WIRE and RECOVERY each execute and report inside this run, and
/// INSTALLED reports NOT_RUN.
#[tokio::test]
async fn vllm_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![json!({"id": VLLM_MODEL, "max_model_len": 131072})],
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
        Config::parse_validated(&vllm_config(&server_uri_v1(&server))).expect("valid");

    // CATALOG: the headerless listing under the vllm entry transform.
    let (provider, _store) = vllm_provider(&config, None);
    let (provider, catalog) = catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if matches!(
            &catalog,
            Ok(models) if models.iter().any(|model| model.id == VLLM_MODEL
                && model.reasoning
                && model.context_window == Some(131072))
        ) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: a bound ref with no store material denies typed.
    let bound = Config::parse_validated(&vllm_bound_config(&server_uri_v1(&server)))
        .expect("valid");
    let (provider, _store) = vllm_provider(&bound, None);
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
        vllm_provider(&config, None),
        &config,
        "/world/vllm",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/vllm", manifest);
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
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let (broker, manifest) = prepared_with(
        vllm_provider_with(&bound, Arc::clone(&store)),
        &bound,
        "/world/vllm",
        "goal: matrix recovery",
    );
    let (broker, denied) = dispatch(broker, "/world/vllm", manifest);
    let denied_ok = matches!(
        denied,
        Err(ModelError::Provider(ProviderError::CredentialAbsent { .. }))
    );
    drop_blocking(broker);
    store.enroll(VLLM_REF, VLLM_KEY.as_bytes());
    let (broker, manifest) = prepared_with(
        vllm_provider_with(&bound, Arc::clone(&store)),
        &bound,
        "/world/vllm",
        "goal: matrix recovery",
    );
    let (broker, retried) = dispatch(broker, "/world/vllm", manifest);
    let recovered = matches!(&retried, Ok(reply) if reply.text == "matrix");
    reported.insert(
        "RECOVERY",
        if denied_ok && recovered {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

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

// ----- TP-PROVIDER-INSTALLED::vllm -------------------------------------------

/// TP-PROVIDER-INSTALLED::vllm = NOT_RUN: the installed-provider proof is a
/// live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::vllm = NOT_RUN"]
fn provider_installed_vllm() {}

// ----- venice ----------------------------------------------------------------

// The `venice` connection's proof legs (HZN-008 class B — the
// public-catalogue cell): the shared Chat Completions adapter serves the
// literal id under its own recorded predicates. The configured `endpoint`
// carries the API base verbatim, an empty one resolves the recorded
// `https://api.venice.ai/api/v1` default, and a configured `region` is
// denied: the contract names none. The `/models` catalogue is public: the
// listing rides headerless when the store resolves no material, and that
// answer is never authentication — the same absent material denies a send
// `CredentialAbsent` before any chat leg. The model-request key is the
// plain bearer; it is distinct from the administrative key, but `SecretRef`
// material carries no class label, so that discrimination is a residual.
// The class's recorded request names no `stream_options` usage-report
// member, so its body never asks for one and the reported usage may stay
// unknown; every other Chat Completions id keeps the shared body.

/// The literal connection id this class serves.
const VENICE: &str = "venice";

/// The scoped credential ref the declaration binds.
const VENICE_REF: &str = "keyring:rivect-test/venice";

/// Fixture model-request key material — never a real credential, only ever
/// sent to a loopback fixture.
const VENICE_KEY: &str = "fixture-venice-model-key";

/// The pinned model id the fixed-pin legs carry — a listed id.
const VENICE_MODEL: &str = "venice-uncensored";

/// One `venice` connection pointing at the fixture peer: the api-key class
/// binds its scoped model-request key, so the declaration carries the ref
/// the send must resolve.
fn venice_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.venice]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{VENICE_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"venice\", model_id = \"{VENICE_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The adapter over an explicit store — the seam the recovery leg enrolls
/// into after its typed denial.
fn venice_provider_with(
    config: &Config,
    store: Arc<support::MapStore>,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let provider = provider_result(config.clone(), VENICE.to_string(), store.clone())
        .expect("the shared adapter builds for the venice id");
    (provider, store)
}

/// The adapter over a store seeded with the recorded model-request key, or
/// an empty store for the keyless catalogue leg.
fn venice_provider(
    config: &Config,
    material: Option<&str>,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = match material {
        None => Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        Some(material) => {
            Arc::new(support::MapStore::seeded(STORE_KIND, &[(VENICE_REF, material)]))
        }
    };
    venice_provider_with(config, store)
}

// ----- TP-PROVIDER-WIRE::venice ----------------------------------------------

/// A configured `venice` connection returns a verified model outcome through
/// the standard Broker: the api_key pin prepares offline, the adapter posts
/// exactly the frozen manifest as a `chat/completions` request — model id
/// verbatim, system+user messages, `stream` — under the resolved bearer,
/// never a `stream_options` member the class does not request and never a
/// `reasoning_effort` for auto effort — the SSE stream validates its
/// terminal, and the one physical send is charged once with the reported
/// usage.
#[tokio::test]
async fn venice_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified venice outcome",
            Some(json!({"prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17})),
        ),
    )
    .await;
    let config = Config::parse_validated(&venice_config(&server_uri_v1(&server))).expect("valid");
    assert_eq!(
        config.connections[VENICE].credential_ref.as_deref(),
        Some(VENICE_REF),
        "the recorded api-key class binds its scoped ref"
    );
    let (broker, manifest) = prepared_with(
        venice_provider(&config, Some(VENICE_KEY)),
        &config,
        "/world/venice",
        "goal: prove the wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/venice", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified venice outcome");
    assert!(reply.tool_calls.is_empty());

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {VENICE_KEY}"),
        "the resolved model-request key bears the wire"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"], VENICE_MODEL,
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
    assert!(
        body.get("stream_options").is_none(),
        "the recorded class names no usage report, so the body asks for none"
    );
    assert!(
        body.get("reasoning_effort").is_none(),
        "auto effort emits no reasoning_effort member"
    );

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, VENICE);
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 12,
            completion_tokens: 5,
            total_tokens: 17,
        }
    );
    drop_blocking(broker);
}

/// The recorded request body is the shared Chat Completions envelope minus
/// the usage-report member only on `venice`: a sibling CC id's body keeps
/// `stream_options.include_usage`, so the predicate is narrow rather than a
/// shared removal.
#[tokio::test]
async fn venice_request_body_omits_stream_options() {
    let venice_server = MockServer::start().await;
    mount_chat(&venice_server, completed_stream("venice body", None)).await;
    let config =
        Config::parse_validated(&venice_config(&server_uri_v1(&venice_server))).expect("valid");
    let (broker, manifest) = prepared_with(
        venice_provider(&config, Some(VENICE_KEY)),
        &config,
        "/world/venice",
        "goal: body shape",
    );
    let (broker, outcome) = dispatch(broker, "/world/venice", manifest.clone());
    outcome.expect("the venice send dispatches");
    assert_eq!(broker.accounted_requests(), 1, "the send is charged once");
    assert_eq!(
        broker
            .accounting_record(&manifest.attempt_id)
            .expect("the send is accounted")
            .usage,
        UsageDelta::Unknown,
        "a class that never asked for the report charges what the peer stated, else unknown"
    );
    drop_blocking(broker);
    let requests = venice_server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1);
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert!(
        body.get("stream_options").is_none(),
        "venice sends no stream_options member: {body}"
    );

    // the sibling generic class keeps the shared usage-report request
    let sibling_server = MockServer::start().await;
    mount_chat(&sibling_server, completed_stream("sibling body", None)).await;
    let sibling =
        Config::parse_validated(&local_config(&server_uri_v1(&sibling_server))).expect("valid");
    let (broker, manifest) = prepared_with(
        local_provider(&sibling),
        &sibling,
        "/world/local",
        "goal: body shape",
    );
    let (broker, outcome) = dispatch(broker, "/world/local", manifest);
    outcome.expect("the sibling send dispatches");
    drop_blocking(broker);
    let requests = sibling_server
        .received_requests()
        .await
        .expect("the mock recorded the sibling send");
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["stream_options"],
        json!({"include_usage": true}),
        "every other Chat Completions id keeps the recorded usage request"
    );
}

// ----- TP-PROVIDER-CATALOG::venice -------------------------------------------

/// The public `/models` catalogue: the listing rides headerless when the
/// store resolves no material, each `data[]` row maps the id plus the
/// generic `context_length`/`max_completion_tokens` limits when stated, and
/// a listing answer is never authentication — the same keyless declaration
/// denies a send `CredentialAbsent` without opening a chat leg. An empty
/// listing has no floor to fall back to: no offer is invented.
#[tokio::test]
async fn venice_catalog_is_public_and_never_entitlement() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "venice-uncensored", "context_length": 131072, "max_completion_tokens": 8192}),
            json!({"id": "venice-roleplay", "context_length": 32768}),
            json!({"id": "venice-bare"}),
            json!({"id": "venice-zero", "context_length": 0, "max_completion_tokens": "4096"}),
            json!({"id": "   "}),
        ],
    )
    .await;
    let config = Config::parse_validated(&venice_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = venice_provider(&config, None);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the keyless catalogue answers");
    assert_eq!(
        models,
        vec![
            CatalogModel {
                id: "venice-bare".to_string(),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "venice-roleplay".to_string(),
                context_window: Some(32768),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "venice-uncensored".to_string(),
                context_window: Some(131072),
                max_output_tokens: Some(8192),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "venice-zero".to_string(),
                max_output_tokens: Some(4096),
                ..CatalogModel::default()
            },
        ],
        "the generic limits map when stated; a zero or whitespace id offers nothing"
    );

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the listing");
    assert_eq!(requests.len(), 1, "the listing is the one catalogue leg");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_headerless(&requests[0]);

    // the wire leg's tolerance is not an ingress tolerance: the recorded
    // class is not config-keyless, so an unbound declaration is refused
    let unbound = venice_config(&server_uri_v1(&server))
        .replace(&format!("credential_ref = \"{VENICE_REF}\"\n"), "");
    let err = Config::parse_validated(&unbound)
        .expect_err("the recorded class requires its scoped binding at ingress");
    assert!(
        matches!(err.issue, ConfigIssue::CredentialRefRequired { .. }),
        "the unbound declaration is the typed ingress denial: {err}"
    );

    // the public listing confers no authentication: the same keyless
    // declaration cannot send
    let (provider, denied) = send_on_thread(provider, prepared_manifest(&config));
    let err = denied.expect_err("a keyless send is denied, never entitlemented by the listing");
    assert!(
        matches!(err, ProviderError::CredentialAbsent { .. }),
        "the absent model-request key is the typed denial: {err}"
    );
    assert_no_secret_or_body(&err, VENICE_KEY.as_bytes());
    drop_blocking(provider);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        1,
        "the denied send opened no chat leg"
    );

    // an empty listing has no recorded floor: the catalogue answers empty
    let empty = MockServer::start().await;
    mount_models(&empty, Vec::new()).await;
    let config = Config::parse_validated(&venice_config(&server_uri_v1(&empty))).expect("valid");
    let (provider, _store) = venice_provider(&config, None);
    let (provider, catalog) = catalog_on_thread(provider);
    assert_eq!(
        catalog.expect("an empty listing is an empty catalogue, not a denial"),
        Vec::new(),
        "no floor is invented for the seedless class"
    );
    drop_blocking(provider);
}

// ----- TP-PROVIDER-AUTH::venice ----------------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `venice`: a configured `region` — the recorded contract names none —
/// denies `RegionMismatch` with the connection context, a profile-bound ref
/// whose scope disagrees with the binding denies
/// `CredentialProfileMismatch`, and a refused model-request key lands the
/// typed transport denial carrying the peer's status alone — no error, nor
/// the offered credential material or the peer's body, reaches Display or
/// Debug.
#[tokio::test]
async fn venice_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling scope
    // holds real material so the no-secret assertion proves no cross-scope
    // leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &venice_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        VENICE.to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, VENICE_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, VENICE);
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, VENICE_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.venice]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"venice\", model_id = \"{VENICE_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        VENICE.to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, VENICE_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, VENICE_KEY.as_bytes());

    // a refused key is a typed transport denial: the wire never coerces a
    // wrong credential into success, and the request carried the bearer
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&venice_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = venice_provider(&config, Some(VENICE_KEY));
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused key is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused key is transport: {err}")
    };
    assert_eq!(connection, VENICE);
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, VENICE_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {VENICE_KEY}"),
        "the admitted bearer reached the wire — the denial is the peer's status"
    );
}

// ----- TP-PROVIDER-RECOVERY::venice ------------------------------------------

/// Hostile stream input never reports success for `venice`: a stream ended
/// mid `tool_calls` fragment — a partial call that never executes — and a
/// finish_reason the dialect cannot classify are each the unknown terminal,
/// and a rejected send charges nothing.
#[tokio::test]
async fn venice_rejects_partial_tool_block_and_unknown_terminal() {
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
    let config = Config::parse_validated(&venice_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        venice_provider(&config, Some(VENICE_KEY)),
        &config,
        "/world/venice",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/venice", manifest);
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

    // a finish_reason the dialect cannot classify is unknown, never success
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
    let config = Config::parse_validated(&venice_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        venice_provider(&config, Some(VENICE_KEY)),
        &config,
        "/world/venice",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/venice", manifest);
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

/// The recorded Bearer recovery: a bound scope the store cannot resolve
/// denies `CredentialAbsent` with no chat leg sent and nothing accounted —
/// the public catalogue leg is not a substitute — and enrolling the scoped
/// key and building again yields one verified outcome and exactly one
/// accounted physical request.
#[tokio::test]
async fn venice_typed_denial_recovers_after_correct_binding() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered venice outcome",
            Some(json!({"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5})),
        ),
    )
    .await;
    let config = Config::parse_validated(&venice_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));

    let (broker, manifest) = prepared_with(
        venice_provider_with(&config, Arc::clone(&store)),
        &config,
        "/world/venice",
        "goal: recovery",
    );
    let (broker, denied) = dispatch(broker, "/world/venice", manifest);
    assert!(
        matches!(
            denied,
            Err(ModelError::Provider(ProviderError::CredentialAbsent { .. }))
        ),
        "the unresolved binding denies typed: {denied:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "the denial charges nothing"
    );
    drop_blocking(broker);

    store.enroll(VENICE_REF, VENICE_KEY.as_bytes());
    let (broker, manifest) = prepared_with(
        venice_provider_with(&config, Arc::clone(&store)),
        &config,
        "/world/venice",
        "goal: recovery",
    );
    let (broker, outcome) = dispatch(broker, "/world/venice", manifest);
    let reply = outcome.expect("the corrected binding dispatches");
    assert_eq!(reply.text, "recovered venice outcome");
    assert_eq!(broker.accounted_requests(), 1);
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "only the corrected send reached the wire");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {VENICE_KEY}"),
        "the corrected binding bears the wire"
    );
}

// ----- TP-PROVIDER-DIALECT::venice -------------------------------------------

/// The dialect is keyed on the literal connection id: the map routes
/// `venice` to the shared Chat Completions dialect, an empty endpoint
/// resolves its own recorded `api.venice.ai/api/v1` base — never a sibling
/// class's default — a configured base stays verbatim, and loopback never
/// serves the reserved id.
#[test]
fn venice_discriminates_the_recorded_default_base() {
    assert_eq!(
        rivect::providers::dialect_for(VENICE),
        Some(rivect::providers::Dialect::ChatCompletions)
    );

    // the required endpoint's empty string resolves the recorded base —
    // proved on the adapter's `Debug` surface, no byte toward the host
    let config = Config::parse_validated(&venice_config("")).expect("the fixture config is valid");
    let provider = provider_result(
        config,
        VENICE.to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("the shared adapter builds for the venice id");
    let debug = format!("{provider:?}");
    assert!(
        debug.contains("endpoint: \"https://api.venice.ai/api/v1\""),
        "an empty endpoint resolves the recorded base: {debug}"
    );
    assert!(
        !debug.contains("127.0.0.1") && !debug.contains("api.together.xyz"),
        "venice never borrows a sibling class's base: {debug}"
    );
    drop_blocking(provider);

    // a configured base wins verbatim, trailing slashes trimmed
    let configured = Config::parse_validated(&venice_config("https://api.venice.ai/api/v1/"))
        .expect("the trailing-slash config is valid");
    let provider = provider_result(
        configured,
        VENICE.to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("the shared adapter builds for the venice id");
    assert!(
        format!("{provider:?}").contains("endpoint: \"https://api.venice.ai/api/v1\""),
        "the configured base is normalized, not replaced"
    );
    drop_blocking(provider);

    // loopback never serves the reserved id, and the required-binding
    // contract denies the credential-free kind
    let local = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.venice]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"venice\", model_id = \"{VENICE_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the local declaration is admitted");
    let entry = local.connections.get(VENICE).expect("declared");
    let loopback = rivect::providers::LoopbackProvider::new();
    assert!(
        !loopback.serves(VENICE, entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );
    let err = provider_result(
        local,
        VENICE.to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a local declaration cannot satisfy the required binding");
    assert!(
        matches!(err, ProviderError::CredentialUnresolved { .. }),
        "the kind denial is typed: {err}"
    );
}

// ----- TP-PROVIDER-MATRIX::venice --------------------------------------------

/// The legs matrix enforces the recorded expected set for `venice`: CATALOG,
/// AUTH, WIRE and RECOVERY each execute and report inside this run, and
/// INSTALLED reports NOT_RUN.
#[tokio::test]
async fn venice_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![json!({"id": VENICE_MODEL, "context_length": 131072})],
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
    let config = Config::parse_validated(&venice_config(&server_uri_v1(&server))).expect("valid");

    // CATALOG: the keyless listing under the generic entry transform.
    let (provider, _store) = venice_provider(&config, None);
    let (provider, catalog) = catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if matches!(
            &catalog,
            Ok(models) if models.iter().any(|model| model.id == VENICE_MODEL
                && model.context_window == Some(131072))
        ) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: a bound ref with no store material denies typed — the public
    // catalogue is never authentication.
    let (provider, _store) = venice_provider(&config, None);
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
        venice_provider(&config, Some(VENICE_KEY)),
        &config,
        "/world/venice",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/venice", manifest);
    reported.insert(
        "WIRE",
        if matches!(&outcome, Ok(reply) if reply.text == "matrix") {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

    // RECOVERY: the typed denial is followed by a successful retry through
    // the same credential seam.
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let (broker, manifest) = prepared_with(
        venice_provider_with(&config, Arc::clone(&store)),
        &config,
        "/world/venice",
        "goal: matrix recovery",
    );
    let (broker, denied) = dispatch(broker, "/world/venice", manifest);
    let denied_ok = matches!(
        denied,
        Err(ModelError::Provider(ProviderError::CredentialAbsent { .. }))
    );
    drop_blocking(broker);
    store.enroll(VENICE_REF, VENICE_KEY.as_bytes());
    let (broker, manifest) = prepared_with(
        venice_provider_with(&config, Arc::clone(&store)),
        &config,
        "/world/venice",
        "goal: matrix recovery",
    );
    let (broker, retried) = dispatch(broker, "/world/venice", manifest);
    let recovered = matches!(&retried, Ok(reply) if reply.text == "matrix");
    reported.insert(
        "RECOVERY",
        if denied_ok && recovered {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

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

// ----- TP-PROVIDER-INSTALLED::venice -----------------------------------------

/// TP-PROVIDER-INSTALLED::venice = NOT_RUN: the installed-provider proof is a
/// live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::venice = NOT_RUN"]
fn provider_installed_venice() {}

// ----- xai-oauth -------------------------------------------------------------

// The `xai-oauth` connection's proof legs: the shared Responses adapter
// serves the literal id under its own recorded contract. The
// device-code-produced token is supplied as the scoped `SecretRef`
// material — the live login, refresh, revocation, and the separate
// `grok.com` accounting origin stay NOT_RUN — the configured `endpoint`
// carries the API base verbatim and an empty one resolves the recorded
// `https://api.x.ai/v1` default, while a configured `region` is denied:
// the contract names none. The xAI `/models` listing is authoritative and
// no vendored selected list is retained, so the listing alone offers ids
// and a failed listing denies typed with no fabricated floor.

/// The literal connection id this class serves.
const XAI_OAUTH: &str = "xai-oauth";

/// The scoped credential ref carrying the device-code-produced token.
const XAI_OAUTH_REF: &str = "keyring:rivect-test/xai-oauth";

/// Fixture device-code-produced token material — never a live token, only
/// ever sent to localhost.
const XAI_OAUTH_KEY: &str = "fixture-xai-oauth-device-token";

/// The pinned model id the fixed-pin legs carry.
const XAI_OAUTH_MODEL: &str = "grok-4";

/// One configured `xai-oauth` connection pointing at the fixture peer: the
/// api_key auth class resolves the device-code token through the scoped
/// `SecretRef` seam, and the dialect comes from the literal connection id.
fn xai_oauth_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.xai-oauth]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{XAI_OAUTH_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"xai-oauth\", model_id = \"{XAI_OAUTH_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The shared Responses adapter over an explicit store — the seam the
/// recovery leg enrolls into after its typed denial.
fn xai_oauth_provider_result(
    config: Config,
    store: Arc<support::MapStore>,
) -> Result<OpenAiProvider, ProviderError> {
    std::thread::spawn(move || OpenAiProvider::new(&config, XAI_OAUTH, store))
        .join()
        .expect("the provider thread joins")
}

fn xai_oauth_provider_with(
    config: &Config,
    store: Arc<support::MapStore>,
) -> (OpenAiProvider, Arc<support::MapStore>) {
    let provider = xai_oauth_provider_result(config.clone(), Arc::clone(&store))
        .expect("the shared adapter builds for the xai-oauth id");
    (provider, store)
}

/// The adapter over a store seeded with the device-code token.
fn xai_oauth_provider(config: &Config) -> (OpenAiProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(XAI_OAUTH_REF, XAI_OAUTH_KEY)],
    ));
    xai_oauth_provider_with(config, store)
}

/// A bare catalogue lookup on a plain OS thread: reqwest's blocking client
/// must not run inside the tokio context.
fn xai_oauth_catalog_on_thread(
    provider: OpenAiProvider,
) -> (
    OpenAiProvider,
    Result<Vec<CatalogModel>, ProviderError>,
) {
    std::thread::spawn(move || {
        let catalog = provider.catalog_models();
        (provider, catalog)
    })
    .join()
    .expect("the catalog thread joins")
}

// ----- TP-PROVIDER-WIRE::xai-oauth -------------------------------------------

/// A configured `xai-oauth` connection returns a verified model outcome
/// through the standard Broker: the resolved device-code token rides the
/// bearer, the adapter posts exactly the frozen manifest as a Responses
/// request — `store: false`, `stream: true`, model and instructions
/// verbatim, auto effort emitting no reasoning member and no
/// `include` artifact the recorded contract does not name — and the one
/// physical send is charged once with the provider's reported usage.
#[tokio::test]
async fn xai_oauth_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "verified xai-oauth outcome",
            Vec::new(),
            Some(json!({"input_tokens": 11, "output_tokens": 7, "total_tokens": 18})),
        ),
    )
    .await;
    let config = Config::parse_validated(&xai_oauth_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        xai_oauth_provider(&config),
        &config,
        "/world/xai-oauth",
        "goal: prove the wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/xai-oauth", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified xai-oauth outcome");
    assert!(reply.tool_calls.is_empty());

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/responses");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {XAI_OAUTH_KEY}"),
        "the resolved device-code token rides the bearer"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(XAI_OAUTH_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], XAI_OAUTH_MODEL);
    assert_eq!(body["store"], false);
    assert_eq!(body["stream"], true);
    assert!(
        body.get("include").is_none(),
        "the recorded contract names no replay artifact — none is requested: {body}"
    );
    assert_eq!(body["instructions"], manifest.instructions);
    assert!(
        body.get("reasoning").is_none(),
        "auto effort emits no reasoning member: {body}"
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
    assert_eq!(record.connection, XAI_OAUTH);
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 11,
            completion_tokens: 7,
            total_tokens: 18,
        }
    );
    drop_blocking(broker);
}

// ----- TP-PROVIDER-CATALOG::xai-oauth ----------------------------------------

/// The xAI `/models` listing is authoritative: every listed id offers as
/// an id-only entry and no vendored selected list adds a floor, so an
/// empty listing offers nothing. The listing leg authenticates with the
/// resolved device-code token.
#[tokio::test]
async fn xai_oauth_catalog_is_the_authoritative_listing() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "grok-4", "context_length": 131072, "reasoning": true}),
            json!({"id": "grok-3"}),
        ],
    )
    .await;
    let config = Config::parse_validated(&xai_oauth_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = xai_oauth_provider(&config);
    let (provider, catalog) = xai_oauth_catalog_on_thread(provider);
    let models = catalog.expect("the authoritative listing answers");
    assert_eq!(model_ids(&models), vec!["grok-3", "grok-4"]);
    assert!(
        models.iter().all(|model| *model
            == CatalogModel {
                id: model.id.clone(),
                ..CatalogModel::default()
            }),
        "the listing offers ids only, with no mapped surfaces or vendored floor: {models:?}"
    );
    drop_blocking(provider);

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the listing");
    assert_eq!(requests.len(), 1, "one catalogue leg");
    assert_eq!(requests[0].method.as_str(), "GET");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {XAI_OAUTH_KEY}"),
        "the listing leg resolves the scoped token"
    );

    // an empty authoritative listing offers nothing: no retained selected
    // list is vendored to fabricate a floor
    let empty_server = MockServer::start().await;
    mount_models(&empty_server, Vec::new()).await;
    let config =
        Config::parse_validated(&xai_oauth_config(&server_uri_v1(&empty_server))).expect("valid");
    let (provider, _store) = xai_oauth_provider(&config);
    let (provider, catalog) = xai_oauth_catalog_on_thread(provider);
    let models = catalog.expect("the empty listing answers");
    assert!(
        models.is_empty(),
        "an empty authoritative listing offers no fabricated floor: {models:?}"
    );
    drop_blocking(provider);
}

/// A failed xAI listing denies typed with no fabricated floor: the
/// non-success status is the typed transport denial, never a vendored
/// selected-list answer, and neither the token nor the peer body reaches
/// the diagnostic.
#[tokio::test]
async fn xai_oauth_failed_listing_denies_without_a_fabricated_floor() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(503).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&xai_oauth_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = xai_oauth_provider(&config);
    let (provider, catalog) = xai_oauth_catalog_on_thread(provider);
    let err = catalog.expect_err("a failed listing denies typed");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a failed listing is the typed transport denial: {err}")
    };
    assert_eq!(connection, XAI_OAUTH);
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 503 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, XAI_OAUTH_KEY.as_bytes());
    drop_blocking(provider);

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the listing");
    assert_eq!(requests.len(), 1, "the refusal is the one catalogue leg");
}

// ----- TP-PROVIDER-AUTH::xai-oauth -------------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `xai-oauth`: an absent binding is refused at the config ingress, a
/// configured `region` denies `RegionMismatch`, a profile-bound ref whose
/// scope disagrees denies `CredentialProfileMismatch`, a scoped ref with
/// no resolvable material denies `CredentialAbsent`, and a resolved token
/// the peer refuses is the typed transport denial — no error, nor the
/// offered device-code token or the peer body, reaches Display or Debug.
#[tokio::test]
async fn xai_oauth_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // the required binding cannot be absent: the ingress names the member
    let absent = xai_oauth_config(&server_uri_v1(&server)).replace(
        &format!("credential_ref = \"{XAI_OAUTH_REF}\"\n"),
        "",
    );
    let err = Config::parse_validated(&absent).expect_err("the required binding cannot be absent");
    assert!(
        matches!(err.issue, ConfigIssue::CredentialRefRequired { .. }),
        "the absent binding is the typed ingress denial: {err}"
    );

    // a configured region is denied — never ignored — with a sibling scope
    // holding material so the no-secret assertion proves no cross-scope leak
    let regioned = Config::parse_validated(
        &xai_oauth_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = xai_oauth_provider_result(
        regioned,
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, XAI_OAUTH_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, XAI_OAUTH);
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, XAI_OAUTH_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.xai-oauth]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"xai-oauth\", model_id = \"{XAI_OAUTH_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = xai_oauth_provider_result(
        mismatched,
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, XAI_OAUTH_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, XAI_OAUTH_KEY.as_bytes());

    // a bound scope the store cannot resolve denies before any wire leg
    let config = Config::parse_validated(&xai_oauth_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = xai_oauth_provider_with(
        &config,
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, XAI_OAUTH_KEY)],
        )),
    );
    let (provider, denied) = send_on_thread(provider, prepared_manifest(&config));
    let Err(denied) = denied else {
        panic!("an unresolvable token never produces a reply")
    };
    assert!(
        matches!(&denied, ProviderError::CredentialAbsent { .. }),
        "the unresolved binding denies typed: {denied}"
    );
    assert_no_secret_or_body(&denied, XAI_OAUTH_KEY.as_bytes());
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("the mock recorded no send")
            .is_empty(),
        "the credential denial sends no byte"
    );

    // a resolved token the peer refuses is a typed transport denial: the
    // wire never coerces a wrong credential into success
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&xai_oauth_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = xai_oauth_provider(&config);
    let (provider, refused) = send_on_thread(provider, prepared_manifest(&config));
    let refused = refused.expect_err("a refused token is the typed transport denial");
    let ProviderError::Transport { connection, cause } = &refused else {
        panic!("a refused token is transport: {refused}")
    };
    assert_eq!(connection, XAI_OAUTH);
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&refused, XAI_OAUTH_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(requests[0].url.path(), "/v1/responses");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {XAI_OAUTH_KEY}"),
        "the resolved token reached the wire — the denial is the peer's status"
    );
}

// ----- TP-PROVIDER-RECOVERY::xai-oauth ---------------------------------------

/// Hostile Responses input never reports success for `xai-oauth`: a stream
/// ended mid function-call item — a partial call that never executes — is
/// the typed stream violation, an unclassifiable completion status is the
/// unknown terminal, and a rejected send charges nothing.
#[tokio::test]
async fn xai_oauth_rejects_partial_tool_block_and_unknown_terminal() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        sse_block(
            "response.output_item.added",
            &json!({
                "item": {
                    "id": "fc_1",
                    "type": "function_call",
                    "status": "in_progress",
                    "name": "read_file",
                    "arguments": "",
                },
                "output_index": 0,
            }),
        ),
    )
    .await;
    let config = Config::parse_validated(&xai_oauth_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        xai_oauth_provider(&config),
        &config,
        "/world/xai-oauth",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/xai-oauth", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "EOF mid function-call item is the stream violation — never a usable call: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);

    // a completion status the dialect cannot classify is unknown, never
    // success
    let server = MockServer::start().await;
    mount_responses(
        &server,
        sse_block(
            "response.completed",
            &json!({"response": {"id": "resp_1", "status": "mystery", "output": []}}),
        ),
    )
    .await;
    let config = Config::parse_validated(&xai_oauth_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        xai_oauth_provider(&config),
        &config,
        "/world/xai-oauth",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/xai-oauth", manifest);
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

// ----- TP-PROVIDER-DIALECT::xai-oauth ----------------------------------------

/// The dialect is keyed on the literal connection id: the map routes
/// `xai-oauth` to the shared Responses dialect, an empty endpoint resolves
/// the recorded `api.x.ai/v1` base — never a sibling class's default — a
/// configured base stays verbatim, and loopback never serves the reserved
/// id.
#[test]
fn xai_oauth_discriminates_the_recorded_default_base() {
    assert_eq!(
        rivect::providers::dialect_for(XAI_OAUTH),
        Some(rivect::providers::Dialect::Responses)
    );

    // the required endpoint's empty string resolves the recorded base —
    // proved on the adapter's `Debug` surface, no byte toward the host
    let config = Config::parse_validated(&xai_oauth_config("")).expect("the fixture config is valid");
    let (provider, _store) = xai_oauth_provider(&config);
    let debug = format!("{provider:?}");
    assert!(
        debug.contains("endpoint: \"https://api.x.ai/v1\""),
        "an empty endpoint resolves the recorded base: {debug}"
    );
    assert!(
        !debug.contains("api.openai.com")
            && !debug.contains("api.sakana.ai")
            && !debug.contains("openrouter.ai")
            && !debug.contains("127.0.0.1"),
        "xai-oauth never borrows a sibling class's base: {debug}"
    );
    drop_blocking(provider);

    // a configured base wins verbatim, trailing slashes trimmed
    let configured = Config::parse_validated(&xai_oauth_config("https://api.x.ai/v1///"))
        .expect("the trailing-slash config is valid");
    let (provider, _store) = xai_oauth_provider(&configured);
    assert!(
        format!("{provider:?}").contains("endpoint: \"https://api.x.ai/v1\""),
        "the configured base is normalized, not replaced"
    );
    drop_blocking(provider);

    // loopback never serves the reserved id, and the required-binding
    // contract denies the credential-free kind
    let local = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.xai-oauth]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"xai-oauth\", model_id = \"{XAI_OAUTH_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the local declaration is admitted");
    let entry = local.connections.get(XAI_OAUTH).expect("declared");
    let loopback = rivect::providers::LoopbackProvider::new();
    assert!(
        !loopback.serves(XAI_OAUTH, entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );
    let err = xai_oauth_provider_result(
        local,
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a local declaration cannot satisfy the required binding");
    assert!(
        matches!(err, ProviderError::CredentialUnresolved { .. }),
        "the kind denial is typed: {err}"
    );
}

// ----- TP-PROVIDER-MATRIX::xai-oauth -----------------------------------------

/// The legs matrix enforces the recorded expected set for `xai-oauth`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside this
/// run, and INSTALLED reports NOT_RUN — the live device-code transition and
/// the `grok.com` accounting origin are never claimed.
#[tokio::test]
async fn xai_oauth_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": XAI_OAUTH_MODEL})]).await;
    mount_responses(
        &server,
        responses_completed_stream(
            "matrix",
            Vec::new(),
            Some(json!({"input_tokens": 1, "output_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&xai_oauth_config(&server_uri_v1(&server))).expect("valid");

    // CATALOG: the authoritative listing under the id-only entry rule.
    let (provider, _store) = xai_oauth_provider(&config);
    let (provider, catalog) = xai_oauth_catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if matches!(
            &catalog,
            Ok(models) if models.iter().any(|model| model.id == XAI_OAUTH_MODEL)
        ) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: a bound ref with no store material denies typed.
    let (provider, _store) = xai_oauth_provider_with(
        &config,
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    );
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
        xai_oauth_provider(&config),
        &config,
        "/world/xai-oauth",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/xai-oauth", manifest);
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
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let (broker, manifest) = prepared_with(
        xai_oauth_provider_with(&config, Arc::clone(&store)),
        &config,
        "/world/xai-oauth",
        "goal: matrix recovery",
    );
    let (broker, denied) = dispatch(broker, "/world/xai-oauth", manifest);
    let denied_ok = matches!(
        denied,
        Err(ModelError::Provider(ProviderError::CredentialAbsent { .. }))
    );
    drop_blocking(broker);
    store.enroll(XAI_OAUTH_REF, XAI_OAUTH_KEY.as_bytes());
    let (broker, manifest) = prepared_with(
        xai_oauth_provider_with(&config, Arc::clone(&store)),
        &config,
        "/world/xai-oauth",
        "goal: matrix recovery",
    );
    let (broker, retried) = dispatch(broker, "/world/xai-oauth", manifest);
    let recovered = matches!(&retried, Ok(reply) if reply.text == "matrix");
    reported.insert(
        "RECOVERY",
        if denied_ok && recovered {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

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

// ----- TP-PROVIDER-INSTALLED::xai-oauth --------------------------------------

/// TP-PROVIDER-INSTALLED::xai-oauth = NOT_RUN: the installed-provider proof
/// is a live-environment leg this offline slice never runs; the live
/// device-code login, refresh, revocation and `grok.com` accounting origin
/// stay out of scope.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::xai-oauth = NOT_RUN"]
fn provider_installed_xai_oauth() {}

// ----- xai -------------------------------------------------------------------

// The `xai` connection's proof legs: the shared Responses adapter serves
// the literal id under its own recorded contract. The api-key bearer is
// required at the scoped `SecretRef` seam, the configured `endpoint`
// carries the API base verbatim and an empty one resolves the recorded
// `https://api.x.ai/v1` default, while a configured `region` is denied:
// the contract names none. The xAI `/models` listing is authoritative and
// carries no vendored floor, so the listing alone offers ids. The listing's
// recorded negative effort residue rejects a pinned effort where it names
// the model; the positive effort ladder, cache migration and SuperGrok
// pool stay residuals.

/// The literal connection id this class serves.
const XAI: &str = "xai";

/// The scoped credential ref carrying the api key.
const XAI_REF: &str = "keyring:rivect-test/xai";

/// Fixture api-key material — never a live key, only ever sent to localhost.
const XAI_KEY: &str = "fixture-xai-api-key";

/// The pinned model id the fixed-pin legs carry — an id outside the
/// recorded effort-suppression residue.
const XAI_MODEL: &str = "grok-4.3";

/// A listing id the recorded residue suppresses: the dial is unsupported.
const XAI_SUPPRESSED_MODEL: &str = "grok-4.20-0309-reasoning";

/// One configured `xai` connection pointing at the fixture peer: the
/// api_key auth class resolves the key through the scoped `SecretRef`
/// seam, and the dialect comes from the literal connection id.
fn xai_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.xai]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{XAI_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"xai\", model_id = \"{XAI_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The shared Responses adapter over an explicit store — the seam the
/// recovery leg enrolls into after its typed denial.
fn xai_provider_result(
    config: Config,
    store: Arc<support::MapStore>,
) -> Result<OpenAiProvider, ProviderError> {
    std::thread::spawn(move || OpenAiProvider::new(&config, XAI, store))
        .join()
        .expect("the provider thread joins")
}

fn xai_provider_with(
    config: &Config,
    store: Arc<support::MapStore>,
) -> (OpenAiProvider, Arc<support::MapStore>) {
    let provider = xai_provider_result(config.clone(), Arc::clone(&store))
        .expect("the shared adapter builds for the xai id");
    (provider, store)
}

/// The adapter over a store seeded with the api key.
fn xai_provider(config: &Config) -> (OpenAiProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(XAI_REF, XAI_KEY)],
    ));
    xai_provider_with(config, store)
}

/// A bare catalogue lookup on a plain OS thread: reqwest's blocking client
/// must not run inside the tokio context.
fn xai_catalog_on_thread(
    provider: OpenAiProvider,
) -> (
    OpenAiProvider,
    Result<Vec<CatalogModel>, ProviderError>,
) {
    std::thread::spawn(move || {
        let catalog = provider.catalog_models();
        (provider, catalog)
    })
    .join()
    .expect("the catalog thread joins")
}

// ----- TP-PROVIDER-WIRE::xai -------------------------------------------------

/// A configured `xai` connection returns a verified model outcome through
/// the standard Broker: the resolved api key rides the bearer, the adapter
/// posts exactly the frozen manifest as a Responses request — `store:
/// false`, `stream: true`, model and instructions verbatim, auto effort
/// emitting no reasoning member and no `include` artifact the recorded
/// contract does not name — and the one physical send is charged once with
/// the provider's reported usage.
#[tokio::test]
async fn xai_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "verified xai outcome",
            Vec::new(),
            Some(json!({"input_tokens": 11, "output_tokens": 7, "total_tokens": 18})),
        ),
    )
    .await;
    let config = Config::parse_validated(&xai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        xai_provider(&config),
        &config,
        "/world/xai",
        "goal: prove the wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/xai", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified xai outcome");
    assert!(reply.tool_calls.is_empty());

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/responses");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {XAI_KEY}"),
        "the resolved api key rides the bearer"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(XAI_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], XAI_MODEL);
    assert_eq!(body["store"], false);
    assert_eq!(body["stream"], true);
    assert!(
        body.get("include").is_none(),
        "the recorded contract names no replay artifact — none is requested: {body}"
    );
    assert_eq!(body["instructions"], manifest.instructions);
    assert!(
        body.get("reasoning").is_none(),
        "auto effort emits no reasoning member: {body}"
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
    assert_eq!(record.connection, XAI);
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 11,
            completion_tokens: 7,
            total_tokens: 18,
        }
    );
    drop_blocking(broker);
}

// ----- TP-PROVIDER-CATALOG::xai ----------------------------------------------

/// The xAI `/models` listing is authoritative: every listed id offers as
/// an id-only entry and no vendored floor adds a model, so an empty
/// listing offers nothing. The listing leg authenticates with the
/// resolved api key.
#[tokio::test]
async fn xai_catalog_is_the_authoritative_listing() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "grok-4.3", "context_length": 1000000, "reasoning": true}),
            json!({"id": "grok-3"}),
        ],
    )
    .await;
    let config = Config::parse_validated(&xai_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = xai_provider(&config);
    let (provider, catalog) = xai_catalog_on_thread(provider);
    let models = catalog.expect("the authoritative listing answers");
    assert_eq!(model_ids(&models), vec!["grok-3", "grok-4.3"]);
    assert!(
        models.iter().all(|model| *model
            == CatalogModel {
                id: model.id.clone(),
                ..CatalogModel::default()
            }),
        "the listing offers ids only, with no mapped surfaces or vendored floor: {models:?}"
    );
    drop_blocking(provider);

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the listing");
    assert_eq!(requests.len(), 1, "one catalogue leg");
    assert_eq!(requests[0].method.as_str(), "GET");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {XAI_KEY}"),
        "the listing leg resolves the scoped key"
    );

    // an empty authoritative listing offers nothing: no retained floor is
    // vendored to fabricate one
    let empty_server = MockServer::start().await;
    mount_models(&empty_server, Vec::new()).await;
    let config =
        Config::parse_validated(&xai_config(&server_uri_v1(&empty_server))).expect("valid");
    let (provider, _store) = xai_provider(&config);
    let (provider, catalog) = xai_catalog_on_thread(provider);
    let models = catalog.expect("the empty listing answers");
    assert!(
        models.is_empty(),
        "an empty authoritative listing offers no fabricated floor: {models:?}"
    );
    drop_blocking(provider);
}

/// A pinned effort on a model the recorded listing suppresses is a
/// parameter the contract rejects: the denial lands typed before the wire
/// body exists, never a request carrying a silently dropped
/// `reasoning.effort`. A non-suppressed id keeps the same pin — the
/// positive effort ladder is a residual, not an invented allowlist.
#[tokio::test]
async fn xai_suppressed_model_rejects_a_pinned_effort() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream("never reached", Vec::new(), None),
    )
    .await;
    let config = Config::parse_validated(
        &xai_config(&server_uri_v1(&server))
            .replace(XAI_MODEL, XAI_SUPPRESSED_MODEL)
            .replace(
                "effort = { mode = \"auto\" }",
                "effort = { mode = \"fixed\", value = \"high\" }",
            ),
    )
    .expect("valid");
    let (broker, manifest) = prepared_with(
        xai_provider(&config),
        &config,
        "/world/xai",
        "goal: suppressed effort",
    );
    let (broker, outcome) = dispatch(broker, "/world/xai", manifest);
    let err = match outcome {
        Err(ModelError::Provider(err)) => err,
        other => panic!("the pinned effort is a typed denial, not a reply: {other:?}"),
    };
    let ProviderError::UnsupportedParameter {
        connection,
        parameter,
        model,
    } = &err
    else {
        panic!("the pinned effort is the typed unsupported parameter: {err:?}")
    };
    assert_eq!(connection, XAI);
    assert_eq!(*parameter, "reasoning_effort");
    assert_eq!(model, XAI_SUPPRESSED_MODEL);
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected parameter charges nothing"
    );
    drop_blocking(broker);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the denial lands before any wire leg"
    );

    // the same pinned effort is admissible on an id outside the residue
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "admissible pinned effort",
            Vec::new(),
            Some(json!({"input_tokens": 1, "output_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(
        &xai_config(&server_uri_v1(&server)).replace(
            "effort = { mode = \"auto\" }",
            "effort = { mode = \"fixed\", value = \"high\" }",
        ),
    )
    .expect("valid");
    let (broker, manifest) = prepared_with(
        xai_provider(&config),
        &config,
        "/world/xai",
        "goal: admissible effort",
    );
    let (broker, outcome) = dispatch(broker, "/world/xai", manifest);
    let reply = outcome.expect("the pin outside the suppression set is admissible");
    assert_eq!(reply.text, "admissible pinned effort");
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "the admissible pin is one physical send");
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["reasoning"]["effort"], "high",
        "the admissible pin rides the reasoning surface: {body}"
    );
    assert_eq!(broker.accounted_requests(), 1);
    drop_blocking(broker);
}

// ----- TP-PROVIDER-AUTH::xai -------------------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `xai`: an absent binding is refused at the config ingress, a configured
/// `region` denies `RegionMismatch`, a profile-bound ref whose scope
/// disagrees denies `CredentialProfileMismatch`, a scoped ref with no
/// resolvable material denies `CredentialAbsent`, and a resolved key the
/// peer refuses is the typed transport denial — no error, nor the offered
/// key or the peer body, reaches Display or Debug.
#[tokio::test]
async fn xai_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // the required binding cannot be absent: the ingress names the member
    let absent = xai_config(&server_uri_v1(&server))
        .replace(&format!("credential_ref = \"{XAI_REF}\"\n"), "");
    let err = Config::parse_validated(&absent).expect_err("the required binding cannot be absent");
    assert!(
        matches!(err.issue, ConfigIssue::CredentialRefRequired { .. }),
        "the absent binding is the typed ingress denial: {err}"
    );

    // a configured region is denied — never ignored — with a sibling scope
    // holding material so the no-secret assertion proves no cross-scope leak
    let regioned = Config::parse_validated(
        &xai_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = xai_provider_result(
        regioned,
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, XAI_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, XAI);
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, XAI_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.xai]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"xai\", model_id = \"{XAI_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = xai_provider_result(
        mismatched,
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, XAI_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, XAI_KEY.as_bytes());

    // a bound scope the store cannot resolve denies before any wire leg
    let config = Config::parse_validated(&xai_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = xai_provider_with(
        &config,
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, XAI_KEY)],
        )),
    );
    let (provider, denied) = send_on_thread(provider, prepared_manifest(&config));
    let Err(denied) = denied else {
        panic!("an unresolvable key never produces a reply")
    };
    assert!(
        matches!(&denied, ProviderError::CredentialAbsent { .. }),
        "the unresolved binding denies typed: {denied}"
    );
    assert_no_secret_or_body(&denied, XAI_KEY.as_bytes());
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("the mock recorded no send")
            .is_empty(),
        "the credential denial sends no byte"
    );

    // a resolved key the peer refuses is a typed transport denial: the
    // wire never coerces a wrong credential into success
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&xai_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = xai_provider(&config);
    let (provider, refused) = send_on_thread(provider, prepared_manifest(&config));
    let refused = refused.expect_err("a refused key is the typed transport denial");
    let ProviderError::Transport { connection, cause } = &refused else {
        panic!("a refused key is transport: {refused}")
    };
    assert_eq!(connection, XAI);
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&refused, XAI_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(requests[0].url.path(), "/v1/responses");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {XAI_KEY}"),
        "the resolved key reached the wire — the denial is the peer's status"
    );
}

// ----- TP-PROVIDER-RECOVERY::xai ---------------------------------------------

/// Hostile Responses input never reports success for `xai`: a stream
/// ended mid function-call item — a partial call that never executes — is
/// the typed stream violation, an unclassifiable completion status is the
/// unknown terminal, and a rejected send charges nothing.
#[tokio::test]
async fn xai_rejects_partial_tool_block_and_unknown_terminal() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        sse_block(
            "response.output_item.added",
            &json!({
                "item": {
                    "id": "fc_1",
                    "type": "function_call",
                    "status": "in_progress",
                    "name": "read_file",
                    "arguments": "",
                },
                "output_index": 0,
            }),
        ),
    )
    .await;
    let config = Config::parse_validated(&xai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        xai_provider(&config),
        &config,
        "/world/xai",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/xai", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "EOF mid function-call item is the stream violation — never a usable call: {outcome:?}"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected send charges nothing"
    );
    drop_blocking(broker);

    // a completion status the dialect cannot classify is unknown, never
    // success
    let server = MockServer::start().await;
    mount_responses(
        &server,
        sse_block(
            "response.completed",
            &json!({"response": {"id": "resp_1", "status": "mystery", "output": []}}),
        ),
    )
    .await;
    let config = Config::parse_validated(&xai_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        xai_provider(&config),
        &config,
        "/world/xai",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/xai", manifest);
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

/// A typed credential denial is recoverable through the same seam: after
/// the scoped key is enrolled, the corrected binding returns one outcome
/// and exactly one accounted physical request.
#[tokio::test]
async fn xai_typed_denial_recovers_after_correct_binding() {
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "recovered xai outcome",
            Vec::new(),
            Some(json!({"input_tokens": 3, "output_tokens": 2, "total_tokens": 5})),
        ),
    )
    .await;
    let config = Config::parse_validated(&xai_config(&server_uri_v1(&server))).expect("valid");

    // the empty store denies typed and sends nothing
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let (broker, manifest) = prepared_with(
        xai_provider_with(&config, Arc::clone(&store)),
        &config,
        "/world/xai",
        "goal: typed denial",
    );
    let (broker, denied) = dispatch(broker, "/world/xai", manifest);
    assert!(
        matches!(
            denied,
            Err(ModelError::Provider(ProviderError::CredentialAbsent { .. }))
        ),
        "the empty store is the typed absent credential: {denied:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);
    assert!(
        server
            .received_requests()
            .await
            .expect("the mock recorded no send")
            .is_empty(),
        "the denial sends no byte"
    );

    // the corrected binding is one outcome and one physical usage
    store.enroll(XAI_REF, XAI_KEY.as_bytes());
    let (broker, manifest) = prepared_with(
        xai_provider_with(&config, Arc::clone(&store)),
        &config,
        "/world/xai",
        "goal: corrected binding",
    );
    let (broker, outcome) = dispatch(broker, "/world/xai", manifest);
    let reply = outcome.expect("the corrected binding dispatches");
    assert_eq!(reply.text, "recovered xai outcome");
    assert_eq!(broker.accounted_requests(), 1);
    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "the recovery is one physical request");
    assert_eq!(requests[0].url.path(), "/v1/responses");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {XAI_KEY}"),
        "the corrected key rides the bearer"
    );
    drop_blocking(broker);
}

// ----- TP-PROVIDER-DIALECT::xai ----------------------------------------------

/// The dialect is keyed on the literal connection id: the map routes `xai`
/// to the shared Responses dialect, an empty endpoint resolves the recorded
/// `api.x.ai/v1` base — never a sibling class's default — a configured
/// base stays verbatim, and loopback never serves the reserved id.
#[test]
fn xai_discriminates_the_recorded_default_base() {
    assert_eq!(
        rivect::providers::dialect_for(XAI),
        Some(rivect::providers::Dialect::Responses)
    );

    // the required endpoint's empty string resolves the recorded base —
    // proved on the adapter's `Debug` surface, no byte toward the host
    let config = Config::parse_validated(&xai_config("")).expect("the fixture config is valid");
    let (provider, _store) = xai_provider(&config);
    let debug = format!("{provider:?}");
    assert!(
        debug.contains("endpoint: \"https://api.x.ai/v1\""),
        "an empty endpoint resolves the recorded base: {debug}"
    );
    assert!(
        !debug.contains("api.openai.com")
            && !debug.contains("api.sakana.ai")
            && !debug.contains("openrouter.ai")
            && !debug.contains("127.0.0.1"),
        "xai never borrows a sibling class's base: {debug}"
    );
    drop_blocking(provider);

    // a configured base wins verbatim, trailing slashes trimmed
    let configured = Config::parse_validated(&xai_config("https://api.x.ai/v1///"))
        .expect("the trailing-slash config is valid");
    let (provider, _store) = xai_provider(&configured);
    assert!(
        format!("{provider:?}").contains("endpoint: \"https://api.x.ai/v1\""),
        "the configured base is normalized, not replaced"
    );
    drop_blocking(provider);

    // loopback never serves the reserved id, and the required-binding
    // contract denies the credential-free kind
    let local = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.xai]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"xai\", model_id = \"{XAI_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the local declaration is admitted");
    let entry = local.connections.get(XAI).expect("declared");
    let loopback = rivect::providers::LoopbackProvider::new();
    assert!(
        !loopback.serves(XAI, entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );
    let err = xai_provider_result(
        local,
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a local declaration cannot satisfy the required binding");
    assert!(
        matches!(err, ProviderError::CredentialUnresolved { .. }),
        "the kind denial is typed: {err}"
    );
}

// ----- TP-PROVIDER-MATRIX::xai -----------------------------------------------

/// The legs matrix enforces the recorded expected set for `xai`: CATALOG,
/// AUTH, WIRE and RECOVERY each execute and report inside this run, and
/// INSTALLED reports NOT_RUN — no live xAI call is ever claimed.
#[tokio::test]
async fn xai_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": XAI_MODEL})]).await;
    mount_responses(
        &server,
        responses_completed_stream(
            "matrix",
            Vec::new(),
            Some(json!({"input_tokens": 1, "output_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&xai_config(&server_uri_v1(&server))).expect("valid");

    // CATALOG: the authoritative listing under the id-only entry rule.
    let (provider, _store) = xai_provider(&config);
    let (provider, catalog) = xai_catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if matches!(
            &catalog,
            Ok(models) if models.iter().any(|model| model.id == XAI_MODEL)
        ) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: a bound ref with no store material denies typed.
    let (provider, _store) = xai_provider_with(
        &config,
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    );
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
        xai_provider(&config),
        &config,
        "/world/xai",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/xai", manifest);
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
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let (broker, manifest) = prepared_with(
        xai_provider_with(&config, Arc::clone(&store)),
        &config,
        "/world/xai",
        "goal: matrix recovery",
    );
    let (broker, denied) = dispatch(broker, "/world/xai", manifest);
    let denied_ok = matches!(
        denied,
        Err(ModelError::Provider(ProviderError::CredentialAbsent { .. }))
    );
    drop_blocking(broker);
    store.enroll(XAI_REF, XAI_KEY.as_bytes());
    let (broker, manifest) = prepared_with(
        xai_provider_with(&config, Arc::clone(&store)),
        &config,
        "/world/xai",
        "goal: matrix recovery",
    );
    let (broker, retried) = dispatch(broker, "/world/xai", manifest);
    let recovered = matches!(&retried, Ok(reply) if reply.text == "matrix");
    reported.insert(
        "RECOVERY",
        if denied_ok && recovered {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

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

// ----- TP-PROVIDER-INSTALLED::xai --------------------------------------------

/// TP-PROVIDER-INSTALLED::xai = NOT_RUN: the installed-provider proof is a
/// live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::xai = NOT_RUN"]
fn provider_installed_xai() {}

// ----- wafer-serverless ------------------------------------------------------

// The `wafer-serverless` connection's proof legs (HZN-008 class B — the
// api-key cell): the shared Chat Completions adapter serves the literal
// id under its own recorded predicates. The configured `endpoint`
// carries the API base verbatim, an empty one resolves the recorded
// `https://pass.wafer.ai/v1` default, and a configured `region` is
// denied: the contract names none. The descriptor's `oauthProvider`
// row is abstract login metadata, never an OAuth class — the recorded
// auth is the api key riding the plain bearer. The authoritative
// `/v1/models` listing carries the `wafer` envelope: `context_length`
// (with the recorded top-level `max_model_len` fallback), the
// `capabilities` reasoning/vision marks, and the per-million cents
// price converted to the public Serverless USD rate
// (`cents × 125 / 10000`). The envelope's upstream `provider` thinking
// shape (`thinking`/`enable_thinking`/`reasoning_effort`), the
// tools-capability mark and the `zdr_supported` flag have no manifest
// carrier — residuals, never fabricated fields — and the recorded
// reasoning control is not `reasoning_effort`, so a pinned effort
// denies typed rather than being dropped at the send seam.

/// The literal connection id this class serves.
const WAFER: &str = "wafer-serverless";

/// The scoped credential ref the declaration binds.
const WAFER_REF: &str = "keyring:rivect-test/wafer-serverless";

/// Fixture api-key material — never a real credential, only ever sent to
/// localhost.
const WAFER_KEY: &str = "fixture-wafer-serverless-key";

/// The pinned model id the fixed-pin legs carry — a listed id.
const WAFER_MODEL: &str = "glm-4.6";

/// One `wafer-serverless` connection pointing at the fixture peer: the
/// api-key class binds its scoped model-request key, and auto effort
/// keeps the pinned-effort denial out of the control leg.
fn wafer_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.wafer-serverless]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{WAFER_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"wafer-serverless\", model_id = \"{WAFER_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The adapter over an explicit store — the seam the recovery leg enrolls
/// into after its typed denial.
fn wafer_provider_with(
    config: &Config,
    store: Arc<support::MapStore>,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let provider = provider_result(config.clone(), WAFER.to_string(), store.clone())
        .expect("the shared adapter builds for the wafer-serverless id");
    (provider, store)
}

/// The adapter over a store seeded with the recorded api key.
fn wafer_provider(
    config: &Config,
    material: Option<&str>,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = match material {
        None => Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        Some(material) => {
            Arc::new(support::MapStore::seeded(STORE_KIND, &[(WAFER_REF, material)]))
        }
    };
    wafer_provider_with(config, store)
}

// ----- TP-PROVIDER-WIRE::wafer-serverless ------------------------------------

/// A configured `wafer-serverless` connection returns a verified model
/// outcome through the standard Broker: the api_key pin prepares
/// offline, the adapter posts exactly the frozen manifest as a
/// `chat/completions` request — model id verbatim, system+user
/// messages, `stream` with the shared `stream_options.include_usage`,
/// auto effort emitting no `reasoning_effort` member — the SSE stream
/// validates its terminal, and the one physical send is charged once
/// with the reported usage. The descriptor's `oauthProvider` row is
/// login metadata, so the declaration's class is the recorded api key,
/// never a subscription form.
#[tokio::test]
async fn wafer_serverless_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified wafer outcome",
            Some(json!({"prompt_tokens": 10, "completion_tokens": 6, "total_tokens": 16})),
        ),
    )
    .await;
    let config = Config::parse_validated(&wafer_config(&server_uri_v1(&server))).expect("valid");
    assert_eq!(
        config.connections[WAFER].kind,
        rivect::config::ConnKind::ApiKey,
        "the descriptor's oauthProvider metadata is not an OAuth class: the recorded auth is api-key"
    );
    assert_eq!(
        config.connections[WAFER].credential_ref.as_deref(),
        Some(WAFER_REF),
        "the recorded api-key class binds its scoped ref"
    );
    let (broker, manifest) = prepared_with(
        wafer_provider(&config, Some(WAFER_KEY)),
        &config,
        "/world/wafer",
        "goal: prove the wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/wafer", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified wafer outcome");
    assert!(reply.tool_calls.is_empty());

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {WAFER_KEY}"),
        "the resolved api key bears the wire"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(WAFER_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"], WAFER_MODEL,
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
        "the shared Chat Completions envelope keeps the usage report"
    );
    assert!(
        body.get("reasoning_effort").is_none(),
        "auto effort emits no reasoning_effort member"
    );

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, WAFER);
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 10,
            completion_tokens: 6,
            total_tokens: 16,
        }
    );
    drop_blocking(broker);
}

// ----- TP-PROVIDER-CATALOG::wafer-serverless ---------------------------------

/// The authoritative `/v1/models` listing maps the `wafer` envelope
/// fields the entry actually states: `context_length` (falling back to
/// the recorded top-level `max_model_len`), the reasoning and vision
/// capability marks, the output cap at the recorded 65536 ceiling, and
/// the per-million cents price converted to the public Serverless USD
/// rate. A field the entry does not state stays empty or `Unknown` —
/// never a default — and the envelope's thinking shape, tools mark and
/// ZDR flag land nowhere because no manifest carrier exists.
#[tokio::test]
async fn wafer_serverless_catalog_maps_the_envelope() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({
                "id": WAFER_MODEL,
                "wafer": {
                    "context_length": 200000,
                    "provider": "zai",
                    "capabilities": {"reasoning": true, "vision": false, "tools": true},
                    "pricing": {
                        "input_cents_per_million": 160,
                        "output_cents_per_million": 320,
                        "cache_read_cents_per_million": 40,
                    },
                    "display_name": "GLM 4.6",
                    "zdr_supported": true,
                },
            }),
            json!({
                "id": "qwen-vl",
                "wafer": {
                    "context_length": 32768,
                    "capabilities": {"vision": true},
                },
            }),
            json!({"id": "context-capped", "wafer": {"context_length": 131072}}),
            json!({"id": "legacy-window", "max_model_len": 65536}),
            json!({"id": "bare"}),
            json!({
                "id": "string-cents",
                "wafer": {"pricing": {
                    "input_cents_per_million": "80",
                    "output_cents_per_million": "160",
                }},
            }),
            json!({
                "id": "partial-price",
                "wafer": {"pricing": {"input_cents_per_million": 80}},
            }),
            json!({"id": "   "}),
        ],
    )
    .await;
    let config = Config::parse_validated(&wafer_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = wafer_provider(&config, Some(WAFER_KEY));
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the authoritative listing answers");
    assert_eq!(
        models,
        vec![
            CatalogModel {
                id: "bare".to_string(),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "context-capped".to_string(),
                context_window: Some(131072),
                max_output_tokens: Some(65536),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: WAFER_MODEL.to_string(),
                reasoning: true,
                context_window: Some(200000),
                max_output_tokens: Some(65536),
                price: ModelPrice::Usd {
                    input_per_1m: 2.0,
                    output_per_1m: 4.0,
                },
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "legacy-window".to_string(),
                context_window: Some(65536),
                max_output_tokens: Some(65536),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "partial-price".to_string(),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "qwen-vl".to_string(),
                vision: true,
                context_window: Some(32768),
                max_output_tokens: Some(32768),
                ..CatalogModel::default()
            },
            CatalogModel {
                id: "string-cents".to_string(),
                price: ModelPrice::Usd {
                    input_per_1m: 1.0,
                    output_per_1m: 2.0,
                },
                ..CatalogModel::default()
            },
        ],
        "the envelope maps only the fields each entry states"
    );
    assert!(
        models
            .iter()
            .all(|model| model.efforts.is_empty() && model.effort_default.is_none()),
        "the upstream thinking shape has no manifest carrier: no effort dial is invented"
    );
    drop_blocking(provider);

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the listing");
    assert_eq!(requests.len(), 1, "the listing is the one catalogue leg");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {WAFER_KEY}"),
        "the api-key listing leg resolves the scoped key"
    );

    // the authoritative listing is seedless: an empty answer has no floor
    let empty = MockServer::start().await;
    mount_models(&empty, Vec::new()).await;
    let config = Config::parse_validated(&wafer_config(&server_uri_v1(&empty))).expect("valid");
    let (provider, _store) = wafer_provider(&config, Some(WAFER_KEY));
    let (provider, catalog) = catalog_on_thread(provider);
    assert_eq!(
        catalog.expect("an empty listing is an empty catalogue, not a denial"),
        Vec::new(),
        "no floor is invented for the seedless class"
    );
    drop_blocking(provider);
}

// ----- TP-PROVIDER-RECOVERY::wafer-serverless --------------------------------

/// The recorded reasoning control is the upstream `thinking` shape, not
/// `reasoning_effort`: a pinned effort denies typed before any wire leg
/// and charges nothing — it is never silently dropped from the body.
#[tokio::test]
async fn wafer_serverless_pinned_effort_denies_not_dropped() {
    let server = MockServer::start().await;
    mount_chat(&server, completed_stream("never reached", None)).await;
    let config = Config::parse_validated(
        &wafer_config(&server_uri_v1(&server)).replace(
            "effort = { mode = \"auto\" }",
            "effort = { mode = \"fixed\", value = \"medium\" }",
        ),
    )
    .expect("valid");
    let (broker, manifest) = prepared_with(
        wafer_provider(&config, Some(WAFER_KEY)),
        &config,
        "/world/wafer",
        "goal: pinned effort",
    );
    let (broker, outcome) = dispatch(broker, "/world/wafer", manifest);
    let err = match outcome {
        Err(ModelError::Provider(err)) => err,
        other => panic!("the pinned effort is a typed denial, not a reply: {other:?}"),
    };
    let ProviderError::UnsupportedParameter {
        connection,
        parameter,
        model,
    } = &err
    else {
        panic!("the pinned effort is the typed unsupported parameter: {err:?}")
    };
    assert_eq!(connection, WAFER);
    assert_eq!(*parameter, "reasoning_effort");
    assert_eq!(model, WAFER_MODEL);
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected parameter charges nothing"
    );
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

// ----- TP-PROVIDER-AUTH::wafer-serverless ------------------------------------

/// Wrong, absent or unresolvable credential, or a configured region,
/// never produce a false success for `wafer-serverless`: an unbound
/// declaration is refused at ingress, a bound scope the store cannot
/// resolve denies `CredentialAbsent` with no wire leg, a configured
/// `region` denies `RegionMismatch`, a profile-bound ref whose scope
/// disagrees with the binding denies `CredentialProfileMismatch`, and a
/// refused api key lands the typed transport denial carrying the peer's
/// status alone — no error, nor the offered credential material or the
/// peer's body, reaches Display or Debug.
#[tokio::test]
async fn wafer_serverless_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets()
{
    let server = MockServer::start().await;

    // the recorded api-key class requires its scoped binding at ingress
    let unbound = wafer_config(&server_uri_v1(&server))
        .replace(&format!("credential_ref = \"{WAFER_REF}\"\n"), "");
    let err = Config::parse_validated(&unbound)
        .expect_err("the recorded class requires its scoped binding at ingress");
    assert!(
        matches!(err.issue, ConfigIssue::CredentialRefRequired { .. }),
        "the unbound declaration is the typed ingress denial: {err}"
    );

    // a bound scope the store cannot resolve denies before any wire leg
    let config = Config::parse_validated(&wafer_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = wafer_provider(&config, None);
    let (provider, denied) = send_on_thread(provider, prepared_manifest(&config));
    let err = denied.expect_err("the unresolved binding denies typed");
    assert!(
        matches!(err, ProviderError::CredentialAbsent { .. }),
        "the absent api key is the typed denial: {err}"
    );
    assert_no_secret_or_body(&err, WAFER_KEY.as_bytes());
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the unresolved binding opened no wire leg"
    );

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &wafer_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        WAFER.to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, WAFER_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, WAFER);
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, WAFER_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.wafer-serverless]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"wafer-serverless\", model_id = \"{WAFER_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        WAFER.to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, WAFER_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, WAFER_KEY.as_bytes());

    // a refused key is a typed transport denial: the wire never coerces a
    // wrong credential into success, and the request carried the bearer
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let (provider, _store) = wafer_provider(&config, Some(WAFER_KEY));
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused key is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused key is transport: {err}")
    };
    assert_eq!(connection, WAFER);
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, WAFER_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {WAFER_KEY}"),
        "the admitted bearer reached the wire — the denial is the peer's status"
    );
}

// ----- TP-PROVIDER-RECOVERY::wafer-serverless (adverse wire) ------------------

/// Hostile stream input never reports success for `wafer-serverless`: a
/// stream ended mid `tool_calls` fragment — a partial call that never
/// executes — and a finish_reason the dialect cannot classify are each
/// the unknown terminal, and a rejected send charges nothing.
#[tokio::test]
async fn wafer_serverless_rejects_partial_tool_block_and_unknown_terminal() {
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
    let config = Config::parse_validated(&wafer_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        wafer_provider(&config, Some(WAFER_KEY)),
        &config,
        "/world/wafer",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/wafer", manifest);
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

    // a finish_reason the dialect cannot classify is unknown, never success
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
    let config = Config::parse_validated(&wafer_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        wafer_provider(&config, Some(WAFER_KEY)),
        &config,
        "/world/wafer",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/wafer", manifest);
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

// ----- TP-PROVIDER-DIALECT::wafer-serverless ----------------------------------

/// The dialect is keyed on the literal connection id: the map routes
/// `wafer-serverless` to the shared Chat Completions dialect, an empty
/// endpoint resolves its own recorded `pass.wafer.ai/v1` base — never a
/// sibling class's default — a configured base stays verbatim, and
/// loopback never serves the reserved id.
#[test]
fn wafer_serverless_discriminates_the_recorded_default_base() {
    assert_eq!(
        rivect::providers::dialect_for(WAFER),
        Some(rivect::providers::Dialect::ChatCompletions)
    );

    // the required endpoint's empty string resolves the recorded base —
    // proved on the adapter's `Debug` surface, no byte toward the host
    let config = Config::parse_validated(&wafer_config("")).expect("the fixture config is valid");
    let provider = provider_result(
        config,
        WAFER.to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("the shared adapter builds for the wafer-serverless id");
    let debug = format!("{provider:?}");
    assert!(
        debug.contains("endpoint: \"https://pass.wafer.ai/v1\""),
        "an empty endpoint resolves the recorded base: {debug}"
    );
    assert!(
        !debug.contains("127.0.0.1")
            && !debug.contains("api.venice.ai")
            && !debug.contains("api.x.ai"),
        "wafer-serverless never borrows a sibling class's base: {debug}"
    );
    drop_blocking(provider);

    // a configured base wins verbatim, trailing slashes trimmed
    let configured = Config::parse_validated(&wafer_config("https://pass.wafer.ai/v1/"))
        .expect("the trailing-slash config is valid");
    let provider = provider_result(
        configured,
        WAFER.to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("the shared adapter builds for the wafer-serverless id");
    assert!(
        format!("{provider:?}").contains("endpoint: \"https://pass.wafer.ai/v1\""),
        "the configured base is normalized, not replaced"
    );
    drop_blocking(provider);

    // loopback never serves the reserved id, and the required-binding
    // contract denies the credential-free kind
    let local = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.wafer-serverless]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"wafer-serverless\", model_id = \"{WAFER_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the local declaration is admitted");
    let entry = local.connections.get(WAFER).expect("declared");
    let loopback = rivect::providers::LoopbackProvider::new();
    assert!(
        !loopback.serves(WAFER, entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );
    let err = provider_result(
        local,
        WAFER.to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a local declaration cannot satisfy the required binding");
    assert!(
        matches!(err, ProviderError::CredentialUnresolved { .. }),
        "the kind denial is typed: {err}"
    );
}

// ----- TP-PROVIDER-MATRIX::wafer-serverless -----------------------------------

/// The legs matrix enforces the recorded expected set for
/// `wafer-serverless`: CATALOG, AUTH, WIRE and RECOVERY each execute and
/// report inside this run, and INSTALLED reports NOT_RUN.
#[tokio::test]
async fn wafer_serverless_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![json!({
            "id": WAFER_MODEL,
            "wafer": {
                "context_length": 200000,
                "capabilities": {"reasoning": true},
                "pricing": {"input_cents_per_million": 160, "output_cents_per_million": 320},
            },
        })],
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
    let config = Config::parse_validated(&wafer_config(&server_uri_v1(&server))).expect("valid");

    // CATALOG: the authoritative keyed listing under the envelope transform.
    let (provider, _store) = wafer_provider(&config, Some(WAFER_KEY));
    let (provider, catalog) = catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if matches!(
            &catalog,
            Ok(models) if models.iter().any(|model| model.id == WAFER_MODEL
                && model.reasoning
                && model.context_window == Some(200000)
                && model.price == ModelPrice::Usd {
                    input_per_1m: 2.0,
                    output_per_1m: 4.0,
                })
        ) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: a bound ref with no store material denies typed.
    let (provider, _store) = wafer_provider(&config, None);
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
        wafer_provider(&config, Some(WAFER_KEY)),
        &config,
        "/world/wafer",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/wafer", manifest);
    reported.insert(
        "WIRE",
        if matches!(&outcome, Ok(reply) if reply.text == "matrix") {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

    // RECOVERY: the typed denial is followed by a successful retry through
    // the same credential seam.
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let (broker, manifest) = prepared_with(
        wafer_provider_with(&config, Arc::clone(&store)),
        &config,
        "/world/wafer",
        "goal: matrix recovery",
    );
    let (broker, denied) = dispatch(broker, "/world/wafer", manifest);
    let denied_ok = matches!(
        denied,
        Err(ModelError::Provider(ProviderError::CredentialAbsent { .. }))
    );
    drop_blocking(broker);
    store.enroll(WAFER_REF, WAFER_KEY.as_bytes());
    let (broker, manifest) = prepared_with(
        wafer_provider_with(&config, Arc::clone(&store)),
        &config,
        "/world/wafer",
        "goal: matrix recovery",
    );
    let (broker, retried) = dispatch(broker, "/world/wafer", manifest);
    let recovered = matches!(&retried, Ok(reply) if reply.text == "matrix");
    reported.insert(
        "RECOVERY",
        if denied_ok && recovered {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

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

// ----- TP-PROVIDER-INSTALLED::wafer-serverless --------------------------------

/// TP-PROVIDER-INSTALLED::wafer-serverless = NOT_RUN: the
/// installed-provider proof is a live-environment leg this offline slice
/// never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::wafer-serverless = NOT_RUN"]
fn provider_installed_wafer_serverless() {}

// ----- xiaomi ----------------------------------------------------------------

// The `xiaomi` connection's proof legs (HZN-008 class B — the PAYG
// api-key cell): the shared Chat Completions adapter serves the literal id
// under its own recorded predicates. The configured `endpoint` carries the
// API base verbatim, an empty one resolves the recorded PAYG literal
// `https://api.xiaomimimo.com/v1`, and a configured `region` is denied: the
// contract names none. The three token-plan bases are separate literals, and
// this arm never selects one — not from a `tp-` key prefix, not from a
// profile, and never by probing another cluster (PROH-010): the configured
// base is the only host a leg opens a wire toward. The `/models` listing is
// the whole catalogue under ids-only offers, and the plain bearer carries
// the PAYG key.

/// The literal connection id this class serves.
const XIAOMI: &str = "xiaomi";

/// The scoped credential ref the declaration binds.
const XIAOMI_REF: &str = "keyring:rivect-test/xiaomi";

/// Fixture PAYG key material — never a real credential, only ever sent to a
/// loopback fixture.
const XIAOMI_KEY: &str = "fixture-xiaomi-payg-key";

/// A fixture key shaped like a token-plan key: the class records no key-class
/// sniffing, so this prefix selects no base.
const XIAOMI_TOKEN_PLAN_SHAPED_KEY: &str = "tp-fixture-token-plan-key";

/// The pinned model id the fixed-pin legs carry — a listed id.
const XIAOMI_MODEL: &str = "mimo-v2-flash";

/// One `xiaomi` connection pointing at the fixture peer: the api-key class
/// binds its scoped PAYG key, so the declaration carries the ref the send
/// must resolve.
fn xiaomi_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.xiaomi]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{XIAOMI_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"xiaomi\", model_id = \"{XIAOMI_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The adapter over an explicit store — the seam the recovery leg enrolls
/// into after its typed denial.
fn xiaomi_provider_with(
    config: &Config,
    store: Arc<support::MapStore>,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let provider = provider_result(config.clone(), XIAOMI.to_string(), store.clone())
        .expect("the shared adapter builds for the xiaomi id");
    (provider, store)
}

/// The adapter over a store seeded with the recorded PAYG key, or an empty
/// store for the absent-binding leg.
fn xiaomi_provider(
    config: &Config,
    material: Option<&str>,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = match material {
        None => Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        Some(material) => {
            Arc::new(support::MapStore::seeded(STORE_KIND, &[(XIAOMI_REF, material)]))
        }
    };
    xiaomi_provider_with(config, store)
}

// ----- TP-PROVIDER-WIRE::xiaomi ----------------------------------------------

/// A configured `xiaomi` connection returns a verified model outcome through
/// the standard Broker: the api-key pin prepares offline, the adapter posts
/// exactly the frozen manifest as a `chat/completions` request — model id
/// verbatim, system+user messages, `stream` and the shared
/// `stream_options.include_usage` member — under the resolved bearer, never a
/// `reasoning_effort` for auto effort — the SSE stream validates its
/// terminal, and the one physical send is charged once with the reported
/// usage.
#[tokio::test]
async fn xiaomi_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified xiaomi outcome",
            Some(json!({"prompt_tokens": 9, "completion_tokens": 4, "total_tokens": 13})),
        ),
    )
    .await;
    let config = Config::parse_validated(&xiaomi_config(&server_uri_v1(&server))).expect("valid");
    assert_eq!(
        config.connections[XIAOMI].credential_ref.as_deref(),
        Some(XIAOMI_REF),
        "the recorded api-key class binds its scoped ref"
    );
    let (broker, manifest) = prepared_with(
        xiaomi_provider(&config, Some(XIAOMI_KEY)),
        &config,
        "/world/xiaomi",
        "goal: prove the wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/xiaomi", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified xiaomi outcome");
    assert!(reply.tool_calls.is_empty());

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {XIAOMI_KEY}"),
        "the resolved PAYG key bears the wire"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"], XIAOMI_MODEL,
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
        "the shared Chat Completions body asks for the usage report"
    );
    assert!(
        body.get("reasoning_effort").is_none(),
        "auto effort emits no reasoning_effort member"
    );

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, XIAOMI);
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

// ----- TP-PROVIDER-CATALOG::xiaomi -------------------------------------------

/// The configured base's `/models` listing is the whole catalogue and the
/// configured base is the only host any leg contacts: the listing and the send
/// both ride the configured peer, a stand-in for another cluster receives
/// nothing, and a token-plan-shaped key resolves the PAYG literal rather than
/// selecting a token-plan host (PROH-010). A failed listing is the typed
/// denial on its one attempt — never a fallback to another cluster.
#[tokio::test]
async fn xiaomi_never_probes_another_region() {
    // a token-plan stand-in: mounted and answering, but never configured, so
    // any byte it sees would be an unrecorded cross-cluster probe
    let sibling = MockServer::start().await;
    mount_models(&sibling, vec![json!({"id": "token-plan-sibling"})]).await;
    mount_chat(&sibling, completed_stream("sibling", None)).await;

    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": XIAOMI_MODEL})]).await;
    mount_chat(&server, completed_stream("payg", None)).await;
    let config = Config::parse_validated(&xiaomi_config(&server_uri_v1(&server))).expect("valid");

    let (provider, _store) = xiaomi_provider(&config, Some(XIAOMI_KEY));
    let (provider, catalog) = catalog_on_thread(provider);
    assert_eq!(
        catalog.expect("the PAYG listing answers"),
        vec![CatalogModel {
            id: XIAOMI_MODEL.to_string(),
            ..CatalogModel::default()
        }],
        "the listing is offered id-only under the recorded transform"
    );
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    outcome.expect("the configured PAYG base serves the send");
    drop_blocking(provider);

    let primary = server.received_requests().await.expect("recorded");
    assert_eq!(
        primary.len(),
        2,
        "one listing and one chat request on the configured base"
    );
    assert_eq!(primary[0].url.path(), "/v1/models");
    assert_eq!(primary[1].url.path(), "/v1/chat/completions");
    for request in &primary {
        assert_eq!(received_auth(request), format!("Bearer {XIAOMI_KEY}"));
    }
    let sibling_requests = sibling.received_requests().await.expect("recorded");
    assert!(
        sibling_requests.is_empty(),
        "no other cluster was contacted: {sibling_requests:?}"
    );

    // a token-plan-shaped key selects no base: the empty endpoint still
    // resolves the PAYG literal, and no token-plan host appears anywhere
    let config = Config::parse_validated(&xiaomi_config("")).expect("valid");
    let provider = provider_result(
        config,
        XIAOMI.to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(XIAOMI_REF, XIAOMI_TOKEN_PLAN_SHAPED_KEY)],
        )),
    )
    .expect("the shared adapter builds for the xiaomi id");
    let debug = format!("{provider:?}");
    assert!(
        debug.contains("endpoint: \"https://api.xiaomimimo.com/v1\""),
        "the PAYG literal is the recorded default: {debug}"
    );
    assert!(
        !debug.contains("token-plan-"),
        "a token-plan-shaped key never selects a cluster: {debug}"
    );
    drop_blocking(provider);
    assert!(
        sibling.received_requests().await.expect("recorded").is_empty(),
        "resolving the key opened no probe to the stand-in cluster"
    );

    // a failed listing is a typed denial on its one attempt: no fallback
    // to a sibling cluster, and nothing accounted
    let failing = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&failing)
        .await;
    let config = Config::parse_validated(&xiaomi_config(&server_uri_v1(&failing))).expect("valid");
    let (provider, _store) = xiaomi_provider(&config, Some(XIAOMI_KEY));
    let (provider, denied) = catalog_on_thread(provider);
    let ProviderError::Transport { connection, cause } =
        denied.expect_err("a failed listing denies typed instead of inventing a floor")
    else {
        panic!("a failed listing is the typed transport denial")
    };
    assert_eq!(connection, XIAOMI);
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 500 },
        "the peer's status is the context: {cause}"
    );
    drop_blocking(provider);
    assert_eq!(
        failing.received_requests().await.expect("recorded").len(),
        1,
        "the failed listing is one attempt, never a cross-cluster retry"
    );
    assert!(
        sibling.received_requests().await.expect("recorded").is_empty(),
        "the failed leg never reached another cluster"
    );
}

// ----- TP-PROVIDER-AUTH::xiaomi ----------------------------------------------

/// Wrong, absent or unresolvable credential, or a configured region, never
/// produce a false success for `xiaomi`: a configured `region` — the recorded
/// contract names none — denies `RegionMismatch` with the connection context,
/// a profile-bound ref whose scope disagrees with the binding denies
/// `CredentialProfileMismatch`, an unseeded binding denies `CredentialAbsent`
/// before any wire leg, and a refused PAYG key lands the typed transport
/// denial carrying the peer's status alone — no error, nor the offered
/// credential material or the peer's body, reaches Display or Debug.
#[tokio::test]
async fn xiaomi_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling scope
    // holds real material so the no-secret assertion proves no cross-scope
    // leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &xiaomi_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        XIAOMI.to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, XIAOMI_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, XIAOMI);
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, XIAOMI_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.xiaomi]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"xiaomi\", model_id = \"{XIAOMI_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        XIAOMI.to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, XIAOMI_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, XIAOMI_KEY.as_bytes());

    // an unresolvable binding denies before opening a chat leg
    let config = Config::parse_validated(&xiaomi_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = xiaomi_provider(&config, None);
    let (provider, denied) = send_on_thread(provider, prepared_manifest(&config));
    let err = denied.expect_err("an unseeded binding denies typed");
    assert!(
        matches!(err, ProviderError::CredentialAbsent { .. }),
        "the absent PAYG key is the typed denial: {err}"
    );
    assert_no_secret_or_body(&err, XIAOMI_KEY.as_bytes());
    drop_blocking(provider);
    assert!(
        server.received_requests().await.expect("recorded").is_empty(),
        "the three denied legs opened no wire leg"
    );

    // a refused key is a typed transport denial: the wire never coerces a
    // wrong credential into success, and the request carried the bearer
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let (provider, _store) = xiaomi_provider(&config, Some(XIAOMI_KEY));
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused key is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused key is transport: {err}")
    };
    assert_eq!(connection, XIAOMI);
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, XIAOMI_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {XIAOMI_KEY}"),
        "the admitted bearer reached the wire — the denial is the peer's status"
    );
}

// ----- TP-PROVIDER-RECOVERY::xiaomi ------------------------------------------

/// Hostile stream input never reports success for `xiaomi`: a stream ended
/// mid `tool_calls` fragment — a partial call that never executes — and a
/// finish_reason the dialect cannot classify are each the unknown terminal,
/// and a rejected send charges nothing.
#[tokio::test]
async fn xiaomi_rejects_partial_tool_block_and_unknown_terminal() {
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
    let config = Config::parse_validated(&xiaomi_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        xiaomi_provider(&config, Some(XIAOMI_KEY)),
        &config,
        "/world/xiaomi",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/xiaomi", manifest);
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

    // a finish_reason the dialect cannot classify is unknown, never success
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
    let config = Config::parse_validated(&xiaomi_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        xiaomi_provider(&config, Some(XIAOMI_KEY)),
        &config,
        "/world/xiaomi",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/xiaomi", manifest);
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

// ----- TP-PROVIDER-DIALECT::xiaomi -------------------------------------------

/// The dialect is keyed on the literal connection id: the map routes `xiaomi`
/// to the shared Chat Completions dialect, an empty endpoint resolves its own
/// recorded PAYG `api.xiaomimimo.com/v1` base — never a token-plan literal or a
/// sibling class's default — a configured base stays verbatim, and loopback
/// never serves the reserved id.
#[test]
fn xiaomi_default_base_is_the_payg_literal() {
    assert_eq!(
        rivect::providers::dialect_for(XIAOMI),
        Some(rivect::providers::Dialect::ChatCompletions)
    );

    // the required endpoint's empty string resolves the recorded base —
    // proved on the adapter's `Debug` surface, no byte toward the host
    let config = Config::parse_validated(&xiaomi_config("")).expect("the fixture config is valid");
    let provider = provider_result(
        config,
        XIAOMI.to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("the shared adapter builds for the xiaomi id");
    let debug = format!("{provider:?}");
    assert!(
        debug.contains("endpoint: \"https://api.xiaomimimo.com/v1\""),
        "an empty endpoint resolves the recorded PAYG base: {debug}"
    );
    assert!(
        !debug.contains("token-plan-") && !debug.contains("127.0.0.1"),
        "xiaomi never borrows a token-plan or sibling class base: {debug}"
    );
    drop_blocking(provider);

    // a configured base wins verbatim, trailing slashes trimmed
    let configured =
        Config::parse_validated(&xiaomi_config("https://gateway.example.test/xiaomi/v1/"))
            .expect("the trailing-slash config is valid");
    let provider = provider_result(
        configured,
        XIAOMI.to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("the shared adapter builds for the xiaomi id");
    assert!(
        format!("{provider:?}").contains("endpoint: \"https://gateway.example.test/xiaomi/v1\""),
        "the configured base is normalized, not replaced"
    );
    drop_blocking(provider);

    // loopback never serves the reserved id, and the required-binding
    // contract denies the credential-free kind
    let local = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.xiaomi]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"xiaomi\", model_id = \"{XIAOMI_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the local declaration is admitted");
    let entry = local.connections.get(XIAOMI).expect("declared");
    let loopback = rivect::providers::LoopbackProvider::new();
    assert!(
        !loopback.serves(XIAOMI, entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );
    let err = provider_result(
        local,
        XIAOMI.to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a local declaration cannot satisfy the required binding");
    assert!(
        matches!(err, ProviderError::CredentialUnresolved { .. }),
        "the kind denial is typed: {err}"
    );
}

// ----- TP-PROVIDER-MATRIX::xiaomi --------------------------------------------

/// The legs matrix enforces the recorded expected set for `xiaomi`: CATALOG,
/// AUTH, WIRE and RECOVERY each execute and report inside this run, and
/// INSTALLED reports NOT_RUN.
#[tokio::test]
async fn xiaomi_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![json!({"id": XIAOMI_MODEL, "context_length": 131072})],
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
    let config = Config::parse_validated(&xiaomi_config(&server_uri_v1(&server))).expect("valid");

    // CATALOG: the keyed listing under the ids-only transform — a stated
    // `context_length` maps nothing for this class.
    let (provider, _store) = xiaomi_provider(&config, Some(XIAOMI_KEY));
    let (provider, catalog) = catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if matches!(
            &catalog,
            Ok(models) if models.iter().any(|model| model.id == XIAOMI_MODEL
                && model.context_window.is_none())
        ) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: a bound ref with no store material denies typed.
    let (provider, _store) = xiaomi_provider(&config, None);
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
        xiaomi_provider(&config, Some(XIAOMI_KEY)),
        &config,
        "/world/xiaomi",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/xiaomi", manifest);
    reported.insert(
        "WIRE",
        if matches!(&outcome, Ok(reply) if reply.text == "matrix") {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

    // RECOVERY: the typed denial is followed by a successful retry through
    // the same credential seam.
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let (broker, manifest) = prepared_with(
        xiaomi_provider_with(&config, Arc::clone(&store)),
        &config,
        "/world/xiaomi",
        "goal: matrix recovery",
    );
    let (broker, denied) = dispatch(broker, "/world/xiaomi", manifest);
    let denied_ok = matches!(
        denied,
        Err(ModelError::Provider(ProviderError::CredentialAbsent { .. }))
    );
    drop_blocking(broker);
    store.enroll(XIAOMI_REF, XIAOMI_KEY.as_bytes());
    let (broker, manifest) = prepared_with(
        xiaomi_provider_with(&config, Arc::clone(&store)),
        &config,
        "/world/xiaomi",
        "goal: matrix recovery",
    );
    let (broker, retried) = dispatch(broker, "/world/xiaomi", manifest);
    let recovered = matches!(&retried, Ok(reply) if reply.text == "matrix");
    reported.insert(
        "RECOVERY",
        if denied_ok && recovered {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

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

// ----- TP-PROVIDER-INSTALLED::xiaomi -----------------------------------------

/// TP-PROVIDER-INSTALLED::xiaomi = NOT_RUN: the installed-provider proof is a
/// live-environment leg this offline slice never runs — a real PAYG request
/// needs its own fresh authorization.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::xiaomi = NOT_RUN"]
fn provider_installed_xiaomi() {}
