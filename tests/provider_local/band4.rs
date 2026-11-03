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
