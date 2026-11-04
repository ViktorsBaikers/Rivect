// ----- zhipu-coding-plan -----------------------------------------------------

// The `zhipu-coding-plan` connection's proof legs (DEC-007): the shared
// Chat Completions adapter serves the literal id under its own recorded
// predicates. The recorded base is
// `https://open.bigmodel.cn/api/coding/paas/v4`, an empty configured
// `endpoint` resolves it, and the recorded key is the `<id>.<secret>`
// form — material outside that grammar denies typed before any wire
// leg. The listing is authoritative and key-gated: a resolved key opens
// the one `/models` leg, a failed listing has no seed floor, and no
// offer is invented. `reasoning_content` stays stream progress and never
// joins `text`; the body constructs no developer role and no
// `reasoning_effort` member, and a pinned effort denies typed because
// the class records no effort dial.

/// The literal connection id this class serves.
const ZHIPU: &str = "zhipu-coding-plan";

/// The scoped credential ref the recorded binding carries.
const ZHIPU_REF: &str = "keyring:rivect-test/zhipu-coding-plan";

/// Fixture `zhipu-coding-plan` material in the recorded `<id>.<secret>`
/// form — never a real credential, only ever sent to localhost.
const ZHIPU_KEY: &str = "fixture-zhipu-id.fixture-zhipu-secret";

/// The pinned model id the fixed-pin legs carry — a listed id.
const ZHIPU_MODEL: &str = "glm-4.6";

/// The recorded base an empty configured endpoint resolves.
const ZHIPU_DEFAULT_BASE: &str = "https://open.bigmodel.cn/api/coding/paas/v4";

/// One bound `zhipu-coding-plan` connection pointing at the fixture
/// peer, with auto effort so no pinned dial is exercised on the wire.
fn zhipu_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.zhipu-coding-plan]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{ZHIPU_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"zhipu-coding-plan\", model_id = \"{ZHIPU_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The adapter over an explicit store — the seam the recovery legs
/// enroll into after their typed denial.
fn zhipu_provider_with(
    config: &Config,
    store: Arc<support::MapStore>,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let provider = provider_result(config.clone(), ZHIPU.to_string(), store.clone())
        .expect("the shared adapter builds for the zhipu-coding-plan id");
    (provider, store)
}

/// The adapter over a store seeded with the recorded key material.
fn zhipu_provider(
    config: &Config,
    material: Option<&str>,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = match material {
        None => Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        Some(material) => Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(ZHIPU_REF, material)],
        )),
    };
    zhipu_provider_with(config, store)
}

/// The adapter under a pinned whole-call deadline — the budget the
/// stalled-peer leg spends deterministically.
fn zhipu_provider_with_deadline(config: &Config, deadline: Duration) -> ChatCompletionsProvider {
    let config = config.clone();
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(ZHIPU_REF, ZHIPU_KEY)],
    ));
    std::thread::spawn(move || {
        ChatCompletionsProvider::with_deadline(&config, ZHIPU, store, deadline)
    })
    .join()
    .expect("the provider thread joins")
    .expect("the adapter builds under the pinned deadline")
}

// ----- TP-PROVIDER-WIRE::zhipu-coding-plan -----------------------------------

/// A configured `zhipu-coding-plan` connection returns a verified model
/// outcome through the standard Broker: the literal id routes to the
/// shared Chat Completions dialect, the frozen manifest is one
/// `chat/completions` request — model id verbatim, system+user messages,
/// `stream` with `stream_options.include_usage`, no developer role and
/// no `reasoning_effort` — the SSE stream validates its terminal, and
/// the one physical send is charged once with the provider's reported
/// usage. An empty endpoint resolves the recorded base and loopback
/// never serves the reserved id.
#[tokio::test]
async fn band5_zhipu_coding_plan_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified zhipu outcome",
            Some(json!({"prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17})),
        ),
    )
    .await;
    let config = Config::parse_validated(&zhipu_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        zhipu_provider(&config, Some(ZHIPU_KEY)),
        &config,
        "/world/zhipu",
        "goal: prove the wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/zhipu", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified zhipu outcome");
    assert!(reply.tool_calls.is_empty());

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the send");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {ZHIPU_KEY}"),
        "the recorded id.secret material rides the bearer verbatim"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], ZHIPU_MODEL);
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
    assert_eq!(record.connection, ZHIPU);
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 12,
            completion_tokens: 5,
            total_tokens: 17,
        }
    );
    drop_blocking(broker);

    // the literal id routes to Chat Completions; loopback never serves it
    assert_eq!(
        rivect::providers::dialect_for(ZHIPU),
        Some(rivect::providers::Dialect::ChatCompletions)
    );
    let loopback = rivect::providers::LoopbackProvider::new();
    let entry = config.connections.get(ZHIPU).expect("declared");
    assert!(
        !loopback.serves(ZHIPU, entry),
        "a literal id the dialect map reserves is never local-fixture served"
    );

    // an empty endpoint resolves the recorded base, proved on the
    // adapter's `Debug` surface with no byte toward the host
    let defaulted = Config::parse_validated(&zhipu_config("")).expect("valid");
    let (provider, _store) = zhipu_provider(&defaulted, None);
    let debug = format!("{provider:?}");
    assert!(
        debug.contains(&format!("endpoint: \"{ZHIPU_DEFAULT_BASE}\"")),
        "an empty endpoint resolves the recorded base: {debug}"
    );
    assert!(
        !debug.contains("127.0.0.1"),
        "zhipu-coding-plan never borrows a sibling class's base: {debug}"
    );
    drop_blocking(provider);
}

// ----- TP-PROVIDER-CATALOG::zhipu-coding-plan --------------------------------

/// The catalogue is the keyed authoritative `/models` listing: the
/// resolved `<id>.<secret>` material rides the one `GET /models` leg,
/// every listed id is offered with the generic metadata the listing
/// states (`context_length`, `max_completion_tokens`) and nothing else,
/// and no seed floor exists — an empty answer offers nothing, and an
/// absent binding opens no wire leg.
#[tokio::test]
async fn band5_zhipu_coding_plan_catalog_is_the_keyed_listing() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({
                "id": ZHIPU_MODEL,
                "context_length": 204_800,
                "max_completion_tokens": 131_072,
            }),
            json!({"id": "glm-4.6-air"}),
        ],
    )
    .await;
    let config = Config::parse_validated(&zhipu_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = zhipu_provider(&config, Some(ZHIPU_KEY));
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the keyed listing answers");
    assert_eq!(
        model_ids(&models),
        vec![ZHIPU_MODEL, "glm-4.6-air"],
        "the listing is authoritative — no seed row widens it"
    );
    let model = &models[0];
    assert_eq!(model.context_window, Some(204_800));
    assert_eq!(model.max_output_tokens, Some(131_072));
    assert_eq!(model.price, ModelPrice::Unknown);
    assert!(
        !model.reasoning && !model.vision && !model.tools,
        "the listing states no capability surface this arm maps"
    );
    assert_eq!(
        models[1].context_window, None,
        "an unstated limit stays absent, never defaulted"
    );
    drop_blocking(provider);

    let requests = server
        .received_requests()
        .await
        .expect("the mock recorded the lookup");
    assert_eq!(requests.len(), 1, "one keyed /models leg");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {ZHIPU_KEY}"),
        "the listing is key-gated"
    );

    // an empty answer offers nothing: no seed floor is invented
    let empty = MockServer::start().await;
    mount_models(&empty, Vec::new()).await;
    let config = Config::parse_validated(&zhipu_config(&server_uri_v1(&empty))).expect("valid");
    let (provider, _store) = zhipu_provider(&config, Some(ZHIPU_KEY));
    let (provider, catalog) = catalog_on_thread(provider);
    assert_eq!(
        catalog.expect("an empty listing is an empty catalogue"),
        Vec::new(),
        "no floor is invented for the seedless class"
    );
    drop_blocking(provider);

    // the absent binding denies the lookup and opens no wire leg
    let gated = MockServer::start().await;
    mount_models(&gated, Vec::new()).await;
    let config = Config::parse_validated(&zhipu_config(&server_uri_v1(&gated))).expect("valid");
    let (provider, _store) = zhipu_provider(&config, None);
    let (provider, denied) = catalog_on_thread(provider);
    assert!(
        matches!(denied, Err(ProviderError::CredentialAbsent { .. })),
        "the key-gated listing denies an unresolved binding: {denied:?}"
    );
    drop_blocking(provider);
    assert!(
        gated
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the unresolved binding opened no wire leg"
    );
}

// ----- TP-PROVIDER-AUTH::zhipu-coding-plan -----------------------------------

/// The recorded credential grammar is the `<id>.<secret>` form: material
/// naming no dot, an empty id half, an empty secret half or only
/// whitespace denies `CredentialMalformed` before any wire leg, and the
/// corrected form posts once with the bearer verbatim.
#[tokio::test]
async fn band5_zhipu_coding_plan_requires_the_id_secret_credential_form() {
    let server = MockServer::start().await;
    mount_chat(&server, completed_stream("corrected form", None)).await;
    let config = Config::parse_validated(&zhipu_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let (provider, _store) = zhipu_provider_with(&config, Arc::clone(&store));
    let manifest = prepared_manifest(&config);

    let mut provider = provider;
    for material in [
        "fixture-zhipu-key",
        ".fixture-zhipu-secret",
        "fixture-zhipu-id.",
        "   ",
    ] {
        store.enroll(ZHIPU_REF, material.as_bytes());
        let (returned, denied) = send_on_thread(provider, manifest.clone());
        provider = returned;
        let err = denied.expect_err("material outside the id.secret grammar denies typed");
        assert!(
            matches!(err, ProviderError::CredentialMalformed { .. }),
            "{material:?} is the typed malformed credential: {err}"
        );
        assert_no_secret_or_body(&err, material.as_bytes());
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "every malformed form denies before any wire leg"
    );

    // the corrected `<id>.<secret>` form posts once with the bearer verbatim
    store.enroll(ZHIPU_REF, ZHIPU_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the corrected credential admits the send");
    assert_eq!(reply.text, "corrected form");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the corrected form posts exactly once");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {ZHIPU_KEY}"),
        "the recorded id.secret material rides the bearer verbatim"
    );
}

// ----- TP-PROVIDER-RECOVERY::zhipu-coding-plan (reasoning) -------------------

/// The recorded `zai` thinking surface streams `reasoning_content` as
/// progress: the reasoning fragments never join `text`, the visible
/// content is the answer, and the request body carries no developer role
/// and no effort field.
#[tokio::test]
async fn band5_zhipu_coding_plan_maps_reasoning_content_and_never_a_developer_role() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        format!(
            "{}{}{}{}{}",
            data_block(&delta_chunk(
                json!({"role": "assistant", "reasoning_content": "think "})
            )),
            data_block(&delta_chunk(json!({"reasoning_content": "harder"}))),
            data_block(&delta_chunk(json!({"content": "final answer"}))),
            data_block(&finish_chunk("stop")),
            DONE_BLOCK,
        ),
    )
    .await;
    let config = Config::parse_validated(&zhipu_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        zhipu_provider(&config, Some(ZHIPU_KEY)),
        &config,
        "/world/zhipu",
        "goal: reasoning progress",
    );

    let (broker, outcome) = dispatch(broker, "/world/zhipu", manifest);
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(
        reply.text, "final answer",
        "reasoning_content is progress, never joined to text"
    );
    assert_eq!(broker.accounted_requests(), 1);
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1);
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    let roles: Vec<&str> = body["messages"]
        .as_array()
        .expect("messages array")
        .iter()
        .filter_map(|message| message["role"].as_str())
        .collect();
    assert_eq!(
        roles,
        vec!["system", "user"],
        "the body never constructs a developer role"
    );
    assert!(
        body.get("reasoning_effort").is_none(),
        "the body never constructs an effort field"
    );
}

/// The class records no reasoning-effort dial: every pinned level denies
/// `UnsupportedParameter` before any wire leg rather than being dropped
/// from the body.
#[tokio::test]
async fn band5_zhipu_coding_plan_pinned_effort_denies_not_dropped() {
    let server = MockServer::start().await;
    mount_chat(&server, completed_stream("never reached", None)).await;
    let config = Config::parse_validated(&zhipu_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = zhipu_provider(&config, Some(ZHIPU_KEY));
    let mut manifest = prepared_manifest(&config);

    let mut provider = provider;
    for level in [
        EffortLevel::Minimal,
        EffortLevel::Low,
        EffortLevel::Medium,
        EffortLevel::High,
        EffortLevel::Xhigh,
    ] {
        manifest.effort = rivect::config::EffortAssign::Fixed { value: level };
        let (returned, denied) = send_on_thread(provider, manifest.clone());
        provider = returned;
        let err = denied.expect_err("a pinned effort never reports success");
        let ProviderError::UnsupportedParameter {
            connection,
            parameter,
            model,
        } = &err
        else {
            panic!("the pinned effort is the typed unsupported parameter: {err:?}");
        };
        assert_eq!(connection, ZHIPU);
        assert_eq!(*parameter, "reasoning_effort");
        assert_eq!(model, ZHIPU_MODEL);
    }
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "every pinned level denies before any wire leg"
    );
}

/// Wrong, absent or unresolvable credential, or a configured region,
/// never produce a false success: an unbound declaration is refused at
/// ingress, a bound scope the store cannot resolve denies
/// `CredentialAbsent` with no wire leg, a configured `region` denies
/// `RegionMismatch`, a profile-bound ref whose scope disagrees with the
/// binding denies `CredentialProfileMismatch`, and a refused key lands
/// the typed transport denial carrying the peer's status alone — no
/// error renders the offered material or the peer's body.
#[tokio::test]
async fn band5_zhipu_coding_plan_wrong_credential_profile_or_region_denies_without_secrets() {
    let server = MockServer::start().await;

    // the recorded class requires its scoped binding at ingress
    let unbound = zhipu_config(&server_uri_v1(&server))
        .replace(&format!("credential_ref = \"{ZHIPU_REF}\"\n"), "");
    let err = Config::parse_validated(&unbound)
        .expect_err("the recorded class requires its scoped binding at ingress");
    assert!(
        matches!(err.issue, ConfigIssue::CredentialRefRequired { .. }),
        "the unbound declaration is the typed ingress denial: {err}"
    );

    // a bound scope the store cannot resolve denies before any wire leg
    let config = Config::parse_validated(&zhipu_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = zhipu_provider(&config, None);
    let (provider, denied) = send_on_thread(provider, prepared_manifest(&config));
    let err = denied.expect_err("the unresolved binding denies typed");
    assert!(
        matches!(err, ProviderError::CredentialAbsent { .. }),
        "the absent credential is the typed denial: {err}"
    );
    assert_no_secret_or_body(&err, ZHIPU_KEY.as_bytes());
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
        &zhipu_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"cn\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        ZHIPU.to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, ZHIPU_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, ZHIPU);
    assert_eq!(region, "cn");
    assert_no_secret_or_body(&err, ZHIPU_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.zhipu-coding-plan]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"zhipu-coding-plan\", model_id = \"{ZHIPU_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        ZHIPU.to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, ZHIPU_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, ZHIPU_KEY.as_bytes());

    // a refused key is a typed transport denial: the wire never coerces a
    // wrong credential into success, and the request carried the bearer
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let (provider, _store) = zhipu_provider(&config, Some(ZHIPU_KEY));
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused key is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused key is transport: {err}")
    };
    assert_eq!(connection, ZHIPU);
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, ZHIPU_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {ZHIPU_KEY}"),
        "the admitted bearer reached the wire — the denial is the peer's status"
    );
}

// ----- TP-PROVIDER-RECOVERY::zhipu-coding-plan (adverse wire) ----------------

/// Hostile stream input never reports success for `zhipu-coding-plan`: a
/// stream ended mid `tool_calls` fragment — a partial call that never
/// executes — and a finish_reason the dialect cannot classify are each
/// the unknown terminal, and a rejected send charges nothing.
#[tokio::test]
async fn band5_zhipu_coding_plan_rejects_partial_tool_block_and_unknown_terminal() {
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
    let config = Config::parse_validated(&zhipu_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        zhipu_provider(&config, Some(ZHIPU_KEY)),
        &config,
        "/world/zhipu",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/zhipu", manifest);
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
    let config = Config::parse_validated(&zhipu_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        zhipu_provider(&config, Some(ZHIPU_KEY)),
        &config,
        "/world/zhipu",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/zhipu", manifest);
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

/// Incompatible tool or reasoning output never reports success: a
/// well-formed call naming a tool the frozen request never declared is
/// the typed `IncompatibleOutput`, and a `reasoning_content` fragment of
/// the wrong type is a typed stream violation — neither is executed or
/// accounted.
#[tokio::test]
async fn band5_zhipu_coding_plan_rejects_incompatible_tools_or_reasoning() {
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
    let config = Config::parse_validated(&zhipu_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        zhipu_provider(&config, Some(ZHIPU_KEY)),
        &config,
        "/world/zhipu",
        "goal: undeclared call",
    );
    let (broker, outcome) = dispatch(broker, "/world/zhipu", manifest);
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

    // a non-string reasoning fragment is output the dialect cannot honour
    let server = MockServer::start().await;
    mount_chat(
        &server,
        data_block(&delta_chunk(json!({"reasoning_content": 42}))),
    )
    .await;
    let config = Config::parse_validated(&zhipu_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        zhipu_provider(&config, Some(ZHIPU_KEY)),
        &config,
        "/world/zhipu",
        "goal: foreign reasoning shape",
    );
    let (broker, outcome) = dispatch(broker, "/world/zhipu", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "a non-string reasoning fragment is the typed violation: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);
}

/// The `/chat/completions` non-success branch is the typed status
/// denial: one physical POST, nothing accounted, and the peer's body
/// never renders.
#[tokio::test]
async fn band5_zhipu_coding_plan_non_success_status_denies() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&zhipu_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        zhipu_provider(&config, Some(ZHIPU_KEY)),
        &config,
        "/world/zhipu",
        "goal: non-success status",
    );

    let (broker, outcome) = dispatch(broker, "/world/zhipu", manifest);
    let err = outcome.expect_err("a non-success status never reports success");
    assert!(
        matches!(
            &err,
            ModelError::Provider(ProviderError::Transport {
                connection,
                cause: TransportCause::Status { status },
            }) if connection == ZHIPU && status.as_u16() == 401
        ),
        "the non-success status is the typed transport status: {err}"
    );
    let ModelError::Provider(provider_err) = &err else {
        panic!("the denial is a provider error: {err}");
    };
    assert_no_secret_or_body(provider_err, ZHIPU_KEY.as_bytes());
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "one physical POST, no send retry");
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a denied send is never accounted"
    );
    drop_blocking(broker);
}

/// A stalled peer past the whole-call deadline is the typed deadline
/// denial: the adapter's own budget check ends the send, nothing is
/// accounted, and no second request is issued.
#[tokio::test]
async fn band5_zhipu_coding_plan_short_deadline_denies_without_a_second_request() {
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the stalled peer");
    let address = listener.local_addr().expect("peer address");
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the send connects");
        let mut scratch = [0u8; 8192];
        let _read = stream.read(&mut scratch);
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
            )
            .expect("the response headers");
        stream
            .write_all(
                data_block(&delta_chunk(json!({
                    "role": "assistant",
                    "content": "stalled",
                })))
                .as_bytes(),
            )
            .expect("the first chunk");
        // Dribble bytes so every read returns and only the total clock
        // can end the stream; the client closes at the deadline.
        for _ in 0..20 {
            if stream.write_all(b" ").is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // A retried send would open a second connection: the listener's
        // backlog answers whether one arrived.
        listener.set_nonblocking(true).expect("nonblocking probe");
        listener.accept().is_ok()
    });

    let config =
        Config::parse_validated(&zhipu_config(&format!("http://{address}"))).expect("valid");
    let provider = zhipu_provider_with_deadline(&config, Duration::from_millis(200));
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/zhipu", "goal: stalled peer")
        .expect("the pin prepares");
    let started = Instant::now();
    let (broker, outcome) = dispatch(broker, "/world/zhipu", manifest);
    let elapsed = started.elapsed();
    let retried = peer.join().expect("the stalled peer ends");

    let err = outcome.expect_err("a stalled peer never reports success");
    assert!(
        matches!(
            &err,
            ModelError::Provider(ProviderError::Transport {
                connection,
                cause: TransportCause::Deadline { .. },
            }) if connection == ZHIPU
        ),
        "the denial is the adapter's typed deadline: {err}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "the budget, not the client backstop, ends the send, got {elapsed:?}"
    );
    assert!(
        !retried,
        "the denied send is not retried onto a second request"
    );
    assert_eq!(broker.accounted_requests(), 0, "nothing is accounted");
    drop_blocking(broker);
}

// ----- TP-PROVIDER-MATRIX::zhipu-coding-plan ---------------------------------

/// The legs matrix enforces the recorded expected set for
/// `zhipu-coding-plan`: CATALOG, AUTH, WIRE and RECOVERY each execute
/// and report inside this run, and INSTALLED reports NOT_RUN.
#[tokio::test]
async fn band5_zhipu_coding_plan_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![json!({
            "id": ZHIPU_MODEL,
            "context_length": 204_800,
            "max_completion_tokens": 131_072,
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
    let config = Config::parse_validated(&zhipu_config(&server_uri_v1(&server))).expect("valid");

    // CATALOG: the authoritative keyed listing under the generic transform.
    let (provider, _store) = zhipu_provider(&config, Some(ZHIPU_KEY));
    let (provider, catalog) = catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if matches!(
            &catalog,
            Ok(models) if models.iter().any(|model| model.id == ZHIPU_MODEL
                && model.context_window == Some(204_800)
                && model.max_output_tokens == Some(131_072))
        ) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: a bound ref with no store material denies typed.
    let (provider, _store) = zhipu_provider(&config, None);
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
        zhipu_provider(&config, Some(ZHIPU_KEY)),
        &config,
        "/world/zhipu",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/zhipu", manifest);
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
        zhipu_provider_with(&config, Arc::clone(&store)),
        &config,
        "/world/zhipu",
        "goal: matrix recovery",
    );
    let (broker, denied) = dispatch(broker, "/world/zhipu", manifest);
    let denied_ok = matches!(
        denied,
        Err(ModelError::Provider(ProviderError::CredentialAbsent { .. }))
    );
    drop_blocking(broker);
    store.enroll(ZHIPU_REF, ZHIPU_KEY.as_bytes());
    let (broker, manifest) = prepared_with(
        zhipu_provider_with(&config, Arc::clone(&store)),
        &config,
        "/world/zhipu",
        "goal: matrix recovery",
    );
    let (broker, retried) = dispatch(broker, "/world/zhipu", manifest);
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

// ----- TP-PROVIDER-INSTALLED::zhipu-coding-plan ------------------------------

/// TP-PROVIDER-INSTALLED::zhipu-coding-plan = NOT_RUN: the
/// installed-provider proof is a live-environment leg this offline slice
/// never runs, and a real Zhipu request needs its own fresh
/// authorization.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::zhipu-coding-plan = NOT_RUN"]
fn provider_installed_zhipu_coding_plan() {}

// ----- opencode-go -----------------------------------------------------------

// The `opencode-go` connection's proof legs (DEC-014/DEC-023): the
// shared routed owner serves the literal id over the shipped codecs.
// Chat Completions is the recorded default; the GPT/Grok/Muse families
// and `deepseek-v4-flash` ride Responses first, and Messages serves
// `claude-*`, `qwen*` and `minimax-m2.5*` except the five CC exacts
// (`minimax-m2.7`, `minimax-m3`, `minimax-m3-free`,
// `qwen3.5-plus`, `qwen3.6-plus`). The recorded base path is
// `https://opencode.ai/zen/go` — the routed owner appends `/v1` — and
// every catalogue and wire leg carries the recorded attribution pair
// beside the scoped key's bearer.

/// The literal routed id under proof.
const GO: &str = "opencode-go";

/// The scoped credential ref the connection binds.
const GO_REF: &str = "keyring:rivect-test/opencode-go";

/// The recorded Chat Completions default model.
const GO_CC_MODEL: &str = "kimi-k2.7-code";

/// A recorded Chat Completions exact.
const GO_CC_EXACT: &str = "qwen3.5-plus";

/// The recorded Responses override model.
const GO_RESPONSES_MODEL: &str = "deepseek-v4-flash";

/// The recorded Messages-family model.
const GO_MESSAGES_MODEL: &str = "claude-sonnet-4-5";

/// A Messages-family id outside the recorded CC exacts.
const GO_MESSAGES_EXACT: &str = "qwen3.6";

/// The recorded MiniMax M2.5 Messages-family id.
const GO_MESSAGES_MINIMAX: &str = "minimax-m2.5";

/// An id matching no recorded override — it rides the CC default.
const GO_UNKNOWN_MODEL: &str = "vendor-mystery-9";

const GO_CC_PATH: &str = "/v1/chat/completions";
const GO_MESSAGES_PATH: &str = "/v1/messages";
const GO_RESPONSES_PATH: &str = "/v1/responses";

fn go_config(endpoint: &str, model: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.{GO}]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{GO_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{GO}\", model_id = \"{model}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn go_with(
    config: &Config,
    store: Arc<support::MapStore>,
    deadline: Duration,
) -> rivect::providers::routed::RoutedProvider {
    let config = config.clone();
    std::thread::spawn(move || {
        rivect::providers::routed::RoutedProvider::with_deadline(&config, GO, store, deadline)
    })
    .join()
    .expect("the provider thread joins")
    .expect("the routed adapter builds")
}

fn go_provider(
    config: &Config,
    deadline: Duration,
) -> (
    rivect::providers::routed::RoutedProvider,
    Arc<support::MapStore>,
) {
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[(GO_REF, SECRET)]));
    (go_with(config, Arc::clone(&store), deadline), store)
}

fn go_catalog_on_thread(
    provider: rivect::providers::routed::RoutedProvider,
) -> (
    rivect::providers::routed::RoutedProvider,
    Result<Vec<String>, ProviderError>,
) {
    std::thread::spawn(move || {
        let outcome = provider.catalog();
        (provider, outcome)
    })
    .join()
    .expect("the catalog thread joins")
}

fn go_header<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
}

/// The attribution session one leg carries, derived from its seed exactly
/// as the routed owner derives it.
fn go_session(seed: &str) -> String {
    support::sha256_hex(seed.as_bytes())
        .chars()
        .take(16)
        .collect()
}

fn go_message_start(input_tokens: u64) -> String {
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

fn go_text_stream(text: &str, input_tokens: u64, output_tokens: u64) -> String {
    format!(
        "{}{}{}{}{}{}",
        go_message_start(input_tokens),
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

async fn mount_go_messages(server: &MockServer, body: String) {
    Mock::given(method("POST"))
        .and(path(GO_MESSAGES_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(server)
        .await;
}

// ----- TP-PROVIDER-WIRE::opencode-go -----------------------------------------

/// A configured `opencode-go` connection returns a verified model
/// outcome through the standard Broker: the recorded Chat Completions
/// default is one `chat/completions` request, its SSE stream validates
/// the terminal, and the one physical send is charged once with the
/// provider's reported usage.
#[tokio::test]
async fn band5_opencode_go_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "go outcome",
            Some(json!({"prompt_tokens": 9, "completion_tokens": 4, "total_tokens": 13})),
        ),
    )
    .await;
    let config = Config::parse_validated(&go_config(&server.uri(), GO_CC_MODEL)).expect("valid");
    let (broker, manifest) = prepared_with(
        go_provider(&config, Duration::from_secs(10)),
        &config,
        "/world/opencode-go",
        "goal: prove the go wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/opencode-go", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "go outcome");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 9,
            completion_tokens: 4,
            total_tokens: 13,
        }
    );

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), GO_CC_PATH);
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], json!(GO_CC_MODEL));

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, GO);
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 9,
            completion_tokens: 4,
            total_tokens: 13,
        }
    );
    drop_blocking(broker);

    assert_eq!(
        rivect::providers::dialect_for(GO),
        Some(rivect::providers::Dialect::ChatCompletions)
    );
    assert_eq!(
        rivect::providers::routes_for(GO),
        [
            rivect::providers::Dialect::ChatCompletions,
            rivect::providers::Dialect::Messages,
            rivect::providers::Dialect::Responses,
        ]
    );
}

// ----- TP-PROVIDER-CATALOG::opencode-go --------------------------------------

/// The catalogue is the gateway's `GET /models` listing filtered by the
/// route table: the CC default carries every id matching no override, the
/// Muse Spark and `deepseek-v4-flash` families resolve Responses, and the
/// Claude/Qwen/MiniMax M2.5 families resolve Messages.
#[tokio::test]
async fn band5_opencode_go_catalog_offers_the_recorded_routes() {
    assert_eq!(
        rivect::providers::routes_for(GO),
        [
            rivect::providers::Dialect::ChatCompletions,
            rivect::providers::Dialect::Messages,
            rivect::providers::Dialect::Responses,
        ]
    );
    for (model, dialect) in [
        ("muse-spark-1.2", rivect::providers::Dialect::Responses),
        ("muse-spark-1.3", rivect::providers::Dialect::Responses),
        (
            "muse-spark-1.3-contributor-free",
            rivect::providers::Dialect::Responses,
        ),
        ("gpt-5.2", rivect::providers::Dialect::Responses),
        ("grok-4", rivect::providers::Dialect::Responses),
        ("deepseek-v4-flash", rivect::providers::Dialect::Responses),
        ("minimax-m2.7", rivect::providers::Dialect::ChatCompletions),
        ("minimax-m3", rivect::providers::Dialect::ChatCompletions),
        (
            "minimax-m3-free",
            rivect::providers::Dialect::ChatCompletions,
        ),
        (GO_CC_EXACT, rivect::providers::Dialect::ChatCompletions),
        ("qwen3.6-plus", rivect::providers::Dialect::ChatCompletions),
        (GO_MESSAGES_MODEL, rivect::providers::Dialect::Messages),
        (GO_MESSAGES_EXACT, rivect::providers::Dialect::Messages),
        (GO_MESSAGES_MINIMAX, rivect::providers::Dialect::Messages),
        (
            "minimax-m2.5-highspeed",
            rivect::providers::Dialect::Messages,
        ),
        (
            GO_UNKNOWN_MODEL,
            rivect::providers::Dialect::ChatCompletions,
        ),
    ] {
        assert_eq!(
            rivect::providers::route_for(GO, model),
            Some(dialect),
            "{model}"
        );
    }
    assert_eq!(
        rivect::providers::route_for("gitlab-duo", "duo-chat-unknown-9"),
        None,
        "the closed GitLab table keeps its denial"
    );

    let server = MockServer::start().await;
    mount_models(
        &server,
        [
            GO_MESSAGES_MODEL,
            GO_RESPONSES_MODEL,
            GO_MESSAGES_MINIMAX,
            "minimax-m3-free",
            "muse-spark-1.2",
            GO_MESSAGES_EXACT,
            "qwen3.6-plus",
            GO_UNKNOWN_MODEL,
        ]
        .into_iter()
        .map(|id| json!({"id": id}))
        .collect(),
    )
    .await;
    let config = Config::parse_validated(&go_config(&server.uri(), GO_CC_MODEL)).expect("valid");
    let (provider, _store) = go_provider(&config, Duration::from_secs(5));
    let (provider, catalog) = go_catalog_on_thread(provider);
    assert_eq!(
        catalog.expect("the listing is the catalogue"),
        [
            GO_MESSAGES_MODEL,
            GO_RESPONSES_MODEL,
            GO_MESSAGES_MINIMAX,
            "minimax-m3-free",
            "muse-spark-1.2",
            GO_MESSAGES_EXACT,
            "qwen3.6-plus",
            GO_UNKNOWN_MODEL,
        ]
        .map(String::from)
    );
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "one keyed /models leg");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {SECRET}"),
        "the listing is key-gated"
    );

    // The Messages arm's own catalogue keeps only its recorded family.
    let reference =
        rivect::providers::resolve_credential(&config, GO).expect("the scoped ref resolves");
    let messages_store = Arc::new(support::MapStore::seeded(STORE_KIND, &[(GO_REF, SECRET)]));
    let messages = std::thread::spawn(move || {
        let provider = rivect::providers::anthropic::MessagesProvider::with_route(
            &config,
            GO,
            messages_store,
            Duration::from_secs(5),
            rivect::providers::WireAuth::Store(Some(reference)),
        )
        .expect("the Messages route constructor builds");
        provider.catalog()
    })
    .join()
    .expect("the Messages catalogue thread joins")
    .expect("the Messages listing answers");
    assert_eq!(
        messages,
        [GO_MESSAGES_MODEL, GO_MESSAGES_MINIMAX, GO_MESSAGES_EXACT].map(String::from),
        "the Messages arm offers its recorded family only"
    );
}

// ----- TP-PROVIDER-WIRE::opencode-go (route dispatch) ------------------------

/// The recorded route table dispatches each model to its codec: a CC
/// exact rides `chat/completions` and a Responses override rides
/// `responses`, both with the model id verbatim.
#[tokio::test]
async fn band5_opencode_go_cc_and_responses_dispatch() {
    // Chat Completions exact
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "go cc",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3})),
        ),
    )
    .await;
    let config = Config::parse_validated(&go_config(&server.uri(), GO_CC_EXACT)).expect("valid");
    let (provider, _store) = go_provider(&config, Duration::from_secs(5));
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let reply = outcome.expect("the CC exact answers");
    assert_eq!(reply.text, "go cc");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), GO_CC_PATH);
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], json!(GO_CC_EXACT));

    // Responses override
    let server = MockServer::start().await;
    mount_responses(
        &server,
        responses_completed_stream(
            "go responses",
            Vec::new(),
            Some(json!({"input_tokens": 4, "output_tokens": 5, "total_tokens": 9})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&go_config(&server.uri(), GO_RESPONSES_MODEL)).expect("valid");
    let (provider, _store) = go_provider(&config, Duration::from_secs(5));
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let reply = outcome.expect("the Responses override answers");
    assert_eq!(reply.text, "go responses");
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
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), GO_RESPONSES_PATH);
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], json!(GO_RESPONSES_MODEL));
}

/// The recorded Responses family dispatches too: a GPT or Grok id posts
/// `/responses` with the model id verbatim, never the CC default.
#[tokio::test]
async fn band5_opencode_go_responses_family_dispatch() {
    for model in ["gpt-5.2", "grok-4"] {
        assert_eq!(
            rivect::providers::route_for(GO, model),
            Some(rivect::providers::Dialect::Responses),
            "{model}"
        );
        let server = MockServer::start().await;
        mount_responses(
            &server,
            responses_completed_stream("go responses family", Vec::new(), None),
        )
        .await;
        let config = Config::parse_validated(&go_config(&server.uri(), model)).expect("valid");
        let (provider, _store) = go_provider(&config, Duration::from_secs(5));
        let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
        outcome.expect("the Responses family answers");
        drop_blocking(provider);
        let requests = server.received_requests().await.expect("recorded");
        assert_eq!(requests.len(), 1, "{model}");
        assert_eq!(requests[0].url.path(), GO_RESPONSES_PATH, "{model}");
        let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
        assert_eq!(body["model"], json!(model));
    }
}

/// A Messages-family model dispatches to `messages`: one physical
/// request, the recorded bearer + `anthropic-version` pair beside the
/// gateway attribution, and one accounted usage from the cumulative
/// `message_delta`.
#[tokio::test]
async fn band5_opencode_go_messages_dispatch() {
    assert_eq!(
        rivect::providers::route_for(GO, GO_MESSAGES_MODEL),
        Some(rivect::providers::Dialect::Messages)
    );
    let server = MockServer::start().await;
    mount_go_messages(&server, go_text_stream("go messages", 2, 3)).await;
    let config =
        Config::parse_validated(&go_config(&server.uri(), GO_MESSAGES_MODEL)).expect("valid");
    let (broker, manifest) = prepared_with(
        go_provider(&config, Duration::from_secs(5)),
        &config,
        "/world/opencode-go",
        "goal: messages route",
    );
    let (broker, outcome) = dispatch(broker, "/world/opencode-go", manifest.clone());
    let reply = outcome.expect("the Messages route answers");
    assert_eq!(reply.text, "go messages");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 2,
            completion_tokens: 3,
            total_tokens: 5,
        }
    );

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "one physical request");
    assert_eq!(requests[0].url.path(), GO_MESSAGES_PATH);
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], json!(GO_MESSAGES_MODEL));
    let bearer = format!("Bearer {SECRET}");
    assert_eq!(
        go_header(&requests[0], "authorization"),
        Some(bearer.as_str()),
        "the gateway key rides the bearer"
    );
    assert_eq!(
        go_header(&requests[0], "anthropic-version"),
        Some("2023-06-01"),
        "the Messages wire carries the recorded version header"
    );
    assert_eq!(
        go_header(&requests[0], "x-api-key"),
        None,
        "the gateway form is bearer, not x-api-key"
    );
    assert_eq!(
        go_header(&requests[0], "x-opencode-session"),
        Some(go_session("/world/opencode-go").as_str()),
        "the Messages leg carries the attribution session"
    );
    assert_eq!(
        go_header(&requests[0], "user-agent"),
        Some(format!("rivect/{}", env!("CARGO_PKG_VERSION")).as_str())
    );

    assert_eq!(broker.accounted_requests(), 1);
    drop_blocking(broker);
}

/// The Messages arm's send gate keys on the same route table: a
/// CC-family id never posts `/messages` through it — the typed model
/// denial lands before the body.
#[tokio::test]
async fn band5_opencode_go_messages_gate_rejects_a_cc_family_model() {
    assert_eq!(
        rivect::providers::route_for(GO, GO_CC_MODEL),
        Some(rivect::providers::Dialect::ChatCompletions)
    );
    let server = MockServer::start().await;
    mount_go_messages(&server, go_text_stream("never reached", 1, 1)).await;
    let config = Config::parse_validated(&go_config(&server.uri(), GO_MESSAGES_MODEL))
        .expect("valid");
    let reference =
        rivect::providers::resolve_credential(&config, GO).expect("the scoped ref resolves");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[(GO_REF, SECRET)]));
    let outcome = std::thread::spawn(move || {
        let mut provider = rivect::providers::anthropic::MessagesProvider::with_route(
            &config,
            GO,
            store,
            Duration::from_secs(5),
            rivect::providers::WireAuth::Store(Some(reference)),
        )
        .expect("the Messages route constructor builds");
        let mut manifest = prepared_manifest(&config);
        manifest.model = rivect::config::ModelAssign::Fixed(rivect::config::FixedModel {
            connection: GO.to_string(),
            model_id: GO_CC_MODEL.to_string(),
        });
        provider.send(&manifest)
    })
    .join()
    .expect("the send thread joins");
    let ProviderError::UnsupportedParameter {
        connection,
        parameter,
        model,
    } = outcome.expect_err("a CC-family model has no Messages route")
    else {
        panic!("expected the typed model denial");
    };
    assert_eq!(connection, GO);
    assert_eq!(parameter, "model");
    assert_eq!(model, GO_CC_MODEL);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the gate denies before any wire leg"
    );
}

/// Every recorded CC exact rides `chat/completions` with the model id
/// verbatim, never the Messages family route its prefix might imply.
#[tokio::test]
async fn band5_opencode_go_cc_exacts_dispatch() {
    for model in [
        "minimax-m2.7",
        "minimax-m3",
        "minimax-m3-free",
        "qwen3.5-plus",
        "qwen3.6-plus",
    ] {
        assert_eq!(
            rivect::providers::route_for(GO, model),
            Some(rivect::providers::Dialect::ChatCompletions),
            "{model}"
        );
        let server = MockServer::start().await;
        mount_chat(&server, completed_stream("go cc exact", None)).await;
        let config = Config::parse_validated(&go_config(&server.uri(), model)).expect("valid");
        let (provider, _store) = go_provider(&config, Duration::from_secs(5));
        let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
        outcome.expect("the CC exact answers");
        drop_blocking(provider);
        let requests = server.received_requests().await.expect("recorded");
        assert_eq!(requests.len(), 1, "{model}: one physical request");
        assert_eq!(requests[0].url.path(), GO_CC_PATH, "{model}");
        let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
        assert_eq!(body["model"], json!(model));
    }
}

/// An id matching no recorded override rides the recorded Chat
/// Completions default rather than being denied or misrouted.
#[tokio::test]
async fn band5_opencode_go_unknown_model_uses_the_recorded_cc_default() {
    assert_eq!(
        rivect::providers::route_for(GO, GO_UNKNOWN_MODEL),
        Some(rivect::providers::Dialect::ChatCompletions)
    );
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "go default",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&go_config(&server.uri(), GO_UNKNOWN_MODEL)).expect("valid");
    let (provider, _store) = go_provider(&config, Duration::from_secs(5));
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let reply = outcome.expect("the unknown id rides the CC default");
    assert_eq!(reply.text, "go default");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), GO_CC_PATH);
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(body["model"], json!(GO_UNKNOWN_MODEL));
}

// ----- TP-PROVIDER-AUTH::opencode-go -----------------------------------------

/// The scoped key rides the bearer on both the catalogue and the wire
/// leg, beside the recorded attribution pair: the crate UA and a stable
/// 16-hex session seeded from the connection id on a catalogue and from
/// the frozen world on a send. The non-Messages Go legs carry no
/// `anthropic-version`; the Messages arm sends the bearer plus
/// `anthropic-version` and no `x-api-key`.
#[tokio::test]
async fn band5_opencode_go_auth_and_attribution_headers() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": GO_CC_MODEL})]).await;
    mount_chat(&server, completed_stream("attributed", None)).await;
    let config = Config::parse_validated(&go_config(&server.uri(), GO_CC_MODEL)).expect("valid");
    let (provider, _store) = go_provider(&config, Duration::from_secs(5));
    let (provider, catalog) = go_catalog_on_thread(provider);
    catalog.expect("the catalogue answers");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    outcome.expect("the wire leg answers");
    drop_blocking(provider);

    // the Responses route carries the same attribution pair
    mount_responses(
        &server,
        responses_completed_stream("attributed responses", Vec::new(), None),
    )
    .await;
    let responses_config =
        Config::parse_validated(&go_config(&server.uri(), GO_RESPONSES_MODEL)).expect("valid");
    let (provider, _store) = go_provider(&responses_config, Duration::from_secs(5));
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&responses_config));
    outcome.expect("the Responses wire leg answers");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        3,
        "the catalogue and both recorded wire routes"
    );
    let expected_agent = format!("rivect/{}", env!("CARGO_PKG_VERSION"));
    let bearer = format!("Bearer {SECRET}");
    for request in &requests {
        assert_eq!(
            go_header(request, "user-agent"),
            Some(expected_agent.as_str())
        );
        let session = go_header(request, "x-opencode-session").expect("attributed session");
        assert_eq!(session.len(), 16, "a truncated digest: {session}");
        assert!(
            session.chars().all(|c| c.is_ascii_hexdigit()),
            "the session is hex: {session}"
        );
        assert_eq!(
            go_header(request, "authorization"),
            Some(bearer.as_str()),
            "the scoped key is the bearer on every leg"
        );
    }
    assert_eq!(
        go_header(&requests[0], "x-opencode-session"),
        Some(go_session(GO).as_str()),
        "the catalogue session seeds from the connection id"
    );
    for request in &requests[1..] {
        assert_eq!(
            go_header(request, "x-opencode-session"),
            Some(go_session("/world/local").as_str()),
            "a wire leg seeds the session from the frozen world"
        );
        assert_eq!(go_header(request, "x-api-key"), None);
        assert_eq!(
            go_header(request, "anthropic-version"),
            None,
            "the non-Messages Go legs carry no `anthropic-version`"
        );
    }
}

/// Wrong, absent or unresolvable credential, or a configured region,
/// never produce a false success: an unbound declaration is refused at
/// ingress, a configured `region` denies `RegionMismatch`, a bound scope
/// the store cannot resolve denies `CredentialAbsent` with no wire leg, a
/// profile-bound ref whose scope disagrees with the binding denies
/// `CredentialProfileMismatch`, and a refused key lands the typed
/// transport denial carrying the peer's status alone — no error renders
/// the offered material or the peer's body.
#[tokio::test]
async fn band5_opencode_go_wrong_credential_profile_or_region_denies_without_secrets() {
    // the recorded class requires its scoped binding at ingress
    let unbound = go_config("https://opencode.ai/zen/go", GO_CC_MODEL)
        .replace(&format!("credential_ref = \"{GO_REF}\"\n"), "");
    let err = Config::parse_validated(&unbound)
        .expect_err("the recorded class requires its scoped binding at ingress");
    assert!(
        matches!(err.issue, ConfigIssue::CredentialRefRequired { .. }),
        "the unbound declaration is the typed ingress denial: {err}"
    );

    // a configured region denies at the routed seam, never ignored
    let regioned = Config::parse_validated(
        &go_config("https://opencode.ai/zen/go", GO_CC_MODEL)
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let denied = std::thread::spawn(move || {
        rivect::providers::routed::RoutedProvider::with_deadline(
            &regioned,
            GO,
            Arc::new(support::MapStore::seeded(
                STORE_KIND,
                &[(NEIGHBOR_REF, SECRET)],
            )),
            Duration::from_secs(1),
        )
    })
    .join()
    .expect("the provider thread joins")
    .expect_err("a configured region denies, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &denied else {
        panic!("a configured region is the typed mismatch: {denied}")
    };
    assert_eq!(connection, GO);
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&denied, SECRET.as_bytes());

    // a bound scope the store cannot resolve denies before any wire leg
    let server = MockServer::start().await;
    mount_chat(&server, completed_stream("never reached", None)).await;
    let config = Config::parse_validated(&go_config(&server.uri(), GO_CC_MODEL)).expect("valid");
    let provider = go_with(
        &config,
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        Duration::from_secs(2),
    );
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("the unresolved binding denies typed");
    assert!(
        matches!(err, ProviderError::CredentialAbsent { .. }),
        "the absent credential is the typed denial: {err}"
    );
    assert_no_secret_or_body(&err, SECRET.as_bytes());
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the unresolved binding opened no wire leg"
    );

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.{GO}]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"{GO}\", model_id = \"{GO_CC_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n",
        server.uri()
    ))
    .expect("valid");
    let denied = std::thread::spawn(move || {
        rivect::providers::routed::RoutedProvider::with_deadline(
            &mismatched,
            GO,
            Arc::new(support::MapStore::seeded(
                STORE_KIND,
                &[(NEIGHBOR_REF, SECRET)],
            )),
            Duration::from_secs(1),
        )
    })
    .join()
    .expect("the provider thread joins")
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        denied,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&denied, SECRET.as_bytes());

    // a refused key is a typed transport denial: the wire never coerces a
    // wrong credential into success, and the request carried the bearer
    let refused = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(GO_CC_PATH))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&refused)
        .await;
    let config = Config::parse_validated(&go_config(&refused.uri(), GO_CC_MODEL)).expect("valid");
    let (provider, _store) = go_provider(&config, Duration::from_secs(5));
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused key is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused key is transport: {err}")
    };
    assert_eq!(connection, GO);
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, SECRET.as_bytes());
    drop_blocking(provider);
    let requests = refused.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(requests[0].url.path(), GO_CC_PATH);
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {SECRET}"),
        "the admitted bearer reached the wire — the denial is the peer's status"
    );
}

// ----- TP-PROVIDER-RECOVERY::opencode-go (adverse wire) ----------------------

/// Hostile stream input never reports success for `opencode-go`: a
/// stream ended mid `tool_calls` fragment — a partial call that never
/// executes — and a finish_reason the dialect cannot classify are each
/// the unknown terminal, and a rejected send charges nothing.
#[tokio::test]
async fn band5_opencode_go_rejects_partial_tool_block_and_unknown_terminal() {
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
    let config = Config::parse_validated(&go_config(&server.uri(), GO_CC_MODEL)).expect("valid");
    let (broker, manifest) = prepared_with(
        go_provider(&config, Duration::from_secs(5)),
        &config,
        "/world/opencode-go",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/opencode-go", manifest);
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
    let config = Config::parse_validated(&go_config(&server.uri(), GO_CC_MODEL)).expect("valid");
    let (broker, manifest) = prepared_with(
        go_provider(&config, Duration::from_secs(5)),
        &config,
        "/world/opencode-go",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/opencode-go", manifest);
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

/// Incompatible tool or reasoning output never reports success: a
/// well-formed call naming a tool the frozen request never declared is
/// the typed `IncompatibleOutput`, and a `reasoning_content` fragment of
/// the wrong type is a typed stream violation — neither is executed or
/// accounted.
#[tokio::test]
async fn band5_opencode_go_rejects_incompatible_tools_or_reasoning() {
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
    let config = Config::parse_validated(&go_config(&server.uri(), GO_CC_MODEL)).expect("valid");
    let (broker, manifest) = prepared_with(
        go_provider(&config, Duration::from_secs(5)),
        &config,
        "/world/opencode-go",
        "goal: undeclared call",
    );
    let (broker, outcome) = dispatch(broker, "/world/opencode-go", manifest);
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

    // a non-string reasoning fragment is output the dialect cannot honour
    let server = MockServer::start().await;
    mount_chat(
        &server,
        data_block(&delta_chunk(json!({"reasoning_content": 42}))),
    )
    .await;
    let config = Config::parse_validated(&go_config(&server.uri(), GO_CC_MODEL)).expect("valid");
    let (broker, manifest) = prepared_with(
        go_provider(&config, Duration::from_secs(5)),
        &config,
        "/world/opencode-go",
        "goal: foreign reasoning shape",
    );
    let (broker, outcome) = dispatch(broker, "/world/opencode-go", manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::StreamViolation { .. }))
        ),
        "a non-string reasoning fragment is the typed violation: {outcome:?}"
    );
    assert_eq!(broker.accounted_requests(), 0);
    drop_blocking(broker);
}

/// The chosen codec's non-success branch is the typed status denial: one
/// physical POST, nothing accounted, and the peer's body never renders.
#[tokio::test]
async fn band5_opencode_go_non_success_status_denies() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(GO_CC_PATH))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&go_config(&server.uri(), GO_CC_MODEL)).expect("valid");
    let (broker, manifest) = prepared_with(
        go_provider(&config, Duration::from_secs(5)),
        &config,
        "/world/opencode-go",
        "goal: non-success status",
    );

    let (broker, outcome) = dispatch(broker, "/world/opencode-go", manifest);
    let err = outcome.expect_err("a non-success status never reports success");
    assert!(
        matches!(
            &err,
            ModelError::Provider(ProviderError::Transport {
                connection,
                cause: TransportCause::Status { status },
            }) if connection == GO && status.as_u16() == 401
        ),
        "the non-success status is the typed transport status: {err}"
    );
    let ModelError::Provider(provider_err) = &err else {
        panic!("the denial is a provider error: {err}");
    };
    assert_no_secret_or_body(provider_err, SECRET.as_bytes());
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "one physical POST, no send retry");
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a denied send is never accounted"
    );
    drop_blocking(broker);
}

/// A stalled peer past the whole-call deadline is the typed deadline
/// denial: the adapter's own budget check ends the send, nothing is
/// accounted, and no second request is issued.
#[tokio::test]
async fn band5_opencode_go_short_deadline_denies_without_a_second_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(GO_CC_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(completed_stream("too late", None))
                .set_delay(Duration::from_millis(400)),
        )
        .mount(&server)
        .await;
    let config = Config::parse_validated(&go_config(&server.uri(), GO_CC_MODEL)).expect("valid");
    let deadline = Duration::from_millis(250);
    let provider = go_with(
        &config,
        Arc::new(support::MapStore::seeded(STORE_KIND, &[(GO_REF, SECRET)])),
        deadline,
    );
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
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

// ----- TP-PROVIDER-MATRIX::opencode-go ---------------------------------------

/// The legs matrix enforces the recorded expected set for `opencode-go`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside this
/// run, and INSTALLED reports NOT_RUN.
#[tokio::test]
async fn band5_opencode_go_provider_legs_matrix_executes_all_expected_legs() {
    use std::collections::BTreeMap;
    let mut reported: BTreeMap<&str, &str> = BTreeMap::new();

    // CATALOG: the one listing filtered by the route table.
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![json!({"id": "muse-spark-1.3"}), json!({"id": GO_CC_EXACT})],
    )
    .await;
    let config = Config::parse_validated(&go_config(&server.uri(), GO_CC_MODEL)).expect("valid");
    let (provider, _store) = go_provider(&config, Duration::from_secs(5));
    let (provider, catalog) = go_catalog_on_thread(provider);
    reported.insert(
        "CATALOG",
        if matches!(
            &catalog,
            Ok(ids) if ids == &["muse-spark-1.3", GO_CC_EXACT].map(String::from)
        ) {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: a bound ref with no store material denies typed.
    let server = MockServer::start().await;
    mount_chat(&server, completed_stream("never reached", None)).await;
    let config = Config::parse_validated(&go_config(&server.uri(), GO_CC_MODEL)).expect("valid");
    let provider = go_with(
        &config,
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        Duration::from_secs(2),
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

    // WIRE: a Responses override returns the verified outcome.
    let server = MockServer::start().await;
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
        Config::parse_validated(&go_config(&server.uri(), GO_RESPONSES_MODEL)).expect("valid");
    let (broker, manifest) = prepared_with(
        go_provider(&config, Duration::from_secs(5)),
        &config,
        "/world/opencode-go",
        "goal: matrix wire",
    );
    let (broker, outcome) = dispatch(broker, "/world/opencode-go", manifest);
    reported.insert(
        "WIRE",
        if matches!(&outcome, Ok(reply) if reply.text == "matrix") {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

    // RECOVERY: a Responses stream without its terminal is never success.
    let server = MockServer::start().await;
    let mut truncated = responses_completed_stream("looks complete", Vec::new(), None);
    truncated.truncate(
        truncated
            .rfind("event: response.completed")
            .expect("the terminal exists"),
    );
    mount_responses(&server, truncated).await;
    let config =
        Config::parse_validated(&go_config(&server.uri(), GO_RESPONSES_MODEL)).expect("valid");
    let (provider, _store) = go_provider(&config, Duration::from_secs(5));
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
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

// ----- TP-PROVIDER-INSTALLED::opencode-go ------------------------------------

/// TP-PROVIDER-INSTALLED::opencode-go = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs, and a
/// real Go request needs its own fresh authorization.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::opencode-go = NOT_RUN"]
fn provider_installed_opencode_go() {}
