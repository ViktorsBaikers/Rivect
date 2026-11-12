// ----- llama.cpp ---------------------------------------------------------------

// The `llama.cpp` connection's proof legs (HZN-008 class B — the
// local-endpoint cell): the shared Chat Completions adapter serves the
// literal id under its own recorded predicates. The endpoint is the
// configured local base verbatim, and the required `endpoint` field's
// empty string resolves the recorded default `http://127.0.0.1:8080`
// from `auth/llama.cpp.kdl`'s login instructions. The recorded auth is
// optional beside a server key, so the credential arm is the shared
// absent-binding form: an unbound declaration rides headerless, a
// declared binding that cannot resolve denies typed, and a scoped key
// bears the wire. The manual model path is the supported route — no
// automatic discovery, no catalogue wire leg and no base-URL merging is
// built or claimed (DEC-008/PROH-009/D7): the catalogue answers no
// offers, a mounted `/models` listing is never consulted, and a fixed
// pin opens exactly one request carrying its own model.

/// The scoped credential ref a server-keyed `llama.cpp` connection binds.
const LLAMA_CPP_REF: &str = "keyring:rivect-test/llama.cpp";

/// Fixture server key — never a real credential, only ever sent to
/// localhost.
const LLAMA_CPP_KEY: &str = "fixture-llama-cpp-server-key";

/// The pinned manual model id the fixed-pin legs carry: a locally
/// served GGUF's own naming, never a recorded catalogue row.
const LLAMA_CPP_MODEL: &str = "fixture-gguf-model";

/// A model id the fixture peer's `/models` answer offers.
const LLAMA_CPP_LISTED: &str = "fixture-listed-gguf";

/// One configured `llama.cpp` connection pointing at the fixture peer,
/// carrying no `credential_ref` — the recorded keyless local mode.
fn llama_cpp_keyless_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.\"llama.cpp\"]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"llama.cpp\", model_id = \"{LLAMA_CPP_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The same connection with a scoped server key enrolled — the recorded
/// server-key mode of the one class.
fn llama_cpp_config(endpoint: &str) -> String {
    llama_cpp_keyless_config(endpoint).replace(
        "endpoint = \"",
        &format!("credential_ref = \"{LLAMA_CPP_REF}\"\nendpoint = \""),
    )
}

fn llama_cpp_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(LLAMA_CPP_REF, material)],
    ));
    let provider = provider_result(config.clone(), "llama.cpp".to_string(), store.clone())
        .expect("the shared adapter builds for the llama.cpp id");
    (provider, store)
}

/// The `llama.cpp` provider over the recorded server key.
fn enrolled_llama_cpp_provider(
    config: &Config,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    llama_cpp_provider(config, LLAMA_CPP_KEY)
}

/// The `llama.cpp` provider over the recorded keyless local mode: no
/// credential is bound, so the store is never consulted.
fn keyless_llama_cpp_provider(config: &Config) -> ChatCompletionsProvider {
    provider_result(
        config.clone(),
        "llama.cpp".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("an unbound declaration is the recorded keyless local mode")
}

// ----- TP-PROVIDER-WIRE::llama.cpp ----------------------------------------------

/// A configured `llama.cpp` connection returns a verified model outcome
/// through the standard Broker on the recorded keyless local mode:
/// prepare admits the api_key pin under DEC-011, the shared adapter
/// posts exactly the frozen manifest as one `chat/completions` request —
/// the pinned id verbatim, system+user messages, `stream` with
/// `stream_options.include_usage` and the pinned effort as
/// `reasoning_effort` verbatim — the SSE stream validates its
/// finish_reason/`[DONE]` terminal, and the one physical send is charged
/// once with the provider's reported usage.
#[tokio::test]
async fn llama_cpp_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified local outcome",
            Some(json!({"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&llama_cpp_keyless_config(&server_uri_v1(&server))).expect("valid");
    assert_eq!(
        config.connections["llama.cpp"].credential_ref, None,
        "the keyless row binds no credential — never a materialized dummy"
    );
    let (broker, manifest) = prepared_with(
        (
            keyless_llama_cpp_provider(&config),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        ),
        &config,
        "/world/llama",
        "goal: prove the wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/llama", manifest.clone());
    let reply = outcome.expect("the keyless pin is admitted and dispatched");
    assert_eq!(reply.text, "verified local outcome");
    assert!(reply.tool_calls.is_empty());

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert!(
        requests[0].headers.get("authorization").is_none(),
        "the keyless local mode sends no Authorization header"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"],
        json!(LLAMA_CPP_MODEL),
        "the pinned model id rides the wire verbatim"
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

    assert_eq!(
        broker.accounted_requests(),
        1,
        "one physical send is charged once"
    );
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "llama.cpp");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 5,
            completion_tokens: 3,
            total_tokens: 8,
        }
    );
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay = broker.dispatch(&mut rivect::model::NullLedger, "/world/llama", &manifest);
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

/// The recorded keyless local mode carries no credential material at
/// all: the declaration binds no `credential_ref`, DEC-011 eligibility
/// admits the pin, the send reaches the peer with no `Authorization`
/// header — never an empty or dummy bearer — and its reply is one
/// outcome charged as one physical usage. The recorded contract opens
/// no catalogue wire leg at all.
#[tokio::test]
async fn llama_cpp_keyless_local_mode_sends_no_credential() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "keyless local outcome",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&llama_cpp_keyless_config(&server_uri_v1(&server))).expect("valid");

    let (broker, manifest) = prepared_with(
        (
            keyless_llama_cpp_provider(&config),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        ),
        &config,
        "/world/llama",
        "goal: keyless local",
    );
    let (broker, outcome) = dispatch(broker, "/world/llama", manifest);
    let reply = outcome.expect("the keyless pin dispatches");
    assert_eq!(reply.text, "keyless local outcome");
    assert_eq!(broker.accounted_requests(), 1);
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        request_paths(&requests),
        ["/v1/chat/completions"],
        "the send opens exactly one chat request — no `/models` egress"
    );
    assert!(
        requests[0].headers.get("authorization").is_none(),
        "no binding means no Authorization header — never a fabricated key"
    );
}

/// The recorded server-key mode of the same class: the enrolled scoped
/// `SecretRef` material is the bearer the send carries — one keyed
/// form, never a mixed one — and the recorded contract opens no
/// catalogue wire leg at all.
#[tokio::test]
async fn llama_cpp_server_key_mode_sends_the_scoped_bearer() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "server key outcome",
            Some(json!({"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&llama_cpp_config(&server_uri_v1(&server))).expect("valid");

    let (provider, _store) = enrolled_llama_cpp_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let reply = outcome.expect("the server key admits the send");
    assert_eq!(reply.text, "server key outcome");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        request_paths(&requests),
        ["/v1/chat/completions"],
        "the send opens exactly one chat request — no `/models` egress"
    );
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {LLAMA_CPP_KEY}"),
        "the enrolled server key bears the send"
    );
}

/// Hostile stream input is never a false success for `llama.cpp`: a
/// stream ended mid `tool_calls` fragment — a partial call that never
/// executes — and a finish_reason the dialect cannot classify are both
/// the unknown terminal, and a rejected send charges nothing.
#[tokio::test]
async fn llama_cpp_adverse_wire_input_never_reports_success() {
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
        Config::parse_validated(&llama_cpp_keyless_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        (
            keyless_llama_cpp_provider(&config),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        ),
        &config,
        "/world/llama",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/llama", manifest);
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
        Config::parse_validated(&llama_cpp_keyless_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        (
            keyless_llama_cpp_provider(&config),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        ),
        &config,
        "/world/llama",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/llama", manifest);
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

// ----- TP-PROVIDER-CATALOG::llama.cpp -------------------------------------------

/// The configured local base resolves verbatim and the required
/// `endpoint` field's empty string resolves the recorded default
/// `http://127.0.0.1:8080` from the auth source — never a borrowed
/// host: `lm-studio`'s `127.0.0.1:1234/v1` and every cloud class's base
/// stay out of this connection (EDGE-006). Offline pin: the adapter's
/// `Debug` surface reports the resolved endpoint, so both arms are
/// proved without one byte toward any host.
#[test]
fn llama_cpp_discriminates_the_recorded_default_base() {
    for endpoint in ["", "   "] {
        let config = Config::parse_validated(&llama_cpp_keyless_config(endpoint))
            .expect("an empty endpoint is valid");
        let provider = keyless_llama_cpp_provider(&config);
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"http://127.0.0.1:8080\""),
            "endpoint {endpoint:?} resolved the recorded local default: {debug}"
        );
        assert!(
            !debug.contains("1234") && !debug.contains("localhost"),
            "no sibling local or cloud host is substituted: {debug}"
        );
        drop_blocking(provider);
    }

    // a configured base wins verbatim — the trailing slash is the only
    // normalization, never a `/v1` append or a default substitution
    let config = Config::parse_validated(&llama_cpp_keyless_config("http://127.0.0.1:9931/v1/"))
        .expect("a configured local base is valid");
    let provider = keyless_llama_cpp_provider(&config);
    let debug = format!("{provider:?}");
    assert!(
        debug.contains("endpoint: \"http://127.0.0.1:9931/v1\""),
        "the configured base rides verbatim: {debug}"
    );
    assert!(
        !debug.contains("8080"),
        "the recorded default never overrides a configured base: {debug}"
    );
    drop_blocking(provider);
}

/// The recorded contract names no discovery leg for `llama.cpp`: the
/// catalogue answers no offers — unrecorded, so empty — with no wire
/// leg and no credential read, a mounted `/models` listing is never
/// consulted and never adds an offer, and a fixed pin still sends its
/// own model as the one chat request — the manual model path is the
/// only served route (DEC-008/PROH-009/D7).
#[tokio::test]
async fn llama_cpp_catalog_opens_no_wire_leg() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": LLAMA_CPP_LISTED})]).await;
    mount_chat(
        &server,
        completed_stream(
            "manual path outcome",
            Some(json!({"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&llama_cpp_keyless_config(&server_uri_v1(&server))).expect("valid");

    // the catalogue is the recorded fixed list alone — unrecorded, so
    // empty; no `/models` request exists on this connection, so the
    // mounted listing can never add an offer
    let (provider, catalogue) = catalog_on_thread(keyless_llama_cpp_provider(&config));
    let models = catalogue.expect("the recorded catalogue answers");
    drop_blocking(provider);
    assert!(
        models.is_empty(),
        "the record names no roster — an offer would be invented input"
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "no discovery leg exists: the listing was never consulted"
    );

    // a fixed pin sends exactly the one chat request, its own model —
    // no `/models` leg opens on the send path either
    let (broker, manifest) = prepared_with(
        (
            keyless_llama_cpp_provider(&config),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        ),
        &config,
        "/world/llama",
        "goal: manual model path",
    );
    let (broker, outcome) = dispatch(broker, "/world/llama", manifest);
    let reply = outcome.expect("the manual pin dispatches");
    assert_eq!(reply.text, "manual path outcome");
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        request_paths(&requests),
        ["/v1/chat/completions"],
        "exactly the one chat request — no discovery leg is attempted"
    );
    assert!(
        !request_paths(&requests).contains(&LM_STUDIO_NATIVE_PATH),
        "a local-endpoint sibling never opens the lm-studio native probe"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"],
        json!(LLAMA_CPP_MODEL),
        "the pinned model rides the wire — a listed id never substitutes it"
    );
}

// ----- TP-PROVIDER-AUTH::llama.cpp ----------------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `llama.cpp`, through the same shared construction its siblings use: a
/// configured `region` — the recorded local contract names none —
/// denies `RegionMismatch` with the connection context, and a
/// profile-bound ref whose scope disagrees with the binding denies
/// `CredentialProfileMismatch`; both deny before the store is read, so
/// neither arm renders material at all. A refused server key then lands
/// the typed transport denial carrying the peer's status alone, and on
/// that arm — the one that resolves and sends the material — neither
/// the offered credential nor the peer's body reaches Display or Debug.
#[tokio::test]
async fn llama_cpp_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    let regioned = Config::parse_validated(
        &llama_cpp_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "llama.cpp".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "llama.cpp");
    assert_eq!(region, "eu");

    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.\"llama.cpp\"]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"llama.cpp\", model_id = \"{LLAMA_CPP_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "llama.cpp".to_string(),
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
    let config =
        Config::parse_validated(&llama_cpp_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_llama_cpp_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused server key is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused key is transport: {err}")
    };
    assert_eq!(connection, "llama.cpp");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, LLAMA_CPP_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {LLAMA_CPP_KEY}"),
        "the admitted server key reached the wire — the denial is the peer's status"
    );
}

// ----- TP-PROVIDER-RECOVERY::llama.cpp ------------------------------------------

/// A typed denial is recoverable through the same seam: material the
/// store resolves but the class cannot use — non-UTF-8 bytes can never
/// be a bearer token — denies `CredentialMalformed` on the first send,
/// and enrolling the recorded server key at the same scope admits the
/// retry with that bearer. No state is wedged and no plaintext path is
/// taken.
#[tokio::test]
async fn llama_cpp_typed_denial_recovers_through_the_same_credential_seam() {
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
        Config::parse_validated(&llama_cpp_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    store.enroll(LLAMA_CPP_REF, &[0xff, 0xfe]);
    let provider =
        provider_result(config.clone(), "llama.cpp".to_string(), store.clone()).expect("binding");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialMalformed { .. })
    ));

    store.enroll(LLAMA_CPP_REF, LLAMA_CPP_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the enrolled server key admits the retry");
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
        format!("Bearer {LLAMA_CPP_KEY}"),
        "the recovered material bears the wire"
    );
}

/// The legs matrix enforces the recorded expected set for `llama.cpp`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside this
/// run, and INSTALLED reports NOT_RUN — an omitted leg fails the suite
/// rather than silently absenting.
#[tokio::test]
async fn llama_cpp_provider_legs_matrix_executes_all_expected_legs() {
    emit_provider_rows("llama.cpp");
    use std::collections::BTreeMap;
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": LLAMA_CPP_LISTED})]).await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&llama_cpp_config(&server_uri_v1(&server))).expect("valid");
    let keyless = Config::parse_validated(&llama_cpp_keyless_config(&server_uri_v1(&server)))
        .expect("the keyless row is valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the recorded contract names no discovery leg — the
    // catalogue answers no offers, the mounted `/models` listing is
    // never consulted, and no offer can carry a price or capability
    // mark the class does not record.
    let (provider, catalogue) = catalog_on_thread(keyless_llama_cpp_provider(&keyless));
    let listed = catalogue.expect("catalog answers");
    let requests = server.received_requests().await.expect("recorded");
    let no_listing_leg = !request_paths(&requests)
        .iter()
        .any(|path| path.ends_with("/models"));
    drop_blocking(provider);
    reported.insert(
        "CATALOG",
        if listed.is_empty() && no_listing_leg {
            "PASS"
        } else {
            "FAIL"
        },
    );

    // AUTH: the one class carries both recorded forms — the server key
    // bears the chat request, the keyless declaration sends headerless.
    let (provider, _store) = enrolled_llama_cpp_provider(&config);
    let (provider, keyed_outcome) = send_on_thread(provider, prepared_manifest(&config));
    let keyed_ok = keyed_outcome.is_ok();
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    let keyed_bearer = requests.last().is_some_and(|request| {
        request.headers.get("authorization").is_some_and(|value| {
            value
                .to_str()
                .is_ok_and(|header| header == format!("Bearer {LLAMA_CPP_KEY}"))
        })
    });
    let (provider, headerless_outcome) = send_on_thread(
        keyless_llama_cpp_provider(&keyless),
        prepared_manifest(&keyless),
    );
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

    // WIRE: the full broker dispatch over the recorded keyless local mode
    // returns the verified outcome.
    let (broker, manifest) = {
        let mut broker = Broker::new(Box::new(keyless_llama_cpp_provider(&keyless)));
        let manifest = broker
            .prepare("main", &keyless, "/world/llama", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
    let (broker, outcome) = dispatch(broker, "/world/llama", manifest);
    reported.insert(
        "WIRE",
        if matches!(&outcome, Ok(reply) if reply.text == "matrix") {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

    // RECOVERY: unusable material denies typed, and the recorded server
    // key at the same scope admits the retry.
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    store.enroll(LLAMA_CPP_REF, &[0xff, 0xfe]);
    let provider =
        provider_result(config.clone(), "llama.cpp".to_string(), store.clone()).expect("binding");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialMalformed { .. }));
    store.enroll(LLAMA_CPP_REF, LLAMA_CPP_KEY.as_bytes());
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

// ----- TP-PROVIDER-INSTALLED::llama.cpp -----------------------------------------

/// TP-PROVIDER-INSTALLED::llama.cpp = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::llama.cpp = NOT_RUN"]
fn provider_installed_llama_cpp() {}

// ----- lm-studio ---------------------------------------------------------------

// The `lm-studio` connection's proof legs (HZN-008 class B — the
// local-endpoint cell): the shared Chat Completions adapter serves the
// literal id under its own recorded predicates. The endpoint is the
// configured local base verbatim, and the required `endpoint` field's
// empty string resolves the recorded default `http://127.0.0.1:1234/v1`
// — its own base, never `llama.cpp`'s `:8080` (EDGE-006). The recorded
// auth is optional beside a server key, so the credential arm is the
// shared absent-binding form: an unbound declaration rides headerless, a
// declared binding that cannot resolve denies typed, and a scoped key
// bears the wire. The class's `/models` listing is its own catalogue
// rule and never paid access — the recorded local class has no shared
// external account, so no account/org predicate exists to assert — and
// no discovery or base-URL merging is built beyond that listing leg
// (D8: the recorded extra `/v1/responses` path stays a different
// connection class).

/// The scoped credential ref a server-keyed `lm-studio` connection binds.
const LM_STUDIO_REF: &str = "keyring:rivect-test/lm-studio";

/// Fixture server key — never a real credential, only ever sent to
/// localhost.
const LM_STUDIO_KEY: &str = "fixture-lm-studio-server-key";

/// The pinned manual model id the fixed-pin legs carry: the locally
/// loaded model's own naming, never a recorded catalogue row.
const LM_STUDIO_MODEL: &str = "fixture-lm-studio-model";

/// A model id the fixture peer's `/models` answer offers.
const LM_STUDIO_LISTED: &str = "fixture-listed-lm-studio";

/// The recorded native loaded-context probe path: the configured `/v1`
/// base stripped to its origin by the recorded native-base rule — the
/// class's own extra catalogue source.
const LM_STUDIO_NATIVE_PATH: &str = "/api/v0/models";

/// Listing ids the native overlay discriminates: one the probe marks
/// vision-capable through its type, one it leaves text-only, two whose
/// windows only the recorded fallback lengths can fill, and one it
/// names without the listing ever offering it.
const LM_STUDIO_VISION: &str = "fixture-vision-lm-studio";
const LM_STUDIO_TEXT: &str = "fixture-text-lm-studio";
const LM_STUDIO_CAPABILITY: &str = "fixture-capability-lm-studio";
const LM_STUDIO_MAX_LEN: &str = "fixture-max-len-lm-studio";
const LM_STUDIO_UNLISTED: &str = "fixture-unlisted-lm-studio";

/// One configured `lm-studio` connection pointing at the fixture peer,
/// carrying no `credential_ref` — the recorded keyless local mode.
fn lm_studio_keyless_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.lm-studio]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"lm-studio\", model_id = \"{LM_STUDIO_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The same connection with a scoped server key enrolled — the recorded
/// server-key mode of the one class.
fn lm_studio_config(endpoint: &str) -> String {
    lm_studio_keyless_config(endpoint).replace(
        "endpoint = \"",
        &format!("credential_ref = \"{LM_STUDIO_REF}\"\nendpoint = \""),
    )
}

fn lm_studio_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(LM_STUDIO_REF, material)],
    ));
    let provider = provider_result(config.clone(), "lm-studio".to_string(), store.clone())
        .expect("the shared adapter builds for the lm-studio id");
    (provider, store)
}

/// The `lm-studio` provider over the recorded server key.
fn enrolled_lm_studio_provider(
    config: &Config,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    lm_studio_provider(config, LM_STUDIO_KEY)
}

/// The `lm-studio` provider over the recorded keyless local mode: no
/// credential is bound, so the store is never consulted.
fn keyless_lm_studio_provider(config: &Config) -> ChatCompletionsProvider {
    provider_result(
        config.clone(),
        "lm-studio".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("an unbound declaration is the recorded keyless local mode")
}

/// Mount the class's native loaded-context probe answer.
async fn mount_native_models(server: &MockServer, template: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(LM_STUDIO_NATIVE_PATH))
        .respond_with(template)
        .mount(server)
        .await;
}

/// The keyless catalogue against the fixture peer, on a plain OS thread.
fn keyless_lm_studio_catalogue(server: &MockServer) -> Vec<CatalogModel> {
    let config =
        Config::parse_validated(&lm_studio_keyless_config(&server_uri_v1(server))).expect("valid");
    let (provider, catalogue) = catalog_on_thread(keyless_lm_studio_provider(&config));
    let models = catalogue.expect("the listing answers");
    drop_blocking(provider);
    models
}

// ----- TP-PROVIDER-WIRE::lm-studio ----------------------------------------------

/// A configured `lm-studio` connection returns a verified model outcome
/// through the standard Broker on the recorded keyless local mode:
/// prepare admits the api_key pin under DEC-011, the shared adapter
/// posts exactly the frozen manifest as one `chat/completions` request —
/// the pinned id verbatim, system+user messages, `stream` with
/// `stream_options.include_usage` and the pinned effort as
/// `reasoning_effort` verbatim — the SSE stream validates its
/// finish_reason/`[DONE]` terminal, and the one physical send is charged
/// once with the provider's reported usage.
#[tokio::test]
async fn lm_studio_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified local outcome",
            Some(json!({"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&lm_studio_keyless_config(&server_uri_v1(&server))).expect("valid");
    assert_eq!(
        config.connections["lm-studio"].credential_ref, None,
        "the keyless row binds no credential — never a materialized dummy"
    );
    let (broker, manifest) = prepared_with(
        (
            keyless_lm_studio_provider(&config),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        ),
        &config,
        "/world/studio",
        "goal: prove the wire",
    );

    let (broker, outcome) = dispatch(broker, "/world/studio", manifest.clone());
    let reply = outcome.expect("the keyless pin is admitted and dispatched");
    assert_eq!(reply.text, "verified local outcome");
    assert!(reply.tool_calls.is_empty());

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "one physical request — no /models leg");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert!(
        requests[0].headers.get("authorization").is_none(),
        "the keyless local mode sends no Authorization header"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"],
        json!(LM_STUDIO_MODEL),
        "the pinned model id rides the wire verbatim"
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

    assert_eq!(
        broker.accounted_requests(),
        1,
        "one physical send is charged once"
    );
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "lm-studio");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 5,
            completion_tokens: 3,
            total_tokens: 8,
        }
    );
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay = broker.dispatch(&mut rivect::model::NullLedger, "/world/studio", &manifest);
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

/// The recorded keyless local mode carries no credential material at
/// all: the declaration binds no `credential_ref`, DEC-011 eligibility
/// admits the pin, the send reaches the peer with no `Authorization`
/// header — never an empty or dummy bearer — and its reply is one
/// outcome charged as one physical usage. The catalogue leg rides the
/// same keyless form.
#[tokio::test]
async fn lm_studio_keyless_local_mode_sends_no_credential() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": LM_STUDIO_LISTED})]).await;
    mount_chat(
        &server,
        completed_stream(
            "keyless local outcome",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&lm_studio_keyless_config(&server_uri_v1(&server))).expect("valid");

    let (provider, catalogue) = catalog_on_thread(keyless_lm_studio_provider(&config));
    let models = catalogue.expect("the keyless catalogue answers headerless");
    drop_blocking(provider);
    assert_eq!(model_ids(&models), [LM_STUDIO_LISTED]);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 2, "the listing leg and the native probe");
    let probe = requests
        .iter()
        .find(|request| request.url.path() == LM_STUDIO_NATIVE_PATH)
        .expect("the native probe rode the catalogue beside the listing");
    assert!(
        probe.headers.get("authorization").is_none(),
        "the keyless local mode sends no Authorization header on the native probe"
    );
    assert!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/v1/models")
            .all(|request| request.headers.get("authorization").is_none()),
        "the keyless listing stays headerless"
    );

    let (broker, manifest) = prepared_with(
        (
            keyless_lm_studio_provider(&config),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        ),
        &config,
        "/world/studio",
        "goal: keyless local",
    );
    let (broker, outcome) = dispatch(broker, "/world/studio", manifest);
    let reply = outcome.expect("the keyless pin dispatches");
    assert_eq!(reply.text, "keyless local outcome");
    assert_eq!(broker.accounted_requests(), 1);
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        3,
        "the listing, the native probe, then the one send"
    );
    assert!(
        requests
            .iter()
            .all(|request| request.headers.get("authorization").is_none()),
        "no binding means no Authorization header on any leg — never a fabricated key"
    );
}

/// The recorded server-key mode of the same class: the enrolled scoped
/// `SecretRef` material is the bearer the send and the catalogue leg
/// both carry — one keyed form, never a mixed one.
#[tokio::test]
async fn lm_studio_server_key_mode_sends_the_scoped_bearer() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": LM_STUDIO_LISTED})]).await;
    mount_chat(
        &server,
        completed_stream(
            "server key outcome",
            Some(json!({"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&lm_studio_config(&server_uri_v1(&server))).expect("valid");

    let (provider, catalogue) = catalog_on_thread(enrolled_lm_studio_provider(&config).0);
    let models = catalogue.expect("the keyed catalogue answers");
    drop_blocking(provider);
    assert_eq!(model_ids(&models), [LM_STUDIO_LISTED]);

    let (provider, _store) = enrolled_lm_studio_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let reply = outcome.expect("the server key admits the send");
    assert_eq!(reply.text, "server key outcome");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    let mut paths = request_paths(&requests);
    paths.sort_unstable();
    assert_eq!(
        paths,
        ["/api/v0/models", "/v1/chat/completions", "/v1/models"],
        "the keyed listing leg, the native probe and the send"
    );
    let probe = requests
        .iter()
        .find(|request| request.url.path() == LM_STUDIO_NATIVE_PATH)
        .expect("the native probe rode the catalogue beside the listing");
    assert_eq!(
        received_auth(probe),
        format!("Bearer {LM_STUDIO_KEY}"),
        "resolved material bears the native probe"
    );
    assert!(
        requests
            .iter()
            .all(|request| received_auth(request) == format!("Bearer {LM_STUDIO_KEY}")),
        "the enrolled server key bears every leg of the same class"
    );
}

/// Hostile stream input is never a false success for `lm-studio`: a
/// stream ended mid `tool_calls` fragment — a partial call that never
/// executes — and a finish_reason the dialect cannot classify are both
/// the unknown terminal, and a rejected send charges nothing.
#[tokio::test]
async fn lm_studio_adverse_wire_input_never_reports_success() {
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
        Config::parse_validated(&lm_studio_keyless_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        (
            keyless_lm_studio_provider(&config),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        ),
        &config,
        "/world/studio",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/studio", manifest);
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
        Config::parse_validated(&lm_studio_keyless_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        (
            keyless_lm_studio_provider(&config),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        ),
        &config,
        "/world/studio",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/studio", manifest);
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

// ----- TP-PROVIDER-CATALOG::lm-studio -------------------------------------------

/// The configured local base resolves verbatim and the required
/// `endpoint` field's empty string resolves the recorded default
/// `http://127.0.0.1:1234/v1`, `/v1` segment included — never
/// `llama.cpp`'s `127.0.0.1:8080` and never a cloud class's base
/// (EDGE-006). Offline pin: the adapter's `Debug` surface reports the
/// resolved endpoint, so both arms are proved without one byte toward
/// any host.
#[test]
fn lm_studio_discriminates_the_recorded_default_base() {
    for endpoint in ["", "   "] {
        let config = Config::parse_validated(&lm_studio_keyless_config(endpoint))
            .expect("an empty endpoint is valid");
        let provider = keyless_lm_studio_provider(&config);
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"http://127.0.0.1:1234/v1\""),
            "endpoint {endpoint:?} resolved the recorded local default: {debug}"
        );
        assert!(
            !debug.contains("8080") && !debug.contains("localhost"),
            "no sibling local or cloud host is substituted: {debug}"
        );
        drop_blocking(provider);
    }

    // a configured base wins verbatim — trailing slashes are the only
    // normalization, never a `/v1` append or a default substitution
    let config = Config::parse_validated(&lm_studio_keyless_config("http://127.0.0.1:9931/v1/"))
        .expect("a configured local base is valid");
    let provider = keyless_lm_studio_provider(&config);
    let debug = format!("{provider:?}");
    assert!(
        debug.contains("endpoint: \"http://127.0.0.1:9931/v1\""),
        "the configured base rides verbatim: {debug}"
    );
    assert!(
        !debug.contains("1234"),
        "the recorded default never overrides a configured base: {debug}"
    );
    drop_blocking(provider);
}

/// A `/models` HTTP 200 is never paid access for `lm-studio` (INV-010):
/// the class's own catalogue rule is the configured base's listing under
/// ids-only offers, so a listed id is offered as served with no price or
/// capability mark, and the fixed pin's send still posts its own model —
/// never the listed id as a substitute. The recorded local class has no
/// shared external account, so no account/org predicate is asserted. An
/// empty listing leaves the class's own floor, which records no seed row.
#[tokio::test]
async fn lm_studio_listing_is_never_entitlement() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "listed-entitlement-claim"})]).await;
    let config =
        Config::parse_validated(&lm_studio_keyless_config(&server_uri_v1(&server))).expect("valid");

    let (provider, catalogue) = catalog_on_thread(keyless_lm_studio_provider(&config));
    let models = catalogue.expect("the local listing answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        ["listed-entitlement-claim"],
        "the class's own catalogue rule decides the offer — no seed floor joins it"
    );
    for model in &models {
        assert_eq!(
            model,
            &CatalogModel {
                id: model.id.clone(),
                ..CatalogModel::default()
            },
            "{} keeps the ids-only surface — a local answer confers no price or capability",
            model.id
        );
    }
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "the listing leg and its native probe, never a paid-access check"
    );
    assert!(
        request_paths(&requests).contains(&LM_STUDIO_NATIVE_PATH),
        "the advisory native probe rides the catalogue"
    );

    let (provider, outcome) = send_on_thread(
        keyless_lm_studio_provider(&config),
        prepared_manifest(&config),
    );
    let err = outcome.expect_err("a 200 listing never releases the pin");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the unmounted request leg is the typed transport denial: {err:?}");
    };
    assert_eq!(connection, "lm-studio");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 404 },
        "the request leg answers the peer's status: {cause}"
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        3,
        "the listing, the native probe and the request leg"
    );
    let chat = requests
        .iter()
        .find(|request| request.url.path() == "/v1/chat/completions")
        .expect("the request leg is the chat post");
    let body: Value = serde_json::from_slice(&chat.body).expect("json body");
    assert_eq!(
        body["model"],
        json!(LM_STUDIO_MODEL),
        "the pinned model rides the wire — a listed id never substitutes it"
    );

    // an empty listing is never an error: the class records no seed row,
    // so its own floor is empty and the offer set stays empty
    let server = MockServer::start().await;
    mount_models(&server, Vec::new()).await;
    let config =
        Config::parse_validated(&lm_studio_keyless_config(&server_uri_v1(&server))).expect("valid");
    let (provider, catalogue) = catalog_on_thread(keyless_lm_studio_provider(&config));
    let models = catalogue.expect("an empty local listing answers");
    drop_blocking(provider);
    assert!(
        models.is_empty(),
        "an empty listing leaves the class's own (seedless) floor: {models:?}"
    );
}

// ----- TP-PROVIDER-AUTH::lm-studio ----------------------------------------------

/// The recorded native loaded-context metadata rides the class's own
/// `/api/v0/models` probe beside the `/models` listing: only an id the
/// listing already offers gains the probe's marks — a `vlm` type or a
/// `vision`/`image` capability marks it vision-capable, and the window
/// is the loaded length of a loaded model, else the max, train or
/// model-len length in the recorded order — while a row the probe alone
/// names adds nothing, because the listing stays authoritative.
#[tokio::test]
async fn lm_studio_native_metadata_overlays_the_listing_offers_only() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": LM_STUDIO_VISION}),
            json!({"id": LM_STUDIO_TEXT}),
            json!({"id": LM_STUDIO_CAPABILITY}),
            json!({"id": LM_STUDIO_MAX_LEN}),
        ],
    )
    .await;
    mount_native_models(
        &server,
        ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "id": LM_STUDIO_VISION,
                    "type": "vlm",
                    "state": "loaded",
                    "loaded_context_length": 8192,
                    "max_context_length": 32768,
                    "context_length": 4096,
                    "max_model_len": 16384,
                },
                {
                    "id": LM_STUDIO_TEXT,
                    "type": "llm",
                    "capabilities": ["text"],
                    "state": "not-loaded",
                    "loaded_context_length": 999,
                    "max_context_length": 2048,
                    "context_length": 1024,
                    "max_model_len": 512,
                },
                {
                    "id": LM_STUDIO_CAPABILITY,
                    "type": "llm",
                    "capabilities": ["TEXT", "Image"],
                    "state": "idle",
                    "context_length": 1024,
                    "max_model_len": 512,
                },
                {"id": LM_STUDIO_MAX_LEN, "type": "llm", "max_model_len": 512},
                {
                    "id": LM_STUDIO_UNLISTED,
                    "type": "vlm",
                    "state": "loaded",
                    "loaded_context_length": 4096,
                },
            ],
        })),
    )
    .await;

    let models = keyless_lm_studio_catalogue(&server);
    assert_eq!(
        model_ids(&models),
        [
            LM_STUDIO_CAPABILITY,
            LM_STUDIO_MAX_LEN,
            LM_STUDIO_TEXT,
            LM_STUDIO_VISION,
        ],
        "the listing keeps its own offers — an id the probe alone names adds nothing"
    );
    let vision = models
        .iter()
        .find(|model| model.id == LM_STUDIO_VISION)
        .expect("the listed vision id is offered");
    assert!(vision.vision, "a vlm type marks the offer vision-capable");
    assert_eq!(
        vision.context_window,
        Some(8192),
        "a loaded model's loaded length wins over the architectural ceiling"
    );
    assert_eq!(
        vision.price,
        ModelPrice::Unknown,
        "the native probe states no price"
    );
    let text = models
        .iter()
        .find(|model| model.id == LM_STUDIO_TEXT)
        .expect("the listed text id is offered");
    assert!(
        !text.vision,
        "an llm type with text capabilities is text-only"
    );
    assert_eq!(
        text.context_window,
        Some(2048),
        "an unloaded model ignores its loaded length and takes the max length"
    );
    let capability = models
        .iter()
        .find(|model| model.id == LM_STUDIO_CAPABILITY)
        .expect("the capability-marked id is offered");
    assert!(
        capability.vision,
        "a vision/image capability marks the offer vision-capable"
    );
    assert_eq!(
        capability.context_window,
        Some(1024),
        "the train length is the third rung of the recorded precedence"
    );
    let max_len = models
        .iter()
        .find(|model| model.id == LM_STUDIO_MAX_LEN)
        .expect("the max-len id is offered");
    assert_eq!(
        max_len.context_window,
        Some(512),
        "the model-len length is the last rung of the recorded precedence"
    );
    let requests = server.received_requests().await.expect("recorded");
    let paths = request_paths(&requests);
    assert!(
        paths.contains(&"/v1/models") && paths.contains(&LM_STUDIO_NATIVE_PATH),
        "the listing and its native probe both ran: {paths:?}"
    );
    assert!(
        !paths.contains(&"/v1/api/v0/models"),
        "the probe base drops the configured /v1 segment: {paths:?}"
    );
}

/// The recorded native probe is advisory: a refused, malformed, absent
/// or timed-out answer leaves the listing's offers exactly as served —
/// the catalogue neither denies nor widens, and the class's seedless
/// floor stays empty.
#[tokio::test]
async fn lm_studio_native_metadata_failures_are_non_fatal() {
    let expected = [CatalogModel {
        id: LM_STUDIO_LISTED.to_string(),
        ..CatalogModel::default()
    }];

    let refused = MockServer::start().await;
    mount_models(&refused, vec![json!({"id": LM_STUDIO_LISTED})]).await;
    mount_native_models(&refused, ResponseTemplate::new(500)).await;
    assert_eq!(
        keyless_lm_studio_catalogue(&refused),
        expected,
        "a refused probe leaves the listing unchanged"
    );
    assert_native_probe_attempted(&refused).await;

    let malformed = MockServer::start().await;
    mount_models(&malformed, vec![json!({"id": LM_STUDIO_LISTED})]).await;
    mount_native_models(
        &malformed,
        ResponseTemplate::new(200).set_body_string("not json"),
    )
    .await;
    assert_eq!(
        keyless_lm_studio_catalogue(&malformed),
        expected,
        "an unreadable probe payload leaves the listing unchanged"
    );

    let absent = MockServer::start().await;
    mount_models(&absent, vec![json!({"id": LM_STUDIO_LISTED})]).await;
    assert_eq!(
        keyless_lm_studio_catalogue(&absent),
        expected,
        "an absent native endpoint leaves the listing unchanged"
    );
    assert_native_probe_attempted(&absent).await;

    let slow = MockServer::start().await;
    mount_models(&slow, vec![json!({"id": LM_STUDIO_LISTED})]).await;
    mount_native_models(
        &slow,
        ResponseTemplate::new(200)
            .set_delay(Duration::from_millis(400))
            .set_body_json(json!({
                "data": [{
                    "id": LM_STUDIO_LISTED,
                    "type": "vlm",
                    "state": "loaded",
                    "loaded_context_length": 4096,
                }],
            })),
    )
    .await;
    let started = Instant::now();
    assert_eq!(
        keyless_lm_studio_catalogue(&slow),
        expected,
        "a timed-out probe leaves the listing unchanged"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the 250 ms probe bound keeps the catalogue from parking on it"
    );
    assert_native_probe_attempted(&slow).await;
}

/// The fixture peer recorded the class's native probe on its path.
async fn assert_native_probe_attempted(server: &MockServer) {
    let requests = server.received_requests().await.expect("recorded");
    let paths = request_paths(&requests);
    assert!(
        paths.contains(&LM_STUDIO_NATIVE_PATH),
        "the probe was attempted and its answer discarded: {paths:?}"
    );
}

// ----- TP-PROVIDER-AUTH::lm-studio ----------------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `lm-studio`, through the same shared construction its siblings use: a
/// configured `region` — the recorded local contract names none —
/// denies `RegionMismatch` with the connection context, and a
/// profile-bound ref whose scope disagrees with the binding denies
/// `CredentialProfileMismatch`; both deny before the store is read, so
/// neither arm renders material at all. A refused server key then lands
/// the typed transport denial carrying the peer's status alone, and on
/// that arm — the one that resolves and sends the material — neither
/// the offered credential nor the peer's body reaches Display or Debug.
#[tokio::test]
async fn lm_studio_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    let regioned = Config::parse_validated(
        &lm_studio_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "lm-studio".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "lm-studio");
    assert_eq!(region, "eu");

    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.lm-studio]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"lm-studio\", model_id = \"{LM_STUDIO_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "lm-studio".to_string(),
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
    let config =
        Config::parse_validated(&lm_studio_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_lm_studio_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused server key is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused key is transport: {err}")
    };
    assert_eq!(connection, "lm-studio");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, LM_STUDIO_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {LM_STUDIO_KEY}"),
        "the admitted server key reached the wire — the denial is the peer's status"
    );
}

// ----- TP-PROVIDER-RECOVERY::lm-studio ------------------------------------------

/// A typed denial is recoverable through the same seam: material the
/// store resolves but the class cannot use — non-UTF-8 bytes can never
/// be a bearer token — denies `CredentialMalformed` on the first send,
/// and enrolling the recorded server key at the same scope admits the
/// retry with that bearer. No state is wedged and no plaintext path is
/// taken.
#[tokio::test]
async fn lm_studio_typed_denial_recovers_through_the_same_credential_seam() {
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
        Config::parse_validated(&lm_studio_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    store.enroll(LM_STUDIO_REF, &[0xff, 0xfe]);
    let provider =
        provider_result(config.clone(), "lm-studio".to_string(), store.clone()).expect("binding");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialMalformed { .. })
    ));

    store.enroll(LM_STUDIO_REF, LM_STUDIO_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the enrolled server key admits the retry");
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
        format!("Bearer {LM_STUDIO_KEY}"),
        "the recovered material bears the wire"
    );
}

/// The legs matrix enforces the recorded expected set for `lm-studio`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside this
/// run, and INSTALLED reports NOT_RUN — an omitted leg fails the suite
/// rather than silently absenting.
#[tokio::test]
async fn lm_studio_provider_legs_matrix_executes_all_expected_legs() {
    emit_provider_rows("lm-studio");
    use std::collections::BTreeMap;
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": LM_STUDIO_LISTED})]).await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&lm_studio_config(&server_uri_v1(&server))).expect("valid");
    let keyless = Config::parse_validated(&lm_studio_keyless_config(&server_uri_v1(&server)))
        .expect("the keyless row is valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the configured base's listing is the whole offer surface —
    // no seed floor — and no offer carries a price or capability mark the
    // class does not record.
    let (provider, catalogue) = catalog_on_thread(keyless_lm_studio_provider(&keyless));
    let listed = catalogue.expect("catalog answers");
    reported.insert(
        "CATALOG",
        if model_ids(&listed) == [LM_STUDIO_LISTED]
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

    // AUTH: the one class carries both recorded forms — the server key
    // bears the chat request, the keyless declaration sends headerless.
    let (provider, _store) = enrolled_lm_studio_provider(&config);
    let (provider, keyed_outcome) = send_on_thread(provider, prepared_manifest(&config));
    let keyed_ok = keyed_outcome.is_ok();
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    let keyed_bearer = requests.last().is_some_and(|request| {
        request.headers.get("authorization").is_some_and(|value| {
            value
                .to_str()
                .is_ok_and(|header| header == format!("Bearer {LM_STUDIO_KEY}"))
        })
    });
    let (provider, headerless_outcome) = send_on_thread(
        keyless_lm_studio_provider(&keyless),
        prepared_manifest(&keyless),
    );
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

    // WIRE: the full broker dispatch over the recorded keyless local mode
    // returns the verified outcome.
    let (broker, manifest) = {
        let mut broker = Broker::new(Box::new(keyless_lm_studio_provider(&keyless)));
        let manifest = broker
            .prepare("main", &keyless, "/world/studio", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
    let (broker, outcome) = dispatch(broker, "/world/studio", manifest);
    reported.insert(
        "WIRE",
        if matches!(&outcome, Ok(reply) if reply.text == "matrix") {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(broker);

    // RECOVERY: unusable material denies typed, and the recorded server
    // key at the same scope admits the retry.
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    store.enroll(LM_STUDIO_REF, &[0xff, 0xfe]);
    let provider =
        provider_result(config.clone(), "lm-studio".to_string(), store.clone()).expect("binding");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialMalformed { .. }));
    store.enroll(LM_STUDIO_REF, LM_STUDIO_KEY.as_bytes());
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

// ----- TP-PROVIDER-INSTALLED::lm-studio -----------------------------------------

/// TP-PROVIDER-INSTALLED::lm-studio = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::lm-studio = NOT_RUN"]
fn provider_installed_lm_studio() {}

// ----- minimax-code ---------------------------------------------------------------

// The `minimax-code` connection's proof legs (HZN-008 class P — the
// plan-key cell): the shared Chat Completions adapter serves the literal
// id — no copied codec — under its own recorded predicates (DEC-025 row:
// `ключ подписки → api.minimax.io/v1` CC). The configured `endpoint`
// carries the API base verbatim — an empty one resolves the recorded
// `api.minimax.io/v1` international default under the same
// absent-override rule the plan classes bind, never the CN plan's
// `api.minimaxi.com` host (EDGE-007) — and a configured `region` is
// denied: the contract names none. The recorded contract names no
// discovery leg — no `/models` call and no vendored roster — so the
// catalogue opens no wire leg, a listing answer never adds an offer,
// and the manual model path is the only served route. The recorded
// subscription key is a plan-scoped `api_key` riding as the plain bearer
// (DEC-010) — never `ConnKind::Subscription` — and the international
// plan vs PAYG split stays a billing fact of the enrolled key: the
// recovery ladder's PAYG mention is never implemented as a substitute
// (DEC-007).

/// The scoped credential ref the `minimax-code` connection binds.
const MINIMAX_CODE_REF: &str = "keyring:rivect-test/minimax-code";

/// Fixture `minimax-code` key material — never a real credential, only
/// ever sent to localhost.
const MINIMAX_CODE_KEY: &str = "fixture-minimax-code-key";

/// The pinned model id the fixed-pin legs carry — the recorded manual
/// model path, so the pin is whatever the config declares.
const MINIMAX_CODE_MODEL: &str = "fixture-minimax-model";

/// One configured `minimax-code` connection pointing at the fixture
/// peer: the api_key auth class resolves a scoped `SecretRef` (DEC-011),
/// the dialect comes from the literal connection id (DEC-007), and the
/// endpoint carries the API base verbatim.
fn minimax_code_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.minimax-code]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{MINIMAX_CODE_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"minimax-code\", model_id = \"{MINIMAX_CODE_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn minimax_code_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(MINIMAX_CODE_REF, material)],
    ));
    let provider = provider_result(config.clone(), "minimax-code".to_string(), store.clone())
        .expect("the shared adapter builds for the minimax-code id");
    (provider, store)
}

/// The `minimax-code` provider over the recorded enrolled plan key.
fn enrolled_minimax_code_provider(
    config: &Config,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    minimax_code_provider(config, MINIMAX_CODE_KEY)
}

// ----- TP-PROVIDER-WIRE::minimax-code ---------------------------------------------

/// A configured `minimax-code` connection returns a verified model
/// outcome through the standard Broker: prepare admits the api_key pin
/// under DEC-011, the plan key rides the `Authorization` header — never
/// the body — and the shared adapter posts exactly the frozen manifest
/// as a `chat/completions` request — the pinned manual model id
/// verbatim, system+user messages, `stream` with
/// `stream_options.include_usage` and the pinned effort as
/// `reasoning_effort` verbatim — the SSE stream validates its
/// finish_reason/`[DONE]` terminal, the one physical send is charged
/// once with the provider's reported usage, and the spent attempt never
/// re-sends.
#[tokio::test]
async fn minimax_code_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified minimax-code outcome",
            Some(json!({"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&minimax_code_config(&base)).expect("valid");
    let (provider, _store) = enrolled_minimax_code_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/minimax", "goal: prove the wire")
        .expect("the minimax-code pin passes DEC-011 eligibility");

    let (broker, outcome) = dispatch(broker, "/world/minimax", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified minimax-code outcome");
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
        format!("Bearer {MINIMAX_CODE_KEY}"),
        "the plan key bears the wire verbatim"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(MINIMAX_CODE_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"], MINIMAX_CODE_MODEL,
        "the manual pin rides the wire verbatim"
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
    assert_eq!(record.connection, "minimax-code");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 7,
            completion_tokens: 5,
            total_tokens: 12,
        }
    );
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay = broker.dispatch(&mut rivect::model::NullLedger, "/world/minimax", &manifest);
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

/// Hostile stream input is never a false success for `minimax-code`: a
/// stream ended mid `tool_calls` fragment — a partial call that never
/// executes — and a finish_reason the dialect cannot classify are both
/// the unknown terminal, and a rejected send charges nothing.
#[tokio::test]
async fn minimax_code_adverse_wire_input_never_reports_success() {
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
        Config::parse_validated(&minimax_code_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_minimax_code_provider(&config),
        &config,
        "/world/minimax",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/minimax", manifest);
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
        Config::parse_validated(&minimax_code_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_minimax_code_provider(&config),
        &config,
        "/world/minimax",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/minimax", manifest);
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

// ----- TP-PROVIDER-CATALOG::minimax-code ------------------------------------------

/// The configured-or-recorded base resolves under the plan classes'
/// absent-override rule: the required `endpoint` field's empty string
/// resolves the recorded `https://api.minimax.io/v1` international
/// default — never the CN plan's `api.minimaxi.com` host and never the
/// `minimax.cn` divergence (EDGE-007/DEC-007) — and a configured base
/// wins verbatim, trailing slashes trimmed. Offline pin: the adapter's
/// `Debug` surface reports the resolved endpoint, so both arms are
/// proved without one byte toward any host.
#[test]
fn minimax_code_discriminates_the_recorded_default_base() {
    for endpoint in ["", "   "] {
        let config = Config::parse_validated(&minimax_code_config(endpoint))
            .expect("an empty endpoint is valid");
        let provider = provider_result(
            config,
            "minimax-code".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the adapter builds");
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"https://api.minimax.io/v1\""),
            "endpoint {endpoint:?} resolved the recorded international default: {debug}"
        );
        assert!(
            !debug.contains("minimaxi") && !debug.contains("minimax.cn"),
            "no CN host or divergence is substituted: {debug}"
        );
        drop_blocking(provider);
    }

    // a configured base wins verbatim — trailing slashes are the only
    // normalization, never a default substitution
    let config = Config::parse_validated(&minimax_code_config("http://127.0.0.1:9931/plan/v1//"))
        .expect("a configured base is valid");
    let provider = provider_result(
        config,
        "minimax-code".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("the adapter builds");
    let debug = format!("{provider:?}");
    assert!(
        debug.contains("endpoint: \"http://127.0.0.1:9931/plan/v1\""),
        "the configured base rides verbatim: {debug}"
    );
    assert!(
        !debug.contains("api.minimax.io"),
        "the recorded default never overrides a configured base: {debug}"
    );
    drop_blocking(provider);
}

/// The recorded contract names no discovery leg for `minimax-code`:
/// the catalogue answers its recorded fixed list — unrecorded, so
/// empty — with no wire leg and no credential read, a mounted
/// `/models` listing never adds an offer, a fixed pin sends exactly
/// the one chat request, and an auto pick denies `UnpinnedModel`
/// rather than opening discovery — the manual model path is the only
/// served route (DEC-007, PROH-009 shape).
#[tokio::test]
async fn minimax_code_names_no_discovery_leg() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "listed-entitlement-claim"})]).await;
    mount_chat(
        &server,
        completed_stream(
            "manual path outcome",
            Some(json!({"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&minimax_code_config(&server_uri_v1(&server))).expect("valid");

    // the catalogue is the recorded fixed list alone — no `/models`
    // request exists on this connection, so no listed id can join it
    let (provider, catalogue) = catalog_on_thread(
        provider_result(
            config.clone(),
            "minimax-code".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the adapter builds"),
    );
    let models = catalogue.expect("the recorded catalogue answers");
    drop_blocking(provider);
    assert!(
        models.is_empty(),
        "the record names no roster — an offer would be invented input"
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "no discovery leg exists: the listing was never consulted"
    );

    // a fixed pin sends exactly the one chat request — no `/models`
    // leg ever opens on the send path either
    let (broker, manifest) = prepared_with(
        enrolled_minimax_code_provider(&config),
        &config,
        "/world/minimax",
        "goal: manual model path",
    );
    let (broker, outcome) = dispatch(broker, "/world/minimax", manifest);
    let reply = outcome.expect("the manual pin dispatches");
    assert_eq!(reply.text, "manual path outcome");
    drop_blocking(broker);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        request_paths(&requests),
        ["/v1/chat/completions"],
        "exactly the one chat request — no discovery leg is attempted"
    );

    // an auto pick has no catalogue to name a model from: the typed
    // denial lands without a request, never a discovery attempt
    let (provider, _store) = enrolled_minimax_code_provider(&config);
    let mut auto = prepared_manifest(&config);
    auto.model = rivect::config::ModelAssign::Auto {
        pool: Some(vec!["minimax-code".to_string()]),
    };
    let (provider, denied) = send_on_thread(provider, auto);
    assert!(
        matches!(denied, Err(ProviderError::UnpinnedModel { .. })),
        "an auto pick denies typed — no discovery leg can name a model: {denied:?}"
    );
    drop_blocking(provider);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        1,
        "the auto pick's denial opened no leg"
    );
}

// ----- TP-PROVIDER-AUTH::minimax-code ---------------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `minimax-code`, through the same shared construction its siblings
/// use: a configured `region` — the recorded contract names none —
/// denies `RegionMismatch` with the connection context, a profile-bound
/// ref whose scope disagrees with the binding denies
/// `CredentialProfileMismatch`, and a refused plan key lands the typed
/// transport denial carrying the peer's status alone — no error, nor
/// the offered credential material or the peer's body, reaches Display
/// or Debug.
#[tokio::test]
async fn minimax_code_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets()
{
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &minimax_code_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "minimax-code".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, MINIMAX_CODE_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "minimax-code");
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, MINIMAX_CODE_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.minimax-code]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"minimax-code\", model_id = \"{MINIMAX_CODE_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "minimax-code".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, MINIMAX_CODE_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, MINIMAX_CODE_KEY.as_bytes());

    // a refused plan key is a typed transport denial — the wire never
    // coerces a wrong credential into success, the peer's body never
    // enters the error, and the request carried the plan key
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&minimax_code_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_minimax_code_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused plan key is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused plan key is transport: {err}")
    };
    assert_eq!(connection, "minimax-code");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, MINIMAX_CODE_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {MINIMAX_CODE_KEY}"),
        "the admitted grammar reached the wire — the denial is the peer's status"
    );
}

// ----- TP-PROVIDER-RECOVERY::minimax-code -----------------------------------------

/// A typed denial is recoverable through the same seam: material the
/// store resolves but the class cannot use — non-UTF-8 bytes can never
/// be a bearer token — denies `CredentialMalformed` on the first send,
/// and enrolling the recorded plan key at the same scope admits the
/// retry with that bearer. The retry is the same credential at the same
/// scope — the recovery ladder's PAYG mention is never implemented as a
/// substitute key class (DEC-007) — no state is wedged and no plaintext
/// path is taken.
#[tokio::test]
async fn minimax_code_typed_denial_recovers_through_the_same_credential_seam() {
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
        Config::parse_validated(&minimax_code_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    store.enroll(MINIMAX_CODE_REF, &[0xff, 0xfe]);
    let provider = provider_result(config.clone(), "minimax-code".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialMalformed { .. })
    ));

    store.enroll(MINIMAX_CODE_REF, MINIMAX_CODE_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the recorded plan key admits the retry");
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
        format!("Bearer {MINIMAX_CODE_KEY}"),
        "the recovered material bears the wire"
    );
}

/// The legs matrix enforces the recorded expected set for
/// `minimax-code`: CATALOG, AUTH, WIRE and RECOVERY each execute and
/// report inside this run, and INSTALLED reports NOT_RUN — an omitted
/// leg fails the suite rather than silently absenting.
#[tokio::test]
async fn minimax_code_provider_legs_matrix_executes_all_expected_legs() {
    emit_provider_rows("minimax-code");
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
    let config =
        Config::parse_validated(&minimax_code_config(&server_uri_v1(&server))).expect("valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the record names no discovery leg and no roster, so the
    // catalogue answers empty with no wire leg — a mounted answer could
    // never join it anyway.
    let (provider, catalogue) = catalog_on_thread(
        provider_result(
            config.clone(),
            "minimax-code".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the adapter builds"),
    );
    let listed = catalogue.expect("catalog answers");
    let no_wire = server
        .received_requests()
        .await
        .expect("recorded")
        .is_empty();
    reported.insert(
        "CATALOG",
        if listed.is_empty() && no_wire {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: an absent credential denies typed before any leg.
    let absent = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "minimax-code".to_string(), absent)
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
        let (provider, _store) = enrolled_minimax_code_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/minimax", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
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

    // RECOVERY: a typed denial is followed by a successful retry
    // through the same credential seam.
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "minimax-code".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    store.enroll(MINIMAX_CODE_REF, MINIMAX_CODE_KEY.as_bytes());
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

    // The row restates the `#[ignore]`d `provider_installed_minimax_code`
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

// ----- TP-PROVIDER-INSTALLED::minimax-code ----------------------------------------

/// TP-PROVIDER-INSTALLED::minimax-code = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::minimax-code = NOT_RUN"]
fn provider_installed_minimax_code() {}

// ----- minimax-code-cn ------------------------------------------------------------

// The `minimax-code-cn` connection's proof legs (HZN-008 class P — the
// CN plan-key cell): the shared Chat Completions adapter serves the
// literal id — no copied codec — under its own recorded predicates
// (DEC-025 row: `ключ подписки → api.minimaxi.com/v1` CC). The
// configured `endpoint` carries the API base verbatim — an empty one
// resolves the recorded `api.minimaxi.com/v1` CN default under the
// same absent-override rule the plan classes bind, never the
// international sibling's `api.minimax.io` host and never the
// `minimax.cn` Anthropic divergence (EDGE-007/DEC-007) — and a
// configured `region` is denied: the contract names none. The
// recorded contract names no discovery leg — no `/models` call and no
// vendored roster — so the catalogue opens no wire leg, a listing
// answer never adds an offer, and the manual model path is the only
// served route. The recorded subscription key is a plan-scoped
// `api_key` riding as the plain bearer (DEC-010) — never
// `ConnKind::Subscription` — and the CN plan's fixed window vs the
// international plan's rolling window stays a billing fact of the
// enrolled key, never a substituted host or window.

/// The scoped credential ref the `minimax-code-cn` connection binds.
const MINIMAX_CODE_CN_REF: &str = "keyring:rivect-test/minimax-code-cn";

/// Fixture `minimax-code-cn` key material — never a real credential,
/// only ever sent to localhost.
const MINIMAX_CODE_CN_KEY: &str = "fixture-minimax-code-cn-key";

/// The pinned model id the fixed-pin legs carry — the recorded manual
/// model path, so the pin is whatever the config declares.
const MINIMAX_CODE_CN_MODEL: &str = "fixture-minimax-cn-model";

/// One configured `minimax-code-cn` connection pointing at the fixture
/// peer: the api_key auth class resolves a scoped `SecretRef`
/// (DEC-011), the dialect comes from the literal connection id
/// (DEC-007), and the endpoint carries the API base verbatim.
fn minimax_code_cn_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.minimax-code-cn]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{MINIMAX_CODE_CN_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"minimax-code-cn\", model_id = \"{MINIMAX_CODE_CN_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn minimax_code_cn_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(MINIMAX_CODE_CN_REF, material)],
    ));
    let provider = provider_result(config.clone(), "minimax-code-cn".to_string(), store.clone())
        .expect("the shared adapter builds for the minimax-code-cn id");
    (provider, store)
}

/// The `minimax-code-cn` provider over the recorded enrolled plan key.
fn enrolled_minimax_code_cn_provider(
    config: &Config,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    minimax_code_cn_provider(config, MINIMAX_CODE_CN_KEY)
}

// ----- TP-PROVIDER-WIRE::minimax-code-cn ------------------------------------------

/// A configured `minimax-code-cn` connection returns a verified model
/// outcome through the standard Broker: prepare admits the api_key pin
/// under DEC-011, the plan key rides the `Authorization` header —
/// never the body — and the shared adapter posts exactly the frozen
/// manifest as a `chat/completions` request — the pinned manual model
/// id verbatim, system+user messages, `stream` with
/// `stream_options.include_usage` and the pinned effort as
/// `reasoning_effort` verbatim — the SSE stream validates its
/// finish_reason/`[DONE]` terminal, the one physical send is charged
/// once with the provider's reported usage, and the spent attempt
/// never re-sends.
#[tokio::test]
async fn minimax_code_cn_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified minimax-code-cn outcome",
            Some(json!({"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&minimax_code_cn_config(&base)).expect("valid");
    let (provider, _store) = enrolled_minimax_code_cn_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/minimax-cn", "goal: prove the wire")
        .expect("the minimax-code-cn pin passes DEC-011 eligibility");

    let (broker, outcome) = dispatch(broker, "/world/minimax-cn", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified minimax-code-cn outcome");
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
        format!("Bearer {MINIMAX_CODE_CN_KEY}"),
        "the plan key bears the wire verbatim"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(MINIMAX_CODE_CN_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"], MINIMAX_CODE_CN_MODEL,
        "the manual pin rides the wire verbatim"
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
    assert_eq!(record.connection, "minimax-code-cn");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 7,
            completion_tokens: 5,
            total_tokens: 12,
        }
    );
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay = broker.dispatch(&mut rivect::model::NullLedger, "/world/minimax-cn", &manifest);
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

/// Hostile stream input is never a false success for
/// `minimax-code-cn`: a stream ended mid `tool_calls` fragment — a
/// partial call that never executes — and a finish_reason the dialect
/// cannot classify are both the unknown terminal, and a rejected send
/// charges nothing.
#[tokio::test]
async fn minimax_code_cn_adverse_wire_input_never_reports_success() {
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
        Config::parse_validated(&minimax_code_cn_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_minimax_code_cn_provider(&config),
        &config,
        "/world/minimax-cn",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/minimax-cn", manifest);
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
        Config::parse_validated(&minimax_code_cn_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_minimax_code_cn_provider(&config),
        &config,
        "/world/minimax-cn",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/minimax-cn", manifest);
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

// ----- TP-PROVIDER-CATALOG::minimax-code-cn ---------------------------------------

/// The configured-or-recorded base resolves under the plan classes'
/// absent-override rule: the required `endpoint` field's empty string
/// resolves the recorded `https://api.minimaxi.com/v1` CN default —
/// never the international sibling's `api.minimax.io` host and never
/// the `minimax.cn` divergence (EDGE-007/DEC-007) — and a configured
/// base wins verbatim, trailing slashes trimmed. Offline pin: the
/// adapter's `Debug` surface reports the resolved endpoint, so both
/// arms are proved without one byte toward any host.
#[test]
fn minimax_code_cn_discriminates_the_recorded_default_base() {
    for endpoint in ["", "   "] {
        let config = Config::parse_validated(&minimax_code_cn_config(endpoint))
            .expect("an empty endpoint is valid");
        let provider = provider_result(
            config,
            "minimax-code-cn".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the adapter builds");
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"https://api.minimaxi.com/v1\""),
            "endpoint {endpoint:?} resolved the recorded CN default: {debug}"
        );
        assert!(
            !debug.contains("api.minimax.io") && !debug.contains("minimax.cn"),
            "no international host or divergence is substituted: {debug}"
        );
        drop_blocking(provider);
    }

    // a configured base wins verbatim — trailing slashes are the only
    // normalization, never a default substitution
    let config =
        Config::parse_validated(&minimax_code_cn_config("http://127.0.0.1:9931/plan/v1//"))
            .expect("a configured base is valid");
    let provider = provider_result(
        config,
        "minimax-code-cn".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("the adapter builds");
    let debug = format!("{provider:?}");
    assert!(
        debug.contains("endpoint: \"http://127.0.0.1:9931/plan/v1\""),
        "the configured base rides verbatim: {debug}"
    );
    assert!(
        !debug.contains("api.minimaxi.com"),
        "the recorded default never overrides a configured base: {debug}"
    );
    drop_blocking(provider);
}

/// EDGE-007's boundary leg: the configured base decides the host —
/// never the connection id. A `minimax-code-cn` row whose `endpoint`
/// names the international sibling's `api.minimax.io` host keeps it
/// verbatim rather than being silently rewritten to the recorded CN
/// host, and the recorded `minimax.cn` Anthropic divergence rides
/// verbatim the same way: a divergence is a record, never a
/// substitution (DEC-007).
#[test]
fn minimax_code_cn_host_is_never_substituted() {
    for base in [
        "https://api.minimax.io/v1",
        "https://api.minimax.io/v1/",
        "https://minimax.cn/anthropic/v1",
    ] {
        let config =
            Config::parse_validated(&minimax_code_cn_config(base)).expect("a configured base");
        let provider = provider_result(
            config,
            "minimax-code-cn".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the adapter builds");
        let debug = format!("{provider:?}");
        let trimmed = base.trim_end_matches('/');
        assert!(
            debug.contains(&format!("endpoint: \"{trimmed}\"")),
            "the configured base decides verbatim — never the CN host: {debug}"
        );
        assert!(
            !debug.contains("api.minimaxi.com"),
            "the recorded CN host is never substituted for a configured base: {debug}"
        );
        drop_blocking(provider);
    }
}

/// The recorded contract names no discovery leg for `minimax-code-cn`:
/// the catalogue answers its recorded fixed list — unrecorded, so
/// empty — with no wire leg and no credential read, a mounted
/// `/models` listing never adds an offer, a fixed pin sends exactly
/// the one chat request, and an auto pick denies `UnpinnedModel`
/// rather than opening discovery — the manual model path is the only
/// served route (DEC-007, PROH-009 shape).
#[tokio::test]
async fn minimax_code_cn_names_no_discovery_leg() {
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "listed-entitlement-claim"})]).await;
    mount_chat(
        &server,
        completed_stream(
            "manual path outcome",
            Some(json!({"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4})),
        ),
    )
    .await;
    let config =
        Config::parse_validated(&minimax_code_cn_config(&server_uri_v1(&server))).expect("valid");

    // the catalogue is the recorded fixed list alone — no `/models`
    // request exists on this connection, so no listed id can join it
    let (provider, catalogue) = catalog_on_thread(
        provider_result(
            config.clone(),
            "minimax-code-cn".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the adapter builds"),
    );
    let models = catalogue.expect("the recorded catalogue answers");
    drop_blocking(provider);
    assert!(
        models.is_empty(),
        "the record names no roster — an offer would be invented input"
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "no discovery leg exists: the listing was never consulted"
    );

    // a fixed pin sends exactly the one chat request — no `/models`
    // leg ever opens on the send path either
    let (broker, manifest) = prepared_with(
        enrolled_minimax_code_cn_provider(&config),
        &config,
        "/world/minimax-cn",
        "goal: manual model path",
    );
    let (broker, outcome) = dispatch(broker, "/world/minimax-cn", manifest);
    let reply = outcome.expect("the manual pin dispatches");
    assert_eq!(reply.text, "manual path outcome");
    drop_blocking(broker);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        request_paths(&requests),
        ["/v1/chat/completions"],
        "exactly the one chat request — no discovery leg is attempted"
    );

    // an auto pick has no catalogue to name a model from: the typed
    // denial lands without a request, never a discovery attempt
    let (provider, _store) = enrolled_minimax_code_cn_provider(&config);
    let mut auto = prepared_manifest(&config);
    auto.model = rivect::config::ModelAssign::Auto {
        pool: Some(vec!["minimax-code-cn".to_string()]),
    };
    let (provider, denied) = send_on_thread(provider, auto);
    assert!(
        matches!(denied, Err(ProviderError::UnpinnedModel { .. })),
        "an auto pick denies typed — no discovery leg can name a model: {denied:?}"
    );
    drop_blocking(provider);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        1,
        "the auto pick's denial opened no leg"
    );
}

// ----- TP-PROVIDER-AUTH::minimax-code-cn ------------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `minimax-code-cn`, through the same shared construction its
/// siblings use: a configured `region` — the recorded contract names
/// none — denies `RegionMismatch` with the connection context, a
/// profile-bound ref whose scope disagrees with the binding denies
/// `CredentialProfileMismatch`, and a refused plan key lands the typed
/// transport denial carrying the peer's status alone — no error, nor
/// the offered credential material or the peer's body, reaches Display
/// or Debug.
#[tokio::test]
async fn minimax_code_cn_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets()
 {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &minimax_code_cn_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "minimax-code-cn".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, MINIMAX_CODE_CN_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "minimax-code-cn");
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, MINIMAX_CODE_CN_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.minimax-code-cn]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"minimax-code-cn\", model_id = \"{MINIMAX_CODE_CN_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "minimax-code-cn".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, MINIMAX_CODE_CN_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, MINIMAX_CODE_CN_KEY.as_bytes());

    // a refused plan key is a typed transport denial — the wire never
    // coerces a wrong credential into success, the peer's body never
    // enters the error, and the request carried the plan key
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config =
        Config::parse_validated(&minimax_code_cn_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_minimax_code_cn_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused plan key is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused plan key is transport: {err}")
    };
    assert_eq!(connection, "minimax-code-cn");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, MINIMAX_CODE_CN_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {MINIMAX_CODE_CN_KEY}"),
        "the admitted grammar reached the wire — the denial is the peer's status"
    );
}

// ----- TP-PROVIDER-RECOVERY::minimax-code-cn --------------------------------------

/// A typed denial is recoverable through the same seam: material the
/// store resolves but the class cannot use — non-UTF-8 bytes can never
/// be a bearer token — denies `CredentialMalformed` on the first send,
/// and enrolling the recorded plan key at the same scope admits the
/// retry with that bearer. The retry is the same credential at the
/// same scope — a plan window, fixed or rolling, is a billing fact of
/// the enrolled key and never a substitute key class (DEC-007) — no
/// state is wedged and no plaintext path is taken.
#[tokio::test]
async fn minimax_code_cn_typed_denial_recovers_through_the_same_credential_seam() {
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
        Config::parse_validated(&minimax_code_cn_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    store.enroll(MINIMAX_CODE_CN_REF, &[0xff, 0xfe]);
    let provider = provider_result(config.clone(), "minimax-code-cn".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialMalformed { .. })
    ));

    store.enroll(MINIMAX_CODE_CN_REF, MINIMAX_CODE_CN_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the recorded plan key admits the retry");
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
        format!("Bearer {MINIMAX_CODE_CN_KEY}"),
        "the recovered material bears the wire"
    );
}

/// The legs matrix enforces the recorded expected set for
/// `minimax-code-cn`: CATALOG, AUTH, WIRE and RECOVERY each execute
/// and report inside this run, and INSTALLED reports NOT_RUN — an
/// omitted leg fails the suite rather than silently absenting.
#[tokio::test]
async fn minimax_code_cn_provider_legs_matrix_executes_all_expected_legs() {
    emit_provider_rows("minimax-code-cn");
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
    let config =
        Config::parse_validated(&minimax_code_cn_config(&server_uri_v1(&server))).expect("valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the record names no discovery leg and no roster, so the
    // catalogue answers empty with no wire leg — a mounted answer could
    // never join it anyway.
    let (provider, catalogue) = catalog_on_thread(
        provider_result(
            config.clone(),
            "minimax-code-cn".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the adapter builds"),
    );
    let listed = catalogue.expect("catalog answers");
    let no_wire = server
        .received_requests()
        .await
        .expect("recorded")
        .is_empty();
    reported.insert(
        "CATALOG",
        if listed.is_empty() && no_wire {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: an absent credential denies typed before any leg.
    let absent = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "minimax-code-cn".to_string(), absent)
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
        let (provider, _store) = enrolled_minimax_code_cn_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/minimax-cn", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
    let (broker, outcome) = dispatch(broker, "/world/minimax-cn", manifest);
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
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "minimax-code-cn".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    store.enroll(MINIMAX_CODE_CN_REF, MINIMAX_CODE_CN_KEY.as_bytes());
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

    // The row restates the `#[ignore]`d `provider_installed_minimax_code_cn`
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

// ----- TP-PROVIDER-INSTALLED::minimax-code-cn -------------------------------------

/// TP-PROVIDER-INSTALLED::minimax-code-cn = NOT_RUN: the
/// installed-provider proof is a live-environment leg this offline
/// slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::minimax-code-cn = NOT_RUN"]
fn provider_installed_minimax_code_cn() {}

// ----- mistral ---------------------------------------------------------------

// The `mistral` connection's proof legs (HZN-008 class B — the
// env/credential-chain cell): the shared Chat Completions adapter
// serves the literal id — no copied codec — under its own recorded
// predicates (DEC-025 row: `Rivect/key → api.mistral.ai/v1` CC). The
// configured `endpoint` carries the API base verbatim — an empty one
// resolves the recorded `api.mistral.ai/v1` default under the same
// absent-override rule the plan classes bind — and a configured
// `region` is denied: the contract names none. The recorded
// `requireApiKey` `/models` listing is the whole catalogue — built-in
// ids are discovered there, the class records no vendored roster (D4),
// so an empty or failed answer has no floor to fall back to — and the
// recorded env/credential-chain class resolves through the scoped
// `SecretRef` seam the same way `groq`'s does (DEC-006): an
// `env:`/`file:`/plaintext ref is refused at ingress and the traversal
// itself stays credential-substrate debt. The recorded parameter-naming
// notes (`random_seed`, `prediction`, `prompt_cache_key`, `safe_prompt`,
// `prompt_mode`) are contract notes, not adapter fields — no leg builds
// or asserts them — and an authorization or payment failure surfaces
// as the typed transport denial.

/// The scoped credential ref the `mistral` connection binds.
const MISTRAL_REF: &str = "keyring:rivect-test/mistral";

/// Fixture `mistral` key material — never a real credential, only
/// ever sent to localhost.
const MISTRAL_KEY: &str = "fixture-mistral-key";

/// The pinned model id the fixed-pin legs carry — a discovered id the
/// `requireApiKey` listing returns.
const MISTRAL_MODEL: &str = "mistral-small-latest";

/// One configured `mistral` connection pointing at the fixture peer:
/// the env/credential-chain class resolves a scoped `SecretRef`
/// (DEC-006/DEC-011), the dialect comes from the literal connection id
/// (DEC-007), and the endpoint carries the API base verbatim.
fn mistral_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.mistral]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{MISTRAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"mistral\", model_id = \"{MISTRAL_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn mistral_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(MISTRAL_REF, material)],
    ));
    let provider = provider_result(config.clone(), "mistral".to_string(), store.clone())
        .expect("the shared adapter builds for the mistral id");
    (provider, store)
}

/// The `mistral` provider over the recorded enrolled key.
fn enrolled_mistral_provider(config: &Config) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    mistral_provider(config, MISTRAL_KEY)
}

// ----- TP-PROVIDER-WIRE::mistral ---------------------------------------------

/// A configured `mistral` connection returns a verified model outcome
/// through the standard Broker: prepare admits the api_key pin under
/// DEC-011, the scoped chain's material rides the `Authorization`
/// header — never the body — and the shared adapter posts exactly the
/// frozen manifest as a `chat/completions` request — the pinned model
/// id verbatim, system+user messages, `stream` with
/// `stream_options.include_usage` and the pinned effort as
/// `reasoning_effort` verbatim — the SSE stream validates its
/// finish_reason/`[DONE]` terminal, the one physical send is charged
/// once with the provider's reported usage, and the spent attempt
/// never re-sends.
#[tokio::test]
async fn mistral_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified mistral outcome",
            Some(json!({"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&mistral_config(&base)).expect("valid");
    let (provider, _store) = enrolled_mistral_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/mistral", "goal: prove the wire")
        .expect("the mistral pin passes DEC-011 eligibility");

    let (broker, outcome) = dispatch(broker, "/world/mistral", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified mistral outcome");
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
        format!("Bearer {MISTRAL_KEY}"),
        "the scoped chain's material bears the wire verbatim"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(MISTRAL_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"], MISTRAL_MODEL,
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
        json!("medium"),
        "the pinned effort rides the recorded reasoning_effort surface"
    );

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "mistral");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 7,
            completion_tokens: 5,
            total_tokens: 12,
        }
    );
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay = broker.dispatch(&mut rivect::model::NullLedger, "/world/mistral", &manifest);
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

/// Hostile stream input is never a false success for `mistral`: a
/// stream ended mid `tool_calls` fragment — a partial call that never
/// executes — and a finish_reason the dialect cannot classify are both
/// the unknown terminal, and a rejected send charges nothing.
#[tokio::test]
async fn mistral_adverse_wire_input_never_reports_success() {
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
    let config = Config::parse_validated(&mistral_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_mistral_provider(&config),
        &config,
        "/world/mistral",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/mistral", manifest);
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
    let config = Config::parse_validated(&mistral_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_mistral_provider(&config),
        &config,
        "/world/mistral",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/mistral", manifest);
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

// ----- TP-PROVIDER-CATALOG::mistral ------------------------------------------

/// The configured-or-recorded base resolves under the plan classes'
/// absent-override rule: the required `endpoint` field's empty string
/// resolves the recorded `https://api.mistral.ai/v1` default, and a
/// configured base wins verbatim, trailing slashes trimmed. Offline
/// pin: the adapter's `Debug` surface reports the resolved endpoint,
/// so both arms are proved without one byte toward any host.
#[test]
fn mistral_discriminates_the_recorded_default_base() {
    for endpoint in ["", "   "] {
        let config =
            Config::parse_validated(&mistral_config(endpoint)).expect("an empty endpoint is valid");
        let provider = provider_result(
            config,
            "mistral".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the adapter builds");
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"https://api.mistral.ai/v1\""),
            "endpoint {endpoint:?} resolved the recorded default: {debug}"
        );
        drop_blocking(provider);
    }

    // a configured base wins verbatim — trailing slashes are the only
    // normalization, never a default substitution
    let config = Config::parse_validated(&mistral_config("http://127.0.0.1:9931/cloud/v1//"))
        .expect("a configured base is valid");
    let provider = provider_result(
        config,
        "mistral".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("the adapter builds");
    let debug = format!("{provider:?}");
    assert!(
        debug.contains("endpoint: \"http://127.0.0.1:9931/cloud/v1\""),
        "the configured base rides verbatim: {debug}"
    );
    assert!(
        !debug.contains("api.mistral.ai"),
        "the recorded default never overrides a configured base: {debug}"
    );
    drop_blocking(provider);
}

/// The recorded `requireApiKey` listing is the whole catalogue for
/// `mistral` (HZN-008 class B): the lookup resolves the scoped
/// material and sends one `GET {endpoint}/models` under the bearer —
/// an absent scope denies `CredentialAbsent` before any request — a
/// listed id is offered ids-only, an empty `data` answer offers
/// nothing (no built-in roster is vendored, D4, so no empty fallback
/// exists), a failed status keeps the typed denial rather than
/// inventing a floor, and a `/models` HTTP 200 confers no entitlement.
#[tokio::test]
async fn mistral_authoritative_listing_requires_material() {
    // the keyed listing answers under the resolved bearer — listed
    // ids are the offers, an empty id names nothing
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": MISTRAL_MODEL}),
            json!({"id": "codestral-latest"}),
            json!({"id": ""}),
        ],
    )
    .await;
    let config = Config::parse_validated(&mistral_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_mistral_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the keyed catalogue answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        ["codestral-latest", MISTRAL_MODEL],
        "the listing's ids alone are the offers — no vendored roster joins them"
    );
    for model in &models {
        assert_eq!(
            model,
            &CatalogModel {
                id: model.id.clone(),
                ..CatalogModel::default()
            },
            "a listed id carries no invented surface"
        );
    }
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the keyed listing is the one leg");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {MISTRAL_KEY}"),
        "the listing requires the resolved material"
    );

    // an empty `data` answer is a real answer with no offers — the
    // record names no vendored roster, so no fallback fills it
    let server = MockServer::start().await;
    mount_models(&server, vec![]).await;
    let config = Config::parse_validated(&mistral_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_mistral_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("an empty listing still answers");
    drop_blocking(provider);
    assert!(
        models.is_empty(),
        "an empty listing has no floor to fall back to: {:?}",
        model_ids(&models)
    );

    // an absent scope denies before any request — the listing
    // requires the material, never a keyless or empty-catalogue form
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "listed-entitlement-claim"})]).await;
    let config = Config::parse_validated(&mistral_config(&server_uri_v1(&server))).expect("valid");
    let (provider, denied) = catalog_on_thread(
        provider_result(
            config,
            "mistral".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the binding resolves"),
    );
    assert!(
        matches!(denied, Err(ProviderError::CredentialAbsent { .. })),
        "the requireApiKey listing denies keyless: {denied:?}"
    );
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the denial opened no wire leg"
    );

    // a `/models` HTTP 200 confers no entitlement (INV-010): the same
    // listing answer never releases a send — the keyless form denies
    // `CredentialAbsent` before the wire, and the keyed pin meets the
    // unmounted request leg's typed transport denial
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "listed-entitlement-claim"})]).await;
    let config = Config::parse_validated(&mistral_config(&server_uri_v1(&server))).expect("valid");

    let (provider, denied) = send_on_thread(
        provider_result(
            config.clone(),
            "mistral".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the binding resolves"),
        prepared_manifest(&config),
    );
    assert!(
        matches!(denied, Err(ProviderError::CredentialAbsent { .. })),
        "a 200 listing never stands in for the material: {denied:?}"
    );
    drop_blocking(provider);

    let (provider, _store) = enrolled_mistral_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a 200 catalogue never releases the pin");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the unmounted request leg is the typed transport denial: {err:?}");
    };
    assert_eq!(connection, "mistral");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 404 },
        "the request leg answers the peer's status, never a listing-granted success: {cause}"
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "the send's own request leg is the only egress — the 200 listing adds nothing"
    );
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");

    // a refused listing — the recorded authorization/payment failure —
    // keeps the typed denial; no floor substitutes an answer
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&mistral_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_mistral_provider(&config);
    let (provider, denied) = catalog_on_thread(provider);
    let err = denied.expect_err("a refused listing is the typed denial, never a floor");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the authorization denial is transport: {err}")
    };
    assert_eq!(connection, "mistral");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the peer's status is the context: {cause}"
    );
    assert_no_secret_or_body(&err, MISTRAL_KEY.as_bytes());
    drop_blocking(provider);
}

/// The auto pick rides the authoritative listing under the record's
/// auto semantic: the dispatch narrows the pool to the `mistral`
/// member, the listing is the whole catalogue — no vendored roster
/// merges (D4) — and the sorted-first listed id names the wire model
/// verbatim, in the inverted order the peer answered.
#[tokio::test]
async fn mistral_auto_pick_resolves_through_the_listing() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "zz-listed-late"}),
            json!({"id": "aa-listed-first"}),
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
         [connections.mistral]\nkind = \"api_key\"\nendpoint = \"{base}\"\ncredential_ref = \"{MISTRAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\", pool = [\"mistral\"] }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let (provider, _store) = enrolled_mistral_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/mistral", "goal: auto pick")
        .expect("the single-member pool pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/mistral", manifest);
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
        json!("aa-listed-first"),
        "the sorted-first listed id names the wire model verbatim"
    );
}

// ----- TP-PROVIDER-AUTH::mistral ----------------------------------------------

/// The recorded env/credential-chain class resolves through the
/// scoped `SecretRef` seam and never through an env, file or
/// plaintext spelling (DEC-006): an `env:`, `file:`-spelled or
/// bare-token `credential_ref` is refused at config ingress — the
/// typed store/refusal that never echoes the value — and on a
/// connection that binds both the connection ref and a profile,
/// DEC-013 precedence sends the profile's scoped material — the
/// connection-scope key never bears the wire.
#[tokio::test]
async fn mistral_env_chain_resolves_through_the_scoped_secret_ref_seam() {
    // the recorded env spelling names no admitted store class — nor
    // does a file indirection or a bare token
    for (spelling, store) in [
        ("env:MISTRAL_API_KEY", "env"),
        ("file:rivect/mistral-key", "file"),
    ] {
        let refused = mistral_config("http://127.0.0.1:1/v1").replace(
            &format!("credential_ref = \"{MISTRAL_REF}\""),
            &format!("credential_ref = \"{spelling}\""),
        );
        let Err(error) = Config::parse_validated(&refused) else {
            panic!("a {spelling} credential reference is refused at ingress")
        };
        assert!(
            matches!(
                &error.issue,
                ConfigIssue::UnsupportedCredentialStore { store: refused }
                    if refused.as_str() == store
            ),
            "the refusal names the refused store class: {error}"
        );
        assert!(
            !error.to_string().contains(spelling),
            "the refusal never echoes the credential value: {error}"
        );
    }
    let bare = mistral_config("http://127.0.0.1:1/v1").replace(
        &format!("credential_ref = \"{MISTRAL_REF}\""),
        "credential_ref = \"fixture-mistral-plaintext\"",
    );
    let Err(error) = Config::parse_validated(&bare) else {
        panic!("a bare credential token is refused at ingress")
    };
    assert!(
        matches!(&error.issue, ConfigIssue::SecretRefExpected { .. }),
        "the bare token is the scoped-ref refusal, not material: {error}"
    );

    // a profile-bound ref is the same ingress — an env or file
    // spelling under `profiles.<name>.credential_ref` is refused typed
    // identically, never resolved through the profile seam
    for (spelling, store) in [
        ("env:MISTRAL_API_KEY", "env"),
        ("file:rivect/mistral-key", "file"),
    ] {
        let refused = mistral_config("http://127.0.0.1:1/v1").replace(
            "[models.defaults]",
            &format!(
                "[profiles.mistral-chain]\ncredential_ref = \"{spelling}\"\n[models.defaults]"
            ),
        );
        let Err(error) = Config::parse_validated(&refused) else {
            panic!("a {spelling} profile credential reference is refused at ingress")
        };
        assert!(
            matches!(
                &error.issue,
                ConfigIssue::UnsupportedCredentialStore { store: refused }
                    if refused.as_str() == store
            ),
            "the profile refusal names the refused store class: {error}"
        );
        assert!(
            !error.to_string().contains(spelling),
            "the refusal never echoes the credential value: {error}"
        );
    }

    // a stored profile binding wins over the connection's own ref —
    // the chain resolves scoped store material, not an env lookup
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
         [connections.mistral]\nkind = \"api_key\"\nendpoint = \"{base}\"\ncredential_ref = \"keyring:rivect-test/mistral-connection\"\nprofile = \"mistral-chain\"\n\
         [profiles.mistral-chain]\ncredential_ref = \"keyring:rivect-test/mistral-chain\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"mistral\", model_id = \"{MISTRAL_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[
            (
                "keyring:rivect-test/mistral-connection",
                "fixture-connection-scope",
            ),
            ("keyring:rivect-test/mistral-chain", MISTRAL_KEY),
        ],
    ));
    let provider = provider_result(config.clone(), "mistral".to_string(), store.clone())
        .expect("the chained binding resolves");
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    outcome.expect("the profile-bound credential admits the send");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {MISTRAL_KEY}"),
        "the profile's scoped material bears the wire"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains("fixture-connection-scope"),
        "the connection-scope material never reaches the wire"
    );
}

/// Wrong credential/profile/region never produce a false success for
/// `mistral`, through the same shared construction its siblings use:
/// a configured `region` — the recorded contract names none — denies
/// `RegionMismatch` with the connection context, a profile-bound ref
/// whose scope disagrees with the binding denies
/// `CredentialProfileMismatch`, and a refused key — the recorded
/// authorization/payment failure — lands the typed transport denial
/// carrying the peer's status alone — no error, nor the offered
/// credential material or the peer's body, reaches Display or Debug.
#[tokio::test]
async fn mistral_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &mistral_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "mistral".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, MISTRAL_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "mistral");
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, MISTRAL_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.mistral]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"mistral\", model_id = \"{MISTRAL_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "mistral".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, MISTRAL_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, MISTRAL_KEY.as_bytes());

    // a refused key is a typed transport denial — the recorded
    // authorization/payment failure: the wire never coerces a wrong
    // credential into success, the peer's body never enters the
    // error, and the request carried the bearer
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&mistral_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_mistral_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused key is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused key is transport: {err}")
    };
    assert_eq!(connection, "mistral");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, MISTRAL_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {MISTRAL_KEY}"),
        "the admitted bearer reached the wire — the denial is the peer's status"
    );
}

// ----- TP-PROVIDER-RECOVERY::mistral -------------------------------------------

/// A typed denial is recoverable through the same seam: material the
/// store resolves but the class cannot use — non-UTF-8 bytes can never
/// be a bearer token — denies `CredentialMalformed` on the first send,
/// and enrolling the recorded key at the same scope admits the retry
/// with that bearer. The retry is the same credential at the same
/// scope — no key class is substituted — no state is wedged and no
/// plaintext path is taken.
#[tokio::test]
async fn mistral_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config = Config::parse_validated(&mistral_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    store.enroll(MISTRAL_REF, &[0xff, 0xfe]);
    let provider = provider_result(config.clone(), "mistral".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialMalformed { .. })
    ));

    store.enroll(MISTRAL_REF, MISTRAL_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the recorded key admits the retry");
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
        format!("Bearer {MISTRAL_KEY}"),
        "the recovered material bears the wire"
    );
}

/// The legs matrix enforces the recorded expected set for `mistral`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside
/// this run, and INSTALLED reports NOT_RUN — an omitted leg fails the
/// suite rather than silently absenting.
#[tokio::test]
async fn mistral_provider_legs_matrix_executes_all_expected_legs() {
    emit_provider_rows("mistral");
    use std::collections::BTreeMap;
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": MISTRAL_MODEL})]).await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&mistral_config(&server_uri_v1(&server))).expect("valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the keyed listing answers the discovered ids under one
    // `/models` leg bearing the scoped material.
    let (provider, _store) = enrolled_mistral_provider(&config);
    let (provider, listed) = catalog_on_thread(provider);
    let listed = listed.expect("catalog answers");
    let discovery = server.received_requests().await.expect("recorded");
    reported.insert(
        "CATALOG",
        if listed.iter().any(|model| model.id == MISTRAL_MODEL)
            && discovery.len() == 1
            && discovery[0].url.path() == "/v1/models"
            && received_auth(&discovery[0]) == format!("Bearer {MISTRAL_KEY}")
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
        provider_result(config.clone(), "mistral".to_string(), absent).expect("binding resolves");
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
        let (provider, _store) = enrolled_mistral_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/mistral", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
    let (broker, outcome) = dispatch(broker, "/world/mistral", manifest);
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
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "mistral".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    store.enroll(MISTRAL_REF, MISTRAL_KEY.as_bytes());
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

    // The row restates the `#[ignore]`d `provider_installed_mistral`
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

// ----- TP-PROVIDER-INSTALLED::mistral ------------------------------------------

/// TP-PROVIDER-INSTALLED::mistral = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::mistral = NOT_RUN"]
fn provider_installed_mistral() {}

// ----- moonshot ---------------------------------------------------------------

// The `moonshot` connection's proof legs (HZN-008 class B — the
// api-key cell): the shared Chat Completions adapter serves the
// literal id — no copied codec — under its own recorded predicates
// (DEC-025 row: `Rivect/key → configured MOONSHOT base, default
// api.moonshot.ai/v1` CC). The configured `endpoint` carries the API
// base verbatim — an empty one resolves the recorded
// `api.moonshot.ai/v1` default under the same absent-override rule
// the plan classes bind — and the configured base redirects
// discovery and streaming alike, while a configured `region` is
// denied: the contract names none. The recorded `requireApiKey`
// `/models` listing is the whole catalogue — listed ids are
// discovered there, no vendored roster or price surface is carried
// (D4/D6), so an empty or failed answer has no floor to fall back
// to — and the api-key class resolves the scoped `SecretRef` seam:
// the recorded `KIMI_API_KEY` fallback key name proves neither
// region nor payment. The recorded K3 top-level `reasoning_effort`
// ladder (`low`/`high`) is a distinct predicate from the K2.x
// `thinking` surface this adapter never constructs: `low`/`high`
// ride the body verbatim, an out-of-ladder pin denies typed, and
// the recorded `max` has no carrier in the shared effort
// vocabulary — no `max` request is ever constructed (DEC-014).

/// The scoped credential ref the `moonshot` connection binds.
const MOONSHOT_REF: &str = "keyring:rivect-test/moonshot";

/// Fixture `moonshot` key material — never a real credential, only
/// ever sent to localhost.
const MOONSHOT_KEY: &str = "fixture-moonshot-key";

/// The pinned model id the fixed-pin legs carry — the recorded K3
/// build whose `reasoning_effort` ladder carries `low`/`high`.
const MOONSHOT_MODEL: &str = "kimi-k3";

/// One configured `moonshot` connection pointing at the fixture
/// peer: the api_key auth class resolves a scoped `SecretRef`
/// (DEC-011), the dialect comes from the literal connection id
/// (DEC-007), and the endpoint carries the API base verbatim. The
/// pin carries `high`: the recorded `max` default has no carrier in
/// the shared vocabulary, so `high` is the in-ladder fixture.
fn moonshot_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.moonshot]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{MOONSHOT_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"moonshot\", model_id = \"{MOONSHOT_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"high\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// A `moonshot` config pinning a specific model and effort.
fn moonshot_pin_config(endpoint: &str, model: &str, effort: &str) -> String {
    moonshot_config(endpoint)
        .replace(MOONSHOT_MODEL, model)
        .replace("value = \"high\"", &format!("value = \"{effort}\""))
}

fn moonshot_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(MOONSHOT_REF, material)],
    ));
    let provider = provider_result(config.clone(), "moonshot".to_string(), store.clone())
        .expect("the shared adapter builds for the moonshot id");
    (provider, store)
}

/// The `moonshot` provider over the recorded enrolled key.
fn enrolled_moonshot_provider(
    config: &Config,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    moonshot_provider(config, MOONSHOT_KEY)
}

// ----- TP-PROVIDER-WIRE::moonshot ---------------------------------------------

/// A configured `moonshot` connection returns a verified model
/// outcome through the standard Broker: prepare admits the api_key
/// pin under DEC-011, the scoped material rides the `Authorization`
/// header — never the body — and the shared adapter posts exactly
/// the frozen manifest as a `chat/completions` request — the pinned
/// model id verbatim, system+user messages, `stream` with
/// `stream_options.include_usage` and the pinned effort as
/// `reasoning_effort` verbatim — the SSE stream validates its
/// finish_reason/`[DONE]` terminal, the one physical send is charged
/// once with the provider's reported usage, and the spent attempt
/// never re-sends.
#[tokio::test]
async fn moonshot_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified moonshot outcome",
            Some(json!({"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&moonshot_config(&base)).expect("valid");
    let (provider, _store) = enrolled_moonshot_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/moonshot", "goal: prove the wire")
        .expect("the moonshot pin passes DEC-011 eligibility");

    let (broker, outcome) = dispatch(broker, "/world/moonshot", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified moonshot outcome");
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
        format!("Bearer {MOONSHOT_KEY}"),
        "the plain key material bears the wire verbatim"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(MOONSHOT_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"], MOONSHOT_MODEL,
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
    assert!(
        body.get("thinking").is_none(),
        "the K2.x thinking surface is a distinct predicate — never constructed"
    );

    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&manifest.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, "moonshot");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 7,
            completion_tokens: 5,
            total_tokens: 12,
        }
    );
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay = broker.dispatch(&mut rivect::model::NullLedger, "/world/moonshot", &manifest);
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

/// Hostile stream input is never a false success for `moonshot`: a
/// stream ended mid `tool_calls` fragment — a partial call that
/// never executes — and a finish_reason the dialect cannot classify
/// are both the unknown terminal, and a rejected send charges
/// nothing.
#[tokio::test]
async fn moonshot_adverse_wire_input_never_reports_success() {
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
    let config = Config::parse_validated(&moonshot_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_moonshot_provider(&config),
        &config,
        "/world/moonshot",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/moonshot", manifest);
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
    let config = Config::parse_validated(&moonshot_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_moonshot_provider(&config),
        &config,
        "/world/moonshot",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/moonshot", manifest);
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

/// The recorded K3 effort ladder rides the body verbatim (DEC-014):
/// a pinned `low` and a pinned `high` each reach the wire as
/// `reasoning_effort` on the K3 build — an always-deny
/// implementation fails this leg — and the K2.x `thinking` surface
/// is never constructed.
#[tokio::test]
async fn moonshot_recorded_effort_levels_ride_the_body() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "effort rides",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    for effort in ["low", "high"] {
        let config = Config::parse_validated(&moonshot_pin_config(&base, MOONSHOT_MODEL, effort))
            .expect("valid");
        let (provider, _store) = enrolled_moonshot_provider(&config);
        let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
        outcome.expect("the recorded level is admitted");
        drop_blocking(provider);
    }

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 2, "each admitted pin is one send");
    for (request, effort) in requests.iter().zip(["low", "high"]) {
        let body: Value = serde_json::from_slice(&request.body).expect("json body");
        assert_eq!(
            body["reasoning_effort"],
            json!(effort),
            "the recorded level rides the body verbatim"
        );
        assert!(
            body.get("thinking").is_none(),
            "the K2.x thinking surface is a distinct predicate — never constructed"
        );
    }
}

/// A pinned effort the K3 build's recorded ladder does not carry is
/// a rejected parameter, never dropped: `minimal`, `medium` and
/// `xhigh` each deny `UnsupportedParameter` naming `reasoning_effort`
/// before any wire leg, a model recording no effort surface denies
/// every pin, and the recorded `max` is never representable — the
/// config carriers refuse the value at ingress, so no `max` request
/// exists to send (DEC-014).
#[tokio::test]
async fn moonshot_out_of_ladder_effort_denies_typed() {
    let server = MockServer::start().await;
    mount_chat(&server, completed_stream("never sent", None)).await;
    let base = server_uri_v1(&server);

    for (model, effort) in [
        (MOONSHOT_MODEL, "minimal"),
        (MOONSHOT_MODEL, "medium"),
        (MOONSHOT_MODEL, "xhigh"),
        ("kimi-k2-instruct", "low"),
    ] {
        let config =
            Config::parse_validated(&moonshot_pin_config(&base, model, effort)).expect("valid");
        let (provider, _store) = enrolled_moonshot_provider(&config);
        let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
        let err = outcome.expect_err("the unrecorded level is a rejected parameter");
        match &err {
            ProviderError::UnsupportedParameter {
                connection,
                parameter,
                model: named,
            } => {
                assert_eq!(connection, "moonshot");
                assert_eq!(*parameter, "reasoning_effort");
                assert_eq!(named, model);
            }
            other => panic!("the rejection is typed and names the parameter: {other:?}"),
        }
        assert_no_secret_or_body(&err, MOONSHOT_KEY.as_bytes());
        drop_blocking(provider);
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the typed denial lands before any wire leg"
    );

    // the recorded `max` has no carrier in the shared vocabulary: the
    // config carriers refuse the value at ingress, so no `max`
    // request is ever constructed
    let Err(error) = Config::parse_validated(&moonshot_pin_config(&base, MOONSHOT_MODEL, "max"))
    else {
        panic!("the recorded max names no effort level this adapter can transmit")
    };
    assert!(
        matches!(
            &error.issue,
            ConfigIssue::UnsupportedEffortValue { value } if value == "max"
        ),
        "the refusal is the typed unsupported-effort value: {error}"
    );
}

// ----- TP-PROVIDER-CATALOG::moonshot -------------------------------------------

/// The configured-or-recorded base resolves under the plan classes'
/// absent-override rule: the required `endpoint` field's empty
/// string resolves the recorded `https://api.moonshot.ai/v1`
/// default, and a configured base wins verbatim, trailing slashes
/// trimmed — discovery and streaming follow it alike. Offline pin:
/// the adapter's `Debug` surface reports the resolved endpoint, so
/// both arms are proved without one byte toward any host.
#[test]
fn moonshot_discriminates_the_recorded_default_base() {
    for endpoint in ["", "   "] {
        let config = Config::parse_validated(&moonshot_config(endpoint))
            .expect("an empty endpoint is valid");
        let provider = provider_result(
            config,
            "moonshot".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the adapter builds");
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"https://api.moonshot.ai/v1\""),
            "endpoint {endpoint:?} resolved the recorded default: {debug}"
        );
        drop_blocking(provider);
    }

    // a configured base wins verbatim — trailing slashes are the only
    // normalization, never a default substitution
    let config = Config::parse_validated(&moonshot_config("http://127.0.0.1:9931/cloud/v1//"))
        .expect("a configured base is valid");
    let provider = provider_result(
        config,
        "moonshot".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("the adapter builds");
    let debug = format!("{provider:?}");
    assert!(
        debug.contains("endpoint: \"http://127.0.0.1:9931/cloud/v1\""),
        "the configured base rides verbatim: {debug}"
    );
    assert!(
        !debug.contains("api.moonshot.ai"),
        "the recorded default never overrides a configured base: {debug}"
    );
    drop_blocking(provider);
}

/// The recorded `requireApiKey` listing is the whole catalogue for
/// `moonshot` (HZN-008 class B): the lookup resolves the scoped
/// material and sends one `GET {endpoint}/models` under the bearer —
/// an absent scope denies `CredentialAbsent` before any request — a
/// listed id is offered ids-only, an empty `data` answer offers
/// nothing (no vendored roster or price surface is carried, so no
/// empty fallback exists), a failed status keeps the typed denial
/// rather than inventing a floor, and a `/models` HTTP 200 confers
/// no entitlement.
#[tokio::test]
async fn moonshot_authoritative_listing_requires_material() {
    // the keyed listing answers under the resolved bearer — listed
    // ids are the offers, an empty id names nothing
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": MOONSHOT_MODEL}),
            json!({"id": "kimi-k2-instruct"}),
            json!({"id": ""}),
        ],
    )
    .await;
    let config = Config::parse_validated(&moonshot_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_moonshot_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the keyed catalogue answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        ["kimi-k2-instruct", MOONSHOT_MODEL],
        "the listing's ids alone are the offers — no vendored roster joins them"
    );
    for model in &models {
        assert_eq!(
            model,
            &CatalogModel {
                id: model.id.clone(),
                ..CatalogModel::default()
            },
            "a listed id carries no invented surface — no price or roster claim"
        );
    }
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the keyed listing is the one leg");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {MOONSHOT_KEY}"),
        "the listing requires the resolved material"
    );

    // an empty `data` answer is a real answer with no offers — the
    // record names no vendored roster, so no fallback fills it
    let server = MockServer::start().await;
    mount_models(&server, vec![]).await;
    let config = Config::parse_validated(&moonshot_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_moonshot_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("an empty listing still answers");
    drop_blocking(provider);
    assert!(
        models.is_empty(),
        "an empty listing has no floor to fall back to: {:?}",
        model_ids(&models)
    );

    // an absent scope denies before any request — the listing
    // requires the material, never a keyless or empty-catalogue form
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "listed-entitlement-claim"})]).await;
    let config = Config::parse_validated(&moonshot_config(&server_uri_v1(&server))).expect("valid");
    let (provider, denied) = catalog_on_thread(
        provider_result(
            config,
            "moonshot".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the binding resolves"),
    );
    assert!(
        matches!(denied, Err(ProviderError::CredentialAbsent { .. })),
        "the requireApiKey listing denies keyless: {denied:?}"
    );
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "the denial opened no wire leg"
    );

    // a `/models` HTTP 200 confers no entitlement (INV-010): the same
    // listing answer never releases a send — the keyless form denies
    // `CredentialAbsent` before the wire, and the keyed pin meets the
    // unmounted request leg's typed transport denial
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "listed-entitlement-claim"})]).await;
    let config = Config::parse_validated(&moonshot_config(&server_uri_v1(&server))).expect("valid");

    let (provider, denied) = send_on_thread(
        provider_result(
            config.clone(),
            "moonshot".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the binding resolves"),
        prepared_manifest(&config),
    );
    assert!(
        matches!(denied, Err(ProviderError::CredentialAbsent { .. })),
        "a 200 listing never stands in for the material: {denied:?}"
    );
    drop_blocking(provider);

    let (provider, _store) = enrolled_moonshot_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a 200 catalogue never releases the pin");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the unmounted request leg is the typed transport denial: {err:?}");
    };
    assert_eq!(connection, "moonshot");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 404 },
        "the request leg answers the peer's status, never a listing-granted success: {cause}"
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "the send's own request leg is the only egress — the 200 listing adds nothing"
    );
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");

    // a refused listing — the recorded authorization/payment
    // failure — keeps the typed denial; no floor substitutes an
    // answer
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&moonshot_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_moonshot_provider(&config);
    let (provider, denied) = catalog_on_thread(provider);
    let err = denied.expect_err("a refused listing is the typed denial, never a floor");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the authorization denial is transport: {err}")
    };
    assert_eq!(connection, "moonshot");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the peer's status is the context: {cause}"
    );
    assert_no_secret_or_body(&err, MOONSHOT_KEY.as_bytes());
    drop_blocking(provider);
}

/// The auto pick rides the authoritative listing under the record's
/// auto semantic — and the configured base redirects the discovery
/// leg the same as the send: the dispatch narrows the pool to the
/// `moonshot` member, the listing is the whole catalogue — no
/// vendored roster merges — and the sorted-first listed id names
/// the wire model verbatim, in the inverted order the peer
/// answered.
#[tokio::test]
async fn moonshot_auto_pick_resolves_through_the_listing() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "zz-listed-late"}),
            json!({"id": "aa-listed-first"}),
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
         [connections.moonshot]\nkind = \"api_key\"\nendpoint = \"{base}\"\ncredential_ref = \"{MOONSHOT_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\", pool = [\"moonshot\"] }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("valid");
    let (provider, _store) = enrolled_moonshot_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/moonshot", "goal: auto pick")
        .expect("the single-member pool pin prepares");
    let (broker, outcome) = dispatch(broker, "/world/moonshot", manifest);
    let reply = outcome.expect("the auto pick dispatches");
    assert_eq!(reply.text, "auto picked");
    drop_blocking(broker);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "the catalogue leg and the send are the only egress — both on the configured base"
    );
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(requests[1].url.path(), "/v1/chat/completions");
    let body: Value = serde_json::from_slice(&requests[1].body).expect("json body");
    assert_eq!(
        body["model"],
        json!("aa-listed-first"),
        "the sorted-first listed id names the wire model verbatim"
    );
}

// ----- TP-PROVIDER-AUTH::moonshot ----------------------------------------------

/// Wrong credential/profile/region never produce a false success
/// for `moonshot`, through the same shared construction its
/// siblings use: a configured `region` — the recorded contract
/// names none — denies `RegionMismatch` with the connection
/// context, a profile-bound ref whose scope disagrees with the
/// binding denies `CredentialProfileMismatch`, and a refused key
/// lands the typed transport denial carrying the peer's status
/// alone — no error, nor the offered credential material or the
/// peer's body, reaches Display or Debug. The recorded `KIMI_API_KEY`
/// fallback key name selects nothing: an env spelling under either
/// recorded name is the identical typed store refusal — the name
/// proves no region or payment class.
#[tokio::test]
async fn moonshot_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    // the recorded env spellings — the primary and the fallback key
    // name alike — name no admitted store class, and never echo the
    // value
    for spelling in ["env:MOONSHOT_API_KEY", "env:KIMI_API_KEY"] {
        let refused = moonshot_config("http://127.0.0.1:1/v1").replace(
            &format!("credential_ref = \"{MOONSHOT_REF}\""),
            &format!("credential_ref = \"{spelling}\""),
        );
        let Err(error) = Config::parse_validated(&refused) else {
            panic!("a {spelling} credential reference is refused at ingress")
        };
        assert!(
            matches!(
                &error.issue,
                ConfigIssue::UnsupportedCredentialStore { store: refused }
                    if refused.as_str() == "env"
            ),
            "either recorded key name is the same store refusal — it selects nothing: {error}"
        );
        assert!(
            !error.to_string().contains(spelling),
            "the refusal never echoes the credential value: {error}"
        );
    }

    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &moonshot_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "moonshot".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, MOONSHOT_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "moonshot");
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, MOONSHOT_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.moonshot]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"moonshot\", model_id = \"{MOONSHOT_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"high\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "moonshot".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, MOONSHOT_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, MOONSHOT_KEY.as_bytes());

    // a refused key is a typed transport denial: the wire never
    // coerces a wrong credential into success, the peer's body never
    // enters the error, and the request carried the bearer
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&moonshot_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_moonshot_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused key is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused key is transport: {err}")
    };
    assert_eq!(connection, "moonshot");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, MOONSHOT_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {MOONSHOT_KEY}"),
        "the admitted bearer reached the wire — the denial is the peer's status"
    );
}

// ----- TP-PROVIDER-RECOVERY::moonshot -------------------------------------------

/// A typed denial is recoverable through the same seam: material the
/// store resolves but the class cannot use — non-UTF-8 bytes can
/// never be a bearer token — denies `CredentialMalformed` on the
/// first send, and enrolling the recorded key at the same scope
/// admits the retry with that bearer. The retry is the same
/// credential at the same scope — no key class is substituted — no
/// state is wedged and no plaintext path is taken.
#[tokio::test]
async fn moonshot_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config = Config::parse_validated(&moonshot_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    store.enroll(MOONSHOT_REF, &[0xff, 0xfe]);
    let provider = provider_result(config.clone(), "moonshot".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialMalformed { .. })
    ));

    store.enroll(MOONSHOT_REF, MOONSHOT_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the recorded key admits the retry");
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
        format!("Bearer {MOONSHOT_KEY}"),
        "the recovered material bears the wire"
    );
}

/// The legs matrix enforces the recorded expected set for
/// `moonshot`: CATALOG, AUTH, WIRE and RECOVERY each execute and
/// report inside this run, and INSTALLED reports NOT_RUN — an
/// omitted leg fails the suite rather than silently absenting.
#[tokio::test]
async fn moonshot_provider_legs_matrix_executes_all_expected_legs() {
    emit_provider_rows("moonshot");
    use std::collections::BTreeMap;
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": MOONSHOT_MODEL})]).await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&moonshot_config(&server_uri_v1(&server))).expect("valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the keyed listing answers the discovered ids under one
    // `/models` leg bearing the scoped material.
    let (provider, _store) = enrolled_moonshot_provider(&config);
    let (provider, listed) = catalog_on_thread(provider);
    let listed = listed.expect("catalog answers");
    let discovery = server.received_requests().await.expect("recorded");
    reported.insert(
        "CATALOG",
        if listed.iter().any(|model| model.id == MOONSHOT_MODEL)
            && discovery.len() == 1
            && discovery[0].url.path() == "/v1/models"
            && received_auth(&discovery[0]) == format!("Bearer {MOONSHOT_KEY}")
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
        provider_result(config.clone(), "moonshot".to_string(), absent).expect("binding resolves");
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
        let (provider, _store) = enrolled_moonshot_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/moonshot", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
    let (broker, outcome) = dispatch(broker, "/world/moonshot", manifest);
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
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "moonshot".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    store.enroll(MOONSHOT_REF, MOONSHOT_KEY.as_bytes());
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

    // The row restates the `#[ignore]`d `provider_installed_moonshot`
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

// ----- TP-PROVIDER-INSTALLED::moonshot ------------------------------------------

/// TP-PROVIDER-INSTALLED::moonshot = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::moonshot = NOT_RUN"]
fn provider_installed_moonshot() {}

// ----- nanogpt ---------------------------------------------------------------

// The `nanogpt` connection's proof legs (HZN-008 class B — the
// api-key cell): the shared Chat Completions adapter serves the
// literal id — no copied codec — under its own recorded predicates
// (DEC-025 row: `Rivect/key → nano-gpt.com/api/v1` CC). The
// configured `endpoint` carries the API base verbatim — an empty one
// resolves the recorded `nano-gpt.com/api/v1` default under the same
// absent-override rule the plan classes bind — while a configured
// `region` is denied: the contract names none. The recorded api-key
// class gates the `/models` listing on resolved material — a keyless
// lookup opens no wire leg — and the listing is the whole catalogue:
// no vendored roster or price/routing carrier exists (D6), so an
// empty or failed answer has no floor to fall back to, a listed
// `:thinking` alias collapses into the one base offer it aliases, and
// a `/models` HTTP 200 confers no entitlement. The recorded
// subscription base is a separate configured payment class — never a
// hidden fallback (DEC-010).

/// The scoped credential ref the `nanogpt` connection binds.
const NANOGPT_REF: &str = "keyring:rivect-test/nanogpt";

/// Fixture `nanogpt` key material — never a real credential, only
/// ever sent to localhost.
const NANOGPT_KEY: &str = "fixture-nanogpt-key";

/// The pinned model id the fixed-pin legs carry — a discovered base
/// id the key-gated listing returns.
const NANOGPT_MODEL: &str = "openai/gpt-5.5";

/// One configured `nanogpt` connection pointing at the fixture peer:
/// the api_key auth class resolves a scoped `SecretRef` (DEC-011),
/// the dialect comes from the literal connection id (DEC-007), and
/// the endpoint carries the API base verbatim.
fn nanogpt_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.nanogpt]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{NANOGPT_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"nanogpt\", model_id = \"{NANOGPT_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"high\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn nanogpt_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(NANOGPT_REF, material)],
    ));
    let provider = provider_result(config.clone(), "nanogpt".to_string(), store.clone())
        .expect("the shared adapter builds for the nanogpt id");
    (provider, store)
}

/// The `nanogpt` provider over the recorded enrolled key.
fn enrolled_nanogpt_provider(config: &Config) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    nanogpt_provider(config, NANOGPT_KEY)
}

// ----- TP-PROVIDER-WIRE::nanogpt ---------------------------------------------

/// A configured `nanogpt` connection returns a verified model outcome
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
async fn nanogpt_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified nanogpt outcome",
            Some(json!({"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&nanogpt_config(&base)).expect("valid");
    let (provider, _store) = enrolled_nanogpt_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/nanogpt", "goal: prove the wire")
        .expect("the nanogpt pin passes DEC-011 eligibility");

    let (broker, outcome) = dispatch(broker, "/world/nanogpt", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified nanogpt outcome");
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
        format!("Bearer {NANOGPT_KEY}"),
        "the plain key material bears the wire verbatim"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(NANOGPT_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"], NANOGPT_MODEL,
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
    assert_eq!(record.connection, "nanogpt");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 7,
            completion_tokens: 5,
            total_tokens: 12,
        }
    );
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay = broker.dispatch(&mut rivect::model::NullLedger, "/world/nanogpt", &manifest);
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

/// Hostile stream input is never a false success for `nanogpt`: a
/// stream ended mid `tool_calls` fragment — a partial call that
/// never executes — and a finish_reason the dialect cannot classify
/// are both the unknown terminal, and a rejected send charges
/// nothing.
#[tokio::test]
async fn nanogpt_adverse_wire_input_never_reports_success() {
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
    let config = Config::parse_validated(&nanogpt_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_nanogpt_provider(&config),
        &config,
        "/world/nanogpt",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/nanogpt", manifest);
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
    let config = Config::parse_validated(&nanogpt_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_nanogpt_provider(&config),
        &config,
        "/world/nanogpt",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/nanogpt", manifest);
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

// ----- TP-PROVIDER-CATALOG::nanogpt -------------------------------------------

/// The configured-or-recorded base resolves under the plan classes'
/// absent-override rule: the required `endpoint` field's empty
/// string resolves the recorded `https://nano-gpt.com/api/v1`
/// default, and a configured base wins verbatim, trailing slashes
/// trimmed — discovery and streaming follow it alike. Offline pin:
/// the adapter's `Debug` surface reports the resolved endpoint, so
/// both arms are proved without one byte toward any host.
#[test]
fn nanogpt_discriminates_the_recorded_default_base() {
    for endpoint in ["", "   "] {
        let config =
            Config::parse_validated(&nanogpt_config(endpoint)).expect("an empty endpoint is valid");
        let provider = provider_result(
            config,
            "nanogpt".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the adapter builds");
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"https://nano-gpt.com/api/v1\""),
            "endpoint {endpoint:?} resolved the recorded default: {debug}"
        );
        drop_blocking(provider);
    }

    // a configured base wins verbatim — trailing slashes are the only
    // normalization, never a default substitution
    let config = Config::parse_validated(&nanogpt_config("http://127.0.0.1:9931/cloud/v1//"))
        .expect("a configured base is valid");
    let provider = provider_result(
        config,
        "nanogpt".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("the adapter builds");
    let debug = format!("{provider:?}");
    assert!(
        debug.contains("endpoint: \"http://127.0.0.1:9931/cloud/v1\""),
        "the configured base rides verbatim: {debug}"
    );
    assert!(
        !debug.contains("nano-gpt.com"),
        "the recorded default never overrides a configured base: {debug}"
    );
    drop_blocking(provider);
}

/// The recorded api-key class gates discovery on resolved material
/// (HZN-008 class B): the conditional `fetchDynamicModels` spread
/// exists only when the key does, so a standalone catalogue read with
/// an absent scope denies `CredentialAbsent` and opens no `/models`
/// leg — never a keyless or headerless listing — while the enrolled
/// key runs the one listing leg under the bearer.
#[tokio::test]
async fn nanogpt_keyless_listing_never_runs() {
    // an absent scope denies before any request — the listing never
    // runs keyless, even where a `/models` answer would serve rows
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": NANOGPT_MODEL})]).await;
    let config = Config::parse_validated(&nanogpt_config(&server_uri_v1(&server))).expect("valid");
    let (provider, denied) = catalog_on_thread(
        provider_result(
            config,
            "nanogpt".to_string(),
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

    // the enrolled key runs the one recorded listing leg under the
    // bearer — the gate is material, never the catalogue itself
    let config = Config::parse_validated(&nanogpt_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_nanogpt_provider(&config);
    let (provider, listed) = catalog_on_thread(provider);
    let models = listed.expect("the keyed catalogue answers");
    drop_blocking(provider);
    assert_eq!(model_ids(&models), [NANOGPT_MODEL]);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the keyed listing is the one leg");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {NANOGPT_KEY}"),
        "the listing runs only under the resolved material"
    );
}

/// The recorded entry filter is authoritative for `nanogpt`: a
/// `:thinking` alias — with or without a `:<level>` tail — never
/// becomes its own offer; it only marks the base id it collapses
/// into, which keeps the one offer and gains the recorded reasoning
/// mark. An id the recorded suffix form cannot name
/// (`:thinking:a:b`) is no alias and rides verbatim, an empty id
/// names nothing, a doubled alias marks the leftmost base only
/// (`dup:thinking:thinking` marks `dup`, never `dup:thinking`), and a
/// case-different suffix is still dropped — upstream's raw-`exec`
/// never marks it, so `cap` stays unmarked.
#[tokio::test]
async fn nanogpt_listing_entry_filter_is_authoritative() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": NANOGPT_MODEL}),
            json!({"id": "openai/gpt-5.5:thinking"}),
            json!({"id": "zeta-base"}),
            json!({"id": "zeta-base:thinking:high"}),
            json!({"id": "dup"}),
            json!({"id": "dup:thinking:thinking"}),
            json!({"id": "cap"}),
            json!({"id": "cap:THINKING"}),
            json!({"id": "orphan:thinking"}),
            json!({"id": "weird:thinking:a:b"}),
            json!({"id": "suffix:thinkingx"}),
            json!({"id": ""}),
        ],
    )
    .await;
    let config = Config::parse_validated(&nanogpt_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_nanogpt_provider(&config);
    let (provider, listed) = catalog_on_thread(provider);
    let models = listed.expect("the keyed catalogue answers");
    drop_blocking(provider);

    // the collapse leaves one offer per base — aliases are never
    // offered — while an id that is no recorded alias rides verbatim
    assert_eq!(
        model_ids(&models),
        [
            "cap",
            "dup",
            NANOGPT_MODEL,
            "suffix:thinkingx",
            "weird:thinking:a:b",
            "zeta-base",
        ],
        "the listing is authoritative: aliases collapse, non-alias ids ride verbatim"
    );
    let marked: Vec<&str> = models
        .iter()
        .filter(|model| model.reasoning)
        .map(|model| model.id.as_str())
        .collect();
    assert_eq!(
        marked,
        ["dup", NANOGPT_MODEL, "zeta-base"],
        "a collapsed alias marks its base offer reasoning-capable — an omitted base stays absent, and a case-different suffix never marks"
    );
    for model in &models {
        assert_eq!(
            model,
            &CatalogModel {
                id: model.id.clone(),
                reasoning: model.reasoning,
                ..CatalogModel::default()
            },
            "a listed id carries no invented surface beyond the recorded reasoning mark"
        );
    }
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the keyed listing is the one leg");
    assert_eq!(requests[0].url.path(), "/v1/models");
}

/// A `/models` HTTP 200 confers no entitlement for `nanogpt`
/// (INV-010): the same listing answer never releases a send — the
/// keyless form denies `CredentialAbsent` before the wire, and the
/// keyed pin meets the unmounted request leg's typed transport
/// denial. An empty listing answers nothing — the record names no
/// vendored roster, so no floor substitutes.
#[tokio::test]
async fn nanogpt_models_http_200_is_never_entitlement() {
    // an empty `data` answer is a real answer with no offers — the
    // record names no vendored roster, so no fallback fills it
    let server = MockServer::start().await;
    mount_models(&server, vec![]).await;
    let config = Config::parse_validated(&nanogpt_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_nanogpt_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("an empty listing still answers");
    drop_blocking(provider);
    assert!(
        models.is_empty(),
        "an empty listing has no floor to fall back to: {:?}",
        model_ids(&models)
    );

    // a failed listing is the leg's typed denial — the class records no
    // vendored roster, so no floor answers in its place
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&nanogpt_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_nanogpt_provider(&config);
    let (provider, failed) = catalog_on_thread(provider);
    let err = failed.expect_err("a failed listing has no floor to answer");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the failed listing is the typed transport denial: {err:?}")
    };
    assert_eq!(connection, "nanogpt");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 503 },
        "the failed listing keeps its typed denial: {cause}"
    );
    drop_blocking(provider);

    // the 200 listing never stands in for the material, and the keyed
    // pin meets the peer's own status on the request leg
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": "listed-entitlement-claim"})]).await;
    let config = Config::parse_validated(&nanogpt_config(&server_uri_v1(&server))).expect("valid");

    let (provider, denied) = send_on_thread(
        provider_result(
            config.clone(),
            "nanogpt".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the binding resolves"),
        prepared_manifest(&config),
    );
    assert!(
        matches!(denied, Err(ProviderError::CredentialAbsent { .. })),
        "a 200 listing never stands in for the material: {denied:?}"
    );
    drop_blocking(provider);

    let (provider, _store) = enrolled_nanogpt_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a 200 catalogue never releases the pin");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the unmounted request leg is the typed transport denial: {err:?}");
    };
    assert_eq!(connection, "nanogpt");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 404 },
        "the request leg answers the peer's status, never a listing-granted success: {cause}"
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "the send's own request leg is the only egress — the 200 listing adds nothing"
    );
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
}

// ----- TP-PROVIDER-AUTH::nanogpt ----------------------------------------------

/// Wrong credential/profile/region never produce a false success
/// for `nanogpt`, through the same shared construction its
/// siblings use: a configured `region` — the recorded contract
/// names none — denies `RegionMismatch` with the connection
/// context, a profile-bound ref whose scope disagrees with the
/// binding denies `CredentialProfileMismatch`, and a refused key
/// lands the typed transport denial carrying the peer's status
/// alone — no error, nor the offered credential material or the
/// peer's body, reaches Display or Debug. The recorded subscription
/// base is a separate configured payment class, never a hidden
/// fallback: a `subscription`-kind declaration names a live grant,
/// never this api-key class's binding.
#[tokio::test]
async fn nanogpt_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    // the recorded env spelling names no admitted store class, and
    // the refusal never echoes the value
    let refused = nanogpt_config("http://127.0.0.1:1/v1").replace(
        &format!("credential_ref = \"{NANOGPT_REF}\""),
        "credential_ref = \"env:NANO_GPT_API_KEY\"",
    );
    let Err(error) = Config::parse_validated(&refused) else {
        panic!("an env credential reference is refused at ingress")
    };
    assert!(
        matches!(
            &error.issue,
            ConfigIssue::UnsupportedCredentialStore { store: refused }
                if refused.as_str() == "env"
        ),
        "the recorded key name is the same store refusal — it selects nothing: {error}"
    );
    assert!(
        !error.to_string().contains("env:NANO_GPT_API_KEY"),
        "the refusal never echoes the credential value: {error}"
    );

    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &nanogpt_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "nanogpt".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, NANOGPT_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "nanogpt");
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, NANOGPT_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.nanogpt]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"nanogpt\", model_id = \"{NANOGPT_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"high\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "nanogpt".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, NANOGPT_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, NANOGPT_KEY.as_bytes());

    // a refused key is a typed transport denial: the wire never
    // coerces a wrong credential into success, the peer's body never
    // enters the error, and the request carried the bearer
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&nanogpt_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_nanogpt_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused key is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused key is transport: {err}")
    };
    assert_eq!(connection, "nanogpt");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, NANOGPT_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {NANOGPT_KEY}"),
        "the admitted bearer reached the wire — the denial is the peer's status"
    );
}

// ----- TP-PROVIDER-RECOVERY::nanogpt -------------------------------------------

/// A typed denial is recoverable through the same seam: material the
/// store resolves but the class cannot use — non-UTF-8 bytes can
/// never be a bearer token — denies `CredentialMalformed` on the
/// first send, and enrolling the recorded key at the same scope
/// admits the retry with that bearer. The retry is the same
/// credential at the same scope — no key class is substituted — no
/// state is wedged and no plaintext path is taken.
#[tokio::test]
async fn nanogpt_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config = Config::parse_validated(&nanogpt_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    store.enroll(NANOGPT_REF, &[0xff, 0xfe]);
    let provider = provider_result(config.clone(), "nanogpt".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialMalformed { .. })
    ));

    store.enroll(NANOGPT_REF, NANOGPT_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the recorded key admits the retry");
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
        format!("Bearer {NANOGPT_KEY}"),
        "the recovered material bears the wire"
    );
}

/// The legs matrix enforces the recorded expected set for
/// `nanogpt`: CATALOG, AUTH, WIRE and RECOVERY each execute and
/// report inside this run, and INSTALLED reports NOT_RUN — an
/// omitted leg fails the suite rather than silently absenting.
#[tokio::test]
async fn nanogpt_provider_legs_matrix_executes_all_expected_legs() {
    emit_provider_rows("nanogpt");
    use std::collections::BTreeMap;
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": NANOGPT_MODEL})]).await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&nanogpt_config(&server_uri_v1(&server))).expect("valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the keyed listing answers the discovered ids under one
    // `/models` leg bearing the scoped material.
    let (provider, _store) = enrolled_nanogpt_provider(&config);
    let (provider, listed) = catalog_on_thread(provider);
    let listed = listed.expect("catalog answers");
    let discovery = server.received_requests().await.expect("recorded");
    reported.insert(
        "CATALOG",
        if listed.iter().any(|model| model.id == NANOGPT_MODEL)
            && discovery.len() == 1
            && discovery[0].url.path() == "/v1/models"
            && received_auth(&discovery[0]) == format!("Bearer {NANOGPT_KEY}")
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
        provider_result(config.clone(), "nanogpt".to_string(), absent).expect("binding resolves");
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
        let (provider, _store) = enrolled_nanogpt_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/nanogpt", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
    let (broker, outcome) = dispatch(broker, "/world/nanogpt", manifest);
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
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "nanogpt".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    store.enroll(NANOGPT_REF, NANOGPT_KEY.as_bytes());
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

    // The row restates the `#[ignore]`d `provider_installed_nanogpt`
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

// ----- TP-PROVIDER-INSTALLED::nanogpt ------------------------------------------

/// TP-PROVIDER-INSTALLED::nanogpt = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::nanogpt = NOT_RUN"]
fn provider_installed_nanogpt() {}

// ----- novita ----------------------------------------------------------------

// The `novita` connection's proof legs (HZN-008 class B — the api-key
// cell): the shared Chat Completions adapter serves the literal id —
// no copied codec — under its own recorded predicates (DEC-025 row:
// `Rivect/key → api.novita.ai/openai/v1` CC). The configured
// `endpoint` carries the API base verbatim — an empty one resolves
// the recorded `api.novita.ai/openai/v1` default under the same
// absent-override rule the plan classes bind — while a configured
// `region` is denied: the contract names none. The recorded
// `catalogDiscovery.allowUnauthenticated` makes the `/models`
// discovery keyless — an absent scope opens the anonymous listing
// with no `Authorization` header, while a send still denies
// `CredentialAbsent` — and that listing is authoritative
// (`dynamicModelsAuthoritative`): no vendored roster or price row
// exists (D6), so an empty or failed answer has no floor to fall back
// to, and an entry offers only under the recorded conjunction
// (active status, non-test id, `chat/completions` endpoint, positive
// `max_output_tokens`). The recorded login validates against
// inference, never payment administration — a limited-role key is
// verified by a model request — and no price or billing fact is
// borrowed from another id.

/// The scoped credential ref the `novita` connection binds.
const NOVITA_REF: &str = "keyring:rivect-test/novita";

/// Fixture `novita` key material — never a real credential, only
/// ever sent to localhost.
const NOVITA_KEY: &str = "fixture-novita-key";

/// The pinned model id the fixed-pin legs carry — the recorded
/// default model the class's login validates with.
const NOVITA_MODEL: &str = "moonshotai/kimi-k2.7-code";

/// One configured `novita` connection pointing at the fixture peer:
/// the api_key auth class resolves a scoped `SecretRef` (DEC-011),
/// the dialect comes from the literal connection id (DEC-007), and
/// the endpoint carries the API base verbatim.
fn novita_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.novita]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{NOVITA_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"novita\", model_id = \"{NOVITA_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"high\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// A listing row the recorded filter admits: active (`status: 1`), a
/// non-test id, the `chat/completions` endpoint and a positive output
/// cap.
fn novita_row(id: &str) -> Value {
    json!({
        "id": id,
        "status": 1,
        "endpoints": ["chat/completions"],
        "max_output_tokens": 4096,
    })
}

fn novita_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(NOVITA_REF, material)],
    ));
    let provider = provider_result(config.clone(), "novita".to_string(), store.clone())
        .expect("the shared adapter builds for the novita id");
    (provider, store)
}

/// The `novita` provider over the recorded enrolled key.
fn enrolled_novita_provider(config: &Config) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    novita_provider(config, NOVITA_KEY)
}

// ----- TP-PROVIDER-WIRE::novita ----------------------------------------------

/// A configured `novita` connection returns a verified model outcome
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
async fn novita_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified novita outcome",
            Some(json!({"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&novita_config(&base)).expect("valid");
    let (provider, _store) = enrolled_novita_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/novita", "goal: prove the wire")
        .expect("the novita pin passes DEC-011 eligibility");

    let (broker, outcome) = dispatch(broker, "/world/novita", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified novita outcome");
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
        format!("Bearer {NOVITA_KEY}"),
        "the plain key material bears the wire verbatim"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(NOVITA_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"], NOVITA_MODEL,
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
    assert_eq!(record.connection, "novita");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 7,
            completion_tokens: 5,
            total_tokens: 12,
        }
    );
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay = broker.dispatch(&mut rivect::model::NullLedger, "/world/novita", &manifest);
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

/// Hostile stream input is never a false success for `novita`: a
/// stream ended mid `tool_calls` fragment — a partial call that
/// never executes — and a finish_reason the dialect cannot classify
/// are both the unknown terminal, and a rejected send charges
/// nothing.
#[tokio::test]
async fn novita_adverse_wire_input_never_reports_success() {
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
    let config = Config::parse_validated(&novita_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_novita_provider(&config),
        &config,
        "/world/novita",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/novita", manifest);
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
    let config = Config::parse_validated(&novita_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_novita_provider(&config),
        &config,
        "/world/novita",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/novita", manifest);
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

// ----- TP-PROVIDER-CATALOG::novita -------------------------------------------

/// The configured-or-recorded base resolves under the plan classes'
/// absent-override rule: the required `endpoint` field's empty
/// string resolves the recorded `https://api.novita.ai/openai/v1`
/// default, and a configured base wins verbatim, trailing slashes
/// trimmed — discovery and streaming follow it alike. Offline pin:
/// the adapter's `Debug` surface reports the resolved endpoint, so
/// both arms are proved without one byte toward any host.
#[test]
fn novita_discriminates_the_recorded_default_base() {
    for endpoint in ["", "   "] {
        let config =
            Config::parse_validated(&novita_config(endpoint)).expect("an empty endpoint is valid");
        let provider = provider_result(
            config,
            "novita".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the adapter builds");
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"https://api.novita.ai/openai/v1\""),
            "endpoint {endpoint:?} resolved the recorded default: {debug}"
        );
        drop_blocking(provider);
    }

    // a configured base wins verbatim — trailing slashes are the only
    // normalization, never a default substitution
    let config = Config::parse_validated(&novita_config("http://127.0.0.1:9931/cloud/v1//"))
        .expect("a configured base is valid");
    let provider = provider_result(
        config,
        "novita".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("the adapter builds");
    let debug = format!("{provider:?}");
    assert!(
        debug.contains("endpoint: \"http://127.0.0.1:9931/cloud/v1\""),
        "the configured base rides verbatim: {debug}"
    );
    assert!(
        !debug.contains("api.novita.ai"),
        "the recorded default never overrides a configured base: {debug}"
    );
    drop_blocking(provider);
}

/// The recorded discovery is keyless (`catalogDiscovery.
/// allowUnauthenticated`, no `requireApiKey`): an absent scope opens
/// one anonymous `/models` listing with no `Authorization` header,
/// and that listing answer is the catalogue — while the same absent
/// scope still denies the send `CredentialAbsent` before any chat
/// request.
#[tokio::test]
async fn novita_keyless_listing_runs_anonymously() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![novita_row(NOVITA_MODEL), novita_row("novita/keyless-peer")],
    )
    .await;
    let config = Config::parse_validated(&novita_config(&server_uri_v1(&server))).expect("valid");
    let (provider, listed) = catalog_on_thread(
        provider_result(
            config.clone(),
            "novita".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the binding resolves"),
    );
    let models = listed.expect("the keyless listing answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        [NOVITA_MODEL, "novita/keyless-peer"],
        "the anonymous listing is the catalogue"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the keyless lookup is one listing leg");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert!(
        requests[0].headers.get("authorization").is_none(),
        "the anonymous listing carries no authorization header"
    );

    // the same absent scope denies the send before any chat request
    let (provider, outcome) = send_on_thread(
        provider_result(
            config.clone(),
            "novita".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the binding resolves"),
        prepared_manifest(&config),
    );
    assert!(
        matches!(outcome, Err(ProviderError::CredentialAbsent { .. })),
        "the send denies the absent scope typed: {outcome:?}"
    );
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "the denied send opens no chat request after the one listing leg"
    );
    assert_eq!(requests[0].url.path(), "/v1/models");
}

/// The recorded entry filter is authoritative for `novita`
/// (`novitaModelManagerOptions`'s `filterModel`): each clause is
/// discriminated on its own row — a numeric `status` other than `1`
/// is inactive while an absent or non-numeric status offers; an
/// `ai_infer_test` id is a test SKU; `endpoints` must carry
/// `chat/completions` as an array member; and a missing, zero,
/// negative or unreadable `max_output_tokens` is not a positive
/// output cap. A row passing every clause offers with no invented
/// surface, and the price-metadata row keeps [`ModelPrice::Unknown`]
/// — no figure is borrowed from another id (D6).
#[tokio::test]
async fn novita_listing_entry_filter_is_authoritative() {
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            // admitted: every clause holds
            novita_row("novita/base"),
            // admitted: an absent status and a decimal-string cap
            json!({
                "id": "novita/absent-status",
                "endpoints": ["embeddings", "chat/completions"],
                "max_output_tokens": "8192",
            }),
            // admitted: upstream reads a non-numeric status as active
            json!({
                "id": "novita/non-numeric-status",
                "status": "active",
                "endpoints": ["chat/completions"],
                "max_output_tokens": 1,
            }),
            // admitted: a float status of 1 is the active status
            json!({
                "id": "novita/float-active",
                "status": 1.0,
                "endpoints": ["chat/completions"],
                "max_output_tokens": 2048,
            }),
            // admitted, but its listing prices never become an offer
            // surface — the class carries no price mapping (D6)
            json!({
                "id": "novita/priced",
                "status": 1,
                "endpoints": ["chat/completions"],
                "max_output_tokens": 2048,
                "input_token_price_per_m": 5000,
                "output_token_price_per_m": 10000,
            }),
            // dropped: numeric status 0 is inactive
            json!({
                "id": "novita/inactive",
                "status": 0,
                "endpoints": ["chat/completions"],
                "max_output_tokens": 4096,
            }),
            // dropped: any other numeric status is inactive too
            json!({
                "id": "novita/suspended",
                "status": 2,
                "endpoints": ["chat/completions"],
                "max_output_tokens": 4096,
            }),
            // dropped: a test SKU, whatever its capability marks
            json!({
                "id": "ai_infer_test_probe",
                "status": 1,
                "endpoints": ["chat/completions"],
                "max_output_tokens": 4096,
            }),
            // dropped: the test-SKU prefix reads case-insensitively
            json!({
                "id": "AI_INFER_TEST_UPPER",
                "status": 1,
                "endpoints": ["chat/completions"],
                "max_output_tokens": 4096,
            }),
            // dropped: no chat/completions endpoint
            json!({
                "id": "novita/embeddings",
                "status": 1,
                "endpoints": ["embeddings"],
                "max_output_tokens": 4096,
            }),
            // dropped: an absent endpoints member
            json!({
                "id": "novita/no-endpoints",
                "status": 1,
                "max_output_tokens": 4096,
            }),
            // dropped: a bare string is not the recorded array member
            json!({
                "id": "novita/bare-endpoint",
                "status": 1,
                "endpoints": "chat/completions",
                "max_output_tokens": 4096,
            }),
            // dropped: a stated zero cap
            json!({
                "id": "novita/zero-output",
                "status": 1,
                "endpoints": ["chat/completions"],
                "max_output_tokens": 0,
            }),
            // dropped: a negative cap
            json!({
                "id": "novita/negative-output",
                "status": 1,
                "endpoints": ["chat/completions"],
                "max_output_tokens": -1,
            }),
            // dropped: an absent cap
            json!({
                "id": "novita/missing-output",
                "status": 1,
                "endpoints": ["chat/completions"],
            }),
            // dropped: an unreadable cap
            json!({
                "id": "novita/text-output",
                "status": 1,
                "endpoints": ["chat/completions"],
                "max_output_tokens": "many",
            }),
            // dropped: an empty-string cap
            json!({
                "id": "novita/empty-output",
                "status": 1,
                "endpoints": ["chat/completions"],
                "max_output_tokens": "",
            }),
            // dropped: an empty id names nothing
            json!({
                "id": "",
                "status": 1,
                "endpoints": ["chat/completions"],
                "max_output_tokens": 4096,
            }),
        ],
    )
    .await;
    let config = Config::parse_validated(&novita_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_novita_provider(&config);
    let (provider, listed) = catalog_on_thread(provider);
    let models = listed.expect("the keyed catalogue answers");
    drop_blocking(provider);

    // The listing is the whole catalogue: only rows passing every
    // recorded clause offer, and no floor or alias row appears.
    assert_eq!(
        model_ids(&models),
        [
            "novita/absent-status",
            "novita/base",
            "novita/float-active",
            "novita/non-numeric-status",
            "novita/priced",
        ],
        "the entry filter admits exactly the recorded conjunction"
    );
    for model in &models {
        assert_eq!(
            model.price,
            ModelPrice::Unknown,
            "no price is mapped, borrowed or invented for {}",
            model.id
        );
        assert_eq!(
            model,
            &CatalogModel {
                id: model.id.clone(),
                ..CatalogModel::default()
            },
            "an admitted id carries no invented surface beyond the recorded filter"
        );
    }
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the keyed listing is the one leg");
    assert_eq!(requests[0].url.path(), "/v1/models");
}

/// The authoritative listing has no floor: an empty `data` answer
/// offers nothing, and a failed listing is the leg's typed denial —
/// never a vendored roster or a substituted success (INV-010).
#[tokio::test]
async fn novita_failed_listing_denies_typed_without_a_floor() {
    // an empty `data` answer is a real answer with no offers
    let server = MockServer::start().await;
    mount_models(&server, vec![]).await;
    let config = Config::parse_validated(&novita_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_novita_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("an empty listing still answers");
    drop_blocking(provider);
    assert!(
        models.is_empty(),
        "an empty listing has no floor to fall back to: {:?}",
        model_ids(&models)
    );

    // a failed listing keeps its typed denial
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&novita_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_novita_provider(&config);
    let (provider, failed) = catalog_on_thread(provider);
    let err = failed.expect_err("a failed listing has no floor to answer");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the failed listing is the typed transport denial: {err:?}")
    };
    assert_eq!(connection, "novita");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 503 },
        "the failed listing keeps its typed denial: {cause}"
    );
    drop_blocking(provider);
}

/// The recorded login validates against inference, never payment
/// administration: a limited-role key's entitlement is verified by
/// the model request leg on `/chat/completions`, and the adapter
/// constructs no billing path at all. A payment endpoint that would
/// refuse this key is never consulted — no billing answer, denied or
/// otherwise, stands in for the inference verdict.
#[tokio::test]
async fn novita_limited_role_key_is_verified_by_a_model_request() {
    let server = MockServer::start().await;
    // The recorded validation comment: a basic team role holds no
    // billing scope, so the balance endpoint refuses the same key.
    Mock::given(method("POST"))
        .and(path("/openapi/v1/billing/balance/detail"))
        .respond_with(ResponseTemplate::new(403).set_body_string("no billing scope"))
        .mount(&server)
        .await;
    mount_chat(
        &server,
        completed_stream(
            "inference-verified",
            Some(json!({"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5})),
        ),
    )
    .await;
    let config = Config::parse_validated(&novita_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_novita_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let reply = outcome.expect("the model request is the verification");
    assert_eq!(reply.text, "inference-verified");
    drop_blocking(provider);

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "one model request verifies the key — no payment administration leg"
    );
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {NOVITA_KEY}"),
        "the same limited-role key bears the model request"
    );
    for request in &requests {
        assert!(
            !request.url.path().contains("billing") && !request.url.path().starts_with("/openapi/"),
            "no payment administration path is ever consulted: {}",
            request.url.path()
        );
    }

    // A key the model endpoint refuses is the typed inference denial —
    // the same limited-role key is never re-judged through a billing
    // answer, and the peer's body never reaches the diagnostic.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(403).set_body_string(format!(
            "{{\"error\": {{\"message\": \"insufficient role {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&novita_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_novita_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a limited-role refusal is typed, never a success");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the refused model request is transport: {err}")
    };
    assert_eq!(connection, "novita");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 403 },
        "the inference refusal carries the peer's status: {cause}"
    );
    assert_no_secret_or_body(&err, NOVITA_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one model request");
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
}

// ----- TP-PROVIDER-AUTH::novita ----------------------------------------------

/// Wrong credential/profile/region never produce a false success
/// for `novita`, through the same shared construction its siblings
/// use: a configured `region` — the recorded contract names none —
/// denies `RegionMismatch` with the connection context, a
/// profile-bound ref whose scope disagrees with the binding denies
/// `CredentialProfileMismatch`, and a refused key lands the typed
/// transport denial carrying the peer's status alone — no error, nor
/// the offered credential material or the peer's body, reaches
/// Display or Debug. The recorded `NOVITA_API_KEY` env spelling is
/// refused at ingress, so no env path substitutes the binding; a
/// `subscription`-kind declaration names a live grant, never this
/// api-key class's binding (DEC-010).
#[tokio::test]
async fn novita_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    // the recorded env spelling names no admitted store class, and
    // the refusal never echoes the value
    let refused = novita_config("http://127.0.0.1:1/v1").replace(
        &format!("credential_ref = \"{NOVITA_REF}\""),
        "credential_ref = \"env:NOVITA_API_KEY\"",
    );
    let Err(error) = Config::parse_validated(&refused) else {
        panic!("an env credential reference is refused at ingress")
    };
    assert!(
        matches!(
            &error.issue,
            ConfigIssue::UnsupportedCredentialStore { store: refused }
                if refused.as_str() == "env"
        ),
        "the recorded key name is the same store refusal — it selects nothing: {error}"
    );
    assert!(
        !error.to_string().contains("env:NOVITA_API_KEY"),
        "the refusal never echoes the credential value: {error}"
    );

    let server = MockServer::start().await;

    // a configured region is denied — never ignored — while a sibling
    // scope holds real material so the no-secret assertion proves no
    // cross-scope leak instead of passing vacuously
    let regioned = Config::parse_validated(
        &novita_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "novita".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, NOVITA_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is the typed mismatch: {err}")
    };
    assert_eq!(connection, "novita");
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, NOVITA_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.novita]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"novita\", model_id = \"{NOVITA_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"high\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("valid");
    let err = provider_result(
        mismatched,
        "novita".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, NOVITA_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, NOVITA_KEY.as_bytes());

    // a refused key is a typed transport denial: the wire never
    // coerces a wrong credential into success, the peer's body never
    // enters the error, and the request carried the bearer
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
        )))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&novita_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_novita_provider(&config);
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a refused key is a typed transport denial");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("a refused key is transport: {err}")
    };
    assert_eq!(connection, "novita");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 401 },
        "the status code is the context: {cause}"
    );
    assert_no_secret_or_body(&err, NOVITA_KEY.as_bytes());
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the refusal is the one request leg");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {NOVITA_KEY}"),
        "the admitted bearer reached the wire — the denial is the peer's status"
    );
}

// ----- TP-PROVIDER-RECOVERY::novita ------------------------------------------

/// A typed denial is recoverable through the same seam: material the
/// store resolves but the class cannot use — non-UTF-8 bytes can
/// never be a bearer token — denies `CredentialMalformed` on the
/// first send, and enrolling the recorded key at the same scope
/// admits the retry with that bearer. The retry is the same
/// credential at the same scope — no key class is substituted — no
/// state is wedged and no plaintext path is taken.
#[tokio::test]
async fn novita_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3})),
        ),
    )
    .await;
    let config = Config::parse_validated(&novita_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    store.enroll(NOVITA_REF, &[0xff, 0xfe]);
    let provider = provider_result(config.clone(), "novita".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialMalformed { .. })
    ));

    store.enroll(NOVITA_REF, NOVITA_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the recorded key admits the retry");
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
        format!("Bearer {NOVITA_KEY}"),
        "the recovered material bears the wire"
    );
}

/// The legs matrix enforces the recorded expected set for
/// `novita`: CATALOG, AUTH, WIRE and RECOVERY each execute and
/// report inside this run, and INSTALLED reports NOT_RUN — an
/// omitted leg fails the suite rather than silently absenting.
#[tokio::test]
async fn novita_provider_legs_matrix_executes_all_expected_legs() {
    emit_provider_rows("novita");
    use std::collections::BTreeMap;
    let server = MockServer::start().await;
    mount_models(&server, vec![novita_row(NOVITA_MODEL)]).await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&novita_config(&server_uri_v1(&server))).expect("valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the keyed listing answers the recorded rows under one
    // `/models` leg bearing the scoped material.
    let (provider, _store) = enrolled_novita_provider(&config);
    let (provider, listed) = catalog_on_thread(provider);
    let listed = listed.expect("catalog answers");
    let discovery = server.received_requests().await.expect("recorded");
    reported.insert(
        "CATALOG",
        if listed.iter().any(|model| model.id == NOVITA_MODEL)
            && discovery.len() == 1
            && discovery[0].url.path() == "/v1/models"
            && received_auth(&discovery[0]) == format!("Bearer {NOVITA_KEY}")
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
        provider_result(config.clone(), "novita".to_string(), absent).expect("binding resolves");
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
        let (provider, _store) = enrolled_novita_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/novita", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
    let (broker, outcome) = dispatch(broker, "/world/novita", manifest);
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
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "novita".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    store.enroll(NOVITA_REF, NOVITA_KEY.as_bytes());
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

    // The row restates the `#[ignore]`d `provider_installed_novita`
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

// ----- TP-PROVIDER-INSTALLED::novita -----------------------------------------

/// TP-PROVIDER-INSTALLED::novita = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::novita = NOT_RUN"]
fn provider_installed_novita() {}

// ----- nvidia ----------------------------------------------------------------

// The `nvidia` connection's proof legs (HZN-008 class B — the api-key
// cell): the shared Chat Completions adapter serves the literal id —
// no copied codec — under its own recorded predicates (DEC-025 row:
// `integrate.api.nvidia.com/v1` CC, `nvidiaModelManagerOptions` →
// `createSimpleOpenAICompletionsOptions`). The configured `endpoint`
// carries the API base verbatim — an empty one resolves the recorded
// `https://integrate.api.nvidia.com/v1` default — while a configured
// `region` is denied: the contract names none. The recorded plain
// `GET /models` listing is the whole catalogue: no vendored floor and
// no per-entry filter, so a listed `vendor/model` namespace rides the
// catalogue and the wire verbatim. The recorded login validation is
// optional (`optional=#true`): a `401`/`403` from the validation/model
// request is the hard auth rejection, any other failure proves neither
// access nor denial.

/// The scoped credential ref the `nvidia` connection binds.
const NVIDIA_REF: &str = "keyring:rivect-test/nvidia";

/// Fixture `nvidia` key material — never a real credential, only ever
/// sent to localhost.
const NVIDIA_KEY: &str = "fixture-nvidia-key";

/// The pinned model id the fixed-pin legs carry — the recorded
/// `vendor/model` namespace the class serves and its login validates
/// against.
const NVIDIA_MODEL: &str = "nvidia/llama-3.1-nemotron-70b-instruct";

/// One configured `nvidia` connection pointing at the fixture peer:
/// the api_key auth class resolves a scoped `SecretRef` (DEC-011), the
/// dialect comes from the literal connection id (DEC-007), and the
/// endpoint carries the API base verbatim.
fn nvidia_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.nvidia]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{NVIDIA_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"nvidia\", model_id = \"{NVIDIA_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"high\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn nvidia_provider(
    config: &Config,
    material: &str,
) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    let store = Arc::new(support::MapStore::seeded(
        STORE_KIND,
        &[(NVIDIA_REF, material)],
    ));
    let provider = provider_result(config.clone(), "nvidia".to_string(), store.clone())
        .expect("the shared adapter builds for the nvidia id");
    (provider, store)
}

/// The `nvidia` provider over the recorded enrolled key.
fn enrolled_nvidia_provider(config: &Config) -> (ChatCompletionsProvider, Arc<support::MapStore>) {
    nvidia_provider(config, NVIDIA_KEY)
}

// ----- TP-PROVIDER-WIRE::nvidia ----------------------------------------------

/// A configured `nvidia` connection returns a verified model outcome
/// through the standard Broker: prepare admits the api_key pin under
/// DEC-011, the scoped material rides the `Authorization` header —
/// never the body — and the shared adapter posts exactly the frozen
/// manifest as a `chat/completions` request — the pinned
/// `vendor/model` id verbatim, system+user messages, `stream` with
/// `stream_options.include_usage` and the pinned effort as
/// `reasoning_effort` verbatim — the SSE stream validates its
/// finish_reason/`[DONE]` terminal, and the one physical send is
/// charged once with the provider's reported usage.
#[tokio::test]
async fn nvidia_valid_control_yields_one_outcome_and_one_physical_usage() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "verified nvidia outcome",
            Some(json!({"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12})),
        ),
    )
    .await;
    let base = server_uri_v1(&server);
    let config = Config::parse_validated(&nvidia_config(&base)).expect("valid");
    let (provider, _store) = enrolled_nvidia_provider(&config);
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, "/world/nvidia", "goal: prove the wire")
        .expect("the nvidia pin passes DEC-011 eligibility");

    let (broker, outcome) = dispatch(broker, "/world/nvidia", manifest.clone());
    let reply = outcome.expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified nvidia outcome");
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
        format!("Bearer {NVIDIA_KEY}"),
        "the plain key material bears the wire verbatim"
    );
    assert!(
        !String::from_utf8_lossy(&requests[0].body).contains(NVIDIA_KEY),
        "credential material rides the authorization header, never the body"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        body["model"], NVIDIA_MODEL,
        "the vendor/model id rides the wire verbatim"
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
    assert_eq!(record.connection, "nvidia");
    assert_eq!(
        record.usage,
        UsageDelta::Exact {
            prompt_tokens: 7,
            completion_tokens: 5,
            total_tokens: 12,
        }
    );
    let (broker, replay) = {
        let manifest = manifest.clone();
        std::thread::spawn(move || {
            let mut broker = broker;
            let replay = broker.dispatch(&mut rivect::model::NullLedger, "/world/nvidia", &manifest);
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

/// Hostile stream input is never a false success for `nvidia`: a
/// stream ended mid `tool_calls` fragment — a partial call that never
/// executes — and a finish_reason the dialect cannot classify are both
/// the unknown terminal, and a rejected send charges nothing.
#[tokio::test]
async fn nvidia_adverse_wire_input_never_reports_success() {
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
    let config = Config::parse_validated(&nvidia_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_nvidia_provider(&config),
        &config,
        "/world/nvidia",
        "goal: partial tool",
    );
    let (broker, outcome) = dispatch(broker, "/world/nvidia", manifest);
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
    let config = Config::parse_validated(&nvidia_config(&server_uri_v1(&server))).expect("valid");
    let (broker, manifest) = prepared_with(
        enrolled_nvidia_provider(&config),
        &config,
        "/world/nvidia",
        "goal: odd terminal",
    );
    let (broker, outcome) = dispatch(broker, "/world/nvidia", manifest);
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

// ----- TP-PROVIDER-CATALOG::nvidia -------------------------------------------

/// The configured-or-recorded base resolves under the plan classes'
/// absent-override rule: the required `endpoint` field's empty string
/// resolves the recorded `https://integrate.api.nvidia.com/v1`
/// default, and a configured base wins verbatim, trailing slashes
/// trimmed — discovery and streaming follow it alike. Offline pin:
/// the adapter's `Debug` surface reports the resolved endpoint, so
/// both arms are proved without one byte toward any host.
#[test]
fn nvidia_discriminates_the_recorded_default_base() {
    for endpoint in ["", "   "] {
        let config =
            Config::parse_validated(&nvidia_config(endpoint)).expect("an empty endpoint is valid");
        let provider = provider_result(
            config,
            "nvidia".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the adapter builds");
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("endpoint: \"https://integrate.api.nvidia.com/v1\""),
            "endpoint {endpoint:?} resolved the recorded default: {debug}"
        );
        drop_blocking(provider);
    }

    // a configured base wins verbatim — trailing slashes are the only
    // normalization, never a default substitution
    let config = Config::parse_validated(&nvidia_config("http://127.0.0.1:9931/nim/v1//"))
        .expect("a configured base is valid");
    let provider = provider_result(
        config,
        "nvidia".to_string(),
        Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
    )
    .expect("the adapter builds");
    let debug = format!("{provider:?}");
    assert!(
        debug.contains("endpoint: \"http://127.0.0.1:9931/nim/v1\""),
        "the configured base rides verbatim: {debug}"
    );
    assert!(
        !debug.contains("integrate.api.nvidia.com"),
        "the recorded default never overrides a configured base: {debug}"
    );
    drop_blocking(provider);
}

/// The recorded `createSimpleOpenAICompletionsOptions` discovery is the
/// plain keyed `/models` listing and the whole catalogue: there is no
/// vendored floor and no per-entry filter, so the listed
/// `vendor/model` ids are offered and sent verbatim. A keyless lookup
/// opens no wire leg (`CredentialAbsent`), an empty answer leaves no
/// offers to fall back to, and a failed listing keeps its typed
/// denial — never a substituted success (INV-010).
#[tokio::test]
async fn nvidia_authoritative_listing_requires_material() {
    // the keyed listing is the whole offer set; vendored namespaces
    // ride the catalogue unchanged
    let server = MockServer::start().await;
    mount_models(
        &server,
        vec![
            json!({"id": "meta/llama-3.3-70b-instruct"}),
            json!({"id": NVIDIA_MODEL}),
        ],
    )
    .await;
    let config = Config::parse_validated(&nvidia_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_nvidia_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the keyed catalogue answers");
    drop_blocking(provider);
    assert_eq!(
        model_ids(&models),
        ["meta/llama-3.3-70b-instruct", NVIDIA_MODEL],
        "the listing is the catalogue and every id rides verbatim"
    );
    for model in &models {
        assert_eq!(
            model.price,
            ModelPrice::Unknown,
            "no borrowed price row is attached to a listed offer"
        );
    }
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "one discovery leg");
    assert_eq!(requests[0].url.path(), "/v1/models");
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {NVIDIA_KEY}"),
        "the listing carries the resolved plain bearer"
    );

    // an empty `data` answer is a real answer with no offers — the
    // record names no floor to fall back to
    let server = MockServer::start().await;
    mount_models(&server, vec![]).await;
    let config = Config::parse_validated(&nvidia_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_nvidia_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("an empty listing still answers");
    drop_blocking(provider);
    assert!(
        models.is_empty(),
        "an empty listing has no floor to fall back to: {:?}",
        model_ids(&models)
    );

    // a keyless lookup opens no wire leg: the listing is key-gated,
    // never the class's absent-binding form (DEC-009)
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": NVIDIA_MODEL})]).await;
    let config = Config::parse_validated(&nvidia_config(&server_uri_v1(&server))).expect("valid");
    let (provider, denied) = catalog_on_thread(
        provider_result(
            config,
            "nvidia".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the binding resolves"),
    );
    assert!(
        matches!(denied, Err(ProviderError::CredentialAbsent { .. })),
        "a keyless lookup denies before any wire leg: {denied:?}"
    );
    drop_blocking(provider);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "an absent scope opens no listing request"
    );

    // a failed listing keeps its typed denial
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&nvidia_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_nvidia_provider(&config);
    let (provider, failed) = catalog_on_thread(provider);
    let err = failed.expect_err("a failed listing has no floor to answer");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the failed listing is the typed transport denial: {err:?}")
    };
    assert_eq!(connection, "nvidia");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 503 },
        "the failed listing keeps its typed denial: {cause}"
    );
    drop_blocking(provider);
}

/// The recorded login validation is optional
/// (`validate ... optional=#true`): a real auth rejection is fatal,
/// while any other non-success answer proves neither access nor
/// denial. Offline the adapter constructs no login probe; a model
/// request answering `401`/`403` is the typed hard denial, and a `503`
/// — even beside a `/models` 200 naming the model — stays a typed
/// denial with no outcome and no access claim.
#[tokio::test]
async fn nvidia_optional_validation_proves_no_access() {
    for status in [401_u16, 403_u16] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(status).set_body_string(format!(
                "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
            )))
            .mount(&server)
            .await;
        let config =
            Config::parse_validated(&nvidia_config(&server_uri_v1(&server))).expect("valid");
        let (provider, _store) = enrolled_nvidia_provider(&config);
        let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
        let err = outcome.expect_err("a real auth rejection is the hard denial");
        let ProviderError::Transport { connection, cause } = &err else {
            panic!("a {status} validation answer is the typed transport denial: {err:?}")
        };
        assert_eq!(connection, "nvidia");
        assert!(
            cause.class() == TransportClass::HttpStatus { code: status },
            "the hard denial carries the peer's status: {cause}"
        );
        assert_no_secret_or_body(&err, NVIDIA_KEY.as_bytes());
        drop_blocking(provider);
        let requests = server.received_requests().await.expect("recorded");
        assert_eq!(requests.len(), 1, "the validation request is the one leg");
        assert_eq!(
            received_auth(&requests[0]),
            format!("Bearer {NVIDIA_KEY}"),
            "the admitted bearer reached the wire — the denial is the peer's status"
        );
    }

    // a non-auth validation failure proves neither access nor denial:
    // a `/models` 200 naming the pinned id is no access claim, and the
    // `503` is never converted into a successful outcome
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": NVIDIA_MODEL})]).await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(503).set_body_string("validation unavailable"))
        .mount(&server)
        .await;
    let config = Config::parse_validated(&nvidia_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_nvidia_provider(&config);
    let (provider, listed) = catalog_on_thread(provider);
    let models = listed.expect("the 200 listing answers");
    assert_eq!(
        model_ids(&models),
        [NVIDIA_MODEL],
        "the listing offers the model but proves no access"
    );
    let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
    let err = outcome.expect_err("a non-auth validation failure is never a success");
    let ProviderError::Transport { connection, cause } = &err else {
        panic!("the optional failure keeps the typed transport denial: {err:?}")
    };
    assert_eq!(connection, "nvidia");
    assert!(
        cause.class() == TransportClass::HttpStatus { code: 503 },
        "the non-auth failure proves neither access nor denial: {cause}"
    );
    drop_blocking(provider);
}

// ----- TP-PROVIDER-AUTH::nvidia ----------------------------------------------

/// Wrong credential/profile/region never produce a false success for
/// `nvidia`, through the same shared construction its siblings use: a
/// configured `region` — the recorded contract names none — denies
/// `RegionMismatch` with the connection context, a profile-bound ref
/// whose scope disagrees with the binding denies
/// `CredentialProfileMismatch`, an absent credential denies
/// `CredentialAbsent`, and a real auth rejection (`401`) is the typed
/// hard denial. None of the denials, nor any Debug surface the
/// boundary exposes, renders the offered credential material or the
/// peer's body. The recorded `NVIDIA_API_KEY` env spelling is refused
/// at ingress, so no env path substitutes the binding; a
/// `subscription`-kind declaration names a live grant, never this
/// api-key class's binding (DEC-010).
#[tokio::test]
async fn nvidia_wrong_credential_profile_or_region_denies_with_typed_context_without_secrets() {
    // the recorded env spelling names no admitted store class, and
    // the refusal never echoes the value
    let refused = nvidia_config("http://127.0.0.1:1/v1").replace(
        &format!("credential_ref = \"{NVIDIA_REF}\""),
        "credential_ref = \"env:NVIDIA_API_KEY\"",
    );
    let Err(error) = Config::parse_validated(&refused) else {
        panic!("an env credential reference is refused at ingress")
    };
    assert!(
        matches!(&error.issue, ConfigIssue::UnsupportedCredentialStore { store } if store == "env"),
        "an env spelling is refused as an unadmitted store class: {error}"
    );
    assert!(
        !error.to_string().contains("env:NVIDIA_API_KEY"),
        "the refusal never echoes the credential value: {error}"
    );

    // a configured region is denied — the contract records none
    let server = MockServer::start().await;
    let regioned = Config::parse_validated(
        &nvidia_config(&server_uri_v1(&server))
            .replace("kind = \"api_key\"", "kind = \"api_key\"\nregion = \"eu\""),
    )
    .expect("valid");
    let err = provider_result(
        regioned,
        "nvidia".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, NVIDIA_KEY)],
        )),
    )
    .expect_err("a configured region is denied, never ignored");
    let ProviderError::RegionMismatch { connection, region } = &err else {
        panic!("a configured region is RegionMismatch: {err:?}")
    };
    assert_eq!(connection, "nvidia");
    assert_eq!(region, "eu");
    assert_no_secret_or_body(&err, NVIDIA_KEY.as_bytes());

    // a profile binding whose ref scope names another profile
    let mismatched = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.nvidia]\nkind = \"api_key\"\nendpoint = \"{}\"\ncredential_ref = \"keyring:rivect-test/work\"\nprofile = \"work\"\n\
         [profiles.work]\ncredential_ref = \"keyring:rivect-test/personal\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"nvidia\", model_id = \"{NVIDIA_MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"high\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        server_uri_v1(&server)
    ))
    .expect("config parses");
    let err = provider_result(
        mismatched,
        "nvidia".to_string(),
        Arc::new(support::MapStore::seeded(
            STORE_KIND,
            &[(NEIGHBOR_REF, NVIDIA_KEY)],
        )),
    )
    .expect_err("a divergent scope is a profile mismatch");
    assert!(matches!(
        &err,
        ProviderError::CredentialProfileMismatch { .. }
    ));
    assert_no_secret_or_body(&err, NVIDIA_KEY.as_bytes());

    // an absent credential is the typed denial before any wire leg
    let config = Config::parse_validated(&nvidia_config(&server_uri_v1(&server))).expect("valid");
    let (provider, denied) = send_on_thread(
        provider_result(
            config.clone(),
            "nvidia".to_string(),
            Arc::new(support::MapStore::seeded(STORE_KIND, &[])),
        )
        .expect("the binding resolves"),
        prepared_manifest(&config),
    );
    assert!(matches!(
        denied,
        Err(ProviderError::CredentialAbsent { .. })
    ));
    drop_blocking(provider);

    // a refused key is a typed transport denial: the wire never
    // coerces a wrong credential into success, the peer's body never
    // enters the error, and the admitted bearer is absent from the
    // rendered denial — a real auth rejection is fatal for either
    // status the recorded validation names
    for status in [401_u16, 403_u16] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(status).set_body_string(format!(
                "{{\"error\": {{\"message\": \"denied {BODY_MARKER}\"}}}}"
            )))
            .mount(&server)
            .await;
        let config =
            Config::parse_validated(&nvidia_config(&server_uri_v1(&server))).expect("valid");
        let (provider, _store) = enrolled_nvidia_provider(&config);
        let (provider, outcome) = send_on_thread(provider, prepared_manifest(&config));
        let err = outcome.expect_err("a refused key is a typed transport denial");
        let ProviderError::Transport { connection, cause } = &err else {
            panic!("a {status} refusal is the typed transport denial: {err:?}")
        };
        assert_eq!(connection, "nvidia");
        assert!(
            cause.class() == TransportClass::HttpStatus { code: status },
            "the status code is the context: {cause}"
        );
        assert_no_secret_or_body(&err, NVIDIA_KEY.as_bytes());
        drop_blocking(provider);
        let requests = server.received_requests().await.expect("recorded");
        assert_eq!(requests.len(), 1, "the refusal is the one request leg");
        assert_eq!(
            received_auth(&requests[0]),
            format!("Bearer {NVIDIA_KEY}"),
            "the admitted bearer reached the wire — the denial is the peer's status"
        );
    }

    // a subscription-kind declaration is offline-ineligible: the
    // recorded class is the api_key binding, never a live-grant form
    // the provider could prepare (DEC-010)
    let subscription = Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.nvidia]\nkind = \"subscription\"\nendpoint = \"https://integrate.api.nvidia.com/v1\"\ncredential_ref = \"keyring:rivect-test/nvidia-plan\"\n\
         [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"nvidia\", model_id = \"{NVIDIA_MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"auto\" }}\n"
    ))
    .expect("a subscription declaration parses");
    assert!(
        !rivect::providers::offline_usable(
            &subscription.connections,
            &subscription.profiles,
            "nvidia",
        ),
        "a subscription declaration never becomes this api-key binding"
    );
}

// ----- TP-PROVIDER-RECOVERY::nvidia ------------------------------------------

/// A typed denial is recoverable through the same seam: material the
/// store resolves but the class cannot use — non-UTF-8 bytes can never
/// be a bearer token — denies typed, and the same provider admits the
/// recorded key once the scope is enrolled, sending exactly one
/// request with that material.
#[tokio::test]
async fn nvidia_typed_denial_recovers_through_the_same_credential_seam() {
    let server = MockServer::start().await;
    mount_chat(
        &server,
        completed_stream(
            "recovered",
            Some(json!({"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4})),
        ),
    )
    .await;
    let config = Config::parse_validated(&nvidia_config(&server_uri_v1(&server))).expect("valid");
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    store.enroll(NVIDIA_REF, &[0xff, 0xfe]);
    let provider = provider_result(config.clone(), "nvidia".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);

    let (provider, denied) = send_on_thread(provider, manifest.clone());
    assert!(
        matches!(denied, Err(ProviderError::CredentialMalformed { .. })),
        "non-UTF-8 material is the typed malformed denial: {denied:?}"
    );

    store.enroll(NVIDIA_REF, NVIDIA_KEY.as_bytes());
    let (provider, outcome) = send_on_thread(provider, manifest);
    let reply = outcome.expect("the recorded key admits the retry");
    assert_eq!(reply.text, "recovered");
    drop_blocking(provider);
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        1,
        "only the recovered send reaches the wire"
    );
    assert_eq!(
        received_auth(&requests[0]),
        format!("Bearer {NVIDIA_KEY}"),
        "the recovered material bears the wire"
    );
}

/// The legs matrix enforces the recorded expected set for `nvidia`:
/// CATALOG, AUTH, WIRE and RECOVERY each execute and report inside
/// this run, and INSTALLED reports NOT_RUN — an omitted leg fails the
/// suite rather than silently absenting.
#[tokio::test]
async fn nvidia_provider_legs_matrix_executes_all_expected_legs() {
    emit_provider_rows("nvidia");
    use std::collections::BTreeMap;
    let server = MockServer::start().await;
    mount_models(&server, vec![json!({"id": NVIDIA_MODEL})]).await;
    mount_chat(
        &server,
        completed_stream(
            "matrix",
            Some(json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})),
        ),
    )
    .await;
    let config = Config::parse_validated(&nvidia_config(&server_uri_v1(&server))).expect("valid");
    let mut reported = BTreeMap::new();

    // CATALOG: the keyed listing answers the recorded rows under one
    // `/models` leg bearing the scoped material.
    let (provider, _store) = enrolled_nvidia_provider(&config);
    let (provider, listed) = catalog_on_thread(provider);
    let listed = listed.expect("catalog answers");
    let discovery = server.received_requests().await.expect("recorded");
    reported.insert(
        "CATALOG",
        if listed.iter().any(|model| model.id == NVIDIA_MODEL)
            && discovery.len() == 1
            && discovery[0].url.path() == "/v1/models"
            && received_auth(&discovery[0]) == format!("Bearer {NVIDIA_KEY}")
        {
            "PASS"
        } else {
            "FAIL"
        },
    );
    drop_blocking(provider);

    // AUTH: an absent binding denies at the credential seam.
    let absent = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider =
        provider_result(config.clone(), "nvidia".to_string(), absent).expect("binding resolves");
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
        let (provider, _store) = enrolled_nvidia_provider(&config);
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/nvidia", "goal: matrix wire")
            .expect("the pin prepares");
        (broker, manifest)
    };
    let (broker, outcome) = dispatch(broker, "/world/nvidia", manifest);
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
    let store = Arc::new(support::MapStore::seeded(STORE_KIND, &[]));
    let provider = provider_result(config.clone(), "nvidia".to_string(), store.clone())
        .expect("binding resolves");
    let manifest = prepared_manifest(&config);
    let (provider, denied) = send_on_thread(provider, manifest.clone());
    let denied_ok = matches!(denied, Err(ProviderError::CredentialAbsent { .. }));
    store.enroll(NVIDIA_REF, NVIDIA_KEY.as_bytes());
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

    // The row restates the `#[ignore]`d `provider_installed_nvidia`
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

// ----- TP-PROVIDER-INSTALLED::nvidia -----------------------------------------

/// TP-PROVIDER-INSTALLED::nvidia = NOT_RUN: the installed-provider
/// proof is a live-environment leg this offline slice never runs.
#[test]
#[ignore = "installed-provider proof is out of scope for the offline gate — TP-PROVIDER-INSTALLED::nvidia = NOT_RUN"]
fn provider_installed_nvidia() {}
