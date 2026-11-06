//! Offline GitLab Duo Agent (DWS) proof: the recorded REST setup
//! chain, the WebSocket workflow stream over a loopback peer, the idle
//! reconnect, the bounded fresh-workflow restarts, and the denial legs
//! that never reach a wire. One loopback peer per leg; no live account
//! and no recorded frame from a real workflow.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/discard conveniences and block-wise fixture assembly; src/ stays strict (standards §14)"
)]

use rivect::config::Config;
use rivect::model::{Broker, ModelError, NullLedger, RequestManifest};
use rivect::providers::gitlab_workflow::{
    GITLAB_DUO_WORKFLOW_DEADLINE, GITLAB_DUO_WORKFLOW_IDLE, GitlabWorkflowProvider, WorkflowBudget,
};
use rivect::providers::{CredentialStore, ProviderError, StoreKind, ToolCall, TransportClass};
use rivect::resources::UsageDelta;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

mod support;

use support::ws_peer::{
    PROFILE_TOKEN, PROJECT_ID, PeerRequest, PeerScript, SocketScript, WORKFLOW_TOKEN, WsPeer,
};
use support::{CountingLedger, MapStore, drop_blocking, prepared_with};

const CONNECTION: &str = "gitlab-duo-agent";
const REF: &str = "keyring:rivect-test/gitlab-duo-agent";
const WORLD: &str = "/world/gitlab-duo-agent";
const MODEL: &str = "duo-chat-sonnet-4-6";
const NAMESPACE: &str = "acme/platform";
const PROJECT: &str = "acme/platform/app";
const GOAL: &str = "goal: one workflow";
const DIRECT_ACCESS_PATH: &str = "/api/v4/ai/duo_workflows/direct_access";
const WORKFLOWS_PATH: &str = "/api/v4/ai/duo_workflows/workflows";
const WS_PATH: &str = "/api/v4/ai/duo_workflows/ws";

/// One provider config: the literal id at `endpoint` with scoped
/// material, and the fixed pin the tests dispatch.
fn config_for(endpoint: &str) -> Config {
    Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.\"{CONNECTION}\"]\n\
         kind = \"api_key\"\n\
         endpoint = \"{endpoint}\"\n\
         credential_ref = \"{REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n\
         [models.purposes.main]\n\
         model = {{ mode = \"fixed\", connection = \"{CONNECTION}\", model_id = \"{MODEL}\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the gitlab-duo-agent fixture config validates")
}

/// The stored workspace profile [`gitlab_agent_login`] writes: the PAT
/// form with the operator's origin, namespace and project.
fn stored_profile(origin: &str, project: Option<&str>) -> String {
    let mut profile = json!({
        "kind": "pat",
        "access_token": PROFILE_TOKEN,
        "origin": origin,
        "namespace": NAMESPACE,
    });
    if let Some(project) = project {
        profile["project"] = json!(project);
    }
    profile.to_string()
}

/// One loopback peer, its admitted config and the seeded store.
struct Fixture {
    peer: WsPeer,
    config: Config,
    store: Arc<MapStore>,
}

fn peer_fixture(script: PeerScript) -> Fixture {
    let peer = WsPeer::start(script);
    let config = config_for(peer.base());
    let store = Arc::new(MapStore::seeded(
        StoreKind::Keychain,
        &[(REF, &stored_profile(peer.base(), Some(PROJECT)))],
    ));
    Fixture {
        peer,
        config,
        store,
    }
}

/// Dispatches through the real Broker: the admitted pin, the one entered
/// send and its settlement row.
fn dispatch(
    fixture: &Fixture,
    idle: Duration,
    budget: WorkflowBudget,
) -> (Broker, RequestManifest) {
    let store: Arc<dyn CredentialStore> = fixture.store.clone();
    let provider = GitlabWorkflowProvider::with_limits(
        &fixture.config,
        CONNECTION,
        store,
        Duration::from_secs(30),
        idle,
        budget,
    )
    .expect("the loopback base is admitted");
    prepared_with(
        (provider, Arc::clone(&fixture.store)),
        &fixture.config,
        WORLD,
        GOAL,
    )
}

/// One checkpoint snapshot carrying the given `ui_chat_log` entries.
fn snapshot(entries: Value) -> String {
    json!({ "channel_values": { "ui_chat_log": entries } }).to_string()
}

/// A frame carrying the goal request and one agent answer.
fn answer_frame(status: &str, text: &str) -> String {
    let entries = json!([
        { "message_type": "request", "content": "goal" },
        { "message_type": "agent", "message_id": "m1", "content": text },
    ]);
    json!({ "status": status, "newCheckpoint": snapshot(entries) }).to_string()
}

/// A frame whose snapshot ends on a tool boundary — the shape the stall
/// signal compares.
fn boundary_frame() -> String {
    let entries = json!([
        { "message_type": "request", "content": "goal" },
        { "message_type": "tool", "content": "read" },
    ]);
    json!({ "status": "RUNNING", "newCheckpoint": snapshot(entries) }).to_string()
}

fn step_limit_frame() -> String {
    json!({
        "status": "FAILED",
        "message": "The workflow reached its maximum step limit and could not complete.",
    })
    .to_string()
}

fn action_frame(request_id: Option<&str>) -> String {
    let mut action = json!({
        "name": "runMCPTool",
        "args": { "toolName": "mcp__omp__read", "args": { "path": "src/main.rs" } },
    });
    if let Some(request_id) = request_id {
        action["requestID"] = json!(request_id);
    }
    json!({ "action": action }).to_string()
}

fn upgrade(requests: &[PeerRequest]) -> &PeerRequest {
    requests
        .iter()
        .find(|request| request.target.contains(WS_PATH))
        .expect("the workflow socket upgrade")
}

fn rest<'a>(requests: &'a [PeerRequest], method: &str, path: &str) -> &'a PeerRequest {
    requests
        .iter()
        .find(|request| request.method == method && request.path() == path)
        .unwrap_or_else(|| panic!("the {method} {path} leg"))
}

fn body(request: &PeerRequest) -> Value {
    serde_json::from_str(&request.body).expect("the recorded setup body is json")
}

#[test]
fn dispatch_returns_one_validated_outcome_and_one_accounting_record() {
    let fixture = peer_fixture(PeerScript {
        sockets: vec![SocketScript {
            frames: vec![
                answer_frame("RUNNING", "Hello "),
                answer_frame("FINISHED", "Hello world"),
            ],
            close: true,
        }],
        silent: false,
    });
    let (mut broker, manifest) =
        dispatch(&fixture, Duration::from_secs(5), WorkflowBudget::recorded());
    let reply = broker
        .dispatch(&mut NullLedger, WORLD, &manifest)
        .expect("the recorded stream finishes");
    assert_eq!(
        reply.text, "Hello world",
        "the replayed checkpoint snapshot must extend the reply, not repeat it"
    );
    assert!(reply.tool_calls.is_empty());
    assert_eq!(reply.usage, UsageDelta::Unknown);
    assert_eq!(reply.wire_retries, 0, "one socket answered this send");
    assert_eq!(
        broker.accounted_requests(),
        1,
        "one entered send is one accounting record"
    );
    assert_eq!(fixture.peer.creates(), 1);
    assert_eq!(fixture.peer.sockets(), 1);

    let requests = fixture.peer.requests();
    let lookup = rest(&requests, "GET", "/api/v4/projects/acme%2Fplatform%2Fapp");
    assert_eq!(
        lookup.headers.get("authorization"),
        Some(&format!("Bearer {}", PROFILE_TOKEN)),
        "the project lookup spends the workspace PAT, never the workflow token"
    );
    let direct = body(rest(&requests, "POST", DIRECT_ACCESS_PATH));
    assert_eq!(direct["workflow_definition"], "ambient");
    assert_eq!(direct["root_namespace_id"], NAMESPACE);
    assert_eq!(
        direct["project_id"], PROJECT,
        "the setup legs carry the recorded project path, not the socket's numeric id"
    );
    let create = body(rest(&requests, "POST", WORKFLOWS_PATH));
    assert_eq!(create["workflow_definition"], "ambient");
    assert_eq!(create["environment"], "ide");
    assert_eq!(create["project_id"], PROJECT);
    assert_eq!(create["goal"], "");
    assert_eq!(create["agent_privileges"], json!([6]));

    let socket = upgrade(&requests);
    let host = socket
        .headers
        .get("host")
        .expect("the upgrade carries the host header");
    let target = format!("ws://{host}{}", socket.target);
    let url = reqwest::Url::parse(&target).expect("the upgrade target is a URL");
    assert_eq!(
        url.scheme(),
        "ws",
        "a loopback peer is the admitted ws form"
    );
    assert_eq!(url.path(), WS_PATH);
    assert_eq!(url.fragment(), None, "the socket URL carries no fragment");
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    assert_eq!(
        pairs,
        vec![
            ("project_id".to_string(), PROJECT_ID.to_string()),
            ("namespace_id".to_string(), NAMESPACE.to_string()),
        ],
        "the query carries exactly the numeric project id and the namespace"
    );
    assert_eq!(
        socket.headers.get("authorization"),
        Some(&format!("Bearer {}", WORKFLOW_TOKEN)),
        "the socket authenticates with the exchanged workflow token"
    );
    assert_eq!(
        socket
            .headers
            .get("x-gitlab-client-type")
            .map(String::as_str),
        Some("node-websocket")
    );
    assert_eq!(
        socket
            .headers
            .get("x-gitlab-language-server-version")
            .map(String::as_str),
        Some("8.104.0")
    );
    assert_eq!(
        socket.headers.get("user-agent").map(String::as_str),
        Some("unknown/unknown unknown/unknown gitlab-language-server/8.104.0")
    );
    assert_eq!(
        socket.headers.get("origin").map(String::as_str),
        Some(fixture.peer.base()),
        "the origin header is the admitted base"
    );
    assert_eq!(
        socket
            .headers
            .get("x-gitlab-project-id")
            .map(String::as_str),
        Some(PROJECT_ID)
    );
    assert_eq!(
        socket
            .headers
            .get("x-gitlab-namespace-id")
            .map(String::as_str),
        Some(NAMESPACE)
    );
    assert_eq!(
        socket
            .headers
            .get("x-gitlab-root-namespace-id")
            .map(String::as_str),
        Some(NAMESPACE)
    );

    let start = fixture.peer.start_frames();
    assert_eq!(start.len(), 1);
    let start = &start[0]["startRequest"];
    assert_eq!(start["workflowID"], "4242");
    assert_eq!(start["workflowDefinition"], "ambient");
    assert_eq!(start["flowConfigSchemaVersion"], "v1");
    assert_eq!(start["goal"], manifest.inputs);
    assert_eq!(
        start["preapproved_tools"].as_array().map(Vec::len),
        Some(manifest.tools.len())
    );
    let metadata: Value = serde_json::from_str(
        start["workflowMetadata"]
            .as_str()
            .expect("workflowMetadata is the recorded string form"),
    )
    .expect("the workflow metadata is json");
    assert_eq!(metadata["projectId"], PROJECT_ID);
    assert_eq!(metadata["namespaceId"], NAMESPACE);
    assert_eq!(metadata["selectedModelIdentifier"], MODEL);
    drop_blocking(broker);
}

#[test]
fn non_default_base_is_admitted_under_the_credential_base_rule() {
    // The denied leg: a profile enrolled for another instance can never
    // reach this base, and the refusal lands before any request.
    let fixture = peer_fixture(PeerScript::default());
    let store = Arc::new(MapStore::seeded(
        StoreKind::Keychain,
        &[(REF, &stored_profile("https://gitlab.com", Some(PROJECT)))],
    ));
    let credential_store: Arc<dyn CredentialStore> = store.clone();
    let provider = GitlabWorkflowProvider::with_limits(
        &fixture.config,
        CONNECTION,
        credential_store,
        Duration::from_secs(30),
        Duration::from_secs(5),
        WorkflowBudget::recorded(),
    )
    .expect("the base itself is admitted");
    let (mut broker, manifest) = prepared_with((provider, store), &fixture.config, WORLD, GOAL);
    let error = broker
        .dispatch(&mut NullLedger, WORLD, &manifest)
        .expect_err("an enrolled-elsewhere profile denies");
    let ModelError::Provider(source) = &error else {
        panic!("expected ModelError::Provider: {error}");
    };
    assert!(
        matches!(
            source,
            ProviderError::CredentialBaseMismatch { connection, enrolled }
                if connection == CONNECTION && enrolled.as_str() == "https://gitlab.com/"
        ),
        "the base rule names the enrolled origin: {source}"
    );
    assert!(
        fixture.peer.requests().is_empty(),
        "the denied credential crosses no wire"
    );
    drop_blocking(broker);

    // The admitted leg: the same shape enrolled for this base streams and
    // opens the socket at exactly the recorded path and query.
    let fixture = peer_fixture(PeerScript {
        sockets: vec![SocketScript {
            frames: vec![answer_frame("FINISHED", "admitted base")],
            close: true,
        }],
        silent: false,
    });
    let (mut broker, manifest) =
        dispatch(&fixture, Duration::from_secs(5), WorkflowBudget::recorded());
    let reply = broker
        .dispatch(&mut NullLedger, WORLD, &manifest)
        .expect("the matching origin is admitted");
    assert_eq!(reply.text, "admitted base");
    let requests = fixture.peer.requests();
    let socket = upgrade(&requests);
    let authority = fixture
        .peer
        .base()
        .trim_start_matches("http://")
        .to_string();
    assert_eq!(
        socket.headers.get("host").map(String::as_str),
        Some(authority.as_str()),
        "the socket targets the admitted base"
    );
    assert_eq!(
        socket.target.split('?').next(),
        Some(WS_PATH),
        "the socket keeps the recorded path"
    );
    drop_blocking(broker);
}

#[test]
fn default_deadline_is_the_recorded_workflow_budget() {
    assert_eq!(
        GITLAB_DUO_WORKFLOW_DEADLINE,
        Duration::from_secs(1920),
        "12 × (2 × 30 s REST + 90 s idle) + 3 × 30 s setup + 30 s margin"
    );
    assert_eq!(
        GITLAB_DUO_WORKFLOW_IDLE,
        Duration::from_secs(90),
        "the recorded socket idle window"
    );
    assert_eq!(
        WorkflowBudget::recorded(),
        WorkflowBudget {
            outer_attempts: 12,
            step_limit: 4,
            stall: 2,
            generic: 1,
        },
        "12 outer attempts with 4 step-limit, 2 stall and 1 generic restart"
    );
    assert_eq!(WorkflowBudget::default(), WorkflowBudget::recorded());
}

#[test]
fn silent_handshake_is_a_typed_timeout_with_one_settlement_row() {
    let fixture = peer_fixture(PeerScript {
        sockets: Vec::new(),
        silent: true,
    });
    let (mut broker, manifest) = dispatch(
        &fixture,
        Duration::from_millis(400),
        WorkflowBudget::recorded(),
    );
    let mut ledger = CountingLedger::new();
    let error = broker
        .dispatch(&mut ledger, WORLD, &manifest)
        .expect_err("a peer that never answers the upgrade is a typed timeout");
    let ModelError::Provider(source) = &error else {
        panic!("expected ModelError::Provider: {error}");
    };
    let ProviderError::Transport { connection, cause } = source else {
        panic!("expected the transport class: {source}");
    };
    assert_eq!(connection, CONNECTION);
    assert_eq!(
        cause.class(),
        TransportClass::Timeout,
        "the silent handshake surfaces as the timeout class"
    );
    assert_eq!(ledger.begun, 1, "the entered send opens one settlement row");
    assert_eq!(
        ledger.finished, 1,
        "the failed send closes the row it opened"
    );
    assert_eq!(ledger.failed, 1, "the row settles as failed");
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a send that produced no reply opens no accounting record"
    );
    assert_eq!(fixture.peer.sockets(), 0, "no socket ever upgraded");
    drop_blocking(broker);
}

#[test]
fn idle_death_reconnects_once_on_the_same_workflow_id() {
    let fixture = peer_fixture(PeerScript {
        sockets: vec![
            SocketScript::default(),
            SocketScript {
                frames: vec![answer_frame("FINISHED", "reconnected")],
                close: true,
            },
        ],
        silent: false,
    });
    let (mut broker, manifest) = dispatch(
        &fixture,
        Duration::from_millis(500),
        WorkflowBudget::recorded(),
    );
    let reply = broker
        .dispatch(&mut NullLedger, WORLD, &manifest)
        .expect("the reconnect resumes the same workflow");
    assert_eq!(reply.text, "reconnected");
    assert_eq!(reply.wire_retries, 1, "the reconnect is the one retry");
    assert_eq!(fixture.peer.sockets(), 2, "one reconnect, one socket");
    assert_eq!(
        fixture.peer.creates(),
        1,
        "the reconnect reuses the workflow id instead of creating another"
    );
    let start = fixture.peer.start_frames();
    assert_eq!(start.len(), 2);
    assert_eq!(start[0]["startRequest"]["workflowID"], "4242");
    assert_eq!(
        start[1]["startRequest"]["workflowID"], "4242",
        "both sockets carry the same workflow id"
    );
    drop_blocking(broker);
}

#[test]
fn step_limit_restarts_are_bounded_by_the_outer_budget() {
    let fixture = peer_fixture(PeerScript {
        sockets: vec![SocketScript {
            frames: vec![step_limit_frame()],
            close: true,
        }],
        silent: false,
    });
    let (mut broker, manifest) =
        dispatch(&fixture, Duration::from_secs(5), WorkflowBudget::recorded());
    let error = broker
        .dispatch(&mut NullLedger, WORLD, &manifest)
        .expect_err("four restarts then the typed stop");
    let ModelError::Provider(source) = &error else {
        panic!("expected ModelError::Provider: {error}");
    };
    assert!(
        matches!(
            source,
            ProviderError::ProviderFailed { connection, reason }
                if connection == CONNECTION && reason == "the workflow reached its maximum step limit"
        ),
        "the exhausted budget surfaces the recorded reason: {source}"
    );
    assert_eq!(
        fixture.peer.sockets(),
        5,
        "the first attempt plus the four recorded restarts"
    );
    assert_eq!(
        fixture.peer.creates(),
        5,
        "every restart asks for a fresh workflow"
    );
    let stops = fixture
        .peer
        .requests()
        .into_iter()
        .filter(|request| request.method == "PATCH")
        .count();
    assert_eq!(stops, 4, "each abandoned workflow is stopped once");
    drop_blocking(broker);
}

#[test]
fn stall_restarts_are_bounded_by_the_stall_cap() {
    let fixture = peer_fixture(PeerScript {
        sockets: vec![SocketScript {
            frames: vec![boundary_frame(), boundary_frame()],
            close: false,
        }],
        silent: false,
    });
    let (mut broker, manifest) = dispatch(
        &fixture,
        Duration::from_secs(5),
        WorkflowBudget {
            outer_attempts: 12,
            step_limit: 4,
            stall: 1,
            generic: 1,
        },
    );
    let error = broker
        .dispatch(&mut NullLedger, WORLD, &manifest)
        .expect_err("a byte-identical boundary stops the run");
    let ModelError::Provider(source) = &error else {
        panic!("expected ModelError::Provider: {error}");
    };
    assert!(
        matches!(
            source,
            ProviderError::ProviderFailed { reason, .. }
                if reason == "the workflow's visible history stopped advancing"
        ),
        "the stall cap surfaces the recorded reason: {source}"
    );
    assert_eq!(
        fixture.peer.creates(),
        2,
        "one restart inside the stall cap, then the typed stop"
    );
    drop_blocking(broker);
}

#[test]
fn a_partial_action_or_unknown_terminal_is_never_success() {
    // An action the seam cannot hand on: no request id means no tool call.
    let fixture = peer_fixture(PeerScript {
        sockets: vec![SocketScript {
            frames: vec![action_frame(None)],
            close: true,
        }],
        silent: false,
    });
    let (mut broker, manifest) =
        dispatch(&fixture, Duration::from_secs(5), WorkflowBudget::recorded());
    let error = broker
        .dispatch(&mut NullLedger, WORLD, &manifest)
        .expect_err("a partial action is not a success");
    let ModelError::Provider(source) = &error else {
        panic!("expected ModelError::Provider: {error}");
    };
    assert!(
        matches!(
            source,
            ProviderError::StreamViolation { connection, reason }
                if connection == CONNECTION && reason == "the workflow action carries no request id"
        ),
        "the partial descriptor is a stream violation: {source}"
    );
    drop_blocking(broker);

    // A socket that closes with no terminal verdict is unknown, never a
    // silent success.
    let fixture = peer_fixture(PeerScript {
        sockets: vec![SocketScript {
            frames: Vec::new(),
            close: true,
        }],
        silent: false,
    });
    let (mut broker, manifest) =
        dispatch(&fixture, Duration::from_secs(5), WorkflowBudget::recorded());
    let error = broker
        .dispatch(&mut NullLedger, WORLD, &manifest)
        .expect_err("a close without a terminal is unknown");
    let ModelError::Provider(source) = &error else {
        panic!("expected ModelError::Provider: {error}");
    };
    assert!(
        matches!(
            source,
            ProviderError::UnknownTerminal { connection } if connection == CONNECTION
        ),
        "an unclassifiable close stays unknown: {source}"
    );
    drop_blocking(broker);
}

#[test]
fn an_action_hands_back_the_recorded_tool_call() {
    let fixture = peer_fixture(PeerScript {
        sockets: vec![SocketScript {
            frames: vec![action_frame(Some("req-7"))],
            close: true,
        }],
        silent: false,
    });
    let (mut broker, manifest) =
        dispatch(&fixture, Duration::from_secs(5), WorkflowBudget::recorded());
    let reply = broker
        .dispatch(&mut NullLedger, WORLD, &manifest)
        .expect("the recorded action is a tool call");
    assert_eq!(
        reply.tool_calls,
        vec![ToolCall {
            tool: "read".to_string(),
            path: Some("src/main.rs".to_string()),
        }],
        "the MCP action maps to the bare tool name and its path argument"
    );
    assert_eq!(reply.text, "");
    assert_eq!(broker.accounted_requests(), 1);
    drop_blocking(broker);
}

#[test]
fn a_wrong_profile_denies_typed_with_zero_requests() {
    let fixture = peer_fixture(PeerScript::default());
    let store = Arc::new(MapStore::seeded(
        StoreKind::Keychain,
        &[(REF, "{\"token\":\"not-a-workspace-profile\"}")],
    ));
    let credential_store: Arc<dyn CredentialStore> = store.clone();
    let provider = GitlabWorkflowProvider::with_limits(
        &fixture.config,
        CONNECTION,
        credential_store,
        Duration::from_secs(30),
        Duration::from_secs(5),
        WorkflowBudget::recorded(),
    )
    .expect("the base itself is admitted");
    let (mut broker, manifest) = prepared_with((provider, store), &fixture.config, WORLD, GOAL);
    let error = broker
        .dispatch(&mut NullLedger, WORLD, &manifest)
        .expect_err("a foreign credential class denies");
    let ModelError::Provider(source) = &error else {
        panic!("expected ModelError::Provider: {error}");
    };
    assert!(
        matches!(
            source,
            ProviderError::CredentialMalformed { connection } if connection == CONNECTION
        ),
        "the profile class is the typed denial: {source}"
    );
    assert!(
        fixture.peer.requests().is_empty(),
        "a profile the adapter cannot read crosses no wire"
    );
    drop_blocking(broker);
}

#[test]
fn a_plaintext_base_is_refused_by_config_ingress() {
    let document = format!(
        "config_version = 1\n\
         [connections.\"{CONNECTION}\"]\n\
         kind = \"api_key\"\n\
         endpoint = \"http://gitlab.example.invalid\"\n\
         credential_ref = \"{REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    );
    assert!(
        Config::parse_validated(&document).is_err(),
        "a plaintext non-loopback base never reaches an adapter"
    );
}
