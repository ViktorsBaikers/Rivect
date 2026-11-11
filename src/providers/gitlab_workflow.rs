//! The GitLab Duo Agent workflow (DWS) transport owner: the recorded
//! REST setup legs, the WebSocket workflow stream and the bounded
//! restart budget — one entered send, one settled outcome.
//!
//! The recorded contract is OMP's `providers/gitlab-duo-workflow.ts`
//! (`0133f7ff`, sha256 `05072ba5…`). The send reads the workspace
//! profile [`WorkspaceCredential`] once, resolves the numeric project id
//! only when the profile carries a project path, exchanges the profile
//! token for the workflow token at `…/duo_workflows/direct_access`,
//! creates the workflow at `…/duo_workflows/workflows`, and opens the
//! socket at `…/duo_workflows/ws?project_id=…&namespace_id=…` with the
//! source headers. Every REST fetch is bounded at 30 s by the request
//! timeout — the total for connect, send and the body — plus the leg
//! clock checked before each read; the clock alone would let an
//! in-flight read overrun. The socket is bounded by
//! [`GITLAB_DUO_WORKFLOW_IDLE`], and the whole send by the recorded
//! [`GITLAB_DUO_WORKFLOW_DEADLINE`].
//!
//! The WS target is the recorded `https://gitlab.com` base or the
//! operator's configured base, admitted only when the stored profile's
//! origin is that same base (`CredentialBaseMismatch` otherwise); `ws:`
//! reaches a loopback peer only, and no credential travels in the query
//! or a fragment. An idle or half-open socket reconnects once on the
//! same workflow id and then stops typed; a step-limit, stall or generic
//! terminal restarts a fresh workflow inside [`WorkflowBudget`], and a
//! partial action or unknown terminal is never success.

use super::gitlab_agent_login::WorkspaceCredential;
use super::{
    CredentialStore, Provider, ProviderError, ProviderReply, SecretRef, ToolCall, TransportCause,
    check_deadline, percent_encode_component, read_catalog_body, transport, transport_status,
    violation, wire_body,
};
use crate::config::{Config, ModelAssign};
use crate::model::RequestManifest;
use crate::resources::UsageDelta;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tungstenite::handshake::HandshakeError;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{ClientRequestBuilder, Message, WebSocket};

/// The whole-send budget: 12 outer attempts × (2 × 30 s REST + 90 s idle)
/// + 3 × 30 s setup + 30 s margin.
pub const GITLAB_DUO_WORKFLOW_DEADLINE: Duration = Duration::from_secs(1920);

/// The socket's idle deadline: no frame within this window means the
/// connection went half-open and is reconnected once on the same
/// workflow id.
pub const GITLAB_DUO_WORKFLOW_IDLE: Duration = Duration::from_secs(90);

/// The bound on each REST setup fetch.
const REST_TIMEOUT: Duration = Duration::from_secs(30);

/// The recorded instance base when the connection configures none.
const DEFAULT_BASE: &str = "https://gitlab.com";

const WS_PATH: &str = "/api/v4/ai/duo_workflows/ws";
const DIRECT_ACCESS_PATH: &str = "/api/v4/ai/duo_workflows/direct_access";
const WORKFLOWS_PATH: &str = "/api/v4/ai/duo_workflows/workflows";
const PROJECTS_PATH: &str = "/api/v4/projects/";

const WORKFLOW_DEFINITION: &str = "ambient";
const CLIENT_VERSION: &str = "1.0";
const CLIENT_TYPE: &str = "node-websocket";
const LANGUAGE_SERVER_VERSION: &str = "8.104.0";
const USER_AGENT: &str = "unknown/unknown unknown/unknown gitlab-language-server/8.104.0";
const CLIENT_CAPABILITIES: [&str; 5] = [
    "incremental_streaming",
    "read_file_chunked",
    "shell_command",
    "command_timeout",
    "tool_call_approval",
];
const AGENT_NAME: &str = "omp_agent";
const PROMPT_ID: &str = "omp_inline_prompt";
const UI_LOG_EVENTS: [&str; 4] = [
    "on_agent_reasoning",
    "on_agent_final_answer",
    "on_tool_execution_success",
    "on_tool_execution_failed",
];
/// The empty MCP input schema the frozen manifest can honestly declare:
/// it carries tool names, never their definitions.
const EMPTY_SCHEMA: &str = "{\"type\":\"object\",\"properties\":{},\"required\":[]}";

/// The stable clause of the server's graph-recursion cap message.
const STEP_LIMIT_CLAUSE: &str = "reached its maximum step limit";
/// The stable clause of the server's de-identified catch-all `FAILED`.
const GENERIC_CLAUSE: &str = "error processing your request in the duo agent platform";

/// The bounded fresh-workflow restart budget. Caps are per send, not per
/// frame: a restart spends one outer attempt and one class allowance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkflowBudget {
    /// The most sockets one send may open.
    pub outer_attempts: u32,
    /// Fresh-workflow restarts after the server's step limit.
    pub step_limit: u32,
    /// Fresh-workflow restarts after a stalled workflow.
    pub stall: u32,
    /// Fresh-workflow retries after the generic processing failure.
    pub generic: u32,
}

impl WorkflowBudget {
    /// The recorded budget: 12 / 4 / 2 / 1.
    #[must_use]
    pub const fn recorded() -> Self {
        Self {
            outer_attempts: 12,
            step_limit: 4,
            stall: 2,
            generic: 1,
        }
    }
}

impl Default for WorkflowBudget {
    fn default() -> Self {
        Self::recorded()
    }
}

/// The DWS adapter: one send is one REST setup chain plus a bounded
/// sequence of workflow sockets, so a restart never opens a second
/// settlement.
pub struct GitlabWorkflowProvider {
    connection: String,
    /// The admitted base URL, without a trailing slash.
    base: reqwest::Url,
    /// The base's canonical origin, compared against the stored profile.
    origin: String,
    reference: SecretRef,
    store: Arc<dyn CredentialStore>,
    client: reqwest::blocking::Client,
    deadline: Duration,
    idle: Duration,
    budget: WorkflowBudget,
}

impl std::fmt::Debug for GitlabWorkflowProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitlabWorkflowProvider")
            .field("connection", &self.connection)
            .field("base", &self.base.as_str())
            .field("deadline", &self.deadline)
            .field("idle", &self.idle)
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

/// How one socket ended.
enum SocketEnd {
    /// A recorded completion terminal with the text it accumulated.
    Reply(String),
    /// An action the workflow awaits: the turn's tool call.
    Action(ToolCall),
    /// No frame inside the idle window.
    Idle,
    /// The server reported its graph-recursion cap.
    StepLimit,
    /// The workflow's visible history stopped advancing.
    Stalled,
    /// The server's de-identified catch-all failure.
    Retryable(String),
}

/// One frame's verdict within a socket.
enum Frame {
    Continue,
    Terminal,
    Action(ToolCall),
    StepLimit,
    Stalled,
    Retryable(String),
}

/// The reply text one send accumulates across sockets. A checkpoint is a
/// full `ui_chat_log` snapshot, so a later frame replays earlier entries:
/// the per-key prefix and the per-turn content signature drop the replay
/// without dropping a genuinely new later message.
#[derive(Default)]
struct CheckpointState {
    text: String,
    content: BTreeMap<String, String>,
    signatures: BTreeSet<String>,
    turn: u32,
    /// Whether the last absorbed snapshot ends on a tool/request boundary.
    ends_at_boundary: bool,
    last_checkpoint_len: Option<usize>,
    last_boundary_len: Option<usize>,
}

impl CheckpointState {
    /// Absorbs one checkpoint snapshot's agent text. The recorded wire form
    /// is a serialized snapshot string, parsed once; an already-parsed
    /// object is borrowed directly instead of being serialized back. A
    /// snapshot without a readable `ui_chat_log` carries no text and is not
    /// a violation.
    fn absorb(&mut self, checkpoint: &Value) {
        match checkpoint {
            Value::String(text) => {
                self.last_checkpoint_len = Some(text.len());
                match serde_json::from_str::<Value>(text) {
                    Ok(parsed) => self.absorb_snapshot(&parsed),
                    Err(_parse) => self.ends_at_boundary = false,
                }
            }
            Value::Object(_) => {
                self.absorb_snapshot(checkpoint);
                // The serialized length is the comparable reading only when
                // the snapshot ends on a tool/request boundary, where the
                // stall signal consumes it; a non-boundary frame never pays
                // the serialization.
                self.last_checkpoint_len =
                    self.ends_at_boundary.then(|| checkpoint.to_string().len());
            }
            _ => self.ends_at_boundary = false,
        }
    }

    /// Absorbs one parsed snapshot's `ui_chat_log` entries.
    fn absorb_snapshot(&mut self, parsed: &Value) {
        let Some(entries) = parsed
            .get("channel_values")
            .and_then(|values| values.get("ui_chat_log"))
            .and_then(Value::as_array)
        else {
            self.ends_at_boundary = false;
            return;
        };
        self.ends_at_boundary = entries
            .last()
            .and_then(|entry| entry.get("message_type"))
            .and_then(Value::as_str)
            .is_some_and(|message_type| message_type == "request" || message_type == "tool");
        for (index, entry) in entries.iter().enumerate() {
            let Some(message_type) = entry.get("message_type").and_then(Value::as_str) else {
                continue;
            };
            if message_type == "request" || message_type == "tool" {
                self.turn += 1;
                continue;
            }
            if message_type != "agent" {
                continue;
            }
            // A `reasoning` sub-type is pre-tool-call commentary this seam
            // has no channel for; only answer text reaches the reply.
            if entry.get("message_sub_type").and_then(Value::as_str) == Some("reasoning") {
                continue;
            }
            let Some(content) = entry.get("content").and_then(Value::as_str) else {
                continue;
            };
            let key = entry
                .get("message_id")
                .and_then(Value::as_str)
                .map_or_else(|| format!("agent:{index}"), |id| format!("agent:{id}"));
            self.push(&key, content);
        }
    }

    /// Appends one agent message's delta: a replay of an already-seen key
    /// grows the text only by its newly emitted suffix, and a replayed
    /// snapshot position is dropped entirely. An unchanged entry returns
    /// before the signature string and the content copy, so replaying a full
    /// snapshot costs a comparison per entry, not a re-copy.
    fn push(&mut self, key: &str, content: &str) {
        if self
            .content
            .get(key)
            .is_some_and(|previous| previous.as_str() == content)
        {
            return;
        }
        let signature = format!("{}\u{0}{content}", self.turn);
        let duplicate = !self.content.contains_key(key) && self.signatures.contains(&signature);
        if !duplicate {
            match self.content.get(key) {
                Some(previous) => {
                    if let Some(growth) = content.strip_prefix(previous.as_str()) {
                        self.text.push_str(growth);
                    }
                }
                None => self.text.push_str(content),
            }
        }
        self.content.insert(key.to_string(), content.to_string());
        self.signatures.insert(signature);
    }

    /// Whether a snapshot that ends on a tool/request boundary repeated
    /// the previous boundary snapshot's byte length — the recorded stall
    /// signal. A checkpoint is a full snapshot, so a boundary that
    /// re-emits the same bytes is the server replaying a turn that never
    /// advanced. The first boundary has no comparable reading and a
    /// snapshot without a boundary never triggers.
    fn stalled(&mut self) -> bool {
        let Some(length) = self.last_checkpoint_len.filter(|_| self.ends_at_boundary) else {
            return false;
        };
        let previous = self.last_boundary_len;
        self.last_boundary_len = Some(length);
        previous.is_some_and(|previous| previous == length)
    }
}

impl GitlabWorkflowProvider {
    /// Builds the adapter under the recorded deadline, idle window and
    /// restart budget.
    ///
    /// # Errors
    /// [`ProviderError::UnknownConnection`] for an undeclared id,
    /// [`ProviderError::RegionMismatch`] for a configured region,
    /// [`ProviderError::UnsendableRequest`] for an unusable base, the
    /// credential seam's typed denials, and
    /// [`ProviderError::Transport`] when the HTTP client cannot build.
    pub fn new(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
    ) -> Result<Self, ProviderError> {
        Self::with_limits(
            config,
            connection,
            store,
            GITLAB_DUO_WORKFLOW_DEADLINE,
            GITLAB_DUO_WORKFLOW_IDLE,
            WorkflowBudget::recorded(),
        )
    }

    /// The same adapter under explicit bounds — the offline proof's seam
    /// for a short idle window and a small restart budget.
    ///
    /// The recorded composition is 12 outer sockets × (two 30 s REST legs
    /// plus the 90 s idle window) plus 3 × 30 s setup and a 30 s margin,
    /// which is the shipped deadline. The class caps (4 step-limit, 2
    /// stall, 1 generic) can spend at most 8 sockets after the first one,
    /// so the recorded outer cap is unreachable under [`Self::new`];
    /// [`Self::new`] always uses [`WorkflowBudget::recorded`], and only
    /// this seam composes a smaller bound for proof. Under such a
    /// composed bound a restart may create the next workflow as the last
    /// socket is spent: that workflow is never socketed and never stopped
    /// — the recorded orphan of the composed budget, not a second
    /// settlement.
    ///
    /// # Errors
    /// [`Self::new`]'s contract.
    pub fn with_limits(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
        idle: Duration,
        budget: WorkflowBudget,
    ) -> Result<Self, ProviderError> {
        let entry =
            config
                .connections
                .get(connection)
                .ok_or_else(|| ProviderError::UnknownConnection {
                    connection: connection.to_string(),
                })?;
        if let Some(region) = &entry.region {
            return Err(ProviderError::RegionMismatch {
                connection: connection.to_string(),
                region: region.clone(),
            });
        }
        let base = admit_base(connection, &entry.endpoint)?;
        let origin = base.origin().ascii_serialization();
        let reference = super::resolve_credential(config, connection)?;
        let client = reqwest::blocking::Client::builder()
            .timeout(REST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| transport(connection, err))?;
        Ok(Self {
            connection: connection.to_string(),
            base,
            origin,
            reference,
            store,
            client,
            deadline,
            idle,
            budget,
        })
    }

    /// The stored workspace profile, gate by gate: parse, origin match,
    /// non-empty token. Every denial lands before any request.
    fn credential(&self) -> Result<WorkspaceCredential, ProviderError> {
        let material = self.store.resolve(&self.reference)?;
        let credential: WorkspaceCredential =
            serde_json::from_slice(&material).map_err(|_parse| {
                ProviderError::CredentialMalformed {
                    connection: self.connection.clone(),
                }
            })?;
        let enrolled = reqwest::Url::parse(credential.origin()).map_err(|_parse| {
            ProviderError::CredentialMalformed {
                connection: self.connection.clone(),
            }
        })?;
        if enrolled.origin().ascii_serialization() != self.origin {
            return Err(ProviderError::CredentialBaseMismatch {
                connection: self.connection.clone(),
                enrolled: crate::policy::canonical_egress_target(credential.origin()),
            });
        }
        if credential.access_token().trim().is_empty() {
            return Err(ProviderError::CredentialMalformed {
                connection: self.connection.clone(),
            });
        }
        Ok(credential)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base.as_str().trim_end_matches('/'))
    }

    fn leg(&self, started: Instant) -> Result<(), ProviderError> {
        check_deadline(&self.connection, self.deadline, started)
    }

    /// One REST fetch under the recorded 30 s bound: the request timeout
    /// is the total span from connect until the body is finished, and the
    /// leg clock starts before `send` and is checked before every read, so
    /// the phases cannot each spend a fresh 30 s. The clock alone would
    /// let an in-flight read overrun the bound; the request timeout is
    /// what cuts it. The client's per-read timeout stays the default for
    /// every other request this adapter makes.
    fn fetch(
        &self,
        request: reqwest::blocking::RequestBuilder,
        started: Instant,
    ) -> Result<Value, ProviderError> {
        self.leg(started)?;
        let leg = Instant::now();
        let mut response = request
            .timeout(REST_TIMEOUT)
            .send()
            .map_err(|err| transport(&self.connection, err))?;
        if !response.status().is_success() {
            return Err(transport_status(&self.connection, response.status()));
        }
        let body = read_catalog_body(&self.connection, REST_TIMEOUT, &mut response, leg)?;
        serde_json::from_slice(&body)
            .map_err(|_parse| violation(&self.connection, "the setup reply is not json"))
    }

    /// The numeric project id the socket routes with: the recorded id
    /// verbatim, else the best-effort path lookup the source keeps. A
    /// failed lookup leaves the socket namespace-only rather than
    /// blocking the stream on a hanging project read, so this answers
    /// `None` instead of failing the send.
    fn numeric_project_id(
        &self,
        credential: &WorkspaceCredential,
        started: Instant,
    ) -> Option<String> {
        let project = credential.project().filter(|path| !path.is_empty())?;
        if project.bytes().all(|byte| byte.is_ascii_digit()) {
            return Some(project.to_string());
        }
        let path = format!("{}{}", PROJECTS_PATH, percent_encode_component(project));
        let request = self
            .client
            .get(self.url(&path))
            .header(reqwest::header::ACCEPT, "application/json")
            .bearer_auth(credential.access_token());
        match self.fetch(request, started) {
            Ok(payload) => payload.get("id").and_then(id_text),
            // The recorded lookup is best-effort: an unresolvable path
            // routes the socket by namespace instead of failing the send.
            Err(_lookup) => None,
        }
    }

    /// The workflow token the socket authenticates with, spent only here.
    fn direct_access(
        &self,
        credential: &WorkspaceCredential,
        project: Option<&str>,
        started: Instant,
    ) -> Result<String, ProviderError> {
        let mut body = Map::new();
        body.insert(
            "workflow_definition".to_string(),
            json!(WORKFLOW_DEFINITION),
        );
        body.insert(
            "root_namespace_id".to_string(),
            json!(graphql_namespace(credential.namespace())),
        );
        if let Some(project) = project {
            body.insert("project_id".to_string(), json!(project));
        }
        let bytes = wire_body(&self.connection, &Value::Object(body))?;
        let request = self
            .client
            .post(self.url(DIRECT_ACCESS_PATH))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .bearer_auth(credential.access_token())
            .body(bytes);
        let payload = self.fetch(request, started)?;
        workflow_token(&payload).ok_or_else(|| {
            violation(
                &self.connection,
                "direct access response carries no workflow token",
            )
        })
    }

    /// Creates a workflow and returns its id.
    fn create_workflow(
        &self,
        credential: &WorkspaceCredential,
        project: Option<&str>,
        started: Instant,
    ) -> Result<String, ProviderError> {
        let mut body = Map::new();
        body.insert(
            "workflow_definition".to_string(),
            json!(WORKFLOW_DEFINITION),
        );
        body.insert("environment".to_string(), json!("ide"));
        body.insert("allow_agent_to_request_user".to_string(), json!(false));
        body.insert("agent_privileges".to_string(), json!([6]));
        body.insert("pre_approved_agent_privileges".to_string(), json!([6]));
        body.insert("requires_duo_cli_enabled".to_string(), json!(false));
        match project {
            Some(project) => {
                body.insert("project_id".to_string(), json!(project));
            }
            None => {
                body.insert(
                    "namespace_id".to_string(),
                    json!(rest_namespace(credential.namespace())),
                );
            }
        }
        body.insert("goal".to_string(), json!(""));
        let bytes = wire_body(&self.connection, &Value::Object(body))?;
        let request = self
            .client
            .post(self.url(WORKFLOWS_PATH))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .bearer_auth(credential.access_token())
            .body(bytes);
        let payload = self.fetch(request, started)?;
        let id = payload
            .get("id")
            .or_else(|| payload.get("workflow_id"))
            .or_else(|| payload.get("workflowId"))
            .and_then(id_text)
            .ok_or_else(|| violation(&self.connection, "workflow create response carries no id"))?;
        Ok(id)
    }

    /// Stops a workflow a restart abandoned. Best-effort by contract: a
    /// refusal never changes the caller's verdict — the restart already
    /// decided it — so both outcomes end this seam without propagating,
    /// and the restart arm's explicit counter is the record of the
    /// abandoned workflow.
    fn stop(&self, credential: &WorkspaceCredential, workflow_id: &str, started: Instant) {
        let path = format!(
            "{}{}",
            WORKFLOWS_PATH,
            percent_encode_component(workflow_id)
        );
        let Ok(bytes) = wire_body(&self.connection, &json!({ "status_event": "stop" })) else {
            return;
        };
        let request = self
            .client
            .patch(self.url(&path))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .bearer_auth(credential.access_token())
            .body(bytes);
        // Declared fallback: the refusal has no reader, because the
        // restart has already decided the caller's outcome.
        let Ok(_reply) = self.fetch(request, started) else {
            return;
        };
    }

    /// The `startRequest` envelope one socket sends on open.
    fn start_request(
        &self,
        workflow_id: &str,
        manifest: &RequestManifest,
        credential: &WorkspaceCredential,
        project: Option<&str>,
        model: &str,
    ) -> Value {
        let namespace = rest_namespace(credential.namespace());
        let mut metadata = Map::new();
        metadata.insert("environment".to_string(), json!("ide"));
        metadata.insert("client_type".to_string(), json!(CLIENT_TYPE));
        if let Some(project) = project {
            metadata.insert("projectId".to_string(), json!(project));
        }
        metadata.insert("namespaceId".to_string(), json!(namespace));
        metadata.insert("rootNamespaceId".to_string(), json!(namespace));
        metadata.insert("selectedModelIdentifier".to_string(), json!(model));
        let mcp_tools: Vec<Value> = manifest
            .tools
            .iter()
            .map(|tool| {
                json!({
                    "name": tool,
                    "originalToolName": tool,
                    "serverName": "omp",
                    "description": "",
                    "inputSchema": EMPTY_SCHEMA,
                    "isApproved": true,
                })
            })
            .collect();
        json!({
            "startRequest": {
                "workflowID": workflow_id,
                "clientVersion": CLIENT_VERSION,
                "workflowDefinition": WORKFLOW_DEFINITION,
                "goal": manifest.inputs,
                "workflowMetadata": Value::Object(metadata).to_string(),
                "additional_context": [],
                "clientCapabilities": CLIENT_CAPABILITIES,
                "mcpTools": mcp_tools,
                "preapproved_tools": manifest.tools,
                "flowConfigSchemaVersion": "v1",
                "flowConfig": {
                    "version": "v1",
                    "environment": "ambient",
                    "flow": { "entry_point": AGENT_NAME },
                    "components": [{
                        "name": AGENT_NAME,
                        "type": "AgentComponent",
                        "prompt_id": PROMPT_ID,
                        "toolset": [],
                        "inputs": [{ "from": "context:goal", "as": "goal" }],
                        "ui_log_events": UI_LOG_EVENTS,
                    }],
                    "routers": [{ "from": AGENT_NAME, "to": "end" }],
                    "prompts": [{
                        "name": PROMPT_ID,
                        "prompt_id": PROMPT_ID,
                        "unit_primitives": ["duo_agent_platform"],
                        "prompt_template": {
                            "system": manifest.instructions,
                            "user": "{{goal}}",
                            "placeholder": "history",
                        },
                    }],
                },
            }
        })
    }

    /// The socket URL and headers one attempt opens with: exactly
    /// `project_id`/`namespace_id` in the query, the source headers, no
    /// credential and no fragment.
    fn socket_target(
        &self,
        token: &str,
        credential: &WorkspaceCredential,
        project: Option<&str>,
    ) -> Result<(String, Vec<(String, String)>), ProviderError> {
        let scheme = if self.base.scheme() == "https" {
            "wss"
        } else {
            "ws"
        };
        let host = self
            .base
            .host_str()
            .ok_or_else(|| ProviderError::UnsendableRequest {
                connection: self.connection.clone(),
                reason: "the base carries no host".to_string(),
            })?;
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_string()
        };
        let mut target = format!("{scheme}://{host}");
        if let Some(port) = self.base.port() {
            target.push_str(&format!(":{port}"));
        }
        target.push_str(self.base.path().trim_end_matches('/'));
        target.push_str(WS_PATH);
        let mut url =
            reqwest::Url::parse(&target).map_err(|_parse| ProviderError::UnsendableRequest {
                connection: self.connection.clone(),
                reason: "the socket target is not a URL".to_string(),
            })?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(project) = project {
                query.append_pair("project_id", project);
            }
            query.append_pair("namespace_id", &rest_namespace(credential.namespace()));
        }
        let namespace = rest_namespace(credential.namespace());
        let mut headers = vec![
            ("authorization".to_string(), format!("Bearer {token}")),
            ("x-gitlab-client-type".to_string(), CLIENT_TYPE.to_string()),
            (
                "x-gitlab-language-server-version".to_string(),
                LANGUAGE_SERVER_VERSION.to_string(),
            ),
            ("user-agent".to_string(), USER_AGENT.to_string()),
            (
                "origin".to_string(),
                self.base.origin().ascii_serialization(),
            ),
            ("x-gitlab-namespace-id".to_string(), namespace.clone()),
            ("x-gitlab-root-namespace-id".to_string(), namespace),
        ];
        if let Some(project) = project {
            headers.push(("x-gitlab-project-id".to_string(), project.to_string()));
        }
        Ok((url.to_string(), headers))
    }

    /// Opens the socket, sends the start envelope and reads until one
    /// socket verdict. The read timeout is the idle deadline itself, so a
    /// silent peer or a half-open link surfaces as the idle verdict
    /// instead of blocking the send.
    fn run_socket(
        &self,
        target: &str,
        headers: &[(String, String)],
        start: &Value,
        state: &mut CheckpointState,
        started: Instant,
    ) -> Result<SocketEnd, ProviderError> {
        // Connect and handshake are part of this leg: the probe runs before
        // the socket exists, not only before its first frame.
        self.leg(started)?;
        let mut socket = self.open_socket(target, headers)?;
        socket
            .send(Message::Text(start.to_string().into()))
            .map_err(|err| self.socket_failure(err))?;
        loop {
            self.leg(started)?;
            let message = match socket.read() {
                Ok(message) => message,
                Err(tungstenite::Error::Io(err)) if is_timeout(&err) => {
                    close_quietly(&mut socket);
                    return Ok(SocketEnd::Idle);
                }
                Err(err) => return Err(self.socket_failure(err)),
            };
            let payload = match message {
                Message::Text(text) => text.to_string(),
                Message::Binary(bytes) => match String::from_utf8(bytes.to_vec()) {
                    Ok(text) => text,
                    Err(_utf8) => {
                        return Err(violation(
                            &self.connection,
                            "the workflow frame is not utf-8",
                        ));
                    }
                },
                Message::Close(_) => {
                    return Err(ProviderError::UnknownTerminal {
                        connection: self.connection.clone(),
                    });
                }
                _ => continue,
            };
            // A frame that is not JSON carries no verdict; the recorded
            // socket ignores it and keeps waiting inside the idle window.
            let Ok(event) = serde_json::from_str::<Value>(&payload) else {
                continue;
            };
            match self.handle_frame(&event, state)? {
                Frame::Continue => {}
                Frame::Terminal => {
                    close_quietly(&mut socket);
                    return Ok(SocketEnd::Reply(std::mem::take(&mut state.text)));
                }
                Frame::Action(tool) => {
                    // shortcut: the blocking Provider seam cannot resume an
                    // action turn, so the socket closes after handing the tool
                    // call back; upgrade when the seam grows a resume channel.
                    close_quietly(&mut socket);
                    return Ok(SocketEnd::Action(tool));
                }
                Frame::StepLimit => return Ok(SocketEnd::StepLimit),
                Frame::Stalled => return Ok(SocketEnd::Stalled),
                Frame::Retryable(message) => return Ok(SocketEnd::Retryable(message)),
            }
        }
    }

    fn open_socket(
        &self,
        target: &str,
        headers: &[(String, String)],
    ) -> Result<WebSocket<MaybeTlsStream<TcpStream>>, ProviderError> {
        let uri: tungstenite::http::Uri =
            target
                .parse()
                .map_err(|_parse| ProviderError::UnsendableRequest {
                    connection: self.connection.clone(),
                    reason: "the socket target is not a URI".to_string(),
                })?;
        let host = uri.host().ok_or_else(|| ProviderError::UnsendableRequest {
            connection: self.connection.clone(),
            reason: "the socket target carries no host".to_string(),
        })?;
        let port = uri.port_u16().unwrap_or_else(|| {
            if self.base.scheme() == "https" {
                443
            } else {
                80
            }
        });
        let stream = self.connect(host, port)?;
        let mut builder = ClientRequestBuilder::new(uri);
        for (name, value) in headers {
            builder = builder.with_header(name, value);
        }
        match tungstenite::client_tls_with_config(builder, stream, None, None) {
            Ok((socket, _response)) => Ok(socket),
            Err(HandshakeError::Failure(err)) => Err(self.socket_failure(err)),
            // A blocking handshake that cannot complete inside the socket's
            // read window returns `Interrupted` (the machine treats
            // `WouldBlock` as "try later"); for this adapter that is the
            // idle window expiring, not a frame violation.
            Err(HandshakeError::Interrupted(_partial)) => {
                Err(self.retained_io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "the websocket handshake stayed unanswered",
                )))
            }
        }
    }

    /// One TCP connect bounded by the idle window, with the same window
    /// left on the socket so a silent peer — no `101`, no frame — surfaces
    /// as the typed timeout instead of hanging the send.
    fn connect(&self, host: &str, port: u16) -> Result<TcpStream, ProviderError> {
        let addresses = (host, port)
            .to_socket_addrs()
            .map_err(|err| self.socket_failure(tungstenite::Error::Io(err)))?;
        let mut last = None;
        for address in addresses {
            match TcpStream::connect_timeout(&address, self.idle) {
                Ok(stream) => {
                    stream
                        .set_read_timeout(Some(self.idle))
                        .map_err(|err| self.socket_failure(tungstenite::Error::Io(err)))?;
                    stream
                        .set_write_timeout(Some(REST_TIMEOUT))
                        .map_err(|err| self.socket_failure(tungstenite::Error::Io(err)))?;
                    // Nagle is a tuning knob; its refusal changes no outcome.
                    let _tuned = stream.set_nodelay(true);
                    return Ok(stream);
                }
                Err(err) => last = Some(err),
            }
        }
        match last {
            Some(err) => Err(self.socket_failure(tungstenite::Error::Io(err))),
            None => Err(violation(
                &self.connection,
                "the socket target resolved no address",
            )),
        }
    }

    /// A socket-leg failure with no peer text in the diagnostic.
    fn socket_failure(&self, error: tungstenite::Error) -> ProviderError {
        match error {
            tungstenite::Error::Io(err) => self.retained_io(err),
            tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => {
                ProviderError::UnknownTerminal {
                    connection: self.connection.clone(),
                }
            }
            tungstenite::Error::Http(response) => {
                transport_status(&self.connection, response.status())
            }
            tungstenite::Error::Url(_) | tungstenite::Error::HttpFormat(_) => {
                ProviderError::UnsendableRequest {
                    connection: self.connection.clone(),
                    reason: "the socket target is not an admitted websocket URL".to_string(),
                }
            }
            tungstenite::Error::Protocol(_)
            | tungstenite::Error::Capacity(_)
            | tungstenite::Error::Utf8(_)
            | tungstenite::Error::WriteBufferFull(_)
            | tungstenite::Error::AttackAttempt
            | tungstenite::Error::Tls(_) => violation(
                &self.connection,
                "the websocket leg violated the frame contract",
            ),
        }
    }

    /// An I/O leg whose class is retained programmatically, never as text.
    fn retained_io(&self, err: std::io::Error) -> ProviderError {
        ProviderError::Transport {
            connection: self.connection.clone(),
            cause: TransportCause::Read {
                source: Arc::new(err),
            },
        }
    }

    fn handle_frame(
        &self,
        event: &Value,
        state: &mut CheckpointState,
    ) -> Result<Frame, ProviderError> {
        if let Some(checkpoint) = checkpoint_of(event) {
            state.absorb(checkpoint);
        }
        if let Some(status) = status_of(event) {
            if status == "FINISHED" || status == "INPUT_REQUIRED" {
                return Ok(Frame::Terminal);
            }
            if status == "PLAN_APPROVAL_REQUIRED" || status == "TOOL_CALL_APPROVAL_REQUIRED" {
                return Err(ProviderError::IncompatibleOutput {
                    connection: self.connection.clone(),
                    reason: "the workflow awaits an approval this adapter cannot grant".to_string(),
                });
            }
            if status == "FAILED" || status == "STOPPED" {
                let message = event
                    .get("error")
                    .and_then(Value::as_str)
                    .or_else(|| event.get("message").and_then(Value::as_str))
                    .unwrap_or(status);
                let lowered = message.to_lowercase();
                if status == "FAILED" && lowered.contains(STEP_LIMIT_CLAUSE) {
                    return Ok(Frame::StepLimit);
                }
                if status == "FAILED" && lowered.contains(GENERIC_CLAUSE) {
                    return Ok(Frame::Retryable(super::bounded_reason(message)));
                }
                return Err(ProviderError::ProviderFailed {
                    connection: self.connection.clone(),
                    reason: super::bounded_reason(message),
                });
            }
        }
        if state.stalled() {
            return Ok(Frame::Stalled);
        }
        let Some(action) = action_of(event) else {
            return Ok(Frame::Continue);
        };
        action_tool(&self.connection, &action).map(Frame::Action)
    }
}

impl Provider for GitlabWorkflowProvider {
    fn name(&self) -> &'static str {
        "gitlab-workflow"
    }

    fn serves(&self, connection: &str, _entry: &crate::config::Connection) -> bool {
        connection == self.connection
    }

    /// Runs the recorded DWS sequence inside one settlement: the REST
    /// setup chain, then the bounded socket sequence. Every restart stays
    /// inside this one send, so the caller meets one reply or one typed
    /// denial and the ledger closes one row.
    ///
    /// # Errors
    /// The credential, base, transport and stream denials this module
    /// documents; a partial action or unknown terminal is never success.
    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        let started = Instant::now();
        self.leg(started)?;
        let model = match &manifest.model {
            ModelAssign::Fixed(fixed) if fixed.connection == self.connection => {
                fixed.model_id.clone()
            }
            ModelAssign::Fixed(fixed) => {
                return Err(ProviderError::DialectMismatch {
                    connection: fixed.connection.clone(),
                });
            }
            ModelAssign::Auto { .. } | ModelAssign::Inherit => {
                return Err(ProviderError::UnpinnedModel {
                    connection: self.connection.clone(),
                });
            }
        };
        let credential = self.credential()?;
        let rest_project = credential.project().map(str::to_string);
        let socket_project = self.numeric_project_id(&credential, started);
        let token = self.direct_access(&credential, rest_project.as_deref(), started)?;
        let mut state = CheckpointState::default();
        let mut workflow_id =
            self.create_workflow(&credential, rest_project.as_deref(), started)?;
        let mut sockets = 0_u32;
        let mut reconnected = false;
        let mut step_restarts = 0_u32;
        let mut stall_restarts = 0_u32;
        let mut generic_restarts = 0_u32;
        while sockets < self.budget.outer_attempts {
            self.leg(started)?;
            let (target, headers) =
                self.socket_target(&token, &credential, socket_project.as_deref())?;
            let start = self.start_request(
                &workflow_id,
                manifest,
                &credential,
                socket_project.as_deref(),
                &model,
            );
            let end = self.run_socket(&target, &headers, &start, &mut state, started)?;
            sockets += 1;
            match end {
                SocketEnd::Reply(text) => {
                    return Ok(ProviderReply {
                        text,
                        tool_calls: Vec::new(),
                        usage: UsageDelta::Unknown,
                        wire_retries: sockets.saturating_sub(1),
                        dropped_reasoning: 0,
                    });
                }
                SocketEnd::Action(tool) => {
                    return Ok(ProviderReply {
                        text: std::mem::take(&mut state.text),
                        tool_calls: vec![tool],
                        usage: UsageDelta::Unknown,
                        wire_retries: sockets.saturating_sub(1),
                        dropped_reasoning: 0,
                    });
                }
                SocketEnd::Idle => {
                    // One reconnect on the same workflow id; a second idle
                    // death is the typed stop, and the caller decides.
                    if reconnected {
                        return Err(self.retained_io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "the workflow socket stayed idle",
                        )));
                    }
                    reconnected = true;
                }
                SocketEnd::StepLimit => {
                    if step_restarts >= self.budget.step_limit {
                        return Err(ProviderError::ProviderFailed {
                            connection: self.connection.clone(),
                            reason: "the workflow reached its maximum step limit".to_string(),
                        });
                    }
                    step_restarts += 1;
                    // Best-effort stop: the restart counter above is this
                    // arm's accounting; a refused stop is not propagated.
                    self.stop(&credential, &workflow_id, started);
                    workflow_id =
                        self.create_workflow(&credential, rest_project.as_deref(), started)?;
                }
                SocketEnd::Stalled => {
                    if stall_restarts >= self.budget.stall {
                        return Err(ProviderError::ProviderFailed {
                            connection: self.connection.clone(),
                            reason: "the workflow's visible history stopped advancing".to_string(),
                        });
                    }
                    stall_restarts += 1;
                    // Best-effort stop: the restart counter above is this
                    // arm's accounting; a refused stop is not propagated.
                    self.stop(&credential, &workflow_id, started);
                    workflow_id =
                        self.create_workflow(&credential, rest_project.as_deref(), started)?;
                }
                SocketEnd::Retryable(message) => {
                    if generic_restarts >= self.budget.generic {
                        return Err(ProviderError::ProviderFailed {
                            connection: self.connection.clone(),
                            reason: message,
                        });
                    }
                    generic_restarts += 1;
                    // Best-effort stop: the restart counter above is this
                    // arm's accounting; a refused stop is not propagated.
                    self.stop(&credential, &workflow_id, started);
                    workflow_id =
                        self.create_workflow(&credential, rest_project.as_deref(), started)?;
                }
            }
        }
        Err(ProviderError::UnknownTerminal {
            connection: self.connection.clone(),
        })
    }
}

/// Closes the socket; the connection is dropped next, so a close-frame
/// refusal cannot change the verdict the caller already decided.
fn close_quietly(socket: &mut WebSocket<MaybeTlsStream<TcpStream>>) {
    let _closed = socket.close(None);
}

/// The admitted base: the recorded default or the operator's configured
/// origin — config ingress already refuses a plaintext non-loopback host
/// — with no userinfo, query or fragment and no trailing slash. A base
/// path is preserved, like the recorded relative install base.
fn admit_base(connection: &str, raw: &str) -> Result<reqwest::Url, ProviderError> {
    let trimmed = raw.trim().trim_end_matches('/');
    let raw = if trimmed.is_empty() {
        DEFAULT_BASE
    } else {
        trimmed
    };
    let url = reqwest::Url::parse(raw).map_err(|_parse| ProviderError::UnsendableRequest {
        connection: connection.to_string(),
        reason: "the configured endpoint is not a URL".to_string(),
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ProviderError::UnsendableRequest {
            connection: connection.to_string(),
            reason: "the configured endpoint is not an admitted origin".to_string(),
        });
    }
    Ok(url)
}

/// An id field as text: the DWS payloads carry it in either form.
fn id_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// The workflow token, in the recorded precedence.
fn workflow_token(payload: &Value) -> Option<String> {
    let nested = |outer: &str| {
        payload
            .get(outer)
            .and_then(|section| section.get("token"))
            .and_then(Value::as_str)
    };
    [
        nested("gitlab_rails"),
        nested("duo_workflow_service"),
        payload
            .get("duo_workflow_access_token")
            .and_then(Value::as_str),
        payload.get("workflow_token").and_then(Value::as_str),
        payload.get("token").and_then(Value::as_str),
        payload.get("access_token").and_then(Value::as_str),
        payload.get("jwt").and_then(Value::as_str),
    ]
    .into_iter()
    .flatten()
    .find(|token| !token.is_empty())
    .map(str::to_string)
}

/// The GraphQL namespace form `direct_access` records: a numeric id
/// becomes a group global id, a path stays verbatim.
fn graphql_namespace(namespace: &str) -> String {
    if namespace.bytes().all(|byte| byte.is_ascii_digit()) {
        format!("gid://gitlab/Group/{namespace}")
    } else {
        namespace.to_string()
    }
}

/// The REST namespace form: a group global id unwraps to its numeric id,
/// anything else stays verbatim.
fn rest_namespace(namespace: &str) -> String {
    let Some(tail) = namespace
        .strip_prefix("gid://gitlab/Group/")
        .or_else(|| namespace.strip_prefix("gid://gitlab/Namespace/"))
    else {
        return namespace.to_string();
    };
    if tail.bytes().all(|byte| byte.is_ascii_digit()) {
        tail.to_string()
    } else {
        namespace.to_string()
    }
}

/// The frame's status: root, `workflowStatus.status` or
/// `newCheckpoint.status`.
fn status_of(event: &Value) -> Option<&str> {
    event
        .get("status")
        .and_then(Value::as_str)
        .or_else(|| {
            event
                .get("workflowStatus")
                .and_then(|status| status.get("status"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            event
                .get("newCheckpoint")
                .and_then(|status| status.get("status"))
                .and_then(Value::as_str)
        })
}

/// The checkpoint the frame carries, borrowed from the parsed frame: the
/// recorded wire form is a serialized string, an already-parsed object is
/// passed through, and any other shape carries no checkpoint.
fn checkpoint_of(event: &Value) -> Option<&Value> {
    let checkpoint = event
        .get("action")
        .and_then(|action| action.get("newCheckpoint"))
        .or_else(|| event.get("newCheckpoint"))
        .or_else(|| event.get("checkpoint"))?;
    match checkpoint {
        Value::String(_) | Value::Object(_) => Some(checkpoint),
        _ => None,
    }
}

/// The action descriptor a frame carries: the wrapped form first, then
/// the recorded bare action names.
fn action_of(event: &Value) -> Option<Value> {
    for key in ["action", "workflowAction", "toolCall"] {
        let Some(wrapped) = event.get(key).filter(|wrapped| wrapped.is_object()) else {
            continue;
        };
        if wrapped.get("newCheckpoint").is_some() {
            return None;
        }
        return Some(wrapped.clone());
    }
    for name in ["runMCPTool", "run_mcp_tool"] {
        let Some(args) = event.get(name).filter(|args| args.is_object()) else {
            continue;
        };
        let mut action = Map::new();
        action.insert("name".to_string(), json!(name));
        action.insert("args".to_string(), args.clone());
        if let Some(request_id) = event
            .get("requestID")
            .or_else(|| event.get("requestId"))
            .and_then(Value::as_str)
        {
            action.insert("requestID".to_string(), json!(request_id));
        }
        return Some(Value::Object(action));
    }
    None
}

/// The tool call an action represents. The recorded descriptor must carry
/// its request id and a mapped tool name; anything less is a partial tool
/// the seam cannot hand on, never a fabricated call.
fn action_tool(connection: &str, action: &Value) -> Result<ToolCall, ProviderError> {
    let request_id = action
        .get("requestID")
        .or_else(|| action.get("requestId"))
        .or_else(|| action.get("id"))
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty());
    if request_id.is_none() {
        return Err(violation(
            connection,
            "the workflow action carries no request id",
        ));
    }
    let name = action
        .get("name")
        .or_else(|| action.get("action"))
        .or_else(|| action.get("type"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let raw_arguments = action
        .get("args")
        .or_else(|| action.get("arguments"))
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let (tool, arguments) = if name == "runMCPTool" || name == "run_mcp_tool" {
        let bare = raw_arguments
            .get("toolName")
            .or_else(|| raw_arguments.get("tool_name"))
            .or_else(|| raw_arguments.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let tool = bare.strip_prefix("mcp__omp__").unwrap_or(bare).to_string();
        let arguments = raw_arguments
            .get("args")
            .or_else(|| raw_arguments.get("arguments"))
            .map_or_else(
                || Value::Object(Map::new()),
                |value| mcp_arguments(value.clone()),
            );
        (tool, arguments)
    } else {
        (name.to_string(), raw_arguments)
    };
    if tool.is_empty() {
        return Err(ProviderError::IncompatibleOutput {
            connection: connection.to_string(),
            reason: "the workflow action names no tool".to_string(),
        });
    }
    let path = arguments
        .get("path")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(ToolCall { tool, path })
}

/// The recorded MCP argument form: an object, or a JSON-string object;
/// anything else is no arguments.
fn mcp_arguments(value: Value) -> Value {
    match value {
        Value::String(text) => match serde_json::from_str::<Value>(&text) {
            Ok(parsed) if parsed.is_object() => parsed,
            Ok(_scalar) => Value::Object(Map::new()),
            Err(_parse) => Value::Object(Map::new()),
        },
        Value::Object(_) => value,
        _ => Value::Object(Map::new()),
    }
}

/// Whether one I/O failure is a timeout — the idle window expiring.
fn is_timeout(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::TimedOut || err.kind() == std::io::ErrorKind::WouldBlock
}

#[cfg(test)]
mod tests {
    use super::CheckpointState;
    use serde_json::json;

    /// An unchanged snapshot replay leaves the stored reply state alone:
    /// the per-turn signature table does not grow, so a later distinct
    /// message with the same text at the same turn is not suppressed as a
    /// duplicate.
    #[test]
    fn an_unchanged_snapshot_replay_does_not_touch_the_stored_state() {
        let snapshot = json!({
            "channel_values": {
                "ui_chat_log": [
                    { "message_type": "request", "content": "goal" },
                    { "message_type": "agent", "message_id": "m1", "content": "answer" },
                ],
            },
        });
        let mut state = CheckpointState::default();
        state.absorb(&snapshot);
        let signatures = state.signatures.clone();
        let content = state.content.clone();
        let text = state.text.clone();
        state.absorb(&snapshot);
        assert_eq!(
            state.signatures, signatures,
            "the replay stores no new signature"
        );
        assert_eq!(state.content, content, "the replay rewrites no stored text");
        assert_eq!(state.text, text, "the replay appends nothing");
    }
}
