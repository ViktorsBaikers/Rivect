//! Single public ingress producer (architecture: `dispatch_runtime_request`
//! is the one dispatcher; `src/api.rs` later only wraps transport). Strict
//! JSON-RPC framing, per-method typed params, fail-closed machine ingress.

use crate::config::{self, EffectiveConfig};
use crate::contracts::{
    AnswerSelection, ErrorCode, OptionId, PAGE_DEFAULT, Page, QuestionId, QuestionResult,
    RetryClass, RpcErrorBody, RpcResponse, SCHEMA_VERSION, SessionId, TaskId, WireError,
};
use crate::model::Broker;
use crate::owner::{Owner, OwnerError};
use crate::policy::Policy;
use crate::providers::Provider;
use crate::resources::NotificationQueue;
use crate::state::StoreError;
use serde::Serialize;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ingress {
    /// Trusted explicit CLI/TUI input adapter: server-owned human origin.
    TrustedHuman,
    /// Plain SDK/machine JSON: never proves human consent.
    Machine,
}

pub struct Runtime {
    pub owner: Owner,
    pub policy: Policy,
    pub broker: Broker,
    pub notifications: NotificationQueue,
    pub effective: EffectiveConfig,
    /// Purpose used by the first-task model loop; resolved through the
    /// production config schema, never an allow-default profile.
    pub purpose: String,
    pub scope_root: PathBuf,
    pub scoped_file: PathBuf,
    pub provider_calls: u64,
    /// The one injected backend seam; defaults to the real macOS worker.
    pub read_worker: Box<dyn crate::executor::ReadWorker>,
}

impl Runtime {
    pub fn open(data_root: &Path, provider: Box<dyn Provider>) -> Result<Self, OwnerError> {
        Self::open_with_worker(
            data_root,
            provider,
            Box::new(crate::executor::macos::MacosReadWorker),
        )
    }

    pub fn open_with_worker(
        data_root: &Path,
        provider: Box<dyn Provider>,
        read_worker: Box<dyn crate::executor::ReadWorker>,
    ) -> Result<Self, OwnerError> {
        let owner = Owner::elect(data_root)?;
        let user_toml = std::fs::read_to_string(data_root.join("config.toml")).ok();
        let effective = config::resolve_effective(user_toml.as_deref())
            .map_err(|err| OwnerError::Io(std::io::Error::other(err.to_string())))?;
        Ok(Self {
            owner,
            policy: Policy::default(),
            broker: Broker::new(provider),
            notifications: NotificationQueue::new(8),
            effective,
            purpose: String::new(),
            scope_root: PathBuf::new(),
            scoped_file: PathBuf::new(),
            provider_calls: 0,
            read_worker,
        })
    }

    /// Grants the single scoped read used by the first-task loop and records
    /// the scope root/file pair the loop is confined to.
    pub fn set_read_scope(&mut self, root: PathBuf, file: PathBuf) -> String {
        self.scope_root = root.clone();
        self.scoped_file = file;
        self.policy.grant_read(root)
    }

    pub fn config_for_broker(&self) -> crate::config::Config {
        self.effective.parsed.clone().unwrap_or_default()
    }

    pub fn goal_bytes(&self, task_id: &TaskId) -> Vec<u8> {
        self.owner.store.goal_bytes(task_id).unwrap_or_default()
    }
}

#[derive(Debug, Serialize)]
pub struct StatusResult {
    pub schema_version: u32,
    pub session_id: SessionId,
    pub owner_generation: u64,
    pub state: String,
    pub workflow: config::ConfigEntry,
    pub tasks: Page<crate::contracts::TaskStatus>,
}

#[derive(Debug, Serialize)]
pub struct ConfigReadResult {
    pub schema_version: u32,
    pub source_digest: String,
    pub entries: Page<config::ConfigEntry>,
}

const METHODS: &[&str] = &[
    "session.open",
    "session.attach",
    "session.close",
    "runtime.status",
    "config.read",
    "task.submit",
    "task.snapshot",
    "question.current",
    "events.read",
    "task.collection",
    "command.describe",
    "command.execute",
    "artifact.read",
];

pub fn dispatch_runtime_request(
    rt: &mut Runtime,
    ingress: Ingress,
    connection_id: &str,
    request: &str,
) -> String {
    let response = dispatch_inner(rt, ingress, connection_id, request);
    serde_json::to_string(&response).unwrap_or_else(|_| {
        "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32000,\"message\":\"internal_error\"}}"
            .to_string()
    })
}

fn dispatch_inner(
    rt: &mut Runtime,
    ingress: Ingress,
    connection_id: &str,
    request: &str,
) -> RpcResponse {
    if request.len() > crate::contracts::REQUEST_MAX_BYTES {
        return envelope_error(
            Value::Null,
            ErrorCode::InvalidInput,
            "-32602",
            "request exceeds the 1 MiB cap",
        );
    }
    let parsed: Value = match serde_json::from_str(request) {
        Ok(value) => value,
        Err(_) => {
            return RpcResponse {
                jsonrpc: "2.0",
                id: Value::Null,
                result: None,
                error: Some(RpcErrorBody {
                    code: -32700,
                    message: "parse error".to_string(),
                    data: WireError::new(ErrorCode::InvalidInput, "request is not valid JSON"),
                }),
            };
        }
    };
    let Some(id) = parsed.get("id").cloned() else {
        return envelope_error(
            Value::Null,
            ErrorCode::InvalidInput,
            "-32600",
            "request id is required",
        );
    };
    if id.is_null() {
        return envelope_error(
            id,
            ErrorCode::InvalidInput,
            "-32600",
            "notification ids are not accepted",
        );
    }
    match &id {
        Value::String(s) if s.len() <= 256 => {}
        Value::Number(n) if n.is_i64() => {}
        _ => {
            return envelope_error(
                id,
                ErrorCode::InvalidInput,
                "-32600",
                "id must be a string of at most 256 bytes or an exact integer",
            );
        }
    }
    if parsed.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return envelope_error(
            id,
            ErrorCode::InvalidInput,
            "-32600",
            "jsonrpc must be \"2.0\"",
        );
    }
    if parsed.get("method").and_then(Value::as_str).is_none() {
        return envelope_error(id, ErrorCode::InvalidInput, "-32600", "method is required");
    }
    if parsed.get("params").map(Value::is_object) != Some(true) {
        return envelope_error(
            id,
            ErrorCode::InvalidInput,
            "-32602",
            "params must be an object",
        );
    }
    let method = parsed["method"].as_str().unwrap_or_default().to_string();
    let params = parsed["params"].clone();
    if !METHODS.contains(&method.as_str()) {
        return envelope_error(
            id,
            ErrorCode::UnknownMethod,
            "-32601",
            &format!("unknown method {method}"),
        );
    }
    let schema = params.get("schema_version").and_then(Value::as_u64);
    match schema {
        None => {
            return envelope_error(
                id,
                ErrorCode::InvalidInput,
                "-32602",
                "schema_version is required",
            );
        }
        Some(1) => {}
        Some(other) => {
            return envelope_error(
                id,
                ErrorCode::UnsupportedVersion,
                "-32000",
                &format!("unsupported schema_version {other}"),
            );
        }
    }
    handle_method(rt, ingress, connection_id, &method, params, id)
}

fn envelope_error(id: Value, code: ErrorCode, rpc_code: &str, message: &str) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcErrorBody {
            code: rpc_code.parse::<i64>().unwrap_or(-32000),
            message: code.as_str().to_string(),
            data: WireError {
                code,
                message: message.to_string(),
                boundary_id: None,
                retry_class: RetryClass::None,
            },
        }),
    }
}

fn store_error(id: Value, err: &StoreError) -> RpcResponse {
    let message = err.to_string();
    let recovery = match err {
        StoreError::NotFound(_) => "; read runtime.status to list tasks",
        StoreError::Conflict(_) => "; re-read the current snapshot before retrying",
        StoreError::StaleIntent { .. } => "; read task.snapshot for current revisions",
        StoreError::AlreadyTerminal => "; the historical outcome is preserved",
        StoreError::InvalidInput(_) => "",
        StoreError::Storage(_) => "; retry after checking local storage",
    };
    envelope_error(id, err.code(), "-32000", &format!("{message}{recovery}"))
}

fn handle_method(
    rt: &mut Runtime,
    ingress: Ingress,
    connection_id: &str,
    method: &str,
    params: Value,
    id: Value,
) -> RpcResponse {
    match method {
        "session.open" | "session.attach" => {
            let bootstrap = params
                .get("bootstrap_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if bootstrap.is_empty() {
                return envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    "bootstrap_id is required",
                );
            }
            let attach_to = params
                .get("session_id")
                .and_then(Value::as_str)
                .map(|s| SessionId(s.to_string()));
            match rt
                .owner
                .store
                .open_session(&bootstrap, connection_id, attach_to.as_ref())
            {
                Ok((session_id, attachment_id, generation, _replayed)) => {
                    let revision = 1;
                    RpcResponse::ok(
                        id,
                        json!({
                            "schema_version": SCHEMA_VERSION,
                            "session_id": session_id.0,
                            "owner_generation": generation,
                            "state": "attached",
                            "attachment_id": attachment_id.0,
                            "session_revision": revision,
                        }),
                    )
                }
                Err(err) => store_error(id, &err),
            }
        }
        "session.close" => {
            let Some(session) = session_param(&params) else {
                return missing_session(id);
            };
            RpcResponse::ok(
                id,
                json!({
                    "schema_version": SCHEMA_VERSION,
                    "session_id": session.0,
                    "owner_generation": 1u64,
                    "state": "closed",
                    "attachment_id": params.get("bootstrap_id").and_then(Value::as_str).unwrap_or_default(),
                    "session_revision": 1u64,
                }),
            )
        }
        "runtime.status" => {
            let Some(session) = session_param(&params) else {
                return missing_session(id);
            };
            match rt.owner.store.task_status_page(&session) {
                Ok(tasks) => {
                    let result = StatusResult {
                        schema_version: SCHEMA_VERSION,
                        session_id: session.clone(),
                        owner_generation: rt.owner.generation,
                        state: "ready".to_string(),
                        workflow: rt.effective.workflow_entry.clone(),
                        tasks,
                    };
                    RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
                }
                Err(err) => store_error(id, &err),
            }
        }
        "config.read" => {
            let Some(_session) = session_param(&params) else {
                return missing_session(id);
            };
            let Some(keys) = params.get("keys").and_then(Value::as_array) else {
                return envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    "keys must be a non-empty array",
                );
            };
            if keys.is_empty() {
                return envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    "keys must be non-empty",
                );
            }
            let mut seen = std::collections::BTreeSet::new();
            for key in keys {
                let Some(key) = key.as_str() else {
                    return envelope_error(
                        id,
                        ErrorCode::InvalidInput,
                        "-32602",
                        "keys must be strings",
                    );
                };
                if !seen.insert(key.to_string()) {
                    return envelope_error(
                        id,
                        ErrorCode::InvalidInput,
                        "-32602",
                        &format!("duplicate key {key}"),
                    );
                }
                if key != config::WORKFLOW_KEY {
                    return envelope_error(
                        id,
                        ErrorCode::InvalidInput,
                        "-32602",
                        &format!("invalid key {key}"),
                    );
                }
            }
            let result = ConfigReadResult {
                schema_version: SCHEMA_VERSION,
                source_digest: rt.effective.sources_digest.clone(),
                entries: Page::new(vec![rt.effective.workflow_entry.clone()], 0),
            };
            RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
        }
        "task.submit" => submit_task(rt, ingress, params, id),
        "task.snapshot" => {
            let Some(_session) = session_param(&params) else {
                return missing_session(id);
            };
            let Some(task) = task_param(&params) else {
                return envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    "task_id is required",
                );
            };
            match rt.owner.store.snapshot(&task) {
                Ok(snapshot) => {
                    RpcResponse::ok(id, serde_json::to_value(&snapshot).unwrap_or(Value::Null))
                }
                Err(err) => store_error(id, &err),
            }
        }
        "question.current" => {
            let Some(_session) = session_param(&params) else {
                return missing_session(id);
            };
            let Some(task) = task_param(&params) else {
                return envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    "task_id is required",
                );
            };
            match rt.owner.store.current_question(&task) {
                Ok(None) => {
                    let snapshot = match rt.owner.store.snapshot(&task) {
                        Ok(snapshot) => snapshot,
                        Err(err) => return store_error(id, &err),
                    };
                    let result = QuestionResult {
                        schema_version: SCHEMA_VERSION,
                        task_id: task.clone(),
                        task_revision: snapshot.revision,
                        intent_revision: snapshot.intent_revision,
                        question: None,
                    };
                    RpcResponse::ok(id, serde_json::to_value(&result).unwrap_or(Value::Null))
                }
                Ok(Some((question, task_revision))) => {
                    let result = QuestionResult {
                        schema_version: SCHEMA_VERSION,
                        task_id: task.clone(),
                        task_revision,
                        intent_revision: question.intent_revision,
                        question: Some(question),
                    };
                    RpcResponse::ok(id, serde_json::to_value(&result).unwrap_or(Value::Null))
                }
                Err(err) => store_error(id, &err),
            }
        }
        "events.read" => {
            let Some(session) = session_param(&params) else {
                return missing_session(id);
            };
            let after = params
                .get("after_cursor")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let task = task_param(&params);
            let limit = page_limit(&params);
            match rt
                .owner
                .store
                .events_after(&session, task.as_ref(), after, limit)
            {
                Ok(events) => {
                    let items = events
                        .iter()
                        .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
                        .collect();
                    RpcResponse::ok(
                        id,
                        serde_json::to_value(Page::new(items, after)).unwrap_or(Value::Null),
                    )
                }
                Err(err) => store_error(id, &err),
            }
        }
        "task.collection" => {
            let Some(_session) = session_param(&params) else {
                return missing_session(id);
            };
            let Some(task) = task_param(&params) else {
                return envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    "task_id is required",
                );
            };
            let Some(collection) = params.get("collection").and_then(Value::as_str) else {
                return envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    "collection is required",
                );
            };
            let cursor_gen = params
                .get("page")
                .and_then(|p| p.get("cursor"))
                .and_then(Value::as_str)
                .and_then(|c| c.strip_prefix("gen:"))
                .and_then(|g| g.parse::<u64>().ok());
            match rt.owner.store.collection(&task, collection, cursor_gen) {
                Ok(page) => RpcResponse::ok(id, serde_json::to_value(&page).unwrap_or(Value::Null)),
                Err(err) => store_error(id, &err),
            }
        }
        "command.describe" => {
            let page = crate::tools::describe();
            RpcResponse::ok(id, serde_json::to_value(&page).unwrap_or(Value::Null))
        }
        "command.execute" => {
            let Some(kind) = params
                .get("command")
                .and_then(|c| c.get("kind"))
                .and_then(Value::as_str)
            else {
                return envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    "command.kind is required",
                );
            };
            match crate::tools::local_command_kind(kind) {
                crate::tools::LocalKind::Unknown => envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    &format!("unknown local command {kind}"),
                ),
                crate::tools::LocalKind::PlannedUnimplemented => envelope_error(
                    id,
                    ErrorCode::CapabilityUnavailable,
                    "-32000",
                    &format!("{kind} is known but not available in this build"),
                ),
            }
        }
        "artifact.read" => envelope_error(
            id,
            ErrorCode::CapabilityUnavailable,
            "-32000",
            "artifact.read is known but not available in this build",
        ),
        other => envelope_error(
            id,
            ErrorCode::UnknownMethod,
            "-32601",
            &format!("unknown method {other}"),
        ),
    }
}

fn session_param(params: &Value) -> Option<SessionId> {
    params
        .get("session_id")
        .and_then(Value::as_str)
        .map(|s| SessionId(s.to_string()))
}

fn missing_session(id: Value) -> RpcResponse {
    envelope_error(
        id,
        ErrorCode::InvalidInput,
        "-32602",
        "session_id is required",
    )
}

fn task_param(params: &Value) -> Option<TaskId> {
    params
        .get("task_id")
        .and_then(Value::as_str)
        .map(|s| TaskId(s.to_string()))
}

fn page_limit(params: &Value) -> u32 {
    let limit = params
        .get("page")
        .and_then(|p| p.get("page_size"))
        .and_then(Value::as_u64)
        .unwrap_or(PAGE_DEFAULT as u64) as u32;
    limit.clamp(1, crate::contracts::PAGE_MAX)
}

fn submit_task(rt: &mut Runtime, ingress: Ingress, params: Value, id: Value) -> RpcResponse {
    let Some(session) = session_param(&params) else {
        return missing_session(id);
    };
    let command_id = params
        .get("command_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if command_id.is_empty() {
        return envelope_error(
            id,
            ErrorCode::InvalidInput,
            "-32602",
            "command_id is required",
        );
    }
    let kind = params
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if !crate::contracts::TASK_COMMAND_KINDS.contains(&kind.as_str()) {
        return envelope_error(
            id,
            ErrorCode::InvalidInput,
            "-32602",
            &format!("unknown command kind {kind}"),
        );
    }
    let principal = match ingress {
        Ingress::TrustedHuman => "local_user",
        Ingress::Machine => "machine",
    };
    match kind.as_str() {
        "create" => {
            if params.get("task_id").is_some() {
                return envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    "task_id is forbidden on create",
                );
            }
            let Some(goal) = params.get("goal").and_then(Value::as_str) else {
                return envelope_error(id, ErrorCode::InvalidInput, "-32602", "goal is required");
            };
            let contract = params.get("contract").cloned().unwrap_or(Value::Null);
            let criteria = string_array(&contract, "criteria");
            let constraints = string_array(&contract, "constraints");
            match rt.owner.store.create_task(
                &session,
                &command_id,
                principal,
                goal,
                (&criteria, &constraints),
            ) {
                Ok(result) => {
                    RpcResponse::ok(id, serde_json::to_value(&result).unwrap_or(Value::Null))
                }
                Err(err) => store_error(id, &err),
            }
        }
        "answer" => {
            if matches!(ingress, Ingress::Machine) {
                // Fail closed: an SDK answer never proves human consent, and
                // the pending question is preserved untouched.
                return envelope_error(
                    id,
                    ErrorCode::Denied,
                    "-32000",
                    "machine answer without an explicit delegation is denied; the pending question is preserved",
                );
            }
            let Some(task) = task_param(&params) else {
                return envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    "task_id is required",
                );
            };
            let expected_intent = params
                .get("expected_intent_revision")
                .and_then(Value::as_u64);
            let Some(question_id) = params
                .get("question_id")
                .and_then(Value::as_str)
                .map(|s| QuestionId(s.to_string()))
            else {
                return envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    "question_id is required",
                );
            };
            let question_revision = params.get("question_revision").and_then(Value::as_u64);
            let (Some(expected_intent), Some(question_revision)) =
                (expected_intent, question_revision)
            else {
                return envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    "revision fields are required",
                );
            };
            let Some(selection_value) = params.get("selection") else {
                return envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    "selection is required",
                );
            };
            let selection = match parse_selection(selection_value) {
                Ok(selection) => selection,
                Err(message) => {
                    return envelope_error(id, ErrorCode::InvalidInput, "-32602", &message);
                }
            };
            let snapshot = match rt.owner.store.snapshot(&task) {
                Ok(snapshot) => snapshot,
                Err(err) => return store_error(id, &err),
            };
            if snapshot.intent_revision != expected_intent {
                return store_error(
                    id,
                    &StoreError::StaleIntent {
                        expected: expected_intent,
                        current: snapshot.intent_revision,
                    },
                );
            }
            match rt.owner.store.answer_question(
                &session,
                &task,
                &question_id,
                question_revision,
                &selection,
                "human",
            ) {
                Ok(result) => {
                    RpcResponse::ok(id, serde_json::to_value(&result).unwrap_or(Value::Null))
                }
                Err(err) => store_error(id, &err),
            }
        }
        "steer" => {
            let Some(task) = task_param(&params) else {
                return envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    "task_id is required",
                );
            };
            let (Some(expected_intent), Some(expected_task)) = (
                params
                    .get("expected_intent_revision")
                    .and_then(Value::as_u64),
                params.get("expected_task_revision").and_then(Value::as_u64),
            ) else {
                return envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    "revision fields are required",
                );
            };
            let Some(instruction) = params.get("instruction").and_then(Value::as_str) else {
                return envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    "instruction is required",
                );
            };
            match rt.owner.store.steer_task(
                &session,
                &task,
                expected_intent,
                expected_task,
                instruction,
            ) {
                Ok(result) => {
                    RpcResponse::ok(id, serde_json::to_value(&result).unwrap_or(Value::Null))
                }
                Err(err) => store_error(id, &err),
            }
        }
        "cancel" => {
            let Some(task) = task_param(&params) else {
                return envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    "task_id is required",
                );
            };
            let Some(expected_intent) = params
                .get("expected_intent_revision")
                .and_then(Value::as_u64)
            else {
                return envelope_error(
                    id,
                    ErrorCode::InvalidInput,
                    "-32602",
                    "expected_intent_revision is required",
                );
            };
            let reason = params.get("reason").and_then(Value::as_str);
            match rt
                .owner
                .store
                .cancel_task(&session, &task, expected_intent, reason)
            {
                Ok(result) => {
                    RpcResponse::ok(id, serde_json::to_value(&result).unwrap_or(Value::Null))
                }
                Err(err) => store_error(id, &err),
            }
        }
        other => envelope_error(
            id,
            ErrorCode::CapabilityUnavailable,
            "-32000",
            &format!("{other} is not available in this build"),
        ),
    }
}

fn parse_selection(value: &Value) -> std::result::Result<AnswerSelection, String> {
    match value.get("kind").and_then(Value::as_str) {
        Some("option") => {
            if value.get("text").is_some() {
                return Err("selection cannot carry both option_id and text".to_string());
            }
            let option_id = value
                .get("option_id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "option_id is required".to_string())?;
            Ok(AnswerSelection::Option {
                option_id: OptionId(option_id.to_string()),
            })
        }
        Some("custom") => {
            if value.get("option_id").is_some() {
                return Err("selection cannot carry both option_id and text".to_string());
            }
            let text = value
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| "text is required".to_string())?;
            Ok(AnswerSelection::Custom {
                text: text.to_string(),
            })
        }
        _ => Err("selection.kind must be option or custom".to_string()),
    }
}

fn string_array(contract: &Value, field: &str) -> Vec<String> {
    contract
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}
