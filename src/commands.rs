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
use crate::scheduler::{DEFAULT_MAX_SLOTS, DEFAULT_RESOURCE_CAP, Scheduler};
use crate::state::StoreError;
use crate::supervisor::{Supervisor, SupervisorPolicy};
use serde::Serialize;
use serde_json::{Value, json};
use std::io::Read;
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
    /// The one bounded task-tree scheduler (INV-020): slot release on
    /// parent wait, strict-FIFO admission, terminal cancellation.
    pub scheduler: Scheduler,
    /// The sterile-retry supervisor (INV-027): reads the scheduler's
    /// own outcome stream and journals one bounded reaction per
    /// detector firing; never dispatches.
    pub supervisor: Supervisor,
    pub notifications: NotificationQueue,
    pub effective: EffectiveConfig,
    /// Purpose used by the first-task model loop; resolved through the
    /// production config schema, never an allow-default profile.
    pub purpose: String,
    pub scope_root: PathBuf,
    pub scoped_file: PathBuf,
    /// Grant id matching the scoped read pair; scheduler nodes freeze it
    /// at answer time and their decision steps re-check it.
    pub scoped_grant: String,
    /// Publication target of the journaled config carrier (AC-095).
    pub config_path: PathBuf,
    pub provider_calls: u64,
    /// The one injected backend seam; defaults to the platform worker
    /// (Linux Landlock/seccomp/netns on Linux, Seatbelt elsewhere).
    pub read_worker: Box<dyn crate::executor::ReadWorker>,
    /// Boot-time publication-recovery verdicts a human must resolve:
    /// collected, sanitized lines with their resolution. Each surface
    /// reports them its own way — headless stderr, TUI transcript — and
    /// receipted rows stay silent.
    pub boot_diagnostics: Vec<String>,
}

impl Runtime {
    pub fn open(data_root: &Path, provider: Box<dyn Provider>) -> Result<Self, OwnerError> {
        #[cfg(target_os = "linux")]
        let worker: Box<dyn crate::executor::ReadWorker> =
            Box::new(crate::executor::linux::LinuxWorker);
        #[cfg(not(target_os = "linux"))]
        let worker: Box<dyn crate::executor::ReadWorker> =
            Box::new(crate::executor::macos::MacosReadWorker);
        Self::open_with_worker(data_root, provider, worker)
    }

    pub fn open_with_worker(
        data_root: &Path,
        provider: Box<dyn Provider>,
        read_worker: Box<dyn crate::executor::ReadWorker>,
    ) -> Result<Self, OwnerError> {
        let mut owner = Owner::elect(data_root)?;
        // Boot recovery: a crash between the managed write and its receipt
        // leaves one pending row; receipt exactly the writes attributable
        // to this publisher before any config surface serves (AC-093).
        // Every verdict a human must resolve is collected into
        // `boot_diagnostics` — each surface reports the lines its own
        // way — while the receipted rows stay silent.
        let boot_diagnostics: Vec<String> = config::recover_publications(&mut owner.store)?
            .iter()
            .filter_map(recovery_diagnostic)
            .collect();
        let config_path = data_root.join("config.toml");
        let user_toml = match std::fs::File::open(&config_path) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take((CONFIG_MAX_BYTES as u64) + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|source| OwnerError::ConfigRead {
                        path: config_path.clone(),
                        source,
                    })?;
                if bytes.len() > CONFIG_MAX_BYTES {
                    return Err(OwnerError::ConfigTooLarge {
                        path: config_path,
                        limit: CONFIG_MAX_BYTES,
                    });
                }
                let text = String::from_utf8(bytes).map_err(|source| OwnerError::ConfigRead {
                    path: config_path.clone(),
                    source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
                })?;
                Some(text)
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => None,
            Err(source) => {
                return Err(OwnerError::ConfigRead {
                    path: config_path,
                    source,
                });
            }
        };
        let effective = config::resolve_effective(user_toml.as_deref()).map_err(|source| {
            OwnerError::Config {
                path: config_path.clone(),
                source,
            }
        })?;
        Ok(Self {
            owner,
            policy: Policy::default(),
            broker: Broker::new(provider),
            notifications: NotificationQueue::new(8),
            scheduler: Scheduler::new(DEFAULT_MAX_SLOTS, DEFAULT_RESOURCE_CAP),
            supervisor: Supervisor::new(SupervisorPolicy::default())?,
            effective,
            purpose: String::new(),
            scope_root: PathBuf::new(),
            scoped_file: PathBuf::new(),
            scoped_grant: String::new(),
            config_path,
            provider_calls: 0,
            read_worker,
            boot_diagnostics,
        })
    }

    /// Grants the single scoped read used by the first-task loop and records
    /// the scope root/file pair the loop is confined to.
    pub fn set_read_scope(&mut self, root: PathBuf, file: PathBuf) -> String {
        self.scope_root = root.clone();
        self.scoped_file = file;
        let grant = self.policy.grant_read(root);
        self.scoped_grant = grant.clone();
        grant
    }

    pub fn config_for_broker(&self) -> config::Config {
        self.effective.parsed.clone().unwrap_or_default()
    }

    pub fn goal_bytes(&self, task_id: &TaskId) -> Vec<u8> {
        self.owner.store.goal_bytes(task_id).unwrap_or_default()
    }
}

const CONFIG_MAX_BYTES: usize = crate::contracts::REQUEST_MAX_BYTES;

#[derive(Debug, Serialize)]
pub struct StatusResult {
    pub schema_version: u32,
    pub session_id: SessionId,
    pub owner_generation: u64,
    pub state: String,
    pub workflow: config::ConfigEntry,
    pub tasks: Page<crate::contracts::TaskStatus>,
    pub todo: Page<crate::contracts::TodoItem>,
    pub scheduler: Page<crate::contracts::SchedulerItem>,
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

#[derive(Debug, thiserror::Error)]
enum RequestError {
    #[error("request exceeds the 1 MiB cap")]
    RequestTooLarge,
    #[error("request is not valid JSON")]
    InvalidJson,
    #[error("request id is required")]
    MissingRequestId,
    #[error("notification ids are not accepted")]
    NotificationId,
    #[error("id must be a string of at most 256 bytes or an exact integer")]
    InvalidRequestId,
    #[error("jsonrpc must be \"2.0\"")]
    WrongJsonRpc,
    #[error("method is required")]
    MissingMethod,
    #[error("page must be an object")]
    InvalidPage,
    #[error("page_size must be a positive integer")]
    InvalidPageSize,
    #[error("response serialization failed")]
    Serialization,
    #[error("page cursor must be gen:<generation>:offset:<offset>")]
    InvalidPageCursor,
    #[error("page cursor offset is out of range")]
    PageCursorOffsetOutOfRange,
    #[error("after_cursor must be a non-negative integer within the SQLite cursor range")]
    InvalidAfterCursor,
    #[error("params must be an object")]
    ParamsNotObject,
    #[error("unknown method {method}")]
    UnknownMethod { method: String },
    #[error("{field} is required")]
    Required { field: &'static str },
    #[error("unsupported schema_version {version}")]
    UnsupportedVersion { version: u64 },
    #[error("keys must be a non-empty array")]
    KeysNotArray,
    #[error("{field} exceeds {max} items")]
    ArrayTooLarge { field: &'static str, max: usize },
    #[error("{field} must be an array")]
    ArrayNotArray { field: &'static str },
    #[error("{field} items must be strings")]
    ArrayItemNotString { field: &'static str },
    #[error("keys must be a non-empty array")]
    EmptyKeys,
    #[error("keys must be strings")]
    KeysNotStrings,
    #[error("duplicate key {key}")]
    DuplicateKey { key: String },
    #[error("unknown key {key}; known keys: {}", crate::config::WORKFLOW_KEY)]
    InvalidKey { key: String },
    #[error("unknown local command {command}")]
    UnknownLocalCommand { command: String },
    #[error("{command} is known but not available in this build")]
    KnownCommandUnavailable { command: String },
    #[error("artifact.read is known but not available in this build")]
    ArtifactReadUnavailable,
    #[error("unknown command kind {kind}")]
    UnknownCommandKind { kind: String },
    #[error("task_id is forbidden on create")]
    TaskIdForbiddenOnCreate,
    #[error(
        "machine answer without an explicit delegation is denied; the pending question is preserved"
    )]
    MachineAnswerDenied,
    #[error("revision fields are required")]
    MissingRevisionFields,
    #[error(transparent)]
    Selection(#[from] SelectionError),
    #[error("{method} is not available in this build")]
    MethodUnavailable { method: String },
}

impl RequestError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::UnknownMethod { .. } => ErrorCode::UnknownMethod,
            Self::UnsupportedVersion { .. } => ErrorCode::UnsupportedVersion,
            Self::KnownCommandUnavailable { .. }
            | Self::ArtifactReadUnavailable
            | Self::MethodUnavailable { .. } => ErrorCode::CapabilityUnavailable,
            Self::MachineAnswerDenied => ErrorCode::Denied,
            Self::Serialization => ErrorCode::InternalError,
            _ => ErrorCode::InvalidInput,
        }
    }

    fn rpc_code(&self) -> i64 {
        match self {
            Self::InvalidJson => -32700,
            Self::MissingRequestId
            | Self::NotificationId
            | Self::InvalidRequestId
            | Self::WrongJsonRpc
            | Self::MissingMethod => -32600,
            Self::UnknownMethod { .. } => -32601,
            Self::UnsupportedVersion { .. }
            | Self::KnownCommandUnavailable { .. }
            | Self::ArtifactReadUnavailable
            | Self::MachineAnswerDenied
            | Self::MethodUnavailable { .. }
            | Self::Serialization => -32000,
            _ => -32602,
        }
    }

    fn rpc_message(&self) -> &'static str {
        match self {
            Self::InvalidJson => "parse error",
            _ => self.code().as_str(),
        }
    }
}

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
        return request_error(Value::Null, RequestError::RequestTooLarge);
    }
    let parsed: Value = match serde_json::from_str(request) {
        Ok(value) => value,
        Err(_) => return request_error(Value::Null, RequestError::InvalidJson),
    };
    let Some(id) = parsed.get("id").cloned() else {
        return request_error(Value::Null, RequestError::MissingRequestId);
    };
    if id.is_null() {
        return request_error(id, RequestError::NotificationId);
    }
    match &id {
        Value::String(s) if s.len() <= 256 => {}
        Value::Number(n) if n.is_i64() => {}
        _ => return request_error(id, RequestError::InvalidRequestId),
    }
    if parsed.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return request_error(id, RequestError::WrongJsonRpc);
    }
    if parsed.get("method").and_then(Value::as_str).is_none() {
        return request_error(id, RequestError::MissingMethod);
    }
    if parsed.get("params").map(Value::is_object) != Some(true) {
        return request_error(id, RequestError::ParamsNotObject);
    }
    let method = parsed["method"].as_str().unwrap_or_default().to_string();
    let params = parsed["params"].clone();
    if !METHODS.contains(&method.as_str()) {
        return request_error(id, RequestError::UnknownMethod { method });
    }
    let schema = params.get("schema_version").and_then(Value::as_u64);
    match schema {
        None => {
            return request_error(
                id,
                RequestError::Required {
                    field: "schema_version",
                },
            );
        }
        Some(1) => {}
        Some(version) => {
            return request_error(id, RequestError::UnsupportedVersion { version });
        }
    }
    handle_method(rt, ingress, connection_id, &method, params, id)
}

const RECOVERY_NOT_FOUND: &str = "; read runtime.status to list tasks";
const RECOVERY_CONFLICT: &str = "; re-read the current snapshot before retrying";
const RECOVERY_STALE_INTENT: &str = "; read task.snapshot for current revisions";
const RECOVERY_ALREADY_TERMINAL: &str = "; the historical outcome is preserved";
const RECOVERY_STORAGE: &str = "; retry after checking local storage";

fn envelope_error(id: Value, code: ErrorCode, rpc_code: i64, message: &str) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcErrorBody {
            code: rpc_code,
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

fn request_error(id: Value, err: RequestError) -> RpcResponse {
    let code = err.code();
    RpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcErrorBody {
            code: err.rpc_code(),
            message: err.rpc_message().to_string(),
            data: WireError::new(code, err.to_string()),
        }),
    }
}

fn store_error(id: Value, err: &StoreError) -> RpcResponse {
    let message = err.to_string();
    let recovery = match err {
        StoreError::NotFound(_) => RECOVERY_NOT_FOUND,
        StoreError::Conflict(_) => RECOVERY_CONFLICT,
        StoreError::StaleIntent { .. } => RECOVERY_STALE_INTENT,
        StoreError::AlreadyTerminal => RECOVERY_ALREADY_TERMINAL,
        StoreError::InvalidInput(_) => "",
        StoreError::Storage(_) => RECOVERY_STORAGE,
    };
    envelope_error(id, err.code(), -32000, &format!("{message}{recovery}"))
}

/// Snapshot of the retained config view one edit is applied against: the
/// document plus the entry the read surface serves from it.
struct RetainedView {
    parsed: Option<config::Config>,
    workflow_entry: config::ConfigEntry,
}

fn retained_view(rt: &Runtime) -> RetainedView {
    RetainedView {
        parsed: rt.effective.parsed.clone(),
        workflow_entry: rt.effective.workflow_entry.clone(),
    }
}

/// Puts the pre-edit retained view back: the command was never journaled,
/// so no surface may observe its edit.
fn restore_retained_view(rt: &mut Runtime, before: &RetainedView) {
    rt.effective.parsed = before.parsed.clone();
    rt.effective.workflow_entry = before.workflow_entry.clone();
}

/// Applies one typed edit to the retained config document. `Config::set`
/// and `Config::reset` restore the original document on rejection, so the
/// retained view always mirrors the last accepted edit; the document is
/// put back either way — this carrier never owns a second config.
fn retained_edit(
    rt: &mut Runtime,
    apply: impl FnOnce(&mut config::Config) -> Result<config::ConfigEdit, config::ConfigError>,
) -> Result<config::ConfigEdit, config::ConfigError> {
    let mut retained = std::mem::take(&mut rt.effective.parsed).unwrap_or_default();
    let edit = apply(&mut retained);
    rt.effective.parsed = Some(retained);
    edit
}

fn config_error(id: Value, err: &config::ConfigError) -> RpcResponse {
    envelope_error(id, ErrorCode::InvalidInput, -32602, &err.to_string())
}

/// Journal owner string for the CLI carrier; the file surface admits with
/// its own owner spelling through the same singleflight.
const CONFIG_CARRIER_OWNER: &str = "cli";

/// Admits one accepted edit through the singleflight journal. The read
/// surface is refreshed first, so the retained doc and its served entry
/// move together; a rejected admission restores `before` — the command
/// was never journaled, so no surface may observe its edit.
fn admit_config_command(
    rt: &mut Runtime,
    id: Value,
    command: &str,
    key: &str,
    edit: &config::ConfigEdit,
    before: RetainedView,
) -> RpcResponse {
    rt.effective.refresh_workflow_entry(&edit.digest);
    let intent = match config::admit_publication(
        &mut rt.owner.store,
        CONFIG_CARRIER_OWNER,
        &rt.config_path,
        edit,
    ) {
        // Fresh admission owns the durable publication: the checked-fd
        // write lands the bytes against the staged identity, then the
        // receipt completes the journal row.
        Ok(config::PublicationAdmission::Staged(intent)) => {
            match config::publish_intent(&mut rt.owner.store, &intent, &edit.bytes) {
                Ok(()) => intent,
                Err(err) => {
                    // Fail closed: a write that cannot run leaves the row
                    // pending — the crash-window recovery owns it — and no
                    // surface serves the edit. A receipt that cannot be
                    // recorded after the bytes landed keeps the edit
                    // durable and served; the next boot receipts it.
                    if !matches!(err, config::PublicationError::Journal(_)) {
                        restore_retained_view(rt, &before);
                    }
                    return publication_error(id, &err);
                }
            }
        }
        // A pending row is never answered from the retained document
        // alone. A foreign winner's write may still be in flight — the
        // replay observes it — while a row this carrier admitted is
        // healed: the bytes already hold and take the receipt, or the
        // retry re-runs the managed write, so no retry reports an edit
        // that is not on disk.
        Ok(config::PublicationAdmission::Pending(pending)) => {
            match config::resolve_pending_publication(
                &mut rt.owner.store,
                CONFIG_CARRIER_OWNER,
                &pending,
                &edit.bytes,
            ) {
                Ok(intent) => intent,
                Err(err) => {
                    // The fresh write's fail-closed contract, word for
                    // word: an unlanded edit is served by no surface,
                    // while landed bytes keep serving as the receipt
                    // waits for the next boot.
                    if !matches!(err, config::PublicationError::Journal(_)) {
                        restore_retained_view(rt, &before);
                    }
                    return publication_error(id, &err);
                }
            }
        }
        // A terminal row already proved its bytes hold; the replay
        // answers the winner's historical outcome.
        Ok(config::PublicationAdmission::Applied(applied)) => applied,
        Err(err) => {
            restore_retained_view(rt, &before);
            return publication_error(id, &err);
        }
    };
    RpcResponse::ok(
        id,
        json!({
            "schema_version": SCHEMA_VERSION,
            "command": command,
            "key": key,
            "digest": edit.digest,
            "owner": intent.owner,
            "admission_seq": intent.admission_seq,
        }),
    )
}

/// Wire shape of a publication failure, one code per variant wherever
/// the family surfaces (P-001): journal trouble keeps the store's typed
/// error and its recovery text; the managed write's own failure takes
/// the same code the executor assigns that worker error — a sandbox
/// that cannot start is a capability failure, a denied write a denial —
/// and the target variants split caller-input codes from backend ones
/// instead of collapsing into `internal_error`.
fn publication_error(id: Value, err: &config::PublicationError) -> RpcResponse {
    let (code, rpc_code) = match err {
        config::PublicationError::Journal(store) => return store_error(id, store),
        config::PublicationError::Write(worker) => {
            (crate::executor::worker_error_code(worker), -32000)
        }
        config::PublicationError::TargetAbsent(_) => (ErrorCode::NotFound, -32000),
        config::PublicationError::TargetNotUtf8 => (ErrorCode::InvalidInput, -32602),
        config::PublicationError::Target(_) => (ErrorCode::StorageUnavailable, -32000),
        config::PublicationError::IdentityMissing => (ErrorCode::InternalError, -32000),
    };
    envelope_error(id, code, rpc_code, &err.to_string())
}

/// One diagnostic line for a recovery verdict a human must resolve:
/// the verdict token names what the bytes at the target failed to
/// prove, the sanitized target names where — no control character the
/// path could carry reaches a terminal — and the resolution names the
/// retry that settles the row. The healed `ExactlyNew` verdict — our
/// own write receipted by the boot — stays silent.
fn recovery_diagnostic(recovery: &config::PublicationRecovery) -> Option<String> {
    let verdict = match recovery.verdict {
        config::PublicationVerdict::ExactlyNew => return None,
        config::PublicationVerdict::Old => "old",
        config::PublicationVerdict::ByteIdenticalThird => "byte_identical_third",
        config::PublicationVerdict::Conflicting => "conflicting",
        config::PublicationVerdict::TornOrUnparseable => "torn_or_unparseable",
        config::PublicationVerdict::Absent => "absent",
        config::PublicationVerdict::Unknown => "unknown",
    };
    Some(format!(
        "publication recovery: {verdict} verdict stays pending at {}; \
         resolution: inspect the target, then re-run the configuration edit that owns the pending publication",
        crate::resources::sanitize_status_cause(&recovery.intent.target)
    ))
}

/// Shared tail of the config.set/unset arms: capture the retained view,
/// apply one typed edit, answer a rejection with the typed ConfigError,
/// and admit an accepted edit through the singleflight journal.
fn commit_config_edit(
    rt: &mut Runtime,
    id: Value,
    command: &str,
    key: &str,
    apply: impl FnOnce(&mut config::Config) -> Result<config::ConfigEdit, config::ConfigError>,
) -> RpcResponse {
    let before = retained_view(rt);
    let edit = match retained_edit(rt, apply) {
        Ok(edit) => edit,
        Err(err) => return config_error(id, &err),
    };
    admit_config_command(rt, id, command, key, &edit, before)
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
                return request_error(
                    id,
                    RequestError::Required {
                        field: "bootstrap_id",
                    },
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
            let (cursor, limit) = match status_page(&params) {
                Ok(page) => page,
                Err(err) => return request_error(id, err),
            };
            let tasks = match rt.owner.store.task_status_page(&session, limit, cursor) {
                Ok(tasks) => tasks,
                Err(err) => return store_error(id, &err),
            };
            let todo = match rt.owner.store.todo_page(&session, limit, cursor) {
                Ok(todo) => todo,
                Err(err) => return store_error(id, &err),
            };
            let scheduler = match rt.owner.store.scheduler_page(&session, limit, cursor) {
                Ok(scheduler) => scheduler,
                Err(err) => return store_error(id, &err),
            };
            let result = StatusResult {
                schema_version: SCHEMA_VERSION,
                session_id: session,
                owner_generation: rt.owner.generation,
                state: "ready".to_string(),
                workflow: rt.effective.workflow_entry.clone(),
                tasks,
                todo,
                scheduler,
            };
            let Ok(payload) = serde_json::to_value(&result) else {
                return request_error(id, RequestError::Serialization);
            };
            RpcResponse::ok(id, payload)
        }
        "config.read" => {
            let Some(_session) = session_param(&params) else {
                return missing_session(id);
            };
            let Some(keys) = params.get("keys").and_then(Value::as_array) else {
                return request_error(id, RequestError::KeysNotArray);
            };
            if keys.is_empty() {
                return request_error(id, RequestError::EmptyKeys);
            }
            let mut seen = std::collections::BTreeSet::new();
            for key in keys {
                let Some(key) = key.as_str() else {
                    return request_error(id, RequestError::KeysNotStrings);
                };
                if !seen.insert(key.to_string()) {
                    return request_error(
                        id,
                        RequestError::DuplicateKey {
                            key: key.to_string(),
                        },
                    );
                }
                if key != config::WORKFLOW_KEY {
                    return request_error(
                        id,
                        RequestError::InvalidKey {
                            key: key.to_string(),
                        },
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
                return request_error(id, RequestError::Required { field: "task_id" });
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
                return request_error(id, RequestError::Required { field: "task_id" });
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
            let after = match after_cursor(&params) {
                Ok(after) => after,
                Err(err) => return request_error(id, err),
            };
            let task = task_param(&params);
            let limit = match page_limit(&params) {
                Ok(limit) => limit,
                Err(err) => return request_error(id, err),
            };
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
                return request_error(id, RequestError::Required { field: "task_id" });
            };
            let Some(collection) = params.get("collection").and_then(Value::as_str) else {
                return request_error(
                    id,
                    RequestError::Required {
                        field: "collection",
                    },
                );
            };
            let cursor = match status_cursor(&params) {
                Ok(cursor) => cursor,
                Err(err) => return request_error(id, err),
            };
            let limit = match page_limit(&params) {
                Ok(limit) => limit,
                Err(err) => return request_error(id, err),
            };
            match rt.owner.store.collection(&task, collection, cursor, limit) {
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
                return request_error(
                    id,
                    RequestError::Required {
                        field: "command.kind",
                    },
                );
            };
            match crate::tools::local_command_kind(kind) {
                crate::tools::LocalKind::ConfigSet => {
                    let Some(_session) = session_param(&params) else {
                        return missing_session(id);
                    };
                    let Some(key) = params.get("key").and_then(Value::as_str) else {
                        return request_error(id, RequestError::Required { field: "key" });
                    };
                    let Some(value) = params.get("value") else {
                        return request_error(id, RequestError::Required { field: "value" });
                    };
                    commit_config_edit(rt, id, "config.set", key, |config| {
                        config.set_wire(key, value)
                    })
                }
                crate::tools::LocalKind::ConfigUnset => {
                    let Some(_session) = session_param(&params) else {
                        return missing_session(id);
                    };
                    let Some(key) = params.get("key").and_then(Value::as_str) else {
                        return request_error(id, RequestError::Required { field: "key" });
                    };
                    commit_config_edit(rt, id, "config.unset", key, |config| config.reset(key))
                }
                crate::tools::LocalKind::Unknown => request_error(
                    id,
                    RequestError::UnknownLocalCommand {
                        command: kind.to_string(),
                    },
                ),
                crate::tools::LocalKind::PlannedUnimplemented => request_error(
                    id,
                    RequestError::KnownCommandUnavailable {
                        command: kind.to_string(),
                    },
                ),
            }
        }
        "artifact.read" => request_error(id, RequestError::ArtifactReadUnavailable),
        other => request_error(
            id,
            RequestError::UnknownMethod {
                method: other.to_string(),
            },
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
    request_error(
        id,
        RequestError::Required {
            field: "session_id",
        },
    )
}

fn task_param(params: &Value) -> Option<TaskId> {
    params
        .get("task_id")
        .and_then(Value::as_str)
        .map(|s| TaskId(s.to_string()))
}

fn after_cursor(params: &Value) -> Result<u64, RequestError> {
    let Some(value) = params.get("after_cursor") else {
        return Ok(0);
    };
    let Some(cursor) = value.as_u64() else {
        return Err(RequestError::InvalidAfterCursor);
    };
    i64::try_from(cursor).map_err(|_conversion| RequestError::InvalidAfterCursor)?;
    Ok(cursor)
}

fn page_limit(params: &Value) -> Result<u32, RequestError> {
    let Some(page) = params.get("page") else {
        return Ok(PAGE_DEFAULT);
    };
    let Some(page) = page.as_object() else {
        return Err(RequestError::InvalidPage);
    };
    let Some(page_size) = page.get("page_size") else {
        return Ok(PAGE_DEFAULT);
    };
    let Some(page_size) = page_size.as_u64() else {
        return Err(RequestError::InvalidPageSize);
    };
    if page_size == 0 {
        return Err(RequestError::InvalidPageSize);
    }
    let bounded = page_size.min(u64::from(crate::contracts::PAGE_MAX));
    match u32::try_from(bounded) {
        Ok(limit) => Ok(limit),
        Err(_) => Err(RequestError::InvalidPageSize),
    }
}

fn status_page(params: &Value) -> Result<(Option<(u64, u64)>, u32), RequestError> {
    let limit = page_limit(params)?;
    let cursor = status_cursor(params)?;
    Ok((cursor, limit))
}

fn status_cursor(params: &Value) -> Result<Option<(u64, u64)>, RequestError> {
    let Some(page) = params.get("page") else {
        return Ok(None);
    };
    let Some(page) = page.as_object() else {
        return Err(RequestError::InvalidPage);
    };
    let Some(cursor) = page.get("cursor") else {
        return Ok(None);
    };
    let Some(cursor) = cursor.as_str() else {
        return Err(RequestError::InvalidPageCursor);
    };
    let Some(cursor) = cursor.strip_prefix("gen:") else {
        return Err(RequestError::InvalidPageCursor);
    };
    let Some((generation, offset)) = cursor.split_once(":offset:") else {
        let Ok(generation) = cursor.parse::<u64>() else {
            return Err(RequestError::InvalidPageCursor);
        };
        return Ok(Some((generation, 0)));
    };
    let Ok(generation) = generation.parse::<u64>() else {
        return Err(RequestError::InvalidPageCursor);
    };
    let Ok(offset) = offset.parse::<u64>() else {
        return Err(RequestError::InvalidPageCursor);
    };
    if offset > i64::MAX.unsigned_abs() {
        return Err(RequestError::PageCursorOffsetOutOfRange);
    }
    Ok(Some((generation, offset)))
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
        return request_error(
            id,
            RequestError::Required {
                field: "command_id",
            },
        );
    }
    let kind = params
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if !crate::contracts::TASK_COMMAND_KINDS.contains(&kind.as_str()) {
        return request_error(id, RequestError::UnknownCommandKind { kind });
    }
    let principal = match ingress {
        Ingress::TrustedHuman => "local_user",
        Ingress::Machine => "machine",
    };
    match kind.as_str() {
        "create" => {
            if params.get("task_id").is_some() {
                return request_error(id, RequestError::TaskIdForbiddenOnCreate);
            }
            let Some(goal) = params.get("goal").and_then(Value::as_str) else {
                return request_error(id, RequestError::Required { field: "goal" });
            };
            let contract = params.get("contract").cloned().unwrap_or(Value::Null);
            let criteria = match string_array(&contract, "criteria") {
                Ok(criteria) => criteria,
                Err(err) => return request_error(id, err),
            };
            let constraints = match string_array(&contract, "constraints") {
                Ok(constraints) => constraints,
                Err(err) => return request_error(id, err),
            };
            let parent_task = params
                .get("parent_task_id")
                .and_then(Value::as_str)
                .map(|id| TaskId(id.to_string()));
            if let Some(parent) = &parent_task {
                // Fail closed before any row is written: an unknown
                // parent task must not create an orphan tree linkage.
                if let Err(err) = rt.owner.store.snapshot(parent) {
                    return store_error(id, &err);
                }
            }
            match rt.owner.store.create_task(
                &session,
                &command_id,
                principal,
                goal,
                (&criteria, &constraints),
            ) {
                Ok(result) => {
                    // The scheduler owns the tree shape (INV-020):
                    // parentage recorded at creation links the child's
                    // runnable node under its parent's when the answer
                    // freezes.
                    if let Some(parent) = parent_task {
                        rt.scheduler.adopt(result.task_id.clone(), parent);
                    }
                    RpcResponse::ok(id, serde_json::to_value(&result).unwrap_or(Value::Null))
                }
                Err(err) => store_error(id, &err),
            }
        }
        "answer" => {
            if matches!(ingress, Ingress::Machine) {
                // Fail closed: an SDK answer never proves human consent, and
                // the pending question is preserved untouched.
                return request_error(id, RequestError::MachineAnswerDenied);
            }
            let Some(task) = task_param(&params) else {
                return request_error(id, RequestError::Required { field: "task_id" });
            };
            let expected_intent = params
                .get("expected_intent_revision")
                .and_then(Value::as_u64);
            let Some(question_id) = params
                .get("question_id")
                .and_then(Value::as_str)
                .map(|s| QuestionId(s.to_string()))
            else {
                return request_error(
                    id,
                    RequestError::Required {
                        field: "question_id",
                    },
                );
            };
            let question_revision = params.get("question_revision").and_then(Value::as_u64);
            let (Some(expected_intent), Some(question_revision)) =
                (expected_intent, question_revision)
            else {
                return request_error(id, RequestError::MissingRevisionFields);
            };
            let Some(selection_value) = params.get("selection") else {
                return request_error(id, RequestError::Required { field: "selection" });
            };
            let selection = match parse_selection(selection_value) {
                Ok(selection) => selection,
                Err(err) => return request_error(id, err.into()),
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
                    // The frozen answer builds the task's runnable
                    // scheduler node through the production path; a
                    // settled tree grows nothing runnable — the answer
                    // itself stays durable (INV-021).
                    let serialize_answer = |id: Value| match serde_json::to_value(&result) {
                        Ok(value) => RpcResponse::ok(id, value),
                        Err(err) => {
                            envelope_error(id, ErrorCode::InternalError, -32000, &err.to_string())
                        }
                    };
                    match rt.scheduler.submit_answered(
                        task.clone(),
                        selection.clone(),
                        rt.scoped_grant.clone(),
                    ) {
                        Ok(Some(_)) => {
                            if let Err(err) = rt.drain_scheduler(&session) {
                                return envelope_error(
                                    id,
                                    err.error_code(),
                                    -32000,
                                    &err.to_string(),
                                );
                            }
                            serialize_answer(id)
                        }
                        Ok(None) => serialize_answer(id),
                        Err(err) => {
                            let message = err.to_string();
                            envelope_error(
                                id,
                                crate::controller::ControllerError::Scheduler(err).error_code(),
                                -32000,
                                &message,
                            )
                        }
                    }
                }
                Err(err) => store_error(id, &err),
            }
        }
        "steer" => {
            let Some(task) = task_param(&params) else {
                return request_error(id, RequestError::Required { field: "task_id" });
            };
            let (Some(expected_intent), Some(expected_task)) = (
                params
                    .get("expected_intent_revision")
                    .and_then(Value::as_u64),
                params.get("expected_task_revision").and_then(Value::as_u64),
            ) else {
                return request_error(id, RequestError::MissingRevisionFields);
            };
            let Some(instruction) = params.get("instruction").and_then(Value::as_str) else {
                return request_error(
                    id,
                    RequestError::Required {
                        field: "instruction",
                    },
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
                return request_error(id, RequestError::Required { field: "task_id" });
            };
            let Some(expected_intent) = params
                .get("expected_intent_revision")
                .and_then(Value::as_u64)
            else {
                return request_error(
                    id,
                    RequestError::Required {
                        field: "expected_intent_revision",
                    },
                );
            };
            let reason = params.get("reason").and_then(Value::as_str);
            match rt
                .owner
                .store
                .cancel_task(&session, &task, expected_intent, reason)
            {
                Ok(result) => {
                    // The tree drains with the store cancellation: the
                    // remaining children of the cancelled task never admit
                    // or dispatch (AC-012).
                    match rt.scheduler.cancel_task_tree(&task) {
                        Ok(_) => RpcResponse::ok(
                            id,
                            serde_json::to_value(&result).unwrap_or(Value::Null),
                        ),
                        Err(err) => {
                            let message = err.to_string();
                            envelope_error(
                                id,
                                crate::controller::ControllerError::Scheduler(err).error_code(),
                                -32000,
                                &message,
                            )
                        }
                    }
                }
                Err(err) => store_error(id, &err),
            }
        }
        other => request_error(
            id,
            RequestError::MethodUnavailable {
                method: other.to_string(),
            },
        ),
    }
}

#[derive(Debug, thiserror::Error)]
enum SelectionError {
    #[error("selection cannot carry both option_id and text")]
    ConflictingFields,
    #[error("option_id is required")]
    MissingOptionId,
    #[error("custom text exceeds {max} bytes")]
    TextTooLarge { max: usize },
    #[error("custom text is required")]
    MissingText,
    #[error("selection.kind must be option or custom")]
    UnsupportedKind,
}

fn parse_selection(value: &Value) -> Result<AnswerSelection, SelectionError> {
    match value.get("kind").and_then(Value::as_str) {
        Some("option") => {
            if value.get("text").is_some() {
                return Err(SelectionError::ConflictingFields);
            }
            let option_id = value
                .get("option_id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or(SelectionError::MissingOptionId)?;
            Ok(AnswerSelection::Option {
                option_id: OptionId(option_id.to_string()),
            })
        }
        Some("custom") => {
            if value.get("option_id").is_some() {
                return Err(SelectionError::ConflictingFields);
            }
            let text = value
                .get("text")
                .and_then(Value::as_str)
                .ok_or(SelectionError::MissingText)?;
            if text.len() > crate::contracts::TEXT_MAX_BYTES {
                return Err(SelectionError::TextTooLarge {
                    max: crate::contracts::TEXT_MAX_BYTES,
                });
            }
            Ok(AnswerSelection::Custom {
                text: text.to_string(),
            })
        }
        _ => Err(SelectionError::UnsupportedKind),
    }
}

fn string_array(contract: &Value, field: &'static str) -> Result<Vec<String>, RequestError> {
    let Some(value) = contract.get(field) else {
        return Ok(Vec::new());
    };
    let Some(items) = value.as_array() else {
        return Err(RequestError::ArrayNotArray { field });
    };
    if items.len() > crate::contracts::ARRAY_MAX_ITEMS {
        return Err(RequestError::ArrayTooLarge {
            field,
            max: crate::contracts::ARRAY_MAX_ITEMS,
        });
    }
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or(RequestError::ArrayItemNotString { field })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{publication_error, recovery_diagnostic};
    use crate::config::{self, ConfigValue};
    use crate::contracts::ErrorCode;
    use crate::executor::WorkerError;
    use crate::state::{StoreError, TaskStore};
    use serde_json::Value;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    const BASE_CONFIG: &str = "config_version = 1\n\
         [connections.primary]\n\
         kind = \"api_key\"\n\
         endpoint = \"https://api.openai.com/v1\"\n\
         credential_ref = \"keyring:primary\"\n\
         [models.defaults]\n\
         model = { mode = \"auto\" }\n\
         effort = { mode = \"auto\" }\n\
         fallback = { mode = \"auto\" }\n";

    fn wire_code(err: &config::PublicationError) -> Option<ErrorCode> {
        publication_error(Value::from(1), err)
            .error
            .map(|error| error.data.code)
    }

    #[test]
    fn publication_error_maps_each_variant_to_its_own_wire_code() {
        assert_eq!(
            wire_code(&config::PublicationError::TargetAbsent(
                "/data/config.toml".to_string()
            )),
            Some(ErrorCode::NotFound),
            "an absent publication target is not_found, not a generic fault"
        );
        assert_eq!(
            wire_code(&config::PublicationError::TargetNotUtf8),
            Some(ErrorCode::InvalidInput)
        );
        assert_eq!(
            wire_code(&config::PublicationError::Target(std::io::Error::other(
                "permission denied"
            ))),
            Some(ErrorCode::StorageUnavailable)
        );
        assert_eq!(
            wire_code(&config::PublicationError::IdentityMissing),
            Some(ErrorCode::InternalError)
        );
        assert_eq!(
            wire_code(&config::PublicationError::Write(
                WorkerError::SandboxSpawnFailed {
                    source: std::io::Error::other("spawn failed")
                }
            )),
            Some(ErrorCode::CapabilityUnavailable),
            "a sandbox that cannot start is a capability failure, not internal"
        );
        assert_eq!(
            wire_code(&config::PublicationError::Write(WorkerError::WriteFailed {
                source: std::io::Error::other("denied")
            })),
            Some(ErrorCode::Denied),
            "a denied managed write surfaces the executor's denied code"
        );
    }

    #[test]
    fn publication_journal_error_keeps_the_store_code_and_recovery_text() {
        let response = publication_error(
            Value::from(1),
            &config::PublicationError::Journal(StoreError::Storage(
                std::io::Error::other("disk full").into(),
            )),
        );
        let Some(error) = response.error else {
            unreachable!("journal arm must answer an error: {response:?}");
        };
        assert_eq!(error.data.code, ErrorCode::StorageUnavailable);
        assert!(
            error
                .data
                .message
                .contains("retry after checking local storage"),
            "the journal arm keeps the store recovery text: {error:?}"
        );
    }

    fn recovery(verdict: config::PublicationVerdict, target: &str) -> config::PublicationRecovery {
        config::PublicationRecovery {
            intent: config::PublicationIntent {
                owner: "cli".to_string(),
                target: target.to_string(),
                admission_seq: 1,
                intended_digest: "digest".to_string(),
                base_digest: None,
                publish_identity: None,
            },
            verdict,
        }
    }

    #[test]
    fn recovery_diagnostic_names_verdict_and_target_only_when_unhealed() {
        for (verdict, token) in [
            (config::PublicationVerdict::Old, "old"),
            (
                config::PublicationVerdict::ByteIdenticalThird,
                "byte_identical_third",
            ),
            (config::PublicationVerdict::Conflicting, "conflicting"),
            (
                config::PublicationVerdict::TornOrUnparseable,
                "torn_or_unparseable",
            ),
            (config::PublicationVerdict::Absent, "absent"),
            (config::PublicationVerdict::Unknown, "unknown"),
        ] {
            let line = recovery_diagnostic(&recovery(verdict, "/data/config.toml"));
            let Some(text) = line else {
                unreachable!("{verdict:?} must surface a diagnostic");
            };
            assert!(
                text.contains(token),
                "{verdict:?} diagnostic names the verdict: {text}"
            );
            assert!(
                text.contains("/data/config.toml"),
                "{verdict:?} diagnostic names the target: {text}"
            );
            assert!(
                text.contains("resolution:"),
                "{verdict:?} diagnostic names the resolution: {text}"
            );
        }
        assert_eq!(
            recovery_diagnostic(&recovery(
                config::PublicationVerdict::ExactlyNew,
                "/data/config.toml"
            )),
            None,
            "the healed receipted verdict stays silent"
        );
    }

    #[test]
    fn recovery_diagnostic_sanitizes_the_target() {
        let line = recovery_diagnostic(&recovery(
            config::PublicationVerdict::Conflicting,
            "/data/evil\u{7}\u{1b}[2J.toml",
        ));
        let Some(text) = line else {
            unreachable!("an unhealed verdict must surface a diagnostic");
        };
        for ch in text.chars() {
            assert!(
                !ch.is_control(),
                "no control character reaches the diagnostic: {text:?}"
            );
        }
        assert!(
            text.contains("^G"),
            "the bell survives as visible, inert data: {text}"
        );
    }

    #[test]
    fn recovery_diagnostics_compose_over_a_seeded_journal() -> TestResult {
        let root =
            std::env::temp_dir().join(format!("rivect-recovery-diag-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&root));
        std::fs::create_dir_all(&root)?;
        let target = root.join("config.toml");
        std::fs::write(&target, BASE_CONFIG)?;
        let mut store = TaskStore::open(&root.join("state.db"))?;
        let mut parsed = config::Config::parse_validated(BASE_CONFIG)?;
        let edit = parsed.set("workflow.enabled", ConfigValue::Bool(false))?;
        config::stage_publication(&mut store, "cli", &target, &edit)?;

        // The crash window before the write: base bytes still hold, the
        // verdict is Old and surfaces exactly one diagnostic line.
        let lines: Vec<String> = config::recover_publications(&mut store)?
            .iter()
            .filter_map(recovery_diagnostic)
            .collect();
        assert_eq!(lines.len(), 1, "one unresolved verdict, one line");
        assert!(lines[0].contains("old"));
        assert!(lines[0].contains(&*target.to_string_lossy()));

        // The healed crash window — intended bytes under the staged
        // inode — receipts and emits nothing.
        std::fs::write(&target, &edit.bytes)?;
        let silent: Vec<String> = config::recover_publications(&mut store)?
            .iter()
            .filter_map(recovery_diagnostic)
            .collect();
        assert!(
            silent.is_empty(),
            "the receipted verdict emits no diagnostic: {silent:?}"
        );
        drop(std::fs::remove_dir_all(&root));
        Ok(())
    }
}
