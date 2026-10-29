//! The declared MCP wire subset: a blocking JSON-RPC client over a child
//! process's stdio, with the logical operation bound to the executor's own
//! attempt ledger.
//!
//! `rmcp` is not admitted (DEC-005): its transport is async while this build
//! authors no product async code, and AC-075 grades continuation, honest
//! outcomes and credential origin — not platform breadth. This module
//! therefore declares exactly what it speaks ([`MCP_DECLARED_METHODS`],
//! [`MCP_PROTOCOL_VERSION`]) and refuses anything else as a typed refusal, so
//! an unsupported peer degrades visibly instead of being guessed at.
//!
//! A request names a server; it never supplies one. The program, its
//! arguments, its environment and the origin the egress is admitted against
//! come from the operator's own `[mcp.servers.<name>]` declaration
//! ([`crate::config::McpServerDeclaration`]), so the origin a credential is
//! enrolled for is compared against operator data rather than against a string
//! the request carried. `arguments` is opaque passthrough — the tool's own
//! input, forwarded verbatim — and a scoped credential reference arriving there
//! is refused, because credential material reaches the child as environment
//! material and never as a frame field.
//!
//! INV-004 shapes the persistence: the logical operation *is* the attempt id
//! the executor already plans, and every durable fact about it is written
//! through the store's existing `retained` and `attempts` owners. No second
//! ledger, no second operation identity.
//!
//! `tools/call` is consumptive — one attempt may mutate external state, so a
//! rerun is not equivalent. The one-shot contract (`standards/one-shot-actions.md`)
//! is met here: the pre-send claim and the retained line are written before
//! the first byte, every terminal path appends a bounded line to
//! `reports/mcp-<operation>.jsonl`, the failure seams carry stable
//! [`MCP_BOUNDARY_IDS`] fingerprints through [`McpReason`], and cleanup never
//! touches the artifact.

use crate::config::{McpCredentialDeclaration, McpServerDeclaration, is_bounded_origin};
use crate::contracts::{ErrorCode, TaskId};
use crate::providers::{CredentialStore, SecretRef};
use crate::state::TaskStore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Digest;
use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::time::{Duration, Instant};

/// The one wire version this client declares. A peer that answers with
/// another version ends as a typed `unsupported_version` refusal that names
/// this domain — never as a fallback handshake loop.
pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

/// The handshake that opens a session. No byte of it can carry a call's
/// effect, so the cancellation watch reads a failure while only this frame has
/// left as pre-send.
const MCP_HANDSHAKE_METHOD: &str = "initialize";

/// The one method whose frame carries the call's effect. The classification of
/// a settlement reads this frame's own bytes rather than the session's total,
/// which the handshake has already grown.
const MCP_CALL_METHOD: &str = "tools/call";

/// The methods this client speaks. A reply to anything else is a
/// `capability_unavailable` refusal, not a scheme this build invents.
pub const MCP_DECLARED_METHODS: &[&str] = &[MCP_HANDSHAKE_METHOD, MCP_CALL_METHOD];

/// One bounded wait: an answer, a stop, or the peer's death — never an
/// unbounded read.
pub const MCP_WAIT_TIMEOUT: Duration = Duration::from_secs(2);

/// One bounded write: a peer that stops reading its own stdin must not hold
/// the turn, so a frame past this bound ends the call as an unknown outcome
/// instead of waiting for a drain that never comes.
pub const MCP_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// The poll slice the reader thread, the wait loop and a draining write turn
/// on, so a stop is observed promptly even while a pipe stays open.
const MCP_POLL_SLICE: Duration = Duration::from_millis(20);

/// One frame past this bound is a framing refusal, never a retained blob.
pub const MCP_FRAME_MAX_BYTES: usize = 64 * 1024;

/// The largest request this client hands a peer. The bound is a write bound,
/// not a pipe bound: a payload past it is refused before the write, and one
/// under it still has to drain within [`MCP_WRITE_TIMEOUT`].
pub const MCP_REQUEST_MAX_BYTES: usize = 4 * MCP_FRAME_MAX_BYTES;

/// Frames the reader may queue past the caller's own request. A peer that
/// answers twice for one request is a protocol violation, not a backlog.
const MCP_FRAME_QUEUE: usize = 2;

/// Lines retained per logical operation (INV-010: every persistent kind
/// carries a named bound).
pub const MCP_RETAINED_MAX_LINES: usize = 64;

/// Bytes retained per line: a longer record is replaced by a fixed bounded
/// one, so a hostile peer cannot grow the artifact.
pub const MCP_RETAINED_MAX_LINE_BYTES: usize = 4096;

/// The workspace directory the retained artifacts live in — outside the
/// disposable child trees, so cleanup cannot take the evidence with it.
pub const MCP_REPORTS_DIR: &str = "reports";

/// The id a seam reports when the map somehow does not carry it. It exists so
/// the lookup is total without a panic; a case asserts every seam maps to its
/// own id, so this value can never stand for one in a shipped record.
pub const MCP_UNMAPPED_BOUNDARY_ID: &str = "MCP-0";

/// The base environment a declared server inherits. Credentials, provider
/// keys, the assistant's own session state and `HOME` — the data root the
/// retained evidence lives under — stay out of a child's environment
/// (AGENTS §11G); a server declares the rest itself.
const MCP_ENV_ALLOWLIST: &[&str] = &["PATH"];

/// The fields only the operator's declaration may set. A request that carries
/// one is supplying a program, an environment or a destination, so it is
/// refused instead of being half-trusted.
pub const MCP_CALLER_SUPPLIED_FIELDS: &[&str] = &["program", "args", "env", "origin", "credential"];

/// The seams that can emit a retained record or a typed refusal. The map is
/// finite and injective ([`MCP_BOUNDARY_IDS`]): one retained fingerprint
/// names one actionable failure site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum McpSeam {
    /// The pre-send seam: the record of the claim itself, and every
    /// settlement this side writes for its own call — an artifact that
    /// cannot be retained, a refused credential, an admission withdrawn
    /// before the first byte, a cancelled task, a cancellation this side
    /// cannot read, a destination the executor refuses, an operation whose
    /// earlier send was never reconciled. The settlement line's `bytes_sent`
    /// counts every byte the session wrote — the handshake included — while
    /// the seam itself reads the call frame's own bytes, so a handshake in
    /// that count is never taken for a call frame's size.
    PreSend,
    /// The peer's bytes are not one bounded JSON-RPC line, or this client's
    /// request is not one.
    Framing,
    /// A well-formed refusal: a JSON-RPC error, another protocol version, an
    /// unknown result type, or a session that could not start.
    Protocol,
    /// The bounded wait or the bounded write expired.
    Timeout,
    /// The peer, or the pipe to it, ended before it answered.
    Signal,
    /// The cleanup verdict after a non-success terminal path.
    Cleanup,
}

impl McpSeam {
    /// Every seam, in map order — the completeness sweep reads this.
    pub const ALL: [Self; 6] = [
        Self::PreSend,
        Self::Framing,
        Self::Protocol,
        Self::Timeout,
        Self::Signal,
        Self::Cleanup,
    ];

    /// The stable spelling of this seam in diagnostics.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreSend => "pre_send",
            Self::Framing => "framing",
            Self::Protocol => "protocol",
            Self::Timeout => "timeout",
            Self::Signal => "signal",
            Self::Cleanup => "cleanup",
        }
    }
}

/// The one seam-to-fingerprint map. Every emit site reads its id from here.
pub const MCP_BOUNDARY_IDS: &[(&str, McpSeam)] = &[
    ("MCP-1", McpSeam::PreSend),
    ("MCP-2", McpSeam::Framing),
    ("MCP-3", McpSeam::Protocol),
    ("MCP-4", McpSeam::Timeout),
    ("MCP-5", McpSeam::Signal),
    ("MCP-6", McpSeam::Cleanup),
];

/// Every reason this module can retain, and the seam that owns it. An emit
/// site names its reason here and reads its fingerprint from that seam, so a
/// record can never carry a code the map does not place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum McpReason {
    ArtifactUnavailable,
    ClaimUnavailable,
    CredentialRefused,
    CancellationUnreadable,
    AdmissionWithdrawn,
    Cancelled,
    DestinationRefused,
    UnreconciledOperation,
    MalformedFrame,
    RequestNotEncodable,
    RequestOverBound,
    FrameOverBound,
    AnswersOverBound,
    AnswerNamesAnotherRequest,
    AnswerCarriesNoResult,
    ReadUnavailable,
    ReadFailed,
    UndeclaredMethod,
    ProtocolError,
    SpawnFailed,
    MissingProtocolVersion,
    UnsupportedProtocolVersion,
    UnknownResultType,
    ContinuationWithoutHandle,
    ContinuationHandleUnbounded,
    Timeout,
    WriteTimeout,
    SignalDeath,
    PeerClosed,
    ReaderClosed,
    StdinClosed,
    StdinUnavailable,
    WriteClosed,
    WriteFailed,
    CleanupIncomplete,
}

impl McpReason {
    /// Every reason, in map order — the completeness sweep reads this.
    pub const ALL: [Self; 35] = [
        Self::ArtifactUnavailable,
        Self::ClaimUnavailable,
        Self::CredentialRefused,
        Self::CancellationUnreadable,
        Self::AdmissionWithdrawn,
        Self::Cancelled,
        Self::DestinationRefused,
        Self::UnreconciledOperation,
        Self::MalformedFrame,
        Self::RequestNotEncodable,
        Self::RequestOverBound,
        Self::FrameOverBound,
        Self::AnswersOverBound,
        Self::AnswerNamesAnotherRequest,
        Self::AnswerCarriesNoResult,
        Self::ReadUnavailable,
        Self::ReadFailed,
        Self::UndeclaredMethod,
        Self::ProtocolError,
        Self::SpawnFailed,
        Self::MissingProtocolVersion,
        Self::UnsupportedProtocolVersion,
        Self::UnknownResultType,
        Self::ContinuationWithoutHandle,
        Self::ContinuationHandleUnbounded,
        Self::Timeout,
        Self::WriteTimeout,
        Self::SignalDeath,
        Self::PeerClosed,
        Self::ReaderClosed,
        Self::StdinClosed,
        Self::StdinUnavailable,
        Self::WriteClosed,
        Self::WriteFailed,
        Self::CleanupIncomplete,
    ];

    /// The stable spelling of this reason in a retained record.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactUnavailable => "artifact_unavailable",
            Self::ClaimUnavailable => "claim_unavailable",
            Self::CredentialRefused => "credential_refused",
            Self::CancellationUnreadable => "cancellation_unreadable",
            Self::AdmissionWithdrawn => "admission_withdrawn",
            Self::Cancelled => "cancelled",
            Self::DestinationRefused => "destination_refused",
            Self::UnreconciledOperation => "unreconciled_operation",
            Self::MalformedFrame => "malformed_frame",
            Self::RequestNotEncodable => "request_not_encodable",
            Self::RequestOverBound => "request_over_bound",
            Self::FrameOverBound => "frame_over_bound",
            Self::AnswersOverBound => "answers_over_bound",
            Self::AnswerNamesAnotherRequest => "answer_names_another_request",
            Self::AnswerCarriesNoResult => "answer_carries_no_result",
            Self::ReadUnavailable => "read_unavailable",
            Self::ReadFailed => "read_failed",
            Self::UndeclaredMethod => "undeclared_method",
            Self::ProtocolError => "protocol_error",
            Self::SpawnFailed => "spawn_failed",
            Self::MissingProtocolVersion => "missing_protocol_version",
            Self::UnsupportedProtocolVersion => "unsupported_protocol_version",
            Self::UnknownResultType => "unknown_result_type",
            Self::ContinuationWithoutHandle => "continuation_without_handle",
            Self::ContinuationHandleUnbounded => "continuation_handle_unbounded",
            Self::Timeout => "timeout",
            Self::WriteTimeout => "write_timeout",
            Self::SignalDeath => "signal_death",
            Self::PeerClosed => "peer_closed",
            Self::ReaderClosed => "reader_closed",
            Self::StdinClosed => "stdin_closed",
            Self::StdinUnavailable => "stdin_unavailable",
            Self::WriteClosed => "write_closed",
            Self::WriteFailed => "write_failed",
            Self::CleanupIncomplete => "cleanup_incomplete",
        }
    }

    /// The seam this reason is retained at.
    #[must_use]
    pub fn seam(self) -> McpSeam {
        match self {
            Self::ArtifactUnavailable
            | Self::ClaimUnavailable
            | Self::CredentialRefused
            | Self::CancellationUnreadable
            | Self::AdmissionWithdrawn
            | Self::Cancelled
            | Self::DestinationRefused
            | Self::UnreconciledOperation => McpSeam::PreSend,
            Self::MalformedFrame
            | Self::RequestNotEncodable
            | Self::RequestOverBound
            | Self::FrameOverBound
            | Self::AnswersOverBound
            | Self::AnswerNamesAnotherRequest
            | Self::AnswerCarriesNoResult
            | Self::ReadUnavailable
            | Self::ReadFailed => McpSeam::Framing,
            Self::UndeclaredMethod
            | Self::ProtocolError
            | Self::SpawnFailed
            | Self::MissingProtocolVersion
            | Self::UnsupportedProtocolVersion
            | Self::UnknownResultType
            | Self::ContinuationWithoutHandle
            | Self::ContinuationHandleUnbounded => McpSeam::Protocol,
            Self::Timeout | Self::WriteTimeout => McpSeam::Timeout,
            Self::SignalDeath
            | Self::PeerClosed
            | Self::ReaderClosed
            | Self::StdinClosed
            | Self::StdinUnavailable
            | Self::WriteClosed
            | Self::WriteFailed => McpSeam::Signal,
            Self::CleanupIncomplete => McpSeam::Cleanup,
        }
    }
}

/// The stable fingerprint of one seam.
#[must_use]
pub fn boundary_id(seam: McpSeam) -> &'static str {
    MCP_BOUNDARY_IDS
        .iter()
        .find(|(_, mapped)| *mapped == seam)
        .map_or(MCP_UNMAPPED_BOUNDARY_ID, |(id, _)| *id)
}

/// The first alias in a candidate map: two seams sharing one fingerprint
/// make a retained record ambiguous about which site failed, so the map is
/// rejected rather than used. `None` is an injective map.
#[must_use]
pub fn boundary_collision(
    map: &[(&'static str, McpSeam)],
) -> Option<(&'static str, McpSeam, McpSeam)> {
    for (index, (id, seam)) in map.iter().enumerate() {
        for (seen, (other_id, other)) in map.iter().enumerate() {
            if seen != index && other_id == id && other != seam {
                return Some((id, *seam, *other));
            }
        }
    }
    None
}

/// The terminal size of one logical operation. `InputRequired` is not
/// terminal: the remote call is pending and the continuation handle carries
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpState {
    Succeeded,
    Failed,
    OutcomeUnknown,
    InputRequired,
}

impl McpState {
    /// The stable spelling of this state on the wire and in the store.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::OutcomeUnknown => "outcome_unknown",
            Self::InputRequired => "input_required",
        }
    }

    /// Whether the operation reached a settled terminal state.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::OutcomeUnknown)
    }
}

/// Owner-local refusals. Everything the peer does after the first byte is an
/// *outcome* ([`McpOutcome`]), not an error: a remote effect that may have
/// happened is data about the operation, never a transport failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum McpError {
    #[error("mcp call names no `{field}`")]
    MissingField { field: &'static str },
    #[error("mcp call field `{field}` is not the declared shape: {cause}")]
    MalformedField { field: &'static str, cause: String },
    #[error("mcp call supplies `{field}`, which only the server declaration may set")]
    CallerSuppliedField { field: &'static str },
    #[error("mcp server {server} is not declared by this installation")]
    UndeclaredServer { server: String },
    #[error("mcp server name {name} is not a bounded identifier")]
    InvalidServerName { name: String },
    #[error("mcp server {name} declares no absolute program to launch")]
    InvalidProgram { name: String },
    /// The document refuses this spelling at parse
    /// ([`crate::config::ConfigIssue::McpOriginInvalid`]); this answer guards
    /// a server built outside it and names the same accepted form.
    #[error(
        "mcp server {name} declares an origin that is not <scheme>://<host> over ASCII letters, digits or . _ - : / +, at most 128 characters"
    )]
    InvalidOrigin { name: String },
    #[error("mcp tool {tool} is not a bounded identifier")]
    InvalidTool { tool: String },
    #[error("mcp server {name} declares an environment variable that is reserved: {variable}")]
    ReservedEnvironment { name: String, variable: String },
    #[error("mcp call arguments carry a credential reference at {field}")]
    ArgumentsCarryCredential { field: String },
    #[error("mcp operation {operation} is not a bounded identifier")]
    InvalidOperation { operation: String },
    #[error("mcp operation {operation} was never opened by this store")]
    UnknownOperation { operation: String },
    #[error("mcp operation {operation} was opened for another {field}")]
    OperationMismatch {
        operation: String,
        field: &'static str,
    },
    #[error("credential for server {server} is enrolled for a different origin: {enrolled}")]
    CredentialOriginMismatch { server: String, enrolled: String },
    #[error("credential reference for server {server} is not a scoped store:scope reference")]
    CredentialMalformed { server: String, cause: String },
    #[error("server {server} declares a credential reference but no credential store is bound")]
    CredentialUnavailable { server: String },
    #[error("credential for server {server} is unresolved: {cause}")]
    CredentialUnresolved { server: String, cause: String },
    #[error("credential for server {server} is not usable as environment material")]
    CredentialNotMaterial { server: String, cause: String },
    #[error("mcp call to {server} was refused before its first byte: {cause}")]
    AdmissionWithdrawn { server: String, cause: String },
    #[error("mcp operation {operation} was cancelled before it was sent")]
    Cancelled { operation: String },
    #[error("mcp operation {operation} cannot record its pre-send claim: {cause}")]
    PreSend { operation: String, cause: String },
    #[error("mcp server {server} could not start: {cause}")]
    Spawn { server: String, cause: String },
    #[error("mcp operation {operation} has no readable record: {cause}")]
    Record { operation: String, cause: String },
}

impl McpError {
    /// The wire code this refusal carries.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::MissingField { .. }
            | Self::MalformedField { .. }
            | Self::CallerSuppliedField { .. }
            | Self::InvalidServerName { .. }
            | Self::InvalidProgram { .. }
            | Self::InvalidOrigin { .. }
            | Self::InvalidTool { .. }
            | Self::ReservedEnvironment { .. }
            | Self::ArgumentsCarryCredential { .. }
            | Self::InvalidOperation { .. } => ErrorCode::InvalidInput,
            Self::UndeclaredServer { .. } | Self::UnknownOperation { .. } => ErrorCode::NotFound,
            Self::OperationMismatch { .. } => ErrorCode::Conflict,
            Self::CredentialOriginMismatch { .. } | Self::AdmissionWithdrawn { .. } => {
                ErrorCode::Denied
            }
            Self::Cancelled { .. } => ErrorCode::Cancelled,
            Self::CredentialMalformed { .. } | Self::CredentialNotMaterial { .. } => {
                ErrorCode::InvalidInput
            }
            Self::CredentialUnavailable { .. } => ErrorCode::CapabilityUnavailable,
            Self::CredentialUnresolved { .. } => ErrorCode::DependencyBlocked,
            Self::PreSend { .. } | Self::Record { .. } => ErrorCode::StorageUnavailable,
            Self::Spawn { .. } => ErrorCode::CapabilityUnavailable,
        }
    }

    /// The seam this refusal was emitted at, when it has one.
    #[must_use]
    pub fn boundary_id(&self) -> Option<&'static str> {
        match self {
            Self::PreSend { .. } => Some(boundary_id(McpSeam::PreSend)),
            _ => None,
        }
    }
}

/// One declared server, as the call path reads it: the operator's declaration
/// under the name a request used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServer {
    pub name: String,
    /// The server's declared identity — what the executor's egress admission
    /// binds the destination to and what a credential reference is enrolled
    /// for, so a reference for another origin can never be handed to this
    /// child.
    pub origin: String,
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub credential: Option<McpCredentialDeclaration>,
}

impl McpServer {
    /// The server one declaration names.
    #[must_use]
    pub fn declared(name: &str, declaration: &McpServerDeclaration) -> Self {
        Self {
            name: name.to_string(),
            origin: declaration.origin.clone(),
            program: declaration.program.clone(),
            args: declaration.args.clone(),
            env: declaration.env.clone(),
            credential: declaration.credential.clone(),
        }
    }
}

/// The part of a `mcp.call` request the caller owns: which declared server to
/// name, which tool to call, the arguments to pass and the optional operation
/// to continue. The program, its environment and the origin are not in here —
/// they are the operator's declaration, and a request that carries them is
/// refused rather than half-trusted.
#[derive(Debug, Clone, PartialEq)]
pub struct McpRequest {
    pub server: String,
    pub tool: String,
    pub arguments: Value,
    pub operation: Option<String>,
}

impl McpRequest {
    /// The typed request a `mcp.call` carrier names. A malformed field is a
    /// refusal of that field, never a guess.
    ///
    /// # Errors
    /// [`McpError::MissingField`]/[`McpError::MalformedField`] when the
    /// carrier does not hold the declared shape, and
    /// [`McpError::CallerSuppliedField`] when the request tries to supply the
    /// program, environment, credential or origin a declaration owns.
    pub fn from_value(params: &Value) -> Result<Self, McpError> {
        if let Some(server) = params.get("server")
            && !server.is_string()
        {
            if let Some(field) = MCP_CALLER_SUPPLIED_FIELDS
                .iter()
                .find(|field| server.get(field).is_some())
            {
                return Err(McpError::CallerSuppliedField { field });
            }
            return Err(McpError::MalformedField {
                field: "server",
                cause: "server is not a declared server name".to_string(),
            });
        }
        if let Some(field) = MCP_CALLER_SUPPLIED_FIELDS
            .iter()
            .find(|field| params.get(field).is_some())
        {
            return Err(McpError::CallerSuppliedField { field });
        }
        let server = params
            .get("server")
            .and_then(Value::as_str)
            .ok_or(McpError::MissingField { field: "server" })?
            .to_string();
        let tool = params
            .get("tool")
            .and_then(Value::as_str)
            .ok_or(McpError::MissingField { field: "tool" })?
            .to_string();
        let arguments = params
            .get("arguments")
            .cloned()
            .ok_or(McpError::MissingField { field: "arguments" })?;
        if !arguments.is_object() {
            return Err(McpError::MalformedField {
                field: "arguments",
                cause: "arguments is not an object".to_string(),
            });
        }
        let operation = match params.get("operation") {
            None | Some(Value::Null) => None,
            Some(Value::String(operation)) => Some(operation.clone()),
            Some(_) => {
                return Err(McpError::MalformedField {
                    field: "operation",
                    cause: "operation is not a string".to_string(),
                });
            }
        };
        Ok(Self {
            server,
            tool,
            arguments,
            operation,
        })
    }
}

/// One logical operation's call: the settled operation it continues, or a
/// fresh one, bound to the server its name declares.
#[derive(Debug, Clone, PartialEq)]
pub struct McpCall {
    pub server: McpServer,
    pub tool: String,
    pub arguments: Value,
    pub operation: Option<String>,
}

impl McpCall {
    /// Binds a caller-owned request to the one server its name declares.
    #[must_use]
    pub fn declared(request: &McpRequest, declaration: &McpServerDeclaration) -> Self {
        Self {
            server: McpServer::declared(&request.server, declaration),
            tool: request.tool.clone(),
            arguments: request.arguments.clone(),
            operation: request.operation.clone(),
        }
    }

    /// The shape checks that must hold before anything is planned, spawned or
    /// sent: a credential enrolled for another origin — both sides of the
    /// comparison now operator data — and a credential reference smuggled into
    /// the arguments are refused here, before the first byte.
    ///
    /// # Errors
    /// [`McpError::CredentialOriginMismatch`] when the declared reference was
    /// enrolled for another origin; [`McpError::ArgumentsCarryCredential`]
    /// when the arguments carry a scoped reference; the shape refusals
    /// otherwise.
    pub fn validate(&self) -> Result<(), McpError> {
        let server = &self.server;
        if !is_bounded_token(&server.name, 64) {
            return Err(McpError::InvalidServerName {
                name: server.name.clone(),
            });
        }
        if !server.program.is_absolute() {
            return Err(McpError::InvalidProgram {
                name: server.name.clone(),
            });
        }
        if !is_bounded_origin(&server.origin) {
            return Err(McpError::InvalidOrigin {
                name: server.name.clone(),
            });
        }
        if !is_bounded_token(&self.tool, 128) {
            return Err(McpError::InvalidTool {
                tool: self.tool.clone(),
            });
        }
        for variable in server.env.keys() {
            if !is_bounded_variable(variable) {
                return Err(McpError::ReservedEnvironment {
                    name: server.name.clone(),
                    variable: variable.clone(),
                });
            }
        }
        if let Some(credential) = &server.credential {
            if let Err(cause) = SecretRef::parse(&credential.reference) {
                return Err(McpError::CredentialMalformed {
                    server: server.name.clone(),
                    cause: cause.to_string(),
                });
            }
            if !is_bounded_variable(&credential.variable) {
                return Err(McpError::ReservedEnvironment {
                    name: server.name.clone(),
                    variable: credential.variable.clone(),
                });
            }
            if credential.origin != server.origin {
                return Err(McpError::CredentialOriginMismatch {
                    server: server.name.clone(),
                    enrolled: credential.origin.clone(),
                });
            }
        }
        if let Some(field) = scoped_reference_in(&self.arguments) {
            return Err(McpError::ArgumentsCarryCredential { field });
        }
        if let Some(operation) = &self.operation
            && !is_bounded_operation(operation)
        {
            return Err(McpError::InvalidOperation {
                operation: operation.clone(),
            });
        }
        Ok(())
    }
}

/// The first field of `arguments` whose string value is a scoped credential
/// reference. The walk is iterative, so a deeply nested payload cannot exhaust
/// the stack, and the answer names the field rather than echoing any value.
fn scoped_reference_in(arguments: &Value) -> Option<String> {
    let mut pending: Vec<(&str, &Value)> = vec![("arguments", arguments)];
    while let Some((field, value)) = pending.pop() {
        match value {
            Value::String(text) => {
                if SecretRef::parse(text).is_ok() {
                    return Some(field.to_string());
                }
            }
            Value::Array(items) => {
                for item in items {
                    pending.push((field, item));
                }
            }
            Value::Object(fields) => {
                for (name, item) in fields {
                    pending.push((name.as_str(), item));
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    None
}

fn is_bounded_token(raw: &str, max: usize) -> bool {
    !raw.is_empty()
        && raw.len() <= max
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/'))
}

fn is_bounded_operation(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 64
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn is_bounded_variable(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 64
        && raw.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && raw
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && !raw.starts_with("LD_")
        && !raw.starts_with("DYLD_")
        && !MCP_ENV_ALLOWLIST.contains(&raw)
}

/// One retained line of one logical operation. Every field is bounded or a
/// closed vocabulary; a peer's bytes reach it only as a fixed reason code or
/// a digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetainedLine {
    pub logical_operation_id: String,
    /// `send`, `input_required`, `terminal` or `cleanup` — what this line is.
    pub record: &'static str,
    /// The terminal state, for a `terminal` line.
    pub outcome: Option<&'static str>,
    pub boundary_id: Option<String>,
    pub reason_code: Option<String>,
    pub server_origin: String,
    /// Every byte this session wrote, the `initialize` handshake included: a
    /// handshake-only count is not the size of a call frame.
    pub bytes_sent: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_version_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_reaped: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reader_joined: Option<bool>,
}

impl RetainedLine {
    fn sanitize(&mut self) {
        if !is_bounded_origin(&self.server_origin) {
            self.server_origin = REDACTED_ORIGIN.to_string();
        }
    }
}

const REDACTED_ORIGIN: &str = "<redacted-origin>";

/// The retained artifact of one logical operation: one open handle, written
/// and flushed before the first side effect and after every terminal path.
/// Cleanup closes it; nothing deletes or rewrites it.
pub struct RetainedLog {
    file: std::fs::File,
    path: PathBuf,
    operation: String,
    lines: usize,
}

impl RetainedLog {
    /// Opens (or resumes) the operation's artifact under `root/reports`.
    ///
    /// # Errors
    /// [`McpError::PreSend`] when the identifier is not bounded or the
    /// directory or file cannot be created.
    pub fn open(root: &Path, operation: &str) -> Result<Self, McpError> {
        if !is_bounded_operation(operation) {
            return Err(McpError::PreSend {
                operation: operation.to_string(),
                cause: "identifier is not bounded".to_string(),
            });
        }
        let directory = root.join(MCP_REPORTS_DIR);
        std::fs::create_dir_all(&directory).map_err(|source| McpError::PreSend {
            operation: operation.to_string(),
            cause: source.kind().to_string(),
        })?;
        let path = directory.join(format!("mcp-{operation}.jsonl"));
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| McpError::PreSend {
                operation: operation.to_string(),
                cause: source.kind().to_string(),
            })?;
        let lines = std::fs::read_to_string(&path)
            .map(|written| written.lines().count())
            .unwrap_or(0);
        Ok(Self {
            file,
            path,
            operation: operation.to_string(),
            lines,
        })
    }

    /// The artifact this log appends to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one bounded line and flushes it durably. A line past the
    /// per-operation bound is dropped: the bound is the policy, and the
    /// pre-send claim is always the first line of the file.
    ///
    /// # Errors
    /// [`McpError::PreSend`] when the write or the flush fails.
    pub fn append(&mut self, line: &RetainedLine) -> Result<(), McpError> {
        if self.lines >= MCP_RETAINED_MAX_LINES {
            return Ok(());
        }
        let mut line = line.clone();
        line.sanitize();
        let mut encoded = serde_json::to_string(&line).map_err(|source| McpError::PreSend {
            operation: self.operation.clone(),
            cause: source.to_string(),
        })?;
        if encoded.len() > MCP_RETAINED_MAX_LINE_BYTES {
            encoded = serde_json::to_string(&RetainedLine {
                server_origin: REDACTED_ORIGIN.to_string(),
                peer_version_digest: None,
                child_reaped: line.child_reaped,
                reader_joined: line.reader_joined,
                ..line
            })
            .map_err(|source| McpError::PreSend {
                operation: self.operation.clone(),
                cause: source.to_string(),
            })?;
        }
        encoded.push('\n');
        self.file
            .write_all(encoded.as_bytes())
            .and_then(|()| self.file.flush())
            .map_err(|source| McpError::PreSend {
                operation: self.operation.clone(),
                cause: source.kind().to_string(),
            })?;
        self.lines += 1;
        Ok(())
    }
}

/// One logical operation's continuation: the peer's opaque handle, bound to
/// the operation that owns it. Two `input_required` answers for one operation
/// keep the first handle — a later handle names a state this client did not
/// create.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Continuation {
    pub handle: String,
    pub logical_operation_id: String,
}

/// What one logical operation ended as, on the surface and in the store.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct McpOutcome {
    pub operation: String,
    pub attempt: String,
    pub state: McpState,
    pub code: Option<ErrorCode>,
    pub message: Option<String>,
    pub boundary_id: Option<String>,
    pub reason_code: Option<String>,
    pub continuation: Option<Continuation>,
    pub result: Option<Value>,
    /// Every byte this session wrote, the `initialize` handshake included, so
    /// the count describes the session and never only the call frame.
    pub bytes_sent: u64,
    pub artifact: String,
    pub peer_version_digest: Option<String>,
}

impl McpOutcome {
    /// This outcome as the `mcp.call` result payload.
    #[must_use]
    pub fn wire(&self, server: &str) -> Value {
        json!({
            "schema_version": crate::contracts::SCHEMA_VERSION,
            "kind": "mcp.call",
            "server": server,
            "logical_operation_id": self.operation,
            "attempt_id": self.attempt,
            "state": self.state.as_str(),
            "code": self.code,
            "message": self.message,
            "boundary_id": self.boundary_id,
            "reason_code": self.reason_code,
            "continuation": self.continuation,
            "result": self.result,
            "bytes_sent": self.bytes_sent,
            "artifact": self.artifact,
        })
    }
}

/// The durable claim written before the first byte: this operation exists,
/// and it exists once.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OperationClaim {
    operation: String,
    attempt: String,
    server: String,
    origin: String,
    tool: String,
    artifact: String,
}

impl OperationClaim {
    /// A continuation must name what the claim opened: an operation id is not
    /// a handle onto a different program, a different destination or a
    /// different tool.
    fn assert_same_call(&self, operation: &str, call: &McpCall) -> Result<(), McpError> {
        let field = if self.server != call.server.name {
            "server"
        } else if self.origin != call.server.origin {
            "origin"
        } else if self.tool != call.tool {
            "tool"
        } else {
            return Ok(());
        };
        Err(McpError::OperationMismatch {
            operation: operation.to_string(),
            field,
        })
    }
}

/// The durable terminal record of one operation, read back before anything
/// could be sent again.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TerminalRecord {
    operation: String,
    attempt: String,
    state: McpState,
    boundary_id: Option<String>,
    reason_code: Option<String>,
    code: Option<ErrorCode>,
    message: Option<String>,
    continuation: Option<Continuation>,
    bytes_sent: u64,
    artifact: String,
    peer_version_digest: Option<String>,
}

fn claim_boundary(operation: &str) -> String {
    format!("mcp:{operation}:claim")
}

fn continuation_boundary(operation: &str) -> String {
    format!("mcp:{operation}:continuation")
}

fn terminal_boundary(operation: &str) -> String {
    format!("mcp:{operation}:terminal")
}

fn artifact_relative(operation: &str) -> String {
    format!("{MCP_REPORTS_DIR}/mcp-{operation}.jsonl")
}

fn read_record<T: serde::de::DeserializeOwned>(
    store: &TaskStore,
    boundary: &str,
    operation: &str,
) -> Result<Option<T>, McpError> {
    let Some(stored) = store
        .retained(boundary)
        .map_err(|source| McpError::Record {
            operation: operation.to_string(),
            cause: source.to_string(),
        })?
    else {
        return Ok(None);
    };
    let parsed: T = serde_json::from_str(&stored).map_err(|source| McpError::Record {
        operation: operation.to_string(),
        cause: source.to_string(),
    })?;
    Ok(Some(parsed))
}

fn write_record<T: Serialize>(
    store: &mut TaskStore,
    boundary: &str,
    operation: &str,
    value: &T,
) -> Result<(), McpError> {
    let encoded = serde_json::to_string(value).map_err(|source| McpError::Record {
        operation: operation.to_string(),
        cause: source.to_string(),
    })?;
    store
        .retain(&encoded, boundary)
        .map_err(|source| McpError::Record {
            operation: operation.to_string(),
            cause: source.to_string(),
        })
}

fn terminal_record(outcome: &McpOutcome) -> TerminalRecord {
    TerminalRecord {
        operation: outcome.operation.clone(),
        attempt: outcome.attempt.clone(),
        state: outcome.state,
        boundary_id: outcome.boundary_id.clone(),
        reason_code: outcome.reason_code.clone(),
        code: outcome.code,
        message: outcome.message.clone(),
        continuation: outcome.continuation.clone(),
        bytes_sent: outcome.bytes_sent,
        artifact: outcome.artifact.clone(),
        peer_version_digest: outcome.peer_version_digest.clone(),
    }
}

/// The settled outcome of one logical operation, when it has one. A caller
/// reads this before planning any attempt: a settled operation is answered
/// from the record and nothing is sent again.
///
/// # Errors
/// [`McpError::Record`] when the durable row cannot be read, parsed, or names
/// another operation.
pub fn recorded(store: &TaskStore, operation: &str) -> Result<Option<McpOutcome>, McpError> {
    let Some(record) =
        read_record::<TerminalRecord>(store, &terminal_boundary(operation), operation)?
    else {
        return Ok(None);
    };
    if record.operation != operation {
        return Err(McpError::Record {
            operation: operation.to_string(),
            cause: "the retained record names another operation".to_string(),
        });
    }
    Ok(Some(McpOutcome {
        operation: record.operation,
        attempt: record.attempt,
        state: record.state,
        code: record.code,
        message: record.message,
        boundary_id: record.boundary_id,
        reason_code: record.reason_code,
        continuation: record.continuation,
        result: None,
        bytes_sent: record.bytes_sent,
        artifact: record.artifact,
        peer_version_digest: record.peer_version_digest,
    }))
}

/// Whether this store opened the operation: only an operation it claimed can
/// be settled, so a caller-chosen id never lands a terminal row.
///
/// # Errors
/// [`McpError::Record`] when the claim row cannot be read.
pub fn opened(store: &TaskStore, operation: &str) -> Result<bool, McpError> {
    Ok(read_record::<OperationClaim>(store, &claim_boundary(operation), operation)?.is_some())
}

/// Settles an operation this store opened that can never be sent again — a
/// cancelled task, or a destination the executor refuses. The remote outcome
/// is unknown, so it is recorded as unknown: a pending remote call is never
/// reported as a success and never forgotten as a failure.
///
/// The settlement is the operation's own, so the destination it writes is the
/// one the claim recorded, not one a settling request names: the retained line
/// is the failure evidence, and evidence that names another destination is not
/// evidence of this operation. A settlement naming another server is refused
/// for the same reason — an id is not a handle onto another operation.
///
/// An operation id no claim owns is refused instead of settled: a caller that
/// names an arbitrary id never lands a durable row, so no retained line ever
/// claims a send the ledger does not hold.
///
/// # Errors
/// [`McpError::UnknownOperation`] when no claim owns the id;
/// [`McpError::OperationMismatch`] when the claim names another server;
/// [`McpError::Record`]/[`McpError::PreSend`] when the durable record or the
/// retained line cannot be written.
pub fn settle_unresolved(
    store: &mut TaskStore,
    reports_root: &Path,
    operation: &str,
    server: &str,
    reason: McpReason,
) -> Result<McpOutcome, McpError> {
    if let Some(existing) = recorded(store, operation)? {
        return Ok(existing);
    }
    let Some(claim) = read_record::<OperationClaim>(store, &claim_boundary(operation), operation)?
    else {
        return Err(McpError::UnknownOperation {
            operation: operation.to_string(),
        });
    };
    if claim.server != server {
        return Err(McpError::OperationMismatch {
            operation: operation.to_string(),
            field: "server",
        });
    }
    // The claim names the attempt that sent: a settled operation settles that
    // attempt too, so the ledger never reads as still in flight for an
    // operation the record already closed.
    if !claim.attempt.is_empty() {
        store
            .attempt_unknown(&claim.attempt, reason.as_str())
            .map_err(|source| McpError::Record {
                operation: operation.to_string(),
                cause: source.to_string(),
            })?;
    }
    let outcome = McpOutcome {
        operation: operation.to_string(),
        attempt: String::new(),
        state: McpState::OutcomeUnknown,
        code: None,
        message: None,
        boundary_id: Some(boundary_id(reason.seam()).to_string()),
        reason_code: Some(reason.as_str().to_string()),
        continuation: None,
        result: None,
        bytes_sent: 0,
        artifact: artifact_relative(operation),
        peer_version_digest: None,
    };
    write_record(
        store,
        &terminal_boundary(operation),
        operation,
        &terminal_record(&outcome),
    )?;
    let mut log = RetainedLog::open(reports_root, operation)?;
    log.append(&terminal_line(&outcome, &claim.origin))?;
    Ok(outcome)
}

fn terminal_line(outcome: &McpOutcome, origin: &str) -> RetainedLine {
    RetainedLine {
        logical_operation_id: outcome.operation.clone(),
        record: "terminal",
        outcome: Some(outcome.state.as_str()),
        boundary_id: outcome.boundary_id.clone(),
        reason_code: outcome.reason_code.clone(),
        server_origin: origin.to_string(),
        bytes_sent: outcome.bytes_sent,
        peer_version_digest: outcome.peer_version_digest.clone(),
        child_reaped: None,
        reader_joined: None,
    }
}

/// The cleanup verdict of one operation as a retained line. A verdict that
/// could not confirm both facts keeps [`McpReason::CleanupIncomplete`], so the
/// artifact names what cleanup could not confirm instead of dropping it.
/// `bytes_sent` repeats the session's own count — the handshake included — so
/// the cleanup line never reads as a call frame's size.
#[must_use]
pub fn cleanup_line(
    operation: &str,
    origin: &str,
    bytes_sent: u64,
    cleanup: Cleanup,
) -> RetainedLine {
    RetainedLine {
        logical_operation_id: operation.to_string(),
        record: "cleanup",
        outcome: None,
        boundary_id: Some(boundary_id(McpSeam::Cleanup).to_string()),
        reason_code: (!cleanup.is_clean())
            .then(|| McpReason::CleanupIncomplete.as_str().to_string()),
        server_origin: origin.to_string(),
        bytes_sent,
        peer_version_digest: None,
        child_reaped: Some(cleanup.child_reaped),
        reader_joined: Some(cleanup.reader_joined),
    }
}

/// One seam's refusal of a request: which reason was retained, why, and the
/// wire code it carries. Built at the emit site, so the fingerprint is never
/// guessed later.
#[derive(Clone)]
struct SeamFailure {
    reason: McpReason,
    state: McpState,
    code: ErrorCode,
    message: String,
}

fn bounded_peer_text(raw: &str, max: usize) -> String {
    if raw.is_empty()
        || raw.len() > max
        || !raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | ':' | '/'))
    {
        return "<redacted-peer-value>".to_string();
    }
    raw.to_string()
}

impl SeamFailure {
    fn seam(&self) -> McpSeam {
        self.reason.seam()
    }

    /// The peer's bytes are not one bounded JSON-RPC line: the call may have
    /// taken effect, so the outcome stays unknown.
    fn framing(reason: McpReason) -> Self {
        Self {
            reason,
            state: McpState::OutcomeUnknown,
            code: ErrorCode::CapabilityUnavailable,
            message: "the mcp server answered bytes that are not a bounded json-rpc line"
                .to_string(),
        }
    }

    fn framing_source(reason: McpReason, source: &serde_json::Error) -> Self {
        Self {
            message: format!(
                "the mcp server answered bytes this client cannot read: {:?}",
                source.classify()
            ),
            ..Self::framing(reason)
        }
    }

    /// This client's own request is not a frame it will hand a peer. Nothing
    /// reached the pipe, so the call did not take effect.
    fn request_refused(reason: McpReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            state: McpState::Failed,
            code: ErrorCode::CapabilityUnavailable,
            message: message.into(),
        }
    }

    fn write_failed(kind: ErrorKind) -> Self {
        Self {
            message: format!("the mcp server's stdin failed: {kind}"),
            ..Self::signal(McpReason::WriteFailed)
        }
    }

    /// A well-formed refusal: the peer answered, and its answer is a verdict,
    /// so the call did not take effect.
    fn protocol(reason: McpReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            state: McpState::Failed,
            code: ErrorCode::CapabilityUnavailable,
            message: message.into(),
        }
    }

    /// A well-formed answer this client cannot read as a verdict: the peer may
    /// have completed the call, so the outcome stays unknown.
    fn unreadable_verdict(reason: McpReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            state: McpState::OutcomeUnknown,
            code: ErrorCode::CapabilityUnavailable,
            message: message.into(),
        }
    }

    /// A refusal on this side of the first byte: nothing left, nothing took
    /// effect.
    fn pre_send(reason: McpReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            state: McpState::Failed,
            code: ErrorCode::StorageUnavailable,
            message: message.into(),
        }
    }

    /// A failure on this side after the first byte left. The cause is local,
    /// but the peer may hold the frame or its answer, so nothing here can
    /// claim the effect did not happen: the remote outcome stays unknown, the
    /// way it does for a stop observed in flight.
    fn unknown_after_send(reason: McpReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            state: McpState::OutcomeUnknown,
            code: ErrorCode::OutcomeUnknown,
            message: message.into(),
        }
    }

    /// The executor's admission was withdrawn between the plan and the first
    /// byte: still nothing left, so the call is a clean refusal.
    fn admission_withdrawn(message: impl Into<String>) -> Self {
        Self {
            reason: McpReason::AdmissionWithdrawn,
            state: McpState::Failed,
            code: ErrorCode::Denied,
            message: message.into(),
        }
    }

    /// A stop this side observed while the call was in flight: the peer may
    /// hold a prefix or the whole frame, so the remote outcome stays unknown.
    fn cancelled() -> Self {
        Self {
            reason: McpReason::Cancelled,
            state: McpState::OutcomeUnknown,
            code: ErrorCode::Cancelled,
            message: "the mcp call was cancelled before its outcome was known".to_string(),
        }
    }

    fn timeout() -> Self {
        Self {
            reason: McpReason::Timeout,
            state: McpState::OutcomeUnknown,
            code: ErrorCode::OutcomeUnknown,
            message: "the mcp server did not answer within the bounded wait".to_string(),
        }
    }

    /// The bounded write expired: the peer may hold a prefix of the frame, so
    /// the remote outcome stays unknown.
    fn write_timeout() -> Self {
        Self {
            reason: McpReason::WriteTimeout,
            state: McpState::OutcomeUnknown,
            code: ErrorCode::OutcomeUnknown,
            message: "the mcp server did not read its request within the bounded write".to_string(),
        }
    }

    fn signal(reason: McpReason) -> Self {
        Self {
            reason,
            state: McpState::OutcomeUnknown,
            code: ErrorCode::OutcomeUnknown,
            message: "the mcp server process ended before it answered".to_string(),
        }
    }
}

/// What the reader thread delivered.
enum Frame {
    Line(Vec<u8>),
    Eof,
    Failed(McpReason),
}

/// The reader thread body: bounded frames, one queue, and a stop flag that
/// ends it even while a peer or an escaped descendant keeps the pipe open.
fn read_frames(
    mut stdout: ChildStdout,
    frames: SyncSender<Frame>,
    stop: Arc<AtomicBool>,
    overflow: Arc<AtomicBool>,
) {
    if rivect_sandbox_helper::set_nonblocking(&stdout).is_err() {
        deliver(
            &frames,
            Frame::Failed(McpReason::ReadUnavailable),
            &overflow,
        );
        return;
    }
    let mut scratch = [0u8; 4096];
    let mut pending: Vec<u8> = Vec::new();
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        match stdout.read(&mut scratch) {
            Ok(0) => {
                deliver(&frames, Frame::Eof, &overflow);
                return;
            }
            Ok(read) => {
                pending.extend_from_slice(&scratch[..read]);
                if pending.len() > MCP_FRAME_MAX_BYTES {
                    deliver(&frames, Frame::Failed(McpReason::FrameOverBound), &overflow);
                    return;
                }
                while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                    let line: Vec<u8> = pending.drain(..=end).collect();
                    if !deliver(&frames, Frame::Line(line), &overflow) {
                        return;
                    }
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                let fd = stdout.as_fd();
                if rivect_sandbox_helper::wait_ready(&[fd], &[], MCP_POLL_SLICE).is_err() {
                    deliver(
                        &frames,
                        Frame::Failed(McpReason::ReadUnavailable),
                        &overflow,
                    );
                    return;
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => {
                deliver(&frames, Frame::Failed(McpReason::ReadFailed), &overflow);
                return;
            }
        }
    }
}

fn deliver(frames: &SyncSender<Frame>, frame: Frame, overflow: &AtomicBool) -> bool {
    match frames.try_send(frame) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            overflow.store(true, Ordering::Relaxed);
            false
        }
        Err(TrySendError::Disconnected(_)) => false,
    }
}

/// The cleanup verdict: the two facts cleanup must confirm, recorded on every
/// non-success terminal path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cleanup {
    pub child_reaped: bool,
    pub reader_joined: bool,
}

impl Cleanup {
    /// Nothing to clean yet — used by a path that refused before spawning.
    const NOTHING_TO_CLEAN: Self = Self {
        child_reaped: true,
        reader_joined: true,
    };

    /// Whether cleanup confirmed both facts.
    #[must_use]
    pub fn is_clean(self) -> bool {
        self.child_reaped && self.reader_joined
    }
}

/// The caller-owned re-consult of one call's admission. It runs immediately
/// before the first byte, so a grant revoked, an enrolled deny added or a
/// stricter mode landed after the plan still stops a consumptive call.
/// Cancellation is not part of it: the frame write watches the task itself, so
/// each guard has one owner.
pub trait FirstByteGate {
    /// Re-consults the grant, the enrolled denies and the permission mode of
    /// one destination.
    ///
    /// # Errors
    /// The caller's own typed refusal when the admission no longer holds.
    fn reconsult(&mut self, store: &TaskStore, server: &McpServer) -> Result<(), McpError>;
}

/// The cancellation watch the write and the wait poll: the task's
/// cancellation is re-read on every poll slice, so a cancel that lands while a
/// stalled pipe drains, or while the peer holds its answer, stops the call
/// instead of waiting out the deadline.
struct CancelWatch<'a> {
    store: &'a mut TaskStore,
    task: &'a TaskId,
}

impl CancelWatch<'_> {
    /// Whether the task is cancelled, with a failed read classified by how far
    /// the *call frame* got: `sent` is that frame's own bytes, never the
    /// session's total, so a handshake at the peer keeps the pre-send
    /// classification. Before a call byte nothing of the effect can have
    /// happened, so the call is a clean pre-send refusal; once a call byte is
    /// at the peer, the effect may already have happened, so the read failure
    /// is an unknown outcome — never the "nothing left, nothing took effect" a
    /// rejected attempt would claim.
    fn cancelled(&mut self, sent: u64) -> Result<bool, SeamFailure> {
        self.store.task_cancelled(self.task).map_err(|source| {
            if sent == 0 {
                SeamFailure::pre_send(
                    McpReason::CancellationUnreadable,
                    format!("the task's cancellation cannot be read: {source}"),
                )
            } else {
                SeamFailure::unknown_after_send(
                    McpReason::CancellationUnreadable,
                    format!(
                        "the task's cancellation cannot be read after a byte of the call \
                         frame reached the mcp server: {source}"
                    ),
                )
            }
        })
    }
}

/// Which frame of its session one request writes. The two are not
/// interchangeable: only a byte of the call frame can mean the peer acted, so
/// the cancellation watch is fed that frame's own bytes and never the
/// session's total, which the handshake has already grown.
#[derive(Clone, Copy)]
enum RequestFrame {
    /// The [`MCP_HANDSHAKE_METHOD`] frame that opens the session: a read that
    /// fails after only this frame has left stays pre-send.
    Handshake,
    /// A frame that may carry an effect — the [`MCP_CALL_METHOD`] one. It is
    /// the default, so a method added later is never exempted by omission.
    Call,
}

impl RequestFrame {
    /// The frame one request writes: only the handshake is a frame that cannot
    /// carry an effect. An undeclared method is refused before its frame is
    /// written, so it never reaches here.
    fn of(method: &str) -> Self {
        if method == MCP_HANDSHAKE_METHOD {
            Self::Handshake
        } else {
            Self::Call
        }
    }
}

/// One live stdio session with a declared server: the child, its stdin, and
/// the reader thread draining its stdout.
pub struct Session {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    frames: Receiver<Frame>,
    stop: Arc<AtomicBool>,
    overflow: Arc<AtomicBool>,
    reader: Option<std::thread::JoinHandle<()>>,
    next_id: u64,
    bytes_sent: u64,
    /// The bytes of the call frame itself, the handshake excluded: the only
    /// count whose presence means the peer may have acted on the call.
    call_bytes: u64,
}

impl Session {
    /// Starts the declared program and its reader thread. The child gets a
    /// cleared environment: the base allowlist, the declaration's own
    /// entries, and — at most — the one credential variable.
    fn open(server: &McpServer, credential: Option<(&str, &str)>) -> Result<Self, McpError> {
        let mut command = Command::new(&server.program);
        command.args(&server.args);
        // Its own process group, so a stop reaches the tree the server
        // started and a descendant cannot keep the pipe open past cleanup.
        command.process_group(0);
        command.env_clear();
        for name in MCP_ENV_ALLOWLIST {
            if let Ok(value) = std::env::var(name) {
                command.env(name, value);
            }
        }
        for (name, value) in &server.env {
            command.env(name, value);
        }
        if let Some((variable, material)) = credential {
            command.env(variable, material);
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(|source| McpError::Spawn {
            server: server.name.clone(),
            cause: source.kind().to_string(),
        })?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            drop(rivect_sandbox_helper::kill_process_group(child.id()));
            drop(child.kill());
            drop(child.wait());
            return Err(McpError::Spawn {
                server: server.name.clone(),
                cause: "the session pipes were not created".to_string(),
            });
        };
        let (send, receive) = std::sync::mpsc::sync_channel::<Frame>(MCP_FRAME_QUEUE);
        let stop = Arc::new(AtomicBool::new(false));
        let overflow = Arc::new(AtomicBool::new(false));
        let reader_stop = Arc::clone(&stop);
        let reader_overflow = Arc::clone(&overflow);
        // The handle lands in `reader` and `Session::shutdown` joins it, so
        // this never outlives its session (standards §5).
        let reader = std::thread::spawn(move || {
            read_frames(stdout, send, reader_stop, reader_overflow);
        });
        Ok(Self {
            child: Some(child),
            stdin: Some(stdin),
            frames: receive,
            stop,
            overflow,
            reader: Some(reader),
            next_id: 0,
            bytes_sent: 0,
            call_bytes: 0,
        })
    }

    /// One request and its bounded answer. A JSON-RPC error answer is a
    /// protocol refusal, malformed bytes a framing refusal, a wait past
    /// [`MCP_WAIT_TIMEOUT`] a timeout, and a peer that ends first a signal.
    fn request(
        &mut self,
        method: &str,
        params: Value,
        watch: &mut CancelWatch<'_>,
    ) -> Result<Value, SeamFailure> {
        if !MCP_DECLARED_METHODS.contains(&method) {
            return Err(SeamFailure::protocol(
                McpReason::UndeclaredMethod,
                "the mcp client does not serve the requested method",
            ));
        }
        let id = self.next_id.saturating_add(1);
        self.next_id = id;
        let mut encoded = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .map_err(|source| SeamFailure::framing_source(McpReason::RequestNotEncodable, &source))?;
        encoded.push(b'\n');
        self.write_frame(&encoded, watch, RequestFrame::of(method))?;
        let answer = self.wait(watch)?;
        let parsed: Value = serde_json::from_slice(&answer)
            .map_err(|source| SeamFailure::framing_source(McpReason::MalformedFrame, &source))?;
        if parsed.get("id").and_then(Value::as_u64) != Some(id) {
            return Err(SeamFailure::framing(McpReason::AnswerNamesAnotherRequest));
        }
        if let Some(error) = parsed.get("error") {
            let missing_method = error.get("code").and_then(Value::as_i64) == Some(-32601);
            return Err(SeamFailure::protocol(
                McpReason::ProtocolError,
                if missing_method {
                    "the mcp server does not serve the requested method"
                } else {
                    "the mcp server refused the request"
                },
            ));
        }
        parsed
            .get("result")
            .cloned()
            .ok_or_else(|| SeamFailure::framing(McpReason::AnswerCarriesNoResult))
    }

    /// Writes one frame within its size bound and its deadline, polling both
    /// the cancellation watch and the pipe so a peer that stops reading is a
    /// bounded unknown outcome instead of a wedged turn. The watch reads the
    /// call frame's own bytes: a handshake byte at the peer precedes the
    /// effect, so it cannot mean one happened.
    fn write_frame(
        &mut self,
        encoded: &[u8],
        watch: &mut CancelWatch<'_>,
        frame: RequestFrame,
    ) -> Result<(), SeamFailure> {
        if encoded.len() > MCP_REQUEST_MAX_BYTES {
            return Err(SeamFailure::request_refused(
                McpReason::RequestOverBound,
                "the mcp request frame is past the size this client will write",
            ));
        }
        let Some(stdin) = self.stdin.as_mut() else {
            return Err(SeamFailure::signal(McpReason::StdinClosed));
        };
        if rivect_sandbox_helper::set_nonblocking(&*stdin).is_err() {
            return Err(SeamFailure::signal(McpReason::StdinUnavailable));
        }
        let deadline = Instant::now() + MCP_WRITE_TIMEOUT;
        let already = self.call_bytes;
        let mut written = 0;
        let verdict = loop {
            if written == encoded.len() {
                break Ok(());
            }
            match watch.cancelled(already.saturating_add(written as u64)) {
                Ok(true) => break Err(SeamFailure::cancelled()),
                Ok(false) => {}
                Err(failure) => break Err(failure),
            }
            if Instant::now() >= deadline {
                break Err(SeamFailure::write_timeout());
            }
            match stdin.write(&encoded[written..]) {
                Ok(0) => break Err(SeamFailure::signal(McpReason::WriteClosed)),
                Ok(count) => written += count,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    let fd = stdin.as_fd();
                    if let Err(error) =
                        rivect_sandbox_helper::wait_ready(&[], &[fd], MCP_POLL_SLICE)
                        && error.kind() != ErrorKind::Interrupted
                    {
                        break Err(SeamFailure::signal(McpReason::StdinUnavailable));
                    }
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => break Err(SeamFailure::write_failed(error.kind())),
            }
        };
        // The bytes that reached the kernel are the ones the peer may have
        // read, so a stalled or cancelled frame reports the prefix it handed
        // over instead of the frame it meant to send. The session's total
        // keeps the handshake as well; the call frame's own count is the one a
        // settlement's classification reads.
        self.bytes_sent = self.bytes_sent.saturating_add(written as u64);
        if matches!(frame, RequestFrame::Call) {
            self.call_bytes = self.call_bytes.saturating_add(written as u64);
        }
        verdict
    }

    /// The bounded wait for one answer, polling the cancellation watch on
    /// every poll slice: a stop that lands while the peer holds its answer
    /// ends the call as an unknown outcome instead of waiting out the
    /// deadline. The wait and the write read the same watch, and both hand it
    /// the call frame's own bytes, so a wait that never wrote one stays a
    /// pre-send failure. A task's cancellation has one owner and neither stage
    /// can outlast it.
    fn wait(&mut self, watch: &mut CancelWatch<'_>) -> Result<Vec<u8>, SeamFailure> {
        let deadline = Instant::now() + MCP_WAIT_TIMEOUT;
        loop {
            match watch.cancelled(self.call_bytes) {
                Ok(false) => {}
                Ok(true) => return Err(SeamFailure::cancelled()),
                Err(failure) => return Err(failure),
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SeamFailure::timeout());
            }

            match self.frames.recv_timeout(remaining.min(MCP_POLL_SLICE)) {
                Ok(Frame::Line(line)) => return Ok(line),
                Ok(Frame::Eof) => {
                    let reason = self.exit_reason();
                    return Err(SeamFailure::signal(reason));
                }
                Ok(Frame::Failed(reason)) => return Err(SeamFailure::framing(reason)),
                Err(RecvTimeoutError::Timeout) => {
                    if let Some(child) = self.child.as_mut()
                        && matches!(child.try_wait(), Ok(Some(_)))
                    {
                        return Err(SeamFailure::signal(McpReason::SignalDeath));
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(if self.overflow.load(Ordering::Relaxed) {
                        SeamFailure::framing(McpReason::AnswersOverBound)
                    } else {
                        SeamFailure::signal(McpReason::ReaderClosed)
                    });
                }
            }
        }
    }

    /// Why the peer's stream ended: a signal death is named as one, and a
    /// plain close keeps its own reason. The status is polled for at most one
    /// poll slice — a peer that closed the pipe without exiting is reported as
    /// closed, never waited for without a bound.
    fn exit_reason(&mut self) -> McpReason {
        let deadline = Instant::now() + MCP_POLL_SLICE;
        loop {
            let status = self.child.as_mut().and_then(|child| child.try_wait().ok());
            match status {
                Some(Some(status)) => {
                    return if status.signal().is_some() {
                        McpReason::SignalDeath
                    } else {
                        McpReason::PeerClosed
                    };
                }
                Some(None) if Instant::now() < deadline => {
                    if rivect_sandbox_helper::wait_ready(&[], &[], Duration::from_millis(1))
                        .is_err()
                    {
                        return McpReason::PeerClosed;
                    }
                }
                _ => return McpReason::PeerClosed,
            }
        }
    }

    /// Ends the session: the process group killed, the leader reaped, the
    /// reader thread stopped and joined. Bounded by one poll slice, even for a
    /// descendant that escaped the group.
    fn shutdown(&mut self) -> Cleanup {
        let mut cleanup = Cleanup::NOTHING_TO_CLEAN;
        self.stop.store(true, Ordering::Relaxed);
        drop(self.stdin.take());
        if let Some(mut child) = self.child.take() {
            drop(rivect_sandbox_helper::kill_process_group(child.id()));
            drop(child.kill());
            cleanup.child_reaped = child.wait().is_ok();
        }
        if let Some(reader) = self.reader.take() {
            cleanup.reader_joined = reader.join().is_ok();
        }
        cleanup
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Resolves the server's own credential, refusing before the transport when
/// the declaration cannot be honoured. The material goes to the child's
/// environment only; it is never part of a frame.
fn credential_material(
    server: &McpServer,
    credentials: Option<&dyn CredentialStore>,
) -> Result<Option<(String, String)>, McpError> {
    let Some(credential) = &server.credential else {
        return Ok(None);
    };
    let reference = SecretRef::parse(&credential.reference).map_err(|source| {
        McpError::CredentialMalformed {
            server: server.name.clone(),
            cause: source.to_string(),
        }
    })?;
    let Some(store) = credentials else {
        return Err(McpError::CredentialUnavailable {
            server: server.name.clone(),
        });
    };
    let material = store
        .resolve(&reference)
        .map_err(|source| McpError::CredentialUnresolved {
            server: server.name.clone(),
            cause: source.to_string(),
        })?;
    let material =
        String::from_utf8(material).map_err(|source| McpError::CredentialNotMaterial {
            server: server.name.clone(),
            cause: source.utf8_error().to_string(),
        })?;
    Ok(Some((credential.variable.clone(), material)))
}

fn peer_version_digest(version: &str) -> String {
    crate::config::hex(&sha2::Sha256::digest(version.as_bytes()))
        .chars()
        .take(16)
        .collect()
}

/// The handshake's version verdict: the declared version is the only one this
/// client speaks, and the peer's answer is fingerprinted rather than retained.
fn negotiate(result: &Value) -> Result<String, SeamFailure> {
    let version = result
        .get("protocolVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            SeamFailure::protocol(
                McpReason::MissingProtocolVersion,
                "the mcp server answered no protocol version",
            )
        })?;
    if version != MCP_PROTOCOL_VERSION {
        return Err(SeamFailure {
            reason: McpReason::UnsupportedProtocolVersion,
            state: McpState::Failed,
            code: ErrorCode::UnsupportedVersion,
            message: format!(
                "mcp protocol version {} is outside the declared subset",
                bounded_peer_text(version, 40)
            ),
        });
    }
    Ok(peer_version_digest(version))
}

/// Where one logical operation's run stands when a call is refused after its
/// pre-send claim was written.
struct Running<'a> {
    store: &'a mut TaskStore,
    operation: String,
    attempt: String,
    artifact: String,
    origin: String,
    log: Option<RetainedLog>,
}

impl Running<'_> {
    /// Records the outcome: attempt settlement, the durable terminal record,
    /// the retained terminal line and — after a failure — the cleanup verdict.
    fn finish(
        &mut self,
        outcome: McpOutcome,
        cleanup: Option<Cleanup>,
    ) -> Result<McpOutcome, McpError> {
        if outcome.state.is_terminal() {
            self.settle_attempt(&outcome)?;
            write_record(
                self.store,
                &terminal_boundary(&self.operation),
                &self.operation,
                &terminal_record(&outcome),
            )?;
        }
        let Some(log) = self.log.as_mut() else {
            return Ok(outcome);
        };
        if outcome.state.is_terminal() {
            log.append(&terminal_line(&outcome, &self.origin))?;
        }
        if let Some(cleanup) =
            cleanup.filter(|_| outcome.state.is_terminal() && outcome.state != McpState::Succeeded)
        {
            log.append(&cleanup_line(
                &self.operation,
                &self.origin,
                outcome.bytes_sent,
                cleanup,
            ))?;
        }
        Ok(outcome)
    }

    /// A refusal before the first byte: nothing was sent, so the settlement
    /// carries zero bytes and there is no session to clean up.
    fn refuse(&mut self, failure: &SeamFailure) -> Result<McpOutcome, McpError> {
        let outcome = self.outcome(McpState::Failed, Some(failure), None, 0);
        self.finish(outcome, None)
    }

    /// The attempt is stamped running before the first byte: a cancel or a
    /// crash between the send and its settlement leaves a running row the
    /// ledger can name, never a planned row that reads as "never started".
    fn stamp(&mut self) -> Result<(), McpError> {
        if self.attempt.is_empty() {
            return Ok(());
        }
        self.store
            .attempt_running(&self.attempt)
            .map_err(|source| McpError::Record {
                operation: self.operation.clone(),
                cause: source.to_string(),
            })
    }

    fn settle_attempt(&mut self, outcome: &McpOutcome) -> Result<(), McpError> {
        if outcome.attempt.is_empty() {
            return Ok(());
        }
        let settled = match outcome.state {
            McpState::Succeeded => self.store.attempt_confirmed(&outcome.attempt),
            McpState::Failed => self.store.attempt_rejected(
                &outcome.attempt,
                outcome.reason_code.as_deref().unwrap_or("failed"),
            ),
            McpState::OutcomeUnknown => self.store.attempt_unknown(
                &outcome.attempt,
                outcome.reason_code.as_deref().unwrap_or("outcome_unknown"),
            ),
            McpState::InputRequired => Ok(()),
        };
        settled.map_err(|source| McpError::Record {
            operation: self.operation.clone(),
            cause: source.to_string(),
        })
    }

    fn outcome(
        &self,
        state: McpState,
        failure: Option<&SeamFailure>,
        result: Option<Value>,
        bytes_sent: u64,
    ) -> McpOutcome {
        McpOutcome {
            operation: self.operation.clone(),
            attempt: self.attempt.clone(),
            state,
            code: failure.map(|failure| failure.code),
            message: failure.map(|failure| failure.message.clone()),
            boundary_id: failure.map(|failure| boundary_id(failure.seam()).to_string()),
            reason_code: failure.map(|failure| failure.reason.as_str().to_string()),
            continuation: None,
            result,
            bytes_sent,
            artifact: self.artifact.clone(),
            peer_version_digest: None,
        }
    }
}

/// Runs one physical call for one logical operation and settles it.
///
/// `attempt` is the executor's own attempt for this send (INV-004): the
/// operation is the first attempt of the conversation, and every later send
/// continues it without creating a second operation.
///
/// # Errors
/// [`McpError`] only for refusals that happen before a call byte left — a
/// peer failure after that is an [`McpOutcome`], never an error.
pub fn run(
    store: &mut TaskStore,
    credentials: Option<&dyn CredentialStore>,
    reports_root: &Path,
    call: &McpCall,
    task: &TaskId,
    attempt: &str,
    gate: &mut dyn FirstByteGate,
) -> Result<McpOutcome, McpError> {
    call.validate()?;
    let operation = call
        .operation
        .clone()
        .unwrap_or_else(|| attempt.to_string());
    if !is_bounded_operation(&operation) {
        return Err(McpError::InvalidOperation { operation });
    }
    let mut continuation = None;
    let claimed = opened(store, &operation)?;
    if call.operation.is_some() {
        if let Some(settled) = recorded(store, &operation)? {
            return Ok(settled);
        }
        // Only an operation this store opened can be continued, and only for
        // the call that opened it: a caller cannot name a key that lands a
        // retained row, and an opened operation never points at another
        // program, destination or tool (INV-010).
        let Some(claim) =
            read_record::<OperationClaim>(store, &claim_boundary(&operation), &operation)?
        else {
            return Err(McpError::UnknownOperation { operation });
        };
        claim.assert_same_call(&operation, call)?;
        continuation = recorded_continuation(store, &operation)?;
        if continuation.is_none() {
            // A previous send may already have had an effect: re-sending
            // would duplicate it, so the operation stays honestly unknown.
            return settle_unresolved(
                store,
                reports_root,
                &operation,
                &call.server.name,
                McpReason::UnreconciledOperation,
            );
        }
    }
    let cancelled = store
        .task_cancelled(task)
        .map_err(|source| McpError::Record {
            operation: operation.clone(),
            cause: source.to_string(),
        })?;
    if cancelled {
        // An operation already claimed stays honestly unknown; one this store
        // never opened is refused instead of settled, so no terminal row lands
        // for an id no claim owns.
        return match claimed {
            true => settle_unresolved(
                store,
                reports_root,
                &operation,
                &call.server.name,
                McpReason::Cancelled,
            ),
            false => Err(McpError::Cancelled { operation }),
        };
    }
    // The pre-send claim: durable before the first side effect, and written
    // once per operation — a continuation keeps the claim that opened it.
    if !claimed {
        write_record(
            store,
            &claim_boundary(&operation),
            &operation,
            &OperationClaim {
                operation: operation.clone(),
                attempt: attempt.to_string(),
                server: call.server.name.clone(),
                origin: call.server.origin.clone(),
                tool: call.tool.clone(),
                artifact: artifact_relative(&operation),
            },
        )?;
    }
    let mut running = Running {
        store,
        operation: operation.clone(),
        attempt: attempt.to_string(),
        artifact: artifact_relative(&operation),
        origin: call.server.origin.clone(),
        log: None,
    };
    let mut log = match RetainedLog::open(reports_root, &operation) {
        Ok(log) => log,
        Err(error) => {
            let failure = SeamFailure::pre_send(McpReason::ArtifactUnavailable, error.to_string());
            return running.refuse(&failure);
        }
    };
    let send_line = log.append(&RetainedLine {
        logical_operation_id: operation.clone(),
        record: "send",
        outcome: None,
        boundary_id: Some(boundary_id(McpSeam::PreSend).to_string()),
        reason_code: None,
        server_origin: call.server.origin.clone(),
        bytes_sent: 0,
        peer_version_digest: None,
        child_reaped: None,
        reader_joined: None,
    });
    if let Err(error) = send_line {
        let failure = SeamFailure::pre_send(McpReason::ArtifactUnavailable, error.to_string());
        return running.refuse(&failure);
    }
    running.log = Some(log);
    if let Err(error) = running.stamp() {
        let failure = SeamFailure::pre_send(McpReason::ClaimUnavailable, error.to_string());
        return running.refuse(&failure);
    }
    let credential = match credential_material(&call.server, credentials) {
        Ok(credential) => credential,
        Err(error) => {
            let failure = SeamFailure::pre_send(McpReason::CredentialRefused, error.to_string());
            running.refuse(&failure)?;
            return Err(error);
        }
    };
    let mut session = match Session::open(
        &call.server,
        credential
            .as_ref()
            .map(|(variable, material)| (variable.as_str(), material.as_str())),
    ) {
        Ok(session) => session,
        Err(error) => {
            let failure = SeamFailure::protocol(McpReason::SpawnFailed, error.to_string());
            return running.refuse(&failure);
        }
    };
    // The first byte is the handshake, so the executor's own admission inputs
    // are re-consulted here — after the claim, the artifact and the child
    // exist, and before any byte reaches the peer.
    if let Err(error) = gate.reconsult(&*running.store, &call.server) {
        let failure = SeamFailure::admission_withdrawn(error.to_string());
        let outcome = running.outcome(McpState::Failed, Some(&failure), None, 0);
        let cleanup = session.shutdown();
        running.finish(outcome, Some(cleanup))?;
        return Err(error);
    }
    let live: &mut TaskStore = &mut *running.store;
    let mut watch = CancelWatch { store: live, task };
    let mut params = json!({ "name": call.tool, "arguments": call.arguments });
    if let Some(handle) = continuation {
        params["requestState"] = Value::String(handle);
    }
    let version = session.request(
        "initialize",
        json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "rivect", "version": env!("CARGO_PKG_VERSION") },
        }),
        &mut watch,
    );
    let peer_version = version
        .as_ref()
        .ok()
        .and_then(|result| result.get("protocolVersion"))
        .and_then(Value::as_str)
        .map(|version| peer_version_digest(&bounded_peer_text(version, 40)));
    let answered = version.and_then(|result| {
        negotiate(&result)?;
        // The same spelling [`RequestFrame::of`] classifies on, so the call
        // frame cannot be mistaken for the handshake.
        session.request(MCP_CALL_METHOD, params, &mut watch)
    });
    // The count the settlement keeps is every byte this session wrote — the
    // handshake included — so the artifact shows a handshake even when no call
    // frame left; the seam above was classified on the call frame's own bytes.
    let bytes_sent = session.bytes_sent;
    let outcome = match answered {
        Ok(result) => {
            let kind = result
                .get("resultType")
                .and_then(Value::as_str)
                .unwrap_or_default();
            match kind {
                "input_required" => {
                    let handle = result
                        .get("requestState")
                        .and_then(Value::as_str)
                        .map(|handle| bounded_peer_text(handle, 64))
                        .unwrap_or_default();
                    if !is_bounded_token(&handle, 64) {
                        let failure = SeamFailure::unreadable_verdict(
                            McpReason::ContinuationHandleUnbounded,
                            "the mcp server asked for input with an unusable continuation handle",
                        );
                        running.outcome(failure.state, Some(&failure), None, bytes_sent)
                    } else if handle.is_empty() {
                        let failure = SeamFailure::protocol(
                            McpReason::ContinuationWithoutHandle,
                            "the mcp server asked for input without a continuation handle",
                        );
                        running.outcome(McpState::Failed, Some(&failure), None, bytes_sent)
                    } else {
                        let first = recorded_continuation(&*running.store, &operation)?;
                        let handle = first.unwrap_or(handle);
                        write_record(
                            running.store,
                            &continuation_boundary(&operation),
                            &operation,
                            &Continuation {
                                handle: handle.clone(),
                                logical_operation_id: operation.clone(),
                            },
                        )?;
                        let mut outcome =
                            running.outcome(McpState::InputRequired, None, None, bytes_sent);
                        outcome.continuation = Some(Continuation {
                            handle,
                            logical_operation_id: operation.clone(),
                        });
                        outcome
                    }
                }
                "complete" => running.outcome(
                    McpState::Succeeded,
                    None,
                    result.get("content").cloned(),
                    bytes_sent,
                ),
                _ => {
                    let failure = SeamFailure::unreadable_verdict(
                        McpReason::UnknownResultType,
                        "the mcp server answered a result type this client does not declare",
                    );
                    running.outcome(failure.state, Some(&failure), None, bytes_sent)
                }
            }
        }
        Err(failure) => running.outcome(failure.state, Some(&failure), None, bytes_sent),
    };
    let mut outcome = outcome;
    outcome.peer_version_digest = peer_version;
    let cleanup = session.shutdown();
    running.finish(outcome, Some(cleanup))
}

fn recorded_continuation(store: &TaskStore, operation: &str) -> Result<Option<String>, McpError> {
    let Some(record) =
        read_record::<Continuation>(store, &continuation_boundary(operation), operation)?
    else {
        return Ok(None);
    };
    if record.logical_operation_id != operation {
        return Err(McpError::Record {
            operation: operation.to_string(),
            cause: "the continuation names another operation".to_string(),
        });
    }
    Ok(Some(record.handle))
}
