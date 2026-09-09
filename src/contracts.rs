//! Canonical runtime contract types (architecture «Канонический runtime
//! interface»). One owner for `TaskCommand`, `TaskSnapshot`, `Question`,
//! `Event`, `CommandDescriptor` and the public method catalog; `src/config.rs`
//! owns config types. Wire forms follow the JSON-RPC shapes in architecture;
//! all IDs are nominal UUIDv4 strings.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCHEMA_VERSION: u32 = 1;
pub const TEXT_MAX_BYTES: usize = 65_536;
pub const LABEL_MAX_BYTES: usize = 256;
pub const ARRAY_MAX_ITEMS: usize = 200;
pub const REQUEST_MAX_BYTES: usize = 1 << 20;
pub const PAGE_DEFAULT: u32 = 20;
pub const PAGE_MAX: u32 = 200;

/// Runtime error codes of the public contract, with JSON-RPC exit semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidInput,
    UnsupportedVersion,
    UnknownMethod,
    NotFound,
    Conflict,
    StaleIntent,
    AlreadyTerminal,
    Denied,
    CapabilityUnavailable,
    DependencyBlocked,
    OutcomeUnknown,
    ContextOverflow,
    BudgetExhausted,
    StorageUnavailable,
    OutputLimit,
    InternalError,
    Cancelled,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnknownMethod => "unknown_method",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::StaleIntent => "stale_intent",
            Self::AlreadyTerminal => "already_terminal",
            Self::Denied => "denied",
            Self::CapabilityUnavailable => "capability_unavailable",
            Self::DependencyBlocked => "dependency_blocked",
            Self::OutcomeUnknown => "outcome_unknown",
            Self::ContextOverflow => "context_overflow",
            Self::BudgetExhausted => "budget_exhausted",
            Self::StorageUnavailable => "storage_unavailable",
            Self::OutputLimit => "output_limit",
            Self::InternalError => "internal_error",
            Self::Cancelled => "cancelled",
        }
    }

    /// Process exit code for the CLI surface (architecture error mapping).
    pub fn exit_code(self) -> u8 {
        match self {
            Self::InvalidInput | Self::UnsupportedVersion | Self::UnknownMethod => 2,
            Self::StorageUnavailable | Self::InternalError | Self::OutputLimit => 1,
            Self::Cancelled => 130,
            _ => 3,
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryClass {
    None,
    Transport,
    Reconcile,
    Semantic,
    Plan,
}

/// Safe, bounded wire error: names the failed operation, a safe cause and the
/// allowed recovery read, never secret bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WireError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boundary_id: Option<String>,
    pub retry_class: RetryClass,
}

impl WireError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            boundary_id: None,
            retry_class: RetryClass::None,
        }
    }
}

macro_rules! nominal_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn generate() -> Self {
                Self(uuid::Uuid::new_v4().to_string())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

nominal_id!(SessionId);
nominal_id!(TaskId);
nominal_id!(CommandId);
nominal_id!(QuestionId);
nominal_id!(AttachmentId);
nominal_id!(CriterionId);
nominal_id!(EvidenceId);
nominal_id!(AttemptId);
nominal_id!(ActionId);
nominal_id!(ArtifactId);
nominal_id!(DecisionRef);
nominal_id!(EventId);

/// Option IDs are nominal ASCII `[A-Za-z0-9._-]{1,64}`, stable within one
/// QuestionId/revision.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OptionId(pub String);

/// Reference to durable immutable bytes owned by the state store.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub id: ArtifactId,
    pub digest: String,
    pub size_bytes: u64,
    pub media_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Running,
    Waiting,
    Paused,
    Blocked,
    Completed,
    Cancelled,
}

impl Lifecycle {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationApplicability {
    Required,
    NotApplicable,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationExecution {
    Pending,
    Satisfied,
    Failed,
    Stale,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Obligation {
    pub id: String,
    pub criterion_refs: Vec<CriterionId>,
    pub applicability: ObligationApplicability,
    pub execution: ObligationExecution,
    pub basis_refs: Vec<EvidenceId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Criterion {
    pub id: CriterionId,
    pub text: String,
}

/// Bounded page of a snapshot collection. The CLI starts at `page_size` 20
/// without a cursor; `next_cursor` is absent on the last page.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub snapshot_generation: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl<T> Page<T> {
    pub fn new(items: Vec<T>, snapshot_generation: u64) -> Self {
        Self {
            items,
            snapshot_generation,
            next_cursor: None,
        }
    }
}

/// Why a task cannot progress; `waiting`/`blocked` snapshots always carry a
/// non-empty list of these.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Blocker {
    pub reason: ErrorCode,
    pub owner: String,
    pub condition: ResumeCondition,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResumeCondition {
    Decision {
        question_id: QuestionId,
        revision: u64,
    },
    Dependency {
        action_id: ActionId,
    },
    Reconciliation {
        action_id: ActionId,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskSnapshot {
    pub task_id: TaskId,
    pub revision: u64,
    pub intent_revision: u64,
    pub lifecycle: Lifecycle,
    pub goal_ref: ArtifactRef,
    pub contract_revision: u64,
    pub constraints: Page<String>,
    pub criteria: Page<Criterion>,
    pub obligations: Page<Obligation>,
    pub actions: Page<String>,
    pub attempts: Page<AttemptRef>,
    pub decision_refs: Page<DecisionRef>,
    pub event_cursor: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockers: Option<Vec<Blocker>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttemptRef {
    pub attempt_id: AttemptId,
    pub action_id: ActionId,
    pub effect_class: EffectClass,
    pub state: AttemptState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    Read,
    Write,
    Exec,
    Egress,
    Model,
    Control,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    Planned,
    Admitted,
    Running,
    Confirmed,
    Rejected,
    CancelRequested,
    Unknown,
}

impl AttemptState {
    pub fn is_settled(self) -> bool {
        matches!(self, Self::Confirmed | Self::Rejected | Self::Unknown)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    pub schema_version: u32,
    pub event_id: EventId,
    pub aggregate_id: String,
    pub aggregate_revision: u64,
    pub cursor: u64,
    pub session_id: SessionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<TaskId>,
    #[serde(rename = "type")]
    pub event_type: String,
    pub delta: Value,
    pub origin: String,
}

pub const TASK_COMMAND_KINDS: &[&str] = &[
    "create", "steer", "resume", "pause", "cancel", "answer", "approve", "deny",
];

/// Strictly-parsed public task command. `mutate` is not part of the public
/// enum and yields `invalid_input` on the wire.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskCommand {
    pub command_id: CommandId,
    pub session_id: SessionId,
    pub kind: TaskCommandKind,
    pub variant: TaskCommandVariant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskCommandKind {
    Create,
    Steer,
    Resume,
    Pause,
    Cancel,
    Answer,
    Approve,
    Deny,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TaskCommandVariant {
    Create {
        goal: String,
        contract: ContractInput,
    },
    Steer {
        task_id: TaskId,
        expected_intent_revision: u64,
        expected_task_revision: u64,
        instruction: String,
    },
    Resume {
        task_id: TaskId,
        expected_intent_revision: u64,
        expected_task_revision: u64,
    },
    Pause {
        task_id: TaskId,
        expected_intent_revision: u64,
        reason: Option<String>,
    },
    Cancel {
        task_id: TaskId,
        expected_intent_revision: u64,
        reason: Option<String>,
    },
    Answer {
        task_id: TaskId,
        expected_intent_revision: u64,
        question_id: QuestionId,
        question_revision: u64,
        selection: AnswerSelection,
    },
    Approve {
        task_id: TaskId,
        expected_intent_revision: u64,
        grant_request_id: String,
        grant_request_revision: u64,
        effect_digest: String,
    },
    Deny {
        task_id: TaskId,
        expected_intent_revision: u64,
        grant_request_id: String,
        grant_request_revision: u64,
        effect_digest: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractInput {
    pub criteria: Vec<String>,
    pub constraints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AnswerSelection {
    Option { option_id: OptionId },
    Custom { text: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Question {
    pub question_id: QuestionId,
    pub question_revision: u64,
    pub task_id: TaskId,
    pub intent_revision: u64,
    pub prompt: String,
    pub options: Vec<QuestionOption>,
    pub recommended_option_id: OptionId,
    pub recommendation_basis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuestionOption {
    pub option_id: OptionId,
    pub label: String,
    pub consequences: String,
    pub availability: Availability,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Availability {
    Enabled,
    Disabled { reason: String },
}

/// Result of a task command: task-only, always carries the current snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub status: String,
    pub task_id: TaskId,
    pub task_revision: u64,
    pub intent_revision: u64,
    pub event_cursor: u64,
    pub snapshot: TaskSnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_revision: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResult {
    pub schema_version: u32,
    pub session_id: SessionId,
    pub owner_generation: u64,
    pub state: String,
    pub attachment_id: AttachmentId,
    pub session_revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskStatus {
    pub task_id: TaskId,
    pub task_revision: u64,
    pub intent_revision: u64,
    pub lifecycle: Lifecycle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionResult {
    pub schema_version: u32,
    pub task_id: TaskId,
    pub task_revision: u64,
    pub intent_revision: u64,
    pub question: Option<Question>,
}

/// Local command carrier descriptor (architecture §DXV-1). Known-but-unknown
/// commands report `capability_unavailable`, never fake success.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommandDescriptor {
    pub canonical_id: String,
    pub aliases: Vec<String>,
    pub description: String,
    pub busy_policy: String,
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailability_reason: Option<String>,
}

/// JSON-RPC envelope for the corpus-driven ingress tests.
#[derive(Debug, Clone, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    pub params: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct RpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcErrorBody>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RpcErrorBody {
    pub code: i64,
    pub message: String,
    pub data: WireError,
}

impl RpcResponse {
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Value, code: i64, wire: WireError) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(RpcErrorBody {
                code,
                message: wire.code.as_str().to_string(),
                data: wire,
            }),
        }
    }
}
