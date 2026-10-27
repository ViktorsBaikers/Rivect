//! The shared action catalog (architecture «Реестр действий»): one
//! `ActionRegistry` of versioned `ActionDefinition` rows with typed
//! `ActionInput`/`ActionOutcome` carriers. `resolve_decision` is this
//! position's handler: it serves one material fork as exactly five honest
//! positions plus an always-available multiline custom path, publishes
//! the one versioned `Question` through the existing store seam in `ask`
//! mode, and — only inside an explicit bounded delegation — answers it in
//! `auto` mode with a non-human author. Focus and recommendation are
//! display state, never consent; `auto` never grants authority, payment,
//! or permission, and a fork without delegation always asks.
//!
//! The plan rows — `frame_goal`, `challenge_direction`,
//! `design_contracts`, `plan_work`, `assess_plan` — each declare how this
//! build runs them. [`ActionRegistry::select`] is the only producer of
//! plan rows: it records one versioned selection bound to a canonical
//! digest of the typed request facts. Local legs close their rows through
//! the one plan-row write; a Broker-purpose leg without a broker seam
//! answers the exact `capability_unavailable` blocker, never a template.
//! With a [`BrokerSeam`] the purpose legs call their Broker purpose and
//! close their rows only on a strict reply bound to the selection.
//! [`plan_gate`] reports whether non-read work may start; the selection,
//! the gate and the local legs call no model.
//!
//! `inspect_system` is the boundary report: it declares the source-query
//! kinds the mechanical table admits, probes the parse legs through the
//! index worker — the only runtime path to untrusted parsing (DEC-028) —
//! and reports the rows that probe served, the coverage it disclosed and
//! how current the stored project index is. A probe that did not answer is
//! reported as `Unanswered` with its own wire class, never served as a
//! clean or complete answer.

use crate::config::{Config, DecisionMode};
use crate::context::QueryKind;
use crate::contracts::{
    ARRAY_MAX_ITEMS, AnswerAttemptOutcome, AnswerSelection, Availability, Blocker, CommandResult,
    Criterion, CriterionId, ErrorCode, ObligationApplicability, ObligationExecution, OptionId,
    Question, QuestionId, QuestionOption, ResumeCondition, SessionId, TEXT_MAX_BYTES, TaskId,
    TaskSnapshot,
};
use crate::index::SearchBackend;
use crate::index::{Completeness, GenerationState, MatchKind, PartialReason, QueryResult};
use crate::lsp::SymbolOp;
use crate::model::{Broker, CallContract, ModelError};
use crate::providers::ProviderReply;
use crate::state::{
    ConflictCause, PLAN_BLOCKER_OWNER, PlanAssessmentWrite, PlanObligationRecord,
    PlanRevisionRecord, PlanRevisionWrite, PlanRowChange, PlanRowUpdate, PlanRowWrite,
    PlanSelectionRecord, PlanSelectionWrite, PlanVerdict, StoreError, TaskStore, plan_blocker,
};
use crate::verification::{
    AssumptionCheckRecord, AssumptionClassification, AssumptionSeam, CheckObservation,
    ExpectedResult,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

pub use crate::state::{PlanGate, RequestKind};

/// Semantic id of the one decision action this build serves.
pub const RESOLVE_DECISION: &str = "resolve_decision";
/// The catalog id of the decision-mode carrier command; `commands`
/// dispatches it through the journaled config publication.
pub const DECISIONS_CONTROL: &str = "decisions.control";
/// The decision card's fixed arity: five honest positions. An unavailable
/// position stays visible as a disabled row carrying its reason — slots
/// are never invented to fill the card and never hidden to shrink it.
pub const DECISION_OPTION_SLOTS: usize = 5;
/// Semantic id of the boundary-inspection surface. The catalog row is
/// the metadata contract — what the action is for and what it must never
/// do; the execution body reports the boundary's own declared, satisfied
/// and detected systems by kind, with the index's freshness and the
/// residual risk its one probe disclosed. It never answers a source
/// query of its own, and it never parses project source in process: the
/// probe rides the index worker like every other runtime parse (DEC-028).
pub const INSPECT_SYSTEM: &str = "inspect_system";
/// The plan rows. Each fires on its own trigger over the typed request
/// facts, never on its place in a list: a sufficient contract or a known
/// local change runs none of the stages it does not need.
pub const FRAME_GOAL: &str = "frame_goal";
pub const CHALLENGE_DIRECTION: &str = "challenge_direction";
pub const DESIGN_CONTRACTS: &str = "design_contracts";
pub const PLAN_WORK: &str = "plan_work";
pub const ASSESS_PLAN: &str = "assess_plan";
pub const TEST_ASSUMPTION: &str = "test_assumption";
pub const PREPARE_ENVIRONMENT: &str = "prepare_environment";
/// The plan-phase rows in dependency order: a required stage that has
/// not closed keeps the gate paused. Every other selected row is
/// execution-phase — it follows or checks the non-read effect, so it
/// holds completion and never the gate.
pub const PLAN_STAGES: [&str; 5] = [
    FRAME_GOAL,
    CHALLENGE_DIRECTION,
    DESIGN_CONTRACTS,
    PLAN_WORK,
    ASSESS_PLAN,
];
/// Execution-phase checks a request can require that have no catalog row
/// in this build. An obligation naming one stays visible with an exact
/// blocker — it is never dropped and never closed by an unrelated
/// handler.
pub const ASSESS_SECURITY: &str = "assess_security";
pub const AUDIT_TESTS: &str = "audit_tests";
pub const ASSESS_READINESS: &str = "assess_readiness";
pub const IMPLEMENT_CHANGE: &str = "implement_change";
pub const DELIVER_CHANGE: &str = "deliver_change";
pub const REVIEW_CHANGE: &str = "review_change";
pub const DIAGNOSE_ISSUE: &str = "diagnose_issue";

/// How this build runs a catalog row (§5.20, PROH-004).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Implementation {
    /// A local handler.
    Local,
    /// A Broker purpose named by the action id.
    Purpose,
    /// A local mechanical leg plus a Broker-purpose semantic leg.
    LocalAndPurpose,
    /// Registered for discovery; dispatch answers `capability_unavailable`.
    Unavailable,
}

/// One catalog row: the action's semantic id, its revision, the case it
/// triggers on, the case it must never answer, the outcome contract, and
/// how this build runs it. `&'static` rows are compile-time — a catalog
/// revision bumps only with the code that ships it.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionDefinition {
    pub id: &'static str,
    pub revision: u64,
    pub trigger: &'static str,
    pub negative_trigger: &'static str,
    pub outcome: &'static str,
    pub implementation: Implementation,
}

/// Who an auto-mode answer attributes itself to. `Human` exists so the
/// boundary can reject it by type: a machine answer never impersonates
/// consent, whatever string the caller tried to pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionAuthor {
    System,
    Agent,
    Human,
}

impl DecisionAuthor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Agent => "agent",
            Self::Human => "human",
        }
    }
}

/// One bounded machine mandate: the named action on the named task —
/// never a blanket right. A delegation that does not cover this exact
/// (action, task) pair covers nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    pub action: String,
    pub task_id: TaskId,
}

impl Delegation {
    pub fn covers(&self, action: &str, task_id: &TaskId) -> bool {
        self.action == action && self.task_id == *task_id
    }
}

/// The material fork `resolve_decision` serves: prompt, exactly
/// [`DECISION_OPTION_SLOTS`] honest positions, the recommended position
/// plus its basis — and the two fields that gate machine resolution:
/// `delegation` bounds what `auto` may answer, `author` names the
/// non-human origin it must attribute itself to.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolveDecisionInput {
    pub task_id: TaskId,
    pub prompt: String,
    pub options: Vec<QuestionOption>,
    pub recommended_option_id: OptionId,
    pub recommendation_basis: String,
    pub delegation: Option<Delegation>,
    pub author: Option<DecisionAuthor>,
}

/// A surface the request touches (master:749 vocabulary). Risk comes
/// from these facts, never from how long the request text is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    Local,
    Auth,
    PublicApi,
    Migration,
    Permissions,
    Secrets,
    Trust,
    UntrustedInput,
    Isolation,
    Dependencies,
    PrivateData,
}

impl Surface {
    /// The surface an impact label names, `None` outside the vocabulary.
    pub fn parse(label: &str) -> Option<Self> {
        Some(match label {
            "local" => Self::Local,
            "auth" => Self::Auth,
            "public_api" => Self::PublicApi,
            "migration" => Self::Migration,
            "permissions" => Self::Permissions,
            "secrets" => Self::Secrets,
            "trust" => Self::Trust,
            "untrusted_input" => Self::UntrustedInput,
            "isolation" => Self::Isolation,
            "dependencies" => Self::Dependencies,
            "private_data" => Self::PrivateData,
            _ => return None,
        })
    }

    /// The wire label [`Surface::parse`] reads.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Auth => "auth",
            Self::PublicApi => "public_api",
            Self::Migration => "migration",
            Self::Permissions => "permissions",
            Self::Secrets => "secrets",
            Self::Trust => "trust",
            Self::UntrustedInput => "untrusted_input",
            Self::Isolation => "isolation",
            Self::Dependencies => "dependencies",
            Self::PrivateData => "private_data",
        }
    }

    fn is_risk(self) -> bool {
        !matches!(self, Self::Local)
    }

    /// The `assess_security` trigger classes (master:749): rights,
    /// secrets, trust, input, isolation, dependencies, private data.
    fn triggers_security(self) -> bool {
        matches!(
            self,
            Self::Auth
                | Self::Permissions
                | Self::Secrets
                | Self::Trust
                | Self::UntrustedInput
                | Self::Isolation
                | Self::Dependencies
                | Self::PrivateData
        )
    }
}

/// The impact scan the selection reads. `Unknown` is an evaluation that
/// could not decide; an empty `Known` scan decides nothing either — both
/// leave dependent rows `unresolved`, never "no risky surface".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurfaceScan {
    Known(BTreeSet<Surface>),
    Unknown,
}

impl SurfaceScan {
    /// The scan an impact producer's labels describe: an empty list or
    /// any label outside the vocabulary is `Unknown`.
    pub fn from_labels<'a>(labels: impl IntoIterator<Item = &'a str>) -> Self {
        let mut surfaces = BTreeSet::new();
        for label in labels {
            match Surface::parse(label) {
                Some(surface) => {
                    surfaces.insert(surface);
                }
                None => return Self::Unknown,
            }
        }
        if surfaces.is_empty() {
            Self::Unknown
        } else {
            Self::Known(surfaces)
        }
    }

    /// The decided surfaces; `None` when the scan decided nothing.
    fn decided(&self) -> Option<&BTreeSet<Surface>> {
        match self {
            Self::Known(surfaces) if !surfaces.is_empty() => Some(surfaces),
            Self::Known(_) | Self::Unknown => None,
        }
    }
}

/// Whether an approved contract (goal, direction and design) already
/// covers the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractBasis {
    Absent,
    Approved,
}

/// One verifiable part of the work: the criteria it serves, the parts it
/// waits on, and the check that proves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkPart {
    pub id: String,
    pub criteria: Vec<CriterionId>,
    pub depends_on: Vec<String>,
    pub proof: String,
}

/// The typed facts the selection and plan handlers read. A handler
/// runs only on facts whose digest is the current selection's; a material
/// fork's delegation and author, when supplied, belong to this caller input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanRequest {
    pub task_id: TaskId,
    pub kind: RequestKind,
    pub surfaces: SurfaceScan,
    pub contract: ContractBasis,
    pub parts: Vec<WorkPart>,
    pub delegation: Option<Delegation>,
    pub author: Option<DecisionAuthor>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ActionInput {
    ResolveDecision(ResolveDecisionInput),
    /// The boundary-inspection carrier: what the boundary was asked to
    /// report, bounded by the caller's budget and cancellable through a
    /// task. The project root is deliberately absent — it is the index
    /// seam's own pinned root, never a caller's — and the parse legs are
    /// probed through the index worker, so a dispatch never parses
    /// project source in process.
    InspectSystem(InspectSystemInput),
    FrameGoal(PlanRequest),
    ChallengeDirection(PlanRequest),
    DesignContracts(PlanRequest),
    PlanWork(PlanRequest),
    /// Judges the latest stored plan revision of the current selection —
    /// the stored plan, not a caller copy, is what execution follows.
    AssessPlan(PlanRequest),
    TestAssumption(TestAssumptionInput),
    PrepareEnvironment(PrepareEnvironmentInput),
}

/// One check result for a named assumption. The expected result and
/// assertion are pinned on first record and cannot be weakened later.
#[derive(Clone, PartialEq, Eq)]
pub struct TestAssumptionInput {
    pub task_id: TaskId,
    pub check_id: String,
    pub expected_result: ExpectedResult,
    pub assertion: String,
    pub observation: CheckObservation,
}

impl std::fmt::Debug for TestAssumptionInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TestAssumptionInput")
            .field("task_id", &self.task_id)
            .field("check_id", &self.check_id)
            .field("expected_result", &self.expected_result)
            .field("assertion", &"<redacted>")
            .field("assertion_bytes", &self.assertion.len())
            .field("observation", &self.observation)
            .finish()
    }
}

/// A grant-scoped restoration of one existing fixture file.
#[derive(Clone, PartialEq, Eq)]
pub struct PrepareEnvironmentInput {
    pub task_id: TaskId,
    pub check_id: String,
    pub grant_id: String,
    pub target: PathBuf,
    pub replacement: Vec<u8>,
}

impl std::fmt::Debug for PrepareEnvironmentInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrepareEnvironmentInput")
            .field("task_id", &self.task_id)
            .field("check_id", &self.check_id)
            .field("grant_id", &"<redacted>")
            .field("target", &"<scoped path>")
            .field("replacement_bytes", &self.replacement.len())
            .finish()
    }
}

/// A validated restore payload waiting for executor admission.
#[derive(Clone, PartialEq, Eq)]
pub struct EnvironmentRestore {
    pub grant_id: String,
    pub target: PathBuf,
    pub replacement: Vec<u8>,
}

impl std::fmt::Debug for EnvironmentRestore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnvironmentRestore")
            .field("grant_id", &"<redacted>")
            .field("target", &"<scoped path>")
            .field("replacement_bytes", &self.replacement.len())
            .finish()
    }
}

/// Why no allowed handler can close an obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteBlock {
    /// No catalog row for the capability exists in this build.
    NotInBuild,
    /// The capability is registered but its execution is unavailable.
    Unavailable,
}

/// Who can close an obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// The capability's own local handler.
    Local(&'static str),
    /// An allowed equivalent local handler.
    Equivalent(&'static str),
    /// A Broker purpose named by the action id. The row waits on
    /// `capability_unavailable` until a strict reply through a broker
    /// seam closes it.
    Purpose(&'static str),
    Blocked(RouteBlock),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedObligation {
    pub capability: &'static str,
    pub applicability: ObligationApplicability,
    pub route: Route,
}

/// Why a handler produced no result, or why a shortlisted action was not
/// admitted. `NeedsInformation` is an undecided applicability or a
/// missing prerequisite — never `NotNeeded`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    NotNeeded,
    AlreadySatisfied,
    NeedsInformation,
    Unsupported,
}

/// A shortlisted action the facts did not admit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declined {
    pub action: String,
    pub reason: SkipReason,
}

/// One recorded selection: its revision and facts digest, every
/// obligation the facts require in dependency order, and the trace of
/// shortlisted actions they declined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub revision: u64,
    pub facts_digest: String,
    pub obligations: Vec<SelectedObligation>,
    pub declined: Vec<Declined>,
}

/// An open question the framed goal still carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameUnknown {
    /// The impact scan could not decide which surfaces the work touches.
    ImpactSurface,
    /// The task names no addressable criterion.
    AddressableCriteria,
}

/// One plan: the parts and the order their dependencies allow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub order: Vec<String>,
    pub parts: Vec<WorkPart>,
}

/// What the mechanical `assess_plan` leg flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlanFinding {
    /// The task names no criterion, so coverage cannot be judged.
    ZeroCriteria,
    /// A task criterion no part serves.
    UncoveredCriterion { criterion: CriterionId },
    /// A part serves a criterion the task does not have.
    UnknownCriterion {
        part: String,
        criterion: CriterionId,
    },
    /// A part names no check that would prove it.
    MissingProof { part: String },
}

/// A mechanical verdict bound to the exact plan revision it judged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Assessment {
    pub plan_revision: u64,
    pub verdict: PlanVerdict,
    pub findings: Vec<PlanFinding>,
}

/// What the catalog reports: `Asked` — one versioned question published
/// and the task waiting — or `Answered` — a delegated machine resolution
/// applied through the same answer seam a human answer rides, attributed
/// to its declared non-human author.
#[derive(Debug, Clone)]
pub enum ActionOutcome {
    Asked {
        question: Question,
        snapshot: TaskSnapshot,
    },
    /// A delegated machine answer committed through the shared seam.
    /// The store write alone leaves the task running but unscheduled:
    /// the caller owes the post-answer resume — `Runtime::resume_answered`
    /// or its moral equivalent — because [`ActionContext`] holds no
    /// scheduler handle. A producer that stops at this outcome parks the
    /// task on a drained question; the wire and card ingresses already
    /// perform the resume this type cannot reach.
    Answered {
        question_id: QuestionId,
        selection: AnswerSelection,
        author: String,
        result: CommandResult,
    },
    /// The task's own addressable criteria and constraints, read from
    /// the store — never a rewrite of the user's request.
    Framed {
        criteria: Vec<Criterion>,
        constraints: Vec<String>,
        unknowns: Vec<FrameUnknown>,
    },
    Planned {
        revision: u64,
        plan: Plan,
    },
    Assessed(Assessment),
    /// Risks the `challenge_direction` purpose returned, each bound to a
    /// surface of the current selection.
    Challenged {
        risks: Vec<SurfaceNote>,
    },
    /// Boundary contracts the `design_contracts` purpose returned, each
    /// bound to a surface of the current selection.
    Designed {
        contracts: Vec<SurfaceNote>,
    },
    /// The `assess_plan` purpose's semantic verdict on the stored plan
    /// revision the mechanical leg passed.
    Judged {
        plan_revision: u64,
        verdict: SemanticVerdict,
        findings: Vec<String>,
    },
    /// A material choice a semantic reply surfaced, resolved through
    /// `resolve_decision`; the stage's row waits on it.
    Forked {
        action: &'static str,
        resolution: Box<ActionOutcome>,
    },
    /// The boundary inspection: what this build declares, what its one
    /// worker-routed probe answered, and what it could not cover. A leg
    /// whose probe did not answer is reported `Unanswered` with its wire
    /// class, never served as if it had.
    Inspected(Box<BoundaryReport>),
    AssumptionTested(AssumptionCheckRecord),
    /// A bounded restore request for executor admission, paired with the
    /// original check expectation the caller must rerun unchanged.
    EnvironmentRequested {
        restore: EnvironmentRestore,
        original: AssumptionCheckRecord,
    },
    /// The handler's row is not open on these facts.
    Skipped {
        action: &'static str,
        reason: SkipReason,
    },
}

/// What one boundary inspection was asked for: the budget its probe is
/// bounded by, and the task whose cancellation reaches the worker. The
/// project root is deliberately absent — it is the index seam's own
/// pinned root, so no caller can widen what the boundary reads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InspectSystemInput {
    pub budget_ms: Option<u64>,
    pub task_id: Option<TaskId>,
}

/// Whether a declared capability answered when the boundary probed it.
/// An unanswered leg is named by its wire class and by the closed tag
/// of the branch that decided it, so a consumer learns why the boundary
/// does not know without reading prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// The leg answered through the index worker: its rows, its
    /// coverage and its snapshot are the boundary's own facts.
    Answered,
    /// The leg is declared and this build does not probe it. The
    /// admitted engine behind it is in-process work whose answer would
    /// be a project report rather than a boundary fact, so the boundary
    /// states the declaration and never an `Answered` it did not
    /// observe.
    Declared { engine: &'static str },
    /// The isolated run ended without an answer. `code` is the class
    /// the refusal maps to and `cause` the DEC-033 branch tag.
    Unanswered { code: ErrorCode, cause: String },
}

/// One system the boundary reports: a source-query kind, the admitted
/// engine behind it, and whether the boundary's probe of it answered.
/// A kind with no admitted backend is declared and never satisfied — the
/// boundary reports the refusal that interface gives, whatever the probe
/// did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReportedSystem {
    pub kind: QueryKind,
    pub backend: Option<SearchBackend>,
    pub outcome: ProbeOutcome,
}

/// One row the boundary's probe actually served: where the name was
/// defined, and the document version the bytes carried. A row here is an
/// observation the worker read — never an inference from the corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DetectedRow {
    pub path: PathBuf,
    pub line: u64,
    pub name: String,
    pub version: i32,
}

/// How current the stored project index is. A generation that was never
/// cut reads as `Live` — the boundary scanned nothing, and says so
/// rather than reporting a generation that does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "freshness", rename_all = "snake_case")]
pub enum IndexFreshness {
    Live,
    Generation(GenerationState),
}

/// The boundary's own report: which source-query kinds it declares, the
/// outcome of the one probe that reaches the parse legs, the rows that
/// probe served, how current the project index is, and what the probe
/// could not cover. It is a statement about the boundary — never a
/// project report the boundary did not read.
#[derive(Clone, Serialize)]
pub struct BoundaryReport {
    pub systems: Vec<ReportedSystem>,
    pub detected: Vec<DetectedRow>,
    pub freshness: IndexFreshness,
    /// The probe's own coverage reasons, verbatim: a partial answer
    /// carries them rather than a clean `Complete`.
    pub residual_risk: Vec<PartialReason>,
    /// Why nothing is watching the project, when the backend refused
    /// the watch. A generation is kept current by re-cutting it, and
    /// the watch is what tells the runtime the project moved, so a
    /// refused watch is a disclosed gap in freshness detection — named
    /// here rather than leaving a stale generation to read as current.
    pub watch_refusal: Option<String>,
    #[serde(skip)]
    probe_error: Option<Arc<crate::context::ContextError>>,
}

impl BoundaryReport {
    /// Constructs a boundary report from its five ordinary public fields.
    ///
    /// # Examples
    /// ```
    /// use rivect::actions::{BoundaryReport, DetectedRow, IndexFreshness, ReportedSystem};
    /// use rivect::index::PartialReason;
    ///
    /// let systems: Vec<ReportedSystem> = Vec::new();
    /// let detected: Vec<DetectedRow> = Vec::new();
    /// let residual_risk: Vec<PartialReason> = Vec::new();
    /// let report = BoundaryReport::new(
    ///     systems, detected, IndexFreshness::Live, residual_risk, None,
    /// );
    /// assert!(report.probe_error().is_none());
    /// ```
    #[must_use]
    pub fn new(
        systems: Vec<ReportedSystem>,
        detected: Vec<DetectedRow>,
        freshness: IndexFreshness,
        residual_risk: Vec<PartialReason>,
        watch_refusal: Option<String>,
    ) -> Self {
        Self {
            systems,
            detected,
            freshness,
            residual_risk,
            watch_refusal,
            probe_error: None,
        }
    }

    /// Borrows the original failed probe while this report or a clone owns it.
    pub fn probe_error(&self) -> Option<&crate::context::ContextError> {
        self.probe_error.as_deref()
    }
}

impl std::fmt::Debug for BoundaryReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundaryReport")
            .field("systems", &self.systems)
            .field("detected", &self.detected)
            .field("freshness", &self.freshness)
            .field("residual_risk", &self.residual_risk)
            .field("watch_refusal", &self.watch_refusal)
            .field(
                "probe_error",
                &self
                    .probe_error
                    .as_ref()
                    .map(|error| (error.error_code(), error.tag())),
            )
            .finish()
    }
}

impl PartialEq for BoundaryReport {
    fn eq(&self, other: &Self) -> bool {
        self.systems == other.systems
            && self.detected == other.detected
            && self.freshness == other.freshness
            && self.residual_risk == other.residual_risk
            && self.watch_refusal == other.watch_refusal
    }
}

impl Eq for BoundaryReport {}

/// The definition the boundary probe asks the symbol leg for. It is a
/// name no project is expected to define, because the probe is about
/// whether the leg *answers* — the isolated run, the envelope, the
/// whole build — and not about what any particular corpus contains. A
/// project that did define it would have its rows reported, never a
/// fabricated one.
pub const BOUNDARY_PROBE_NAME: &str = "__rivect_boundary_probe";

/// Borrowed surfaces a handler needs: the owning store (question
/// publication and answer), the session events attach to, the
/// effective config the mode reads from, and the index seam every
/// runtime parse rides.
///
/// ```compile_fail
/// use rivect::{commands::Runtime, config::Config, contracts::SessionId};
/// fn f(rt: &mut Runtime, session: &SessionId, config: &Config) {
///     let ctx = rt.action_context(session, config);
///     let _s = ctx.store;
/// }
/// ```
///
/// ```
/// use rivect::{commands::Runtime, config::Config, contracts::SessionId};
/// fn f(rt: &mut Runtime, session: &SessionId, config: &Config) {
///     let ctx = rt.action_context(session, config);
///     let _id = ctx.session_id;
/// }
/// ```
///
/// ```compile_fail
/// use rivect::{actions::ActionContext, commands::IndexSeam, config::Config, contracts::SessionId, state::TaskStore};
/// fn f(store: &mut TaskStore, session: &SessionId, config: &Config, index: &IndexSeam) {
///     let _ctx = ActionContext { store, session_id: session, config, index };
/// }
/// ```
///
/// ```
/// use rivect::{actions::ActionContext, commands::IndexSeam, config::Config, contracts::SessionId, state::TaskStore};
/// fn f(store: &mut TaskStore, session: &SessionId, config: &Config, index: &IndexSeam) {
///     let _ = (store, session, config, index);
///     let _: Option<ActionContext<'_>> = None;
/// }
/// ```
///
/// ```compile_fail
/// use rivect::{actions::ActionContext, commands::IndexSeam, config::Config, contracts::SessionId, state::TaskStore};
/// fn f(store: &mut TaskStore, session: &SessionId, config: &Config, index: &IndexSeam) {
///     let _ctx = ActionContext::new(store, session, config, index);
/// }
/// ```
///
/// ```
/// use rivect::{commands::Runtime, config::Config, contracts::SessionId};
/// fn f(rt: &mut Runtime, session: &SessionId, config: &Config) {
///     let _ctx = rt.action_context(session, config);
/// }
/// ```
pub struct ActionContext<'a> {
    store: &'a mut TaskStore,
    pub session_id: &'a SessionId,
    pub config: &'a Config,
    /// The pinned project root and the capped index worker, shared with
    /// the `command.execute` dispatcher. One root and one worker program
    /// for the whole runtime, so a handler and the dispatcher can never
    /// disagree about what is being read or what parses it (DEC-031).
    pub index: &'a crate::commands::IndexSeam,
}

impl<'a> ActionContext<'a> {
    /// The one constructor: the store borrow is private, so a context is
    /// built only from a runtime's own store (`Runtime::action_context`).
    pub(crate) fn new(
        store: &'a mut TaskStore,
        session_id: &'a SessionId,
        config: &'a Config,
        index: &'a crate::commands::IndexSeam,
    ) -> Self {
        Self {
            store,
            session_id,
            config,
            index,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ActionError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("inspection freshness could not be read after probe failure")]
    InspectionFreshnessFailed {
        #[source]
        primary: Box<crate::context::ContextError>,
        secondary: StoreError,
    },
    #[error("decision prompt is required")]
    EmptyPrompt,
    #[error("decision prompt exceeds {max} bytes")]
    PromptTooLarge { max: usize },
    #[error(
        "decision fork carries {actual} positions; exactly {expected} honest positions are required"
    )]
    OptionSlots { expected: usize, actual: usize },
    #[error("duplicate option id {option_id}")]
    DuplicateOptionId { option_id: String },
    #[error("option id {option_id} must be non-empty ASCII within 64 bytes ([A-Za-z0-9._-])")]
    InvalidOptionId { option_id: String },
    #[error("disabled option {option_id} must carry a reason")]
    DisabledWithoutReason { option_id: String },
    #[error("recommended option {option_id} is not an enabled position")]
    RecommendationNotSelectable { option_id: String },
    #[error("recommendation basis is required")]
    EmptyBasis,
    #[error("machine answer requires an explicit non-human author")]
    AutoAuthorRequired,
    #[error("auto mode must not impersonate a human answer")]
    AutoImpersonatesHuman,
    #[error("action {action} is registered but not executable in this build")]
    Unavailable { action: &'static str },
    #[error("a plan needs at least one part")]
    EmptyPlan,
    #[error("a plan list exceeds {max} items")]
    PlanTooLarge { max: usize },
    #[error("part id {part} must be non-empty ASCII within 64 bytes ([A-Za-z0-9._-])")]
    InvalidPartId { part: String },
    #[error("part {part} proof exceeds {max} bytes")]
    ProofTooLarge { part: String, max: usize },
    #[error("duplicate part id {part}")]
    DuplicatePart { part: String },
    #[error("part {part} depends on unknown part {dependency}")]
    UnknownDependency { part: String, dependency: String },
    #[error("part {part} is in a dependency cycle")]
    DependencyCycle { part: String },
    #[error("plan record could not be encoded or decoded: {0}")]
    PlanRecord(#[from] serde_json::Error),
    #[error("check id must be non-empty ASCII within 64 bytes ([A-Za-z0-9._-])")]
    InvalidCheckId,
    #[error("assumption assertion must be non-empty and within {max} bytes")]
    InvalidAssertion { max: usize },
    #[error("environment grant id is required")]
    MissingEnvironmentGrant,
    #[error("environment target must be an absolute normalized path")]
    InvalidEnvironmentTarget,
    #[error("environment restore exceeds {max} bytes")]
    EnvironmentRestoreTooLarge { max: usize },
    #[error("assumption check is not recorded")]
    AssumptionNotRecorded,
    #[error("environment preparation does not apply to this result")]
    EnvironmentNotNeeded,
    #[error("semantic purpose {action} did not answer")]
    SemanticDispatch {
        action: &'static str,
        #[source]
        source: Box<ModelError>,
    },
    #[error("semantic purpose {action} reply refused")]
    SemanticReply {
        action: &'static str,
        #[source]
        cause: SemanticRefusal,
    },
}

impl ActionError {
    /// The wire code one failing action maps to: store denials keep
    /// their own class; a malformed fork, plan or undelegated machine
    /// answer is a caller error; an unreadable plan record is storage.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Store(source) => source.code(),
            Self::InspectionFreshnessFailed { secondary, .. } => secondary.code(),
            Self::AutoAuthorRequired | Self::AutoImpersonatesHuman => ErrorCode::Denied,
            Self::Unavailable { .. } | Self::SemanticDispatch { .. } => {
                ErrorCode::CapabilityUnavailable
            }
            Self::SemanticReply { .. } => ErrorCode::DependencyBlocked,
            Self::PlanRecord(_) => ErrorCode::StorageUnavailable,
            Self::AssumptionNotRecorded => ErrorCode::NotFound,
            Self::EnvironmentNotNeeded => ErrorCode::Conflict,
            Self::EmptyPrompt
            | Self::InvalidCheckId
            | Self::InvalidAssertion { .. }
            | Self::MissingEnvironmentGrant
            | Self::InvalidEnvironmentTarget
            | Self::EnvironmentRestoreTooLarge { .. }
            | Self::PromptTooLarge { .. }
            | Self::OptionSlots { .. }
            | Self::DuplicateOptionId { .. }
            | Self::InvalidOptionId { .. }
            | Self::DisabledWithoutReason { .. }
            | Self::RecommendationNotSelectable { .. }
            | Self::EmptyBasis
            | Self::EmptyPlan
            | Self::PlanTooLarge { .. }
            | Self::InvalidPartId { .. }
            | Self::ProofTooLarge { .. }
            | Self::DuplicatePart { .. }
            | Self::UnknownDependency { .. }
            | Self::DependencyCycle { .. } => ErrorCode::InvalidInput,
        }
    }
}

/// The shared catalog. One registry serves every producer — per-agent
/// registries would fork the contract this row pins.
pub struct ActionRegistry {
    definitions: BTreeMap<&'static str, ActionDefinition>,
}

impl Default for ActionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionRegistry {
    pub fn new() -> Self {
        let mut definitions = BTreeMap::new();
        definitions.insert(
            RESOLVE_DECISION,
            ActionDefinition {
                id: RESOLVE_DECISION,
                revision: 1,
                trigger: "a material fork needs a versioned ask/auto decision",
                negative_trigger: "not for workflow gates, permission asks, or answers — it publishes the fork, it never consents",
                outcome: "one pending Question in ask mode, or an applied machine answer under a bounded delegation in auto mode",
                implementation: Implementation::Local,
            },
        );
        definitions.insert(
            INSPECT_SYSTEM,
            ActionDefinition {
                id: INSPECT_SYSTEM,
                revision: 2,
                trigger: "a caller asks which project capabilities the system layer actually knows",
                negative_trigger: "not a search kind — it reports the boundary's declared/satisfied/detected systems, it never answers a query and never parses project source in process",
                outcome: "a typed boundary payload — declared/satisfied/detected systems by kind with freshness and residual risk; the parse legs are probed through the index worker, and a probe that did not answer is reported with its wire class",
                implementation: Implementation::Local,
            },
        );
        definitions.insert(
            TEST_ASSUMPTION,
            ActionDefinition {
                id: TEST_ASSUMPTION,
                revision: 1,
                trigger: "a check result tests a named hypothesis against its expected result",
                negative_trigger: "an unavailable executable, fixture, or environment is a setup gap, not a product result",
                outcome: "the expected result and a typed distinction between product outcomes and setup gaps",
                implementation: Implementation::Local,
            },
        );
        definitions.insert(
            PREPARE_ENVIRONMENT,
            ActionDefinition {
                id: PREPARE_ENVIRONMENT,
                revision: 1,
                trigger: "a prior assumption check recorded a setup gap that an authorized restore can address",
                negative_trigger: "not for a completed check or a product defect",
                outcome: "a bounded environment restoration request and the unchanged original check expectation",
                implementation: Implementation::Local,
            },
        );
        for definition in plan_definitions() {
            definitions.insert(definition.id, definition);
        }
        Self { definitions }
    }

    pub fn definitions(&self) -> impl Iterator<Item = &ActionDefinition> {
        self.definitions.values()
    }

    pub fn definition(&self, id: &str) -> Option<&ActionDefinition> {
        self.definitions.get(id)
    }

    /// Typed dispatch on the input's own shape — the carrier, not a
    /// string, picks the handler, so a malformed kind cannot reach a
    /// handler it was never meant for.
    pub fn execute(
        &self,
        input: ActionInput,
        ctx: &mut ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionError> {
        self.execute_with_seam(input, ctx, None)
    }

    /// [`ActionRegistry::execute`] with an optional broker seam: with one,
    /// `challenge_direction`, `design_contracts` and the semantic leg of
    /// `assess_plan` dispatch through their Broker purposes; without one
    /// they answer exactly as `execute` does. Every other action ignores
    /// the seam — `plan_work` stays local.
    ///
    /// # Errors
    /// The handler's own refusals; a semantic leg adds
    /// [`ActionError::SemanticDispatch`] and [`ActionError::SemanticReply`]
    /// after leaving its row open on the exact blocker.
    pub fn execute_with_seam(
        &self,
        input: ActionInput,
        ctx: &mut ActionContext<'_>,
        seam: Option<&mut BrokerSeam<'_>>,
    ) -> Result<ActionOutcome, ActionError> {
        self.dispatch(input, ctx, seam, None)
    }

    fn dispatch(
        &self,
        input: ActionInput,
        ctx: &mut ActionContext<'_>,
        seam: Option<&mut BrokerSeam<'_>>,
        fork_row: Option<&ForkRow<'_>>,
    ) -> Result<ActionOutcome, ActionError> {
        if let Some(seam) = seam {
            match input {
                ActionInput::ChallengeDirection(request) => {
                    return self.semantic_stage(CHALLENGE_DIRECTION, &request, ctx, seam);
                }
                ActionInput::DesignContracts(request) => {
                    return self.semantic_stage(DESIGN_CONTRACTS, &request, ctx, seam);
                }
                ActionInput::AssessPlan(request) => return judge_plan(&request, ctx, seam),
                other => return self.dispatch(other, ctx, None, fork_row),
            }
        }
        match input {
            ActionInput::ResolveDecision(input) => self.resolve_fork(input, ctx, fork_row),
            ActionInput::InspectSystem(input) => inspect_system(input, ctx),
            ActionInput::FrameGoal(request) => frame_goal(&request, ctx),
            ActionInput::ChallengeDirection(request) => {
                purpose_leg(CHALLENGE_DIRECTION, &request, ctx)
            }
            ActionInput::DesignContracts(request) => purpose_leg(DESIGN_CONTRACTS, &request, ctx),
            ActionInput::PlanWork(request) => plan_work(&request, ctx),
            ActionInput::AssessPlan(request) => assess_plan(&request, ctx),
            ActionInput::TestAssumption(input) => test_assumption(input, ctx),
            ActionInput::PrepareEnvironment(input) => prepare_environment(input, ctx),
        }
    }

    /// Records the one versioned selection the request facts require —
    /// revision, canonical facts digest, request kind and rows, in one
    /// transaction — each row routed to its handler, an allowed
    /// equivalent, or an exact blocker. `shortlist` is a ranking's
    /// advisory top-K: it can neither drop a required obligation nor
    /// admit one the facts do not need, and every shortlisted action the
    /// facts decline is traced with its reason. The code decides from
    /// typed facts; no model is called.
    ///
    /// # Errors
    /// Returns [`ActionError::Store`] when the task is unknown or
    /// terminal or the selection cannot be recorded.
    pub fn select(
        &self,
        request: &PlanRequest,
        shortlist: &[&str],
        ctx: &mut ActionContext<'_>,
    ) -> Result<Selection, ActionError> {
        let needs = needs(request);
        let obligations: Vec<SelectedObligation> = needs
            .iter()
            .filter_map(|&(capability, need, equivalent)| {
                let applicability = match need {
                    Need::Required => ObligationApplicability::Required,
                    Need::Unresolved => ObligationApplicability::Unresolved,
                    Need::Skip(_) => return None,
                };
                Some(SelectedObligation {
                    capability,
                    applicability,
                    route: self.route(capability, equivalent),
                })
            })
            .collect();
        let declined = shortlist
            .iter()
            .filter(|id| !obligations.iter().any(|row| row.capability == **id))
            .map(|id| Declined {
                action: (*id).to_string(),
                reason: self.decline_reason(id, &needs),
            })
            .collect();
        let rows: Vec<PlanRowWrite<'_>> = obligations.iter().map(row_write).collect();
        let facts_digest = facts_digest(request)?;
        let record = ctx.store.record_plan_selection(
            ctx.session_id,
            &request.task_id,
            &PlanSelectionWrite {
                facts_digest: &facts_digest,
                request_kind: request.kind,
                rows: &rows,
            },
        )?;
        Ok(Selection {
            revision: record.revision,
            facts_digest: record.facts_digest,
            obligations,
            declined,
        })
    }

    /// The capability's own handler or Broker purpose when this build
    /// declares one, else the allowed local equivalent, else the exact
    /// reason nothing can run.
    fn route(&self, capability: &'static str, equivalent: Option<&'static str>) -> Route {
        let local = |id: &str| {
            self.definition(id).is_some_and(|row| {
                matches!(
                    row.implementation,
                    Implementation::Local | Implementation::LocalAndPurpose
                )
            })
        };
        if local(capability) {
            return Route::Local(capability);
        }
        if self
            .definition(capability)
            .is_some_and(|row| row.implementation == Implementation::Purpose)
        {
            return Route::Purpose(capability);
        }
        if let Some(equivalent) = equivalent.filter(|id| local(id)) {
            return Route::Equivalent(equivalent);
        }
        if self.definition(capability).is_some() {
            Route::Blocked(RouteBlock::Unavailable)
        } else {
            Route::Blocked(RouteBlock::NotInBuild)
        }
    }

    fn decline_reason(
        &self,
        id: &str,
        needs: &[(&'static str, Need, Option<&'static str>)],
    ) -> SkipReason {
        match needs.iter().find(|(capability, ..)| *capability == id) {
            Some((_, Need::Skip(reason), _)) => *reason,
            _ if self.definition(id).is_some() => SkipReason::NotNeeded,
            _ => SkipReason::Unsupported,
        }
    }

    /// One material fork: validate the five honest positions, then the
    /// effective mode decides — `ask` (and an undelegated `auto`) publish
    /// one versioned question; a delegated `auto` applies the recommended
    /// position through the same answer seam, attributed to its declared
    /// non-human author.
    pub fn resolve_decision(
        &self,
        input: ResolveDecisionInput,
        ctx: &mut ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionError> {
        self.dispatch(ActionInput::ResolveDecision(input), ctx, None, None)
    }

    /// `resolve_decision` with the plan row a semantic stage's fork waits
    /// on: its publish also records the row's `Decision` blocker.
    fn resolve_fork(
        &self,
        input: ResolveDecisionInput,
        ctx: &mut ActionContext<'_>,
        row: Option<&ForkRow<'_>>,
    ) -> Result<ActionOutcome, ActionError> {
        let auto = ctx.config.decisions_mode() == DecisionMode::Auto;
        // In auto the author gate precedes all answer work: a call that
        // cannot name a non-human origin — or names "human" — is
        // refused before the fork is validated, read, or published.
        let author = if auto {
            Some(match input.author {
                Some(author @ (DecisionAuthor::System | DecisionAuthor::Agent)) => author.as_str(),
                Some(DecisionAuthor::Human) => return Err(ActionError::AutoImpersonatesHuman),
                None => return Err(ActionError::AutoAuthorRequired),
            })
        } else {
            None
        };
        validate_fork(&input)?;
        let snapshot = ctx.store.snapshot(&input.task_id)?;
        let question = Question {
            question_id: QuestionId::generate(),
            question_revision: 1,
            task_id: input.task_id.clone(),
            intent_revision: snapshot.intent_revision,
            prompt: input.prompt.clone(),
            options: input.options.clone(),
            recommended_option_id: input.recommended_option_id.clone(),
            recommendation_basis: input.recommendation_basis.clone(),
        };
        if !auto {
            let (question, snapshot) = publish_or_dedupe(ctx, &question, row)?;
            return Ok(ActionOutcome::Asked { question, snapshot });
        }
        // The gate above returns early on a missing author — auto mode
        // past this point always carries one.
        let author = author.ok_or(ActionError::AutoAuthorRequired)?;
        // Fail closed to ask: an undelegated auto can never answer, but
        // the material fork still surfaces one versioned question —
        // silent resolution and silent dropping are both forbidden.
        let delegated = input
            .delegation
            .as_ref()
            .is_some_and(|delegation| delegation.covers(RESOLVE_DECISION, &input.task_id));
        if !delegated {
            let (question, snapshot) = publish_or_dedupe(ctx, &question, row)?;
            return Ok(ActionOutcome::Asked { question, snapshot });
        }
        let (question, _snapshot) = publish_or_dedupe(ctx, &question, row)?;
        // The delegation covers one (action, task_id) pair — a grant
        // for another action or another task cannot answer this fork;
        // the answer selects the recommended position and rides the
        // same revision/intent/option gates a human answer does —
        // stale, replayed or disabled answers deny identically and
        // journal the same attempt rows.
        let selection = AnswerSelection::Option {
            option_id: question.recommended_option_id.clone(),
        };
        let result = ctx.store.answer_question(
            ctx.session_id,
            &input.task_id,
            &question.question_id,
            question.question_revision,
            &selection,
            author,
        )?;
        Ok(ActionOutcome::Answered {
            question_id: question.question_id,
            selection,
            author: author.to_string(),
            result,
        })
    }
}

/// The boundary inspection: one typed report about what this build can
/// do, not about any particular project.
///
/// It declares every source-query kind the mechanical backend table
/// admits (a kind with no admitted backend is declared and never
/// satisfied), probes the parse legs through the index worker — the only
/// runtime path to untrusted parsing (DEC-028) — and reports the rows
/// that probe served, the coverage it disclosed, and how current the
/// stored project index is.
///
/// The probe never answers in process: a missing helper, a cancelled
/// task, a deadline, a cap or a worker refusal is reported as
/// `Unanswered` with its own wire class, and the report carries no rows.
/// That is the whole invariant behind this surface — a boundary that
/// cannot parse does not pretend to have parsed.
///
/// # Errors
/// Returns [`ActionError::Store`] when the stored index generation
/// cannot be read.
fn inspect_system(
    input: InspectSystemInput,
    ctx: &ActionContext<'_>,
) -> Result<ActionOutcome, ActionError> {
    use crate::context::{IgnorePolicy, Query};

    let query = Query {
        kind: QueryKind::Symbol,
        root: ctx.index.root.clone(),
        pattern: BOUNDARY_PROBE_NAME.to_string(),
        scope_glob: None,
        ignore: IgnorePolicy::Respect,
        limit: 1,
        symbol_op: Some(SymbolOp::Definition),
        document: None,
    };
    let deadline = crate::commands::index_deadline(input.budget_ms);
    // A poll that cannot read the task's state cannot prove the task is
    // live, and cancellation is the highest-priority verdict here: the
    // run ends cancelled rather than parsing on an authority nobody can
    // confirm.
    let outcome = match input.task_id.as_ref() {
        None => {
            let never = || false;
            let run = ctx.index.worker.run(deadline, &never);
            crate::context::query_isolated(&query, &run)
        }
        Some(task_id) => {
            let store: &TaskStore = ctx.store;
            let poll = || !matches!(store.task_cancelled(task_id), Ok(false));
            let run = ctx.index.worker.run(deadline, &poll);
            crate::context::query_isolated(&query, &run)
        }
    };
    // The declared set is the mechanical table, read once: the probe says
    // whether one leg answered, never what the table should be.
    let probe = match &outcome {
        Ok(_) => ProbeOutcome::Answered,
        Err(error) => ProbeOutcome::Unanswered {
            code: error.error_code(),
            cause: refusal_tag(error),
        },
    };
    let systems = KNOWN_BOUNDARY_KINDS
        .iter()
        .map(|kind| {
            let backend = crate::context::backend_for(*kind);
            // A kind no admitted backend claims is reported with the
            // refusal a dispatch of that interface gives, whatever the
            // probe did: the boundary does not serve it in any build.
            let outcome = match backend {
                None => ProbeOutcome::Unanswered {
                    code: ErrorCode::CapabilityUnavailable,
                    cause: UNSUPPORTED_KIND_TAG.to_string(),
                },
                Some(_) if parse_leg(*kind) => probe.clone(),
                // A read-only leg is declared, not probed: the one
                // probe rides the symbol leg, so nothing here observed
                // whether this leg would answer.
                Some(backend) => ProbeOutcome::Declared {
                    engine: backend.engine(),
                },
            };
            ReportedSystem {
                kind: *kind,
                backend,
                outcome,
            }
        })
        .collect();
    // The coverage reasons are the probe's own, and only when the probe
    // answered. An unanswered probe measured no coverage, so there are
    // no reasons to report: the refusal's class on every parse leg is
    // what discloses it, in `systems[*].outcome`. `residual_risk` is a
    // list of *observed* coverage reasons, so an empty one here means
    // "this probe measured nothing" and never "this probe found no
    // risk" — the two are told apart by the same `systems` array, not
    // by this field.
    let residual_risk = match &outcome {
        Ok(result) => coverage_reasons(result),
        Err(_) => Vec::new(),
    };
    let freshness = match index_freshness(ctx) {
        Ok(freshness) => freshness,
        Err(secondary) => {
            return Err(match outcome {
                Err(primary) => ActionError::InspectionFreshnessFailed {
                    primary: Box::new(primary),
                    secondary,
                },
                Ok(_) => ActionError::Store(secondary),
            });
        }
    };
    let mut report = BoundaryReport::new(
        systems,
        match &outcome {
            Ok(result) => detected_rows(result),
            Err(_) => Vec::new(),
        },
        freshness,
        residual_risk,
        ctx.index.watch_refusal.clone(),
    );
    report.probe_error = outcome.err().map(Arc::new);
    Ok(ActionOutcome::Inspected(Box::new(report)))
}

/// Every source-query kind the boundary reports on, in the fixed order
/// of the mechanical table — never a set a caller supplies.
const KNOWN_BOUNDARY_KINDS: &[QueryKind] = &[
    QueryKind::Text,
    QueryKind::Path,
    QueryKind::Source,
    QueryKind::Ast,
    QueryKind::Symbol,
    QueryKind::Graph,
];

/// The refusal tag a kind with no admitted backend carries, the one the
/// engine's own `UnsupportedKind` refusal uses.
const UNSUPPORTED_KIND_TAG: &str = "unsupported_kind";

/// The tag naming the branch that actually decided a refusal. An
/// isolated run's own tag is the parent-side wrapper; the DEC-033 cause
/// beneath it is the fact a consumer acts on, so that is what the
/// boundary reports.
fn refusal_tag(error: &crate::context::ContextError) -> String {
    match error {
        crate::context::ContextError::IsolatedRun { cause, .. } => cause.tag().to_string(),
        other => other.tag().to_string(),
    }
}

/// Whether a kind reaches the untrusted parser — the kinds whose probe
/// must ride the index worker rather than run in process.
fn parse_leg(kind: QueryKind) -> bool {
    matches!(kind, QueryKind::Ast | QueryKind::Symbol | QueryKind::Graph)
}

/// The rows the probe served, in the worker's own order: the project
/// relative path the query reported, the line, the name, and the
/// document version its bytes carried. A row with no line is not
/// reported at all — a symbol row always carries one, and substituting
/// a coordinate the worker never gave would be a fabricated location.
fn detected_rows(result: &QueryResult) -> Vec<DetectedRow> {
    result
        .matches
        .iter()
        .filter_map(|hit| {
            let MatchKind::Symbol(row) = &hit.kind else {
                return None;
            };
            Some(DetectedRow {
                path: hit.source.path.clone(),
                line: hit.source.line?,
                name: row.name.clone(),
                version: row.version,
            })
        })
        .collect()
}

/// The probe's coverage reasons, verbatim. A complete answer contributes
/// none, so an empty residual risk and a complete coverage say the same
/// thing — and a partial one never reads as complete.
fn coverage_reasons(result: &QueryResult) -> Vec<PartialReason> {
    match &result.completeness {
        Completeness::Complete => Vec::new(),
        Completeness::Partial { reasons } => reasons.clone(),
    }
}

/// How current the stored project index is, read through the same store
/// seam in one statement. A generation that was never cut is `Live`: the
/// boundary read nothing, and says so rather than naming a generation
/// that does not exist. A generation whose build never finished reads as
/// `Stale { Interrupted }` — never as current.
fn index_freshness(ctx: &ActionContext<'_>) -> Result<IndexFreshness, StoreError> {
    Ok(match ctx.store.latest_index_state()? {
        None => IndexFreshness::Live,
        Some((_, state)) => IndexFreshness::Generation(state),
    })
}

/// Whether non-read work may start: `Unassessed` without a selection —
/// never `Open` — `Open` once no selected row waits on its applicability,
/// every required plan-phase row closed and, when `plan_work` is
/// required, the current selection's latest plan revision passed;
/// `Paused` otherwise. Execution-phase rows never gate. Reads never
/// consult it.
///
/// # Errors
/// Returns [`StoreError::Storage`] when the plan records cannot be read.
pub fn plan_gate(store: &TaskStore, task_id: &TaskId) -> Result<PlanGate, StoreError> {
    store.plan_gate(task_id)
}

/// A trigger evaluated on the request facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Need {
    Required,
    /// The facts the trigger reads are undecided.
    Unresolved,
    Skip(SkipReason),
}

/// Every capability the selection weighs, with its need and allowed
/// equivalent: the plan stages first, then the checks.
fn needs(request: &PlanRequest) -> Vec<(&'static str, Need, Option<&'static str>)> {
    let decided = request.surfaces.decided();
    let approved = request.contract == ContractBasis::Approved;
    let risky = decided.map(|surfaces| surfaces.iter().any(|surface| surface.is_risk()));
    let when = |holds: bool| {
        if holds {
            Need::Required
        } else {
            Need::Skip(SkipReason::NotNeeded)
        }
    };
    let frame = if approved {
        Need::Skip(SkipReason::AlreadySatisfied)
    } else {
        Need::Required
    };
    // Direction and design follow the risky surfaces — never the prompt
    // length — unless an approved contract already covers them.
    let risk = match (approved, risky) {
        (true, _) => Need::Skip(SkipReason::AlreadySatisfied),
        (false, None) => Need::Unresolved,
        (false, Some(risky)) => when(risky),
    };
    // A plan is needed when asked for, when parts need coordination, or
    // when a risky surface has no approved contract; it depends on the
    // design, so an undecided scan leaves it unresolved.
    let coordinated =
        request.parts.len() > 1 || request.parts.iter().any(|part| !part.depends_on.is_empty());
    let plan = match risky {
        None => Need::Unresolved,
        Some(risky) => {
            when(request.kind == RequestKind::PlanOnly || coordinated || (risky && !approved))
        }
    };
    let (inspect, security) = match decided {
        None => (Need::Required, Need::Unresolved),
        Some(surfaces) => (
            Need::Skip(SkipReason::AlreadySatisfied),
            when(surfaces.iter().any(|surface| surface.triggers_security())),
        ),
    };
    let kind = request.kind;
    let edits = matches!(kind, RequestKind::Change | RequestKind::Deliver);
    // Readiness of a plan artifact is exactly what the plan assessment
    // checks; readiness of code or a report is not.
    let readiness_equivalent = (kind == RequestKind::PlanOnly).then_some(ASSESS_PLAN);
    vec![
        (FRAME_GOAL, frame, None),
        (CHALLENGE_DIRECTION, risk, None),
        (DESIGN_CONTRACTS, risk, None),
        (PLAN_WORK, plan, None),
        (ASSESS_PLAN, plan, None),
        (INSPECT_SYSTEM, inspect, None),
        (ASSESS_SECURITY, security, None),
        (AUDIT_TESTS, when(edits), None),
        (IMPLEMENT_CHANGE, when(edits), None),
        (DELIVER_CHANGE, when(kind == RequestKind::Deliver), None),
        (REVIEW_CHANGE, when(kind == RequestKind::Audit), None),
        (DIAGNOSE_ISSUE, when(kind == RequestKind::Diagnose), None),
        (ASSESS_READINESS, Need::Required, readiness_equivalent),
    ]
}

/// The row a selected obligation records: its phase, its handler and —
/// for an undecided applicability or a route this build cannot run — the
/// exact blocker it waits on.
fn row_write(row: &SelectedObligation) -> PlanRowWrite<'static> {
    let (handler, route_blocker) = match row.route {
        Route::Local(handler) | Route::Equivalent(handler) => (Some(handler), None),
        // PG-1: a purpose row without a broker seam waits on the exact
        // capability blocker — never a template, never not_applicable.
        Route::Purpose(handler) => (Some(handler), Some(ErrorCode::CapabilityUnavailable)),
        Route::Blocked(_) => (None, Some(ErrorCode::CapabilityUnavailable)),
    };
    let reason = if row.applicability == ObligationApplicability::Unresolved {
        Some(ErrorCode::DependencyBlocked)
    } else {
        route_blocker
    };
    PlanRowWrite {
        capability: row.capability,
        applicability: row.applicability,
        stage: PLAN_STAGES.contains(&row.capability),
        handler,
        blocker: reason.map(|reason| plan_blocker(reason, row.capability)),
    }
}

/// The canonical facts digest: request kind, the decided surfaces (an
/// undecided scan digests as none), contract basis and parts. Prompt
/// text is not a fact.
fn facts_digest(request: &PlanRequest) -> Result<String, ActionError> {
    #[derive(Serialize)]
    struct CanonicalFacts<'a> {
        kind: RequestKind,
        surfaces: Option<&'a BTreeSet<Surface>>,
        contract: ContractBasis,
        parts: &'a [WorkPart],
    }
    let canonical = serde_json::to_vec(&CanonicalFacts {
        kind: request.kind,
        surfaces: request.surfaces.decided(),
        contract: request.contract,
        parts: &request.parts,
    })?;
    Ok(crate::config::hex(&sha2::Sha256::digest(&canonical)))
}

/// The current selection a handler's facts are bound to. Facts whose
/// digest is not the selection's close nothing — the store re-checks
/// the same binding inside every write.
struct Bound {
    selection: PlanSelectionRecord,
    facts_digest: String,
}

fn bind(request: &PlanRequest, ctx: &ActionContext<'_>) -> Result<Bound, ActionError> {
    let facts_digest = facts_digest(request)?;
    let selection = ctx
        .store
        .plan_selection(&request.task_id)?
        .ok_or(StoreError::Conflict(ConflictCause::PlanSelectionMissing))?;
    if selection.facts_digest != facts_digest {
        return Err(StoreError::Conflict(ConflictCause::PlanSelectionStale {
            revision: selection.revision,
        })
        .into());
    }
    Ok(Bound {
        selection,
        facts_digest,
    })
}

/// Where a handler's own row stands under the bound selection.
enum RowState {
    /// The selection did not require the row; the reason the facts gave.
    Absent(SkipReason),
    Unresolved,
    Open(ObligationExecution),
}

fn row_state(
    request: &PlanRequest,
    capability: &str,
    ctx: &ActionContext<'_>,
) -> Result<RowState, ActionError> {
    let row = ctx
        .store
        .plan_obligations(&request.task_id)?
        .into_iter()
        .find(|row| row.capability == capability);
    Ok(match row {
        None => RowState::Absent(
            match needs(request).iter().find(|(id, ..)| *id == capability) {
                Some((_, Need::Skip(reason), _)) => *reason,
                _ => SkipReason::NotNeeded,
            },
        ),
        Some(row) if row.applicability == ObligationApplicability::Unresolved => {
            RowState::Unresolved
        }
        Some(row) => RowState::Open(row.execution),
    })
}

fn skip(action: &'static str, reason: SkipReason) -> ActionOutcome {
    ActionOutcome::Skipped { action, reason }
}

fn frame_goal(
    request: &PlanRequest,
    ctx: &mut ActionContext<'_>,
) -> Result<ActionOutcome, ActionError> {
    let bound = bind(request, ctx)?;
    match row_state(request, FRAME_GOAL, ctx)? {
        RowState::Absent(reason) => return Ok(skip(FRAME_GOAL, reason)),
        RowState::Unresolved => return Ok(skip(FRAME_GOAL, SkipReason::NeedsInformation)),
        RowState::Open(ObligationExecution::Satisfied) => {
            return Ok(skip(FRAME_GOAL, SkipReason::AlreadySatisfied));
        }
        RowState::Open(_) => {}
    }
    let snapshot = ctx.store.snapshot(&request.task_id)?;
    let mut unknowns = Vec::new();
    if request.surfaces.decided().is_none() {
        unknowns.push(FrameUnknown::ImpactSurface);
    }
    if snapshot.criteria.items.is_empty() {
        unknowns.push(FrameUnknown::AddressableCriteria);
    }
    let criteria = snapshot.criteria.items;
    let criterion_ids: Vec<&CriterionId> = criteria.iter().map(|criterion| &criterion.id).collect();
    let outcome_json =
        serde_json::json!({ "criteria": criterion_ids, "unknowns": unknowns }).to_string();
    ctx.store.update_plan_row(
        &request.task_id,
        &PlanRowUpdate {
            capability: FRAME_GOAL,
            handler: FRAME_GOAL,
            selection_revision: bound.selection.revision,
            facts_digest: &bound.facts_digest,
            change: PlanRowChange::Close {
                execution: ObligationExecution::Satisfied,
                outcome_json,
            },
        },
    )?;
    Ok(ActionOutcome::Framed {
        criteria,
        constraints: snapshot.constraints.items,
        unknowns,
    })
}

/// `challenge_direction` and `design_contracts` are Broker purposes named
/// by their action ids. Called without a broker seam, a required row
/// answers the exact `capability_unavailable` refusal and stays open on
/// that blocker — never a fixed per-surface template sold as a checked
/// risk or contract.
fn purpose_leg(
    action: &'static str,
    request: &PlanRequest,
    ctx: &ActionContext<'_>,
) -> Result<ActionOutcome, ActionError> {
    bind(request, ctx)?;
    match row_state(request, action, ctx)? {
        RowState::Absent(reason) => Ok(skip(action, reason)),
        RowState::Unresolved => Ok(skip(action, SkipReason::NeedsInformation)),
        RowState::Open(ObligationExecution::Satisfied) => {
            Ok(skip(action, SkipReason::AlreadySatisfied))
        }
        RowState::Open(_) => Err(ActionError::Unavailable { action }),
    }
}

/// Validates and orders the parts, then records the revision under the
/// current selection, closes `plan_work` and reopens `assess_plan` in one
/// transaction. A satisfied `plan_work` may record again: every new
/// revision reopens the assessment.
fn plan_work(
    request: &PlanRequest,
    ctx: &mut ActionContext<'_>,
) -> Result<ActionOutcome, ActionError> {
    let bound = bind(request, ctx)?;
    match row_state(request, PLAN_WORK, ctx)? {
        RowState::Absent(reason) => return Ok(skip(PLAN_WORK, reason)),
        RowState::Unresolved => return Ok(skip(PLAN_WORK, SkipReason::NeedsInformation)),
        RowState::Open(_) => {}
    }
    let plan = Plan {
        order: dependency_order(&request.parts)?,
        parts: request.parts.clone(),
    };
    let body_json = serde_json::to_string(&plan)?;
    let revision = ctx.store.record_plan_revision(
        &request.task_id,
        &PlanRevisionWrite {
            handler: PLAN_WORK,
            reopens: ASSESS_PLAN,
            selection_revision: bound.selection.revision,
            facts_digest: &bound.facts_digest,
            body_json: &body_json,
        },
    )?;
    Ok(ActionOutcome::Planned { revision, plan })
}

/// Validates the parts and orders them so every part follows the parts
/// it depends on; ties keep the caller's order.
fn dependency_order(parts: &[WorkPart]) -> Result<Vec<String>, ActionError> {
    if parts.is_empty() {
        return Err(ActionError::EmptyPlan);
    }
    if parts.len() > ARRAY_MAX_ITEMS {
        return Err(ActionError::PlanTooLarge {
            max: ARRAY_MAX_ITEMS,
        });
    }
    let mut ids = BTreeSet::new();
    for part in parts {
        if part.criteria.len() > ARRAY_MAX_ITEMS || part.depends_on.len() > ARRAY_MAX_ITEMS {
            return Err(ActionError::PlanTooLarge {
                max: ARRAY_MAX_ITEMS,
            });
        }
        if !legal_id(&part.id) {
            return Err(ActionError::InvalidPartId {
                part: part.id.clone(),
            });
        }
        if part.proof.len() > TEXT_MAX_BYTES {
            return Err(ActionError::ProofTooLarge {
                part: part.id.clone(),
                max: TEXT_MAX_BYTES,
            });
        }
        if !ids.insert(part.id.as_str()) {
            return Err(ActionError::DuplicatePart {
                part: part.id.clone(),
            });
        }
    }
    for part in parts {
        if let Some(dependency) = part
            .depends_on
            .iter()
            .find(|dependency| !ids.contains(dependency.as_str()))
        {
            return Err(ActionError::UnknownDependency {
                part: part.id.clone(),
                dependency: dependency.clone(),
            });
        }
    }
    let mut placed = BTreeSet::new();
    let mut order = Vec::with_capacity(parts.len());
    while let Some(stuck) = parts.iter().find(|part| !placed.contains(part.id.as_str())) {
        let before = order.len();
        for part in parts {
            if !placed.contains(part.id.as_str())
                && part
                    .depends_on
                    .iter()
                    .all(|dependency| placed.contains(dependency.as_str()))
            {
                placed.insert(part.id.as_str());
                order.push(part.id.clone());
            }
        }
        if order.len() == before {
            return Err(ActionError::DependencyCycle {
                part: stuck.id.clone(),
            });
        }
    }
    Ok(order)
}

/// The mechanical leg judges the latest revision of the current selection
/// for coverage and test design. `Pass` needs the `assess_plan`
/// Broker-purpose leg too. Without that seam, a passing row stays open on
/// the exact `capability_unavailable` blocker; a failing one closes
/// `failed` on a dependency blocker until a new revision reopens it.
fn assess_plan(
    request: &PlanRequest,
    ctx: &mut ActionContext<'_>,
) -> Result<ActionOutcome, ActionError> {
    let bound = bind(request, ctx)?;
    match row_state(request, ASSESS_PLAN, ctx)? {
        RowState::Absent(reason) => return Ok(skip(ASSESS_PLAN, reason)),
        RowState::Unresolved => return Ok(skip(ASSESS_PLAN, SkipReason::NeedsInformation)),
        RowState::Open(_) => {}
    }
    let Some(latest) = ctx
        .store
        .plan_revisions(&request.task_id)?
        .into_iter()
        .rev()
        .find(|plan| plan.selection_revision == bound.selection.revision)
    else {
        return Ok(skip(ASSESS_PLAN, SkipReason::NeedsInformation));
    };
    if latest.verdict.is_some() {
        return Err(StoreError::Conflict(ConflictCause::PlanNotAssessable {
            revision: latest.revision,
        })
        .into());
    }
    let plan: Plan = serde_json::from_str(&latest.body_json)?;
    let criteria = ctx.store.snapshot(&request.task_id)?.criteria.items;
    let findings = plan_findings(&plan, &criteria);
    let verdict = if findings.is_empty() {
        PlanVerdict::Pass
    } else {
        PlanVerdict::Fail
    };
    let assessment = Assessment {
        plan_revision: latest.revision,
        verdict,
        findings,
    };
    let assessment_json = serde_json::to_string(&assessment)?;
    let mut changes = Vec::new();
    for row in ctx.store.plan_obligations(&request.task_id)? {
        if row.handler.as_deref() != Some(ASSESS_PLAN)
            || row.applicability != ObligationApplicability::Required
        {
            continue;
        }
        match verdict {
            PlanVerdict::Pass => {
                let blocker = plan_blocker(ErrorCode::CapabilityUnavailable, &row.capability);
                changes.push((row.capability, PlanRowChange::Block(blocker)));
            }
            PlanVerdict::Fail => {
                let blocker = plan_blocker(ErrorCode::DependencyBlocked, &row.capability);
                changes.push((
                    row.capability.clone(),
                    PlanRowChange::Close {
                        execution: ObligationExecution::Failed,
                        outcome_json: assessment_json.clone(),
                    },
                ));
                changes.push((row.capability, PlanRowChange::Block(blocker)));
            }
        }
    }
    ctx.store.record_plan_assessment(
        &request.task_id,
        &PlanAssessmentWrite {
            handler: ASSESS_PLAN,
            selection_revision: bound.selection.revision,
            facts_digest: &bound.facts_digest,
            plan_revision: latest.revision,
            verdict,
            assessment_json: &assessment_json,
            changes,
        },
    )?;
    Ok(ActionOutcome::Assessed(assessment))
}

/// Coverage and test design: the task names criteria, every criterion is
/// served by a part, every part serves only the task's criteria, and
/// every part names the check that proves it.
fn plan_findings(plan: &Plan, criteria: &[Criterion]) -> Vec<PlanFinding> {
    let mut findings = Vec::new();
    if criteria.is_empty() {
        findings.push(PlanFinding::ZeroCriteria);
    }
    findings.extend(
        criteria
            .iter()
            .filter(|criterion| {
                !plan
                    .parts
                    .iter()
                    .any(|part| part.criteria.contains(&criterion.id))
            })
            .map(|criterion| PlanFinding::UncoveredCriterion {
                criterion: criterion.id.clone(),
            }),
    );
    for part in &plan.parts {
        findings.extend(
            part.criteria
                .iter()
                .filter(|id| !criteria.iter().any(|criterion| criterion.id == **id))
                .map(|id| PlanFinding::UnknownCriterion {
                    part: part.id.clone(),
                    criterion: id.clone(),
                }),
        );
        if part.proof.trim().is_empty() {
            findings.push(PlanFinding::MissingProof {
                part: part.id.clone(),
            });
        }
    }
    findings
}

/// Records one assumption result. A setup gap retains its seam evidence
/// in the same transaction and is never reported as a product outcome.
fn test_assumption(
    input: TestAssumptionInput,
    ctx: &mut ActionContext<'_>,
) -> Result<ActionOutcome, ActionError> {
    if !legal_id(&input.check_id) {
        return Err(ActionError::InvalidCheckId);
    }
    if input.assertion.trim().is_empty() || input.assertion.len() > TEXT_MAX_BYTES {
        return Err(ActionError::InvalidAssertion {
            max: TEXT_MAX_BYTES,
        });
    }
    let classification =
        crate::verification::classify_assumption(input.expected_result, input.observation);
    let retained = match classification {
        AssumptionClassification::Confirmed => None,
        AssumptionClassification::ProductDefect => Some(crate::verification::assumption_evidence(
            &input.task_id,
            &input.check_id,
            AssumptionSeam::ProductDefect,
            "product_defect",
        )),
        AssumptionClassification::NotReproduced => Some(crate::verification::assumption_evidence(
            &input.task_id,
            &input.check_id,
            AssumptionSeam::NotReproduced,
            "not_reproduced",
        )),
        AssumptionClassification::SetupGap(cause) => Some(crate::verification::setup_gap_evidence(
            &input.task_id,
            &input.check_id,
            cause,
        )),
    };
    let record = AssumptionCheckRecord {
        session_id: ctx.session_id.clone(),
        task_id: input.task_id,
        check_id: input.check_id,
        expected_result: input.expected_result,
        assertion_digest: crate::config::hex(&sha2::Sha256::digest(input.assertion.as_bytes())),
        observation: input.observation,
        classification,
        boundary_id: retained
            .as_ref()
            .map(|evidence| evidence.boundary_id.clone()),
    };
    ctx.store.record_assumption(&record, retained.as_ref())?;
    Ok(ActionOutcome::AssumptionTested(record))
}

/// Builds one bounded restore request for a recorded setup gap. Admission
/// and execution stay with the executor.
fn prepare_environment(
    input: PrepareEnvironmentInput,
    ctx: &mut ActionContext<'_>,
) -> Result<ActionOutcome, ActionError> {
    if !legal_id(&input.check_id) {
        return Err(ActionError::InvalidCheckId);
    }
    if input.grant_id.trim().is_empty() {
        if let Some(original) =
            ctx.store
                .assumption_check(ctx.session_id, &input.task_id, &input.check_id)?
            && matches!(
                original.classification,
                AssumptionClassification::SetupGap(_)
            )
        {
            let rejection = crate::verification::assumption_evidence(
                &input.task_id,
                &input.check_id,
                AssumptionSeam::PrepareEnvironment,
                "missing_environment_grant",
            );
            ctx.store.retain_attempt(&rejection)?;
        }
        return Err(ActionError::MissingEnvironmentGrant);
    }
    if !input.target.is_absolute()
        || input.target.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(ActionError::InvalidEnvironmentTarget);
    }
    let max = crate::executor::macos::WRITE_MAX_BYTES;
    if input.replacement.len() > max {
        return Err(ActionError::EnvironmentRestoreTooLarge { max });
    }
    let Some(original) =
        ctx.store
            .assumption_check(ctx.session_id, &input.task_id, &input.check_id)?
    else {
        return Err(ActionError::AssumptionNotRecorded);
    };
    if !matches!(
        original.classification,
        AssumptionClassification::SetupGap(_)
    ) {
        return Err(ActionError::EnvironmentNotNeeded);
    }
    Ok(ActionOutcome::EnvironmentRequested {
        restore: EnvironmentRestore {
            grant_id: input.grant_id,
            target: input.target,
            replacement: input.replacement,
        },
        original,
    })
}

// ----- semantic plan legs: Broker purposes named by their action ids -----

/// The broker seam a semantic plan leg dispatches through. Fork
/// authority stays on [`PlanRequest`], the caller's typed action input;
/// the model reply never supplies delegation or author.
#[derive(Debug)]
pub struct BrokerSeam<'a> {
    pub broker: &'a mut Broker,
    /// The execution world the manifest freezes and dispatch re-checks.
    pub world: &'a str,
}

/// One note a semantic reply makes, bound to a surface of the current
/// selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceNote {
    pub surface: Surface,
    pub text: String,
}

/// The `assess_plan` purpose's verdict on a plan revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticVerdict {
    Pass,
    Fail,
}

/// Why a semantic reply closed nothing. The reply is untrusted data: it
/// parses once into its purpose's strict record or it is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SemanticRefusal {
    #[error("reply asked for a tool call; the purpose declares none")]
    ToolCall,
    #[error("reply is empty")]
    Empty,
    #[error("reply exceeds its byte or item bounds")]
    OverLimit,
    #[error("reply is not the purpose's strict record ({} error)", parse_class(*.class))]
    Malformed { class: serde_json::error::Category },
    #[error("reply names surface {} outside the selection", .surface.as_str())]
    ForeignSurface { surface: Surface },
    #[error("reply leaves selected surface {} unanswered", .surface.as_str())]
    MissingSurface { surface: Surface },
}

// The strict reply records. No field names a delegation, an author, a
// plan part, a row or an obligation — a reply carrying one is malformed.

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeReply {
    risks: Vec<SurfaceNote>,
    #[serde(default)]
    fork: Option<ForkReply>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DesignReply {
    contracts: Vec<SurfaceNote>,
    #[serde(default)]
    fork: Option<ForkReply>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssessReply {
    verdict: SemanticVerdict,
    findings: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForkReply {
    prompt: String,
    options: Vec<ForkOption>,
    recommended: String,
    basis: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForkOption {
    id: String,
    label: String,
    consequences: String,
    #[serde(default)]
    disabled_reason: Option<String>,
}

const CHALLENGE_INSTRUCTIONS: &str = "You are the Rivect challenge_direction purpose. From the task, its criteria and its selected surfaces in the inputs, reply with exactly one JSON object {\"risks\":[{\"surface\":<selected surface>,\"text\":<risk>}]} naming every selected risky surface. A material choice the user must make adds \"fork\":{\"prompt\",\"options\":[five {\"id\",\"label\",\"consequences\",\"disabled_reason\"?}],\"recommended\",\"basis\"}. No other field and no tool call.";
const DESIGN_INSTRUCTIONS: &str = "You are the Rivect design_contracts purpose. From the task, its criteria and its selected surfaces in the inputs, reply with exactly one JSON object {\"contracts\":[{\"surface\":<selected surface>,\"text\":<boundary contract>}]} covering every selected risky surface. A material choice the user must make adds \"fork\":{\"prompt\",\"options\":[five {\"id\",\"label\",\"consequences\",\"disabled_reason\"?}],\"recommended\",\"basis\"}. An applied fork answer arrives as fork_answer. No other field and no tool call.";
const ASSESS_INSTRUCTIONS: &str = "You are the Rivect assess_plan purpose. Judge the stored plan revision in the inputs for feasibility, test design and risk against the task criteria and reply with exactly one JSON object {\"verdict\":\"pass\"|\"fail\",\"findings\":[<text>]}. No other field and no tool call.";

/// The plan row a semantic stage's fork waits on, bound to the selection
/// the stage ran on.
struct ForkRow<'a> {
    capability: &'static str,
    selection_revision: u64,
    facts_digest: &'a str,
}

/// Where the stage's own fork stands.
enum ForkState {
    Clear,
    /// The fork's question is still pending: the stage spends nothing.
    Waiting,
    /// The applied answer the next call carries in its inputs.
    Answered(AnswerSelection),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnsweredForkIdentity {
    kind: String,
    question_id: QuestionId,
    question_revision: u64,
    selection_revision: u64,
    facts_digest: String,
}

/// One semantic stage bound to the selection it runs on. It writes only
/// the rows its own handler owns, and only through the one plan-row
/// write, which re-checks the lifecycle and the selection binding.
struct Stage<'r> {
    action: &'static str,
    instructions: &'static str,
    request: &'r PlanRequest,
    bound: Bound,
}

impl Stage<'_> {
    fn update(
        &self,
        ctx: &mut ActionContext<'_>,
        capability: &str,
        change: PlanRowChange,
    ) -> Result<(), ActionError> {
        ctx.store.update_plan_row(
            &self.request.task_id,
            &PlanRowUpdate {
                capability,
                handler: self.action,
                selection_revision: self.bound.selection.revision,
                facts_digest: &self.bound.facts_digest,
                change,
            },
        )?;
        Ok(())
    }

    /// The required rows this handler still owes.
    fn open_rows(&self, ctx: &ActionContext<'_>) -> Result<Vec<PlanObligationRecord>, ActionError> {
        Ok(ctx
            .store
            .plan_obligations(&self.request.task_id)?
            .into_iter()
            .filter(|row| {
                row.handler.as_deref() == Some(self.action)
                    && row.applicability == ObligationApplicability::Required
                    && row.execution != ObligationExecution::Satisfied
            })
            .collect())
    }

    /// Leaves every owed row open on its exact blocker, preserving a
    /// `Decision` only while that question remains pending.
    fn block(&self, ctx: &mut ActionContext<'_>, reason: ErrorCode) -> Result<(), ActionError> {
        for row in self.open_rows(ctx)? {
            let waiting_on_fork = match row.blocker.as_ref().map(|blocker| &blocker.condition) {
                Some(ResumeCondition::Decision {
                    question_id,
                    revision,
                }) => ctx
                    .store
                    .current_question(&self.request.task_id)?
                    .is_some_and(|(question, _)| {
                        question.question_id == *question_id
                            && question.question_revision == *revision
                    }),
                _ => false,
            };
            if !waiting_on_fork {
                let blocker = plan_blocker(reason, &row.capability);
                self.update(ctx, &row.capability, PlanRowChange::Block(blocker))?;
            }
        }
        Ok(())
    }

    fn close(
        &self,
        ctx: &mut ActionContext<'_>,
        execution: ObligationExecution,
        outcome_json: &str,
    ) -> Result<(), ActionError> {
        for row in self.open_rows(ctx)? {
            let close = PlanRowChange::Close {
                execution,
                outcome_json: outcome_json.to_string(),
            };
            self.update(ctx, &row.capability, close)?;
        }
        Ok(())
    }

    fn refuse(
        &self,
        ctx: &mut ActionContext<'_>,
        cause: SemanticRefusal,
    ) -> Result<ActionOutcome, ActionError> {
        self.block(ctx, ErrorCode::DependencyBlocked)?;
        Err(ActionError::SemanticReply {
            action: self.action,
            cause,
        })
    }

    fn fork_state(&self, ctx: &ActionContext<'_>) -> Result<ForkState, ActionError> {
        let task_id = &self.request.task_id;
        let own = ctx
            .store
            .plan_obligations(task_id)?
            .into_iter()
            .find(|row| row.capability == self.action);
        let Some(own) = own else {
            return Ok(ForkState::Clear);
        };
        let blocker_fork = own
            .blocker
            .as_ref()
            .and_then(|blocker| match &blocker.condition {
                ResumeCondition::Decision {
                    question_id,
                    revision,
                } => Some((question_id.clone(), *revision)),
                _ => None,
            });
        if let Some((question_id, revision)) = blocker_fork.as_ref()
            && ctx
                .store
                .current_question(task_id)?
                .is_some_and(|(question, _)| {
                    question.question_id == *question_id && question.question_revision == *revision
                })
        {
            return Ok(ForkState::Waiting);
        }
        let fork = match blocker_fork {
            Some(fork) => Some(fork),
            None => match own.outcome_json.as_deref() {
                Some(encoded) => {
                    let value: serde_json::Value = serde_json::from_str(encoded)?;
                    if value.get("kind").and_then(serde_json::Value::as_str)
                        == Some("answered_fork")
                    {
                        let identity: AnsweredForkIdentity = serde_json::from_value(value)?;
                        if identity.kind.as_str() != "answered_fork"
                            || identity.selection_revision != self.bound.selection.revision
                            || identity.facts_digest.as_str() != self.bound.facts_digest.as_str()
                        {
                            return Ok(ForkState::Clear);
                        }
                        Some((identity.question_id, identity.question_revision))
                    } else {
                        None
                    }
                }
                None => None,
            },
        };
        let Some((question_id, revision)) = fork else {
            return Ok(ForkState::Clear);
        };
        if let Some(applied) =
            ctx.store
                .answer_attempts(task_id)?
                .into_iter()
                .rev()
                .find(|attempt| {
                    attempt.question_id == question_id
                        && attempt.question_revision == revision
                        && attempt.outcome == AnswerAttemptOutcome::Applied
                })
        {
            return Ok(ForkState::Answered(applied.selection));
        }
        let pending = ctx
            .store
            .current_question(task_id)?
            .is_some_and(|(question, _)| {
                question.question_id == question_id && question.question_revision == revision
            });
        Ok(if pending {
            ForkState::Waiting
        } else {
            ForkState::Clear
        })
    }

    /// The manifest inputs: the task and the current selection, the
    /// stored plan revision the stage judges and the applied fork answer.
    /// A terminal task spends no model call.
    fn inputs(
        &self,
        ctx: &ActionContext<'_>,
        answer: Option<&AnswerSelection>,
        plan: Option<&PlanRevisionRecord>,
    ) -> Result<String, ActionError> {
        let task_id = &self.request.task_id;
        let snapshot = ctx.store.snapshot(task_id)?;
        if snapshot.lifecycle.is_terminal() {
            return Err(StoreError::AlreadyTerminal.into());
        }
        let goal = ctx.store.goal_bytes(task_id)?;
        let surfaces: Vec<Surface> = self
            .request
            .surfaces
            .decided()
            .map(|surfaces| surfaces.iter().copied().collect())
            .unwrap_or_default();
        let plan = match plan {
            Some(plan) => Some(serde_json::json!({
                "revision": plan.revision,
                "body": serde_json::from_str::<serde_json::Value>(&plan.body_json)?,
                "mechanical": plan
                    .assessment_json
                    .as_deref()
                    .map(serde_json::from_str::<serde_json::Value>)
                    .transpose()?,
            })),
            None => None,
        };
        Ok(serde_json::json!({
            "action": self.action,
            "task_id": task_id.0,
            "goal": String::from_utf8_lossy(&goal),
            "criteria": snapshot.criteria.items,
            "selection_revision": self.bound.selection.revision,
            "facts_digest": self.bound.facts_digest,
            "surfaces": surfaces,
            "plan": plan,
            "fork_answer": answer,
        })
        .to_string())
    }

    /// One Broker call under the stage's purpose. Every outcome but a
    /// reply ends its attempt — a pending manual-fallback choice and its
    /// pause pin die with it and no question is published: that pause is
    /// the controller's — and leaves the owed rows on
    /// `capability_unavailable`.
    fn call(
        &self,
        ctx: &mut ActionContext<'_>,
        seam: &mut BrokerSeam<'_>,
        inputs: &str,
    ) -> Result<(String, ProviderReply), ActionError> {
        let contract = CallContract {
            instructions: self.instructions,
            tools: &[],
        };
        let sent =
            match seam
                .broker
                .prepare_call(self.action, ctx.config, seam.world, inputs, &contract)
            {
                Ok(manifest) => match seam.broker.dispatch(seam.world, &manifest) {
                    Ok(reply) => Ok((manifest.attempt_id, reply)),
                    Err(source) => {
                        seam.broker.cancel_attempt(&manifest.attempt_id);
                        Err(source)
                    }
                },
                Err(source) => Err(source),
            };
        match sent {
            Ok(sent) => Ok(sent),
            Err(source) => {
                self.block(ctx, ErrorCode::CapabilityUnavailable)?;
                Err(ActionError::SemanticDispatch {
                    action: self.action,
                    source: Box::new(source),
                })
            }
        }
    }
}

impl ActionRegistry {
    /// `challenge_direction` or `design_contracts` through its Broker
    /// purpose. The row closes only on a strict reply bound to the
    /// selection's surfaces; a material choice in the reply becomes one
    /// `resolve_decision` fork the row then waits on, and only the next
    /// invocation — carrying the applied answer — can close it.
    fn semantic_stage(
        &self,
        action: &'static str,
        request: &PlanRequest,
        ctx: &mut ActionContext<'_>,
        seam: &mut BrokerSeam<'_>,
    ) -> Result<ActionOutcome, ActionError> {
        let challenge = action == CHALLENGE_DIRECTION;
        let stage = Stage {
            action,
            instructions: if challenge {
                CHALLENGE_INSTRUCTIONS
            } else {
                DESIGN_INSTRUCTIONS
            },
            request,
            bound: bind(request, ctx)?,
        };
        match row_state(request, action, ctx)? {
            RowState::Absent(reason) => return Ok(skip(action, reason)),
            RowState::Unresolved => return Ok(skip(action, SkipReason::NeedsInformation)),
            RowState::Open(ObligationExecution::Satisfied) => {
                return Ok(skip(action, SkipReason::AlreadySatisfied));
            }
            RowState::Open(_) => {}
        }
        let answer = match stage.fork_state(ctx)? {
            ForkState::Waiting => return Ok(skip(action, SkipReason::NeedsInformation)),
            ForkState::Answered(selection) => Some(selection),
            ForkState::Clear => None,
        };
        let inputs = stage.inputs(ctx, answer.as_ref(), None)?;
        let (attempt_id, reply) = stage.call(ctx, seam, &inputs)?;
        let parsed = if challenge {
            read_reply::<ChallengeReply>(&reply).map(|reply| (reply.risks, reply.fork))
        } else {
            read_reply::<DesignReply>(&reply).map(|reply| (reply.contracts, reply.fork))
        };
        let (notes, fork) = match parsed
            .and_then(|(notes, fork)| check_notes(&notes, request).map(|()| (notes, fork)))
        {
            Ok(checked) => checked,
            Err(cause) => return stage.refuse(ctx, cause),
        };
        if let Some(fork) = fork {
            return self.fork_stage(&stage, fork, ctx);
        }
        let outcome_json =
            serde_json::json!({ "attempt_id": attempt_id, "notes": notes }).to_string();
        stage.close(ctx, ObligationExecution::Satisfied, &outcome_json)?;
        Ok(if challenge {
            ActionOutcome::Challenged { risks: notes }
        } else {
            ActionOutcome::Designed { contracts: notes }
        })
    }

    /// Routes a reply's material choice through `resolve_decision`, with
    /// delegation and author read only from the caller's `PlanRequest`.
    /// Any refusal leaves the owed rows open on the exact blocker.
    fn fork_stage(
        &self,
        stage: &Stage<'_>,
        fork: ForkReply,
        ctx: &mut ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionError> {
        let input = ResolveDecisionInput {
            task_id: stage.request.task_id.clone(),
            prompt: fork.prompt,
            options: fork
                .options
                .into_iter()
                .map(|option| QuestionOption {
                    option_id: OptionId(option.id),
                    label: option.label,
                    consequences: option.consequences,
                    availability: match option.disabled_reason {
                        Some(reason) => Availability::Disabled { reason },
                        None => Availability::Enabled,
                    },
                })
                .collect(),
            recommended_option_id: OptionId(fork.recommended),
            recommendation_basis: fork.basis,
            delegation: stage.request.delegation.clone(),
            author: stage.request.author,
        };
        let row = ForkRow {
            capability: stage.action,
            selection_revision: stage.bound.selection.revision,
            facts_digest: &stage.bound.facts_digest,
        };
        match self.dispatch(ActionInput::ResolveDecision(input), ctx, None, Some(&row)) {
            Ok(resolution) => Ok(ActionOutcome::Forked {
                action: stage.action,
                resolution: Box::new(resolution),
            }),
            Err(error) => {
                stage.block(ctx, ErrorCode::DependencyBlocked)?;
                Err(error)
            }
        }
    }
}

/// The semantic leg of `assess_plan`: the mechanical leg judges first,
/// and only a revision it passed reaches the purpose, whose verdict then
/// closes the rows the assessor owns.
fn judge_plan(
    request: &PlanRequest,
    ctx: &mut ActionContext<'_>,
    seam: &mut BrokerSeam<'_>,
) -> Result<ActionOutcome, ActionError> {
    let stage = Stage {
        action: ASSESS_PLAN,
        instructions: ASSESS_INSTRUCTIONS,
        request,
        bound: bind(request, ctx)?,
    };
    match row_state(request, ASSESS_PLAN, ctx)? {
        RowState::Absent(reason) => return Ok(skip(ASSESS_PLAN, reason)),
        RowState::Unresolved => return Ok(skip(ASSESS_PLAN, SkipReason::NeedsInformation)),
        RowState::Open(ObligationExecution::Satisfied) => {
            return Ok(skip(ASSESS_PLAN, SkipReason::AlreadySatisfied));
        }
        // A judged failure waits for a new revision: the mechanical
        // leg's typed refusal says so.
        RowState::Open(ObligationExecution::Failed) => return assess_plan(request, ctx),
        RowState::Open(_) => {}
    }
    let revision = stage.bound.selection.revision;
    let Some(latest) = latest_revision(ctx, request, revision)? else {
        return Ok(skip(ASSESS_PLAN, SkipReason::NeedsInformation));
    };
    let latest = match latest.verdict {
        Some(PlanVerdict::Pass) => latest,
        Some(PlanVerdict::Fail) => return assess_plan(request, ctx),
        None => {
            let mechanical = assess_plan(request, ctx)?;
            if !matches!(&mechanical, ActionOutcome::Assessed(assessment) if assessment.verdict == PlanVerdict::Pass)
            {
                return Ok(mechanical);
            }
            latest_revision(ctx, request, revision)?.ok_or(StoreError::Conflict(
                ConflictCause::PlanNotAssessable {
                    revision: latest.revision,
                },
            ))?
        }
    };
    let inputs = stage.inputs(ctx, None, Some(&latest))?;
    let (attempt_id, reply) = stage.call(ctx, seam, &inputs)?;
    let judged = match read_reply::<AssessReply>(&reply)
        .and_then(|judged| check_findings(&judged.findings).map(|()| judged))
    {
        Ok(judged) => judged,
        Err(cause) => return stage.refuse(ctx, cause),
    };
    let outcome_json = serde_json::json!({
        "attempt_id": attempt_id,
        "plan_revision": latest.revision,
        "verdict": judged.verdict,
        "findings": judged.findings,
    })
    .to_string();
    match judged.verdict {
        SemanticVerdict::Pass => stage.close(ctx, ObligationExecution::Satisfied, &outcome_json)?,
        SemanticVerdict::Fail => {
            stage.close(ctx, ObligationExecution::Failed, &outcome_json)?;
            stage.block(ctx, ErrorCode::DependencyBlocked)?;
        }
    }
    Ok(ActionOutcome::Judged {
        plan_revision: latest.revision,
        verdict: judged.verdict,
        findings: judged.findings,
    })
}

fn latest_revision(
    ctx: &ActionContext<'_>,
    request: &PlanRequest,
    selection_revision: u64,
) -> Result<Option<PlanRevisionRecord>, ActionError> {
    Ok(ctx
        .store
        .plan_revisions(&request.task_id)?
        .into_iter()
        .rev()
        .find(|plan| plan.selection_revision == selection_revision))
}

/// Parses a reply once into its strict record: no tool call, bounded
/// text, no field outside the record.
fn read_reply<T: serde::de::DeserializeOwned>(reply: &ProviderReply) -> Result<T, SemanticRefusal> {
    if !reply.tool_calls.is_empty() {
        return Err(SemanticRefusal::ToolCall);
    }
    if reply.text.len() > TEXT_MAX_BYTES {
        return Err(SemanticRefusal::OverLimit);
    }
    let text = reply.text.trim();
    if text.is_empty() {
        return Err(SemanticRefusal::Empty);
    }
    serde_json::from_str(text).map_err(|error| SemanticRefusal::Malformed {
        class: error.classify(),
    })
}

/// A parse error's class, without the reply bytes its message may echo.
fn parse_class(class: serde_json::error::Category) -> &'static str {
    match class {
        serde_json::error::Category::Io => "io",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "schema",
        serde_json::error::Category::Eof => "truncation",
    }
}

/// Every note names a surface of the current selection, and every
/// selected risky surface is answered.
fn check_notes(notes: &[SurfaceNote], request: &PlanRequest) -> Result<(), SemanticRefusal> {
    if notes.len() > ARRAY_MAX_ITEMS {
        return Err(SemanticRefusal::OverLimit);
    }
    let selected = request.surfaces.decided();
    for note in notes {
        if note.text.trim().is_empty() {
            return Err(SemanticRefusal::Empty);
        }
        if !selected.is_some_and(|surfaces| surfaces.contains(&note.surface)) {
            return Err(SemanticRefusal::ForeignSurface {
                surface: note.surface,
            });
        }
    }
    let missing = selected
        .into_iter()
        .flatten()
        .find(|surface| surface.is_risk() && !notes.iter().any(|note| note.surface == **surface));
    match missing {
        Some(surface) => Err(SemanticRefusal::MissingSurface { surface: *surface }),
        None => Ok(()),
    }
}

fn check_findings(findings: &[String]) -> Result<(), SemanticRefusal> {
    if findings.len() > ARRAY_MAX_ITEMS {
        return Err(SemanticRefusal::OverLimit);
    }
    if findings.iter().any(|finding| finding.trim().is_empty()) {
        return Err(SemanticRefusal::Empty);
    }
    Ok(())
}

fn plan_definitions() -> [ActionDefinition; 5] {
    [
        ActionDefinition {
            id: FRAME_GOAL,
            revision: 1,
            trigger: "a new request, a changed intent, or a result contract no approved basis covers",
            negative_trigger: "not for a request an approved contract already frames — and never a rewrite of the user's own words",
            outcome: "the task's addressable criteria, constraints and open unknowns, read from the store",
            implementation: Implementation::Local,
        },
        ActionDefinition {
            id: CHALLENGE_DIRECTION,
            revision: 1,
            trigger: "the work touches a risky surface without an approved contract",
            negative_trigger: "not for a known local change or an approved direction — never a license to shrink the request",
            outcome: "checked risks from the challenge_direction Broker purpose; without a broker seam the row stays open on capability_unavailable",
            implementation: Implementation::Purpose,
        },
        ActionDefinition {
            id: DESIGN_CONTRACTS,
            revision: 1,
            trigger: "a new or changed boundary on a risky surface without an approved contract",
            negative_trigger: "no decorative design for a known local edit or an already approved contract",
            outcome: "boundary contracts from the design_contracts Broker purpose; without a broker seam the row stays open on capability_unavailable",
            implementation: Implementation::Purpose,
        },
        ActionDefinition {
            id: PLAN_WORK,
            revision: 1,
            trigger: "a requested plan, dependent parts, several parts, or a risky surface that needs coordination",
            negative_trigger: "not for a single local part — and never a file list standing in for a plan",
            outcome: "one plan revision under the current selection: parts linked to criteria in the order their dependencies allow",
            implementation: Implementation::Local,
        },
        ActionDefinition {
            id: ASSESS_PLAN,
            revision: 1,
            trigger: "a plan revision of the current selection without a verdict",
            negative_trigger: "not when no plan exists or the latest revision is already judged — plan existence is never the verdict",
            outcome: "a mechanical coverage and test-design verdict bound to the revision; a pass also needs the assess_plan Broker purpose's semantic leg",
            implementation: Implementation::LocalAndPurpose,
        },
    ]
}

/// Publishes the fork — or, when the identical fork is already pending,
/// serves the live question instead of minting a second one. The store
/// admits `publish_question` only on a running task, so the dedupe reads
/// the pending row first: a repeat invocation while the task waits on
/// its question returns that question, a different pending fork
/// conflicts through the store's own vocabulary — one versioned
/// question per material fork, never a shadow queue.
fn publish_or_dedupe(
    ctx: &mut ActionContext<'_>,
    question: &Question,
    row: Option<&ForkRow<'_>>,
) -> Result<(Question, TaskSnapshot), ActionError> {
    if let Some((pending, _)) = ctx.store.current_question(&question.task_id)? {
        if !same_fork(&pending, question) {
            return Err(StoreError::Conflict(ConflictCause::PendingQuestionExists).into());
        }
        if let Some(row) = row
            && !plan_row_waits_for_question(ctx, row.capability, &pending)?
        {
            return Err(StoreError::Conflict(ConflictCause::PendingQuestionExists).into());
        }
        let snapshot = ctx.store.snapshot(&question.task_id)?;
        return Ok((pending, snapshot));
    }
    let snapshot = match row {
        None => ctx.store.publish_question(ctx.session_id, question)?,
        Some(row) => ctx.store.publish_plan_fork(
            ctx.session_id,
            question,
            &PlanRowUpdate {
                capability: row.capability,
                handler: row.capability,
                selection_revision: row.selection_revision,
                facts_digest: row.facts_digest,
                change: PlanRowChange::Block(Blocker {
                    reason: ErrorCode::DependencyBlocked,
                    owner: PLAN_BLOCKER_OWNER.to_string(),
                    condition: ResumeCondition::Decision {
                        question_id: question.question_id.clone(),
                        revision: question.question_revision,
                    },
                }),
            },
        )?,
    };
    Ok((question.clone(), snapshot))
}

/// A pending question can be reused only while this selection's handler
/// row still records that exact `Decision`; re-selection drops the old
/// fork before an answer can be consumed by the new facts.
fn plan_row_waits_for_question(
    ctx: &ActionContext<'_>,
    capability: &str,
    question: &Question,
) -> Result<bool, ActionError> {
    Ok(ctx
        .store
        .plan_obligations(&question.task_id)?
        .iter()
        .any(|row| {
            row.capability == capability
                && row.blocker.as_ref().is_some_and(|blocker| {
                    matches!(
                        &blocker.condition,
                        ResumeCondition::Decision { question_id, revision }
                            if question_id == &question.question_id
                                && *revision == question.question_revision
                    )
                })
        }))
}

/// Fork identity for dedupe: the frozen fields a repeat invocation must
/// reproduce — prompt, positions, recommendation — not the question id
/// the first publish minted.
fn same_fork(pending: &Question, question: &Question) -> bool {
    pending.prompt == question.prompt
        && pending.options == question.options
        && pending.recommended_option_id == question.recommended_option_id
        && pending.recommendation_basis == question.recommendation_basis
}

/// The fork's own contract: exactly five positions, legal unique ids, a
/// reason on every disabled position, and a recommendation that names an
/// enabled position with a non-empty basis. A fork that cannot meet this
/// is rejected before it ever reaches the store.
fn validate_fork(input: &ResolveDecisionInput) -> Result<(), ActionError> {
    if input.prompt.trim().is_empty() {
        return Err(ActionError::EmptyPrompt);
    }
    if input.prompt.len() > TEXT_MAX_BYTES {
        return Err(ActionError::PromptTooLarge {
            max: TEXT_MAX_BYTES,
        });
    }
    if input.options.len() != DECISION_OPTION_SLOTS {
        return Err(ActionError::OptionSlots {
            expected: DECISION_OPTION_SLOTS,
            actual: input.options.len(),
        });
    }
    let mut seen = BTreeSet::new();
    let mut recommended_enabled = false;
    for option in &input.options {
        let raw = &option.option_id.0;
        if !legal_id(raw) {
            return Err(ActionError::InvalidOptionId {
                option_id: raw.clone(),
            });
        }
        if !seen.insert(raw.clone()) {
            return Err(ActionError::DuplicateOptionId {
                option_id: raw.clone(),
            });
        }
        if let Availability::Disabled { reason } = &option.availability
            && reason.trim().is_empty()
        {
            return Err(ActionError::DisabledWithoutReason {
                option_id: raw.clone(),
            });
        }
        if option.option_id == input.recommended_option_id
            && matches!(option.availability, Availability::Enabled)
        {
            recommended_enabled = true;
        }
    }
    if !recommended_enabled {
        return Err(ActionError::RecommendationNotSelectable {
            option_id: input.recommended_option_id.0.clone(),
        });
    }
    if input.recommendation_basis.trim().is_empty() {
        return Err(ActionError::EmptyBasis);
    }
    Ok(())
}

/// Nominal ids for option and plan parts: non-empty ASCII
/// `[A-Za-z0-9._-]` within 64 bytes.
fn legal_id(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 64
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn inspect_failure(
        close_store: bool,
    ) -> Result<
        (tempfile::TempDir, Result<ActionOutcome, ActionError>),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir()?;
        let helper = root.path().join("nonexecutable-helper");
        std::fs::write(&helper, b"not executable\n")?;
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o600))?;
        let mut store = TaskStore::open(&root.path().join("state.db"))?;
        let (session, _, _, _) = store.open_session("owned-inspection", "unit", None)?;
        let config = Config::parse_validated(&format!(
            "{}\n[connections.primary]\nkind = \"api_key\"\nendpoint = \"https://api.openai.com/v1\"\ncredential_ref = \"keyring:primary\"\n",
            crate::config::SHIPPED_DEFAULTS_TOML
        ))?;
        let index = crate::commands::IndexSeam {
            root: root.path().to_path_buf(),
            watch_refusal: None,
            worker: crate::commands::IndexWorker {
                helper,
                program: root.path().join("unused-program"),
            },
        };
        if close_store {
            store.close()?;
        }
        let mut context = ActionContext {
            store: &mut store,
            session_id: &session,
            config: &config,
            index: &index,
        };
        let outcome = ActionRegistry::new().execute(
            ActionInput::InspectSystem(InspectSystemInput::default()),
            &mut context,
        );
        Ok((root, outcome))
    }

    fn assert_original_eacces(error: &(dyn std::error::Error + 'static)) {
        let mut next = Some(error);
        let mut worker = false;
        let mut errno = None;
        while let Some(source) = next {
            worker |= source
                .downcast_ref::<crate::executor::WorkerError>()
                .is_some();
            if let Some(source) = source.downcast_ref::<std::io::Error>() {
                errno = source.raw_os_error();
            }
            next = source.source();
        }
        assert!(worker, "the original worker failure must survive");
        assert_eq!(errno, Some(13), "the original errno must survive");
    }

    #[test]
    fn owned_launch_inspection_retains_primary_across_projection_clone_and_drop() -> TestResult {
        let (_root, outcome) = inspect_failure(false)?;
        let report = match outcome? {
            ActionOutcome::Inspected(report) => Some(report),
            _ => None,
        }
        .expect("inspection must return its report");
        let original = report
            .probe_error()
            .expect("the report owns the actual probe failure");
        assert_original_eacces(original);
        let diagnostic_lifetime =
            Arc::downgrade(report.probe_error.as_ref().expect("private owner"));
        let ordinary = BoundaryReport::new(
            report.systems.clone(),
            report.detected.clone(),
            report.freshness,
            report.residual_risk.clone(),
            report.watch_refusal.clone(),
        );
        assert!(ordinary.probe_error().is_none());
        assert_eq!(
            *report, ordinary,
            "equality compares the five ordinary fields"
        );
        let clone = report.clone();
        assert!(std::ptr::eq(
            original,
            clone.probe_error().expect("clone owns the same original")
        ));
        assert_eq!(report, clone);
        let wire = serde_json::to_value(&report)?;
        assert!(wire.get("probe_error").is_none());
        assert_eq!(wire.as_object().expect("report object").len(), 5);
        assert_eq!(wire, serde_json::to_value(&ordinary)?);
        assert!(!format!("{report:?}").contains("nonexecutable-helper"));
        drop(report);
        assert_original_eacces(clone.probe_error().expect("clone keeps the original alive"));
        assert!(diagnostic_lifetime.upgrade().is_some());
        drop(clone);
        assert!(
            diagnostic_lifetime.upgrade().is_none(),
            "the last report releases diagnostic memory"
        );
        Ok(())
    }

    #[test]
    fn owned_launch_inspection_freshness_keeps_primary_and_store_failure() -> TestResult {
        let (_root, outcome) = inspect_failure(true)?;
        let error = outcome.expect_err("the closed store cannot answer freshness");
        assert_eq!(error.error_code(), ErrorCode::StorageUnavailable);
        assert_original_eacces(&error);
        assert!(matches!(
            error,
            ActionError::InspectionFreshnessFailed {
                secondary: StoreError::Closed,
                ..
            }
        ));
        Ok(())
    }
}

/// The in-crate twins of the closed-surface doctests: the same
/// expressions over `crate::` paths must compile, so each doctest's
/// failure is attributable to visibility only.
#[cfg(test)]
mod closed_surface_twins {
    use super::ActionContext;
    use crate::commands::{IndexSeam, Runtime};
    use crate::config::Config;
    use crate::contracts::SessionId;
    use crate::state::TaskStore;

    fn store_field(rt: &mut Runtime, session: &SessionId, config: &Config) {
        let ctx = rt.action_context(session, config);
        let _s = ctx.store;
    }

    fn literal(store: &mut TaskStore, session: &SessionId, config: &Config, index: &IndexSeam) {
        let _ctx = ActionContext {
            store,
            session_id: session,
            config,
            index,
        };
    }

    fn constructor(store: &mut TaskStore, session: &SessionId, config: &Config, index: &IndexSeam) {
        let _ctx = ActionContext::new(store, session, config, index);
    }

    #[test]
    fn the_closed_action_context_items_are_reachable_inside_the_crate() {
        let _: fn(&mut Runtime, &SessionId, &Config) = store_field;
        let _: fn(&mut TaskStore, &SessionId, &Config, &IndexSeam) = literal;
        let _: fn(&mut TaskStore, &SessionId, &Config, &IndexSeam) = constructor;
    }
}
