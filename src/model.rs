//! Model broker: immutable request manifests and owner-brokered dispatch.
//! The manifest is frozen at prepare time; later config changes never
//! rewrite an in-flight request. Every physical request passes one
//! eligibility gate before ranking and one admission re-check before
//! the send, and is accounted exactly once.

use crate::actions::Surface;
use crate::config::{
    Config, ConfigError, ConnKind, Connection, EffortAssign, EffortLevel, FallbackAssign,
    FixedModel, ModelAssign, Profile, PurposeDef,
};
use crate::instructions::{InstructionConflict, InstructionError, InstructionSet};
use crate::learning::LearningDefinition;
use crate::providers::{self, CatalogModel, Dialect, Provider, ProviderError, ProviderReply};
use crate::resources::UsageDelta;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestManifest {
    pub attempt_id: String,
    pub purpose: String,
    /// The execution world the request's sources and proofs belong to
    /// (AC-013): frozen at prepare, re-checked at dispatch — a manifest
    /// from one world is never sent from another.
    pub world: String,
    pub model: ModelAssign,
    pub effort: EffortAssign,
    /// Mandatory wire parts (AC-013): the system instructions, the
    /// declared tool surface and the output reserve. A request that
    /// does not fit together with them is rejected — they are never
    /// dropped or truncated to make room.
    pub instructions: String,
    pub tools: Vec<String>,
    pub output_reserve: usize,
    pub inputs: String,
    pub inputs_digest: String,
    /// The context epoch of the model-visible prefix (AC-061
    /// contribution): an unchanged prefix replays the same epoch
    /// bytewise; a prefix mutation opens a new epoch carrying the
    /// recorded reason.
    pub epoch_id: String,
    pub mutation_reason: Option<String>,
    /// What the epoch mutation is expected to cost at the provider cache
    /// (AC-061): which envelope part it replaced and how many envelope
    /// bytes the next request rewrites instead of replaying. `None` while
    /// the epoch replays, and for a non-prefix event like a compaction.
    pub epoch_cost: Option<EpochCost>,
    /// Who authored the bytes this request carries in the wire's user
    /// channel (AC-009, INV-003). The marker is client-side: no provider
    /// protocol carries an author, so it never enters
    /// [`RequestManifest::wire_bytes`] — it exists so a consent path asks
    /// the frozen request for its author instead of reading the text.
    pub input_origin: InputOrigin,
    /// The frozen admission bound of this request (INV-022): the
    /// `bound(next)` a budget level must fit beside its spent and
    /// reserved units before the dispatch may send.
    pub cost_bound: u64,
}

/// The author of the bytes a request carries as its user channel
/// (AC-009): text that arrived as a tool output, an effect observation, a
/// folded summary or a model-authored turn is data the platform carried,
/// never a human turn — it can move no intent, policy or grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputOrigin {
    /// A trusted CLI/TUI operator turn: the only origin consent may read
    /// as human authorship.
    Human,
    /// Platform text — a tool output, an observation, a summary or a
    /// model-authored answer. Data, never authorship.
    Tool,
}

impl RequestManifest {
    /// The exact bytes the provider receives (AC-013): mandatory
    /// instructions, declared tools, the output-reserve marker, then the
    /// frozen inputs. This composition is the wire request — the
    /// provider never sees anything not frozen on the manifest.
    #[must_use]
    pub fn wire_bytes(&self) -> String {
        wire_composition(
            &self.instructions,
            &self.model,
            &self.tools,
            self.output_reserve,
            &self.inputs,
        )
    }
}

/// The transmitted/confirmed distinction for one effort assignment
/// (EDGE-006, AC-043): the frozen wire request carries the resolved
/// effort verbatim — a value no layer supports is a typed rejection on
/// both config carriers, never a silent drop — while only provider
/// data can confirm the level actually applied. The offline loopback
/// reports none, so `confirmed` stays `None` and a transmitted
/// assignment is never called confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffortExplain {
    pub transmitted: EffortAssign,
    pub confirmed: Option<EffortLevel>,
}

/// The bound-versus-confirmed distinction for one sent request
/// (EDGE-008, INV-022): the frozen manifest carries the admission
/// bound, and only provider usage data can confirm the units actually
/// consumed. The offline loopback reports none, so `confirmed` stays
/// `None` and an unknown sent cost is retained at the bound — never
/// released as zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentCostExplain {
    pub bound: u64,
    pub confirmed: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("model configuration: {0}")]
    Config(#[from] ConfigError),
    #[error("model provider: {0}")]
    Provider(#[from] ProviderError),
    #[error("instruction discovery: {0}")]
    Instructions(#[from] InstructionError),
    #[error(
        "model request exceeds wire limit: accounted {actual} bytes with mandatory instructions, tools and output reserve exceeds {limit}"
    )]
    RequestTooLarge { limit: usize, actual: usize },
    #[error("dispatch world mismatch: manifest froze {frozen}, dispatch attempted from {current}")]
    WorldMismatch { frozen: String, current: String },
    #[error(
        "no eligible connection for purpose {purpose}: every candidate failed eligibility before ranking{}",
        rejected_text(.rejected.as_slice())
    )]
    NoEligibleCandidate {
        purpose: String,
        /// Every candidate the ranking refused, in pool order; an
        /// inherit resolves no candidates and refuses none.
        rejected: Vec<CandidateRejection>,
    },
    #[error(
        "dispatch blocked for attempt {attempt_id}: eligibility snapshot changed since ranking (connection {connection} admitted at version {frozen}, current version {current})"
    )]
    EligibilityStale {
        attempt_id: String,
        connection: String,
        frozen: u64,
        current: u64,
    },
    #[error(
        "dispatch rejected for attempt {attempt_id}: no admission record for the manifest in this broker"
    )]
    NoAdmission { attempt_id: String },
    #[error(
        "dispatch rejected for attempt {attempt_id}: presented manifest does not match the admitted one"
    )]
    AdmissionMismatch { attempt_id: String },
    #[error("attempt {attempt_id} already accounted: one physical request per attempt id")]
    AttemptAlreadyAccounted { attempt_id: String },
    #[error(
        "attempt {attempt_id} was cancelled; a late retry or provider callback never resurrects it"
    )]
    AttemptCancelled { attempt_id: String },
    /// The frozen bound no longer fits an open budget scope: the attempt
    /// never entered a send, and the controller records the waiting reason
    /// instead of retrying in a loop.
    #[error("dispatch waits for budget at scope {scope}")]
    BudgetExhausted { scope: String },
    /// The settlement ledger refused at the send boundary. A refusal before
    /// the row opens records nothing; a close refusal leaves the opened row
    /// for the reopen to reconcile.
    #[error("settlement ledger: {0}")]
    Ledger(#[from] LedgerError),
    // These two Displays carry the purpose but never the attempt id:
    // a retried step mints a fresh attempt each time, and the
    // supervisor's exact-repeat fingerprint needs equivalent failures
    // to read identically.
    #[error("manual fallback for purpose {purpose} awaits the pending choice on question.current")]
    ManualFallbackPending { attempt_id: String, purpose: String },
    #[error("no pending manual fallback choice is recorded for this attempt")]
    NoPendingChoice { attempt_id: String },
    #[error("manual fallback choice {connection} rejected: {cause}")]
    ManualChoiceRejected {
        attempt_id: String,
        connection: String,
        cause: RejectionCause,
    },
    #[error(
        "fallback for purpose {purpose} exhausted{}{}: {source}",
        rejected_text(.rejected.as_slice()),
        attempted_text(.attempted.as_slice())
    )]
    FallbackExhausted {
        attempt_id: String,
        purpose: String,
        /// Every chain entry the walk skipped or saw fail, in order.
        rejected: Vec<CandidateRejection>,
        /// The chain connections that actually received a send.
        attempted: Vec<String>,
        #[source]
        source: Box<ProviderError>,
    },
}

/// Why one fallback candidate was refused at send time (AC-045b): the
/// dispatch-time re-check runs the same catalogue, egress, entitlement
/// and purpose-eligibility gates the ranking ran at prepare, a
/// candidate failing any of them never receives the request, and a
/// manual pick is additionally confined to the candidates the recorded
/// pause served.
/// `SendFailed` carries `ProviderError` inline so a send failure keeps
/// its typed cause; the sibling variants stay tag-sized.
#[derive(Debug, Clone)]
pub enum RejectionCause {
    UnknownConnection,
    LiveGrantRequired {
        kind: ConnKind,
    },
    NotEntitled,
    NotPurposeEligible,
    /// The pick was never among the candidates the recorded pause
    /// served — the broker never widens the question's offer.
    NotOffered,
    /// The candidate's source class passed eligibility but no adapter
    /// the broker holds speaks its dialect — the send seam fails
    /// closed rather than fabricating a reply.
    DialectMismatch,
    /// The candidate's id is reserved to a recorded dialect and no
    /// installed adapter serves that dialect in this build — a
    /// build-truth denial, not an adapter declining an offered id.
    DialectUnserved {
        dialect: Dialect,
    },
    /// The candidate passed the re-check but its own send failed.
    SendFailed(ProviderError),
    /// The candidate resolves to the same recorded contract as the failed
    /// primary or an already-attempted chain entry, and that contract
    /// forbids re-dispatching a failed send onto a sibling literal: a
    /// failed send is never retried blindly (PROH-020). The text stays
    /// accurate for a denial that lands before any byte crossed.
    BlindRetryRefused,
}

impl std::fmt::Display for RejectionCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownConnection => f.write_str("connection no longer declared"),
            Self::LiveGrantRequired { kind } => {
                write!(f, "{kind} connection requires a separate live grant")
            }
            Self::NotEntitled => f.write_str("outside the account entitlement"),
            Self::NotPurposeEligible => f.write_str("outside the purpose's eligible list"),
            Self::NotOffered => f.write_str("not among the candidates the pending choice served"),
            Self::DialectMismatch => f.write_str("no adapter serves this connection's dialect"),
            Self::DialectUnserved { dialect } => write!(
                f,
                "reserved for dialect {dialect}; no installed adapter serves it in this build"
            ),
            Self::SendFailed(source) => write!(f, "send failed: {source}"),
            Self::BlindRetryRefused => {
                f.write_str("same recorded contract; a failed send is never retried blindly")
            }
        }
    }
}

/// One skipped fallback chain entry with its typed cause.
#[derive(Debug, Clone)]
pub struct CandidateRejection {
    pub connection: String,
    pub cause: RejectionCause,
}

/// `connection: cause` pairs in chain order for the refusal list an
/// exhaustion carries — every cause is typed, so the rendered text can
/// never embed secret material (INV-006). An empty list renders nothing.
fn rejected_text(rejected: &[CandidateRejection]) -> String {
    if rejected.is_empty() {
        return String::new();
    }
    format!(
        "; rejected {}",
        rejected
            .iter()
            .map(|rejection| format!("{}: {}", rejection.connection, rejection.cause))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// The connections that received a send before the chain exhausted;
/// absent when no candidate was attempted.
fn attempted_text(attempted: &[String]) -> String {
    if attempted.is_empty() {
        return String::new();
    }
    format!("; attempted {}", attempted.join(", "))
}

/// A recorded manual-fallback choice (AC-045, DEC-014): the failed
/// attempt stays admitted while the choice is pending — the existing
/// question.current protocol carries it to the human — and the broker
/// never dispatches a substitute on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingFallback {
    pub attempt_id: String,
    pub purpose: String,
    /// The connections passing the current eligibility check, sorted.
    pub candidates: Vec<String>,
    /// The primary failure's classifier verdict: an unknown outcome (a
    /// timeout, a 5xx, a retried leg) may already have applied remotely,
    /// so a substitute send repeats it; `false` means the denial was
    /// definitive and provably never applied.
    pub unknown_outcome: bool,
}

/// The credential profile the latest prepared manifest froze on its
/// bound connection (AC-047): the `active` half of the status surface's
/// pending/active pair — `pending` is the profile the next dispatch on
/// that connection binds under the current config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileBinding {
    pub connection: String,
    pub profile: Option<String>,
}

/// The versioned account-entitlement snapshot a ranking runs under
/// (AC-044): the connections the account currently holds rights to.
/// Offline starts unrestricted — no account probe exists yet — and
/// installing a restricted set bumps the version whenever the content
/// changes, so a dispatch admitted under an older snapshot is
/// re-blocked: rights lost between ranking and dispatch never ship a
/// stale grant, and rights regained demand a fresh ranking.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entitlements {
    version: u64,
    /// `None` is the unrestricted offline default: every declared
    /// connection is entitled until an account surface narrows it.
    rights: Option<BTreeSet<String>>,
}

impl Entitlements {
    fn unrestricted() -> Self {
        Self {
            version: 0,
            rights: None,
        }
    }

    fn allows(&self, connection: &str) -> bool {
        self.rights
            .as_ref()
            .is_none_or(|set| set.contains(connection))
    }
}

/// The admission one physical request was gated through (AC-041):
/// every broker-prepared manifest carries its purpose, the effective
/// assignment with its source, the entitlement snapshot version the
/// ranking ran under, and the frozen manifest itself — dispatch
/// compares the presented manifest against that copy, so an attempt id
/// alone never authorizes bytes the ranking never saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRecord {
    pub purpose: String,
    /// The effective physical connection: a fixed pin names itself, an
    /// auto assignment names the ranked pool winner. Offline pools
    /// carry connections, not model ids — the live endpoint catalogue
    /// names the model later.
    pub connection: String,
    pub model_id: Option<String>,
    pub model_source: String,
    /// The choosing basis the ranking froze on this attempt (AC-096); `None`
    /// while no recorded basis explains the pick — a pin, or a ranking that
    /// ran on unknown task facts.
    pub ranking_basis: Option<String>,
    pub snapshot_version: u64,
    /// The manifest frozen at prepare: the dispatch re-check's
    /// comparison copy.
    pub manifest: RequestManifest,
    /// The resolved fallback assignment for this attempt (AC-045):
    /// frozen at admission — a later config edit never rewrites the
    /// chain an in-flight dispatch walks.
    pub fallback: FallbackAssign,
    /// Where the fallback assignment resolved from, for the child
    /// admission's source label.
    pub fallback_source: String,
}

/// The single accounting record of one physical request (INV-024):
/// keyed by the manifest's attempt id and written exactly once, when
/// the provider send completes. Offline the charge stays at the frozen
/// bound — see [`SentCostExplain`] for the bound-versus-confirmed
/// distinction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountingRecord {
    pub attempt_id: String,
    pub purpose: String,
    pub connection: String,
    pub cost_bound: u64,
    /// The physical usage the provider reported for this one send
    /// (INV-022): `Unknown` when it reported none — the retained bound
    /// is never released as a fabricated zero.
    pub usage: UsageDelta,
}

/// The broker-side typed outcome of one dispatched physical request —
/// the recorded `ProviderReply → ModelOutcome → AccountingRecord`
/// seam: produced inside `Broker::complete_send`, its usage feeds
/// the attempt's single accounting record exactly once, and the reply
/// itself is what the dispatch caller continues with.
#[derive(Debug, Clone, PartialEq)]
pub enum ModelOutcome {
    /// A verified provider reply and the physical usage its one send
    /// reported.
    Reply {
        reply: ProviderReply,
        usage: UsageDelta,
    },
}

impl ModelOutcome {
    /// The physical usage report the accounting record charges.
    #[must_use]
    pub fn usage(&self) -> UsageDelta {
        match self {
            Self::Reply { usage, .. } => *usage,
        }
    }

    /// The reply the dispatch caller continues with.
    #[must_use]
    pub fn into_reply(self) -> ProviderReply {
        match self {
            Self::Reply { reply, .. } => reply,
        }
    }
}

/// What one `complete_send` attempt ended with: the provider's own failure
/// (which a fallback chain may answer) or a ledger refusal (which no chain
/// entry can — the send never started or never settled).
pub(crate) enum SendFailure {
    Provider(ProviderError),
    Ledger(LedgerError),
}

/// Where one dispatched send begins, as the ledger records it (AC-057):
/// the purpose and connection the send ran under, the attempt it fell back
/// from, and the basis the ranking chose it on. `parent_attempt_id` is the
/// failed primary a substitute inherited from — the lineage a later total is
/// derived from, never a second total.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SendContext {
    pub purpose: String,
    pub connection: String,
    pub parent_attempt_id: Option<String>,
    /// The choosing basis the ranker froze on the attempt; `None` while no
    /// recorded basis explains the pick — unknown, never a made-up reason.
    pub ranking_basis: Option<String>,
}

/// What one entered send reports back to the ledger: the provider's own
/// bins and wire retries when it answered, or the failure that ends the
/// attempt with its usage unknown — the bound stays charged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    Settled {
        usage: UsageDelta,
        wire_retries: u32,
    },
    Failed {
        wire_retries: u32,
    },
}

/// The durable identity one `begin_send` minted: the attempt whose
/// settlement row is open, and whether a budget reservation stands behind
/// it. `reserved` is `false` when no scope was open — the row is still
/// recorded, and there is nothing to resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendTicket {
    pub attempt_id: String,
    pub cost_bound: u64,
    pub reserved: bool,
}

/// A ledger failure at the send boundary. The budget refusal is its own
/// variant so the controller reports a waiting reason instead of a provider
/// denial; every other failure is the store's typed error.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error(transparent)]
    Store(crate::state::StoreError),
    #[error("budget exhausted at scope {scope}")]
    BudgetExhausted { scope: String },
}

impl LedgerError {
    /// The wire code this ledger refusal reports (P-001).
    #[must_use]
    pub fn code(&self) -> crate::contracts::ErrorCode {
        match self {
            Self::Store(error) => error.code(),
            Self::BudgetExhausted { .. } => crate::contracts::ErrorCode::BudgetExhausted,
        }
    }
}

/// One ledger refusal at the dispatch boundary: a budget denial becomes the
/// dedicated `BudgetExhausted` error — the one the controller turns into a
/// waiting step with a named reason — and every other store refusal keeps
/// its typed class. A store ledger that surfaced the budget conflict inside
/// its own error keeps the same mapping.
fn ledger_refusal(error: LedgerError) -> ModelError {
    match error {
        LedgerError::BudgetExhausted { scope } => ModelError::BudgetExhausted { scope },
        LedgerError::Store(crate::state::StoreError::Conflict(
            crate::state::ConflictCause::BudgetExhausted { scope, .. },
        )) => ModelError::BudgetExhausted { scope },
        other => ModelError::Ledger(other),
    }
}

/// Whether one entered send ended with an outcome that may still have
/// applied remotely. An unknown outcome — a timeout, a deadline, a read
/// failure, a 5xx/redirect, a retried leg, a post-output provider failure,
/// a stream violation or an unclassifiable terminal — never walks an auto
/// chain: only a definitive denial proves no second request can duplicate
/// the effect. A manual fallback still pauses on it, because the human's
/// choice is explicit. A request-shape refusal that never produced a byte
/// is definitive: it cannot have applied.
fn provider_outcome_unknown(error: &ProviderError) -> bool {
    use crate::providers::{ProviderError as Provider, TransportCause, TransportClass};
    match error {
        // The adapter's own corrected retry crossed the wire more than
        // once, so neither leg's effect can be ruled out.
        Provider::Retried { .. } => true,
        Provider::Transport { cause, .. } => match cause.class() {
            TransportClass::DeadlineExpired
            | TransportClass::Timeout
            | TransportClass::ReadFailure => true,
            TransportClass::HttpStatus { code } => {
                code >= 500 || (300..400).contains(&code) || code == 408 || code == 425
            }
            // Only a request the client never built or never connected is a
            // definitive refusal: reqwest also reports send and hand-off
            // failures here, and those may have crossed the wire.
            TransportClass::RequestFailure => match cause {
                TransportCause::Request { source } => !(source.is_builder() || source.is_connect()),
                _ => true,
            },
        },
        // Adapters emit a provider failure verdict only after the response
        // has started: a terminal incomplete/cancelled event, a non-STOP
        // finish or a mid-stream error already crossed the wire. A
        // malformed stream or foreign artifact likewise follows a
        // partially applied request, so these stay unknown.
        Provider::ProviderFailed { .. }
        | Provider::UnknownTerminal { .. }
        | Provider::StreamViolation { .. }
        | Provider::IncompatibleOutput { .. }
        | Provider::ReasoningProvenance { .. } => true,
        // Every remaining variant is a pre-send binding, catalogue or
        // request-shape denial: the request provably did not apply.
        Provider::UnknownConnection { .. }
        | Provider::LiveGrantRequired { .. }
        | Provider::StoreUnavailable { .. }
        | Provider::StoreAmbiguous { .. }
        | Provider::CredentialUnresolved { .. }
        | Provider::LocalProfileDeclared { .. }
        | Provider::CredentialProfileMismatch { .. }
        | Provider::CredentialOutsideNamespace { .. }
        | Provider::CredentialOccupied { .. }
        | Provider::CredentialAbsent { .. }
        | Provider::CredentialMalformed { .. }
        | Provider::CredentialBaseMismatch { .. }
        | Provider::DialectMismatch { .. }
        | Provider::DialectUnserved { .. }
        | Provider::UnpinnedModel { .. }
        | Provider::RegionMismatch { .. }
        | Provider::EndpointRequired { .. }
        | Provider::UnsupportedCredentialClass { .. }
        | Provider::UnsupportedParameter { .. }
        | Provider::UnsendableRequest { .. } => false,
    }
}

/// The one ledger seam at the Broker call boundary (DEC-012): the broker
/// cannot own the runtime's single `TaskStore`, so the caller lends it a
/// ledger for the duration of one dispatch. `begin_send` runs after the
/// broker's pre-send checks and before the provider sees the request;
/// `finish_send` closes the row it opened. Both are exactly-once.
pub trait Ledger {
    /// # Errors
    /// [`LedgerError::BudgetExhausted`] when the frozen bound no longer fits
    /// an open scope, or [`LedgerError::Store`] for a storage failure.
    fn begin_send(
        &mut self,
        context: &SendContext,
        manifest: &RequestManifest,
    ) -> Result<SendTicket, LedgerError>;

    /// # Errors
    /// [`LedgerError::Store`] when the settlement cannot be written; the row
    /// stays open and the reservation stays held.
    fn finish_send(
        &mut self,
        ticket: &SendTicket,
        outcome: &SendOutcome,
    ) -> Result<(), LedgerError>;
}

/// A ledger that records nothing: the seam's no-op for a caller that reads
/// only the provider reply (adapter and routing proofs) and for the
/// documentation probes. It reserves no bound, because a caller that binds
/// no store has no scope to reserve against.
#[derive(Debug, Default)]
pub struct NullLedger;

impl Ledger for NullLedger {
    fn begin_send(
        &mut self,
        _context: &SendContext,
        manifest: &RequestManifest,
    ) -> Result<SendTicket, LedgerError> {
        Ok(SendTicket {
            attempt_id: manifest.attempt_id.clone(),
            cost_bound: manifest.cost_bound,
            reserved: false,
        })
    }

    fn finish_send(
        &mut self,
        _ticket: &SendTicket,
        _outcome: &SendOutcome,
    ) -> Result<(), LedgerError> {
        Ok(())
    }
}

/// The last frozen model-visible prefix of one purpose: an unchanged
/// digest replays its epoch, while a changed model, instruction set or
/// tool surface opens a new epoch with a mutation reason. The whole
/// prefix digest decides the replay and names the epoch id; the per-part
/// digests beside it decide which part moved, because one digest can
/// only say that something did.
#[derive(Clone)]
struct EpochState {
    prefix_digest: String,
    model_digest: String,
    instructions_digest: String,
    tools_digest: String,
}

/// Recorded reason a context epoch opened (AC-061, INV-009a): the closed
/// vocabulary names which part of the model-visible prefix moved. A
/// learned instruction delta is a system change; compaction and masking
/// are not prefix mutations and never appear here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochMutationReason {
    /// The system instructions changed — a new instruction set or a
    /// learned instruction delta.
    SystemChange,
    /// The declared tool surface changed.
    ToolsChange,
    /// The resolved model assignment changed.
    ModelSwitch,
}

impl EpochMutationReason {
    /// The recorded name — the closed vocabulary of INV-009a.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemChange => "system change",
            Self::ToolsChange => "tools change",
            Self::ModelSwitch => "model switch",
        }
    }
}

impl std::fmt::Display for EpochMutationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The expected provider-cache cost of one prefix mutation (AC-061): the
/// envelope part the mutation replaced and the envelope bytes the next
/// request rewrites instead of replaying. A cached prefix is shared
/// forwards only, so the rewrite starts at the replaced part and covers
/// every part the request re-sends after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochCost {
    pub reason: EpochMutationReason,
    /// The envelope part the mutation replaced: `instructions`, `tools`
    /// or `model`.
    pub replaced_part: &'static str,
    /// Envelope bytes the next request rewrites instead of replaying.
    pub expected_rewrite_bytes: usize,
}

/// Mandatory wire parts every offline request carries (AC-013). Live
/// provider dialects replace these with their real instruction and tool
/// surfaces; offline the constants keep the accounting honest.
pub(crate) const MANDATORY_INSTRUCTIONS: &str = "You are the Rivect decision core. The only permitted action is one scoped file read; request it as `read <path>` on its own line.";

/// The longest instruction base any assembly site composes the learned
/// definition onto: [`MANDATORY_INSTRUCTIONS`] for [`Broker::prepare`], or the
/// caller's own base for [`Broker::prepare_call`] — today the semantic stage
/// contracts in [`crate::actions`]. The learning store measures its composed
/// definition beside this base, so an activation certifies the size of the
/// request part those seams assemble (AC-051).
pub(crate) const LARGEST_INSTRUCTION_BASE: &str = {
    let stage = crate::actions::LONGEST_STAGE_INSTRUCTIONS;
    if stage.len() > MANDATORY_INSTRUCTIONS.len() {
        stage
    } else {
        MANDATORY_INSTRUCTIONS
    }
};
const DECLARED_TOOLS: &[&str] = &["read_file"];
/// One caller's wire parts: its system instructions and declared tool
/// surface, frozen into [`RequestManifest::instructions`] and
/// [`RequestManifest::tools`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallContract<'a> {
    pub instructions: &'a str,
    pub tools: &'a [&'a str],
}

/// Reply bytes every request must leave room for (AC-013): the
/// accounted full-request size includes this reserve, so a request
/// that fits only without it is rejected.
const OUTPUT_RESERVE_BYTES: usize = 16 * 1024;

/// The wire parts and authorship one prepare freezes: everything
/// [`Broker::freeze_manifest`] needs beyond the config and the ranking facts,
/// so the two public entries differ only in where these came from.
struct FreezeRequest<'a> {
    world: &'a str,
    inputs: &'a str,
    origin: InputOrigin,
    instructions: &'a str,
    tools: &'a [String],
}

pub struct Broker {
    provider: Box<dyn Provider>,
    /// Last frozen context epoch per purpose (AC-061 contribution):
    /// the model-visible prefix digest decides replay versus a new
    /// epoch. Ordered map — epoch bookkeeping stays deterministic.
    epochs: BTreeMap<String, EpochState>,
    /// The account-entitlement snapshot every ranking runs under
    /// (AC-044): versioned, compared again at dispatch.
    entitlements: Entitlements,
    /// Admission records keyed by attempt id (AC-041): one entry per
    /// prepared manifest, the dispatch re-check's source of truth. A
    /// completed dispatch prunes its entry — the accounting map answers
    /// replays of a spent attempt — so the map stays bounded by
    /// in-flight attempts, not lifetime traffic.
    admissions: BTreeMap<String, AdmissionRecord>,
    /// The single accounting per physical request (INV-024): one entry
    /// per completed provider send, keyed by the attempt it charged.
    accounting: BTreeMap<String, AccountingRecord>,
    /// The connection catalogue the dispatch-time candidate re-check
    /// reads (AC-045b): refreshed from the latest observed config, so a
    /// candidate removed after admission fails the current check.
    view_connections: BTreeMap<String, Connection>,
    /// The credential profiles the re-check's credential-resolution
    /// leg reads (DEC-011): a profile edit between prepare and
    /// dispatch re-decides a non-local candidate's usability.
    view_profiles: BTreeMap<String, Profile>,
    /// The purpose definitions the re-check's `eligible` input reads.
    view_purposes: BTreeMap<String, PurposeDef>,
    /// Cancelled-attempt tombstones (EDGE-004): a late retry or provider
    /// callback against a cancelled attempt never sends. Bounded by
    /// lifetime cancelled attempts, like the accounting map is by
    /// lifetime completed sends.
    cancelled: BTreeSet<String>,
    /// Pending manual-fallback choices keyed by the failed attempt id
    /// (AC-045): the dispatch that records one never substitutes.
    pending: BTreeMap<String, PendingFallback>,
    /// Attempts currently paused on a manual-fallback choice, keyed by
    /// the failed attempt id (AC-045): the broker-side proof a pause
    /// happened. `pending` drains when the choice is published, so the
    /// admission's frozen `Manual` flag alone can never authorize a
    /// substitute dispatch — only an attempt this map still pins may
    /// answer, and the value is the candidate set the pause served.
    /// Dies with the admission: spent, substituted or cancelled.
    paused: BTreeMap<String, BTreeSet<String>>,
    /// The profile the latest prepared manifest bound (AC-047).
    bound_profile: Option<ProfileBinding>,
    /// The learned definition the next request composes (AC-051): the store's
    /// active deltas, installed by the owner that can read them. Assembly
    /// overlays the *assembled* instruction part with this value, so a
    /// learned delta changes the model-visible prefix and therefore opens a
    /// new context epoch with `system change` — never a second planner and
    /// never an extra model call (INV-009).
    learning: LearningDefinition,
    /// The explicit instruction root whose ancestor chain the next assembly
    /// walks (AC-076). `None` is no discovery, so a caller that pins no root
    /// assembles exactly the bytes the learning seam composed before
    /// instruction files existed.
    instructions_root: Option<PathBuf>,
    /// The typed conflicts the latest assembly found under that root
    /// (AC-076): recorded where discovery ran and read by
    /// [`crate::commands::StatusResult`], so a conflict between two sources
    /// stays visible instead of one of them silently winning.
    instruction_conflicts: Vec<InstructionConflict>,
}

impl std::fmt::Debug for Broker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The provider is a trait object without Debug; its name and
        // the broker's own counters are the observability surface —
        // manifests, credentials and wire data never render here.
        f.debug_struct("Broker")
            .field("provider", &self.provider.name())
            .field("admissions", &self.admissions.len())
            .field("accounted", &self.accounting.len())
            .finish_non_exhaustive()
    }
}

impl Broker {
    pub fn new(provider: Box<dyn Provider>) -> Self {
        Self {
            provider,
            epochs: BTreeMap::new(),
            entitlements: Entitlements::unrestricted(),
            admissions: BTreeMap::new(),
            accounting: BTreeMap::new(),
            view_connections: BTreeMap::new(),
            view_profiles: BTreeMap::new(),
            view_purposes: BTreeMap::new(),
            cancelled: BTreeSet::new(),
            pending: BTreeMap::new(),
            paused: BTreeMap::new(),
            bound_profile: None,
            learning: LearningDefinition::default(),
            instructions_root: None,
            instruction_conflicts: Vec::new(),
        }
    }

    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
    }

    /// Installs the learned definition the next request composes (AC-051).
    /// The owner that holds the store installs it, so activation needs no
    /// per-request call and no model call: assembly reads this value.
    pub fn set_learning_definition(&mut self, definition: LearningDefinition) {
        self.learning = definition;
    }

    /// Pins the instruction root the next assembly walks (AC-076): the root's
    /// own ancestors are the scope chain, outermost first, so a file in a
    /// scope above the root still contributes. The root is an explicit
    /// parameter — a caller that pins none discovers nothing, and no working
    /// directory is ever implied.
    pub fn set_instructions_root(&mut self, root: Option<PathBuf>) {
        self.instructions_root = root;
    }

    /// The typed conflicts the latest assembly found (AC-076): the status
    /// surface serves them, so a status read never re-walks a filesystem.
    #[must_use]
    pub fn instruction_conflicts(&self) -> &[InstructionConflict] {
        &self.instruction_conflicts
    }

    /// The assembled instruction part one request carries (AC-076): the
    /// learning seam over the base, with every instruction file discovered
    /// under the pinned root in front of the learned deltas. Instruction
    /// files are data — they add text to the part and nothing else — and no
    /// root means no discovery, so the bytes are the seam's own.
    ///
    /// # Errors
    ///
    /// The typed failure of a candidate that exists but cannot be observed,
    /// read or bounded: a discovered file is never skipped silently.
    fn assemble_instructions(&mut self, purpose: &str, base: &str) -> Result<String, ModelError> {
        let found = match self.instructions_root.clone() {
            Some(root) => InstructionSet::discover(&instruction_scopes(&root))?,
            None => InstructionSet::default(),
        };
        let mut assembled = base.to_string();
        for entry in &found.entries {
            assembled.push('\n');
            assembled.push_str(&entry.text);
        }
        self.instruction_conflicts = found.conflicts;
        Ok(self.learning.instruction_part(purpose, &assembled))
    }

    /// Refreshes the candidate view the dispatch-time re-check reads
    /// (AC-045b): pushed on boot and on every admitted config edit, and
    /// re-observed on every successful prepare — the fallback walk
    /// always checks against the current view, never a prepare-time
    /// snapshot, and a rejected prepare never steers it.
    pub fn set_config(&mut self, config: &Config) {
        self.observe_config(config);
    }

    fn observe_config(&mut self, config: &Config) {
        self.view_connections = config.connections.clone();
        self.view_profiles = config.profiles.clone();
        self.view_purposes = config.models.purposes.clone();
    }

    /// The pending manual-fallback choice recorded for one attempt
    /// (AC-045); `None` when the attempt never produced one.
    #[must_use]
    pub fn pending_choice(&self, attempt_id: &str) -> Option<&PendingFallback> {
        self.pending.get(attempt_id)
    }

    /// Consumes the pending choice: the caller that publishes it through
    /// question.current owns the pause from here — a repeated read never
    /// re-serves a consumed choice. The pause pin survives the drain:
    /// it is the gate a substitute dispatch must satisfy, cleared only
    /// when the pause itself resolves.
    pub fn take_pending_choice(&mut self, attempt_id: &str) -> Option<PendingFallback> {
        self.pending.remove(attempt_id)
    }

    /// Cancels one admitted attempt (EDGE-004): the admission, any
    /// pending choice and the pause pin die and the attempt is
    /// tombstoned, so a late provider callback or retry is rejected
    /// rather than resurrected.
    /// Returns `false` for an attempt this broker never admitted or
    /// already accounted — a spent attempt reports spent, not cancelled.
    pub fn cancel_attempt(&mut self, attempt_id: &str) -> bool {
        if self.accounting.contains_key(attempt_id) {
            return false;
        }
        if self.admissions.remove(attempt_id).is_none() {
            return false;
        }
        self.pending.remove(attempt_id);
        self.paused.remove(attempt_id);
        self.cancelled.insert(attempt_id.to_string());
        true
    }

    /// The credential profile the latest prepared manifest bound
    /// (AC-047): `active` on the status surface.
    #[must_use]
    pub fn bound_profile(&self) -> Option<ProfileBinding> {
        self.bound_profile.clone()
    }

    /// Installs the account-entitlement snapshot: the connections the
    /// account currently holds rights to. A content change bumps the
    /// version; an identical reinstall does not — the version names
    /// the snapshot a frozen admission is compared against.
    pub fn set_account_rights(&mut self, rights: &[String]) {
        let next: BTreeSet<String> = rights.iter().cloned().collect();
        if self.entitlements.rights.as_ref() != Some(&next) {
            self.entitlements.version += 1;
            self.entitlements.rights = Some(next);
        }
    }

    /// The current entitlement-snapshot version (AC-044): the value a
    /// frozen admission's version must equal for its dispatch to send.
    #[must_use]
    pub fn entitlement_version(&self) -> u64 {
        self.entitlements.version
    }

    /// The admission one broker-prepared attempt was ranked through
    /// (AC-041); attempts this broker never ranked have none.
    #[must_use]
    pub fn admission(&self, attempt_id: &str) -> Option<&AdmissionRecord> {
        self.admissions.get(attempt_id)
    }

    /// The single accounting record of one physical request (INV-024).
    #[must_use]
    pub fn accounting_record(&self, attempt_id: &str) -> Option<&AccountingRecord> {
        self.accounting.get(attempt_id)
    }

    /// How many physical requests this broker accounted.
    #[must_use]
    pub fn accounted_requests(&self) -> usize {
        self.accounting.len()
    }

    /// How many attempts this broker currently holds admissions for:
    /// prepare grows it and a completed dispatch prunes it, so the
    /// count names in-flight attempts, not lifetime traffic.
    #[must_use]
    pub fn admitted_attempts(&self) -> usize {
        self.admissions.len()
    }

    /// Builds the immutable manifest for one model attempt. Eligibility
    /// runs before ranking here — the catalogue, the offline live-grant
    /// rule, the account entitlement and the per-purpose `eligible`
    /// input exclude candidates first — and is re-checked at dispatch.
    /// The manifest freezes the execution world, the mandatory wire
    /// parts and the context epoch; a request that does not fit
    /// together with its mandatory parts is rejected, never truncated.
    ///
    /// This is the operator-class entry: the caller asserts that a human
    /// turn authored `inputs`. A dispatch that reads the authorship from
    /// its carrier calls [`Broker::prepare_authored`] with the origin it
    /// found.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Config`] when the purpose cannot resolve,
    /// [`ModelError::Provider`] when a fixed pin is offline ineligible,
    /// [`ModelError::NoEligibleCandidate`] when no candidate survives
    /// eligibility, [`ModelError::Instructions`] when an instruction file
    /// under the pinned root cannot be loaded, and
    /// [`ModelError::RequestTooLarge`] when the accounted full request
    /// exceeds the wire limit.
    pub fn prepare(
        &mut self,
        purpose: &str,
        config: &Config,
        world: &str,
        inputs: &str,
    ) -> Result<RequestManifest, ModelError> {
        self.prepare_authored(purpose, config, world, inputs, InputOrigin::Human)
    }

    /// [`Broker::prepare`] with the input's authoring origin spelled by
    /// the caller (AC-009): the dispatch site reads who authored the
    /// bytes it carries, so a tool output or a model-authored turn never
    /// freezes as a human request.
    ///
    /// # Errors
    ///
    /// The [`Broker::prepare`] refusals.
    pub fn prepare_authored(
        &mut self,
        purpose: &str,
        config: &Config,
        world: &str,
        inputs: &str,
        origin: InputOrigin,
    ) -> Result<RequestManifest, ModelError> {
        self.prepare_with_facts(
            purpose,
            config,
            world,
            inputs,
            origin,
            &RankingFacts::unknown(),
        )
    }

    /// [`Broker::prepare_authored`] with the task facts `auto` ranks on
    /// (AC-096, DEC-013): the controller builds the recorded facts from the
    /// task snapshot and its obligations and passes them here. Facts and
    /// authorship are different facts of the same request, so the entry
    /// carries both; unknown facts keep the declared pool order and record no
    /// basis.
    ///
    /// # Errors
    ///
    /// The [`Broker::prepare`] refusals.
    pub fn prepare_with_facts(
        &mut self,
        purpose: &str,
        config: &Config,
        world: &str,
        inputs: &str,
        origin: InputOrigin,
        facts: &RankingFacts,
    ) -> Result<RequestManifest, ModelError> {
        let instructions = self.assemble_instructions(purpose, MANDATORY_INSTRUCTIONS)?;
        let tools: Vec<String> = DECLARED_TOOLS
            .iter()
            .map(|tool| (*tool).to_string())
            .collect();
        self.freeze_manifest(
            config,
            purpose,
            &FreezeRequest {
                world,
                inputs,
                origin,
                instructions: &instructions,
                tools: &tools,
            },
            facts,
        )
    }

    /// Builds the immutable manifest for one call under `contract`: the
    /// caller's own instructions and declared tools ride the existing
    /// manifest fields, so their model-visible prefix opens its own
    /// context epoch. Every other gate is [`Broker::prepare`]'s.
    ///
    /// # Errors
    ///
    /// The [`Broker::prepare`] refusals.
    pub fn prepare_call(
        &mut self,
        purpose: &str,
        config: &Config,
        world: &str,
        inputs: &str,
        contract: &CallContract<'_>,
    ) -> Result<RequestManifest, ModelError> {
        self.prepare_call_with_facts(
            purpose,
            config,
            world,
            inputs,
            contract,
            &RankingFacts::unknown(),
        )
    }

    /// [`Broker::prepare_call`] with the task facts `auto` ranks on
    /// (AC-096, DEC-013): the action path passes the request's own recorded
    /// facts, so a semantic leg ranks on its surfaces and obligation shape.
    ///
    /// # Errors
    ///
    /// The [`Broker::prepare`] refusals.
    pub fn prepare_call_with_facts(
        &mut self,
        purpose: &str,
        config: &Config,
        world: &str,
        inputs: &str,
        contract: &CallContract<'_>,
        facts: &RankingFacts,
    ) -> Result<RequestManifest, ModelError> {
        let instructions = self.assemble_instructions(purpose, contract.instructions)?;
        let tools: Vec<String> = contract
            .tools
            .iter()
            .map(|tool| (*tool).to_string())
            .collect();
        self.freeze_manifest(
            config,
            purpose,
            &FreezeRequest {
                world,
                inputs,
                // A per-call contract's parts are catalogue and action text:
                // platform bytes, never an operator turn (AC-009).
                origin: InputOrigin::Tool,
                instructions: &instructions,
                tools: &tools,
            },
            facts,
        )
    }

    /// The one freeze both [`Broker::prepare_with_facts`] and
    /// [`Broker::prepare_call_with_facts`] run: rank on the facts, pin the
    /// recorded model and the chosen effort, account the composed wire parts,
    /// mint the epoch and admit the frozen manifest — so the two entries can
    /// never diverge on what a prepared request is.
    fn freeze_manifest(
        &mut self,
        config: &Config,
        purpose: &str,
        request: &FreezeRequest<'_>,
        facts: &RankingFacts,
    ) -> Result<RequestManifest, ModelError> {
        let resolved = config.resolve_purpose(purpose)?;
        let purpose_def = config.models.purposes.get(purpose);
        let choice = rank_connection(
            purpose,
            &resolved,
            purpose_def,
            &config.connections,
            &config.profiles,
            &self.entitlements,
            facts,
        )?;
        // A recorded model freezes as a fixed pin and the ranked effort as a
        // fixed level; an unrecorded candidate keeps the resolved assignment,
        // so a caller with unknown facts sees exactly the request it saw
        // before task facts existed.
        let model = match &choice.model_id {
            Some(model_id) => ModelAssign::Fixed(FixedModel {
                connection: choice.connection.clone(),
                model_id: model_id.clone(),
            }),
            None => resolved.model.clone(),
        };
        let effort = match choice.effort {
            Some(value) => EffortAssign::Fixed { value },
            None => resolved.effort.clone(),
        };
        let connection = choice.connection;
        let accounted = wire_composition(
            request.instructions,
            &model,
            request.tools,
            OUTPUT_RESERVE_BYTES,
            request.inputs,
        )
        .len()
            + OUTPUT_RESERVE_BYTES;
        if accounted > crate::contracts::MODEL_WIRE_MAX_BYTES {
            return Err(ModelError::RequestTooLarge {
                limit: crate::contracts::MODEL_WIRE_MAX_BYTES,
                actual: accounted,
            });
        }
        let (epoch_id, epoch_cost) =
            self.context_epoch(purpose, &model, request.instructions, request.tools);
        let attempt_id = crate::contracts::AttemptId::generate().0;
        let manifest = RequestManifest {
            attempt_id,
            purpose: purpose.to_string(),
            world: request.world.to_string(),
            model,
            effort,
            instructions: request.instructions.to_string(),
            tools: request.tools.to_vec(),
            output_reserve: OUTPUT_RESERVE_BYTES,
            inputs: request.inputs.to_string(),
            inputs_digest: hex(&Sha256::digest(request.inputs.as_bytes())),
            epoch_id,
            mutation_reason: epoch_cost.map(|cost| cost.reason.to_string()),
            epoch_cost,
            input_origin: request.origin,
            cost_bound: sent_cost_bound(request.inputs),
        };
        // The re-check view tracks the config this prepare ran under —
        // the walk at dispatch time never reads a staler document. The
        // observe rides only a prepare that reached the admission: a
        // purpose resolution, ranking or size rejection above must not
        // steer the re-check with its caller-supplied config.
        self.observe_config(config);
        self.admissions.insert(
            manifest.attempt_id.clone(),
            AdmissionRecord {
                purpose: purpose.to_string(),
                connection: connection.clone(),
                model_id: choice.model_id,
                model_source: resolved.model_source,
                ranking_basis: choice.basis,
                snapshot_version: self.entitlements.version,
                manifest: manifest.clone(),
                fallback: resolved.fallback,
                fallback_source: resolved.fallback_source,
            },
        );
        // The credential profile the admission binds (AC-047): frozen on
        // the broker so the status surface can name it `active` — and
        // only once the admission stands, so a rejected prepare never
        // moves the pending/active pair.
        let profile = config
            .connections
            .get(&connection)
            .and_then(|entry| entry.profile.clone());
        self.bound_profile = Some(ProfileBinding {
            connection,
            profile,
        });
        Ok(manifest)
    }

    /// Dispatches exactly the frozen manifest bytes to the owner-brokered
    /// provider. The execution world is re-checked against the frozen
    /// one, the presented manifest against the frozen copy this broker
    /// admitted at prepare — an attempt id alone authorizes nothing —
    /// and the eligibility snapshot against the version frozen at
    /// ranking: a rights loss between ranking and dispatch re-blocks
    /// the send, all before any provider call. The physical request is
    /// accounted exactly once, and the spent admission is pruned so the
    /// map stays bounded by in-flight attempts. No worker may call
    /// this directly.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::WorldMismatch`] when the dispatch world is
    /// not the world frozen on the manifest,
    /// [`ModelError::AttemptAlreadyAccounted`] when the attempt already
    /// spent its one physical request (checked first, so a replayed
    /// completed attempt reports the spent accounting even after its
    /// admission was pruned), [`ModelError::AttemptCancelled`] when the
    /// attempt was tombstoned by a cancel, [`ModelError::NoAdmission`]
    /// when this broker ranked no manifest with that attempt id,
    /// [`ModelError::AdmissionMismatch`] when the presented manifest is
    /// not the one the ranking admitted, [`ModelError::EligibilityStale`]
    /// when the entitlement snapshot changed since ranking,
    /// [`ModelError::ManualFallbackPending`] when the frozen fallback is
    /// `manual` and the send failed — the pending choice rides
    /// question.current even when the failure's outcome is unknown —
    /// [`ModelError::FallbackExhausted`] when the
    /// auto chain ran out with every entry rejected or failed, or a
    /// `manual` fallback found no servable candidate to pause on, and
    /// [`ModelError::Provider`] when the provider rejects the request or the
    /// auto chain stops on an entered unknown outcome.
    pub fn dispatch(
        &mut self,
        ledger: &mut dyn Ledger,
        world: &str,
        manifest: &RequestManifest,
    ) -> Result<ProviderReply, ModelError> {
        if manifest.world != world {
            return Err(ModelError::WorldMismatch {
                frozen: manifest.world.clone(),
                current: world.to_string(),
            });
        }
        // A completed attempt is spent no matter what else moved: the
        // accounting check precedes every later one, so a replayed
        // completed attempt reports the spent single accounting — never
        // a stale snapshot or a missing admission.
        if self.accounting.contains_key(&manifest.attempt_id) {
            return Err(ModelError::AttemptAlreadyAccounted {
                attempt_id: manifest.attempt_id.clone(),
            });
        }
        // Cancellation is authoritative (EDGE-004): a tombstoned attempt
        // is rejected before any other check can resurrect it — a late
        // provider callback never produces a new dispatch or effect.
        if self.cancelled.contains(&manifest.attempt_id) {
            return Err(ModelError::AttemptCancelled {
                attempt_id: manifest.attempt_id.clone(),
            });
        }
        let admission = {
            let admission = self.admissions.get(&manifest.attempt_id).ok_or_else(|| {
                ModelError::NoAdmission {
                    attempt_id: manifest.attempt_id.clone(),
                }
            })?;
            // The attempt id authenticates nothing by itself: only the
            // frozen manifest this ranking admitted dispatches, so a
            // forged clone with mutated fields never sends bytes no
            // ranking saw.
            if &admission.manifest != manifest {
                return Err(ModelError::AdmissionMismatch {
                    attempt_id: manifest.attempt_id.clone(),
                });
            }
            admission.clone()
        };
        let current_version = self.entitlements.version;
        // The re-check re-evaluates against the live snapshot, not a
        // cached verdict. The version bump on every rights movement is
        // the primary guard — a same-version rights drift is
        // unreachable through `set_account_rights` — and the direct
        // `allows` re-evaluation stays as defense-in-depth against any
        // future surface that mutates rights without a bump.
        if current_version != admission.snapshot_version
            || !self.entitlements.allows(&admission.connection)
        {
            return Err(ModelError::EligibilityStale {
                attempt_id: manifest.attempt_id.clone(),
                connection: admission.connection.clone(),
                frozen: admission.snapshot_version,
                current: current_version,
            });
        }
        match self.complete_send(ledger, manifest, &admission.connection, None) {
            Ok(reply) => Ok(reply),
            Err(SendFailure::Ledger(source)) => Err(ledger_refusal(source)),
            Err(SendFailure::Provider(source)) => {
                // The chain arm alone decides whether an unknown outcome may
                // walk; a manual pause still lets the human answer it.
                self.fallback_or_fail(ledger, manifest, &admission, source)
            }
        }
    }

    /// Sends one frozen manifest and charges its shared reservation
    /// once: admission for the send happened immediately above the call
    /// site — the presented-manifest re-check for the primary, the chain
    /// re-check for a fallback candidate. On success the spent admission
    /// and any stale pending choice die with the send.
    ///
    /// The ledger seam brackets the send (DEC-012): the pre-send checks
    /// run first, so a denial never creates a reservation; `begin_send`
    /// then reserves the frozen bound and opens the settlement row before
    /// a byte crosses the wire, and `finish_send` closes it — with the
    /// provider's bins when it answered, with the usage unknown and the
    /// bound retained when it failed.
    fn complete_send(
        &mut self,
        ledger: &mut dyn Ledger,
        manifest: &RequestManifest,
        connection: &str,
        parent_attempt_id: Option<&str>,
    ) -> Result<ProviderReply, SendFailure> {
        // Fail closed on the provider's own dialect claim (AC-046):
        // the frozen manifest's connection must still be declared, and
        // the injected adapter must actually serve it — eligibility
        // alone never authorizes a send, and the denial lands before
        // the provider sees the request or anything is accounted.
        let Some(entry) = self.view_connections.get(connection) else {
            return Err(SendFailure::Provider(ProviderError::UnknownConnection {
                connection: connection.to_string(),
            }));
        };
        if !self.provider.serves(connection, entry) {
            // An id `dialect_for` reserves fails differently from one
            // the adapter merely declines: the build carries no adapter
            // that speaks the recorded dialect — say so instead of
            // blaming the injected adapter's own dialect.
            return Err(SendFailure::Provider(
                match providers::dialect_for(connection) {
                    Some(dialect) => ProviderError::DialectUnserved {
                        connection: connection.to_string(),
                        dialect,
                    },
                    None => ProviderError::DialectMismatch {
                        connection: connection.to_string(),
                    },
                },
            ));
        }
        // The dispatch decision IS the auto pool's choice: the send
        // narrows the assignment to the one connection this broker
        // routed to, and the adapter's catalogue leg resolves the
        // model id from there — primary and substitute sends share the
        // rule, and a manual pick arrives already narrowed to the same
        // pool of one. A fixed pin passes verbatim.
        let send_manifest;
        let manifest = match &manifest.model {
            ModelAssign::Auto { .. } => {
                send_manifest = RequestManifest {
                    model: ModelAssign::Auto {
                        pool: Some(vec![connection.to_string()]),
                    },
                    ..manifest.clone()
                };
                &send_manifest
            }
            _ => manifest,
        };
        let context = SendContext {
            purpose: manifest.purpose.clone(),
            connection: connection.to_string(),
            parent_attempt_id: parent_attempt_id.map(str::to_string),
            // The ranking that admitted this attempt froze its basis on the
            // admission; the settlement row carries it, never the manifest.
            ranking_basis: self
                .admissions
                .get(&manifest.attempt_id)
                .and_then(|admission| admission.ranking_basis.clone()),
        };
        let ticket = ledger
            .begin_send(&context, manifest)
            .map_err(SendFailure::Ledger)?;
        let reply = match self.provider.send(manifest) {
            Ok(reply) => reply,
            Err(source) => {
                // The send was entered, so its usage is unknown: the
                // settlement closes unknown, the bound stays charged, and
                // the adapter's own retry count rides the failure so a
                // corrected attempt that also failed records every leg it
                // crossed. The marker returns to the failure so the outcome
                // gate sees an unknown even when the last leg's class is a
                // definitive denial.
                let (wire_retries, source) = source.settle();
                ledger
                    .finish_send(&ticket, &SendOutcome::Failed { wire_retries })
                    .map_err(SendFailure::Ledger)?;
                let source = if wire_retries > 0 {
                    ProviderError::Retried {
                        wire_retries,
                        source: Box::new(source),
                    }
                } else {
                    source
                };
                return Err(SendFailure::Provider(source));
            }
        };
        ledger
            .finish_send(
                &ticket,
                &SendOutcome::Settled {
                    usage: reply.usage,
                    wire_retries: reply.wire_retries,
                },
            )
            .map_err(SendFailure::Ledger)?;
        // The reply carries this send's physical usage report; the
        // outcome lifts it into the attempt's single accounting
        // record — the only place it charges.
        let outcome = ModelOutcome::Reply {
            usage: reply.usage,
            reply,
        };
        self.accounting.insert(
            manifest.attempt_id.clone(),
            AccountingRecord {
                attempt_id: manifest.attempt_id.clone(),
                purpose: manifest.purpose.clone(),
                connection: connection.to_string(),
                cost_bound: manifest.cost_bound,
                usage: outcome.usage(),
            },
        );
        self.clear_attempt(&manifest.attempt_id);
        Ok(outcome.into_reply())
    }

    /// Dispatches the manual-fallback candidate the human picked
    /// through question.current (AC-045): the paused attempt's
    /// admission is still live, so its frozen manifest supplies the
    /// task data byte-for-byte while the picked connection mints the
    /// substitute's own attempt id and sends under the same admission
    /// gates — the pick re-runs the CURRENT eligibility check, so a
    /// candidate that lost catalogue presence, offline usability,
    /// entitlement or purpose eligibility between the question and the
    /// answer never receives the send. One physical request, one
    /// accounting; the paused primary's admission is spent with the
    /// substitute so neither id can replay.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::NoAdmission`] when this broker holds no
    /// live admission for the attempt — [`ModelError::AttemptCancelled`]
    /// for a tombstoned one and [`ModelError::AttemptAlreadyAccounted`]
    /// for a spent one — [`ModelError::NoPendingChoice`] when the
    /// attempt is not pinned as paused on a manual fallback (the pin is
    /// set when the failed dispatch records the pending choice and the
    /// frozen `Manual` flag alone never substitutes for it),
    /// [`ModelError::WorldMismatch`] when the dispatch world is not the
    /// frozen one, [`ModelError::ManualChoiceRejected`] when the picked
    /// connection was not among the candidates the pause served or fails
    /// the current eligibility check, and [`ModelError::Provider`] when
    /// the substitute's send fails — the paused attempt stays admitted
    /// for a retry.
    pub fn dispatch_fallback_choice(
        &mut self,
        ledger: &mut dyn Ledger,
        world: &str,
        attempt_id: &str,
        connection: &str,
    ) -> Result<ProviderReply, ModelError> {
        let admission = self.admissions.get(attempt_id).cloned().ok_or_else(|| {
            if self.cancelled.contains(attempt_id) {
                ModelError::AttemptCancelled {
                    attempt_id: attempt_id.to_string(),
                }
            } else if self.accounting.contains_key(attempt_id) {
                ModelError::AttemptAlreadyAccounted {
                    attempt_id: attempt_id.to_string(),
                }
            } else {
                ModelError::NoAdmission {
                    attempt_id: attempt_id.to_string(),
                }
            }
        })?;
        // The pause pin is the gate, not the frozen `Manual` flag: it
        // exists only because a failed dispatch recorded the pending
        // choice, and it survives the publish-time `pending` drain —
        // an un-paused Manual admission reads NoPendingChoice.
        let Some(served) = self.paused.get(attempt_id) else {
            return Err(ModelError::NoPendingChoice {
                attempt_id: attempt_id.to_string(),
            });
        };
        let manifest = &admission.manifest;
        if manifest.world != world {
            return Err(ModelError::WorldMismatch {
                frozen: manifest.world.clone(),
                current: world.to_string(),
            });
        }
        // The same recorded contract as the failed primary is refused for
        // the same reason the auto walk refuses it: a definitive denial is
        // the only failure whose chain may walk, and a sibling literal is
        // never a second independent attempt.
        if providers::blind_retry_refused(&admission.connection, connection) {
            return Err(ModelError::ManualChoiceRejected {
                attempt_id: attempt_id.to_string(),
                connection: connection.to_string(),
                cause: RejectionCause::BlindRetryRefused,
            });
        }
        // The pick is confined to the candidates the pause served — the
        // failed primary is never among them — before the current
        // eligibility re-check runs.
        if !served.contains(connection) {
            return Err(ModelError::ManualChoiceRejected {
                attempt_id: attempt_id.to_string(),
                connection: connection.to_string(),
                cause: RejectionCause::NotOffered,
            });
        }
        if let Some(cause) = self.candidate_rejection(&admission.purpose, connection) {
            return Err(ModelError::ManualChoiceRejected {
                attempt_id: attempt_id.to_string(),
                connection: connection.to_string(),
                cause,
            });
        }
        // A fixed pin's model_id crosses verbatim onto the picked
        // connection — the recorded F22 semantic: the pin survives the
        // substitution, and a peer that does not serve that id answers
        // 400 rather than the broker rewriting it. An auto ranking
        // narrows to a pool of one — the human's pick IS the ranked
        // pool.
        let model = match &manifest.model {
            ModelAssign::Fixed(fixed) => ModelAssign::Fixed(FixedModel {
                connection: connection.to_string(),
                model_id: fixed.model_id.clone(),
            }),
            _ => ModelAssign::Auto {
                pool: Some(vec![connection.to_string()]),
            },
        };
        let (substitute, displaced) = self.mint_substitute(&admission, model, connection, "manual");
        match self.complete_send(ledger, &substitute, connection, Some(attempt_id)) {
            Ok(reply) => {
                // The substitute answered the intent: the paused
                // primary's admission is spent with it, so neither id
                // can replay.
                self.clear_attempt(attempt_id);
                Ok(reply)
            }
            Err(SendFailure::Ledger(source)) => {
                self.abandon_substitute(&substitute.attempt_id, &admission.purpose, displaced);
                Err(ledger_refusal(source))
            }
            Err(SendFailure::Provider(source)) => {
                self.abandon_substitute(&substitute.attempt_id, &admission.purpose, displaced);
                let (_, source) = source.settle();
                Err(ModelError::Provider(source))
            }
        }
    }

    /// The resolved `FallbackAssign` frozen on the failed attempt's
    /// admission decides the pause shape (AC-045): `off` reports the
    /// provider's own error unchanged, `manual` records the pending
    /// choice and reports it without dispatching a substitute — unless
    /// no candidate survives the re-check, where an unanswerable pause
    /// is the honest exhaustion instead — `auto`
    /// walks the chain — an entered unknown outcome of the failed primary
    /// stops that walk before any entry is consulted, because a substitute
    /// could duplicate an effect the peer may already have applied, and
    /// every entry is re-checked against the CURRENT
    /// catalogue, egress, entitlement and purpose-eligibility gates, so
    /// a candidate failing the check never receives the request. An
    /// admitted entry mints one fallback manifest carrying the failed
    /// attempt's frozen task data byte-for-byte under its own attempt
    /// id, the chain entry's fixed model and the same cost bound — each
    /// dispatched attempt reserves and settles exactly once, so the failed
    /// primary and its substitute each carry their own row and charge,
    /// with no second-order fallback.
    fn fallback_or_fail(
        &mut self,
        ledger: &mut dyn Ledger,
        manifest: &RequestManifest,
        admission: &AdmissionRecord,
        source: ProviderError,
    ) -> Result<ProviderReply, ModelError> {
        match &admission.fallback {
            FallbackAssign::Off => {
                // No chain can run, so the retry marker has no decision to
                // route: the caller meets the provider's own class, exactly
                // as it did before the marker existed.
                let (_, source) = source.settle();
                Err(ModelError::Provider(source))
            }
            FallbackAssign::Manual => {
                // The pause hands the classifier verdict to the human: an
                // unknown outcome may already have applied, so the offered
                // picks are stated as a repeat. Computed before any
                // `settle` consumes the failure.
                let unknown_outcome = provider_outcome_unknown(&source);
                let mut candidates = self.eligible_candidates(&admission.purpose);
                // The failed primary never re-enters its own choice
                // list — it already produced this failure — and a
                // candidate resolving to the same recorded contract is
                // refused for the same reason the auto walk refuses it.
                candidates.retain(|name| {
                    name != &admission.connection
                        && !providers::blind_retry_refused(&admission.connection, name)
                });
                if candidates.is_empty() {
                    // An empty served set can never be answered — the
                    // pick must name a served member, so pausing here
                    // would pin a question nothing satisfies. Report
                    // the exhaustion honestly instead: every evaluated
                    // non-primary connection's cause, the filtered
                    // same-contract sibling included, no send attempted,
                    // the primary's own failure as the source.
                    let rejected = self
                        .view_connections
                        .keys()
                        .filter(|name| name.as_str() != admission.connection)
                        .filter_map(|name| {
                            if providers::blind_retry_refused(&admission.connection, name) {
                                return Some(CandidateRejection {
                                    connection: name.clone(),
                                    cause: RejectionCause::BlindRetryRefused,
                                });
                            }
                            self.candidate_rejection(&admission.purpose, name)
                                .map(|cause| CandidateRejection {
                                    connection: name.clone(),
                                    cause,
                                })
                        })
                        .collect();
                    let (_, source) = source.settle();
                    return Err(ModelError::FallbackExhausted {
                        attempt_id: manifest.attempt_id.clone(),
                        purpose: admission.purpose.clone(),
                        rejected,
                        attempted: Vec::new(),
                        source: Box::new(source),
                    });
                }
                let pending = PendingFallback {
                    attempt_id: manifest.attempt_id.clone(),
                    purpose: admission.purpose.clone(),
                    candidates,
                    unknown_outcome,
                };
                // The pause pin outlives the pending record's
                // publish-time drain: it is the broker-side proof a
                // substitute dispatch must satisfy, and its set is the
                // only candidate list the pick may choose from.
                self.paused.insert(
                    manifest.attempt_id.clone(),
                    pending.candidates.iter().cloned().collect(),
                );
                self.pending.insert(manifest.attempt_id.clone(), pending);
                Err(ModelError::ManualFallbackPending {
                    attempt_id: manifest.attempt_id.clone(),
                    purpose: admission.purpose.clone(),
                })
            }
            FallbackAssign::Auto { chain } => {
                // An entered unknown outcome ends the walk before an entry
                // is consulted: a substitute could duplicate an effect the
                // peer may already have applied. Only a definitive denial
                // may walk, and the retry marker routes that decision; the
                // caller meets the failure's own class. `manual` still
                // pauses: the human, not the chain, decides what a second
                // request would repeat.
                if provider_outcome_unknown(&source) {
                    let (_, source) = source.settle();
                    return Err(ModelError::Provider(source));
                }
                let mut rejected = Vec::new();
                let mut attempted = Vec::new();
                for entry in chain {
                    // A failed send to a contract that forbids a blind
                    // same-backend retry never re-dispatches onto a
                    // sibling literal of that contract: every failed
                    // connection in the walk is a refusal source, so an
                    // alias cannot slip past after its canonical entry
                    // failed. The contract gate stays ahead of
                    // eligibility so a sibling literal is refused for
                    // the right reason.
                    let blind_refused = std::iter::once(admission.connection.as_str())
                        .chain(attempted.iter().map(String::as_str))
                        .any(|failed| providers::blind_retry_refused(failed, &entry.connection));
                    if blind_refused {
                        rejected.push(CandidateRejection {
                            connection: entry.connection.clone(),
                            cause: RejectionCause::BlindRetryRefused,
                        });
                        continue;
                    }
                    if let Some(cause) =
                        self.candidate_rejection(&admission.purpose, &entry.connection)
                    {
                        rejected.push(CandidateRejection {
                            connection: entry.connection.clone(),
                            cause,
                        });
                        continue;
                    }
                    let model = ModelAssign::Fixed(FixedModel {
                        connection: entry.connection.clone(),
                        model_id: entry.model_id.clone(),
                    });
                    let (fallback_manifest, displaced) =
                        self.mint_substitute(admission, model, &entry.connection, "fallback");
                    attempted.push(entry.connection.clone());
                    match self.complete_send(
                        ledger,
                        &fallback_manifest,
                        &entry.connection,
                        Some(&manifest.attempt_id),
                    ) {
                        Ok(reply) => {
                            // The substitute answered the intent: the
                            // failed primary's admission is spent with
                            // it, so neither id can replay.
                            self.admissions.remove(&manifest.attempt_id);
                            return Ok(reply);
                        }
                        // A ledger refusal ends the walk: the entry never
                        // entered a send, so the chain gains nothing by
                        // trying the next one.
                        Err(SendFailure::Ledger(source)) => {
                            self.abandon_substitute(
                                &fallback_manifest.attempt_id,
                                &admission.purpose,
                                displaced,
                            );
                            return Err(ledger_refusal(source));
                        }
                        Err(SendFailure::Provider(send_error)) => {
                            self.abandon_substitute(
                                &fallback_manifest.attempt_id,
                                &admission.purpose,
                                displaced,
                            );
                            // An entered unknown outcome ends the walk
                            // exactly as it ends the primary: a later entry
                            // could duplicate an effect this one may already
                            // have applied. The retry marker routes the
                            // decision; the caller meets the inner class.
                            if provider_outcome_unknown(&send_error) {
                                let (_, send_error) = send_error.settle();
                                return Err(ModelError::Provider(send_error));
                            }
                            rejected.push(CandidateRejection {
                                connection: entry.connection.clone(),
                                cause: RejectionCause::SendFailed(send_error),
                            });
                        }
                    }
                }
                Err(ModelError::FallbackExhausted {
                    attempt_id: manifest.attempt_id.clone(),
                    purpose: admission.purpose.clone(),
                    rejected,
                    attempted,
                    source: Box::new(source),
                })
            }
        }
    }

    /// Mints one substitute manifest and admission for a failed or
    /// paused attempt: the frozen manifest supplies the task data
    /// byte-for-byte, the substitute sends under its own fresh attempt
    /// id on the picked connection, and `leg` names the fallback leg on
    /// the child admission's source label. The epoch mint is
    /// provisional until the send lands — the returned displaced entry
    /// is what [`Broker::restore_epoch`] rolls back on a failed send,
    /// so the walk never leaves a phantom model-switch epoch behind a
    /// request that went nowhere.
    fn mint_substitute(
        &mut self,
        admission: &AdmissionRecord,
        model: ModelAssign,
        connection: &str,
        leg: &str,
    ) -> (RequestManifest, Option<EpochState>) {
        let displaced = self.epochs.get(&admission.purpose).cloned();
        let (epoch_id, epoch_cost) = self.context_epoch(
            &admission.purpose,
            &model,
            &admission.manifest.instructions,
            &admission.manifest.tools,
        );
        let model_id = match &model {
            ModelAssign::Fixed(fixed) => Some(fixed.model_id.clone()),
            _ => None,
        };
        let substitute = RequestManifest {
            attempt_id: crate::contracts::AttemptId::generate().0,
            model,
            epoch_id,
            mutation_reason: epoch_cost.map(|cost| cost.reason.to_string()),
            epoch_cost,
            ..admission.manifest.clone()
        };
        self.admissions.insert(
            substitute.attempt_id.clone(),
            AdmissionRecord {
                purpose: admission.purpose.clone(),
                connection: connection.to_string(),
                model_id,
                model_source: format!("{}.{leg}", admission.fallback_source),
                // No ranking chose this connection: the substitute inherits
                // the failed primary's basis never, so its settlement records
                // an unknown basis rather than the primary's explanation.
                ranking_basis: None,
                snapshot_version: self.entitlements.version,
                manifest: substitute.clone(),
                // A substitute send never spawns its own fallback.
                fallback: FallbackAssign::Off,
                fallback_source: admission.fallback_source.clone(),
            },
        );
        (substitute, displaced)
    }

    /// Rolls a provisional epoch mint back after a substitute's send
    /// failed: the entry the mint displaced — or its absence — is
    /// restored so the failed send leaves no phantom epoch behind.
    fn restore_epoch(&mut self, purpose: &str, displaced: Option<EpochState>) {
        match displaced {
            Some(previous) => {
                self.epochs.insert(purpose.to_string(), previous);
            }
            None => {
                self.epochs.remove(purpose);
            }
        }
    }

    /// The attempt is spent and its admission is dead weight: prune it
    /// — a later replay still answers through the accounting map.
    fn clear_attempt(&mut self, attempt_id: &str) {
        self.admissions.remove(attempt_id);
        self.pending.remove(attempt_id);
        self.paused.remove(attempt_id);
    }

    /// A failed substitute send abandons the minted attempt: the
    /// minted manifest never leaves the dispatch scope, so its unspent
    /// admission is dead weight — prune it — and the provisional epoch
    /// mint rolls back to the entry the failed send displaced, so no
    /// phantom epoch outlives a request that went nowhere. A substitute
    /// id provably carries no `pending`/`paused` pins —
    /// [`Broker::mint_substitute`] writes only `admissions` — so
    /// pruning the admission alone is complete.
    fn abandon_substitute(
        &mut self,
        attempt_id: &str,
        purpose: &str,
        displaced: Option<EpochState>,
    ) {
        self.admissions.remove(attempt_id);
        self.restore_epoch(purpose, displaced);
    }

    /// The dispatch-time candidate check (AC-045b): the same gates the
    /// ranking ran at prepare — catalogue presence, the offline
    /// live-grant rule, the account entitlement, the per-purpose
    /// `eligible` input — evaluated against the broker's CURRENT config
    /// view. A candidate failing any gate returns its typed cause and
    /// never receives the request.
    fn candidate_rejection(&self, purpose: &str, connection: &str) -> Option<RejectionCause> {
        let Some(entry) = self.view_connections.get(connection) else {
            return Some(RejectionCause::UnknownConnection);
        };
        if !providers::offline_usable(&self.view_connections, &self.view_profiles, connection) {
            return Some(RejectionCause::LiveGrantRequired { kind: entry.kind });
        }
        // An eligible candidate the injected adapter cannot serve is
        // skipped before the walk ever reaches a send — eligibility
        // and dialect are separate gates (AC-046).
        if !self.provider.serves(connection, entry) {
            // A reserved id reports the build truth — no installed
            // adapter serves the recorded dialect — while an
            // unreserved one is the adapter's own decline.
            return Some(match providers::dialect_for(connection) {
                Some(dialect) => RejectionCause::DialectUnserved { dialect },
                None => RejectionCause::DialectMismatch,
            });
        }
        entitlement_rejection(
            &self.entitlements,
            self.view_purposes.get(purpose),
            connection,
        )
    }

    /// The connections currently eligible for one purpose — the
    /// candidate list a manual fallback choice offers (AC-045).
    fn eligible_candidates(&self, purpose: &str) -> Vec<String> {
        self.view_connections
            .keys()
            .filter(|name| self.candidate_rejection(purpose, name).is_none())
            .cloned()
            .collect()
    }

    /// Explains the effort assignment one frozen manifest transmitted:
    /// the wire request carries it verbatim, and no provider data exists
    /// offline to confirm the applied level, so `confirmed` stays `None`
    /// (transmitted ≠ confirmed, EDGE-006).
    pub fn effort_explain(&self, manifest: &RequestManifest) -> EffortExplain {
        EffortExplain {
            transmitted: manifest.effort.clone(),
            confirmed: None,
        }
    }

    /// Explains the sent cost of one frozen manifest (EDGE-008,
    /// INV-022): the bound is what admission reserved; the confirmed
    /// units come from the provider's physical usage report on the
    /// accounted send — `None` while it reported none, so an unknown
    /// sent cost is retained at the bound, never released as zero.
    pub fn sent_cost_explain(&self, manifest: &RequestManifest) -> SentCostExplain {
        SentCostExplain {
            bound: manifest.cost_bound,
            confirmed: self
                .accounting
                .get(&manifest.attempt_id)
                .and_then(|record| record.usage.confirmed_total()),
        }
    }

    /// Resolves the context epoch for one prepare (AC-061
    /// contribution): the model-visible prefix — purpose, model
    /// assignment, instructions and tools — hashes to the epoch id; an
    /// unchanged prefix replays the previous epoch, a changed one opens
    /// a new epoch whose per-part digests name the reason the mutation
    /// happened and what it is expected to cost.
    fn context_epoch(
        &mut self,
        purpose: &str,
        model: &ModelAssign,
        instructions: &str,
        tools: &[String],
    ) -> (String, Option<EpochCost>) {
        let prefix = format!(
            "purpose:{purpose}\nmodel:{}\ninstructions:{instructions}\ntools:{}",
            model_wire_id(model),
            tools.join(", ")
        );
        let prefix_digest = hex(&Sha256::digest(prefix.as_bytes()));
        let epoch_id = format!("epoch-{}", &prefix_digest[..16]);
        let parts = EpochState {
            prefix_digest: prefix_digest.clone(),
            model_digest: hex(&Sha256::digest(model_wire_id(model).as_bytes())),
            instructions_digest: hex(&Sha256::digest(instructions.as_bytes())),
            tools_digest: hex(&Sha256::digest(tools.join(", ").as_bytes())),
        };
        let epoch_cost = match self.epochs.get(purpose) {
            Some(previous) if previous.prefix_digest == prefix_digest => None,
            Some(previous) => changed_part(previous, &parts)
                .map(|reason| epoch_cost(reason, instructions, model, tools)),
            None => None,
        };
        self.epochs.insert(purpose.to_string(), parts);
        (epoch_id, epoch_cost)
    }
}

/// Which envelope part a mutation replaced (AC-061): classified in wire
/// order, so the earliest changed part names the cause — a system change
/// stays a system change even when the model moved with it.
fn changed_part(previous: &EpochState, current: &EpochState) -> Option<EpochMutationReason> {
    if previous.instructions_digest != current.instructions_digest {
        return Some(EpochMutationReason::SystemChange);
    }
    if previous.model_digest != current.model_digest {
        return Some(EpochMutationReason::ModelSwitch);
    }
    if previous.tools_digest != current.tools_digest {
        return Some(EpochMutationReason::ToolsChange);
    }
    None
}

/// The recorded cost of one mutation (AC-061): the replaced part and the
/// envelope bytes rewritten from it on. A provider caches
/// [`wire_composition`]'s envelope as a prefix, so the replaced part and
/// every part the request re-sends after it are a cache miss while the
/// parts ahead of it still replay.
fn epoch_cost(
    reason: EpochMutationReason,
    instructions: &str,
    model: &ModelAssign,
    tools: &[String],
) -> EpochCost {
    let instructions_line = instructions.len() + 1;
    let model_line = format!("model: {}\n", model_wire_id(model)).len();
    let tools_line = format!("tools: {}\n", tools.join(", ")).len();
    let reserve = format!("output-reserve: {OUTPUT_RESERVE_BYTES}").len();
    let (replaced_part, expected_rewrite_bytes) = match reason {
        EpochMutationReason::SystemChange => (
            "instructions",
            instructions_line + model_line + tools_line + reserve,
        ),
        EpochMutationReason::ModelSwitch => ("model", model_line + tools_line + reserve),
        EpochMutationReason::ToolsChange => ("tools", tools_line + reserve),
    };
    EpochCost {
        reason,
        replaced_part,
        expected_rewrite_bytes,
    }
}

/// The closed surface set a risky task touches (AC-096, DEC-013). Risk is a
/// recorded fact from this set — never the request's length, never a purpose
/// or stage name.
pub(crate) const RISKY_SURFACES: [Surface; 6] = [
    Surface::Auth,
    Surface::PublicApi,
    Surface::Migration,
    Surface::Permissions,
    Surface::Secrets,
    Surface::Trust,
];

/// The task facts `auto` ranks on (AC-096, DEC-013). The controller builds the
/// recorded form from the task snapshot and its obligations and passes it
/// through [`Broker::prepare_with_facts`]; the entries that carry no task facts
/// pass [`RankingFacts::unknown`], and their ranking keeps the declared pool
/// order and records no basis.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RankingFacts {
    /// No task facts were recorded, so no task feature decides.
    #[default]
    Unknown,
    /// The facts one task snapshot supplies.
    Recorded(RecordedFacts),
}

impl RankingFacts {
    /// The facts a caller with no task snapshot passes.
    #[must_use]
    pub fn unknown() -> Self {
        Self::Unknown
    }

    fn recorded(&self) -> Option<&RecordedFacts> {
        match self {
            Self::Unknown => None,
            Self::Recorded(facts) => Some(facts),
        }
    }
}

/// The recorded task facts one ranking runs on (AC-096, DEC-013). The purpose
/// is the ranking call's own argument, so the facts never carry a second copy
/// of it; `surfaces` is `None` when the impact scan decided nothing — undecided,
/// never "no risky surface".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordedFacts {
    /// The decided surfaces, or `None` when the scan decided nothing.
    pub surfaces: Option<BTreeSet<Surface>>,
    /// The task's requested tool modality — not the declared tool surface.
    pub tools_required: bool,
    /// A conservative upper bound over the frozen inputs, in characters.
    pub context_tokens_estimate: u64,
    pub obligations: usize,
    pub criteria: usize,
    /// The units each scope of the chain still holds. A scope absent from the
    /// map recorded nothing and never reads as zero.
    pub remaining_units: BTreeMap<String, u64>,
    /// The task's scope chain, root first.
    pub scope_chain: Vec<String>,
}

impl RecordedFacts {
    /// The first scope of the chain that holds no remaining units, if any:
    /// the budget-feasibility gate the ranking runs before it ranks.
    fn exhausted_scope(&self) -> Option<&str> {
        self.scope_chain
            .iter()
            .map(String::as_str)
            .find(|scope| self.remaining_units.get(*scope) == Some(&0))
    }

    /// The first risky surface the task recorded, if any.
    fn risky_surface(&self) -> Option<Surface> {
        let surfaces = self.surfaces.as_ref()?;
        surfaces
            .iter()
            .copied()
            .find(|surface| RISKY_SURFACES.contains(surface))
    }
}

/// The one model/effort decision one prepare froze (AC-096): the chosen
/// connection, the recorded model id — a ranked model freezes
/// [`ModelAssign::Fixed`] — the effort the task facts chose, and the basis the
/// settlement records. A choice with no recorded model keeps the resolved
/// assignment and carries no model id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RankingChoice {
    pub connection: String,
    pub model_id: Option<String>,
    pub effort: Option<EffortLevel>,
    pub basis: Option<String>,
}

/// The level's position on the effort ladder, for the chooser's comparisons.
fn effort_rank(level: EffortLevel) -> u8 {
    match level {
        EffortLevel::Minimal => 0,
        EffortLevel::Low => 1,
        EffortLevel::Medium => 2,
        EffortLevel::High => 3,
        EffortLevel::Xhigh => 4,
    }
}

/// The smallest level the task facts require (DEC-013): a risky surface asks
/// for high, two or more obligations or three or more criteria for medium,
/// and everything else for low.
fn effort_floor(facts: &RecordedFacts, risky: bool) -> (EffortLevel, &'static str) {
    if risky {
        (EffortLevel::High, "the risky surface")
    } else if facts.obligations >= 2 {
        (EffortLevel::Medium, "two or more obligations")
    } else if facts.criteria >= 3 {
        (EffortLevel::Medium, "three or more criteria")
    } else {
        (EffortLevel::Low, "the default level")
    }
}

/// The effort one recorded candidate offers for the task facts: the smallest
/// recorded level satisfying the floor, else the highest recorded, else
/// nothing — an unrecorded candidate keeps the resolved assignment, and a
/// fixed pin or an inherited effort never moves.
fn ranked_effort(
    facts: &RecordedFacts,
    risky: bool,
    row: Option<&CatalogModel>,
    resolved: &EffortAssign,
) -> Option<(EffortLevel, &'static str)> {
    if !matches!(resolved, EffortAssign::Auto) {
        return None;
    }
    let recorded = &row?.efforts;
    let (floor, reason) = effort_floor(facts, risky);
    let chosen = recorded
        .iter()
        .copied()
        .filter(|level| effort_rank(*level) >= effort_rank(floor))
        .min_by_key(|level| effort_rank(*level))
        .or_else(|| {
            recorded
                .iter()
                .copied()
                .max_by_key(|level| effort_rank(*level))
        })?;
    Some((chosen, reason))
}

/// One candidate the recorded ranking weighs: a connection with one of its
/// recorded rows, or the unknown-fact candidate a connection with no recorded
/// row contributes.
struct RankedCandidate {
    connection: String,
    row: Option<CatalogModel>,
    /// The three-way facts in ranking order: capability match, context fit,
    /// price class. `0` is a known match, `1` unknown, `2` a known miss (the
    /// context class alone reaches `2`); a known price is `0` and an unknown
    /// price `1`, which is why an unknown price ranks last and never free.
    class: (u8, u8, u8),
    /// The stated full cost over the estimate; `None` is the unknown price.
    cost: Option<f64>,
    /// The candidate's position in the declared pool order.
    declaration: usize,
}

impl RankedCandidate {
    /// The candidate a connection with no recorded row contributes: every fact
    /// is unknown, distinct from a recorded miss.
    fn unknown(connection: &str, declaration: usize) -> Self {
        Self {
            connection: connection.to_string(),
            row: None,
            class: (1, 1, 1),
            cost: None,
            declaration,
        }
    }

    fn recorded(
        connection: &str,
        declaration: usize,
        row: CatalogModel,
        facts: &RecordedFacts,
        risky: bool,
    ) -> Self {
        let capability = if (risky && row.reasoning) || (facts.tools_required && row.tools) {
            0
        } else {
            1
        };
        let context = match row.context_window {
            Some(window) if window >= facts.context_tokens_estimate => 0,
            Some(_) => 2,
            None => 1,
        };
        let cost = row.price.full_cost(facts.context_tokens_estimate);
        let price = if cost.is_some() { 0 } else { 1 };
        Self {
            connection: connection.to_string(),
            row: Some(row),
            class: (capability, context, price),
            cost,
            declaration,
        }
    }

    /// The deterministic order: capability, context, price, then declaration
    /// order. The sort is stable, so two rows of one connection keep the order
    /// the registry records them in.
    fn order(left: &Self, right: &Self) -> Ordering {
        left.class
            .cmp(&right.class)
            .then_with(|| match (left.cost, right.cost) {
                (Some(left), Some(right)) => left.total_cmp(&right),
                _ => Ordering::Equal,
            })
            .then_with(|| left.declaration.cmp(&right.declaration))
    }

    /// `connection/model`, or the connection with its unrecorded model named
    /// as such.
    fn label(&self) -> String {
        match &self.row {
            Some(row) => format!("{}/{}", self.connection, row.id),
            None => format!("{}/unrecorded", self.connection),
        }
    }
}

/// Which recorded fact decided the pick over the best candidate of another
/// connection: the first ranking key the winner is better on, with the
/// recorded value that decided it. A tie on every key is the declared order.
fn deciding_criterion(
    winner: &RankedCandidate,
    runner_up: &RankedCandidate,
    facts: &RecordedFacts,
    risky: Option<Surface>,
) -> String {
    if winner.class.0 < runner_up.class.0 {
        if let Some(surface) = risky
            && winner.row.as_ref().is_some_and(|row| row.reasoning)
        {
            return format!(
                "a recorded reasoning fit for risky surface {surface}",
                surface = surface.as_str()
            );
        }
        return "a recorded tool modality".to_string();
    }
    if winner.class.1 < runner_up.class.1 {
        return match winner.class.1 {
            0 => format!(
                "a recorded context fit for {estimate} estimated characters",
                estimate = facts.context_tokens_estimate
            ),
            // The winner's window is unrecorded; that is the winner's own
            // recorded fact, not the runner-up's miss.
            _ => "an unrecorded context window".to_string(),
        };
    }
    if winner.class.2 < runner_up.class.2 {
        return "the cheapest known full cost, where an unknown price ranks last".to_string();
    }
    // Two stated prices: the cheaper one decides before declaration order, so
    // a cheaper candidate declared later is never explained as the pool order.
    if let (Some(left), Some(right)) = (winner.cost, runner_up.cost)
        && left < right
    {
        return format!(
            "the cheaper known full cost of {cost:.4} usd over {estimate} estimated characters",
            cost = left,
            estimate = facts.context_tokens_estimate,
        );
    }
    "the declared order".to_string()
}

/// The basis string one recorded ranking froze: the winner, the best candidate
/// of another connection it beat, the recorded fact that decided it, and the
/// effort the facts chose. It names recorded facts alone — no prompt length, no
/// stage name (PROH-019).
fn ranked_basis(
    winner: &RankedCandidate,
    runner_up: Option<&RankedCandidate>,
    facts: &RecordedFacts,
    risky: Option<Surface>,
    effort: Option<(EffortLevel, &'static str)>,
) -> String {
    let mut basis = format!("auto ranked {}", winner.label());
    match runner_up {
        Some(runner_up) => {
            basis.push_str(" over ");
            basis.push_str(&runner_up.label());
            basis.push_str(" by ");
            basis.push_str(&deciding_criterion(winner, runner_up, facts, risky));
        }
        None => basis.push_str(" as the only eligible connection"),
    }
    if let Some((level, reason)) = effort {
        basis.push_str("; effort ");
        basis.push_str(level.name());
        basis.push_str(" from ");
        basis.push_str(reason);
    }
    basis
}

/// Candidate enumeration and offline ranking for one assignment
/// (AC-044, AC-096): ineligible candidates are filtered out before ranking —
/// unknown to the catalogue, not usable without a separate live grant,
/// outside the account entitlement, the per-purpose `eligible` input or the
/// scope chain's remaining budget. With unknown facts the declared pool order
/// decides; with recorded facts the task's own features rank the recorded
/// catalogue rows, an unrecorded candidate stays an unknown fact, and a
/// recorded window below the estimate demotes rather than denies. An
/// assignment with no surviving candidate fails closed, and a fixed pin keeps
/// the precise typed rejection vocabulary of [`providers::offline_eligible`].
///
/// # Errors
///
/// Returns [`ModelError::Provider`] for an offline-ineligible fixed
/// pin and [`ModelError::NoEligibleCandidate`] when no candidate
/// survives the eligibility filter.
fn rank_connection(
    purpose: &str,
    resolved: &crate::config::ResolvedPurpose,
    purpose_def: Option<&PurposeDef>,
    connections: &BTreeMap<String, Connection>,
    profiles: &BTreeMap<String, Profile>,
    entitlements: &Entitlements,
    facts: &RankingFacts,
) -> Result<RankingChoice, ModelError> {
    match &resolved.model {
        ModelAssign::Fixed(fixed) => {
            providers::offline_eligible(&resolved.model, connections, profiles)?;
            // `offline_eligible` already answered the catalogue and
            // live-grant gates, so only the entitlement tail can refuse
            // a fixed pin here.
            if let Some(cause) = entitlement_rejection(entitlements, purpose_def, &fixed.connection)
            {
                return Err(ModelError::NoEligibleCandidate {
                    purpose: purpose.to_string(),
                    rejected: vec![CandidateRejection {
                        connection: fixed.connection.clone(),
                        cause,
                    }],
                });
            }
            Ok(RankingChoice {
                connection: fixed.connection.clone(),
                model_id: Some(fixed.model_id.clone()),
                effort: None,
                basis: None,
            })
        }
        ModelAssign::Auto { pool } => {
            // the purpose-level pool is the more specific file-only
            // surface; the assignment pool is its inline twin
            let declared = purpose_def
                .and_then(|def| def.pool.as_deref())
                .or(pool.as_deref());
            let candidates: Vec<String> = match declared {
                Some(pool) => pool.to_vec(),
                None => connections.keys().cloned().collect(),
            };
            let recorded = facts.recorded();
            // The budget-feasibility gate precedes ranking: a scope with no
            // remaining units can fund no bound, so no candidate of this
            // request is feasible. The refusal is the same typed waiting
            // signal `begin_send` raises, so the caller records one waiting
            // reason instead of a candidate list; the exact bound is still
            // re-checked by the send.
            if let Some(scope) = recorded.and_then(RecordedFacts::exhausted_scope) {
                return Err(ModelError::BudgetExhausted {
                    scope: scope.to_string(),
                });
            }
            let mut rejected = Vec::new();
            let mut feasible = Vec::new();
            for name in candidates {
                if let Some(cause) =
                    rank_rejection(connections, profiles, entitlements, purpose_def, &name)
                {
                    rejected.push(CandidateRejection {
                        connection: name,
                        cause,
                    });
                    continue;
                }
                feasible.push(name);
            }
            let Some(recorded) = recorded else {
                // Unknown facts decide nothing: the declared pool order is
                // the recorded preference, and no basis claims otherwise.
                return match feasible.into_iter().next() {
                    Some(connection) => Ok(RankingChoice {
                        connection,
                        model_id: None,
                        effort: None,
                        basis: None,
                    }),
                    None => Err(ModelError::NoEligibleCandidate {
                        purpose: purpose.to_string(),
                        rejected,
                    }),
                };
            };
            rank_recorded(purpose, &feasible, recorded, &rejected, &resolved.effort)
        }
        // an inherit that survived resolution names no connection and
        // declares no pool: it has no candidate and fails closed
        ModelAssign::Inherit => Err(ModelError::NoEligibleCandidate {
            purpose: purpose.to_string(),
            rejected: Vec::new(),
        }),
    }
}

/// The recorded-fact ranking over the feasible connections (AC-096): every
/// connection contributes its recorded rows, or one unknown-fact candidate
/// when it records none; the deterministic order picks the winner, the effort
/// chooser sets the level for a single candidate or many, and the basis names
/// what decided.
fn rank_recorded(
    purpose: &str,
    feasible: &[String],
    facts: &RecordedFacts,
    rejected: &[CandidateRejection],
    resolved_effort: &EffortAssign,
) -> Result<RankingChoice, ModelError> {
    let risky = facts.risky_surface();
    let mut ranked = Vec::new();
    for (declaration, connection) in feasible.iter().enumerate() {
        let rows = providers::recorded_models(connection);
        if rows.is_empty() {
            ranked.push(RankedCandidate::unknown(connection, declaration));
        } else {
            for row in rows {
                ranked.push(RankedCandidate::recorded(
                    connection,
                    declaration,
                    row,
                    facts,
                    risky.is_some(),
                ));
            }
        }
    }
    if ranked.is_empty() {
        return Err(ModelError::NoEligibleCandidate {
            purpose: purpose.to_string(),
            rejected: rejected.to_vec(),
        });
    }
    ranked.sort_by(RankedCandidate::order);
    let winner = &ranked[0];
    // The basis names the best candidate of another connection: the model
    // ordering inside the winner's own connection is the registry's, not a
    // second choosing basis.
    let runner_up = ranked
        .iter()
        .find(|candidate| candidate.connection != winner.connection);
    let effort = ranked_effort(facts, risky.is_some(), winner.row.as_ref(), resolved_effort);
    Ok(RankingChoice {
        connection: winner.connection.clone(),
        model_id: winner.row.as_ref().map(|row| row.id.clone()),
        effort: effort.map(|(level, _reason)| level),
        basis: Some(ranked_basis(winner, runner_up, facts, risky, effort)),
    })
}

/// The prepare-time twin of [`Broker::candidate_rejection`] minus the
/// dialect `serves` gate (AC-046 keeps eligibility and dialect
/// separate): a candidate's refusal cause — undeclared, live-grant
/// gated or entitlement denied — in the same gate order.
fn rank_rejection(
    connections: &BTreeMap<String, Connection>,
    profiles: &BTreeMap<String, Profile>,
    entitlements: &Entitlements,
    purpose_def: Option<&PurposeDef>,
    connection: &str,
) -> Option<RejectionCause> {
    let Some(entry) = connections.get(connection) else {
        return Some(RejectionCause::UnknownConnection);
    };
    if !providers::offline_usable(connections, profiles, connection) {
        return Some(RejectionCause::LiveGrantRequired { kind: entry.kind });
    }
    entitlement_rejection(entitlements, purpose_def, connection)
}

/// The entitlement gates as a typed cause: the account's rights first,
/// then the per-purpose `eligible` input — the tail
/// [`Broker::candidate_rejection`] and [`rank_rejection`] share.
fn entitlement_rejection(
    entitlements: &Entitlements,
    purpose_def: Option<&PurposeDef>,
    connection: &str,
) -> Option<RejectionCause> {
    if !entitlements.allows(connection) {
        return Some(RejectionCause::NotEntitled);
    }
    if !purpose_entitled(purpose_def, connection) {
        return Some(RejectionCause::NotPurposeEligible);
    }
    None
}

/// The per-purpose `eligible` input (DEC-012): `None` restricts
/// nothing; a declared list admits only its members.
fn purpose_entitled(purpose_def: Option<&PurposeDef>, connection: &str) -> bool {
    purpose_def
        .and_then(|def| def.eligible.as_deref())
        .is_none_or(|list| list.iter().any(|name| name == connection))
}

/// The scope chain one instruction root is discovered over (AC-076): the
/// root's own ancestors, outermost first — the order
/// [`InstructionSet::discover`] takes, so an inner scope still wins its slot
/// over an outer one.
fn instruction_scopes(root: &Path) -> Vec<PathBuf> {
    let mut scopes: Vec<PathBuf> = root.ancestors().map(Path::to_path_buf).collect();
    scopes.reverse();
    scopes
}

/// The single wire composition shared by freeze and dispatch (AC-013):
/// the manifest's `wire_bytes` and the prepare-time limit accounting
/// are the same function, so the sent bytes can never diverge from the
/// accounted size. The body names its model, like every live provider
/// dialect, so a model switch is visible in the wire prefix.
fn wire_composition(
    instructions: &str,
    model: &ModelAssign,
    tools: &[String],
    output_reserve: usize,
    inputs: &str,
) -> String {
    format!(
        "{instructions}\nmodel: {}\ntools: {}\noutput-reserve: {output_reserve}\n\n{inputs}",
        model_wire_id(model),
        tools.join(", ")
    )
}

/// Deterministic identity of one model assignment inside the
/// model-visible prefix: two resolves hash equal only when the
/// effective assignment is the same.
fn model_wire_id(model: &ModelAssign) -> String {
    match model {
        ModelAssign::Inherit => "inherit".to_string(),
        ModelAssign::Auto { pool } => match pool {
            None => "auto".to_string(),
            Some(names) => format!("auto:{}", names.join("+")),
        },
        ModelAssign::Fixed(fixed) => format!("fixed:{}/{}", fixed.connection, fixed.model_id),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    crate::config::hex(bytes)
}

/// Interim offline cost bound: one unit per slice of transmitted
/// input plus one for the request itself. Priced bounds arrive with
/// live provider dialects; until then admission still needs a finite,
/// deterministic number frozen on the manifest.
const BUDGET_UNIT_INPUT_BYTES: usize = 4096;

/// The deterministic offline dispatch-cost bound (INV-022).
fn sent_cost_bound(inputs: &str) -> u64 {
    // usize widens to u64 losslessly below 2^64 input bytes; the
    // saturating ceiling is unreachable in practice and stays finite.
    1 + u64::try_from(inputs.len().div_ceil(BUDGET_UNIT_INPUT_BYTES)).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Defense-in-depth probe for the dispatch re-check (AC-044): the
    /// version bump on every rights movement is the primary guard and a
    /// same-version rights drift is unreachable through
    /// [`Broker::set_account_rights`], so this leg holds the private
    /// snapshot directly and proves the `allows` conjunct still blocks
    /// the send alone.
    #[test]
    fn dispatch_blocks_a_same_version_rights_drift_on_allows_alone()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::parse_validated(
            "config_version = 1\n\
             [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
             [models.defaults]\n\
             model = { mode = \"fixed\", connection = \"local\", model_id = \"fixture-model\" }\n\
             effort = { mode = \"auto\" }\n\
             fallback = { mode = \"auto\" }\n",
        )?;
        let mut broker = Broker::new(Box::new(providers::LoopbackProvider::new()));
        let manifest = broker.prepare("main", &config, "/world/drift", "goal: fixture")?;
        // rights content changed while the version stayed frozen: only
        // the direct allows re-evaluation can still block the send
        broker.entitlements.rights = Some(BTreeSet::from(["reserve".to_string()]));
        match broker.dispatch(&mut NullLedger, "/world/drift", &manifest) {
            Err(ModelError::EligibilityStale {
                connection,
                frozen: 0,
                current: 0,
                ..
            }) => assert_eq!(connection, "local"),
            Err(other) => return Err(other.into()),
            Ok(reply) => {
                return Err(format!("the drifted dispatch must not send: {reply:?}").into());
            }
        }
        Ok(())
    }

    /// The request-failure class is definitive only when the retained
    /// source proves the client never handed bytes to the wire: a builder
    /// or connect error. The rest of the class table stays unknown — a
    /// send or response-head failure may follow a partially applied
    /// request.
    #[test]
    fn transport_outcome_verdicts_follow_the_retained_source()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::providers::{ProviderError as Provider, TransportCause};
        use std::io::ErrorKind;
        use std::sync::Arc;
        use std::time::Duration;

        let client = reqwest::blocking::Client::builder().no_proxy().build()?;
        let builder = client
            .get("ftp://127.0.0.1/fixture")
            .send()
            .err()
            .ok_or("the unsupported scheme must fail")?;
        assert!(builder.is_builder(), "the fixture carries a builder error");

        let reserved = std::net::TcpListener::bind("127.0.0.1:0")?;
        let closed = reserved.local_addr()?;
        drop(reserved);
        let connect = client
            .get(format!("http://{closed}/fixture"))
            .send()
            .err()
            .ok_or("the closed port must fail")?;
        assert!(connect.is_connect(), "the fixture carries a connect error");

        let request = peer_request_error()?;
        assert!(
            request.is_request()
                && !request.is_connect()
                && !request.is_timeout()
                && !request.is_builder(),
            "the fixture carries a non-connect request failure: {request}"
        );

        let transport = |cause| Provider::Transport {
            connection: "local".to_string(),
            cause,
        };
        let cases = [
            (
                "deadline",
                transport(TransportCause::Deadline {
                    budget: Duration::from_millis(1),
                }),
                true,
            ),
            (
                "timeout",
                transport(TransportCause::Read {
                    source: Arc::new(std::io::Error::new(ErrorKind::TimedOut, "fixture")),
                }),
                true,
            ),
            (
                "read failure",
                transport(TransportCause::Read {
                    source: Arc::new(std::io::Error::other("fixture")),
                }),
                true,
            ),
            (
                "status 500",
                transport(TransportCause::Status {
                    status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                }),
                true,
            ),
            (
                "status 503",
                transport(TransportCause::Status {
                    status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
                }),
                true,
            ),
            (
                "status 408",
                transport(TransportCause::Status {
                    status: reqwest::StatusCode::REQUEST_TIMEOUT,
                }),
                true,
            ),
            (
                "status 425",
                transport(TransportCause::Status {
                    status: reqwest::StatusCode::TOO_EARLY,
                }),
                true,
            ),
            (
                "redirect",
                transport(TransportCause::Status {
                    status: reqwest::StatusCode::MOVED_PERMANENTLY,
                }),
                true,
            ),
            (
                "status 400",
                transport(TransportCause::Status {
                    status: reqwest::StatusCode::BAD_REQUEST,
                }),
                false,
            ),
            (
                "status 401",
                transport(TransportCause::Status {
                    status: reqwest::StatusCode::UNAUTHORIZED,
                }),
                false,
            ),
            (
                "builder",
                transport(TransportCause::Request {
                    source: Arc::new(builder),
                }),
                false,
            ),
            (
                "connect",
                transport(TransportCause::Request {
                    source: Arc::new(connect),
                }),
                false,
            ),
            (
                "request failure",
                transport(TransportCause::Request {
                    source: Arc::new(request),
                }),
                true,
            ),
            (
                "retried",
                Provider::Retried {
                    wire_retries: 1,
                    source: Box::new(transport(TransportCause::Status {
                        status: reqwest::StatusCode::BAD_REQUEST,
                    })),
                },
                true,
            ),
            (
                // Adapters emit this after the response has started, so
                // its effect may already have applied.
                "provider failed",
                Provider::ProviderFailed {
                    connection: "local".to_string(),
                    reason: "terminal incomplete".to_string(),
                },
                true,
            ),
            (
                // A malformed stream follows a partially applied request.
                "stream violation",
                Provider::StreamViolation {
                    connection: "local".to_string(),
                    reason: "stream ended mid output item".to_string(),
                },
                true,
            ),
            (
                // Raised before the post: no byte crossed, so a
                // substitute cannot repeat an effect.
                "unsendable request",
                Provider::UnsendableRequest {
                    connection: "local".to_string(),
                    reason: format!(
                        "request body of {} bytes exceeds the {} byte wire bound",
                        crate::contracts::MODEL_WIRE_MAX_BYTES + 1,
                        crate::contracts::MODEL_WIRE_MAX_BYTES
                    ),
                },
                false,
            ),
        ];
        for (name, error, unknown) in cases {
            assert_eq!(
                provider_outcome_unknown(&error),
                unknown,
                "the {name} verdict"
            );
        }
        Ok(())
    }

    /// One genuine non-connect request error: a loopback peer answers
    /// bytes the HTTP client cannot accept as a response head.
    fn peer_request_error() -> Result<reqwest::Error, Box<dyn std::error::Error>> {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let error = std::thread::scope(|scope| -> std::io::Result<reqwest::Error> {
            let peer = scope.spawn(move || -> std::io::Result<()> {
                let (mut stream, _) = listener.accept()?;
                let mut headers = Vec::new();
                let mut chunk = [0u8; 512];
                while !headers.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let count = stream.read(&mut chunk)?;
                    if count == 0 {
                        return Err(std::io::Error::other("fixture request truncated"));
                    }
                    headers.extend_from_slice(&chunk[..count]);
                }
                stream.write_all(b"invalid-http\r\n\r\n")
            });
            let error = reqwest::blocking::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_secs(2))
                .build()
                .map_err(std::io::Error::other)?
                .get(format!("http://{address}/fixture"))
                .send()
                .err();
            peer.join().map_err(|panic| {
                let detail = panic
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("unknown payload");
                std::io::Error::other(format!("fixture peer panicked: {detail}"))
            })??;
            error.ok_or_else(|| std::io::Error::other("the malformed response decoded"))
        })?;
        Ok(error)
    }
}
