//! Learned definitions (AC-051, REQ-041): the typed change a verified delta
//! contributes — instruction text for one assembled request part or an
//! applicability override for one catalog capability — the pure evaluation
//! both seams run, and the corpus verdict that gates activation.
//!
//! This module holds types and pure functions only (P-002): the store owns
//! every statement and every state transition. A learned condition is data,
//! and the code that owns each fact evaluates it (INV-009), so neither the
//! instruction assembly nor the selection calls a model to decide whether a
//! delta applies. The fact vocabulary is closed by its owner: the broker
//! knows a purpose, the selection knows the request kind and the decided
//! surfaces, and a condition written in a fact its own scope cannot read is
//! refused rather than silently never holding.

use crate::actions::{RequestKind, Surface, weighed_capability};
use crate::contracts::ErrorCode;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The most instruction text one delta may add. The assembled part is a
/// model-visible prefix the mandatory parts must always fit beside, so a
/// learned body is bounded before it can displace them.
pub const DELTA_INSTRUCTION_MAX_BYTES: usize = 2 * 1024;

/// The largest assembled instruction part a definition may reach, measured
/// from the longest instruction base an assembly site assembles onto. It is
/// smaller than two maximal deltas so that composition is a real check rather
/// than a formality: a delta that would push the composed part past this bound
/// never activates, and the next request always carries an instruction part
/// that fits beside the mandatory wire parts.
pub const DEFINITION_MAX_BYTES: usize = 3 * 1024;

/// How many corpus cases one candidate may carry: one per case kind.
pub const CORPUS_CASE_LIMIT: usize = 3;

/// The credential-reference prefix a learned body may never carry (INV-011).
/// A delta body is instruction or condition text, never a place a secret
/// reference may enter learned state.
pub const CREDENTIAL_REFERENCE: &str = "keyring:";

/// Which part of the effective definition one delta changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaScope {
    /// Text the assembled instruction part carries.
    Instruction,
    /// One capability's applicability in the selection.
    Applicability,
}

impl std::fmt::Display for DeltaScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl DeltaScope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Instruction => "instruction",
            Self::Applicability => "applicability",
        }
    }

    /// The scope a stored row names, `None` outside the vocabulary.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "instruction" => Some(Self::Instruction),
            "applicability" => Some(Self::Applicability),
            _ => None,
        }
    }
}

/// Whether a delta composes the effective definition or has stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaState {
    /// Recorded and judged by nothing yet, or judged and refused: only an
    /// inactive delta can activate.
    Inactive,
    /// Composing the effective definition.
    Active,
    /// Activated once and withdrawn: its own effect is gone, the record and
    /// every other delta stay.
    RolledBack,
}

impl DeltaState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inactive => "inactive",
            Self::Active => "active",
            Self::RolledBack => "rolled_back",
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "inactive" => Some(Self::Inactive),
            "active" => Some(Self::Active),
            "rolled_back" => Some(Self::RolledBack),
            _ => None,
        }
    }
}

impl std::fmt::Display for DeltaState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a learned applicability condition does to the capability it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateEffect {
    /// The capability is required whenever the condition holds, even where
    /// the request facts alone declined it.
    Require,
    /// The capability is not needed whenever the condition holds, even where
    /// the request facts alone required it.
    Decline,
}

impl PredicateEffect {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Require => "require",
            Self::Decline => "decline",
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "require" => Some(Self::Require),
            "decline" => Some(Self::Decline),
            _ => None,
        }
    }
}

/// One typed fact a learned condition may read. The vocabulary is closed and
/// each variant belongs to exactly one evaluation site: a purpose is what the
/// broker knows when it assembles a request part, and the kind and surfaces
/// are what the selection knows when it weighs capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "fact", content = "value")]
pub enum ConditionFact {
    /// The purpose whose request part is being assembled.
    Purpose(String),
    /// The request kind the selection was asked for.
    Kind(RequestKind),
    /// One surface the impact scan decided.
    Surface(Surface),
}

impl ConditionFact {
    /// The fact's vocabulary name — the stored form and the error text.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Purpose(_) => "purpose",
            Self::Kind(_) => "kind",
            Self::Surface(_) => "surface",
        }
    }

    /// Whether this fact holds for the given request facts. A fact the given
    /// evaluation site does not carry never holds, so a condition written in
    /// the wrong vocabulary declines instead of matching everything.
    #[must_use]
    pub fn holds(&self, facts: &ConditionFacts) -> bool {
        match self {
            Self::Purpose(purpose) => facts.purpose.as_deref() == Some(purpose.as_str()),
            Self::Kind(kind) => facts.kind == Some(*kind),
            Self::Surface(surface) => facts
                .surfaces
                .as_ref()
                .is_some_and(|decided| decided.contains(surface)),
        }
    }
}

/// The request facts one evaluation site hands a learned condition. The
/// constructors are the only way to build it, so a site can supply exactly
/// the facts it owns and never a fact it guessed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionFacts {
    purpose: Option<String>,
    kind: Option<RequestKind>,
    surfaces: Option<BTreeSet<Surface>>,
}

impl ConditionFacts {
    /// The facts available where a request part is assembled.
    #[must_use]
    pub fn for_purpose(purpose: &str) -> Self {
        Self {
            purpose: Some(purpose.to_string()),
            kind: None,
            surfaces: None,
        }
    }

    /// The facts available where the selection weighs capabilities. An
    /// undecided surface scan is `None`: a surface condition stays undecided
    /// rather than reading as "no such surface".
    #[must_use]
    pub fn for_selection(kind: RequestKind, surfaces: Option<BTreeSet<Surface>>) -> Self {
        Self {
            purpose: None,
            kind: Some(kind),
            surfaces,
        }
    }
}

/// What one delta changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaPayload {
    /// Instruction text appended to one purpose's assembled part.
    Instruction { text: String },
    /// One capability's applicability in the selection.
    Applicability {
        capability: String,
        effect: PredicateEffect,
    },
}

impl DeltaPayload {
    #[must_use]
    pub fn scope(&self) -> DeltaScope {
        match self {
            Self::Instruction { .. } => DeltaScope::Instruction,
            Self::Applicability { .. } => DeltaScope::Applicability,
        }
    }
}

/// One candidate change and the fact that must hold for it to apply.
///
/// An instruction may omit its condition (it then applies to every purpose);
/// a capability override may not, because an unconditional override would be
/// a policy change rather than a learned experience.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaChange {
    pub payload: DeltaPayload,
    pub when: Option<ConditionFact>,
}

impl DeltaChange {
    /// The instruction text this change contributes, when it carries one.
    #[must_use]
    pub fn instruction(&self) -> Option<&str> {
        match &self.payload {
            DeltaPayload::Instruction { text } => Some(text),
            DeltaPayload::Applicability { .. } => None,
        }
    }

    #[must_use]
    pub fn scope(&self) -> DeltaScope {
        self.payload.scope()
    }

    /// Whether this change applies to a request whose facts are `facts`.
    #[must_use]
    pub fn applies(&self, facts: &ConditionFacts) -> bool {
        self.when
            .as_ref()
            .is_none_or(|condition| condition.holds(facts))
    }

    /// The typed refusals of one candidate, checked before any row lands:
    /// a refused body is never stored (INV-011) and a condition its own
    /// scope cannot evaluate is never recorded as a silent no-op.
    ///
    /// # Errors
    ///
    /// Returns the first [`DeltaError`] the candidate violates.
    pub fn validate(&self, delta_id: &str) -> Result<(), DeltaError> {
        match &self.payload {
            DeltaPayload::Instruction { text } => {
                if text.trim().is_empty() {
                    return Err(DeltaError::EmptyBody {
                        delta_id: delta_id.to_string(),
                    });
                }
                if text.len() > DELTA_INSTRUCTION_MAX_BYTES {
                    return Err(DeltaError::TooLarge {
                        delta_id: delta_id.to_string(),
                        size: text.len(),
                        limit: DELTA_INSTRUCTION_MAX_BYTES,
                    });
                }
                if carries_credential_reference(text) {
                    return Err(DeltaError::CredentialReference {
                        delta_id: delta_id.to_string(),
                    });
                }
                match &self.when {
                    None => Ok(()),
                    Some(ConditionFact::Purpose(purpose)) if !purpose.trim().is_empty() => Ok(()),
                    Some(ConditionFact::Purpose(_)) => Err(DeltaError::EmptyPurpose {
                        delta_id: delta_id.to_string(),
                    }),
                    Some(fact) => Err(DeltaError::OutOfScope {
                        delta_id: delta_id.to_string(),
                        scope: DeltaScope::Instruction,
                        fact: fact.as_str(),
                    }),
                }
            }
            DeltaPayload::Applicability { capability, .. } => {
                if !weighed_capability(capability) {
                    return Err(DeltaError::UnknownCapability {
                        delta_id: delta_id.to_string(),
                        capability: capability.clone(),
                    });
                }
                match &self.when {
                    Some(ConditionFact::Kind(_) | ConditionFact::Surface(_)) => Ok(()),
                    Some(fact) => Err(DeltaError::OutOfScope {
                        delta_id: delta_id.to_string(),
                        scope: DeltaScope::Applicability,
                        fact: fact.as_str(),
                    }),
                    None => Err(DeltaError::Unconditional {
                        delta_id: delta_id.to_string(),
                    }),
                }
            }
        }
    }
}

/// One recorded delta: its stable id, the version its state transition last
/// wrote, and the change it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearningDelta {
    pub delta_id: String,
    pub version: u64,
    pub change: DeltaChange,
}

impl LearningDelta {
    /// The bytes this delta appends to an assembled part it applies to: the
    /// separator [`LearningDefinition::instruction_part`] writes plus its own
    /// text. `None` for an applicability delta, which composes no text at all.
    fn appended_bytes(&self) -> Option<usize> {
        self.change.instruction().map(|text| text.len() + 1)
    }
}

/// The effective definition the two seams compose from the active deltas, in
/// the order the store records them. A definition is a value: the broker
/// holds the one its next request carries and the selection reads the store's
/// own, so neither seam re-derives an ordering.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LearningDefinition {
    deltas: Vec<LearningDelta>,
}

impl LearningDefinition {
    #[must_use]
    pub fn new(deltas: Vec<LearningDelta>) -> Self {
        Self { deltas }
    }

    #[must_use]
    pub fn deltas(&self) -> &[LearningDelta] {
        &self.deltas
    }

    /// The definition `delta` would compose into, in the store's order.
    #[must_use]
    pub fn composed_with(&self, delta: &LearningDelta) -> Self {
        let mut deltas = self.deltas.clone();
        deltas.push(delta.clone());
        Self { deltas }
    }

    /// The assembled instruction part one purpose's request carries: the base
    /// part with every instruction delta whose condition holds appended in the
    /// store's order. An unchanged definition assembles the same bytes, so a
    /// replay keeps its context epoch (EDGE-008).
    #[must_use]
    pub fn instruction_part(&self, purpose: &str, base: &str) -> String {
        let facts = ConditionFacts::for_purpose(purpose);
        let mut part = base.to_string();
        for delta in &self.deltas {
            let Some(text) = delta.change.instruction() else {
                continue;
            };
            if !delta.change.applies(&facts) {
                continue;
            }
            part.push('\n');
            part.push_str(text);
        }
        part
    }

    /// The largest assembled instruction part this definition can produce
    /// beside `base`: the base part, every unconditional delta, and the
    /// heaviest set of purpose-conditioned deltas one purpose would carry.
    ///
    /// The maximum is exact and finite — an instruction delta applies only to
    /// the purpose its condition names, and a purpose no delta names carries
    /// the unconditional deltas alone — so a bound checked here holds for
    /// every request this definition composes, whatever purpose it is for.
    #[must_use]
    pub fn max_instruction_bytes(&self, base: &str) -> usize {
        let mut heaviest_by_purpose: BTreeMap<&str, usize> = BTreeMap::new();
        let mut unconditional = 0;
        for delta in &self.deltas {
            let Some(appended) = delta.appended_bytes() else {
                continue;
            };
            match &delta.change.when {
                Some(ConditionFact::Purpose(purpose)) => {
                    *heaviest_by_purpose.entry(purpose.as_str()).or_default() += appended;
                }
                // An instruction delta's own scope reads a purpose or nothing
                // (`DeltaChange::validate`): any other fact never holds where
                // a part is assembled, so it composes nothing.
                Some(_) => {}
                None => unconditional += appended,
            }
        }
        base.len() + unconditional + heaviest_by_purpose.values().copied().max().unwrap_or(0)
    }

    /// The learned effect on one capability for one request, or `None` when
    /// no active condition speaks to it. The last recorded delta wins, so the
    /// answer is deterministic and never depends on iteration order.
    #[must_use]
    pub fn applicability(
        &self,
        capability: &str,
        facts: &ConditionFacts,
    ) -> Option<PredicateEffect> {
        let mut effect = None;
        for delta in &self.deltas {
            let DeltaPayload::Applicability {
                capability: named,
                effect: decided,
            } = &delta.change.payload
            else {
                continue;
            };
            if named != capability || !delta.change.applies(facts) {
                continue;
            }
            effect = Some(*decided);
        }
        effect
    }
}

/// Which independent check a corpus case runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorpusCaseKind {
    /// The delta applies to a task of the kind the experience came from.
    Transfer,
    /// The delta composes with the active definition into one that still
    /// carries every part within the bound.
    Composition,
    /// The delta does not fire where a different, recorded delta provably
    /// applies: an overbroad trigger is refused there.
    NegativeControl,
}

impl CorpusCaseKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::Composition => "composition",
            Self::NegativeControl => "negative_control",
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "transfer" => Some(Self::Transfer),
            "composition" => Some(Self::Composition),
            "negative_control" => Some(Self::NegativeControl),
            _ => None,
        }
    }
}

/// One corpus case. The negative control carries the different delta that
/// must apply on the same facts: a case that only re-reads the candidate's
/// own trigger proves nothing about an overbroad one (I9), so the control is
/// part of the case shape rather than an optional field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorpusCase {
    /// The delta applies to a task of the kind the experience came from.
    Transfer { facts: ConditionFacts },
    /// The delta composes with the active definition into one that still
    /// carries every part within [`DEFINITION_MAX_BYTES`], and the effect it
    /// adds is in the composed definition: an applicability delta carries no
    /// bytes, so it is measured where it does compose — the definition's
    /// selection under the case facts. A delta that contributes nothing to
    /// either part never passes this case.
    Composition { facts: ConditionFacts },
    /// The delta does not fire where the named, already recorded delta
    /// provably does: an overbroad trigger is refused there.
    NegativeControl {
        facts: ConditionFacts,
        control: String,
    },
}

impl CorpusCase {
    #[must_use]
    pub const fn kind(&self) -> CorpusCaseKind {
        match self {
            Self::Transfer { .. } => CorpusCaseKind::Transfer,
            Self::Composition { .. } => CorpusCaseKind::Composition,
            Self::NegativeControl { .. } => CorpusCaseKind::NegativeControl,
        }
    }
}

/// One candidate delta offered to the store: its stable id, the base version
/// it was authored against, the change it makes and the provenance it cites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaCandidate {
    pub delta_id: String,
    pub base_version: u64,
    pub change: DeltaChange,
    pub evidence: String,
}

impl DeltaCandidate {
    /// The typed refusals of one candidate, checked before any row lands
    /// (INV-011).
    ///
    /// # Errors
    ///
    /// Returns the first [`DeltaError`] the candidate violates.
    pub fn validate(&self) -> Result<(), DeltaError> {
        self.change.validate(&self.delta_id)?;
        if self.evidence.trim().is_empty() {
            return Err(DeltaError::MissingEvidence {
                delta_id: self.delta_id.clone(),
            });
        }
        if carries_credential_reference(&self.evidence) {
            return Err(DeltaError::CredentialReference {
                delta_id: self.delta_id.clone(),
            });
        }
        Ok(())
    }
}

/// One recorded corpus verdict. A failing case is recorded too: activation
/// reads the rows instead of a summary, so the named reason survives a
/// restart and no model is asked to re-judge it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusVerdict {
    pub delta_id: String,
    pub delta_version: u64,
    pub kind: CorpusCaseKind,
    pub expected: String,
    pub observed: String,
    pub passed: bool,
}

/// The candidate one corpus run judges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorpusCandidate<'a> {
    pub delta_id: &'a str,
    pub version: u64,
    pub change: &'a DeltaChange,
}

/// The verdict one corpus case yields — a pure function of the candidate, the
/// active definition, the control delta, the case facts and the longest base
/// part an assembly site assembles beside the learned one.
#[must_use]
pub fn corpus_verdict(
    candidate: &CorpusCandidate<'_>,
    active: &LearningDefinition,
    control_delta: Option<&LearningDelta>,
    case: &CorpusCase,
    base: &str,
) -> CorpusVerdict {
    let delta_id = candidate.delta_id.to_string();
    let (expected, observed, passed) = match case {
        CorpusCase::Transfer { facts } => {
            let applies = candidate.change.applies(facts);
            (
                format!("delta {delta_id} applies to the case facts"),
                format!(
                    "delta {delta_id} {}",
                    if applies { "applies" } else { "does not apply" }
                ),
                applies,
            )
        }
        CorpusCase::Composition { facts } => {
            let composed = active.composed_with(&LearningDelta {
                delta_id: delta_id.clone(),
                version: candidate.version,
                change: candidate.change.clone(),
            });
            // The measured part is the one a request would carry: the longest
            // base a request assembles beside the learned text, in its heaviest
            // assembled form. An applicability delta adds no bytes there, so it
            // is measured where it does compose — the selection the definition
            // decides under the case facts — and a delta that adds nothing to
            // either part never passes this case (I9).
            let size = composed.max_instruction_bytes(base);
            let within = size <= DEFINITION_MAX_BYTES;
            match &candidate.change.payload {
                DeltaPayload::Instruction { .. } => (
                    format!(
                        "the composed instruction part stays within {DEFINITION_MAX_BYTES} bytes"
                    ),
                    format!("the heaviest composed instruction part is {size} bytes"),
                    within,
                ),
                DeltaPayload::Applicability { capability, effect } => {
                    let decided = composed.applicability(capability, facts);
                    let named = effect.as_str();
                    (
                        format!(
                            "the composed definition decides {capability} as {named} within {DEFINITION_MAX_BYTES} bytes"
                        ),
                        format!(
                            "the composed definition decides {capability} as {} in {size} bytes",
                            decided.map_or("nothing", PredicateEffect::as_str)
                        ),
                        decided == Some(*effect) && within,
                    )
                }
            }
        }
        CorpusCase::NegativeControl { facts, control } => {
            let control_applies = control_delta.is_some_and(|delta| delta.change.applies(facts));
            let candidate_applies = candidate.change.applies(facts);
            (
                format!("delta {control} applies and delta {delta_id} does not"),
                format!(
                    "delta {control} {}, delta {delta_id} {}",
                    if control_applies {
                        "applies"
                    } else {
                        "does not apply"
                    },
                    if candidate_applies {
                        "applies"
                    } else {
                        "does not apply"
                    }
                ),
                control_applies && !candidate_applies,
            )
        }
    };
    CorpusVerdict {
        delta_id,
        delta_version: candidate.version,
        kind: case.kind(),
        expected,
        observed,
        passed,
    }
}

/// One delta as stored: its payload, the provenance it cites, and its state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaRecord {
    pub delta_id: String,
    pub base_version: u64,
    pub change: DeltaChange,
    pub evidence: String,
    pub state: DeltaState,
    pub version: u64,
}

/// One delta as the status surface reports it (DEC-011).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LearningDeltaView {
    pub delta_id: String,
    pub scope: String,
    pub version: u64,
}

/// Activation, rollback and generation visibility on the status payload
/// (DEC-011): what composes the effective definition now, what was withdrawn,
/// and the schema generation the store reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LearningStatus {
    pub generation: u64,
    pub active: Vec<LearningDeltaView>,
    pub rolled_back: Vec<LearningDeltaView>,
}

/// The typed refusals of the learning owner (P-001). Each one names the delta
/// and the exact condition it failed, so the caller can act without parsing
/// prose.
#[derive(Debug, thiserror::Error)]
pub enum DeltaError {
    #[error("learning delta {delta_id} carries a credential reference")]
    CredentialReference { delta_id: String },
    #[error("learning delta {delta_id} carries an empty body")]
    EmptyBody { delta_id: String },
    #[error("learning delta {delta_id} carries an empty purpose")]
    EmptyPurpose { delta_id: String },
    #[error("learning delta {delta_id} body is {size} bytes, over the {limit}-byte bound")]
    TooLarge {
        delta_id: String,
        size: usize,
        limit: usize,
    },
    #[error(
        "learning delta {delta_id} names capability {capability}, which the selection does not weigh"
    )]
    UnknownCapability {
        delta_id: String,
        capability: String,
    },
    #[error("learning delta {delta_id} carries a {fact} condition its {scope} scope cannot read")]
    OutOfScope {
        delta_id: String,
        scope: DeltaScope,
        fact: &'static str,
    },
    #[error("learning delta {delta_id} overrides a capability without a condition")]
    Unconditional { delta_id: String },
    #[error("learning delta {delta_id} is already recorded")]
    AlreadyRecorded { delta_id: String },
    #[error("learning delta {delta_id} carries no provenance")]
    MissingEvidence { delta_id: String },
    #[error("learning delta {delta_id} carries two {kind} corpus cases")]
    DuplicateCase {
        delta_id: String,
        kind: &'static str,
    },
    #[error("learning delta {delta_id} carries {count} corpus cases, over the {limit} allowed")]
    TooManyCases {
        delta_id: String,
        count: usize,
        limit: usize,
    },
    #[error("learning delta {delta_id} names itself as its own negative control")]
    SelfControl { delta_id: String },
    #[error(
        "learning delta {delta_id} names {control} as a control, but no such delta is recorded"
    )]
    UnknownControl { delta_id: String, control: String },
    #[error(
        "learning delta {delta_id} is {state} at version {version}; activation was pinned to {expected}"
    )]
    ActivationRefused {
        delta_id: String,
        state: DeltaState,
        version: u64,
        expected: u64,
    },
    #[error(
        "learning delta {delta_id} is {state} at version {version}; rollback was pinned to {expected}"
    )]
    RollbackRefused {
        delta_id: String,
        state: DeltaState,
        version: u64,
        expected: u64,
    },
    #[error("learning delta {delta_id} has no {kind} corpus verdict for version {version}")]
    CorpusMissing {
        delta_id: String,
        kind: &'static str,
        version: u64,
    },
    #[error(
        "learning delta {delta_id} failed its {kind} corpus case: expected {expected}, observed {observed}"
    )]
    CorpusRejected {
        delta_id: String,
        kind: &'static str,
        expected: String,
        observed: String,
    },
    #[error(
        "learning delta {delta_id} composes a {size}-byte definition, over the {limit}-byte bound"
    )]
    CompositionExceeded {
        delta_id: String,
        size: usize,
        limit: usize,
    },
}

impl DeltaError {
    /// The wire code this refusal reports (P-001): a malformed candidate is
    /// invalid input, a refused transition conflicts with the stored state.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::CredentialReference { .. }
            | Self::EmptyBody { .. }
            | Self::EmptyPurpose { .. }
            | Self::TooLarge { .. }
            | Self::UnknownCapability { .. }
            | Self::OutOfScope { .. }
            | Self::Unconditional { .. }
            | Self::MissingEvidence { .. }
            | Self::DuplicateCase { .. }
            | Self::TooManyCases { .. }
            | Self::SelfControl { .. }
            | Self::UnknownControl { .. } => ErrorCode::InvalidInput,
            Self::AlreadyRecorded { .. }
            | Self::ActivationRefused { .. }
            | Self::RollbackRefused { .. }
            | Self::CorpusMissing { .. }
            | Self::CorpusRejected { .. }
            | Self::CompositionExceeded { .. } => ErrorCode::Conflict,
        }
    }
}

/// Whether a body carries a credential reference (INV-011). Case-folded
/// because the reference syntax is case-insensitive and a mixed-case spelling
/// is still a reference.
#[must_use]
pub fn carries_credential_reference(text: &str) -> bool {
    text.to_ascii_lowercase().contains(CREDENTIAL_REFERENCE)
}
