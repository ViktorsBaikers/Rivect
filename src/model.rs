//! Model broker: immutable request manifests and owner-brokered dispatch.
//! The manifest is frozen at prepare time; later config changes never
//! rewrite an in-flight request. Every physical request passes one
//! eligibility gate before ranking and one admission re-check before
//! the send, and is accounted exactly once.

use crate::config::{
    Config, ConfigError, ConnKind, Connection, EffortAssign, EffortLevel, FallbackAssign,
    FixedModel, ModelAssign, Profile, PurposeDef,
};
use crate::providers::{self, Provider, ProviderError, ProviderReply};
use crate::resources::UsageDelta;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

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
    /// The frozen admission bound of this request (INV-022): the
    /// `bound(next)` a budget level must fit beside its spent and
    /// reserved units before the dispatch may send.
    pub cost_bound: u64,
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
    #[error(
        "model request exceeds wire limit: accounted {actual} bytes with mandatory instructions, tools and output reserve exceeds {limit}"
    )]
    RequestTooLarge { limit: usize, actual: usize },
    #[error("dispatch world mismatch: manifest froze {frozen}, dispatch attempted from {current}")]
    WorldMismatch { frozen: String, current: String },
    #[error(
        "no eligible connection for purpose {purpose}: every candidate failed eligibility before ranking"
    )]
    NoEligibleCandidate { purpose: String },
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
    #[error("fallback for purpose {purpose} exhausted: {source}")]
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
#[derive(Debug, Clone, PartialEq)]
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
    /// The candidate passed the re-check but its own send failed.
    SendFailed(ProviderError),
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
            Self::SendFailed(source) => write!(f, "send failed: {source}"),
        }
    }
}

/// One skipped fallback chain entry with its typed cause.
#[derive(Debug, Clone, PartialEq)]
pub struct CandidateRejection {
    pub connection: String,
    pub cause: RejectionCause,
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

/// The last frozen model-visible prefix digest of one purpose (AC-061
/// contribution): an unchanged digest replays the epoch, a changed one
/// opens a new epoch with the recorded reason.
#[derive(Clone)]
struct EpochState {
    prefix_digest: String,
}

/// Recorded reason for an epoch mutation. Offline only the resolved
/// model assignment can change between prepares — the instructions and
/// tools are broker constants — so every mutation is a model switch;
/// masking/compaction/system-change reasons arrive with the live
/// provider dialects.
const MODEL_SWITCH: &str = "model switch";

/// Mandatory wire parts every offline request carries (AC-013). Live
/// provider dialects replace these with their real instruction and tool
/// surfaces; offline the constants keep the accounting honest.
const MANDATORY_INSTRUCTIONS: &str = "You are the Rivect decision core. The only permitted action is one scoped file read; request it as `read <path>` on its own line.";
const DECLARED_TOOLS: &[&str] = &["read_file"];

/// Reply bytes every request must leave room for (AC-013): the
/// accounted full-request size includes this reserve, so a request
/// that fits only without it is rejected.
const OUTPUT_RESERVE_BYTES: usize = 16 * 1024;

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
        }
    }

    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
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
    /// # Errors
    ///
    /// Returns [`ModelError::Config`] when the purpose cannot resolve,
    /// [`ModelError::Provider`] when a fixed pin is offline ineligible,
    /// [`ModelError::NoEligibleCandidate`] when no candidate survives
    /// eligibility, and [`ModelError::RequestTooLarge`] when the
    /// accounted full request exceeds the wire limit.
    pub fn prepare(
        &mut self,
        purpose: &str,
        config: &Config,
        world: &str,
        inputs: &str,
    ) -> Result<RequestManifest, ModelError> {
        let resolved = config.resolve_purpose(purpose)?;
        let purpose_def = config.models.purposes.get(purpose);
        let (connection, model_id) = rank_connection(
            purpose,
            &resolved.model,
            purpose_def,
            &config.connections,
            &config.profiles,
            &self.entitlements,
        )?;
        let instructions = MANDATORY_INSTRUCTIONS.to_string();
        let tools: Vec<String> = DECLARED_TOOLS
            .iter()
            .map(|tool| (*tool).to_string())
            .collect();
        let accounted = wire_composition(
            &instructions,
            &resolved.model,
            &tools,
            OUTPUT_RESERVE_BYTES,
            inputs,
        )
        .len()
            + OUTPUT_RESERVE_BYTES;
        if accounted > crate::contracts::MODEL_WIRE_MAX_BYTES {
            return Err(ModelError::RequestTooLarge {
                limit: crate::contracts::MODEL_WIRE_MAX_BYTES,
                actual: accounted,
            });
        }
        let (epoch_id, mutation_reason) =
            self.context_epoch(purpose, &resolved.model, &instructions, &tools);
        let attempt_id = crate::contracts::AttemptId::generate().0;
        let manifest = RequestManifest {
            attempt_id,
            purpose: purpose.to_string(),
            world: world.to_string(),
            model: resolved.model,
            effort: resolved.effort,
            instructions,
            tools,
            output_reserve: OUTPUT_RESERVE_BYTES,
            inputs: inputs.to_string(),
            inputs_digest: hex(&Sha256::digest(inputs.as_bytes())),
            epoch_id,
            mutation_reason,
            cost_bound: sent_cost_bound(inputs),
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
                model_id,
                model_source: resolved.model_source,
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
    /// question.current — [`ModelError::FallbackExhausted`] when the
    /// auto chain ran out with every entry rejected or failed, or a
    /// `manual` fallback found no servable candidate to pause on, and
    /// [`ModelError::Provider`] when the provider rejects the request.
    pub fn dispatch(
        &mut self,
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
        match self.complete_send(manifest, &admission.connection) {
            Ok(reply) => Ok(reply),
            Err(source) => self.fallback_or_fail(manifest, &admission, source),
        }
    }

    /// Sends one frozen manifest and charges its shared reservation
    /// once: admission for the send happened immediately above the call
    /// site — the presented-manifest re-check for the primary, the chain
    /// re-check for a fallback candidate. On success the spent admission
    /// and any stale pending choice die with the send.
    fn complete_send(
        &mut self,
        manifest: &RequestManifest,
        connection: &str,
    ) -> Result<ProviderReply, ProviderError> {
        // Fail closed on the provider's own dialect claim (AC-046):
        // the frozen manifest's connection must still be declared, and
        // the injected adapter must actually serve it — eligibility
        // alone never authorizes a send, and the denial lands before
        // the provider sees the request or anything is accounted.
        let Some(entry) = self.view_connections.get(connection) else {
            return Err(ProviderError::UnknownConnection);
        };
        if !self.provider.serves(connection, entry) {
            return Err(ProviderError::DialectMismatch {
                connection: connection.to_string(),
            });
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
        let reply = self.provider.send(manifest)?;
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
        // The attempt is spent and its admission is dead weight: prune
        // it, and a later replay still answers through the accounting
        // map above.
        self.admissions.remove(&manifest.attempt_id);
        self.pending.remove(&manifest.attempt_id);
        self.paused.remove(&manifest.attempt_id);
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
        match self.complete_send(&substitute, connection) {
            Ok(reply) => {
                // The substitute answered the intent: the paused
                // primary's admission is spent with it, so neither id
                // can replay — and its pending record dies with it.
                self.admissions.remove(attempt_id);
                self.pending.remove(attempt_id);
                self.paused.remove(attempt_id);
                Ok(reply)
            }
            Err(source) => {
                self.admissions.remove(&substitute.attempt_id);
                self.restore_epoch(&admission.purpose, displaced);
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
    /// walks the chain — every entry is re-checked against the CURRENT
    /// catalogue, egress, entitlement and purpose-eligibility gates, so
    /// a candidate failing the check never receives the request. An
    /// admitted entry mints one fallback manifest carrying the failed
    /// attempt's frozen task data byte-for-byte under its own attempt
    /// id, the chain entry's fixed model and the same cost bound — one
    /// reservation, one accounting, no second-order fallback.
    fn fallback_or_fail(
        &mut self,
        manifest: &RequestManifest,
        admission: &AdmissionRecord,
        source: ProviderError,
    ) -> Result<ProviderReply, ModelError> {
        match &admission.fallback {
            FallbackAssign::Off => Err(ModelError::Provider(source)),
            FallbackAssign::Manual => {
                let mut candidates = self.eligible_candidates(&admission.purpose);
                // The failed primary never re-enters its own choice
                // list — it already produced this failure.
                candidates.retain(|name| name != &admission.connection);
                if candidates.is_empty() {
                    // An empty served set can never be answered — the
                    // pick must name a served member, so pausing here
                    // would pin a question nothing satisfies. Report
                    // the exhaustion honestly instead: every evaluated
                    // non-primary connection's cause, no send attempted,
                    // the primary's own failure as the source.
                    let rejected = self
                        .view_connections
                        .keys()
                        .filter(|name| name.as_str() != admission.connection)
                        .filter_map(|name| {
                            self.candidate_rejection(&admission.purpose, name)
                                .map(|cause| CandidateRejection {
                                    connection: name.clone(),
                                    cause,
                                })
                        })
                        .collect();
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
                let mut rejected = Vec::new();
                let mut attempted = Vec::new();
                for entry in chain {
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
                    match self.complete_send(&fallback_manifest, &entry.connection) {
                        Ok(reply) => {
                            // The substitute answered the intent: the
                            // failed primary's admission is spent with
                            // it, so neither id can replay.
                            self.admissions.remove(&manifest.attempt_id);
                            return Ok(reply);
                        }
                        Err(send_error) => {
                            // The minted manifest never leaves this
                            // scope, so its unspent admission is dead
                            // weight — prune it, and roll the
                            // provisional epoch mint back to the entry
                            // the failed send displaced.
                            self.admissions.remove(&fallback_manifest.attempt_id);
                            self.restore_epoch(&admission.purpose, displaced);
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
        let (epoch_id, mutation_reason) = self.context_epoch(
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
            mutation_reason,
            ..admission.manifest.clone()
        };
        self.admissions.insert(
            substitute.attempt_id.clone(),
            AdmissionRecord {
                purpose: admission.purpose.clone(),
                connection: connection.to_string(),
                model_id,
                model_source: format!("{}.{leg}", admission.fallback_source),
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
            return Some(RejectionCause::DialectMismatch);
        }
        if !self.entitlements.allows(connection) {
            return Some(RejectionCause::NotEntitled);
        }
        if !purpose_entitled(self.view_purposes.get(purpose), connection) {
            return Some(RejectionCause::NotPurposeEligible);
        }
        None
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
    /// a new epoch with the recorded mutation reason.
    fn context_epoch(
        &mut self,
        purpose: &str,
        model: &ModelAssign,
        instructions: &str,
        tools: &[String],
    ) -> (String, Option<String>) {
        let prefix = format!(
            "purpose:{purpose}\nmodel:{}\ninstructions:{instructions}\ntools:{}",
            model_wire_id(model),
            tools.join(", ")
        );
        let prefix_digest = hex(&Sha256::digest(prefix.as_bytes()));
        let epoch_id = format!("epoch-{}", &prefix_digest[..16]);
        let mutation_reason = match self.epochs.get(purpose) {
            Some(previous) if previous.prefix_digest == prefix_digest => None,
            Some(_) => Some(MODEL_SWITCH.to_string()),
            None => None,
        };
        self.epochs
            .insert(purpose.to_string(), EpochState { prefix_digest });
        (epoch_id, mutation_reason)
    }
}

/// Candidate enumeration and offline ranking for one assignment
/// (AC-044): ineligible candidates are filtered out before ranking —
/// unknown to the catalogue, not usable without a separate live grant,
/// outside the account entitlement or the per-purpose `eligible`
/// input. Offline ranking is pool order, the declared preference:
/// priced ranking arrives with the live dialects. An assignment with
/// no surviving candidate fails closed, and a fixed pin keeps the
/// precise typed rejection vocabulary of
/// [`providers::offline_eligible`].
///
/// # Errors
///
/// Returns [`ModelError::Provider`] for an offline-ineligible fixed
/// pin and [`ModelError::NoEligibleCandidate`] when no candidate
/// survives the eligibility filter.
fn rank_connection(
    purpose: &str,
    assignment: &ModelAssign,
    purpose_def: Option<&PurposeDef>,
    connections: &BTreeMap<String, Connection>,
    profiles: &BTreeMap<String, Profile>,
    entitlements: &Entitlements,
) -> Result<(String, Option<String>), ModelError> {
    match assignment {
        ModelAssign::Fixed(fixed) => {
            providers::offline_eligible(assignment, connections, profiles)?;
            if !entitled(entitlements, purpose_def, &fixed.connection) {
                return Err(ModelError::NoEligibleCandidate {
                    purpose: purpose.to_string(),
                });
            }
            Ok((fixed.connection.clone(), Some(fixed.model_id.clone())))
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
            candidates
                .into_iter()
                .find(|name| {
                    providers::offline_usable(connections, profiles, name)
                        && entitled(entitlements, purpose_def, name)
                })
                .map(|connection| (connection, None))
                .ok_or_else(|| ModelError::NoEligibleCandidate {
                    purpose: purpose.to_string(),
                })
        }
        // an inherit that survived resolution names no connection and
        // declares no pool: it has no candidate and fails closed
        ModelAssign::Inherit => Err(ModelError::NoEligibleCandidate {
            purpose: purpose.to_string(),
        }),
    }
}

/// Account entitlement and the per-purpose `eligible` input together.
fn entitled(
    entitlements: &Entitlements,
    purpose_def: Option<&PurposeDef>,
    connection: &str,
) -> bool {
    entitlements.allows(connection) && purpose_entitled(purpose_def, connection)
}

/// The per-purpose `eligible` input (DEC-012): `None` restricts
/// nothing; a declared list admits only its members.
fn purpose_entitled(purpose_def: Option<&PurposeDef>, connection: &str) -> bool {
    purpose_def
        .and_then(|def| def.eligible.as_deref())
        .is_none_or(|list| list.iter().any(|name| name == connection))
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
        match broker.dispatch("/world/drift", &manifest) {
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
}
