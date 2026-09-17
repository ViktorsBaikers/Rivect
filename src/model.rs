//! Model broker: immutable request manifests and owner-brokered dispatch.
//! The manifest is frozen at prepare time; later config changes never
//! rewrite an in-flight request. Every physical request passes one
//! eligibility gate before ranking and one admission re-check before
//! the send, and is accounted exactly once.

use crate::config::{
    Config, ConfigError, Connection, EffortAssign, EffortLevel, ModelAssign, PurposeDef,
};
use crate::providers::{self, Provider, ProviderError};
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
}

/// The last frozen model-visible prefix digest of one purpose (AC-061
/// contribution): an unchanged digest replays the epoch, a changed one
/// opens a new epoch with the recorded reason.
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
}

impl Broker {
    pub fn new(provider: Box<dyn Provider>) -> Self {
        Self {
            provider,
            epochs: BTreeMap::new(),
            entitlements: Entitlements::unrestricted(),
            admissions: BTreeMap::new(),
            accounting: BTreeMap::new(),
        }
    }

    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
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
        self.admissions.insert(
            manifest.attempt_id.clone(),
            AdmissionRecord {
                purpose: purpose.to_string(),
                connection,
                model_id,
                model_source: resolved.model_source,
                snapshot_version: self.entitlements.version,
                manifest: manifest.clone(),
            },
        );
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
    /// admission was pruned), [`ModelError::NoAdmission`] when this
    /// broker ranked no manifest with that attempt id,
    /// [`ModelError::AdmissionMismatch`] when the presented manifest is
    /// not the one the ranking admitted, [`ModelError::EligibilityStale`]
    /// when the entitlement snapshot changed since ranking, and
    /// [`ModelError::Provider`] when the provider rejects the request.
    pub fn dispatch(
        &mut self,
        world: &str,
        manifest: &RequestManifest,
    ) -> Result<providers::ProviderReply, ModelError> {
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
        let (connection, frozen_version) = {
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
            (admission.connection.clone(), admission.snapshot_version)
        };
        let current_version = self.entitlements.version;
        // The re-check re-evaluates against the live snapshot, not a
        // cached verdict. The version bump on every rights movement is
        // the primary guard — a same-version rights drift is
        // unreachable through `set_account_rights` — and the direct
        // `allows` re-evaluation stays as defense-in-depth against any
        // future surface that mutates rights without a bump.
        if current_version != frozen_version || !self.entitlements.allows(&connection) {
            return Err(ModelError::EligibilityStale {
                attempt_id: manifest.attempt_id.clone(),
                connection,
                frozen: frozen_version,
                current: current_version,
            });
        }
        let reply = self.provider.send(manifest)?;
        self.accounting.insert(
            manifest.attempt_id.clone(),
            AccountingRecord {
                attempt_id: manifest.attempt_id.clone(),
                purpose: manifest.purpose.clone(),
                connection,
                cost_bound: manifest.cost_bound,
            },
        );
        // The attempt is spent and its admission is dead weight: prune
        // it, and a later replay still answers through the accounting
        // map above.
        self.admissions.remove(&manifest.attempt_id);
        Ok(reply)
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
    /// units stay `None` because no offline provider data exists, so
    /// the charge path retains the bound instead of releasing zero.
    pub fn sent_cost_explain(&self, manifest: &RequestManifest) -> SentCostExplain {
        SentCostExplain {
            bound: manifest.cost_bound,
            confirmed: None,
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
    entitlements: &Entitlements,
) -> Result<(String, Option<String>), ModelError> {
    match assignment {
        ModelAssign::Fixed(fixed) => {
            providers::offline_eligible(
                assignment,
                connections.get(&fixed.connection).map(|c| c.kind),
            )?;
            if !entitlements.allows(&fixed.connection)
                || !purpose_entitled(purpose_def, &fixed.connection)
            {
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
                    connections
                        .get(name)
                        .is_some_and(|c| providers::offline_usable(Some(c.kind)))
                        && entitlements.allows(name)
                        && purpose_entitled(purpose_def, name)
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
