//! Model broker: immutable request manifests and owner-brokered dispatch.
//! The manifest is frozen at prepare time; later config changes never
//! rewrite an in-flight request.

use crate::config::{Config, ConfigError, EffortAssign, EffortLevel, ModelAssign};
use crate::providers::{self, Provider, ProviderError};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
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
}

impl Broker {
    pub fn new(provider: Box<dyn Provider>) -> Self {
        Self {
            provider,
            epochs: BTreeMap::new(),
        }
    }

    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
    }

    /// Builds the immutable manifest for one model attempt. Eligibility
    /// is checked here and again at dispatch. The manifest freezes the
    /// execution world, the mandatory wire parts and the context epoch;
    /// a request that does not fit together with its mandatory parts is
    /// rejected, never truncated.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Config`] when the purpose cannot resolve,
    /// [`ModelError::Provider`] when the assignment is offline
    /// ineligible, and [`ModelError::RequestTooLarge`] when the
    /// accounted full request exceeds the wire limit.
    pub fn prepare(
        &mut self,
        purpose: &str,
        config: &Config,
        world: &str,
        inputs: &str,
    ) -> Result<RequestManifest, ModelError> {
        let resolved = config.resolve_purpose(purpose)?;
        let kind = match &resolved.model {
            ModelAssign::Fixed(fixed) => config.connections.get(&fixed.connection).map(|c| c.kind),
            _ => None,
        };
        providers::offline_eligible(&resolved.model, kind)?;
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
        Ok(RequestManifest {
            attempt_id: crate::contracts::AttemptId::generate().0,
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
        })
    }

    /// Dispatches exactly the frozen manifest bytes to the owner-brokered
    /// provider. The execution world is re-checked against the frozen one
    /// before any provider call — a manifest from another world is
    /// rejected, never re-bound. No worker may call this directly.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::WorldMismatch`] when the dispatch world is
    /// not the world frozen on the manifest, and
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
        Ok(self.provider.send(manifest)?)
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
