//! Model broker: immutable request manifests and owner-brokered dispatch.
//! The manifest is frozen at prepare time; later config changes never
//! rewrite an in-flight request.

use crate::config::{Config, ConfigError, EffortAssign, EffortLevel, ModelAssign};
use crate::providers::{self, Provider, ProviderError};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq)]
pub struct RequestManifest {
    pub attempt_id: String,
    pub purpose: String,
    pub model: ModelAssign,
    pub effort: EffortAssign,
    pub inputs: String,
    pub inputs_digest: String,
    pub epoch_id: String,
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

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("model configuration: {0}")]
    Config(#[from] ConfigError),
    #[error("model provider: {0}")]
    Provider(#[from] ProviderError),
}
pub struct Broker {
    provider: Box<dyn Provider>,
}

impl Broker {
    pub fn new(provider: Box<dyn Provider>) -> Self {
        Self { provider }
    }

    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
    }

    /// Builds the immutable manifest for one model attempt. Eligibility is
    /// checked here and again at dispatch.
    pub fn prepare(
        &self,
        purpose: &str,
        config: &Config,
        inputs: &str,
    ) -> Result<RequestManifest, ModelError> {
        let resolved = config.resolve_purpose(purpose)?;
        let kind = match &resolved.model {
            ModelAssign::Fixed(fixed) => config.connections.get(&fixed.connection).map(|c| c.kind),
            _ => None,
        };
        providers::offline_eligible(&resolved.model, kind)?;
        Ok(RequestManifest {
            attempt_id: crate::contracts::AttemptId::generate().0,
            purpose: purpose.to_string(),
            model: resolved.model,
            effort: resolved.effort,
            inputs: inputs.to_string(),
            inputs_digest: hex(&Sha256::digest(inputs.as_bytes())),
            epoch_id: {
                let seed = hex(&Sha256::digest(purpose.as_bytes()));
                format!("epoch-{}", &seed[..16])
            },
        })
    }

    /// Dispatches exactly the frozen manifest bytes to the owner-brokered
    /// provider. No worker may call this directly.
    pub fn dispatch(
        &mut self,
        manifest: &RequestManifest,
    ) -> Result<providers::ProviderReply, ModelError> {
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
}

pub fn hex(bytes: &[u8]) -> String {
    crate::config::hex(bytes)
}
