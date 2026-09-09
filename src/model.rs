//! Model broker: immutable request manifests and owner-brokered dispatch.
//! The manifest is frozen at prepare time; later config changes never
//! rewrite an in-flight request.

use crate::config::{Config, ConfigError, EffortAssign, ModelAssign};
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
}

pub fn hex(bytes: &[u8]) -> String {
    crate::config::hex(bytes)
}
