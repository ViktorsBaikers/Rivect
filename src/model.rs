//! Model broker: immutable request manifests and owner-brokered dispatch.
//! The manifest is frozen at prepare time; later config changes never
//! rewrite an in-flight request.

use crate::config::{Config, EffortAssign, ModelAssign};
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

#[derive(Debug, Clone, PartialEq)]
pub enum ModelError {
    CapabilityUnavailable(String),
    Storage(String),
}

impl From<ProviderError> for ModelError {
    fn from(err: ProviderError) -> Self {
        match err {
            ProviderError::CapabilityUnavailable(why) => Self::CapabilityUnavailable(why),
            ProviderError::Transport(why) => Self::Storage(why),
        }
    }
}

impl std::fmt::Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapabilityUnavailable(why) => write!(f, "model capability unavailable: {why}"),
            Self::Storage(why) => write!(f, "model storage: {why}"),
        }
    }
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
        let resolved = config
            .resolve_purpose(purpose)
            .map_err(|err| ModelError::CapabilityUnavailable(err.to_string()))?;
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
