//! Provider adapters. The loopback provider is the owner-brokered local
//! fixture for offline first-task proof; live dialects arrive in later
//! slices. Workers never hold a provider handle, only the broker does.

use crate::config::{ConnKind, ModelAssign};
use crate::model::RequestManifest;

#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub tool: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderReply {
    pub text: String,
    pub tool_calls: Vec<ToolCall>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProviderError {
    CapabilityUnavailable(String),
    Transport(String),
}

pub trait Provider: Send {
    fn name(&self) -> &'static str;
    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError>;
}

/// Offline loopback: answers from local fixtures only, zero network. The
/// fixture decision reads a `read <path>` instruction out of the manifest
/// inputs and returns it as a tool call for the executor boundary.
pub struct LoopbackProvider {
    calls: u64,
}

impl LoopbackProvider {
    pub fn new() -> Self {
        Self { calls: 0 }
    }

    pub fn calls(&self) -> u64 {
        self.calls
    }
}

impl Default for LoopbackProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Provider for LoopbackProvider {
    fn name(&self) -> &'static str {
        "loopback"
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        self.calls += 1;
        let path = manifest
            .inputs
            .lines()
            .rev()
            .find_map(|line| line.strip_prefix("read ").map(str::to_string));
        match path {
            Some(path) => Ok(ProviderReply {
                text: "Выполняю разрешённое чтение.".to_string(),
                tool_calls: vec![ToolCall {
                    tool: "read_file".to_string(),
                    path: Some(path),
                }],
            }),
            None => Ok(ProviderReply {
                text: "Нет разрешённого действия; ожидаю решение.".to_string(),
                tool_calls: Vec::new(),
            }),
        }
    }
}

/// Connection eligibility for offline dispatch: only local connections are
/// usable without a separate live grant; fail closed otherwise.
pub fn offline_eligible(
    model: &ModelAssign,
    connection_kind: Option<ConnKind>,
) -> Result<(), ProviderError> {
    match (model, connection_kind) {
        (ModelAssign::Fixed(_), Some(ConnKind::Local)) => Ok(()),
        (ModelAssign::Fixed(_), Some(kind)) => Err(ProviderError::CapabilityUnavailable(format!(
            "{kind:?} connection requires a separate live grant"
        ))),
        (ModelAssign::Fixed(_), None) => Err(ProviderError::CapabilityUnavailable(
            "model references unknown connection".to_string(),
        )),
        _ => Ok(()),
    }
}
