//! Rust arm of `scripts/messages-sdk-trial.mjs`; the peer chooses an ephemeral loopback port.

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    reason = "the opt-in trial prints observed outcomes for its local peer"
)]

use rivect::config::Config;
use rivect::model::{Broker, ModelError, NullLedger};
use rivect::providers::anthropic::MessagesProvider;
use rivect::providers::{ProviderError, StoreKind};
use rivect::resources::UsageDelta;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

mod support;

#[test]
#[ignore = "run with the shared SDK loopback fixture via scripts/messages-sdk-trial.mjs"]
fn direct_against_shared_peer() -> Result<(), Box<dyn std::error::Error>> {
    let port: u16 = std::env::var("RIVECT_MESSAGES_TRIAL_PORT")
        .expect("local fixture port")
        .parse()
        .expect("numeric port");
    let case = std::env::var("RIVECT_MESSAGES_TRIAL_CASE").expect("fixture case");
    let config = Config::parse_validated(&format!(
        r#"config_version = 1
[connections.anthropic]
kind = "api_key"
endpoint = "http://127.0.0.1:{port}/v1"
credential_ref = "keyring:rivect-test/anthropic"
[models.defaults]
model = {{ mode = "fixed", connection = "anthropic", model_id = "claude-opus-4-8" }}
effort = {{ mode = "auto" }}
fallback = {{ mode = "off" }}
"#
    ))
    .expect("fixture config");
    let store = Arc::new(support::MapStore::seeded(
        StoreKind::Keychain,
        &[("keyring:rivect-test/anthropic", "fixture-not-a-key")],
    ));
    let provider =
        MessagesProvider::with_deadline(&config, "anthropic", store, Duration::from_secs(4))?;
    let mut broker = Broker::new(Box::new(provider));
    let world = "/world/messages-trial";
    let manifest = broker.prepare("main", &config, world, "fixture")?;
    let reply = broker.dispatch(&mut NullLedger, world, &manifest);
    let row = match reply {
        Ok(reply) => {
            let (input, output) = match reply.usage {
                UsageDelta::Unknown => (None, None),
                UsageDelta::Exact {
                    prompt_tokens,
                    completion_tokens,
                    ..
                } => (Some(prompt_tokens), Some(completion_tokens)),
                UsageDelta::Legs {
                    prompt_tokens,
                    completion_tokens,
                    ..
                } => (prompt_tokens, completion_tokens),
            };
            assert_eq!(reply.tool_calls.len(), 1, "one assembled tool call");
            let call = &reply.tool_calls[0];
            if case == "cancel" {
                let mut command = String::new();
                std::io::stdin().read_line(&mut command)?;
                assert_eq!(command.trim(), "cancel");
                assert!(
                    !broker.cancel_attempt(&manifest.attempt_id),
                    "the synchronous dispatch spent the attempt"
                );
            }
            assert_eq!(broker.accounted_requests(), 1);
            json!({"status":"ok", "tool":call.tool, "args":{"path":call.path}, "input":input, "output":output})
        }
        Err(ModelError::Provider(err)) => {
            assert_eq!(broker.accounted_requests(), 0);
            let kind = match err {
                ProviderError::UnknownTerminal { .. } => "UnknownTerminal",
                ProviderError::IncompatibleOutput { .. } => "IncompatibleOutput",
                ProviderError::StreamViolation { .. } => "StreamViolation",
                ProviderError::Transport { .. } => "Transport",
                other => return Err(other.into()),
            };
            json!({"status":"error", "kind":kind})
        }
        Err(other) => return Err(other.into()),
    };
    println!("OBS {row}");
    Ok(())
}
