//! Retained one-shot attempt evidence (EVID-301 contribution): a durable
//! pre-effect record with a terminal sync, readable after any restart and
//! never overwritten by a later cleanup success.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetainedStage {
    PreEffect,
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetainedAttempt {
    pub attempt_id: String,
    pub boundary_id: String,
    pub stage: RetainedStage,
    pub cause: String,
    pub digest: String,
    pub build_attempt: String,
}

pub const RETAINED_BOUNDARY: &str = "first_task_effect";

pub fn boundary_id(attempt_id: &str) -> String {
    format!("ret:{RETAINED_BOUNDARY}:{attempt_id}")
}

pub fn record_digest(attempt_id: &str, cause: &str) -> String {
    crate::config::hex(&Sha256::digest(format!("{attempt_id}\n{cause}").as_bytes()))
}
