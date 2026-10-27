//! Retained one-shot attempt evidence (EVID-301 contribution): a durable
//! pre-effect record with a terminal sync, readable after any restart and
//! never overwritten by a later cleanup success. Assumption checks use the
//! same retained seam so a setup gap never reads as a product result.

use crate::contracts::{SessionId, TaskId};
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
    #[serde(default)]
    pub admitted_attempt_id: Option<String>,
}

pub const RETAINED_BOUNDARY: &str = "first_task_effect";

pub fn boundary_id(attempt_id: &str) -> String {
    format!("ret:{RETAINED_BOUNDARY}:{attempt_id}")
}

pub fn terminal_boundary_id(boundary_id: &str) -> String {
    format!("ret:terminal:{boundary_id}")
}

pub fn record_digest(attempt_id: &str, cause: &str) -> String {
    crate::config::hex(&Sha256::digest(format!("{attempt_id}\n{cause}").as_bytes()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedResult {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupGapCause {
    MissingExecutable,
    MissingFixture,
    EnvironmentUnavailable,
    ImportFailure,
    ZeroTestsSelected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckObservation {
    Passed,
    Failed,
    SetupGap(SetupGapCause),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssumptionClassification {
    Confirmed,
    ProductDefect,
    NotReproduced,
    SetupGap(SetupGapCause),
}

impl ExpectedResult {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

impl SetupGapCause {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingExecutable => "missing_executable",
            Self::MissingFixture => "missing_fixture",
            Self::EnvironmentUnavailable => "environment_unavailable",
            Self::ImportFailure => "import_failure",
            Self::ZeroTestsSelected => "zero_tests_selected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssumptionCheckRecord {
    pub session_id: SessionId,
    pub task_id: TaskId,
    pub check_id: String,
    pub expected_result: ExpectedResult,
    pub assertion_digest: String,
    pub observation: CheckObservation,
    pub classification: AssumptionClassification,
    pub boundary_id: Option<String>,
}

pub fn classify_assumption(
    expected: ExpectedResult,
    observation: CheckObservation,
) -> AssumptionClassification {
    match (expected, observation) {
        (_, CheckObservation::SetupGap(cause)) => AssumptionClassification::SetupGap(cause),
        (ExpectedResult::Pass, CheckObservation::Passed)
        | (ExpectedResult::Fail, CheckObservation::Failed) => AssumptionClassification::Confirmed,
        (ExpectedResult::Pass, CheckObservation::Failed) => AssumptionClassification::ProductDefect,
        (ExpectedResult::Fail, CheckObservation::Passed) => AssumptionClassification::NotReproduced,
    }
}

/// Every assumption failure path that retains evidence. The spelling is
/// part of the boundary identity, so each seam keeps a stable id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssumptionSeam {
    SetupGap(SetupGapCause),
    ProductDefect,
    NotReproduced,
    PrepareEnvironment,
}

impl AssumptionSeam {
    fn identity(self) -> &'static str {
        match self {
            Self::SetupGap(cause) => match cause {
                SetupGapCause::MissingExecutable => "setup_gap:missing_executable",
                SetupGapCause::MissingFixture => "setup_gap:missing_fixture",
                SetupGapCause::EnvironmentUnavailable => "setup_gap:environment_unavailable",
                SetupGapCause::ImportFailure => "setup_gap:import_failure",
                SetupGapCause::ZeroTestsSelected => "setup_gap:zero_tests_selected",
            },
            Self::ProductDefect => "product_defect",
            Self::NotReproduced => "not_reproduced",
            Self::PrepareEnvironment => "prepare_environment",
        }
    }
}

/// The boundary for one failure seam. User-controlled assertion contents
/// never enter this id.
pub fn assumption_boundary_id(task_id: &TaskId, check_id: &str, seam: AssumptionSeam) -> String {
    let identity = format!("{}\n{check_id}\n{}", task_id.0, seam.identity());
    format!("ret:assumption:{}", record_digest(&identity, "boundary"))
}

/// Retained evidence for a setup gap, keyed by its typed cause.
pub fn setup_gap_evidence(
    task_id: &TaskId,
    check_id: &str,
    cause: SetupGapCause,
) -> RetainedAttempt {
    assumption_evidence(
        task_id,
        check_id,
        AssumptionSeam::SetupGap(cause),
        &format!("setup gap: {}", cause.as_str()),
    )
}

/// Retained evidence for one assumption seam without caller assertion text.
pub fn assumption_evidence(
    task_id: &TaskId,
    check_id: &str,
    seam: AssumptionSeam,
    cause: &str,
) -> RetainedAttempt {
    let boundary_id = assumption_boundary_id(task_id, check_id, seam);
    RetainedAttempt {
        attempt_id: format!("assumption:{check_id}"),
        digest: record_digest(&boundary_id, cause),
        boundary_id,
        stage: RetainedStage::Terminal,
        cause: cause.to_string(),
        build_attempt: crate::BUILD_ATTEMPT_ID.to_string(),
        admitted_attempt_id: None,
    }
}

/// Pre-effect evidence for one environment restore attempt.
pub fn assumption_pre_effect(task_id: &TaskId, check_id: &str) -> RetainedAttempt {
    let attempt_id = format!("assumption:{check_id}:{}", uuid::Uuid::new_v4());
    let identity = format!(
        "{}\n{check_id}\n{}\n{attempt_id}",
        task_id.0,
        AssumptionSeam::PrepareEnvironment.identity()
    );
    let boundary_id = format!("ret:assumption:{}", record_digest(&identity, "boundary"));
    RetainedAttempt {
        attempt_id: attempt_id.clone(),
        boundary_id,
        stage: RetainedStage::PreEffect,
        cause: "environment restore pending".to_string(),
        digest: record_digest(&attempt_id, "pre"),
        build_attempt: crate::BUILD_ATTEMPT_ID.to_string(),
        admitted_attempt_id: None,
    }
}

pub fn assumption_restore_outcome(
    pending: &RetainedAttempt,
    cause: &str,
    admitted_attempt_id: Option<&str>,
) -> RetainedAttempt {
    RetainedAttempt {
        attempt_id: pending.attempt_id.clone(),
        boundary_id: terminal_boundary_id(&pending.boundary_id),
        stage: RetainedStage::Terminal,
        cause: cause.to_string(),
        digest: record_digest(&pending.attempt_id, cause),
        build_attempt: crate::BUILD_ATTEMPT_ID.to_string(),
        admitted_attempt_id: admitted_attempt_id.map(str::to_owned),
    }
}
