//! Retained one-shot attempt evidence (EVID-301 contribution): a durable
//! pre-effect record with a terminal sync, readable after any restart and
//! never overwritten by a later cleanup success. Assumption checks use the
//! same retained seam so a setup gap never reads as a product result.

use crate::contracts::{ErrorCode, SessionId, TaskId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

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

// ----- conformance evaluation (REQ-067, AC-081) -----

/// The conformance-plan schema this build reads.
pub const CONFORMANCE_SCHEMA: u32 = 1;

/// The largest oracle fixture this build accepts; the holdout is external
/// input, so it is bounded like every other one.
pub const ORACLE_MAX_BYTES: usize = 8 * 1024 * 1024;

/// The three trial classes a matched report must tell apart. A live trial is
/// never counted as deterministic and a replay is never counted as either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialMode {
    Deterministic,
    Replay,
    Live,
}

impl TrialMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deterministic => "deterministic",
            Self::Replay => "replay",
            Self::Live => "live",
        }
    }
}

/// What the oracle declares one case must do: a positive case must pass, a
/// control must fail, and a live-gated case must stay not run rather than be
/// fabricated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedOutcome {
    Pass,
    Fail,
    NotRun,
}

/// What a candidate trial reported. `Censored` is retained as NOT_RUN, never
/// promoted to a pass; `Unserved` is the recorded terminal denial for a
/// provider with no installed adapter, also never a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialOutcome {
    Pass,
    Fail,
    Censored,
    Unserved,
}

/// One source-declared case: its stable id, its expectation and the trial
/// class it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleCase {
    pub case_id: String,
    pub expected: ExpectedOutcome,
    pub mode: TrialMode,
}

/// The protected case plan: what an out-of-tree oracle declares, never what
/// the candidate says about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Oracle {
    pub schema_version: u32,
    pub cases: Vec<OracleCase>,
}

impl Oracle {
    /// Parse one oracle document, refusing a plan that names no case or
    /// another schema.
    pub fn load(bytes: &[u8]) -> Result<Self, ConformanceError> {
        let oracle: Self = serde_json::from_slice(bytes)
            .map_err(|source| ConformanceError::OracleInvalid { source })?;
        if oracle.schema_version != CONFORMANCE_SCHEMA {
            return Err(ConformanceError::OracleSchema {
                found: oracle.schema_version,
                expected: CONFORMANCE_SCHEMA,
            });
        }
        if oracle.cases.is_empty() {
            return Err(ConformanceError::OracleEmpty);
        }
        Ok(oracle)
    }
}

/// One candidate trial: the case it selected, the class it ran under, its
/// outcome and the pointer a reviewer re-reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub case_id: String,
    pub mode: TrialMode,
    pub outcome: TrialOutcome,
    /// The retained evidence pointer. A pass without one is a fake pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// Why a censored trial did not run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
}

/// One candidate's complete run: its implementation identity and every
/// selected trial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateRun {
    pub implementation: String,
    pub observations: Vec<Observation>,
}

/// Why a report is not accepted. Each rejection names the exact cell or path,
/// so a defect is attributable instead of a bare non-pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rejection", rename_all = "snake_case")]
pub enum Rejection {
    /// No case was selected: zero executed cases prove nothing.
    ZeroSelection,
    /// A contract case failed: the candidate is defective.
    ProductDefect { case_id: String },
    /// A pass without evidence, a control that passed, a not-run case that
    /// claims an outcome, a mode mismatch, or an unsupported citation.
    FakePass { case_id: String, cause: String },
    /// A non-pass row carries no evidence to re-read.
    EvidenceMissing { case_id: String },
    /// A required case did not run; NOT_RUN is not a pass.
    NotRun { case_id: String },
    /// The plan names a case twice.
    Collision { case_id: String },
    /// A plan case was never selected.
    Omission { case_id: String },
}

/// One evaluated case: expectation, observation and the verdict with the
/// evidence pointer intact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceRow {
    pub case_id: String,
    pub mode: TrialMode,
    pub expected: ExpectedOutcome,
    pub observed: TrialOutcome,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
}

/// The counted trials of one mode class.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeCounts {
    pub passed: u32,
    pub failed: u32,
    pub censored: u32,
    #[serde(default)]
    pub unserved: u32,
}

/// The counts a matched report carries, split by trial class.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrialCounts {
    pub deterministic: ModeCounts,
    pub replay: ModeCounts,
    pub live: ModeCounts,
}

impl TrialCounts {
    fn record(&mut self, mode: TrialMode, outcome: TrialOutcome) {
        let counts = match mode {
            TrialMode::Deterministic => &mut self.deterministic,
            TrialMode::Replay => &mut self.replay,
            TrialMode::Live => &mut self.live,
        };
        match outcome {
            TrialOutcome::Pass => counts.passed = counts.passed.saturating_add(1),
            TrialOutcome::Fail => counts.failed = counts.failed.saturating_add(1),
            TrialOutcome::Censored => counts.censored = counts.censored.saturating_add(1),
            TrialOutcome::Unserved => counts.unserved = counts.unserved.saturating_add(1),
        }
    }

    /// Every trial that did not run, across classes. A recorded terminal
    /// denial is not a run either.
    pub fn not_run(self) -> u32 {
        self.deterministic
            .censored
            .saturating_add(self.deterministic.unserved)
            .saturating_add(self.replay.censored)
            .saturating_add(self.replay.unserved)
            .saturating_add(self.live.censored)
            .saturating_add(self.live.unserved)
    }
}

/// The evaluator's matched report: the exact candidate, oracle digest, every
/// row (including failed and censored ones) and the one rejection, if any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub schema_version: u32,
    pub candidate: String,
    pub oracle_digest: String,
    pub rows: Vec<ConformanceRow>,
    pub counts: TrialCounts,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection: Option<Rejection>,
}

impl ConformanceReport {
    /// The failed and censored rows a report must keep visible.
    pub fn retained(&self) -> impl Iterator<Item = &ConformanceRow> {
        self.rows.iter().filter(|row| {
            matches!(
                row.observed,
                TrialOutcome::Fail | TrialOutcome::Censored | TrialOutcome::Unserved
            )
        })
    }
}

/// Failures of binding or checking a conformance plan; these are not case
/// verdicts and never carry a fabricated report.
#[derive(Debug, thiserror::Error)]
pub enum ConformanceError {
    #[error("the oracle path {} is inside the candidate", path.display())]
    OracleInsideCandidate { path: PathBuf },
    #[error("the materialized oracle {} is inside the candidate", path.display())]
    MaterializedInsideCandidate { path: PathBuf },
    #[error("the conformance oracle {} could not be read: {source}", path.display())]
    OracleRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("the conformance oracle {} is larger than {limit} bytes", path.display())]
    OracleTooLarge { path: PathBuf, limit: usize },
    #[error("the conformance oracle is not valid: {source}")]
    OracleInvalid {
        #[source]
        source: serde_json::Error,
    },
    #[error("the conformance oracle speaks schema {found}, not {expected}")]
    OracleSchema { found: u32, expected: u32 },
    #[error("the conformance oracle declares no case")]
    OracleEmpty,
    #[error("the conjunction cell {case_id} is missing")]
    ConjunctionMissing { case_id: String },
    #[error("the conjunction cell {case_id} is duplicated")]
    ConjunctionCollision { case_id: String },
    #[error("the conjunction cell {case_id} carries mode {mode}, not {expected}")]
    ConjunctionMode {
        case_id: String,
        mode: &'static str,
        expected: &'static str,
    },
}

impl ConformanceError {
    /// The wire code this failure reports: a leaked or unreadable oracle is a
    /// blocked dependency, a malformed plan is invalid input, and a foreign
    /// schema is an unsupported version.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::OracleRead { .. } | Self::OracleTooLarge { .. } => ErrorCode::DependencyBlocked,
            Self::OracleInsideCandidate { .. } | Self::MaterializedInsideCandidate { .. } => {
                ErrorCode::Denied
            }
            Self::OracleInvalid { .. }
            | Self::OracleEmpty
            | Self::ConjunctionMissing { .. }
            | Self::ConjunctionCollision { .. }
            | Self::ConjunctionMode { .. } => ErrorCode::InvalidInput,
            Self::OracleSchema { .. } => ErrorCode::UnsupportedVersion,
        }
    }
}

/// Reads one oracle file through its byte bound: a non-regular target is
/// refused before the open (a FIFO with no writer never blocks), and the
/// length and take bounds refuse an oversized file.
fn read_bounded_oracle(path: &Path) -> Result<Vec<u8>, ConformanceError> {
    let length = match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(_) => {
            return Err(ConformanceError::OracleRead {
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "oracle is not a regular file",
                ),
            });
        }
        Err(source) => {
            return Err(ConformanceError::OracleRead {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let file = std::fs::File::open(path).map_err(|source| ConformanceError::OracleRead {
        path: path.to_path_buf(),
        source,
    })?;
    if length > ORACLE_MAX_BYTES as u64 {
        return Err(ConformanceError::OracleTooLarge {
            path: path.to_path_buf(),
            limit: ORACLE_MAX_BYTES,
        });
    }
    let mut bytes = Vec::with_capacity(length as usize);
    let mut bounded = file.take(ORACLE_MAX_BYTES as u64 + 1);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|source| ConformanceError::OracleRead {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() > ORACLE_MAX_BYTES {
        return Err(ConformanceError::OracleTooLarge {
            path: path.to_path_buf(),
            limit: ORACLE_MAX_BYTES,
        });
    }
    Ok(bytes)
}

/// One oracle bound from its external path and materialized outside the
/// candidate; the temp directory is the only holder of the bytes the
/// evaluator reads.
#[derive(Debug)]
pub struct ProtectedOracle {
    directory: tempfile::TempDir,
    path: PathBuf,
    digest: String,
    oracle: Oracle,
}

impl ProtectedOracle {
    /// Bind the oracle at `oracle_path` for `candidate_root`: a path inside
    /// the candidate is refused as a leak, the bytes are copied into a
    /// `TempDir` outside the checkout and the parsed plan is kept beside them.
    pub fn bind(candidate_root: &Path, oracle_path: &Path) -> Result<Self, ConformanceError> {
        let candidate = std::fs::canonicalize(candidate_root).map_err(|source| {
            ConformanceError::OracleRead {
                path: candidate_root.to_path_buf(),
                source,
            }
        })?;
        let resolved =
            std::fs::canonicalize(oracle_path).map_err(|source| ConformanceError::OracleRead {
                path: oracle_path.to_path_buf(),
                source,
            })?;
        if resolved.starts_with(&candidate) {
            return Err(ConformanceError::OracleInsideCandidate { path: resolved });
        }
        let bytes = read_bounded_oracle(&resolved)?;
        let oracle = Oracle::load(&bytes)?;
        let directory = tempfile::Builder::new()
            .prefix("rivect-conformance-oracle-")
            .tempdir()
            .map_err(|source| ConformanceError::OracleRead {
                path: std::env::temp_dir(),
                source,
            })?;
        let materialized = std::fs::canonicalize(directory.path()).map_err(|source| {
            ConformanceError::OracleRead {
                path: directory.path().to_path_buf(),
                source,
            }
        })?;
        if materialized.starts_with(&candidate) {
            return Err(ConformanceError::MaterializedInsideCandidate { path: materialized });
        }
        let path = materialized.join("oracle.json");
        std::fs::write(&path, &bytes).map_err(|source| ConformanceError::OracleRead {
            path: path.clone(),
            source,
        })?;
        let digest = crate::config::hex(&Sha256::digest(&bytes));
        Ok(Self {
            directory,
            path,
            digest,
            oracle,
        })
    }

    /// The materialized fixture path, outside the candidate.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The digest of the exact oracle bytes this evaluation reads.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The plan materialized beside the fixture.
    pub fn oracle(&self) -> &Oracle {
        &self.oracle
    }

    /// The temp directory's own path; dropping the binding removes it.
    pub fn directory(&self) -> &Path {
        self.directory.path()
    }
}

fn evidence_present(observation: &Observation) -> bool {
    observation
        .evidence
        .as_deref()
        .is_some_and(|evidence| !evidence.trim().is_empty())
}

fn reject(slot: &mut Option<Rejection>, next: Rejection) {
    if slot.is_none() {
        *slot = Some(next);
    }
}

/// Evaluate one candidate run against its protected oracle. The report is
/// returned even when it is not accepted: failed and censored rows stay
/// retained, and the rejection names exactly what failed.
pub fn evaluate(oracle: &ProtectedOracle, run: &CandidateRun) -> ConformanceReport {
    let mut rejection: Option<Rejection> = None;
    let mut rows = Vec::with_capacity(oracle.oracle.cases.len());
    let mut counts = TrialCounts::default();

    if run.observations.is_empty() {
        reject(&mut rejection, Rejection::ZeroSelection);
    }

    let mut plans: BTreeMap<&str, &OracleCase> = BTreeMap::new();
    for case in &oracle.oracle.cases {
        if plans.insert(case.case_id.as_str(), case).is_some() {
            reject(
                &mut rejection,
                Rejection::Collision {
                    case_id: case.case_id.clone(),
                },
            );
        }
    }

    let mut selected: BTreeMap<&str, &Observation> = BTreeMap::new();
    for observation in &run.observations {
        if !plans.contains_key(observation.case_id.as_str()) {
            reject(
                &mut rejection,
                Rejection::FakePass {
                    case_id: observation.case_id.clone(),
                    cause: "unsupported case".to_string(),
                },
            );
            continue;
        }
        if selected
            .insert(observation.case_id.as_str(), observation)
            .is_some()
        {
            reject(
                &mut rejection,
                Rejection::Collision {
                    case_id: observation.case_id.clone(),
                },
            );
        }
    }

    for case in &oracle.oracle.cases {
        let Some(observation) = selected.get(case.case_id.as_str()) else {
            reject(
                &mut rejection,
                Rejection::Omission {
                    case_id: case.case_id.clone(),
                },
            );
            continue;
        };
        let mut accepted = true;
        if observation.mode != case.mode {
            accepted = false;
            reject(
                &mut rejection,
                Rejection::FakePass {
                    case_id: case.case_id.clone(),
                    cause: "mode mismatch".to_string(),
                },
            );
        }
        match (case.expected, observation.outcome) {
            (ExpectedOutcome::Pass, TrialOutcome::Pass) => {
                if evidence_present(observation) {
                    counts.record(case.mode, TrialOutcome::Pass);
                } else {
                    // A pass without evidence is recorded as no pass, so the
                    // counts never report one the report itself rejected.
                    accepted = false;
                    reject(
                        &mut rejection,
                        Rejection::FakePass {
                            case_id: case.case_id.clone(),
                            cause: "pass without evidence".to_string(),
                        },
                    );
                }
            }
            (ExpectedOutcome::Pass, TrialOutcome::Fail) => {
                accepted = false;
                counts.record(case.mode, TrialOutcome::Fail);
                reject(
                    &mut rejection,
                    Rejection::ProductDefect {
                        case_id: case.case_id.clone(),
                    },
                );
            }
            (ExpectedOutcome::Pass, TrialOutcome::Censored | TrialOutcome::Unserved) => {
                accepted = false;
                counts.record(case.mode, observation.outcome);
                reject(
                    &mut rejection,
                    Rejection::NotRun {
                        case_id: case.case_id.clone(),
                    },
                );
            }
            (ExpectedOutcome::Fail, TrialOutcome::Fail) => {
                if evidence_present(observation) {
                    counts.record(case.mode, TrialOutcome::Fail);
                } else {
                    accepted = false;
                    counts.record(case.mode, TrialOutcome::Fail);
                    reject(
                        &mut rejection,
                        Rejection::EvidenceMissing {
                            case_id: case.case_id.clone(),
                        },
                    );
                }
            }
            (ExpectedOutcome::Fail, TrialOutcome::Pass) => {
                accepted = false;
                counts.record(case.mode, TrialOutcome::Pass);
                reject(
                    &mut rejection,
                    Rejection::FakePass {
                        case_id: case.case_id.clone(),
                        cause: "control passed".to_string(),
                    },
                );
            }
            (ExpectedOutcome::Fail, TrialOutcome::Censored | TrialOutcome::Unserved) => {
                accepted = false;
                counts.record(case.mode, observation.outcome);
                reject(
                    &mut rejection,
                    Rejection::NotRun {
                        case_id: case.case_id.clone(),
                    },
                );
            }
            (ExpectedOutcome::NotRun, TrialOutcome::Censored | TrialOutcome::Unserved) => {
                counts.record(case.mode, observation.outcome);
            }
            (ExpectedOutcome::NotRun, TrialOutcome::Pass | TrialOutcome::Fail) => {
                accepted = false;
                counts.record(case.mode, observation.outcome);
                reject(
                    &mut rejection,
                    Rejection::FakePass {
                        case_id: case.case_id.clone(),
                        cause: "not-run case claims an outcome".to_string(),
                    },
                );
            }
        }
        rows.push(ConformanceRow {
            case_id: case.case_id.clone(),
            mode: case.mode,
            expected: case.expected,
            observed: observation.outcome,
            accepted,
            evidence: observation.evidence.clone(),
            cause: observation.cause.clone(),
        });
    }

    ConformanceReport {
        schema_version: CONFORMANCE_SCHEMA,
        candidate: run.implementation.clone(),
        oracle_digest: oracle.digest.clone(),
        rows,
        counts,
        accepted: rejection.is_none(),
        rejection,
    }
}

/// The three custom dialect paths every provider roster carries.
pub const CUSTOM_DIALECTS: [&str; 3] = [
    "custom-chat-completions",
    "custom-responses",
    "custom-messages",
];

/// The five provider trial classes each custom path carries.
pub const CUSTOM_TRIALS: [&str; 5] = ["CATALOG", "AUTH", "WIRE", "RECOVERY", "INSTALLED"];

/// The five search service rows.
pub const SEARCH_SERVICES: [&str; 5] = ["exa", "kagi", "parallel", "perplexity", "tavily"];

/// The four search trial classes each service carries.
pub const SEARCH_TRIALS: [&str; 4] = ["AUTH", "RESULT", "RECOVERY", "INSTALLED"];

/// One required conjunction cell: the case id and the trial class it must
/// declare. Catalog/auth/wire/result/recovery rows run offline; the installed
/// row is action-time gated and therefore live.
pub fn conjunction_cells() -> Vec<(String, TrialMode)> {
    let mut cells = Vec::with_capacity(
        CUSTOM_DIALECTS.len() * CUSTOM_TRIALS.len() + SEARCH_SERVICES.len() * SEARCH_TRIALS.len(),
    );
    for dialect in CUSTOM_DIALECTS {
        for trial in CUSTOM_TRIALS {
            let mode = if trial == "INSTALLED" {
                TrialMode::Live
            } else {
                TrialMode::Deterministic
            };
            cells.push((format!("TP-PROVIDER-{trial}::{dialect}"), mode));
        }
    }
    for service in SEARCH_SERVICES {
        for trial in SEARCH_TRIALS {
            let mode = if trial == "INSTALLED" {
                TrialMode::Live
            } else {
                TrialMode::Deterministic
            };
            cells.push((format!("TP-SEARCH-{service}-{trial}"), mode));
        }
    }
    cells
}

/// The counted conjunction: how many required cells are present and how many
/// declare an executed (non-censored) trial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConjunctionCounts {
    pub custom: u32,
    pub search: u32,
    pub present: u32,
    pub executed: u32,
}

/// Verify that the custom3×5TP and search5×4TP families are all present,
/// exactly once, under their declared trial class. A missing, duplicated or
/// mislabelled cell is not a smaller denominator: it is a rejected plan.
pub fn verify_conjunction(rows: &[ConformanceRow]) -> Result<ConjunctionCounts, ConformanceError> {
    let mut counts = ConjunctionCounts {
        custom: 0,
        search: 0,
        present: 0,
        executed: 0,
    };
    for (case_id, mode) in conjunction_cells() {
        let matching = rows
            .iter()
            .filter(|row| row.case_id == case_id)
            .collect::<Vec<_>>();
        match matching.as_slice() {
            [] => return Err(ConformanceError::ConjunctionMissing { case_id }),
            [row] => {
                if row.mode != mode {
                    return Err(ConformanceError::ConjunctionMode {
                        case_id,
                        mode: row.mode.as_str(),
                        expected: mode.as_str(),
                    });
                }
                counts.present = counts.present.saturating_add(1);
                if row.observed != TrialOutcome::Censored {
                    counts.executed = counts.executed.saturating_add(1);
                }
                if case_id.starts_with("TP-PROVIDER-") {
                    counts.custom = counts.custom.saturating_add(1);
                } else {
                    counts.search = counts.search.saturating_add(1);
                }
            }
            _ => return Err(ConformanceError::ConjunctionCollision { case_id }),
        }
    }
    Ok(counts)
}

// ----- final release conjunction (REQ-068, AC-082) -----

/// The 36 source scenarios §16.10 the release conjunction must carry.
pub const SOURCE_SCENARIOS: [&str; 36] = [
    "A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10", "A11", "A12", "A13",
    "A14", "A15", "A16", "A17", "A18", "A19", "A20", "A21", "A22", "A23", "A24", "A25", "A26",
    "A27", "A28", "A29", "A30", "A31", "A32", "A33", "A34", "A35", "A36",
];

/// The delivery-criteria sections §17–§17.2.
pub const RELEASE_SECTIONS: [&str; 3] = ["17", "17.1", "17.2"];

/// The upgrade leg AC-082 names: N→N+1→N+2 keeps both the new basis and the
/// personal delta.
pub const UPGRADE_CASE: &str = "AC-082-N-N+1-N+2";

/// The installed ordinary-task leg: the packaged TUI publishes the production
/// start question and `begin` drains it to one settlement; final acceptance
/// reads the candidate-bound retained receipt (`tests/installed.rs`).
pub const INSTALLED_ORDINARY_CASE: &str = "AC-001-INSTALLED-ORDINARY";

/// The installed UI leg: all 19 inherited states render through the packaged
/// `--ui-review` entry, and final acceptance reads the candidate-bound
/// 19×G×I matrix (`tests/installed_tui.rs`).
pub const INSTALLED_UI_CASE: &str = "AC-001-INSTALLED-UI-RENDER";

/// The three release-only cases outside A01–A36 and §17–§17.2.
pub const RELEASE_CASE_IDS: [&str; 3] = [UPGRADE_CASE, INSTALLED_ORDINARY_CASE, INSTALLED_UI_CASE];

/// The 74 provider rows with the dialect the registry must answer for each.
pub const PROVIDER_ROWS: [(&str, &str); 74] = [
    ("openai", "responses"),
    ("abliteration", "responses"),
    ("meta", "responses"),
    ("ollama", "responses"),
    ("custom-responses", "responses"),
    ("openrouter", "responses"),
    ("sakana", "responses"),
    ("xai", "responses"),
    ("xai-oauth", "responses"),
    ("openai-codex", "responses"),
    ("openai-codex-device", "responses"),
    ("amazon-bedrock", "converse"),
    ("bedrock-mantle", "responses"),
    ("cursor", "cursor-agent"),
    ("devin", "devin-agent"),
    ("gitlab-duo-agent", "gitlab-workflow"),
    ("ollama-cloud", "ollama-chat"),
    ("google", "gemini"),
    ("google-vertex", "vertex"),
    ("google-antigravity", "cloudcode"),
    ("google-gemini-cli", "cloudcode"),
    ("anthropic", "messages"),
    ("minimax", "messages"),
    ("umans", "messages"),
    ("cloudflare-ai-gateway", "messages"),
    ("custom-messages", "messages"),
    ("vercel-ai-gateway", "messages"),
    ("kimi-code", "messages"),
    ("zai", "messages"),
    ("zai-coding-plan", "messages"),
    ("gitlab-duo", "chat-completions"),
    ("github-copilot", "chat-completions"),
    ("opencode-go", "chat-completions"),
    ("opencode-zen", "chat-completions"),
    ("custom-chat-completions", "chat-completions"),
    ("aiand", "chat-completions"),
    ("aimlapi", "chat-completions"),
    ("alibaba-coding-plan", "chat-completions"),
    ("alibaba-token-plan", "chat-completions"),
    ("coreweave", "chat-completions"),
    ("deepinfra", "chat-completions"),
    ("deepseek", "chat-completions"),
    ("firepass", "chat-completions"),
    ("fireworks", "chat-completions"),
    ("gmi-cloud", "chat-completions"),
    ("groq", "chat-completions"),
    ("huggingface", "chat-completions"),
    ("kilo", "chat-completions"),
    ("litellm", "chat-completions"),
    ("llama.cpp", "chat-completions"),
    ("lm-studio", "chat-completions"),
    ("minimax-code", "chat-completions"),
    ("minimax-code-cn", "chat-completions"),
    ("mistral", "chat-completions"),
    ("moonshot", "chat-completions"),
    ("nanogpt", "chat-completions"),
    ("novita", "chat-completions"),
    ("nvidia", "chat-completions"),
    ("qianfan", "chat-completions"),
    ("qwen-portal", "chat-completions"),
    ("siliconflow", "chat-completions"),
    ("siliconflow-cn", "chat-completions"),
    ("synthetic", "chat-completions"),
    ("together", "chat-completions"),
    ("venice", "chat-completions"),
    ("vllm", "chat-completions"),
    ("wafer-serverless", "chat-completions"),
    ("xiaomi", "chat-completions"),
    ("xiaomi-token-plan-ams", "chat-completions"),
    ("xiaomi-token-plan-cn", "chat-completions"),
    ("xiaomi-token-plan-sgp", "chat-completions"),
    ("yolo-auto", "chat-completions"),
    ("zenmux", "chat-completions"),
    ("zhipu-coding-plan", "chat-completions"),
];

/// Both login alias rows and the canonical provider each stores.
pub const ALIAS_ROWS: [(&str, &str); 2] = [
    ("openai-codex-device", "openai-codex"),
    ("zai-coding-plan", "zai"),
];

/// The five trial classes every provider row carries.
pub const PROVIDER_TRIALS: [&str; 5] = CUSTOM_TRIALS;

/// The 19 inherited design-brief states the installed UI matrix covers.
pub const UI_STATES: [&str; 19] = [
    "start-no-connection",
    "no-project-index",
    "ready-for-input",
    "streaming-long-output",
    "parallel-work",
    "awaiting-decision",
    "awaiting-permission",
    "fullscreen-inline",
    "pause-cancel",
    "quota-fallback",
    "error-offline-partial",
    "success",
    "settings-default-modified-locked-pending",
    "settings-invalid-conflict",
    "resume-compaction-upgrade",
    "rewind-preview-conflict-partial",
    "big-list-narrow-window",
    "workflow-off",
    "non-tty",
];

/// The five acceptance geometries.
pub const UI_GEOMETRIES: [&str; 5] = ["60x20", "80x24", "120x40", "160x50", "live-resize"];

/// The fourteen accepted input modes.
pub const UI_INPUTS: [&str; 14] = [
    "keyboard-only",
    "vim",
    "unicode",
    "paste",
    "no-color",
    "light",
    "dark",
    "high-contrast",
    "reduced-motion",
    "plain",
    "fullscreen",
    "inline",
    "mouse",
    "tmux",
];

/// 74 provider rows × five trial classes plus both alias rows.
pub const FINAL_PROVIDER_ROWS: usize =
    PROVIDER_ROWS.len() * PROVIDER_TRIALS.len() + ALIAS_ROWS.len();

/// The installed TP's counted rows: 74 providers plus both aliases.
pub const FINAL_INSTALLED_ROWS: usize = PROVIDER_ROWS.len() + ALIAS_ROWS.len();

/// 19 states × five geometries × fourteen input modes.
pub const FINAL_UI_CELLS: usize = UI_STATES.len() * UI_GEOMETRIES.len() * UI_INPUTS.len();

/// One provider trial case: the stable id the aggregate counts.
pub fn provider_case(trial: &str, provider: &str) -> String {
    format!("TP-PROVIDER-{trial}::{provider}")
}

/// The three trial classes the offline provider receipt carries.
pub const OFFLINE_PROVIDER_TRIALS: [&str; 3] = ["AUTH", "WIRE", "RECOVERY"];

/// The 74 providers × three offline trial classes the provider receipt binds.
pub const OFFLINE_PROVIDER_ROWS: usize = PROVIDER_ROWS.len() * OFFLINE_PROVIDER_TRIALS.len();

/// The two recorded providers with no installed adapter. Their six
/// AUTH/WIRE/RECOVERY rows are terminal `Unserved`, never `passed`.
pub const UNSERVED_PROVIDERS: [&str; 2] = ["cursor", "devin"];

/// Every case id the recorded unserved class excludes from `passed`.
pub fn unserved_cases() -> Vec<String> {
    let mut cases = Vec::with_capacity(UNSERVED_PROVIDERS.len() * OFFLINE_PROVIDER_TRIALS.len());
    for provider in UNSERVED_PROVIDERS {
        for trial in OFFLINE_PROVIDER_TRIALS {
            cases.push(provider_case(trial, provider));
        }
    }
    cases
}

/// Whether `case_id` is one of the six recorded terminal denials.
#[must_use]
pub fn is_unserved_case(case_id: &str) -> bool {
    UNSERVED_PROVIDERS.iter().any(|provider| {
        OFFLINE_PROVIDER_TRIALS
            .iter()
            .any(|trial| provider_case(trial, provider) == case_id)
    })
}

/// One alias installed-row case.
pub fn alias_case(alias: &str) -> String {
    format!("TP-ALIAS-INSTALLED::{alias}")
}

/// One installed UI cell case: state, geometry and input mode.
pub fn ui_case(state: &str, geometry: &str, input: &str) -> String {
    format!("UI::{state}::{geometry}::{input}")
}

/// Every case the final conjunction must carry, exactly once. The union
/// includes the conformance cells [`conjunction_cells`] declares, so the
/// provider and search families stay one counted set.
pub fn final_required_cases() -> Vec<String> {
    let mut cases = BTreeSet::new();
    for id in SOURCE_SCENARIOS {
        cases.insert(id.to_string());
    }
    for section in RELEASE_SECTIONS {
        cases.insert(section.to_string());
    }
    for id in RELEASE_CASE_IDS {
        cases.insert(id.to_string());
    }
    for (id, _dialect) in PROVIDER_ROWS {
        for trial in PROVIDER_TRIALS {
            cases.insert(provider_case(trial, id));
        }
    }
    for (alias, _canonical) in ALIAS_ROWS {
        cases.insert(alias_case(alias));
    }
    for (case_id, _mode) in conjunction_cells() {
        cases.insert(case_id);
    }
    for state in UI_STATES {
        for geometry in UI_GEOMETRIES {
            for input in UI_INPUTS {
                cases.insert(ui_case(state, geometry, input));
            }
        }
    }
    cases.into_iter().collect()
}

/// The offline evidence receipt schema this build writes and reads.
pub const OFFLINE_EVIDENCE_SCHEMA: u32 = 1;

/// The producer version this build accepts.
pub const OFFLINE_EVIDENCE_PRODUCER_VERSION: &str = "1";

/// The receipt and manifest byte bounds; an oversized document is refused
/// before it is parsed.
pub const OFFLINE_EVIDENCE_MAX_BYTES: usize = 4 * 1024 * 1024;

/// The three offline evidence families and their fixed denominators.
pub const OFFLINE_FAMILIES: [(&str, usize); 3] = [
    ("provider", OFFLINE_PROVIDER_ROWS),
    ("acceptance", 40),
    ("search", 20),
];

/// The family denominator the receipt must carry, or `None` for an unknown
/// family.
#[must_use]
pub fn offline_family_denominator(family: &str) -> Option<usize> {
    OFFLINE_FAMILIES
        .iter()
        .find(|(name, _count)| *name == family)
        .map(|(_name, count)| *count)
}

/// What one checked-in manifest row expects from its oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialExpectation {
    Pass,
    Unserved,
}

/// One checked-in offline-evidence manifest row: the case, its provider,
/// the exact integration oracles and the marker their output must carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineEvidenceManifestRow {
    pub case_id: String,
    pub provider: String,
    pub oracle: Vec<String>,
    pub marker: String,
    pub expected: TrialExpectation,
    pub observation: String,
}

/// The checked-in manifest a receipt is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineEvidenceManifest {
    pub schema_version: u32,
    pub family: String,
    pub rows: Vec<OfflineEvidenceManifestRow>,
}

impl OfflineEvidenceManifest {
    /// Parse one manifest under the document byte bound.
    ///
    /// # Errors
    /// Returns [`OfflineEvidenceError`] when the document is oversized,
    /// malformed, or fails [`Self::validate`].
    pub fn load(bytes: &[u8]) -> Result<Self, OfflineEvidenceError> {
        if bytes.len() > OFFLINE_EVIDENCE_MAX_BYTES {
            return Err(OfflineEvidenceError::TooLarge {
                limit: OFFLINE_EVIDENCE_MAX_BYTES,
            });
        }
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|source| OfflineEvidenceError::Malformed { source })?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validate the manifest's own shape and its fixed denominator.
    ///
    /// # Errors
    /// Returns [`OfflineEvidenceError`] naming the first rejected row.
    pub fn validate(&self) -> Result<(), OfflineEvidenceError> {
        if self.schema_version != OFFLINE_EVIDENCE_SCHEMA {
            return Err(OfflineEvidenceError::Schema {
                found: self.schema_version,
                expected: OFFLINE_EVIDENCE_SCHEMA,
            });
        }
        let Some(denominator) = offline_family_denominator(&self.family) else {
            return Err(OfflineEvidenceError::UnknownFamily {
                family: self.family.clone(),
            });
        };
        if self.rows.len() != denominator {
            return Err(OfflineEvidenceError::Denominator {
                declared: self.rows.len(),
                expected: denominator,
            });
        }
        let mut seen = BTreeSet::new();
        for row in &self.rows {
            if !seen.insert(row.case_id.as_str()) {
                return Err(OfflineEvidenceError::DuplicateCase {
                    case_id: row.case_id.clone(),
                });
            }
            if row.provider.trim().is_empty() {
                return Err(OfflineEvidenceError::Omission {
                    case_id: row.case_id.clone(),
                });
            }
            if row.oracle.is_empty()
                || row.oracle.iter().any(|oracle| {
                    let Some((target, test)) = oracle.split_once("::") else {
                        return true;
                    };
                    target.trim().is_empty()
                        || test.trim().is_empty()
                        || matches!(target, "lib" | "bin")
                })
            {
                return Err(OfflineEvidenceError::Evidence {
                    case_id: row.case_id.clone(),
                });
            }
            if row.marker.trim().is_empty() {
                return Err(OfflineEvidenceError::Marker {
                    case_id: row.case_id.clone(),
                });
            }
            if row.observation.trim().is_empty() || row.observation.contains('\n') {
                return Err(OfflineEvidenceError::Observation {
                    case_id: row.case_id.clone(),
                });
            }
            match row.expected {
                TrialExpectation::Pass if is_unserved_case(&row.case_id) => {
                    return Err(OfflineEvidenceError::OutcomeMismatch {
                        case_id: row.case_id.clone(),
                    });
                }
                TrialExpectation::Unserved if !is_unserved_case(&row.case_id) => {
                    return Err(OfflineEvidenceError::UnservedOutsideRecordedSet {
                        case_id: row.case_id.clone(),
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// One executed integration target in the receipt: its exact command, exit,
/// retained output digest and the oracle cases it served.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineEvidenceTarget {
    pub target: String,
    pub command: String,
    pub exit: i32,
    pub output_sha256: String,
    pub cases: u32,
}

/// One receipt row: the case, the exact oracle it ran as, the marker that
/// oracle printed and the terminal outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRow {
    pub case_id: String,
    pub evidence: String,
    pub marker: String,
    pub outcome: TrialOutcome,
}

/// The receipt's counted split: every row is terminal, never all passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineEvidenceCounts {
    pub rows: usize,
    pub pass: usize,
    pub unserved: usize,
}

/// The candidate-bound offline evidence receipt the final conjunction
/// consumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineEvidenceReceipt {
    pub schema_version: u32,
    pub producer_version: String,
    pub family: String,
    pub candidate_manifest_sha256: String,
    pub manifest_sha256: String,
    pub targets: Vec<OfflineEvidenceTarget>,
    pub rows: Vec<EvidenceRow>,
    pub counts: OfflineEvidenceCounts,
}

impl OfflineEvidenceReceipt {
    /// Parse one receipt under the document byte bound.
    ///
    /// # Errors
    /// Returns [`OfflineEvidenceError`] when the document is oversized or
    /// malformed.
    pub fn load(bytes: &[u8]) -> Result<Self, OfflineEvidenceError> {
        if bytes.len() > OFFLINE_EVIDENCE_MAX_BYTES {
            return Err(OfflineEvidenceError::TooLarge {
                limit: OFFLINE_EVIDENCE_MAX_BYTES,
            });
        }
        serde_json::from_slice(bytes).map_err(|source| OfflineEvidenceError::Malformed { source })
    }

    /// Validate this receipt against the exact checked-in manifest bytes.
    /// Every accepted row is candidate-bound, oracle-named and terminal.
    ///
    /// # Errors
    /// Returns [`OfflineEvidenceError`] naming the first rejected cell.
    pub fn validate(
        &self,
        manifest_bytes: &[u8],
        manifest: &OfflineEvidenceManifest,
    ) -> Result<(), OfflineEvidenceError> {
        if self.schema_version != OFFLINE_EVIDENCE_SCHEMA {
            return Err(OfflineEvidenceError::Schema {
                found: self.schema_version,
                expected: OFFLINE_EVIDENCE_SCHEMA,
            });
        }
        if self.producer_version != OFFLINE_EVIDENCE_PRODUCER_VERSION {
            return Err(OfflineEvidenceError::ProducerVersion {
                found: self.producer_version.clone(),
                expected: OFFLINE_EVIDENCE_PRODUCER_VERSION,
            });
        }
        if manifest.schema_version != OFFLINE_EVIDENCE_SCHEMA || manifest.family != self.family {
            return Err(OfflineEvidenceError::UnknownFamily {
                family: self.family.clone(),
            });
        }
        let Some(denominator) = offline_family_denominator(&self.family) else {
            return Err(OfflineEvidenceError::UnknownFamily {
                family: self.family.clone(),
            });
        };
        if manifest.rows.len() != denominator || self.rows.len() != denominator {
            return Err(OfflineEvidenceError::Denominator {
                declared: self.rows.len(),
                expected: denominator,
            });
        }
        if !is_hex_64(&self.candidate_manifest_sha256) {
            return Err(OfflineEvidenceError::CandidateDigest);
        }
        let expected_manifest = crate::config::hex(&Sha256::digest(manifest_bytes));
        if self.manifest_sha256 != expected_manifest {
            return Err(OfflineEvidenceError::ManifestDigest {
                declared: self.manifest_sha256.clone(),
                expected: expected_manifest,
            });
        }
        let expected_counts = OfflineEvidenceCounts {
            rows: self.rows.len(),
            pass: self
                .rows
                .iter()
                .filter(|row| row.outcome == TrialOutcome::Pass)
                .count(),
            unserved: self
                .rows
                .iter()
                .filter(|row| row.outcome == TrialOutcome::Unserved)
                .count(),
        };
        if self.counts != expected_counts
            || expected_counts.pass + expected_counts.unserved != denominator
        {
            return Err(OfflineEvidenceError::Counts {
                declared: self.counts,
                expected: expected_counts,
            });
        }

        let mut targets = BTreeSet::new();
        for target in &self.targets {
            if target.target.trim().is_empty()
                || matches!(target.target.as_str(), "lib" | "bin")
                || target.exit != 0
                || !is_hex_64(&target.output_sha256)
                || target.cases == 0
                || !target
                    .command
                    .contains(&format!("--test {}", target.target))
                || !target.command.contains("--locked")
            {
                return Err(OfflineEvidenceError::Target {
                    target: target.target.clone(),
                });
            }
            if !targets.insert(target.target.as_str()) {
                return Err(OfflineEvidenceError::DuplicateTarget {
                    target: target.target.clone(),
                });
            }
        }

        let mut manifest_rows: BTreeMap<&str, &OfflineEvidenceManifestRow> = BTreeMap::new();
        for row in &manifest.rows {
            manifest_rows.insert(row.case_id.as_str(), row);
        }
        let required_cases = final_required_cases();
        let required: BTreeSet<&str> = required_cases.iter().map(String::as_str).collect();
        let mut seen = BTreeSet::new();
        for row in &self.rows {
            if !seen.insert(row.case_id.as_str()) {
                return Err(OfflineEvidenceError::DuplicateCase {
                    case_id: row.case_id.clone(),
                });
            }
            let Some(manifest_row) = manifest_rows.get(row.case_id.as_str()) else {
                return Err(OfflineEvidenceError::Omission {
                    case_id: row.case_id.clone(),
                });
            };
            if !required.contains(row.case_id.as_str()) {
                return Err(OfflineEvidenceError::UnexpectedCase {
                    case_id: row.case_id.clone(),
                });
            }
            let Some((target, test)) = row.evidence.split_once("::") else {
                return Err(OfflineEvidenceError::Evidence {
                    case_id: row.case_id.clone(),
                });
            };
            if row.evidence.trim().is_empty()
                || target.trim().is_empty()
                || test.trim().is_empty()
                || matches!(target, "lib" | "bin")
                || !targets.contains(target)
            {
                return Err(OfflineEvidenceError::Evidence {
                    case_id: row.case_id.clone(),
                });
            }
            if row.marker.trim().is_empty() || row.marker != manifest_row.marker {
                return Err(OfflineEvidenceError::Marker {
                    case_id: row.case_id.clone(),
                });
            }
            let expected_outcome = match manifest_row.expected {
                TrialExpectation::Pass => TrialOutcome::Pass,
                TrialExpectation::Unserved => TrialOutcome::Unserved,
            };
            if row.outcome != expected_outcome {
                return Err(OfflineEvidenceError::OutcomeMismatch {
                    case_id: row.case_id.clone(),
                });
            }
            if row.outcome == TrialOutcome::Unserved && !is_unserved_case(&row.case_id) {
                return Err(OfflineEvidenceError::UnservedOutsideRecordedSet {
                    case_id: row.case_id.clone(),
                });
            }
        }
        if seen.len() != denominator {
            return Err(OfflineEvidenceError::Denominator {
                declared: seen.len(),
                expected: denominator,
            });
        }
        Ok(())
    }
}

fn is_hex_64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Why an offline evidence document is refused.
#[derive(Debug, thiserror::Error)]
pub enum OfflineEvidenceError {
    #[error("the offline evidence document is larger than {limit} bytes")]
    TooLarge { limit: usize },
    #[error("the offline evidence document is not valid: {source}")]
    Malformed {
        #[source]
        source: serde_json::Error,
    },
    #[error("the offline evidence speaks schema {found}, not {expected}")]
    Schema { found: u32, expected: u32 },
    #[error("the offline evidence producer {found} is not {expected}")]
    ProducerVersion {
        found: String,
        expected: &'static str,
    },
    #[error("the offline evidence family {family} is not recorded")]
    UnknownFamily { family: String },
    #[error("the offline evidence declares {declared} rows, not {expected}")]
    Denominator { declared: usize, expected: usize },
    #[error("the offline evidence repeats case {case_id}")]
    DuplicateCase { case_id: String },
    #[error("the offline evidence repeats target {target}")]
    DuplicateTarget { target: String },
    #[error("the offline evidence omits or invents case {case_id}")]
    Omission { case_id: String },
    #[error("the offline evidence names a case outside the required roster: {case_id}")]
    UnexpectedCase { case_id: String },
    #[error("case {case_id} carries no integration oracle")]
    Evidence { case_id: String },
    #[error("case {case_id} carries no row marker")]
    Marker { case_id: String },
    #[error("case {case_id} carries no one-line observation")]
    Observation { case_id: String },
    #[error("case {case_id} declares the wrong terminal outcome")]
    OutcomeMismatch { case_id: String },
    #[error("case {case_id} claims unserved outside the recorded six")]
    UnservedOutsideRecordedSet { case_id: String },
    #[error("the offline evidence candidate digest is not 64 hex characters")]
    CandidateDigest,
    #[error("the offline evidence manifest digest {declared} is not {expected}")]
    ManifestDigest { declared: String, expected: String },
    #[error("the offline evidence counts {declared:?} are not {expected:?}")]
    Counts {
        declared: OfflineEvidenceCounts,
        expected: OfflineEvidenceCounts,
    },
    #[error("target {target} is not an executed integration target")]
    Target { target: String },
}

impl OfflineEvidenceError {
    /// The wire code this failure reports: all of these are malformed or
    /// stale declared evidence, never a case verdict.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::TooLarge { .. } | Self::Malformed { .. } => ErrorCode::InvalidInput,
            Self::Schema { .. } | Self::ProducerVersion { .. } => ErrorCode::UnsupportedVersion,
            Self::UnknownFamily { .. }
            | Self::Denominator { .. }
            | Self::DuplicateCase { .. }
            | Self::DuplicateTarget { .. }
            | Self::Omission { .. }
            | Self::UnexpectedCase { .. }
            | Self::Evidence { .. }
            | Self::Marker { .. }
            | Self::Observation { .. }
            | Self::OutcomeMismatch { .. }
            | Self::UnservedOutsideRecordedSet { .. }
            | Self::CandidateDigest
            | Self::ManifestDigest { .. }
            | Self::Counts { .. }
            | Self::Target { .. } => ErrorCode::InvalidInput,
        }
    }
}

/// One final-conjunction row: the exact case, the candidate whose bytes it
/// was observed on, and the retained pointer or cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalRow {
    pub case_id: String,
    pub candidate: String,
    pub outcome: TrialOutcome,
    pub evidence: Option<String>,
    pub cause: Option<String>,
}

/// Every non-pass row of the final conjunction, grouped by why it blocks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FinalBlockers {
    pub missing: Vec<String>,
    pub stale: Vec<String>,
    pub failed: Vec<String>,
    pub not_run: Vec<String>,
    pub unattributed: Vec<String>,
}

impl FinalBlockers {
    /// Whether no row blocks a full pass.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.missing.is_empty()
            && self.stale.is_empty()
            && self.failed.is_empty()
            && self.not_run.is_empty()
            && self.unattributed.is_empty()
    }
}

/// The counted final conjunction. `full_pass` is true only when every
/// required case is present, current, passed and attributed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalAcceptance {
    pub candidate: String,
    pub required: usize,
    pub present: usize,
    pub current: usize,
    pub passed: usize,
    pub unserved: usize,
    pub provider_rows: usize,
    pub alias_rows: usize,
    pub installed_rows: usize,
    pub ui_cells: usize,
    pub blockers: FinalBlockers,
    pub full_pass: bool,
}

/// The denominator the acceptance manifest declares. A declaration that
/// differs from the fixed roster is rejected, so a 372 installed-row claim or
/// any shrunken denominator is an invalid plan instead of a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalDeclaration {
    pub provider_rows: usize,
    pub installed_rows: usize,
    pub ui_cells: usize,
}

impl FinalDeclaration {
    /// The release denominator: 372 provider+alias rows, 76 installed rows,
    /// 1330 UI cells.
    #[must_use]
    pub const fn release() -> Self {
        Self {
            provider_rows: FINAL_PROVIDER_ROWS,
            installed_rows: FINAL_INSTALLED_ROWS,
            ui_cells: FINAL_UI_CELLS,
        }
    }
}

/// Why a final conjunction cannot be counted. These reject the plan; a
/// present but not-current row is a blocker inside an accepted count.
#[derive(Debug, thiserror::Error)]
pub enum FinalAcceptanceError {
    #[error("the final conjunction row {case_id} is duplicated")]
    RowCollision { case_id: String },
    #[error("the final conjunction row {case_id} is not a required case")]
    UnexpectedRow { case_id: String },
    #[error("the final conjunction row {case_id} declares unserved outside the recorded six")]
    UnservedOutsideRecordedSet { case_id: String },
    #[error("the final conjunction declares {declared} provider rows, not {expected}")]
    ProviderDenominator { declared: usize, expected: usize },
    #[error("the final conjunction declares {declared} installed rows, not {expected}")]
    InstalledDenominator { declared: usize, expected: usize },
    #[error("the final conjunction declares {declared} ui cells, not {expected}")]
    UiDenominator { declared: usize, expected: usize },
}

impl FinalAcceptanceError {
    /// The wire code this failure reports: every variant is an invalid
    /// declared plan, not a case verdict.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        ErrorCode::InvalidInput
    }
}

fn check_denominator(declaration: FinalDeclaration) -> Result<(), FinalAcceptanceError> {
    if declaration.provider_rows != FINAL_PROVIDER_ROWS {
        return Err(FinalAcceptanceError::ProviderDenominator {
            declared: declaration.provider_rows,
            expected: FINAL_PROVIDER_ROWS,
        });
    }
    if declaration.installed_rows != FINAL_INSTALLED_ROWS {
        return Err(FinalAcceptanceError::InstalledDenominator {
            declared: declaration.installed_rows,
            expected: FINAL_INSTALLED_ROWS,
        });
    }
    if declaration.ui_cells != FINAL_UI_CELLS {
        return Err(FinalAcceptanceError::UiDenominator {
            declared: declaration.ui_cells,
            expected: FINAL_UI_CELLS,
        });
    }
    Ok(())
}

fn attributed(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|text| !text.trim().is_empty())
}

/// Evaluate the final conjunction over the exact candidate. A row bound to
/// another candidate is retained as stale, never counted as current bytes.
///
/// # Errors
/// Returns [`FinalAcceptanceError`] when the declared denominator differs
/// from the fixed roster, a supplied row is duplicated, or a supplied row is
/// not a required case.
pub fn evaluate_final(
    candidate: &str,
    declaration: FinalDeclaration,
    rows: &[FinalRow],
) -> Result<FinalAcceptance, FinalAcceptanceError> {
    check_denominator(declaration)?;
    let required = final_required_cases();
    let required_set: BTreeSet<&str> = required.iter().map(String::as_str).collect();
    let mut supplied: BTreeMap<&str, &FinalRow> = BTreeMap::new();
    for row in rows {
        if !required_set.contains(row.case_id.as_str()) {
            return Err(FinalAcceptanceError::UnexpectedRow {
                case_id: row.case_id.clone(),
            });
        }
        if supplied.insert(row.case_id.as_str(), row).is_some() {
            return Err(FinalAcceptanceError::RowCollision {
                case_id: row.case_id.clone(),
            });
        }
    }

    let mut blockers = FinalBlockers::default();
    let mut current = 0usize;
    let mut passed = 0usize;
    let mut unserved = 0usize;
    for case_id in &required {
        let Some(row) = supplied.get(case_id.as_str()) else {
            blockers.missing.push(case_id.clone());
            continue;
        };
        if row.candidate != candidate {
            blockers.stale.push(case_id.clone());
            continue;
        }
        current = current.saturating_add(1);
        match row.outcome {
            TrialOutcome::Pass => {
                if attributed(&row.evidence) {
                    passed = passed.saturating_add(1);
                } else {
                    blockers.unattributed.push(case_id.clone());
                }
            }
            TrialOutcome::Unserved => {
                if !is_unserved_case(case_id) {
                    return Err(FinalAcceptanceError::UnservedOutsideRecordedSet {
                        case_id: case_id.clone(),
                    });
                }
                unserved = unserved.saturating_add(1);
            }
            TrialOutcome::Fail => blockers.failed.push(case_id.clone()),
            TrialOutcome::Censored => {
                if attributed(&row.cause) {
                    blockers.not_run.push(case_id.clone());
                } else {
                    blockers.unattributed.push(case_id.clone());
                }
            }
        }
    }

    let provider_rows = supplied
        .keys()
        .filter(|case_id| case_id.starts_with("TP-PROVIDER-"))
        .count();
    let alias_rows = supplied
        .keys()
        .filter(|case_id| case_id.starts_with("TP-ALIAS-"))
        .count();
    let installed_rows = supplied
        .keys()
        .filter(|case_id| {
            case_id.starts_with("TP-PROVIDER-INSTALLED::")
                || case_id.starts_with("TP-ALIAS-INSTALLED::")
        })
        .count();
    let ui_cells = supplied
        .keys()
        .filter(|case_id| case_id.starts_with("UI::"))
        .count();
    let present = supplied.len();
    let full_pass = current == required.len() && blockers.is_empty();

    Ok(FinalAcceptance {
        candidate: candidate.to_string(),
        required: required.len(),
        present,
        current,
        passed,
        unserved,
        provider_rows,
        alias_rows,
        installed_rows,
        ui_cells,
        blockers,
        full_pass,
    })
}
