//! Update owner (AC-055): one backup/reference snapshot of the store taken
//! only while a cutover waits, and the bounded private record of one update
//! attempt.
//!
//! The snapshot itself runs through [`TaskStore`] (the named
//! `sql::checkpoint_store` statement), so no SQL lives here and the primary is
//! never replaced: `VACUUM INTO` writes a new file beside it. The record is
//! deliberately outside the store transaction and outside the checkpoint tree,
//! so neither a rollback nor a snapshot cleanup can erase the cause an
//! operator still has to act on.

use crate::contracts::{ErrorCode, WireError};
use crate::state::TaskStore;
use rivect_sandbox_helper::{ANCHOR_O_NOFOLLOW, OPEN_NONBLOCK};
use serde::{Deserialize, Serialize};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

/// The schema version this build writes and the only one it reads.
pub const EVIDENCE_VERSION: u8 = 1;
/// The UTF-8 bound on one encoded record.
pub const EVIDENCE_MAX_BYTES: usize = 8192;
/// The bound on committed records in one data root.
pub const EVIDENCE_MAX_RECORDS: usize = 32;
/// The bound on their total bytes.
pub const EVIDENCE_MAX_TOTAL_BYTES: usize = 262_144;
/// The nesting bound the decoder refuses beyond before it projects anything.
pub const EVIDENCE_MAX_DEPTH: usize = 8;
/// The bound on secondary failures; the ninth slot is the fixed overflow row.
pub const SECONDARY_MAX: usize = 8;
/// The bound on the records one status projection decodes: the newest window, plus
/// the newest record carrying a cause. The admission `DEC-024` records lets a
/// same-base attempt through per open while a cutover stays pending, so a tree can
/// legitimately hold more than [`EVIDENCE_MAX_RECORDS`]; the read stays bounded.
pub const PROJECTION_MAX_RECORDS: usize = 32;

/// Where one attempt's record lives, relative to the data root.
pub const EVIDENCE_DIR: &str = "reports/update";
/// Where the snapshot lives, relative to the data root.
const CHECKPOINT_DIR: &str = "runtime/checkpoints";

/// The closed emit map of this slice's own seams. Each token is one distinct
/// boundary and the correction is the one line an operator can act on
/// offline; later update slices append their own rows here, and no site may
/// emit an unmapped generic operation label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UpdateBoundary {
    /// The admission every update attempt starts with: the election over the
    /// data root. A second process holding the root is refused here, so nothing
    /// this attempt owns — snapshot, record, staged row, DDL batch — is written.
    #[serde(rename = "upd.owner")]
    Owner,
    #[serde(rename = "upd.identity")]
    Identity,
    #[serde(rename = "upd.evidence.reserve")]
    EvidenceReserve,
    #[serde(rename = "upd.evidence.write")]
    EvidenceWrite,
    #[serde(rename = "upd.checkpoint.space")]
    CheckpointSpace,
    #[serde(rename = "upd.checkpoint.create")]
    CheckpointCreate,
    #[serde(rename = "upd.checkpoint.sync")]
    CheckpointSync,
    /// The base the update stages under its version: the identity and step the
    /// ledger refuses here are the caller's, not the store's.
    #[serde(rename = "upd.base.stage")]
    BaseStage,
    /// The semantic mapping of stored experiences onto the base's rule set.
    #[serde(rename = "upd.semantic")]
    Semantic,
    /// The effective policy the update validates and pins to the base.
    #[serde(rename = "upd.policy")]
    Policy,
    /// The smoke contract the update runs over the composed generation.
    #[serde(rename = "upd.smoke")]
    Smoke,
    /// The activation itself: the one transaction that replaces the serving
    /// generation.
    #[serde(rename = "upd.base.activate")]
    BaseActivate,
    /// The snapshot removal an attempt performs after its outcome is proved.
    #[serde(rename = "upd.checkpoint.cleanup")]
    CheckpointCleanup,
    /// The explicit `ROLLBACK` of an attempt that was refused before its
    /// commit. A rollback result that is missing, or whose rollback left the
    /// connection unable to say what it holds, is this seam: the attempt is
    /// quarantined instead of reported rolled back.
    #[serde(rename = "upd.tx.rollback")]
    TransactionRollback,
    /// The readback of the tuple after an `COMMIT` whose result did not
    /// establish the outcome. The connection is closed and the store refuses
    /// every call until a compatible reopen reads the whole tuple back.
    #[serde(rename = "upd.outcome.read")]
    OutcomeRead,
    /// The one durable write that records an attempt's outcome. A failure here
    /// leaves the previous record standing and reports the terminal write, never
    /// the success it could not record; the cause the attempt first failed on is
    /// not overwritten by it.
    #[serde(rename = "upd.evidence.terminal")]
    EvidenceTerminal,
    /// The blocker page a status read could not serve: no such base, a set
    /// replaced under the caller's cursor, or a cursor past the rows the set
    /// holds. It is page-scoped, so the rest of the same read still answers.
    #[serde(rename = "upd.base.page")]
    BasePage,
}

impl UpdateBoundary {
    /// Every seam the update path opens, in emit-table order. Per-seam
    /// injection runs over a slice's own half ([`Self::CHECKPOINT_SEAMS`],
    /// [`Self::ACTIVATION_SEAMS`]); the whole set is enumerated once, at the last
    /// slice that opens a seam.
    pub const ALL: [Self; 17] = [
        Self::Owner,
        Self::Identity,
        Self::EvidenceReserve,
        Self::EvidenceWrite,
        Self::CheckpointSpace,
        Self::CheckpointCreate,
        Self::CheckpointSync,
        Self::BaseStage,
        Self::Semantic,
        Self::Policy,
        Self::Smoke,
        Self::BaseActivate,
        Self::CheckpointCleanup,
        Self::TransactionRollback,
        Self::OutcomeRead,
        Self::EvidenceTerminal,
        Self::BasePage,
    ];

    /// The admission seam the update path opens before it owns anything.
    pub const OWNER_SEAMS: [Self; 1] = [Self::Owner];

    /// The seams the store-snapshot and record owner opens.
    pub const CHECKPOINT_SEAMS: [Self; 6] = [
        Self::Identity,
        Self::EvidenceReserve,
        Self::EvidenceWrite,
        Self::CheckpointSpace,
        Self::CheckpointCreate,
        Self::CheckpointSync,
    ];

    /// The seams the activation owner opens: staging, the semantic and policy
    /// validation, the smoke contract, the activation and the cleanup that
    /// follows a proved outcome.
    pub const ACTIVATION_SEAMS: [Self; 6] = [
        Self::BaseStage,
        Self::Semantic,
        Self::Policy,
        Self::Smoke,
        Self::BaseActivate,
        Self::CheckpointCleanup,
    ];

    /// The retained boundary token: the identity a record is matched by.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Owner => "upd.owner",
            Self::Identity => "upd.identity",
            Self::EvidenceReserve => "upd.evidence.reserve",
            Self::EvidenceWrite => "upd.evidence.write",
            Self::CheckpointSpace => "upd.checkpoint.space",
            Self::CheckpointCreate => "upd.checkpoint.create",
            Self::CheckpointSync => "upd.checkpoint.sync",
            Self::BaseStage => "upd.base.stage",
            Self::Semantic => "upd.semantic",
            Self::Policy => "upd.policy",
            Self::Smoke => "upd.smoke",
            Self::BaseActivate => "upd.base.activate",
            Self::CheckpointCleanup => "upd.checkpoint.cleanup",
            Self::TransactionRollback => "upd.tx.rollback",
            Self::OutcomeRead => "upd.outcome.read",
            Self::EvidenceTerminal => "upd.evidence.terminal",
            Self::BasePage => "upd.base.page",
        }
    }

    /// The one line an operator can act on without the repository. Every row
    /// this slice owns names a permission, a path, a capacity or a durability
    /// step — never a source edit.
    #[must_use]
    pub fn correction(self) -> &'static str {
        match self {
            Self::Owner => {
                "stop the update, close the process that holds this data root, then retry"
            }
            Self::Identity => {
                "stop the update, restore the store path that was replaced, then reopen"
            }
            Self::EvidenceReserve => {
                "make the update reports directory private and writable, then retry"
            }
            Self::EvidenceWrite => {
                "check that reports/update is a private writable directory with space, or read its record with the build that wrote it, then retry"
            }
            Self::CheckpointSpace => {
                "make the runtime checkpoint path a private directory the store can copy into, then retry"
            }
            Self::CheckpointCreate => {
                "read the store ledger and checkpoint statement the snapshot runs, then retry"
            }
            Self::CheckpointSync => {
                "check that the checkpoint file and its directory can be synced, then retry"
            }
            Self::BaseStage => {
                "ship the base under the version the ledger expects, or resume the staged one, then retry"
            }
            Self::Semantic => {
                "withdraw the stored delta the mapping refuses, or ship a base whose rules place it, then retry"
            }
            Self::Policy => "fix the effective configuration the base resolves to, then retry",
            Self::Smoke => "fix the store contract the smoke check reads, then retry",
            Self::BaseActivate => {
                "keep the previous base serving and retry once the activation invariant holds"
            }
            Self::CheckpointCleanup => {
                "check that the snapshot directory can be written and synced, then retry"
            }
            Self::TransactionRollback => {
                "close the process that failed the rollback, then reopen this data root to read the tuple it holds"
            }
            Self::OutcomeRead => {
                "reopen this data root with a compatible runtime and read the whole schema, base and policy tuple back before retrying"
            }
            Self::EvidenceTerminal => {
                "free space and fix permissions under the update reports directory, then reopen"
            }
            Self::BasePage => {
                "restart from the first page of the base that serves, or omit the base key, then retry"
            }
        }
    }

    /// The wire projection of one retained boundary: the message is the
    /// correction itself, never prose assembled at the failing site.
    #[must_use]
    pub fn wire(self, code: ErrorCode) -> WireError {
        let mut error = WireError::new(code, self.correction());
        error.boundary_id = Some(self.token().to_string());
        error
    }
}

/// Why one emit-map seam pair is not a bijection: every seam carries one
/// token and one correction, and two actionable seams that answer the same
/// retained fingerprint would leave an operator with a cause they cannot
/// locate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitMapCollision {
    /// Two distinct seams spell one token.
    Token {
        first: UpdateBoundary,
        second: UpdateBoundary,
    },
    /// Two distinct seams spell one correction.
    Correction {
        first: UpdateBoundary,
        second: UpdateBoundary,
    },
}

impl std::fmt::Display for EmitMapCollision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token { first, second } => write!(
                f,
                "{} and {} share the retained token {}",
                first.token(),
                second.token(),
                first.token()
            ),
            Self::Correction { first, second } => write!(
                f,
                "{} and {} share one correction",
                first.token(),
                second.token()
            ),
        }
    }
}

/// Proves one emit map is a bijection: every seam carries one token and one
/// correction, and no two different seams answer the same either. Different
/// message text cannot rescue an alias — the token is the identity a record is
/// matched by, so two seams that answer it are one seam to an operator reading a
/// retained cause.
///
/// The map is passed in rather than read from the enum, so a fixture can prove
/// the validator actually refuses an aliased pair instead of only re-testing
/// that a pure function is pure.
///
/// # Errors
/// The first colliding pair — [`EmitMapCollision::Token`] for one shared token,
/// [`EmitMapCollision::Correction`] for one shared correction.
pub fn validate_emit_map(map: &[(UpdateBoundary, &str)]) -> Result<(), EmitMapCollision> {
    for (index, (first, token)) in map.iter().enumerate() {
        for (second, other) in &map[index + 1..] {
            if first != second && token == other {
                return Err(EmitMapCollision::Token {
                    first: *first,
                    second: *second,
                });
            }
            if first != second && first.correction() == second.correction() {
                return Err(EmitMapCollision::Correction {
                    first: *first,
                    second: *second,
                });
            }
        }
    }
    Ok(())
}

/// The closed attempt phase, owned by the receipt type so the record and the
/// ledger projection cannot spell it two ways. `checked` is a validation
/// milestone, not an apply, so it is recorded here and never as a ledger row.
pub use crate::config::UpdatePhase;

/// The closed terminal class of one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Terminal {
    InProgress,
    Success,
    Nonzero,
    Rejected,
    Timeout,
    Signal,
    CleanupFailure,
}

/// The cleanup state of one attempt: `pending` is durable before any cleanup
/// effect, so a kill leaves the boundary the next open classifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupState {
    Pending,
    Done,
    Failed,
}

/// The closed fixed-code vocabulary this owner writes beside a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    /// The supplied detail was hostile, a path, a control sequence or too long.
    InvalidDetail,
    /// The supplied detail carried secret, reference or auth material.
    RedactedSecret,
    /// The eighth secondary slot: the cause it names is preserved, the rest of
    /// the overflow is not.
    AdditionalFailures,
    /// The attempt's own outcome was never established.
    OutcomeUnknown,
}

/// One recorded schema/base/policy tuple: what a resumed attempt compares the
/// live store with before it claims or cleans anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreTuple {
    pub schema: u32,
    pub base: u64,
    /// The 64 lowercase hex digits of `EffectiveConfig::sources_digest`.
    pub policy: String,
}

/// One failure as the record keeps it. `reason` is present exactly when the
/// detail was replaced: a detail that survived intact carries no fixed code,
/// so no fifth reason is invented for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    pub boundary: UpdateBoundary,
    pub code: ErrorCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<FailureReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Failure {
    /// One failure with its detail classified before it is retained: an
    /// unknown but well-formed non-secret token survives, secret material is
    /// dropped as `redacted_secret`, and hostile, path-shaped, control-bearing
    /// or overlength text becomes the fixed `invalid_detail`. Neither branch
    /// keeps a digest of what it dropped.
    #[must_use]
    pub fn at(boundary: UpdateBoundary, code: ErrorCode, detail: Option<&str>) -> Self {
        let (reason, detail) = match detail {
            None => (
                (code == ErrorCode::OutcomeUnknown).then_some(FailureReason::OutcomeUnknown),
                None,
            ),
            Some(raw) => classify_detail(raw),
        };
        Self {
            boundary,
            code,
            reason,
            detail,
        }
    }
}

/// One attempt's durable record. Every key is closed: the decoder refuses an
/// unknown key, an unknown version and an unknown enum value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateEvidence {
    pub version: u8,
    pub attempt_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered_base: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_tuple: Option<StoreTuple>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_tuple: Option<StoreTuple>,
    /// The boundary persisted before the effect that is about to run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<UpdateBoundary>,
    pub terminal: Terminal,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<UpdatePhase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_failure: Option<Failure>,
    pub secondary: Vec<Failure>,
    pub cleanup: CleanupState,
    pub resolved: bool,
}

impl UpdateEvidence {
    /// A fresh attempt: in progress, nothing pending, nothing failed. The
    /// identity is generated here, so a caller can neither choose nor collide
    /// on a record name.
    #[must_use]
    pub fn fresh(offered_base: Option<u64>) -> Self {
        Self::new(uuid::Uuid::new_v4().to_string(), offered_base)
    }

    /// A fresh attempt under a supplied id: the owner's own tests name an
    /// attempt, and no product caller has a reason to.
    #[must_use]
    pub fn new(attempt_id: impl Into<String>, offered_base: Option<u64>) -> Self {
        Self {
            version: EVIDENCE_VERSION,
            attempt_id: attempt_id.into(),
            offered_base,
            old_tuple: None,
            observed_tuple: None,
            pending: None,
            terminal: Terminal::InProgress,
            phase: None,
            first_failure: None,
            secondary: Vec::new(),
            cleanup: CleanupState::Pending,
            resolved: false,
        }
    }

    /// Adds one failure: the first cause is immutable, later ones fill the
    /// eight secondary slots, and the ninth replaces the eighth with the fixed
    /// overflow row so a hostile stream cannot grow the record past its bound.
    pub fn note_failure(&mut self, failure: Failure) {
        if self.first_failure.is_none() {
            self.first_failure = Some(failure);
            return;
        }
        if self.secondary.len() < SECONDARY_MAX {
            self.secondary.push(failure);
        } else {
            self.secondary[SECONDARY_MAX - 1] = Failure {
                reason: Some(FailureReason::AdditionalFailures),
                detail: None,
                ..failure
            };
        }
    }

    /// The wire projection of the original cause. A secondary cleanup failure
    /// never overwrites what the attempt first failed on.
    #[must_use]
    pub fn wire_error(&self) -> Option<WireError> {
        self.first_failure
            .as_ref()
            .map(|failure| failure.boundary.wire(failure.code))
    }
}

/// Why one update step refused. The variant is the emit seam: [`boundary`]
/// names the retained token, and no variant carries a message the operator
/// must parse.
///
/// [`boundary`]: UpdateError::boundary
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("update identity: the store path no longer names the open database")]
    Identity {
        #[source]
        source: crate::state::StoreError,
    },
    #[error("update evidence: the reports directory cannot hold another record")]
    Saturated,
    #[error("update evidence record: {detail}")]
    Record { detail: &'static str },
    #[error("update checkpoint name: the snapshot was not generated by this store")]
    SnapshotName,
    #[error("update evidence reserve: {source}")]
    Reserve {
        #[source]
        source: std::io::Error,
    },
    #[error("update evidence write: {source}")]
    Write {
        #[source]
        source: std::io::Error,
    },
    #[error("update evidence read: {source}")]
    Read {
        #[source]
        source: std::io::Error,
    },
    #[error("update checkpoint capacity: {source}")]
    Space {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("update checkpoint create: {source}")]
    Create {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("update checkpoint sync: {source}")]
    Sync {
        #[source]
        source: std::io::Error,
    },
    /// The cleanup step of an attempt that reached an outcome: the snapshot it
    /// may now remove could not be removed. The cause is the helper's own
    /// refusal, retained as secondary evidence; the seam is this transaction's.
    #[error("update checkpoint cleanup: {source}")]
    Cleanup {
        #[source]
        source: Box<UpdateError>,
    },
    /// The ledger refused a step of the activation. The variant carries the base
    /// ledger's own refusal, so a caller reads the class the base domain gives it
    /// instead of the storage slot's `storage_unavailable`.
    #[error("{}: {refusal}", .boundary.token())]
    Activation {
        boundary: UpdateBoundary,
        #[source]
        refusal: Box<crate::config::BaseError>,
    },
    /// The record of an attempt's outcome could not be made durable. The
    /// previously committed record stands and the attempt reports this seam
    /// instead of the success it could not retain, so a later reopen never reads
    /// a claim the writer failed to keep.
    #[error("update terminal evidence: {source}")]
    TerminalWrite {
        #[source]
        source: Box<UpdateError>,
    },
}

impl UpdateError {
    /// The retained boundary of this refusal.
    #[must_use]
    pub fn boundary(&self) -> UpdateBoundary {
        match self {
            Self::Identity { .. } => UpdateBoundary::Identity,
            Self::Saturated | Self::Reserve { .. } => UpdateBoundary::EvidenceReserve,
            Self::Record { .. } | Self::Write { .. } | Self::Read { .. } => {
                UpdateBoundary::EvidenceWrite
            }
            Self::Space { .. } => UpdateBoundary::CheckpointSpace,
            Self::Create { .. } => UpdateBoundary::CheckpointCreate,
            // A refused name and an unusable snapshot file are both this
            // store's own snapshot-file seam. The cleanup attribution
            // (`upd.checkpoint.cleanup`) belongs to the update transaction that
            // invokes cleanup, not to the helper that removes one file.
            Self::SnapshotName | Self::Sync { .. } => UpdateBoundary::CheckpointSync,
            Self::Cleanup { .. } => UpdateBoundary::CheckpointCleanup,
            Self::TerminalWrite { .. } => UpdateBoundary::EvidenceTerminal,
            Self::Activation { boundary, .. } => *boundary,
        }
    }

    /// The wire code of this refusal: an unavailable, corrupt or saturated
    /// store, never a caller error the operator could have avoided by input. An
    /// activation refusal keeps the base ledger's own class, so a document
    /// conflict is not reported as an unavailable backend.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Identity { .. }
            | Self::Saturated
            | Self::Record { .. }
            | Self::SnapshotName
            | Self::Reserve { .. }
            | Self::Write { .. }
            | Self::Read { .. }
            | Self::Space { .. }
            | Self::Create { .. }
            | Self::Sync { .. }
            | Self::Cleanup { .. }
            | Self::TerminalWrite { .. } => ErrorCode::StorageUnavailable,
            Self::Activation { refusal, .. } => refusal.code(),
        }
    }

    /// The one line an operator can act on for *this* refusal. It differs from
    /// [`UpdateBoundary::correction`] exactly where two refusals share a boundary
    /// but not a recovery: `Saturated` and a refused reserve both land on
    /// `upd.evidence.reserve`, and only the saturation is cleared by resolving the
    /// retained failure records — widening a writable directory would never move a
    /// count bound.
    #[must_use]
    pub fn correction(&self) -> &'static str {
        match self {
            Self::Saturated => {
                "resolve or remove the retained failure records under reports/update, then retry"
            }
            // A terminal write refused because the record tree refused keeps that
            // inner refusal's recovery: a `Saturated` terminal write is cleared by
            // resolving the retained records, not by widening permissions.
            Self::TerminalWrite { source } => source.correction(),
            other => other.boundary().correction(),
        }
    }
}

/// One backup/reference snapshot, named relative to the data root so no
/// absolute path reaches a caller or a wire response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointSnapshot {
    /// The generated file name under `runtime/checkpoints/`.
    pub name: String,
    pub bytes: u64,
}

/// Takes the one snapshot a waiting cutover owns.
///
/// A store with no staged base is an ordinary open that copies nothing, so
/// `Ok(None)` is the honest answer rather than an empty file. The snapshot is
/// written beside the primary and never over it, so a later transaction
/// rollback — not the snapshot — is what recovers the store.
///
/// # Errors
/// [`UpdateError::Identity`] when the bound path no longer resolves to the
/// inode this writer admitted, [`UpdateError::Space`] when the target
/// cannot hold a copy, [`UpdateError::Create`] when the snapshot
/// statement fails for any other reason, and [`UpdateError::Sync`]
/// when the file or its directory cannot be made durable.
pub fn snapshot(
    store: &TaskStore,
    data_root: &Path,
) -> Result<Option<CheckpointSnapshot>, UpdateError> {
    let pending = store
        .cutover_pending()
        .map_err(|source| UpdateError::Create {
            source: Box::new(source),
        })?;
    if !pending {
        return Ok(None);
    }
    let dir = checkpoint_dir(data_root)?;
    store
        .verify_path_identity()
        .map_err(|source| UpdateError::Identity { source })?;
    let name = format!("{}.db", uuid::Uuid::new_v4());
    let target = dir.join(&name);
    store
        .checkpoint_into(&target)
        .map_err(|source| UpdateError::Create {
            source: Box::new(source),
        })?;
    let bytes = sync_snapshot(&target)?;
    Ok(Some(CheckpointSnapshot { name, bytes }))
}

/// Removes one snapshot this module generated, after the caller has read a
/// coherent primary outcome. The name must be one this module could have
/// written: a caller path, a traversal or any other name is refused and
/// nothing is deleted. The primary is never touched — cleanup removes a copy,
/// it never restores from one.
///
/// # Errors
/// [`UpdateError::SnapshotName`] for a name this module did not generate,
/// [`UpdateError::Space`] when the checkpoint directory cannot be
/// proven private, and [`UpdateError::Sync`] when the removal fails.
pub fn discard_checkpoint(data_root: &Path, name: &str) -> Result<(), UpdateError> {
    let Some(stem) = name.strip_suffix(".db") else {
        return Err(unknown_snapshot());
    };
    if !generated_uuid(stem) {
        return Err(unknown_snapshot());
    }
    let dir = checkpoint_dir(data_root)?;
    match std::fs::remove_file(dir.join(name)) {
        Ok(()) => Ok(()),
        // An absent snapshot discharges the cleanup: nothing is left to remove,
        // and inventing a failure would stop an update over nothing.
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(UpdateError::Sync { source }),
    }
}

fn unknown_snapshot() -> UpdateError {
    UpdateError::SnapshotName
}

/// The newest attempt a data root retained, as a status read projects it.
///
/// `failure` is the original cause — taken from the newest record that carries
/// one, so a clean convergence does not erase what an earlier attempt failed on
/// — and `evidence` names that same record, relative to the data root. `phase`
/// is the milestone of the newest attempt while it is unresolved: a kill between
/// validation and activation therefore reopens as `checked`, never as
/// `activated`, and a discarded attempt reports `rolled_back`. A converged
/// attempt projects nothing here, so the ledger's own row answers.
///
/// `decoded` is how many records this read opened and `truncated` says the tree
/// holds more than the read covered. The admission may carry the tree past
/// [`EVIDENCE_MAX_RECORDS`], so a projection is bounded in records read rather
/// than in records present, and it reports that bound instead of hiding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptProjection {
    pub phase: Option<UpdatePhase>,
    pub failure: Option<WireError>,
    pub evidence: Option<String>,
    pub decoded: usize,
    pub truncated: bool,
}

/// What one settlement pass did: how many earlier records it marked `resolved`
/// and how many it decoded to decide. The decoded count is the pass's own proof
/// that it streamed the tree instead of retaining it, the way
/// [`AttemptProjection::decoded`] proves the status read is bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settlement {
    pub resolved: usize,
    pub decoded: usize,
}

/// The validation the activation gates on (AC-055): the stored semantics, the
/// pinned policy and the store's own readback of the generation it is about to
/// publish. Each check names its own seam, so a refusal says which of the three
/// an operator has to fix instead of reporting one generic validation failure.
///
/// # Errors
/// [`UpdateBoundary::Semantic`] when the stored learning definition cannot be
/// read, [`UpdateBoundary::Policy`] when the pinned generation is not a sha-256
/// digest, and [`UpdateBoundary::Smoke`] when the store cannot answer the
/// generation it holds.
pub fn validate_generation(
    store: &TaskStore,
    install: &crate::config::BaseInstall,
) -> Result<(), UpdateBoundary> {
    store
        .learning_definition()
        .map_err(|_refused| UpdateBoundary::Semantic)?;
    if !is_policy_generation(&install.policy_generation) {
        return Err(UpdateBoundary::Policy);
    }
    store
        .update_status()
        .map_err(|_refused| UpdateBoundary::Smoke)?;
    Ok(())
}

/// What one activation attempt reached (AC-055, REQ-001).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationOutcome {
    /// Validation passed, the activation committed and the generation serves.
    Activated,
    /// Validation failed and the attempt was rolled back: the previous
    /// generation still serves.
    RolledBack,
}

/// One activation attempt over a waiting cutover.
///
/// The record is durable before each actionable step and after each milestone, so
/// a kill leaves the boundary the next compatible open classifies. `checked` is
/// written once the checks passed and the activation has not run — the one
/// milestone the ledger cannot hold, because writing it into the row would claim
/// an apply that had not happened. A failed check reports `rolled_back` only
/// after the store answered that the staged row is gone, never from a dropped
/// handle, and the activation itself is the store's own transaction: no second
/// commit is introduced here.
///
/// `validate` runs the caller's checks and names the seam one failed at;
/// `publish` performs the one `IMMEDIATE` transaction that stages and activates
/// the offered base — the startup passes its generation transaction, a caller
/// that already holds a pinned staged row passes `commit_base`. Its answer is the
/// commit alone: the outcome this function reports is the generation the commit
/// left behind, so a read that runs after it can only add evidence and never turn
/// a landed activation into a refusal. The snapshot is removed only after the
/// outcome is durable and the tuple read back, so cleanup never outruns the
/// evidence.
///
/// # Errors
/// The refusal carries the seam it failed at, and the record retains the first
/// cause; an attempt that cannot make its milestone durable returns
/// [`UpdateError::Reserve`] and no further effect runs.
pub fn activate<F, P>(
    store: &mut TaskStore,
    data_root: &Path,
    evidence: &EvidenceStore,
    attempt: &mut UpdateEvidence,
    snapshot: Option<&str>,
    validate: F,
    publish: P,
) -> Result<ActivationOutcome, UpdateError>
where
    F: FnOnce(&TaskStore) -> Result<(), UpdateBoundary>,
    P: FnOnce(&mut TaskStore) -> Result<(), crate::config::BaseError>,
{
    let Some(offered) = attempt.offered_base else {
        return Err(UpdateError::Record {
            detail: "an activation names the base it activates",
        });
    };
    // Staging is where the base enters the ledger: an attempt that finds no
    // waiting cutover is the caller's mistake, and the record names that seam
    // because it is the step that never landed. The staged row is also the
    // checkpoint a failed validation discards, so its version — not the offered
    // one — is what a rollback removes.
    attempt.pending = Some(UpdateBoundary::BaseStage);
    commit(evidence, attempt)?;
    let staged = store
        .staged_base()
        .map_err(|refusal| refuse(evidence, attempt, UpdateBoundary::BaseStage, refusal))?;
    let Some(staged) = staged else {
        return Err(refuse(
            evidence,
            attempt,
            UpdateBoundary::BaseStage,
            crate::config::BaseError::NotStaged { version: offered },
        ));
    };
    // The validation runs three checks in order — semantics, pinned policy, the
    // smoke readback — so the pending boundary is the one about to run; a
    // refusal names the check that actually failed.
    attempt.pending = Some(UpdateBoundary::Semantic);
    commit(evidence, attempt)?;
    if let Err(boundary) = validate(store) {
        attempt.note_failure(Failure::at(boundary, ErrorCode::Conflict, None));
        attempt.terminal = Terminal::Rejected;
        // `rolled_back` is honest only once the store answered that the staged
        // row is gone: the attempt never reports a phase it did not reach. A failed
        // abandonment is its own seam, so its refusal is reported against the
        // rollback boundary — pairing the validation seam's correction with the
        // abandonment's cause would tell an operator to fix the store contract when
        // the rollback is what failed.
        if let Err(refusal) = store.abandon_base(staged.version) {
            let seam = match refusal {
                crate::config::BaseError::RollbackFailed { .. } => {
                    UpdateBoundary::TransactionRollback
                }
                crate::config::BaseError::OutcomeUnread { .. } => UpdateBoundary::OutcomeRead,
                _ => UpdateBoundary::BaseStage,
            };
            return Err(refuse(evidence, attempt, seam, refusal));
        }
        attempt.phase = Some(UpdatePhase::RolledBack);
        attempt.pending = None;
        settle(evidence, attempt)?;
        // A rolled-back attempt owes its snapshot the same removal the success
        // path performs: the outcome is durable and the rollback read back, so the
        // reference has no reader left and nothing sweeps an orphan later.
        if let Some(name) = snapshot {
            discard_after_outcome(evidence, attempt, data_root, name)?;
        }
        return Ok(ActivationOutcome::RolledBack);
    }
    // Every check passed and nothing is applied yet: the milestone the ledger
    // cannot hold, durable before the activation so a kill between them reopens
    // as checked rather than as activated.
    attempt.phase = Some(UpdatePhase::Checked);
    attempt.pending = Some(UpdateBoundary::BaseActivate);
    commit(evidence, attempt)?;
    pause_after_validation(data_root);
    if let Err(refusal) = publish(store) {
        // A failed rollback or an unreadable commit outcome is its own seam:
        // the record names the step whose result never arrived, so an operator
        // reads that the store waits for a compatible reopen instead of
        // retrying a tuple an interrupted commit may have moved.
        let boundary = match refusal {
            crate::config::BaseError::RollbackFailed { .. } => UpdateBoundary::TransactionRollback,
            crate::config::BaseError::OutcomeUnread { .. } => UpdateBoundary::OutcomeRead,
            _ => UpdateBoundary::BaseActivate,
        };
        // The outcome is unknown until the ledger is read back, so the
        // attempt keeps its pending activation boundary and reports no
        // success; a later open classifies the interruption.
        attempt.note_failure(Failure::at(
            boundary,
            refusal.code(),
            Some("activation-refused"),
        ));
        commit(evidence, attempt)?;
        return Err(UpdateError::Activation {
            boundary,
            refusal: Box::new(refusal),
        });
    }
    // The commit landed, so the activation is the outcome whatever a later read
    // answers: the receipt is read back as evidence of the tuple the store serves,
    // and a read that faults names its own seam in the record without turning the
    // landed generation into a refusal.
    let receipt = store.update_receipt(offered).ok();
    attempt.phase = Some(
        receipt
            .as_ref()
            .and_then(|receipt| receipt.phase)
            .unwrap_or(UpdatePhase::Activated),
    );
    attempt.terminal = Terminal::Success;
    if let Some(receipt) = receipt {
        attempt.observed_tuple = Some(StoreTuple {
            schema: u32::try_from(receipt.schema_generation.unwrap_or(0)).unwrap_or(u32::MAX),
            base: receipt.base_version,
            policy: receipt.policy_generation.unwrap_or_default(),
        });
    } else {
        // The generation serves and the store could not read its own receipt back:
        // the record keeps that as secondary evidence under the readback seam the
        // smoke check owns, so the cause an operator acts on is never invented.
        attempt.note_failure(Failure::at(
            UpdateBoundary::Smoke,
            ErrorCode::StorageUnavailable,
            Some("receipt-readback"),
        ));
    }
    // The snapshot leaves only now: the outcome is durable and the tuple read
    // back, so cleanup cannot take the reference an operator still needs. The
    // pending cleanup boundary is committed before the effect it names, which is
    // also the state a kill between them leaves.
    attempt.pending = Some(UpdateBoundary::CheckpointCleanup);
    commit(evidence, attempt)?;
    // The milestone the AFTER-COMMIT kill proves: the activation committed, the
    // cleanup boundary is durable, and nothing has been removed or exposed, so a
    // kill here leaves the whole new tuple and the snapshot on disk together.
    pause_after_commit(data_root);
    if let Some(name) = snapshot
        && let Err(refusal) = discard_checkpoint(data_root, name)
    {
        // A cleanup failure is secondary: the cause and the success already
        // stand, and the record says which step could not finish.
        let boundary = refusal.boundary();
        attempt.note_failure(Failure::at(boundary, refusal.code(), None));
        attempt.cleanup = CleanupState::Failed;
        attempt.terminal = Terminal::CleanupFailure;
        commit(evidence, attempt)?;
        return Err(UpdateError::Cleanup {
            source: Box::new(refusal),
        });
    }
    attempt.cleanup = CleanupState::Done;
    attempt.pending = None;
    settle(evidence, attempt)?;
    Ok(ActivationOutcome::Activated)
}

/// Removes the snapshot an attempt took once its outcome is durable and read back.
///
/// The rollback path and the success path share one rule; the success path keeps
/// its own cleanup boundary and AFTER-COMMIT milestone, and this helper only
/// names what both owe: the copy leaves after the outcome it references.
fn discard_after_outcome(
    evidence: &EvidenceStore,
    attempt: &mut UpdateEvidence,
    data_root: &Path,
    name: &str,
) -> Result<(), UpdateError> {
    attempt.pending = Some(UpdateBoundary::CheckpointCleanup);
    commit(evidence, attempt)?;
    if let Err(refusal) = discard_checkpoint(data_root, name) {
        // A cleanup failure is secondary to the outcome that already stands; the
        // record says which step could not finish and the attempt reports it.
        let boundary = refusal.boundary();
        attempt.note_failure(Failure::at(boundary, refusal.code(), None));
        attempt.cleanup = CleanupState::Failed;
        attempt.terminal = Terminal::CleanupFailure;
        commit(evidence, attempt)?;
        return Err(UpdateError::Cleanup {
            source: Box::new(refusal),
        });
    }
    attempt.cleanup = CleanupState::Done;
    attempt.pending = None;
    settle(evidence, attempt)
}

/// One durable milestone of an attempt: a record that cannot be written stops
/// the attempt before its next effect, so no step runs on an unrecorded basis.
fn commit(evidence: &EvidenceStore, attempt: &UpdateEvidence) -> Result<(), UpdateError> {
    evidence.write(attempt).map(|_name| ())
}

/// The terminal transition of an attempt that reached its outcome: the record
/// lands, then the root's earlier unresolved records are resolved by the one
/// producer of `resolved`.
fn settle(evidence: &EvidenceStore, attempt: &UpdateEvidence) -> Result<(), UpdateError> {
    // The terminal record is the outcome an operator reads back, so a write that
    // cannot land reports its own seam instead of a success no later reopen could
    // confirm. The cause the attempt first failed on is untouched by it.
    evidence
        .write(attempt)
        .map_err(|source| UpdateError::TerminalWrite {
            source: Box::new(source),
        })?;
    if attempt.terminal == Terminal::Success {
        evidence
            .settle_success()
            .map_err(|source| UpdateError::TerminalWrite {
                source: Box::new(source),
            })?;
    }
    Ok(())
}

/// The ledger's refusal of one activation step, retained at that seam: the
/// record keeps the first cause and the caller gets the same boundary.
fn refuse(
    evidence: &EvidenceStore,
    attempt: &mut UpdateEvidence,
    boundary: UpdateBoundary,
    refusal: crate::config::BaseError,
) -> UpdateError {
    attempt.note_failure(Failure::at(boundary, refusal.code(), None));
    if let Err(source) = evidence.write(attempt) {
        return source;
    }
    UpdateError::Activation {
        boundary,
        refusal: Box::new(refusal),
    }
}

/// Where one refused attempt's evidence stands, so the diagnostics name only what
/// actually exists on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidencePointer<'a> {
    /// The attempt's record was durably written and answers to this generated name.
    Record(&'a str),
    /// No attempt record exists — the directory itself, or a write inside it,
    /// refused — so the line names the directory an operator has to fix.
    Directory,
}

/// The pointer one refused record write owes the diagnostics. Only a refusal that
/// happened *after* this attempt's file was placed may name that file: `write` lists,
/// decodes and prunes the records already in the tree before it renames anything, so a
/// tree that cannot be read, or that holds a record this build will not decode, fails the
/// write with nothing of this attempt on disk. Naming this attempt's generated name then
/// sends an operator to a file that was never written.
#[must_use]
pub fn refusal_pointer<'a>(refusal: &UpdateError, record: &'a str) -> EvidencePointer<'a> {
    match refusal {
        // The tree, not this attempt, is what refused: nothing of this attempt reached
        // the directory, so the directory is the only path that exists.
        UpdateError::Write { .. }
        | UpdateError::Reserve { .. }
        | UpdateError::Read { .. }
        | UpdateError::Record { .. }
        | UpdateError::Saturated => EvidencePointer::Directory,
        // Every later refusal happens with this attempt's terminal record already
        // durable, so the record that carries the cause really is there to read.
        _ => EvidencePointer::Record(record),
    }
}

/// The two fixed diagnostics lines one update refusal owes an operator who
/// cannot read a wire error: the seam the attempt failed at, the path that is
/// really there (its record only when that record was durably written, else the
/// directory), and the correction that clears this refusal.
///
/// The correction comes from the refusal, not from the boundary alone: `Saturated`
/// and a refused reserve share `upd.evidence.reserve`, but only one of them can be
/// cleared by fixing permissions. Telling an operator to widen a directory that is
/// already writable would leave the count bound they actually hit unnamed.
#[must_use]
pub fn refusal_diagnostics(
    pointer: EvidencePointer<'_>,
    boundary: UpdateBoundary,
    correction: &str,
) -> [String; 2] {
    [
        match pointer {
            EvidencePointer::Record(record) => format!(
                "update evidence: {EVIDENCE_DIR}/{record} boundary: {}",
                boundary.token()
            ),
            EvidencePointer::Directory => format!(
                "update evidence directory: {EVIDENCE_DIR} boundary: {}",
                boundary.token()
            ),
        },
        format!("update next: {correction}"),
    ]
}

/// The two fixed lines an ownership refusal owes: the seam, the lock file
/// another process holds — a pointer relative to the data root, never an absolute
/// path the operator has to strip — and the correction the boundary's own row
/// carries. Any other owner failure has nothing to add here and answers no line, so
/// the caller's diagnostics stay exactly what they were.
#[must_use]
pub fn owner_refusal_diagnostics(error: &crate::owner::OwnerError) -> Vec<String> {
    if !matches!(error, crate::owner::OwnerError::AlreadyOwned) {
        return Vec::new();
    }
    vec![
        format!(
            "update boundary: {} pointer: {}",
            UpdateBoundary::Owner.token(),
            crate::owner::OWNER_LOCK
        ),
        format!("update next: {}", UpdateBoundary::Owner.correction()),
    ]
}

/// The ledger's status with the newest retained attempt projected onto it — the
/// one place the status surface reads both owners, so `runtime.status` and a
/// test reading a recovered data root answer the same shape.
///
/// The retained record is additive diagnostics: a report directory that cannot be
/// read leaves the pointer and the cause absent rather than failing the ledger
/// read the caller asked for. That absence is not silence: a refusal of the
/// directory or of one of its records rides the success-shaped `page_conflict` the
/// page reader already uses, naming the record tree and its correction, because
/// "no attempt ever ran" and "the attempt's record cannot be read" are different
/// answers an operator must be able to tell apart.
///
/// # Errors
/// The refusals [`TaskStore::update_status_page`] reports: a malformed page is
/// the caller's, a corrupt ledger the store's.
pub fn project_status(
    store: &TaskStore,
    page: &crate::config::UpdatePage,
    data_root: &Path,
) -> Result<crate::config::UpdateStatus, crate::config::BaseError> {
    let mut status = store.update_status_page(page)?;
    let projection = match EvidenceStore::open(data_root) {
        Ok(records) => records.projection(),
        // A data root no attempt has written to answers by creating the tree, so a
        // refusal here is always a tree this build cannot vouch for — a squatting
        // file, a symlink, a wider mode — and it must not answer like absence.
        Err(refusal) => {
            // The ledger's own conflict wins: a caller whose cursor was invalidated is
            // told to restart, and the unreadable tree is the secondary fact — a
            // record-tree fault that overwrote it would leave that caller with no
            // instruction at all.
            if status.page_conflict.is_none() {
                status.page_conflict = Some(record_fault(refusal.boundary(), refusal.code()));
            }
            return Ok(status);
        }
    };
    match projection {
        Ok(projection) => {
            if projection.phase.is_some() {
                status.phase = projection.phase;
            }
            status.failure = projection.failure;
            status.evidence = projection
                .evidence
                .map(|name| format!("{EVIDENCE_DIR}/{name}"));
            // A read that reached its ceiling reports that on the wire: without it a
            // truncated projection answers exactly like a data root where no attempt
            // ever ran, because the record carrying the cause may lie outside the window.
            // `decoded` stays on the projection — no caller acts on a count, and a field
            // nobody reads is dead weight on the wire.
            status.evidence_truncated = projection.truncated.then(|| {
                format!(
                    "update evidence: {EVIDENCE_DIR} holds more records than this read decodes; \
                     a retained cause older than the newest records is not reported here, so \
                     resolve the settled failure records under {EVIDENCE_DIR} to bring the tree \
                     back inside one read"
                )
            });
        }
        // The directory opened and a record inside it could not be decoded: the
        // attempt exists and its cause is unreadable, which is not "no attempt".
        Err(refusal) => {
            if status.page_conflict.is_none() {
                status.page_conflict = Some(record_fault(refusal.boundary(), refusal.code()));
            }
        }
    }
    Ok(status)
}

/// The success-shaped refusal one unreadable record tree carries: the status read
/// answers, the rest of it survives, and the diagnostic names the tree that could
/// not be read and the correction its own seam carries.
fn record_fault(boundary: UpdateBoundary, code: ErrorCode) -> WireError {
    let mut wire = boundary.wire(code);
    wire.message = format!("update evidence: {EVIDENCE_DIR} {}", boundary.correction());
    wire
}

/// The process-death hatch of the activation milestone: when
/// `RIVECT_UPDATE_PAUSE_AFTER_VALIDATION` names this data root's own generated
/// marker, the process writes its pid there and blocks on stdin, so a parent can
/// kill it between the checks and the activation.
///
/// Contained by build, not by a runtime check, the same shape as the fault seam
/// beside it: the environment probe exists only in a build with debug assertions
/// on, and a release binary carries the no-op below, so no stray inherited variable
/// can wedge a data root while the writer lock is held.
#[cfg(debug_assertions)]
pub fn pause_after_validation(data_root: &Path) {
    if let Err(refusal) = pause_at(
        data_root,
        "RIVECT_UPDATE_PAUSE_AFTER_VALIDATION",
        "update-pause-after-validation",
    ) {
        // The hatch is the proof's own channel, not a step of the update: a
        // marker it refuses must not refuse an activation the store can commit,
        // and the proof observes the missing marker as a failed fixture.
        drop(refusal);
    }
}

/// The release build's answer: no milestone blocks, whatever the environment says.
#[cfg(not(debug_assertions))]
pub fn pause_after_validation(_data_root: &Path) {}

/// The process-death hatch of the AFTER-COMMIT milestone: the activation has
/// committed and the snapshot has not been removed yet, so a parent that kills
/// this process reads back the whole new tuple from the primary and the snapshot
/// from disk. Same shape, same path rule and same build gate as
/// [`pause_after_validation`]: it adds no row to the closed emit map.
#[cfg(debug_assertions)]
pub fn pause_after_commit(data_root: &Path) {
    if let Err(refusal) = pause_at(
        data_root,
        "RIVECT_UPDATE_PAUSE_AFTER_COMMIT",
        "update-pause-after-commit",
    ) {
        // Same rule as the validation hatch: the proof's channel never refuses a
        // commit the store already made durable.
        drop(refusal);
    }
}

/// The release build's answer: no milestone blocks, whatever the environment says.
#[cfg(not(debug_assertions))]
pub fn pause_after_commit(_data_root: &Path) {}

/// The one marker path a data root owns, named by the hatch and never by the
/// caller, so the hatch writes inside `runtime/` or not at all.
pub fn hatch_marker(data_root: &Path, stem: &str) -> PathBuf {
    data_root.join("runtime").join(format!("{stem}.pid"))
}

/// The marker one armed hatch may write, or the caller's refusal: a value that is
/// not exactly the path [`hatch_marker`] generates for this data root is refused
/// here, before any file is created and before stdin is read.
pub fn armed_marker(data_root: &Path, stem: &str, armed: &Path) -> Result<PathBuf, std::io::Error> {
    let marker = hatch_marker(data_root, stem);
    if armed != marker {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the hatch does not name this data root's generated marker",
        ));
    }
    Ok(marker)
}

/// Writes this pid to the data root's own marker and blocks on stdin until the
/// parent closes it or kills the process.
///
/// Contained by build: this function does not exist in a release binary, so no
/// environment string can make a shipped process block while it holds the writer
/// lock.
///
/// # Errors
/// [`std::io::ErrorKind::InvalidInput`] when the variable names any path but the
/// generated marker — the hatch then neither writes nor blocks — and the create,
/// write or sync failure of the anchored marker file.
#[cfg(debug_assertions)]
pub(crate) fn pause_at(data_root: &Path, variable: &str, stem: &str) -> Result<(), std::io::Error> {
    let Some(value) = std::env::var_os(variable) else {
        return Ok(());
    };
    let marker = armed_marker(data_root, stem, Path::new(&value))?;
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(ANCHOR_O_NOFOLLOW | OPEN_NONBLOCK)
        .open(&marker)?;
    // The mode is re-proved on the opened descriptor: a marker an earlier run
    // left wider must not stay readable to another user.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(format!("{}\n", std::process::id()).as_bytes())?;
    file.sync_all()?;
    drop(file);
    let mut sink = std::io::sink();
    drop(std::io::copy(&mut std::io::stdin().lock(), &mut sink));
    Ok(())
}

/// The store's retained record of one attempt, under
/// `<data root>/reports/update` (0700, files 0600). One checked open per
/// operation, generated names only, no caller path.
#[derive(Debug, Clone)]
pub struct EvidenceStore {
    root: PathBuf,
}

/// One committed record as the directory lists it.
#[derive(Debug, Clone)]
struct Stored {
    name: String,
    written: std::time::SystemTime,
    bytes: usize,
}

impl EvidenceStore {
    /// Opens (and proves) the record directory of one data root.
    ///
    /// # Errors
    /// [`UpdateError::Reserve`] when the directory cannot be created, or does
    /// not prove private (0700, a real directory, not a symlink).
    pub fn open(data_root: &Path) -> Result<Self, UpdateError> {
        let root = data_root.join(EVIDENCE_DIR);
        private_dir(&root).map_err(|source| UpdateError::Reserve { source })?;
        Ok(Self { root })
    }

    /// Commits one attempt record with the durable replacement every later
    /// pending/terminal/cleanup transition uses: temp file, `sync_all`, rename,
    /// sync of the parent. A failure leaves the previous committed record in
    /// place, so the caller can stop further effects and cleanup.
    ///
    /// # Errors
    /// [`UpdateError::Record`] when the record itself is outside schema v1 or
    /// its bounds, [`UpdateError::Saturated`] when a *new* attempt of another
    /// offered base would pass the committed-count or total-byte bound (an
    /// existing attempt is always replaceable, and a repeat of the newest
    /// unresolved base is admitted), and
    /// [`UpdateError::Write`]/[`UpdateError::Reserve`] when the file cannot be
    /// placed.
    pub fn write(&self, evidence: &UpdateEvidence) -> Result<String, UpdateError> {
        validate(evidence)?;
        let bytes = serde_json::to_vec(evidence).map_err(|_malformed| malformed_record())?;
        if bytes.len() > EVIDENCE_MAX_BYTES {
            return Err(UpdateError::Record {
                detail: "the record exceeds its byte bound",
            });
        }
        let name = record_name(&evidence.attempt_id)?;
        let replacing = self.stored()?.iter().any(|entry| entry.name == name);
        // A new record must leave room for itself, so the pass targets one
        // slot fewer; a replacement reuses its own slot and prunes to the bound.
        let target = if replacing {
            EVIDENCE_MAX_RECORDS
        } else {
            EVIDENCE_MAX_RECORDS - 1
        };
        self.prune_to(target)?;
        let stored = self.stored()?;
        if !replacing {
            let total: usize = stored.iter().map(|entry| entry.bytes).sum();
            let saturated = stored.len() >= EVIDENCE_MAX_RECORDS
                || total.saturating_add(bytes.len()) > EVIDENCE_MAX_TOTAL_BYTES;
            // A saturated root refuses a *new* attempt of another offered base, so
            // no sequence of different attempts can grow the directory past the
            // count bound. It admits one repeating the offered base of the newest
            // unresolved record: `resolved` has exactly one producer — the landed
            // success of an attempt that continues that base — so refusing it would
            // leave the tree closed to the only write that can settle it, and every
            // later open would fail at its first milestone while the installed
            // version stays usable (INV-007). That admission outranks the count
            // bound; `prune_to` then reclaims what it may — duplicates of a cause a
            // newer record still carries, resolved records with no cause, superseded
            // successes — and leaves the tree over the bound when a cause is all that
            // is left, the cost `DEC-025` records.
            if saturated && !self.continues_unresolved(evidence.offered_base)? {
                return Err(UpdateError::Saturated);
            }
        }
        durable_replace(&self.root, &name, &bytes)
            .map_err(|source| UpdateError::Write { source })?;
        Ok(name)
    }

    /// Reads one committed record back through the bounded decoder: size,
    /// depth, unknown keys, closed enums and the private-file shape are all
    /// checked before anything is projected.
    ///
    /// # Errors
    /// [`UpdateError::Record`] for a name this module did not generate, a file
    /// that is not a private regular file, or bytes outside schema v1; and
    /// [`UpdateError::Read`] when the file cannot be opened or read.
    pub fn read(&self, name: &str) -> Result<UpdateEvidence, UpdateError> {
        if !is_record_name(name) {
            return Err(unknown_record());
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(ANCHOR_O_NOFOLLOW | OPEN_NONBLOCK)
            .open(self.root.join(name))
            .map_err(|source| UpdateError::Read { source })?;
        let metadata = file
            .metadata()
            .map_err(|source| UpdateError::Read { source })?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(not_private());
        }
        if metadata.len() > EVIDENCE_MAX_BYTES as u64 {
            return Err(UpdateError::Record {
                detail: "the record exceeds its byte bound",
            });
        }
        let mut bytes = Vec::new();
        (&file)
            .take(EVIDENCE_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| UpdateError::Read { source })?;
        if bytes.len() > EVIDENCE_MAX_BYTES {
            return Err(UpdateError::Record {
                detail: "the record exceeds its byte bound",
            });
        }
        let text = std::str::from_utf8(&bytes).map_err(|_not_utf8| UpdateError::Record {
            detail: "the record is not utf-8",
        })?;
        if !depth_within(text, EVIDENCE_MAX_DEPTH) {
            return Err(UpdateError::Record {
                detail: "the record nests past its depth bound",
            });
        }
        let evidence: UpdateEvidence =
            serde_json::from_str(text).map_err(|_malformed| malformed_record())?;
        validate(&evidence)?;
        Ok(evidence)
    }

    /// The committed records of this data root, oldest first. A name this
    /// module did not generate is not a record — a crashed replacement temp is
    /// skipped, never attributed — so hand-removal degrades to fewer records.
    ///
    /// # Errors
    /// [`UpdateError::Reserve`] when the directory cannot be listed,
    /// [`UpdateError::Read`] when an entry cannot be inspected, and
    /// [`UpdateError::Record`] when a record-named entry is not a private
    /// regular file.
    pub fn names(&self) -> Result<Vec<String>, UpdateError> {
        Ok(self.stored()?.into_iter().map(|entry| entry.name).collect())
    }

    /// Prunes only what may be pruned — a superseded `success`, a `resolved` record,
    /// and a `resolved` record whose cause a newer record repeats — oldest first, until
    /// the count and byte bounds hold again or nothing prunable is left. An unresolved
    /// record is never retention-evicted, and neither is the newest record carrying a
    /// cause, the one an operator still has to act on, nor the newest
    /// `terminal: success`, the one record that proves a convergence happened.
    ///
    /// # Errors
    /// [`UpdateError::Reserve`] when the directory cannot be listed,
    /// [`UpdateError::Read`] when a record cannot be decoded, and
    /// [`UpdateError::Write`] when a removable record cannot be removed.
    pub fn prune(&self) -> Result<usize, UpdateError> {
        self.prune_to(EVIDENCE_MAX_RECORDS)
    }

    /// Prunes until at most `count` records and their bytes fit the total bound, or
    /// until nothing evictable is left.
    ///
    /// A tree already inside the bounds is not decoded at all: the byte total and the
    /// count are both the listing's own metadata. Past them the newest carrier of every
    /// cause is found first — so the pass knows which records it may never evict — and the
    /// removal walk then stops once it has passed [`EVIDENCE_MAX_RECORDS`] records it may
    /// not evict.
    ///
    /// The newest success is protected; finding it costs only the records newer than it,
    /// because the walk from the newest record backwards stops at the first success it
    /// reads. The carrier walk that follows reads the tree once more in the same
    /// direction, so a pass that finds nothing removable has paid two decodes of the
    /// tree.
    fn prune_to(&self, count: usize) -> Result<usize, UpdateError> {
        let stored = self.stored()?;
        let (success, _decoded) = self.newest_success(&stored)?;
        self.prune_stored(&stored, count, success, &[])
    }

    /// The index of the newest `terminal: success` record in a listing, and how many
    /// records the walk decoded to find it. The scan runs newest-first and stops at the
    /// first success, so a settled tree costs one read.
    fn newest_success(&self, stored: &[Stored]) -> Result<(Option<usize>, usize), UpdateError> {
        let mut decoded = 0;
        for (index, entry) in stored.iter().enumerate().rev() {
            decoded += 1;
            if self.read(&entry.name)?.terminal == Terminal::Success {
                return Ok((Some(index), decoded));
            }
        }
        Ok((None, decoded))
    }

    /// [`EvidenceStore::prune_to`] over a listing the caller already took. What is
    /// never evicted here: `success` — the index of the newest `terminal: success`, the
    /// only evidence a convergence happened — every name in `settled`, the records the
    /// settlement pass that called this just rewrote, every unresolved record, and the
    /// newest record carrying each cause. An older record carrying a cause a newer one
    /// still carries is a duplicate of it and may go, so a settled backlog does not
    /// freeze the tree while every cause stays readable.
    ///
    /// The rule holds on every prune, not only on the settling pass: `durable_replace`
    /// rewrites a settled record newer than the success that settled it, and neither that
    /// rewrite nor an ordinary write after it can evict the cause an operator still has to
    /// act on.
    ///
    /// A tree whose newest causes alone exceed `count` or the byte bound therefore stays
    /// over it: that is the cost `DEC-025` records, not a bound this pass restores.
    fn prune_stored(
        &self,
        stored: &[Stored],
        count: usize,
        success: Option<usize>,
        settled: &[String],
    ) -> Result<usize, UpdateError> {
        let mut remaining = stored.len();
        let mut total: usize = stored.iter().map(|entry| entry.bytes).sum();
        if remaining <= count && total <= EVIDENCE_MAX_TOTAL_BYTES {
            return Ok(0);
        }
        let mut removed = 0;
        let mut kept = 0;
        // Oldest-first removal, so the record an operator has least need of goes first;
        // the newest carrier of every cause is excluded up front.
        let carriers = self.newest_carriers(stored)?;
        for (index, entry) in stored.iter().enumerate() {
            if remaining <= count && total <= EVIDENCE_MAX_TOTAL_BYTES {
                break;
            }
            if Some(index) == success
                || settled.binary_search(&entry.name).is_ok()
                || carriers.binary_search(&entry.name).is_ok()
            {
                continue;
            }
            let record = self.read(&entry.name)?;
            // A superseded success, a resolved record with no cause, or a duplicate of a
            // cause a newer record still carries. An unresolved record never qualifies.
            if !(record.resolved || record.terminal == Terminal::Success) {
                kept += 1;
                if kept >= EVIDENCE_MAX_RECORDS {
                    break;
                }
                continue;
            }
            std::fs::remove_file(self.root.join(&entry.name))
                .map_err(|source| UpdateError::Write { source })?;
            remaining -= 1;
            total -= entry.bytes;
            removed += 1;
        }
        Ok(removed)
    }

    /// The newest record carrying each distinct cause, sorted by name. One newest-first
    /// walk decides the whole rule: an older record with that cause is a duplicate whose
    /// eviction loses nothing an operator can still read.
    fn newest_carriers(&self, stored: &[Stored]) -> Result<Vec<String>, UpdateError> {
        let mut causes: Vec<Failure> = Vec::new();
        let mut carriers: Vec<String> = Vec::new();
        for entry in stored.iter().rev() {
            let Some(cause) = self.read(&entry.name)?.first_failure else {
                continue;
            };
            if !causes.contains(&cause) {
                causes.push(cause);
                carriers.push(entry.name.clone());
            }
        }
        carriers.sort_unstable();
        Ok(carriers)
    }

    /// The newest attempt this data root retained, projected onto the status:
    /// the milestone of the newest record while it is unresolved, the original
    /// cause of the newest record that carries one (so a clean convergence never
    /// erases what an earlier attempt failed on), and that record's name relative
    /// to the data root. A data root with no record answers nothing, and the
    /// ledger's own row is then the whole projection.
    ///
    /// The tree may hold more than [`EVIDENCE_MAX_RECORDS`] because the recorded
    /// admission lets a same-base attempt through while a cutover stays pending, so
    /// the read decodes the newest [`PROJECTION_MAX_RECORDS`] records plus the newest
    /// record carrying a cause, and reports `decoded` and `truncated`. Without that
    /// bound every `runtime.status` would be linear in a set the count bound no longer
    /// bounds.
    ///
    /// # Errors
    /// Any error a listing or a bounded decode reports.
    pub fn projection(&self) -> Result<AttemptProjection, UpdateError> {
        let stored = self.stored()?;
        let present = stored.len();
        // The newest window, plus — when no record in it carries a cause — the newest
        // record outside it that does, found by walking back from the window's edge so
        // the first match is the one an operator reads.
        let window = present.saturating_sub(PROJECTION_MAX_RECORDS);
        let mut decoded = 0usize;
        let mut newest: Option<String> = None;
        let mut failed: Option<(UpdateEvidence, String)> = None;
        // A converged attempt's milestone is the ledger row's own answer, so the
        // phase is the newest attempt that has not reached `success` since the last
        // one that did. Resolution is what `settle_success` writes, and it rewrites
        // the earlier records in place — which moves their write time — so a phase
        // taken from the newest file alone would resurface a rollback the activation
        // already resolved.
        let mut phase = None;
        for entry in &stored[window..] {
            let record = self.read(&entry.name)?;
            decoded += 1;
            // `stored()` is oldest-first, so each record that carries a cause
            // replaces the last: the operator reads the newest attempt that failed.
            if record.first_failure.is_some() {
                failed = Some((record.clone(), entry.name.clone()));
            }
            if record.terminal == Terminal::Success {
                phase = None;
            } else if !record.resolved {
                phase = record.phase;
            }
            newest = Some(entry.name.clone());
        }
        if failed.is_none() {
            // Nothing in the newest window carries a cause, so the newest record outside
            // it is found by walking back — bounded by the same fixed window, so the read
            // is never linear in the tree. A cause further back than that window is not
            // reached by this read; the projection then reports the truncation instead of
            // decoding to the bottom of the tree, and the ledger's own row still answers.
            for entry in stored[..window].iter().rev().take(PROJECTION_MAX_RECORDS) {
                let record = self.read(&entry.name)?;
                decoded += 1;
                if record.first_failure.is_some() {
                    failed = Some((record, entry.name.clone()));
                    break;
                }
            }
        }
        let Some(newest_name) = newest else {
            return Ok(AttemptProjection {
                phase: None,
                failure: None,
                evidence: None,
                decoded,
                truncated: false,
            });
        };
        let (failure, evidence) = match failed {
            Some((record, name)) => (record.wire_error(), Some(name)),
            // No record carries a cause: the newest record is what an operator
            // can still read, even when it is the resolved success.
            None => (None, Some(newest_name)),
        };
        Ok(AttemptProjection {
            phase,
            failure,
            evidence,
            decoded,
            truncated: present > decoded,
        })
    }

    /// The one producer of `resolved`: a later attempt that reached
    /// `terminal: success` marks every earlier unresolved record of this data
    /// root resolved in the same durable pass, then prunes what became
    /// prunable. It runs inside the update cleanup seam and opens no new one.
    ///
    /// The pass walks the listing twice and retains no decoded record between
    /// reads: settlement is exactly the moment `DEC-024` admits the tree may hold
    /// more than [`EVIDENCE_MAX_RECORDS`], so a pass sized by the listing would put
    /// one record per entry on the heap at that moment. The first walk finds the
    /// newest success, the second rewrites only what precedes it — the records this
    /// success supersedes — and stops there.
    ///
    /// The prune that follows takes the listing from *before* the rewrite. A
    /// `durable_replace` moves a settled record's write time to now, past the success
    /// that settled it, so a fresh listing would offer that success first and evict the
    /// evidence the convergence happened before the causes it settled. The settled names
    /// are skipped there too: this pass retains the records it just rewrote, and no later
    /// pass evicts the newest carrier of a cause either — only a duplicate of a cause a
    /// newer record still holds, or a resolved record with no cause, may go.
    ///
    /// # Errors
    /// Any error a read, a durable replacement or the prune reports.
    pub fn settle_success(&self) -> Result<Settlement, UpdateError> {
        let stored = self.stored()?;
        let (success, mut decoded) = self.newest_success(&stored)?;
        let Some(index) = success else {
            return Ok(Settlement {
                resolved: 0,
                decoded,
            });
        };
        let mut settled: Vec<String> = Vec::new();
        for entry in &stored[..index] {
            let record = self.read(&entry.name)?;
            decoded += 1;
            if record.resolved {
                continue;
            }
            let mut resolved = record;
            resolved.resolved = true;
            let bytes = serde_json::to_vec(&resolved).map_err(|_malformed| malformed_record())?;
            durable_replace(&self.root, &entry.name, &bytes)
                .map_err(|source| UpdateError::Write { source })?;
            settled.push(entry.name.clone());
        }
        settled.sort_unstable();
        self.prune_stored(&stored, EVIDENCE_MAX_RECORDS, success, &settled)?;
        Ok(Settlement {
            resolved: settled.len(),
            decoded,
        })
    }

    /// Whether this attempt continues the base the newest unresolved record
    /// names. Without that check a saturated root could not produce the success
    /// that resolves it, and `resolved` would have no producer at all.
    fn continues_unresolved(&self, offered_base: Option<u64>) -> Result<bool, UpdateError> {
        for entry in self.stored()?.into_iter().rev() {
            let record = self.read(&entry.name)?;
            if record.resolved || record.terminal == Terminal::Success {
                continue;
            }
            return Ok(record.offered_base == offered_base);
        }
        Ok(false)
    }

    fn stored(&self) -> Result<Vec<Stored>, UpdateError> {
        let mut entries = Vec::new();
        for entry in
            std::fs::read_dir(&self.root).map_err(|source| UpdateError::Reserve { source })?
        {
            let entry = entry.map_err(|source| UpdateError::Reserve { source })?;
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if !is_record_name(&name) {
                continue;
            }
            let metadata = std::fs::symlink_metadata(entry.path())
                .map_err(|source| UpdateError::Read { source })?;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(not_private());
            }
            let written = metadata
                .modified()
                .map_err(|source| UpdateError::Read { source })?;
            let bytes = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
            entries.push(Stored {
                name,
                written,
                bytes,
            });
        }
        // Attempt order is the durable write time — a UUIDv4 carries none — and
        // the generated name only breaks a tie inside one timestamp. A
        // hand-removed record therefore leaves a gap the pruner walks over
        // instead of a sequence it insists on.
        entries.sort_by(|left, right| {
            left.written
                .cmp(&right.written)
                .then_with(|| left.name.cmp(&right.name))
        });
        Ok(entries)
    }
}

fn malformed_record() -> UpdateError {
    UpdateError::Record {
        detail: "the record is not schema v1",
    }
}

fn unknown_record() -> UpdateError {
    UpdateError::Record {
        detail: "the record name was not generated by this store",
    }
}

fn not_private() -> UpdateError {
    UpdateError::Record {
        detail: "the record is not a private regular file",
    }
}

/// Refuses a record that is outside schema v1 before it is written or projected.
fn validate(evidence: &UpdateEvidence) -> Result<(), UpdateError> {
    let refuse = |detail: &'static str| Err(UpdateError::Record { detail });
    if evidence.version != EVIDENCE_VERSION {
        return refuse("the record version is not this schema");
    }
    if !generated_uuid(&evidence.attempt_id) {
        return refuse("the attempt id is not a generated uuid");
    }
    if evidence
        .offered_base
        .is_some_and(|base| base > i64::MAX as u64)
    {
        return refuse("the offered base is past the storable range");
    }
    for tuple in [
        evidence.old_tuple.as_ref(),
        evidence.observed_tuple.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if tuple.schema > i32::MAX as u32 || !is_policy_generation(&tuple.policy) {
            return refuse("the stored tuple is outside its schema");
        }
    }
    if evidence.secondary.len() > SECONDARY_MAX {
        return refuse("the secondary failures exceed their bound");
    }
    for failure in evidence
        .first_failure
        .iter()
        .chain(evidence.secondary.iter())
    {
        if failure
            .detail
            .as_deref()
            .is_some_and(|detail| !bounded_token(detail))
        {
            return refuse("the retained detail is not a bounded token");
        }
    }
    Ok(())
}

/// The classification one supplied detail goes through before it is retained:
/// an unknown but well-formed non-secret token survives, secret material is
/// dropped as `redacted_secret`, and hostile, path-shaped, control-bearing or
/// overlength text becomes the fixed `invalid_detail`.
fn classify_detail(raw: &str) -> (Option<FailureReason>, Option<String>) {
    const SECRET_MARKERS: [&str; 8] = [
        "secret",
        "token",
        "password",
        "passwd",
        "apikey",
        "api_key",
        "credential",
        "bearer",
    ];
    if !bounded_token(raw) {
        return (Some(FailureReason::InvalidDetail), None);
    }
    if SECRET_MARKERS.iter().any(|marker| raw.contains(marker)) {
        return (Some(FailureReason::RedactedSecret), None);
    }
    (None, Some(raw.to_string()))
}

/// A bounded token: `[a-z][a-z0-9_.-]{0,63}`. Anything else — a path, a control
/// sequence, an upper-case or overlength run — is not retainable.
fn bounded_token(raw: &str) -> bool {
    let mut bytes = raw.bytes();
    match bytes.next() {
        Some(first) if first.is_ascii_lowercase() => {}
        _ => return false,
    }
    raw.len() <= 64
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
}

fn generated_uuid(stem: &str) -> bool {
    stem.len() == 36 && uuid::Uuid::parse_str(stem).is_ok()
}

fn is_policy_generation(policy: &str) -> bool {
    policy.len() == 64
        && policy
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_record_name(name: &str) -> bool {
    name.strip_suffix(".json").is_some_and(generated_uuid)
}

fn record_name(attempt_id: &str) -> Result<String, UpdateError> {
    if !generated_uuid(attempt_id) {
        return Err(UpdateError::Record {
            detail: "the attempt id is not a generated uuid",
        });
    }
    Ok(format!("{attempt_id}.json"))
}

/// Refuses a record that nests deeper than the decoder's bound before serde
/// allocates anything for it.
fn depth_within(text: &str, max: usize) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in text.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    return false;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

/// Creates (or proves) one private directory: a real directory, never a
/// symlink, at 0700, with the same identity after the narrowing.
fn private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    let before = std::fs::symlink_metadata(path)?;
    if !before.is_dir() {
        return Err(std::io::Error::other("the path is not a directory"));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    let after = std::fs::symlink_metadata(path)?;
    if !after.is_dir()
        || after.permissions().mode() & 0o777 != 0o700
        || after.dev() != before.dev()
        || after.ino() != before.ino()
    {
        return Err(std::io::Error::other("the directory is not private"));
    }
    Ok(())
}

/// The one durable replacement: at most one bounded temp beside the record,
/// then file sync, rename and parent sync. A crash at any step leaves either
/// the previous record or the new one, never a half-written record.
fn durable_replace(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let temp = dir.join(format!("{name}.tmp"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(ANCHOR_O_NOFOLLOW | OPEN_NONBLOCK)
        .open(&temp)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(std::io::Error::other(
            "the replacement is not a private file",
        ));
    }
    // A temp left by an earlier crash may carry a wider mode; narrow it and
    // read it back before anything is written into it.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    if file.metadata()?.permissions().mode() & 0o777 != 0o600 {
        return Err(std::io::Error::other("the replacement mode is not private"));
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temp, dir.join(name))?;
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

fn checkpoint_dir(data_root: &Path) -> Result<PathBuf, UpdateError> {
    let root = data_root
        .canonicalize()
        .map_err(|source| UpdateError::Space {
            source: Box::new(source),
        })?;
    let dir = root.join(CHECKPOINT_DIR);
    private_dir(&dir).map_err(|source| UpdateError::Space {
        source: Box::new(source),
    })?;
    Ok(dir)
}

/// Narrows the snapshot to a private regular file, reads the mode back, and
/// syncs the file and its directory: without both syncs a crash could leave a
/// name with no durable content, which is not a snapshot an update may claim.
fn sync_snapshot(target: &Path) -> Result<u64, UpdateError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(ANCHOR_O_NOFOLLOW | OPEN_NONBLOCK)
        .open(target)
        .map_err(|source| UpdateError::Sync { source })?;
    let metadata = file
        .metadata()
        .map_err(|source| UpdateError::Sync { source })?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(UpdateError::Sync {
            source: std::io::Error::other("the snapshot is not a private regular file"),
        });
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|source| UpdateError::Sync { source })?;
    let metadata = file
        .metadata()
        .map_err(|source| UpdateError::Sync { source })?;
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(UpdateError::Sync {
            source: std::io::Error::other("the snapshot mode is not private"),
        });
    }
    file.sync_all()
        .map_err(|source| UpdateError::Sync { source })?;
    let parent = target.parent().ok_or(UpdateError::Sync {
        source: std::io::Error::other("the snapshot has no directory"),
    })?;
    std::fs::File::open(parent)
        .and_then(|dir| dir.sync_all())
        .map_err(|source| UpdateError::Sync { source })?;
    Ok(metadata.len())
}
