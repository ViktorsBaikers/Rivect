//! Task/evidence state owner: SQLite-backed store with revision/CAS
//! commits, outbox events, question durability, command dedupe receipts,
//! the attempt ledger and retained records. One writer, short transactions.

use crate::contracts::{
    AnswerAttempt, AnswerAttemptOutcome, AnswerSelection, ArtifactRef, AttachmentId, AttemptId,
    AttemptRef, AttemptState, Availability, Blocker, CommandResult, Criterion, CriterionId,
    ErrorCode, Event, EventId, Evidence, EvidenceId, EvidenceValidity, KNOWN_READY_OPTION,
    Lifecycle, Obligation, ObligationApplicability, ObligationExecution, OptionId, Page, Question,
    QuestionId, QuestionOption, ResumeCondition, SchedulerItem, SessionId, TaskId, TaskSnapshot,
    TodoItem,
};
use crate::executor::{FileIdentity, Unattested, WriteIdentity};
use crate::index::{
    CarryPolicy, EdgeConfidence, EdgeKind, EdgeProvenance, GenerationState, IndexEdge,
    ProjectGraph, SourceRef, StaleCause,
};
use crate::model::InputOrigin;
use crate::verification::{AssumptionCheckRecord, RetainedAttempt};
use rivect_sandbox_helper::{REUSE_TOKEN_MAX, ReuseToken};
use rusqlite::types::Value as SqlValue;
use rusqlite::{
    Connection, DropBehavior, OpenFlags, OptionalExtension, TransactionBehavior, params,
    params_from_iter,
};
use serde_json::{Value, json};
use sha2::Digest;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

mod learning;
mod sql;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum Missing {
    #[error("session {0}")]
    Session(String),
    #[error("task {0}")]
    Task(String),
    #[error("question {0}")]
    Question(String),
    #[error("attempt {0}")]
    Attempt(String),
    #[error("evidence {0}")]
    Evidence(String),
    #[error("budget scope {0}")]
    BudgetScope(String),
    #[error("budget reservation {0}")]
    Reservation(String),
    #[error("obligation")]
    Obligation,
    #[error("learning delta {0}")]
    Delta(String),
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ConflictCause {
    #[error("command {command_id} already recorded with different params")]
    DuplicateCommand { command_id: String },
    #[error("cannot publish a question for a {lifecycle} task")]
    QuestionOnLifecycle { lifecycle: String },
    #[error("a pending question already exists")]
    PendingQuestionExists,
    #[error("event {event_id} is not present in the owner store")]
    EventNotFound { event_id: String },
    #[error("event {event_id} conflicts with the owner store")]
    EventConflict { event_id: String },
    #[error("event {event_id} belongs to another session")]
    EventSessionMismatch { event_id: String },
    #[error("question is no longer pending")]
    QuestionNotPending,
    #[error("question revision {expected} is not the current revision {current}")]
    QuestionRevision { expected: u64, current: u64 },
    #[error("terminal task cannot be reopened")]
    TerminalCannotReopen,
    #[error("task revision {expected} is not the current revision {current}")]
    TaskRevision { expected: u64, current: u64 },
    #[error("cursor generation {expected} does not match snapshot generation {current}")]
    CursorGeneration { expected: u64, current: u64 },
    #[error("task is already terminal")]
    TaskAlreadyTerminal,
    #[error(
        "completion rejected: {unsatisfied} unsatisfied, {unresolved} unresolved, {unknown} unknown"
    )]
    CompletionOpen {
        unsatisfied: u64,
        unresolved: u64,
        unknown: u64,
    },
    #[error("completion rejected: {stale} stale evidence")]
    CompletionStale { stale: u64 },
    #[error("compaction would not shorten the history: folded {folded} bytes replace {before}")]
    CompactionNotShorter { before: usize, folded: usize },
    #[error("attempt {attempt_id} is {state}, not reconcile-able")]
    AttemptNotReconcileable { attempt_id: String, state: String },
    #[error("publication intent {owner}/{target}#{admission_seq} is not pending")]
    PublicationNotPending {
        owner: String,
        target: String,
        admission_seq: u64,
    },
    #[error("budget scope {scope} is already open")]
    BudgetScopeExists { scope: String },
    #[error(
        "budget scope {scope} exhausted: spent {spent} + reserved {reserved} + bound {bound} exceeds limit {limit}"
    )]
    BudgetExhausted {
        scope: String,
        spent: u64,
        reserved: u64,
        bound: u64,
        limit: u64,
    },
    #[error("budget reservation {reservation_id} is already recorded")]
    ReservationAlreadyRecorded { reservation_id: String },
    #[error("budget reservation {reservation_id} is {state}, not reserved")]
    ReservationNotReserved {
        reservation_id: String,
        state: String,
    },
    #[error("budget scope {scope} reserved {reserved} is below charge bound {bound}")]
    ChargeReservedBelowBound {
        scope: String,
        reserved: u64,
        bound: u64,
    },
    #[error("task has no plan selection")]
    PlanSelectionMissing,
    #[error("plan facts do not match the current selection revision {revision}")]
    PlanSelectionStale { revision: u64 },
    #[error("plan row {capability} is not in the current selection")]
    PlanRowMissing { capability: String },
    #[error("plan row {capability} is not closed by {handler}")]
    PlanRowHandler { capability: String, handler: String },
    #[error("plan row {capability} waits on its applicability")]
    PlanRowUnresolved { capability: String },
    #[error(
        "plan revision {revision} is not the latest unassessed revision of the current selection"
    )]
    PlanNotAssessable { revision: u64 },
    #[error("assumption expectation or assertion changed")]
    AssumptionCheckChanged,
    #[error("retained boundary {boundary_id} already records different evidence")]
    RetainedBoundaryCollision { boundary_id: String },
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum InvalidCause {
    #[error("goal must be non-empty bounded text")]
    EmptyGoal,
    #[error("unknown option {option_id} for question {question_id}")]
    UnknownOption {
        option_id: String,
        question_id: String,
    },
    #[error("option {option_id} is disabled: {reason}")]
    DisabledOption { option_id: String, reason: String },
    #[error("custom answer must be non-empty")]
    EmptyCustomAnswer,
    #[error("unknown collection {0}")]
    UnknownCollection(String),
    #[error("attempt {attempt_id} belongs to task {owner_task}, not {expected}")]
    AttemptTaskMismatch {
        attempt_id: String,
        owner_task: String,
        expected: String,
    },
    #[error("attempt {attempt_id} carries no read-performed marker")]
    MissingReadMarker { attempt_id: String },
    #[error("page cursor offset is out of range")]
    CursorOffsetOutOfRange,
    #[error("event cursor is out of range")]
    EventCursorOutOfRange,
    #[error("budget units {0} exceed the storable range")]
    BudgetUnitsOutOfRange(u64),
    #[error("budget reservation must name at least one scope")]
    EmptyBudgetScopes,
    #[error("confirmed cost {confirmed} exceeds reservation bound {bound}")]
    ConfirmedExceedsBound { confirmed: u64, bound: u64 },
}
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("not found: {0}")]
    NotFound(#[source] Missing),
    #[error("conflict: {0}")]
    Conflict(#[source] ConflictCause),
    #[error("stale intent: expected {expected}, current {current}")]
    StaleIntent { expected: u64, current: u64 },
    #[error("already terminal")]
    AlreadyTerminal,
    #[error("invalid input: {0}")]
    InvalidInput(#[source] InvalidCause),
    #[error("storage: {0}")]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// A denial whose journal write failed: the typed denial stays the
    /// primary error — it is what the caller matches on — and the journal
    /// failure rides along named, never masked, never silently dropped.
    #[error("answer denied: {denial}; the denial journal write failed: {journal}")]
    DenialJournalFailed {
        denial: Box<StoreError>,
        journal: Box<StoreError>,
    },
    /// The store's connection slot is empty or its claim-commit holder
    /// is set (DEC-048 «Reopen и quarantine»): every store call is
    /// typed-refused without SQL until a successful `TaskStore::reopen`
    /// (which first writes any held record) or a restart.
    #[error("task store is closed; reopen required")]
    Closed,
    /// `TaskStore::reopen` was shown a different database pathname than
    /// the one this store is bound to (DEC-054): a held record and the
    /// presented database are both left untouched — the holder never
    /// travels into another initialized database.
    #[error("reopen refused: database identity {presented} is not the bound {bound}")]
    ReopenIdentity { bound: PathBuf, presented: PathBuf },
    /// The database reports a schema generation this build does not know
    /// (DEC-008, I-6): it was written by a newer build, so it is refused
    /// typed before this build's learning batch runs and the generation it
    /// reports is never rewritten. The connection settles its own settings
    /// (file mode, journal) before the ledger is read, so a refused open is a
    /// refusal to serve, not an untouched file.
    #[error("store schema generation {found} is newer than the {known} this build knows")]
    UnsupportedGeneration { found: u64, known: u64 },
    /// A learning-domain refusal, kept as its own typed class (P-001): the
    /// delta owner's error surfaces unchanged instead of degrading into a
    /// storage failure.
    #[error("learning: {0}")]
    Delta(#[from] crate::learning::DeltaError),
}

impl StoreError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) => ErrorCode::NotFound,
            Self::Conflict(ConflictCause::BudgetExhausted { .. }) => ErrorCode::BudgetExhausted,
            Self::Conflict(_) => ErrorCode::Conflict,
            Self::StaleIntent { .. } => ErrorCode::StaleIntent,
            Self::AlreadyTerminal => ErrorCode::AlreadyTerminal,
            Self::InvalidInput(_) => ErrorCode::InvalidInput,
            Self::Storage(_) => ErrorCode::StorageUnavailable,
            Self::Closed => ErrorCode::StorageUnavailable,
            Self::ReopenIdentity { .. } => ErrorCode::InvalidInput,
            Self::UnsupportedGeneration { .. } => ErrorCode::UnsupportedVersion,
            Self::Delta(error) => error.code(),
            // The wire code stays the denial's: a caller acting on the
            // denial sees the same class whether or not its journal row
            // landed.
            Self::DenialJournalFailed { denial, .. } => denial.code(),
        }
    }

    pub fn missing_session(id: impl Into<String>) -> Self {
        Self::NotFound(Missing::Session(id.into()))
    }

    pub fn missing_task(id: impl Into<String>) -> Self {
        Self::NotFound(Missing::Task(id.into()))
    }

    pub fn missing_question(id: impl Into<String>) -> Self {
        Self::NotFound(Missing::Question(id.into()))
    }

    pub fn missing_attempt(id: impl Into<String>) -> Self {
        Self::NotFound(Missing::Attempt(id.into()))
    }

    pub fn missing_evidence(id: impl Into<String>) -> Self {
        Self::NotFound(Missing::Evidence(id.into()))
    }

    pub fn missing_obligation() -> Self {
        Self::NotFound(Missing::Obligation)
    }
}

pub type Result<T, E = StoreError> = std::result::Result<T, E>;

/// The journaled denial class for one rejected answer attempt — the typed
/// reason the journal keeps, never a prose string the caller must parse.
/// `pub(crate)` so the dispatch layer journals denials raised before
/// `answer_question` can run under the same taxonomy the store uses.
pub(crate) fn denial_class(error: &StoreError) -> &'static str {
    match error {
        StoreError::StaleIntent { .. } => "stale_intent",
        StoreError::AlreadyTerminal => "already_terminal",
        StoreError::NotFound(_) => "not_found",
        StoreError::Conflict(ConflictCause::QuestionNotPending) => "replayed_answer",
        StoreError::Conflict(ConflictCause::QuestionRevision { .. }) => "stale_revision",
        StoreError::Conflict(_) => "conflict",
        StoreError::InvalidInput(InvalidCause::UnknownOption { .. }) => "unknown_option",
        StoreError::InvalidInput(InvalidCause::DisabledOption { .. }) => "disabled_option",
        StoreError::InvalidInput(InvalidCause::EmptyCustomAnswer) => "empty_custom",
        StoreError::InvalidInput(_) => "invalid_input",
        StoreError::ReopenIdentity { .. } => "invalid_input",
        StoreError::UnsupportedGeneration { .. } => "unsupported_version",
        StoreError::Delta(error) => error.code().as_str(),
        StoreError::Storage(_) => "storage",
        StoreError::Closed => "storage",
        StoreError::DenialJournalFailed { denial, .. } => denial_class(denial),
    }
}

fn storage(err: impl std::error::Error + Send + Sync + 'static) -> StoreError {
    StoreError::Storage(Box::new(err))
}

/// Idempotency step for the reaction journal (DEC-016 schema residual):
/// `CREATE TABLE IF NOT EXISTS` leaves untouched a database whose
/// `supervisor_reactions` predates the `id` append identity
/// (intermediate commit 0131781), so `ORDER BY id` paging would fail.
/// A current table is left as-is; an id-less one is rebuilt in one
/// immediate transaction, preserving journal order by rowid.
fn migrate_supervisor_reactions(conn: &mut Connection) -> Result<()> {
    let has_id = {
        let mut stmt = conn
            .prepare(sql::SUPERVISOR_REACTIONS_COLUMNS)
            .map_err(storage)?;
        let columns = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        columns.iter().any(|name| name == "id")
    };
    if has_id {
        return Ok(());
    }
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage)?;
    tx.execute_batch(sql::MIGRATE_SUPERVISOR_REACTIONS)
        .map_err(storage)?;
    tx.commit().map_err(storage)?;
    Ok(())
}

fn event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Event> {
    Ok(Event {
        schema_version: 1,
        event_id: EventId(row.get(0)?),
        aggregate_id: row.get(1)?,
        aggregate_revision: row.get::<_, i64>(2)? as u64,
        cursor: row.get::<_, i64>(3)? as u64,
        session_id: SessionId(row.get(4)?),
        task_id: row.get::<_, Option<String>>(5)?.map(TaskId),
        event_type: row.get(6)?,
        delta: serde_json::from_str(&row.get::<_, String>(7)?).map_err(|source| {
            rusqlite::Error::FromSqlConversionFailure(
                7,
                rusqlite::types::Type::Text,
                Box::new(source),
            )
        })?,
        origin: row.get(8)?,
    })
}
fn publication_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<crate::config::PublicationIntent> {
    let identity: Option<String> = row.get(5)?;
    let publish_identity = identity
        .map(|raw| parse_publish_identity(&raw))
        .transpose()?;
    Ok(crate::config::PublicationIntent {
        owner: row.get(0)?,
        target: row.get(1)?,
        admission_seq: row.get::<_, i64>(2)? as u64,
        intended_digest: row.get(3)?,
        base_digest: row.get(4)?,
        publish_identity,
    })
}

/// Longest `identity` column: `v2:`, two 16-digit fields, two separators
/// and the hex of a [`REUSE_TOKEN_MAX`]-byte token.
const PUBLICATION_IDENTITY_MAX: usize = 3 + 2 * 16 + 2 + 2 * REUSE_TOKEN_MAX;

/// The `identity` column of one write identity: `v2:<dev>:<ino>:<token>`
/// when attested, the legacy `<dev>:<ino>` when not, all lowercase hex.
fn encode_publish_identity(identity: &WriteIdentity) -> String {
    let file = identity.file();
    match identity.reuse() {
        Ok(token) => format!(
            "v2:{:x}:{:x}:{}",
            file.dev(),
            file.ino(),
            crate::config::hex(token.as_bytes())
        ),
        Err(Unattested::Unsupported | Unattested::Unrecorded) => {
            format!("{:x}:{:x}", file.dev(), file.ino())
        }
    }
}

/// A malformed `identity` column is a corrupted journal row; reading it
/// fails instead of guessing an attribution. A legacy two-field row was
/// recorded without a reuse token and reads as unattested; a `v2` row
/// reads only with a token whose platform shape validates.
fn parse_publish_identity(raw: &str) -> rusqlite::Result<WriteIdentity> {
    let identity_error = |source: std::io::Error| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(source))
    };
    let malformed = |what: &'static str| {
        identity_error(std::io::Error::new(std::io::ErrorKind::InvalidData, what))
    };
    if raw.len() > PUBLICATION_IDENTITY_MAX {
        return Err(malformed("publication identity column is too long"));
    }
    let fields: Vec<&str> = raw.split(':').collect();
    let (dev, ino, reuse) = match fields.as_slice() {
        [dev, ino] => (*dev, *ino, Err(Unattested::Unrecorded)),
        ["v2", dev, ino, token] => {
            let token = parse_reuse_token(token)
                .ok_or_else(|| malformed("malformed publication identity token"))?;
            (*dev, *ino, Ok(token))
        }
        _ => return Err(malformed("malformed publication identity column")),
    };
    let hex64 = |digits: &str| {
        if digits.is_empty() || digits.len() > 16 || !digits.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(malformed("malformed publication identity field"));
        }
        u64::from_str_radix(digits, 16).map_err(|source| {
            identity_error(std::io::Error::new(std::io::ErrorKind::InvalidData, source))
        })
    };
    Ok(WriteIdentity::new(
        FileIdentity::new(hex64(dev)?, hex64(ino)?),
        reuse,
    ))
}

/// Decodes the hex digits of a stored reuse token: a nonempty, even run
/// of at most `2 * REUSE_TOKEN_MAX` digits whose bytes form a valid
/// platform token.
fn parse_reuse_token(digits: &str) -> Option<ReuseToken> {
    if digits.is_empty() || digits.len() > 2 * REUSE_TOKEN_MAX {
        return None;
    }
    let (pairs, []) = digits.as_bytes().as_chunks::<2>() else {
        return None;
    };
    let bytes = pairs
        .iter()
        .map(|&[high, low]| Some(hex_digit(high)? * 16 + hex_digit(low)?))
        .collect::<Option<Vec<u8>>>()?;
    ReuseToken::from_bytes(&bytes)
}

fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

const ASSUMPTION_RECORD_VERSION: i64 = 1;

/// Owner-local connect/close failures of the shared §9 conn-init
/// (DEC-048 «Reopen и quarantine»): every refusal is typed before any
/// row is read or written, and `file` never carries a raw path.
#[derive(Debug, thiserror::Error)]
enum ConnectionLifecycleError {
    #[error("connection setting {pragma} did not apply")]
    SettingMismatch { pragma: &'static str },
    #[error("database file {file} is not a private regular file")]
    FileMode { file: &'static str },
    #[error("checking database file {file} failed")]
    FileCheck {
        file: &'static str,
        #[source]
        source: std::io::Error,
    },
    /// The database file already has a writer in this or another process.
    /// Reuse that store (`Runtime::store_writer` or `Runtime::store` for a
    /// bound store, `TaskStore::writer` for a standalone one), or drop it and
    /// the `Runtime` or `Owner` that owns it before opening again. `close`
    /// keeps the admission and releases nothing; a writer in another process
    /// is released only when that process drops its store or exits. After a
    /// reported `database writer lock release failed` or `owner lock release
    /// failed` line, a descriptor that a child of that process inherited can
    /// keep refusing until the child execs or exits; wait for it or restart
    /// the process.
    #[error("the database already has a writer")]
    WriterHeld,
    #[error("the database file has more than one name")]
    DatabaseAliased,
    #[error("the database path no longer names the locked file")]
    DatabaseMoved,
    /// The filesystem lacks open-file-description locks. Place the data root
    /// on a supported local filesystem.
    #[error("the database writer lock is unavailable on this filesystem")]
    WriterLockUnavailable,
    /// A panic poisoned the process-wide writer registry. Every later
    /// admission in this process refuses; existing stores keep working and
    /// still release on drop. Recovery is a process restart.
    #[error("the database writer registry is unavailable")]
    WriterRegistry,
    /// Admission could not reserve storage or reached the parked-descriptor
    /// cap. For the cap, drop the stores that hold parked descriptors; for a
    /// failed reservation, free process memory or restart the process. There
    /// may be no parked descriptors to release.
    #[error("the database writer admission capacity is exhausted")]
    WriterAdmissionSaturated,
    #[error("wal checkpoint did not complete")]
    CheckpointIncomplete,
}

/// `(dev, ino)` of one database file.
type FileId = (u64, u64);

/// The sentinel byte of the writer lock: disjoint from SQLite's own
/// lock bytes (`PENDING_BYTE`, `RESERVED_BYTE`, the shared range).
const STORE_WRITER_LOCK_OFFSET: i64 = i64::MAX - 1;

/// The per-process bound on parked and unidentified descriptors.
const STORE_PARKED_MAX: usize = 32;

/// Which advisory lock a failed release concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReleasedLock {
    /// The database writer lock of a store's registry entry.
    Writer,
    /// The `owner.lock` election lock.
    Owner,
}

impl ReleasedLock {
    const fn name(self) -> &'static str {
        match self {
            Self::Writer => "database writer",
            Self::Owner => "owner",
        }
    }
}

/// One failed lock release. It is `Copy` and keeps only the kind and raw
/// errno of the failure, never a path, so handing it off allocates
/// nothing and its text is the errno text alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{} lock release failed: {}", self.lock.name(), self.error())]
pub(crate) struct ReleaseFault {
    lock: ReleasedLock,
    kind: std::io::ErrorKind,
    os: Option<i32>,
}

impl ReleaseFault {
    fn error(&self) -> std::io::Error {
        self.os.map_or_else(
            || std::io::Error::from(self.kind),
            std::io::Error::from_raw_os_error,
        )
    }
}

/// The per-thread carrier of failed releases: the first two in order
/// plus a saturating count of the rest. It is `Copy` and needs no
/// `Drop`, so its `const` thread-local is reachable from any destructor.
#[derive(Debug, Clone, Copy)]
struct ReleaseFaults {
    held: [Option<ReleaseFault>; 2],
    more: u16,
}

impl ReleaseFaults {
    const EMPTY: Self = Self {
        held: [None, None],
        more: 0,
    };
}

thread_local! {
    static RELEASE_FAULTS: Cell<ReleaseFaults> = const { Cell::new(ReleaseFaults::EMPTY) };
}

/// Runs one lock release. A failure, any errno, is handed to this
/// thread's carrier for [`take_release_lines`]; the descriptor still
/// closes afterwards (it can only over-hold until a duplicate closes, so
/// the next admission is a typed refusal, never a second writer). The
/// hand-off does no I/O, takes no lock and allocates nothing, so no
/// destructor blocks on it; a fault arriving while two are held is only
/// counted (load-shed).
pub(crate) fn unlock_or_hand_off(lock: ReleasedLock, unlock: impl FnOnce() -> std::io::Result<()>) {
    let released = match proof::unlock_fault() {
        Some(error) => Err(error),
        None => unlock(),
    };
    let Err(error) = released else {
        return;
    };
    let fault = ReleaseFault {
        lock,
        kind: error.kind(),
        os: error.raw_os_error(),
    };
    RELEASE_FAULTS.with(|cell| {
        let mut faults = cell.get();
        if let Some(slot) = faults.held.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(fault);
        } else {
            faults.more = faults.more.saturating_add(1);
        }
        cell.set(faults);
    });
}

/// Empties this thread's carrier into one-line strings: each retained
/// fault's text, then the count of the rest. The surface that dropped
/// the owner calls it after the drop, outside every destructor, guard
/// and lock, so each fault is delivered exactly once.
pub(crate) fn take_release_lines() -> Vec<String> {
    let faults = RELEASE_FAULTS.with(|cell| cell.replace(ReleaseFaults::EMPTY));
    let mut lines: Vec<String> = faults
        .held
        .iter()
        .flatten()
        .map(ToString::to_string)
        .collect();
    if faults.more > 0 {
        lines.push(format!("further lock release failures: {}", faults.more));
    }
    lines
}

/// The process-wide writer registry (F1): one identity fd per admitted
/// database inode, holding its OFD lock for the life of the entry.
/// Descriptors that must not close while the process may hold locks on
/// their inode sit in `parked` (keyed by the holder they were parked
/// under) or `unidentified`. No method clears or replaces it.
struct Registry {
    held: HashMap<FileId, OwnedFd>,
    parked: Vec<(FileId, OwnedFd)>,
    unidentified: Vec<OwnedFd>,
}

static WRITERS: LazyLock<Mutex<Registry>> = LazyLock::new(|| {
    Mutex::new(Registry {
        held: HashMap::new(),
        parked: Vec::new(),
        unidentified: Vec::new(),
    })
});

/// A registry destination one admission can reserve and place into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dest {
    Held,
    Parked,
    Unidentified,
}

/// The statement-position witnesses of one admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriterPoint {
    AfterReserve,
    CreationOpen,
    CreationDrop,
    AfterOpen,
    AfterPlace,
}

/// The outcome of one admission: the inode, and whether this call
/// inserted its registry entry (a same-inode reopen keeps its own).
struct Admitted {
    id: FileId,
    fresh: bool,
}

fn writer_file_check(file: &'static str, source: std::io::Error) -> StoreError {
    storage(ConnectionLifecycleError::FileCheck { file, source })
}

/// Reserves one slot in every destination an admission can reach, so
/// the placement after the identity fd opens never allocates.
fn reserve_writer_slots(registry: &mut Registry) -> bool {
    !proof::reserve_fault(Dest::Held)
        && registry.held.try_reserve(1).is_ok()
        && !proof::reserve_fault(Dest::Parked)
        && registry.parked.try_reserve(1).is_ok()
        && !proof::reserve_fault(Dest::Unidentified)
        && registry.unidentified.try_reserve(1).is_ok()
}

/// Steps (c)-(e): the identity fd ends in exactly one reserved
/// destination or is closed after membership exclusion. Nothing here
/// allocates: refusals are plain enum values, boxed after the guard.
fn place_writer(
    registry: &mut Registry,
    db: &Path,
    id: FileId,
) -> std::result::Result<(), ConnectionLifecycleError> {
    use rivect_sandbox_helper::{
        ANCHOR_O_NOFOLLOW, OPEN_NONBLOCK, OfdLockError, ofd_try_write_lock,
    };
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(ANCHOR_O_NOFOLLOW | OPEN_NONBLOCK)
        .open(db)
        .map_err(|source| ConnectionLifecycleError::FileCheck { file: "db", source })?;
    proof::identity_fd_opened();
    proof::writer_point(WriterPoint::AfterOpen, registry);
    let metadata = if proof::fstat_fault() {
        Err(std::io::Error::other("injected fstat fault"))
    } else {
        file.metadata()
    };
    let metadata = match metadata {
        Ok(metadata) => metadata,
        Err(source) => {
            registry.unidentified.push(OwnedFd::from(file));
            return Err(ConnectionLifecycleError::FileCheck { file: "db", source });
        }
    };
    let found = (metadata.dev(), metadata.ino());
    if registry.held.contains_key(&found) {
        // Parking keeps the holder's locks alive until entry destruction
        // closes the descriptor. The test switch closes it here instead,
        // which drops those locks while the holder still lives.
        if proof::close_instead_of_park() {
            drop(file);
            return Err(ConnectionLifecycleError::WriterHeld);
        }
        registry.parked.push((found, OwnedFd::from(file)));
        return Err(ConnectionLifecycleError::WriterHeld);
    }
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(ConnectionLifecycleError::DatabaseAliased);
    }
    if found != id {
        return Err(ConnectionLifecycleError::DatabaseMoved);
    }
    // std's `OpenOptions::open` ORs `O_CLOEXEC` into every open and
    // `custom_flags` cannot clear it, so the identity fd is close-on-exec
    // before this lock: a concurrent `fork` never carries the OFD lock
    // into a child across `exec`. A held lock is refused at once.
    let locked = match proof::lock_fault() {
        Some(error) => Err(error),
        None => ofd_try_write_lock(&file, STORE_WRITER_LOCK_OFFSET),
    };
    match locked {
        Ok(()) => {}
        Err(OfdLockError::Held) => return Err(ConnectionLifecycleError::WriterHeld),
        Err(OfdLockError::Unsupported) => {
            return Err(ConnectionLifecycleError::WriterLockUnavailable);
        }
        Err(OfdLockError::Io(source)) => {
            return Err(ConnectionLifecycleError::FileCheck {
                file: "lock",
                source,
            });
        }
    }
    registry.held.insert(id, OwnedFd::from(file));
    Ok(())
}

/// Entry destruction: the caller closed any SQLite connection first;
/// one critical section removes the entry, closes its parked fds in
/// place, unlocks the identity description (a failure is handed off,
/// never raised: see [`unlock_or_hand_off`]), then closes the identity
/// fd last. A poisoned guard is recovered so the order always
/// completes.
#[allow(
    clippy::significant_drop_tightening,
    reason = "the identity fd must close before the registry guard releases"
)]
fn retire_writer(id: FileId) {
    let mut registry = WRITERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if proof::release_before_close() {
        // Test switch: the entry is gone and the guard is released
        // before any descriptor of this holder closes.
        let identity = registry.held.remove(&id);
        let mut parked = Vec::new();
        let mut kept = Vec::new();
        for item in registry.parked.drain(..) {
            if item.0 == id {
                parked.push(item);
            } else {
                kept.push(item);
            }
        }
        registry.parked = kept;
        // The entry owns the sentinel, so releasing the entry includes its
        // unlock; only the closes stay behind.
        if let Some(identity) = &identity {
            unlock_or_hand_off(ReleasedLock::Writer, || {
                rivect_sandbox_helper::ofd_unlock(identity, STORE_WRITER_LOCK_OFFSET)
            });
        }
        drop(registry);
        proof::entry_destruction();
        drop(parked);
        drop(identity);
        return;
    }
    let identity = registry.held.remove(&id);
    if let Some(index) = registry
        .parked
        .iter()
        .position(|(parked_under, _fd)| *parked_under == id)
    {
        registry.parked.remove(index);
    }
    proof::entry_destruction();
    registry
        .parked
        .retain(|(parked_under, _fd)| *parked_under != id);
    // The explicit unlock releases the description even while a
    // descriptor a forked child inherited keeps it open; the close
    // below happens whatever it returned.
    if let Some(identity) = &identity {
        unlock_or_hand_off(ReleasedLock::Writer, || {
            rivect_sandbox_helper::ofd_unlock(identity, STORE_WRITER_LOCK_OFFSET)
        });
    }
    drop(identity);
}

/// Owner-operation sites of the DEC-048 first-only dispatch claim: one
/// stable suffix per refusing statement or observation, injective by
/// the inline proof — an alias would hide the offline correction the
/// retained row names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaimSite {
    WaitRead,
    WaitSet,
    Cancel,
    Deadline,
    Busy,
    Begin,
    Read,
    TerminalRead,
    Lifecycle,
    Attempt,
    Replay,
    SelectionRead,
    Selection,
    GateRead,
    Gate,
    Update,
    Marker,
    WaitRestore,
    Commit,
}

impl ClaimSite {
    /// The retained suffix of this site; the map is exhaustive and
    /// injective (checked inline).
    pub(crate) fn suffix(self) -> &'static str {
        match self {
            Self::WaitRead => "admit.claim_wait_read",
            Self::WaitSet => "admit.claim_wait_set",
            Self::Cancel => "admit.claim_cancel",
            Self::Deadline => "admit.claim_deadline",
            Self::Busy => "admit.claim_busy",
            Self::Begin => "admit.claim_begin",
            Self::Read => "admit.claim_read",
            Self::TerminalRead => "admit.claim_terminal_read",
            Self::Lifecycle => "admit.claim_lifecycle",
            Self::Attempt => "admit.attempt",
            Self::Replay => "admit.replay",
            Self::SelectionRead => "admit.claim_selection_read",
            Self::Selection => "admit.claim_selection",
            Self::GateRead => "admit.claim_gate_read",
            Self::Gate => "admit.claim_gate",
            Self::Update => "admit.claim_update",
            Self::Marker => "admit.claim_marker",
            Self::WaitRestore => "admit.claim_wait_restore",
            Self::Commit => "admit.claim_commit",
        }
    }
}

/// The binding one confined check claims under: the task, the planned
/// Exec attempt, the process context and the opaque binding digest of
/// the owning admission. `native` selects the explicit variant: a
/// Native claim additionally verifies the actual selection
/// revision/facts, request kind, and the shared Open-gate semantics
/// (#7/#8); a Custom-off claim binds no native selection and skips
/// both statements by this flag, never by sentinel field values.
pub(crate) struct CheckClaim {
    pub(crate) task_id: TaskId,
    pub(crate) attempt_id: String,
    pub(crate) native: bool,
    pub(crate) selection_revision: u64,
    pub(crate) facts_digest: String,
    pub(crate) request_kind: RequestKind,
    pub(crate) binding_digest: String,
}

/// The typed outcome of one claim call: either the first-only marker
/// committed (phase Pending→Claimed) or one refusal site with its
/// retention outcome.
pub(crate) enum ClaimOutcome {
    Claimed,
    Refused(ClaimRefusal),
}

/// The internal outcome of the claim transaction body.
enum ClaimTxOutcome {
    Claimed,
    Refused(ClaimRefusal),
    /// The COMMIT was attempted and its outcome was reported as an
    /// error; the caller — with every transaction borrow released —
    /// observes `transaction_ended` and builds the record once.
    CommitReported {
        primary: String,
    },
}

/// The in-transaction statement outcome of one claim: a finished claim
/// outcome, or a refusal site whose transaction was dropped (rollback)
/// and whose denial row belongs to the caller. A refusal caused by an
/// engine-reported statement error carries its numeric SQLite primary
/// result code into the denial row.
enum InTxn {
    Complete(ClaimTxOutcome),
    Refused(ClaimSite, Option<i32>),
}

/// The numeric primary code of one store error, when it wraps an
/// engine-reported SQLite failure.
fn store_primary_numeric(error: &StoreError) -> Option<i32> {
    match error {
        StoreError::Storage(source) => source
            .downcast_ref::<rusqlite::Error>()
            .and_then(sqlite_primary_numeric),
        _ => None,
    }
}

/// The shared stop check of every claim checkpoint (#3): observed
/// cancellation first, then the absolute monotonic deadline.
fn claim_checkpoint(
    cancel: &std::sync::atomic::AtomicBool,
    deadline: std::time::Instant,
) -> Option<ClaimSite> {
    if proof::fault(proof::Site::Cancel).is_err()
        || cancel.load(std::sync::atomic::Ordering::Relaxed)
    {
        return Some(ClaimSite::Cancel);
    }
    if proof::fault(proof::Site::Deadline).is_err() || deadline <= std::time::Instant::now() {
        return Some(ClaimSite::Deadline);
    }
    None
}

/// The SQLite primary result code (`extended & 0xff`) of one rusqlite
/// error, for the fixed cause of an ambiguous COMMIT; `unknown` when
/// the error carries no engine code. The fixed `unknown`/`injected`
/// markers keep their own semantics.
fn sqlite_primary_code(error: &rusqlite::Error) -> String {
    sqlite_primary_numeric(error).map_or_else(|| "unknown".to_string(), |code| code.to_string())
}

/// The `-wal`/`-shm` sibling path of one database file.
fn sidecar_path(db: &Path, sidecar: &str) -> PathBuf {
    let mut name = db.file_name().unwrap_or_default().to_os_string();
    name.push("-");
    name.push(sidecar);
    db.with_file_name(name)
}

pub(crate) struct ClaimRefusal {
    pub(crate) site: ClaimSite,
    pub(crate) retention: RetentionOutcome,
    /// Whether the scoped timeout restoration after this refusal also
    /// failed — a typed secondary that never replaces the primary row.
    pub(crate) restore_failed: bool,
}

/// Whether a refusal's zero-wait denial row landed: a held writer lock
/// or an unusable connection leaves no row — that absence is proven by
/// its own discriminator, never papered over.
pub(crate) enum RetentionOutcome {
    Retained,
    Unavailable,
}

/// The boundary id of one check emit site's retained row
/// (`ret:check:<attempt-id>:<site>`).
pub(crate) fn check_boundary(attempt_id: &str, site: &str) -> String {
    format!("ret:check:{attempt_id}:{site}")
}

/// The invocation-unique identity of one rejection row: the existing
/// UUID generator, so two invocations — in any process, on any
/// connection — can never collide on a boundary id, and an aliased site
/// surfaces in the exact readback rather than as a write conflict.
fn rejection_identity() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// The numeric SQLite primary result code (`extended & 0xff`) of one
/// rusqlite error when the engine reported one.
fn sqlite_primary_numeric(error: &rusqlite::Error) -> Option<i32> {
    match error {
        rusqlite::Error::SqliteFailure(code, _) => Some(code.extended_code & 0xff),
        _ => None,
    }
}

/// The private holder of one ambiguous-COMMIT record (DEC-050): the
/// payload is immutable, built once at the COMMIT-error site, and
/// written only through [`TaskStore::retain_attempt`] — the same
/// object survives failed closes and opens inside `reopen`, never a
/// rebuild or a re-wrap.
mod held {
    use super::{Result, RetainedAttempt, TaskStore, proof};
    pub(super) struct HeldClaimCommit {
        payload: RetainedAttempt,
    }
    impl HeldClaimCommit {
        pub(super) fn new(payload: RetainedAttempt) -> Self {
            proof::built(&payload);
            Self { payload }
        }
        pub(super) fn retain(&self, store: &mut TaskStore) -> Result<()> {
            proof::carry(&self.payload);
            store.retain_attempt(&self.payload)
        }
    }
}

/// The task store. Reopen and close are the runtime's own lifecycle
/// operations; an external caller cannot reach them.
///
/// ```compile_fail
/// use rivect::state::TaskStore;
/// fn f(store: &mut TaskStore, path: &std::path::Path) { let _ = store.reopen(path); }
/// ```
///
/// ```
/// use rivect::state::TaskStore;
/// fn f(store: &mut TaskStore, path: &std::path::Path) { let _writer = store.writer(); let _ = path; }
/// ```
///
/// ```compile_fail
/// use rivect::state::TaskStore;
/// fn f(store: &mut TaskStore) { let _ = store.close(); }
/// ```
///
/// ```
/// use rivect::state::TaskStore;
/// fn f(store: &mut TaskStore) { let _writer = store.writer(); }
/// ```
pub struct TaskStore {
    /// The single connection slot: empty while the store is quarantined
    /// or closed; every method reaches it through the typed accessors.
    conn: Option<Connection>,
    /// The one private holder of an ambiguous-COMMIT record (DEC-050):
    /// set until a successful `reopen` carries it as the first store
    /// operation or the store itself ends.
    held_claim_commit: Option<held::HeldClaimCommit>,
    /// The canonical database pathname this store is bound to (DEC-054):
    /// a reopen naming any other database refuses before the old
    /// connection closes, so a held record never travels into another
    /// initialized database. Recreation of the same bound pathname after
    /// deletion stays legal.
    bound_db: PathBuf,
    /// Unforgeable instance identity for the admission binding
    /// (DEC-048 п.1): token equality, never a public string.
    identity: std::sync::Arc<()>,
    /// The inode this store's registry entry is keyed by; the entry
    /// lives until the store drops (reopen on the same inode keeps it).
    writer: FileId,
}

impl Drop for TaskStore {
    fn drop(&mut self) {
        // The connection closes first, outside the registry guard.
        drop(self.conn.take());
        retire_writer(self.writer);
    }
}

/// Refuses a store a newer build wrote (I-6): the generation the ledger reports
/// is compared against the one this build knows, before any DDL runs and again
/// inside the batch's write transaction, so a store that advanced in between is
/// refused typed instead of being rewound by this build's ledger write.
fn require_known_generation(generation: u64) -> Result<()> {
    if generation > learning::KNOWN_SCHEMA_GENERATION {
        return Err(StoreError::UnsupportedGeneration {
            found: generation,
            known: learning::KNOWN_SCHEMA_GENERATION,
        });
    }
    Ok(())
}

impl TaskStore {
    /// Opens the database at `path` as the one admitted writer of its file.
    ///
    /// A second writer on the same database file, in this or another
    /// process, is refused before any SQL statement runs.
    ///
    /// # Errors
    /// Every admission refusal is a typed storage error with one cause:
    /// - the file already has a writer: reuse that store
    ///   (`Runtime::store_writer` or `Runtime::store` for a bound store,
    ///   `TaskStore::writer` for a standalone one), or drop it and the
    ///   `Runtime` or `Owner` that owns it before opening again. `close`
    ///   keeps the admission and releases nothing. A writer in another
    ///   process is released only when that process drops its store or
    ///   exits. After a reported `database writer lock release failed`
    ///   or `owner lock release failed` line, a descriptor that a child of
    ///   that process inherited can keep refusing until the child execs or
    ///   exits; wait for it or restart the process;
    /// - the file has more than one name, or the path no longer names the
    ///   locked file: the open is refused before any SQL statement runs;
    /// - the filesystem lacks open-file-description locks: place the data
    ///   root on a supported local filesystem;
    /// - a panic poisoned the process-wide writer registry: every later
    ///   admission in this process refuses, existing stores keep working
    ///   and still release on drop, and recovery is a process restart;
    /// - admission could not reserve storage or reached the
    ///   parked-descriptor cap: for the cap, drop the stores that hold
    ///   parked descriptors; for a failed reservation, free process memory
    ///   or restart the process. There may be no parked descriptors to
    ///   release.
    ///
    /// Any other failure of the data root or the SQLite connection is the
    /// storage error of that step.
    pub fn open(path: &Path) -> Result<Self> {
        let bound_db = Self::canonical_db_path(path)?;
        let (conn, writer) = Self::connect(path, None)?;
        let mut store = Self {
            conn: Some(conn),
            held_claim_commit: None,
            bound_db,
            identity: std::sync::Arc::new(()),
            writer,
        };
        store.bootstrap()?;
        Ok(store)
    }

    /// The canonical spelling `connect` opens: the parent directory
    /// resolved, the file name appended verbatim (a symlinked name is
    /// the open guard's to refuse, not this helper's).
    fn canonical_db_path(path: &Path) -> Result<PathBuf> {
        let parent = path.parent().ok_or_else(|| {
            storage(ConnectionLifecycleError::FileCheck {
                file: "directory",
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "the database path has no parent directory",
                ),
            })
        })?;
        let parent = parent.canonicalize().map_err(|source| {
            storage(ConnectionLifecycleError::FileCheck {
                file: "directory",
                source,
            })
        })?;
        let file_name = path
            .file_name()
            .ok_or_else(|| {
                storage(ConnectionLifecycleError::FileCheck {
                    file: "db",
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "the database path has no file name",
                    ),
                })
            })?
            .to_os_string();
        Ok(parent.join(file_name))
    }

    /// The instance identity admissions bind to.
    pub(crate) fn identity(&self) -> &std::sync::Arc<()> {
        &self.identity
    }

    fn conn(&self) -> Result<&Connection> {
        self.unquarantined()?;
        self.conn.as_ref().ok_or(StoreError::Closed)
    }

    fn conn_mut(&mut self) -> Result<&mut Connection> {
        self.unquarantined()?;
        self.conn.as_mut().ok_or(StoreError::Closed)
    }

    /// A held claim-commit record quarantines the store exactly like an
    /// empty slot: every call is typed-refused without SQL until a
    /// successful reopen carries the record.
    fn unquarantined(&self) -> Result<()> {
        if self.held_claim_commit.is_some() {
            return Err(StoreError::Closed);
        }
        Ok(())
    }

    /// Whether the store refuses every call without SQL: an empty slot
    /// or a held claim-commit record. In-memory only.
    pub(crate) fn is_quarantined(&self) -> bool {
        self.conn.is_none() || self.held_claim_commit.is_some()
    }

    /// The shared §9 connect (DEC-048 «Reopen и quarantine»): a pre-open
    /// file guard with no SQL, `SQLITE_OPEN_NOFOLLOW`, the explicit
    /// statement-cache capacity and busy timeout through the API, then
    /// exactly the enumerated settings statements in order, each value
    /// read back, and a final file-mode readback. No task, attempt,
    /// retained or projection row is read or written here.
    fn connect(path: &Path, own: Option<FileId>) -> Result<(Connection, FileId)> {
        let (parent, file_name) = {
            let parent = path.parent().ok_or_else(|| {
                storage(ConnectionLifecycleError::FileCheck {
                    file: "directory",
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "the database path has no parent directory",
                    ),
                })
            })?;
            let parent = parent.canonicalize().map_err(|source| {
                storage(ConnectionLifecycleError::FileCheck {
                    file: "directory",
                    source,
                })
            })?;
            let mut components = path.components();
            let file_name = components.next_back().ok_or_else(|| {
                storage(ConnectionLifecycleError::FileCheck {
                    file: "db",
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "the database path has no file name",
                    ),
                })
            })?;
            if !matches!(file_name, std::path::Component::Normal(_)) {
                return Err(storage(ConnectionLifecycleError::FileCheck {
                    file: "db",
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "the database file name is not a normal path component",
                    ),
                }));
            }
            let mut rest = components;
            let _ = rest.next_back();
            (parent, file_name.as_os_str().to_os_string())
        };
        let db = parent.join(file_name);
        let admitted = Self::admit_writer(&db, own)?;
        if proof::open_flags_fault() {
            if admitted.fresh {
                retire_writer(admitted.id);
            }
            return Err(storage(ConnectionLifecycleError::FileCheck {
                file: "db",
                source: std::io::Error::other("injected open fault"),
            }));
        }
        let settled = Connection::open_with_flags(
            &db,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(storage)
        .and_then(|conn| Self::settle_admitted(conn, &db, admitted.id));
        match settled {
            Ok(conn) => Ok((conn, admitted.id)),
            Err(error) => {
                if admitted.fresh {
                    retire_writer(admitted.id);
                }
                Err(error)
            }
        }
    }

    /// Writer admission by database identity (F1), before any SQL: the
    /// whole admission runs inside one registry critical section, with
    /// every destination reserved before any fd is created or opened.
    fn admit_writer(db: &Path, own: Option<FileId>) -> Result<Admitted> {
        use std::os::unix::fs::MetadataExt as _;
        proof::before_registry_lock();
        let wal = sidecar_path(db, "wal");
        let shm = sidecar_path(db, "shm");
        if proof::creation_outside_section() {
            // Test switch: the creation runs before the registry guard (the
            // pre-F1 order); the in-section pass below then finds the file.
            let outside = Registry {
                held: HashMap::new(),
                parked: Vec::new(),
                unidentified: Vec::new(),
            };
            Self::guard_database_file(db, &wal, &shm, &outside)?;
        }
        let mut registry = WRITERS
            .lock()
            .map_err(|_poisoned| storage(ConnectionLifecycleError::WriterRegistry))?;
        if registry.parked.len() + registry.unidentified.len() >= STORE_PARKED_MAX
            || !reserve_writer_slots(&mut registry)
        {
            return Err(storage(ConnectionLifecycleError::WriterAdmissionSaturated));
        }
        proof::writer_point(WriterPoint::AfterReserve, &registry);
        Self::guard_database_file(db, &wal, &shm, &registry)?;
        proof::after_guard(db);
        let stat =
            std::fs::symlink_metadata(db).map_err(|source| writer_file_check("db", source))?;
        let id = (stat.dev(), stat.ino());
        if own == Some(id) {
            proof::after_own_admit(db);
            return Ok(Admitted { id, fresh: false });
        }
        if registry.held.contains_key(&id) {
            return Err(storage(ConnectionLifecycleError::WriterHeld));
        }
        proof::after_stat(db);
        let placed = place_writer(&mut registry, db, id);
        proof::writer_point(WriterPoint::AfterPlace, &registry);
        drop(registry);
        placed.map_err(storage)?;
        Ok(Admitted { id, fresh: true })
    }

    /// (g)-(h): the path must still name the admitted inode before the
    /// first settings statement; a failure drops the connection.
    fn settle_admitted(conn: Connection, db: &Path, id: FileId) -> Result<Connection> {
        use std::os::unix::fs::MetadataExt as _;
        proof::install(&conn);
        if proof::settle_fault() {
            return Err(storage(ConnectionLifecycleError::FileCheck {
                file: "db",
                source: std::io::Error::other("injected settle fault"),
            }));
        }
        let stat =
            std::fs::symlink_metadata(db).map_err(|source| writer_file_check("db", source))?;
        if stat.nlink() != 1 {
            return Err(storage(ConnectionLifecycleError::DatabaseAliased));
        }
        if (stat.dev(), stat.ino()) != id {
            return Err(storage(ConnectionLifecycleError::DatabaseMoved));
        }
        conn.set_prepared_statement_cache_capacity(16);
        conn.busy_timeout(std::time::Duration::from_millis(5000))
            .map_err(storage)?;
        Self::connect_settings(&conn)?;
        Self::readback_file_modes(db)?;
        Ok(conn)
    }

    /// (1a/1e) the pre-open guard and the post-settings mode readback:
    /// `<db>` is created `0600` with `create_new` (no symlink follows),
    /// and any existing db/-wal/-shm must be a regular file narrowed to
    /// `0600` with an unchanged `(dev, ino)`.
    fn guard_database_file(db: &Path, wal: &Path, shm: &Path, registry: &Registry) -> Result<()> {
        let file_check = |file: &'static str, source: std::io::Error| {
            storage(ConnectionLifecycleError::FileCheck { file, source })
        };
        #[cfg(unix)]
        let create_private = || {
            use std::os::unix::fs::OpenOptionsExt as _;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(db)
        };
        #[cfg(not(unix))]
        let create_private = || {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(db)
        };
        match create_private() {
            Ok(handle) => {
                proof::creation_fd_opened();
                proof::writer_point(WriterPoint::CreationOpen, registry);
                drop(handle);
                proof::writer_point(WriterPoint::CreationDrop, registry);
            }
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                Self::narrow_existing("db", db)?;
            }
            Err(source) => return Err(file_check("db", source)),
        }
        for (file, path) in [("wal", wal), ("shm", shm)] {
            match std::fs::symlink_metadata(path) {
                Ok(_) => Self::narrow_existing(file, path)?,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => return Err(file_check(file, source)),
            }
        }
        Ok(())
    }

    /// Narrows one existing database file to a private regular file:
    /// symlink/dir/fifo refuse, a wider mode is chmodded to `0600` and
    /// read back with the same `(dev, ino)`.
    #[cfg(unix)]
    fn narrow_existing(file: &'static str, path: &Path) -> Result<()> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt as _};
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|source| storage(ConnectionLifecycleError::FileCheck { file, source }))?;
        if !metadata.is_file() {
            return Err(storage(ConnectionLifecycleError::FileMode { file }));
        }
        if metadata.permissions().mode() & 0o777 != 0o600 {
            let (dev, ino) = (metadata.dev(), metadata.ino());
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|source| storage(ConnectionLifecycleError::FileCheck { file, source }))?;
            let readback = std::fs::symlink_metadata(path)
                .map_err(|source| storage(ConnectionLifecycleError::FileCheck { file, source }))?;
            if !readback.is_file()
                || readback.permissions().mode() & 0o777 != 0o600
                || readback.dev() != dev
                || readback.ino() != ino
            {
                return Err(storage(ConnectionLifecycleError::FileMode { file }));
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn narrow_existing(file: &'static str, path: &Path) -> Result<()> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() => Ok(()),
            Ok(_) => Err(storage(ConnectionLifecycleError::FileMode { file })),
            Err(source) => Err(storage(ConnectionLifecycleError::FileCheck {
                file,
                source,
            })),
        }
    }

    fn readback_file_modes(db: &Path) -> Result<()> {
        for (file, path) in [("db", db.to_path_buf()), ("wal", sidecar_path(db, "wal"))] {
            match std::fs::symlink_metadata(&path) {
                Ok(_) => Self::narrow_existing(file, &path)?,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(storage(ConnectionLifecycleError::FileCheck {
                        file,
                        source,
                    }));
                }
            }
        }
        Ok(())
    }

    /// (1d) the enumerated settings statements in the contract order,
    /// every value read back.
    fn connect_settings(conn: &Connection) -> Result<()> {
        if proof::settings_fault() {
            return Err(storage(ConnectionLifecycleError::SettingMismatch {
                pragma: "journal_mode",
            }));
        }
        let wal: String = conn
            .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
            .map_err(storage)?;
        if wal != "wal" {
            return Err(storage(ConnectionLifecycleError::SettingMismatch {
                pragma: "journal_mode",
            }));
        }
        let setting = |pragma: &'static str, value: &str| -> Result<()> {
            conn.pragma_update(None, pragma, value).map_err(storage)?;
            let readback: i64 = conn
                .pragma_query_value(None, pragma, |row| row.get(0))
                .map_err(storage)?;
            if readback.to_string() != value {
                return Err(storage(ConnectionLifecycleError::SettingMismatch {
                    pragma,
                }));
            }
            Ok(())
        };
        setting("synchronous", "2")?;
        setting("foreign_keys", "1")?;
        let busy: i64 = conn
            .query_row(sql::BUSY_TIMEOUT_READ, [], |row| row.get(0))
            .map_err(storage)?;
        if busy != 5000 {
            return Err(storage(ConnectionLifecycleError::SettingMismatch {
                pragma: "busy_timeout",
            }));
        }
        setting("temp_store", "2")?;
        setting("cache_size", "-2000")?;
        setting("secure_delete", "1")?;
        setting("journal_size_limit", "16777216")?;
        #[cfg(target_pointer_width = "64")]
        setting("mmap_size", "268435456")?;
        Ok(())
    }

    /// (3) the bootstrap split of the former `TaskStore::open`: the same
    /// statements, order and error mapping, run once per open/reopen and
    /// never before a carried write.
    ///
    /// The schema ledger (DEC-008) is read before any generation's DDL: a
    /// store a newer build wrote is refused typed before any DDL runs, and
    /// the generation this build introduces runs its idempotent batch in one
    /// immediate transaction. The batch runs whether or not the ledger already
    /// reports this generation, because the ledger records that the batch ran,
    /// not that its schema is present: a store whose table was dropped — a
    /// rollback that removed the generation-2 tables, or a later slice
    /// appending DDL to the same batch — is repaired on the next open instead
    /// of failing later as an untagged storage error.
    fn bootstrap(&mut self) -> Result<()> {
        if proof::bootstrap_fault() {
            return Err(storage(ConnectionLifecycleError::SettingMismatch {
                pragma: "schema",
            }));
        }
        let conn = self.conn_mut()?;
        require_known_generation(learning::schema_generation_on(conn)?)?;
        conn.execute_batch(sql::SCHEMA).map_err(storage)?;
        conn.execute_batch(sql::DECISIONS_SCHEMA).map_err(storage)?;
        conn.execute_batch(sql::PLANS_SCHEMA).map_err(storage)?;
        conn.execute_batch(sql::INDEX_SCHEMA).map_err(storage)?;
        conn.execute_batch(sql::ASSUMPTIONS_SCHEMA)
            .map_err(storage)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        // The ledger is read again inside the write transaction (INV-010a): a
        // store that advanced past this build between the read above and this
        // batch is refused typed instead of being rewound by the ledger write
        // below.
        let current = learning::schema_generation_on(&tx)?;
        require_known_generation(current)?;
        tx.execute_batch(sql::LEARNING_SCHEMA).map_err(storage)?;
        if current < learning::KNOWN_SCHEMA_GENERATION {
            tx.execute_batch(&sql::set_schema_generation(
                learning::KNOWN_SCHEMA_GENERATION,
            ))
            .map_err(storage)?;
        }
        tx.commit().map_err(storage)?;
        migrate_supervisor_reactions(conn)
    }

    /// DEC-048 «Reopen и quarantine»: closes the old connection
    /// explicitly (never open-before-close), connects through the shared
    /// §9 init, then — only with a held record — makes exactly one
    /// carried write the first store operation, before the bootstrap
    /// and any other store use. A bootstrap error after any carried
    /// outcome is partial initialization: the same record is held again
    /// and the slot stays empty.
    pub(crate) fn reopen(&mut self, path: &Path) -> Result<()> {
        // The database identity gate (DEC-054): a reopen naming a
        // different database than the one this store is bound to refuses
        // BEFORE the old connection closes — the holder, the open
        // connection, and the presented database B all stay unchanged,
        // and a held record never travels into another initialized
        // database.
        let presented = Self::canonical_db_path(path)?;
        if presented != self.bound_db {
            return Err(StoreError::ReopenIdentity {
                bound: self.bound_db.clone(),
                presented,
            });
        }
        if let Some(old) = self.conn.take() {
            if let Err(error) = proof::fault(proof::Site::Close) {
                // The handle never returns to the slot; its Drop closes
                // the real connection and releases the writer lock.
                drop(old);
                return Err(storage(error));
            }
            if let Err((handle, error)) = old.close() {
                drop(handle);
                return Err(storage(error));
            }
        }
        if let Err(error) = proof::fault(proof::Site::Open) {
            // The injected open failure: the connect is never attempted;
            // the slot stays empty and the record stays held.
            return Err(storage(error));
        }
        let (conn, writer) = Self::connect(path, Some(self.writer))?;
        if writer != self.writer {
            retire_writer(self.writer);
            self.writer = writer;
        }
        self.conn = Some(conn);
        let held = self.held_claim_commit.take();
        let carried = match held.as_ref() {
            Some(record) => {
                if let Err(error) = proof::fault(proof::Site::CarriedWrite) {
                    Err(storage(error))
                } else {
                    record.retain(self)
                }
            }
            None => Ok(()),
        };
        match (carried, self.bootstrap()) {
            (_, Err(error)) => {
                // Partial initialization: the slot empties before the
                // return and the same held object moves back — never a
                // rebuild, never a release.
                self.conn = None;
                if let Some(record) = held {
                    self.held_claim_commit = Some(record);
                }
                Err(error)
            }
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
        }
    }

    /// DEC-051 close: the healthy path runs `PRAGMA optimize` then the
    /// truncating checkpoint and one explicit close; any other state —
    /// an empty slot, a held record, or an open transaction — emits no
    /// SQL statement at all. The first error propagates typed with the
    /// slot already taken; a repeated close is `Ok` without SQL. An
    /// explicit quarantined or empty-slot close ENDS the holder
    /// (test-plan (g), DEC-050 residual R): the record is never written,
    /// and only the internal recovery close inside `reopen` preserves a
    /// held record for its first-write carry.
    pub(crate) fn close(&mut self) -> Result<()> {
        let healthy =
            !self.is_quarantined() && self.conn.as_ref().is_some_and(Connection::is_autocommit);
        if !healthy {
            // An explicit quarantined or empty-slot close ends the holder
            // (test-plan (g), DEC-051/DEC-050 residual R): the record was
            // never durably carried, no SQL may run to change that, and
            // only a restart can build a fresh holder. The internal
            // recovery close inside `reopen` is the one close that
            // preserves the holder — this explicit path never does.
            self.held_claim_commit = None;
            if let Some(old) = self.conn.take() {
                if let Err(error) = proof::fault(proof::Site::CloseExplicit) {
                    drop(old);
                    return Err(storage(error));
                }
                if let Err((handle, error)) = old.close() {
                    drop(handle);
                    return Err(storage(error));
                }
            }
            return Ok(());
        }
        let first_error = (|| -> Result<()> {
            if let Err(error) = proof::fault(proof::Site::CloseOptimize) {
                return Err(storage(error));
            }
            self.conn_mut()?
                .execute_batch(sql::OPTIMIZE)
                .map_err(storage)?;
            if let Err(error) = proof::fault(proof::Site::CloseCheckpoint) {
                return Err(storage(error));
            }
            let (busy, _log, _checkpointed): (i64, i64, i64) = self
                .conn_mut()?
                .query_row(sql::WAL_CHECKPOINT_TRUNCATE, [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .map_err(storage)?;
            if busy != 0 {
                return Err(storage(ConnectionLifecycleError::CheckpointIncomplete));
            }
            Ok(())
        })();
        // The slot is taken before the explicit close on every exit
        // path; a later fault or close error never outranks the first.
        if let Some(old) = self.conn.take() {
            if first_error.is_ok()
                && let Err(error) = proof::fault(proof::Site::CloseExplicit)
            {
                drop(old);
                return Err(storage(error));
            }
            if let Err((handle, error)) = old.close() {
                drop(handle);
                if first_error.is_ok() {
                    return Err(storage(error));
                }
            }
        }
        first_error
    }

    /// The DEC-048 first-only dispatch claim: one short `Immediate`
    /// transaction under a scoped zero wait, the binding read
    /// transaction-consistently, the conditional planned→running
    /// transition, the first-only marker, and the restoration of the
    /// actual prior timeout before COMMIT. Every refusal carries its
    /// own site; an ambiguous COMMIT builds its record once and either
    /// writes it on this connection (only when the transaction ended)
    /// or moves it into the private holder — never more than one
    /// record exists per store.
    pub(crate) fn claim_check(
        &mut self,
        claim: &CheckClaim,
        cancel: &std::sync::atomic::AtomicBool,
        deadline: std::time::Instant,
    ) -> Result<ClaimOutcome> {
        // #1 the actual prior timeout, as a typed row. A read failure
        // or an out-of-range value leaves the timeout untouched.
        let prior_ms: i64 = {
            let conn = self.conn_mut()?;
            if proof::fault(proof::Site::WaitRead).is_err() {
                return Ok(ClaimOutcome::Refused(ClaimRefusal {
                    site: ClaimSite::WaitRead,
                    retention: RetentionOutcome::Unavailable,
                    restore_failed: false,
                }));
            }
            match conn.query_row(sql::BUSY_TIMEOUT_READ, [], |row| row.get(0)) {
                Ok(value) => value,
                Err(_) => {
                    return Ok(ClaimOutcome::Refused(ClaimRefusal {
                        site: ClaimSite::WaitRead,
                        retention: RetentionOutcome::Unavailable,
                        restore_failed: false,
                    }));
                }
            }
        };
        let Ok(prior) = u64::try_from(prior_ms) else {
            return Ok(ClaimOutcome::Refused(ClaimRefusal {
                site: ClaimSite::WaitRead,
                retention: RetentionOutcome::Unavailable,
                restore_failed: false,
            }));
        };
        if prior > i32::MAX as u64 {
            return Ok(ClaimOutcome::Refused(ClaimRefusal {
                site: ClaimSite::WaitRead,
                retention: RetentionOutcome::Unavailable,
                restore_failed: false,
            }));
        }
        let prior = std::time::Duration::from_millis(prior);
        // #2 the zero wait itself; a failure restores the read value
        // before refusing, and a restoration that itself fails proves
        // the handle unusable: the slot empties so no later SQL runs on
        // it before a reopen (DEC-054). The setter is in-memory: no
        // SQL, no lock.
        if proof::fault(proof::Site::WaitSet).is_err() {
            let restore_failed = self.restore_or_quarantine(prior);
            return Ok(ClaimOutcome::Refused(ClaimRefusal {
                site: ClaimSite::WaitSet,
                retention: RetentionOutcome::Unavailable,
                restore_failed,
            }));
        }
        if self
            .conn_mut()?
            .busy_timeout(std::time::Duration::ZERO)
            .is_err()
        {
            let restore_failed = self.restore_or_quarantine(prior);
            return Ok(ClaimOutcome::Refused(ClaimRefusal {
                site: ClaimSite::WaitSet,
                retention: RetentionOutcome::Unavailable,
                restore_failed,
            }));
        }
        match self.claim_transaction(claim, cancel, deadline, prior)? {
            ClaimTxOutcome::Claimed => Ok(ClaimOutcome::Claimed),
            ClaimTxOutcome::Refused(refusal) => {
                // A restoration that failed inside the transaction body
                // (#11) leaves the handle unusable: the slot empties so
                // no later SQL runs on it before a reopen (DEC-054). No
                // held COMMIT is synthesized — the claim never reached
                // its COMMIT.
                if refusal.restore_failed && matches!(refusal.site, ClaimSite::WaitRestore) {
                    self.conn = None;
                }
                Ok(ClaimOutcome::Refused(refusal))
            }
            ClaimTxOutcome::CommitReported { primary } => {
                // Every transaction borrow has ended: observe whether a
                // transaction is still open on this connection — an
                // observation, never a rollback proof — then build the
                // record exactly once, at this site.
                let ended = self.conn().is_ok_and(Connection::is_autocommit);
                let record = Self::commit_ambiguous_record(claim, &primary, ended);
                let held = held::HeldClaimCommit::new(record);
                let retention = if ended
                    && proof::fault(proof::Site::SameConnectionWrite).is_ok()
                    && held.retain(self).is_ok()
                {
                    RetentionOutcome::Retained
                } else {
                    self.held_claim_commit = Some(held);
                    RetentionOutcome::Unavailable
                };
                Ok(ClaimOutcome::Refused(ClaimRefusal {
                    site: ClaimSite::Commit,
                    retention,
                    restore_failed: false,
                }))
            }
        }
    }

    /// Restores the scoped timeout after a refusal, reporting whether
    /// the restoration itself failed; a failed restoration empties the
    /// slot — the handle is unusable, and no later SQL may run on it
    /// before a reopen (DEC-054). The holder is untouched.
    fn restore_or_quarantine(&mut self, prior: std::time::Duration) -> bool {
        match self.conn.as_mut().map(|conn| conn.busy_timeout(prior)) {
            Some(Ok(())) => false,
            Some(Err(_)) | None => {
                self.conn = None;
                true
            }
        }
    }

    /// The zero-wait transaction body of one claim (#3–#12). The
    /// pre-BEGIN refusals run on the store's connection; the open
    /// transaction is consumed by [`Self::claim_in_transaction`], whose
    /// refusals drop it (rollback) and return their site so this caller
    /// — with the borrow released — writes the one zero-wait denial row
    /// and restores the prior timeout.
    fn claim_transaction(
        &mut self,
        claim: &CheckClaim,
        cancel: &std::sync::atomic::AtomicBool,
        deadline: std::time::Instant,
        prior: std::time::Duration,
    ) -> Result<ClaimTxOutcome> {
        if let Some(site) = claim_checkpoint(cancel, deadline) {
            return Ok(self.refuse_claim(claim, site, prior));
        }
        // #4/#5 BEGIN IMMEDIATE, busy classified apart from other
        // begin failures.
        if proof::fault(proof::Site::Busy).is_err() {
            return Ok(self.refuse_claim(claim, ClaimSite::Busy, prior));
        }
        if proof::fault(proof::Site::Begin).is_err() {
            return Ok(self.refuse_claim(claim, ClaimSite::Begin, prior));
        }
        let outcome = {
            let conn = self.conn_mut()?;
            match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
                Ok(tx) => Self::claim_in_transaction(tx, claim, cancel, deadline, prior),
                Err(error) => {
                    InTxn::Refused(Self::begin_site(&error), sqlite_primary_numeric(&error))
                }
            }
        };
        match outcome {
            InTxn::Complete(done) => Ok(done),
            InTxn::Refused(site, primary) => {
                Ok(self.refuse_claim_with(claim, site, prior, primary))
            }
        }
    }

    /// One post-BEGIN refusal tail without an engine code.
    fn refuse_claim(
        &mut self,
        claim: &CheckClaim,
        site: ClaimSite,
        prior: std::time::Duration,
    ) -> ClaimTxOutcome {
        self.refuse_claim_with(claim, site, prior, None)
    }

    /// One post-BEGIN refusal tail: the zero-wait denial row, then the
    /// scoped restoration — quarantining the handle when the
    /// restoration itself fails (DEC-054). Runs only after the
    /// transaction has been dropped — its rollback is the first step of
    /// the refusal. An engine-reported statement error carries its
    /// numeric primary result code into the row.
    fn refuse_claim_with(
        &mut self,
        claim: &CheckClaim,
        site: ClaimSite,
        prior: std::time::Duration,
        primary: Option<i32>,
    ) -> ClaimTxOutcome {
        let retention = self
            .conn()
            .map(|conn| Self::retain_rejection(conn, claim, site, primary))
            .unwrap_or(RetentionOutcome::Unavailable);
        let restore_failed = self.restore_or_quarantine(prior);
        ClaimTxOutcome::Refused(ClaimRefusal {
            site,
            retention,
            restore_failed,
        })
    }

    /// The busy/locked classification of a failed BEGIN; every other
    /// failure is a plain begin refusal.
    fn begin_site(error: &rusqlite::Error) -> ClaimSite {
        match error {
            rusqlite::Error::SqliteFailure(code, _)
                if matches!(
                    code.code,
                    rusqlite::ffi::ErrorCode::DatabaseBusy
                        | rusqlite::ffi::ErrorCode::DatabaseLocked
                ) =>
            {
                ClaimSite::Busy
            }
            _ => ClaimSite::Begin,
        }
    }

    /// The statements of one open claim transaction (#3–#10 inside,
    /// #11/#12 at the tail). A refusal drops the transaction — the
    /// rollback — and returns its site; the denial row and the
    /// restoration belong to the caller, which owns the connection
    /// again once this call returns.
    fn claim_in_transaction(
        mut tx: rusqlite::Transaction<'_>,
        claim: &CheckClaim,
        cancel: &std::sync::atomic::AtomicBool,
        deadline: std::time::Instant,
        prior: std::time::Duration,
    ) -> InTxn {
        macro_rules! refuse_tx {
            ($site:expr) => {
                return InTxn::Refused($site, None)
            };
            ($site:expr, $primary:expr) => {
                return InTxn::Refused($site, $primary)
            };
        }
        if let Some(site) = claim_checkpoint(cancel, deadline) {
            refuse_tx!(site);
        }
        // #6a the binding read: one statement, five facts.
        if proof::fault(proof::Site::Read).is_err() {
            refuse_tx!(ClaimSite::Read);
        }
        let marker_boundary = check_boundary(&claim.attempt_id, "admit.claim");
        let row: Option<(String, String, String, String, bool)> = match tx
            .query_row(
                sql::CLAIM_ATTEMPT_READ,
                params![&claim.attempt_id, &marker_boundary],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
        {
            Ok(row) => row,
            Err(error) => refuse_tx!(ClaimSite::Read, sqlite_primary_numeric(&error)),
        };
        let Some((task_id, effect_class, state, lifecycle, marker)) = row else {
            refuse_tx!(ClaimSite::Attempt);
        };
        if task_id != claim.task_id.0 || effect_class != "exec" {
            refuse_tx!(ClaimSite::Attempt);
        }
        if marker {
            refuse_tx!(ClaimSite::Replay);
        }
        if lifecycle == "completed" || lifecycle == "cancelled" {
            refuse_tx!(ClaimSite::Lifecycle);
        }
        if state != "planned" {
            refuse_tx!(ClaimSite::Replay);
        }
        // #6b the durable claim-commit row of a prior ambiguous COMMIT
        // refuses as a replay even when the marker never landed.
        if let Some(site) = claim_checkpoint(cancel, deadline) {
            refuse_tx!(site);
        }
        if proof::fault(proof::Site::TerminalRead).is_err() {
            refuse_tx!(ClaimSite::TerminalRead);
        }
        let commit_row_present: bool = match tx.query_row(
            sql::EXISTS_RETAINED,
            params![check_boundary(&claim.attempt_id, "admit.claim_commit")],
            |row| row.get(0),
        ) {
            Ok(present) => present,
            Err(error) => refuse_tx!(ClaimSite::TerminalRead, sqlite_primary_numeric(&error)),
        };
        if commit_row_present {
            refuse_tx!(ClaimSite::Replay);
        }
        // #7/#8 the Native selection context and the shared Open-gate
        // semantics, in transaction — a Custom-off claim runs neither
        // statement: its variant is the explicit flag, never sentinel
        // field values (DEC-048 item 4).
        if claim.native {
            if let Some(site) = claim_checkpoint(cancel, deadline) {
                refuse_tx!(site);
            }
            if proof::fault(proof::Site::SelectionRead).is_err() {
                refuse_tx!(ClaimSite::SelectionRead);
            }
            match Self::plan_selection_on(&tx, &claim.task_id) {
                Ok(Some(record))
                    if record.revision == claim.selection_revision
                        && record.facts_digest == claim.facts_digest
                        && record.request_kind == claim.request_kind => {}
                Ok(_) => refuse_tx!(ClaimSite::Selection),
                Err(error) => refuse_tx!(ClaimSite::SelectionRead, store_primary_numeric(&error)),
            }
            // #8 the shared Open-gate semantics, in transaction.
            if proof::fault(proof::Site::GateRead).is_err() {
                refuse_tx!(ClaimSite::GateRead);
            }
            match Self::gate_on(&tx, &claim.task_id) {
                Ok(PlanGate::Open) => {}
                Ok(_) => refuse_tx!(ClaimSite::Gate),
                Err(error) => refuse_tx!(ClaimSite::GateRead, store_primary_numeric(&error)),
            }
        }
        // #9 the conditional planned→running transition.
        if let Some(site) = claim_checkpoint(cancel, deadline) {
            refuse_tx!(site);
        }
        if proof::fault(proof::Site::Update).is_err() {
            refuse_tx!(ClaimSite::Update);
        }
        match tx.execute(
            sql::CLAIM_ATTEMPT_RUNNING,
            params![&claim.attempt_id, &claim.task_id.0],
        ) {
            Ok(changed) if changed > 0 => {}
            Ok(_) => refuse_tx!(ClaimSite::Update),
            Err(error) => refuse_tx!(ClaimSite::Update, sqlite_primary_numeric(&error)),
        }
        // #10 the first-only marker; an existing marker already refused
        // at #6a, so an identical Ok here cannot mint a second claim.
        if let Some(site) = claim_checkpoint(cancel, deadline) {
            refuse_tx!(site);
        }
        if proof::fault(proof::Site::Marker).is_err() {
            refuse_tx!(ClaimSite::Marker);
        }
        let marker_record = json!({
            "site": "admit.claim",
            "attempt": claim.attempt_id,
            "binding": claim.binding_digest,
        })
        .to_string();
        if let Err(error) = Self::retain_once(&tx, &marker_record, &marker_boundary) {
            refuse_tx!(ClaimSite::Marker, store_primary_numeric(&error));
        }
        // #3 the last stop check, then #11 the scoped restoration — a
        // failure here never executes the COMMIT and leaves no row.
        if let Some(site) = claim_checkpoint(cancel, deadline) {
            refuse_tx!(site);
        }
        if proof::fault(proof::Site::WaitRestore).is_err() {
            drop(tx.busy_timeout(prior));
            return InTxn::Complete(ClaimTxOutcome::Refused(ClaimRefusal {
                site: ClaimSite::WaitRestore,
                retention: RetentionOutcome::Unavailable,
                restore_failed: true,
            }));
        }
        if tx.busy_timeout(prior).is_err() {
            return InTxn::Complete(ClaimTxOutcome::Refused(ClaimRefusal {
                site: ClaimSite::WaitRestore,
                retention: RetentionOutcome::Unavailable,
                restore_failed: true,
            }));
        }
        // #12 COMMIT under the restored timeout. `commit` consumes the
        // transaction; its own Drop rollback result confirms nothing.
        if proof::fault(proof::Site::CommitBeforeExec).is_err() {
            // The rollback control may leave the failed transaction
            // open: the forced `transaction_ended = false` leg.
            if proof::fault(proof::Site::RollbackAfterCommitError).is_err() {
                tx.set_drop_behavior(DropBehavior::Ignore);
            }
            drop(tx);
            return InTxn::Complete(ClaimTxOutcome::CommitReported {
                primary: "injected".to_string(),
            });
        }
        match tx.commit() {
            Ok(()) => {
                if proof::fault(proof::Site::CommitAfterDurable).is_err() {
                    return InTxn::Complete(ClaimTxOutcome::CommitReported {
                        primary: "injected".to_string(),
                    });
                }
                InTxn::Complete(ClaimTxOutcome::Claimed)
            }
            Err(error) => InTxn::Complete(ClaimTxOutcome::CommitReported {
                primary: sqlite_primary_code(&error),
            }),
        }
    }

    /// The one zero-wait denial row attempt: unique rejection identity,
    /// bounded non-secret payload, no retry.
    fn retain_rejection(
        conn: &Connection,
        claim: &CheckClaim,
        site: ClaimSite,
        primary: Option<i32>,
    ) -> RetentionOutcome {
        let boundary = format!(
            "ret:check-rejection:{}:{}",
            rejection_identity(),
            site.suffix()
        );
        let mut record = json!({
            "site": site.suffix(),
            "cause": "claim refused",
            "binding": claim.binding_digest,
        });
        if let Some(code) = primary {
            record["primary"] = json!(code.to_string());
        }
        match Self::retain_once(conn, &record.to_string(), &boundary) {
            Ok(()) => RetentionOutcome::Retained,
            Err(_) => RetentionOutcome::Unavailable,
        }
    }

    /// The executor-side pre-claim denial row (DEC-048 item 6): one
    /// server-invocation-scoped non-authoritative record of a refused
    /// presentation — UUID rejection identity, bounded fixed cause and
    /// binding digest, no roots, grant ids, diagnostics, or forged
    /// admitted-attempt relation. The one write runs under a scoped
    /// ZERO busy timeout: the actual prior value is read, zeroed for
    /// the single write, and restored afterwards — a restoration that
    /// itself fails quarantines the handle exactly like the claim's
    /// restoration. No retry exists, and a retention failure has no
    /// effect and never creates a terminal row; the typed refusal
    /// stands alone.
    pub(crate) fn retain_preclaim_rejection(
        &mut self,
        site: &str,
        binding_digest: &str,
    ) -> RetentionOutcome {
        let prior_ms: i64 = match self.conn().and_then(|conn| {
            conn.query_row(sql::BUSY_TIMEOUT_READ, [], |row| row.get(0))
                .map_err(storage)
        }) {
            Ok(value) => value,
            Err(_) => return RetentionOutcome::Unavailable,
        };
        let Ok(prior) = u64::try_from(prior_ms) else {
            return RetentionOutcome::Unavailable;
        };
        if prior > i32::MAX as u64 {
            return RetentionOutcome::Unavailable;
        }
        let prior = std::time::Duration::from_millis(prior);
        let zeroed = self.conn_mut().and_then(|conn| {
            conn.busy_timeout(std::time::Duration::ZERO)
                .map_err(storage)
        });
        if zeroed.is_err() {
            self.restore_or_quarantine(prior);
            return RetentionOutcome::Unavailable;
        }
        let boundary = format!("ret:check-rejection:{}:{site}", rejection_identity());
        let record = json!({
            "site": site,
            "cause": "pre-claim refusal",
            "binding": binding_digest,
        })
        .to_string();
        let written = self
            .conn()
            .map(|conn| Self::retain_once(conn, &record, &boundary).is_ok());
        // A failed restoration quarantines the slot exactly like the
        // claim path's own restoration failure; the proof seam injects
        // that failure without breaking the live handle by hand. The
        // row's own fate is independent of the restoration.
        if proof::fault(proof::Site::RejectionRestore).is_err() {
            self.conn = None;
        } else {
            self.restore_or_quarantine(prior);
        }
        match written {
            Ok(true) => RetentionOutcome::Retained,
            _ => RetentionOutcome::Unavailable,
        }
    }

    /// The ambiguous-COMMIT record, built once from the caller's
    /// `transaction_ended` observation (an observation, never a
    /// rollback proof).
    fn commit_ambiguous_record(claim: &CheckClaim, primary: &str, ended: bool) -> RetainedAttempt {
        let cause = format!(
            "admit.claim_commit: transaction_ended={ended} binding={} primary={primary}",
            claim.binding_digest
        );
        RetainedAttempt {
            attempt_id: claim.attempt_id.clone(),
            boundary_id: check_boundary(&claim.attempt_id, "admit.claim_commit"),
            stage: crate::verification::RetainedStage::Terminal,
            digest: crate::verification::record_digest(&claim.attempt_id, &cause),
            cause,
            build_attempt: claim.attempt_id.clone(),
            admitted_attempt_id: Some(claim.attempt_id.clone()),
        }
    }

    pub fn recover_events(&mut self, session_id: &SessionId, events: &[Event]) -> Result<()> {
        let tx = self.conn_mut()?.transaction().map_err(storage)?;
        let mut applied = BTreeSet::new();
        for event in events {
            if event.session_id != *session_id {
                return Err(StoreError::Conflict(ConflictCause::EventSessionMismatch {
                    event_id: event.event_id.0.clone(),
                }));
            }
            let canonical = tx
                .query_row(
                    sql::EVENT_BY_AGGREGATE_REVISION,
                    params![event.aggregate_id, event.aggregate_revision as i64],
                    event_from_row,
                )
                .optional()
                .map_err(storage)?
                .ok_or_else(|| {
                    StoreError::Conflict(ConflictCause::EventNotFound {
                        event_id: event.event_id.0.clone(),
                    })
                })?;
            if canonical != *event {
                return Err(StoreError::Conflict(ConflictCause::EventConflict {
                    event_id: event.event_id.0.clone(),
                }));
            }
            if !applied.insert((event.aggregate_id.clone(), event.aggregate_revision)) {
                continue;
            }
            if let Some(task_id) = &event.task_id {
                tx.execute(sql::REPLAY_TODO_PROJECTION, params![task_id.0])
                    .map_err(storage)?;
            }
        }
        tx.commit().map_err(storage)
    }

    // ----- sessions -----

    pub fn open_session(
        &mut self,
        bootstrap_id: &str,
        connection_id: &str,
        attach_to: Option<&SessionId>,
    ) -> Result<(SessionId, AttachmentId, u64, bool)> {
        let params_digest = format!(
            "{bootstrap_id}|{connection_id}|attach={}",
            attach_to.is_some()
        );
        let key = format!("{connection_id}|{bootstrap_id}");
        let replay = self
            .conn()?
            .query_row(sql::BOOTSTRAP_RECEIPT_BY_KEY, params![key], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .map_err(storage)?;
        if let Some(result_json) = replay {
            let value: Value = serde_json::from_str(&result_json).map_err(storage)?;
            let session_id =
                SessionId(value["session_id"].as_str().unwrap_or_default().to_string());
            let attachment_id = AttachmentId(
                value["attachment_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            );
            let generation = value["owner_generation"].as_u64().unwrap_or(1);
            return Ok((session_id, attachment_id, generation, true));
        }
        let session_id = match attach_to {
            Some(id) => {
                let exists: bool = self
                    .conn()?
                    .query_row(sql::SESSION_EXISTS, params![id.0], |row| row.get(0))
                    .map_err(storage)?;
                if !exists {
                    return Err(StoreError::missing_session(&id.0));
                }
                id.clone()
            }
            None => SessionId::generate(),
        };
        let attachment_id = AttachmentId::generate();
        self.conn()?
            .execute(
                sql::INSERT_ATTACHMENT,
                params![
                    attachment_id.0,
                    session_id.0,
                    connection_id,
                    bootstrap_id,
                    params_digest
                ],
            )
            .map_err(storage)?;
        let revision: u64 = self
            .conn()?
            .query_row(sql::NEXT_SESSION_REVISION, params![session_id.0], |row| {
                row.get::<_, i64>(0).map(|v| v as u64)
            })
            .map_err(storage)?;
        if attach_to.is_none() {
            self.conn()?
                .execute(sql::INSERT_SESSION, params![session_id.0, revision as i64])
                .map_err(storage)?;
        } else {
            self.conn()?
                .execute(
                    sql::UPDATE_SESSION_REVISION,
                    params![session_id.0, revision as i64],
                )
                .map_err(storage)?;
        }
        let result_json = serde_json::to_string(&json!({
            "session_id": session_id.0,
            "attachment_id": attachment_id.0,
            "owner_generation": 1u64,
        }))
        .map_err(storage)?;
        self.conn()?
            .execute(
                sql::INSERT_BOOTSTRAP_RECEIPT,
                params![key, attachment_id.0, result_json],
            )
            .map_err(storage)?;
        Ok((session_id, attachment_id, 1, false))
    }

    // ----- events -----

    fn next_cursor(tx: &rusqlite::Transaction<'_>) -> Result<u64> {
        let cursor: u64 = tx
            .query_row(sql::NEXT_EVENT_CURSOR, [], |row| {
                row.get::<_, i64>(0).map(|v| v as u64)
            })
            .map_err(storage)?;
        Ok(cursor)
    }

    fn append_event(
        tx: &rusqlite::Transaction<'_>,
        session_id: &SessionId,
        task_id: Option<&TaskId>,
        aggregate: (&str, u64),
        event_type: &str,
        delta: Value,
        origin: &str,
    ) -> Result<Event> {
        let (aggregate_id, aggregate_revision) = aggregate;
        let cursor = Self::next_cursor(tx)?;
        let event = Event {
            schema_version: 1,
            event_id: EventId::generate(),
            aggregate_id: aggregate_id.to_string(),
            aggregate_revision,
            cursor,
            session_id: session_id.clone(),
            task_id: task_id.cloned(),
            event_type: event_type.to_string(),
            delta,
            origin: origin.to_string(),
        };
        tx.execute(
            sql::INSERT_EVENT,
            params![
                event.event_id.0,
                event.aggregate_id,
                event.aggregate_revision as i64,
                event.cursor as i64,
                event.session_id.0,
                event.task_id.as_ref().map(|id| id.0.clone()),
                event.event_type,
                serde_json::to_string(&event.delta).map_err(storage)?,
                event.origin
            ],
        )
        .map_err(storage)?;
        Ok(event)
    }

    /// Kills the pending rows whose intent pin `live_intent` no longer
    /// matches — superseded rows stay for audit — and journals one
    /// `question.superseded` event per killed row in the same
    /// transaction, so an `events.read` replay watches the row die
    /// instead of reading it pending forever. The event's aggregate is
    /// the question itself at its own revision: a row is superseded at
    /// most once, so (question_id, revision) never collides with the
    /// task's own aggregate stream, while the `task_id` column keeps the
    /// death inside the task's replay feed.
    fn supersede_pending_questions(
        tx: &rusqlite::Transaction<'_>,
        session_id: &SessionId,
        task_id: &TaskId,
        live_intent: u64,
        origin: &str,
    ) -> Result<()> {
        let killed: Vec<(String, u64, u64)> = tx
            .prepare_cached(sql::SUPERSEDE_PENDING_QUESTIONS)
            .map_err(storage)?
            .query_map(params![task_id.0, live_intent as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u64,
                ))
            })
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        for (question_id, question_revision, stale_intent) in killed {
            Self::append_event(
                tx,
                session_id,
                Some(task_id),
                (&question_id, question_revision),
                "question.superseded",
                json!({
                    "question_id": question_id,
                    "question_revision": question_revision,
                    "stale_intent_revision": stale_intent,
                    "live_intent_revision": live_intent,
                }),
                origin,
            )?;
        }
        Ok(())
    }

    /// Supersedes pending questions named by the replaced selection's
    /// plan rows and journals each death in the selection transaction.
    fn supersede_plan_questions(
        tx: &rusqlite::Transaction<'_>,
        session_id: &SessionId,
        task_id: &TaskId,
        selection_revision: u64,
        next_selection_revision: u64,
    ) -> Result<()> {
        let mut superseded = false;
        for row in Self::plan_rows_on(tx, task_id)? {
            let Some(Blocker {
                condition:
                    ResumeCondition::Decision {
                        question_id,
                        revision,
                    },
                ..
            }) = row.blocker
            else {
                continue;
            };
            let killed_revision: Option<i64> = tx
                .query_row(
                    sql::SUPERSEDE_PLAN_QUESTION,
                    params![question_id.0, task_id.0, stored_u64(revision)?],
                    |row| row.get(0),
                )
                .optional()
                .map_err(storage)?;
            let Some(killed_revision) = killed_revision else {
                continue;
            };
            let question_revision = unsigned(killed_revision)?;
            Self::append_event(
                tx,
                session_id,
                Some(task_id),
                (&question_id.0, question_revision),
                "question.superseded",
                json!({
                    "question_id": question_id.0,
                    "question_revision": question_revision,
                    "selection_revision": selection_revision,
                    "next_selection_revision": next_selection_revision,
                }),
                "state",
            )?;
            superseded = true;
        }
        if superseded {
            tx.execute(sql::SUPERSESSION_RESUMES_TASK, params![task_id.0])
                .map_err(storage)?;
        }
        Ok(())
    }

    /// Every pending row dies when its task goes terminal: no intent can
    /// publish the fork the row was waiting on, so the kill cause is the
    /// lifecycle, not a stale pin. Callers run it inside the transition's
    /// own transaction — a task row that lands `completed`/`cancelled`
    /// cannot leave a live pending question behind, and a caller that
    /// observes an already-terminal task still heals a pending row left
    /// by a pre-journal write or a foreign writer.
    fn supersede_terminal_questions(
        tx: &rusqlite::Transaction<'_>,
        session_id: &SessionId,
        task_id: &TaskId,
        lifecycle: &str,
        origin: &str,
    ) -> Result<()> {
        let killed: Vec<(String, u64)> = tx
            .prepare_cached(sql::SUPERSEDE_TERMINAL_QUESTIONS)
            .map_err(storage)?
            .query_map(params![task_id.0], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
            })
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        for (question_id, question_revision) in killed {
            Self::append_event(
                tx,
                session_id,
                Some(task_id),
                (&question_id, question_revision),
                "question.superseded",
                json!({
                    "question_id": question_id,
                    "question_revision": question_revision,
                    "lifecycle": lifecycle,
                }),
                origin,
            )?;
        }
        Ok(())
    }

    pub fn events_after(
        &self,
        session_id: &SessionId,
        task_id: Option<&TaskId>,
        after: u64,
        limit: u32,
    ) -> Result<Vec<Event>> {
        let after = i64::try_from(after)
            .map_err(|_conversion| StoreError::InvalidInput(InvalidCause::EventCursorOutOfRange))?;
        let (query, args): (&str, Vec<Box<dyn rusqlite::ToSql>>) = if let Some(id) = task_id {
            (
                sql::EVENTS_AFTER_FOR_TASK,
                vec![
                    Box::new(session_id.0.clone()),
                    Box::new(after),
                    Box::new(id.0.clone()),
                    Box::new(limit as i64),
                ],
            )
        } else {
            (
                sql::EVENTS_AFTER,
                vec![
                    Box::new(session_id.0.clone()),
                    Box::new(after),
                    Box::new(limit as i64),
                ],
            )
        };
        let mut stmt = self.conn()?.prepare(query).map_err(storage)?;
        let rows = stmt
            .query_map(params_from_iter(args.iter()), event_from_row)
            .map_err(storage)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(storage)?);
        }
        Ok(out)
    }

    /// Total rows in the event outbox, across sessions: the emission
    /// observable for paths that must stay silent (recovery-only journal
    /// completion emits no hooks).
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when the count query fails.
    pub fn event_count(&self) -> Result<u64> {
        let count: i64 = self
            .conn()?
            .query_row(sql::EVENT_COUNT, [], |row| row.get(0))
            .map_err(storage)?;
        // COUNT(*) is never negative; the fallback only satisfies the
        // checked-conversion lint on an impossible value.
        Ok(u64::try_from(count).unwrap_or(0))
    }

    // ----- command dedupe -----

    pub fn receipt(&self, command_id: &str) -> Result<Option<(String, String)>> {
        let row = self
            .conn()?
            .query_row(sql::RECEIPT_BY_COMMAND, params![command_id], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()
            .map_err(storage)?;
        Ok(row)
    }

    fn record_receipt(
        tx: &rusqlite::Transaction<'_>,
        command_id: &str,
        session_id: &SessionId,
        principal: &str,
        params_digest: &str,
        result: &CommandResult,
    ) -> Result<()> {
        tx.execute(
            sql::INSERT_RECEIPT,
            params![
                command_id,
                session_id.0,
                principal,
                params_digest,
                serde_json::to_string(result).map_err(storage)?
            ],
        )
        .map_err(storage)?;
        Ok(())
    }

    /// One command receipt for a result produced outside the task-command
    /// transactions — `decisions.control` lands its edit through the
    /// config journal, so the idempotency record commits after the
    /// durable landing, keyed on the same `(command_id → params_digest,
    /// result)` contract `create_task` binds inside its own transaction.
    /// A replay whose digest matches answers the recorded result instead
    /// of re-running the command.
    pub fn record_command_receipt(
        &mut self,
        command_id: &str,
        session_id: &SessionId,
        principal: &str,
        params_digest: &str,
        result_json: &str,
    ) -> Result<()> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        tx.execute(
            sql::INSERT_RECEIPT,
            params![
                command_id,
                session_id.0,
                principal,
                params_digest,
                result_json
            ],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }

    // ----- task lifecycle -----

    pub fn create_task(
        &mut self,
        session_id: &SessionId,
        command_id: &str,
        principal: &str,
        goal: &str,
        contract: (&[String], &[String]),
    ) -> Result<CommandResult> {
        let (criteria, constraints) = contract;
        if goal.is_empty() || goal.len() > crate::contracts::TEXT_MAX_BYTES {
            return Err(StoreError::InvalidInput(InvalidCause::EmptyGoal));
        }
        let params_digest =
            serde_json::to_string(&(&session_id.0, principal, goal, criteria, constraints))
                .map_err(storage)?;
        if let Some((digest, result_json)) = self.receipt(command_id)? {
            if digest != params_digest {
                return Err(StoreError::Conflict(ConflictCause::DuplicateCommand {
                    command_id: command_id.to_string(),
                }));
            }
            let result: CommandResult = serde_json::from_str(&result_json).map_err(storage)?;
            return Ok(result);
        }
        let task_id = TaskId::generate();
        let goal_bytes = goal.as_bytes().to_vec();
        let digest = crate::config::hex(&sha2::Sha256::digest(&goal_bytes));
        let tx = self.conn_mut()?.transaction().map_err(storage)?;
        tx.execute(
            sql::INSERT_TASK,
            params![
                task_id.0,
                session_id.0,
                goal_bytes,
                digest,
                goal_artifact_id(&task_id),
            ],
        )
        .map_err(storage)?;
        for (position, text) in criteria.iter().enumerate() {
            let criterion_id = CriterionId::generate();
            tx.execute(
                sql::INSERT_CRITERION,
                params![criterion_id.0, task_id.0, position as i64, text],
            )
            .map_err(storage)?;
        }
        for (position, text) in constraints.iter().enumerate() {
            tx.execute(
                sql::INSERT_CONSTRAINT,
                params![task_id.0, position as i64, text],
            )
            .map_err(storage)?;
        }
        tx.execute(sql::TOUCH_EVENT_CURSOR, params![task_id.0])
            .map_err(storage)?;
        Self::append_event(
            &tx,
            session_id,
            Some(&task_id),
            (&task_id.0, 1),
            "task.created",
            json!({ "task_id": task_id.0, "goal_digest": digest }),
            "human",
        )?;
        let snapshot = Self::snapshot_in_tx(&tx, &task_id)?;
        let result = CommandResult {
            status: "accepted".to_string(),
            task_id,
            task_revision: snapshot.revision,
            intent_revision: snapshot.intent_revision,
            event_cursor: 1,
            snapshot,
            contract_revision: Some(1),
        };
        Self::record_receipt(
            &tx,
            command_id,
            session_id,
            principal,
            &params_digest,
            &result,
        )?;
        tx.commit().map_err(storage)?;
        Ok(result)
    }

    /// The single question producer (architecture TP-PUBLIC): atomically
    /// stores the pending question and moves the task to `waiting` with a
    /// decision blocker in the same commit. The intent pin the caller
    /// froze is re-checked inside the write transaction — a steer between
    /// the snapshot read and this commit would otherwise plant a question
    /// that is stale on arrival. A `waiting` task admits too: a steer
    /// supersedes its dead pending row, and this publish is the
    /// replacement fork it waits on. Rows pinned to a superseded intent —
    /// a steer's own casualty or a leftover an older build wrote — die
    /// here first, so publication never wedges on a question nothing can
    /// answer.
    pub fn publish_question(
        &mut self,
        session_id: &SessionId,
        question: &Question,
    ) -> Result<TaskSnapshot> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        Self::insert_question(&tx, session_id, question)?;
        tx.commit().map_err(storage)?;
        self.snapshot(&question.task_id)
    }

    /// Publishes a plan handler's fork and records its `Decision` wait
    /// on the handler's own row in one transaction, bound to the current
    /// selection like every plan-row write. A task `blocked` solely by
    /// plan-owned holds is released first so the question can land; any
    /// other block — or a terminal task — refuses the whole write, so no
    /// row waits on a question that was never published.
    ///
    /// # Errors
    /// The [`TaskStore::update_plan_row`] refusals and the
    /// [`TaskStore::publish_question`] ones.
    pub(crate) fn publish_plan_fork(
        &mut self,
        session_id: &SessionId,
        question: &Question,
        update: &PlanRowUpdate<'_>,
    ) -> Result<TaskSnapshot> {
        let task_id = &question.task_id;
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        Self::check_plan_binding(&tx, task_id, update.selection_revision, update.facts_digest)?;
        let lifecycle: String = tx
            .query_row(sql::TASK_LIFECYCLE, params![task_id.0], |row| row.get(0))
            .map_err(storage)?;
        if lifecycle == "blocked" {
            Self::release_plan_owned_block(&tx, task_id)?;
        }
        Self::apply_plan_row_change(
            &tx,
            task_id,
            update.capability,
            update.handler,
            &update.change,
        )?;
        Self::insert_question(&tx, session_id, question)?;
        Self::settle_plan_state(&tx, task_id)?;
        tx.commit().map_err(storage)?;
        self.snapshot(task_id)
    }

    fn insert_question(
        tx: &rusqlite::Transaction<'_>,
        session_id: &SessionId,
        question: &Question,
    ) -> Result<()> {
        let (revision, intent_revision, lifecycle): (u64, u64, String) = tx
            .query_row(sql::TASK_REVISIONS, params![question.task_id.0], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get(2)?,
                ))
            })
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_task(&question.task_id.0))?;
        match lifecycle.as_str() {
            "running" | "waiting" => {}
            _ => {
                return Err(StoreError::Conflict(ConflictCause::QuestionOnLifecycle {
                    lifecycle,
                }));
            }
        }
        if question.intent_revision != intent_revision {
            return Err(StoreError::StaleIntent {
                expected: question.intent_revision,
                current: intent_revision,
            });
        }
        Self::supersede_pending_questions(
            tx,
            session_id,
            &question.task_id,
            intent_revision,
            "state",
        )?;
        let pending: bool = tx
            .query_row(
                sql::PENDING_QUESTION_EXISTS,
                params![question.task_id.0],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if pending {
            return Err(StoreError::Conflict(ConflictCause::PendingQuestionExists));
        }
        tx.execute(
            sql::INSERT_QUESTION,
            params![
                question.question_id.0,
                question.task_id.0,
                question.question_revision as i64,
                question.intent_revision as i64,
                question.prompt,
                serde_json::to_string(question).map_err(storage)?
            ],
        )
        .map_err(storage)?;
        let new_revision = revision + 1;
        tx.execute(
            sql::TASK_SET_WAITING,
            params![question.task_id.0, new_revision as i64],
        )
        .map_err(storage)?;
        Self::append_event(
            tx,
            session_id,
            Some(&question.task_id),
            (&question.task_id.0, new_revision),
            "question.published",
            json!({ "question_id": question.question_id.0, "question_revision": question.question_revision }),
            "state",
        )?;
        Ok(())
    }

    pub fn current_question(&self, task_id: &TaskId) -> Result<Option<(Question, u64)>> {
        // A pending question is pinned to the intent revision it was
        // authored under. Once a steer supersedes that intent the row
        // stays for audit but is no longer the task's current question.
        // The pending row and the task's live intent revision read in
        // one statement — the pin comparison below never sees a task
        // row younger than the question it judges — and the statement
        // itself refuses rows beside a terminal lifecycle: a cancelled or
        // completed task has no current question even if a stale pending
        // row survives.
        let row = self
            .conn()?
            .query_row(sql::CURRENT_QUESTION, params![task_id.0], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .optional()
            .map_err(storage)?;
        match row {
            None => Ok(None),
            Some((body, revision, intent_revision)) => {
                let question: Question = serde_json::from_str(&body).map_err(storage)?;
                if question.intent_revision != intent_revision as u64 {
                    return Ok(None);
                }
                Ok(Some((question, revision as u64)))
            }
        }
    }

    /// Every answer attempt is journaled in `answer_attempts`: an applied
    /// answer rides the same transaction as the state change, a denied one
    /// commits on its own so the rejection record survives even though the
    /// answer itself did not. The journal is append-only — later answers
    /// never erase earlier attempts.
    pub fn answer_question(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        question_id: &QuestionId,
        question_revision: u64,
        selection: &AnswerSelection,
        author: &str,
    ) -> Result<CommandResult> {
        match self.answer_question_commit(
            session_id,
            task_id,
            question_id,
            question_revision,
            selection,
            author,
        ) {
            Ok(result) => Ok(result),
            Err(error) => {
                let journal =
                    serde_json::to_string(selection)
                        .map_err(storage)
                        .and_then(|selection_json| {
                            self.record_denied_attempt(
                                task_id,
                                question_id,
                                question_revision,
                                &selection_json,
                                author,
                                denial_class(&error),
                            )
                        });
                match journal {
                    Ok(()) => Err(error),
                    // The denial is the outcome the caller acts on — a
                    // journal write failure must not mask it; it rides
                    // along named so the audit gap is never silent.
                    Err(journal) => Err(StoreError::DenialJournalFailed {
                        denial: Box::new(error),
                        journal: Box::new(journal),
                    }),
                }
            }
        }
    }

    fn answer_question_commit(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        question_id: &QuestionId,
        question_revision: u64,
        selection: &AnswerSelection,
        author: &str,
    ) -> Result<CommandResult> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let (revision, intent_revision, lifecycle): (u64, u64, String) = tx
            .query_row(sql::TASK_REVISIONS, params![task_id.0], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get(2)?,
                ))
            })
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_task(&task_id.0))?;
        if Lifecycle::from_db(&lifecycle).is_terminal() {
            return Err(StoreError::AlreadyTerminal);
        }
        let (stored_revision, state, body_json, stored_intent): (u64, String, String, u64) = tx
            .query_row(
                sql::QUESTION_BY_ID,
                params![question_id.0, task_id.0],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u64,
                        row.get(1)?,
                        row.get(2)?,
                        row.get::<_, i64>(3)? as u64,
                    ))
                },
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_question(&question_id.0))?;
        if state != "pending" {
            // A row whose intent pin no longer matches the live intent
            // was superseded by a steer — the denial names the stale pin,
            // not a generic not-pending conflict, so the caller learns
            // the question it answered is dead rather than replayed.
            if stored_intent != intent_revision {
                return Err(StoreError::StaleIntent {
                    expected: stored_intent,
                    current: intent_revision,
                });
            }
            return Err(StoreError::Conflict(ConflictCause::QuestionNotPending));
        }
        if stored_revision != question_revision {
            return Err(StoreError::Conflict(ConflictCause::QuestionRevision {
                expected: question_revision,
                current: stored_revision,
            }));
        }
        let question: Question = serde_json::from_str(&body_json).map_err(storage)?;
        // The question is pinned to the intent it was authored under.
        // A steer since then supersedes it: an answer quoting the live
        // intent must not commit against a stale pin — the frozen
        // manifest it would resume no longer reflects the task intent.
        if question.intent_revision != intent_revision {
            return Err(StoreError::StaleIntent {
                expected: question.intent_revision,
                current: intent_revision,
            });
        }
        match selection {
            AnswerSelection::Option { option_id } => {
                let Some(option) = question.options.iter().find(|o| o.option_id == *option_id)
                else {
                    return Err(StoreError::InvalidInput(InvalidCause::UnknownOption {
                        option_id: option_id.0.clone(),
                        question_id: question_id.0.clone(),
                    }));
                };
                if let Availability::Disabled { reason } = &option.availability {
                    return Err(StoreError::InvalidInput(InvalidCause::DisabledOption {
                        option_id: option_id.0.clone(),
                        reason: reason.clone(),
                    }));
                }
            }
            AnswerSelection::Custom { text } => {
                if text.trim().is_empty() {
                    return Err(StoreError::InvalidInput(InvalidCause::EmptyCustomAnswer));
                }
            }
        }
        let answer_json = serde_json::to_string(selection).map_err(storage)?;
        tx.execute(
            sql::ANSWER_QUESTION,
            params![question_id.0, answer_json, author],
        )
        .map_err(storage)?;
        let new_revision = revision + 1;
        tx.execute(
            sql::TASK_SET_RUNNING,
            params![task_id.0, new_revision as i64],
        )
        .map_err(storage)?;
        Self::append_event(
            &tx,
            session_id,
            Some(task_id),
            (&task_id.0, new_revision),
            "question.answered",
            json!({ "question_id": question_id.0, "author": author }),
            author,
        )?;
        tx.execute(
            sql::INSERT_ANSWER_ATTEMPT,
            params![
                question_id.0,
                task_id.0,
                question_revision as i64,
                answer_json,
                author,
                "applied",
                Option::<String>::None,
            ],
        )
        .map_err(storage)?;
        Self::retain_answered_plan_fork(&tx, task_id, question_id, question_revision)?;
        // The answer ends the wait, not a plan block: a task whose plan
        // rows or gate hold still hold it goes back to `blocked`.
        Self::settle_plan_lifecycle(&tx, task_id)?;
        let snapshot = Self::snapshot_in_tx(&tx, task_id)?;
        tx.commit().map_err(storage)?;
        Ok(CommandResult {
            status: "applied".to_string(),
            task_id: task_id.clone(),
            task_revision: snapshot.revision,
            intent_revision,
            event_cursor: snapshot.event_cursor,
            snapshot,
            contract_revision: None,
        })
    }
    fn retain_answered_plan_fork(
        tx: &rusqlite::Transaction<'_>,
        task_id: &TaskId,
        question_id: &QuestionId,
        question_revision: u64,
    ) -> Result<()> {
        let Some(selection) = Self::plan_selection_on(tx, task_id)? else {
            return Ok(());
        };
        let Some(row) = Self::plan_rows_on(tx, task_id)?.into_iter().find(|row| {
            matches!(
                row.blocker.as_ref().map(|blocker| &blocker.condition),
                Some(ResumeCondition::Decision {
                    question_id: fork_id,
                    revision,
                }) if fork_id == question_id && *revision == question_revision
            )
        }) else {
            return Ok(());
        };
        let identity = json!({
            "kind": "answered_fork",
            "question_id": question_id.0,
            "question_revision": question_revision,
            "selection_revision": selection.revision,
            "facts_digest": selection.facts_digest,
        })
        .to_string();
        tx.execute(
            sql::RETAIN_ANSWERED_PLAN_FORK,
            params![task_id.0, row.capability, identity],
        )
        .map_err(storage)?;
        Ok(())
    }

    /// One denied answer attempt into the append-only journal. The row
    /// commits alone: a denial that could not be journaled reports the
    /// storage failure, never a silent drop. The dispatch layer calls
    /// this directly for denials raised before `answer_question` can run —
    /// machine ingress, missing revision pins, an unparseable selection —
    /// because every denied attempt journals, not only the ones the
    /// store itself rejects. `selection_json` is the serialized attempt:
    /// the canonical `AnswerSelection` for parsed requests, the
    /// request's raw `selection` value (`"null"` when it was absent) for
    /// ones that never parsed.
    pub fn record_denied_attempt(
        &mut self,
        task_id: &TaskId,
        question_id: &QuestionId,
        question_revision: u64,
        selection_json: &str,
        author: &str,
        denial: &str,
    ) -> Result<()> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        tx.execute(
            sql::INSERT_ANSWER_ATTEMPT,
            params![
                question_id.0,
                task_id.0,
                question_revision as i64,
                selection_json,
                author,
                "denied",
                denial,
            ],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }

    /// The task's answer-attempt history in commit order — applied and
    /// denied rows interleaved as they happened.
    pub fn answer_attempts(&self, task_id: &TaskId) -> Result<Vec<AnswerAttempt>> {
        let mut stmt = self
            .conn()?
            .prepare(sql::ANSWER_ATTEMPTS_FOR_TASK)
            .map_err(storage)?;
        let rows = stmt
            .query_map(params![task_id.0], |row| {
                let outcome: String = row.get(6)?;
                let selection_json: String = row.get(4)?;
                Ok((
                    row.get::<_, i64>(0)?,
                    QuestionId(row.get::<_, String>(1)?),
                    TaskId(row.get::<_, String>(2)?),
                    row.get::<_, i64>(3)?,
                    selection_json,
                    row.get::<_, String>(5)?,
                    outcome,
                    row.get::<_, Option<String>>(7)?,
                ))
            })
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        rows.into_iter()
            .map(
                |(id, question_id, task_id, revision, selection_json, author, outcome, denial)| {
                    // A denial raised before the selection parsed
                    // journals the request's serialized selection value;
                    // the typed read degrades to it verbatim rather than
                    // breaking the audit surface.
                    let selection: AnswerSelection = serde_json::from_str(&selection_json)
                        .unwrap_or(AnswerSelection::Custom {
                            text: selection_json.clone(),
                        });
                    let outcome = AnswerAttemptOutcome::from_db(&outcome).ok_or_else(|| {
                        StoreError::Storage(format!("unknown attempt outcome {outcome}").into())
                    })?;
                    Ok(AnswerAttempt {
                        id: id as u64,
                        question_id,
                        task_id,
                        question_revision: revision as u64,
                        selection,
                        author,
                        outcome,
                        denial,
                    })
                },
            )
            .collect()
    }

    /// The question the task's latest applied answer committed against —
    /// `None` when nothing has applied yet. The decision step runs
    /// immediately after that commit, so this names the fork the step
    /// resolves.
    pub fn latest_applied_answer_question(&self, task_id: &TaskId) -> Result<Option<QuestionId>> {
        let row = self
            .conn()?
            .query_row(sql::LATEST_APPLIED_ANSWER, params![task_id.0], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .map_err(storage)?;
        Ok(row.map(QuestionId))
    }

    /// Every evidence row bound to the task, in insertion order — the
    /// recorded D5 split's typed shape.
    pub fn evidence_for_task(&self, task_id: &TaskId) -> Result<Vec<Evidence>> {
        let mut stmt = self
            .conn()?
            .prepare(sql::EVIDENCE_FOR_TASK)
            .map_err(storage)?;
        let rows = stmt
            .query_map(params![task_id.0], |row| {
                let validity: String = row.get(5)?;
                Ok((
                    EvidenceId(row.get::<_, String>(0)?),
                    TaskId(row.get::<_, String>(1)?),
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    validity,
                    row.get::<_, String>(6)?,
                ))
            })
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        rows.into_iter()
            .map(
                |(evidence_id, task_id, scope, observation, digest, validity, obligation_id)| {
                    let validity = match validity.as_str() {
                        "current" => EvidenceValidity::Current,
                        "stale" => EvidenceValidity::Stale,
                        other => {
                            return Err(StoreError::Storage(
                                format!("unknown evidence validity {other}").into(),
                            ));
                        }
                    };
                    Ok(Evidence {
                        evidence_id,
                        task_id,
                        scope,
                        observation,
                        digest,
                        validity,
                        obligation_id,
                    })
                },
            )
            .collect()
    }

    /// Records the off transition's pause (AC-024/EDGE-016): work in
    /// flight stops where it is — its checkpoint and its settled effects
    /// intact — and only a new intent (`steer_task`) releases it. A
    /// `blocked` task keeps its own hold, because converting it would
    /// overwrite a plan-owned reason the off transition can never restore.
    /// Idempotent: an already paused, blocked or terminal task gains no
    /// transition and no second event.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] for an unknown task and
    /// [`StoreError::Storage`] when the transition cannot be written.
    pub fn pause_for_workflow_off(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
    ) -> Result<bool> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let (revision, lifecycle): (u64, String) = tx
            .query_row(sql::TASK_REVISIONS, params![task_id.0], |row| {
                Ok((row.get::<_, i64>(0)? as u64, row.get(2)?))
            })
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_task(&task_id.0))?;
        let paused = tx
            .execute(PAUSE_TASK_FOR_WORKFLOW_OFF, params![task_id.0])
            .map_err(storage)?;
        if paused == 0 {
            return Ok(false);
        }
        Self::append_event(
            &tx,
            session_id,
            Some(task_id),
            (&task_id.0, revision + 1),
            "task.paused",
            json!({ "kind": "workflow_off", "from": lifecycle }),
            "runtime",
        )?;
        tx.commit().map_err(storage)?;
        Ok(true)
    }

    pub fn steer_task(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        expected_intent_revision: u64,
        expected_task_revision: u64,
        instruction: &str,
    ) -> Result<CommandResult> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let (revision, intent_revision, lifecycle): (u64, u64, String) = tx
            .query_row(sql::TASK_REVISIONS, params![task_id.0], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get(2)?,
                ))
            })
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_task(&task_id.0))?;
        if Lifecycle::from_db(&lifecycle).is_terminal() {
            return Err(StoreError::Conflict(ConflictCause::TerminalCannotReopen));
        }
        if intent_revision != expected_intent_revision {
            return Err(StoreError::StaleIntent {
                expected: expected_intent_revision,
                current: intent_revision,
            });
        }
        if revision != expected_task_revision {
            return Err(StoreError::Conflict(ConflictCause::TaskRevision {
                expected: expected_task_revision,
                current: revision,
            }));
        }
        let new_revision = revision + 1;
        let new_intent = intent_revision + 1;
        tx.execute(
            sql::UPDATE_INTENT,
            params![task_id.0, new_revision as i64, new_intent as i64],
        )
        .map_err(storage)?;
        // A pending question is pinned to the intent it was authored
        // under — the steer just superseded it, so the row is dead:
        // `current_question` hides it and `answer_question` denies it.
        // Mark it superseded in the same transaction — the row stays for
        // audit, each death journals its `question.superseded` event, and
        // the stale row never blocks the new fork's publication. The task
        // stops waiting with it: a `waiting` snapshot must name its
        // blocker, and the dead question is none.
        Self::supersede_pending_questions(&tx, session_id, task_id, new_intent, "human")?;
        tx.execute(sql::SUPERSESSION_RESUMES_TASK, params![task_id.0])
            .map_err(storage)?;
        Self::append_event(
            &tx,
            session_id,
            Some(task_id),
            (&task_id.0, new_revision),
            "task.steered",
            json!({ "instruction": instruction }),
            "human",
        )?;
        // A new intent is what releases the off pause (AC-024/DX-C1): the
        // pause holds the intent that was in flight, so the revision this
        // steer opens displaces it. The plan's own lifecycle rule still
        // runs afterwards — a plan-owned block is never erased here.
        tx.execute(RELEASE_WORKFLOW_OFF_PAUSE, params![task_id.0])
            .map_err(storage)?;
        // Same rule as the answer path: ending the wait never erases a
        // plan block.
        Self::settle_plan_lifecycle(&tx, task_id)?;
        let snapshot = Self::snapshot_in_tx(&tx, task_id)?;
        tx.commit().map_err(storage)?;
        Ok(CommandResult {
            status: "applied".to_string(),
            task_id: task_id.clone(),
            task_revision: snapshot.revision,
            intent_revision: new_intent,
            event_cursor: snapshot.event_cursor,
            snapshot,
            contract_revision: None,
        })
    }

    /// Monotonic control of the current intent. Terminal tasks answer
    /// `already_terminal`; a stale intent is `stale_intent` even then.
    /// This is the operator's seam: the settle journals `human`. A
    /// settle the state machine itself drives — a dead tree the
    /// answered task's resume discovers — goes through
    /// `cancel_task_with_origin` so the journal names its
    /// real driver.
    pub fn cancel_task(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        expected_intent_revision: u64,
        reason: Option<&str>,
    ) -> Result<CommandResult> {
        self.cancel_task_with_origin(
            session_id,
            task_id,
            expected_intent_revision,
            reason,
            "human",
        )
    }

    /// `cancel_task` with the journal attribution spelled by the
    /// caller: `"state"` when a store-driven transition settles the row
    /// — the same spelling `complete_if_eligible` writes — `"human"`
    /// for operator ingress. The origin rides `task.cancelled` and
    /// every `question.superseded` the transition emits, so a replay
    /// reads who actually settled the task.
    ///
    /// `origin` names the request class, not the client actor:
    /// `"human"` is the external operator-class ingress spelling, so a
    /// headless `Ingress::Machine` client driving `task.submit`
    /// cancel/create still journals `"human"` here even though its
    /// denied `answer` journals `author:"machine"` and its denied
    /// `steer` never reaches the store at all. Attributing
    /// machine-vs-human clients on the remaining kinds is a deferred
    /// contract decision; until then the journal keeps the request-class
    /// convention.
    pub(crate) fn cancel_task_with_origin(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        expected_intent_revision: u64,
        reason: Option<&str>,
        origin: &str,
    ) -> Result<CommandResult> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let (revision, intent_revision, lifecycle): (u64, u64, String) = tx
            .query_row(sql::TASK_REVISIONS, params![task_id.0], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get(2)?,
                ))
            })
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_task(&task_id.0))?;
        let terminal = Lifecycle::from_db(&lifecycle).is_terminal();
        if intent_revision != expected_intent_revision {
            return Err(StoreError::StaleIntent {
                expected: expected_intent_revision,
                current: intent_revision,
            });
        }
        let snapshot;
        if terminal {
            // The observe is idempotent but not write-free: a pending row
            // can outlive its task only by pre-journal writes or a
            // foreign writer, so this arm still kills and journals it.
            Self::supersede_terminal_questions(&tx, session_id, task_id, &lifecycle, origin)?;
            snapshot = Self::snapshot_in_tx(&tx, task_id)?;
            tx.commit().map_err(storage)?;
            return Ok(CommandResult {
                status: "already_terminal".to_string(),
                task_id: task_id.clone(),
                task_revision: revision,
                intent_revision,
                event_cursor: snapshot.event_cursor,
                snapshot,
                contract_revision: None,
            });
        }
        tx.execute(sql::CANCEL_TASK, params![task_id.0, (revision + 1) as i64])
            .map_err(storage)?;
        Self::supersede_terminal_questions(&tx, session_id, task_id, "cancelled", origin)?;
        Self::append_event(
            &tx,
            session_id,
            Some(task_id),
            (&task_id.0, revision + 1),
            "task.cancelled",
            json!({ "reason": reason }),
            origin,
        )?;
        snapshot = Self::snapshot_in_tx(&tx, task_id)?;
        tx.commit().map_err(storage)?;
        Ok(CommandResult {
            status: "applied".to_string(),
            task_id: task_id.clone(),
            task_revision: revision + 1,
            intent_revision,
            event_cursor: snapshot.event_cursor,
            snapshot,
            contract_revision: None,
        })
    }

    pub fn task_cancelled(&self, task_id: &TaskId) -> Result<bool> {
        Ok(self.task_lifecycle(task_id)? == Lifecycle::Cancelled)
    }

    /// Task lifecycle without loading the full snapshot.
    pub fn task_lifecycle(&self, task_id: &TaskId) -> Result<Lifecycle> {
        let lifecycle: String = self
            .conn()?
            .query_row(sql::TASK_LIFECYCLE, params![task_id.0], |row| row.get(0))
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_task(&task_id.0))?;
        Ok(Lifecycle::from_db(&lifecycle))
    }

    // ----- snapshots -----

    fn snapshot_in_tx(tx: &rusqlite::Transaction<'_>, task_id: &TaskId) -> Result<TaskSnapshot> {
        let (
            revision,
            intent_revision,
            contract_revision,
            lifecycle,
            goal_digest,
            artifact_id,
            goal_len,
            event_cursor,
        ): (u64, u64, u64, String, String, String, usize, u64) = tx
            .query_row(sql::SNAPSHOT_TASK, params![task_id.0], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u64,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get::<_, i64>(6)? as usize,
                    row.get::<_, i64>(7)? as u64,
                ))
            })
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_task(&task_id.0))?;
        let mut criteria_stmt = tx.prepare(sql::CRITERIA_FOR_TASK).map_err(storage)?;
        let criteria = criteria_stmt
            .query_map(params![task_id.0], |row| {
                Ok(Criterion {
                    id: CriterionId(row.get(0)?),
                    text: row.get(1)?,
                })
            })
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        let mut constraints_stmt = tx.prepare(sql::CONSTRAINTS_FOR_TASK).map_err(storage)?;
        let constraints = constraints_stmt
            .query_map(params![task_id.0], |row| row.get::<_, String>(0))
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        let mut obligations_stmt = tx.prepare(sql::OBLIGATIONS_FOR_TASK).map_err(storage)?;
        let stored = obligations_stmt
            .query_map(params![task_id.0], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        // Stored states decode strictly: an unknown value is corrupt
        // storage, never silently read as `required` or `pending`.
        let mut obligations = stored
            .into_iter()
            .map(|(id, criterion_id, applicability, execution)| {
                Ok(Obligation {
                    id,
                    criterion_refs: vec![CriterionId(criterion_id)],
                    applicability: applicability_from_db(&applicability)?,
                    execution: execution_from_db(&execution)?,
                    basis_refs: Vec::new(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        // Plan rows follow the criterion obligations on the same page:
        // one owner-visible list, the plan's rows named `plan:<capability>`.
        obligations.extend(
            Self::plan_rows_on(tx, task_id)?
                .iter()
                .map(PlanObligationRecord::obligation),
        );
        let mut attempts_stmt = tx.prepare(sql::ATTEMPTS_FOR_TASK).map_err(storage)?;
        let attempts = attempts_stmt
            .query_map(params![task_id.0], |row| {
                Ok(AttemptRef {
                    attempt_id: AttemptId(row.get(0)?),
                    action_id: crate::contracts::ActionId(row.get(1)?),
                    effect_class: match row.get::<_, String>(2)?.as_str() {
                        "write" => crate::contracts::EffectClass::Write,
                        "exec" => crate::contracts::EffectClass::Exec,
                        "egress" => crate::contracts::EffectClass::Egress,
                        "model" => crate::contracts::EffectClass::Model,
                        "control" => crate::contracts::EffectClass::Control,
                        _ => crate::contracts::EffectClass::Read,
                    },
                    state: match row.get::<_, String>(3)?.as_str() {
                        "admitted" => AttemptState::Admitted,
                        "running" => AttemptState::Running,
                        "confirmed" => AttemptState::Confirmed,
                        "rejected" => AttemptState::Rejected,
                        "cancel_requested" => AttemptState::CancelRequested,
                        "unknown" => AttemptState::Unknown,
                        _ => AttemptState::Planned,
                    },
                })
            })
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        let blockers = Self::blockers_in_tx(tx, task_id)?;
        Ok(TaskSnapshot {
            task_id: task_id.clone(),
            revision,
            intent_revision,
            lifecycle: Lifecycle::from_db(&lifecycle),
            goal_ref: ArtifactRef {
                id: crate::contracts::ArtifactId(artifact_id),
                digest: goal_digest,
                size_bytes: goal_len as u64,
                media_type: "text/plain;charset=utf-8".to_string(),
                scope: Some(format!("task:{}", task_id.0)),
            },
            contract_revision,
            constraints: Page::new(constraints, revision),
            criteria: Page::new(criteria, revision),
            obligations: Page::new(obligations, revision),
            actions: Page::new(Vec::new(), revision),
            attempts: Page::new(attempts, revision),
            decision_refs: Page::new(Vec::new(), revision),
            event_cursor,
            blockers,
        })
    }

    fn blockers_in_tx(
        tx: &rusqlite::Transaction<'_>,
        task_id: &TaskId,
    ) -> Result<Option<Vec<Blocker>>> {
        let lifecycle: String = tx
            .query_row(sql::TASK_LIFECYCLE, params![task_id.0], |row| row.get(0))
            .map_err(storage)?;
        let mut blockers = Vec::new();
        let pending: Option<(String, u64)> = tx
            .query_row(sql::PENDING_QUESTION, params![task_id.0], |row| {
                Ok((row.get(0)?, row.get::<_, i64>(1)? as u64))
            })
            .optional()
            .map_err(storage)?;
        match lifecycle.as_str() {
            "waiting" => {
                if let Some((question_id, revision)) = &pending {
                    blockers.push(Blocker {
                        reason: ErrorCode::DependencyBlocked,
                        owner: "state".to_string(),
                        condition: ResumeCondition::Decision {
                            question_id: QuestionId(question_id.clone()),
                            revision: *revision,
                        },
                    });
                }
            }
            "blocked" => {
                let unresolved: u64 = tx
                    .query_row(sql::UNRESOLVED_OBLIGATIONS, params![task_id.0], |row| {
                        row.get::<_, i64>(0).map(|v| v as u64)
                    })
                    .map_err(storage)?;
                if unresolved > 0 {
                    blockers.push(Blocker {
                        reason: ErrorCode::DependencyBlocked,
                        owner: "state".to_string(),
                        condition: ResumeCondition::Dependency {
                            action_id: crate::contracts::ActionId(format!(
                                "obligations:{unresolved}"
                            )),
                        },
                    });
                }
                let unknown: u64 = tx
                    .query_row(sql::UNKNOWN_ATTEMPTS, params![task_id.0], |row| {
                        row.get::<_, i64>(0).map(|v| v as u64)
                    })
                    .map_err(storage)?;
                if unknown > 0 {
                    blockers.push(Blocker {
                        reason: ErrorCode::OutcomeUnknown,
                        owner: "executor".to_string(),
                        condition: ResumeCondition::Reconciliation {
                            action_id: crate::contracts::ActionId(format!("attempts:{unknown}")),
                        },
                    });
                }
            }
            // The off pause holds its own state, so it projects its own
            // blocker: nothing in the plan tables can erase it (AC-024/I5).
            "paused" => blockers.push(workflow_off_blocker()),
            _ => {}
        }
        if matches!(lifecycle.as_str(), "waiting" | "blocked" | "paused") {
            let plan = Self::plan_blockers_on(tx, std::slice::from_ref(&task_id.0))?
                .remove(&task_id.0)
                .unwrap_or_default();
            extend_plan_blockers(&mut blockers, plan, pending.as_ref());
        }
        // Only a block nothing else explains reads as "no ready action":
        // a plan blocker names its exact capability instead.
        if lifecycle == "blocked" && blockers.is_empty() {
            blockers.push(Blocker {
                reason: ErrorCode::DependencyBlocked,
                owner: "controller".to_string(),
                condition: ResumeCondition::NoReadyAction {},
            });
        }
        if blockers.is_empty() {
            Ok(None)
        } else {
            Ok(Some(blockers))
        }
    }

    pub fn snapshot(&self, task_id: &TaskId) -> Result<TaskSnapshot> {
        let tx = self.conn()?.unchecked_transaction().map_err(storage)?;
        let snapshot = Self::snapshot_in_tx(&tx, task_id)?;
        Ok(snapshot)
    }

    fn batched_blockers(
        &self,
        tasks: &[(TaskId, Lifecycle)],
    ) -> Result<BTreeMap<String, Vec<Blocker>>> {
        let mut blockers = BTreeMap::<String, Vec<Blocker>>::new();
        if tasks.is_empty() {
            return Ok(blockers);
        }
        let task_ids: Vec<String> = tasks.iter().map(|(task_id, _)| task_id.0.clone()).collect();
        let lifecycles: BTreeMap<String, Lifecycle> = tasks
            .iter()
            .map(|(task_id, lifecycle)| (task_id.0.clone(), *lifecycle))
            .collect();
        let tx = self.conn()?.unchecked_transaction().map_err(storage)?;

        let pending_sql = sql::pending_questions_for_tasks(task_ids.len());
        let mut stmt = tx.prepare(&pending_sql).map_err(storage)?;
        let rows = stmt
            .query_map(params_from_iter(task_ids.iter()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)? as u64,
                ))
            })
            .map_err(storage)?;
        let mut pending = BTreeMap::<String, (String, u64)>::new();
        for row in rows {
            let (task_id, question_id, revision) = row.map_err(storage)?;
            pending.insert(task_id.clone(), (question_id.clone(), revision));
            if lifecycles.get(&task_id) != Some(&Lifecycle::Waiting) {
                continue;
            }
            blockers.entry(task_id).or_default().push(Blocker {
                reason: ErrorCode::DependencyBlocked,
                owner: "state".to_string(),
                condition: ResumeCondition::Decision {
                    question_id: QuestionId(question_id),
                    revision,
                },
            });
        }
        drop(stmt);

        let unresolved_sql = sql::unresolved_obligations_for_tasks(task_ids.len());
        let mut stmt = tx.prepare(&unresolved_sql).map_err(storage)?;
        let rows = stmt
            .query_map(params_from_iter(task_ids.iter()), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
            })
            .map_err(storage)?;
        for row in rows {
            let (task_id, unresolved) = row.map_err(storage)?;
            if lifecycles.get(&task_id) != Some(&Lifecycle::Blocked) {
                continue;
            }
            blockers.entry(task_id).or_default().push(Blocker {
                reason: ErrorCode::DependencyBlocked,
                owner: "state".to_string(),
                condition: ResumeCondition::Dependency {
                    action_id: crate::contracts::ActionId(format!("obligations:{unresolved}")),
                },
            });
        }
        drop(stmt);

        let unknown_sql = sql::unknown_attempts_for_tasks(task_ids.len());
        let mut stmt = tx.prepare(&unknown_sql).map_err(storage)?;
        let rows = stmt
            .query_map(params_from_iter(task_ids.iter()), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
            })
            .map_err(storage)?;
        for row in rows {
            let (task_id, unknown) = row.map_err(storage)?;
            if lifecycles.get(&task_id) != Some(&Lifecycle::Blocked) {
                continue;
            }
            blockers.entry(task_id).or_default().push(Blocker {
                reason: ErrorCode::OutcomeUnknown,
                owner: "executor".to_string(),
                condition: ResumeCondition::Reconciliation {
                    action_id: crate::contracts::ActionId(format!("attempts:{unknown}")),
                },
            });
        }
        drop(stmt);

        // One statement for every task's plan blockers (never a query
        // per task); only a waiting, blocked or paused task projects them.
        let mut plan = Self::plan_blockers_on(&tx, &task_ids)?;
        for (task_id, lifecycle) in tasks {
            if !matches!(
                lifecycle,
                Lifecycle::Waiting | Lifecycle::Blocked | Lifecycle::Paused
            ) {
                continue;
            }
            if let Some(rows) = plan.remove(&task_id.0) {
                let entry = blockers.entry(task_id.0.clone()).or_default();
                extend_plan_blockers(entry, rows, pending.get(&task_id.0));
                // A skipped stale fork must not leave an empty list: an
                // absent list and an empty one read differently.
                if entry.is_empty() {
                    blockers.remove(&task_id.0);
                }
            }
        }

        for (task_id, lifecycle) in tasks {
            if *lifecycle == Lifecycle::Paused {
                blockers
                    .entry(task_id.0.clone())
                    .or_default()
                    .push(workflow_off_blocker());
            }
            if *lifecycle == Lifecycle::Blocked {
                let entry = blockers.entry(task_id.0.clone()).or_default();
                if entry.is_empty() {
                    entry.push(Blocker {
                        reason: ErrorCode::DependencyBlocked,
                        owner: "controller".to_string(),
                        condition: ResumeCondition::NoReadyAction {},
                    });
                }
            }
        }
        Ok(blockers)
    }

    fn status_page_context(
        &self,
        session_id: &SessionId,
        cursor: Option<(u64, u64)>,
    ) -> Result<(u64, u64)> {
        let generation: u64 = self
            .conn()?
            .query_row(sql::SESSION_GENERATION, params![session_id.0], |row| {
                row.get::<_, i64>(0).map(|value| value as u64)
            })
            .map_err(storage)?;
        let offset = cursor.map_or(0, |(_, offset)| offset);
        if let Some((expected, _)) = cursor
            && expected != generation
        {
            return Err(StoreError::Conflict(ConflictCause::CursorGeneration {
                expected,
                current: generation,
            }));
        }
        if offset > i64::MAX.unsigned_abs() {
            return Err(StoreError::InvalidInput(
                InvalidCause::CursorOffsetOutOfRange,
            ));
        }
        Ok((generation, offset))
    }

    fn next_page_offset(offset: u64, limit: u32) -> Result<u64> {
        let next = offset
            .checked_add(u64::from(limit))
            .ok_or(StoreError::InvalidInput(
                InvalidCause::CursorOffsetOutOfRange,
            ))?;
        if next > i64::MAX.unsigned_abs() {
            return Err(StoreError::InvalidInput(
                InvalidCause::CursorOffsetOutOfRange,
            ));
        }
        Ok(next)
    }

    fn sql_offset(offset: u64) -> Result<i64> {
        match i64::try_from(offset) {
            Ok(value) => Ok(value),
            Err(_) => Err(StoreError::InvalidInput(
                InvalidCause::CursorOffsetOutOfRange,
            )),
        }
    }

    pub fn task_status_page(
        &self,
        session_id: &SessionId,
        limit: u32,
        cursor: Option<(u64, u64)>,
    ) -> Result<Page<crate::contracts::TaskStatus>> {
        let (generation, offset) = self.status_page_context(session_id, cursor)?;
        let next_offset = Self::next_page_offset(offset, limit)?;
        let sql_offset = Self::sql_offset(offset)?;
        let mut stmt = self
            .conn()?
            .prepare(sql::TASKS_FOR_SESSION_PAGE)
            .map_err(storage)?;
        let rows = stmt
            .query_map(
                params![session_id.0, i64::from(limit) + 1, sql_offset],
                |row| {
                    Ok((
                        TaskId(row.get(0)?),
                        row.get::<_, i64>(1)? as u64,
                        row.get::<_, i64>(2)? as u64,
                        Lifecycle::from_db(&row.get::<_, String>(3)?),
                    ))
                },
            )
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        drop(stmt);
        let has_more = rows.len() > limit as usize;
        let mut rows = rows;
        rows.truncate(limit as usize);
        let task_keys: Vec<_> = rows
            .iter()
            .map(|(task_id, _, _, lifecycle)| (task_id.clone(), *lifecycle))
            .collect();
        let mut blockers = self.batched_blockers(&task_keys)?;
        let items = rows
            .into_iter()
            .map(|(task_id, task_revision, intent_revision, lifecycle)| {
                Ok(crate::contracts::TaskStatus {
                    blockers: blockers.remove(&task_id.0),
                    task_id,
                    task_revision,
                    intent_revision,
                    lifecycle,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut page = Page::new(items, generation);
        if has_more {
            page.next_cursor = Some(format!("gen:{generation}:offset:{next_offset}"));
        }
        Ok(page)
    }

    fn todo_items(
        &self,
        session_id: &SessionId,
        limit: u32,
        cursor: Option<(u64, u64)>,
    ) -> Result<(Vec<TodoItem>, u64, u64, bool)> {
        let (generation, offset) = self.status_page_context(session_id, cursor)?;
        let next_offset = Self::next_page_offset(offset, limit)?;
        let sql_offset = Self::sql_offset(offset)?;
        let mut stmt = self
            .conn()?
            .prepare(sql::TODO_FOR_SESSION_PAGE)
            .map_err(storage)?;
        let rows = stmt
            .query_map(
                params![session_id.0, i64::from(limit) + 1, sql_offset],
                |row| {
                    Ok((
                        TaskId(row.get(0)?),
                        row.get::<_, i64>(1)? as u64,
                        Lifecycle::from_db(&row.get::<_, String>(2)?),
                    ))
                },
            )
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        drop(stmt);
        let has_more = rows.len() > limit as usize;
        let mut rows = rows;
        rows.truncate(limit as usize);
        let task_keys: Vec<_> = rows
            .iter()
            .map(|(task_id, _, lifecycle)| (task_id.clone(), *lifecycle))
            .collect();
        let mut blockers = self.batched_blockers(&task_keys)?;
        let items = rows
            .into_iter()
            .map(|(task_id, task_revision, lifecycle)| TodoItem {
                blockers: blockers.remove(&task_id.0),
                task_id,
                task_revision,
                lifecycle,
            })
            .collect();
        Ok((items, generation, next_offset, has_more))
    }

    pub fn todo_page(
        &self,
        session_id: &SessionId,
        limit: u32,
        cursor: Option<(u64, u64)>,
    ) -> Result<Page<TodoItem>> {
        let (items, generation, next_offset, has_more) =
            self.todo_items(session_id, limit, cursor)?;
        let mut page = Page::new(items, generation);
        if has_more {
            page.next_cursor = Some(format!("gen:{generation}:offset:{next_offset}"));
        }
        Ok(page)
    }

    pub fn scheduler_page(
        &self,
        session_id: &SessionId,
        limit: u32,
        cursor: Option<(u64, u64)>,
    ) -> Result<Page<SchedulerItem>> {
        let (todo, generation, next_offset, has_more) =
            self.todo_items(session_id, limit, cursor)?;
        let items = todo
            .into_iter()
            .map(|item| SchedulerItem {
                ready: item.lifecycle == Lifecycle::Running && item.blockers.is_none(),
                task_id: item.task_id,
                task_revision: item.task_revision,
                lifecycle: item.lifecycle,
                blockers: item.blockers,
            })
            .collect();
        let mut page = Page::new(items, generation);
        if has_more {
            page.next_cursor = Some(format!("gen:{generation}:offset:{next_offset}"));
        }
        Ok(page)
    }

    /// Paged snapshot collection: the strict cursor `gen:{generation}` /
    /// `gen:{generation}:offset:{offset}` checks the snapshot revision
    /// (conflict on mismatch, unchanged behaviour) while `page_size` and
    /// offset slice the item list. `next_cursor` advances by `page_size`
    /// while items remain and is absent on the last page; nothing is
    /// silently discarded.
    pub fn collection(
        &self,
        task_id: &TaskId,
        collection: &str,
        cursor: Option<(u64, u64)>,
        limit: u32,
    ) -> Result<Page<Value>> {
        let snapshot = self.snapshot(task_id)?;
        if let Some((generation, _)) = cursor
            && generation != snapshot.revision
        {
            return Err(StoreError::Conflict(ConflictCause::CursorGeneration {
                expected: generation,
                current: snapshot.revision,
            }));
        }
        let generation = snapshot.revision;
        let items: Vec<Value> = match collection {
            "criteria" => snapshot
                .criteria
                .items
                .iter()
                .map(|c| json!({ "id": c.id.0, "text": c.text }))
                .collect(),
            "constraints" => snapshot
                .constraints
                .items
                .iter()
                .map(|c| Value::String(c.clone()))
                .collect(),
            "obligations" => snapshot
                .obligations
                .items
                .iter()
                .map(|o| serde_json::to_value(o).unwrap_or(Value::Null))
                .collect(),
            "attempts" => snapshot
                .attempts
                .items
                .iter()
                .map(|a| serde_json::to_value(a).unwrap_or(Value::Null))
                .collect(),
            other => {
                return Err(StoreError::InvalidInput(InvalidCause::UnknownCollection(
                    other.to_string(),
                )));
            }
        };
        let offset = cursor.map_or(0, |(_, offset)| offset);
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(items.len());
        let end = start.saturating_add(limit as usize).min(items.len());
        let mut page = Page::new(items[start..end].to_vec(), generation);
        if end < items.len() {
            page.next_cursor = Some(format!("gen:{generation}:offset:{end}"));
        }
        Ok(page)
    }

    // ----- attempts / effects ledger -----

    pub fn plan_attempt(
        &mut self,
        task_id: &TaskId,
        class: crate::contracts::EffectClass,
        describe: &str,
    ) -> Result<String> {
        let attempt_id = AttemptId::generate().0;
        self.conn()?
            .execute(
                sql::INSERT_ATTEMPT,
                params![
                    attempt_id,
                    task_id.0,
                    format!("action-{attempt_id}"),
                    format!("{class:?}").to_lowercase(),
                    describe
                ],
            )
            .map_err(storage)?;
        Ok(attempt_id)
    }

    pub fn set_attempt_state(
        &mut self,
        attempt_id: &str,
        state: &str,
        detail: Option<&str>,
    ) -> Result<()> {
        let changed = self
            .conn()?
            .execute(sql::UPDATE_ATTEMPT, params![attempt_id, state, detail])
            .map_err(storage)?;
        if changed == 0 {
            return Err(StoreError::missing_attempt(attempt_id));
        }
        Ok(())
    }

    pub fn attempt_state(&self, attempt_id: &str) -> Result<Option<String>> {
        let state = self
            .conn()?
            .query_row(sql::ATTEMPT_STATE, params![attempt_id], |row| row.get(0))
            .optional()
            .map_err(storage)?;
        Ok(state)
    }

    /// (task_id, state, detail) of one attempt; reconcile validates against
    /// this instead of trusting an arbitrary id.
    pub fn attempt_record(
        &self,
        attempt_id: &str,
    ) -> Result<Option<(String, String, Option<String>)>> {
        let record = self
            .conn()?
            .query_row(sql::ATTEMPT_RECORD, params![attempt_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .optional()
            .map_err(storage)?;
        Ok(record)
    }

    /// The newest unresolved (running or unknown) attempt of a task, if any:
    /// the no-repeat guard for the next dispatch decision.
    pub fn latest_unresolved_attempt(&self, task_id: &TaskId) -> Result<Option<String>> {
        let attempt_id = self
            .conn()?
            .query_row(sql::LATEST_UNRESOLVED_ATTEMPT, params![task_id.0], |row| {
                row.get(0)
            })
            .optional()
            .map_err(storage)?;
        Ok(attempt_id)
    }

    pub fn attempt_running(&mut self, attempt_id: &str) -> Result<()> {
        self.set_attempt_state(attempt_id, "running", None)
    }

    pub fn attempt_confirmed(&mut self, attempt_id: &str) -> Result<()> {
        self.set_attempt_state(attempt_id, "confirmed", None)
    }

    pub fn attempt_rejected(&mut self, attempt_id: &str, detail: &str) -> Result<()> {
        self.set_attempt_state(attempt_id, "rejected", Some(detail))
    }

    pub fn attempt_unknown(&mut self, attempt_id: &str, detail: &str) -> Result<()> {
        self.set_attempt_state(attempt_id, "unknown", Some(detail))
    }

    pub fn goal_bytes(&self, task_id: &TaskId) -> Result<Vec<u8>> {
        let bytes = self
            .conn()?
            .query_row(sql::GOAL_BYTES, params![task_id.0], |row| row.get(0))
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_task(&task_id.0))?;
        Ok(bytes)
    }

    pub fn obligations_count(&self, task_id: &TaskId) -> Result<usize> {
        let count = self
            .conn()?
            .query_row(sql::OBLIGATION_COUNT, params![task_id.0], |row| {
                row.get::<_, i64>(0).map(|v| v as usize)
            })
            .map_err(storage)?;
        Ok(count)
    }

    /// The durable recorded answer for a task: (answer json, author origin).
    pub fn answered_question(&self, task_id: &TaskId) -> Result<Option<(String, String)>> {
        let row = self
            .conn()?
            .query_row(sql::ANSWERED_QUESTION, params![task_id.0], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            })
            .optional()
            .map_err(storage)?;
        Ok(row.and_then(|(answer, origin)| Some((answer?, origin?))))
    }

    /// The origin of the bytes a request of this task carries into the
    /// wire's user channel (AC-009, INV-003). The store owns the journal
    /// vocabulary, so the recorded author is parsed here and no caller
    /// compares the column's text. Only a recorded human answer proves
    /// human authorship — an agent/system turn, an unrecognised spelling
    /// or no answer at all reads as tool text, never as consent.
    pub fn answer_input_origin(&self, task_id: &TaskId) -> Result<InputOrigin> {
        let author = self
            .answered_question(task_id)?
            .map(|(_answer, author)| author);
        Ok(match author.as_deref() {
            Some("human") => InputOrigin::Human,
            Some(_) | None => InputOrigin::Tool,
        })
    }

    pub fn insert_evidence(
        &mut self,
        task_id: &TaskId,
        obligation_index: usize,
        scope: &str,
        observation: &str,
        digest: &str,
    ) -> Result<String> {
        let obligation_id: String = self
            .conn()?
            .query_row(
                sql::OBLIGATION_AT_OFFSET,
                params![task_id.0, obligation_index as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(StoreError::missing_obligation)?;
        let evidence_id = EvidenceId::generate().0;
        self.conn()?
            .execute(
                sql::INSERT_EVIDENCE,
                params![
                    evidence_id,
                    task_id.0,
                    scope,
                    observation,
                    digest,
                    obligation_id
                ],
            )
            .map_err(storage)?;
        self.conn()?
            .execute(sql::SATISFY_OBLIGATION, params![obligation_id])
            .map_err(storage)?;
        Ok(evidence_id)
    }

    /// Inserts the same evidence for every obligation of the task and
    /// satisfies each, in one Immediate transaction.
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when any statement fails.
    pub fn insert_evidence_for_task(
        &mut self,
        task_id: &TaskId,
        scope: &str,
        observation: &str,
        digest: &str,
    ) -> Result<()> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let ids = {
            let mut stmt = tx.prepare(sql::OBLIGATION_IDS_FOR_TASK).map_err(storage)?;
            stmt.query_map(params![task_id.0], |row| row.get(0))
                .map_err(storage)?
                .collect::<std::result::Result<Vec<String>, _>>()
                .map_err(storage)?
        };
        for obligation_id in ids {
            let evidence_id = EvidenceId::generate().0;
            tx.execute(
                sql::INSERT_EVIDENCE,
                params![
                    evidence_id,
                    task_id.0,
                    scope,
                    observation,
                    digest,
                    obligation_id
                ],
            )
            .map_err(storage)?;
            tx.execute(sql::SATISFY_OBLIGATION, params![obligation_id])
                .map_err(storage)?;
        }
        tx.commit().map_err(storage)?;
        Ok(())
    }

    pub fn invalidate_evidence(&mut self, evidence_id: &str) -> Result<String> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let obligation_id: String = tx
            .query_row(sql::STALE_EVIDENCE, params![evidence_id], |row| row.get(0))
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_evidence(evidence_id))?;
        tx.execute(sql::STALE_OBLIGATION, params![obligation_id])
            .map_err(storage)?;
        let task_id: String = tx
            .query_row(sql::TASK_ID_FOR_OBLIGATION, params![obligation_id], |row| {
                row.get(0)
            })
            .map_err(storage)?;
        Self::block_foreign(&tx, &task_id, sql::BLOCK_TASK_NOT_CANCELLED)?;
        tx.commit().map_err(storage)?;
        Ok(task_id)
    }

    /// DEC-068 unknown/error-applicability write: the obligation's
    /// applicability becomes `unresolved` while its execution stays
    /// untouched — the stale-evidence leg (`invalidate_evidence`) keeps
    /// the only `execution='stale'` writer — and the owning task blocks
    /// unless already cancelled. The evaluation that failed is the
    /// task's, so its plan rows go `unresolved` in the same transaction,
    /// their stored blockers untouched. Returns the owning task
    /// id; a `plan:<capability>` id names no task, so it is acknowledged
    /// with `None` — a task with no criterion obligation goes through
    /// [`TaskStore::mark_plan_applicability_unresolved`] instead.
    ///
    /// # Errors
    /// Returns [`StoreError::missing_obligation`] when the obligation
    /// does not exist and [`StoreError::Storage`] when any statement
    /// fails.
    pub fn mark_applicability_unresolved(&mut self, obligation_id: &str) -> Result<Option<String>> {
        if obligation_id.starts_with(PLAN_OBLIGATION_PREFIX) {
            return Ok(None);
        }
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let changed = tx
            .execute(sql::UNRESOLVED_APPLICABILITY, params![obligation_id])
            .map_err(storage)?;
        if changed == 0 {
            return Err(StoreError::missing_obligation());
        }
        let task_id: String = tx
            .query_row(sql::TASK_ID_FOR_OBLIGATION, params![obligation_id], |row| {
                row.get(0)
            })
            .map_err(storage)?;
        Self::unresolve_plan_rows(&tx, &task_id)?;
        Self::block_foreign(&tx, &task_id, sql::BLOCK_TASK_NOT_CANCELLED)?;
        tx.commit().map_err(storage)?;
        Ok(Some(task_id))
    }

    /// The applicability-unknown sentinel for the task itself — the path
    /// a task with zero criteria needs, since a `plan:` id names no task.
    /// One Immediate transaction: every plan row goes `unresolved` with
    /// its stored blocker untouched (the step the criterion cascade
    /// shares), then the plan's lifecycle rule moves a `running` task to
    /// `blocked` as a plan-owned block. A task without a selection has no
    /// plan row, so nothing is written.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] for an unknown task,
    /// [`StoreError::AlreadyTerminal`] for a terminal one (nothing is
    /// written), and [`StoreError::Storage`] when any statement fails.
    pub fn mark_plan_applicability_unresolved(&mut self, task_id: &TaskId) -> Result<()> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        Self::require_open_task(&tx, task_id)?;
        if Self::plan_selection_on(&tx, task_id)?.is_none() {
            return Ok(());
        }
        Self::unresolve_plan_rows(&tx, &task_id.0)?;
        Self::settle_plan_state(&tx, task_id)?;
        tx.commit().map_err(storage)
    }

    /// Every plan row of the task goes `unresolved`; nothing else on the
    /// row changes — its projection names the dependency instead.
    fn unresolve_plan_rows(tx: &rusqlite::Transaction<'_>, task_id: &str) -> Result<()> {
        tx.execute(sql::UNRESOLVE_PLAN_ROWS, params![task_id])
            .map_err(storage)?;
        Ok(())
    }

    pub fn evidence_validity(&self, evidence_id: &str) -> Result<Option<String>> {
        let validity = self
            .conn()?
            .query_row(sql::EVIDENCE_VALIDITY, params![evidence_id], |row| {
                row.get(0)
            })
            .optional()
            .map_err(storage)?;
        Ok(validity)
    }

    /// A dispatch whose receipt was lost blocks the scope until the owner
    /// reconciles it; the snapshot carries an outcome_unknown blocker.
    pub fn mark_outcome_unknown(&mut self, task_id: &TaskId) -> Result<()> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        Self::block_foreign(&tx, &task_id.0, sql::BLOCK_TASK_OPEN)?;
        tx.commit().map_err(storage)
    }

    pub fn mark_no_ready(&mut self, task_id: &TaskId) -> Result<()> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        Self::block_foreign(&tx, &task_id.0, sql::BLOCK_TASK_OPEN)?;
        tx.commit().map_err(storage)
    }

    /// A block the plan did not make. It takes the plan-owned mark with
    /// it in the same transaction, so a later plan resolution can never
    /// erase it — whichever of the two blocks came first.
    fn block_foreign(tx: &rusqlite::Transaction<'_>, task_id: &str, block: &str) -> Result<()> {
        tx.execute(block, params![task_id]).map_err(storage)?;
        tx.execute(sql::CLEAR_PLAN_BLOCK, params![task_id])
            .map_err(storage)?;
        Ok(())
    }

    /// frame_goal contribution: the accepted receipt carries empty
    pub fn materialize_obligations(&mut self, task_id: &TaskId) -> Result<()> {
        let mut stmt = self
            .conn()?
            .prepare(sql::MISSING_OBLIGATIONS)
            .map_err(storage)?;
        let missing: Vec<String> = stmt
            .query_map(params![task_id.0], |row| row.get(0))
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        drop(stmt);
        for criterion_id in missing {
            self.conn()?
                .execute(
                    sql::INSERT_OBLIGATION,
                    params![EvidenceId::generate().0, task_id.0, criterion_id],
                )
                .map_err(storage)?;
        }
        Ok(())
    }

    /// Completion guard (EDGE-001): `completed` requires every criterion's
    /// and no unknown attempt. An empty ready queue never completes a task.
    pub fn complete_if_eligible(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
    ) -> Result<TaskSnapshot> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let lifecycle: String = tx
            .query_row(sql::TASK_LIFECYCLE, params![task_id.0], |row| row.get(0))
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_task(&task_id.0))?;
        if Lifecycle::from_db(&lifecycle).is_terminal() {
            return Err(StoreError::Conflict(ConflictCause::TaskAlreadyTerminal));
        }
        let (unsatisfied, unresolved, unknown): (u64, u64, u64) = tx
            .query_row(sql::COMPLETION_COUNTS, params![task_id.0], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u64,
                ))
            })
            .map_err(storage)?;
        if unsatisfied > 0 || unresolved > 0 || unknown > 0 {
            tx.execute(sql::PAUSE_RUNNING_TASK, params![task_id.0])
                .map_err(storage)?;
            tx.commit().map_err(storage)?;
            return Err(StoreError::Conflict(ConflictCause::CompletionOpen {
                unsatisfied,
                unresolved,
                unknown,
            }));
        }
        let stale: u64 = tx
            .query_row(sql::STALE_EVIDENCE_COUNT, params![task_id.0], |row| {
                row.get::<_, i64>(0).map(|v| v as u64)
            })
            .map_err(storage)?;
        if stale > 0 {
            return Err(StoreError::Conflict(ConflictCause::CompletionStale {
                stale,
            }));
        }
        let revision: u64 = tx
            .query_row(sql::TASK_REVISION, params![task_id.0], |row| {
                row.get::<_, i64>(0).map(|v| v as u64)
            })
            .map_err(storage)?;
        tx.execute(
            sql::COMPLETE_TASK,
            params![task_id.0, (revision + 1) as i64],
        )
        .map_err(storage)?;
        // Same kill as cancel: a pending question cannot outlive the task
        // it was waiting on — the rows die inside this transaction.
        Self::supersede_terminal_questions(&tx, session_id, task_id, "completed", "state")?;
        Self::append_event(
            &tx,
            session_id,
            Some(task_id),
            (&task_id.0, revision + 1),
            "task.completed",
            json!({}),
            "state",
        )?;
        let snapshot = Self::snapshot_in_tx(&tx, task_id)?;
        tx.commit().map_err(storage)?;
        Ok(snapshot)
    }

    // ----- plan selection and plan rows (actions.rs owns the rules) -----

    /// Records one versioned selection in one Immediate transaction.
    /// Identical facts keep the recorded selection and touch only rows
    /// still `unresolved`: a row whose applicability recovered is reset in
    /// place (PG-4), and with nothing to reset nothing is written. Changed
    /// facts bump the revision and rewrite every row, superseding pending
    /// questions named by the replaced selection's plan rows in this same
    /// transaction. Earlier plan revisions stay for audit and never gate
    /// the new selection; the gate hold and plan-owned block settle there.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] for an unknown task,
    /// [`StoreError::AlreadyTerminal`] for a terminal one, and
    /// [`StoreError::Storage`] when any statement fails.
    pub(crate) fn record_plan_selection(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        selection: &PlanSelectionWrite<'_>,
    ) -> Result<PlanSelectionRecord> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        Self::require_open_task(&tx, task_id)?;
        let current = Self::plan_selection_on(&tx, task_id)?;
        if let Some(current) = current
            .as_ref()
            .filter(|current| current.facts_digest == selection.facts_digest)
        {
            if Self::reset_recovered_plan_rows(&tx, task_id, selection.rows)? {
                Self::settle_plan_state(&tx, task_id)?;
                tx.commit().map_err(storage)?;
            }
            return Ok(current.clone());
        }
        let revision = current.as_ref().map_or(1, |current| current.revision + 1);
        if let Some(current) = current.as_ref() {
            Self::supersede_plan_questions(&tx, session_id, task_id, current.revision, revision)?;
        }
        tx.execute(
            sql::UPSERT_PLAN_SELECTION,
            params![
                task_id.0,
                stored_u64(revision)?,
                selection.facts_digest,
                selection.request_kind.as_str()
            ],
        )
        .map_err(storage)?;
        tx.execute(sql::DELETE_PLAN_OBLIGATIONS, params![task_id.0])
            .map_err(storage)?;
        for row in selection.rows {
            let blocker = row.blocker.as_ref().map(blocker_json).transpose()?;
            tx.execute(
                sql::INSERT_PLAN_OBLIGATION,
                params![
                    task_id.0,
                    row.capability,
                    applicability_db(row.applicability),
                    i64::from(row.stage),
                    row.handler,
                    blocker
                ],
            )
            .map_err(storage)?;
        }
        Self::settle_plan_state(&tx, task_id)?;
        tx.commit().map_err(storage)?;
        Ok(PlanSelectionRecord {
            revision,
            facts_digest: selection.facts_digest.to_string(),
            request_kind: selection.request_kind,
        })
    }

    /// PG-4 under identical facts: while any criterion obligation is
    /// still `unresolved`, its cascade keeps every plan row `unresolved`.
    /// Otherwise each stored `unresolved` row the facts decide takes back
    /// its derived applicability in place and nothing else — execution,
    /// outcome and the stored verdict, fork or route blocker stay, so the
    /// release rule sees them hold again. Returns whether any row was
    /// reset.
    fn reset_recovered_plan_rows(
        tx: &rusqlite::Transaction<'_>,
        task_id: &TaskId,
        derived: &[PlanRowWrite<'_>],
    ) -> Result<bool> {
        let cascaded: i64 = tx
            .query_row(sql::UNRESOLVED_OBLIGATIONS, params![task_id.0], |row| {
                row.get(0)
            })
            .map_err(storage)?;
        if cascaded > 0 {
            return Ok(false);
        }
        let mut reset = false;
        for stored in Self::plan_rows_on(tx, task_id)? {
            if stored.applicability != ObligationApplicability::Unresolved {
                continue;
            }
            let Some(recovered) = derived.iter().find(|row| {
                row.capability == stored.capability
                    && row.applicability != ObligationApplicability::Unresolved
            }) else {
                continue;
            };
            tx.execute(
                sql::RESET_PLAN_ROW_APPLICABILITY,
                params![
                    task_id.0,
                    stored.capability,
                    applicability_db(recovered.applicability)
                ],
            )
            .map_err(storage)?;
            reset = true;
        }
        Ok(reset)
    }

    /// The task's current plan selection, if one was recorded.
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when the read fails or the row
    /// carries a value outside the recorded vocabulary.
    pub fn plan_selection(&self, task_id: &TaskId) -> Result<Option<PlanSelectionRecord>> {
        Self::plan_selection_on(self.conn()?, task_id)
    }

    /// The current selection's plan rows in selection order.
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when the read fails or a row
    /// carries a value outside the recorded vocabulary.
    pub fn plan_obligations(&self, task_id: &TaskId) -> Result<Vec<PlanObligationRecord>> {
        Self::plan_rows_on(self.conn()?, task_id)
    }

    /// Every plan revision of the task, oldest first.
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when the read fails or a verdict
    /// is outside the recorded vocabulary.
    pub fn plan_revisions(&self, task_id: &TaskId) -> Result<Vec<PlanRevisionRecord>> {
        let mut stmt = self
            .conn()?
            .prepare_cached(sql::PLAN_REVISIONS_FOR_TASK)
            .map_err(storage)?;
        let stored = stmt
            .query_map(params![task_id.0], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        stored
            .into_iter()
            .map(
                |(revision, selection_revision, body_json, verdict, assessment_json)| {
                    Ok(PlanRevisionRecord {
                        revision: unsigned(revision)?,
                        selection_revision: unsigned(selection_revision)?,
                        body_json,
                        verdict: verdict.as_deref().map(PlanVerdict::from_db).transpose()?,
                        assessment_json,
                    })
                },
            )
            .collect()
    }

    /// Whether execution may start, read in one snapshot of the plan
    /// tables.
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when the plan records cannot be
    /// read or decode.
    pub fn plan_gate(&self, task_id: &TaskId) -> Result<PlanGate> {
        let tx = self.conn()?.unchecked_transaction().map_err(storage)?;
        Self::gate_on(&tx, task_id)
    }

    /// The one plan-row write after the selection: a close or a blocker,
    /// in one Immediate transaction that re-checks the lifecycle (not
    /// terminal), the current selection revision and facts digest, and
    /// that the row's stored handler is the invoking action and the row
    /// is not `unresolved` — any mismatch writes nothing. A close clears
    /// the row's blocker. The
    /// gate hold and the plan-owned block settle in the same transaction.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] for an unknown task,
    /// [`StoreError::AlreadyTerminal`] for a terminal one,
    /// [`ConflictCause::PlanSelectionMissing`]/[`ConflictCause::PlanSelectionStale`]
    /// for facts that are not the current selection's,
    /// [`ConflictCause::PlanRowMissing`]/[`ConflictCause::PlanRowHandler`]
    /// for a row the handler does not own,
    /// [`ConflictCause::PlanRowUnresolved`] for any change to a row still
    /// waiting on its applicability, and [`StoreError::Storage`] when any
    /// statement fails.
    pub fn update_plan_row(&mut self, task_id: &TaskId, update: &PlanRowUpdate<'_>) -> Result<()> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        Self::check_plan_binding(&tx, task_id, update.selection_revision, update.facts_digest)?;
        Self::apply_plan_row_change(
            &tx,
            task_id,
            update.capability,
            update.handler,
            &update.change,
        )?;
        Self::settle_plan_state(&tx, task_id)?;
        tx.commit().map_err(storage)
    }

    /// Records the next plan revision under the current selection,
    /// closes the handler's row and reopens every required row
    /// `revision.reopens` closed — all in one transaction, so a failure
    /// anywhere leaves no new revision and a changed plan is never
    /// covered by the verdict on the plan it replaced. Returns the new
    /// revision.
    ///
    /// # Errors
    /// The [`TaskStore::update_plan_row`] refusals, and
    /// [`StoreError::Storage`] when any statement fails.
    pub(crate) fn record_plan_revision(
        &mut self,
        task_id: &TaskId,
        revision: &PlanRevisionWrite<'_>,
    ) -> Result<u64> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        Self::check_plan_binding(
            &tx,
            task_id,
            revision.selection_revision,
            revision.facts_digest,
        )?;
        let next: i64 = tx
            .query_row(sql::NEXT_PLAN_REVISION, params![task_id.0], |row| {
                row.get(0)
            })
            .map_err(storage)?;
        let plan_revision = unsigned(next)?;
        tx.execute(
            sql::INSERT_PLAN_REVISION,
            params![
                task_id.0,
                next,
                stored_u64(revision.selection_revision)?,
                revision.body_json
            ],
        )
        .map_err(storage)?;
        let close = PlanRowChange::Close {
            execution: ObligationExecution::Satisfied,
            outcome_json: json!({ "revision": plan_revision }).to_string(),
        };
        Self::apply_plan_row_change(&tx, task_id, revision.handler, revision.handler, &close)?;
        tx.execute(
            sql::REOPEN_PLAN_ROWS_BY_HANDLER,
            params![task_id.0, revision.reopens],
        )
        .map_err(storage)?;
        Self::settle_plan_state(&tx, task_id)?;
        tx.commit().map_err(storage)?;
        Ok(plan_revision)
    }

    /// Binds a mechanical verdict to the latest, still-unjudged plan
    /// revision of the current selection and applies the assessor's row
    /// changes, in one transaction.
    ///
    /// # Errors
    /// [`ConflictCause::PlanNotAssessable`] when the revision is
    /// superseded, already judged, or of an earlier selection; the
    /// [`TaskStore::update_plan_row`] refusals; and
    /// [`StoreError::Storage`] when any statement fails.
    pub fn record_plan_assessment(
        &mut self,
        task_id: &TaskId,
        assessment: &PlanAssessmentWrite<'_>,
    ) -> Result<()> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        Self::check_plan_binding(
            &tx,
            task_id,
            assessment.selection_revision,
            assessment.facts_digest,
        )?;
        let changed = tx
            .execute(
                sql::ASSESS_PLAN_REVISION,
                params![
                    task_id.0,
                    stored_u64(assessment.plan_revision)?,
                    stored_u64(assessment.selection_revision)?,
                    assessment.verdict.as_str(),
                    assessment.assessment_json
                ],
            )
            .map_err(storage)?;
        if changed == 0 {
            return Err(StoreError::Conflict(ConflictCause::PlanNotAssessable {
                revision: assessment.plan_revision,
            }));
        }
        for (capability, change) in &assessment.changes {
            Self::apply_plan_row_change(&tx, task_id, capability, assessment.handler, change)?;
        }
        Self::settle_plan_state(&tx, task_id)?;
        tx.commit().map_err(storage)
    }

    /// Persists the gate hold a refused non-read effect raises. The gate
    /// is re-read inside the transaction: an `Open` gate records no hold
    /// and reports `None`. Otherwise one hold per task is kept —
    /// idempotent per kind, an `Unassessed` hold turning `Paused` once a
    /// selection exists — and a `running` task moves to `blocked` as a
    /// plan-owned block. Returns the hold as recorded.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] for an unknown task,
    /// [`StoreError::AlreadyTerminal`] for a terminal one (nothing is
    /// persisted), and [`StoreError::Storage`] when any statement fails.
    pub fn hold_for_plan_gate(
        &mut self,
        task_id: &TaskId,
        observed: PlanGateHold,
    ) -> Result<Option<PlanGateHold>> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        Self::require_open_task(&tx, task_id)?;
        if Self::gate_on(&tx, task_id)? != PlanGate::Open {
            tx.execute(
                sql::UPSERT_PLAN_GATE_HOLD,
                params![task_id.0, observed.as_str()],
            )
            .map_err(storage)?;
        }
        Self::settle_plan_state(&tx, task_id)?;
        let held = Self::gate_hold_on(&tx, task_id)?;
        tx.commit().map_err(storage)?;
        Ok(held)
    }

    /// Plan writes name a live task: an unknown task has nothing to plan
    /// and a terminal one can never execute the plan.
    fn require_open_task(tx: &rusqlite::Transaction<'_>, task_id: &TaskId) -> Result<()> {
        let lifecycle: String = tx
            .query_row(sql::TASK_LIFECYCLE, params![task_id.0], |row| row.get(0))
            .optional()
            .map_err(storage)?
            .ok_or_else(|| StoreError::missing_task(&task_id.0))?;
        if Lifecycle::from_db(&lifecycle).is_terminal() {
            return Err(StoreError::AlreadyTerminal);
        }
        Ok(())
    }

    /// Facts bound to anything but the current selection close nothing.
    fn check_plan_binding(
        tx: &rusqlite::Transaction<'_>,
        task_id: &TaskId,
        selection_revision: u64,
        facts_digest: &str,
    ) -> Result<()> {
        Self::require_open_task(tx, task_id)?;
        let current = Self::plan_selection_on(tx, task_id)?
            .ok_or(StoreError::Conflict(ConflictCause::PlanSelectionMissing))?;
        if current.revision != selection_revision || current.facts_digest != facts_digest {
            return Err(StoreError::Conflict(ConflictCause::PlanSelectionStale {
                revision: current.revision,
            }));
        }
        Ok(())
    }

    /// One row change after the row's owner is checked: only the stored
    /// handler writes its row, and an unresolved row takes no handler
    /// write at all — only a re-selection decides its applicability, so a
    /// handler holding the current revision never clears unknown
    /// applicability (D-073).
    fn apply_plan_row_change(
        tx: &rusqlite::Transaction<'_>,
        task_id: &TaskId,
        capability: &str,
        handler: &str,
        change: &PlanRowChange,
    ) -> Result<()> {
        let (applicability, stored_handler): (String, Option<String>) = tx
            .query_row(sql::PLAN_ROW, params![task_id.0, capability], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()
            .map_err(storage)?
            .ok_or_else(|| {
                StoreError::Conflict(ConflictCause::PlanRowMissing {
                    capability: capability.to_string(),
                })
            })?;
        if stored_handler.as_deref() != Some(handler) {
            return Err(StoreError::Conflict(ConflictCause::PlanRowHandler {
                capability: capability.to_string(),
                handler: handler.to_string(),
            }));
        }
        if applicability_from_db(&applicability)? == ObligationApplicability::Unresolved {
            return Err(StoreError::Conflict(ConflictCause::PlanRowUnresolved {
                capability: capability.to_string(),
            }));
        }
        match change {
            PlanRowChange::Close {
                execution,
                outcome_json,
            } => {
                tx.execute(
                    sql::CLOSE_PLAN_ROW,
                    params![
                        task_id.0,
                        capability,
                        execution_db(*execution),
                        outcome_json
                    ],
                )
                .map_err(storage)?;
            }
            PlanRowChange::Block(blocker) => {
                tx.execute(
                    sql::BLOCK_PLAN_ROW,
                    params![task_id.0, capability, blocker_json(blocker)?],
                )
                .map_err(storage)?;
            }
        }
        Ok(())
    }

    /// Brings the gate hold and the plan-owned block in line with the
    /// plan tables after a plan write: an opened gate drops its hold, a
    /// closed gate names its current kind — an `Unassessed` hold turns
    /// `Paused` once a selection exists — then the lifecycle rule
    /// applies.
    fn settle_plan_state(tx: &rusqlite::Transaction<'_>, task_id: &TaskId) -> Result<()> {
        if let Some(hold) = Self::gate_hold_on(tx, task_id)? {
            match Self::gate_on(tx, task_id)? {
                PlanGate::Open => {
                    tx.execute(sql::DELETE_PLAN_GATE_HOLD, params![task_id.0])
                        .map_err(storage)?;
                }
                gate => {
                    let kind = if gate == PlanGate::Unassessed {
                        PlanGateHold::Unassessed
                    } else {
                        PlanGateHold::Paused
                    };
                    if kind != hold {
                        tx.execute(
                            sql::UPSERT_PLAN_GATE_HOLD,
                            params![task_id.0, kind.as_str()],
                        )
                        .map_err(storage)?;
                    }
                }
            }
        }
        Self::settle_plan_lifecycle(tx, task_id)
    }

    /// The plan's lifecycle rule. A `running` task held by a plan row or a
    /// gate hold moves to `blocked`, marked plan-owned. A `blocked` task
    /// returns to `running` only when the plan made that block and nothing
    /// holds it any more — no holding plan row or gate hold, no unresolved
    /// criterion obligation, no unknown attempt, no pending question. A
    /// waiting or terminal task never flips.
    fn settle_plan_lifecycle(tx: &rusqlite::Transaction<'_>, task_id: &TaskId) -> Result<()> {
        let lifecycle: String = tx
            .query_row(sql::TASK_LIFECYCLE, params![task_id.0], |row| row.get(0))
            .map_err(storage)?;
        let held =
            Self::gate_hold_on(tx, task_id)?.is_some() || Self::plan_row_holds_on(tx, task_id)?;
        match lifecycle.as_str() {
            "running" if held => {
                tx.execute(sql::PLAN_BLOCK_RUNNING_TASK, params![task_id.0])
                    .map_err(storage)?;
                tx.execute(sql::MARK_PLAN_BLOCK, params![task_id.0])
                    .map_err(storage)?;
            }
            "blocked" if !held => Self::release_plan_owned_block(tx, task_id)?,
            _ => {}
        }
        Ok(())
    }

    /// Returns a `blocked` task to `running` when the plan made the block
    /// and no other source holds it: no unresolved criterion obligation,
    /// no unknown attempt, no pending question.
    fn release_plan_owned_block(tx: &rusqlite::Transaction<'_>, task_id: &TaskId) -> Result<()> {
        let plan_owned: bool = tx
            .query_row(sql::PLAN_BLOCK_EXISTS, params![task_id.0], |row| row.get(0))
            .map_err(storage)?;
        let other_sources: i64 = tx
            .query_row(
                sql::PLAN_RELEASE_BLOCKING_SOURCES,
                params![task_id.0],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if plan_owned && other_sources == 0 {
            tx.execute(sql::PLAN_RELEASE_TASK, params![task_id.0])
                .map_err(storage)?;
            tx.execute(sql::CLEAR_PLAN_BLOCK, params![task_id.0])
                .map_err(storage)?;
        }
        Ok(())
    }

    /// Whether any plan row holds the lifecycle.
    fn plan_row_holds_on(conn: &Connection, task_id: &TaskId) -> Result<bool> {
        Ok(Self::plan_rows_on(conn, task_id)?
            .iter()
            .any(PlanObligationRecord::holds_lifecycle))
    }

    fn gate_hold_on(conn: &Connection, task_id: &TaskId) -> Result<Option<PlanGateHold>> {
        conn.query_row(sql::PLAN_GATE_HOLD, params![task_id.0], |row| {
            row.get::<_, String>(0)
        })
        .optional()
        .map_err(storage)?
        .as_deref()
        .map(PlanGateHold::from_db)
        .transpose()
    }

    fn plan_selection_on(
        conn: &Connection,
        task_id: &TaskId,
    ) -> Result<Option<PlanSelectionRecord>> {
        let stored = conn
            .query_row(sql::PLAN_SELECTION, params![task_id.0], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .optional()
            .map_err(storage)?;
        stored
            .map(|(revision, facts_digest, request_kind)| {
                Ok(PlanSelectionRecord {
                    revision: unsigned(revision)?,
                    facts_digest,
                    request_kind: RequestKind::from_db(&request_kind)?,
                })
            })
            .transpose()
    }

    fn plan_rows_on(conn: &Connection, task_id: &TaskId) -> Result<Vec<PlanObligationRecord>> {
        let stored = conn
            .prepare_cached(sql::PLAN_OBLIGATIONS_FOR_TASK)
            .map_err(storage)?
            .query_map(params![task_id.0], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            })
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        stored
            .into_iter()
            .map(
                |(capability, applicability, execution, stage, handler, blocker, outcome_json)| {
                    Ok(PlanObligationRecord {
                        capability,
                        applicability: applicability_from_db(&applicability)?,
                        execution: execution_from_db(&execution)?,
                        stage: stage_from_db(stage)?,
                        handler,
                        blocker: blocker.as_deref().map(blocker_from_db).transpose()?,
                        outcome_json,
                    })
                },
            )
            .collect()
    }

    /// The gate rule (DEC-035/039): no selection is `Unassessed`, never
    /// `Open`. With a selection the gate opens when no row of either
    /// phase waits on its applicability, every required plan-phase row is
    /// satisfied and — only when `plan_work` is a required row of this
    /// selection — the latest plan revision recorded under it passed.
    /// Execution-phase rows never gate: they follow the effect this gate
    /// admits.
    fn gate_on(conn: &Connection, task_id: &TaskId) -> Result<PlanGate> {
        let Some(selection) = Self::plan_selection_on(conn, task_id)? else {
            return Ok(PlanGate::Unassessed);
        };
        let rows = Self::plan_rows_on(conn, task_id)?;
        let unresolved: Vec<String> = rows
            .iter()
            .filter(|row| row.applicability == ObligationApplicability::Unresolved)
            .map(|row| row.capability.clone())
            .collect();
        let mut open_stages: Vec<String> = rows
            .iter()
            .filter(|row| {
                row.stage
                    && row.applicability == ObligationApplicability::Required
                    && row.execution != ObligationExecution::Satisfied
            })
            .map(|row| row.capability.clone())
            .collect();
        let plan_required = rows.iter().any(|row| {
            row.capability == crate::actions::PLAN_WORK
                && row.applicability == ObligationApplicability::Required
        });
        if plan_required {
            let verdict = conn
                .query_row(
                    sql::LATEST_PLAN_VERDICT_FOR_SELECTION,
                    params![task_id.0, stored_u64(selection.revision)?],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .map_err(storage)?
                .flatten();
            let passed = verdict.as_deref().map(PlanVerdict::from_db).transpose()?
                == Some(PlanVerdict::Pass);
            if !passed
                && !open_stages
                    .iter()
                    .any(|stage| stage == crate::actions::ASSESS_PLAN)
            {
                open_stages.push(crate::actions::ASSESS_PLAN.to_string());
            }
        }
        if unresolved.is_empty() && open_stages.is_empty() {
            Ok(PlanGate::Open)
        } else {
            Ok(PlanGate::Paused {
                unresolved,
                open_stages,
            })
        }
    }

    /// Plan blockers of a page of tasks in one statement: each row's
    /// stored `Blocker` verbatim — an `unresolved` row projects its one
    /// `dependency_blocked` in its place (D-076) — then the gate hold.
    fn plan_blockers_on(
        conn: &Connection,
        task_ids: &[String],
    ) -> Result<BTreeMap<String, Vec<Blocker>>> {
        let mut blockers = BTreeMap::<String, Vec<Blocker>>::new();
        if task_ids.is_empty() {
            return Ok(blockers);
        }
        let statement = sql::plan_blockers_for_tasks(task_ids.len());
        let mut stmt = conn.prepare(&statement).map_err(storage)?;
        let stored = stmt
            .query_map(params_from_iter(task_ids.iter()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        for (task_id, capability, applicability, row_blocker, hold) in stored {
            let blocker = match (capability, applicability, row_blocker, hold) {
                (Some(capability), Some(applicability), row_blocker, None) => {
                    let kept = row_blocker.as_deref().map(blocker_from_db).transpose()?;
                    if applicability_from_db(&applicability)? == ObligationApplicability::Unresolved
                    {
                        plan_blocker(ErrorCode::DependencyBlocked, &capability)
                    } else {
                        kept.ok_or_else(|| corrupt_column("plan blocker source", &task_id))?
                    }
                }
                (None, None, None, Some(kind)) => PlanGateHold::from_db(&kind)?.blocker(),
                _ => return Err(corrupt_column("plan blocker source", &task_id)),
            };
            blockers.entry(task_id).or_default().push(blocker);
        }
        Ok(blockers)
    }

    // ----- index snapshot generations (index.rs owns the rows) -----

    /// Reserves the next generation number. The reserved row is
    /// `stale`/`interrupted` and unsealed, so a build that never reaches
    /// [`TaskStore::seal_index_generation`] leaves a row that reads as
    /// broken rather than current (INV-007).
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when the generation cannot be
    /// reserved.
    pub fn reserve_index_generation(&mut self) -> Result<u64> {
        let tx = self.conn_mut()?.transaction().map_err(storage)?;
        let generation: u64 = tx
            .query_row(sql::NEXT_INDEX_GENERATION, [], |row| row.get::<_, i64>(0))
            .map_err(storage)
            .and_then(unsigned)
            .map_err(storage)?;
        tx.execute(sql::RESERVE_INDEX_GENERATION, params![generation as i64])
            .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(generation)
    }

    /// Seals one reserved generation: its state, coverage and unresolved
    /// specifiers, then its edges, and in the same transaction the
    /// generation it replaces stops being current. What `policy` keeps
    /// from the replaced generation is stated by the policy rather than
    /// inferred, so the merge, the seal and the supersession commit
    /// together — a reader never sees a half-written generation, and
    /// never sees two generations both claiming to be current (INV-007).
    /// Retention keeps the newest [`INDEX_GENERATION_RETENTION`]
    /// generations.
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when the generation is unknown or
    /// any write fails.
    pub fn seal_index_generation(
        &mut self,
        generation: u64,
        policy: CarryPolicy<'_>,
        state: GenerationState,
        graph: &ProjectGraph,
    ) -> Result<()> {
        let replaced: &[PathBuf] = match policy {
            CarryPolicy::Full | CarryPolicy::Nothing => &[],
            CarryPolicy::Narrowed { replaced } => replaced,
        };
        let tx = self.conn_mut()?.transaction().map_err(storage)?;
        let previous = tx
            .query_row(
                sql::PREVIOUS_INDEX_GENERATION,
                params![generation as i64],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(storage)?
            .map(unsigned)
            .transpose()
            .map_err(storage)?;
        // `Nothing` still names the generation it supersedes; it just
        // reads none of its rows.
        let carry_from = matches!(policy, CarryPolicy::Narrowed { .. });
        let mut carried: Vec<IndexEdge> = Vec::new();
        if carry_from && let Some(previous) = previous {
            let sql =
                sql::INDEX_EDGES_TO_CARRY.replace("{}", &path_placeholders(2, replaced.len()));
            let mut stmt = tx.prepare(&sql).map_err(storage)?;
            // The generation and the replaced paths are heterogeneous bind
            // values, so they travel as the connection's own value type.
            let carried_params = params_from_iter(
                std::iter::once(SqlValue::Integer(previous as i64)).chain(
                    replaced
                        .iter()
                        .map(|path| SqlValue::Text(path.to_string_lossy().into_owned())),
                ),
            );
            carried = stmt
                .query_map(carried_params, edge_from_row)
                .map_err(storage)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(storage)?
                .into_iter()
                .map(StoredEdge::decode)
                .collect::<Result<Vec<_>>>()?;
        }
        let coverage = serde_json::to_string(&graph.completeness).map_err(storage)?;
        let unresolved = serde_json::to_string(&graph.unresolved).map_err(storage)?;
        tx.execute(
            sql::SEAL_INDEX_GENERATION,
            params![
                generation as i64,
                state.as_stored(),
                stale_cause_of(state),
                coverage,
                unresolved,
            ],
        )
        .map_err(storage)?;
        for edge in carried.iter().chain(graph.edges.iter()) {
            write_edge(&tx, generation, edge)?;
        }
        // The indexed file set is written with the rows: it is the
        // record of what this generation was cut from, and a later cut
        // reads it to decide whether its own narrowing is sound.
        for document in &graph.documents {
            tx.execute(
                sql::INSERT_INDEX_DOCUMENT,
                params![generation as i64, document.to_string_lossy()],
            )
            .map_err(storage)?;
        }
        // The generation this one replaces stops being current in the
        // same commit. A row that already carries a more specific cause
        // keeps it, so a watcher-disclosed `watcher_missed` is not
        // overwritten by the weaker "a newer generation exists".
        if let Some(previous) = previous {
            tx.execute(sql::SUPERSEDE_INDEX_GENERATION, params![previous as i64])
                .map_err(storage)?;
        }
        tx.execute_batch(&sql::prune_index_generations(INDEX_GENERATION_RETENTION))
            .map_err(storage)?;
        tx.commit().map_err(storage)
    }

    /// One generation's stored state and derived graph, or `None` when
    /// retention has already retired the number. A `SnapshotId` is
    /// never reissued, so a retired generation is reported absent
    /// rather than answered with another generation's rows.
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when the row carries a value
    /// outside the recorded vocabulary or a column cannot be decoded.
    pub fn index_graph(&self, generation: u64) -> Result<Option<IndexGeneration>> {
        let tx = self.conn()?.unchecked_transaction().map_err(storage)?;
        let stored = tx
            .query_row(
                sql::INDEX_GENERATION_ROW,
                params![generation as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?;
        let Some((state, cause, coverage_json, unresolved_json, sealed)) = stored else {
            return Ok(None);
        };
        let state = generation_state(state, cause.as_deref(), sealed == 1)?;
        let documents = {
            let mut stmt = tx
                .prepare_cached(sql::INDEX_DOCUMENTS_FOR_GENERATION)
                .map_err(storage)?;
            let rows = stmt
                .query_map(params![generation as i64], |row| row.get::<_, String>(0))
                .map_err(storage)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(storage)?;
            rows.into_iter().map(PathBuf::from).collect()
        };
        let mut stmt = tx
            .prepare_cached(sql::INDEX_EDGES_FOR_GENERATION)
            .map_err(storage)?;
        let edges = stmt
            .query_map(params![generation as i64], edge_from_row)
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?
            .into_iter()
            .map(StoredEdge::decode)
            .collect::<Result<Vec<_>>>()?;
        let graph = ProjectGraph {
            edges,
            completeness: serde_json::from_str(&coverage_json).map_err(storage)?,
            unresolved: serde_json::from_str(&unresolved_json).map_err(storage)?,
            // Which documents a past cut re-derived is not a fact the
            // rows keep; the field is the answer's own provenance and a
            // read-back reports no narrowing.
            narrowed_to: Vec::new(),
            documents,
        };
        Ok(Some(IndexGeneration {
            generation,
            state,
            graph,
        }))
    }

    /// The newest generation number, or `None` when none was ever cut.
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when the read fails.
    pub fn latest_index_generation(&self) -> Result<Option<u64>> {
        let stored = self
            .conn()?
            .query_row(sql::LATEST_INDEX_GENERATION, [], |row| row.get::<_, i64>(0))
            .optional()
            .map_err(storage)?;
        stored.map(unsigned).transpose().map_err(storage)
    }

    /// The newest generation's state, read in one statement — so a
    /// report never reads "nothing was cut" because a cut landed between
    /// two reads. `None` when no generation was ever cut.
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when the read fails or a value is
    /// outside the recorded vocabulary.
    pub fn latest_index_state(&self) -> Result<Option<(u64, GenerationState)>> {
        let stored = self
            .conn()?
            .query_row(sql::LATEST_INDEX_STATE, [], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .optional()
            .map_err(storage)?;
        stored
            .map(|(generation, state, cause, sealed)| {
                Ok((
                    unsigned(generation)?,
                    generation_state(state, cause.as_deref(), sealed == 1)?,
                ))
            })
            .transpose()
    }

    /// Marks one generation stale with its cause, so a reader that finds
    /// it knows the graph needs a repair instead of taking its rows as
    /// current. The coverage and unresolved specifiers the build
    /// observed are kept: a generation that failed for one reason is
    /// still the record of what the rest of the project showed, and
    /// overwriting them would report `Complete` over a partial row set.
    /// A fresh generation is marked like any other — a project that
    /// moved under one is precisely what must stop reading as current.
    /// `false` means the number is unknown and nothing was written.
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when the write fails.
    pub fn mark_index_generation_stale(
        &mut self,
        generation: u64,
        cause: StaleCause,
    ) -> Result<bool> {
        let changed = self
            .conn()?
            .execute(
                sql::MARK_INDEX_GENERATION_STALE,
                params![
                    generation as i64,
                    GenerationState::Stale { cause }.as_stored(),
                    cause_name(cause),
                ],
            )
            .map_err(storage)?;
        Ok(changed > 0)
    }

    // ----- retained records -----

    fn retain_once(connection: &Connection, record_json: &str, boundary_id: &str) -> Result<()> {
        proof::insert(record_json);
        let inserted = connection
            .execute(sql::INSERT_RETAINED_ONCE, params![boundary_id, record_json])
            .map_err(storage)?;
        if inserted > 0 {
            return Ok(());
        }
        let existing: String = connection
            .query_row(sql::RETAINED_BY_ID, params![boundary_id], |row| row.get(0))
            .map_err(storage)?;
        if existing == record_json {
            return Ok(());
        }
        Err(StoreError::Conflict(
            ConflictCause::RetainedBoundaryCollision {
                boundary_id: boundary_id.to_string(),
            },
        ))
    }

    pub fn record_assumption(
        &mut self,
        record: &AssumptionCheckRecord,
        retained: Option<&RetainedAttempt>,
    ) -> Result<()> {
        let record_json = serde_json::to_string(record).map_err(storage)?;
        let retained_json = retained
            .map(serde_json::to_string)
            .transpose()
            .map_err(storage)?;
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let task_exists: bool = tx
            .query_row(
                sql::ASSUMPTION_TASK_IN_SESSION,
                params![record.session_id.0, record.task_id.0],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if !task_exists {
            return Err(StoreError::missing_task(record.task_id.0.clone()));
        }
        let changed = tx
            .execute(
                sql::RECORD_ASSUMPTION_CHECK,
                params![
                    record.session_id.0,
                    record.task_id.0,
                    record.check_id,
                    record.expected_result.as_str(),
                    record.assertion_digest,
                    ASSUMPTION_RECORD_VERSION,
                    record_json,
                ],
            )
            .map_err(storage)?;
        if changed == 0 {
            return Err(StoreError::Conflict(ConflictCause::AssumptionCheckChanged));
        }
        if let (Some(retained), Some(retained_json)) = (retained, retained_json) {
            if record.boundary_id.as_deref() != Some(retained.boundary_id.as_str()) {
                return Err(StoreError::Conflict(
                    ConflictCause::RetainedBoundaryCollision {
                        boundary_id: retained.boundary_id.clone(),
                    },
                ));
            }
            Self::retain_once(&tx, &retained_json, &retained.boundary_id)?;
        }
        tx.commit().map_err(storage)
    }

    pub fn assumption_check(
        &self,
        session_id: &SessionId,
        task_id: &TaskId,
        check_id: &str,
    ) -> Result<Option<AssumptionCheckRecord>> {
        let row: Option<(i64, String)> = self
            .conn()?
            .query_row(
                sql::ASSUMPTION_CHECK_BY_ID,
                params![session_id.0, task_id.0, check_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage)?;
        let Some((record_version, record_json)) = row else {
            return Ok(None);
        };
        if record_version != ASSUMPTION_RECORD_VERSION {
            return Err(storage(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported assumption record version",
            )));
        }
        let record: AssumptionCheckRecord = serde_json::from_str(&record_json).map_err(storage)?;
        if record.session_id != *session_id
            || record.task_id != *task_id
            || record.check_id != check_id
        {
            return Err(storage(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "assumption record identity mismatch",
            )));
        }
        Ok(Some(record))
    }

    pub fn retain(&mut self, record_json: &str, boundary_id: &str) -> Result<()> {
        Self::retain_once(self.conn()?, record_json, boundary_id)
    }

    /// One retained-attempt write. The collision check reads BOTH keys
    /// of the row — the direct boundary and its terminal twin — so a
    /// conflicting row at either key is a typed conflict: an identical
    /// row at the other key can never hide it (the single-row
    /// terminal-first read did). Identical rows at both keys stay
    /// idempotent; the held record is never rebuilt here.
    pub fn retain_attempt(&mut self, attempt: &RetainedAttempt) -> Result<()> {
        proof::used(attempt);
        let record_json = serde_json::to_string(attempt).map_err(storage)?;
        let terminal_boundary_id = crate::verification::terminal_boundary_id(&attempt.boundary_id);
        let conn = self.conn()?;
        let mut seen = false;
        let mut statement = conn
            .prepare_cached(sql::RETAINED_BY_BOTH_KEYS)
            .map_err(storage)?;
        let mut rows = statement
            .query(params![&terminal_boundary_id, &attempt.boundary_id])
            .map_err(storage)?;
        while let Some(row) = rows.next().map_err(storage)? {
            seen = true;
            let previous_json: String = row.get(0).map_err(storage)?;
            if previous_json != record_json {
                return Err(StoreError::Conflict(
                    ConflictCause::RetainedBoundaryCollision {
                        boundary_id: attempt.boundary_id.clone(),
                    },
                ));
            }
        }
        drop(rows);
        drop(statement);
        if seen {
            return Ok(());
        }
        self.retain(&record_json, &attempt.boundary_id)
    }

    /// Every retained check row of one attempt, parsed as the record
    /// shape [`RetainedAttempt`]. The one expected non-record row — the
    /// first-only `admit.claim` history marker, a different record
    /// shape by design — is skipped by its boundary; any other
    /// unparseable row is a storage fault, never a guess.
    pub(crate) fn retained_check_rows(&self, attempt_id: &str) -> Result<Vec<RetainedAttempt>> {
        let lower = check_boundary(attempt_id, "");
        let upper = format!("ret:check:{attempt_id};");
        let conn = self.conn()?;
        let mut statement = conn
            .prepare_cached(sql::CHECK_RETAINED_ROWS)
            .map_err(storage)?;
        let rows = statement
            .query_map(params![&lower, &upper], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        drop(statement);
        let marker_boundary = check_boundary(attempt_id, "admit.claim");
        let mut records = Vec::new();
        for (boundary, json) in rows {
            if boundary == marker_boundary {
                continue;
            }
            let record: RetainedAttempt = serde_json::from_str(&json).map_err(|source| {
                storage(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("corrupt retained row at {boundary}: {source}"),
                ))
            })?;
            records.push(record);
        }
        Ok(records)
    }

    pub fn retained(&self, boundary_id: &str) -> Result<Option<String>> {
        let terminal_boundary_id = crate::verification::terminal_boundary_id(boundary_id);
        let record = self
            .conn()?
            .query_row(
                sql::RETAINED_LATEST_BY_ID,
                params![terminal_boundary_id, boundary_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        Ok(record)
    }

    pub fn has_retained(&self, boundary_id: &str) -> Result<bool> {
        self.conn()?
            .query_row(sql::EXISTS_RETAINED, params![boundary_id], |row| row.get(0))
            .map_err(storage)
    }

    /// Whether a retained row exists at either key of this boundary:
    /// the direct id or its terminal twin. Reads both through the
    /// existing dual-key statement — no new SQL text, no write.
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when the read fails.
    pub(crate) fn has_retained_either_key(&self, boundary_id: &str) -> Result<bool> {
        let terminal = crate::verification::terminal_boundary_id(boundary_id);
        let record: Option<String> = self
            .conn()?
            .query_row(
                sql::RETAINED_BY_BOTH_KEYS,
                params![terminal, boundary_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        Ok(record.is_some())
    }

    /// Every check attempt whose first-only dispatch claim marker is
    /// durable (DEC-047): the Runtime-open recovery reconcile reads
    /// this one view and decides settlement vs cleanup-resume from the
    /// durable rows alone — the volatile ledger state string is not
    /// part of that decision.
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when the read fails.
    pub(crate) fn claimed_check_attempts(&mut self) -> Result<Vec<String>> {
        let attempts = self
            .conn()?
            .prepare_cached(sql::CHECK_CLAIMED_ATTEMPTS)
            .map_err(storage)?
            .query_map(params!["ret:check:"], |row| row.get(0))
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?;
        Ok(attempts)
    }

    // ----- supervisor reaction journal (supervisor.rs owns the reaction) -----

    /// Appends one supervisor detector firing to the task's durable
    /// reaction journal: one row per firing, carrying the stall cause
    /// and the class limits/cooldown in force (INV-027).
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when serialization or the insert
    /// fails.
    pub fn record_supervisor_reaction(
        &mut self,
        reaction: &crate::supervisor::Reaction,
    ) -> Result<()> {
        let reaction_json = serde_json::to_string(reaction).map_err(storage)?;
        self.conn()?
            .execute(
                sql::INSERT_SUPERVISOR_REACTION,
                params![reaction.task.0, reaction_json],
            )
            .map_err(storage)?;
        Ok(())
    }

    /// Paged retrieval of one task's supervisor reactions, oldest first:
    /// `limit + 1` rows are fetched so `has_more` never hides a row, and
    /// a malformed journal row fails instead of guessing a cause.
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when the query or a reaction row's
    /// JSON fails to parse.
    pub fn supervisor_reactions(
        &self,
        task_id: &TaskId,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<crate::supervisor::Reaction>, bool)> {
        let mut stmt = self
            .conn()?
            .prepare(sql::SUPERVISOR_REACTIONS_PAGE)
            .map_err(storage)?;
        let rows = stmt
            .query_map(
                params![task_id.0, i64::from(limit) + 1, i64::from(offset)],
                |row| row.get::<_, String>(0),
            )
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        drop(stmt);
        let has_more = rows.len() > limit as usize;
        let mut rows = rows;
        rows.truncate(limit as usize);
        let reactions = rows
            .iter()
            .map(|json| serde_json::from_str(json).map_err(storage))
            .collect::<Result<Vec<_>>>()?;
        Ok((reactions, has_more))
    }

    // ----- config publication journal (config.rs owns the intent) -----

    /// Appends one publication intent and returns its admission sequence.
    /// The counter is scoped to the target so concurrent intents on one
    /// target draw from the same sequence: admission order, never owner
    /// spelling, decides selection later (EDGE-009).
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when the transaction or either
    /// statement fails.
    pub fn append_publication(
        &mut self,
        owner: &str,
        target: &str,
        intended_digest: &str,
        base_digest: Option<&str>,
        identity: Option<WriteIdentity>,
    ) -> Result<u64> {
        let identity = identity.as_ref().map(encode_publish_identity);
        let tx = self.conn_mut()?.transaction().map_err(storage)?;
        let admission_seq: u64 = tx
            .query_row(sql::NEXT_PUBLICATION_SEQ, params![target], |row| {
                row.get::<_, i64>(0).map(|value| value as u64)
            })
            .map_err(storage)?;
        tx.execute(
            sql::INSERT_PUBLICATION,
            params![
                owner,
                target,
                admission_seq as i64,
                intended_digest,
                base_digest,
                identity
            ],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(admission_seq)
    }

    /// Pending intents in `(target, admission_seq)` order — admission
    /// order per target. The journal key stays `(owner, target,
    /// admission_seq)`; owner spelling (a UUID) decides selection only
    /// for rows journaled before the per-target counter — its legacy
    /// per-(owner, target) sequence could tie across owners. Every row
    /// this build writes has a unique `(target, admission_seq)`.
    pub fn pending_publications(&self) -> Result<Vec<crate::config::PublicationIntent>> {
        self.publications(sql::PENDING_PUBLICATIONS)
    }

    /// Applied intents in `(target, admission_seq)` order — the terminal
    /// results the singleflight replay matches against.
    pub fn applied_publications(&self) -> Result<Vec<crate::config::PublicationIntent>> {
        self.publications(sql::APPLIED_PUBLICATIONS)
    }

    /// Shared body of the two publication reads; only the SQL const
    /// differs.
    fn publications(
        &self,
        statement: &'static str,
    ) -> Result<Vec<crate::config::PublicationIntent>> {
        let mut stmt = self.conn()?.prepare(statement).map_err(storage)?;
        let rows = stmt
            .query_map([], publication_from_row)
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        Ok(rows)
    }

    /// Records the receipt for one intent; only recovery for a write it
    /// attributed to itself calls this. A zero-row update means the intent
    /// left the pending state underneath us (already receipted or gone) —
    /// that is a typed conflict, never a silent success.
    pub fn complete_publication(
        &mut self,
        owner: &str,
        target: &str,
        admission_seq: u64,
    ) -> Result<()> {
        // The receipt's own write is the one failure window after the
        // managed bytes already landed (DEC-056 item 5): the proof seam
        // injects it without touching the landed file.
        if proof::fault(proof::Site::PublicationReceipt).is_err() {
            return Err(storage(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
                Some("injected PublicationReceipt".to_string()),
            )));
        }
        let receipted = self
            .conn()?
            .execute(
                sql::COMPLETE_PUBLICATION,
                params![owner, target, admission_seq as i64],
            )
            .map_err(storage)?;
        if receipted == 0 {
            return Err(StoreError::Conflict(ConflictCause::PublicationNotPending {
                owner: owner.to_string(),
                target: target.to_string(),
                admission_seq,
            }));
        }
        Ok(())
    }

    // ----- preapprovals (the mode decision reads these) -----

    /// Records or renews one limited-grant consent; `ttl_seconds` may be
    /// negative to register an already-expired row.
    pub fn record_preapproval(
        &mut self,
        scope: &str,
        granted_by: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        let modifier = format!("{ttl_seconds:+} seconds");
        self.conn()?
            .execute(
                sql::INSERT_PREAPPROVAL,
                params![scope, granted_by, modifier],
            )
            .map_err(storage)?;
        Ok(())
    }

    /// Whether a non-expired grant covers `scope`; absent scopes fail closed.
    pub fn is_preapproved(&self, scope: &str) -> Result<bool> {
        self.conn()?
            .query_row(sql::PREAPPROVAL_LIVE, params![scope], |row| row.get(0))
            .map_err(storage)
    }
    // ----- budget ledger (INV-022) -----

    /// Opens one budget scope with an immutable limit. A scope opens
    /// once; a replayed open is a typed conflict, never a silent
    /// re-limit of a live ledger.
    pub fn open_budget(&mut self, scope: &str, limit_units: u64) -> Result<()> {
        let stored_limit = budget_units_i64(limit_units)?;
        let replayed = self
            .conn()?
            .query_row(sql::BUDGET_SCOPE_ROW, params![scope], |row| {
                row.get::<_, i64>(0)
            })
            .optional()
            .map_err(storage)?;
        if replayed.is_some() {
            return Err(StoreError::Conflict(ConflictCause::BudgetScopeExists {
                scope: scope.to_string(),
            }));
        }
        self.conn()?
            .execute(sql::INSERT_BUDGET_SCOPE, params![scope, stored_limit])
            .map_err(storage)?;
        Ok(())
    }

    /// Atomically reserves `bound` units at every applicable scope
    /// (INV-022): one immediate transaction checks
    /// `spent + reserved + bound <= limit` at each level and applies
    /// every increment, or nothing. A level that cannot fit denies the
    /// whole reservation — a partial multi-level spend cannot exist —
    /// and the reservation id is single-use, so a replayed reserve can
    /// never double-spend.
    pub fn budget_reserve(
        &mut self,
        reservation_id: &str,
        scopes: &[&str],
        bound: u64,
    ) -> Result<()> {
        if scopes.is_empty() {
            return Err(StoreError::InvalidInput(InvalidCause::EmptyBudgetScopes));
        }
        let stored_bound = budget_units_i64(bound)?;
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let replayed: bool = tx
            .query_row(sql::RESERVATION_EXISTS, params![reservation_id], |row| {
                row.get(0)
            })
            .map_err(storage)?;
        if replayed {
            return Err(StoreError::Conflict(
                ConflictCause::ReservationAlreadyRecorded {
                    reservation_id: reservation_id.to_string(),
                },
            ));
        }
        for scope in scopes {
            // The invariant rides in the WHERE clause: the check and
            // the increment are one statement, so concurrent children
            // racing for the last reserveable budget serialize on the
            // write lock and exactly one wins.
            let reserved = tx
                .execute(sql::RESERVE_BUDGET, params![scope, stored_bound])
                .map_err(storage)?;
            if reserved == 0 {
                return Err(Self::reserve_denied(&tx, scope, bound));
            }
            tx.execute(
                sql::INSERT_BUDGET_RESERVATION,
                params![reservation_id, scope, stored_bound],
            )
            .map_err(storage)?;
        }
        tx.commit().map_err(storage)?;
        Ok(())
    }

    /// Resolves one reservation against the sent request's cost
    /// (INV-022): a confirmed cost spends the confirmed units, an
    /// unknown sent cost retains the full bound — never released as
    /// zero. The reservation is the proof reserve: it converts to
    /// spent only through this explicit transition, exactly once.
    pub fn budget_charge(&mut self, reservation_id: &str, confirmed: Option<u64>) -> Result<()> {
        let stored_confirmed = confirmed.map(budget_units_i64).transpose()?;
        self.resolve_reservation(reservation_id, "charged", stored_confirmed, false)
    }

    /// Releases a reservation whose request never sent: the reserved
    /// units return to every scope untouched and nothing is spent.
    /// Exactly-once, like the charge.
    pub fn budget_release(&mut self, reservation_id: &str) -> Result<()> {
        self.resolve_reservation(reservation_id, "released", None, true)
    }

    /// One reservation's ledger face: the scope's admission invariant
    /// is `spent + reserved + bound(next) <= limit`.
    pub fn budget_status(&self, scope: &str) -> Result<BudgetStatus> {
        let row = self
            .conn()?
            .query_row(sql::BUDGET_SCOPE_ROW, params![scope], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .optional()
            .map_err(storage)?;
        match row {
            None => Err(StoreError::NotFound(Missing::BudgetScope(
                scope.to_string(),
            ))),
            Some((limit_units, spent, reserved)) => Ok(BudgetStatus {
                limit_units: unsigned(limit_units)?,
                spent: unsigned(spent)?,
                reserved: unsigned(reserved)?,
            }),
        }
    }

    /// One reservation's resolution record: `charged` is the confirmed
    /// cost, or `None` when the sent cost stayed unknown and the bound
    /// was retained.
    pub fn budget_reservation(&self, reservation_id: &str) -> Result<BudgetReservation> {
        let row = self
            .conn()?
            .query_row(
                sql::BUDGET_RESERVATION_ROW,
                params![reservation_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?;
        match row {
            None => Err(StoreError::NotFound(Missing::Reservation(
                reservation_id.to_string(),
            ))),
            Some((state, bound, charged)) => Ok(BudgetReservation {
                state: BudgetReservationState::from_db(&state)?,
                bound: unsigned(bound)?,
                charged: charged.map(unsigned).transpose()?,
            }),
        }
    }

    /// Shared body of the two resolutions: load the reservation's
    /// scope rows, refuse anything not still `reserved` — the
    /// exactly-once guard against double-spend and silent conversion —
    /// then apply the scope deltas and the terminal state together.
    fn resolve_reservation(
        &mut self,
        reservation_id: &str,
        terminal_state: &'static str,
        confirmed: Option<i64>,
        release: bool,
    ) -> Result<()> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let rows = tx
            .prepare(sql::BUDGET_RESERVATION_SCOPES)
            .map_err(storage)?
            .query_map(params![reservation_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage)?;
        if rows.is_empty() {
            return Err(StoreError::NotFound(Missing::Reservation(
                reservation_id.to_string(),
            )));
        }
        if let Some((_, _, state)) = rows.iter().find(|(_, _, state)| state != "reserved") {
            return Err(StoreError::Conflict(
                ConflictCause::ReservationNotReserved {
                    reservation_id: reservation_id.to_string(),
                    state: state.clone(),
                },
            ));
        }
        for (scope, bound, _) in &rows {
            if release {
                tx.execute(sql::RELEASE_BUDGET_SCOPE, params![scope, bound])
                    .map_err(storage)?;
            } else {
                // An unknown sent cost retains the bound: the delta is
                // the confirmed units, or the bound itself.
                if let Some(delta) = confirmed
                    && delta > *bound
                {
                    return Err(StoreError::InvalidInput(
                        InvalidCause::ConfirmedExceedsBound {
                            confirmed: unsigned(delta)?,
                            bound: unsigned(*bound)?,
                        },
                    ));
                }
                let delta = confirmed.unwrap_or(*bound);
                let charged = tx
                    .execute(sql::CHARGE_BUDGET_SCOPE, params![scope, delta, bound])
                    .map_err(storage)?;
                if charged == 0 {
                    let reserved = tx
                        .query_row(sql::BUDGET_SCOPE_ROW, params![scope], |row| {
                            row.get::<_, i64>(2)
                        })
                        .optional()
                        .map_err(storage)?
                        .unwrap_or(0);
                    return Err(StoreError::Conflict(
                        ConflictCause::ChargeReservedBelowBound {
                            scope: scope.clone(),
                            reserved: unsigned(reserved)?,
                            bound: unsigned(*bound)?,
                        },
                    ));
                }
            }
        }
        tx.execute(
            sql::SET_BUDGET_RESERVATION_STATE,
            params![reservation_id, terminal_state, confirmed],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(())
    }

    /// Classifies a zero-row reserve: a scope that never opened is a
    /// missing lookup; an open scope that cannot fit carries its own
    /// numbers for the typed exhaustion conflict.
    fn reserve_denied(tx: &rusqlite::Transaction<'_>, scope: &str, bound: u64) -> StoreError {
        let row = tx
            .query_row(sql::BUDGET_SCOPE_ROW, params![scope], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .optional();
        match row {
            Ok(None) => StoreError::NotFound(Missing::BudgetScope(scope.to_string())),
            Ok(Some((limit, spent, reserved))) => {
                match (unsigned(spent), unsigned(reserved), unsigned(limit)) {
                    (Ok(spent), Ok(reserved), Ok(limit)) => {
                        StoreError::Conflict(ConflictCause::BudgetExhausted {
                            scope: scope.to_string(),
                            spent,
                            reserved,
                            bound,
                            limit,
                        })
                    }
                    (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => error,
                }
            }
            // The scope row itself failed to read: the storage error
            // wins over guessing an admission verdict.
            Err(source) => storage(source),
        }
    }
}

/// The latest recorded compaction checkpoint of one task. The event's
/// aggregate is the checkpoint itself, which is why no task revision
/// moves; the task column is the feed a resume reads by. Statement texts
/// are named beside their only reader, like every statement in the shared
/// catalogue (P-002).
const LATEST_COMPACTION: &str = "SELECT delta_json FROM events WHERE task_id = ?1 AND event_type = 'task.compacted' ORDER BY cursor DESC LIMIT 1";

/// The one line a folded history assembles to — the checkpoint the next
/// request reads instead of the records it replaced. One spelling, so the
/// line `force_compaction` measures against the history it folds is the
/// very line `assembled_context` serves afterwards.
fn compacted_history_line(checkpoint: &ContinuationCheckpoint) -> String {
    format!(
        "history: compacted {} {} records digest {}\n",
        checkpoint.checkpoint_id, checkpoint.folded_records, checkpoint.history_digest
    )
}

/// The obligation one scoped record supports, read before the record is
/// deleted so the row that stops being supported is reopened in the same
/// transaction.
const SCOPED_RECORD_OBLIGATION: &str =
    "SELECT obligation_id FROM evidence WHERE evidence_id = ?1 AND task_id = ?2";

/// How many records still support one obligation after a deletion.
const OBLIGATION_SUPPORT_COUNT: &str = "SELECT COUNT(*) FROM evidence WHERE obligation_id = ?1";

/// Reopens an obligation no record supports any more: a satisfied row
/// without evidence would claim proof that is gone.
const REOPEN_OBLIGATION: &str =
    "UPDATE obligations SET execution = 'pending' WHERE obligation_id = ?1";

/// Deletes one authoritative scoped record of a task. A derived view is
/// filtered against this table, never against its own copy, so a deleted
/// record cannot come back from a checkpoint.
const DELETE_SCOPED_RECORD: &str = "DELETE FROM evidence WHERE evidence_id = ?1 AND task_id = ?2";

/// One spend ledger entry the continuation carries: the scope it was
/// recorded under (the model that spent it) and the units it spent. The
/// scope travels with the checkpoint, so a later model switch appends a
/// new entry instead of rewriting the recorded one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SpendEntry {
    pub scope: String,
    pub spent: u64,
}

/// One scoped record as a checkpoint recorded it: the identity, the
/// validity it had and the digest of what it observed. The observation
/// text itself is part of the episodic history, so the recorded index
/// stays small while the availability of the record is preserved.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScopedIndexEntry {
    pub evidence_id: String,
    pub validity: String,
    pub digest: String,
}

/// The checkpoint a forced compaction leaves behind: the working state the
/// next request is rebuilt from, plus the digests a resume re-checks
/// before it replays anything.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContinuationCheckpoint {
    pub checkpoint_id: String,
    pub task_id: String,
    pub intent_revision: u64,
    pub question_id: Option<String>,
    pub question_revision: Option<u64>,
    /// The pinned inputs of the task at compaction: what the resume
    /// compares its live digests with, never guessing staleness.
    pub goal_digest: String,
    pub answer_digest: String,
    pub evidence_digest: String,
    /// The scoped records the history was folded with, with their
    /// recorded validity.
    pub evidence: Vec<ScopedIndexEntry>,
    /// The spend ledger at compaction, per scope.
    pub spend: Vec<SpendEntry>,
    /// How many episodic records the history line replaced.
    pub folded_records: u64,
    /// The digest of the folded history: what it said, not only that it
    /// was folded.
    pub history_digest: String,
}

impl ContinuationCheckpoint {
    /// The first pinned input the live state no longer matches, or `None`
    /// when every pin still holds. The name is the field, never a prose
    /// sentence, so a refusal names what moved.
    #[must_use]
    pub fn stale_pin(&self, live: &PinnedInputs) -> Option<&'static str> {
        if self.intent_revision != live.intent_revision {
            return Some("intent");
        }
        if self.goal_digest != live.goal_digest {
            return Some("goal");
        }
        if self.answer_digest != live.answer_digest {
            return Some("answer");
        }
        if self.evidence_digest != live.evidence_digest {
            return Some("evidence");
        }
        None
    }
}

/// The pinned inputs of one task as they are now: the digests a resume
/// compares a checkpoint's recorded pins with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedInputs {
    pub intent_revision: u64,
    pub goal_digest: String,
    pub answer_digest: String,
    pub evidence_digest: String,
}

/// One task's working context: what its next request carries. Every part
/// is a section of [`AssembledContext::text`]; a forced compaction may
/// only shorten the history part, so the decision, the remainder and the
/// spend come back byte-identical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledContext {
    pub text: String,
    pub intent: String,
    pub decision: String,
    pub evidence: String,
    pub remainder: String,
    pub spend: String,
    pub history: String,
}

/// What one forced compaction changed: the checkpoint it wrote and the
/// assembled context before and after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionReport {
    pub checkpoint_id: String,
    pub before_bytes: usize,
    pub after_bytes: usize,
    pub folded_records: u64,
}

/// One digest of a byte slice, hex encoded: the pin shape every checkpoint
/// field uses.
fn digest_of(bytes: &[u8]) -> String {
    crate::config::hex(&sha2::Sha256::digest(bytes))
}

impl TaskStore {
    /// The context one request of this task carries, assembled from the
    /// authoritative rows: goal and intent, the decision, the scoped
    /// records, what remains, the spend ledger and the episodic history.
    /// The history is the only part a checkpoint folds; every other part
    /// is read from its owner, so compaction can never rewrite it.
    pub fn assembled_context(&self, task_id: &TaskId) -> Result<AssembledContext> {
        let snapshot = self.snapshot(task_id)?;
        let goal = String::from_utf8_lossy(&self.goal_bytes(task_id)?).into_owned();
        let question = self.current_question(task_id)?;
        let answer = self.answered_question(task_id)?;
        let records = self.evidence_for_task(task_id)?;
        let checkpoint = self.continuation_checkpoint(task_id)?;
        let intent = format!("goal: {goal}\nintent: {}\n", snapshot.intent_revision);
        let mut decision = String::from("decision:\n");
        match &question {
            Some((question, revision)) => decision.push_str(&format!(
                "question: {} r{revision} pending\n",
                question.question_id.0
            )),
            None => decision.push_str("question: none\n"),
        }
        match &answer {
            Some((answer, origin)) => decision.push_str(&format!("answer: {origin} {answer}\n")),
            None => decision.push_str("answer: none\n"),
        }
        let mut evidence = format!("records: {}\n", records.len());
        for record in &records {
            evidence.push_str(&format!(
                "{} {} {}\n",
                record.evidence_id.0,
                validity_text(record.validity),
                record.digest
            ));
        }
        let mut remainder = String::from("remainder:\n");
        let mut outstanding = 0_u64;
        for obligation in &snapshot.obligations.items {
            if obligation.execution == ObligationExecution::Satisfied {
                continue;
            }
            outstanding += 1;
            remainder.push_str(&format!(
                "{} {:?} {:?}\n",
                obligation.id, obligation.applicability, obligation.execution
            ));
        }
        remainder = format!("{remainder}outstanding: {outstanding}\n");
        let spend = self.spend_part(task_id)?;
        let history = match &checkpoint {
            Some(checkpoint) => compacted_history_line(checkpoint),
            None => {
                let mut history = String::from("history:\n");
                for record in &records {
                    history.push_str(&format!(
                        "record {} {}\n",
                        record.evidence_id.0, record.observation
                    ));
                }
                for attempt in &snapshot.attempts.items {
                    history.push_str(&format!(
                        "attempt {} {} {:?} {:?}\n",
                        attempt.attempt_id.0,
                        attempt.action_id.0,
                        attempt.effect_class,
                        attempt.state
                    ));
                }
                history
            }
        };
        let text = format!("{intent}{decision}{evidence}{remainder}{spend}{history}");
        Ok(AssembledContext {
            text,
            intent,
            decision,
            evidence,
            remainder,
            spend,
            history,
        })
    }

    /// The spend part of one assembled context: every scope this task has
    /// spent under, read from the live ledger. The scope name carries the
    /// model that spent it, so a switch appends its own scope and never
    /// rewrites an earlier one.
    fn spend_part(&self, task_id: &TaskId) -> Result<String> {
        let mut scopes = self
            .conn()?
            .prepare(SPEND_SCOPES)
            .map_err(storage)?
            .query_map(params![task_scope_prefix(task_id)], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage)?;
        scopes.sort();
        if scopes.is_empty() {
            return Ok(String::from("spend: none\n"));
        }
        let mut spend = String::from("spend:\n");
        for (scope, spent) in scopes {
            spend.push_str(&format!("{scope} {}\n", unsigned(spent)?));
        }
        Ok(spend)
    }

    /// The digests of the task's pinned inputs as they are now: what a
    /// resume compares a checkpoint against before it replays a step.
    pub fn pinned_inputs(&self, task_id: &TaskId) -> Result<PinnedInputs> {
        let snapshot = self.snapshot(task_id)?;
        let goal = digest_of(&self.goal_bytes(task_id)?);
        let answer = digest_of(
            self.answered_question(task_id)?
                .as_ref()
                .map_or(b"", |(answer, _)| answer.as_bytes()),
        );
        Ok(PinnedInputs {
            intent_revision: snapshot.intent_revision,
            goal_digest: goal,
            answer_digest: answer,
            evidence_digest: digest_of(&evidence_index_bytes(&self.evidence_for_task(task_id)?)),
        })
    }

    /// The latest checkpoint recorded for a task, if a forced compaction
    /// ever ran on it.
    pub fn continuation_checkpoint(
        &self,
        task_id: &TaskId,
    ) -> Result<Option<ContinuationCheckpoint>> {
        let delta: Option<String> = self
            .conn()?
            .query_row(LATEST_COMPACTION, params![task_id.0], |row| row.get(0))
            .optional()
            .map_err(storage)?;
        match delta {
            None => Ok(None),
            Some(delta) => serde_json::from_str(&delta)
                .map(Some)
                .map_err(|error| StoreError::Storage(error.into())),
        }
    }

    /// The derived index of a task's scoped records: the checkpoint's
    /// recorded entries, filtered against the authoritative rows, so a
    /// record deleted after compaction is never served from the derived
    /// copy while a surviving one keeps its recorded validity.
    pub fn scoped_index(&self, task_id: &TaskId) -> Result<Vec<ScopedIndexEntry>> {
        let Some(checkpoint) = self.continuation_checkpoint(task_id)? else {
            return Ok(Vec::new());
        };
        let live: BTreeSet<String> = self
            .evidence_for_task(task_id)?
            .into_iter()
            .map(|record| record.evidence_id.0)
            .collect();
        Ok(checkpoint
            .evidence
            .into_iter()
            .filter(|record| live.contains(&record.evidence_id))
            .collect())
    }

    /// One forced runtime compaction (AC-049): folds the episodic history
    /// into a checkpoint — goal and intent, the decision, the scoped
    /// records with their validity, the spend ledger and what remains —
    /// and appends it as its own aggregate, so the task row, its question,
    /// its answer, its obligations and its spend are never rewritten and
    /// the next assembled context is only shorter. The fold is refused
    /// typed when the line it would leave is not strictly smaller than the
    /// history it replaces: a compaction that only appends a record leaves
    /// the assembled size unchanged, so it would claim work it did not do.
    pub fn force_compaction(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
    ) -> Result<CompactionReport> {
        let before = self.assembled_context(task_id)?;
        let pins = self.pinned_inputs(task_id)?;
        let records = self.evidence_for_task(task_id)?;
        let snapshot = self.snapshot(task_id)?;
        let question = self.current_question(task_id)?;
        let checkpoint = ContinuationCheckpoint {
            checkpoint_id: EventId::generate().0,
            task_id: task_id.0.clone(),
            intent_revision: pins.intent_revision,
            question_id: question
                .as_ref()
                .map(|(question, _)| question.question_id.0.clone()),
            question_revision: question.as_ref().map(|(_, revision)| *revision),
            goal_digest: pins.goal_digest,
            answer_digest: pins.answer_digest,
            evidence_digest: pins.evidence_digest,
            evidence: records
                .iter()
                .map(|record| ScopedIndexEntry {
                    evidence_id: record.evidence_id.0.clone(),
                    validity: validity_text(record.validity).to_string(),
                    digest: record.digest.clone(),
                })
                .collect(),
            spend: self.recorded_spend(task_id)?,
            folded_records: records.len() as u64 + snapshot.attempts.items.len() as u64,
            history_digest: digest_of(before.history.as_bytes()),
        };
        // The prospective fold is measured before anything is written: the
        // next context may only be shorter, so a line that is not strictly
        // smaller than the history it replaces is refused typed instead of
        // journaled as a compaction that shrank nothing.
        let folded = compacted_history_line(&checkpoint);
        if folded.len() >= before.history.len() {
            return Err(StoreError::Conflict(ConflictCause::CompactionNotShorter {
                before: before.history.len(),
                folded: folded.len(),
            }));
        }
        let delta =
            serde_json::to_value(&checkpoint).map_err(|error| StoreError::Storage(error.into()))?;
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        Self::append_event(
            &tx,
            session_id,
            Some(task_id),
            (&checkpoint.checkpoint_id, 1),
            "task.compacted",
            delta,
            "runtime",
        )?;
        tx.commit().map_err(storage)?;
        let after = self.assembled_context(task_id)?;
        Ok(CompactionReport {
            checkpoint_id: checkpoint.checkpoint_id,
            before_bytes: before.text.len(),
            after_bytes: after.text.len(),
            folded_records: checkpoint.folded_records,
        })
    }

    /// The spend ledger at compaction: one entry per scope already spent
    /// under. The scope name is the model that spent it, so a later switch
    /// appends its own entry instead of relabelling this one.
    fn recorded_spend(&self, task_id: &TaskId) -> Result<Vec<SpendEntry>> {
        let mut scopes = self
            .conn()?
            .prepare(SPEND_SCOPES)
            .map_err(storage)?
            .query_map(params![task_scope_prefix(task_id)], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage)?;
        scopes.sort();
        scopes
            .into_iter()
            .map(|(scope, spent)| {
                Ok(SpendEntry {
                    scope,
                    spent: unsigned(spent)?,
                })
            })
            .collect()
    }

    /// Deletes one scoped record of a task. Every derived view is filtered
    /// against this table, so the continuation and its recorded index stop
    /// returning the record the moment it is gone — the checkpoint's own
    /// copy stays what it recorded, and the filter is what withholds it.
    /// The obligation the record supported is reopened in the same
    /// transaction once no record supports it: a satisfied row without
    /// evidence would claim proof that no longer exists.
    pub fn delete_scoped_record(&mut self, task_id: &TaskId, evidence_id: &str) -> Result<()> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let obligation: Option<String> = tx
            .query_row(
                SCOPED_RECORD_OBLIGATION,
                params![evidence_id, task_id.0],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        let Some(obligation_id) = obligation else {
            return Err(StoreError::NotFound(Missing::Evidence(
                evidence_id.to_string(),
            )));
        };
        tx.execute(DELETE_SCOPED_RECORD, params![evidence_id, task_id.0])
            .map_err(storage)?;
        let support: u64 = tx
            .query_row(OBLIGATION_SUPPORT_COUNT, params![obligation_id], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(storage)? as u64;
        if support == 0 {
            tx.execute(REOPEN_OBLIGATION, params![obligation_id])
                .map_err(storage)?;
        }
        tx.commit().map_err(storage)?;
        Ok(())
    }
}

/// The ledger scopes one task has already spent under, matched by the
/// task-scoped name prefix, ordered by name.
const SPEND_SCOPES: &str =
    "SELECT scope, spent FROM budget_scopes WHERE scope LIKE ?1 || '%' ORDER BY scope";

/// The name prefix every task-scoped ledger row carries: `task:<id>` for
/// the task's own row, and `task:<id>/<label>` when the label names who
/// spent it (the model, for a spend ledger). The same prefix scopes the
/// task's evidence rows, so one task is one namespace.
fn task_scope_prefix(task_id: &TaskId) -> String {
    format!("task:{}", task_id.0)
}

/// One recorded validity as the store spells it.
fn validity_text(validity: EvidenceValidity) -> &'static str {
    match validity {
        EvidenceValidity::Current => "current",
        EvidenceValidity::Stale => "stale",
    }
}

/// The canonical bytes of an evidence set: what the freshness pin digests,
/// so an added, removed or invalidated record moves the pin.
fn evidence_index_bytes(records: &[Evidence]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for record in records {
        bytes.extend_from_slice(record.evidence_id.0.as_bytes());
        bytes.push(b' ');
        bytes.extend_from_slice(validity_text(record.validity).as_bytes());
        bytes.push(b' ');
        bytes.extend_from_slice(record.digest.as_bytes());
        bytes.push(b'\n');
    }
    bytes
}

impl TaskStore {
    /// Lends the one write surface of a standalone store. A runtime-bound
    /// store is reached only through `Runtime::store_writer`.
    pub fn writer(&mut self) -> StoreWriter<'_> {
        StoreWriter { store: self }
    }
}

/// The closed write surface of a task store: a private `&mut` borrow that
/// exposes only the delegating operations below, so an external caller can
/// neither swap, close nor reopen the store it writes through. Reads go
/// through [`StoreWriter::store`].
///
/// ```compile_fail
/// use rivect::commands::Runtime;
/// fn f(rt: &mut Runtime) { let w = rt.store_writer(); let _s = w.store; }
/// ```
///
/// ```
/// use rivect::{commands::Runtime, state::TaskStore};
/// fn f(rt: &mut Runtime) { let w = rt.store_writer(); let _s: &TaskStore = w.store(); }
/// ```
pub struct StoreWriter<'a> {
    store: &'a mut TaskStore,
}

impl std::fmt::Debug for StoreWriter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreWriter").finish()
    }
}

impl StoreWriter<'_> {
    /// The store behind this writer, for reads.
    #[must_use]
    pub fn store(&self) -> &TaskStore {
        self.store
    }

    /// # Errors
    /// See [`TaskStore::answer_question`].
    pub fn answer_question(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        question_id: &QuestionId,
        question_revision: u64,
        selection: &AnswerSelection,
        author: &str,
    ) -> Result<CommandResult> {
        self.store.answer_question(
            session_id,
            task_id,
            question_id,
            question_revision,
            selection,
            author,
        )
    }

    /// # Errors
    /// See [`TaskStore::append_publication`].
    pub fn append_publication(
        &mut self,
        owner: &str,
        target: &str,
        intended_digest: &str,
        base_digest: Option<&str>,
        identity: Option<WriteIdentity>,
    ) -> Result<u64> {
        self.store
            .append_publication(owner, target, intended_digest, base_digest, identity)
    }

    /// # Errors
    /// See [`TaskStore::attempt_confirmed`].
    pub fn attempt_confirmed(&mut self, attempt_id: &str) -> Result<()> {
        self.store.attempt_confirmed(attempt_id)
    }

    /// # Errors
    /// See [`TaskStore::attempt_rejected`].
    pub fn attempt_rejected(&mut self, attempt_id: &str, detail: &str) -> Result<()> {
        self.store.attempt_rejected(attempt_id, detail)
    }

    /// # Errors
    /// See [`TaskStore::attempt_unknown`].
    pub fn attempt_unknown(&mut self, attempt_id: &str, detail: &str) -> Result<()> {
        self.store.attempt_unknown(attempt_id, detail)
    }

    /// # Errors
    /// See [`TaskStore::cancel_task`].
    pub fn cancel_task(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        expected_intent_revision: u64,
        reason: Option<&str>,
    ) -> Result<CommandResult> {
        self.store
            .cancel_task(session_id, task_id, expected_intent_revision, reason)
    }

    /// # Errors
    /// See [`TaskStore::complete_if_eligible`].
    pub fn complete_if_eligible(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
    ) -> Result<TaskSnapshot> {
        self.store.complete_if_eligible(session_id, task_id)
    }

    /// # Errors
    /// See [`TaskStore::complete_publication`].
    pub fn complete_publication(
        &mut self,
        owner: &str,
        target: &str,
        admission_seq: u64,
    ) -> Result<()> {
        self.store
            .complete_publication(owner, target, admission_seq)
    }

    /// # Errors
    /// See [`TaskStore::hold_for_plan_gate`].
    pub fn hold_for_plan_gate(
        &mut self,
        task_id: &TaskId,
        observed: PlanGateHold,
    ) -> Result<Option<PlanGateHold>> {
        self.store.hold_for_plan_gate(task_id, observed)
    }

    /// # Errors
    /// See [`TaskStore::insert_evidence`].
    pub fn insert_evidence(
        &mut self,
        task_id: &TaskId,
        obligation_index: usize,
        scope: &str,
        observation: &str,
        digest: &str,
    ) -> Result<String> {
        self.store
            .insert_evidence(task_id, obligation_index, scope, observation, digest)
    }

    /// # Errors
    /// See [`TaskStore::insert_evidence_for_task`].
    pub fn insert_evidence_for_task(
        &mut self,
        task_id: &TaskId,
        scope: &str,
        observation: &str,
        digest: &str,
    ) -> Result<()> {
        self.store
            .insert_evidence_for_task(task_id, scope, observation, digest)
    }

    /// # Errors
    /// See [`TaskStore::invalidate_evidence`].
    pub fn invalidate_evidence(&mut self, evidence_id: &str) -> Result<String> {
        self.store.invalidate_evidence(evidence_id)
    }

    /// # Errors
    /// See [`TaskStore::record_learning_corpus`].
    pub fn record_learning_corpus(
        &mut self,
        delta_id: &str,
        cases: &[crate::learning::CorpusCase],
    ) -> Result<Vec<crate::learning::CorpusVerdict>> {
        self.store.record_learning_corpus(delta_id, cases)
    }

    /// # Errors
    /// See [`TaskStore::record_learning_delta`].
    pub fn record_learning_delta(
        &mut self,
        candidate: &crate::learning::DeltaCandidate,
    ) -> Result<crate::learning::DeltaRecord> {
        self.store.record_learning_delta(candidate)
    }

    /// # Errors
    /// See [`TaskStore::mark_applicability_unresolved`].
    pub fn mark_applicability_unresolved(&mut self, obligation_id: &str) -> Result<Option<String>> {
        self.store.mark_applicability_unresolved(obligation_id)
    }

    /// # Errors
    /// See [`TaskStore::mark_index_generation_stale`].
    pub fn mark_index_generation_stale(
        &mut self,
        generation: u64,
        cause: StaleCause,
    ) -> Result<bool> {
        self.store.mark_index_generation_stale(generation, cause)
    }

    /// # Errors
    /// See [`TaskStore::mark_no_ready`].
    pub fn mark_no_ready(&mut self, task_id: &TaskId) -> Result<()> {
        self.store.mark_no_ready(task_id)
    }

    /// # Errors
    /// See [`TaskStore::mark_outcome_unknown`].
    pub fn mark_outcome_unknown(&mut self, task_id: &TaskId) -> Result<()> {
        self.store.mark_outcome_unknown(task_id)
    }

    /// # Errors
    /// See [`TaskStore::mark_plan_applicability_unresolved`].
    pub fn mark_plan_applicability_unresolved(&mut self, task_id: &TaskId) -> Result<()> {
        self.store.mark_plan_applicability_unresolved(task_id)
    }

    /// # Errors
    /// See [`TaskStore::materialize_obligations`].
    pub fn materialize_obligations(&mut self, task_id: &TaskId) -> Result<()> {
        self.store.materialize_obligations(task_id)
    }

    /// # Errors
    /// See [`TaskStore::open_budget`].
    pub fn open_budget(&mut self, scope: &str, limit_units: u64) -> Result<()> {
        self.store.open_budget(scope, limit_units)
    }

    /// # Errors
    /// See [`TaskStore::budget_reserve`].
    pub fn budget_reserve(
        &mut self,
        reservation_id: &str,
        scopes: &[&str],
        bound: u64,
    ) -> Result<()> {
        self.store.budget_reserve(reservation_id, scopes, bound)
    }

    /// # Errors
    /// See [`TaskStore::budget_charge`].
    pub fn budget_charge(&mut self, reservation_id: &str, confirmed: Option<u64>) -> Result<()> {
        self.store.budget_charge(reservation_id, confirmed)
    }

    /// # Errors
    /// See [`TaskStore::force_compaction`].
    pub fn force_compaction(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
    ) -> Result<CompactionReport> {
        self.store.force_compaction(session_id, task_id)
    }

    /// # Errors
    /// See [`TaskStore::delete_scoped_record`].
    pub fn delete_scoped_record(&mut self, task_id: &TaskId, evidence_id: &str) -> Result<()> {
        self.store.delete_scoped_record(task_id, evidence_id)
    }

    /// # Errors
    /// See [`TaskStore::open_session`].
    pub fn open_session(
        &mut self,
        bootstrap_id: &str,
        connection_id: &str,
        attach_to: Option<&SessionId>,
    ) -> Result<(SessionId, AttachmentId, u64, bool)> {
        self.store
            .open_session(bootstrap_id, connection_id, attach_to)
    }

    /// # Errors
    /// See [`TaskStore::plan_attempt`].
    pub fn plan_attempt(
        &mut self,
        task_id: &TaskId,
        class: crate::contracts::EffectClass,
        describe: &str,
    ) -> Result<String> {
        self.store.plan_attempt(task_id, class, describe)
    }

    /// # Errors
    /// See [`TaskStore::publish_question`].
    pub fn publish_question(
        &mut self,
        session_id: &SessionId,
        question: &Question,
    ) -> Result<TaskSnapshot> {
        self.store.publish_question(session_id, question)
    }

    /// # Errors
    /// See [`TaskStore::record_plan_assessment`].
    pub fn record_plan_assessment(
        &mut self,
        task_id: &TaskId,
        assessment: &PlanAssessmentWrite<'_>,
    ) -> Result<()> {
        self.store.record_plan_assessment(task_id, assessment)
    }

    /// # Errors
    /// See [`TaskStore::record_preapproval`].
    pub fn record_preapproval(
        &mut self,
        scope: &str,
        granted_by: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        self.store
            .record_preapproval(scope, granted_by, ttl_seconds)
    }

    /// # Errors
    /// See [`TaskStore::record_supervisor_reaction`].
    pub fn record_supervisor_reaction(
        &mut self,
        reaction: &crate::supervisor::Reaction,
    ) -> Result<()> {
        self.store.record_supervisor_reaction(reaction)
    }

    /// # Errors
    /// See [`TaskStore::recover_events`].
    pub fn recover_events(&mut self, session_id: &SessionId, events: &[Event]) -> Result<()> {
        self.store.recover_events(session_id, events)
    }

    /// # Errors
    /// See [`TaskStore::reserve_index_generation`].
    pub fn reserve_index_generation(&mut self) -> Result<u64> {
        self.store.reserve_index_generation()
    }

    /// # Errors
    /// See [`TaskStore::retain`].
    pub fn retain(&mut self, record_json: &str, boundary_id: &str) -> Result<()> {
        self.store.retain(record_json, boundary_id)
    }

    /// # Errors
    /// See [`TaskStore::retain_attempt`].
    pub fn retain_attempt(&mut self, attempt: &RetainedAttempt) -> Result<()> {
        self.store.retain_attempt(attempt)
    }

    /// # Errors
    /// See [`TaskStore::steer_task`].
    pub fn steer_task(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        expected_intent_revision: u64,
        expected_task_revision: u64,
        instruction: &str,
    ) -> Result<CommandResult> {
        self.store.steer_task(
            session_id,
            task_id,
            expected_intent_revision,
            expected_task_revision,
            instruction,
        )
    }

    /// # Errors
    /// See [`TaskStore::update_plan_row`].
    pub fn update_plan_row(&mut self, task_id: &TaskId, update: &PlanRowUpdate<'_>) -> Result<()> {
        self.store.update_plan_row(task_id, update)
    }

    /// # Errors
    /// See [`crate::config::stage_publication`].
    pub fn stage_publication(
        &mut self,
        owner: &str,
        target: &Path,
        edit: &crate::config::ConfigEdit,
    ) -> std::result::Result<crate::config::PublicationIntent, crate::config::PublicationError>
    {
        crate::config::stage_publication(self.store, owner, target, edit)
    }

    /// # Errors
    /// See [`crate::config::admit_publication`].
    pub fn admit_publication(
        &mut self,
        owner: &str,
        target: &Path,
        edit: &crate::config::ConfigEdit,
    ) -> std::result::Result<crate::config::PublicationAdmission, crate::config::PublicationError>
    {
        crate::config::admit_publication(self.store, owner, target, edit)
    }

    /// # Errors
    /// See [`crate::config::publish_intent`].
    pub fn publish_intent(
        &mut self,
        intent: &crate::config::PublicationIntent,
        bytes: &[u8],
    ) -> std::result::Result<(), crate::config::PublicationError> {
        crate::config::publish_intent(self.store, intent, bytes)
    }

    /// # Errors
    /// See [`crate::config::recover_publications`].
    pub fn recover_publications(&mut self) -> Result<Vec<crate::config::PublicationRecovery>> {
        crate::config::recover_publications(self.store)
    }
}

/// One budget scope's ledger face (INV-022): the admission invariant
/// is `spent + reserved + bound(next) <= limit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetStatus {
    pub limit_units: u64,
    pub spent: u64,
    pub reserved: u64,
}

/// One reservation's resolution: `charged` is the confirmed cost, or
/// `None` while the reservation is held or was released without a
/// send — and `None` on a charged row means the sent cost stayed
/// unknown and the bound was retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetReservation {
    pub state: BudgetReservationState,
    pub bound: u64,
    pub charged: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetReservationState {
    Reserved,
    Charged,
    Released,
}

impl BudgetReservationState {
    /// A column value off the recorded set is a corrupted row: the
    /// read fails instead of guessing a resolution state.
    fn from_db(raw: &str) -> Result<Self> {
        match raw {
            "reserved" => Ok(Self::Reserved),
            "charged" => Ok(Self::Charged),
            "released" => Ok(Self::Released),
            _ => Err(storage(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown budget reservation state {raw:?}"),
            ))),
        }
    }
}

/// Budget units are u64 in the API and i64 in SQLite; a value past the
/// storable range is a typed rejection, never a truncating cast.
fn budget_units_i64(units: u64) -> Result<i64> {
    match i64::try_from(units) {
        Ok(stored) => Ok(stored),
        Err(_) => Err(StoreError::InvalidInput(
            InvalidCause::BudgetUnitsOutOfRange(units),
        )),
    }
}
/// Ledger columns are written non-negative; a negative value is corrupt
/// storage, never a wrapping grant of `u64::MAX`.
fn unsigned(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_negative| {
        storage(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("negative ledger column {value}"),
        ))
    })
}

/// A revision past the storable range is corrupt state, never a
/// truncating cast.
fn stored_u64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_overflow| corrupt_column("revision", &value.to_string()))
}

fn corrupt_column(column: &str, raw: &str) -> StoreError {
    storage(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("unknown {column} {raw:?}"),
    ))
}

/// The prefix plan rows carry among a snapshot's obligations.
pub const PLAN_OBLIGATION_PREFIX: &str = "plan:";
/// Every plan blocker and gate hold names this owner.
pub const PLAN_BLOCKER_OWNER: &str = "plan";

/// The exact blocker one plan row or gate hold raises: the owner is the
/// plan and the condition names what must happen before work resumes.
pub fn plan_blocker(reason: ErrorCode, action_id: &str) -> Blocker {
    Blocker {
        reason,
        owner: PLAN_BLOCKER_OWNER.to_string(),
        condition: ResumeCondition::Dependency {
            action_id: crate::contracts::ActionId(action_id.to_string()),
        },
    }
}

/// Every off pause names this owner, never the plan's: the pause has its
/// own record because the single `plan_gate_holds` row is deleted and
/// rewritten by the plan settlement (AC-024/I5).
const WORKFLOW_OFF_BLOCKER_OWNER: &str = "workflow";

/// The blocker kind one off pause raises. Distinct from the plan gate's
/// `plan_gate:*` kinds, so a reader never confuses the two holds.
const WORKFLOW_OFF_BLOCKER_KIND: &str = "workflow_off:paused";

/// The lifecycle write the off transition applies: work in flight stops
/// where it is. A blocked task keeps its own hold, and a terminal one is
/// already settled.
const PAUSE_TASK_FOR_WORKFLOW_OFF: &str = "UPDATE tasks SET revision = revision + 1, lifecycle = 'paused', event_cursor = event_cursor + 1\n                 WHERE task_id = ?1 AND lifecycle IN ('running', 'waiting')";

/// The one release of that pause: a new intent displaces the off hold.
/// Only the off pause's own state matches, so a plan-owned block or a
/// waiting question is never touched by it.
const RELEASE_WORKFLOW_OFF_PAUSE: &str =
    "UPDATE tasks SET lifecycle = 'running' WHERE task_id = ?1 AND lifecycle = 'paused'";

/// The exact blocker one off pause raises: the workflow surface owns it and
/// the condition names what must happen before work resumes — a new intent.
fn workflow_off_blocker() -> Blocker {
    Blocker {
        reason: ErrorCode::DependencyBlocked,
        owner: WORKFLOW_OFF_BLOCKER_OWNER.to_string(),
        condition: ResumeCondition::Dependency {
            action_id: crate::contracts::ActionId(WORKFLOW_OFF_BLOCKER_KIND.to_string()),
        },
    }
}

/// Appends a task's plan blockers after the ones the store already
/// derived. A pending fork's `Decision` blocker shows only while that
/// question is the task's pending one and no equal blocker is listed —
/// one wait, one blocker: an answered, superseded or duplicate fork never
/// reads as a second wait.
fn extend_plan_blockers(
    blockers: &mut Vec<Blocker>,
    plan: Vec<Blocker>,
    pending: Option<&(String, u64)>,
) {
    for blocker in plan {
        if let ResumeCondition::Decision {
            question_id,
            revision,
        } = &blocker.condition
        {
            let live = pending.is_some_and(|(pending_id, pending_revision)| {
                *pending_id == question_id.0 && pending_revision == revision
            });
            if !live
                || blockers
                    .iter()
                    .any(|listed| listed.condition == blocker.condition)
            {
                continue;
            }
        }
        blockers.push(blocker);
    }
}

fn blocker_json(blocker: &Blocker) -> Result<String> {
    serde_json::to_string(blocker).map_err(storage)
}

/// A stored blocker decodes strictly: an unknown condition kind or
/// reason is corrupt storage, never a guessed wait.
fn blocker_from_db(raw: &str) -> Result<Blocker> {
    serde_json::from_str(raw).map_err(storage)
}

fn applicability_db(applicability: ObligationApplicability) -> &'static str {
    match applicability {
        ObligationApplicability::Required => "required",
        ObligationApplicability::NotApplicable => "not_applicable",
        ObligationApplicability::Unresolved => "unresolved",
    }
}

fn applicability_from_db(raw: &str) -> Result<ObligationApplicability> {
    match raw {
        "required" => Ok(ObligationApplicability::Required),
        "not_applicable" => Ok(ObligationApplicability::NotApplicable),
        "unresolved" => Ok(ObligationApplicability::Unresolved),
        _ => Err(corrupt_column("obligation applicability", raw)),
    }
}

fn execution_db(execution: ObligationExecution) -> &'static str {
    match execution {
        ObligationExecution::Pending => "pending",
        ObligationExecution::Satisfied => "satisfied",
        ObligationExecution::Failed => "failed",
        ObligationExecution::Stale => "stale",
    }
}

fn execution_from_db(raw: &str) -> Result<ObligationExecution> {
    match raw {
        "pending" => Ok(ObligationExecution::Pending),
        "satisfied" => Ok(ObligationExecution::Satisfied),
        "failed" => Ok(ObligationExecution::Failed),
        "stale" => Ok(ObligationExecution::Stale),
        _ => Err(corrupt_column("obligation execution", raw)),
    }
}

fn stage_from_db(raw: i64) -> Result<bool> {
    match raw {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(corrupt_column("plan stage flag", &raw.to_string())),
    }
}

/// What the request asks for. Only a change or a delivery ever edits;
/// only a delivery ever ships. The selection persists it so the effect
/// gate reads the kind the plan was selected for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    Change,
    Deliver,
    PlanOnly,
    Audit,
    Diagnose,
}

impl RequestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Change => "change",
            Self::Deliver => "deliver",
            Self::PlanOnly => "plan_only",
            Self::Audit => "audit",
            Self::Diagnose => "diagnose",
        }
    }

    fn from_db(raw: &str) -> Result<Self> {
        match raw {
            "change" => Ok(Self::Change),
            "deliver" => Ok(Self::Deliver),
            "plan_only" => Ok(Self::PlanOnly),
            "audit" => Ok(Self::Audit),
            "diagnose" => Ok(Self::Diagnose),
            _ => Err(corrupt_column("request kind", raw)),
        }
    }
}

/// One stored index generation: its number, the state it is in, and the
/// derived graph it carries.
#[derive(Debug, Clone, PartialEq)]
pub struct IndexGeneration {
    pub generation: u64,
    pub state: GenerationState,
    pub graph: ProjectGraph,
}

/// How many generations the store keeps. Retention is a bound on
/// derived data, not a delete policy: the rows are rebuildable from the
/// project, and a `SnapshotId` past the window reports absent rather
/// than answering with another generation.
pub const INDEX_GENERATION_RETENTION: usize = 8;

/// How many candidate deltas the store keeps (INV-010, AC-051). A
/// never-activated candidate is a proposal, not experience, so retention may
/// evict it; an activated delta and the tombstone a rollback leaves are
/// primary evidence and are outside the pruning statements' reach.
pub const LEARNING_DELTA_RETENTION: usize = 32;

/// How many corpus verdict rows one delta keeps: one per case kind, so a
/// verdict set cannot grow without bound and the newest judgement stays the
/// readable one.
pub const LEARNING_CORPUS_RETENTION: usize = crate::learning::CORPUS_CASE_LIMIT;

fn stale_cause_of(state: GenerationState) -> Option<&'static str> {
    match state {
        GenerationState::Fresh => None,
        GenerationState::Stale { cause } => Some(cause_name(cause)),
    }
}

fn cause_name(cause: StaleCause) -> &'static str {
    match cause {
        StaleCause::IsolatedRun => "isolated_run",
        StaleCause::WorkerRefused => "worker_refused",
        StaleCause::WatcherMissed => "watcher_missed",
        StaleCause::Interrupted => "interrupted",
        StaleCause::SourceChanged => "source_changed",
        StaleCause::Superseded => "superseded",
        StaleCause::PartialCoverage => "partial_coverage",
    }
}

/// One stored generation's state, read back. A value outside the
/// recorded vocabulary is a typed storage error, never a guess: a
/// state this build cannot read is corrupt storage, and reporting it as
/// `interrupted` would name a build that died mid-index when the bytes
/// say something else. An unsealed row *is* a build that never
/// finished, so that row is reported stale whatever it recorded.
fn generation_state(state: String, cause: Option<&str>, sealed: bool) -> Result<GenerationState> {
    match GenerationState::from_stored(&state, cause) {
        Some(state) if sealed => Ok(state),
        Some(_) => Ok(GenerationState::Stale {
            cause: StaleCause::Interrupted,
        }),
        None => Err(corrupt_column("index generation state", &state)),
    }
}

/// A stored edge read back strictly: a value outside the recorded
/// vocabulary is a typed storage error, never a default that would
/// report a wrong relation as observed. The row is read raw and decoded
/// after the mapping, the way every other strict column in this store
/// is.
fn edge_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEdge> {
    Ok(StoredEdge {
        from_path: row.get::<_, String>(0)?,
        from_line: row.get::<_, i64>(1)?,
        from_ignored: row.get::<_, i64>(2)? != 0,
        to_path: row.get::<_, String>(3)?,
        kind: row.get::<_, String>(4)?,
        provenance: row.get::<_, String>(5)?,
        version: row.get::<_, i64>(6)?,
        confidence: row.get::<_, String>(7)?,
    })
}

/// One stored edge's raw columns, before the vocabulary is resolved.
struct StoredEdge {
    from_path: String,
    from_line: i64,
    from_ignored: bool,
    to_path: String,
    kind: String,
    provenance: String,
    version: i64,
    confidence: String,
}

impl StoredEdge {
    fn decode(self) -> Result<IndexEdge> {
        let kind = EdgeKind::from_name(&self.kind)
            .ok_or_else(|| corrupt_column("edge kind", &self.kind))?;
        let provenance = EdgeProvenance::from_name(&self.provenance)
            .ok_or_else(|| corrupt_column("edge provenance", &self.provenance))?;
        let confidence = EdgeConfidence::from_name(&self.confidence)
            .ok_or_else(|| corrupt_column("edge confidence", &self.confidence))?;
        Ok(IndexEdge {
            from: SourceRef {
                path: PathBuf::from(self.from_path),
                // The column is `NOT NULL` (index.sql): the derivation
                // reads every edge from a located line, so a stored
                // negative would be corrupt storage rather than a row
                // with no line.
                line: Some(u64::try_from(self.from_line).map_err(|out_of_range| {
                    corrupt_column("index edge line", &out_of_range.to_string())
                })?),
                ignored: self.from_ignored,
            },
            to: SourceRef {
                path: PathBuf::from(self.to_path),
                line: None,
                ignored: false,
            },
            kind,
            provenance,
            version: self.version as i32,
            confidence,
        })
    }
}

fn write_edge(tx: &rusqlite::Transaction<'_>, generation: u64, edge: &IndexEdge) -> Result<()> {
    let kind = match edge.kind {
        EdgeKind::Import => "import",
        EdgeKind::Call => "call",
        EdgeKind::Test => "test",
    };
    let provenance = match edge.provenance {
        EdgeProvenance::Observed => "observed",
        EdgeProvenance::Inferred => "inferred",
        EdgeProvenance::Structural => "structural",
    };
    let confidence = match edge.confidence {
        EdgeConfidence::Certain => "certain",
        EdgeConfidence::Unknown => "unknown",
    };
    // The subject line is the column's whole reason to exist, so an
    // edge without one is refused rather than stored as line zero: a
    // fabricated coordinate is exactly what a reader cannot audit.
    let Some(line) = edge.from.line else {
        return Err(corrupt_column(
            "index edge line",
            &edge.from.path.to_string_lossy(),
        ));
    };
    tx.execute(
        sql::INSERT_INDEX_EDGE,
        params![
            generation as i64,
            edge.from.path.to_string_lossy(),
            i64::try_from(line).map_err(|out_of_range| corrupt_column(
                "index edge line",
                &out_of_range.to_string()
            ))?,
            i64::from(edge.from.ignored),
            edge.to.path.to_string_lossy(),
            kind,
            provenance,
            i64::from(edge.version),
            confidence,
        ],
    )
    .map_err(storage)?;
    Ok(())
}

fn path_placeholders(start: usize, count: usize) -> String {
    (start..start + count)
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// One recorded plan selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanSelectionRecord {
    pub revision: u64,
    pub facts_digest: String,
    pub request_kind: RequestKind,
}

/// One row a selection records; every row starts `pending`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PlanRowWrite<'a> {
    pub(crate) capability: &'a str,
    pub(crate) applicability: ObligationApplicability,
    pub(crate) stage: bool,
    pub(crate) handler: Option<&'a str>,
    pub(crate) blocker: Option<Blocker>,
}

/// The selection a caller records: the canonical facts digest, the
/// request kind and every row the facts require.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PlanSelectionWrite<'a> {
    pub(crate) facts_digest: &'a str,
    pub(crate) request_kind: RequestKind,
    pub(crate) rows: &'a [PlanRowWrite<'a>],
}

/// One plan row as the owner stores it: its phase (`stage` marks the
/// plan-phase rows that gate; every other row is execution-phase), the
/// handler that may close it — the capability itself or an allowed
/// equivalent, `None` when this build has none, its blocker, and either
/// its closed output or its selection-bound identity for an answered fork.
#[derive(Debug, Clone, PartialEq)]
pub struct PlanObligationRecord {
    pub capability: String,
    pub applicability: ObligationApplicability,
    pub execution: ObligationExecution,
    pub stage: bool,
    pub handler: Option<String>,
    pub blocker: Option<Blocker>,
    pub outcome_json: Option<String>,
}

impl PlanObligationRecord {
    /// The row as a snapshot obligation, id `plan:<capability>`.
    pub fn obligation(&self) -> Obligation {
        Obligation {
            id: format!("{PLAN_OBLIGATION_PREFIX}{}", self.capability),
            criterion_refs: Vec::new(),
            applicability: self.applicability,
            execution: self.execution,
            basis_refs: Vec::new(),
        }
    }

    /// Whether the row holds the lifecycle (DEC-039). An `unresolved` row
    /// always does, whatever it stored (D-076). Otherwise its blocker
    /// decides; a fork's `Decision` never holds: a pending fork's task
    /// waits on the question itself, an answered one waits on nothing. A
    /// required execution-phase row with no handler in this build keeps
    /// its `capability_unavailable` blocker for the completion guard only
    /// — blocking on it would deadlock the effect it follows.
    fn holds_lifecycle(&self) -> bool {
        if self.applicability == ObligationApplicability::Unresolved {
            return true;
        }
        let Some(blocker) = &self.blocker else {
            return false;
        };
        if matches!(blocker.condition, ResumeCondition::Decision { .. }) {
            return false;
        }
        let handlerless_execution = !self.stage
            && self.handler.is_none()
            && self.applicability == ObligationApplicability::Required
            && blocker.reason == ErrorCode::CapabilityUnavailable;
        !handlerless_execution
    }
}

/// A change the one plan-row write applies.
#[derive(Debug, Clone, PartialEq)]
pub enum PlanRowChange {
    /// Closes the row with the output that closed it; clears its blocker.
    Close {
        execution: ObligationExecution,
        outcome_json: String,
    },
    /// Leaves the row open on this exact blocker.
    Block(Blocker),
}

/// The one plan-row write API every close and blocker after the
/// selection goes through (PG-9): bound to the selection revision and
/// facts digest the handler ran on, owned by the invoking handler.
#[derive(Debug, Clone, PartialEq)]
pub struct PlanRowUpdate<'a> {
    pub capability: &'a str,
    pub handler: &'a str,
    pub selection_revision: u64,
    pub facts_digest: &'a str,
    pub change: PlanRowChange,
}

/// A plan revision `handler` records; `reopens` names the handler whose
/// rows the new revision reopens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlanRevisionWrite<'a> {
    pub(crate) handler: &'a str,
    pub(crate) reopens: &'a str,
    pub(crate) selection_revision: u64,
    pub(crate) facts_digest: &'a str,
    pub(crate) body_json: &'a str,
}

/// One mechanical verdict and the assessor's row changes.
#[derive(Debug, Clone, PartialEq)]
pub struct PlanAssessmentWrite<'a> {
    pub handler: &'a str,
    pub selection_revision: u64,
    pub facts_digest: &'a str,
    pub plan_revision: u64,
    pub verdict: PlanVerdict,
    pub assessment_json: &'a str,
    pub changes: Vec<(String, PlanRowChange)>,
}

/// One stored plan revision with the mechanical verdict bound to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanRevisionRecord {
    pub revision: u64,
    pub selection_revision: u64,
    pub body_json: String,
    pub verdict: Option<PlanVerdict>,
    pub assessment_json: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanVerdict {
    Pass,
    Fail,
}

impl PlanVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }

    fn from_db(raw: &str) -> Result<Self> {
        match raw {
            "pass" => Ok(Self::Pass),
            "fail" => Ok(Self::Fail),
            _ => Err(corrupt_column("plan verdict", raw)),
        }
    }
}

/// Whether non-read work may start. No selection is `Unassessed` —
/// never `Open`: plan absence is not "no risk".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanGate {
    Unassessed,
    Open,
    /// Rows of either phase still waiting on their applicability, and
    /// required plan-phase rows (or the plan revision's assessment) not
    /// yet closed.
    Paused {
        unresolved: Vec<String>,
        open_stages: Vec<String>,
    },
}

/// The closed gate a refused non-read effect waits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanGateHold {
    Unassessed,
    Paused,
}

impl PlanGateHold {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unassessed => "unassessed",
            Self::Paused => "paused",
        }
    }

    fn from_db(raw: &str) -> Result<Self> {
        match raw {
            "unassessed" => Ok(Self::Unassessed),
            "paused" => Ok(Self::Paused),
            _ => Err(corrupt_column("plan gate hold", raw)),
        }
    }

    /// The hold as the exact blocker `task.get`, the status todo and the
    /// dock show: `plan_gate:unassessed` or `plan_gate:paused`.
    pub fn blocker(self) -> Blocker {
        plan_blocker(
            ErrorCode::DependencyBlocked,
            &format!("plan_gate:{}", self.as_str()),
        )
    }
}

impl Lifecycle {
    fn from_db(raw: &str) -> Self {
        match raw {
            "waiting" => Self::Waiting,
            "paused" => Self::Paused,
            "blocked" => Self::Blocked,
            "completed" => Self::Completed,
            "cancelled" => Self::Cancelled,
            _ => Self::Running,
        }
    }
}

fn goal_artifact_id(task_id: &TaskId) -> String {
    format!("goal-{}", task_id.0)
}

const ASK_PROMPT: &str = "Which form should we use?";
const ASK_BRIEF_LABEL: &str = "Brief answer";
const ASK_BRIEF_CONSEQUENCES: &str = "The essentials without a breakdown.";
const ASK_STEPS_LABEL: &str = "Step-by-step";
const ASK_STEPS_CONSEQUENCES: &str = "Sequential steps with an explanation of each.";
const ASK_WORKED_LABEL: &str = "Worked example";
const ASK_WORKED_CONSEQUENCES: &str = "A full example from the given conditions to the result.";
const ASK_COMPARE_LABEL: &str = "Compare options";
const ASK_COMPARE_CONSEQUENCES: &str = "A table of trade-offs.";
const ASK_DIAGRAM_LABEL: &str = "Diagram";
const ASK_DIAGRAM_CONSEQUENCES: &str = "A visual structure diagram.";
const ASK_DIAGRAM_DISABLED: &str = "no useful diagram for this topic";
const ASK_RECOMMENDATION: &str =
    "the request does not need a detailed breakdown; the brief form meets the criterion.";

impl Question {
    pub fn fixture(task_id: &TaskId, intent_revision: u64) -> Self {
        let option = |id: &str, label: &str, consequences: &str, availability: Availability| {
            QuestionOption {
                option_id: OptionId(id.to_string()),
                label: label.to_string(),
                consequences: consequences.to_string(),
                availability,
            }
        };
        Self {
            question_id: QuestionId::generate(),
            question_revision: 1,
            task_id: task_id.clone(),
            intent_revision,
            prompt: ASK_PROMPT.to_string(),
            options: vec![
                option(
                    KNOWN_READY_OPTION,
                    ASK_BRIEF_LABEL,
                    ASK_BRIEF_CONSEQUENCES,
                    Availability::Enabled,
                ),
                option(
                    "steps",
                    ASK_STEPS_LABEL,
                    ASK_STEPS_CONSEQUENCES,
                    Availability::Enabled,
                ),
                option(
                    "worked",
                    ASK_WORKED_LABEL,
                    ASK_WORKED_CONSEQUENCES,
                    Availability::Enabled,
                ),
                option(
                    "compare",
                    ASK_COMPARE_LABEL,
                    ASK_COMPARE_CONSEQUENCES,
                    Availability::Enabled,
                ),
                option(
                    "diagram",
                    ASK_DIAGRAM_LABEL,
                    ASK_DIAGRAM_CONSEQUENCES,
                    Availability::Disabled {
                        reason: ASK_DIAGRAM_DISABLED.to_string(),
                    },
                ),
            ],
            recommended_option_id: OptionId(KNOWN_READY_OPTION.to_string()),
            recommendation_basis: ASK_RECOMMENDATION.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TaskStore;
    use super::proof::{CHILD_ROOT, ChildEntry, custody_failure, run_probe_child, spawn_child};
    use crate::contracts::TaskId;
    use rusqlite::OptionalExtension as _;
    use rusqlite::params;

    #[test]
    fn reopening_store_does_not_rewrite_existing_projection()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::TempDir::with_prefix("rivect-state-projection-")?;
        let path = root.path().join("state.db");
        let task_id = TaskId::generate().0;
        {
            let store = TaskStore::open(&path)?;
            store.conn.as_ref().expect("store connection is open").execute(
                "INSERT INTO tasks (task_id, session_id, revision, intent_revision, contract_revision, lifecycle, goal_bytes, goal_digest, goal_artifact_id, event_cursor)
                 VALUES (?1, ?2, 1, 1, 1, 'running', ?3, ?4, ?5, 0)",
                params![task_id, "session", vec![b'g'], "digest", "artifact"],
            )?;
        }
        let reopened = TaskStore::open(&path)?;
        assert_eq!(
            reopened
                .conn
                .as_ref()
                .expect("store connection is open")
                .total_changes(),
            0,
            "opening an in-sync store must not rewrite todo_projection"
        );
        let projection_count: i64 = reopened
            .conn
            .as_ref()
            .expect("store connection is open")
            .query_row(
                "SELECT COUNT(*) FROM todo_projection WHERE task_id = ?1",
                params![task_id],
                |row| row.get(0),
            )?;
        assert_eq!(projection_count, 1);
        drop(reopened);

        let drifted = TaskStore::open(&path)?;
        drifted
            .conn
            .as_ref()
            .expect("store connection is open")
            .execute(
                "DELETE FROM todo_projection WHERE task_id = ?1",
                params![task_id],
            )?;
        drop(drifted);
        let repaired = TaskStore::open(&path)?;
        assert_eq!(
            repaired
                .conn
                .as_ref()
                .expect("store connection is open")
                .total_changes(),
            1
        );
        let repaired_count: i64 = repaired
            .conn
            .as_ref()
            .expect("store connection is open")
            .query_row(
                "SELECT COUNT(*) FROM todo_projection WHERE task_id = ?1",
                params![task_id],
                |row| row.get(0),
            )?;
        assert_eq!(repaired_count, 1);
        drop(repaired);

        Ok(())
    }

    /// The publication `identity` column keeps an attested write identity
    /// as `v2:` with its reuse token and an unattested one as the legacy
    /// pair, and a column it cannot decode fails the read. One journal
    /// holding every row form survives a reopen and the boot recovery with
    /// no row added, removed or converted.
    #[test]
    fn publication_identity_column_round_trips_and_rejects_malformed()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::config::{PublicationIntent, PublicationVerdict};
        use crate::executor::{FileIdentity, Unattested, WriteIdentity};
        use rivect_sandbox_helper::ReuseToken;

        let linux_token = ReuseToken::from_bytes(&[
            1, 0x81, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03,
        ])
        .ok_or("linux token shape")?;
        let darwin_token = ReuseToken::from_bytes(&[
            2, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ])
        .ok_or("darwin token shape")?;
        let full_handle = [[1, 0x81, 0, 0, 0].as_slice(), &[0x5a; 128]].concat();
        let full_token = ReuseToken::from_bytes(&full_handle).ok_or("full handle token shape")?;

        // Codec: each form against its independently spelled column.
        let full_column = format!(
            "v2:ffffffffffffffff:ffffffffffffffff:0181000000{}",
            "5a".repeat(128)
        );
        for (identity, column) in [
            (
                WriteIdentity::new(FileIdentity::new(0x2a, 0x7), Ok(linux_token)),
                "v2:2a:7:0181000000deadbeef00010203",
            ),
            (
                WriteIdentity::new(FileIdentity::new(0x2a, 0x7), Ok(darwin_token)),
                "v2:2a:7:021032547698badcfe0123456789abcdef",
            ),
            (
                WriteIdentity::new(FileIdentity::new(u64::MAX, u64::MAX), Ok(full_token)),
                full_column.as_str(),
            ),
        ] {
            assert_eq!(super::encode_publish_identity(&identity), column);
            assert_eq!(super::parse_publish_identity(column)?, identity);
        }
        let longest = super::encode_publish_identity(&WriteIdentity::new(
            FileIdentity::new(u64::MAX, u64::MAX),
            Ok(full_token),
        ));
        assert_eq!(longest.len(), 303, "the longest column is the bound");
        assert_eq!(
            super::encode_publish_identity(&WriteIdentity::new(
                FileIdentity::new(0x2a, 0x7),
                Err(Unattested::Unsupported)
            )),
            "2a:7"
        );
        assert_eq!(
            super::parse_publish_identity("2a:7")?,
            WriteIdentity::new(FileIdentity::new(0x2a, 0x7), Err(Unattested::Unrecorded))
        );

        let too_long = format!("{longest}0");
        let oversized_token = format!("v2:2a:7:0181000000{}", "5a".repeat(129));
        for malformed in [
            "",
            "2a",
            "2a:7:9",
            ":7",
            "2a:",
            "+2a:7",
            "2a:-7",
            "g:7",
            "00000000000000001:7",
            "v2:2a:7",
            "v2:2a:7:",
            "v2:2a:7:018",
            "v2:2a:7:01810000zz",
            "v3:2a:7:0181000000deadbeef00010203",
            "v2:2a:7:0381000000deadbeef00010203",
            "v2:2a:7:0181000000",
            "v2:2a:7:0181000000dead",
            "v2:2a:7:021032547698badcfe0123456789abcd",
            "v2:2a:7:0181000000deadbeef00010203:00",
            "v2::7:0181000000deadbeef00010203",
            oversized_token.as_str(),
            too_long.as_str(),
        ] {
            assert!(
                matches!(
                    super::parse_publish_identity(malformed),
                    Err(rusqlite::Error::FromSqlConversionFailure(
                        5,
                        rusqlite::types::Type::Text,
                        _
                    ))
                ),
                "{malformed:?} must fail the read"
            );
        }

        // Mixed journal: pending v2, applied v2, pending legacy and
        // pending identity-less rows, all on absent targets.
        let root = tempfile::TempDir::with_prefix("rivect-publication-identity-")?;
        let db = root.path().join("state.db");
        let target = |name: &str| -> Result<String, Box<dyn std::error::Error>> {
            Ok(root
                .path()
                .join("absent")
                .join(name)
                .to_str()
                .ok_or("utf-8 target")?
                .to_string())
        };
        let (pending_v2, applied_v2, legacy, bare) = (
            target("a-pending-v2.toml")?,
            target("b-applied-v2.toml")?,
            target("c-pending-legacy.toml")?,
            target("d-pending-bare.toml")?,
        );
        let mut store = TaskStore::open(&db)?;
        let pending_v2_seq = store.append_publication(
            "owner-a",
            &pending_v2,
            "intended-a",
            Some("base-a"),
            Some(WriteIdentity::new(
                FileIdentity::new(0x10, 0x20),
                Ok(linux_token),
            )),
        )?;
        let applied_v2_seq = store.append_publication(
            "owner-b",
            &applied_v2,
            "intended-b",
            None,
            Some(WriteIdentity::new(
                FileIdentity::new(0x11, 0x21),
                Ok(darwin_token),
            )),
        )?;
        store.complete_publication("owner-b", &applied_v2, applied_v2_seq)?;
        let legacy_seq = store.append_publication(
            "owner-c",
            &legacy,
            "intended-c",
            Some("base-c"),
            Some(WriteIdentity::new(
                FileIdentity::new(0x12, 0x22),
                Err(Unattested::Unsupported),
            )),
        )?;
        let bare_seq = store.append_publication("owner-d", &bare, "intended-d", None, None)?;

        let intent = |owner: &str,
                      target: &str,
                      admission_seq: u64,
                      intended: &str,
                      base: Option<&str>,
                      identity: Option<WriteIdentity>| PublicationIntent {
            owner: owner.to_string(),
            target: target.to_string(),
            admission_seq,
            intended_digest: intended.to_string(),
            base_digest: base.map(str::to_string),
            publish_identity: identity,
        };
        let pending = store.pending_publications()?;
        let applied = store.applied_publications()?;
        assert_eq!(
            pending,
            vec![
                intent(
                    "owner-a",
                    &pending_v2,
                    pending_v2_seq,
                    "intended-a",
                    Some("base-a"),
                    Some(WriteIdentity::new(
                        FileIdentity::new(0x10, 0x20),
                        Ok(linux_token)
                    )),
                ),
                intent(
                    "owner-c",
                    &legacy,
                    legacy_seq,
                    "intended-c",
                    Some("base-c"),
                    Some(WriteIdentity::new(
                        FileIdentity::new(0x12, 0x22),
                        Err(Unattested::Unrecorded)
                    )),
                ),
                intent("owner-d", &bare, bare_seq, "intended-d", None, None),
            ]
        );
        assert_eq!(
            applied,
            vec![intent(
                "owner-b",
                &applied_v2,
                applied_v2_seq,
                "intended-b",
                None,
                Some(WriteIdentity::new(
                    FileIdentity::new(0x11, 0x21),
                    Ok(darwin_token)
                )),
            )]
        );
        assert_eq!(
            pending[0].publish_identity.map(|identity| identity.reuse()),
            Some(Ok(linux_token)),
            "the pending attested row keeps its token"
        );
        assert_eq!(
            applied[0].publish_identity.map(|identity| identity.reuse()),
            Some(Ok(darwin_token)),
            "the applied attested row keeps its token"
        );
        drop(store);

        let mut store = TaskStore::open(&db)?;
        let recoveries = crate::config::recover_publications(&mut store)?;
        assert_eq!(
            recoveries
                .iter()
                .map(|recovery| (&recovery.intent, recovery.verdict))
                .collect::<Vec<_>>(),
            pending
                .iter()
                .map(|intent| (intent, PublicationVerdict::Absent))
                .collect::<Vec<_>>(),
            "the boot recovery sees exactly the pending rows, each absent"
        );
        assert_eq!(store.pending_publications()?, pending, "no row receipted");
        assert_eq!(store.applied_publications()?, applied);
        Ok(())
    }

    /// CR-8, FP-064-G: every obligation, plan-row, selection, gate-hold
    /// and verdict decoder refuses a stored value outside its vocabulary
    /// on its read path — corrupt state is never read as `required`,
    /// `pending`, a guessed wait, a request kind, a hold or a verdict.
    #[test]
    fn stored_obligation_states_decode_strictly() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::TempDir::with_prefix("rivect-strict-decode-")?;
        let mut store = TaskStore::open(&root.path().join("state.db"))?;
        let session = crate::contracts::SessionId("strict-session".to_string());
        let task = store
            .create_task(
                &session,
                "cmd-strict",
                "human",
                "decode strictly",
                (&["one criterion".to_string()], &[]),
            )?
            .task_id;
        store.materialize_obligations(&task)?;
        assert!(store.snapshot(&task).is_ok(), "the clean rows decode");

        let is_storage = |result: super::Result<crate::contracts::TaskSnapshot>| {
            matches!(result, Err(super::StoreError::Storage(_)))
        };
        for (column, bogus) in [("applicability", "maybe"), ("execution", "done")] {
            let clean = if column == "applicability" {
                "required"
            } else {
                "pending"
            };
            store
                .conn
                .as_ref()
                .expect("store connection is open")
                .execute(
                    &format!("UPDATE obligations SET {column} = ?2 WHERE task_id = ?1"),
                    params![task.0, bogus],
                )?;
            assert!(
                is_storage(store.snapshot(&task)),
                "an unknown stored {column} {bogus:?} is corrupt storage"
            );
            store
                .conn
                .as_ref()
                .expect("store connection is open")
                .execute(
                    &format!("UPDATE obligations SET {column} = ?2 WHERE task_id = ?1"),
                    params![task.0, clean],
                )?;
        }
        assert!(store.snapshot(&task).is_ok());

        let insert_row = |store: &TaskStore,
                          applicability: &str,
                          execution: &str,
                          stage: i64,
                          blocker: Option<&str>| {
            store
                .conn
                .as_ref()
                .expect("store connection is open")
                .execute(
                    "INSERT OR REPLACE INTO plan_obligations
                     (task_id, capability, applicability, execution, stage, handler, blocker)
                 VALUES (?1, 'frame_goal', ?2, ?3, ?4, 'frame_goal', ?5)",
                    params![task.0, applicability, execution, stage, blocker],
                )
        };
        let clean_blocker = serde_json::to_string(&super::plan_blocker(
            crate::contracts::ErrorCode::DependencyBlocked,
            "frame_goal",
        ))?;
        insert_row(&store, "required", "pending", 1, Some(&clean_blocker))?;
        assert!(
            store.plan_obligations(&task).is_ok(),
            "a clean plan row decodes"
        );
        let unknown_kind = clean_blocker.replace("\"dependency\"", "\"telepathy\"");
        for (applicability, execution, stage, blocker) in [
            ("sometimes", "pending", 1, Some(clean_blocker.as_str())),
            ("required", "finished", 1, Some(clean_blocker.as_str())),
            ("required", "pending", 7, Some(clean_blocker.as_str())),
            ("required", "pending", 1, Some(unknown_kind.as_str())),
        ] {
            insert_row(&store, applicability, execution, stage, blocker)?;
            assert!(
                matches!(
                    store.plan_obligations(&task),
                    Err(super::StoreError::Storage(_))
                ),
                "plan row ({applicability}, {execution}, {stage}, {blocker:?}) is corrupt storage"
            );
            assert!(
                is_storage(store.snapshot(&task)),
                "the snapshot refuses the corrupt plan row too"
            );
        }
        insert_row(&store, "required", "pending", 1, Some(&clean_blocker))?;

        // The selection's request kind: its reader and the gate refuse it.
        store
            .conn
            .as_ref()
            .expect("store connection is open")
            .execute(
                "INSERT INTO plan_selections (task_id, revision, facts_digest, request_kind)
             VALUES (?1, 1, 'digest', 'vibes')",
                params![task.0],
            )?;
        assert!(
            matches!(
                store.plan_selection(&task),
                Err(super::StoreError::Storage(_))
            ),
            "an unknown request kind is corrupt storage"
        );
        assert!(
            matches!(store.plan_gate(&task), Err(super::StoreError::Storage(_))),
            "the gate never reads a corrupt selection"
        );
        store
            .conn
            .as_ref()
            .expect("store connection is open")
            .execute(
                "UPDATE plan_selections SET request_kind = 'change' WHERE task_id = ?1",
                params![task.0],
            )?;
        assert!(store.plan_selection(&task).is_ok());

        // A plan verdict: the revision reader and the gate's revision
        // conjunct (a required `plan_work`) refuse it.
        store
            .conn
            .as_ref()
            .expect("store connection is open")
            .execute(
                "INSERT INTO plan_obligations
                 (task_id, capability, applicability, execution, stage, handler)
             VALUES (?1, 'plan_work', 'required', 'satisfied', 1, 'plan_work')",
                params![task.0],
            )?;
        store
            .conn
            .as_ref()
            .expect("store connection is open")
            .execute(
                "INSERT INTO plans (task_id, revision, selection_revision, body_json, verdict)
             VALUES (?1, 1, 1, '{}', 'maybe')",
                params![task.0],
            )?;
        assert!(
            matches!(
                store.plan_revisions(&task),
                Err(super::StoreError::Storage(_))
            ),
            "an unknown verdict is corrupt storage"
        );
        assert!(
            matches!(store.plan_gate(&task), Err(super::StoreError::Storage(_))),
            "the gate never reads a corrupt verdict"
        );
        store
            .conn
            .as_ref()
            .expect("store connection is open")
            .execute(
                "UPDATE plans SET verdict = 'pass' WHERE task_id = ?1",
                params![task.0],
            )?;
        assert!(store.plan_revisions(&task).is_ok());
        assert!(store.plan_gate(&task).is_ok());

        // A gate hold's kind: a blocked task projects its hold, so the
        // snapshot is its read path.
        store
            .conn
            .as_ref()
            .expect("store connection is open")
            .execute(
                "INSERT INTO plan_gate_holds (task_id, kind) VALUES (?1, 'sleepy')",
                params![task.0],
            )?;
        store.mark_no_ready(&task)?;
        assert!(
            is_storage(store.snapshot(&task)),
            "an unknown gate hold kind is corrupt storage"
        );
        store
            .conn
            .as_ref()
            .expect("store connection is open")
            .execute(
                "UPDATE plan_gate_holds SET kind = 'paused' WHERE task_id = ?1",
                params![task.0],
            )?;
        assert!(store.snapshot(&task).is_ok());
        drop(store);

        Ok(())
    }

    #[test]
    fn charge_sql_requires_reserved_ge_bound() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::TempDir::with_prefix("rivect-charge-reserved-")?;
        let path = root.path().join("state.db");
        let mut store = TaskStore::open(&path)?;
        store.open_budget("root", 8)?;
        store.budget_reserve("res", &["root"], 4)?;
        store
            .conn
            .as_ref()
            .expect("store connection is open")
            .execute(
                "UPDATE budget_scopes SET reserved = 1 WHERE scope = ?1",
                params!["root"],
            )?;
        let error = store
            .budget_charge("res", Some(1))
            .expect_err("reserved below bound");
        assert!(
            matches!(
                error,
                super::StoreError::Conflict(super::ConflictCause::ChargeReservedBelowBound {
                    reserved: 1,
                    bound: 4,
                    ..
                })
            ),
            "{error}"
        );
        drop(store);

        Ok(())
    }

    fn claim_fixture(
        tag: &str,
    ) -> (
        tempfile::TempDir,
        TaskStore,
        crate::contracts::SessionId,
        TaskId,
        String,
        super::CheckClaim,
    ) {
        let root = tempfile::TempDir::with_prefix(format!("rivect-claim-{tag}-"))
            .unwrap_or_else(|error| unreachable!("the claim root is created: {error}"));
        let mut store = TaskStore::open(&root.path().join("state.db"))
            .unwrap_or_else(|error| unreachable!("the claim store opens: {error:?}"));
        let (session, _, _, _) = store
            .open_session(&format!("session-{tag}"), &format!("conn-{tag}"), None)
            .expect("session");
        let task = store
            .create_task(
                &session,
                &format!("command-{tag}"),
                "unit",
                "claim goal",
                (&[], &[]),
            )
            .expect("task")
            .task_id;
        let record = store
            .record_plan_selection(
                &session,
                &task,
                &crate::state::PlanSelectionWrite {
                    facts_digest: "claim-facts",
                    request_kind: crate::state::RequestKind::PlanOnly,
                    rows: &[],
                },
            )
            .expect("selection");
        assert_eq!(record.revision, 1);
        let attempt = store
            .plan_attempt(
                &task,
                crate::contracts::EffectClass::Exec,
                "confined check claim",
            )
            .expect("attempt");
        let claim = super::CheckClaim {
            task_id: task.clone(),
            attempt_id: attempt.clone(),
            native: true,
            selection_revision: 1,
            facts_digest: "claim-facts".to_string(),
            request_kind: crate::state::RequestKind::PlanOnly,
            binding_digest: "claim-binding".to_string(),
        };
        (root, store, session, task, attempt, claim)
    }

    fn refusal(outcome: super::Result<super::ClaimOutcome>) -> super::ClaimRefusal {
        match outcome.expect("claim call reaches its typed outcome") {
            super::ClaimOutcome::Refused(refusal) => refusal,
            super::ClaimOutcome::Claimed => unreachable!("expected a typed refusal"),
        }
    }

    fn marker_boundary(attempt: &str) -> String {
        format!("ret:check:{attempt}:admit.claim")
    }

    fn commit_boundary(attempt: &str) -> String {
        format!("ret:check:{attempt}:admit.claim_commit")
    }

    #[test]
    fn check_issuer_store_claim_is_atomic() {
        // (a) the claim site map is exhaustive and injective: every
        // refusal carries one stable suffix and no two sites alias.
        let table = [
            (super::ClaimSite::WaitRead, "admit.claim_wait_read"),
            (super::ClaimSite::WaitSet, "admit.claim_wait_set"),
            (super::ClaimSite::Cancel, "admit.claim_cancel"),
            (super::ClaimSite::Deadline, "admit.claim_deadline"),
            (super::ClaimSite::Busy, "admit.claim_busy"),
            (super::ClaimSite::Begin, "admit.claim_begin"),
            (super::ClaimSite::Read, "admit.claim_read"),
            (super::ClaimSite::TerminalRead, "admit.claim_terminal_read"),
            (super::ClaimSite::Lifecycle, "admit.claim_lifecycle"),
            (super::ClaimSite::Attempt, "admit.attempt"),
            (super::ClaimSite::Replay, "admit.replay"),
            (
                super::ClaimSite::SelectionRead,
                "admit.claim_selection_read",
            ),
            (super::ClaimSite::Selection, "admit.claim_selection"),
            (super::ClaimSite::GateRead, "admit.claim_gate_read"),
            (super::ClaimSite::Gate, "admit.claim_gate"),
            (super::ClaimSite::Update, "admit.claim_update"),
            (super::ClaimSite::Marker, "admit.claim_marker"),
            (super::ClaimSite::WaitRestore, "admit.claim_wait_restore"),
            (super::ClaimSite::Commit, "admit.claim_commit"),
        ];
        for (index, (site, suffix)) in table.iter().enumerate() {
            assert_eq!(site.suffix(), *suffix, "site {index}");
        }
        let mut suffixes: Vec<_> = table.iter().map(|(_, suffix)| *suffix).collect();
        suffixes.sort_unstable();
        let distinct = suffixes
            .windows(2)
            .filter(|pair| pair[0] == pair[1])
            .count()
            == 0;
        assert!(distinct, "no two claim sites may share one suffix");

        // (b) a successful claim is first-only: marker row, running
        // state, and every later presentation refuses as a replay.
        let (_root, mut store, _session, _task, attempt, claim) = claim_fixture("success");
        assert!(matches!(
            store.claim_check(
                &claim,
                &std::sync::atomic::AtomicBool::new(false),
                claim_deadline()
            ),
            Ok(super::ClaimOutcome::Claimed)
        ));
        assert!(
            store
                .has_retained(&marker_boundary(&attempt))
                .expect("marker read")
        );
        assert_eq!(
            store.attempt_state(&attempt).expect("state").as_deref(),
            Some("running")
        );
        assert_eq!(
            refusal(store.claim_check(
                &claim,
                &std::sync::atomic::AtomicBool::new(false),
                claim_deadline()
            ))
            .site,
            super::ClaimSite::Replay
        );
        drop(store);

        // (b2) the Custom-off variant skips the selection and gate
        // statements by its explicit flag, never by field values: the
        // same zero/empty selection fields claim a task with no
        // recorded selection when `native` is false, and refuse at
        // `admit.claim_selection` when the flag is true.
        let (_root, mut store, session, _task, _attempt, _claim) = claim_fixture("custom-off");
        let bare = store
            .create_task(
                &session,
                "custom-command",
                "unit",
                "custom goal",
                (&[], &[]),
            )
            .expect("bare task")
            .task_id;
        let bare_attempt = store
            .plan_attempt(
                &bare,
                crate::contracts::EffectClass::Exec,
                "custom check claim",
            )
            .expect("bare attempt");
        let custom = super::CheckClaim {
            task_id: bare.clone(),
            attempt_id: bare_attempt.clone(),
            native: false,
            selection_revision: 0,
            facts_digest: String::new(),
            request_kind: crate::state::RequestKind::PlanOnly,
            binding_digest: "custom-binding".to_string(),
        };
        assert!(matches!(
            store.claim_check(
                &custom,
                &std::sync::atomic::AtomicBool::new(false),
                claim_deadline()
            ),
            Ok(super::ClaimOutcome::Claimed)
        ));
        assert!(
            store
                .has_retained(&marker_boundary(&bare_attempt))
                .expect("marker read")
        );
        // A fresh attempt carries the same zero/empty selection fields
        // with `native: true`: the store's recorded selection (revision
        // 1 from the fixture) does not match, and the claim refuses at
        // the selection seam — the flag, not the field values, drives
        // the skip. (A second claim on the same attempt would refuse as
        // a replay before #7 ever runs.)
        let native_attempt = store
            .plan_attempt(
                &bare,
                crate::contracts::EffectClass::Exec,
                "custom check claim",
            )
            .expect("native-shape attempt");
        let native_shape = super::CheckClaim {
            attempt_id: native_attempt,
            native: true,
            ..custom
        };
        assert_eq!(
            refusal(store.claim_check(
                &native_shape,
                &std::sync::atomic::AtomicBool::new(false),
                claim_deadline()
            ))
            .site,
            super::ClaimSite::Selection
        );
        drop(store);

        // (c) each claim statement failure returns its own site with
        // zero effect: the attempt stays planned and no marker exists.
        let fault_sites = [
            (super::proof::Site::WaitRead, super::ClaimSite::WaitRead),
            (super::proof::Site::WaitSet, super::ClaimSite::WaitSet),
            (super::proof::Site::Begin, super::ClaimSite::Begin),
            (super::proof::Site::Read, super::ClaimSite::Read),
            (
                super::proof::Site::TerminalRead,
                super::ClaimSite::TerminalRead,
            ),
            (
                super::proof::Site::SelectionRead,
                super::ClaimSite::SelectionRead,
            ),
            (super::proof::Site::GateRead, super::ClaimSite::GateRead),
            (super::proof::Site::Update, super::ClaimSite::Update),
            (super::proof::Site::Marker, super::ClaimSite::Marker),
        ];
        for (fault, expected) in fault_sites {
            let (_root, mut store, _session, _task, attempt, claim) = claim_fixture("fault");
            super::proof::arm_fault(fault);
            let outcome = store.claim_check(
                &claim,
                &std::sync::atomic::AtomicBool::new(false),
                claim_deadline(),
            );
            assert_eq!(refusal(outcome).site, expected, "fault {fault:?}");
            assert!(
                !store
                    .has_retained(&marker_boundary(&attempt))
                    .expect("marker read")
            );
            assert_eq!(
                store.attempt_state(&attempt).expect("state").as_deref(),
                Some("planned")
            );
            drop(store);
        }

        // (d) cancellation and an expired deadline refuse before BEGIN.
        let (_root, mut store, _session, _task, _attempt, claim) = claim_fixture("stops");
        assert_eq!(
            refusal(store.claim_check(
                &claim,
                &std::sync::atomic::AtomicBool::new(true),
                claim_deadline()
            ))
            .site,
            super::ClaimSite::Cancel
        );
        assert_eq!(
            refusal(store.claim_check(
                &claim,
                &std::sync::atomic::AtomicBool::new(false),
                std::time::Instant::now()
            ))
            .site,
            super::ClaimSite::Deadline
        );
        drop(store);

        // (e) a held writer lock refuses busy without waiting: the
        // claim returns while the second connection still holds BEGIN
        // IMMEDIATE, zero claim, and the denial row could not land.
        let (root, mut store, _session, _task, attempt, claim) = claim_fixture("busy");
        let holder = rusqlite::Connection::open(root.path().join("state.db"))
            .unwrap_or_else(|error| unreachable!("the holder connection opens: {error}"));
        holder
            .busy_timeout(std::time::Duration::ZERO)
            .expect("zero wait");
        holder.execute_batch("BEGIN IMMEDIATE").expect("lock");
        let started = std::time::Instant::now();
        let outcome = refusal(store.claim_check(
            &claim,
            &std::sync::atomic::AtomicBool::new(false),
            claim_deadline(),
        ));
        assert_eq!(outcome.site, super::ClaimSite::Busy);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(matches!(
            outcome.retention,
            super::RetentionOutcome::Unavailable
        ));
        assert!(
            !store
                .has_retained(&marker_boundary(&attempt))
                .expect("marker read")
        );
        drop(holder);
        drop(store);

        // (f) an ambiguous COMMIT both ways: the same typed site, and
        // only the authoritative marker separates durable from not.
        let (_root, mut store, _session, _task, attempt, claim) =
            claim_fixture("commit-nondurable");
        super::proof::arm_fault(super::proof::Site::CommitBeforeExec);
        let outcome = refusal(store.claim_check(
            &claim,
            &std::sync::atomic::AtomicBool::new(false),
            claim_deadline(),
        ));
        assert_eq!(outcome.site, super::ClaimSite::Commit);
        assert!(
            !store
                .has_retained(&marker_boundary(&attempt))
                .expect("marker read")
        );
        assert_eq!(
            store.attempt_state(&attempt).expect("state").as_deref(),
            Some("planned")
        );
        drop(store);

        let (_root, mut store, _session, _task, attempt, claim) = claim_fixture("commit-durable");
        super::proof::arm_fault(super::proof::Site::CommitAfterDurable);
        let outcome = refusal(store.claim_check(
            &claim,
            &std::sync::atomic::AtomicBool::new(false),
            claim_deadline(),
        ));
        assert_eq!(outcome.site, super::ClaimSite::Commit);
        assert!(
            store
                .has_retained(&marker_boundary(&attempt))
                .expect("marker read")
        );
        assert_eq!(
            store.attempt_state(&attempt).expect("state").as_deref(),
            Some("running")
        );
        drop(store);

        // (g) a held COMMIT record moves into the private holder when
        // the same-connection write cannot run, quarantining the store
        // until a reopen of the same path writes it as the first store
        // operation — before every bootstrap statement.
        let (root, mut store, _session, _task, attempt, claim) = claim_fixture("held");
        super::proof::arm_fault(super::proof::Site::CommitBeforeExec);
        super::proof::arm_fault(super::proof::Site::RollbackAfterCommitError);
        let outcome = refusal(store.claim_check(
            &claim,
            &std::sync::atomic::AtomicBool::new(false),
            claim_deadline(),
        ));
        assert_eq!(outcome.site, super::ClaimSite::Commit);
        assert!(
            store.is_quarantined(),
            "the held record quarantines the store"
        );
        assert!(matches!(
            store.attempt_state(&attempt),
            Err(super::StoreError::Closed)
        ));
        assert!(matches!(
            store.has_retained(&marker_boundary(&attempt)),
            Err(super::StoreError::Closed)
        ));
        store
            .reopen(&root.path().join("state.db"))
            .expect("reopen writes the held record");
        assert!(!store.is_quarantined());
        let record = store
            .retained(&commit_boundary(&attempt))
            .expect("readback")
            .expect("the carried row landed");
        assert!(
            record.contains("admit.claim_commit"),
            "the carried record keeps its fixed cause: {record}"
        );
        assert!(
            !matches!(store.has_retained(&marker_boundary(&attempt)), Ok(true)),
            "a COMMIT that never executed leaves no marker"
        );
        drop(store);

        // (h) the same-connection write failing lands in the same
        // holder path.
        let (root, mut store, _session, _task, attempt, claim) = claim_fixture("same-conn-write");
        super::proof::arm_fault(super::proof::Site::CommitBeforeExec);
        super::proof::arm_fault(super::proof::Site::SameConnectionWrite);
        let outcome = refusal(store.claim_check(
            &claim,
            &std::sync::atomic::AtomicBool::new(false),
            claim_deadline(),
        ));
        assert_eq!(outcome.site, super::ClaimSite::Commit);
        assert!(store.is_quarantined());
        store
            .reopen(&root.path().join("state.db"))
            .expect("reopen writes the held record");
        assert!(
            store
                .retained(&commit_boundary(&attempt))
                .expect("readback")
                .is_some()
        );
        drop(store);

        // (i) reopen contract: an injected close failure (live slot, the
        // fallible open never attempted, the returned handle dropped so
        // a second connection takes the writer lock) and then an
        // injected open failure (empty slot) each leave every store
        // call typed-closed with the record held; a later successful
        // reopen writes the exact carried record.
        let (root, mut store, _session, _task, attempt, claim) = claim_fixture("reopen-failures");
        super::proof::arm_fault(super::proof::Site::CommitBeforeExec);
        super::proof::arm_fault(super::proof::Site::RollbackAfterCommitError);
        refusal(store.claim_check(
            &claim,
            &std::sync::atomic::AtomicBool::new(false),
            claim_deadline(),
        ));
        assert!(store.is_quarantined());
        super::proof::arm_fault(super::proof::Site::Close);
        assert!(matches!(
            store.reopen(&root.path().join("state.db")),
            Err(super::StoreError::Storage(_))
        ));
        assert!(store.is_quarantined());
        assert!(matches!(
            store.snapshot(&TaskId("gone".to_string())),
            Err(super::StoreError::Closed)
        ));
        {
            let probe = rusqlite::Connection::open(root.path().join("state.db"))
                .unwrap_or_else(|error| unreachable!("the probe connection opens: {error}"));
            probe
                .busy_timeout(std::time::Duration::ZERO)
                .expect("zero wait");
            probe
                .execute_batch("BEGIN IMMEDIATE")
                .expect("dropped handle released the writer lock");
            probe.execute_batch("ROLLBACK").expect("rollback");
        }
        super::proof::arm_fault(super::proof::Site::Open);
        assert!(matches!(
            store.reopen(&root.path().join("state.db")),
            Err(super::StoreError::Storage(_))
        ));
        assert!(store.is_quarantined());
        store
            .reopen(&root.path().join("state.db"))
            .expect("reopen writes the held record");
        assert!(
            store
                .retained(&commit_boundary(&attempt))
                .expect("readback")
                .is_some()
        );
        drop(store);

        // (j) final carried-write failure: a live slot, an empty
        // holder, no row anywhere, and a later reopen writes nothing.
        let (root, mut store, _session, _task, attempt, claim) = claim_fixture("final-write");
        super::proof::arm_fault(super::proof::Site::CommitBeforeExec);
        super::proof::arm_fault(super::proof::Site::RollbackAfterCommitError);
        refusal(store.claim_check(
            &claim,
            &std::sync::atomic::AtomicBool::new(false),
            claim_deadline(),
        ));
        super::proof::arm_fault(super::proof::Site::CarriedWrite);
        assert!(matches!(
            store.reopen(&root.path().join("state.db")),
            Err(super::StoreError::Storage(_))
        ));
        assert!(!store.is_quarantined());
        assert!(
            store
                .retained(&commit_boundary(&attempt))
                .expect("readback")
                .is_none()
        );
        store
            .reopen(&root.path().join("state.db"))
            .expect("no second write");
        assert!(
            store
                .retained(&commit_boundary(&attempt))
                .expect("readback")
                .is_none()
        );
        drop(store);

        // (k) the holder ends with the store: a fresh open sees no row.
        let (root, mut store, _session, _task, attempt, claim) = claim_fixture("holder-end");
        super::proof::arm_fault(super::proof::Site::CommitBeforeExec);
        super::proof::arm_fault(super::proof::Site::RollbackAfterCommitError);
        refusal(store.claim_check(
            &claim,
            &std::sync::atomic::AtomicBool::new(false),
            claim_deadline(),
        ));
        drop(store);
        let fresh = TaskStore::open(&root.path().join("state.db"))
            .unwrap_or_else(|error| unreachable!("the fresh open succeeds: {error:?}"));
        assert!(
            fresh
                .retained(&commit_boundary(&attempt))
                .expect("readback")
                .is_none()
        );
        drop(fresh);

        // (l) the owner routes: reopen through Owner::reopen_store and
        // a healthy close through Owner::close_store; the owner lock
        // stays held across a failed reopen.
        let root = tempfile::TempDir::with_prefix("rivect-claim-owner-")
            .unwrap_or_else(|error| unreachable!("the scratch root is created: {error}"));
        {
            let mut owner = crate::owner::Owner::elect(root.path())
                .unwrap_or_else(|error| unreachable!("the owner is elected: {error:?}"));
            let (session, _, _, _) = owner
                .store
                .open_session("owner-session", "owner-conn", None)
                .expect("session");
            let task = owner
                .store
                .create_task(&session, "owner-command", "unit", "claim goal", (&[], &[]))
                .expect("task")
                .task_id;
            owner
                .store
                .record_plan_selection(
                    &session,
                    &task,
                    &crate::state::PlanSelectionWrite {
                        facts_digest: "claim-facts",
                        request_kind: crate::state::RequestKind::PlanOnly,
                        rows: &[],
                    },
                )
                .expect("selection");
            let attempt = owner
                .store
                .plan_attempt(
                    &task,
                    crate::contracts::EffectClass::Exec,
                    "confined check claim",
                )
                .expect("attempt");
            let claim = super::CheckClaim {
                task_id: task,
                attempt_id: attempt.clone(),
                native: true,
                selection_revision: 1,
                facts_digest: "claim-facts".to_string(),
                request_kind: crate::state::RequestKind::PlanOnly,
                binding_digest: "claim-binding".to_string(),
            };
            super::proof::arm_fault(super::proof::Site::CommitBeforeExec);
            super::proof::arm_fault(super::proof::Site::RollbackAfterCommitError);
            refusal(owner.store.claim_check(
                &claim,
                &std::sync::atomic::AtomicBool::new(false),
                claim_deadline(),
            ));
            super::proof::arm_fault(super::proof::Site::Open);
            assert!(owner.reopen_store().is_err());
            assert!(matches!(
                crate::owner::Owner::elect(root.path()),
                Err(crate::owner::OwnerError::AlreadyOwned)
            ));
            owner
                .reopen_store()
                .expect("owner reopen writes the record");
            assert!(
                owner
                    .store
                    .retained(&commit_boundary(&attempt))
                    .expect("readback")
                    .is_some()
            );
            owner.close_store().expect("healthy close");
            assert!(matches!(
                owner.store.snapshot(&TaskId("gone".to_string())),
                Err(super::StoreError::Closed)
            ));
            owner.close_store().expect("repeat close is ok");
        }

        statement_stream_leg();
        after_guard_leg();
    }

    #[test]
    fn an_explicit_close_ends_the_held_record_and_a_later_reopen_writes_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, mut store, _session, _task, attempt, claim) = claim_fixture("held-close");
        super::proof::arm_fault(super::proof::Site::CommitBeforeExec);
        super::proof::arm_fault(super::proof::Site::RollbackAfterCommitError);
        let refusal = refusal(store.claim_check(
            &claim,
            &std::sync::atomic::AtomicBool::new(false),
            std::time::Instant::now() + std::time::Duration::from_secs(30),
        ));
        assert_eq!(refusal.site, super::ClaimSite::Commit);
        assert!(
            matches!(refusal.retention, super::RetentionOutcome::Unavailable),
            "the ambiguous record is held, not written on this connection"
        );
        assert!(store.is_quarantined(), "the held record quarantines");
        // DEC-051 / test-plan (g): an explicit quarantined close emits no
        // SQL statement and ENDS the holder — only the internal recovery
        // close inside `reopen` preserves it.
        super::proof::arm();
        store.close()?;
        store.close()?;
        let (close_events, _overflow) = super::proof::take().ok_or("the sink was armed")?;
        let close_sql: Vec<_> = close_events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    super::proof::ProofEvent::Stmt(sql) if !sql.starts_with("-- ")
                )
            })
            .collect();
        assert!(
            close_sql.is_empty(),
            "an explicit quarantined close runs no SQL: {close_sql:?}"
        );
        store.reopen(&root.path().join("state.db"))?;
        assert!(
            !store.is_quarantined(),
            "the ended holder leaves a live, unquarantined store"
        );
        assert!(
            store.retained(&commit_boundary(&attempt))?.is_none(),
            "residual R: the ended holder's record is never written"
        );

        Ok(())
    }

    #[test]
    fn conflicting_direct_row_behind_an_identical_terminal_row_collides() {
        let root = tempfile::TempDir::with_prefix("rivect-dual-")
            .unwrap_or_else(|error| unreachable!("the scratch root is created: {error}"));
        let mut store = TaskStore::open(&root.path().join("state.db"))
            .unwrap_or_else(|error| unreachable!("the store opens: {error:?}"));
        let attempt = format!("dual-{}", TaskId::generate().0);
        let boundary = format!("ret:check:{attempt}:dep.cache_links");
        let record = crate::verification::RetainedAttempt {
            attempt_id: attempt.clone(),
            boundary_id: boundary.clone(),
            stage: crate::verification::RetainedStage::Terminal,
            cause: "first cause".to_string(),
            digest: crate::verification::record_digest(&attempt, "first cause"),
            build_attempt: attempt.clone(),
            admitted_attempt_id: Some(attempt.clone()),
        };
        let conflicting = crate::verification::RetainedAttempt {
            cause: "second cause".to_string(),
            digest: crate::verification::record_digest(&attempt, "second cause"),
            ..record.clone()
        };
        let record_json = serde_json::to_string(&record).expect("record json");
        let conflicting_json = serde_json::to_string(&conflicting).expect("conflicting json");
        // The terminal key holds the identical record while the direct
        // key holds a conflicting one: the hidden conflict must surface.
        store
            .retain(
                &record_json,
                &crate::verification::terminal_boundary_id(&boundary),
            )
            .expect("identical terminal seed");
        store
            .retain(&conflicting_json, &boundary)
            .expect("conflicting direct seed");
        match store.retain_attempt(&record) {
            Err(super::StoreError::Conflict(super::ConflictCause::RetainedBoundaryCollision {
                ..
            })) => {}
            Err(other) => unreachable!("a dual-key collision is a conflict, got {other:?}"),
            Ok(()) => unreachable!("the conflicting direct row must not hide behind the terminal"),
        }
        // Control: identical rows at both keys stay idempotent.
        let control = crate::verification::RetainedAttempt {
            attempt_id: attempt.clone(),
            boundary_id: format!("ret:check:{attempt}:dep.checksum"),
            cause: "first cause".to_string(),
            digest: crate::verification::record_digest(&attempt, "first cause"),
            ..record
        };
        let control_json = serde_json::to_string(&control).expect("control json");
        store
            .retain(
                &control_json,
                &crate::verification::terminal_boundary_id(&control.boundary_id),
            )
            .expect("identical terminal seed");
        store
            .retain(&control_json, &control.boundary_id)
            .expect("identical direct seed");
        store
            .retain_attempt(&control)
            .expect("identical rows at both keys stay idempotent");
    }

    /// The dual-key presence predicate (DEC-057) counts a row at the
    /// direct key or at its terminal twin, and each call is one exact
    /// `RETAINED_BY_BOTH_KEYS` statement and never a write. The trace
    /// is installed by the connect that runs while the sink is armed,
    /// so the fixture open is armed too and its stream discarded; every
    /// later read re-arms the same installed trace.
    #[test]
    fn has_retained_either_key_counts_a_row_at_either_key() {
        let root = tempfile::TempDir::with_prefix("rivect-either-key-")
            .unwrap_or_else(|error| unreachable!("the scratch root is created: {error}"));
        super::proof::arm();
        let mut store = TaskStore::open(&root.path().join("state.db"))
            .unwrap_or_else(|error| unreachable!("the store opens: {error:?}"));
        let (_open_events, _open_overflow) =
            super::proof::take().expect("the fixture open was armed");
        let attempt = format!("either-{}", TaskId::generate().0);
        let direct_only = format!("ret:check:{attempt}:close.phase_closed");
        let terminal_only = format!("ret:check:{attempt}:close.unexpected_green");
        let both = format!("ret:check:{attempt}:close.wrong_cause");
        let neither = format!("ret:check:{attempt}:close.green_failed");
        let other_attempt = format!("other-{}", TaskId::generate().0);
        let other = format!("ret:check:{other_attempt}:close.phase_closed");
        let record = crate::verification::RetainedAttempt {
            attempt_id: attempt.clone(),
            boundary_id: direct_only.clone(),
            stage: crate::verification::RetainedStage::Terminal,
            cause: "either key".to_string(),
            digest: crate::verification::record_digest(&attempt, "either key"),
            build_attempt: attempt.clone(),
            admitted_attempt_id: Some(attempt.clone()),
        };
        let record_json = serde_json::to_string(&record).expect("record json");
        store
            .retain(&record_json, &direct_only)
            .expect("direct-only row");
        store
            .retain(
                &record_json,
                &crate::verification::terminal_boundary_id(&terminal_only),
            )
            .expect("terminal-only row");
        store
            .retain(&record_json, &both)
            .expect("both-keys direct row");
        store
            .retain(
                &record_json,
                &crate::verification::terminal_boundary_id(&both),
            )
            .expect("both-keys terminal row");
        let other_record = crate::verification::RetainedAttempt {
            attempt_id: other_attempt,
            boundary_id: other.clone(),
            ..record
        };
        let other_json = serde_json::to_string(&other_record).expect("other record json");
        store
            .retain(&other_json, &other)
            .expect("other attempt's direct row");
        store
            .retain(
                &other_json,
                &crate::verification::terminal_boundary_id(&other),
            )
            .expect("other attempt's terminal row");
        let read = |boundary: &str| {
            super::proof::arm();
            let present = store
                .has_retained_either_key(boundary)
                .expect("dual-key presence read");
            let (events, overflow) = super::proof::take().expect("the read was armed");
            assert!(!overflow, "no sink overflow on the presence read");
            assert_eq!(
                events,
                [super::proof::ProofEvent::Stmt(
                    super::sql::RETAINED_BY_BOTH_KEYS.to_string()
                )],
                "one exact dual-key statement at {boundary}"
            );
            assert!(
                !events
                    .iter()
                    .any(|event| matches!(event, super::proof::ProofEvent::Insert { .. })),
                "a presence read never inserts at {boundary}"
            );
            present
        };
        assert!(read(&direct_only), "a direct-only row is present");
        assert!(read(&terminal_only), "a terminal-only row is present");
        assert!(read(&both), "rows at both keys are present");
        // The other attempt holds rows at both of its keys before the
        // false read: neither its direct nor its terminal key counts.
        assert!(
            !read(&neither),
            "another attempt's direct and terminal keys never count"
        );
        assert!(
            read(&other),
            "the other attempt's direct row is its own boundary"
        );
        drop(store);
    }

    /// (m) statement stream and identity witness: the settings
    /// prefix is exact, the carried write precedes the bootstrap,
    /// the healthy close is optimize then checkpoint, a non-healthy
    /// close emits nothing, and the record is built exactly once.
    fn statement_stream_leg() {
        let (root, mut store, _session, _task, _attempt, claim) = claim_fixture("stream");
        super::proof::arm_fault(super::proof::Site::CommitBeforeExec);
        super::proof::arm_fault(super::proof::Site::RollbackAfterCommitError);
        super::proof::arm();
        refusal(store.claim_check(
            &claim,
            &std::sync::atomic::AtomicBool::new(false),
            claim_deadline(),
        ));
        let (claim_events, claim_overflow) = super::proof::take().expect("armed");
        assert!(!claim_overflow, "no sink overflow on the claim call");
        let built_idents: Vec<_> = claim_events
            .iter()
            .filter_map(|event| match event {
                super::proof::ProofEvent::Built { ident, .. } => Some(*ident),
                _ => None,
            })
            .collect();
        assert_eq!(built_idents.len(), 1, "the record is built exactly once");
        let ident_w = built_idents[0];
        let json_w = claim_events
            .iter()
            .find_map(|event| match event {
                super::proof::ProofEvent::Built { json, .. } => Some(json.clone()),
                _ => None,
            })
            .expect("built json");
        super::proof::arm();
        store
            .reopen(&root.path().join("state.db"))
            .unwrap_or_else(|error| unreachable!("the reopen succeeds: {error:?}"));
        let (events, reopen_overflow) = super::proof::take().expect("armed");
        let mut first_bootstrap_at = None;
        let mut carry_at = None;
        let mut settings_seen = 0;
        let mut inserted_json = None;
        for (index, event) in events.iter().enumerate() {
            match event {
                super::proof::ProofEvent::Stmt(sql) => {
                    if settings_seen < 9 {
                        settings_seen += 1;
                        assert!(sql.starts_with("PRAGMA "), "statement {index}: {sql}");
                    }
                    if first_bootstrap_at.is_none() && sql.contains("CREATE TABLE") {
                        first_bootstrap_at = Some(index);
                    }
                }
                super::proof::ProofEvent::Built { .. } => {
                    unreachable!("reopen never rebuilds the record")
                }
                super::proof::ProofEvent::Carry { ident } => {
                    assert_eq!(ident, &ident_w, "carry keeps the built identity");
                    carry_at = Some(index);
                }
                super::proof::ProofEvent::Used { ident } => {
                    assert_eq!(ident, &ident_w);
                    assert_eq!(carry_at, Some(index - 1), "used follows carry");
                }
                super::proof::ProofEvent::Insert { json } => {
                    inserted_json = Some(json.clone());
                }
            }
        }
        assert_eq!(
            Some(json_w),
            inserted_json,
            "the row value equals the built record"
        );
        assert!(!reopen_overflow, "no sink overflow on reopen");
        // The settings prefix is exactly the enumerated statements in
        // contract order, all before the carried write.
        let pragma_names: Vec<String> = events
            .iter()
            .take(carry_at.expect("carry ran"))
            .filter_map(|event| match event {
                super::proof::ProofEvent::Stmt(sql) => sql.strip_prefix("PRAGMA ").map(|rest| {
                    rest.trim_start_matches("main.")
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect::<String>()
                }),
                _ => None,
            })
            .collect();
        assert_eq!(
            pragma_names,
            // Each setting is one write then its own read-back; journal_mode
            // is a single update-and-check and busy_timeout a set-by-API
            // plus one read.
            [
                "journal_mode",
                "synchronous",
                "synchronous",
                "foreign_keys",
                "foreign_keys",
                "busy_timeout",
                "temp_store",
                "temp_store",
                "cache_size",
                "cache_size",
                "secure_delete",
                "secure_delete",
                "journal_size_limit",
                "journal_size_limit",
                "mmap_size",
                "mmap_size"
            ],
            "the settings prefix is exact and ordered"
        );
        // Carry, Used, RETAINED_LATEST_BY_ID, Insert, INSERT_RETAINED_ONCE,
        // then the first SCHEMA statement — nothing else in between.
        let carry_index = carry_at.expect("carry ran");
        assert!(matches!(
            events.get(carry_index + 1),
            Some(super::proof::ProofEvent::Used { .. })
        ));
        assert!(matches!(
            events.get(carry_index + 2),
            Some(super::proof::ProofEvent::Stmt(sql)) if sql.contains("boundary_id = ?2")
        ));
        assert!(matches!(
            events.get(carry_index + 3),
            Some(super::proof::ProofEvent::Insert { .. })
        ));
        assert!(matches!(
            events.get(carry_index + 4),
            Some(super::proof::ProofEvent::Stmt(sql)) if sql.starts_with("INSERT INTO retained")
        ));
        // The schema ledger is read before any DDL (DEC-008), so the first
        // bootstrap statement is the ledger read and the SCHEMA batch follows.
        assert!(matches!(
            events.get(carry_index + 5),
            Some(super::proof::ProofEvent::Stmt(sql)) if sql == super::sql::SCHEMA_GENERATION
        ));
        assert!(matches!(
            events.get(carry_index + 6),
            Some(super::proof::ProofEvent::Stmt(sql)) if sql.contains("CREATE TABLE IF NOT EXISTS sessions")
        ));
        let bootstrap_at = first_bootstrap_at.expect("bootstrap ran");
        assert!(
            carry_at.expect("carry ran") < bootstrap_at,
            "the carried write precedes every bootstrap statement"
        );
        assert!(
            settings_seen >= 9,
            "the settings prefix ran: {settings_seen} statements"
        );
        // The healthy close emits exactly optimize then checkpoint.
        super::proof::arm();
        store.close().expect("healthy close");
        let (close_events, close_overflow) = super::proof::take().expect("armed");
        let close_sql: Vec<_> = close_events
            .iter()
            .filter_map(|event| match event {
                super::proof::ProofEvent::Stmt(sql) if !sql.starts_with("-- ") => Some(sql.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            close_sql.len(),
            2,
            "healthy close statements: {close_sql:?}"
        );
        assert!(close_sql[0].starts_with("PRAGMA optimize"));
        assert!(close_sql[1].starts_with("PRAGMA wal_checkpoint"));
        assert!(!close_overflow, "no sink overflow on close");
        drop(store);
    }

    /// (g) the pre-open file guard: a new db is private before open,
    /// a symlinked db or sidecar is refused typed before any open, a
    /// wider existing file narrows in place, and the cfg(test) hook
    /// that swaps the db for a symlink between guard and open is
    /// refused by `SQLITE_OPEN_NOFOLLOW` with the sentinel untouched.
    fn after_guard_leg() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        let root = tempfile::TempDir::with_prefix("rivect-guard-")
            .unwrap_or_else(|error| unreachable!("the guard root is created: {error}"));
        let sentinel = root.path().join("sentinel");
        std::fs::write(&sentinel, b"sentinel bytes").expect("sentinel");

        // New db: private, with private sidecars once the WAL is live.
        let db = root.path().join("fresh.db");
        let store = TaskStore::open(&db).expect("fresh open");
        assert_eq!(std::fs::metadata(&db).expect("db").mode() & 0o777, 0o600);
        drop(store);

        // A pre-existing wide file narrows with the same inode.
        let wide = root.path().join("wide.db");
        drop(rusqlite::Connection::open(&wide).expect("raw create"));
        std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o644)).expect("widen");
        let before = std::fs::metadata(&wide).expect("wide").ino();
        drop(TaskStore::open(&wide).expect("wide open"));
        let after = std::fs::metadata(&wide).expect("wide after");
        assert_eq!(after.mode() & 0o777, 0o600);
        assert_eq!(after.ino(), before, "narrowed in place");

        // A symlinked db path (existing sentinel, then dangling) is
        // refused typed; the sentinel stays byte-identical and the
        // dangling target is never created.
        let linked = root.path().join("linked.db");
        symlink(&sentinel, &linked).expect("symlink");
        assert!(matches!(
            TaskStore::open(&linked),
            Err(super::StoreError::Storage(..))
        ));
        assert_eq!(std::fs::read(&sentinel).expect("read"), b"sentinel bytes");
        let dangling = root.path().join("dangling.db");
        let target = root.path().join("never-created");
        symlink(&target, &dangling).expect("dangling symlink");
        assert!(TaskStore::open(&dangling).is_err());
        assert!(!target.exists(), "the dangling target is not created");

        // A symlinked -wal sidecar is refused before the open.
        let sidecar_db = root.path().join("sidecar.db");
        drop(TaskStore::open(&sidecar_db).expect("sidecar base"));
        let wal = super::sidecar_path(&sidecar_db, "wal");
        drop(std::fs::remove_file(&wal));
        symlink(&sentinel, &wal).expect("wal symlink");
        assert!(TaskStore::open(&sidecar_db).is_err());
        assert_eq!(std::fs::read(&sentinel).expect("read"), b"sentinel bytes");

        // The swap between guard and open: NOFOLLOW refuses and the
        // sentinel is never initialised as a database.
        let swapped = root.path().join("swapped.db");
        super::proof::arm_after_guard(sentinel.clone());
        assert!(matches!(
            TaskStore::open(&swapped),
            Err(super::StoreError::Storage(..))
        ));
        assert_eq!(std::fs::read(&sentinel).expect("read"), b"sentinel bytes");
    }

    /// The held-record proof legs of the DEC-050 reopen contract
    /// (test-plan (b)-(i)): every leg uses real SQLite files, second
    /// connections as independent oracles, and the exact statement and
    /// identity witnesses — never a substring approximation.
    mod held_proof {
        use super::{claim_deadline, claim_fixture, commit_boundary, refusal};
        use crate::contracts::TaskId;
        use crate::state::{
            ClaimSite, ConflictCause, ConnectionLifecycleError, RetentionOutcome, StoreError,
            TaskStore, proof, sql,
        };
        use rusqlite::{Connection, OptionalExtension as _};
        use std::path::{Path, PathBuf};
        use std::sync::atomic::AtomicBool;
        use std::time::Duration;

        type TestResult = Result<(), Box<dyn std::error::Error>>;

        /// One store holding an ambiguous COMMIT record on a live idle
        /// connection, plus the oracle facts the legs compare against.
        struct Held {
            store: TaskStore,
            attempt: String,
            claim: crate::state::CheckClaim,
            ghost: String,
            ident: proof::CheckIdent,
            json: String,
            root: tempfile::TempDir,
        }

        impl Held {
            fn db(&self) -> PathBuf {
                self.root.path().join("state.db")
            }
            fn boundary(&self) -> String {
                commit_boundary(&self.attempt)
            }
        }

        /// The COMMIT reports an error after its transaction ended and
        /// the same-connection write fails: the record is built exactly
        /// once and moves into the holder with the connection idle (a
        /// second connection can then write — the jam fixtures need it).
        fn held(tag: &str) -> Result<Held, Box<dyn std::error::Error>> {
            let (root, mut store, session, _task, attempt, claim) = claim_fixture(tag);
            let ghost = store
                .create_task(&session, "ghost-command", "unit", "ghost goal", (&[], &[]))?
                .task_id
                .0;
            proof::arm_fault(proof::Site::CommitBeforeExec);
            proof::arm_fault(proof::Site::SameConnectionWrite);
            proof::arm();
            let outcome =
                refusal(store.claim_check(&claim, &AtomicBool::new(false), claim_deadline()));
            let (events, overflow) = proof::take().ok_or("the sink was armed")?;
            assert!(!overflow, "no sink overflow on the claim call");
            assert_eq!(outcome.site, ClaimSite::Commit);
            assert!(matches!(outcome.retention, RetentionOutcome::Unavailable));
            assert!(store.is_quarantined(), "the held record quarantines");
            let built: Vec<_> = events
                .iter()
                .filter_map(|event| match event {
                    proof::ProofEvent::Built { ident, json } => Some((*ident, json.clone())),
                    _ => None,
                })
                .collect();
            assert_eq!(built.len(), 1, "the record is built exactly once");
            let (ident, json) = built.into_iter().next().ok_or("one built record")?;
            Ok(Held {
                root,
                store,
                attempt,
                claim,
                ghost,
                ident,
                json,
            })
        }

        fn second_connection(db: &Path) -> Result<Connection, Box<dyn std::error::Error>> {
            let conn = Connection::open(db)?;
            conn.busy_timeout(Duration::from_secs(5))?;
            Ok(conn)
        }

        /// The bootstrap jam: a task whose projection row is gone plus a
        /// trigger aborting the backfill insert for it — the bootstrap
        /// fails AFTER the carried write.
        fn jam(db: &Path, ghost: &str) -> TestResult {
            let conn = second_connection(db)?;
            conn.execute(
                "DELETE FROM todo_projection WHERE task_id = ?1",
                rusqlite::params![ghost],
            )?;
            conn.execute_batch(&format!(
                "CREATE TRIGGER jam BEFORE INSERT ON todo_projection \
                 WHEN NEW.task_id = '{ghost}' BEGIN SELECT RAISE(ABORT, 'jam'); END;"
            ))?;
            Ok(())
        }

        fn unjam(db: &Path) -> TestResult {
            second_connection(db)?.execute_batch("DROP TRIGGER jam")?;
            Ok(())
        }

        fn row(db: &Path, boundary: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
            Ok(second_connection(db)?
                .query_row(
                    "SELECT record_json FROM retained WHERE boundary_id = ?1",
                    rusqlite::params![boundary],
                    |row| row.get(0),
                )
                .optional()?)
        }

        fn retained_count(db: &Path) -> Result<i64, Box<dyn std::error::Error>> {
            Ok(second_connection(db)?
                .query_row("SELECT COUNT(*) FROM retained", [], |row| row.get(0))?)
        }

        fn remove_database_files(db: &Path) -> TestResult {
            for suffix in ["", "-wal", "-shm"] {
                let mut name = db.as_os_str().to_os_string();
                name.push(suffix);
                match std::fs::remove_file(PathBuf::from(name)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        }

        /// Runs `call` with the statement/identity sink armed.
        fn witnessed<T>(
            call: impl FnOnce() -> T,
        ) -> Result<(T, Vec<proof::ProofEvent>), Box<dyn std::error::Error>> {
            proof::arm();
            let value = call();
            let (events, overflow) = proof::take().ok_or("the sink was armed")?;
            assert!(!overflow, "no sink overflow");
            Ok((value, events))
        }

        fn carries(events: &[proof::ProofEvent]) -> Vec<proof::CheckIdent> {
            events
                .iter()
                .filter_map(|event| match event {
                    proof::ProofEvent::Carry { ident } => Some(*ident),
                    _ => None,
                })
                .collect()
        }

        fn builds(events: &[proof::ProofEvent]) -> usize {
            events
                .iter()
                .filter(|event| matches!(event, proof::ProofEvent::Built { .. }))
                .count()
        }

        fn inserts(events: &[proof::ProofEvent]) -> Vec<String> {
            events
                .iter()
                .filter_map(|event| match event {
                    proof::ProofEvent::Insert { json } => Some(json.clone()),
                    _ => None,
                })
                .collect()
        }

        fn projection_count(db: &Path, task: &str) -> Result<i64, Box<dyn std::error::Error>> {
            Ok(second_connection(db)?.query_row(
                "SELECT COUNT(*) FROM todo_projection WHERE task_id = ?1",
                rusqlite::params![task],
                |row| row.get(0),
            )?)
        }

        fn seed(db: &Path, boundary: &str, json: &str) -> TestResult {
            second_connection(db)?.execute(
                "INSERT INTO retained (boundary_id, record_json) VALUES (?1, ?2)",
                rusqlite::params![boundary, json],
            )?;
            Ok(())
        }

        fn wal_length(db: &Path) -> Result<u64, Box<dyn std::error::Error>> {
            Ok(std::fs::metadata(crate::state::sidecar_path(db, "wal"))?.len())
        }

        fn closed(store: &TaskStore) -> bool {
            matches!(
                store.snapshot(&TaskId("gone".to_string())),
                Err(StoreError::Closed)
            )
        }

        #[test]
        fn carry_instant_probe_shows_no_bootstrap_stage_ran_before_the_carried_write() -> TestResult
        {
            let mut h = held("carry-probe")?;
            let db = h.db();
            second_connection(&db)?.execute_batch(&format!(
                "DROP TABLE sessions; DROP TABLE answer_attempts; DROP TABLE plan_selections; \
                 DROP TABLE index_generations; DROP TABLE assumption_checks; \
                 DROP TABLE supervisor_reactions; \
                 CREATE TABLE supervisor_reactions (task_id TEXT NOT NULL, reaction_json TEXT NOT NULL); \
                 DELETE FROM todo_projection WHERE task_id = '{ghost}'; \
                 CREATE TABLE carry_probe (boundary TEXT, sessions INTEGER, answer_attempts INTEGER, \
                    plan_selections INTEGER, index_generations INTEGER, assumption_checks INTEGER, \
                    ghost_projection INTEGER, legacy_journal INTEGER); \
                 CREATE TRIGGER carry_probe_trigger AFTER INSERT ON retained BEGIN \
                    INSERT INTO carry_probe VALUES (NEW.boundary_id, \
                        (SELECT COUNT(*) FROM sqlite_schema WHERE name = 'sessions'), \
                        (SELECT COUNT(*) FROM sqlite_schema WHERE name = 'answer_attempts'), \
                        (SELECT COUNT(*) FROM sqlite_schema WHERE name = 'plan_selections'), \
                        (SELECT COUNT(*) FROM sqlite_schema WHERE name = 'index_generations'), \
                        (SELECT COUNT(*) FROM sqlite_schema WHERE name = 'assumption_checks'), \
                        (SELECT COUNT(*) FROM todo_projection WHERE task_id = '{ghost}'), \
                        (SELECT COUNT(*) FROM sqlite_schema WHERE name = 'supervisor_reactions' \
                            AND sql NOT LIKE '%PRIMARY KEY%')); END;",
                ghost = h.ghost
            ))?;
            h.store.reopen(&db)?;
            let probe: (i64, i64, i64, i64, i64, i64, i64) = second_connection(&db)?.query_row(
                "SELECT sessions, answer_attempts, plan_selections, index_generations, \
                    assumption_checks, ghost_projection, legacy_journal \
                 FROM carry_probe WHERE boundary = ?1",
                rusqlite::params![h.boundary()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )?;
            assert_eq!(
                probe,
                (0, 0, 0, 0, 0, 0, 1),
                "at the carried write every bootstrap object was still absent or legacy"
            );
            assert_eq!(
                row(&db, &h.boundary())?,
                Some(h.json.clone()),
                "the exact built record landed"
            );
            let restored: i64 = second_connection(&db)?.query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name IN \
                 ('sessions', 'answer_attempts', 'plan_selections', 'index_generations', \
                  'assumption_checks')",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(restored, 5, "every dropped object was restored afterwards");
            assert_eq!(projection_count(&db, &h.ghost)?, 1);
            let migrated: i64 = second_connection(&db)?.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('supervisor_reactions') WHERE name = 'id'",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(migrated, 1, "the legacy journal migrated afterwards");

            Ok(())
        }

        #[test]
        fn partial_initialization_keeps_the_same_record_and_a_later_reopen_is_identical()
        -> TestResult {
            let mut h = held("partial")?;
            let db = h.db();
            jam(&db, &h.ghost)?;
            let (outcome, events) = witnessed(|| h.store.reopen(&db))?;
            assert!(
                matches!(outcome, Err(StoreError::Storage(_))),
                "{outcome:?}"
            );
            assert_eq!(
                carries(&events),
                vec![h.ident],
                "the carry is the built object"
            );
            assert_eq!(builds(&events), 0, "a reopen never rebuilds the record");
            assert_eq!(inserts(&events), vec![h.json.clone()]);
            assert!(h.store.is_quarantined());
            assert!(h.store.conn.is_none(), "the slot is empty immediately");
            assert!(closed(&h.store), "the next store call is typed closed");
            assert_eq!(
                row(&db, &h.boundary())?,
                Some(h.json.clone()),
                "a second connection sees the exact carried row"
            );
            let before = retained_count(&db)?;
            unjam(&db)?;
            let (outcome, events) = witnessed(|| h.store.reopen(&db))?;
            outcome?;
            assert_eq!(
                carries(&events),
                vec![h.ident],
                "the same held object survived the bootstrap failure"
            );
            assert!(
                inserts(&events).is_empty(),
                "an identical row inserts nothing"
            );
            assert_eq!(retained_count(&db)?, before, "no second row");
            assert!(!h.store.is_quarantined());
            assert_eq!(
                projection_count(&db, &h.ghost)?,
                1,
                "the projection is repaired"
            );
            let (outcome, events) = witnessed(|| h.store.reopen(&db))?;
            outcome?;
            assert!(
                carries(&events).is_empty(),
                "the holder is empty afterwards"
            );

            Ok(())
        }

        #[test]
        fn holder_survives_a_partial_initialization_until_a_fresh_file_makes_the_write_final()
        -> TestResult {
            let mut h = held("survival")?;
            let db = h.db();
            jam(&db, &h.ghost)?;
            assert!(matches!(h.store.reopen(&db), Err(StoreError::Storage(_))));
            assert!(h.store.is_quarantined());
            remove_database_files(&db)?;
            // The carried write fails on the fresh file (no `retained`
            // table yet) while the bootstrap succeeds: a holder lost at
            // the earlier bootstrap failure would return Ok here.
            assert!(matches!(h.store.reopen(&db), Err(StoreError::Storage(_))));
            assert!(
                !h.store.is_quarantined(),
                "final: a live slot, an empty holder"
            );
            assert_eq!(row(&db, &h.boundary())?, None, "no row anywhere");
            let (outcome, events) = witnessed(|| h.store.reopen(&db))?;
            outcome?;
            assert!(carries(&events).is_empty(), "a final record never retries");
            assert_eq!(row(&db, &h.boundary())?, None);

            Ok(())
        }

        #[test]
        fn a_missing_file_after_an_open_failure_makes_the_held_write_final() -> TestResult {
            let mut h = held("missing-file")?;
            let db = h.db();
            proof::arm_fault(proof::Site::Open);
            assert!(matches!(h.store.reopen(&db), Err(StoreError::Storage(_))));
            assert!(
                h.store.is_quarantined(),
                "held across the injected open failure"
            );
            remove_database_files(&db)?;
            // Bootstrap-before-carry would give Ok plus a row here.
            assert!(matches!(h.store.reopen(&db), Err(StoreError::Storage(_))));
            assert!(!h.store.is_quarantined());
            assert_eq!(row(&db, &h.boundary())?, None);

            Ok(())
        }

        #[test]
        fn a_carried_write_fault_plus_a_jam_holds_and_a_later_reopen_writes_it_first() -> TestResult
        {
            let mut h = held("fault-jam")?;
            let db = h.db();
            jam(&db, &h.ghost)?;
            proof::arm_fault(proof::Site::CarriedWrite);
            assert!(matches!(h.store.reopen(&db), Err(StoreError::Storage(_))));
            assert!(
                h.store.is_quarantined(),
                "held: the write fault and the jam"
            );
            assert_eq!(
                row(&db, &h.boundary())?,
                None,
                "the faulted write landed nothing"
            );
            unjam(&db)?;
            let (outcome, events) = witnessed(|| h.store.reopen(&db))?;
            outcome?;
            assert_eq!(carries(&events), vec![h.ident]);
            assert_eq!(inserts(&events), vec![h.json.clone()]);
            assert_eq!(builds(&events), 0);
            h.store.retain("{}", "ret:test:after-reopen")?;
            let (first, later): (i64, i64) = second_connection(&db)?.query_row(
                "SELECT (SELECT rowid FROM retained WHERE boundary_id = ?1), \
                        (SELECT rowid FROM retained WHERE boundary_id = ?2)",
                rusqlite::params![h.boundary(), "ret:test:after-reopen"],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            assert!(first < later, "the carried row precedes every later row");

            Ok(())
        }

        #[test]
        fn a_collision_at_the_direct_or_terminal_key_is_final_and_the_conflicting_row_stays_identical()
        -> TestResult {
            for terminal in [false, true] {
                let mut h = held(if terminal {
                    "collide-terminal"
                } else {
                    "collide-direct"
                })?;
                let db = h.db();
                let key = if terminal {
                    crate::verification::terminal_boundary_id(&h.boundary())
                } else {
                    h.boundary()
                };
                let seeded = r#"{"seeded":"conflicting record"}"#;
                seed(&db, &key, seeded)?;
                let before = retained_count(&db)?;
                let (outcome, events) = witnessed(|| h.store.reopen(&db))?;
                assert!(
                    matches!(
                        outcome,
                        Err(StoreError::Conflict(
                            ConflictCause::RetainedBoundaryCollision { .. }
                        ))
                    ),
                    "terminal={terminal}: {outcome:?}"
                );
                assert!(!h.store.is_quarantined(), "final: the holder is released");
                assert_eq!(row(&db, &key)?, Some(seeded.to_string()), "byte-identical");
                assert_eq!(retained_count(&db)?, before, "nothing was written");
                let carried_rows: i64 = second_connection(&db)?.query_row(
                    "SELECT COUNT(*) FROM retained WHERE record_json = ?1",
                    rusqlite::params![h.json],
                    |row| row.get(0),
                )?;
                assert_eq!(carried_rows, 0, "the carried value is written nowhere");
                assert!(
                    inserts(&events).is_empty(),
                    "a collision never reaches the insert"
                );
                if !terminal {
                    let again = refusal(h.store.claim_check(
                        &h.claim,
                        &AtomicBool::new(false),
                        claim_deadline(),
                    ));
                    assert_eq!(
                        again.site,
                        ClaimSite::Replay,
                        "a re-presented claim never dispatches"
                    );
                    assert_eq!(
                        h.store.attempt_state(&h.attempt)?.as_deref(),
                        Some("planned")
                    );
                }
            }
            Ok(())
        }

        #[test]
        fn a_collision_behind_a_jam_is_held_then_final_and_a_further_reopen_writes_nothing()
        -> TestResult {
            let mut h = held("collide-jam")?;
            let db = h.db();
            let seeded = r#"{"seeded":"conflicting record"}"#;
            seed(&db, &h.boundary(), seeded)?;
            jam(&db, &h.ghost)?;
            assert!(matches!(h.store.reopen(&db), Err(StoreError::Storage(_))));
            assert!(h.store.is_quarantined(), "held behind the jam");
            unjam(&db)?;
            assert!(matches!(
                h.store.reopen(&db),
                Err(StoreError::Conflict(
                    ConflictCause::RetainedBoundaryCollision { .. }
                ))
            ));
            assert!(
                !h.store.is_quarantined(),
                "final once the bootstrap succeeds"
            );
            let (outcome, events) = witnessed(|| h.store.reopen(&db))?;
            outcome?;
            assert!(
                carries(&events).is_empty(),
                "a further reopen is Ok with no write"
            );
            assert!(inserts(&events).is_empty());
            assert_eq!(row(&db, &h.boundary())?, Some(seeded.to_string()));

            Ok(())
        }

        #[test]
        fn the_identity_witness_survives_failed_close_failed_connect_and_partial_reopens()
        -> TestResult {
            let mut h = held("identity")?;
            let db = h.db();
            let mut seen = Vec::new();
            proof::arm_fault(proof::Site::Close);
            let (outcome, events) = witnessed(|| h.store.reopen(&db))?;
            assert!(matches!(outcome, Err(StoreError::Storage(_))));
            seen.push(events);
            proof::arm_fault(proof::Site::Open);
            let (outcome, events) = witnessed(|| h.store.reopen(&db))?;
            assert!(matches!(outcome, Err(StoreError::Storage(_))));
            seen.push(events);
            jam(&db, &h.ghost)?;
            let (outcome, events) = witnessed(|| h.store.reopen(&db))?;
            assert!(matches!(outcome, Err(StoreError::Storage(_))));
            seen.push(events);
            unjam(&db)?;
            let (outcome, events) = witnessed(|| h.store.reopen(&db))?;
            outcome?;
            seen.push(events);
            for events in &seen {
                assert_eq!(builds(events), 0, "no second Built across the chain");
                for ident in carries(events) {
                    assert_eq!(ident, h.ident, "every carry is the built object");
                }
                for (index, event) in events.iter().enumerate() {
                    if matches!(event, proof::ProofEvent::Carry { .. }) {
                        assert_eq!(
                            events.get(index + 1),
                            Some(&proof::ProofEvent::Used { ident: h.ident }),
                            "Used immediately follows Carry"
                        );
                    }
                }
            }
            assert!(
                carries(&seen[0]).is_empty() && carries(&seen[1]).is_empty(),
                "a failed close and a failed connect carry nothing"
            );
            assert_eq!(carries(&seen[2]).len(), 1);
            assert_eq!(carries(&seen[3]).len(), 1);

            Ok(())
        }

        #[test]
        fn the_carried_write_stream_is_exact_and_precedes_the_bootstrap() -> TestResult {
            let mut h = held("stream-exact")?;
            let db = h.db();
            let (outcome, events) = witnessed(|| h.store.reopen(&db))?;
            outcome?;
            let carry_at = events
                .iter()
                .position(|event| matches!(event, proof::ProofEvent::Carry { .. }))
                .ok_or("the carry ran")?;
            // Everything before the carry is the settings prefix: only
            // PRAGMA statements, in the contract order, each read back.
            let mut pragmas = Vec::new();
            for event in &events[..carry_at] {
                match event {
                    proof::ProofEvent::Stmt(sql) if sql.starts_with("PRAGMA ") => {
                        pragmas.push(
                            sql.trim_start_matches("PRAGMA ")
                                .trim_start_matches("main.")
                                .chars()
                                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                                .collect::<String>(),
                        );
                    }
                    other => {
                        return Err(
                            format!("non-settings event before the carry: {other:?}").into()
                        );
                    }
                }
            }
            assert_eq!(
                pragmas,
                [
                    "journal_mode",
                    "synchronous",
                    "synchronous",
                    "foreign_keys",
                    "foreign_keys",
                    "busy_timeout",
                    "temp_store",
                    "temp_store",
                    "cache_size",
                    "cache_size",
                    "secure_delete",
                    "secure_delete",
                    "journal_size_limit",
                    "journal_size_limit",
                    "mmap_size",
                    "mmap_size"
                ],
                "the settings prefix is exact and ordered"
            );
            assert_eq!(
                events[carry_at + 1],
                proof::ProofEvent::Used { ident: h.ident }
            );
            assert_eq!(
                events[carry_at + 2],
                proof::ProofEvent::Stmt(sql::RETAINED_BY_BOTH_KEYS.to_string()),
                "the dual-key collision read"
            );
            assert_eq!(
                events[carry_at + 3],
                proof::ProofEvent::Insert { json: h.json }
            );
            assert_eq!(
                events[carry_at + 4],
                proof::ProofEvent::Stmt(sql::INSERT_RETAINED_ONCE.to_string()),
                "the once-only insert"
            );
            match events.get(carry_at + 5) {
                Some(proof::ProofEvent::Stmt(ledger)) => {
                    assert_eq!(
                        ledger,
                        sql::SCHEMA_GENERATION,
                        "the schema ledger is read before any DDL (DEC-008)"
                    );
                }
                other => return Err(format!("the bootstrap follows the carry: {other:?}").into()),
            }
            match events.get(carry_at + 6) {
                Some(proof::ProofEvent::Stmt(first)) => {
                    assert!(
                        first.starts_with("CREATE TABLE IF NOT EXISTS sessions")
                            && sql::SCHEMA.trim_start().starts_with(first.as_str()),
                        "the first SCHEMA statement follows the ledger read: {first}"
                    );
                }
                other => {
                    return Err(format!("the bootstrap DDL follows the carry: {other:?}").into());
                }
            }

            Ok(())
        }

        #[test]
        fn a_failed_restoration_empties_the_slot_and_a_later_reopen_serves_a_fresh_claim()
        -> TestResult {
            let (root, mut store, _session, _task, attempt, claim) = claim_fixture("restore-fail");
            let db = root.path().join("state.db");
            proof::arm_fault(proof::Site::WaitRestore);
            let outcome =
                refusal(store.claim_check(&claim, &AtomicBool::new(false), claim_deadline()));
            assert_eq!(outcome.site, ClaimSite::WaitRestore);
            assert!(
                outcome.restore_failed,
                "the restoration failure is its own status"
            );
            assert!(
                matches!(outcome.retention, RetentionOutcome::Unavailable),
                "the retention status is separate and honest"
            );
            assert!(store.is_quarantined(), "an unusable handle is never reused");
            assert!(
                matches!(store.attempt_state(&attempt), Err(StoreError::Closed)),
                "no SQL runs on the unusable handle before a reopen"
            );
            store.reopen(&db)?;
            assert_eq!(
                store.attempt_state(&attempt)?.as_deref(),
                Some("planned"),
                "the failed claim effected nothing"
            );
            assert!(
                !store.has_retained(&commit_boundary(&attempt))?,
                "no held COMMIT was synthesized"
            );
            assert!(!store.has_retained(&super::marker_boundary(&attempt))?);
            assert!(matches!(
                store.claim_check(&claim, &AtomicBool::new(false), claim_deadline()),
                Ok(crate::state::ClaimOutcome::Claimed)
            ));

            Ok(())
        }

        #[test]
        fn a_reopen_naming_another_database_refuses_before_the_holder_or_either_file_moves()
        -> TestResult {
            let mut h = held("bound-a")?;
            let db_a = h.db();
            let db_b = h.root.path().join("other.db");
            drop(TaskStore::open(&db_b)?);
            match h.store.reopen(&db_b) {
                Err(StoreError::ReopenIdentity { .. }) => {}
                other => return Err(format!("another database must refuse, got {other:?}").into()),
            }
            assert!(h.store.is_quarantined(), "the holder is unchanged");
            assert!(h.store.conn.is_some(), "the old connection never closed");
            assert_eq!(
                row(&db_b, &h.boundary())?,
                None,
                "the presented database is untouched"
            );
            h.store.reopen(&db_a)?;
            assert_eq!(
                row(&db_a, &h.boundary())?,
                Some(h.json.clone()),
                "the bound pathname still carries the record"
            );
            // Recreation after deletion stays legal at the bound pathname.
            remove_database_files(&db_a)?;
            h.store.reopen(&db_a)?;

            Ok(())
        }

        #[test]
        fn a_healthy_close_truncates_the_wal_releases_the_writer_and_ends_use() -> TestResult {
            let (root, mut store, _session, _task, _attempt, _claim) =
                claim_fixture("healthy-close");
            let db = root.path().join("state.db");
            let idle = second_connection(&db)?;
            idle.busy_timeout(Duration::ZERO)?;
            idle.query_row("SELECT COUNT(*) FROM tasks", [], |row| row.get::<_, i64>(0))?;
            store.close()?;
            assert_eq!(wal_length(&db)?, 0, "the truncating checkpoint ran");
            idle.execute_batch("BEGIN IMMEDIATE")?;
            idle.execute_batch("ROLLBACK")?;
            assert!(closed(&store), "the next store call is typed closed");
            let (outcome, events) = witnessed(|| store.close())?;
            outcome?;
            assert!(
                !events
                    .iter()
                    .any(|event| matches!(event, proof::ProofEvent::Stmt(_))),
                "a repeated close emits no SQL: {events:?}"
            );
            drop(idle);

            Ok(())
        }

        #[test]
        fn a_healthy_close_beside_a_read_transaction_is_a_typed_checkpoint_failure() -> TestResult {
            let (root, mut store, _session, _task, _attempt, _claim) =
                claim_fixture("close-reader");
            let db = root.path().join("state.db");
            let reader = second_connection(&db)?;
            reader.execute_batch("BEGIN")?;
            reader.query_row("SELECT COUNT(*) FROM tasks", [], |row| row.get::<_, i64>(0))?;
            store.open_session("later-session", "later-conn", None)?;
            match store.close() {
                Err(StoreError::Storage(source)) => assert!(
                    matches!(
                        source.downcast_ref::<ConnectionLifecycleError>(),
                        Some(ConnectionLifecycleError::CheckpointIncomplete)
                    ),
                    "typed CheckpointIncomplete, got {source}"
                ),
                other => {
                    return Err(format!("the checkpoint must fail typed, got {other:?}").into());
                }
            }
            assert!(
                store.conn.is_none(),
                "the slot is empty and the connection closed"
            );
            assert!(closed(&store));
            let writer = second_connection(&db)?;
            writer.busy_timeout(Duration::ZERO)?;
            writer.execute_batch("BEGIN IMMEDIATE")?;
            writer.execute_batch("ROLLBACK")?;
            reader.execute_batch("ROLLBACK")?;

            Ok(())
        }

        #[test]
        fn a_quarantined_close_leaves_the_wal_unchanged_and_ends_the_holder() -> TestResult {
            let mut h = held("quarantined-close")?;
            let db = h.db();
            let idle = second_connection(&db)?;
            idle.query_row("SELECT COUNT(*) FROM tasks", [], |row| row.get::<_, i64>(0))?;
            let before = wal_length(&db)?;
            h.store.close()?;
            assert_eq!(
                wal_length(&db)?,
                before,
                "no checkpoint ran on a quarantined close"
            );
            assert!(!h.store.is_quarantined() || h.store.conn.is_none());
            drop(idle);
            h.store.reopen(&db)?;
            assert_eq!(
                row(&db, &h.boundary())?,
                None,
                "the ended holder wrote nothing"
            );

            Ok(())
        }
    }
    fn claim_deadline() -> std::time::Instant {
        std::time::Instant::now() + std::time::Duration::from_secs(30)
    }

    #[test]
    fn rejection_identities_are_invocation_unique_uuids() -> Result<(), Box<dyn std::error::Error>>
    {
        let (root, mut store, _session, _task, _attempt, claim) = claim_fixture("rejection-uuid");
        super::proof::arm_fault(super::proof::Site::Read);
        let refusal = refusal(store.claim_check(
            &claim,
            &std::sync::atomic::AtomicBool::new(false),
            claim_deadline(),
        ));
        assert_eq!(refusal.site, super::ClaimSite::Read);
        let boundaries: Vec<String> = {
            let conn = rusqlite::Connection::open(root.path().join("state.db"))?;
            let mut statement =
                conn.prepare("SELECT boundary_id FROM retained WHERE boundary_id LIKE ?1")?;
            statement
                .query_map(["ret:check-rejection:%"], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        assert_eq!(
            boundaries.len(),
            1,
            "one refusal wrote exactly one rejection row: {boundaries:?}"
        );
        // The identity is invocation-unique through the existing UUID
        // generator — never a process-local sequence.
        let identity = boundaries[0]
            .strip_prefix("ret:check-rejection:")
            .and_then(|rest| rest.split_once(':'))
            .map(|(identity, _site)| identity)
            .unwrap_or("");
        assert!(
            uuid::Uuid::parse_str(identity).is_ok(),
            "the rejection identity {identity:?} is a UUID"
        );
        drop(store);

        Ok(())
    }

    #[test]
    fn a_claim_denial_row_carries_the_sqlite_primary_code() -> Result<(), Box<dyn std::error::Error>>
    {
        let (root, mut store, _session, _task, _attempt, claim) =
            claim_fixture("rejection-primary");
        // A real statement failure with an engine code: the binding
        // read's table is gone, so the refusal carries SQLite's numeric
        // primary result code (extended & 0xff).
        {
            let conn = rusqlite::Connection::open(root.path().join("state.db"))?;
            conn.execute_batch("DROP TABLE attempts")?;
        }
        let refusal = refusal(store.claim_check(
            &claim,
            &std::sync::atomic::AtomicBool::new(false),
            claim_deadline(),
        ));
        assert_eq!(refusal.site, super::ClaimSite::Read);
        let record: Option<String> = {
            let conn = rusqlite::Connection::open(root.path().join("state.db"))?;
            conn.query_row(
                "SELECT record_json FROM retained WHERE boundary_id LIKE ?1",
                ["ret:check-rejection:%:admit.claim_read"],
                |row| row.get(0),
            )
            .optional()?
        };
        let record = record.ok_or("the refusal wrote its denial row")?;
        let payload: serde_json::Value = serde_json::from_str(&record)?;
        assert_eq!(
            payload.get("primary").and_then(serde_json::Value::as_str),
            Some("1"),
            "the denial row carries the numeric primary code: {record}"
        );
        drop(store);

        Ok(())
    }

    #[test]
    fn the_scoped_busy_timeout_round_trips_the_actual_value()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_root, mut store, _session, task, _attempt, claim) =
            claim_fixture("timeout-round-trip");
        let prior = std::time::Duration::from_millis(1234);
        store.conn_mut()?.busy_timeout(prior)?;
        fn read_timeout(store: &TaskStore) -> Result<i64, Box<dyn std::error::Error>> {
            Ok(store
                .conn()?
                .query_row(super::sql::BUSY_TIMEOUT_READ, [], |row| row.get(0))?)
        }
        // Before: the actual prior value is what the scoped read saw.
        assert_eq!(read_timeout(&store)?, 1234);
        // A refused claim restores the actual value after the
        // zero-wait write, not a generic fallback.
        super::proof::arm_fault(super::proof::Site::Read);
        let _ = refusal(store.claim_check(
            &claim,
            &std::sync::atomic::AtomicBool::new(false),
            claim_deadline(),
        ));
        assert_eq!(read_timeout(&store)?, 1234, "a refusal restores the prior");
        // A successful claim restores the actual value BEFORE the
        // COMMIT — the pre-COMMIT restoration — so the post-claim
        // connection still carries it.
        let second =
            store.plan_attempt(&task, crate::contracts::EffectClass::Exec, "second claim")?;
        let mut second_claim = claim;
        second_claim.attempt_id = second;
        match store.claim_check(
            &second_claim,
            &std::sync::atomic::AtomicBool::new(false),
            claim_deadline(),
        )? {
            super::ClaimOutcome::Claimed => {}
            super::ClaimOutcome::Refused(refused) => {
                unreachable!("the second attempt claims: {:?}", refused.site.suffix())
            }
        }
        assert_eq!(
            read_timeout(&store)?,
            1234,
            "a successful claim restores the prior before the COMMIT"
        );
        drop(store);

        Ok(())
    }

    #[test]
    fn two_contenders_race_through_the_one_admitted_writer_and_exactly_one_claims()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, store, _session, _task, attempt, claim) = claim_fixture("one-winner-race");
        let db = root.path().join("state.db");
        let shared = std::sync::Mutex::new(store);
        let barrier = std::sync::Barrier::new(2);
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let deadline = claim_deadline();
        let contend = || {
            barrier.wait();
            shared.lock().is_ok_and(|mut store| {
                store
                    .claim_check(&claim, &cancel, deadline)
                    .is_ok_and(|outcome| matches!(outcome, super::ClaimOutcome::Claimed))
            })
        };
        let (left, right) = std::thread::scope(|scope| {
            let left = scope.spawn(contend);
            let right = scope.spawn(contend);
            (left.join(), right.join())
        });
        let left = left.map_err(|_left_panic| "the left claim thread panicked".to_string())?;
        let right = right.map_err(|_right_panic| "the right claim thread panicked".to_string())?;
        let winners = usize::from(left) + usize::from(right);
        assert_eq!(
            winners, 1,
            "exactly one contender wins the first-only claim"
        );
        let marker: i64 = rusqlite::Connection::open(&db)?.query_row(
            "SELECT COUNT(*) FROM retained WHERE boundary_id = ?1",
            [format!("ret:check:{attempt}:admit.claim")],
            |row| row.get(0),
        )?;
        assert_eq!(marker, 1, "the marker exists exactly once");
        drop(shared);

        Ok(())
    }

    fn lifecycle_of(error: &super::StoreError) -> Option<&super::ConnectionLifecycleError> {
        match error {
            super::StoreError::Storage(source) => source.downcast_ref(),
            _ => None,
        }
    }

    #[test]
    fn task_store_open_refuses_a_hard_link_alias_before_sql() -> ProofResult {
        let root = tempfile::TempDir::with_prefix("rivect-writer-held-")?;
        let db = root.path().join("state.db");
        let linked = root.path().join("linked.db");
        let store = TaskStore::open(&db)?;
        std::fs::hard_link(&db, &linked)?;
        super::proof::arm();
        let by_name = TaskStore::open(&db);
        let by_link = TaskStore::open(&linked);
        let (events, _overflow) = super::proof::take().ok_or("the sink was armed")?;
        for refused in [by_name, by_link] {
            let error = match refused {
                Err(error) => error,
                Ok(_second) => return Err("a second writer was admitted".into()),
            };
            assert!(
                matches!(
                    lifecycle_of(&error),
                    Some(super::ConnectionLifecycleError::WriterHeld)
                ),
                "{error:?}"
            );
        }
        assert!(events.is_empty(), "no SQL statement ran: {events:?}");
        std::fs::remove_file(&linked)?;
        drop(store);
        drop(TaskStore::open(&db)?);
        Ok(())
    }

    #[test]
    fn a_failed_reservation_refuses_saturated_before_any_fd_or_file() -> ProofResult {
        let root = tempfile::TempDir::with_prefix("rivect-writer-reserve-")?;
        // Control: a successful admission of an absent path opens exactly
        // one creation fd and one identity fd, so the counters observe.
        let control = root.path().join("control.db");
        let before = super::proof::fd_counts();
        drop(TaskStore::open(&control)?);
        let after = super::proof::fd_counts();
        assert_eq!(
            (after.0 - before.0, after.1 - before.1),
            (1, 1),
            "the control admission opens one creation fd and one identity fd"
        );
        for dest in [
            super::Dest::Held,
            super::Dest::Parked,
            super::Dest::Unidentified,
        ] {
            // An existing database (identity fd would open) and an absent
            // path (creation fd would open too).
            let existing = root.path().join(format!("{dest:?}-existing.db"));
            drop(TaskStore::open(&existing)?);
            let absent = root.path().join(format!("{dest:?}-absent.db"));
            for (label, db) in [("existing", &existing), ("absent", &absent)] {
                let was_present = db.exists();
                let before = super::proof::fd_counts();
                super::proof::arm_reserve_fault(dest);
                let error = match TaskStore::open(db) {
                    Err(error) => error,
                    Ok(_store) => {
                        return Err(format!("{dest:?} {label} reservation failure admitted").into());
                    }
                };
                assert!(
                    matches!(
                        lifecycle_of(&error),
                        Some(super::ConnectionLifecycleError::WriterAdmissionSaturated)
                    ),
                    "{dest:?} {label}: {error:?}"
                );
                assert_eq!(
                    super::proof::fd_counts(),
                    before,
                    "{dest:?} {label}: no creation or identity fd was opened"
                );
                assert_eq!(
                    db.exists(),
                    was_present,
                    "{dest:?} {label}: the path is left as it was"
                );
            }
        }
        Ok(())
    }

    const LOCK_PROBE: &str = "state::tests::lock_probe_child";
    const WRITER_OPEN: &str = "state::tests::writer_open_child";

    /// One interactive child entry. It holds the parent's root from spawn
    /// to reap: a failed step, a receipt still missing at the outer bound,
    /// a wait without success and a last receipt other than `done` all
    /// retain the root and panic, sending no signal and not waiting again.
    /// Receipts are `receipt: <text>` lines on the child's stdout.
    struct ExperimentChild<'root> {
        root: &'root mut tempfile::TempDir,
        child: Option<std::process::Child>,
        stdin: Option<std::process::ChildStdin>,
        lines: std::sync::mpsc::Receiver<std::io::Result<String>>,
        reader: Option<std::thread::JoinHandle<()>>,
        finished: bool,
    }

    impl<'root> ExperimentChild<'root> {
        fn spawn(root: &'root mut tempfile::TempDir, entry: &str) -> Self {
            use std::io::BufRead as _;
            let spawned = spawn_child(
                ChildEntry::Ignored(entry),
                root.path(),
                std::process::Stdio::inherit(),
            );
            let mut child = match spawned {
                Ok(child) => child,
                Err(error) => custody_failure(Some(root), &error),
            };
            let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
                custody_failure(Some(root), &"the child pipes were missing");
            };
            let (sender, lines) = std::sync::mpsc::sync_channel(64);
            let reader = std::thread::Builder::new()
                .name("state-child-stdout".to_owned())
                .spawn(move || {
                    for line in std::io::BufReader::new(stdout).lines() {
                        let failed = line.is_err();
                        if sender.send(line).is_err() || failed {
                            return;
                        }
                    }
                });
            let reader = match reader {
                Ok(reader) => reader,
                Err(error) => custody_failure(Some(root), &error),
            };
            Self {
                root,
                child: Some(child),
                stdin: Some(stdin),
                lines,
                reader: Some(reader),
                finished: false,
            }
        }

        fn retain_and_panic(&mut self, error: &dyn std::fmt::Display) -> ! {
            custody_failure(Some(&mut *self.root), error)
        }

        /// The next receipt, or `None` once the child closed its stdout.
        fn next_receipt(&mut self) -> Result<Option<String>, String> {
            use std::sync::mpsc::RecvTimeoutError;
            let deadline = std::time::Instant::now() + super::proof::DEADLINE;
            loop {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                match self.lines.recv_timeout(remaining) {
                    Ok(Ok(line)) => {
                        if let Some((_, receipt)) = line.split_once("receipt: ") {
                            return Ok(Some(receipt.to_owned()));
                        }
                    }
                    Ok(Err(error)) => {
                        return Err(format!("reading the child stdout failed: {error}"));
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        return Err("a receipt is still missing at the outer bound".to_owned());
                    }
                    Err(RecvTimeoutError::Disconnected) => return Ok(None),
                }
            }
        }

        /// Requires the next receipt to be `want`.
        fn await_receipt(&mut self, want: &str) {
            match self.next_receipt() {
                Ok(Some(got)) if got == want => {}
                Ok(Some(got)) => {
                    self.retain_and_panic(&format!("expected receipt {want}, read {got}"));
                }
                Ok(None) => {
                    self.retain_and_panic(&format!("the child closed stdout before {want}"));
                }
                Err(error) => self.retain_and_panic(&error),
            }
        }

        /// One line on the child's stdin.
        fn send(&mut self, line: &str) {
            use std::io::Write as _;
            let written = match self.stdin.as_mut() {
                Some(pipe) => writeln!(pipe, "{line}").and_then(|()| pipe.flush()),
                None => Err(std::io::Error::other("the child stdin was already closed")),
            };
            if let Err(error) = written {
                self.retain_and_panic(&error);
            }
        }

        /// A one-shot child of the same parent while this one waits.
        fn probe(&mut self, entry: &str, request: &[u8]) -> std::process::Output {
            let root = self.root.path().to_path_buf();
            run_probe_child(
                Some(&mut *self.root),
                &root,
                ChildEntry::Ignored(entry),
                request,
            )
        }

        /// Closes stdin, reads the remaining receipts, waits within the
        /// outer bound and returns the receipts after a successful exit
        /// whose last receipt is `done`.
        fn finish(mut self) -> Vec<String> {
            drop(self.stdin.take());
            let mut receipts = Vec::new();
            loop {
                match self.next_receipt() {
                    Ok(Some(receipt)) => receipts.push(receipt),
                    Ok(None) => break,
                    Err(error) => self.retain_and_panic(&error),
                }
            }
            let Some(mut child) = self.child.take() else {
                self.retain_and_panic(&"the child was already reaped");
            };
            // `wait` has no deadline of its own: a waiter thread reports the
            // status over a bounded channel, so a hang fails at the bound.
            let (reported, waited) = std::sync::mpsc::sync_channel(1);
            let waiter = std::thread::Builder::new()
                .name("state-child-wait".to_owned())
                .spawn(move || drop(reported.send(child.wait())));
            let waiter = match waiter {
                Ok(waiter) => waiter,
                Err(error) => self.retain_and_panic(&error),
            };
            let status = match waited.recv_timeout(super::proof::DEADLINE) {
                Ok(Ok(status)) => status,
                Ok(Err(error)) => self.retain_and_panic(&error),
                Err(error) => {
                    self.retain_and_panic(&format!("the wait returned no status: {error}"))
                }
            };
            if waiter.join().is_err()
                || self
                    .reader
                    .take()
                    .is_some_and(|reader| reader.join().is_err())
            {
                self.retain_and_panic(&"a child helper thread panicked");
            }
            if !status.success() {
                self.retain_and_panic(&format!(
                    "the child failed ({status}); receipts {receipts:?}"
                ));
            }
            if receipts.last().map(String::as_str) != Some("done") {
                self.retain_and_panic(&format!(
                    "the child never reported done; receipts {receipts:?}"
                ));
            }
            self.finished = true;
            receipts
        }
    }

    impl Drop for ExperimentChild<'_> {
        fn drop(&mut self) {
            if !self.finished {
                // Unwinding between steps: the child may still be alive.
                self.root.disable_cleanup(true);
            }
        }
    }

    /// Child side of the experiment protocol: one `receipt: <text>` line.
    fn receipt(text: &str) -> ProofResult {
        use std::io::Write as _;
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "receipt: {text}")?;
        stdout.flush()?;
        Ok(())
    }

    /// Blocks for the parent's next stdin line. End-of-file means the
    /// parent stopped waiting, so the entry fails at once.
    fn await_line(want: &str) -> ProofResult {
        use std::io::BufRead as _;
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line)? == 0 {
            return Err(format!("stdin closed before the {want} line").into());
        }
        if line.trim_end() != want {
            return Err(format!("expected the {want} line, read {line:?}").into());
        }
        Ok(())
    }

    /// The parent-owned root of a child entry; the cleared environment
    /// leaves exactly the marker.
    fn child_root() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let root =
            std::env::var_os(CHILD_ROOT).ok_or("the child entry runs only under its parent")?;
        let vars = std::env::vars_os().count();
        if vars != 1 {
            return Err(format!("the child environment holds {vars} variables, not 1").into());
        }
        Ok(root.into())
    }

    /// The identity fd registered for `id` and the fds parked under it.
    fn registry_entry(id: super::FileId) -> (Option<std::os::fd::RawFd>, Vec<std::os::fd::RawFd>) {
        use std::os::fd::AsRawFd as _;
        let identity = super::WRITERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .held
            .get(&id)
            .map(|fd| fd.as_raw_fd());
        let parked = super::WRITERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .parked
            .iter()
            .filter(|(under, _fd)| *under == id)
            .map(|(_under, fd)| fd.as_raw_fd())
            .collect();
        (identity, parked)
    }

    /// Whether `fd` is open in this process, observed through the native
    /// `/dev/fd` entry (a link into procfs on Linux, fdesc on Darwin): a
    /// closed descriptor has no entry.
    fn fd_is_open(fd: std::os::fd::RawFd) -> bool {
        std::fs::metadata(format!("/dev/fd/{fd}")).is_ok()
    }

    #[test]
    fn poisoned_registry_refuses_before_any_fd_and_drop_still_closes_in_order() -> ProofResult {
        let mut root = tempfile::TempDir::with_prefix("rivect-poisoned-registry-")?;
        let holder_db = root.path().join("holder.db");
        let unrelated = root.path().join("unrelated.db");
        drop(TaskStore::open(&unrelated)?);
        let mut child = ExperimentChild::spawn(&mut root, "state::tests::poisoned_registry_child");
        child.await_receipt("holder_dropped");
        // Every parent step stays a value until the child is reaped.
        let request = format!("{}\n", holder_db.display());
        let opened = child.probe(WRITER_OPEN, request.as_bytes());
        let reported = open_report(&opened);
        child.send("go");
        assert_eq!(child.finish(), ["done"]);
        let (outcome, statements) = reported?;
        assert_eq!(
            outcome, "opened",
            "the cross-process open is admitted once the poisoned holder dropped"
        );
        assert!(statements > 0, "an open runs SQL the armed sink records");
        drop(TaskStore::open(&unrelated)?);
        Ok(())
    }

    /// Child entry: a poisoned registry refuses every admission before
    /// a descriptor opens, and the holder's drop still closes its parked
    /// fds and then its identity fd through the recovered guard.
    #[test]
    #[ignore = "child entry of poisoned_registry_refuses_before_any_fd_and_drop_still_closes_in_order"]
    fn poisoned_registry_child() -> ProofResult {
        let root = child_root()?;
        let holder_db = root.join("holder.db");
        let existing = root.join("existing.db");
        let absent = root.join("absent.db");
        drop(TaskStore::open(&existing)?);
        let holder = TaskStore::open(&holder_db)?;
        // Two names swapped onto the held inode park two fds under it.
        for name in ["parked-0.db", "parked-1.db"] {
            super::proof::arm_after_stat(holder_db.clone());
            let refused = TaskStore::open(&root.join(name));
            assert!(
                matches!(
                    refused.as_ref().err().and_then(lifecycle_of),
                    Some(super::ConnectionLifecycleError::WriterHeld)
                ),
                "{name}: {:?}",
                refused.as_ref().err()
            );
        }
        let id = holder.writer;
        let (identity, parked) = registry_entry(id);
        let identity = identity.ok_or("the holder has an identity fd")?;
        assert_eq!(parked.len(), 2, "two fds are parked under the holder");
        let tracked: Vec<_> = parked.into_iter().chain([identity]).collect();
        assert!(
            tracked.iter().copied().all(fd_is_open),
            "control: every tracked fd is open before the drop"
        );

        let poisoned = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _guard = super::WRITERS.lock();
                    std::panic::resume_unwind(Box::new("poisoning the writer registry"));
                })
                .join()
        });
        assert!(poisoned.is_err(), "the poisoner unwinds");
        assert!(super::WRITERS.is_poisoned(), "the registry is poisoned");

        for (label, path) in [("existing", &existing), ("absent", &absent)] {
            let before = super::proof::fd_counts();
            let refused = TaskStore::open(path);
            assert!(
                matches!(
                    refused.as_ref().err().and_then(lifecycle_of),
                    Some(super::ConnectionLifecycleError::WriterRegistry)
                ),
                "{label}: {:?}",
                refused.as_ref().err()
            );
            assert_eq!(
                super::proof::fd_counts(),
                before,
                "{label}: no creation or identity fd was opened"
            );
        }
        assert!(existing.exists(), "the existing database is left alone");
        assert!(!absent.exists(), "the absent path stays absent");

        drop(holder);
        let (identity, parked) = registry_entry(id);
        assert!(
            identity.is_none() && parked.is_empty(),
            "the drop removed the entry and its parked fds through the recovered guard"
        );
        assert!(
            !tracked.iter().copied().any(fd_is_open),
            "every parked fd and the identity fd are closed"
        );
        // The two parked names were hard links to the holder's inode; with
        // the holder released they are this fixture's own aliases, and a
        // cross-process open must meet an ordinary one-link database.
        for name in ["parked-0.db", "parked-1.db"] {
            std::fs::remove_file(root.join(name))?;
        }
        // The holder's sentinel is released: the parent's cross-process
        // open of its database is admitted while this registry stays poisoned.
        receipt("holder_dropped")?;
        await_line("go")?;
        // The poison is permanent: no reset ran, so the next admission still refuses.
        assert!(super::WRITERS.is_poisoned(), "the poison stays");
        let refused = TaskStore::open(&absent);
        assert!(
            matches!(
                refused.as_ref().err().and_then(lifecycle_of),
                Some(super::ConnectionLifecycleError::WriterRegistry)
            ),
            "{:?}",
            refused.as_ref().err()
        );
        receipt("done")?;
        Ok(())
    }

    /// The one report line a probe or opener child printed. The child
    /// must have exited successfully with exactly its own test passed.
    fn child_report(output: &std::process::Output, prefix: &str) -> Result<String, String> {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() || !stdout.contains("test result: ok. 1 passed;") {
            return Err(format!(
                "the child failed ({}):\n{stdout}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        stdout
            .lines()
            .find_map(|line| line.split_once(prefix).map(|(_, rest)| rest.to_owned()))
            .ok_or_else(|| format!("the child printed no {prefix:?} report:\n{stdout}"))
    }

    /// `(outcome, statements)` of one opener child.
    fn open_report(output: &std::process::Output) -> Result<(String, usize), String> {
        let report = child_report(output, "open-child: ")?;
        let (outcome, statements) = report
            .split_once(' ')
            .ok_or_else(|| format!("malformed open report {report:?}"))?;
        let statements = statements
            .parse::<usize>()
            .map_err(|error| format!("malformed statement count {statements:?}: {error}"))?;
        Ok((outcome.to_owned(), statements))
    }

    /// A parent's cross-process opener of `db`; its root is retained when
    /// the child's reap is unproven.
    fn open_child(
        owner: &mut tempfile::TempDir,
        db: &std::path::Path,
    ) -> Result<(String, usize), String> {
        let root = owner.path().to_path_buf();
        let request = format!("{}\n", db.display());
        open_report(&run_probe_child(
            Some(owner),
            &root,
            ChildEntry::Ignored(WRITER_OPEN),
            request.as_bytes(),
        ))
    }

    /// One foreign POSIX lock probe of `range` (`offset`, `len`) of `db`.
    fn lock_probe(
        owner: Option<&mut tempfile::TempDir>,
        root: &std::path::Path,
        kind: &str,
        db: &std::path::Path,
        range: (i64, i64),
    ) -> Result<String, String> {
        let request = format!("{kind} {} {} {}\n", range.0, range.1, db.display());
        child_report(
            &run_probe_child(
                owner,
                root,
                ChildEntry::Ignored(LOCK_PROBE),
                request.as_bytes(),
            ),
            "probe-child: ",
        )
    }

    /// A parent's probe of SQLite's shared range of the main file: `held`
    /// or `acquired`.
    fn probe_main_file_range(
        owner: &mut tempfile::TempDir,
        db: &std::path::Path,
    ) -> Result<String, String> {
        let root = owner.path().to_path_buf();
        lock_probe(
            Some(owner),
            &root,
            "write",
            db,
            (SQLITE_SHARED_FIRST, SQLITE_SHARED_SIZE),
        )
    }

    /// The request a parent wrote to this child's stdin before closing it.
    fn child_request() -> Result<String, Box<dyn std::error::Error>> {
        use std::io::Read as _;
        let mut request = String::new();
        std::io::stdin().read_to_string(&mut request)?;
        if request.trim().is_empty() {
            return Err("the child entry got no request".into());
        }
        Ok(request)
    }

    #[test]
    fn cross_process_second_writer_is_refused_before_sql() -> ProofResult {
        let mut root = tempfile::TempDir::with_prefix("rivect-cross-process-sink-")?;
        let db = root.path().join("state.db");
        let holder = TaskStore::open(&db)?;
        let (outcome, statements) = open_child(&mut root, &db)?;
        assert_eq!(
            (outcome.as_str(), statements),
            ("WriterHeld", 0),
            "the second process is refused with no SQL statement"
        );
        // Control: once the holder drops, the same child opens and its
        // sink is non-empty, so a zero above is not a dead sink.
        drop(holder);
        let (outcome, statements) = open_child(&mut root, &db)?;
        assert_eq!(outcome, "opened", "the child opens after the holder drops");
        assert!(statements > 0, "an open runs SQL the armed sink records");
        Ok(())
    }

    /// Child entry of the cross-process sink proof: arms the sink, opens
    /// the database the request names, and reports the outcome and the
    /// number of recorded statements on stdout.
    #[test]
    #[ignore = "child entry started only through run_probe_child"]
    fn writer_open_child() -> ProofResult {
        use std::io::Write as _;
        let root = child_root()?;
        let request = child_request()?;
        let db = std::path::PathBuf::from(request.trim_end());
        if !db.starts_with(&root) {
            return Err(format!("{} lies outside the child root", db.display()).into());
        }
        super::proof::arm();
        let opened = TaskStore::open(&db);
        let (events, _overflow) = super::proof::take().ok_or("the sink was armed")?;
        let outcome = match &opened {
            Ok(_store) => "opened",
            Err(error) => match lifecycle_of(error) {
                Some(super::ConnectionLifecycleError::WriterHeld) => "WriterHeld",
                _ => return Err(format!("unexpected open refusal: {error:?}").into()),
            },
        };
        writeln!(std::io::stdout(), "open-child: {outcome} {}", events.len())?;
        Ok(())
    }

    #[test]
    fn admission_cap_is_checked_under_the_registry_lock() -> ProofResult {
        let mut root = tempfile::TempDir::with_prefix("rivect-admission-cap-")?;
        let unrelated = root.path().join("unrelated.db");
        drop(TaskStore::open(&unrelated)?);
        let mut child = ExperimentChild::spawn(&mut root, "state::tests::admission_cap_child");
        child.await_receipt("saturated");
        // Every parent step stays a value until the child is reaped.
        let between = TaskStore::open(&unrelated).map(drop);
        child.send("release");
        assert_eq!(child.finish(), ["done"]);
        between?;
        drop(TaskStore::open(&unrelated)?);
        Ok(())
    }

    /// Child entry: one barrier releases 33 openers that each find their
    /// name swapped onto a held inode. Exactly the contractual 32 park an fd
    /// and refuse `WriterHeld`; the one beyond refuses saturated having
    /// opened no fd and created no file.
    #[test]
    #[ignore = "child entry of admission_cap_is_checked_under_the_registry_lock"]
    fn admission_cap_child() -> ProofResult {
        #[derive(Debug, PartialEq, Eq)]
        enum Outcome {
            Admitted,
            Held,
            Saturated,
            Other(String),
        }
        // Contract literals, not `STORE_PARKED_MAX`: a cap raised by mistake
        // admits the 33rd opener and fails the saturation checks below.
        const CAP: usize = 32;
        const CONTENDERS: usize = 33;
        let root = child_root()?;
        let holder_db = root.join("holder.db");
        let holder = TaskStore::open(&holder_db)?;
        let id = holder.writer;
        let barrier = std::sync::Barrier::new(CONTENDERS);
        let joined: Result<Vec<_>, _> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..CONTENDERS)
                .map(|n| {
                    let path = root.join(format!("contender-{n}.db"));
                    let (barrier, holder_db) = (&barrier, &holder_db);
                    scope.spawn(move || {
                        super::proof::arm_after_stat(holder_db.clone());
                        barrier.wait();
                        let outcome = match TaskStore::open(&path) {
                            Ok(_store) => Outcome::Admitted,
                            Err(error) => match lifecycle_of(&error) {
                                Some(super::ConnectionLifecycleError::WriterHeld) => Outcome::Held,
                                Some(super::ConnectionLifecycleError::WriterAdmissionSaturated) => {
                                    Outcome::Saturated
                                }
                                _ => Outcome::Other(format!("{error:?}")),
                            },
                        };
                        (path, outcome, super::proof::fd_counts())
                    })
                })
                .collect();
            handles.into_iter().map(|handle| handle.join()).collect()
        });
        let outcomes = joined.map_err(|_panic| "a contender thread panicked")?;
        let mut saturated = 0;
        for (path, outcome, counts) in &outcomes {
            match outcome {
                Outcome::Held => {
                    assert_eq!(
                        *counts,
                        (1, 1),
                        "{path:?}: one creation and one identity fd"
                    );
                    assert!(path.exists(), "{path:?}: the swapped name stays");
                }
                Outcome::Saturated => {
                    saturated += 1;
                    assert_eq!(*counts, (0, 0), "{path:?}: no fd was opened");
                    assert!(!path.exists(), "{path:?}: the path stays absent");
                }
                Outcome::Admitted | Outcome::Other(_) => {
                    return Err(format!("{path:?}: unexpected {outcome:?}").into());
                }
            }
        }
        assert_eq!(saturated, 1, "exactly one opener is beyond the cap");
        let identity_fds: usize = outcomes
            .iter()
            .map(|(_path, _outcome, counts)| counts.1)
            .sum();
        assert_eq!(identity_fds, CAP, "the cap bounds identity fds");
        assert_eq!(
            registry_entry(id).1.len(),
            CAP,
            "the holder has the cap's worth of parked fds"
        );

        let absent = root.join("absent.db");
        let before = super::proof::fd_counts();
        let refused = TaskStore::open(&absent);
        assert!(
            matches!(
                refused.as_ref().err().and_then(lifecycle_of),
                Some(super::ConnectionLifecycleError::WriterAdmissionSaturated)
            ),
            "{:?}",
            refused.as_ref().err()
        );
        assert_eq!(super::proof::fd_counts(), before, "no fd was opened");
        assert!(!absent.exists(), "the absent path stays absent");
        // The child reports saturation and waits: the parent admits an
        // unrelated store meanwhile, then releases the holder.
        receipt("saturated")?;
        await_line("release")?;

        drop(holder);
        assert!(
            registry_entry(id).1.is_empty(),
            "the drop closed every parked fd"
        );
        drop(TaskStore::open(&absent)?);
        receipt("done")?;
        Ok(())
    }

    /// SQLite's shared-lock byte range of the main database file
    /// (`PENDING_BYTE + 2`, `SHARED_SIZE`): a reader or WAL connection
    /// holds it, so a foreign exclusive request over it must conflict.
    const SQLITE_SHARED_FIRST: i64 = 0x4000_0002;
    const SQLITE_SHARED_SIZE: i64 = 510;

    #[test]
    fn fresh_file_creation_fd_closes_inside_registry_exclusion() -> ProofResult {
        let mut root = tempfile::TempDir::with_prefix("rivect-fresh-creation-")?;
        let unrelated = root.path().join("unrelated.db");
        drop(TaskStore::open(&unrelated)?);
        let child = ExperimentChild::spawn(&mut root, "state::tests::fresh_file_creation_child");
        assert_eq!(child.finish(), ["done"]);
        drop(TaskStore::open(&unrelated)?);
        Ok(())
    }

    fn expect_receipt(inbox: &std::sync::mpsc::Receiver<String>, want: &str) -> ProofResult {
        let read = inbox
            .recv_timeout(super::proof::DEADLINE)
            .map_err(|error| format!("no {want} receipt: {error}"))?;
        if read != want {
            return Err(format!("expected receipt {want}, read {read}").into());
        }
        Ok(())
    }

    /// The mutant branch of the creation proof, reached only when B's first
    /// receipt was `B:acquired`: B was admitted while A still held its
    /// creation fd. B's own transaction is calibrated first (the main-file
    /// range conflicts, the WAL write lock is BUSY); once A closes its
    /// creation fd, the main-file range must still conflict. A range that
    /// is free while the WAL stays BUSY shows the close dropped B's lock,
    /// and that causal loss fails the proof before any receipt order is
    /// read. Every path returns an error: a correct build never gets here.
    fn creation_escaped_the_section(
        inbox: &std::sync::mpsc::Receiver<String>,
        release: &std::sync::mpsc::SyncSender<()>,
        second_result: &std::sync::mpsc::Receiver<super::Result<TaskStore>>,
        db: &std::path::Path,
        probe: &dyn Fn() -> Result<String, String>,
    ) -> Result<std::convert::Infallible, Box<dyn std::error::Error>> {
        let store_b = second_result
            .recv_timeout(super::proof::DEADLINE)
            .map_err(|error| format!("B returned no store while A held its creation fd: {error}"))?
            .map_err(|error| format!("B was refused while A held its creation fd: {error:?}"))?;
        store_b
            .conn
            .as_ref()
            .ok_or("B has no connection")?
            .execute_batch("BEGIN IMMEDIATE")?;
        let main_before = probe()?;
        let wal_before = sqlite_immediate_is_busy(db);
        release.send(())?;
        let deadline = std::time::Instant::now() + super::proof::DEADLINE;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let receipt = inbox
                .recv_timeout(remaining)
                .map_err(|error| format!("no A:closed receipt: {error}"))?;
            if receipt == "A:closed" {
                break;
            }
        }
        let main_after = probe()?;
        let wal_after = sqlite_immediate_is_busy(db);
        if main_before != "held" || wal_before.is_err() {
            return Err(format!(
                "calibration failed: main-file range {main_before}, WAL {wal_before:?}"
            )
            .into());
        }
        if main_after == "acquired" && wal_after.is_ok() {
            return Err(
                "A closed its creation fd outside the registry exclusion: B's main-file lock was lost while the WAL range stayed BUSY"
                    .into(),
            );
        }
        Err("B was admitted before A closed its creation fd; the receipts A:closed, A:section_end, B:acquired are out of order"
            .into())
    }

    /// Child entry: two threads open one absent database. The first is
    /// held inside the creation section after `create_new` and before
    /// its creation fd drops; the second must find the registry guard
    /// taken, and only after the first closes its fd and leaves the
    /// section does it enter, so it sees the file and refuses. While the
    /// first holds a write transaction, a foreign process cannot take
    /// SQLite's shared range and a second connection finds the writer
    /// busy; both clear once it commits and drops.
    #[test]
    #[ignore = "child entry of fresh_file_creation_fd_closes_inside_registry_exclusion"]
    fn fresh_file_creation_child() -> ProofResult {
        use super::WriterPoint as Point;
        use super::proof::{DEADLINE, WriterProbe, arm_probe};
        use std::sync::mpsc::sync_channel;
        type Opened = super::Result<TaskStore>;
        let root = child_root()?;
        let db = root.join("fresh.db");
        let probe = || {
            lock_probe(
                None,
                &root,
                "write",
                &db,
                (SQLITE_SHARED_FIRST, SQLITE_SHARED_SIZE),
            )
        };
        // Every wait below is bounded by DEADLINE; the channels live in
        // the scope so an early return drops `release` and frees the
        // paused thread before the scope joins.
        let (opened, counts, refused) = std::thread::scope(|scope| {
            let (receipts, inbox) = sync_channel::<String>(16);
            let (release, held) = sync_channel::<()>(1);
            let (first_done, first_result) = sync_channel::<(Opened, (usize, usize))>(1);
            let (second_done, second_result) = sync_channel::<Opened>(1);

            let first = scope.spawn({
                let (receipts, db) = (receipts.clone(), &db);
                move || {
                    arm_probe(WriterProbe {
                        receipts,
                        points: &[
                            (Point::CreationOpen, "A:open"),
                            (Point::CreationDrop, "A:closed"),
                            (Point::AfterPlace, "A:section_end"),
                        ],
                        pause: Some((Point::CreationOpen, held)),
                    });
                    let opened = TaskStore::open(db);
                    drop(first_done.send((opened, super::proof::fd_counts())));
                }
            });
            expect_receipt(&inbox, "A:open")?;

            // The first thread now holds the registry guard with its
            // creation fd open. The second starts only after that
            // receipt, and its admission is not awaited while the first
            // is paused.
            let second = scope.spawn({
                let db = &db;
                move || {
                    arm_probe(WriterProbe {
                        receipts: receipts.clone(),
                        points: &[(Point::AfterReserve, "B:acquired")],
                        pause: None,
                    });
                    let attempt = super::WRITERS.try_lock();
                    let first_receipt =
                        if matches!(attempt, Err(std::sync::TryLockError::WouldBlock)) {
                            "B:contended"
                        } else {
                            "B:acquired"
                        };
                    drop(attempt);
                    drop(receipts.send(first_receipt.to_owned()));
                    drop(second_done.send(TaskStore::open(db)));
                }
            });
            // B's first receipt decides the branch. `B:contended` is the
            // correct build: B found the guard held and waits behind A.
            // `B:acquired` means A's creation ran outside the exclusion.
            let first_of_b = inbox
                .recv_timeout(DEADLINE)
                .map_err(|error| format!("B reported no first receipt: {error}"))?;
            if first_of_b == "B:acquired" {
                let never =
                    creation_escaped_the_section(&inbox, &release, &second_result, &db, &probe)?;
                match never {}
            }
            if first_of_b != "B:contended" {
                return Err(format!("unexpected first receipt of B: {first_of_b}").into());
            }
            release.send(())?;
            for want in ["A:closed", "A:section_end", "B:acquired"] {
                expect_receipt(&inbox, want)?;
            }
            let (opened, counts) = first_result
                .recv_timeout(DEADLINE)
                .map_err(|error| format!("the first opener returned no result: {error}"))?;
            let refused = second_result
                .recv_timeout(DEADLINE)
                .map_err(|error| format!("the second opener returned no result: {error}"))?;
            first.join().map_err(|_panic| "the first opener panicked")?;
            second
                .join()
                .map_err(|_panic| "the second opener panicked")?;
            Ok::<_, Box<dyn std::error::Error>>((opened, counts, refused))
        })?;

        let store = opened.map_err(|error| format!("the first opener was refused: {error:?}"))?;
        assert_eq!(counts, (1, 1), "one creation fd and one identity fd");
        let refusal = refused.err().ok_or("the second opener was admitted")?;
        assert!(
            matches!(
                lifecycle_of(&refusal),
                Some(super::ConnectionLifecycleError::WriterHeld)
            ),
            "{refusal:?}"
        );

        let conn = store.conn.as_ref().ok_or("the first store is open")?;
        conn.execute_batch("BEGIN IMMEDIATE")?;
        assert_eq!(
            probe()?,
            "held",
            "a foreign process cannot take SQLite's shared range"
        );
        sqlite_immediate_is_busy(&db)?;
        conn.execute_batch("COMMIT")?;
        drop(store);
        assert_eq!(
            probe()?,
            "acquired",
            "the range is free once the writer commits and drops"
        );
        receipt("done")?;
        Ok(())
    }

    /// Child entry: takes one POSIX byte-range lock over the main file the
    /// request names and reports whether another process held it. The
    /// request is `<read|write> <offset> <len> <path>`.
    #[test]
    #[ignore = "child entry started only through run_probe_child"]
    fn lock_probe_child() -> ProofResult {
        use rivect_sandbox_helper::{OfdLockError, posix_try_read_range, posix_try_write_range};
        use std::io::Write as _;
        let root = child_root()?;
        let request = child_request()?;
        let mut fields = request.trim_end().splitn(4, ' ');
        let (Some(kind), Some(offset), Some(len), Some(db)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(format!("malformed lock probe request {request:?}").into());
        };
        let (offset, len): (i64, i64) = (offset.parse()?, len.parse()?);
        let db = std::path::PathBuf::from(db);
        if !db.starts_with(&root) {
            return Err(format!("{} lies outside the child root", db.display()).into());
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&db)?;
        let probed = match kind {
            "read" => posix_try_read_range(&file, offset, len),
            "write" => posix_try_write_range(&file, offset, len),
            other => return Err(format!("unknown lock kind {other:?}").into()),
        };
        let outcome = match probed {
            Ok(()) => "acquired",
            Err(OfdLockError::Held) => "held",
            Err(error) => return Err(format!("the range probe failed: {error:?}").into()),
        };
        writeln!(std::io::stdout(), "probe-child: {outcome}")?;
        Ok(())
    }

    fn assert_open_refused_without_sql(path: &std::path::Path) -> ProofResult {
        super::proof::arm();
        let refused = TaskStore::open(path);
        let (events, _overflow) = super::proof::take().ok_or("the sink was armed")?;
        match refused {
            Err(error) => assert!(
                matches!(
                    lifecycle_of(&error),
                    Some(super::ConnectionLifecycleError::WriterHeld)
                ),
                "{error:?}"
            ),
            Ok(_second) => return Err("a second writer was admitted".into()),
        }
        assert!(events.is_empty(), "no SQL statement ran: {events:?}");
        Ok(())
    }

    #[test]
    fn task_store_open_refuses_a_second_writer_for_the_same_db() -> ProofResult {
        let root = tempfile::TempDir::with_prefix("rivect-writer-same-")?;
        let db = root.path().join("state.db");
        let store = TaskStore::open(&db)?;
        assert_open_refused_without_sql(&db)?;
        drop(store);
        drop(TaskStore::open(&db)?);
        Ok(())
    }

    #[test]
    fn task_store_open_refuses_a_second_writer_through_a_renamed_path() -> ProofResult {
        let root = tempfile::TempDir::with_prefix("rivect-writer-renamed-")?;
        let db = root.path().join("state.db");
        let store = TaskStore::open(&db)?;
        let same_dir = root.path().join("renamed.db");
        std::fs::rename(&db, &same_dir)?;
        assert_open_refused_without_sql(&same_dir)?;
        let other_dir = root.path().join("elsewhere");
        std::fs::create_dir(&other_dir)?;
        let cross_dir = other_dir.join("moved.db");
        std::fs::rename(&same_dir, &cross_dir)?;
        assert_open_refused_without_sql(&cross_dir)?;
        drop(store);
        Ok(())
    }

    #[test]
    fn writer_lock_survives_reopen_and_releases_on_drop() -> ProofResult {
        let root = tempfile::TempDir::with_prefix("rivect-writer-reopen-")?;
        let db = root.path().join("state.db");
        let mut store = TaskStore::open(&db)?;
        store.reopen(&db)?;
        assert_open_refused_without_sql(&db)?;
        drop(store);
        drop(TaskStore::open(&db)?);
        Ok(())
    }

    /// One refused open of a writer-held database, seen in this process
    /// and through a second one: typed `WriterHeld`, no SQL statement,
    /// and the registry entry of `id` still present.
    fn assert_writer_kept(
        root: &mut tempfile::TempDir,
        db: &std::path::Path,
        id: super::FileId,
        label: &str,
    ) -> ProofResult {
        assert_open_refused_without_sql(db)?;
        let (outcome, statements) = open_child(root, db)?;
        assert_eq!(
            (outcome.as_str(), statements),
            ("WriterHeld", 0),
            "{label}: the second process is refused with no SQL statement"
        );
        assert!(
            !writer_entry_absent(id),
            "{label}: the writer entry survived"
        );
        Ok(())
    }

    fn arm_open_fault() {
        super::proof::arm_fault(super::proof::Site::Open);
    }

    #[test]
    fn failed_same_inode_reopen_keeps_the_writer_entry_until_drop() -> ProofResult {
        let mut root = tempfile::TempDir::with_prefix("rivect-writer-failed-reopen-")?;
        let db = root.path().join("state.db");
        let mut store = TaskStore::open(&db)?;
        let id = store.writer;
        // One seam per stage of the same-inode reopen: the injected open,
        // the connect's open flags, its settle check, the settings and
        // the bootstrap.
        let seams: [(&str, fn()); 5] = [
            ("open", arm_open_fault),
            ("open-flags", super::proof::arm_open_flags_fault),
            ("settle", super::proof::arm_settle_fault),
            ("settings", super::proof::arm_settings_fault),
            ("bootstrap", super::proof::arm_bootstrap_fault),
        ];
        for (label, arm) in seams {
            arm();
            if store.reopen(&db).is_ok() {
                return Err(
                    format!("{label}: the injected fault did not refuse the reopen").into(),
                );
            }
            assert_writer_kept(&mut root, &db, id, label)?;
            store.reopen(&db)?;
        }
        store.close()?;
        assert_writer_kept(&mut root, &db, id, "close")?;
        drop(store);
        assert!(writer_entry_absent(id), "the drop destroyed the entry");
        drop(TaskStore::open(&db)?);
        let (outcome, statements) = open_child(&mut root, &db)?;
        assert_eq!(
            outcome, "opened",
            "the second process is admitted once the store dropped"
        );
        assert!(statements > 0, "an open runs SQL the armed sink records");

        // Delete-and-recreate with a failed connect of the new inode: the
        // new inode's entry is destroyed, the old inode's entry stays.
        let mut moved = tempfile::TempDir::with_prefix("rivect-writer-failed-recreate-")?;
        let db = moved.path().join("state.db");
        let mut store = TaskStore::open(&db)?;
        let old = store.writer;
        let alias = moved.path().join("alias.db");
        std::fs::hard_link(&db, &alias)?;
        for name in ["state.db", "state.db-wal", "state.db-shm"] {
            drop(std::fs::remove_file(moved.path().join(name)));
        }
        super::proof::arm_open_flags_fault();
        if store.reopen(&db).is_ok() {
            return Err("the recreated inode connected despite the injected fault".into());
        }
        let new = database_id(&db)?;
        assert_ne!(new, old, "the recreated path is a new inode");
        assert!(
            writer_entry_absent(new),
            "the failed connect destroyed the new inode's entry"
        );
        assert!(!writer_entry_absent(old), "the old inode's entry stays");
        let (outcome, statements) = open_child(&mut moved, &alias)?;
        assert_eq!(
            (outcome.as_str(), statements),
            ("WriterHeld", 0),
            "the old inode is still refused through its second name"
        );
        drop(store);
        assert!(writer_entry_absent(old), "the drop destroyed the old entry");
        Ok(())
    }

    #[test]
    fn reopen_after_delete_and_recreate_relocks_the_new_inode() -> ProofResult {
        let root = tempfile::TempDir::with_prefix("rivect-writer-recreate-")?;
        let db = root.path().join("state.db");
        let mut store = TaskStore::open(&db)?;
        let old = store.writer;
        for name in ["state.db", "state.db-wal", "state.db-shm"] {
            drop(std::fs::remove_file(root.path().join(name)));
        }
        store.reopen(&db)?;
        assert_ne!(store.writer, old, "the recreated path is a new inode");
        assert_open_refused_without_sql(&db)?;
        drop(store);
        drop(TaskStore::open(&db)?);
        Ok(())
    }

    #[test]
    fn writer_sentinel_is_disjoint_from_sqlite_lock_bytes() -> ProofResult {
        // SQLite locks PENDING_BYTE, RESERVED_BYTE and the shared range
        // [SHARED_FIRST, SHARED_FIRST + SHARED_SIZE); the sentinel lies far above.
        const PENDING_BYTE: i64 = SQLITE_SHARED_FIRST - 2;
        let mut root = tempfile::TempDir::with_prefix("rivect-writer-sentinel-")?;
        let root_path = root.path().to_path_buf();
        let db = root_path.join("state.db");
        let store = TaskStore::open(&db)?;
        // The sentinel is held from the open on, and the store's own
        // transaction runs beside it.
        let conn = store.conn.as_ref().ok_or("the store has no connection")?;
        conn.execute_batch("BEGIN IMMEDIATE")?;
        conn.execute_batch("COMMIT")?;
        // Idle: a foreign read lock over every byte SQLite uses is granted,
        // so the sentinel overlaps none of them.
        let sqlite_bytes = (
            PENDING_BYTE,
            SQLITE_SHARED_FIRST + SQLITE_SHARED_SIZE - PENDING_BYTE,
        );
        assert_eq!(
            lock_probe(Some(&mut root), &root_path, "read", &db, sqlite_bytes)?,
            "acquired",
            "an idle store holds nothing a foreign reader needs"
        );
        // The sentinel itself conflicts with a foreign write lock until the
        // store drops.
        let sentinel = (super::STORE_WRITER_LOCK_OFFSET, 1);
        assert_eq!(
            lock_probe(Some(&mut root), &root_path, "write", &db, sentinel)?,
            "held",
            "the live store holds the sentinel byte"
        );
        drop(store);
        assert_eq!(
            lock_probe(Some(&mut root), &root_path, "write", &db, sentinel)?,
            "acquired",
            "the sentinel is released with the store"
        );
        Ok(())
    }

    type WriterLog = Vec<(super::WriterPoint, super::proof::RegistrySnapshot)>;

    /// One admission's witness: the vector capacities are equal across all
    /// its snapshots, the `held` capacity never falls below and its free
    /// slack never rises above the reserved ones, nothing lands before the
    /// identity fd is open, and exactly one slot of exactly `destination`
    /// fills afterwards.
    fn writer_witness(log: &WriterLog, destination: super::Dest, creates: bool) -> ProofResult {
        use super::WriterPoint as Point;
        let points: Vec<Point> = log.iter().map(|(point, _)| *point).collect();
        let expected = if creates {
            vec![
                Point::AfterReserve,
                Point::CreationOpen,
                Point::CreationDrop,
                Point::AfterOpen,
                Point::AfterPlace,
            ]
        } else {
            vec![Point::AfterReserve, Point::AfterOpen, Point::AfterPlace]
        };
        assert_eq!(points, expected, "the admission records its witness points");
        let first = log.first().ok_or("an admission records")?.1;
        let (held_first, parked_first, unidentified_first) = first.capacities();
        // `HashMap::capacity` is `items + growth_left`, a lower bound: an
        // insert into a reused tombstone raises it by one without
        // allocating. So `held` may not fall and its free slack may not
        // rise, while the vectors, whose capacity is exact, may not move.
        let held_slack = |snapshot: super::proof::RegistrySnapshot| {
            snapshot
                .capacities()
                .0
                .checked_sub(snapshot.len_of(super::Dest::Held))
                .ok_or_else(|| format!("held capacity is below its length; witness {log:?}"))
        };
        let reserved_slack = held_slack(first)?;
        for (point, snapshot) in log {
            let (held, parked, unidentified) = snapshot.capacities();
            assert_eq!(
                (parked, unidentified),
                (parked_first, unidentified_first),
                "{point:?} changed a registry capacity; witness {log:?}"
            );
            let slack = held_slack(*snapshot)?;
            assert!(
                held >= held_first && slack <= reserved_slack,
                "{point:?} lowered the held capacity or raised its slack; witness {log:?}"
            );
        }
        let at = |wanted: Point| {
            log.iter()
                .find(|(point, _)| *point == wanted)
                .map(|(_, snapshot)| *snapshot)
                .ok_or("the point was recorded")
        };
        let reserved = at(Point::AfterReserve)?;
        let opened = at(Point::AfterOpen)?;
        let placed = at(Point::AfterPlace)?;
        assert_eq!(reserved, opened, "nothing lands before the fd is open");
        for dest in [
            super::Dest::Held,
            super::Dest::Parked,
            super::Dest::Unidentified,
        ] {
            assert_eq!(
                placed.len_of(dest),
                opened.len_of(dest) + usize::from(dest == destination),
                "{dest:?}"
            );
        }
        Ok(())
    }

    /// The free `unidentified` slots (capacity minus length) one admission
    /// recorded at `wanted`.
    fn free_unidentified(
        log: &WriterLog,
        wanted: super::WriterPoint,
    ) -> Result<usize, &'static str> {
        let (_, snapshot) = log
            .iter()
            .find(|(point, _)| *point == wanted)
            .ok_or("fixture not established: the point was not recorded")?;
        Ok(snapshot
            .capacities()
            .2
            .saturating_sub(snapshot.len_of(super::Dest::Unidentified)))
    }

    fn sqlite_immediate_is_busy(db: &std::path::Path) -> ProofResult {
        let rival = rusqlite::Connection::open(db)?;
        rival.busy_timeout(std::time::Duration::ZERO)?;
        let busy = rival.execute_batch("BEGIN IMMEDIATE");
        if !matches!(
            &busy,
            Err(rusqlite::Error::SqliteFailure(failure, _))
                if failure.code == rusqlite::ErrorCode::DatabaseBusy
        ) {
            return Err(format!("BEGIN IMMEDIATE was not busy: {busy:?}").into());
        }
        Ok(())
    }

    fn database_id(db: &std::path::Path) -> Result<super::FileId, Box<dyn std::error::Error>> {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = std::fs::symlink_metadata(db)?;
        Ok((metadata.dev(), metadata.ino()))
    }

    fn writer_entry_absent(id: super::FileId) -> bool {
        let (identity, parked) = registry_entry(id);
        identity.is_none() && parked.is_empty()
    }

    fn refusal_recorded_no_sql() -> Result<Vec<super::proof::ProofEvent>, Box<dyn std::error::Error>>
    {
        let (events, _overflow) = super::proof::take().ok_or("the sink was armed")?;
        Ok(events)
    }

    /// `rename` moves the held database onto the opened path; otherwise
    /// the opened path becomes a hard link to it.
    fn swap_keeps_the_holders_main_file_lock(rename: bool) -> ProofResult {
        let mut root = tempfile::TempDir::with_prefix(if rename {
            "rivect-writer-swap-rename-"
        } else {
            "rivect-writer-swap-link-"
        })?;
        let holder_db = root.path().join("holder.db");
        let holder = TaskStore::open(&holder_db)?;
        let id = holder.writer;
        holder
            .conn
            .as_ref()
            .ok_or("the holder has no connection")?
            .execute_batch("BEGIN IMMEDIATE")?;
        if probe_main_file_range(&mut root, &holder_db)? != "held" {
            return Err(
                "the pinned WAL holder did not hold the main-file range; Plan repair of the range, never a pass"
                    .into(),
            );
        }
        let victim = root.path().join("victim.db");
        if rename {
            super::proof::arm_after_stat_rename(holder_db.clone());
        } else {
            super::proof::arm_after_stat(holder_db.clone());
        }
        super::proof::arm();
        let refused = TaskStore::open(&victim);
        let events = refusal_recorded_no_sql()?;
        if !events.is_empty() {
            return Err(format!("the refused open ran SQL: {events:?}").into());
        }
        let error = refused.err().ok_or("the swapped open was admitted")?;
        if !matches!(
            lifecycle_of(&error),
            Some(super::ConnectionLifecycleError::WriterHeld)
        ) {
            return Err(format!("the swapped open was not WriterHeld: {error:?}").into());
        }
        if registry_entry(id).1.is_empty() {
            return Err("the identity fd was not parked under the holder".into());
        }
        if probe_main_file_range(&mut root, &victim)? != "held" {
            return Err("the main-file range was free while the holder lived".into());
        }
        // The WAL sidecar follows the name SQLite opened. A hard link of
        // the main file does not carry it, and a rename of the main file
        // leaves it behind, so the busy check uses the name the sidecar
        // actually has.
        let busy_at = if rename {
            for suffix in ["-wal", "-shm"] {
                let from = root.path().join(format!("holder.db{suffix}"));
                let to = root.path().join(format!("victim.db{suffix}"));
                if from.exists() {
                    std::fs::rename(&from, &to)?;
                }
            }
            &victim
        } else {
            &holder_db
        };
        sqlite_immediate_is_busy(busy_at)?;
        holder
            .conn
            .as_ref()
            .ok_or("the holder has no connection")?
            .execute_batch("COMMIT")?;
        drop(holder);
        if !writer_entry_absent(id) {
            return Err("the holder drop left a writer entry".into());
        }
        if probe_main_file_range(&mut root, &victim)? != "acquired" {
            return Err("the main-file range stayed held after the holder dropped".into());
        }
        Ok(())
    }

    /// Names the three mutation switches without arming them, so a throwaway
    /// run can call them and this binary still links them.
    fn proof_switches_stay_unarmed() {
        let switches: [fn(); 3] = [
            super::proof::arm_close_instead_of_park,
            super::proof::arm_release_before_close,
            super::proof::arm_creation_outside_section,
        ];
        assert_eq!(switches.len(), 3);
    }

    #[test]
    fn swap_onto_a_held_inode_parks_the_identity_fd_and_keeps_the_holders_main_file_lock()
    -> ProofResult {
        proof_switches_stay_unarmed();
        swap_keeps_the_holders_main_file_lock(false)?;
        swap_keeps_the_holders_main_file_lock(true)
    }

    #[test]
    fn drop_keeps_registry_exclusion_until_every_descriptor_closes() -> ProofResult {
        super::proof::run_isolated_release_test(
            "state::tests::drop_keeps_registry_exclusion_until_every_descriptor_closes",
            || {
                use std::sync::mpsc::sync_channel;
                let mut root = tempfile::TempDir::with_prefix("rivect-writer-drop-")?;
                let holder_db = root.path().join("holder.db");
                let holder = TaskStore::open(&holder_db)?;
                let id = holder.writer;
                // Two parked descriptors: the destruction closes the first before
                // its pause and the second after it, so a close that outlives the
                // pause is real.
                for name in ["swap-a.db", "swap-b.db"] {
                    let swap = root.path().join(name);
                    super::proof::arm_after_stat(holder_db.clone());
                    let parked = TaskStore::open(&swap);
                    let parked_error = parked.err().ok_or("the swap was admitted")?;
                    if !matches!(
                        lifecycle_of(&parked_error),
                        Some(super::ConnectionLifecycleError::WriterHeld)
                    ) {
                        return Err(format!("the swap was not WriterHeld: {parked_error:?}").into());
                    }
                    // The swap leaves a second name. Drop it so the inode's link
                    // count is 1 again; the parked descriptor stays open.
                    std::fs::remove_file(&swap)?;
                }
                if registry_entry(id).1.len() != 2 {
                    return Err("the holder does not own two parked descriptors".into());
                }

                let (receipts, inbox) = sync_channel(8);
                // One slot: the parent releases the pause exactly once. Drop
                // sends it if the proof returns early, so the holder cannot sit
                // in the pause until the deadline.
                struct Release(Option<std::sync::mpsc::SyncSender<()>>);
                impl Release {
                    fn release_holder(&mut self) -> ProofResult {
                        let sender = self.0.take().ok_or("the release was already sent")?;
                        sender.send(()).map_err(
                            |_send_error| "the holder left the pause before it was released",
                        )?;
                        Ok(())
                    }
                }
                impl Drop for Release {
                    fn drop(&mut self) {
                        if let Some(sender) = self.0.take()
                            && sender.send(()).is_err()
                        {
                            // The holder thread has already left the pause.
                        }
                    }
                }
                let holder_receipts = receipts.clone();
                let admitted_db = holder_db.clone();
                let admitted_receipts = receipts;

                std::thread::scope(|scope| {
                    // Both gates live in the scope body: an early return drops them,
                    // which frees the paused holder and the waiting admitted writer
                    // before the scope joins.
                    let (release_tx, release_rx) = sync_channel(1);
                    let (proceed_tx, proceed_rx) = sync_channel(1);
                    let mut release = Release(Some(release_tx));
                    let holder_task = scope.spawn(move || {
                        super::proof::arm_destruction_gate(holder_receipts, release_rx);
                        drop(holder);
                    });
                    expect_receipt(&inbox, "H:paused")?;
                    let admitted_task = scope.spawn(move || -> Result<(), String> {
                        super::proof::arm_before_lock(admitted_receipts.clone());
                        let store = TaskStore::open(&admitted_db).map_err(|error| {
                            format!("the waiter was not admitted after the drop: {error:?}")
                        })?;
                        if admitted_receipts.send("B:admitted".to_owned()).is_err() {
                            return Err("the parent stopped reading receipts".to_owned());
                        }
                        store
                            .conn
                            .as_ref()
                            .ok_or("the admitted store has no connection")?
                            .execute_batch("BEGIN IMMEDIATE")
                            .map_err(|error| format!("BEGIN IMMEDIATE failed: {error}"))?;
                        if admitted_receipts.send("B:immediate".to_owned()).is_err() {
                            return Err("the parent stopped reading receipts".to_owned());
                        }
                        if proceed_rx.recv_timeout(super::proof::DEADLINE).is_err() {
                            return Err(
                                "the parent did not release the admitted transaction".to_owned()
                            );
                        }
                        store
                            .conn
                            .as_ref()
                            .ok_or("the admitted store has no connection")?
                            .execute_batch("COMMIT")
                            .map_err(|error| format!("COMMIT failed: {error}"))?;
                        drop(store);
                        Ok(())
                    });
                    // B's first receipt is the result of one real nonblocking
                    // registry acquisition while H is paused. `B:contended` is the
                    // correct build: H still holds the guard, so B waits behind it.
                    // `B:acquired` means the destruction released the guard early.
                    let first_of_b = inbox
                        .recv_timeout(super::proof::DEADLINE)
                        .map_err(|error| format!("B reported no registry receipt: {error}"))?;
                    let contended = match first_of_b.as_str() {
                        "B:contended" => true,
                        "B:acquired" => false,
                        other => {
                            return Err(format!("unexpected first receipt of B: {other}").into());
                        }
                    };
                    if contended {
                        release.release_holder()?;
                    }
                    expect_receipt(&inbox, "B:admitted")?;
                    expect_receipt(&inbox, "B:immediate")?;
                    if !contended {
                        // B was admitted and holds its transaction while H is still
                        // paused. H now runs its remaining closes, and the physical
                        // main-file range below shows whether they dropped B's lock.
                        release.release_holder()?;
                    }
                    holder_task
                        .join()
                        .map_err(|_join_panic| "the holder drop panicked")?;
                    if probe_main_file_range(&mut root, &holder_db)? != "held" {
                        return Err(
                            "the main-file range was free while the admitted transaction lived"
                                .into(),
                        );
                    }
                    proceed_tx
                        .send(())
                        .map_err(|_send_error| "the admitted writer stopped waiting")?;
                    admitted_task
                        .join()
                        .map_err(|_join_panic| "the admitted writer panicked")??;
                    if probe_main_file_range(&mut root, &holder_db)? != "acquired" {
                        return Err(
                            "the main-file range stayed held after the admitted writer dropped"
                                .into(),
                        );
                    }
                    if !contended {
                        return Err(
                            "the registry was acquired while the holder was inside destruction"
                                .into(),
                        );
                    }
                    Ok(())
                })
            },
        )
    }

    #[test]
    fn writer_lock_maps_helper_errors_after_membership_exclusion() -> ProofResult {
        let root = tempfile::TempDir::with_prefix("rivect-writer-lock-map-")?;
        let cases: [(&str, fn(), bool); 2] = [
            ("unsupported", super::proof::arm_lock_unsupported, true),
            ("io", super::proof::arm_lock_io, false),
        ];
        for (label, arm, unavailable) in cases {
            let db = root.path().join(format!("{label}.db"));
            arm();
            super::proof::arm();
            let refused = TaskStore::open(&db);
            let events = refusal_recorded_no_sql()?;
            if !events.is_empty() {
                return Err(format!("{label}: the refusal ran SQL: {events:?}").into());
            }
            let error = refused
                .err()
                .ok_or_else(|| format!("{label}: the open was admitted"))?;
            let matches_error = if unavailable {
                matches!(
                    lifecycle_of(&error),
                    Some(super::ConnectionLifecycleError::WriterLockUnavailable)
                )
            } else {
                matches!(
                    lifecycle_of(&error),
                    Some(super::ConnectionLifecycleError::FileCheck { file: "lock", .. })
                )
            };
            if !matches_error {
                return Err(format!("{label}: unexpected refusal {error:?}").into());
            }
            let id = database_id(&db)?;
            if !writer_entry_absent(id) {
                return Err(format!("{label}: the refused open left a writer entry").into());
            }
            drop(TaskStore::open(&db)?);
        }
        Ok(())
    }

    #[test]
    fn failed_connect_settings_and_bootstrap_release_in_close_order() -> ProofResult {
        let mut root = tempfile::TempDir::with_prefix("rivect-writer-failed-open-")?;
        let holder_db = root.path().join("holder.db");
        let holder = TaskStore::open(&holder_db)?;
        holder
            .conn
            .as_ref()
            .ok_or("the holder has no connection")?
            .execute_batch("BEGIN IMMEDIATE")?;
        if probe_main_file_range(&mut root, &holder_db)? != "held" {
            return Err("the separate holder did not hold the main-file range".into());
        }
        let cases: [(&str, fn()); 4] = [
            ("open-flags", super::proof::arm_open_flags_fault),
            ("settle", super::proof::arm_settle_fault),
            ("settings", super::proof::arm_settings_fault),
            ("bootstrap", super::proof::arm_bootstrap_fault),
        ];
        for (label, arm) in cases {
            let db = root.path().join(format!("{label}.db"));
            arm();
            super::proof::arm();
            let refused = TaskStore::open(&db);
            let events = refusal_recorded_no_sql()?;
            let schema = events.iter().any(|event| {
                matches!(event, super::proof::ProofEvent::Stmt(sql) if sql.contains("CREATE"))
            });
            if schema {
                return Err(format!("{label}: bootstrap SQL ran on the refused open").into());
            }
            if label != "bootstrap" && !events.is_empty() {
                return Err(format!("{label}: the refusal ran SQL: {events:?}").into());
            }
            if refused.is_ok() {
                return Err(format!("{label}: the open was admitted").into());
            }
            if db.exists() {
                let id = database_id(&db)?;
                if !writer_entry_absent(id) {
                    return Err(format!("{label}: the refused open left a writer entry").into());
                }
            }
            if probe_main_file_range(&mut root, &holder_db)? != "held" {
                return Err(
                    format!("{label}: the separate holder's main-file range was released").into(),
                );
            }
        }
        drop(holder);
        Ok(())
    }

    fn assert_no_release_lines() {
        assert_eq!(
            super::take_release_lines(),
            Vec::<String>::new(),
            "no release fault is pending"
        );
    }

    /// Opens `db` once and drops it, so the file exists and its inode is
    /// known before a proof arms a seam on it.
    fn created_database(db: &std::path::Path) -> Result<super::FileId, Box<dyn std::error::Error>> {
        drop(TaskStore::open(db)?);
        database_id(db)
    }

    #[test]
    fn writer_entry_destruction_releases_while_a_duplicate_lives() -> ProofResult {
        super::proof::run_isolated_release_test(
            "state::tests::writer_entry_destruction_releases_while_a_duplicate_lives",
            || {
                assert_no_release_lines();
                let root = tempfile::TempDir::with_prefix("rivect-writer-dup-release-")?;
                let db = root.path().join("state.db");
                let id = created_database(&db)?;
                super::proof::arm_duplicate_at_place(id);
                let store = TaskStore::open(&db)?;
                let duplicate = super::proof::take_duplicate().ok_or("the identity duplicate")?;
                drop(store);
                // The duplicate keeps the destroyed entry's description, and so
                // its lock, alive: only the explicit unlock admits the next
                // writer. Closing any descriptor of the inode drops this
                // process's POSIX locks, so the new store drops first.
                let reopened = TaskStore::open(&db)?;
                drop(reopened);
                drop(duplicate);
                assert_no_release_lines();
                Ok(())
            },
        )
    }

    #[test]
    fn failed_open_releases_while_a_duplicate_lives() -> ProofResult {
        super::proof::run_isolated_release_test(
            "state::tests::failed_open_releases_while_a_duplicate_lives",
            || {
                assert_no_release_lines();
                let root = tempfile::TempDir::with_prefix("rivect-writer-dup-failed-")?;
                let db = root.path().join("state.db");
                let id = created_database(&db)?;
                super::proof::arm_duplicate_at_place(id);
                super::proof::arm_bootstrap_fault();
                if TaskStore::open(&db).is_ok() {
                    return Err("the bootstrap-faulted open was admitted".into());
                }
                let duplicate = super::proof::take_duplicate().ok_or("the identity duplicate")?;
                let reopened = TaskStore::open(&db)?;
                drop(reopened);
                drop(duplicate);
                assert_no_release_lines();
                Ok(())
            },
        )
    }

    #[test]
    fn writer_release_failure_closes_and_hands_off_once() -> ProofResult {
        super::proof::run_isolated_release_test(
            "state::tests::writer_release_failure_closes_and_hands_off_once",
            || {
                assert_no_release_lines();
                let root = tempfile::TempDir::with_prefix("rivect-writer-release-fault-")?;
                let db = root.path().join("state.db");
                let id = created_database(&db)?;
                super::proof::arm_duplicate_at_place(id);
                let store = TaskStore::open(&db)?;
                let duplicate = super::proof::take_duplicate().ok_or("the identity duplicate")?;
                super::proof::arm_unlock_faults(1);
                drop(store);
                // The unlock failed, the descriptor still closed: the duplicate
                // keeps the lock, so the next admission is the typed refusal.
                assert_open_refused_without_sql(&db)?;
                assert_eq!(
                    super::take_release_lines(),
                    ["database writer lock release failed: other error"]
                );
                assert_no_release_lines();
                drop(duplicate);
                drop(TaskStore::open(&db)?);
                assert_no_release_lines();
                Ok(())
            },
        )
    }

    #[test]
    fn release_faults_are_bounded_and_drain_once() {
        use super::ReleasedLock;
        assert_no_release_lines();
        let fail = |lock| {
            super::unlock_or_hand_off(lock, || {
                Err(std::io::Error::from(std::io::ErrorKind::Other))
            });
        };
        fail(ReleasedLock::Writer);
        fail(ReleasedLock::Owner);
        fail(ReleasedLock::Writer);
        assert_eq!(
            super::take_release_lines(),
            [
                "database writer lock release failed: other error",
                "owner lock release failed: other error",
                "further lock release failures: 1",
            ],
            "three hand-offs keep the first two in order and count the third"
        );
        assert_no_release_lines();
        // The two retained plus 65 536 counted: one past `u16::MAX`.
        fail(ReleasedLock::Writer);
        fail(ReleasedLock::Owner);
        for _ in 0..65_536 {
            fail(ReleasedLock::Writer);
        }
        assert_eq!(
            super::take_release_lines(),
            [
                "database writer lock release failed: other error",
                "owner lock release failed: other error",
                "further lock release failures: 65535",
            ],
            "the count saturates instead of wrapping"
        );
        assert_no_release_lines();
    }

    #[test]
    fn reopen_rechecks_database_identity_and_link_count() -> ProofResult {
        let root = tempfile::TempDir::with_prefix("rivect-writer-reopen-link-")?;
        let db = root.path().join("state.db");
        let mut store = TaskStore::open(&db)?;
        let id = store.writer;
        let alias = root.path().join("alias.db");
        std::fs::hard_link(&db, &alias)?;
        let refused = store.reopen(&db);
        let error = refused.err().ok_or("a hard-linked database was reopened")?;
        if !matches!(
            lifecycle_of(&error),
            Some(super::ConnectionLifecycleError::DatabaseAliased)
        ) {
            return Err(format!("the extra link was not DatabaseAliased: {error:?}").into());
        }
        if writer_entry_absent(id) {
            return Err("the aliased reopen dropped the writer entry".into());
        }
        assert_open_refused_without_sql(&alias)?;
        std::fs::remove_file(&alias)?;
        store.reopen(&db)?;
        if store.writer != id {
            return Err("a same-inode reopen replaced the writer entry".into());
        }
        drop(store);

        let root = tempfile::TempDir::with_prefix("rivect-writer-reopen-id-")?;
        let db = root.path().join("state.db");
        let mut store = TaskStore::open(&db)?;
        let id = store.writer;
        let other = root.path().join("other.db");
        drop(TaskStore::open(&other)?);
        let old_name = root.path().join("old-name.db");
        std::fs::hard_link(&db, &old_name)?;
        super::proof::arm_after_own_admit(other);
        let refused = store.reopen(&db);
        let error = refused.err().ok_or("a replaced inode was reopened")?;
        if !matches!(
            lifecycle_of(&error),
            Some(super::ConnectionLifecycleError::DatabaseMoved)
        ) {
            return Err(format!("the replaced inode was not DatabaseMoved: {error:?}").into());
        }
        if writer_entry_absent(id) {
            return Err("the identity refusal dropped the old writer entry".into());
        }
        assert_open_refused_without_sql(&old_name)?;
        drop(store);
        if !writer_entry_absent(id) {
            return Err("dropping the store left the old writer entry".into());
        }
        drop(TaskStore::open(&db)?);
        Ok(())
    }

    #[test]
    fn writer_admission_never_allocates_after_open() -> ProofResult {
        use super::proof;
        let root = tempfile::TempDir::with_prefix("rivect-writer-alloc-")?;
        let holder_db = root.path().join("holder.db");
        let holder = TaskStore::open(&holder_db)?;

        // The normal insert on an absent path (creation window), then
        // on the now-existing database.
        let fresh = root.path().join("fresh.db");
        for creates in [true, false] {
            proof::shrink_registry();
            proof::arm_writer_log();
            let store = TaskStore::open(&fresh)?;
            writer_witness(&proof::take_writer_log(), super::Dest::Held, creates)?;
            drop(store);
        }

        // fstat failure: the fd moves into `unidentified`.
        let faulty = root.path().join("faulty.db");
        proof::shrink_registry();
        // The shrink leaves the next `try_reserve(1)` its own growth, so
        // `unidentified` is first filled through the real entry: genuine
        // fstat-faulted admissions of a separate database push their own
        // identity fds until exactly one slot is free.
        let fill = root.path().join("fill.db");
        let mut one_free = false;
        for _ in 0..super::STORE_PARKED_MAX {
            proof::arm_writer_log();
            proof::arm_fstat_fault();
            let refused = TaskStore::open(&fill);
            let log = proof::take_writer_log();
            if !matches!(
                refused.as_ref().err().and_then(lifecycle_of),
                Some(super::ConnectionLifecycleError::FileCheck { file: "db", .. })
            ) {
                return Err("fixture not established: fill was not an fstat refusal".into());
            }
            if free_unidentified(&log, super::WriterPoint::AfterPlace)? == 1 {
                one_free = true;
                break;
            }
        }
        if !one_free {
            return Err("fixture not established: the fill bound was reached".into());
        }
        proof::arm_writer_log();
        proof::arm_fstat_fault();
        let refused = TaskStore::open(&faulty);
        let log = proof::take_writer_log();
        assert!(
            matches!(
                refused.as_ref().err().and_then(lifecycle_of),
                Some(super::ConnectionLifecycleError::FileCheck { file: "db", .. })
            ),
            "fstat failure is a typed file check"
        );
        let free = free_unidentified(&log, super::WriterPoint::AfterReserve)?;
        if free != 1 {
            return Err(format!(
                "fixture not established: {free} free slots at the witnessed reservation"
            )
            .into());
        }
        writer_witness(&log, super::Dest::Unidentified, true)?;

        // The path becomes a name of a held inode after the stat: the
        // fd parks under its holder.
        let swap = root.path().join("swap.db");
        proof::shrink_registry();
        proof::arm_writer_log();
        proof::arm_after_stat(holder_db);
        let refused = TaskStore::open(&swap);
        let log = proof::take_writer_log();
        assert!(
            matches!(
                refused.as_ref().err().and_then(lifecycle_of),
                Some(super::ConnectionLifecycleError::WriterHeld)
            ),
            "a held inode refuses"
        );
        writer_witness(&log, super::Dest::Parked, true)?;
        drop(holder);
        Ok(())
    }

    type ProofResult = Result<(), Box<dyn std::error::Error>>;

    /// Every non-authoritative denial row of one database, decoded, in
    /// boundary order, read through a separate connection.
    fn denial_rows(
        db: &std::path::Path,
    ) -> Result<Vec<(String, serde_json::Value)>, Box<dyn std::error::Error>> {
        let conn = rusqlite::Connection::open(db)?;
        let mut statement = conn.prepare(
            "SELECT boundary_id, record_json FROM retained
             WHERE boundary_id LIKE ?1 ORDER BY boundary_id",
        )?;
        let raw = statement
            .query_map(["ret:check-rejection:%"], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        raw.into_iter()
            .map(|(boundary, json)| Ok((boundary, serde_json::from_str(&json)?)))
            .collect()
    }

    fn timeout_of(store: &TaskStore) -> Result<i64, Box<dyn std::error::Error>> {
        Ok(store
            .conn()?
            .query_row(super::sql::BUSY_TIMEOUT_READ, [], |row| row.get(0))?)
    }

    #[test]
    fn a_held_writer_refuses_the_preclaim_rejection_at_zero_wait_while_a_generic_write_waits()
    -> ProofResult {
        let (root, mut store, _session, _task, _attempt, _claim) =
            claim_fixture("rejection-zero-wait");
        let db = root.path().join("state.db");
        store
            .conn_mut()?
            .busy_timeout(std::time::Duration::from_millis(1500))?;
        let holder = rusqlite::Connection::open(&db)?;
        holder.execute_batch("BEGIN IMMEDIATE")?;
        // The scoped refusal: the single denial write runs at ZERO wait,
        // so a held writer refuses immediately — far inside the 1500 ms
        // the connection would otherwise wait — and the actual prior
        // value is restored afterwards.
        let started = std::time::Instant::now();
        let outcome = store.retain_preclaim_rejection("admit.exec", "binding-digest");
        let scoped = started.elapsed();
        assert!(
            matches!(outcome, super::RetentionOutcome::Unavailable),
            "a held writer leaves the denial unavailable"
        );
        assert!(
            scoped < std::time::Duration::from_millis(700),
            "the scoped write waits zero, not the connection timeout: {scoped:?}"
        );
        assert_eq!(timeout_of(&store)?, 1500, "the actual prior is restored");
        // The generic control under the SAME held lock waits its full
        // timeout: the zero wait above is the scoped guard's doing.
        store
            .conn_mut()?
            .busy_timeout(std::time::Duration::from_millis(400))?;
        let started = std::time::Instant::now();
        let generic = store.record_preapproval("control-scope", "tester", 60);
        let waited = started.elapsed();
        assert!(generic.is_err(), "a generic write under a held lock fails");
        assert!(
            waited >= std::time::Duration::from_millis(300),
            "a generic write waits its timeout: {waited:?}"
        );
        // Released: the very same call now retains its single row.
        holder.execute_batch("ROLLBACK")?;
        assert!(matches!(
            store.retain_preclaim_rejection("admit.exec", "binding-digest"),
            super::RetentionOutcome::Retained
        ));
        assert_eq!(denial_rows(&db)?.len(), 1);
        drop(holder);
        drop(store);

        Ok(())
    }

    #[test]
    fn a_failed_rejection_restore_quarantines_the_handle_after_one_bounded_write() -> ProofResult {
        let (root, mut store, _session, _task, attempt, _claim) =
            claim_fixture("rejection-restore-fail");
        let db = root.path().join("state.db");
        store
            .conn_mut()?
            .busy_timeout(std::time::Duration::from_millis(1234))?;
        super::proof::arm_fault(super::proof::Site::RejectionRestore);
        let outcome = store.retain_preclaim_rejection("admit.exec", "binding-digest");
        assert!(
            matches!(outcome, super::RetentionOutcome::Retained),
            "the one bounded write landed independent of the restoration"
        );
        assert!(store.is_quarantined(), "the failed restoration quarantines");
        assert!(
            matches!(
                store.attempt_state(&attempt),
                Err(super::StoreError::Closed)
            ),
            "every later store call is typed-closed"
        );
        assert_eq!(
            denial_rows(&db)?.len(),
            1,
            "no retry wrote a second denial row"
        );
        store.reopen(&db)?;
        assert!(!store.is_quarantined(), "a reopen yields a live handle");
        assert_eq!(store.attempt_state(&attempt)?.as_deref(), Some("planned"));
        drop(store);

        Ok(())
    }

    #[test]
    fn both_rejection_producers_draw_distinct_uuid_identities_per_invocation() -> ProofResult {
        let (root, mut store, _session, _task, _attempt, claim) =
            claim_fixture("rejection-namespace");
        let db = root.path().join("state.db");
        // Producer one: the claim's own denial row.
        super::proof::arm_fault(super::proof::Site::Read);
        let refused = refusal(store.claim_check(
            &claim,
            &std::sync::atomic::AtomicBool::new(false),
            claim_deadline(),
        ));
        assert!(matches!(
            refused.retention,
            super::RetentionOutcome::Retained
        ));
        // Producer two: the executor-side pre-claim row, eight
        // invocations with the SAME site and binding digest — a
        // process-local sequence or a content key would repeat or
        // collapse them.
        for _ in 0..8 {
            assert!(matches!(
                store.retain_preclaim_rejection("admit.exec", "same-binding"),
                super::RetentionOutcome::Retained
            ));
        }
        let rows = denial_rows(&db)?;
        assert_eq!(rows.len(), 9, "nine invocations wrote nine rows: {rows:?}");
        let mut identities = Vec::new();
        for (boundary, _) in &rows {
            let identity = boundary
                .strip_prefix("ret:check-rejection:")
                .and_then(|rest| rest.split_once(':'))
                .map(|(identity, _site)| identity.to_string())
                .ok_or("the boundary names an identity and a site")?;
            uuid::Uuid::parse_str(&identity)?;
            identities.push(identity);
        }
        identities.sort_unstable();
        identities.dedup();
        assert_eq!(identities.len(), 9, "every invocation owns its own UUID");
        let claim_rows = rows
            .iter()
            .filter(|(_, record)| record["cause"] == "claim refused")
            .count();
        let preclaim_rows = rows
            .iter()
            .filter(|(_, record)| record["cause"] == "pre-claim refusal")
            .count();
        assert_eq!(
            (claim_rows, preclaim_rows),
            (1, 8),
            "the producers stay apart"
        );
        drop(store);

        Ok(())
    }

    #[test]
    fn every_claim_statement_refuses_with_its_own_decoded_row_native_and_custom_off_then_restarts()
    -> ProofResult {
        use super::ClaimSite as Site;
        use super::proof::Site as Fault;
        // (native, injected fault, expected site, whether a denial row
        // is writable at that position: pre-BEGIN sites have none).
        let legs = [
            (true, Fault::WaitRead, Site::WaitRead, false),
            (true, Fault::WaitSet, Site::WaitSet, false),
            (true, Fault::Begin, Site::Begin, true),
            (true, Fault::Read, Site::Read, true),
            (true, Fault::TerminalRead, Site::TerminalRead, true),
            (true, Fault::SelectionRead, Site::SelectionRead, true),
            (true, Fault::GateRead, Site::GateRead, true),
            (true, Fault::Update, Site::Update, true),
            (true, Fault::Marker, Site::Marker, true),
            (false, Fault::WaitRead, Site::WaitRead, false),
            (false, Fault::WaitSet, Site::WaitSet, false),
            (false, Fault::Begin, Site::Begin, true),
            (false, Fault::Read, Site::Read, true),
            (false, Fault::TerminalRead, Site::TerminalRead, true),
            (false, Fault::Update, Site::Update, true),
            (false, Fault::Marker, Site::Marker, true),
        ];
        let mut native_payloads = Vec::new();
        for (native, fault, site, writes_row) in legs {
            let (root, mut store, _session, _task, attempt, claim) = claim_fixture("claim-matrix");
            let claim = if native {
                claim
            } else {
                super::CheckClaim {
                    native: false,
                    selection_revision: 0,
                    facts_digest: String::new(),
                    ..claim
                }
            };
            let db = root.path().join("state.db");
            let label = format!("native={native} {fault:?}");
            super::proof::arm_fault(fault);
            let refused = refusal(store.claim_check(
                &claim,
                &std::sync::atomic::AtomicBool::new(false),
                claim_deadline(),
            ));
            assert_eq!(refused.site, site, "{label}");
            assert_eq!(
                matches!(refused.retention, super::RetentionOutcome::Retained),
                writes_row,
                "{label}"
            );
            assert!(!refused.restore_failed, "{label}");
            assert_eq!(store.attempt_state(&attempt)?.as_deref(), Some("planned"));
            assert!(!store.has_retained(&marker_boundary(&attempt))?, "{label}");
            let rows = denial_rows(&db)?;
            if writes_row {
                assert_eq!(rows.len(), 1, "{label}: {rows:?}");
                let (boundary, record) = &rows[0];
                assert!(
                    boundary.ends_with(&format!(":{}", site.suffix())),
                    "{label}"
                );
                assert_eq!(record["site"], site.suffix(), "{label}");
                assert_eq!(record["cause"], "claim refused", "{label}");
                assert_eq!(record["binding"], claim.binding_digest, "{label}");
                assert_eq!(
                    record.as_object().map(serde_json::Map::len),
                    Some(3),
                    "{label}: an injected fault carries no engine primary: {record}"
                );
                if native {
                    native_payloads.push((site.suffix(), record.to_string()));
                }
            } else {
                assert!(rows.is_empty(), "{label}: a pre-BEGIN site writes no row");
            }
            // Restart: a fresh store over the same file claims the very
            // same attempt (the fault was consumed), and the denial row
            // is neither lost nor duplicated.
            drop(store);
            let mut reopened = TaskStore::open(&db)?;
            assert!(
                matches!(
                    reopened.claim_check(
                        &claim,
                        &std::sync::atomic::AtomicBool::new(false),
                        claim_deadline()
                    )?,
                    super::ClaimOutcome::Claimed
                ),
                "{label}: the restarted store claims"
            );
            assert_eq!(denial_rows(&db)?.len(), usize::from(writes_row), "{label}");
            drop(reopened);
        }
        // 6a and 6b stay independent payloads: the binding read and the
        // terminal read never alias their site or their body.
        let read = native_payloads
            .iter()
            .find(|(suffix, _)| *suffix == "admit.claim_read")
            .ok_or("the 6a payload")?;
        let terminal = native_payloads
            .iter()
            .find(|(suffix, _)| *suffix == "admit.claim_terminal_read")
            .ok_or("the 6b payload")?;
        assert_ne!(read, terminal);
        assert_ne!(read.1, terminal.1);
        // The Custom-off flag, not field values, skips the two Native
        // statements: faults armed at them never fire for a Custom claim.
        let (_root, mut store, _session, _task, attempt, claim) = claim_fixture("custom-skip");
        let custom = super::CheckClaim {
            native: false,
            selection_revision: 0,
            facts_digest: String::new(),
            ..claim
        };
        super::proof::arm_fault(Fault::SelectionRead);
        super::proof::arm_fault(Fault::GateRead);
        assert!(matches!(
            store.claim_check(
                &custom,
                &std::sync::atomic::AtomicBool::new(false),
                claim_deadline()
            )?,
            super::ClaimOutcome::Claimed
        ));
        assert!(store.has_retained(&marker_boundary(&attempt))?);
        drop(store);

        Ok(())
    }

    #[test]
    fn the_commit_cause_carries_the_actual_engine_primary_never_the_injected_marker() -> ProofResult
    {
        // A real engine COMMIT failure: a deferred foreign-key
        // violation fails at COMMIT with SQLITE_CONSTRAINT (extended
        // 787, primary 19).
        let conn = rusqlite::Connection::open_in_memory()?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE parent (id INTEGER PRIMARY KEY);
             CREATE TABLE child (
                 parent_id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED
             );
             BEGIN;
             INSERT INTO child (parent_id) VALUES (42);",
        )?;
        let error = conn
            .execute_batch("COMMIT")
            .err()
            .ok_or("a deferred violation must fail the COMMIT")?;
        assert_eq!(super::sqlite_primary_numeric(&error), Some(19));
        assert_eq!(super::sqlite_primary_code(&error), "19");
        // An error without an engine code is the fixed `unknown`
        // marker; an extended code collapses to its primary
        // (SQLITE_IOERR_FSYNC 1034 -> SQLITE_IOERR 10).
        assert_eq!(
            super::sqlite_primary_code(&rusqlite::Error::QueryReturnedNoRows),
            "unknown"
        );
        let fsync = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1034), None);
        assert_eq!(super::sqlite_primary_code(&fsync), "10");
        // The ambiguous COMMIT record built from the real engine code
        // differs from the injected marker only in that field, and the
        // boundary — the key — is shared.
        let (_root, store, _session, _task, _attempt, claim) = claim_fixture("commit-primary");
        let real =
            TaskStore::commit_ambiguous_record(&claim, &super::sqlite_primary_code(&error), true);
        let injected = TaskStore::commit_ambiguous_record(&claim, "injected", true);
        assert!(real.cause.ends_with("primary=19"), "{}", real.cause);
        assert!(
            injected.cause.ends_with("primary=injected"),
            "{}",
            injected.cause
        );
        assert_eq!(real.boundary_id, injected.boundary_id);
        assert_ne!(real.digest, injected.digest);
        drop(store);

        Ok(())
    }
}

/// Production proof seam (DEC-048): statement-position witnesses and
/// the site-local fault hook, compiled to no-ops outside tests. The
/// unarmed build is production-equivalent; an armed fault is the one
/// explicit typed site-local deviation inside inline legs.
#[cfg(not(test))]
mod proof {
    pub(super) enum Site {
        WaitRead,
        WaitSet,
        Cancel,
        Deadline,
        Busy,
        Begin,
        Read,
        TerminalRead,
        SelectionRead,
        GateRead,
        Update,
        Marker,
        WaitRestore,
        CommitBeforeExec,
        CommitAfterDurable,
        RollbackAfterCommitError,
        SameConnectionWrite,
        Close,
        Open,
        CarriedWrite,
        CloseOptimize,
        CloseCheckpoint,
        CloseExplicit,
        PublicationReceipt,
        RejectionRestore,
    }
    #[expect(
        clippy::unnecessary_wraps,
        reason = "the test twin returns the armed typed fault; both builds share one call shape"
    )]
    pub(super) fn fault(_: Site) -> rusqlite::Result<()> {
        Ok(())
    }
    pub(super) fn install(_: &rusqlite::Connection) {}
    pub(super) fn after_guard(_: &std::path::Path) {}
    pub(super) fn built(_: &super::RetainedAttempt) {}
    pub(super) fn carry(_: &super::RetainedAttempt) {}
    pub(super) fn used(_: &super::RetainedAttempt) {}
    pub(super) fn insert(_: &str) {}
    pub(super) fn writer_point(_: super::WriterPoint, _: &super::Registry) {}
    pub(super) fn reserve_fault(_: super::Dest) -> bool {
        false
    }
    pub(super) fn after_stat(_: &std::path::Path) {}
    pub(super) fn fstat_fault() -> bool {
        false
    }
    pub(super) fn creation_fd_opened() {}
    pub(super) fn identity_fd_opened() {}
    pub(super) fn lock_fault() -> Option<rivect_sandbox_helper::OfdLockError> {
        None
    }
    pub(super) fn unlock_fault() -> Option<std::io::Error> {
        None
    }
    pub(super) fn close_instead_of_park() -> bool {
        false
    }
    pub(super) fn release_before_close() -> bool {
        false
    }
    pub(super) fn creation_outside_section() -> bool {
        false
    }
    pub(super) fn entry_destruction() {}
    pub(super) fn before_registry_lock() {}
    pub(super) fn open_flags_fault() -> bool {
        false
    }
    pub(super) fn settle_fault() -> bool {
        false
    }
    pub(super) fn settings_fault() -> bool {
        false
    }
    pub(super) fn bootstrap_fault() -> bool {
        false
    }
    pub(super) fn after_own_admit(_: &std::path::Path) {}
}

/// The test twin of the proof seam: a bounded thread-local event sink
/// (armed and disarmed around one call), the identity witness, the
/// once-per-site fault injection, and the after-guard swap hook. It
/// runs no SQL of its own and takes no `&mut`.
#[cfg(test)]
pub mod proof {
    use super::RetainedAttempt;
    use super::{Dest, Registry, WRITERS, WriterPoint};
    use rusqlite::trace::{TraceEvent, TraceEventCodes};
    use std::cell::{Cell, RefCell};
    use std::os::fd::OwnedFd;
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::{Receiver, SyncSender};

    /// Upper bound on recorded events; a longer stream sets the
    /// overflow flag instead of growing.
    pub(crate) const SINK_CAP: usize = 256;

    /// Heap-buffer addresses of one record's `attempt_id`,
    /// `boundary_id` and `digest`: a clone or rebuild living beside the
    /// original gets other addresses; a move keeps them.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct CheckIdent {
        pub(crate) attempt: usize,
        pub(crate) boundary: usize,
        pub(crate) digest: usize,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum ProofEvent {
        /// Unexpanded statement text of one traced SQL statement.
        Stmt(String),
        Built {
            ident: CheckIdent,
            json: String,
        },
        Carry {
            ident: CheckIdent,
        },
        Used {
            ident: CheckIdent,
        },
        Insert {
            json: String,
        },
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Site {
        WaitRead,
        WaitSet,
        Cancel,
        Deadline,
        Busy,
        Begin,
        Read,
        TerminalRead,
        SelectionRead,
        GateRead,
        Update,
        Marker,
        WaitRestore,
        CommitBeforeExec,
        CommitAfterDurable,
        RollbackAfterCommitError,
        SameConnectionWrite,
        Close,
        Open,
        CarriedWrite,
        CloseOptimize,
        CloseCheckpoint,
        CloseExplicit,
        PublicationReceipt,
        RejectionRestore,
    }

    struct Sink {
        events: Vec<ProofEvent>,
        overflow: bool,
    }

    thread_local! {
        static SINK: RefCell<Option<Sink>> = const { RefCell::new(None) };
        static FAULTS: RefCell<Vec<Site>> = const { RefCell::new(Vec::new()) };
        static AFTER_GUARD: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    }

    fn record(push: impl FnOnce(&mut Sink)) {
        SINK.with(|sink| {
            if let Some(sink) = sink.borrow_mut().as_mut() {
                if sink.events.len() < SINK_CAP {
                    push(sink);
                } else {
                    sink.overflow = true;
                }
            }
        });
    }

    fn ident_of(payload: &RetainedAttempt) -> CheckIdent {
        CheckIdent {
            attempt: payload.attempt_id.as_ptr() as usize,
            boundary: payload.boundary_id.as_ptr() as usize,
            digest: payload.digest.as_ptr() as usize,
        }
    }

    fn trace_stmt(event: TraceEvent<'_>) {
        if let TraceEvent::Stmt(_, sql) = event {
            let sql = sql.to_string();
            record(|sink| sink.events.push(ProofEvent::Stmt(sql)));
        }
    }

    pub(crate) fn arm() {
        SINK.with(|sink| {
            *sink.borrow_mut() = Some(Sink {
                events: Vec::new(),
                overflow: false,
            });
        });
    }

    /// Disarms and returns the recorded events with the overflow flag.
    pub(crate) fn take() -> Option<(Vec<ProofEvent>, bool)> {
        SINK.with(|sink| {
            sink.borrow_mut()
                .take()
                .map(|sink| (sink.events, sink.overflow))
        })
    }

    pub(crate) fn arm_fault(site: Site) {
        FAULTS.with(|faults| faults.borrow_mut().push(site));
    }

    pub(crate) fn fault(site: Site) -> rusqlite::Result<()> {
        let fired = FAULTS.with(|faults| {
            let mut faults = faults.borrow_mut();
            faults
                .iter()
                .position(|armed| *armed == site)
                .map(|position| faults.remove(position))
        });
        match fired {
            Some(_) => Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
                Some(format!("injected {site:?}")),
            )),
            None => Ok(()),
        }
    }

    pub(crate) fn install(conn: &rusqlite::Connection) {
        let armed = SINK.with(|sink| sink.borrow().is_some());
        if armed {
            conn.trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(trace_stmt));
        }
    }

    /// Arms the after-guard swap: the next guarded open finds `<db>`
    /// replaced by a symlink to this sentinel between (1a) and (1b).
    pub(crate) fn arm_after_guard(sentinel: PathBuf) {
        AFTER_GUARD.with(|hook| *hook.borrow_mut() = Some(sentinel));
    }

    pub(crate) fn after_guard(db: &Path) {
        let swap = AFTER_GUARD.with(|hook| hook.borrow_mut().take());
        if let Some(sentinel) = swap {
            #[cfg(unix)]
            {
                drop(std::fs::remove_file(db));
                drop(std::os::unix::fs::symlink(&sentinel, db));
            }
            #[cfg(not(unix))]
            {
                let _ = sentinel;
                let _ = db;
            }
        }
    }

    pub(crate) fn built(payload: &RetainedAttempt) {
        let ident = ident_of(payload);
        let json =
            serde_json::to_string(payload).unwrap_or_else(|_| "unserializable record".to_string());
        record(|sink| sink.events.push(ProofEvent::Built { ident, json }));
    }

    pub(crate) fn carry(payload: &RetainedAttempt) {
        let ident = ident_of(payload);
        record(|sink| sink.events.push(ProofEvent::Carry { ident }));
    }

    pub(crate) fn used(payload: &RetainedAttempt) {
        let ident = ident_of(payload);
        record(|sink| sink.events.push(ProofEvent::Used { ident }));
    }

    pub(crate) fn insert(record_json: &str) {
        let json = record_json.to_string();
        record(|sink| sink.events.push(ProofEvent::Insert { json }));
    }

    /// `(len, capacity)` of the three registry destinations at one
    /// admission point.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct RegistrySnapshot {
        held: (usize, usize),
        parked: (usize, usize),
        unidentified: (usize, usize),
    }

    impl RegistrySnapshot {
        pub(crate) fn len_of(&self, dest: Dest) -> usize {
            match dest {
                Dest::Held => self.held.0,
                Dest::Parked => self.parked.0,
                Dest::Unidentified => self.unidentified.0,
            }
        }

        pub(crate) fn capacities(&self) -> (usize, usize, usize) {
            (self.held.1, self.parked.1, self.unidentified.1)
        }
    }

    thread_local! {
        static WRITER_LOG: RefCell<Option<Vec<(WriterPoint, RegistrySnapshot)>>> =
            const { RefCell::new(None) };
        static RESERVE_FAULT: Cell<Option<Dest>> = const { Cell::new(None) };
        static AFTER_STAT: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
        static AFTER_STAT_RENAME: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
        static OWN_ADMIT_SWAP: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
        static FSTAT_FAULT: Cell<bool> = const { Cell::new(false) };
        static INJECTED: Cell<Option<InjectedFault>> = const { Cell::new(None) };
        static CLOSE_INSTEAD: Cell<bool> = const { Cell::new(false) };
        static RELEASE_BEFORE_CLOSE: Cell<bool> = const { Cell::new(false) };
        static CREATION_OUTSIDE: Cell<bool> = const { Cell::new(false) };
        static DESTRUCTION_GATE: RefCell<Option<PauseGate>> = const { RefCell::new(None) };
        static BEFORE_LOCK: RefCell<Option<SyncSender<String>>> = const { RefCell::new(None) };
    }

    pub(super) fn writer_point(point: WriterPoint, registry: &Registry) {
        if point == WriterPoint::AfterPlace {
            capture_duplicate(registry);
        }
        WRITER_LOG.with(|log| {
            if let Some(log) = log.borrow_mut().as_mut() {
                log.push((
                    point,
                    RegistrySnapshot {
                        held: (registry.held.len(), registry.held.capacity()),
                        parked: (registry.parked.len(), registry.parked.capacity()),
                        unidentified: (
                            registry.unidentified.len(),
                            registry.unidentified.capacity(),
                        ),
                    },
                ));
            }
        });
        probe_point(point);
    }

    pub(crate) fn arm_writer_log() {
        WRITER_LOG.with(|log| *log.borrow_mut() = Some(Vec::new()));
    }

    pub(crate) fn take_writer_log() -> Vec<(WriterPoint, RegistrySnapshot)> {
        WRITER_LOG.with(|log| log.borrow_mut().take().unwrap_or_default())
    }

    /// The one outer deadline of the two-opener proof: a hold, a receipt
    /// wait or a join that outlasts it fails the proof as a hang.
    pub(crate) const DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

    /// The writer points one thread reports as receipts, and the one
    /// point it holds at until released. Only a proof that arms it on
    /// its own thread ever waits: every other admission, and the
    /// production stub, never do.
    #[derive(Debug)]
    pub(crate) struct WriterProbe {
        pub(crate) receipts: SyncSender<String>,
        pub(crate) points: &'static [(WriterPoint, &'static str)],
        pub(crate) pause: Option<(WriterPoint, Receiver<()>)>,
    }

    thread_local! {
        static PROBE: RefCell<Option<WriterProbe>> = const { RefCell::new(None) };
    }

    pub(crate) fn arm_probe(probe: WriterProbe) {
        PROBE.with(|slot| *slot.borrow_mut() = Some(probe));
    }

    /// Reports `point` as a receipt and, at the paused point, holds the
    /// caller (and so the registry guard it passed in) until released.
    fn probe_point(point: WriterPoint) {
        PROBE.with(|slot| {
            let slot = slot.borrow();
            let Some(probe) = slot.as_ref() else {
                return;
            };
            let Some((_, receipt)) = probe.points.iter().find(|(at, _)| *at == point) else {
                return;
            };
            if probe.receipts.send((*receipt).to_owned()).is_err() {
                return;
            }
            if let Some((at, release)) = &probe.pause
                && *at == point
                && release.recv_timeout(DEADLINE).is_err()
            {
                // Unreleased: the proof's own deadline reports the hang, and
                // this receipt breaks its order check if it is the one to read.
                drop(probe.receipts.send("pause:abandoned".to_owned()));
            }
        });
    }

    /// Shrinks the three registry vectors under the guard with no
    /// admission in progress, so a push beyond the reserved slot must
    /// reallocate. It never clears, resets or replaces an entry or the
    /// poison flag.
    pub(crate) fn shrink_registry() {
        let mut registry = WRITERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.held.shrink_to_fit();
        registry.parked.shrink_to_fit();
        registry.unidentified.shrink_to_fit();
    }

    /// Arms one reservation failure at the next admission's `dest`.
    pub(crate) fn arm_reserve_fault(dest: Dest) {
        RESERVE_FAULT.with(|fault| fault.set(Some(dest)));
    }

    pub(super) fn reserve_fault(dest: Dest) -> bool {
        RESERVE_FAULT.with(|fault| {
            let fired = fault.get() == Some(dest);
            if fired {
                fault.set(None);
            }
            fired
        })
    }

    /// Arms the swap between the path stat and the identity open: the
    /// next admitted `<db>` is replaced by a hard link to `target`.
    pub(crate) fn arm_after_stat(target: PathBuf) {
        AFTER_STAT.with(|hook| *hook.borrow_mut() = Some(target));
    }

    pub(super) fn after_stat(db: &Path) {
        let rename = AFTER_STAT_RENAME.with(|hook| hook.borrow_mut().take());
        if let Some(target) = rename {
            // Same best-effort shape as the hard-link swap below: the
            // caller's identity check reports a swap that did not land.
            drop(std::fs::remove_file(db));
            drop(std::fs::rename(&target, db));
            return;
        }
        let target = AFTER_STAT.with(|hook| hook.borrow_mut().take());
        if let Some(target) = target {
            drop(std::fs::remove_file(db));
            drop(std::fs::hard_link(&target, db));
        }
    }

    /// Arms the same window as [`arm_after_stat`], replacing `<db>` by
    /// renaming `target` onto it instead of hard-linking.
    pub(crate) fn arm_after_stat_rename(target: PathBuf) {
        AFTER_STAT_RENAME.with(|hook| *hook.borrow_mut() = Some(target));
    }

    pub(crate) fn arm_after_own_admit(other: PathBuf) {
        OWN_ADMIT_SWAP.with(|hook| *hook.borrow_mut() = Some(other));
    }

    /// Replaces `<db>` with `other` after a same-inode reopen has been
    /// recognized, so the settle recheck observes the new inode.
    pub(super) fn after_own_admit(db: &Path) {
        let other = OWN_ADMIT_SWAP.with(|hook| hook.borrow_mut().take());
        if let Some(other) = other {
            drop(std::fs::remove_file(db));
            drop(std::fs::rename(&other, db));
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum InjectedFault {
        OpenFlags,
        Settle,
        Settings,
        Bootstrap,
        LockUnsupported,
        LockIo,
    }

    fn take_fault(want: InjectedFault) -> bool {
        INJECTED.with(|cell| {
            if cell.get() == Some(want) {
                cell.set(None);
                true
            } else {
                false
            }
        })
    }

    pub(super) fn lock_fault() -> Option<rivect_sandbox_helper::OfdLockError> {
        use rivect_sandbox_helper::OfdLockError;
        INJECTED.with(|cell| match cell.get() {
            Some(InjectedFault::LockUnsupported) => {
                cell.set(None);
                Some(OfdLockError::Unsupported)
            }
            Some(InjectedFault::LockIo) => {
                cell.set(None);
                Some(OfdLockError::Io(std::io::Error::other(
                    "injected lock fault",
                )))
            }
            _ => None,
        })
    }

    pub(crate) fn arm_lock_unsupported() {
        INJECTED.with(|cell| cell.set(Some(InjectedFault::LockUnsupported)));
    }

    pub(crate) fn arm_lock_io() {
        INJECTED.with(|cell| cell.set(Some(InjectedFault::LockIo)));
    }

    pub(super) fn open_flags_fault() -> bool {
        take_fault(InjectedFault::OpenFlags)
    }

    pub(crate) fn arm_open_flags_fault() {
        INJECTED.with(|cell| cell.set(Some(InjectedFault::OpenFlags)));
    }

    pub(super) fn settle_fault() -> bool {
        take_fault(InjectedFault::Settle)
    }

    pub(crate) fn arm_settle_fault() {
        INJECTED.with(|cell| cell.set(Some(InjectedFault::Settle)));
    }

    pub(super) fn settings_fault() -> bool {
        take_fault(InjectedFault::Settings)
    }

    pub(crate) fn arm_settings_fault() {
        INJECTED.with(|cell| cell.set(Some(InjectedFault::Settings)));
    }

    pub(super) fn bootstrap_fault() -> bool {
        take_fault(InjectedFault::Bootstrap)
    }

    pub(crate) fn arm_bootstrap_fault() {
        INJECTED.with(|cell| cell.set(Some(InjectedFault::Bootstrap)));
    }

    pub(super) fn close_instead_of_park() -> bool {
        CLOSE_INSTEAD.with(Cell::get)
    }

    /// Sticky on this thread: a mutation run arms it for the whole open.
    pub(crate) fn arm_close_instead_of_park() {
        CLOSE_INSTEAD.with(|cell| cell.set(true));
    }

    pub(super) fn release_before_close() -> bool {
        RELEASE_BEFORE_CLOSE.with(Cell::get)
    }

    /// Sticky on this thread: a mutation run arms it for the whole drop.
    pub(crate) fn arm_release_before_close() {
        RELEASE_BEFORE_CLOSE.with(|cell| cell.set(true));
    }

    pub(super) fn creation_outside_section() -> bool {
        CREATION_OUTSIDE.with(Cell::get)
    }

    /// Sticky on this thread: a mutation run arms it for the whole open,
    /// so the creation runs before the registry guard (the pre-F1 order).
    pub(crate) fn arm_creation_outside_section() {
        CREATION_OUTSIDE.with(|cell| cell.set(true));
    }

    struct PauseGate {
        receipts: SyncSender<String>,
        release: Receiver<()>,
    }

    pub(crate) fn arm_destruction_gate(receipts: SyncSender<String>, release: Receiver<()>) {
        DESTRUCTION_GATE.with(|slot| {
            *slot.borrow_mut() = Some(PauseGate { receipts, release });
        });
    }

    /// Pauses entry destruction after the first close, while the registry
    /// guard is still held, until the parent releases it.
    pub(super) fn entry_destruction() {
        let gate = DESTRUCTION_GATE.with(|slot| slot.borrow_mut().take());
        if let Some(gate) = gate {
            if gate.receipts.send("H:paused".to_owned()).is_err() {
                return;
            }
            if gate.release.recv_timeout(DEADLINE).is_err() {
                // The parent stopped waiting. Destruction still finishes,
                // so the descriptor is not left open in this process.
            }
        }
    }

    pub(crate) fn arm_before_lock(receipts: SyncSender<String>) {
        BEFORE_LOCK.with(|slot| *slot.borrow_mut() = Some(receipts));
    }

    /// Reports the real outcome of one nonblocking registry acquisition by
    /// this thread, just before admission takes the guard for good:
    /// `B:contended` while another thread holds it, `B:acquired` when it
    /// was free. The probe guard is dropped before the receipt is sent.
    pub(super) fn before_registry_lock() {
        let sender = BEFORE_LOCK.with(|slot| slot.borrow_mut().take());
        if let Some(sender) = sender {
            let attempt = WRITERS.try_lock();
            let receipt = if matches!(attempt, Err(std::sync::TryLockError::WouldBlock)) {
                "B:contended"
            } else {
                "B:acquired"
            };
            drop(attempt);
            if sender.send(receipt.to_owned()).is_err() {
                // The parent is gone. Admission continues either way.
            }
        }
    }

    /// Arms one `fstat` failure of the next identity fd.
    pub(crate) fn arm_fstat_fault() {
        FSTAT_FAULT.with(|fault| fault.set(true));
    }

    pub(super) fn fstat_fault() -> bool {
        FSTAT_FAULT.with(Cell::take)
    }

    thread_local! {
        static FD_COUNTS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    }

    pub(super) fn creation_fd_opened() {
        FD_COUNTS.with(|counts| {
            let (creation, identity) = counts.get();
            counts.set((creation + 1, identity));
        });
    }

    pub(super) fn identity_fd_opened() {
        FD_COUNTS.with(|counts| {
            let (creation, identity) = counts.get();
            counts.set((creation, identity + 1));
        });
    }

    /// `(creation_fd_opened, identity_fd_opened)` of this thread's admissions.
    pub(crate) fn fd_counts() -> (usize, usize) {
        FD_COUNTS.with(Cell::get)
    }

    thread_local! {
        static UNLOCK_FAULTS: Cell<u8> = const { Cell::new(0) };
        static DUPLICATE_AT: Cell<Option<super::FileId>> = const { Cell::new(None) };
        static DUPLICATE: RefCell<Option<OwnedFd>> = const { RefCell::new(None) };
    }

    /// Makes the next `count` unlocks on this thread fail with
    /// `io::ErrorKind::Other` without unlocking.
    pub(crate) fn arm_unlock_faults(count: u8) {
        UNLOCK_FAULTS.with(|faults| faults.set(count));
    }

    pub(super) fn unlock_fault() -> Option<std::io::Error> {
        UNLOCK_FAULTS.with(|faults| {
            let left = faults.get();
            if left == 0 {
                return None;
            }
            faults.set(left - 1);
            Some(std::io::Error::from(std::io::ErrorKind::Other))
        })
    }

    /// Makes the next admission's `AfterPlace` point duplicate the held
    /// identity descriptor of `id`, which stays open until
    /// [`take_duplicate`] hands it out. The duplicate shares the open file
    /// description, so it is locked exactly like a forked child's copy.
    pub(crate) fn arm_duplicate_at_place(id: super::FileId) {
        DUPLICATE_AT.with(|at| at.set(Some(id)));
    }

    pub(crate) fn take_duplicate() -> Option<OwnedFd> {
        DUPLICATE.with(|slot| slot.borrow_mut().take())
    }

    fn capture_duplicate(registry: &Registry) {
        let Some(id) = DUPLICATE_AT.with(Cell::get) else {
            return;
        };
        let Some(identity) = registry.held.get(&id) else {
            return;
        };
        if let Ok(duplicate) = identity.try_clone() {
            DUPLICATE_AT.with(|at| at.set(None));
            DUPLICATE.with(|slot| *slot.borrow_mut() = Some(duplicate));
        }
    }

    /// The one marker variable of a child entry: its value is the
    /// parent-owned scratch root, so a child started any other way
    /// finds it missing and refuses.
    pub(crate) const CHILD_ROOT: &str = "RIVECT_STATE_CHILD_ROOT";

    /// Fails a custody step whose reap is unproven. With an owner, its
    /// root is retained first (`disable_cleanup`): a child that may still
    /// be alive keeps naming it, and the panic reports the path before the
    /// original error. No signal is sent and no step is retried.
    pub(crate) fn custody_failure(
        owner: Option<&mut tempfile::TempDir>,
        error: &dyn std::fmt::Display,
    ) -> ! {
        match owner {
            Some(owner) => {
                owner.disable_cleanup(true);
                unreachable!(
                    "retained root {}: child reap unproven: {error}",
                    owner.path().display()
                )
            }
            None => unreachable!("child reap unproven: {error}"),
        }
    }

    /// How a child process selects its test: an `#[ignore]` entry that
    /// only a parent runs, or one ordinary test chosen by its exact name.
    #[derive(Debug)]
    pub(crate) enum ChildEntry<'a> {
        Ignored(&'a str),
        Exact(&'a str),
    }

    /// This test binary on one child entry, with an empty environment
    /// holding only the root marker (an exact entry adds `TMPDIR` on the
    /// same root, so every root its body creates lives inside it) and
    /// piped stdin/stdout.
    pub(crate) fn spawn_child(
        entry: ChildEntry<'_>,
        root: &Path,
        stderr: std::process::Stdio,
    ) -> std::io::Result<std::process::Child> {
        use std::process::{Command, Stdio};
        let mut command = Command::new(std::env::current_exe()?);
        command
            .env_clear()
            .env(CHILD_ROOT, root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr);
        match entry {
            ChildEntry::Ignored(entry) => {
                command.args([entry, "--exact", "--ignored", "--nocapture"]);
            }
            ChildEntry::Exact(entry) => {
                command
                    .args([entry, "--exact", "--nocapture"])
                    .env("TMPDIR", root);
            }
        }
        command.spawn()
    }

    /// One-shot child: spawns the entry, writes `request` to its stdin,
    /// closes it and waits for the output. Every step stays a value until
    /// the wait settles; a step that fails leaves the reap unproven, so
    /// the owner's root is retained (`None` retains nothing) before the
    /// panic. `root` is an owned clone of the owner's path.
    pub(crate) fn run_probe_child(
        owner: Option<&mut tempfile::TempDir>,
        root: &Path,
        entry: ChildEntry<'_>,
        request: &[u8],
    ) -> std::process::Output {
        use std::io::Write as _;
        let steps = spawn_child(entry, root, std::process::Stdio::piped()).map(|mut child| {
            let wrote = child.stdin.take().map(|mut pipe| pipe.write_all(request));
            (wrote, child.wait_with_output())
        });
        match steps {
            Ok((Some(Ok(())), Ok(output))) => output,
            Ok((Some(Err(error)), _) | (_, Err(error))) | Err(error) => {
                custody_failure(owner, &error)
            }
            Ok((None, _)) => custody_failure(owner, &"the child stdin pipe was missing"),
        }
    }

    /// Runs one release test body alone in its own process. A body that
    /// releases a lock and then reacquires the root must not share a
    /// process with a sibling whose spawn holds a close-on-exec copy of
    /// the released description. The exact one-test arguments (a self
    /// re-exec child or a direct run of that test) run `body`; any other
    /// invocation runs no line of it and delegates to one such child. A red
    /// child's container is removed nonrecursively before the panic, so only
    /// a root its body leaked stays on disk, named in the report.
    pub(crate) fn run_isolated_release_test(
        name: &str,
        body: impl FnOnce() -> Result<(), Box<dyn std::error::Error>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write as _;
        if std::env::args_os()
            .skip(1)
            .eq([name, "--exact", "--nocapture"])
        {
            return body();
        }
        if std::env::var_os(CHILD_ROOT).is_some() {
            return Err(format!(
                "{CHILD_ROOT} is set but the arguments do not select {name} alone"
            )
            .into());
        }
        let mut container = tempfile::TempDir::with_prefix("rivect-isolated-release-")?;
        let root = container.path().to_path_buf();
        let output = run_probe_child(Some(&mut container), &root, ChildEntry::Exact(name), &[]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let (mut ran, mut named, mut passed) = (0_usize, 0_usize, 0_usize);
        for line in stdout.lines() {
            if line == "running 1 test" {
                ran += 1;
            } else if line
                .strip_prefix("test ")
                .and_then(|rest| rest.strip_suffix(" ... ok"))
                == Some(name)
            {
                named += 1;
            } else if line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;") {
                passed += 1;
            }
        }
        if !output.status.success() || (ran, named, passed) != (1, 1, 1) {
            container.disable_cleanup(true);
            let retained = match std::fs::remove_dir(container.path()) {
                Ok(()) => String::new(),
                Err(error) => format!("\nretained root {}: {error}", container.path().display()),
            };
            unreachable!(
                "isolated release test {name} failed: {}\nstdout:\n{stdout}\nstderr:\n{}{retained}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::io::stderr().write_all(&output.stderr)?;
        Ok(())
    }
}

/// The in-crate twins of the closed-surface doctests: the same
/// expressions over `crate::` paths must compile, so each doctest's
/// failure is attributable to visibility only.
#[cfg(test)]
mod closed_surface_twins {
    use super::TaskStore;
    use crate::commands::Runtime;

    fn reopen(store: &mut TaskStore, path: &std::path::Path) {
        drop(store.reopen(path));
    }

    fn close(store: &mut TaskStore) {
        drop(store.close());
    }

    fn writer_store(rt: &mut Runtime) {
        let w = rt.store_writer();
        let _s = w.store;
    }

    #[test]
    fn the_closed_store_items_are_reachable_inside_the_crate() {
        let _: fn(&mut TaskStore, &std::path::Path) = reopen;
        let _: fn(&mut TaskStore) = close;
        let _: fn(&mut Runtime) = writer_store;
    }
}
