//! The source-query facade (architecture «Context»): typed query kinds
//! classified mechanically onto the admitted in-process backends. The
//! choice is a fixed table — never an LLM pick, never a fallback chain
//! (INV-006). A kind without an admitted backend in this build gets a
//! typed refusal, not an empty result sold as coverage; a truncated or
//! partially covered scan is `Completeness::Partial`, never complete.

use crate::contracts::ErrorCode;
use crate::executor::{
    self, IndexRunError, ObserveBounds, ObserveOutcome, ObservedChild, WORKER_ENV_ALLOWLIST,
};
use crate::index::{
    Completeness, DerivationInputs, IndexedSource, MatchKind, PartialReason, ProjectGraph,
    QueryResult, SearchBackend, SearchMatch, SnapshotId, SourceRef, TraversalLimits, derive_edges,
    impact_traversal,
};
use crate::lsp::{
    CandidateFile, DocumentPin, MAX_INDEX_PARSE_TIME, MAX_SYMBOL_FILE_BYTES, MAX_SYMBOL_ROWS,
    SymbolIndex, SymbolOp, SymbolRequest, path_to_uri,
};
use ast_grep_core::matcher::{PatternBuilder, PatternNode, kind_utils};
use ast_grep_core::tree_sitter::{LanguageExt, StrDoc, TSLanguage};
use ast_grep_core::{AstGrep, Language, Pattern, PatternError};
use globset::{Glob, GlobMatcher};
use grep_matcher::Matcher;
use grep_regex::RegexMatcherBuilder;
use grep_searcher::{BinaryDetection, Searcher, SearcherBuilder, sinks::Bytes};
use ignore::WalkBuilder;
use lsp_types::PositionEncodingKind;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The recorded query vocabulary — the master's example names
/// (`search.text`, `code.symbol`, `source.slice`, …) classify onto these
/// kinds. A kind whose backend is not admitted in this build stays
/// visible as a typed refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryKind {
    /// Byte-faithful text search — a regex over content lines.
    Text,
    /// Path discovery — a glob over scope-relative paths; content is
    /// never opened.
    Path,
    /// The exact bytes of one named file.
    Source,
    /// Structural AST shapes over the admitted grammar set (SRC-007).
    Ast,
    /// Semantic symbol navigation over the typed symbol index (DEC-005).
    Symbol,
    /// Dependency/impact graph queries — owned by the index slice.
    Graph,
}

impl QueryKind {
    /// The stable interface name — the recorded future-interface
    /// examples map here, never the other way around.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "search.text",
            Self::Path => "search.paths",
            Self::Source => "source.slice",
            Self::Ast => "search.structure",
            Self::Symbol => SYMBOL_INTERFACE,
            Self::Graph => "code.impact",
        }
    }

    /// Boundary parse of an interface name: every recorded name lands on
    /// its kind, anything else is a typed refusal — an unknown name is a
    /// caller error, not a best-effort guess. Reference queries land on
    /// `Symbol` — they are the typed-symbol-index leg, not impact rows.
    pub fn from_name(name: &str) -> Result<Self, ContextError> {
        match name {
            "search.text" => Ok(Self::Text),
            "search.paths" => Ok(Self::Path),
            "source.slice" => Ok(Self::Source),
            "search.structure" => Ok(Self::Ast),
            SYMBOL_INTERFACE | REFERENCES_INTERFACE => Ok(Self::Symbol),
            "code.impact" => Ok(Self::Graph),
            _ => Err(ContextError::UnknownKind {
                name: name.to_string(),
                known: KNOWN_KIND_NAMES,
            }),
        }
    }
}

/// The definition-query interface name — one spelling shared by the
/// kind table and the symbol leg's op mapping.
pub(crate) const SYMBOL_INTERFACE: &str = "code.symbol";

/// The reference-query interface name — shared the same way.
pub(crate) const REFERENCES_INTERFACE: &str = "code.references";

/// The interface names `from_name` accepts — exactly the recorded
/// vocabulary, and the domain an `UnknownKind` refusal reports back to
/// the caller.
const KNOWN_KIND_NAMES: &[&str] = &[
    "search.text",
    "search.paths",
    "source.slice",
    "search.structure",
    SYMBOL_INTERFACE,
    REFERENCES_INTERFACE,
    "code.impact",
];

/// How the standard ignore/hidden filters apply to candidate
/// enumeration. An explicit file path (`source.slice`) is read either
/// way — the policy governs enumeration, and the result's `ignored` flag
/// reports what the rules would have done with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IgnorePolicy {
    /// The bundled engine's default: hidden, `.ignore`, `.gitignore`,
    /// global and parent rules all exclude candidates.
    #[default]
    Respect,
    /// The ignore-rule family is disabled for enumeration; hidden stays
    /// filtered (hidden is not an ignore rule). Matches the rules would
    /// have dropped are reported flagged `ignored: true`, never as
    /// ordinary hits.
    Include,
}

/// One source query: its kind, the scope root, and the kind's own
/// pattern — a regex for `Text`, a glob for `Path`, a root-relative file
/// path for `Source`, an ast-grep pattern (`$VAR`/`$$$VAR`
/// meta-variables) for `Ast`, the symbol's name for `Symbol`.
/// `scope_glob` additionally restricts `Text`/`Path`/`Ast`/`Symbol`
/// candidates; `limit` is the required positive bound on returned items
/// (`Source`: bytes). Fields are public like the other contract
/// carriers; `query` validates before any backend runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Query {
    pub kind: QueryKind,
    pub root: PathBuf,
    /// The kind's own pattern, interpreted mechanically — never
    /// negotiated: a `Path` pattern is always glob-interpreted (there is
    /// no literal escape) and a bare name with no separator or glob
    /// metas auto-promotes to `**/name`; a `Text` pattern is
    /// `grep-regex` dialect — no lookaround, no backrefs; a `Source`
    /// pattern is a root-relative file path; a `Symbol` pattern (at most
    /// 1024 bytes) is the symbol's name — optionally `scope::name`
    /// qualified at the last `::`, where the scope matches by trailing
    /// segments: `a::b::helper` addresses every scope ending in `a::b`,
    /// `crate::a::helper` only the root-level `a`, `::helper` only the
    /// root (a Rust anchor: `crate::`/`self::` never address a
    /// TypeScript document) — for definitions, types and the uses
    /// certainly bound to them a Rust file's own module path
    /// (`src/a/b.rs` → `a::b`) continues its scopes; an `Ast` pattern
    /// is ast-grep syntax compiled once per admitted grammar — rust
    /// (`rs`), typescript (`ts`, `cts`, `mts`) and tsx (`tsx`), and an
    /// `Ast` pattern over 1024 bytes is refused at the boundary. A
    /// pattern no grammar parses is a typed refusal; one at least one
    /// grammar parses serves its languages while files under the
    /// rejecting grammars count `UnsupportedLanguage` — partial, never
    /// silent. Rust meta-var sigils are rewritten to `µ` before
    /// parsing; the extractor reads a meta-variable only out of an
    /// `[A-Z_][A-Z0-9_]*` tail, so a literal `µfoo` stays an identifier
    /// while `µFOO`/`µµF`-shaped names read as meta-vars.
    pub pattern: String,
    pub scope_glob: Option<String>,
    pub ignore: IgnorePolicy,
    pub limit: usize,
    /// The symbol leg's operation — required on a `Symbol` query and
    /// refused on every other kind. `code.symbol` and `code.references`
    /// both route to `Symbol`, so the op is what separates them:
    /// `SymbolOp::from_interface_name` supplies each name's op, and a
    /// missing op is refused rather than defaulted — a reference name
    /// can never silently answer definitions.
    pub symbol_op: Option<SymbolOp>,
    /// A single-document pin — the LSP `textDocument` analogue: the
    /// request is about one root-relative document, optionally pinned
    /// to its content version and the caller's position encoding.
    /// Its definitions/uses are the subject — resolution and type
    /// answers still range over every fresh document — and the
    /// completeness reasons describe what it serves — that document and
    /// any a served row comes from, or for a type answer every document
    /// it may draw on. A pin naming no candidate the index
    /// claims (missing, a directory, outside the scope glob, ignored,
    /// unclaimed) lands in `unresolved`; a claimed file that failed to
    /// index is `EntriesFailed`; a version pinned on either is refused
    /// as unverifiable; an escape is denied; a mismatched version is a
    /// typed conflict. Refused on non-`Symbol` kinds.
    pub document: Option<DocumentPin>,
}

#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    #[error("unknown query kind {name}; known names: {}", .known.join(", "))]
    UnknownKind {
        name: String,
        known: &'static [&'static str],
    },
    #[error("query kind {kind} has no admitted backend in this build")]
    UnsupportedKind { kind: &'static str },
    #[error("query root {path} is not usable: {source}")]
    InvalidRoot {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("query root {path} is not a directory")]
    RootNotDirectory { path: String },
    #[error("pattern is required for {kind}")]
    EmptyPattern { kind: &'static str },
    #[error("limit must be a positive bound")]
    UnboundedLimit,
    #[error("scope glob does not apply to {kind}")]
    ScopeNotApplicable { kind: &'static str },
    #[error("invalid text pattern {pattern}: {source}")]
    InvalidTextPattern {
        pattern: String,
        #[source]
        source: grep_regex::Error,
    },
    #[error("invalid glob {glob}: {source}")]
    InvalidGlob {
        glob: String,
        #[source]
        source: globset::Error,
    },
    #[error("path {path} resolves outside the query root")]
    EscapedRoot { path: String },
    #[error("invalid ast pattern {pattern} for admitted grammars ({languages}): {detail}")]
    InvalidAstPattern {
        pattern: String,
        languages: String,
        detail: String,
    },
    #[error("ast pattern exceeds the {limit}-byte bound")]
    AstPatternTooLarge { limit: usize },
    #[error("symbol field {field} does not apply to a {kind} query")]
    SymbolFieldNotApplicable {
        field: &'static str,
        kind: &'static str,
    },
    #[error("symbol queries require an operation")]
    SymbolOpRequired,
    #[error("symbol pattern exceeds the {limit}-byte bound")]
    SymbolPatternTooLarge { limit: usize },
    #[error("document {path} is at version {actual}, not the pinned {pinned}")]
    StaleDocumentVersion {
        path: String,
        pinned: i32,
        actual: i32,
    },
    #[error("document {path} is not indexed, so its pinned version cannot be verified")]
    UnverifiableDocumentVersion { path: String },
    /// `encoding` is `utf-16`, `utf-32` or `unrecognized` — the caller's
    /// own string is never echoed.
    #[error("position encoding {encoding} is not served; the index answers utf-8")]
    UnsupportedPositionEncoding { encoding: &'static str },
    /// The isolated run ended without an answer; the cause names the one
    /// parent-side classification branch that decided it (DEC-033).
    #[error("isolated index run failed: {cause}")]
    IsolatedRun {
        cause: IsolatedCause,
        #[source]
        source: Option<Box<IsolatedRunSource>>,
    },
    /// The worker's own engine refused the query: its code, variant tag
    /// and message, exactly as the in-process engine would have answered.
    #[error("index worker answered {tag}: {message}")]
    WorkerRefused {
        code: ErrorCode,
        tag: String,
        message: String,
    },
    /// A bound an isolated answer could not carry within its size cap,
    /// refused before any worker starts.
    #[error("query limit {limit} exceeds the isolated ceiling {ceiling}")]
    LimitTooLarge { limit: usize, ceiling: usize },
}

/// The original executor failure or the prior failure beneath cancellation.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct IsolatedRunSource(IsolatedRunSourceKind);

#[derive(Debug, thiserror::Error)]
enum IsolatedRunSourceKind {
    #[error("isolated executor failed")]
    Executor(#[source] IndexRunError),
    #[error("isolated run was cancelled after failure")]
    Prior(#[source] Box<ContextError>),
}

impl IsolatedRunSource {
    pub(crate) fn prior(error: ContextError) -> Self {
        Self(IsolatedRunSourceKind::Prior(Box::new(error)))
    }
}

impl ContextError {
    /// The wire code one failing query maps to: an unwired kind is a
    /// capability fact, a root that does not resolve is a finding, a
    /// root escape is a boundary denial, an isolated run answers its
    /// cause's code and a worker refusal the engine's own; the rest —
    /// including a root that resolves to a file — are caller errors.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::UnsupportedKind { .. } => ErrorCode::CapabilityUnavailable,
            Self::InvalidRoot { .. } => ErrorCode::NotFound,
            Self::EscapedRoot { .. } => ErrorCode::Denied,
            Self::StaleDocumentVersion { .. } | Self::UnverifiableDocumentVersion { .. } => {
                ErrorCode::Conflict
            }
            Self::UnknownKind { .. }
            | Self::RootNotDirectory { .. }
            | Self::EmptyPattern { .. }
            | Self::UnboundedLimit
            | Self::ScopeNotApplicable { .. }
            | Self::InvalidTextPattern { .. }
            | Self::InvalidGlob { .. }
            | Self::InvalidAstPattern { .. }
            | Self::AstPatternTooLarge { .. }
            | Self::SymbolFieldNotApplicable { .. }
            | Self::SymbolOpRequired
            | Self::SymbolPatternTooLarge { .. }
            | Self::UnsupportedPositionEncoding { .. }
            | Self::LimitTooLarge { .. } => ErrorCode::InvalidInput,
            Self::IsolatedRun { cause, .. } => cause.error_code(),
            Self::WorkerRefused { code, .. } => *code,
        }
    }

    /// The variant's stable name — what a worker refusal carries across
    /// the process boundary beside its code and message, and what a
    /// caller that cannot read the code matches on.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::UnknownKind { .. } => "unknown_kind",
            Self::UnsupportedKind { .. } => "unsupported_kind",
            Self::InvalidRoot { .. } => "invalid_root",
            Self::RootNotDirectory { .. } => "root_not_directory",
            Self::EmptyPattern { .. } => "empty_pattern",
            Self::UnboundedLimit => "unbounded_limit",
            Self::ScopeNotApplicable { .. } => "scope_not_applicable",
            Self::InvalidTextPattern { .. } => "invalid_text_pattern",
            Self::InvalidGlob { .. } => "invalid_glob",
            Self::EscapedRoot { .. } => "escaped_root",
            Self::InvalidAstPattern { .. } => "invalid_ast_pattern",
            Self::AstPatternTooLarge { .. } => "ast_pattern_too_large",
            Self::SymbolFieldNotApplicable { .. } => "symbol_field_not_applicable",
            Self::SymbolOpRequired => "symbol_op_required",
            Self::SymbolPatternTooLarge { .. } => "symbol_pattern_too_large",
            Self::StaleDocumentVersion { .. } => "stale_document_version",
            Self::UnverifiableDocumentVersion { .. } => "unverifiable_document_version",
            Self::UnsupportedPositionEncoding { .. } => "unsupported_position_encoding",
            Self::IsolatedRun { .. } => "isolated_run",
            Self::WorkerRefused { .. } => "worker_refused",
            Self::LimitTooLarge { .. } => "limit_too_large",
        }
    }
}

/// Why an isolated query ended without an answer — one variant per
/// parent-side classification branch of the declared map (DEC-033). The
/// parent's own stops (cancel, deadline, over-cap, over-budget footprint)
/// are classified before any signal is read, so its own kill is never a
/// resource limit; a signal number is carried, never part of the
/// identity.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IsolatedCause {
    #[error("the query cannot be encoded for the index worker")]
    RequestUnencodable,
    #[error("the index deadline had already passed")]
    DeadlinePassed,
    #[error("the query was cancelled before the index worker started")]
    CancelledBeforeSpawn,
    #[error("the sandbox helper is unavailable")]
    HelperUnavailable,
    #[error("the sandbox helper could not apply its limits")]
    HelperInitFailed,
    #[error("the sandbox helper rejected its launch arguments")]
    HelperProtocol,
    #[error("the index worker program was not found")]
    WorkerMissing,
    #[error("the index worker program could not be executed")]
    WorkerExecFailed,
    #[error("the query was cancelled while the index worker ran")]
    Cancelled,
    #[error("the index worker ran past its deadline")]
    DeadlineExceeded,
    #[error("the index worker answer exceeded its size cap")]
    AnswerTooLarge,
    /// The parent's footprint poll saw the worker above its memory budget
    /// and killed it (macOS, DEC-038).
    #[error("the index worker exceeded its memory budget")]
    MemoryExceeded,
    #[error("the index worker hit a resource limit (signal {signal})")]
    ResourceLimit { signal: i32 },
    #[error("the index worker crashed on signal {signal}")]
    WorkerCrashed { signal: i32 },
    #[error("the index worker exited with status {code}")]
    WorkerFailed { code: i32 },
    #[error("the index worker exited without an answer")]
    EmptyAnswer,
    #[error("the index worker answer is not a complete envelope")]
    WorkerProtocol,
    #[error("the index worker speaks another protocol or crate version")]
    VersionMismatch,
    #[error("the index worker rejected the request")]
    RequestRejected,
    #[error("the index worker has no finite memory cap within the bound")]
    WorkerUncapped,
    #[error("the index worker environment holds a key outside the allowlist")]
    WorkerEnvRejected,
    #[error("observing the index worker failed")]
    ObserveFailed,
}

impl IsolatedCause {
    /// The branch's stable tag — injective over the declared map.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::RequestUnencodable => "request_unencodable",
            Self::DeadlinePassed => "deadline_passed",
            Self::CancelledBeforeSpawn => "cancelled_before_spawn",
            Self::HelperUnavailable => "helper_unavailable",
            Self::HelperInitFailed => "helper_init_failed",
            Self::HelperProtocol => "helper_protocol",
            Self::WorkerMissing => "worker_missing",
            Self::WorkerExecFailed => "worker_exec_failed",
            Self::Cancelled => "cancelled",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::AnswerTooLarge => "answer_too_large",
            Self::MemoryExceeded => "memory_exceeded",
            Self::ResourceLimit { .. } => "resource_limit",
            Self::WorkerCrashed { .. } => "worker_crashed",
            Self::WorkerFailed { .. } => "worker_failed",
            Self::EmptyAnswer => "empty_answer",
            Self::WorkerProtocol => "worker_protocol",
            Self::VersionMismatch => "version_mismatch",
            Self::RequestRejected => "request_rejected",
            Self::WorkerUncapped => "worker_uncapped",
            Self::WorkerEnvRejected => "worker_env_rejected",
            Self::ObserveFailed => "observe_failed",
        }
    }

    /// The branch's wire code; codes, unlike tags, may repeat.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::RequestUnencodable => ErrorCode::InvalidInput,
            Self::DeadlinePassed
            | Self::DeadlineExceeded
            | Self::MemoryExceeded
            | Self::ResourceLimit { .. } => ErrorCode::BudgetExhausted,
            Self::CancelledBeforeSpawn | Self::Cancelled => ErrorCode::Cancelled,
            Self::HelperUnavailable
            | Self::HelperInitFailed
            | Self::HelperProtocol
            | Self::WorkerMissing
            | Self::WorkerExecFailed
            | Self::WorkerUncapped
            | Self::ObserveFailed => ErrorCode::CapabilityUnavailable,
            Self::AnswerTooLarge => ErrorCode::OutputLimit,
            Self::WorkerCrashed { .. }
            | Self::WorkerFailed { .. }
            | Self::EmptyAnswer
            | Self::WorkerProtocol
            | Self::WorkerEnvRejected => ErrorCode::InternalError,
            Self::VersionMismatch | Self::RequestRejected => ErrorCode::UnsupportedVersion,
        }
    }
}

/// The fixed dispatch table (INV-006): kind → admitted in-process
/// backend. Growing it is a row here plus its engine — the choice
/// itself is never delegated to a model.
pub fn backend_for(kind: QueryKind) -> Option<SearchBackend> {
    match kind {
        QueryKind::Text => Some(SearchBackend::Text),
        QueryKind::Path => Some(SearchBackend::Path),
        QueryKind::Source => Some(SearchBackend::Source),
        QueryKind::Ast => Some(SearchBackend::Ast),
        QueryKind::Symbol => Some(SearchBackend::Symbol),
        QueryKind::Graph => Some(SearchBackend::Graph),
    }
}

/// Run one typed query: boundary validation first, then the mechanical
/// dispatch. A kind with no admitted backend answers the typed refusal —
/// never an empty result. The legs do synchronous blocking filesystem
/// I/O — a dispatch surface that wires this in must run it off the
/// input/dispatch path (INV-011), and untrusted content must reach it
/// only through [`query_isolated`] (DEC-028).
pub fn query(request: &Query) -> Result<QueryResult, ContextError> {
    query_until(
        request,
        Instant::now()
            .checked_add(MAX_INDEX_PARSE_TIME)
            .unwrap_or_else(Instant::now),
    )
}

/// [`query`] under an explicit index deadline. Only the symbol leg
/// checks it (in its parse progress callback); the other legs run to
/// completion, so the isolated run's wall-kill is what bounds them.
pub fn query_until(request: &Query, deadline: Instant) -> Result<QueryResult, ContextError> {
    let root = validate(request)?;
    match backend_for(request.kind) {
        Some(SearchBackend::Text) => text_query(request, &root),
        Some(SearchBackend::Path) => path_query(request, &root),
        Some(SearchBackend::Source) => source_query(request, &root),
        Some(SearchBackend::Ast) => ast_query(request, &root),
        Some(SearchBackend::Symbol) => symbol_query(request, &root, deadline),
        Some(SearchBackend::Graph) => graph_query(request, &root, deadline),
        None => Err(ContextError::UnsupportedKind {
            kind: request.kind.as_str(),
        }),
    }
}

// ----- isolated index worker (DEC-028/030/031/033/038) -----

/// Keys the platform sets inside this process itself, never inherited:
/// CoreFoundation, linked into `rivect`, sets `__CF_USER_TEXT_ENCODING`
/// at image load whenever the environment lacks it — as the worker's
/// cleared environment always does. The worker's check tolerates them;
/// the parent never forwards them.
#[cfg(target_os = "macos")]
const SELF_SET_ENV: &[&str] = &["__CF_USER_TEXT_ENCODING"];
#[cfg(not(target_os = "macos"))]
const SELF_SET_ENV: &[&str] = &[];

/// How long past the index deadline the parent waits before it kills the
/// worker's process group: room for the worker's own deadline check to
/// answer honestly partial before the wall-kill ends it.
pub const WORKER_KILL_GRACE: Duration = Duration::from_secs(2);

/// The largest answer the parent accepts from a worker; a caller's cap
/// only tightens it.
pub const WORKER_ANSWER_MAX: usize = 32 * 1024 * 1024;

/// The largest request the parent sends and the worker reads.
const WORKER_REQUEST_MAX: usize = 1024 * 1024;

/// Room the envelope needs beside a `Source` answer's bytes: versions,
/// provenance and a path escaped at worst six bytes per byte.
const ENVELOPE_MARGIN: usize = 64 * 1024;

/// Worst-case JSON expansion of one served byte.
const JSON_BYTE_EXPANSION: usize = 6;

/// The worker wire version; the crate version rides beside it.
const WORKER_PROTOCOL: u32 = 1;

/// One isolated query run. Both paths are explicit: the helper override
/// is thread-local, and a runtime caller runs the query off the dispatch
/// thread (INV-011).
pub struct IsolatedRun<'a> {
    /// The `rivect` executable re-run as the worker.
    pub program: &'a Path,
    /// The `rivect-sandbox-helper` that caps and launches it.
    pub helper: &'a Path,
    /// The caller's deadline; absent or later than
    /// `now + MAX_INDEX_PARSE_TIME`, that bound stands instead.
    pub deadline: Option<Instant>,
    /// Polled before the spawn and on every observation step: `true`
    /// kills the worker's process group and ends the run cancelled.
    pub cancel: &'a dyn Fn() -> bool,
    /// The caller's answer size cap, tightened to [`WORKER_ANSWER_MAX`].
    pub answer_cap: usize,
}

impl std::fmt::Debug for IsolatedRun<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsolatedRun")
            .field("program", &self.program)
            .field("helper", &self.helper)
            .field("deadline", &self.deadline)
            .field("answer_cap", &self.answer_cap)
            .finish_non_exhaustive()
    }
}

/// The index deadline one run is bounded by (DEC-030 #1): the caller's
/// deadline narrowed by [`MAX_INDEX_PARSE_TIME`], so a distant or absent
/// caller deadline cannot widen it. Cancellation is decided before the
/// clock, and a deadline already past starts no worker.
fn effective_deadline(run: &IsolatedRun<'_>) -> Result<Instant, ContextError> {
    if (run.cancel)() {
        return isolated_failure(IsolatedCause::CancelledBeforeSpawn);
    }
    let now = Instant::now();
    let ceiling = now.checked_add(MAX_INDEX_PARSE_TIME).unwrap_or(now);
    let deadline = run.deadline.map_or(ceiling, |caller| caller.min(ceiling));
    if deadline <= now {
        return isolated_failure(IsolatedCause::DeadlinePassed);
    }
    Ok(deadline)
}

/// The spawn-and-decode seam both isolated entry points share: bounds
/// are fixed, the worker runs under the helper, and exactly one
/// complete exit-0 envelope is decoded (DEC-028/033).
fn observe_worker(
    run: &IsolatedRun<'_>,
    deadline: Instant,
    answer_cap: usize,
    wire: &WorkerRequest,
) -> Result<WorkerBody, ContextError> {
    // JSON carries no non-UTF-8 path, and a request past the worker's
    // read bound is one it could only reject.
    let payload = match serde_json::to_vec(wire) {
        Ok(payload) if payload.len() <= WORKER_REQUEST_MAX => payload,
        Ok(_) | Err(_) => return isolated_failure(IsolatedCause::RequestUnencodable),
    };
    let mut observed_stop = None;
    let bounds = ObserveBounds {
        deadline: deadline.checked_add(WORKER_KILL_GRACE).unwrap_or(deadline),
        // One byte past the cap is the over-cap proof; the rest is dropped.
        stdout_cap: answer_cap.saturating_add(1),
        stop: |retained: usize| {
            if (run.cancel)() {
                observed_stop = Some(IsolatedCause::Cancelled);
                Some(IsolatedCause::Cancelled)
            } else if retained > answer_cap {
                observed_stop = Some(IsolatedCause::AnswerTooLarge);
                Some(IsolatedCause::AnswerTooLarge)
            } else {
                None
            }
        },
        // A helper that fails before it execs the worker never reads the
        // request; its prefixed exit, not the broken pipe, is the verdict.
        stdin_close_ends_payload: true,
    };
    let observed = match executor::run_index_worker(
        run.helper,
        run.program,
        &payload,
        deadline,
        run.cancel,
        bounds,
        &|cause| match cause {
            IsolatedCause::Cancelled => rivect_sandbox_helper::OwnedStop::Cancelled,
            _ => rivect_sandbox_helper::OwnedStop::Observation,
        },
    ) {
        Ok(ObserveOutcome::Exited(observed)) => observed,
        Ok(ObserveOutcome::Stopped(cause)) => return isolated_failure(cause),
        Err(error) => {
            let cause = match error.request_stop() {
                Some(rivect_sandbox_helper::OwnedStop::Cancelled) => {
                    IsolatedCause::CancelledBeforeSpawn
                }
                Some(rivect_sandbox_helper::OwnedStop::Deadline) => IsolatedCause::DeadlinePassed,
                _ => match (observed_stop, error.observed_stop()) {
                    (Some(cause), _) => cause,
                    (_, Some(rivect_sandbox_helper::OwnedStop::Cancelled)) => {
                        IsolatedCause::Cancelled
                    }
                    (_, Some(rivect_sandbox_helper::OwnedStop::Deadline)) => {
                        IsolatedCause::DeadlineExceeded
                    }
                    _ if error.worker_exec_errno() == Some(2) => IsolatedCause::WorkerMissing,
                    _ if error.worker_exec_errno().is_some() => IsolatedCause::WorkerExecFailed,
                    _ if error.observation_lost() => IsolatedCause::ObserveFailed,
                    _ => match &error {
                        IndexRunError::Unavailable { .. } => IsolatedCause::HelperUnavailable,
                        #[cfg(target_os = "macos")]
                        IndexRunError::TimedOut => IsolatedCause::DeadlineExceeded,
                        #[cfg(target_os = "macos")]
                        IndexRunError::MemoryExceeded => IsolatedCause::MemoryExceeded,
                        #[cfg(target_os = "macos")]
                        IndexRunError::Observe { .. } => IsolatedCause::ObserveFailed,
                    },
                },
            };
            return Err(ContextError::IsolatedRun {
                cause,
                source: Some(Box::new(IsolatedRunSource(
                    IsolatedRunSourceKind::Executor(error),
                ))),
            });
        }
    };
    classify_exit(&observed, answer_cap)
}

/// Runs one query in a capped `rivect --index-worker` child under the
/// sandbox helper — the only runtime path to untrusted parsing
/// (DEC-028/031). There is no in-process fallback: every way the run can
/// end without an answer is a typed [`IsolatedCause`], and a refusal by
/// the worker's engine is [`ContextError::WorkerRefused`] with the code
/// the in-process engine would answer.
///
/// # Errors
/// [`ContextError::LimitTooLarge`] before any spawn when the bound
/// exceeds what an answer can carry; [`ContextError::IsolatedRun`] with
/// the classification branch that ended the run otherwise.
pub fn query_isolated(request: &Query, run: &IsolatedRun<'_>) -> Result<QueryResult, ContextError> {
    let deadline = effective_deadline(run)?;
    let answer_cap = run.answer_cap.min(WORKER_ANSWER_MAX);
    refuse_uncarriable_limit(request, answer_cap)?;
    let wire = query_request(request, deadline, answer_cap);
    match observe_worker(run, deadline, answer_cap, &wire)? {
        WorkerBody::Answer { result } => Ok(result),
        // A body this call did not ask for is a protocol mismatch, not
        // an answer: the worker cannot answer one request with another.
        WorkerBody::Project { .. } | WorkerBody::Refused { .. } => {
            isolated_failure(IsolatedCause::WorkerProtocol)
        }
        WorkerBody::Failed { code, tag, message } => match engine_refusal_code(&tag) {
            Some(expected) if expected == code => {
                Err(ContextError::WorkerRefused { code, tag, message })
            }
            _ => isolated_failure(IsolatedCause::WorkerProtocol),
        },
    }
}

/// Runs one project-index build in the same capped child: the derived
/// generation's edges, its coverage and the specifiers it could not
/// place. It is the only runtime path to a project-index parse, and it
/// answers a body of its own kind — a query answer is a protocol
/// mismatch here, exactly as a project answer is one there.
///
/// # Errors
/// [`ContextError::LimitTooLarge`] before any spawn when the edge bound
/// exceeds what an answer can carry; [`ContextError::IsolatedRun`] with
/// the classification branch that ended the run otherwise.
pub fn project_index_isolated(
    request: &ProjectRequest,
    run: &IsolatedRun<'_>,
) -> Result<ProjectGraph, ContextError> {
    let deadline = effective_deadline(run)?;
    let answer_cap = run.answer_cap.min(WORKER_ANSWER_MAX);
    if request.limit == 0 || request.limit > MAX_SYMBOL_ROWS {
        return Err(ContextError::LimitTooLarge {
            limit: request.limit,
            ceiling: MAX_SYMBOL_ROWS,
        });
    }
    let wire = WorkerRequest {
        protocol: WORKER_PROTOCOL,
        crate_version: env!("CARGO_PKG_VERSION").to_string(),
        query: None,
        project: Some(request.clone()),
        deadline_ms: wire_millis(deadline),
        answer_cap,
    };
    match observe_worker(run, deadline, answer_cap, &wire)? {
        WorkerBody::Project { graph } => Ok(graph),
        WorkerBody::Answer { .. } | WorkerBody::Refused { .. } => {
            isolated_failure(IsolatedCause::WorkerProtocol)
        }
        WorkerBody::Failed { code, tag, message } => match engine_refusal_code(&tag) {
            Some(expected) if expected == code => {
                Err(ContextError::WorkerRefused { code, tag, message })
            }
            _ => isolated_failure(IsolatedCause::WorkerProtocol),
        },
    }
}

fn query_request(request: &Query, deadline: Instant, answer_cap: usize) -> WorkerRequest {
    WorkerRequest {
        protocol: WORKER_PROTOCOL,
        crate_version: env!("CARGO_PKG_VERSION").to_string(),
        query: Some(request.clone()),
        project: None,
        deadline_ms: wire_millis(deadline),
        answer_cap,
    }
}

/// The remaining milliseconds, rounded up so a sub-millisecond
/// remainder is not sent as "past".
fn wire_millis(deadline: Instant) -> u64 {
    let now = Instant::now();
    let remaining = deadline.saturating_duration_since(now);
    u64::try_from(remaining.as_nanos().div_ceil(1_000_000)).unwrap_or(u64::MAX)
}

fn isolated_failure<T>(cause: IsolatedCause) -> Result<T, ContextError> {
    Err(ContextError::IsolatedRun {
        cause,
        source: None,
    })
}

/// A bound whose answer could not fit the cap is refused before any
/// spawn (AC-036c): items past [`MAX_SYMBOL_ROWS`], or `Source` bytes
/// past what the cap carries at worst-case JSON escaping.
fn refuse_uncarriable_limit(request: &Query, answer_cap: usize) -> Result<(), ContextError> {
    let ceiling = match request.kind {
        QueryKind::Source => answer_cap.saturating_sub(ENVELOPE_MARGIN) / JSON_BYTE_EXPANSION,
        QueryKind::Text
        | QueryKind::Path
        | QueryKind::Ast
        | QueryKind::Symbol
        | QueryKind::Graph => MAX_SYMBOL_ROWS,
    };
    if request.limit > ceiling {
        return Err(ContextError::LimitTooLarge {
            limit: request.limit,
            ceiling,
        });
    }
    Ok(())
}

const SIGABRT: i32 = 6;
const SIGKILL: i32 = 9;
const SIGXCPU: i32 = 24;

/// The declared map's branches for a worker that ended on its own. An
/// over-cap answer is the parent's stop and is decided first; helper
/// verdicts count only behind the helper's stderr-prefix gate.
fn classify_exit(observed: &ObservedChild, answer_cap: usize) -> Result<WorkerBody, ContextError> {
    if observed.stdout.len() > answer_cap {
        return isolated_failure(IsolatedCause::AnswerTooLarge);
    }
    // The gate answers only for the helper's own verdict codes.
    let from_helper = || executor::helper_launch_init_failed(observed).is_some();
    let cause = match (observed.status.code(), observed.status.signal()) {
        (Some(0), _) => return decode_envelope(&observed.stdout),
        (Some(rivect_sandbox_helper::EXIT_SANDBOX_INIT), _) if from_helper() => {
            IsolatedCause::HelperInitFailed
        }
        (Some(rivect_sandbox_helper::EXIT_PROTOCOL), _) if from_helper() => {
            IsolatedCause::HelperProtocol
        }
        (Some(rivect_sandbox_helper::EXIT_LAUNCH_NOT_FOUND), _) if from_helper() => {
            IsolatedCause::WorkerMissing
        }
        (Some(rivect_sandbox_helper::EXIT_LAUNCH_EXEC), _) if from_helper() => {
            IsolatedCause::WorkerExecFailed
        }
        (Some(code), _) => IsolatedCause::WorkerFailed { code },
        (None, Some(signal @ (SIGABRT | SIGKILL | SIGXCPU))) => {
            IsolatedCause::ResourceLimit { signal }
        }
        (None, Some(signal)) => IsolatedCause::WorkerCrashed { signal },
        // Neither an exit code nor a signal: nothing to classify.
        (None, None) => IsolatedCause::ObserveFailed,
    };
    isolated_failure(cause)
}

/// Decodes a complete exit-0 envelope: the header (protocol and crate
/// version) first, then the body — a body is never read under another
/// version, and a partial envelope is never read at all. The body comes
/// back unprojected; each entry point accepts only the one kind it
/// asked for, so an answer of the wrong kind is a protocol mismatch
/// rather than a misread answer.
fn decode_envelope(stdout: &[u8]) -> Result<WorkerBody, ContextError> {
    if stdout.is_empty() {
        return isolated_failure(IsolatedCause::EmptyAnswer);
    }
    let Ok(header) = serde_json::from_slice::<WireHeader>(stdout) else {
        return isolated_failure(IsolatedCause::WorkerProtocol);
    };
    if header.protocol != WORKER_PROTOCOL || header.crate_version != env!("CARGO_PKG_VERSION") {
        return isolated_failure(IsolatedCause::VersionMismatch);
    }
    let Ok(envelope) = serde_json::from_slice::<WorkerEnvelope>(stdout) else {
        return isolated_failure(IsolatedCause::WorkerProtocol);
    };
    match envelope.body {
        body @ WorkerBody::Answer { .. } | body @ WorkerBody::Project { .. } => Ok(body),
        // A refusal crosses only as one the engine can give, with the
        // code the engine gives it: the worker cannot relabel its failure.
        WorkerBody::Failed { code, tag, message } if engine_refusal_code(&tag) == Some(code) => {
            Ok(WorkerBody::Failed { code, tag, message })
        }
        WorkerBody::Failed { .. } => isolated_failure(IsolatedCause::WorkerProtocol),
        WorkerBody::Refused { reason } => isolated_failure(match reason {
            WorkerRefusal::RequestRejected => IsolatedCause::RequestRejected,
            WorkerRefusal::Uncapped => IsolatedCause::WorkerUncapped,
            WorkerRefusal::EnvRejected => IsolatedCause::WorkerEnvRejected,
        }),
    }
}

/// The code the in-process engine answers under each refusal tag it can
/// give; the parent-side variants (`isolated_run`, `worker_refused`,
/// `limit_too_large`) never come from a worker.
///
/// The pairing is written out again in [`ContextError::error_code`]
/// because this side must answer from the tag alone: a refusal crosses
/// the wire carrying a tag, with none of the variant's fields to rebuild
/// it from. The build binds only the per-variant arms — `error_code` and
/// `tag` match every variant with no `_` arm — and binds nothing here,
/// where a new tag falls through `_ => None`.
///
/// `engine_refusal_table_matches_every_variant` is what holds the two
/// tables together: its own match over `ContextError` has no `_` arm, so
/// a new variant breaks the build and must be classified, and it asserts
/// the two sides agree on the code for every variant in its `cases` — a
/// variant its author never lists there is unpaired.
fn engine_refusal_code(tag: &str) -> Option<ErrorCode> {
    match tag {
        "unsupported_kind" => Some(ErrorCode::CapabilityUnavailable),
        "invalid_root" => Some(ErrorCode::NotFound),
        "escaped_root" => Some(ErrorCode::Denied),
        "stale_document_version" | "unverifiable_document_version" => Some(ErrorCode::Conflict),
        "unknown_kind"
        | "root_not_directory"
        | "empty_pattern"
        | "unbounded_limit"
        | "scope_not_applicable"
        | "invalid_text_pattern"
        | "invalid_glob"
        | "invalid_ast_pattern"
        | "ast_pattern_too_large"
        | "symbol_field_not_applicable"
        | "symbol_op_required"
        | "symbol_pattern_too_large"
        | "unsupported_position_encoding" => Some(ErrorCode::InvalidInput),
        _ => None,
    }
}

/// The request the parent writes on the worker's stdin — never argv.
/// Exactly one of `query`/`project` is present: the same envelope, the
/// same protocol version, one definition read by both sides (SLICE-032
/// extends it; there is no second protocol).
#[derive(Serialize, Deserialize)]
struct WorkerRequest {
    protocol: u32,
    crate_version: String,
    query: Option<Query>,
    project: Option<ProjectRequest>,
    deadline_ms: u64,
    answer_cap: usize,
}

/// The project-index request: the parent-pinned project root, the
/// root-relative paths a coalesced watcher batch reported — empty for a
/// full build or a repair — whether that batch saw the file set itself
/// move, and the positive bound on served edges. The worker reads
/// nothing but the root the pin set, so a project build can never widen
/// the scope it was given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRequest {
    pub root: PathBuf,
    pub changed: Vec<PathBuf>,
    /// The parent's own verdict that the file set moved: an added,
    /// removed or renamed entry can resolve or unresolve *any* subject,
    /// so a narrowed cut is unsound and the whole project is re-derived.
    ///
    /// **Advisory (D-105).** It may only ever *add* a widening. A
    /// persistent file-set change outside the narrowing is exactly a
    /// disagreement between this cut's indexed set and the replaced
    /// generation's, outside the narrowing — which is what
    /// `previous_documents` is compared for, and a backend's event kinds
    /// cannot say more than that comparison can. The two things only this
    /// flag carries travel by their own routes: a change the backend
    /// coalesced away is `WatchBatch::missed`, which already turns the
    /// repair into a full cut, and the freshness of the newest generation
    /// is marked from the batch independently of this field.
    ///
    /// So the flag is trusted to widen and never trusted to hold: a
    /// backend that reports an in-place overwrite as a create must not
    /// cost the project a whole re-derivation, and a backend that stays
    /// silent about one is caught by the comparison instead.
    #[serde(default)]
    pub file_set_moved: bool,
    /// The documents the generation this cut replaces was indexed from.
    /// This is the *proof* a narrowing needs and an event list is not:
    /// a backend that coalesces a create or a delete away reports
    /// nothing to compare, and the comparison is what notices that a
    /// document outside the narrowing appeared or vanished. Empty when
    /// nothing was ever cut, which is also when a full build is the only
    /// cut there is.
    #[serde(default)]
    pub previous_documents: Vec<PathBuf>,
    pub limit: usize,
}

/// The versions both wire messages lead with, read before anything else.
#[derive(Deserialize)]
struct WireHeader {
    protocol: u32,
    crate_version: String,
}

/// The one message the worker writes on stdout.
#[derive(Serialize, Deserialize)]
struct WorkerEnvelope {
    protocol: u32,
    crate_version: String,
    body: WorkerBody,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum WorkerBody {
    Answer {
        result: QueryResult,
    },
    /// One derived project generation (SLICE-032): the edges it
    /// observed, its coverage, and the specifiers it could not place.
    Project {
        graph: ProjectGraph,
    },
    /// The engine's own typed refusal.
    Failed {
        code: ErrorCode,
        tag: String,
        message: String,
    },
    /// The worker would not serve the request at all.
    Refused {
        reason: WorkerRefusal,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WorkerRefusal {
    RequestRejected,
    Uncapped,
    EnvRejected,
}

/// The index-worker mode: reads one request from `input`, answers one
/// envelope on `output`. It serves only under a finite memory cap within
/// the bound and with nothing but the allowlisted environment; the
/// query runs on this thread under the request's deadline, re-clamped to
/// [`MAX_INDEX_PARSE_TIME`]. An answer past the request's cap is cut one
/// byte past it — the parent refuses it either way, and the pipe never
/// carries the tail.
///
/// # Errors
/// Returns the I/O error when the envelope cannot be encoded or written.
pub fn serve_index_worker(mut input: impl Read, mut output: impl Write) -> io::Result<()> {
    // The request is read — and an over-size one drained — before any
    // refusal, so the parent's write never meets a closed pipe.
    let mut bytes = Vec::new();
    (&mut input)
        .take(WORKER_REQUEST_MAX as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > WORKER_REQUEST_MAX {
        io::copy(&mut input, &mut io::sink())?;
    }
    let (body, answer_cap) = worker_answer(&bytes);
    let mut encoded = serde_json::to_vec(&WorkerEnvelope {
        protocol: WORKER_PROTOCOL,
        crate_version: env!("CARGO_PKG_VERSION").to_string(),
        body,
    })?;
    encoded.truncate(answer_cap.saturating_add(1));
    output.write_all(&encoded)?;
    output.flush()
}

/// The project files the index reads as project configuration — the
/// package root, the lock generation and the toolchain — rather than as
/// source documents it claims. They are inputs, so they are not counted
/// as uncovered coverage: a manifest no grammar claims is a fact about
/// the project, not a gap in the index.
const PROJECT_INPUT_FILES: &[&str] = &["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"];

/// The project index (SLICE-032): one bounded pass over the pinned root
/// that turns its admitted sources into the derived graph's inputs, and
/// one mechanical derivation per source. It never parses a tree — the
/// edges are lexical observations — and it never spawns anything: it
/// runs inside the worker, under the caller's deadline and the answer
/// cap.
///
/// `changed` narrows the derivation to the documents a coalesced watcher
/// batch reported. A batch that created or removed a file takes the
/// full path set: cross-file resolution depends on which files exist, so
/// a file set that moved re-derives everything — which is what makes an
/// incremental generation comparable with a full one.
fn project_index(
    request: &ProjectRequest,
    deadline: Instant,
) -> Result<ProjectGraph, ContextError> {
    let root = validate_project_root(&request.root)?;
    let mut files = Candidates::new(&root, IgnorePolicy::Respect, None);
    let enumerated: Vec<CandidateFile> = files.by_ref().collect();
    let mut sources = Vec::new();
    let mut unsupported = 0u64;
    let mut failed = files.failed;
    for file in &enumerated {
        if Grammar::for_path(&file.relative).is_none() {
            if !PROJECT_INPUT_FILES.contains(&file_name(&file.relative)) {
                unsupported += 1;
            }
            continue;
        }
        if Instant::now() >= deadline {
            failed += 1;
            continue;
        }
        match read_capped(&file.absolute, MAX_SYMBOL_FILE_BYTES) {
            Some((bytes, _)) => {
                // A document whose bytes are not UTF-8 states no relation
                // any admitted reader can scan. Admitting it and
                // scanning it would produce no rows and read as "this
                // document depends on nothing", so the decode is a
                // coverage failure counted with the unreadable entries —
                // never a silent skip.
                if std::str::from_utf8(&bytes).is_err() {
                    failed += 1;
                    continue;
                }
                let version = content_version(&bytes);
                sources.push(IndexedSource {
                    relative: file.relative.clone(),
                    bytes,
                    version,
                    ignored: file.ignored,
                });
            }
            None => failed += 1,
        }
    }
    let indexed: BTreeSet<PathBuf> = sources
        .iter()
        .map(|source| source.relative.clone())
        .collect();
    let inputs = DerivationInputs {
        files: &indexed,
        packages: &package_roots(&root, &enumerated),
    };
    let narrowed: BTreeSet<PathBuf> = request.changed.iter().cloned().collect();
    // A narrowing is sound only while the file set outside the
    // narrowing held still: an added or removed file can resolve or
    // unresolve *any* subject, so the carried rows would be placed
    // against targets the project no longer holds. Four things say it may
    // not be shown to have held, and the set comparison is the one that
    // decides (D-105):
    //
    // 1. the parent's own watch verdict, which may only ever add a
    //    widening — it is advisory, because an event kind is weaker
    //    evidence than the comparison below;
    // 2. a build that could not read everything it enumerated, which is
    //    disclosed as `EntriesFailed` either way;
    // 3. no previous set to compare against — a first-ever cut has
    //    nothing that says the rest of the project held still, and
    //    "cannot be shown" widens (FP-105-A);
    // 4. this enumeration disagreeing with the replaced generation's
    //    indexed set outside the narrowing, which is the authoritative
    //    check: a persistent create, remove or rename outside the
    //    narrowing is exactly that disagreement.
    let file_set_moved = request.file_set_moved
        || failed > 0
        || request.previous_documents.is_empty()
        || !file_set_held(&request.previous_documents, &indexed, &narrowed);
    let mut graph = ProjectGraph {
        edges: Vec::new(),
        completeness: Completeness::Complete,
        unresolved: Vec::new(),
        // Filled below with the set this cut actually re-derived, which
        // is the request's narrowing only when the cut kept it, and with
        // the file set the rows were cut from.
        narrowed_to: Vec::new(),
        documents: Vec::new(),
    };
    let mut reasons = Vec::new();
    for source in &sources {
        if !file_set_moved && !narrowed.is_empty() && !narrowed.contains(&source.relative) {
            continue;
        }
        let derived = derive_edges(source, &inputs);
        if graph.edges.len().saturating_add(derived.edges.len()) > request.limit {
            reasons.push(PartialReason::LimitReached {
                limit: request.limit,
            });
            break;
        }
        graph.unresolved.extend(derived.unresolved);
        graph.edges.extend(derived.edges);
    }
    if failed > 0 {
        reasons.push(PartialReason::EntriesFailed { count: failed });
    }
    if unsupported > 0 {
        reasons.push(PartialReason::UnsupportedLanguage { count: unsupported });
    }
    let unresolved = graph.unresolved.len() as u64;
    if unresolved > 0 {
        reasons.push(PartialReason::UnresolvedPaths { count: unresolved });
    }
    graph.edges.sort();
    graph.unresolved.sort();
    graph.unresolved.dedup();
    graph.completeness = Completeness::from_reasons(reasons);
    graph.documents = indexed.into_iter().collect();
    // The narrowing the answer reports is the one it kept: a cut that
    // widened itself states no narrowing, so the writer carries nothing
    // on top of rows it has already re-derived. The set is the
    // *narrowing*, not the documents that produced rows — a narrowed-to
    // path no admitted grammar claims (a lockfile, a manifest) yields no
    // edge and still has to be reported, or the writer would read the
    // cut as a full re-derivation and drop every carried row.
    graph.narrowed_to = if file_set_moved {
        Vec::new()
    } else {
        narrowed.iter().cloned().collect()
    };
    Ok(graph)
}

/// Whether the file set outside `narrowed` is the one the replaced
/// generation was cut from. A narrowing may only re-derive the
/// documents it names, so everything else must resolve to the same
/// files: a document that appeared or vanished outside the narrowing
/// changes some subject's placement, and the carried rows would be
/// wrong.
///
/// An empty `previous` is answered honestly rather than waved through:
/// there is no replaced generation, so there is nothing the rest of the
/// project can be shown to have matched, and this returns `false`. The
/// caller widens on an empty set for the same reason, and a second
/// `true` here would have been a way to read a narrowed first cut as a
/// sound one (FP-105-A).
fn file_set_held(
    previous: &[PathBuf],
    indexed: &BTreeSet<PathBuf>,
    narrowed: &BTreeSet<PathBuf>,
) -> bool {
    let outside = |set: &BTreeSet<PathBuf>| -> BTreeSet<PathBuf> {
        set.iter()
            .filter(|path| !narrowed.contains(*path))
            .cloned()
            .collect()
    };
    let was: BTreeSet<PathBuf> = previous
        .iter()
        .filter(|path| !narrowed.contains(*path))
        .cloned()
        .collect();
    outside(indexed) == was
}

/// The project root boundary a project build shares with every query:
/// it must resolve and be a directory, or the build is a typed refusal
/// naming the same cause a query would.
fn validate_project_root(root: &Path) -> Result<PathBuf, ContextError> {
    let canonical = root
        .canonicalize()
        .map_err(|source| ContextError::InvalidRoot {
            path: root.display().to_string(),
            source,
        })?;
    if !canonical.is_dir() {
        return Err(ContextError::RootNotDirectory {
            path: canonical.display().to_string(),
        });
    }
    Ok(canonical)
}

/// The file name of a project-relative path, or the empty string for a
/// path with none.
fn file_name(relative: &Path) -> &str {
    relative
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
}

/// Every package root the enumerated files sit under: a directory
/// holding a `Cargo.toml`, expressed project-relative. A file under no
/// package derives no module path, so its relations stay unknown rather
/// than being placed at the query root.
fn package_roots(root: &Path, files: &[CandidateFile]) -> BTreeSet<PathBuf> {
    let mut packages = BTreeSet::new();
    for file in files {
        let mut directory = file.absolute.parent();
        while let Some(current) = directory {
            if current.join("Cargo.toml").is_file() {
                if let Ok(relative) = current.strip_prefix(root) {
                    packages.insert(relative.to_path_buf());
                }
                break;
            }
            if current == root {
                break;
            }
            directory = current.parent();
        }
    }
    packages
}

/// The content-derived document version: a sha-256 prefix coerced
/// i32-positive — same bytes, same version, and a change under a pinned
/// version is detectably different. The identity the typed index stamps
/// too, so a graph row and a symbol row name one document version.
fn content_version(bytes: &[u8]) -> i32 {
    let digest = sha2::Sha256::digest(bytes);
    i32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) & i32::MAX
}

fn worker_answer(request: &[u8]) -> (WorkerBody, usize) {
    let refused = |reason| (WorkerBody::Refused { reason }, WORKER_ANSWER_MAX);
    if std::env::vars_os().any(|(key, _)| {
        !WORKER_ENV_ALLOWLIST
            .iter()
            .chain(SELF_SET_ENV)
            .any(|allowed| key == *allowed)
    }) {
        return refused(WorkerRefusal::EnvRejected);
    }
    if !memory_capped() {
        return refused(WorkerRefusal::Uncapped);
    }
    let Some(request) = serde_json::from_slice::<WireHeader>(request)
        .ok()
        .filter(|header| {
            header.protocol == WORKER_PROTOCOL && header.crate_version == env!("CARGO_PKG_VERSION")
        })
        .and_then(|_| serde_json::from_slice::<WorkerRequest>(request).ok())
    else {
        return refused(WorkerRefusal::RequestRejected);
    };
    // The wire value only narrows the deadline; it never widens it.
    let remaining = Duration::from_millis(request.deadline_ms).min(MAX_INDEX_PARSE_TIME);
    let now = Instant::now();
    let deadline = now.checked_add(remaining).unwrap_or(now);
    // Exactly one request kind, or the message is not one this worker
    // serves: a run that asks for both, or for neither, is refused
    // rather than answered with whichever half parsed.
    let body = match (request.query.as_ref(), request.project.as_ref()) {
        (Some(query), None) => match query_until(query, deadline) {
            Ok(result) => WorkerBody::Answer {
                result: without_unencodable_paths(result),
            },
            Err(error) => WorkerBody::Failed {
                code: error.error_code(),
                tag: error.tag().to_string(),
                message: error.to_string(),
            },
        },
        (None, Some(project)) => match project_index(project, deadline) {
            Ok(graph) => WorkerBody::Project {
                graph: without_unencodable_graph(graph),
            },
            Err(error) => WorkerBody::Failed {
                code: error.error_code(),
                tag: error.tag().to_string(),
                message: error.to_string(),
            },
        },
        _ => return refused(WorkerRefusal::RequestRejected),
    };
    (body, request.answer_cap.min(WORKER_ANSWER_MAX))
}

/// JSON has no spelling for a non-UTF-8 path, so an edge whose subject
/// or target is one cannot cross the envelope: it is dropped and the
/// entry counted as failed, making the generation honestly partial
/// instead of losing the whole envelope. The unit is the entry, not the
/// edge — one unencodable file with several relations still costs one
/// failed entry, which is what the coverage reports.
fn without_unencodable_graph(mut graph: ProjectGraph) -> ProjectGraph {
    let mut dropped: BTreeSet<PathBuf> = BTreeSet::new();
    graph.edges.retain(|edge| {
        let encodable = edge.from.path.to_str().is_some() && edge.to.path.to_str().is_some();
        if !encodable {
            dropped.insert(edge.from.path.clone());
        }
        encodable
    });
    graph.unresolved.retain(|path| {
        let encodable = path.to_str().is_some();
        if !encodable {
            dropped.insert(path.clone());
        }
        encodable
    });
    if dropped.is_empty() {
        return graph;
    }
    let mut reasons = match graph.completeness {
        Completeness::Complete => Vec::new(),
        Completeness::Partial { reasons } => reasons,
    };
    let failed = reasons.iter_mut().find_map(|reason| {
        if let PartialReason::EntriesFailed { count } = reason {
            Some(count)
        } else {
            None
        }
    });
    let dropped = dropped.len() as u64;
    match failed {
        Some(count) => *count = count.saturating_add(dropped),
        None => reasons.push(PartialReason::EntriesFailed { count: dropped }),
    }
    graph.completeness = Completeness::from_reasons(reasons);
    graph
}

/// JSON has no spelling for a non-UTF-8 path, so a match whose path is
/// one (Linux allows such entry names) cannot cross the envelope: it is
/// dropped and its entry counted as failed, making the answer honestly
/// partial instead of losing the whole envelope. The unit is the entry,
/// not the match — one unencodable file with several matching lines
/// still costs one failed entry, which is what the coverage reports.
/// Unresolved paths come from the UTF-8 request, so they always encode.
fn without_unencodable_paths(mut result: QueryResult) -> QueryResult {
    let mut dropped: BTreeSet<PathBuf> = BTreeSet::new();
    let mut encodable = |path: &Path| -> bool {
        let spelled = path.to_str().is_some();
        if !spelled {
            dropped.insert(path.to_path_buf());
        }
        spelled
    };
    result.matches.retain(|hit| encodable(&hit.source.path));
    if let Some(impact) = result.impact.as_mut() {
        impact.edges.retain(|edge| {
            let subject = encodable(&edge.from.path);
            let target = encodable(&edge.to.path);
            subject && target
        });
        impact.nodes.retain(|node| encodable(&node.document.path));
        if let Some(cursor) = impact.continuation.as_mut() {
            cursor
                .frontier
                .retain(|node| encodable(&node.document.path));
            cursor.visited.retain(|path| encodable(path));
        }
    }
    if dropped.is_empty() {
        return result;
    }
    let mut reasons = match result.completeness {
        Completeness::Complete => Vec::new(),
        Completeness::Partial { reasons } => reasons,
    };
    let failed = reasons.iter_mut().find_map(|reason| {
        if let PartialReason::EntriesFailed { count } = reason {
            Some(count)
        } else {
            None
        }
    });
    let dropped = dropped.len() as u64;
    match failed {
        Some(count) => *count = count.saturating_add(dropped),
        None => reasons.push(PartialReason::EntriesFailed { count: dropped }),
    }
    let completeness = Completeness::from_reasons(reasons);
    result.completeness = completeness.clone();
    if let Some(impact) = result.impact.as_mut() {
        // The slice and the envelope state one completeness; a dropped row
        // moves both, never one of them.
        impact.completeness = completeness;
    }
    result
}

/// Whether this process runs under a finite memory limit within the
/// worker bound — so a stale helper that ignored `--memory-budget`
/// never gets an uncapped parse (DEC-033). Linux caps the address space
/// at the budget itself; macOS caps it relative to the map measured at
/// launch, so the headroom left over this process's own map is what is
/// bounded (at most twice the budget, allowing for the exec'd image).
fn memory_capped() -> bool {
    let Ok(Some(limit)) = rivect_sandbox_helper::memory_limit() else {
        return false;
    };
    #[cfg(target_os = "macos")]
    {
        rivect_sandbox_helper::current_map_size().is_ok_and(|map| {
            limit.saturating_sub(map) <= 2 * rivect_sandbox_helper::INDEX_WORKER_MEMORY_BUDGET
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        limit <= rivect_sandbox_helper::INDEX_WORKER_MEMORY_BUDGET
    }
}

/// Boundary validation shared by every backend: a required pattern, a
/// positive bound, a scope glob only where it means something, and the
/// canonical scope root every walk and containment check runs against.
fn validate(request: &Query) -> Result<PathBuf, ContextError> {
    if request.pattern.is_empty() {
        return Err(ContextError::EmptyPattern {
            kind: request.kind.as_str(),
        });
    }
    if request.limit == 0 {
        return Err(ContextError::UnboundedLimit);
    }
    if request.scope_glob.is_some() && matches!(request.kind, QueryKind::Source) {
        return Err(ContextError::ScopeNotApplicable {
            kind: request.kind.as_str(),
        });
    }
    // The symbol leg's own fields are refused on every other kind —
    // silently ignored input would be a lie about what ran.
    if !matches!(request.kind, QueryKind::Symbol) {
        if request.symbol_op.is_some() {
            return Err(ContextError::SymbolFieldNotApplicable {
                field: "symbol_op",
                kind: request.kind.as_str(),
            });
        }
        if request.document.is_some() {
            return Err(ContextError::SymbolFieldNotApplicable {
                field: "document",
                kind: request.kind.as_str(),
            });
        }
    }
    let root = request
        .root
        .canonicalize()
        .map_err(|source| ContextError::InvalidRoot {
            path: request.root.display().to_string(),
            source,
        })?;
    if !root.is_dir() {
        return Err(ContextError::RootNotDirectory {
            path: request.root.display().to_string(),
        });
    }
    Ok(root)
}

/// A fresh result stamped with this build's honest snapshot: `Live`,
/// because no persisted generation store exists yet — inventing a
/// generation number would be a lie.
fn live_result(backend: SearchBackend) -> QueryResult {
    QueryResult {
        snapshot: SnapshotId::Live,
        backend,
        completeness: Completeness::Complete,
        matches: Vec::new(),
        unresolved: Vec::new(),
        impact: None,
    }
}

/// One deterministic pass over the scope. `Respect` applies the bundled
/// engine's standard filters (hidden, ignore files, git rules, parents);
/// `Include` disables only the ignore-rule family — hidden is not an
/// ignore rule and stays filtered. Symlinks are never followed under
/// either policy (the rg/fd default): a symlinked file surfaces under
/// neither `Respect` nor `Include`. Sorted so two runs enumerate
/// identically.
fn walker(root: &Path, ignore: IgnorePolicy) -> ignore::Walk {
    let mut builder = WalkBuilder::new(root);
    match ignore {
        IgnorePolicy::Respect => {
            builder.standard_filters(true);
        }
        IgnorePolicy::Include => {
            builder
                .hidden(true)
                .parents(false)
                .ignore(false)
                .git_ignore(false)
                .git_global(false)
                .git_exclude(false);
        }
    }
    builder.sort_by_file_path(|left, right| left.cmp(right));
    builder.build()
}

/// The set a `Respect` walk surfaces — the baseline an `Include` result
/// is flagged against: a hit absent from it is one the standard rules
/// would have excluded. Baseline walk errors count toward the query's
/// `EntriesFailed`, the same coverage they cost it.
fn visible_paths(root: &Path) -> (BTreeSet<PathBuf>, u64) {
    let mut visible = BTreeSet::new();
    let mut failed = 0u64;
    for entry in walker(root, IgnorePolicy::Respect) {
        match entry {
            Ok(entry) => {
                visible.insert(entry.into_path());
            }
            Err(_) => failed += 1,
        }
    }
    (visible, failed)
}

/// The `(visible, failed)` enumeration prelude every walking leg shares
/// (NOTE-001): `Respect` walks the filtered set directly; `Include`
/// materializes the standard-filters baseline up front so served rows
/// can be flagged, and baseline walk failures count toward the query's
/// `EntriesFailed` — the same coverage they cost it.
fn enumeration_baseline(root: &Path, ignore: IgnorePolicy) -> (Option<BTreeSet<PathBuf>>, u64) {
    match ignore {
        IgnorePolicy::Respect => (None, 0),
        IgnorePolicy::Include => {
            let (paths, failed) = visible_paths(root);
            (Some(paths), failed)
        }
    }
}

/// The `ignored` flag's verdict for one served path: `true` when a
/// `Respect` enumeration of the same root never surfaces `target` — the
/// standard filters would have excluded it. Only `target`'s ancestor
/// chain can carry rules that filter it, so the walk is pruned to that
/// chain — each ancestor level still pays its sibling listing, but the
/// rest of the tree is never entered. `target` is canonical and
/// the walker never descends a symlinked dir, so every yielded entry is
/// already spelled resolved and a direct compare cannot be mislabeled
/// by a symlinked component. `failed` counts entries the pruned walk
/// could not read — the caller folds them into `EntriesFailed`, the
/// same accounting the Text/Path legs report.
fn filtered_by_standard_rules(root: &Path, target: &Path) -> (bool, u64) {
    let mut builder = WalkBuilder::new(root);
    builder.standard_filters(true);
    let needle = target.to_path_buf();
    builder.filter_entry(move |entry| needle.starts_with(entry.path()));
    let mut failed = 0u64;
    for entry in builder.build() {
        let Ok(entry) = entry else {
            failed += 1;
            continue;
        };
        if entry.path() == target {
            return (false, failed);
        }
    }
    (true, failed)
}

/// The caller's scope restriction, compiled — a malformed glob is a
/// caller error before any candidate is enumerated.
fn scope_matcher(request: &Query) -> Result<Option<GlobMatcher>, ContextError> {
    match &request.scope_glob {
        Some(glob) => Ok(Some(
            Glob::new(glob)
                .map_err(|source| ContextError::InvalidGlob {
                    glob: glob.clone(),
                    source,
                })?
                .compile_matcher(),
        )),
        None => Ok(None),
    }
}

/// The ignore/scope-filtered file candidates the ast and symbol legs
/// share: regular files only, each flagged `ignored` against the
/// `Include` baseline. The caller compiles the scope glob first, so a
/// malformed glob is refused before any baseline walk runs; walk
/// failures accumulate in `failed` as the iterator advances.
struct Candidates<'r> {
    root: &'r Path,
    walk: ignore::Walk,
    scope: Option<GlobMatcher>,
    visible: Option<BTreeSet<PathBuf>>,
    failed: u64,
}

impl<'r> Candidates<'r> {
    fn new(root: &'r Path, ignore: IgnorePolicy, scope: Option<GlobMatcher>) -> Self {
        let (visible, failed) = enumeration_baseline(root, ignore);
        Self {
            root,
            walk: walker(root, ignore),
            scope,
            visible,
            failed,
        }
    }
}

impl Iterator for Candidates<'_> {
    type Item = CandidateFile;

    fn next(&mut self) -> Option<CandidateFile> {
        for entry in self.walk.by_ref() {
            let Ok(entry) = entry else {
                self.failed += 1;
                continue;
            };
            if !entry.file_type().is_some_and(|kind| kind.is_file()) {
                continue;
            }
            let Ok(relative) = entry.path().strip_prefix(self.root) else {
                // The walker only yields root-joined paths — a strip
                // failure cannot happen; the entry is skipped rather
                // than guessed at.
                continue;
            };
            if let Some(scope) = &self.scope
                && !scope.is_match(relative)
            {
                continue;
            }
            let ignored = self
                .visible
                .as_ref()
                .is_some_and(|set| !set.contains(entry.path()));
            return Some(CandidateFile {
                absolute: entry.path().to_path_buf(),
                relative: relative.to_path_buf(),
                ignored,
            });
        }
        None
    }
}

/// A bare name (no separator, no glob metas) means "this name anywhere
/// in the scope" — `**/name`; a pattern carrying structure is used
/// verbatim. The normalization is mechanical, never a guess.
fn has_glob_structure(pattern: &str) -> bool {
    pattern.contains('/') || pattern.contains(['*', '?', '[', ']', '{', '}', '\\'])
}

/// Per-file search over the engine's own `Matcher` bound — the seam
/// `grep-matcher` supplies (SRC-008); the searcher consumes `&M`, so one
/// compiled matcher serves the whole walk.
fn search_file<M, F>(
    searcher: &mut Searcher,
    matcher: &M,
    path: &Path,
    on_match: F,
) -> Result<(), io::Error>
where
    M: Matcher,
    F: FnMut(u64, &[u8]) -> Result<bool, io::Error>,
{
    searcher.search_path(matcher, path, Bytes(on_match))
}

/// Text leg: regex over content lines, ignore/scope-filtered walk, the
/// caller's bound honored — a hit beyond the bound marks the result
/// partial instead of silently dropping the tail.
fn text_query(request: &Query, root: &Path) -> Result<QueryResult, ContextError> {
    // A caller-supplied regex gets an explicit budget — compiled
    // program, lazy DFA and parse depth — so a hostile pattern fails
    // typed instead of burning memory.
    let matcher = RegexMatcherBuilder::new()
        .size_limit(4 * 1024 * 1024)
        .dfa_size_limit(32 * 1024 * 1024)
        .nest_limit(100)
        .build(&request.pattern)
        .map_err(|source| ContextError::InvalidTextPattern {
            pattern: request.pattern.clone(),
            source,
        })?;
    let scope = scope_matcher(request)?;
    let mut result = live_result(SearchBackend::Text);
    // Raw file bytes only — BOM sniffing would strip a UTF-8 BOM or
    // transcode UTF-16, and `line_bytes` carries the file's own bytes.
    // Binary detection is pinned off (the crate default, made explicit):
    // a NUL must never silently truncate coverage — binary hits are
    // real matches (REQ-027).
    let mut searcher = SearcherBuilder::new()
        .line_number(true)
        .bom_sniffing(false)
        .binary_detection(BinaryDetection::none())
        // One line may not grow the line buffer past this bound: an
        // oversized line fails the file's search as an io error —
        // counted EntriesFailed, an honest Partial — instead of
        // unbounded buffer growth on hostile input.
        .heap_limit(Some(64 * 1024 * 1024))
        .build();
    let mut truncated = false;

    let (visible, mut failed) = enumeration_baseline(root, request.ignore);

    for entry in walker(root, request.ignore) {
        let Ok(entry) = entry else {
            failed += 1;
            continue;
        };
        if !entry.file_type().is_some_and(|kind| kind.is_file()) {
            continue;
        }
        let Ok(relative) = entry.path().strip_prefix(root) else {
            // The walker only yields root-joined paths — a strip failure
            // cannot happen; the entry is skipped rather than guessed at.
            continue;
        };
        if let Some(scope) = &scope
            && !scope.is_match(relative)
        {
            continue;
        }
        let ignored = visible
            .as_ref()
            .is_some_and(|set| !set.contains(entry.path()));
        let searched = search_file(&mut searcher, &matcher, entry.path(), |line, bytes| {
            if result.matches.len() >= request.limit {
                truncated = true;
                return Ok(false);
            }
            result.matches.push(SearchMatch {
                source: SourceRef {
                    path: relative.to_path_buf(),
                    line: Some(line),
                    ignored,
                },
                kind: MatchKind::Text {
                    line_bytes: bytes.to_vec(),
                },
            });
            Ok(true)
        });
        if searched.is_err() {
            failed += 1;
        }
        if truncated {
            break;
        }
    }

    let mut reasons = Vec::new();
    if truncated {
        reasons.push(PartialReason::LimitReached {
            limit: request.limit,
        });
    }
    if failed > 0 {
        reasons.push(PartialReason::EntriesFailed { count: failed });
    }
    result.completeness = Completeness::from_reasons(reasons);
    Ok(result)
}

/// Path leg: glob over scope-relative paths — identity only, content is
/// never opened, so the hit is proof the file exists in scope.
fn path_query(request: &Query, root: &Path) -> Result<QueryResult, ContextError> {
    let pattern = if has_glob_structure(&request.pattern) {
        request.pattern.clone()
    } else {
        format!("**/{}", request.pattern)
    };
    let matcher = Glob::new(&pattern)
        .map_err(|source| ContextError::InvalidGlob {
            glob: pattern.clone(),
            source,
        })?
        .compile_matcher();
    let scope = scope_matcher(request)?;
    let mut result = live_result(SearchBackend::Path);
    let mut truncated = false;
    let (visible, mut failed) = enumeration_baseline(root, request.ignore);

    for entry in walker(root, request.ignore) {
        let Ok(entry) = entry else {
            failed += 1;
            continue;
        };
        if !entry.file_type().is_some_and(|kind| kind.is_file()) {
            continue;
        }
        let Ok(relative) = entry.path().strip_prefix(root) else {
            continue;
        };
        if !matcher.is_match(relative) {
            continue;
        }
        if let Some(scope) = &scope
            && !scope.is_match(relative)
        {
            continue;
        }
        if result.matches.len() >= request.limit {
            truncated = true;
            break;
        }
        let ignored = visible
            .as_ref()
            .is_some_and(|set| !set.contains(entry.path()));
        result.matches.push(SearchMatch {
            source: SourceRef {
                path: relative.to_path_buf(),
                line: None,
                ignored,
            },
            kind: MatchKind::Path,
        });
    }

    let mut reasons = Vec::new();
    if truncated {
        reasons.push(PartialReason::LimitReached {
            limit: request.limit,
        });
    }
    if failed > 0 {
        reasons.push(PartialReason::EntriesFailed { count: failed });
    }
    result.completeness = Completeness::from_reasons(reasons);
    Ok(result)
}

/// The path stayed unresolved — it is named on the result and the
/// answer reports itself partial, never absent, never complete. It
/// replaces `result.completeness` outright: the contract is a fresh
/// result at the leg's single call site, not a merge onto reasons
/// another path may already have set.
fn mark_unresolved(result: &mut QueryResult, relative: &Path) {
    result.unresolved.push(relative.to_path_buf());
    result.completeness = Completeness::from_reasons(vec![PartialReason::UnresolvedPaths {
        count: result.unresolved.len() as u64,
    }]);
}

/// The legs' shared bounded read: regular files only — a directory,
/// fifo, device or unreadable entry returns `None` so the caller
/// discloses a failed entry instead of hanging a blocking `open` on a
/// special file. The `cap + 1` read makes `len > cap` the exact
/// over-bound proof — the tail is never hauled into memory to be sliced
/// away; the caller decides whether over-bound truncates (`Source`) or
/// fails the entry (`Ast`/`Symbol`). The metadata is the opened
/// handle's — the file whose bytes are read, never a path swapped in
/// between — and it is taken before the read: a write racing the read
/// lands after the stamp, so a freshness check sees it as stale. Taken
/// after, the stamp could describe the new bytes over a read of the
/// old ones and the change would never be noticed.
pub(crate) fn read_capped(target: &Path, cap: u64) -> Option<(Vec<u8>, std::fs::Metadata)> {
    if !target.metadata().is_ok_and(|meta| meta.is_file()) {
        return None;
    }
    let mut file = File::open(target).ok()?;
    let meta = file.metadata().ok()?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    Some((bytes, meta))
}

/// Source leg: the exact bytes of one named, root-contained file. A
/// path that does not resolve stays named in `unresolved`; an escape
/// outside the root is a boundary denial; a resolved entry that cannot
/// be served — special file or read error — is a failed entry, and a
/// read past the byte cap is partial.
fn source_query(request: &Query, root: &Path) -> Result<QueryResult, ContextError> {
    let relative = Path::new(&request.pattern);
    let mut result = live_result(SearchBackend::Source);
    // Canonicalizing resolves `.`/`..`/links — what cannot be resolved
    // is reported unknown, and what resolves outside the root is denied.
    // TOCTOU: a symlink swapped between this check and the open in
    // `read_capped` can still redirect the read outside the root, and a
    // regular file swapped for a fifo or device in the same
    // `metadata`→`open` window hangs the blocking `File::open` — the
    // recorded fix covers both (handle-relative I/O, openat/cap-std or
    // O_NONBLOCK + fstat), out of scope this build.
    let Ok(target) = root.join(relative).canonicalize() else {
        mark_unresolved(&mut result, relative);
        return Ok(result);
    };
    if !target.starts_with(root) {
        return Err(ContextError::EscapedRoot {
            path: request.pattern.clone(),
        });
    }
    // The served path is reported root-relative and normalized — the
    // caller's `.`/`..` spelling is never echoed back.
    let provenance = target
        .strip_prefix(root)
        .map_or_else(|_| target.clone(), Path::to_path_buf);
    let Some((mut bytes, _)) = read_capped(&target, request.limit as u64) else {
        // Resolved inside the root but not serveable — a directory,
        // fifo or unreadable file is a coverage failure, not "unknown".
        result.completeness =
            Completeness::from_reasons(vec![PartialReason::EntriesFailed { count: 1 }]);
        return Ok(result);
    };
    let (ignored, failed) = filtered_by_standard_rules(root, &target);
    let mut reasons = Vec::new();
    if bytes.len() > request.limit {
        reasons.push(PartialReason::LimitReached {
            limit: request.limit,
        });
        bytes.truncate(request.limit);
    }
    if failed > 0 {
        reasons.push(PartialReason::EntriesFailed { count: failed });
    }
    result.matches.push(SearchMatch {
        source: SourceRef {
            path: provenance,
            line: None,
            ignored,
        },
        kind: MatchKind::Source { bytes },
    });
    result.completeness = Completeness::from_reasons(reasons);
    Ok(result)
}

/// Graph leg (AC-034): the impact traversal of one named document over
/// the project's derived rows. The answer is the documents that depend on
/// the named one, the real directed rows that reached them, its own
/// incompleteness and the cursor that resumes it.
///
/// The rows are the project index's own derivation, so a caller traverses
/// what a stored generation records. A document the graph does not hold
/// stays named in `unresolved` rather than being reported as a document
/// nothing depends on. The walk's wall allowance is the ceiling every
/// index leg runs under, and the request's deadline bounds the derivation
/// that feeds it.
fn graph_query(
    request: &Query,
    root: &Path,
    deadline: Instant,
) -> Result<QueryResult, ContextError> {
    let relative = Path::new(&request.pattern);
    let mut result = live_result(SearchBackend::Graph);
    // The seed resolves like `source.slice`: what cannot be resolved stays
    // named in `unresolved`, and a path that resolves outside the root is
    // denied.
    let Ok(target) = root.join(relative).canonicalize() else {
        mark_unresolved(&mut result, relative);
        return Ok(result);
    };
    if !target.starts_with(root) {
        return Err(ContextError::EscapedRoot {
            path: request.pattern.clone(),
        });
    }
    let document = target
        .strip_prefix(root)
        .map_or_else(|_| target.clone(), Path::to_path_buf);
    let graph = project_index(
        &ProjectRequest {
            root: root.to_path_buf(),
            changed: Vec::new(),
            file_set_moved: false,
            previous_documents: Vec::new(),
            limit: request.limit,
        },
        deadline,
    )?;
    if !graph.documents.contains(&document) {
        mark_unresolved(&mut result, &document);
        return Ok(result);
    }
    result.unresolved = graph.unresolved.clone();
    let slice = impact_traversal(
        &graph,
        &[SourceRef {
            path: document,
            line: None,
            // The graph indexes under the standard filters, so a document
            // it holds surfaced through them: the seed's flag is that
            // fact, not a second walk of the tree.
            ignored: false,
        }],
        TraversalLimits {
            // A walk cannot be deeper than the documents that bound it, so
            // the caller's own bound is the depth bound too.
            depth: request.limit,
            nodes: request.limit,
            time: MAX_INDEX_PARSE_TIME,
        },
    );
    // The envelope states the slice's own completeness, so a reader that
    // never opens `impact` still sees that the answer stopped short.
    result.completeness = slice.completeness.clone();
    result.impact = Some(Box::new(slice));
    Ok(result)
}

// ----- structural search (SRC-007) -----

/// One admitted grammar — claimed only while the corpus leg proves it
/// (`grammar_corpus_cases_pass_per_claimed_language`). `for_path`
/// mirrors the engine's own extension mapping: `rs`; `ts`, `cts`,
/// `mts`; `tsx`. A file whose language no grammar claims is a coverage
/// gap the result must disclose — never a silently skipped candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Grammar {
    Rust,
    TypeScript,
    Tsx,
}

impl Grammar {
    /// The admitted set in fixed order so pattern-compile detail and
    /// coverage accounting are deterministic.
    const ALL: [Self; 3] = [Self::Rust, Self::TypeScript, Self::Tsx];

    /// The grammar a path claims — file extension only, never content
    /// sniffing: the result says exactly which files no grammar covers.
    /// `pub(crate)` for the typed symbol index, which claims files by
    /// the same rule (DEC-005).
    pub(crate) fn for_path(path: &Path) -> Option<Self> {
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("rs") => Some(Self::Rust),
            Some("ts" | "cts" | "mts") => Some(Self::TypeScript),
            Some("tsx") => Some(Self::Tsx),
            _ => None,
        }
    }

    /// The name a match reports — the grammar identity a syntax shape
    /// carries instead of a symbol claim.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::TypeScript => "typescript",
            Self::Tsx => "tsx",
        }
    }

    /// The tree-sitter grammar behind the claim.
    pub(crate) fn ts_language(self) -> TSLanguage {
        match self {
            Self::Rust => tree_sitter_rust::LANGUAGE.into(),
            Self::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Self::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        }
    }
}

impl Language for Grammar {
    fn kind_to_id(&self, kind: &str) -> u16 {
        self.ts_language().id_for_node_kind(kind, true)
    }

    fn field_to_id(&self, field: &str) -> Option<u16> {
        self.ts_language()
            .field_id_for_name(field)
            .map(|id| id.get())
    }

    fn build_pattern(&self, builder: &PatternBuilder<'_>) -> Result<Pattern, PatternError> {
        builder.build(|src| StrDoc::try_new(src, *self))
    }

    /// The parser-facing sigil: tree-sitter-rust has no `$` inside
    /// identifiers, so the pattern's meta-var sigil runs are rewritten
    /// to `µ` — a char its Unicode identifier rule accepts — before the
    /// grammar ever sees them. TypeScript grammars take `$` verbatim.
    fn expando_char(&self) -> char {
        match self {
            Self::Rust => 'µ',
            Self::TypeScript | Self::Tsx => '$',
        }
    }

    fn pre_process_pattern<'q>(&self, query: &'q str) -> Cow<'q, str> {
        match self {
            Self::Rust => expando_rewrite(query, self.expando_char()),
            Self::TypeScript | Self::Tsx => Cow::Borrowed(query),
        }
    }
}

impl LanguageExt for Grammar {
    fn get_ts_language(&self) -> TSLanguage {
        self.ts_language()
    }
}

/// The vendored `ast-grep-language` expando loop, ported verbatim: a
/// `$`/`$$`/`$$$` run rewrites to the expando char only when it is a
/// meta-var sigil — followed by an `[A-Z_]` name char, or a bare `$$$`
/// (anonymous multiple). Every other `$` stays literal: a blanket
/// replace would corrupt Rust patterns carrying real dollars (`'$'`,
/// `"$schema"`, `macro_rules!` transcribers `$(`/`$i`) into silent
/// under-matches reported complete.
fn expando_rewrite(query: &str, expando: char) -> Cow<'_, str> {
    let mut ret = Vec::with_capacity(query.len());
    let mut dollar_count = 0;
    for c in query.chars() {
        if c == '$' {
            dollar_count += 1;
            continue;
        }
        let need_replace = matches!(c, 'A'..='Z' | '_') // $A or $$A or $$$A
            || dollar_count == 3; // anonymous multiple
        let sigil = if need_replace { expando } else { '$' };
        ret.extend(std::iter::repeat_n(sigil, dollar_count));
        dollar_count = 0;
        ret.push(c);
    }
    // trailing anonymous multiple
    let sigil = if dollar_count == 3 { expando } else { '$' };
    ret.extend(std::iter::repeat_n(sigil, dollar_count));
    Cow::Owned(ret.into_iter().collect())
}

/// `Pattern::has_error` inspects only the pattern root's kind — an
/// ERROR node nested under a valid wrapper (`fn f() { let x = ; }`)
/// survives it. Walk the compiled tree: any error-kind node means the
/// pattern is not valid syntax under this grammar — the same verdict
/// the root check renders.
fn pattern_has_error_nodes(pattern: &Pattern) -> bool {
    fn node_has_error(node: &PatternNode) -> bool {
        match node {
            PatternNode::MetaVar { .. } => false,
            PatternNode::Terminal { kind_id, .. } => kind_utils::is_error_kind(*kind_id),
            PatternNode::Internal { kind_id, children } => {
                kind_utils::is_error_kind(*kind_id) || children.iter().any(node_has_error)
            }
        }
    }
    node_has_error(&pattern.node)
}

/// The largest single file the leg reads whole — the same order as the
/// text leg's per-line heap bound: a giant generated source is a failed
/// entry, never an unbounded read. The bound is on bytes, not on parse
/// cost: tree-sitter's GLR recovery can grow time and memory without
/// limit on far smaller hostile input (TypeScript `x<y,` repeated:
/// 32 KiB took 1.13 GB here), and nothing in-process stops it — the
/// wiring slice must isolate this parse in a resource-limited child
/// process (DEC-028, NOTE-003). The typed symbol index parses under its
/// own, tighter bound (`MAX_SYMBOL_FILE_BYTES`); its unparsed
/// literal-hint scan reads under this one.
pub(crate) const MAX_AST_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// The largest pattern the leg compiles: `Pattern::try_new`,
/// `pattern_has_error_nodes` and the `PatternNode` drop all recurse
/// once per pattern-tree nesting level, and the worst case costs one
/// byte per level — unary prefix/postfix chains (`!`×N, `x?`×N) — so
/// the byte bound IS the frame bound: 1024 caps recursion near 1K
/// frames — about a 1 MiB stack under release codegen, inside the
/// 2 MiB floor the wiring surface runs on (INV-011). The margin is
/// release-calibrated: debug frames run ~2-3 KiB, so the wiring
/// surface must either spawn the worker on an explicit stack or
/// tighten the bound — 1024 is not blanket-safe on a 2 MiB stack
/// (NOTE-002).
const MAX_AST_PATTERN_BYTES: usize = 1024;

/// Ast leg: the caller's ast-grep pattern compiled once per admitted
/// grammar — the pattern's own syntax decides which languages it can
/// speak, and a pattern no grammar parses is a caller error, never an
/// empty result. The walk is the same ignore/scope-filtered pass the
/// other legs run. A candidate the compiled pattern cannot cover — no
/// admitted grammar for its language, or the pattern is not valid
/// syntax under that grammar — is counted `UnsupportedLanguage`; a
/// file whose tree carries error or missing nodes still serves its
/// intact subtrees but is disclosed `ParseErrors`; a file that cannot
/// be read, decoded or parsed at all is a failed entry. The caller's
/// bound truncates like every other leg — partial, not dropped.
fn ast_query(request: &Query, root: &Path) -> Result<QueryResult, ContextError> {
    // Pattern compilation recurses per pattern-tree depth — the byte
    // bound keeps worst-case nesting far under the stack limit instead
    // of an uncatchable overflow.
    if request.pattern.len() > MAX_AST_PATTERN_BYTES {
        return Err(ContextError::AstPatternTooLarge {
            limit: MAX_AST_PATTERN_BYTES,
        });
    }
    let mut compiled = Vec::with_capacity(Grammar::ALL.len());
    let mut failures = Vec::new();
    for grammar in Grammar::ALL {
        match Pattern::try_new(&request.pattern, grammar) {
            // A pattern whose tree parses into error nodes — at the
            // root or nested inside a valid wrapper — is not valid
            // syntax under this grammar: the grammar does not claim it.
            Ok(pattern) if !pattern_has_error_nodes(&pattern) => {
                compiled.push((grammar, pattern));
            }
            Ok(_) => failures.push(format!(
                "{}: the pattern parses to error nodes",
                grammar.name()
            )),
            Err(source) => failures.push(format!("{}: {source}", grammar.name())),
        }
    }
    if compiled.is_empty() {
        return Err(ContextError::InvalidAstPattern {
            pattern: request.pattern.clone(),
            languages: Grammar::ALL
                .iter()
                .map(|grammar| grammar.name())
                .collect::<Vec<_>>()
                .join(", "),
            // Source strings can carry their own terminal punctuation —
            // the contract error keeps the lowercase/no-punct shape.
            detail: failures
                .join("; ")
                .trim_end_matches(['.', '!', '?', ';'])
                .to_string(),
        });
    }

    let mut files = Candidates::new(root, request.ignore, scope_matcher(request)?);
    let mut result = live_result(SearchBackend::Ast);
    let mut truncated = false;
    let mut uncovered = 0u64;
    let mut damaged = 0u64;
    let mut failed = 0u64;

    for file in files.by_ref() {
        let relative = file.relative.as_path();
        let ignored = file.ignored;
        // A candidate the compiled pattern cannot cover — no admitted
        // grammar for its language, or the pattern is not valid syntax
        // under that grammar — is counted, never silently skipped.
        let Some(grammar) = Grammar::for_path(relative) else {
            uncovered += 1;
            continue;
        };
        let Some((_, pattern)) = compiled.iter().find(|(claimed, _)| *claimed == grammar) else {
            uncovered += 1;
            continue;
        };
        // Read/UTF-8/parse failures mean this file could not be searched
        // — a failed entry, the same accounting the text leg reports.
        // The size bound rides on the opened handle (`read_capped`):
        // `open` → `take(bound + 1)` → `read_to_end` closes the
        // check-then-act window a `metadata().len()` → `fs::read` pair
        // leaves — a file grown or swapped between the two syscalls
        // would defeat the cap. An oversized entry fails without being
        // parsed: a truncated file yields wrong matches.
        let Some((bytes, _)) = read_capped(&file.absolute, MAX_AST_FILE_BYTES) else {
            failed += 1;
            continue;
        };
        if bytes.len() as u64 > MAX_AST_FILE_BYTES {
            failed += 1;
            continue;
        }
        let Ok(source) = String::from_utf8(bytes) else {
            failed += 1;
            continue;
        };
        // Unbounded in-process on hostile input (see MAX_AST_FILE_BYTES):
        // no runtime caller may reach this parse un-isolated (DEC-028).
        let Ok(ast) = AstGrep::<StrDoc<Grammar>>::try_new(&source, grammar) else {
            failed += 1;
            continue;
        };
        if ast
            .root()
            .dfs()
            .any(|node| node.is_error() || node.is_missing())
        {
            damaged += 1;
        }
        for hit in ast.root().find_all(pattern) {
            if result.matches.len() >= request.limit {
                truncated = true;
                break;
            }
            let node = hit.get_node();
            let span = node.range();
            result.matches.push(SearchMatch {
                source: SourceRef {
                    path: relative.to_path_buf(),
                    // The facade reports 1-based lines; tree-sitter
                    // positions are 0-based.
                    line: Some(node.start_pos().line() as u64 + 1),
                    ignored,
                },
                kind: MatchKind::Ast {
                    language: grammar.name().to_string(),
                    node_kind: node.kind().into_owned(),
                    start_byte: span.start as u64,
                    end_byte: span.end as u64,
                },
            });
        }
        if truncated {
            break;
        }
    }

    let failed = failed + files.failed;
    let mut reasons = Vec::new();
    if truncated {
        reasons.push(PartialReason::LimitReached {
            limit: request.limit,
        });
    }
    if failed > 0 {
        reasons.push(PartialReason::EntriesFailed { count: failed });
    }
    if uncovered > 0 {
        reasons.push(PartialReason::UnsupportedLanguage { count: uncovered });
    }
    if damaged > 0 {
        reasons.push(PartialReason::ParseErrors { count: damaged });
    }
    result.completeness = Completeness::from_reasons(reasons);
    Ok(result)
}

// ----- semantic symbol navigation (DEC-005) -----

/// The largest symbol pattern the leg accepts — the same bound as the
/// ast leg's, so no caller string sizes the per-row name compare or the
/// per-line fallback scan.
const MAX_SYMBOL_PATTERN_BYTES: usize = 1024;

/// Symbol leg: the typed in-process index over the admitted grammars —
/// definition/reference/type rows carrying the document's LSP identity
/// (uri/version/encoding/root), never a language-server subprocess. The
/// walk is the same ignore/scope-filtered pass the other legs run; a
/// file no grammar claims is counted `UnsupportedLanguage` and joins
/// the literal-hint fallback (labelled `MatchKind::Text`, non-exact by
/// construction — never a reference). The index is rebuilt from a live
/// scan per query, so the result is stamped `Live`; document identity
/// rides each row's `version`. A pinned document resolves like
/// `source.slice` — escapes are denied — and must name an indexed
/// document: otherwise it is reported `unresolved` (or `EntriesFailed`
/// when it was claimed but failed), or refused when a version was
/// pinned, since that version cannot be verified. A version pin that
/// does not match the indexed version is a typed conflict — a stale
/// document is never served as current (AC-039a).
fn symbol_query(
    request: &Query,
    root: &Path,
    deadline: Instant,
) -> Result<QueryResult, ContextError> {
    let Some(op) = request.symbol_op else {
        return Err(ContextError::SymbolOpRequired);
    };
    if request.pattern.len() > MAX_SYMBOL_PATTERN_BYTES {
        return Err(ContextError::SymbolPatternTooLarge {
            limit: MAX_SYMBOL_PATTERN_BYTES,
        });
    }
    // The pin's declared encoding is a request-shape fact — refused
    // before any filesystem work, naming only encodings LSP defines.
    if let Some(pin) = &request.document
        && let Some(encoding) = &pin.encoding
        && *encoding != PositionEncodingKind::UTF8
    {
        let encoding = if *encoding == PositionEncodingKind::UTF16 {
            "utf-16"
        } else if *encoding == PositionEncodingKind::UTF32 {
            "utf-32"
        } else {
            "unrecognized"
        };
        return Err(ContextError::UnsupportedPositionEncoding { encoding });
    }

    // `scope::name` — the qualifier splits at the LAST `::` so
    // `a::b::helper` addresses scope `a::b`.
    let (qualified_scope, name) = match request.pattern.rsplit_once("::") {
        Some((scope, name)) => (Some(scope), name),
        None => (None, request.pattern.as_str()),
    };
    if name.is_empty() {
        return Err(ContextError::EmptyPattern {
            kind: request.kind.as_str(),
        });
    }
    // A malformed glob is a caller error before the pin or any walk.
    let scope = scope_matcher(request)?;

    // The document pin resolves like `source.slice`: canonicalize and
    // deny escapes. What cannot be resolved — or cannot be a URI —
    // names no LSP document and is settled before any walk.
    let mut document_uri = None;
    if let Some(pin) = &request.document {
        match root.join(&pin.path).canonicalize() {
            Ok(target) if target.starts_with(root) => {
                document_uri = path_to_uri(&target);
            }
            Ok(_) => {
                return Err(ContextError::EscapedRoot {
                    path: pin.path.display().to_string(),
                });
            }
            Err(_) => {}
        }
        if document_uri.is_none() {
            return unindexed_pin(pin);
        }
    }

    let mut files = Candidates::new(root, request.ignore, scope);
    let index = SymbolIndex::build(
        root,
        files.by_ref(),
        SymbolRequest {
            name,
            scope: qualified_scope,
            op,
            document: document_uri.as_ref(),
            limit: request.limit,
        },
        Some(deadline),
    );

    // A pin must name an indexed document, and a version pin binds only
    // when it equals the indexed version — serving another version's
    // rows under the pin is the stale-version lie; refusing is honest.
    if let (Some(pin), Some(uri)) = (&request.document, &document_uri) {
        let Some(document) = index.document(uri) else {
            return if index.pin_failed() {
                failed_pin(pin)
            } else {
                unindexed_pin(pin)
            };
        };
        if let Some(pinned) = pin.version
            && pinned != document.version
        {
            return Err(ContextError::StaleDocumentVersion {
                path: pin.path.display().to_string(),
                pinned,
                actual: document.version,
            });
        }
    }

    let answer = index.answer();
    let mut result = live_result(SearchBackend::Symbol);
    result.matches = answer.matches;
    let mut reasons = Vec::new();
    if answer.truncated {
        reasons.push(PartialReason::LimitReached {
            limit: request.limit,
        });
    }
    let unpinned = request.document.is_none();
    if unpinned || op == SymbolOp::Type {
        // The answer draws on every document — a pinned type answer may
        // serve any document's candidates — so, as with staleness, a
        // document that failed or is damaged anywhere may hide a row. An
        // unclaimed file the hint scan (unpinned only) could not read is
        // a failed entry — counted under that one reason, not also as
        // uncovered.
        let failed = files.failed + index.coverage.failed + answer.unreadable_fallback;
        if failed > 0 {
            reasons.push(PartialReason::EntriesFailed { count: failed });
        }
        if unpinned {
            let unsupported = index
                .coverage
                .unsupported
                .saturating_sub(answer.unreadable_fallback);
            if unsupported > 0 {
                reasons.push(PartialReason::UnsupportedLanguage { count: unsupported });
            }
        }
        if index.coverage.damaged > 0 {
            reasons.push(PartialReason::ParseErrors {
                count: index.coverage.damaged,
            });
        }
    } else if answer.damaged_documents > 0 {
        // A pinned answer is about one indexed document: coverage gaps
        // elsewhere cannot hide its rows — they only leave some edges
        // `resolved: false`, which is already unknown. What it serves
        // is disclosed: damage in the pinned document or in any
        // document a served row comes from.
        reasons.push(PartialReason::ParseErrors {
            count: answer.damaged_documents,
        });
    }
    if answer.stale_documents > 0 {
        reasons.push(PartialReason::StaleDocuments {
            count: answer.stale_documents,
        });
    }
    if answer.unknown_module_paths > 0 {
        reasons.push(PartialReason::UnknownModulePaths {
            count: answer.unknown_module_paths,
        });
    }
    result.completeness = Completeness::from_reasons(reasons);
    Ok(result)
}

/// A version pinned on a document the index does not hold cannot be
/// verified — that request is refused rather than answered without its
/// version.
fn refuse_unverifiable(pin: &DocumentPin) -> Result<(), ContextError> {
    match pin.version {
        Some(_) => Err(ContextError::UnverifiableDocumentVersion {
            path: pin.path.display().to_string(),
        }),
        None => Ok(()),
    }
}

/// A pin naming no indexed document is unknown, never an empty
/// complete answer.
fn unindexed_pin(pin: &DocumentPin) -> Result<QueryResult, ContextError> {
    refuse_unverifiable(pin)?;
    let mut result = live_result(SearchBackend::Symbol);
    mark_unresolved(&mut result, &pin.path);
    Ok(result)
}

/// A pin naming a claimed file that could not be indexed — unreadable,
/// not utf-8, over a budget — is a failed entry: the path is known, its
/// rows are not.
fn failed_pin(pin: &DocumentPin) -> Result<QueryResult, ContextError> {
    refuse_unverifiable(pin)?;
    let mut result = live_result(SearchBackend::Symbol);
    result.completeness =
        Completeness::from_reasons(vec![PartialReason::EntriesFailed { count: 1 }]);
    Ok(result)
}

#[cfg(test)]
mod tests {
    #[test]
    fn owned_launch_index_source_survives_query_and_project() {
        use super::*;
        use crate::executor::WorkerError;
        use std::os::unix::fs::PermissionsExt as _;

        let isolated = std::env::args().skip(1).eq([
            "--exact",
            "context::tests::owned_launch_index_source_survives_query_and_project",
            "--nocapture",
            "--test-threads=1",
        ]);
        if !isolated {
            use std::os::unix::process::CommandExt as _;
            use std::process::{Command, Stdio};

            let mut child = Command::new(std::env::current_exe().expect("test binary path"))
                .args([
                    "--exact",
                    "context::tests::owned_launch_index_source_survives_query_and_project",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env_clear()
                .process_group(0)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("run the isolated root reader fixture");
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            let observed = executor::observe_confined_child(&mut child, None, &[], stdout, stderr)
                .expect("observe and reap the bounded root reader fixture");
            let stdout = String::from_utf8_lossy(&observed.stdout);
            let stderr = String::from_utf8_lossy(&observed.stderr);
            assert!(
                observed.status.success(),
                "root reader fixture: {}\n{stdout}\n{stderr}",
                observed.status
            );
            assert!(
                stdout.contains("1 passed; 0 failed; 0 ignored;"),
                "the isolated root reader assertions must execute: {stdout}"
            );
            return;
        }
        assert!(
            isolated,
            "the root reader fixture requires its isolated single-test process"
        );
        let fixture = tempfile::tempdir().expect("own the index source fixture");
        let helper = fixture.path().join("nonexecutable-helper");
        std::fs::write(&helper, b"not executable\n").expect("write helper");
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o600))
            .expect("refuse executable access");
        let direct = std::process::Command::new(&helper)
            .env_clear()
            .spawn()
            .expect_err("the independent OS control must refuse execution");
        assert_eq!(direct.raw_os_error(), Some(13));
        let never = || false;
        let run = IsolatedRun {
            program: Path::new("/unused-index-program"),
            helper: &helper,
            deadline: None,
            cancel: &never,
            answer_cap: WORKER_ANSWER_MAX,
        };
        let query = Query {
            kind: QueryKind::Path,
            root: fixture.path().to_path_buf(),
            pattern: "*.rs".to_string(),
            scope_glob: None,
            ignore: IgnorePolicy::Respect,
            limit: 1,
            symbol_op: None,
            document: None,
        };
        let project = ProjectRequest {
            root: fixture.path().to_path_buf(),
            changed: Vec::new(),
            file_set_moved: false,
            previous_documents: Vec::new(),
            limit: 1,
        };
        for error in [
            query_isolated(&query, &run).expect_err("query launch must fail"),
            project_index_isolated(&project, &run).expect_err("project launch must fail"),
        ] {
            assert!(matches!(
                &error,
                ContextError::IsolatedRun {
                    cause: IsolatedCause::HelperUnavailable,
                    ..
                }
            ));
            assert_eq!(error.error_code(), ErrorCode::CapabilityUnavailable);
            assert_eq!(error.tag(), "isolated_run");
            let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
            let mut worker = false;
            let mut errno = None;
            while let Some(original) = source {
                worker |= original.downcast_ref::<WorkerError>().is_some();
                if let Some(io) = original.downcast_ref::<io::Error>() {
                    errno = io.raw_os_error();
                }
                source = original.source();
            }
            assert!(worker, "the original worker error must survive: {error:?}");
            assert_eq!(errno, Some(13), "the original EACCES must survive");
        }
        #[cfg(target_os = "linux")]
        {
            use std::sync::atomic::{AtomicBool, Ordering};
            let marker = fixture.path().join("must-not-launch");
            std::fs::write(
                &helper,
                format!("#!/bin/sh\nprintf launched > '{}'\n", marker.display()),
            )
            .expect("write independent spawn witness");
            std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700))
                .expect("the spawn witness is executable");
            let process_status = PathBuf::from(format!("/proc/{}/status", std::process::id()));
            let thread = std::fs::read_link("/proc/thread-self")
                .expect("identify the fixture thread in the trusted proc view");
            assert!(thread.starts_with(format!("{}/task", std::process::id())));
            let thread_status = Path::new("/proc").join(thread).join("status");
            assert_ne!(thread_status, process_status);
            for (project_entry, task_reader) in
                [(false, false), (true, false), (false, true), (true, true)]
            {
                let own_status = if task_reader {
                    thread_status.clone()
                } else {
                    process_status.clone()
                };
                for deadline_stop in [false, true] {
                    let observed = AtomicBool::new(false);
                    let deadline = Instant::now()
                        + if task_reader {
                            Duration::from_millis(100)
                        } else {
                            Duration::from_secs(2)
                        };
                    let control = || {
                        let held = std::fs::read_dir("/proc/self/fd")
                            .expect("inspect held root descriptors")
                            .filter_map(Result::ok)
                            .any(|entry| {
                                std::fs::read_link(entry.path()).ok().as_ref() == Some(&own_status)
                            });
                        if held {
                            observed.store(true, Ordering::Release);
                            if deadline_stop {
                                while Instant::now() < deadline {
                                    std::thread::yield_now();
                                }
                                false
                            } else {
                                true
                            }
                        } else {
                            false
                        }
                    };
                    let controlled = IsolatedRun {
                        program: Path::new("/unused-index-program"),
                        helper: &helper,
                        deadline: Some(deadline),
                        cancel: &control,
                        answer_cap: WORKER_ANSWER_MAX,
                    };
                    let error = if project_entry {
                        project_index_isolated(&project, &controlled)
                            .expect_err("root reader must stop project launch")
                    } else {
                        query_isolated(&query, &controlled)
                            .expect_err("root reader must stop query launch")
                    };
                    assert!(
                        observed.load(Ordering::Acquire),
                        "the actual root identity reader was reached"
                    );
                    let (expected, tag, code) = if deadline_stop {
                        (
                            IsolatedCause::DeadlinePassed,
                            "deadline_passed",
                            ErrorCode::BudgetExhausted,
                        )
                    } else {
                        (
                            IsolatedCause::CancelledBeforeSpawn,
                            "cancelled_before_spawn",
                            ErrorCode::Cancelled,
                        )
                    };
                    let cause = match &error {
                        ContextError::IsolatedRun {
                            cause,
                            source: Some(_),
                        } => Some(cause),
                        _ => None,
                    }
                    .expect("the typed root reader source must survive");
                    assert_eq!(*cause, expected);
                    assert_eq!(cause.tag(), tag);
                    assert_eq!(error.error_code(), code);
                    assert_eq!(error.tag(), "isolated_run");
                    let mut source = std::error::Error::source(&error);
                    let mut original = None;
                    while let Some(next) = source {
                        if let Some(parent) =
                            next.downcast_ref::<rivect_sandbox_helper::OwnedParentError>()
                        {
                            assert_eq!(
                                parent.boundary(),
                                if task_reader {
                                    "owned.parent.task_budget"
                                } else {
                                    "owned.waiter.parent_death"
                                }
                            );
                            original = parent.request_stop();
                        }
                        source = next.source();
                    }
                    assert_eq!(
                        original,
                        Some(if deadline_stop {
                            rivect_sandbox_helper::OwnedStop::Deadline
                        } else {
                            rivect_sandbox_helper::OwnedStop::Cancelled
                        })
                    );
                    assert!(
                        !marker.exists(),
                        "no child reaches the independent launch witness"
                    );
                    let still_held = std::fs::read_dir("/proc/self/fd")
                        .expect("inspect retirement")
                        .filter_map(Result::ok)
                        .any(|entry| {
                            std::fs::read_link(entry.path()).ok().as_ref() == Some(&own_status)
                        });
                    assert!(
                        !still_held,
                        "the acquired root status descriptor was retired"
                    );
                }
            }
        }
    }

    use super::{
        Completeness, ContextError, ErrorCode, IsolatedCause, MatchKind, PartialReason,
        SearchBackend, SearchMatch, SourceRef, engine_refusal_code, live_result,
        without_unencodable_paths,
    };
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::PathBuf;

    /// The parent accepts a worker refusal only under the engine's own
    /// (tag, code) pair — the table must agree with every engine variant
    /// and admit no parent-side one.
    #[test]
    fn engine_refusal_table_matches_every_variant() {
        let io = || std::io::Error::other("io");
        let cases = [
            ContextError::UnknownKind {
                name: "x".into(),
                known: &[],
            },
            ContextError::UnsupportedKind {
                kind: "code.impact",
            },
            ContextError::InvalidRoot {
                path: "x".into(),
                source: io(),
            },
            ContextError::RootNotDirectory { path: "x".into() },
            ContextError::EmptyPattern {
                kind: "search.text",
            },
            ContextError::UnboundedLimit,
            ContextError::ScopeNotApplicable {
                kind: "source.slice",
            },
            ContextError::InvalidTextPattern {
                pattern: "(".into(),
                source: grep_regex::RegexMatcherBuilder::new()
                    .build("(")
                    .expect_err("an unclosed group"),
            },
            ContextError::InvalidGlob {
                glob: "[".into(),
                source: globset::Glob::new("[").expect_err("an unclosed class"),
            },
            ContextError::EscapedRoot { path: "..".into() },
            ContextError::InvalidAstPattern {
                pattern: "x".into(),
                languages: "rust".into(),
                detail: "d".into(),
            },
            ContextError::AstPatternTooLarge { limit: 1 },
            ContextError::SymbolFieldNotApplicable {
                field: "document",
                kind: "search.text",
            },
            ContextError::SymbolOpRequired,
            ContextError::SymbolPatternTooLarge { limit: 1 },
            ContextError::StaleDocumentVersion {
                path: "x".into(),
                pinned: 1,
                actual: 2,
            },
            ContextError::UnverifiableDocumentVersion { path: "x".into() },
            ContextError::UnsupportedPositionEncoding { encoding: "utf-16" },
            ContextError::IsolatedRun {
                cause: IsolatedCause::WorkerProtocol,
                source: None,
            },
            ContextError::WorkerRefused {
                code: ErrorCode::NotFound,
                tag: "invalid_root".into(),
                message: "m".into(),
            },
            ContextError::LimitTooLarge {
                limit: 2,
                ceiling: 1,
            },
        ];
        for error in &cases {
            // No `_` arm: a new variant must be placed on one side.
            let from_engine = match error {
                ContextError::IsolatedRun { .. }
                | ContextError::WorkerRefused { .. }
                | ContextError::LimitTooLarge { .. } => false,
                ContextError::UnknownKind { .. }
                | ContextError::UnsupportedKind { .. }
                | ContextError::InvalidRoot { .. }
                | ContextError::RootNotDirectory { .. }
                | ContextError::EmptyPattern { .. }
                | ContextError::UnboundedLimit
                | ContextError::ScopeNotApplicable { .. }
                | ContextError::InvalidTextPattern { .. }
                | ContextError::InvalidGlob { .. }
                | ContextError::EscapedRoot { .. }
                | ContextError::InvalidAstPattern { .. }
                | ContextError::AstPatternTooLarge { .. }
                | ContextError::SymbolFieldNotApplicable { .. }
                | ContextError::SymbolOpRequired
                | ContextError::SymbolPatternTooLarge { .. }
                | ContextError::StaleDocumentVersion { .. }
                | ContextError::UnverifiableDocumentVersion { .. }
                | ContextError::UnsupportedPositionEncoding { .. } => true,
            };
            let expected = from_engine.then(|| error.error_code());
            assert_eq!(engine_refusal_code(error.tag()), expected, "{error:?}");
        }
    }

    /// A non-UTF-8 match path cannot be encoded: it leaves the answer and
    /// joins any failed-entry count already there.
    #[test]
    fn unencodable_match_paths_become_failed_entries() {
        let hit = |path: PathBuf| SearchMatch {
            source: SourceRef {
                path,
                line: None,
                ignored: false,
            },
            kind: MatchKind::Path,
        };
        let mut result = live_result(SearchBackend::Path);
        result.matches = vec![
            hit(PathBuf::from("good.txt")),
            hit(PathBuf::from(OsStr::from_bytes(b"bad\xff.txt"))),
        ];
        let clean = without_unencodable_paths(result.clone());
        assert_eq!(clean.matches, vec![hit(PathBuf::from("good.txt"))]);
        assert_eq!(
            clean.completeness,
            Completeness::Partial {
                reasons: vec![PartialReason::EntriesFailed { count: 1 }]
            }
        );

        result.completeness = Completeness::Partial {
            reasons: vec![
                PartialReason::LimitReached { limit: 2 },
                PartialReason::EntriesFailed { count: 2 },
            ],
        };
        assert_eq!(
            without_unencodable_paths(result).completeness,
            Completeness::Partial {
                reasons: vec![
                    PartialReason::LimitReached { limit: 2 },
                    PartialReason::EntriesFailed { count: 3 },
                ]
            }
        );
    }

    /// One unencodable entry costs one failed entry however many of its
    /// lines matched: the count is entries, which is what the coverage
    /// later consumes — two dropped matches are not two unsearched
    /// entries.
    #[test]
    fn one_unencodable_entry_costs_one_failed_entry() {
        let hit = |path: PathBuf, line: u64| SearchMatch {
            source: SourceRef {
                path,
                line: Some(line),
                ignored: false,
            },
            kind: MatchKind::Path,
        };
        let bad = PathBuf::from(OsStr::from_bytes(b"bad\xff.txt"));
        let mut result = live_result(SearchBackend::Text);
        result.matches = vec![
            hit(PathBuf::from("good.txt"), 1),
            hit(bad.clone(), 1),
            hit(bad, 2),
        ];
        assert_eq!(
            without_unencodable_paths(result).completeness,
            Completeness::Partial {
                reasons: vec![PartialReason::EntriesFailed { count: 1 }]
            }
        );
    }
}
