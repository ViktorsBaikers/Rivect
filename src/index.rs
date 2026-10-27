//! The code-intelligence index contract (architecture «Index» layer):
//! `SnapshotId`, `SourceRef` and `QueryResult` — the typed payload every
//! source query carries with its snapshot generation, producing backend,
//! completeness and any named paths that stayed unresolved. An
//! unresolved path is reported, never silently dropped; a truncated or
//! partially covered scan is `Partial`, never a clean answer. Absence of
//! an edge is never proof an edge does not exist — coverage claims live
//! in `Completeness`, not in the presence or absence of rows.
//!
//! This layer also owns the derived project graph: the typed directed
//! provenance edges one snapshot generation carries, and the mechanical
//! producer that derives them from a bounded read of the admitted
//! sources. Every edge names where it was read (its subject document and
//! line), how its target was obtained, which document version it was
//! read at, and how certain that target is — an unresolvable specifier
//! stays an `Unknown`-confidence row whose raw specifier is reported as
//! unresolved, never a missing edge.

use crate::commands::LoopEvent;
use lsp_types::{PositionEncodingKind, Range, Uri};
use notify::event::{EventKind, ModifyKind};
use notify::{Event, RecursiveMode, Watcher as _};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex};

/// The snapshot a result was computed over. `Live` states — honestly —
/// that no persisted generation exists in this build: the result was
/// computed by a live filesystem scan, so two queries may observe
/// different bytes. `Generation` is a versioned store generation; the
/// store that owns it lands with the project index owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotId {
    Live,
    Generation(u64),
}

/// The admitted in-process backend that produced a result — provenance
/// the caller can audit. `engine` names the SRC-007/SRC-008 crate stack; no
/// backend is a subprocess or a model call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchBackend {
    /// grep-regex over grep-searcher, walking candidates through the
    /// ignore crate's filters.
    Text,
    /// The ignore walker plus globset matching — path identity only,
    /// file content is never opened.
    Path,
    /// A bounded exact-byte read of one named file.
    Source,
    /// tree-sitter grammars matched by ast-grep-core patterns —
    /// structural syntax shapes, never symbol identity.
    Ast,
    /// The typed in-process symbol index (DEC-005): tree-sitter
    /// grammars extract definition/use rows; `lsp-types` shapes carry
    /// the document identity. No language-server subprocess runs.
    Symbol,
}

impl SearchBackend {
    /// The admitted engine set behind the backend (SRC-007/SRC-008) —
    /// provenance names the real substrate, never a generic "search".
    pub fn engine(self) -> &'static str {
        match self {
            Self::Text => "grep-searcher+grep-regex",
            Self::Path => "ignore+globset",
            Self::Source => "std::fs",
            Self::Ast => "tree-sitter+ast-grep-core",
            Self::Symbol => "tree-sitter+lsp-types",
        }
    }
}

/// One location in project source: the query-root-relative `path`, the
/// 1-based `line` when the hit carries one, and `ignored` — true when a
/// standard-filters enumeration of the same root would not have surfaced
/// the path. The flag is provenance: an include-ignored result reports
/// that it exists despite the rules instead of silently appearing as an
/// ordinary hit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceRef {
    pub path: PathBuf,
    pub line: Option<u64>,
    pub ignored: bool,
}

/// Why a result does not cover the whole requested scope — each cause is
/// typed, never folded into a bare "maybe incomplete".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum PartialReason {
    /// The caller's bound was reached and more matches existed beyond it.
    LimitReached { limit: usize },
    /// Entries inside the scope could not be enumerated or searched.
    EntriesFailed { count: u64 },
    /// Named paths could not be resolved; they are listed on the result.
    UnresolvedPaths { count: u64 },
    /// Entries carried a language this query could not cover — no
    /// admitted grammar claims it, or the caller's pattern is not valid
    /// syntax under its grammar. Counted, never silently skipped.
    UnsupportedLanguage { count: u64 },
    /// Files whose parse tree contains error or missing nodes: intact
    /// subtrees still matched, but the damaged span may hide matches.
    ParseErrors { count: u64 },
    /// Documents the typed index had captured whose bytes changed under
    /// it — their rows were withheld rather than served as current
    /// (AC-039a).
    StaleDocuments { count: u64 },
    /// Documents holding a same-name definition, or a use certainly
    /// bound to one, whose module path could not be derived from their
    /// location: a qualified definition, type or references query could
    /// not tell whether they match, so their rows were withheld rather
    /// than claimed absent (DEC-029).
    UnknownModulePaths { count: u64 },
}

/// Completeness of one query result — `Complete` only when nothing was
/// truncated, failed or left unresolved. A bounded or partially covered
/// answer is `Partial` with its typed reasons; it is never sold as full
/// coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Completeness {
    Complete,
    Partial { reasons: Vec<PartialReason> },
}

impl Completeness {
    /// `Complete` iff there is nothing to disclose; otherwise `Partial`
    /// carrying exactly the observed reasons.
    pub fn from_reasons(reasons: Vec<PartialReason>) -> Self {
        if reasons.is_empty() {
            Self::Complete
        } else {
            Self::Partial { reasons }
        }
    }

    /// True only for a fully covered result — a truncated, errored or
    /// unresolved-bearing answer reports false.
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Why a symbol row is in the answer — the operation that produced it,
/// never an inference from surrounding text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolRole {
    /// A definition site (`textDocument/definition`-shaped).
    Definition,
    /// A use site (`textDocument/references`-shaped).
    Reference,
    /// A type answer: the named type's own definition row — `resolved:
    /// true` only when exactly one candidate binds certainly (DEC-025);
    /// otherwise every candidate the use could mean is served
    /// `resolved: false` (several in its own document, or same-name
    /// types of other documents), and when none exists the annotation
    /// that spells the type name (`resolved: false`).
    Type,
}

/// One typed symbol row (AC-036 leg): the name's own coordinates plus
/// its document's LSP identity — uri, content version, position
/// encoding and workspace root (lsp-types shapes; no server runs). The
/// `range` is zero-based in `encoding` units; `start_byte`/`end_byte`
/// carry the same span as document bytes so either coordinate space is
/// auditable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolMatch {
    /// The grammar that produced the row — `rust`, `typescript`, `tsx`.
    pub language: String,
    /// The symbol's own text — the name node's bytes.
    pub name: String,
    /// The honest semantic kind — `function`, `struct`, `method`, … —
    /// a name, never a faked `lsp_types::SymbolKind` number. On
    /// reference rows it is the use site's node kind (`identifier`,
    /// `type_identifier`, …): a use knows only that it is a name.
    pub symbol_kind: String,
    pub role: SymbolRole,
    /// The enclosing named containers, `::`-joined outermost first —
    /// `""` at top level. This is how same-name symbols are told apart.
    pub scope: String,
    /// `file://` uri of the document — the LSP document identity.
    pub uri: Uri,
    /// The document's content-derived version at index time.
    pub version: i32,
    /// The position space `range` is expressed in — always `utf-8`.
    pub encoding: PositionEncodingKind,
    /// `file://` uri of the workspace root the index was built under.
    pub root: Uri,
    /// The name node's range, zero-based, in `encoding` units.
    pub range: Range,
    /// The same span as document bytes.
    pub start_byte: u64,
    pub end_byte: u64,
    /// Edge evidence, never proof of absence (DEC-025, DEC-029): on a
    /// reference or type row `true` reports exactly one certain binding
    /// — the use sits in a value, type or path-leaf position, and its
    /// nearest enclosing scope (or its spelled `q::` path, walked through
    /// modules only) holds exactly one candidate of that kind, in the
    /// use's own fresh document, with no import, glob, item-introducing
    /// macro or Rust `mod` boundary in between. `false` stays unknown,
    /// never an absent-dependency claim: another document's candidate
    /// (imports are not followed), any path through a type (`T::new`,
    /// `E::A`, trait methods), `crate::` outside a crate-root document,
    /// path qualifier segments, macro names and token trees, members,
    /// import leaves, signature parameters, TypeScript `var`s, `infer`
    /// and mapped-type keys, reopened namespaces, a module merged with a
    /// same-name function or type, Rust locals sharing a name with a
    /// `const`/`static`/`struct`, import or alias of their document or
    /// under a glob or item-introducing macro in their own scope or one
    /// around it, every use in a damaged document, and
    /// unmodelled forms are all `false`; a qualified references answer
    /// serves every such same-name use rather than dropping it.
    /// Definition rows always carry `true`.
    pub resolved: bool,
}

/// What one match carries. Content bytes are present only on kinds that
/// read content — a `Path` hit is proof the file was never opened, and
/// `line_bytes` are the raw matched line (terminator included), never
/// transcoded or lossy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MatchKind {
    Text {
        line_bytes: Vec<u8>,
    },
    Path,
    Source {
        bytes: Vec<u8>,
    },
    /// A structural syntax match: the admitted grammar that parsed the
    /// file, the tree-sitter node kind at the match root, and the
    /// matched node's byte span inside the file. Naming grammar and
    /// node kind is what separates a syntax shape from a symbol
    /// identity — this variant can never answer `code.symbol`.
    Ast {
        language: String,
        node_kind: String,
        start_byte: u64,
        end_byte: u64,
    },
    /// A typed symbol row produced by the in-process index — boxed so
    /// the discriminated union stays pointer-sized (clippy's
    /// `variant_size_differences` gate).
    Symbol(Box<SymbolMatch>),
}

/// One match: where it is plus what it carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchMatch {
    pub source: SourceRef,
    pub kind: MatchKind,
}

/// The typed result of one source query: the snapshot it was computed
/// over, the backend that produced it, its completeness, the matches,
/// and the named paths that stayed unresolved — `unresolved` is a
/// report, not a drop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryResult {
    pub snapshot: SnapshotId,
    pub backend: SearchBackend,
    pub completeness: Completeness,
    pub matches: Vec<SearchMatch>,
    pub unresolved: Vec<PathBuf>,
}

/// What relation one directed edge reports — the three kinds the
/// project index derives mechanically, never a fourth invented by a
/// caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// A module-level dependency the source declares (`use a::b;`,
    /// `import … from "a/b"`).
    Import,
    /// A dependency on a named item reached through a qualified path
    /// (`a::b::name`, `a.b.name`, `require("a/b")`).
    Call,
    /// A dependency of a test target — a document under a package's
    /// `tests/` directory. Same relation, different subject: the edge
    /// kind is what a consumer reads, not a separate table.
    Test,
}

impl EdgeKind {
    /// The stable name one spelling maps to; `None` outside the
    /// recorded vocabulary.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "import" => Self::Import,
            "call" => Self::Call,
            "test" => Self::Test,
            _ => return None,
        })
    }
}

/// How an edge's target was obtained — the provenance a consumer audits
/// before trusting the row. It never says anything about the target's
/// existence: that is [`EdgeConfidence`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeProvenance {
    /// The relation text spells the target as a path, and that path
    /// names a file in the generation.
    Observed,
    /// The relation names a module and the file was derived from the
    /// package-root module layout — the Cargo/Node convention, not a
    /// path the source wrote.
    Inferred,
    /// The relation declares a whole namespace (a glob or re-export), so
    /// no single file is claimed; the subject module is the target.
    Structural,
}

impl EdgeProvenance {
    /// The stable name one spelling maps to; `None` outside the
    /// recorded vocabulary.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "observed" => Self::Observed,
            "inferred" => Self::Inferred,
            "structural" => Self::Structural,
            _ => return None,
        })
    }
}

/// Whether an edge's target is the one the relation names. `Unknown`
/// stays unknown: it never claims the dependency does not exist, and it
/// never travels as a missing row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeConfidence {
    /// The target is a file this generation indexed.
    Certain,
    /// The specifier could not be placed — a dynamic path, a bare
    /// name, an alias, or a target outside the pinned root. The raw
    /// specifier rides `IndexEdge::to` and is reported unresolved.
    Unknown,
}

impl EdgeConfidence {
    /// The stable name one spelling maps to; `None` outside the
    /// recorded vocabulary.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "certain" => Self::Certain,
            "unknown" => Self::Unknown,
            _ => return None,
        })
    }
}

/// One typed directed provenance edge of a project generation: which
/// document the relation was read at (`from`, with its 1-based line and
/// the ignore flag the standard rules would have given it), which
/// document it points at (`to`, with no line — a relation names a
/// target document, never a line inside it), what the relation is, how
/// the target was obtained, the content version the subject document
/// carried at index time, and how certain the target is.
///
/// An `Unknown` row is a real row: the specifier that could not be
/// placed is the target, and absence of a row is never proof absence of
/// a dependency (AC-031, INV-007).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IndexEdge {
    pub from: SourceRef,
    pub to: SourceRef,
    pub kind: EdgeKind,
    pub provenance: EdgeProvenance,
    pub version: i32,
    pub confidence: EdgeConfidence,
}

/// Why a stored generation no longer describes the project. Every
/// variant is a repair trigger: the generation is rebuilt, or it is
/// reported `stale` with this cause — never served as current (INV-007).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleCause {
    /// The isolated index run ended without an answer (DEC-033), so
    /// nothing about the project was verified under it.
    IsolatedRun,
    /// The worker refused the request with its own typed refusal.
    WorkerRefused,
    /// The watcher's backend reported that events were missed, so the
    /// path set this generation was cut from is incomplete.
    WatcherMissed,
    /// A previous build was begun and never sealed — the writer died
    /// mid-index.
    Interrupted,
    /// A file under the generation changed with no generation cut for
    /// it.
    SourceChanged,
    /// A newer generation replaced this one, so its rows describe a file
    /// set this generation no longer owns. Recorded by the seal that
    /// replaced it, never by a reader: a generation stops being current
    /// when its successor commits, not when someone looks (INV-007).
    Superseded,
    /// The build could not cover the whole project: a language no
    /// admitted grammar claims, an entry that could not be read, or a
    /// specifier that could not be placed. The rows are what was
    /// observed, never the whole project.
    PartialCoverage,
}

impl StaleCause {
    /// The stable name one spelling maps to; `None` outside the
    /// recorded vocabulary. An unknown stored cause is a typed storage
    /// error, never a default.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "isolated_run" => Self::IsolatedRun,
            "worker_refused" => Self::WorkerRefused,
            "watcher_missed" => Self::WatcherMissed,
            "interrupted" => Self::Interrupted,
            "source_changed" => Self::SourceChanged,
            "superseded" => Self::Superseded,
            "partial_coverage" => Self::PartialCoverage,
            _ => return None,
        })
    }
}

/// Whether a stored generation still describes the project: `Fresh` is a
/// claim, `Stale` names why not. There is no third state — a generation
/// whose build never finished is `Stale { Interrupted }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GenerationState {
    Fresh,
    Stale { cause: StaleCause },
}

impl GenerationState {
    /// Whether the generation may be served as current.
    pub fn is_fresh(&self) -> bool {
        matches!(self, Self::Fresh)
    }

    /// The stable stored spelling.
    pub fn as_stored(&self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale { .. } => "stale",
        }
    }

    /// The stored spelling read back; an unknown value is a typed
    /// storage error the caller must surface, never a `Fresh` default.
    pub fn from_stored(state: &str, cause: Option<&str>) -> Option<Self> {
        Some(match (state, cause) {
            ("fresh", None) => Self::Fresh,
            ("stale", Some(cause)) => Self::Stale {
                cause: StaleCause::from_name(cause)?,
            },
            _ => return None,
        })
    }
}

/// One admitted source file as the edge producer reads it: its
/// project-relative path, the bytes the generation was cut from, the
/// content version those bytes carry, and whether the ignore baseline
/// would have excluded it. Everything the derivation reads is here, so
/// the result is a pure function of the generation's inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedSource {
    pub relative: PathBuf,
    pub bytes: Vec<u8>,
    pub version: i32,
    pub ignored: bool,
}

/// The edges one subject document contributes, and the specifiers that
/// could not be placed — reported, never dropped (AC-031).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DerivedEdges {
    pub edges: Vec<IndexEdge>,
    pub unresolved: Vec<PathBuf>,
}

/// Everything one generation's edge derivation may read besides the
/// subject document: the project-relative files it indexed, and the
/// package roots those files sit under. Holding both makes the
/// derivation a pure function of the generation's inputs, which is what
/// lets an incremental generation be compared against a full one.
#[derive(Debug, Clone, Copy)]
pub struct DerivationInputs<'a> {
    pub files: &'a BTreeSet<PathBuf>,
    pub packages: &'a BTreeSet<PathBuf>,
}

impl DerivationInputs<'_> {
    /// The package a project-relative file belongs to — the longest
    /// package root enclosing its directory. `None` for a file under no
    /// package inside the pinned root.
    pub fn package_of(&self, relative: &Path) -> Option<&Path> {
        let directory = relative.parent()?;
        self.packages
            .iter()
            .filter(|root| directory.starts_with(root))
            .max_by_key(|root| root.as_os_str().len())
            .map(PathBuf::as_path)
    }

    /// Whether a file is a test target of the package enclosing it: the
    /// package's `tests/` directory, the recorded location of a test
    /// corpus. A file under no package is not a test target.
    pub fn is_test_target(&self, relative: &Path) -> bool {
        self.package_of(relative)
            .is_some_and(|root| relative.starts_with(root.join("tests")))
    }
}

/// The derived graph of one project generation: its edges, its
/// completeness, the specifiers it could not place, and the documents
/// this cut actually re-derived. Absent edge ≠ absent dependency — a
/// generation's rows are what was observed, and the completeness and
/// `unresolved` lists are what was not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectGraph {
    pub edges: Vec<IndexEdge>,
    pub completeness: Completeness,
    pub unresolved: Vec<PathBuf>,
    /// The project-relative documents this cut re-derived, when it was
    /// narrowed to a set. Empty for a full build *and* for a narrowing
    /// the derivation itself refused to apply — a cut that widened
    /// itself re-derived every document, so it states no narrowing. The
    /// writer needs this to know what a seal may carry: a carried row
    /// whose subject this cut also re-derived is a row the answer has
    /// already replaced, and keeping it would serve the old placement
    /// beside the new one.
    ///
    /// This is a property of the *answer*, so it rides the run that
    /// produced it. A generation read back out of the store reports it
    /// empty: which documents a past cut re-derived is not a fact the
    /// rows keep, and inventing one would be a claim about a build
    /// nobody observed.
    pub narrowed_to: Vec<PathBuf>,
    /// The project-relative documents this cut indexed — the file set
    /// the rows were derived from, kept so a later cut can tell whether
    /// the file set outside its own narrowing held still. An edge set
    /// alone cannot answer that: a document with no relations is indexed
    /// and is not a subject of any row.
    pub documents: Vec<PathBuf>,
}

/// What one seal keeps from the generation it replaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarryPolicy<'a> {
    /// A full build: every document was re-derived, so nothing carries
    /// and the generation is exactly what the run observed.
    Full,
    /// A narrowed cut: the documents in `replaced` were re-derived, so
    /// every other subject's rows carry forward unchanged.
    Narrowed { replaced: &'a [PathBuf] },
    /// The run learned nothing — refused, cancelled or never answered —
    /// so the generation carries no rows at all. Reporting the replaced
    /// generation's observations here would attribute them to a build
    /// that made none.
    Nothing,
}

/// The Node extensions a specifier may omit, and the directory index a
/// directory specifier names.
const NODE_EXTENSIONS: &[&str] = &[".ts", ".tsx", ".mts", ".cts"];
const NODE_INDEX: &[&str] = &["index.ts", "index.tsx", "index.mts", "index.cts"];

/// Where a relation's `::`/`crate::`/`self::` prefix puts the module it
/// names — the Rust 2018 anchors, and the two shapes that name no
/// placeable module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Anchor {
    /// `crate::x` — the package's crate root.
    Crate,
    /// `self::x` — the subject's own module.
    Own,
    /// A `mod x;` declaration — relative to the subject's module.
    Subject,
    /// A bare `use a::b` (2018 names an external crate) or a `super::`
    /// chain: no placeable module, and never a guessed one.
    Unplaceable,
}

/// What one relation states, and therefore what its edge's provenance
/// reports: a spelled Node path, a Node module name, a Rust module path
/// the layout resolves, or a declaration about the subject's own
/// structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    /// A Node specifier — `./x` and `../x` spell the path, a bare or
    /// dotted one names a module the extension search resolves.
    Node { spelled: bool },
    /// A Rust module path, with its 2018 anchor.
    Rust(Anchor),
    /// A `mod` declaration or a glob import — a namespace relation, so
    /// the target is the declared module itself.
    Declared(Anchor),
}

impl Target {
    fn provenance(self) -> EdgeProvenance {
        match self {
            Self::Node { spelled: true } => EdgeProvenance::Observed,
            Self::Node { .. } | Self::Rust(_) => EdgeProvenance::Inferred,
            Self::Declared(_) => EdgeProvenance::Structural,
        }
    }
}

/// Derives the directed edges one subject document contributes, and the
/// specifiers it could not place. Mechanical and total: a comment
/// yields no relation, an extension the admitted grammar set does not
/// claim yields no edge, and every specifier that names no indexed file
/// still yields an `Unknown`-confidence row whose target is the raw
/// specifier — the graph never turns an unresolved path into a missing
/// dependency (AC-031).
pub fn derive_edges(source: &IndexedSource, inputs: &DerivationInputs<'_>) -> DerivedEdges {
    let mut derived = DerivedEdges::default();
    let Some(package) = inputs.package_of(&source.relative) else {
        return derived;
    };
    // A file the admitted grammar set does not claim is counted by the
    // caller as unsupported coverage; a lexical scan of it would only
    // guess at its syntax.
    if !claimed_language(&source.relative) {
        return derived;
    }
    let kind = if inputs.is_test_target(&source.relative) {
        EdgeKind::Test
    } else {
        EdgeKind::Import
    };
    let subject = Subject {
        relative: &source.relative,
        version: source.version,
        ignored: source.ignored,
        kind,
        // The canonical Cargo layout, read from its one owner: a graph
        // edge and a symbol row then name the same module, and a
        // location the layout does not spell derives none instead of
        // guessing the crate root.
        own_module: crate::lsp::module_name(&source.relative, package),
        package,
        inputs: *inputs,
    };
    // Bytes that are not UTF-8 state no relation this lexical scan can
    // read. The caller is the reader that admitted the document, and it
    // counts the decode failure as a coverage failure rather than
    // handing the document to a scan that would return nothing and
    // read as "this document has no dependencies".
    let Ok(text) = std::str::from_utf8(&source.bytes) else {
        return derived;
    };
    for (index, raw) in text.lines().enumerate() {
        for relation in relations(raw) {
            let edge = subject.place(relation, index as u64 + 1);
            if edge.confidence == EdgeConfidence::Unknown {
                derived.unresolved.push(edge.to.path.clone());
            }
            derived.edges.push(edge);
        }
    }
    derived
}

/// Whether an admitted grammar claims the file — extension only, the
/// same rule the typed index and the AST leg claim candidates by.
fn claimed_language(relative: &Path) -> bool {
    matches!(
        relative.extension().and_then(|ext| ext.to_str()),
        Some("rs" | "ts" | "cts" | "mts" | "tsx")
    )
}

/// The subject document every relation of one file is placed against.
struct Subject<'a> {
    relative: &'a Path,
    version: i32,
    ignored: bool,
    kind: EdgeKind,
    own_module: Option<String>,
    package: &'a Path,
    inputs: DerivationInputs<'a>,
}

/// One relation a line states: what it is, what it points at, and how.
struct Relation<'l> {
    kind: EdgeKind,
    target: Target,
    text: &'l str,
    /// The dynamic form: a `import("x")` argument is a value, so its
    /// specifier is never certain even when the file is indexed.
    dynamic: bool,
}

impl Subject<'_> {
    /// One relation, placed: the target is the first candidate this
    /// generation actually indexed, or the raw specifier at `Unknown`
    /// confidence. A specifier that escapes the pinned root is
    /// `Unknown` too — the derivation never touches the filesystem, so
    /// the boundary is checked lexically.
    fn place(&self, relation: Relation<'_>, line: u64) -> IndexEdge {
        let candidates = self.candidates(&relation);
        let (to, confidence) = match candidates
            .iter()
            .find(|candidate| self.inputs.files.contains(*candidate))
        {
            Some(target) => (target.clone(), EdgeConfidence::Certain),
            None => (PathBuf::from(relation.text), EdgeConfidence::Unknown),
        };
        IndexEdge {
            from: SourceRef {
                path: self.relative.to_path_buf(),
                line: Some(line),
                ignored: self.ignored,
            },
            to: SourceRef {
                path: to,
                line: None,
                ignored: false,
            },
            // A test target's relations are test relations: the kind a
            // consumer reads, not a separate table.
            kind: if self.kind == EdgeKind::Test {
                EdgeKind::Test
            } else {
                relation.kind
            },
            provenance: relation.target.provenance(),
            version: self.version,
            // A dynamic import names a value; the file it happens to
            // equal is an observation, not a certainty.
            confidence: if relation.dynamic {
                EdgeConfidence::Unknown
            } else {
                confidence
            },
        }
    }

    /// The project-relative files a relation could name, in preference
    /// order. Empty when the relation names no placeable module.
    fn candidates(&self, relation: &Relation<'_>) -> Vec<PathBuf> {
        match relation.target {
            Target::Node { spelled } => self.node_candidates(relation.text, spelled),
            Target::Rust(anchor) => self.rust_candidates(anchor, relation.text),
            Target::Declared(anchor) => self.declared_candidates(anchor, relation.text),
        }
    }

    /// The files a Rust module names under the package, in the layout's
    /// preference order. A `use` or a call names an item as often as a
    /// module, so the whole path is tried first and the path without its
    /// last segment after it — the first spelling this generation indexed
    /// is the one reported, and neither is invented.
    fn rust_candidates(&self, anchor: Anchor, text: &str) -> Vec<PathBuf> {
        let Some(module) = self.module(anchor, text) else {
            return Vec::new();
        };
        let indexed = self.indexed_module_files(&module);
        if indexed.is_empty() {
            return self.indexed_module_files(&without_last_segment(&module));
        }
        indexed
    }

    /// A declaration names a module or a namespace, never an item, so it
    /// reads one spelling only: `mod helper;` in a crate root must not
    /// fall back onto the crate root itself when its module is absent.
    fn declared_candidates(&self, anchor: Anchor, text: &str) -> Vec<PathBuf> {
        self.module(anchor, text)
            .map_or_else(Vec::new, |module| self.indexed_module_files(&module))
    }

    fn indexed_module_files(&self, module: &str) -> Vec<PathBuf> {
        crate::lsp::module_files(self.package, module)
            .into_iter()
            .filter(|path| self.inputs.files.contains(path))
            .collect()
    }

    /// The Rust module a relation names, with its anchor resolved. The
    /// subject's own module is the base for `self::` and for a `mod`
    /// declaration; `crate::` is the package's crate root; a bare
    /// `use a::b` (2018 names an external crate) and a `super::` chain
    /// place nothing, and are never guessed.
    fn module(&self, anchor: Anchor, text: &str) -> Option<String> {
        let (anchor, rest) = if let Some(rest) = text.strip_prefix("crate::") {
            (Anchor::Crate, rest)
        } else if let Some(rest) = text.strip_prefix("self::") {
            (Anchor::Own, rest)
        } else if text == "self" {
            (Anchor::Own, "")
        } else {
            (anchor, text)
        };
        match anchor {
            Anchor::Unplaceable => None,
            Anchor::Crate => Some(rest.to_string()),
            Anchor::Own | Anchor::Subject => Some(match self.own_module.as_deref() {
                Some(own) if !own.is_empty() && !rest.is_empty() => {
                    format!("{own}::{rest}")
                }
                _ => rest.to_string(),
            }),
        }
    }

    /// The Node-shaped candidates of a specifier: the spelled path
    /// itself, each admitted extension, then each directory index. A
    /// bare or dotted specifier is a module name, so its dots are the
    /// Node directory separators. A `..` that would leave the pinned
    /// root yields nothing, so an escaping specifier stays unknown.
    fn node_candidates(&self, specifier: &str, spelled: bool) -> Vec<PathBuf> {
        let joined;
        let specifier = if spelled {
            specifier
        } else {
            joined = specifier.replace('.', "/");
            joined.as_str()
        };
        let base = if spelled {
            self.relative
                .parent()
                .unwrap_or(Path::new(""))
                .join(specifier)
        } else {
            PathBuf::from(specifier.trim_start_matches("./"))
        };
        let Some(normalized) = normalize(&base) else {
            return Vec::new();
        };
        let mut candidates = vec![normalized.clone()];
        candidates.extend(NODE_EXTENSIONS.iter().map(|extension| {
            let mut with_extension = normalized.clone().into_os_string();
            with_extension.push(extension);
            PathBuf::from(with_extension)
        }));
        candidates.extend(NODE_INDEX.iter().map(|index| normalized.join(index)));
        candidates
    }
}

/// A module path without its last segment — the module a `use` of a
/// named item points into. The empty path is returned unchanged, so a
/// crate-root spelling is never truncated into nothing.
fn without_last_segment(module: &str) -> String {
    module
        .rsplit_once("::")
        .map_or_else(String::new, |(parent, _)| parent.to_string())
}

/// The lexical `.`/`..` collapse — no filesystem access, so a symlinked
/// `..` cannot redirect the result. `None` when the path would leave
/// the pinned root.
fn normalize(path: &Path) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            std::path::Component::Normal(part) => normalized.push(part),
            std::path::Component::RootDir | std::path::Component::Prefix(_) => return None,
        }
    }
    (!normalized.as_os_str().is_empty()).then_some(normalized)
}

/// The relations one line states. A comment carries none: the tail is
/// cut before anything is read, so this can only lose an edge — never
/// invent one. The cut is string-literal aware, so a `//` inside a
/// quoted specifier stays part of that specifier.
fn relations(line: &str) -> Vec<Relation<'_>> {
    let line = strip_comment(line);
    let line = visibility_prefix(line);
    if line.is_empty() {
        return Vec::new();
    }
    if let Some(rest) = strip_keyword(line, "use ") {
        return rust_use(rest);
    }
    if let Some(rest) = strip_keyword(line, "mod ") {
        return vec![Relation {
            kind: EdgeKind::Import,
            target: Target::Declared(Anchor::Subject),
            text: rest.trim_end_matches(';').trim(),
            dynamic: false,
        }];
    }
    if let Some(specifier) = node_declaration(line) {
        return vec![node_relation(specifier, EdgeKind::Import, false)];
    }
    let mut found: Vec<Relation<'_>> = node_calls(line)
        .into_iter()
        .map(|(specifier, dynamic)| node_relation(specifier, EdgeKind::Call, dynamic))
        .collect();
    found.extend(qualified_calls(line));
    found
}

fn node_relation(specifier: &str, kind: EdgeKind, dynamic: bool) -> Relation<'_> {
    Relation {
        kind,
        target: Target::Node {
            spelled: specifier.starts_with("./") || specifier.starts_with("../"),
        },
        text: specifier,
        dynamic,
    }
}

/// A `//` or `/*` tail is cut; a comment-only line carries no relation.
/// The scan is string-literal aware, so a `//` inside a quoted
/// specifier is part of the specifier and not a comment opener.
fn strip_comment(line: &str) -> &str {
    let line = line.trim_start();
    if line.starts_with("//") || line.starts_with("/*") || line.starts_with('*') {
        return "";
    }
    let bytes = line.as_bytes();
    let mut quoted: Option<u8> = None;
    for (at, byte) in bytes.iter().enumerate() {
        match quoted {
            Some(open) if *byte == open => quoted = None,
            Some(_) => {}
            None if *byte == b'"' || *byte == b'\'' => quoted = Some(*byte),
            None if *byte == b'/' && bytes.get(at + 1) == Some(&b'/') => {
                return line[..at].trim_end();
            }
            None => {}
        }
    }
    line.trim_end()
}

/// A leading `pub`/`pub(crate)`/`pub(super)` is a visibility, not part
/// of the relation.
fn visibility_prefix(line: &str) -> &str {
    ["pub(crate) ", "pub(super) ", "pub "]
        .into_iter()
        .find_map(|prefix| line.strip_prefix(prefix))
        .unwrap_or(line)
}

fn strip_keyword<'l>(line: &'l str, keyword: &str) -> Option<&'l str> {
    line.strip_prefix(keyword)
        .map(str::trim_start)
        .filter(|rest| !rest.is_empty())
}

/// A Rust `use`: its first path, with the anchors the 2018 paths
/// declare. A brace list is a declaration of several relations, so the
/// head is reported once and the list's own contents are left to the
/// symbol leg — one opaque row would be a claim the bytes do not make.
fn rust_use(rest: &str) -> Vec<Relation<'_>> {
    let body = rest.split('{').next().unwrap_or(rest);
    let head = body
        .split(';')
        .next()
        .unwrap_or(body)
        .split(',')
        .next()
        .unwrap_or(body)
        .trim();
    let path = head
        .split(" as ")
        .next()
        .unwrap_or(head)
        .trim()
        .trim_end_matches(';')
        .trim();
    let namespace = rest.contains('{') || path.ends_with("::*") || path == "*";
    let path = path.trim_end_matches("::*").trim_end_matches('*').trim();
    if path.is_empty() {
        return Vec::new();
    }
    let anchor = if namespace {
        Anchor::Crate
    } else if path.starts_with("super::") || path == "super" {
        Anchor::Unplaceable
    } else {
        Anchor::Crate
    };
    vec![Relation {
        kind: EdgeKind::Import,
        target: if namespace {
            Target::Declared(anchor)
        } else {
            Target::Rust(anchor)
        },
        text: path,
        dynamic: false,
    }]
}

/// The specifier of a Node module declaration: `import … from "x"`,
/// `import "x"`, `export … from "x"`. A statement that is not a
/// declaration — `export const s = "x"` — names no module, so its string
/// is never read as one.
fn node_declaration(line: &str) -> Option<&str> {
    let rest = line
        .strip_prefix("import ")
        .or_else(|| line.strip_prefix("export "))?;
    let open = rest.find(['"', '\''])?;
    let lead = rest[..open].trim();
    if !lead.is_empty() && !lead.ends_with("from") {
        return None;
    }
    quoted_literal(rest)
}

/// A `require("x")` or a dynamic `import("x")`. The dynamic form's
/// argument is a value, so the relation is never certain.
fn node_calls(line: &str) -> Vec<(&str, bool)> {
    let mut found = Vec::new();
    for (keyword, dynamic) in [("require(", false), ("import(", true)] {
        let mut rest = line;
        while let Some(at) = rest.find(keyword) {
            rest = &rest[at + keyword.len()..];
            let Some(specifier) = quoted_literal(rest) else {
                break;
            };
            let consumed = specifier.len() + 2;
            if !specifier.is_empty() {
                found.push((specifier, dynamic));
            }
            rest = &rest[consumed.min(rest.len())..];
        }
    }
    found
}

/// Qualified calls only: a callee spelled with at least two segments
/// (`a::b(…)`, `a.b(…)`). A bare local call is not a cross-file
/// dependency, and reporting one would bury the real coverage gaps.
fn qualified_calls(line: &str) -> Vec<Relation<'_>> {
    let mut found = Vec::new();
    let mut cursor = 0;
    while let Some(offset) = line[cursor..].find('(') {
        let open = cursor + offset;
        let mut begin = open;
        while let Some(previous) = line[..begin].chars().next_back()
            && (previous.is_alphanumeric() || matches!(previous, '_' | '.' | ':'))
        {
            begin -= previous.len_utf8();
        }
        cursor = open + 1;
        let path = &line[begin..open];
        // A method call's head is the receiver; a `::` tail is the path.
        let path = path.strip_suffix("::").unwrap_or(path);
        if path.starts_with('.') || path.ends_with('.') || segments(path) < 2 {
            continue;
        }
        // `a::b::c(` names module `a::b`; `a.b.c(` names `a/b/c`.
        let (target, text) = match path.rsplit_once("::") {
            Some((module, _)) => (Target::Rust(Anchor::Crate), module),
            None => (
                Target::Node { spelled: false },
                path.trim_end_matches(".js"),
            ),
        };
        found.push(Relation {
            kind: EdgeKind::Call,
            target,
            text,
            dynamic: false,
        });
    }
    found
}

fn segments(path: &str) -> usize {
    path.split("::")
        .flat_map(|part| part.split('.'))
        .filter(|part| !part.is_empty())
        .count()
}

/// The first quoted literal's content, or `None` when the text holds no
/// balanced pair — a truncated literal names no specifier.
fn quoted_literal(text: &str) -> Option<&str> {
    let open = text.find(['"', '\''])?;
    let quote = text[open..].chars().next()?;
    let rest = &text[open + quote.len_utf8()..];
    let end = rest.find(quote)?;
    Some(&rest[..end])
}

// ----- the project's own watcher -----

/// What one coalesced watcher batch carries: the paths the backend
/// reported, whether it said it missed events, and whether the file set
/// itself moved. A batch is the unit one generation is cut from — never
/// one write per event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WatchBatch {
    /// The project-relative paths this batch reported.
    pub paths: BTreeSet<PathBuf>,
    /// The backend reported that its own change set is incomplete, so
    /// this batch is not the whole change set.
    pub missed: bool,
    /// A file appeared, vanished or was renamed: which documents resolve
    /// is no longer what the previous generation saw, so a narrow
    /// re-derivation cannot be trusted.
    pub file_set_moved: bool,
}

impl WatchBatch {
    /// Whether this batch must be re-derived whole rather than narrowed
    /// to its paths (INV-007). A repair is the honest response to a
    /// batch that cannot describe its own change set.
    pub fn needs_full_rebuild(&self) -> bool {
        self.missed || self.file_set_moved || self.paths.is_empty()
    }
}

/// The project watcher: the backend handle plus the receiving end of the
/// bounded channel the single index writer drains. The backend's
/// callback thread touches only a lock and a channel — no SQLite call
/// ever happens there.
pub struct IndexWatcher {
    /// The runtime's own state directory, which the watch excludes when
    /// it sits inside the watched root. Every generation the writer
    /// seals lands in it, so a watch that reported those writes would
    /// feed its own repairs: a rebuild writes a database, the database
    /// is reported as a change, and the batch asks for another rebuild.
    /// A runtime whose data root is also the project root is an ordinary
    /// deployment, so the exclusion is a correctness requirement and not
    /// a convenience.
    runtime_dir: Option<PathBuf>,
    pending: Arc<Mutex<WatchBatch>>,
    /// Whether the consumer that was handed the wake channel is still
    /// there. A wake send that finds the channel disconnected means the
    /// dispatch loop is gone, so the flag records it and the backend's
    /// own thread stops trying: the watch is on its way down and must
    /// not keep paying for a send that cannot land.
    consumer_live: Arc<AtomicBool>,
    /// Held for the watch itself; dropping the watcher stops it.
    _backend: notify::RecommendedWatcher,
}

/// How many distinct paths one pending batch may name. The set is
/// coalesced for the life of the process behind the lock, so it needs
/// a bound of its own: a checkout, a `target/` build or a branch switch
/// reports thousands of paths, and every one of them past this bound is
/// a change the batch can no longer describe. Overflow flips `missed`,
/// which is the honest verdict — a repair of the whole project — rather
/// than a silently narrowed re-derivation over a path set that stopped
/// early.
pub const WATCH_PATH_CAPACITY: usize = 4_096;

/// Directory names the project's own enumeration excludes under the
/// standard filters, so the watch does not report the build output,
/// the version-control metadata or a dependency tree as project
/// changes. The list is the recorded one, not a per-caller guess.
const WATCH_IGNORED_DIRS: &[&str] = &[".git", "target", "node_modules"];

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("the project watch could not be started: {source}")]
    Unavailable {
        #[source]
        source: notify::Error,
    },
}

impl IndexWatcher {
    /// Starts watching `root` recursively: a relation can cross any
    /// directory boundary, and a backend that cannot watch the root is a
    /// typed refusal rather than a silently narrower index. The backend
    /// has no ignore filter of its own, so the recorded exclusions are
    /// applied where the events arrive — a `target/` build is not a
    /// change to the project, and the same walker excludes it from the
    /// enumeration a generation is cut from. Recorded paths are
    /// project-relative to `root`, so a batch names the documents the
    /// generation indexes.
    ///
    /// `runtime_dir` is the runtime's own state directory, excluded when
    /// it sits inside `root` — see [`IndexWatcher::runtime_dir`].
    ///
    /// `wake` is the consumer's own channel, held by the backend's
    /// callback: the batch is read through [`IndexWatcher::pending_batch`]
    /// and `wake` only says that something arrived. The consumer is the
    /// dispatch loop (INV-011), which blocks on that channel rather than
    /// polling for a change — a full channel is the overflow policy, and
    /// a disconnected one is the consumer's own teardown.
    ///
    /// # Errors
    /// Returns [`WatchError::Unavailable`] when the backend cannot be
    /// created or cannot watch the root.
    pub fn start(
        root: &Path,
        runtime_dir: Option<&Path>,
        wake: SyncSender<LoopEvent>,
    ) -> Result<Self, WatchError> {
        // The backend reports the real directory it watches, which is not
        // the spelling a caller passed when that path runs through a
        // symlink (`/var` against `/private/var` on macOS). Watching and
        // relativizing the canonical directory is what lets a reported
        // path be placed at all; a path still outside it is recorded as
        // a lost event rather than a narrow one.
        let watched = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let reported = watched.clone();
        let pending = Arc::new(Mutex::new(WatchBatch::default()));
        let consumer_live = Arc::new(AtomicBool::new(true));
        // Canonicalised on both sides, so a symlinked spelling of either
        // path still compares: an exclusion that does not match would
        // let the runtime's own writes back in.
        let watched_root = watched.clone();
        let runtime_dir = runtime_dir.and_then(|dir| {
            dir.canonicalize()
                .ok()
                .filter(|dir| dir.starts_with(&watched_root))
        });
        let sink = Arc::clone(&pending);
        let listening = Arc::clone(&consumer_live);
        let inside = runtime_dir.clone();
        let mut backend = notify::recommended_watcher(move |event| {
            record(
                &sink,
                &listening,
                &wake,
                &reported,
                inside.as_deref(),
                event,
            );
        })
        .map_err(|source| WatchError::Unavailable { source })?;
        backend
            .watch(&watched, RecursiveMode::Recursive)
            .map_err(|source| WatchError::Unavailable { source })?;
        Ok(Self {
            runtime_dir,
            pending,
            consumer_live,
            _backend: backend,
        })
    }

    /// The runtime's own state directory, when the watch excludes it.
    /// `None` when the runtime's data lives outside the watched root,
    /// which is the common deployment and needs no exclusion.
    pub fn runtime_dir(&self) -> Option<&Path> {
        self.runtime_dir.as_deref()
    }

    /// Whether the consumer that was handed the wake channel is still
    /// reachable. `false` once a wake found the channel disconnected:
    /// nothing is pinging that consumer any more, so a caller that
    /// rebuilt a loop must hand the watch a new one rather than believe
    /// a change will be reported.
    pub fn consumer_live(&self) -> bool {
        self.consumer_live.load(Ordering::Relaxed)
    }

    /// The batch as it stands right now, without waiting and without
    /// consuming it — what a writer polls to notice a change without
    /// blocking on the backend, and what a caller that must not lose the
    /// batch reads.
    pub fn peek_batch(&self) -> WatchBatch {
        match self.pending.lock() {
            Ok(batch) => batch.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// The batch as it stands right now, taking it: a writer that is
    /// about to cut a generation claims the whole set under one lock, so
    /// a batch is never split across two generations.
    pub fn pending_batch(&self) -> WatchBatch {
        take_batch(&self.pending)
    }
}

/// The pending batch, reset. A lock a panicking callback poisoned is
/// recovered rather than propagated: dropping the batch would lose a
/// change silently, which is the one outcome the index may never report
/// as current.
fn take_batch(pending: &Arc<Mutex<WatchBatch>>) -> WatchBatch {
    let mut batch = match pending.lock() {
        Ok(batch) => batch,
        Err(poisoned) => poisoned.into_inner(),
    };
    std::mem::take(&mut *batch)
}

/// One backend event, coalesced into the pending batch. The lock is
/// released before the wake-up is sent, so a full channel can never
/// block the backend's own thread.
fn record(
    pending: &Arc<Mutex<WatchBatch>>,
    consumer_live: &AtomicBool,
    sender: &SyncSender<LoopEvent>,
    watched: &Path,
    runtime_dir: Option<&Path>,
    event: notify::Result<Event>,
) {
    {
        let mut batch = match pending.lock() {
            Ok(batch) => batch,
            Err(poisoned) => poisoned.into_inner(),
        };
        match event {
            // The backend states that its own change set is incomplete.
            Ok(event) if event.need_rescan() => batch.missed = true,
            // Index reads trigger inotify opens without changing project bytes.
            Ok(event)
                if matches!(event.kind, EventKind::Access(kind)
                    if kind != notify::event::AccessKind::Close(notify::event::AccessMode::Write)) =>
                {}
            Ok(event) => {
                if kind_moves_the_file_set(&event) {
                    batch.file_set_moved = true;
                }
                for path in event.paths {
                    // The generation's file set is project-relative, so
                    // a path outside the watched root names no document
                    // it could hold: that is a change this batch cannot
                    // place, which is a lost event, not a narrow one.
                    let Ok(relative) = path.strip_prefix(watched) else {
                        batch.missed = true;
                        continue;
                    };
                    // The same directories the enumeration's ignore
                    // rules exclude carry no project document, so a
                    // build or a fetch is not a change to re-derive
                    // from. `need_rescan` already covers a rescan flag,
                    // so an event that is nothing but excluded noise
                    // leaves the batch as it stands.
                    if excluded_by_rules(relative) {
                        continue;
                    }
                    // The runtime's own writes are not project changes,
                    // and a batch that reported them would ask the owner
                    // to rebuild what it just wrote.
                    if runtime_dir.is_some_and(|dir| {
                        watched
                            .join(relative)
                            .canonicalize()
                            .is_ok_and(|path| path.starts_with(dir))
                    }) {
                        continue;
                    }
                    if batch.paths.len() < WATCH_PATH_CAPACITY {
                        batch.paths.insert(relative.to_path_buf());
                    } else {
                        // Past the bound this batch cannot describe its
                        // own change set, so it says so instead of
                        // narrowing a re-derivation to the paths that
                        // happened to arrive first.
                        batch.missed = true;
                    }
                }
            }
            Err(_) => batch.missed = true,
        }
    }
    // The wake is a hint, never a wait: the backend's own thread must
    // never block, and the coalesced set already carries this event's
    // paths whether the hint lands or not. A full channel is the
    // overflow policy — the consumer was already told. A disconnected
    // one means the consumer is gone, which is the runtime's teardown
    // and is recorded so the next event does not pay for the send.
    if !consumer_live.load(Ordering::Relaxed) {
        return;
    }
    if let Err(TrySendError::Disconnected(_)) = sender.try_send(LoopEvent::Index) {
        consumer_live.store(false, Ordering::Relaxed);
    }
}

/// Whether the event added, removed or renamed an entry — the file set
/// itself moved, so a narrow re-derivation would read a stale set.
fn kind_moves_the_file_set(event: &Event) -> bool {
    matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Remove(_) | EventKind::Modify(ModifyKind::Name(_))
    )
}

/// Whether a project-relative path sits under one of the recorded
/// exclusions. Any component matching is enough: the path is inside
/// that subtree, whatever its own name is.
fn excluded_by_rules(relative: &Path) -> bool {
    relative.components().any(|component| {
        matches!(component, std::path::Component::Normal(name)
            if name.to_str().is_some_and(|name| WATCH_IGNORED_DIRS.contains(&name)))
    })
}

#[cfg(test)]
mod tests {
    use super::{Event, EventKind, IndexWatcher, ModifyKind, WatchBatch, record};
    use crate::commands::LoopEvent;
    use notify::event::CreateKind;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex, mpsc};

    #[test]
    fn watcher_snapshots_keep_pending_until_atomic_take() {
        let created = WatchBatch {
            paths: BTreeSet::from([PathBuf::from("src/a.rs")]),
            missed: false,
            file_set_moved: true,
        };
        let accumulated = WatchBatch {
            paths: BTreeSet::from([PathBuf::from("src/a.rs"), PathBuf::from("src/b.rs")]),
            missed: false,
            file_set_moved: true,
        };
        let modified = WatchBatch {
            paths: BTreeSet::from([PathBuf::from("src/a.rs")]),
            missed: false,
            file_set_moved: false,
        };
        let missed = WatchBatch {
            paths: BTreeSet::new(),
            missed: true,
            file_set_moved: false,
        };
        let empty = WatchBatch::default();
        let (wake, woken) = mpsc::sync_channel(1);
        let watcher = IndexWatcher {
            runtime_dir: None,
            pending: Arc::new(Mutex::new(WatchBatch::default())),
            consumer_live: Arc::new(AtomicBool::new(true)),
            _backend: notify::recommended_watcher(|_| {}).expect("create unregistered backend"),
        };
        let root = Path::new("/watcher-snapshot-fixture");
        let emit = |event| {
            record(
                &watcher.pending,
                &watcher.consumer_live,
                &wake,
                root,
                None,
                event,
            );
        };
        let create = Event::new(EventKind::Create(CreateKind::File))
            .add_path(root.join("src/a.rs"))
            .add_path(root.join("src/a.rs"));
        emit(Ok(create.clone()));
        emit(Ok(create));
        let first = watcher.peek_batch();
        assert_eq!(first, created);
        assert!(first.needs_full_rebuild());
        let repeated = watcher.peek_batch();
        assert_eq!(repeated, created);
        assert!(repeated.needs_full_rebuild());
        assert!(matches!(woken.try_recv(), Ok(LoopEvent::Index)));

        emit(Ok(
            Event::new(EventKind::Modify(ModifyKind::Any)).add_path(root.join("src/b.rs"))
        ));
        let next = watcher.peek_batch();
        assert_eq!(next, accumulated);
        assert!(next.needs_full_rebuild());
        let claimed = watcher.pending_batch();
        assert_eq!(claimed, accumulated);
        assert!(claimed.needs_full_rebuild());
        let reset = watcher.pending_batch();
        assert_eq!(reset, empty);
        assert!(reset.needs_full_rebuild());
        assert!(matches!(woken.try_recv(), Ok(LoopEvent::Index)));

        emit(Ok(
            Event::new(EventKind::Modify(ModifyKind::Any)).add_path(root.join("src/a.rs"))
        ));
        let late = watcher.peek_batch();
        assert_eq!(late, modified);
        assert!(!late.needs_full_rebuild());
        let claimed = watcher.pending_batch();
        assert_eq!(claimed, modified);
        assert!(!claimed.needs_full_rebuild());
        let reset = watcher.pending_batch();
        assert_eq!(reset, empty);
        assert!(reset.needs_full_rebuild());
        assert!(matches!(woken.try_recv(), Ok(LoopEvent::Index)));

        emit(Err(notify::Error::generic("backend failure")));
        let failed = watcher.peek_batch();
        assert_eq!(failed, missed);
        assert!(failed.needs_full_rebuild());
        let claimed = watcher.pending_batch();
        assert_eq!(claimed, missed);
        assert!(claimed.needs_full_rebuild());
        let reset = watcher.pending_batch();
        assert_eq!(reset, empty);
        assert!(reset.needs_full_rebuild());
        assert!(matches!(woken.try_recv(), Ok(LoopEvent::Index)));
    }
}
