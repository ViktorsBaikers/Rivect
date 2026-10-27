//! The typed in-process symbol index (DEC-005): definition, reference
//! and type rows over the bundled grammars — no language-server
//! subprocess is spawned and no watcher runs (rebuild freshness belongs
//! to the index bundle). Every indexed document carries its LSP
//! identity — uri, content version, position encoding, workspace root —
//! and a document whose bytes moved under the index is stale: its rows
//! are withheld, never served as a current answer (AC-039a).
//!
//! # Budgets
//!
//! One index is built per request. A file past [`MAX_SYMBOL_FILE_BYTES`]
//! is never parsed; each parse stops after [`MAX_PARSE_CHECKS`], all of
//! them together after [`MAX_INDEX_PARSE_CHECKS`] or the build's
//! deadline (the facade's: [`MAX_INDEX_PARSE_TIME`]), and the whole build
//! parses at most [`MAX_PARSED_BYTES`]; once the pool or the deadline is
//! spent, or a file is larger than the bytes left, the file fails before
//! its read. These bound ordinary parse work only: the
//! progress checks never run inside tree-sitter's GLR recovery, whose
//! time and memory are unbounded in-process on hostile input — the
//! wiring slice must run the parse in a resource-limited child process
//! before any runtime caller reaches this index (DEC-028, NOTE-004).
//! Each parsed file is walked once with a tree cursor — ancestor
//! context rides a stack, so the walk is linear in the tree — and fails
//! past [`MAX_TREE_DEPTH`], [`MAX_FILE_NODES`] or a scope path rendering
//! past [`MAX_SCOPE_PATH_BYTES`]. Rows are charged as the walk records
//! them against the index-wide [`MAX_SYMBOL_ROWS`], and every byte of
//! text and scope the index keeps against [`MAX_RETAINED_BYTES`]; the
//! file whose parse or walk crosses a budget is a failed entry, never a
//! silently partial one. Only a references request keeps use rows; a
//! definition or type request keeps definitions (and, for binding,
//! imports) alone. An answer sorts and truncates lightweight picks
//! before it builds any served row.
//!
//! # Resolution (DEC-024, DEC-025, DEC-029)
//!
//! A row claims `resolved: true` only when exactly one binding is
//! certain under the rules modelled here; everything else is
//! `resolved: false` — unknown, never an absent dependency.
//!
//! - Only allowlisted use positions bind: an identifier in a value
//!   expression (call target, operand, argument, initializer, the
//!   receiver of a field access, …), a type identifier in a type
//!   position (annotation, generic argument, bound, `impl` target, …),
//!   and the last segment of a path `q::name` that itself sits in such
//!   a position. Every other use is opaque and never binds: path
//!   qualifier segments, macro names and macro token trees, members
//!   after a receiver (`x.f`, `x.m()`, struct literal and pattern field
//!   names, TypeScript properties and keys), `use`/import leaves,
//!   patterns, decorators, JSX names, export specifiers, `typeof`
//!   queries and anything else unlisted. Lifetimes and loop labels are
//!   no rows at all.
//! - A value binds only a local (parameter, variable) or a value item;
//!   a type binds only a type-level item or type parameter.
//! - Members — what an `impl`/`trait`/`struct`/`enum`/`union`, a class,
//!   interface, object type or object literal declares — are never
//!   candidates, bare or through a path. Type parameters are not
//!   members.
//! - Certainty stays inside the use's own document: a candidate in
//!   another document, one or many, leaves the use unknown, because
//!   imports, globs and preludes are not followed. A bare Rust name does
//!   not cross a `mod` boundary, and an item nested in a Rust function
//!   sees none of that function's locals or generics. A name the index
//!   cannot follow, met on the way outward before a candidate, makes the
//!   use unknown: a `use`/import of it, a Rust glob, a macro invocation
//!   that may expand to items (one at a module's top level, or a
//!   brace-delimited one anywhere: `thread_local! { … }`), a
//!   TypeScript `var` of it (hoisted to its function or namespace), a
//!   TypeScript `infer` or mapped-type key of it (their conditional type
//!   or index signature is an anonymous scope), or a Rust local of it
//!   when the document has a same-name `const`, `static`, `struct` or
//!   import, or when such a glob or macro sits in the local's own scope
//!   or any scope around it (the pattern may name an item it brings).
//!   So do several candidates
//!   in one scope (`#[cfg]` twins) and a candidate in a scope the
//!   document opens with blocks that do not share names — a TypeScript
//!   namespace it reopens, or a module or namespace beside a same-name
//!   function or type.
//! - Scopes are named containers (Rust `mod`/`impl`/`trait`/type items/
//!   `fn`/`macro_rules!`; TypeScript namespaces, modules, classes,
//!   interfaces, enums, functions, methods) and anonymous ones (Rust
//!   blocks, closures, match arms, `if`/`while`/`for`, signature-only
//!   declarations and fn types; TypeScript blocks, arrow/function/class
//!   expressions, `catch`, `for` loops, `switch` bodies, signatures,
//!   function and constructor types, conditional types, index
//!   signatures, and namespaces named by a dotted path or a string).
//! - Locals bind only where declared: `let x = x + 1` reads the outer
//!   `x`; an `if let`/`while let` binding is visible in its block alone;
//!   a `for` pattern in the loop body alone; a parameter inside its own
//!   function, closure, arm or `catch` only; each plain name a
//!   TypeScript `using` declaration lists (`using a = …, b = …`, the
//!   first on the `using` token's line) like a `const` — when the
//!   declaration stands as a statement or a `for` head; as an argument
//!   or inside parentheses it is an assignment. A TypeScript
//!   use ahead of a same-scope declaration sits in its temporal dead
//!   zone — unknown.
//!   Items bind throughout their scope whatever the order.
//! - A path `q::name` is certain only through modules: its first
//!   segment must name a module of the use's own document — looked up
//!   outward like a bare name, with no type item, type parameter or
//!   import of that name met first — and every later segment a module
//!   inside it. A path through a type (`T::new`, `String::len`, `E::A`,
//!   a trait method) hangs on impls and dispatch the index does not
//!   model: unknown. In Rust, `self::` starts at the enclosing module
//!   and `crate::` at the root, but only in a crate-root document
//!   (`src/lib.rs`, `src/main.rs`, `src/bin/*.rs`, …; see
//!   `module_path`); `super` is never guessed. Rust anchors mean nothing
//!   in TypeScript, where `crate.I` names a namespace `crate` — and a
//!   query's `crate::`/`self::` qualifier addresses no TypeScript
//!   document (`::name` addresses its root).
//! - No use in a damaged document — one whose tree carries an error or
//!   missing node — is certain: the node may hold the declaration it
//!   names. Its definitions still serve.
//!
//! A bare query serves every same-name use. A qualified references
//! query serves each use certainly bound to a definition the qualifier
//! matches plus every same-name use that binds nowhere, unresolved — a
//! use the model cannot bind is never dropped as an absence. A
//! qualifier matches by trailing named segments, stepping over
//! anonymous scopes between them; a definition in an anonymous scope
//! answers the named path its row renders, and so do the uses certainly
//! bound to it — a references answer serves what the same qualifier's
//! definition answer finds. A qualifier runs on past a Rust document's top
//! level into the module path its location derives (`src/b/c.rs` →
//! `b::c`), so `b::c::helper` and `c::helper` both find `helper` there
//! and the uses certainly bound to it — binding itself still never
//! crosses a file; a document whose module path cannot be
//! derived withholds a row that would need it, and the answer discloses
//! it (`PartialReason::UnknownModulePaths`) rather than claim absence.
//! A type answer serves the certain candidate, else the own document's
//! candidates, else the nearest same-name type items of any document —
//! each unresolved — else the annotation's spelling site.
//!
//! Known limits: to a use, files are not modules and imports, globs,
//! preludes and re-exports are not followed — every use they could
//! reach stays unknown; traits, method dispatch,
//! type inference and macro expansion are not modelled, so no path
//! through a type is ever certain; a file's module path is the Cargo
//! layout's convention (`#[path]` is not seen), derived from the path
//! relative to the query root — a root other than the package's (a
//! workspace root, `src/` itself) derives none or the wrong one, so the
//! wiring slice must hand the index the package root; a parenthesized
//! or bracketed macro invocation inside a body is read as introducing no
//! item, though an item-defining one (`some_items!(…);`) can — a use
//! walking past it may bind an outer item it shadows; a glob or an
//! item-introducing macro makes unknown every Rust local in its own
//! scope and every scope inside it, even inside a nested `mod` it does
//! not reach; every use of a TypeScript
//! `var` — even beside its declaration — stays unknown; a TypeScript
//! `for (using … of …)` head is outside the grammar, and so is an
//! assignment to a variable named `using` (a damaged document: no use in
//! it certain, and the latter's names are lost to the error node); a
//! TypeScript enum member used bare inside
//! its own enum stays unknown; declarations merged across files are
//! never certain.

use crate::context::{
    Grammar, MAX_AST_FILE_BYTES, REFERENCES_INTERFACE, SYMBOL_INTERFACE, read_capped,
};
use crate::index::{MatchKind, SearchMatch, SourceRef, SymbolMatch, SymbolRole};
use grep_matcher::Matcher;
use grep_regex::RegexMatcherBuilder;
use lsp_types::{Position, PositionEncodingKind, Range, Uri};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, Instant, UNIX_EPOCH};
use tree_sitter::{Node, ParseOptions, ParseState, Parser};

/// The largest file the index parses. Dense Rust (`a;` in a body)
/// spends 1.5 parse-tree nodes per byte, so it crosses
/// [`MAX_FILE_NODES`] near 683 KiB; ordinary source measured about 0.2
/// nodes per byte (this crate's `src/context.rs` repeated to 1 MiB: 218 k
/// nodes), five times under the node budget at the cap. A larger file
/// is refused before its parse, whose cost and memory grow with it
/// (8 MiB of dense source: 12.6 M nodes, 2.4 GB, 4.6 s optimized).
pub const MAX_SYMBOL_FILE_BYTES: u64 = 1024 * 1024;

/// The most progress checks one file's parse may take. tree-sitter
/// invokes the progress callback about once per 100 parse operations,
/// but never inside GLR reduction or error recovery, so the count
/// tracks ordinary parse work only: a parse stalled in recovery grows
/// time and memory between two checks without any bound here
/// (TypeScript `x<y,` repeated: 64 KiB of source took 4.3 GB). Nothing
/// in-process can stop that under `unsafe = forbid`; untrusted parses
/// must run in a resource-limited child process before any runtime
/// caller reaches this index (DEC-028, NOTE-004). A file of exactly
/// [`MAX_FILE_NODES`] dense nodes takes 48 964 checks; this leaves a
/// third more, and a parse past it — a file the walk would refuse
/// anyway — stops as a failed entry.
pub const MAX_PARSE_CHECKS: u64 = 1 << 16;

/// The most progress checks one index build's parses may take in all,
/// drawn file by file; a parse that would cross it stops as a failed
/// entry. Twice [`MAX_PARSE_CHECKS`], so one file at its own budget
/// never starves the rest. Measured in an optimized build: this
/// repository's 51 Rust sources (3.4 MB) take 24 691 checks in about
/// 0.3 s; ordinary Rust costs
/// ~13 µs a check (the pool is ~24 MiB of it, ~1.7 s), dense `a;` ~24 µs
/// (~3.2 s) and TypeScript recovery input `a,(` ~64 µs (~8.4 s) — where
/// 33 such 1 MiB files had taken 122 s under the per-file budget alone.
pub const MAX_INDEX_PARSE_CHECKS: u64 = 1 << 17;

/// The wall-clock time one index build's parses may run — the deadline
/// the facade hands `SymbolIndex::build` until a caller supplies its
/// own. Checked in the same progress callback: a parse still running
/// past it stops as a failed entry, and every file after it fails
/// unread. It carries real load, not only a backstop behind
/// [`MAX_INDEX_PARSE_CHECKS`]: GLR-heavy TypeScript spends far more
/// time per check than the pool's measured Rust and recovery inputs (60
/// files of 16 KiB stopped here at 10.15 s). Like the pool it cannot
/// reach inside recovery (see [`MAX_PARSE_CHECKS`]).
pub const MAX_INDEX_PARSE_TIME: Duration = Duration::from_secs(10);

/// The most source bytes one index build hands the parser across its
/// files. Each file is charged before its parse, and one that would
/// cross the budget is a failed entry, never parsed. Bytes do not bound
/// parse cost — [`MAX_PARSE_CHECKS`] says what does and does not.
pub const MAX_PARSED_BYTES: u64 = 32 * 1024 * 1024;

/// The deepest parse-tree node a file may carry (root = 0). The walk's
/// ancestor stack lives on the heap, so the cap bounds memory and the
/// per-row scope path, not native recursion; real sources sit far
/// below it, and a deeper file is a failed entry.
pub const MAX_TREE_DEPTH: usize = 1024;

/// The most parse-tree nodes (anonymous tokens included) one file's
/// walk may visit — annotation, `impl`-target and TypeScript `using`
/// lookups draw from the same budget, so per-file work stays linear and
/// bounded however the tree is shaped.
pub const MAX_FILE_NODES: usize = 1 << 20;

/// The most rows one index build may retain across all files, charged
/// row by row: the file whose walk records the first row past it is a
/// failed entry; later files that retain nothing still index.
pub const MAX_SYMBOL_ROWS: usize = 1 << 16;

/// The longest scope path a served row may render (`a::b::…`, anonymous
/// scopes skipped). A file whose walk enters a longer path fails, so a
/// served row never carries more than this much scope text.
pub const MAX_SCOPE_PATH_BYTES: usize = 4096;

/// The most text and scope structure one index build may keep — row
/// names and spelled qualifiers, type annotations, interned scopes — a
/// quarter KiB per row at the full row budget. Charged as it is kept:
/// the file whose walk crosses it is a failed entry. Only a type
/// parameter dropped with its document (see `SymbolIndex::index_file`)
/// returns its name's bytes.
pub const MAX_RETAINED_BYTES: usize = 16 * 1024 * 1024;

/// What one interned scope costs the retained-bytes budget beyond its
/// name: the node and its entry in the parent's child map.
const SCOPE_NODE_BYTES: usize = 128;

/// What recording one document's bearer of a named scope costs the
/// retained-bytes budget.
const BEARER_ENTRY_BYTES: usize = 32;

/// The name a Rust glob import (`use m::*;`) is recorded under — never
/// an identifier, so it never meets a requested name.
const GLOB: &str = "*";

/// The semantic operation a `code.symbol`/`code.references` query runs —
/// carried on `Query::symbol_op`, never negotiated from the pattern
/// text: the op is the semantics, the interface name is routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolOp {
    /// Where a name is defined — `textDocument/definition`-shaped.
    Definition,
    /// Where a name is used — `textDocument/references`-shaped.
    References,
    /// Which named type a definition produces — a `-> T`/`: T`
    /// annotation resolves to `T`'s type-level definition; a type-level
    /// name resolves to itself; an enum member to its enum; an
    /// unannotated value names no type.
    Type,
}

impl SymbolOp {
    /// The op an interface name carries: `code.symbol` asks for
    /// definitions, `code.references` for uses; any other name carries
    /// none. A caller building a query from a name takes the op from
    /// here, so a reference name can never answer definitions.
    pub fn from_interface_name(name: &str) -> Option<Self> {
        match name {
            SYMBOL_INTERFACE => Some(Self::Definition),
            REFERENCES_INTERFACE => Some(Self::References),
            _ => None,
        }
    }
}

/// A single-document pin on a symbol query — the LSP `textDocument`
/// analogue carried on `Query::document`. `path` is root-relative and
/// boundary-checked like `source.slice`; `version` pins the request to
/// the document's content version (a mismatch or an unverifiable pin is
/// a typed refusal, never a stale answer); `encoding` is the caller's
/// position space — only utf-8 is served.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentPin {
    pub path: PathBuf,
    pub version: Option<i32>,
    pub encoding: Option<PositionEncodingKind>,
}

/// One file the enumeration prelude hands the index — the caller owns
/// walking and ignore decisions; the index owns grammar claims and
/// bounded reads.
#[derive(Debug, Clone)]
pub struct CandidateFile {
    pub absolute: PathBuf,
    pub relative: PathBuf,
    pub ignored: bool,
}

/// What one build observed — the honest coverage counters the facade
/// folds into `PartialReason`s, plus the work the parses and walks did.
#[derive(Debug, Default, Clone)]
pub struct IndexCoverage {
    /// Files no admitted grammar claims — fallback-scan candidates.
    pub unsupported: u64,
    /// Files that could not be read bounded, decoded, named, parsed
    /// inside the parse budgets (or came once they were spent), or
    /// walked inside the depth, node, row, scope and retained budgets.
    pub failed: u64,
    /// Indexed files whose tree carries error or missing nodes.
    pub damaged: u64,
    /// Parse-tree nodes the walks visited, failed walks included, and
    /// their lookup steps — each file's draw on [`MAX_FILE_NODES`]. A
    /// verification counter (read
    /// by the budget tests): the build's walk work stays auditable as
    /// linear in what it parsed.
    pub nodes_visited: u64,
    /// Progress checks the parses took, stopped parses included — each
    /// file's draw on [`MAX_PARSE_CHECKS`], all of them the build's draw
    /// on [`MAX_INDEX_PARSE_CHECKS`]. A verification counter (read by the
    /// budget tests).
    pub parse_checks: u64,
}

/// The `(len, mtime)` identity a document's freshness is checked
/// against — re-stat at query time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<i128>,
}

fn file_stamp(meta: &std::fs::Metadata) -> FileStamp {
    FileStamp {
        len: meta.len(),
        modified: meta
            .modified()
            .ok()
            .and_then(|mtime| mtime.duration_since(UNIX_EPOCH).ok())
            .map(|since| since.as_nanos() as i128),
    }
}

impl FileStamp {
    /// Does `now` still describe the indexed bytes? An mtime that could
    /// not be read on either side is unverifiable — never current.
    fn is_current(self, now: Self) -> bool {
        self.modified.is_some() && self == now
    }
}

/// One parsed document inside the index — its LSP identity plus the
/// freshness stamp its rows are gated on.
#[derive(Debug)]
pub struct IndexedDocument {
    /// `file://` uri of the absolute path — the LSP document identity.
    pub uri: Uri,
    /// `file://` uri of the workspace root the index was built under.
    pub root: Uri,
    /// Content-derived version (sha-256 prefix, i32-positive): same
    /// bytes, same version — a document identity, not a wall clock.
    pub version: i32,
    /// The position space every row's range is expressed in.
    pub encoding: PositionEncodingKind,
    /// Whether the ignore baseline flags it — surfaced on served rows.
    pub ignored: bool,
    /// The tree carries error or missing nodes: intact rows still
    /// serve, but the damaged span may hide some.
    pub damaged: bool,
    grammar: Grammar,
    relative: PathBuf,
    absolute: PathBuf,
    stamp: FileStamp,
    /// The module path the document's top level lives at, outermost
    /// first — empty at a crate root and for every TypeScript document
    /// (whose files share one root); `None` for a Rust file outside the
    /// layouts `module_path` derives.
    module: Option<Vec<Box<str>>>,
}

impl IndexedDocument {
    /// A Rust crate root — where `crate::` names this document's own
    /// top level.
    fn is_crate_root(&self) -> bool {
        self.grammar == Grammar::Rust && self.module.as_ref().is_some_and(Vec::is_empty)
    }

    /// Is the file on disk still the indexed bytes? A document that
    /// cannot be re-stat'd, was replaced, grew/shrank, or whose mtime is
    /// unreadable is stale — its rows are withheld rather than served
    /// under a dead version (AC-039a). `len`+`mtime` is the same
    /// freshness signal the other legs' staleness notes record; a
    /// content compare would cost a re-read of every document per
    /// query.
    pub fn is_stale(&self) -> bool {
        let Ok(meta) = std::fs::metadata(&self.absolute) else {
            return true;
        };
        !meta.is_file() || !self.stamp.is_current(file_stamp(&meta))
    }
}

/// A row's coordinates: the name node's LSP range plus the same span as
/// document bytes.
#[derive(Debug, Clone, Copy)]
struct Span {
    range: Range,
    start_byte: u64,
    end_byte: u64,
}

impl Span {
    fn of(node: &Node<'_>) -> Self {
        let start = node.start_position();
        let end = node.end_position();
        Self {
            // tree-sitter columns are byte offsets — utf-8's unit.
            range: Range {
                start: Position::new(start.row as u32, start.column as u32),
                end: Position::new(end.row as u32, end.column as u32),
            },
            start_byte: node.start_byte() as u64,
            end_byte: node.end_byte() as u64,
        }
    }
}

/// Which kind of definition a use looks its name up among.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Namespace {
    /// Locals, functions, constants, statics, unit/tuple structs,
    /// TypeScript classes, enums and namespaces.
    Value,
    /// Type-level items and type parameters.
    Type,
}

/// How a use names its target.
#[derive(Debug)]
enum Spelling {
    /// An allowlisted position: a bare name, bound lexically, or the
    /// last segment of `q::name` — `q` as written (TypeScript `.` read
    /// as `::`).
    Bindable {
        namespace: Namespace,
        qualifier: Option<Box<str>>,
    },
    /// Any other position: never bound.
    Opaque,
    /// A `use`/import leaf (or, named [`GLOB`], a Rust glob): never
    /// bound itself, and a binding in the scope it sits in that the
    /// index does not follow.
    Import,
}

/// A recorded row's role inside the index — the internal shape; served
/// rows carry `SymbolRole` instead.
#[derive(Debug)]
enum RowRole {
    /// A definition site; `type_ref` is the named type its annotation
    /// spells — `fn f() -> T`/`const X: T`/`let x: T`/`field: T` —
    /// recorded only on the requested name's value-level definitions
    /// for a type query. Type-level definitions carry none: their name
    /// is their type.
    Definition { type_ref: Option<TypeRef> },
    /// A use site and how it spells its target.
    Reference { spelling: Spelling },
}

/// Where a definition's annotation names its type — the last path
/// segment, its spelled qualifier, the spelling site's coordinates (so
/// an unresolved type still reports where it was written) and the scope
/// the annotation sits in, which is where its name resolves from.
#[derive(Debug)]
struct TypeRef {
    name: Box<str>,
    qualifier: Option<Box<str>>,
    span: Span,
    scope: usize,
}

/// One retained row — a definition or a use of a name — with the name
/// node's coordinates, its interned scope and the role payload.
#[derive(Debug)]
struct IndexedSymbol {
    document: usize,
    /// The row's own text when it is not the requested name — the
    /// common row repeats the request and stores nothing.
    name: Option<Box<str>>,
    symbol_kind: &'static str,
    scope: usize,
    span: Span,
    /// The document bytes `[from, until)` a local binding is visible
    /// over; items are visible throughout their scope.
    visible: (u64, u64),
    /// A definition a member-bearing container declares — reachable
    /// only through a path, never bare.
    member: bool,
    role: RowRole,
}

impl IndexedSymbol {
    fn name<'r>(&'r self, requested: &'r str) -> &'r str {
        self.name.as_deref().unwrap_or(requested)
    }
}

/// Parameters and variables bind only inside their own document and
/// only where declared; every other definition kind is an item.
fn is_local(kind: &str) -> bool {
    matches!(kind, "parameter" | "variable")
}

/// Which namespaces a definition kind binds in: `(value, type)`. A Rust
/// struct is also a value (its unit or tuple constructor); a TypeScript
/// class or enum is both; modules, macros, fields and aliases bind in
/// neither — a path reaches a module, an alias is an import.
fn namespaces(grammar: Grammar, kind: &str) -> (bool, bool) {
    match kind {
        "function" | "method" | "const" | "static" | "parameter" | "variable" | "namespace"
        | "member" => (true, false),
        "struct" | "class" => (true, true),
        "enum" => (grammar != Grammar::Rust, true),
        "union" | "trait" | "type" | "interface" | "type_parameter" => (false, true),
        _ => (false, false),
    }
}

/// A named scope a qualifier segment may walk into — a module.
const PATH_SCOPE: u8 = 1;
/// A Rust `mod`: a bare name's walk stops after it.
const MODULE_SCOPE: u8 = 1 << 1;
/// A function: never a qualifier segment, and a Rust item nested inside
/// sees none of its locals or generics.
const FUNCTION_SCOPE: u8 = 1 << 2;
/// A named scope the document opens with blocks that do not share their
/// names: a TypeScript namespace opened more than once, or a module or
/// namespace merged with a same-name function or type.
const REOPENED: u8 = 1 << 3;
/// A TypeScript function or namespace — where a `var` inside it lives.
const HOISTS: u8 = 1 << 4;

/// The scope paths retained rows live in, interned as a trie: each
/// language family has its own root, and a named path shared by two
/// files is one node — the flattened root scope the module docs
/// describe. Anonymous scopes are keyed by `(document, start byte)`, so
/// they are never shared across documents; what bore a named scope is
/// recorded per document, so one file's `mod x` never makes another's
/// `fn x` walkable.
#[derive(Debug)]
struct ScopeTable {
    nodes: Vec<ScopeNode>,
    /// `(scope, document)` → the bearer categories that opened it there.
    bearers: BTreeMap<(usize, usize), u8>,
}

#[derive(Debug)]
struct ScopeNode {
    parent: Option<usize>,
    /// `None` for an anonymous scope — no path names it.
    name: Option<Box<str>>,
    /// The nearest named scope (or root) at or above this one.
    named_at: usize,
    named: BTreeMap<Box<str>, usize>,
    anonymous: BTreeMap<(usize, usize), usize>,
}

impl ScopeNode {
    fn new(parent: Option<usize>, name: Option<Box<str>>, named_at: usize) -> Self {
        Self {
            parent,
            name,
            named_at,
            named: BTreeMap::new(),
            anonymous: BTreeMap::new(),
        }
    }
}

impl ScopeTable {
    fn new() -> Self {
        Self {
            nodes: vec![ScopeNode::new(None, None, 0), ScopeNode::new(None, None, 1)],
            bearers: BTreeMap::new(),
        }
    }

    /// The root a grammar's rows live under — TypeScript and TSX share
    /// one family.
    fn root_for(grammar: Grammar) -> usize {
        match grammar {
            Grammar::Rust => 0,
            Grammar::TypeScript | Grammar::Tsx => 1,
        }
    }

    /// The named child `name` of `parent`, and whether it was new.
    fn intern_named(&mut self, parent: usize, name: &str) -> (usize, bool) {
        if let Some(&id) = self.nodes[parent].named.get(name) {
            return (id, false);
        }
        let id = self.nodes.len();
        self.nodes
            .push(ScopeNode::new(Some(parent), Some(name.into()), id));
        self.nodes[parent].named.insert(name.into(), id);
        (id, true)
    }

    /// The anonymous child of `parent` keyed `(document, start byte)`,
    /// and whether it was new.
    fn intern_anonymous(&mut self, parent: usize, key: (usize, usize)) -> (usize, bool) {
        if let Some(&id) = self.nodes[parent].anonymous.get(&key) {
            return (id, false);
        }
        let id = self.nodes.len();
        let named_at = self.nodes[parent].named_at;
        self.nodes
            .push(ScopeNode::new(Some(parent), None, named_at));
        self.nodes[parent].anonymous.insert(key, id);
        (id, true)
    }

    fn parent(&self, id: usize) -> Option<usize> {
        self.nodes[id].parent
    }

    fn is_anonymous(&self, id: usize) -> bool {
        self.nodes[id].name.is_none() && self.nodes[id].parent.is_some()
    }

    /// The bearer categories `document` opened scope `id` with.
    fn bearer(&self, id: usize, document: usize) -> u8 {
        self.bearers.get(&(id, document)).copied().unwrap_or(0)
    }

    /// The `::`-joined named path, outermost first — `""` at a root;
    /// anonymous scopes are skipped.
    fn render(&self, mut id: usize) -> String {
        let mut parts = Vec::new();
        while let Some(parent) = self.parent(id) {
            if let Some(name) = self.nodes[id].name.as_deref() {
                parts.push(name);
            }
            id = parent;
        }
        parts.reverse();
        parts.join("::")
    }

    /// Does scope `id` answer the query's `q` qualifier? Segment-suffix
    /// match over named scopes — `Foo` matches `m::Foo`, `a::b` matches
    /// `x::a::b`, anonymous scopes between them stepped over — so a
    /// partial path addresses every scope ending in it; `crate::q`
    /// anchors the match at the crate root and `::name` (an empty `q`)
    /// means the crate root itself. An anonymous `id` answers from the
    /// nearest named scope around it — the path its row renders.
    /// Segments left over at the scope root go on into `module`, the
    /// path the document's root lives at; `None` there — a path that
    /// cannot be derived — leaves such a match undecided (`None`).
    fn ends_with(&self, id: usize, q: &str, module: Option<&[Box<str>]>) -> Option<bool> {
        let (anchored, q) = query_anchor(q);
        let mut current = self.nodes[id].named_at;
        let mut segments = q.rsplit("::").filter(|segment| !segment.is_empty());
        let mut pending = segments.next();
        while let Some(segment) = pending {
            let node = &self.nodes[current];
            let Some(parent) = node.parent else {
                break;
            };
            if node.name.as_deref() != Some(segment) {
                return Some(false);
            }
            current = self.nodes[parent].named_at;
            pending = segments.next();
        }
        if pending.is_none() && self.nodes[current].parent.is_some() {
            return Some(!anchored);
        }
        // At the scope root: what is left names the module path's tail.
        let Some(module) = module else {
            return (pending.is_none() && !anchored).then_some(true);
        };
        let mut outer = module.iter().rev();
        for segment in pending.into_iter().chain(segments) {
            if outer.next().map(|part| &**part) != Some(segment) {
                return Some(false);
            }
        }
        Some(!anchored || outer.next().is_none())
    }
}

/// A query qualifier split into (anchored at the root, the rest):
/// `crate::a` → `(true, "a")`, `crate` or `""` → `(true, "")`.
fn query_anchor(q: &str) -> (bool, &str) {
    match q.strip_prefix("crate::") {
        Some(rest) => (true, rest),
        None if q == "crate" || q.is_empty() => (true, ""),
        None => (false, q),
    }
}

/// Where a spelled qualifier's path starts.
#[derive(Debug, Clone, Copy)]
enum Anchor<'q> {
    /// `crate::rest` — at the root.
    Root(&'q str),
    /// `self::rest` — at the use's enclosing module.
    Module(&'q str),
    /// `first::rest` — `first` looked up outward from the use.
    Lexical(&'q str),
}

/// A use's spelled qualifier normalized: a `super` segment — module
/// structure the index does not model — makes it unusable (`None`).
fn spelled_anchor(qualifier: &str) -> Option<Anchor<'_>> {
    if qualifier.split("::").any(|segment| segment == "super") {
        return None;
    }
    Some(match qualifier {
        "crate" => Anchor::Root(""),
        "self" => Anchor::Module(""),
        _ => match (
            qualifier.strip_prefix("crate::"),
            qualifier.strip_prefix("self::"),
        ) {
            (Some(rest), _) => Anchor::Root(rest),
            (None, Some(rest)) => Anchor::Module(rest),
            (None, None) => Anchor::Lexical(qualifier),
        },
    })
}

/// One symbol-leg request — the operation, the name (with its `scope::`
/// qualifier split out by the caller), an optional document pin and the
/// caller's bound. An index is built for exactly one request.
#[derive(Debug, Clone, Copy)]
pub struct SymbolRequest<'a> {
    /// The symbol's name — the pattern text after any `scope::` split.
    pub name: &'a str,
    /// The `scope::name` qualifier the pattern spelled, if any — matched
    /// against scopes by segment suffix (see the facade's `Query` docs).
    pub scope: Option<&'a str>,
    pub op: SymbolOp,
    /// The resolved `textDocument` pin: it selects which document's
    /// definitions/uses are the subject. A use binds only inside its own
    /// document, so a references answer draws on the pinned one alone; a
    /// type answer may serve any fresh document's candidates.
    pub document: Option<&'a Uri>,
    /// The required positive bound on returned rows.
    pub limit: usize,
}

/// What the index answered — the rows plus the honesty counters the
/// facade folds into `Completeness`.
#[derive(Debug, Default)]
pub struct SymbolAnswer {
    pub matches: Vec<SearchMatch>,
    /// Stale documents the answer could draw on — every one, or under a
    /// pin the pinned one (and every one for a type answer, whose
    /// candidates may live anywhere). Their rows were withheld.
    pub stale_documents: u64,
    /// Damaged documents the served rows come from, plus the pinned one.
    pub damaged_documents: u64,
    /// More rows existed than the limit served.
    pub truncated: bool,
    /// Fallback candidates that could not be scanned for hints.
    pub unreadable_fallback: u64,
    /// Documents holding a same-name definition, or a use certainly bound
    /// at their top level, a qualified query could not place: whether it
    /// matches hangs on a module path their location does not derive.
    /// Their rows were withheld.
    pub unknown_module_paths: u64,
    /// Resolution steps the answer took — scopes examined, binding
    /// decisions, qualifier segments walked and candidate rows served. A
    /// verification counter (read by the budget tests): resolution work
    /// stays auditable as linear in the uses it resolved.
    pub resolution_steps: u64,
}

/// The typed index for one request: built from candidate files in one
/// pass, then answered — repeatedly, so freshness is re-checked per
/// answer.
pub struct SymbolIndex<'a> {
    request: SymbolRequest<'a>,
    documents: Vec<IndexedDocument>,
    /// Files no admitted grammar claimed — the literal-hint scan pool.
    unclaimed: Vec<CandidateFile>,
    /// Retained rows, in (walk-order, byte-offset) order.
    rows: Vec<IndexedSymbol>,
    scopes: ScopeTable,
    /// What is left of [`MAX_RETAINED_BYTES`].
    retained_left: usize,
    /// What is left of [`MAX_PARSED_BYTES`].
    parsed_left: u64,
    /// What is left of [`MAX_INDEX_PARSE_CHECKS`].
    checks_left: u64,
    /// When the build's parses stop (`None`: not representable, so every
    /// parse stops).
    parse_deadline: Option<Instant>,
    /// The pinned document was a claimed candidate that failed.
    pin_failed: bool,
    /// The build's honest coverage counters.
    pub coverage: IndexCoverage,
    /// The pinned query root — the boundary the package search stops at.
    root: PathBuf,
    /// Resolved package roots, per file directory: a build reads many
    /// files from few directories, and each miss is a filesystem walk.
    packages: BTreeMap<PathBuf, PathBuf>,
}

/// A file's walk crossed one of its budgets.
struct OverBudget;

/// `(scope, document)` → whether it answers an answer's qualifier;
/// `None` when the document's module path cannot decide it.
type Placed = BTreeMap<(usize, usize), Option<bool>>;

/// Draws `bytes` from a retained-bytes allowance.
fn spend(left: &mut usize, bytes: usize) -> Result<(), OverBudget> {
    *left = left.checked_sub(bytes).ok_or(OverBudget)?;
    Ok(())
}

impl<'a> SymbolIndex<'a> {
    /// Builds the index for `request` over `files`: each candidate is
    /// grammar-claimed (else it joins the unclaimed fallback pool), read
    /// under [`MAX_SYMBOL_FILE_BYTES`], parsed, and walked once. The
    /// parses stop at `deadline`, which the caller owns and the index
    /// does not shorten — the facade passes now plus
    /// [`MAX_INDEX_PARSE_TIME`]; `None`, a deadline past what `Instant`
    /// can represent, stops every parse. Nothing is spawned; every
    /// outcome lands in `coverage`.
    pub fn build(
        root: &Path,
        files: impl IntoIterator<Item = CandidateFile>,
        request: SymbolRequest<'a>,
        deadline: Option<Instant>,
    ) -> Self {
        let root_uri = path_to_uri(root);
        let mut index = Self {
            request,
            documents: Vec::new(),
            unclaimed: Vec::new(),
            rows: Vec::new(),
            scopes: ScopeTable::new(),
            retained_left: MAX_RETAINED_BYTES,
            parsed_left: MAX_PARSED_BYTES,
            checks_left: MAX_INDEX_PARSE_CHECKS,
            parse_deadline: deadline,
            pin_failed: false,
            coverage: IndexCoverage::default(),
            root: root.to_path_buf(),
            packages: BTreeMap::new(),
        };
        for file in files {
            index.index_file(root_uri.as_ref(), file);
        }
        index
    }

    /// The indexed document with this uri, if any — the pin check's
    /// seam: absence means the pinned file was never indexed.
    pub fn document(&self, uri: &Uri) -> Option<&IndexedDocument> {
        self.documents.iter().find(|doc| &doc.uri == uri)
    }

    /// Whether the pinned document was a claimed candidate that could
    /// not be indexed — a failed entry, not an unknown path.
    pub fn pin_failed(&self) -> bool {
        self.pin_failed
    }

    /// The package root one file's module path is read from, memoized
    /// per directory (DEC-030 #4).
    fn package_of(&mut self, file: &CandidateFile) -> PathBuf {
        let directory = file
            .absolute
            .ancestors()
            .nth(1)
            .map_or_else(|| self.root.clone(), Path::to_path_buf);
        self.packages
            .entry(directory.clone())
            .or_insert_with(|| package_root_of(&directory, &self.root))
            .clone()
    }

    fn fail(&mut self, file: &CandidateFile) {
        self.coverage.failed += 1;
        if let Some(pin) = self.request.document
            && path_to_uri(&file.absolute).as_ref() == Some(pin)
        {
            self.pin_failed = true;
        }
    }

    fn index_file(&mut self, root_uri: Option<&Uri>, file: CandidateFile) {
        let Some(grammar) = Grammar::for_path(&file.relative) else {
            self.coverage.unsupported += 1;
            self.unclaimed.push(file);
            return;
        };
        // Once the check pool or the deadline is spent, every later file
        // fails unread — even one too small to reach a progress check,
        // which would otherwise parse past the bound — and so does one
        // larger than the bytes left to parse: the read would buy nothing.
        let spent =
            self.checks_left == 0 || self.parse_deadline.is_none_or(|end| Instant::now() >= end);
        let fits = std::fs::metadata(&file.absolute)
            .is_ok_and(|meta| meta.len() <= self.parsed_left.min(MAX_SYMBOL_FILE_BYTES));
        if spent || !fits {
            return self.fail(&file);
        }
        let Some((bytes, meta)) = read_capped(&file.absolute, MAX_SYMBOL_FILE_BYTES) else {
            return self.fail(&file);
        };
        if bytes.len() as u64 > MAX_SYMBOL_FILE_BYTES {
            return self.fail(&file);
        }
        // Rows carry node text — a file that is not utf-8 cannot name
        // its symbols, so it is a failed entry, not a partial parse.
        let Ok(source) = String::from_utf8(bytes) else {
            return self.fail(&file);
        };
        let (Some(uri), Some(root_uri)) = (path_to_uri(&file.absolute), root_uri) else {
            // A document that cannot be named cannot produce
            // LSP-shaped rows — a failed entry, never an anonymous one.
            return self.fail(&file);
        };
        let Some(parsed_left) = self.parsed_left.checked_sub(source.len() as u64) else {
            return self.fail(&file);
        };
        self.parsed_left = parsed_left;
        let (tree, checks) = parse(
            grammar,
            &source,
            MAX_PARSE_CHECKS.min(self.checks_left),
            self.parse_deadline,
        );
        // `checks` never exceeds the limit it was given.
        self.checks_left = self.checks_left.saturating_sub(checks);
        self.coverage.parse_checks += checks;
        let Some(tree) = tree else {
            return self.fail(&file);
        };
        let mut walk = Walk {
            grammar,
            source: &source,
            document: self.documents.len(),
            name: self.request.name,
            op: self.request.op,
            scopes: &mut self.scopes,
            path: Vec::new(),
            visited: 0,
            rows_left: MAX_SYMBOL_ROWS.saturating_sub(self.rows.len()),
            deferred_left: MAX_SYMBOL_ROWS,
            retained_left: &mut self.retained_left,
            rows: Vec::new(),
            subject_seen: false,
            heads: BTreeSet::new(),
            namespaces: BTreeSet::new(),
        };
        let walked = walk.run(&tree);
        let (visited, mut rows, subject_seen, heads) =
            (walk.visited, walk.rows, walk.subject_seen, walk.heads);
        self.coverage.nodes_visited += visited as u64;
        if walked.is_err() {
            return self.fail(&file);
        }
        // Deferred rows the document turned out not to need go, and their
        // names' bytes return to the retained budget. A type parameter
        // binds only inside its own document, and only a subject's
        // annotation reads bindings in a type answer: with no subject,
        // this document's type parameters go. A references walk kept each
        // type-level definition only as a possible shadow of a path's
        // first segment: those no retained path here starts with go.
        let op = self.request.op;
        let unread = |row: &IndexedSymbol| match op {
            SymbolOp::Type => !subject_seen && row.symbol_kind == "type_parameter",
            SymbolOp::References => row.name.as_deref().is_some_and(|name| {
                matches!(row.role, RowRole::Definition { .. })
                    && TYPE_LEVEL_KINDS.contains(&row.symbol_kind)
                    && !heads.contains(name)
            }),
            SymbolOp::Definition => false,
        };
        let retained_left = &mut self.retained_left;
        rows.retain(|row| {
            let keep = !unread(row);
            if !keep {
                *retained_left += row.name.as_deref().map_or(0, str::len);
            }
            keep
        });
        if self.rows.len() + rows.len() > MAX_SYMBOL_ROWS {
            return self.fail(&file);
        }
        let damaged = tree.root_node().has_error();
        if damaged {
            self.coverage.damaged += 1;
        }
        self.rows.extend(rows);
        let module = match grammar {
            Grammar::Rust => module_path(&file.relative, &self.package_of(&file)),
            Grammar::TypeScript | Grammar::Tsx => Some(Vec::new()),
        };
        self.documents.push(IndexedDocument {
            uri,
            root: root_uri.clone(),
            version: content_version(source.as_bytes()),
            encoding: PositionEncodingKind::UTF8,
            ignored: file.ignored,
            damaged,
            grammar,
            relative: file.relative,
            absolute: file.absolute,
            // The opened handle's own stat, taken before its read: the
            // stamp names the bytes that were indexed, and a write that
            // races the read moves the file past it — stale, never a
            // newer stamp over older bytes.
            stamp: file_stamp(&meta),
            module,
        });
    }

    /// Answers the request. Freshness is re-checked per document: rows
    /// never come from a stale document. Candidate rows are chosen,
    /// sorted and truncated as lightweight picks; only the kept ones are
    /// built into served rows.
    pub fn answer(&self) -> SymbolAnswer {
        let request = self.request;
        let fresh: Vec<bool> = self.documents.iter().map(|doc| !doc.is_stale()).collect();
        // `Some(None)`: pinned to a document the index does not hold.
        let pin = request
            .document
            .map(|uri| self.documents.iter().position(|doc| &doc.uri == uri));
        let in_pin = |document: usize| pin.is_none_or(|pinned| pinned == Some(document));
        let draws_on = |document: usize| in_pin(document) || request.op == SymbolOp::Type;
        let mut answer = SymbolAnswer {
            stale_documents: (0..self.documents.len())
                .filter(|&document| draws_on(document) && !fresh[document])
                .count() as u64,
            ..SymbolAnswer::default()
        };
        // Subject rows: the requested name, in a served document.
        let subjects = (0..self.rows.len()).filter(|&row| {
            let row = &self.rows[row];
            row.name.is_none() && fresh[row.document] && in_pin(row.document)
        });
        let mut placed = Placed::new();
        let mut named = |row: usize| {
            let symbol = &self.rows[row];
            self.in_scope(symbol.scope, symbol.document, &mut placed)
        };

        let mut picks: Vec<Pick<'_>> = Vec::new();
        match request.op {
            SymbolOp::Definition => {
                for row in subjects {
                    if matches!(self.rows[row].role, RowRole::Definition { .. }) && named(row) {
                        picks.push(Pick::Row {
                            row,
                            role: SymbolRole::Definition,
                            resolved: true,
                        });
                    }
                }
            }
            SymbolOp::References => {
                let mut binder = Binder::new(self, &fresh);
                for row in subjects {
                    if let Some(pick) = self.reference_pick(row, &mut binder, &mut placed) {
                        picks.push(pick);
                    }
                }
                answer.resolution_steps = binder.steps;
            }
            SymbolOp::Type => {
                let mut binder = Binder::new(self, &fresh);
                let mut seen = BTreeSet::new();
                for row in subjects {
                    if named(row) {
                        self.type_picks(row, &mut binder, &mut seen, &mut picks);
                    }
                }
                answer.resolution_steps = binder.steps;
            }
        }
        let unplaced: BTreeSet<usize> = placed
            .iter()
            .filter(|(_, matched)| matched.is_none())
            .map(|(&(_, document), _)| document)
            .collect();
        answer.unknown_module_paths = unplaced.len() as u64;

        // Type answers resolve across documents, so the answer is
        // sorted explicitly — by path, then byte offset; ties keep
        // their pick order.
        picks.sort_by(|left, right| {
            let (left_doc, left_byte) = self.pick_key(left);
            let (right_doc, right_byte) = self.pick_key(right);
            self.documents[left_doc]
                .relative
                .cmp(&self.documents[right_doc].relative)
                .then(left_byte.cmp(&right_byte))
        });
        answer.truncated = picks.len() > request.limit;
        picks.truncate(request.limit);

        let mut drawn: BTreeSet<usize> = picks.iter().map(|pick| self.pick_key(pick).0).collect();
        if let Some(Some(pinned)) = pin {
            drawn.insert(pinned);
        }
        answer.damaged_documents = drawn
            .iter()
            .filter(|&&document| self.documents[document].damaged)
            .count() as u64;

        let mut matched: Vec<SearchMatch> =
            picks.iter().map(|pick| self.materialize(pick)).collect();
        if request.document.is_none() {
            let more_hints = self.fallback_hints(&mut matched, &mut answer.unreadable_fallback);
            answer.truncated = answer.truncated || more_hints;
        }
        answer.matches = matched;
        answer
    }

    /// Does `scope`, as `document` holds it, answer the query's
    /// qualifier? The match runs on into the document's module path; a
    /// document with no derivable one leaves the match undecided
    /// (`None` in `placed`), never answered or claimed absent. `crate`
    /// and `self` anchor Rust modules only: a TypeScript root answers
    /// `::name` alone. Each pair is matched once per answer, however
    /// many uses bind there.
    fn in_scope(&self, scope: usize, document: usize, placed: &mut Placed) -> bool {
        let Some(q) = self.request.scope else {
            return true;
        };
        let matched = *placed.entry((scope, document)).or_insert_with(|| {
            let document_at = &self.documents[document];
            if document_at.grammar != Grammar::Rust
                && matches!(q.split("::").next(), Some("crate" | "self"))
            {
                return Some(false);
            }
            self.scopes
                .ends_with(scope, q, document_at.module.as_deref())
        });
        matched == Some(true)
    }

    /// The pick for one use row, if the query's qualifier wants it. A
    /// qualified query keeps a use certainly bound to a definition it
    /// matches, and every use bound nowhere — unresolved, never dropped.
    fn reference_pick<'r>(
        &'r self,
        row: usize,
        binder: &mut Binder<'r, 'a>,
        placed: &mut Placed,
    ) -> Option<Pick<'r>> {
        let symbol = &self.rows[row];
        let RowRole::Reference { spelling } = &symbol.role else {
            return None;
        };
        let name = self.request.name;
        // A damaged tree may hold the declaration a use names inside an
        // error node (`for (using x of …)`, `let x = @;` taking the next
        // call as its value): no use in it binds with certainty.
        let intact = !self.documents[symbol.document].damaged;
        let bound = match spelling {
            Spelling::Bindable {
                namespace,
                qualifier: None,
            } if intact => binder.lexical(
                symbol.scope,
                name,
                symbol.document,
                symbol.span.start_byte,
                *namespace,
            ),
            Spelling::Bindable {
                namespace,
                qualifier: Some(qualifier),
            } if intact => {
                binder.qualified(symbol.scope, qualifier, name, symbol.document, *namespace)
            }
            Spelling::Bindable { .. } | Spelling::Opaque | Spelling::Import => Bound::Unknown,
        };
        // Binding never crosses a file, but the answer places a certain
        // binding where its definition row lives — the path that row
        // renders, run on into its file's module path — so a qualifier
        // answers the certain uses of whatever definition it answers.
        let (wanted, resolved) = match bound {
            Bound::Certain { row: binding } => {
                let binding = &self.rows[binding];
                (self.in_scope(binding.scope, binding.document, placed), true)
            }
            Bound::Ambiguous { .. } | Bound::Unknown => (true, false),
        };
        wanted.then_some(Pick::Row {
            row,
            role: SymbolRole::Reference,
            resolved,
        })
    }

    /// The type picks for one subject definition: its own row when it
    /// is type-level, its enum for a member, the annotation's binding
    /// otherwise — or, when nothing binds, the spelling site marked
    /// `resolved: false`. An unannotated value names no type.
    fn type_picks<'r>(
        &'r self,
        subject: usize,
        binder: &mut Binder<'r, 'a>,
        seen: &mut BTreeSet<(usize, u64)>,
        picks: &mut Vec<Pick<'r>>,
    ) {
        let row = &self.rows[subject];
        let RowRole::Definition { type_ref } = &row.role else {
            return;
        };
        let (bound, from, name, span) = if TYPE_LEVEL_KINDS.contains(&row.symbol_kind) {
            if seen.insert((row.document, row.span.start_byte)) {
                picks.push(Pick::Row {
                    row: subject,
                    role: SymbolRole::Type,
                    resolved: true,
                });
            }
            return;
        } else if row.symbol_kind == "member" {
            // A member's scope is its enum: the enum's own definition is
            // that scope's name, inside the enum's parent scope. A member
            // at a root had no nameable enum — it names no type.
            let (Some(parent), Some(enum_name)) = (
                self.scopes.parent(row.scope),
                self.scopes.nodes[row.scope].name.as_deref(),
            ) else {
                return;
            };
            let bound = binder.enum_of(parent, enum_name, row.document);
            (bound, parent, enum_name, row.span)
        } else if let Some(type_ref) = type_ref {
            let bound = match &type_ref.qualifier {
                Some(qualifier) => binder.qualified(
                    type_ref.scope,
                    qualifier,
                    &type_ref.name,
                    row.document,
                    Namespace::Type,
                ),
                None => binder.lexical(
                    type_ref.scope,
                    &type_ref.name,
                    row.document,
                    type_ref.span.start_byte,
                    Namespace::Type,
                ),
            };
            (bound, type_ref.scope, &*type_ref.name, type_ref.span)
        } else {
            return;
        };
        let mut targets = Vec::new();
        if !binder.type_targets(bound, from, name, row.document, &mut targets) {
            if seen.insert((row.document, span.start_byte)) {
                picks.push(Pick::Spelled {
                    subject,
                    name,
                    span,
                });
            }
            return;
        }
        for (target, resolved) in targets {
            let target_row = &self.rows[target];
            if seen.insert((target_row.document, target_row.span.start_byte)) {
                picks.push(Pick::Row {
                    row: target,
                    role: SymbolRole::Type,
                    resolved,
                });
            }
        }
    }

    /// A pick's sort key: its document and byte offset.
    fn pick_key(&self, pick: &Pick<'_>) -> (usize, u64) {
        match *pick {
            Pick::Row { row, .. } => (self.rows[row].document, self.rows[row].span.start_byte),
            Pick::Spelled { subject, span, .. } => (self.rows[subject].document, span.start_byte),
        }
    }

    fn materialize(&self, pick: &Pick<'_>) -> SearchMatch {
        match *pick {
            Pick::Row {
                row,
                role,
                resolved,
            } => {
                let symbol = &self.rows[row];
                self.served(
                    symbol,
                    symbol.name(self.request.name),
                    symbol.symbol_kind,
                    symbol.span,
                    role,
                    resolved,
                )
            }
            Pick::Spelled {
                subject,
                name,
                span,
            } => self.served(
                &self.rows[subject],
                name,
                "type",
                span,
                SymbolRole::Type,
                false,
            ),
        }
    }

    /// The literal hint over files no grammar claimed: every hit is
    /// `MatchKind::Text`, labelled non-exact by its kind — never a
    /// reference, never an exact answer. Unclaimed files carry no
    /// freshness stamp; the scan reads live bytes each answer. Returns
    /// whether more hints existed than the remaining bound.
    fn fallback_hints(&self, matched: &mut Vec<SearchMatch>, unreadable: &mut u64) -> bool {
        // A fixed-string matcher over the raw line bytes: lossless — no
        // utf-8 decoding — and linear in each line.
        let Ok(literal) = RegexMatcherBuilder::new()
            .fixed_strings(true)
            .build(self.request.name)
        else {
            // No matcher, no scan: every unclaimed file goes unscanned
            // and is counted so, never silently skipped.
            *unreadable += self.unclaimed.len() as u64;
            return false;
        };
        let mut budget = self.request.limit.saturating_sub(matched.len());
        // Nothing is parsed here, so the scan reads under the ast leg's
        // whole-file bound rather than the parse bound.
        'files: for file in &self.unclaimed {
            let Some((bytes, _)) = read_capped(&file.absolute, MAX_AST_FILE_BYTES) else {
                *unreadable += 1;
                continue;
            };
            if bytes.len() as u64 > MAX_AST_FILE_BYTES {
                *unreadable += 1;
                continue;
            }
            // `split_inclusive` keeps the terminator so `line_bytes`
            // matches the text leg's raw-line convention.
            for (index, line) in bytes.split_inclusive(|byte| *byte == b'\n').enumerate() {
                let Ok(hit) = literal.is_match(line) else {
                    *unreadable += 1;
                    continue 'files;
                };
                if !hit {
                    continue;
                }
                if budget == 0 {
                    return true;
                }
                budget -= 1;
                matched.push(SearchMatch {
                    source: SourceRef {
                        path: file.relative.clone(),
                        // The facade reports 1-based lines.
                        line: Some(index as u64 + 1),
                        ignored: file.ignored,
                    },
                    kind: MatchKind::Text {
                        line_bytes: line.to_vec(),
                    },
                });
            }
        }
        false
    }

    /// One served row: the facade's `SourceRef` plus the `SymbolMatch`
    /// payload — the document's LSP identity rides on every row.
    fn served(
        &self,
        row: &IndexedSymbol,
        name: &str,
        symbol_kind: &str,
        span: Span,
        role: SymbolRole,
        resolved: bool,
    ) -> SearchMatch {
        let document = &self.documents[row.document];
        SearchMatch {
            source: SourceRef {
                path: document.relative.clone(),
                // The facade reports 1-based lines; LSP positions are
                // 0-based.
                line: Some(u64::from(span.range.start.line) + 1),
                ignored: document.ignored,
            },
            kind: MatchKind::Symbol(Box::new(SymbolMatch {
                language: document.grammar.name().to_string(),
                name: name.to_string(),
                symbol_kind: symbol_kind.to_string(),
                role,
                scope: self.scopes.render(row.scope),
                uri: document.uri.clone(),
                version: document.version,
                encoding: document.encoding.clone(),
                root: document.root.clone(),
                range: span.range,
                start_byte: span.start_byte,
                end_byte: span.end_byte,
                resolved,
            })),
        }
    }
}

/// One candidate answer row before it is built — cheap to sort and
/// truncate, so only kept rows pay for rendering.
#[derive(Debug, Clone, Copy)]
enum Pick<'r> {
    /// A retained row served under `role`.
    Row {
        row: usize,
        role: SymbolRole,
        resolved: bool,
    },
    /// A type name nothing binds, served at its spelling site.
    Spelled {
        subject: usize,
        name: &'r str,
        span: Span,
    },
}

/// Where a use bound.
#[derive(Debug, Clone, Copy)]
enum Bound {
    /// Exactly one candidate in the use's own document: its row.
    Certain { row: usize },
    /// Several own-document candidates in one scope — none certain;
    /// `generics` says whether type parameters were among them.
    Ambiguous { scope: usize, generics: bool },
    /// Nothing binds with certainty.
    Unknown,
}

/// One scope's entries for one name in one document. Members are none
/// of these: no bare walk and no path the index follows reaches them.
#[derive(Debug, Default)]
struct Entries {
    /// Parameters and variables, in declaration order.
    locals: Vec<usize>,
    /// Value items a bare use may bind.
    values: Vec<usize>,
    /// Type items a bare use may bind, type parameters apart.
    types: Vec<usize>,
    type_params: Vec<usize>,
    /// The name is bound here by something the index does not follow —
    /// a `use`/import (under [`GLOB`]: a glob or an item-introducing
    /// macro), a TypeScript `var`, `infer` or mapped-type key, or a
    /// pattern that may name a constant.
    import: bool,
}

impl Entries {
    /// The item candidates of `namespace` — with the type parameters
    /// when `generics` (a bare walk no enclosing Rust function hides
    /// them from).
    fn candidates(&self, namespace: Namespace, generics: bool) -> impl Iterator<Item = usize> + '_ {
        let (items, more): (&[usize], &[usize]) = match namespace {
            Namespace::Value => (&self.values, &[]),
            Namespace::Type => (&self.types, if generics { &self.type_params } else { &[] }),
        };
        items.iter().chain(more).copied()
    }
}

/// `(scope, name, document, namespace, crossed a Rust function)` — the
/// key a bare walk's memo is kept under.
type WalkKey<'r> = (usize, &'r str, usize, Namespace, bool);

/// Where the fresh documents' globs and item-introducing macros sit, and
/// which scopes are known to lie under one.
struct Globs {
    /// `(scope, document)` holding a [`GLOB`] row.
    at: BTreeSet<(usize, usize)>,
    /// The documents holding any — the only ones a cover walk runs in.
    documents: BTreeSet<usize>,
    covered: BTreeMap<(usize, usize), bool>,
}

impl Globs {
    fn new(index: &SymbolIndex<'_>, fresh: &[bool]) -> Self {
        let at: BTreeSet<(usize, usize)> = index
            .rows
            .iter()
            .filter(|row| fresh[row.document] && row.name.as_deref() == Some(GLOB))
            .map(|row| (row.scope, row.document))
            .collect();
        let documents = at.iter().map(|&(_, document)| document).collect();
        Self {
            at,
            documents,
            covered: BTreeMap::new(),
        }
    }

    /// Does `scope` of `document`, or any scope around it, hold a glob?
    /// The walk runs the whole chain — past a module too: a glob there
    /// may not reach inside, but over-reaching only leaves a local
    /// unknown — and is memoized per scope, each step counted.
    fn cover(
        &mut self,
        scopes: &ScopeTable,
        scope: usize,
        document: usize,
        steps: &mut u64,
    ) -> bool {
        if !self.documents.contains(&document) {
            return false;
        }
        let mut visited = Vec::new();
        let mut at = Some(scope);
        let found = loop {
            let Some(current) = at else {
                break false;
            };
            *steps += 1;
            if let Some(&cached) = self.covered.get(&(current, document)) {
                break cached;
            }
            visited.push(current);
            if self.at.contains(&(current, document)) {
                break true;
            }
            at = scopes.parent(current);
        };
        for current in visited {
            self.covered.insert((current, document), found);
        }
        found
    }
}

/// Binding over the fresh rows one op resolves against. Entries are keyed
/// by `(scope, name, document)`, so a use only ever reads its own
/// document's candidates; every walk is memoized — the nearest stop per
/// scope, the walk past an anonymous use scope, the qualifier's base
/// per scope, a whole path per spelling, a served candidate list per
/// scope — so resolution stays linear in the uses it resolves.
struct Binder<'r, 'a> {
    index: &'r SymbolIndex<'a>,
    entries: BTreeMap<(usize, &'r str, usize), Entries>,
    /// Non-member type items of every document, by `(scope, name)` —
    /// what an unbound type answer may still serve, unresolved.
    any_types: BTreeMap<(usize, &'r str), Vec<usize>>,
    nearest: BTreeMap<WalkKey<'r>, Option<(usize, bool)>>,
    /// What the walk past an anonymous use scope bound, per scope.
    beyond: BTreeMap<(usize, &'r str, usize, Namespace), Bound>,
    bases: BTreeMap<(usize, &'r str, usize), Option<usize>>,
    modules: BTreeMap<(usize, usize), usize>,
    paths: BTreeMap<(usize, &'r str, &'r str, usize, Namespace), Bound>,
    fallbacks: BTreeMap<(usize, &'r str), Option<usize>>,
    served: BTreeSet<(usize, &'r str, Option<usize>, bool)>,
    steps: u64,
}

impl<'r, 'a> Binder<'r, 'a> {
    fn new(index: &'r SymbolIndex<'a>, fresh: &[bool]) -> Self {
        let rust = |row: &IndexedSymbol| index.documents[row.document].grammar == Grammar::Rust;
        // A Rust pattern identifier may name a constant, a static or a
        // unit struct instead of binding — never a function — so a local
        // sharing a name with one of those items in its document, or
        // with an import that may bring one, binds nothing certain; nor
        // does a local under a glob or an item-introducing macro — in its
        // own scope or one around it — which may bring any name.
        let pattern_items: BTreeSet<(usize, &str)> = index
            .rows
            .iter()
            .filter(|row| {
                fresh[row.document]
                    && rust(row)
                    && !row.member
                    && match &row.role {
                        RowRole::Definition { .. } => {
                            matches!(row.symbol_kind, "const" | "static" | "struct" | "alias")
                        }
                        RowRole::Reference { spelling } => matches!(spelling, Spelling::Import),
                    }
            })
            .map(|row| (row.document, row.name(index.request.name)))
            .collect();
        let mut globs = Globs::new(index, fresh);
        let mut steps = 0;
        let mut entries: BTreeMap<(usize, &'r str, usize), Entries> = BTreeMap::new();
        let mut any_types: BTreeMap<(usize, &'r str), Vec<usize>> = BTreeMap::new();
        for (position, row) in index.rows.iter().enumerate() {
            // Members bind nowhere a walk or a followed path reaches.
            if !fresh[row.document] || row.member {
                continue;
            }
            let name = row.name(index.request.name);
            let key = (row.scope, name, row.document);
            match &row.role {
                RowRole::Reference {
                    spelling: Spelling::Import,
                } => entries.entry(key).or_default().import = true,
                RowRole::Reference { .. } => {}
                RowRole::Definition { .. } => {
                    let set = entries.entry(key).or_default();
                    let kind = row.symbol_kind;
                    let shadowed = is_local(kind)
                        && rust(row)
                        && (pattern_items.contains(&(row.document, name))
                            || globs.cover(&index.scopes, row.scope, row.document, &mut steps));
                    if kind == "alias" || kind == "var" || shadowed {
                        set.import = true;
                    } else if is_local(kind) {
                        set.locals.push(position);
                    } else {
                        let grammar = index.documents[row.document].grammar;
                        let (value, type_level) = namespaces(grammar, kind);
                        if value {
                            set.values.push(position);
                        }
                        if type_level && kind == "type_parameter" {
                            set.type_params.push(position);
                        } else if type_level {
                            set.types.push(position);
                            any_types
                                .entry((row.scope, name))
                                .or_default()
                                .push(position);
                        }
                    }
                }
            }
        }
        Self {
            index,
            entries,
            any_types,
            nearest: BTreeMap::new(),
            beyond: BTreeMap::new(),
            bases: BTreeMap::new(),
            modules: BTreeMap::new(),
            paths: BTreeMap::new(),
            fallbacks: BTreeMap::new(),
            served: BTreeSet::new(),
            steps,
        }
    }

    fn is_rust(&self, document: usize) -> bool {
        self.index.documents[document].grammar == Grammar::Rust
    }

    fn bears(&self, scope: usize, document: usize, category: u8) -> bool {
        self.index.scopes.bearer(scope, document) & category != 0
    }

    fn glob(&self, scope: usize, document: usize) -> bool {
        self.entries
            .get(&(scope, GLOB, document))
            .is_some_and(|set| set.import)
    }

    /// Past a Rust function on the way out, the anonymous and function
    /// scopes around it are another function's body: their locals and
    /// generics are not in scope.
    fn hides_locals(&self, scope: usize, crossed: bool, document: usize) -> bool {
        crossed
            && self.is_rust(document)
            && (self.index.scopes.is_anonymous(scope)
                || self.bears(scope, document, FUNCTION_SCOPE))
    }

    /// Does `scope` hold anything a bare use of `name` must stop at?
    fn relevant(
        &self,
        scope: usize,
        crossed: bool,
        name: &str,
        document: usize,
        namespace: Namespace,
    ) -> bool {
        if self.glob(scope, document) {
            return true;
        }
        let Some(set) = self.entries.get(&(scope, name, document)) else {
            return false;
        };
        let open = !self.hides_locals(scope, crossed, document);
        set.import
            || (namespace == Namespace::Value && open && !set.locals.is_empty())
            || set.candidates(namespace, open).next().is_some()
    }

    /// Where a bare use of `name` at byte `at` of `document`, in `scope`,
    /// binds. An anonymous scope is one node, and every scope above it
    /// declares its locals outside it and ends them outside or past it,
    /// so all uses in it see the same decisions above: its own scope
    /// decides by position, the walk past it is memoized per scope.
    fn lexical(
        &mut self,
        scope: usize,
        name: &'r str,
        document: usize,
        at: u64,
        namespace: Namespace,
    ) -> Bound {
        if !self.index.scopes.is_anonymous(scope) {
            return self.walk(scope, name, document, at, namespace);
        }
        if let Some(bound) = self.decide(scope, false, name, document, at, namespace) {
            return bound;
        }
        let key = (scope, name, document, namespace);
        if let Some(&bound) = self.beyond.get(&key) {
            return bound;
        }
        let bound = match self.index.scopes.parent(scope) {
            Some(parent) => self.walk(parent, name, document, at, namespace),
            None => Bound::Unknown,
        };
        self.beyond.insert(key, bound);
        bound
    }

    /// The outward walk from `scope`: the nearest scope a bare use must
    /// stop at decides, or the walk goes on past it.
    fn walk(
        &mut self,
        scope: usize,
        name: &'r str,
        document: usize,
        at: u64,
        namespace: Namespace,
    ) -> Bound {
        let rust = self.is_rust(document);
        let mut from = Some((scope, false));
        while let Some((start, crossed)) = from {
            let Some((candidate, crossed)) =
                self.nearest(start, crossed, name, document, namespace)
            else {
                return Bound::Unknown;
            };
            if let Some(bound) = self.decide(candidate, crossed, name, document, at, namespace) {
                return bound;
            }
            if rust && self.bears(candidate, document, MODULE_SCOPE) {
                return Bound::Unknown;
            }
            let crossed = crossed || (rust && self.bears(candidate, document, FUNCTION_SCOPE));
            from = self
                .index
                .scopes
                .parent(candidate)
                .map(|parent| (parent, crossed));
        }
        Bound::Unknown
    }

    /// The nearest scope at or above `start` a bare use of `name` must
    /// stop at, and whether a Rust function was crossed to reach it —
    /// `None` past the root or a Rust module with nothing to stop at.
    fn nearest(
        &mut self,
        start: usize,
        crossed: bool,
        name: &'r str,
        document: usize,
        namespace: Namespace,
    ) -> Option<(usize, bool)> {
        let rust = self.is_rust(document);
        let mut visited = Vec::new();
        let mut at = Some((start, crossed));
        let found = loop {
            let Some((scope, crossed)) = at else {
                break None;
            };
            self.steps += 1;
            if let Some(&cached) = self
                .nearest
                .get(&(scope, name, document, namespace, crossed))
            {
                break cached;
            }
            visited.push((scope, crossed));
            if self.relevant(scope, crossed, name, document, namespace) {
                break Some((scope, crossed));
            }
            if rust && self.bears(scope, document, MODULE_SCOPE) {
                break None;
            }
            let crossed = crossed || (rust && self.bears(scope, document, FUNCTION_SCOPE));
            at = self
                .index
                .scopes
                .parent(scope)
                .map(|parent| (parent, crossed));
        };
        for (scope, crossed) in visited {
            self.nearest
                .insert((scope, name, document, namespace, crossed), found);
        }
        found
    }

    /// What `scope` says about a bare use: a bound, or `None` to keep
    /// walking outward.
    fn decide(
        &mut self,
        scope: usize,
        crossed: bool,
        name: &str,
        document: usize,
        at: u64,
        namespace: Namespace,
    ) -> Option<Bound> {
        self.steps += 1;
        let glob = self.glob(scope, document);
        let open = !self.hides_locals(scope, crossed, document);
        let rows = &self.index.rows;
        let Some(set) = self.entries.get(&(scope, name, document)) else {
            return glob.then_some(Bound::Unknown);
        };
        // A namespace reopened in the document: its blocks do not share
        // their unexported names, and which block declared this one is
        // not tracked.
        if set.import || self.bears(scope, document, REOPENED) {
            return Some(Bound::Unknown);
        }
        if namespace == Namespace::Value && open && !set.locals.is_empty() {
            // Locals are in declaration order: the last one declared at
            // or before the use is the binding when its range covers it.
            let declared = set.locals.partition_point(|&row| rows[row].visible.0 <= at);
            if let Some(&row) = declared
                .checked_sub(1)
                .and_then(|last| set.locals.get(last))
                && at < rows[row].visible.1
            {
                return Some(Bound::Certain { row });
            }
            // A TypeScript use ahead of its scope's declaration is in the
            // temporal dead zone — it names the local, which is not live
            // yet; Rust reads past it.
            if !self.is_rust(document) && declared < set.locals.len() {
                return Some(Bound::Unknown);
            }
        }
        // Items are visible throughout their scope; a generic parameter
        // over its owner only.
        let mut candidates = set.candidates(namespace, open).filter(|&row| {
            let (from, until) = rows[row].visible;
            from <= at && at < until
        });
        match (candidates.next(), candidates.next()) {
            (Some(row), None) => Some(Bound::Certain { row }),
            (Some(_), Some(_)) => Some(Bound::Ambiguous {
                scope,
                generics: open,
            }),
            (None, _) => glob.then_some(Bound::Unknown),
        }
    }

    /// Where the last segment `name` of a path `qualifier::name` binds.
    fn qualified(
        &mut self,
        scope: usize,
        qualifier: &'r str,
        name: &'r str,
        document: usize,
        namespace: Namespace,
    ) -> Bound {
        let key = (scope, qualifier, name, document, namespace);
        if let Some(&bound) = self.paths.get(&key) {
            self.steps += 1;
            return bound;
        }
        let bound = self.resolve_path(scope, qualifier, name, document, namespace);
        self.paths.insert(key, bound);
        bound
    }

    fn resolve_path(
        &mut self,
        scope: usize,
        qualifier: &'r str,
        name: &str,
        document: usize,
        namespace: Namespace,
    ) -> Bound {
        // Rust's anchors mean nothing in TypeScript, where a qualifier's
        // first segment is always a name looked up outward.
        let anchor = if self.is_rust(document) {
            spelled_anchor(qualifier)
        } else {
            Some(Anchor::Lexical(qualifier))
        };
        let Some(anchor) = anchor else {
            return Bound::Unknown;
        };
        let (base, rest) = match anchor {
            // Only in a crate-root document is the root `crate::` names
            // the one this document's items live in.
            Anchor::Root(rest) if self.index.documents[document].is_crate_root() => {
                (ScopeTable::root_for(Grammar::Rust), rest)
            }
            Anchor::Root(_) => return Bound::Unknown,
            Anchor::Module(rest) => (self.module_of(scope, document), rest),
            Anchor::Lexical(path) => {
                let (first, rest) = path.split_once("::").unwrap_or((path, ""));
                match self.qualifier_base(scope, first, document) {
                    Some(base) => (base, rest),
                    None => return Bound::Unknown,
                }
            }
        };
        let mut target = base;
        for segment in rest.split("::").filter(|segment| !segment.is_empty()) {
            self.steps += 1;
            match self.path_child(target, segment, document) {
                Some(child) => target = child,
                None => return Bound::Unknown,
            }
        }
        self.steps += 1;
        let Some(set) = self.entries.get(&(target, name, document)) else {
            return Bound::Unknown;
        };
        if set.import {
            return Bound::Unknown;
        }
        let mut candidates = set.candidates(namespace, false);
        match (candidates.next(), candidates.next()) {
            (Some(row), None) => Bound::Certain { row },
            (Some(_), Some(_)) => Bound::Ambiguous {
                scope: target,
                generics: false,
            },
            (None, _) => Bound::Unknown,
        }
    }

    /// The child `segment` of `scope` a path may walk into: one this
    /// document opened as a module, never also as a function.
    fn path_child(&self, scope: usize, segment: &str, document: usize) -> Option<usize> {
        let child = *self.index.scopes.nodes[scope].named.get(segment)?;
        let bearer = self.index.scopes.bearer(child, document);
        (bearer & PATH_SCOPE != 0 && bearer & FUNCTION_SCOPE == 0).then_some(child)
    }

    /// The module a path's first segment `first` names, looked up outward
    /// from `scope` like a bare name: an import of it, a type-level
    /// binding of it (a type item or parameter — the path would then be
    /// type-qualified), a glob or a Rust module boundary met first
    /// leaves it unknown.
    fn qualifier_base(&mut self, scope: usize, first: &'r str, document: usize) -> Option<usize> {
        let rust = self.is_rust(document);
        let mut visited = Vec::new();
        let mut at = Some(scope);
        let found = loop {
            let Some(current) = at else {
                break None;
            };
            self.steps += 1;
            if let Some(&cached) = self.bases.get(&(current, first, document)) {
                break cached;
            }
            visited.push(current);
            // Wherever its range ends, a type parameter here may be the
            // one in view: any type-level binding of the name stops it.
            if self
                .entries
                .get(&(current, first, document))
                .is_some_and(|set| {
                    set.import || !set.types.is_empty() || !set.type_params.is_empty()
                })
            {
                break None;
            }
            if let Some(child) = self.path_child(current, first, document) {
                break Some(child);
            }
            if self.glob(current, document) || (rust && self.bears(current, document, MODULE_SCOPE))
            {
                break None;
            }
            at = self.index.scopes.parent(current);
        };
        for current in visited {
            self.bases.insert((current, first, document), found);
        }
        found
    }

    /// The Rust module (or root) enclosing `scope` — where `self::`
    /// starts.
    fn module_of(&mut self, scope: usize, document: usize) -> usize {
        let mut visited = Vec::new();
        let mut current = scope;
        let found = loop {
            self.steps += 1;
            if let Some(&cached) = self.modules.get(&(current, document)) {
                break cached;
            }
            visited.push(current);
            if self.bears(current, document, MODULE_SCOPE) {
                break current;
            }
            match self.index.scopes.parent(current) {
                Some(parent) => current = parent,
                None => break current,
            }
        };
        for current in visited {
            self.modules.insert((current, document), found);
        }
        found
    }

    /// Where an enum member's enum — `enum_name` in `scope` — binds.
    fn enum_of(&mut self, scope: usize, enum_name: &str, document: usize) -> Bound {
        self.steps += 1;
        let Some(set) = self.entries.get(&(scope, enum_name, document)) else {
            return Bound::Unknown;
        };
        let mut candidates = set.candidates(Namespace::Type, false);
        match (candidates.next(), candidates.next()) {
            (Some(row), None) => Bound::Certain { row },
            (Some(_), Some(_)) => Bound::Ambiguous {
                scope,
                generics: false,
            },
            (None, _) => Bound::Unknown,
        }
    }

    /// The rows a type answer serves for `bound` of `name`, each with its
    /// `resolved` claim: the certain row (unresolved when `document` is
    /// damaged); else the ambiguous own-document
    /// candidates; else the nearest same-name type items of any document
    /// outward from `from` — unresolved. A candidate list is served once
    /// per answer. `false` when nothing at all could be served.
    fn type_targets(
        &mut self,
        bound: Bound,
        from: usize,
        name: &'r str,
        document: usize,
        out: &mut Vec<(usize, bool)>,
    ) -> bool {
        match bound {
            // Nothing in a damaged document binds with certainty (see
            // `reference_pick`): its candidate is served, unresolved.
            Bound::Certain { row } => {
                out.push((row, !self.index.documents[document].damaged));
                true
            }
            Bound::Ambiguous { scope, generics } => {
                self.serve(scope, name, Some(document), generics, out);
                true
            }
            Bound::Unknown => match self.fallback(from, name) {
                Some(scope) => {
                    self.serve(scope, name, None, false, out);
                    true
                }
                None => false,
            },
        }
    }

    /// Serves one candidate list unresolved — once: a repeat costs one
    /// step and serves nothing new.
    fn serve(
        &mut self,
        scope: usize,
        name: &'r str,
        document: Option<usize>,
        generics: bool,
        out: &mut Vec<(usize, bool)>,
    ) {
        if !self.served.insert((scope, name, document, generics)) {
            self.steps += 1;
            return;
        }
        let rows: Vec<usize> = match document {
            Some(document) => self
                .entries
                .get(&(scope, name, document))
                .map(|set| set.candidates(Namespace::Type, generics).collect())
                .unwrap_or_default(),
            None => self
                .any_types
                .get(&(scope, name))
                .cloned()
                .unwrap_or_default(),
        };
        for row in rows {
            self.steps += 1;
            out.push((row, false));
        }
    }

    /// The nearest scope at or above `scope` holding a same-name type
    /// item of any document.
    fn fallback(&mut self, scope: usize, name: &'r str) -> Option<usize> {
        let mut visited = Vec::new();
        let mut at = Some(scope);
        let found = loop {
            let Some(current) = at else {
                break None;
            };
            self.steps += 1;
            if let Some(&cached) = self.fallbacks.get(&(current, name)) {
                break cached;
            }
            visited.push(current);
            if self.any_types.contains_key(&(current, name)) {
                break Some(current);
            }
            at = self.index.scopes.parent(current);
        };
        for current in visited {
            self.fallbacks.insert((current, name), found);
        }
        found
    }
}

/// One file's single cursor walk. Ancestor context — scope path,
/// binding pattern, `use` trees, member bodies — rides
/// `path`/the frame stack, so no node ever searches for its parent.
struct Walk<'s, 't> {
    grammar: Grammar,
    source: &'s str,
    document: usize,
    name: &'s str,
    op: SymbolOp,
    scopes: &'t mut ScopeTable,
    path: Vec<PathEntry<'s>>,
    /// Nodes charged so far — the draw on [`MAX_FILE_NODES`].
    visited: usize,
    /// Rows this walk may still record under [`MAX_SYMBOL_ROWS`].
    rows_left: usize,
    /// Rows the walk may hold until it knows whether the document keeps
    /// them — a type walk's type parameters, a references walk's
    /// type-level definitions (see `SymbolIndex::index_file`).
    deferred_left: usize,
    retained_left: &'t mut usize,
    rows: Vec<IndexedSymbol>,
    /// The walk recorded a definition of the requested name.
    subject_seen: bool,
    /// The first segments of the retained uses' spelled qualifiers.
    heads: BTreeSet<&'s str>,
    /// The TypeScript namespace scopes the walk has entered.
    namespaces: BTreeSet<usize>,
}

/// One enclosing scope on the walk's path.
struct PathEntry<'s> {
    segment: Segment<'s>,
    /// The interned id, once a retained row needed the path.
    id: Option<usize>,
    /// The rendered byte length of the named path through this entry.
    rendered: usize,
    /// What bore the scope — [`PATH_SCOPE`], [`MODULE_SCOPE`],
    /// [`FUNCTION_SCOPE`] — recorded for this document on interning.
    bearer: u8,
}

#[derive(Clone, Copy)]
enum Segment<'s> {
    Named(&'s str),
    /// Keyed by the bearer's start byte.
    Anonymous(usize),
}

/// What entering a node did to the scope path.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Opened {
    Nothing,
    /// A named scope; the bearer's own name lives outside it.
    Named,
    /// An anonymous scope; a named bearer (a function or class
    /// expression) keeps its name inside.
    Anonymous,
    /// An anonymous scope around a signature's parameters and generics;
    /// the bearer's name lives outside it.
    Signature,
}

/// A binding pattern's context: the local kind its identifiers declare
/// and the bytes `[from, until)` they are visible over — `from: None`
/// means from the identifier itself.
#[derive(Clone, Copy)]
struct Local {
    kind: &'static str,
    from: Option<u64>,
    until: u64,
}

/// What a node's descendants inherit from it.
#[derive(Clone, Copy, Default)]
struct Inherited {
    /// Inside a Rust `use` declaration: names are import paths.
    use_tree: bool,
    /// The definitions directly inside are members.
    members: bool,
}

/// One open ancestor on the walk's stack.
struct Frame<'tree> {
    node: Node<'tree>,
    /// The field `node` fills in its own parent.
    field: Option<&'tree str>,
    opened: Opened,
    /// The binding context its descendants' identifiers inherit.
    local: Option<Local>,
    inherited: Inherited,
    /// A TypeScript node standing where a `using` declaration may: an
    /// expression statement's expression, a `for` initializer, the
    /// operand of an `await` so placed, or the first item of a list so
    /// placed.
    statement: bool,
    /// A TypeScript assignment or list that is a `using` declaration:
    /// the plain names it assigns declare.
    declares: bool,
}

/// What the walk makes of one identifier-shaped node.
enum Site<'f, 'tree> {
    /// A definition of `kind`; `declaring` is the node whose name field
    /// it fills (`None` for a pattern binding).
    Definition {
        kind: &'static str,
        declaring: Option<&'f Frame<'tree>>,
    },
    Use(UsePosition<'tree>),
}

/// Where a use sits — before any text is retained for it.
enum UsePosition<'tree> {
    /// An allowlisted position; `qualifier` is the path node before a
    /// path's last segment.
    Bindable {
        namespace: Namespace,
        qualifier: Option<Node<'tree>>,
    },
    Opaque,
    Import,
}

impl<'s> Walk<'s, '_> {
    fn run(&mut self, tree: &tree_sitter::Tree) -> Result<(), OverBudget> {
        let mut cursor = tree.walk();
        let mut frames: Vec<Frame<'_>> = Vec::new();
        loop {
            self.charge()?;
            let node = cursor.node();
            let field = cursor.field_name();
            let local = child_local(self.grammar, &frames, field, node);
            self.visit(node, &frames, field, local)?;
            if cursor.goto_first_child() {
                // The children sit one level below `node`, whose depth
                // is `frames.len()`.
                if frames.len() >= MAX_TREE_DEPTH {
                    return Err(OverBudget);
                }
                let opened = self.enter_scope(node, frames.last())?;
                let inherited = inherit(self.grammar, node, opened, frames.last());
                let (statement, declares) = self.using_context(node, field, frames.last())?;
                frames.push(Frame {
                    node,
                    field,
                    opened,
                    local,
                    inherited,
                    statement,
                    declares,
                });
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return Ok(());
                }
                if frames
                    .pop()
                    .is_some_and(|frame| frame.opened != Opened::Nothing)
                {
                    self.path.pop();
                }
            }
        }
    }

    fn charge(&mut self) -> Result<(), OverBudget> {
        if self.visited >= MAX_FILE_NODES {
            return Err(OverBudget);
        }
        self.visited += 1;
        Ok(())
    }

    /// A copy of `text` the index keeps, charged to the retained bytes.
    fn retain(&mut self, text: &str) -> Result<Box<str>, OverBudget> {
        spend(self.retained_left, text.len())?;
        Ok(text.into())
    }

    /// Records `node` when it is a retained definition, use, import or
    /// glob.
    fn visit<'tree>(
        &mut self,
        node: Node<'tree>,
        frames: &[Frame<'tree>],
        field: Option<&str>,
        local: Option<Local>,
    ) -> Result<(), OverBudget> {
        if !node.is_named() {
            return Ok(());
        }
        if self.grammar == Grammar::Rust && node.kind() == "use_wildcard" {
            return self.record_glob(node);
        }
        // A macro invocation may expand to items — at a module's top level
        // whatever its delimiter (`mk_consts!(limit);`), anywhere when
        // brace-delimited (`thread_local! { static X … }`) — so like a
        // glob it leaves every name walked through its scope unknown, and
        // every Rust local under it. A parenthesized or bracketed one in
        // a body is taken for an expression or statement: most are, but
        // an item-defining one can shadow too — a known limit (module
        // docs), kept so a formatting macro call does not blank every
        // walk. Its token tree closes the invocation, so the last byte
        // names the delimiter.
        if self.grammar == Grammar::Rust
            && node.kind() == "macro_invocation"
            && (at_module_level(frames)
                || node
                    .end_byte()
                    .checked_sub(1)
                    .and_then(|last| self.source.as_bytes().get(last))
                    == Some(&b'}'))
        {
            return self.record_glob(node);
        }
        // The table's own `'static` spelling — a use row reports its
        // node kind (`identifier`, `type_identifier`, …).
        let Some(kind) = ident_kinds(self.grammar)
            .iter()
            .copied()
            .find(|ident| *ident == node.kind())
        else {
            return Ok(());
        };
        let parent = frames.last();
        // A lifetime or a loop label names neither a value nor a type.
        if parent.is_some_and(|frame| matches!(frame.node.kind(), "lifetime" | "label")) {
            return Ok(());
        }
        let Some(text) = node_text(&node, self.source) else {
            return Ok(());
        };
        // A def node's own name field is its definition site; an
        // identifier in a binding pattern (params, let/match/if-let
        // destructuring) is a binding — neither is ever a use.
        let declared = parent.and_then(|frame| {
            def_kind(self.grammar, frame.node.kind(), field).map(|kind| Site::Definition {
                // A `var` declarator's pattern context names it hoisted.
                kind: match local {
                    Some(Local { kind: "var", .. }) if kind == "variable" => "var",
                    _ => kind,
                },
                declaring: Some(frame),
            })
        });
        let site = declared
            .or_else(|| {
                local
                    .filter(|_| is_binding_name(self.grammar, kind, text))
                    .map(|local| Site::Definition {
                        kind: local.kind,
                        declaring: None,
                    })
            })
            .unwrap_or_else(|| Site::Use(self.use_position(frames, field, kind)));
        let requested = text == self.name;
        let import = matches!(
            site,
            Site::Definition { kind: "alias", .. } | Site::Use(UsePosition::Import)
        );
        let retained = match (&site, self.op) {
            (Site::Definition { .. }, SymbolOp::Definition) => requested,
            (Site::Use(_), SymbolOp::Definition) => false,
            (Site::Definition { kind, .. }, SymbolOp::References | SymbolOp::Type) => {
                requested || import || TYPE_LEVEL_KINDS.contains(kind)
            }
            (Site::Use(_), SymbolOp::References) => requested || import,
            (Site::Use(_), SymbolOp::Type) => import,
        };
        if !retained {
            return Ok(());
        }
        // Whether a document needs these is known when its walk ends, so
        // until then they draw on their own allowance: a type parameter
        // matters to a type answer only in a document holding a subject,
        // and to a references answer another type-level definition
        // matters only as the shadow of a path's first segment.
        let deferred = !requested
            && match (&site, self.op) {
                (Site::Definition { kind, .. }, SymbolOp::Type) => *kind == "type_parameter",
                (Site::Definition { kind, .. }, SymbolOp::References) => {
                    TYPE_LEVEL_KINDS.contains(kind)
                }
                _ => false,
            };
        let allowance = if deferred {
            &mut self.deferred_left
        } else {
            &mut self.rows_left
        };
        *allowance = allowance.checked_sub(1).ok_or(OverBudget)?;
        let span = Span::of(&node);
        let (role, symbol_kind, member, name_outside) = match site {
            Site::Definition {
                kind: def,
                declaring,
            } => {
                self.subject_seen |= requested;
                let type_ref = match declaring {
                    Some(frame)
                        if self.op == SymbolOp::Type
                            && requested
                            && !TYPE_LEVEL_KINDS.contains(&def) =>
                    {
                        self.type_ref_of(frame.node)?
                    }
                    _ => None,
                };
                // The frame above the declaring node says whether what
                // it declares is a member; generic parameters — type or
                // const — never are, whatever container owns them.
                let member = declaring.is_some()
                    && generic_owner(frames, field).is_none()
                    && frames
                        .len()
                        .checked_sub(2)
                        .and_then(|at| frames.get(at))
                        .is_some_and(|above| above.inherited.members);
                // A def node that opened a named or signature scope
                // pushed it — the definition lives in the scope around
                // it; an anonymous bearer keeps its name inside.
                let outside = declaring
                    .is_some_and(|frame| matches!(frame.opened, Opened::Named | Opened::Signature));
                (RowRole::Definition { type_ref }, def, member, outside)
            }
            Site::Use(position) => {
                let spelling = self.spelling(position)?;
                (RowRole::Reference { spelling }, kind, false, false)
            }
        };
        let name = if requested {
            None
        } else {
            Some(self.retain(text)?)
        };
        // A TypeScript `var` lives in the nearest function or namespace
        // (or the root), whatever block declares it.
        let depth = if symbol_kind == "var" {
            self.path
                .iter()
                .rposition(|entry| entry.bearer & HOISTS != 0)
                .map_or(0, |at| at + 1)
        } else {
            self.path.len() - usize::from(name_outside)
        };
        let scope = self.scope_id(depth)?;
        let visible = match (local, generic_owner(frames, field)) {
            (Some(local), _) if is_local(symbol_kind) => {
                (local.from.unwrap_or(span.start_byte), local.until)
            }
            // A generic parameter is visible over its owner alone: a
            // struct's `T` and its `impl`'s `T` share the scope `S`, and
            // a type alias's `T` never leaks into the scope around it.
            (_, Some(owner)) => (owner.start_byte() as u64, owner.end_byte() as u64),
            _ => (0, u64::MAX),
        };
        self.rows.push(IndexedSymbol {
            document: self.document,
            name,
            symbol_kind,
            scope,
            span,
            visible,
            member,
            role,
        });
        Ok(())
    }

    /// Records a Rust glob import (`use m::*;`) or an item-introducing
    /// macro under [`GLOB`] — every name bare-walked through its scope,
    /// and every Rust local under it, becomes unknown. Only a binding
    /// answer reads it.
    fn record_glob(&mut self, node: Node<'_>) -> Result<(), OverBudget> {
        if self.op == SymbolOp::Definition {
            return Ok(());
        }
        self.rows_left = self.rows_left.checked_sub(1).ok_or(OverBudget)?;
        let name = Some(self.retain(GLOB)?);
        let scope = self.scope_id(self.path.len())?;
        self.rows.push(IndexedSymbol {
            document: self.document,
            name,
            symbol_kind: "use_wildcard",
            scope,
            span: Span::of(&node),
            visible: (0, u64::MAX),
            member: false,
            role: RowRole::Reference {
                spelling: Spelling::Import,
            },
        });
        Ok(())
    }

    /// Where a use sits: an allowlisted value or type position, the last
    /// segment of a path sitting in one, an import binding — or opaque.
    fn use_position<'tree>(
        &self,
        frames: &[Frame<'tree>],
        field: Option<&str>,
        kind: &str,
    ) -> UsePosition<'tree> {
        // A macro's token tree is no allowlisted parent: names inside it
        // bind only after an expansion the index does not run.
        let Some(parent) = frames.last() else {
            return UsePosition::Opaque;
        };
        let grand = frames.len().checked_sub(2).and_then(|at| frames.get(at));
        let parent_kind = parent.node.kind();
        if parent.inherited.use_tree {
            return if rust_import_leaf(parent_kind, field, parent.field, grand) {
                UsePosition::Import
            } else {
                UsePosition::Opaque
            };
        }
        if binds_import(self.grammar, parent, field) {
            return UsePosition::Import;
        }
        if field == Some("name")
            && let Some((namespace, qualifier_field)) = path_shape(self.grammar, parent_kind)
        {
            // The path's leaf binds only when the whole path sits in a
            // use position; a path inside another path is a qualifier.
            let placed = grand.is_some_and(|above| {
                in_position(self.grammar, namespace, above.node.kind(), parent.field)
            });
            return match (placed, parent.node.child_by_field_name(qualifier_field)) {
                (true, Some(qualifier)) => UsePosition::Bindable {
                    namespace,
                    qualifier: Some(qualifier),
                },
                _ => UsePosition::Opaque,
            };
        }
        let namespace = match (self.grammar, kind) {
            (_, "type_identifier") => Namespace::Type,
            (Grammar::Rust, "identifier")
            | (
                Grammar::TypeScript | Grammar::Tsx,
                "identifier" | "shorthand_property_identifier",
            ) => Namespace::Value,
            _ => return UsePosition::Opaque,
        };
        if in_position(self.grammar, namespace, parent_kind, field) {
            UsePosition::Bindable {
                namespace,
                qualifier: None,
            }
        } else {
            UsePosition::Opaque
        }
    }

    /// The spelling a retained use keeps — a path copies its qualifier,
    /// and its first segment joins the walk's `heads`.
    fn spelling(&mut self, position: UsePosition<'_>) -> Result<Spelling, OverBudget> {
        Ok(match position {
            UsePosition::Bindable {
                namespace,
                qualifier: None,
            } => Spelling::Bindable {
                namespace,
                qualifier: None,
            },
            UsePosition::Bindable {
                namespace,
                qualifier: Some(qualifier),
            } => match node_text(&qualifier, self.source) {
                Some(text) => {
                    if let Some(head) = text.split([':', '.']).next() {
                        self.heads.insert(head);
                    }
                    Spelling::Bindable {
                        namespace,
                        qualifier: Some(self.retain(&text.replace('.', "::"))?),
                    }
                }
                None => Spelling::Opaque,
            },
            UsePosition::Opaque => Spelling::Opaque,
            UsePosition::Import => Spelling::Import,
        })
    }

    /// Pushes `node`'s scope component when it bears a scope — a fresh
    /// anonymous one, the bearer's own name, or for `impl` blocks the
    /// implemented type's. A named path rendering past
    /// [`MAX_SCOPE_PATH_BYTES`] fails the file.
    fn enter_scope(
        &mut self,
        node: Node<'_>,
        parent: Option<&Frame<'_>>,
    ) -> Result<Opened, OverBudget> {
        if !node.is_named() {
            return Ok(Opened::Nothing);
        }
        let kind = node.kind();
        let rendered = self.path.last().map_or(0, |entry| entry.rendered);
        // An anonymous TypeScript function or namespace still hosts the
        // `var`s inside it.
        let anonymous = PathEntry {
            segment: Segment::Anonymous(node.start_byte()),
            id: None,
            rendered,
            bearer: match kind {
                "arrow_function"
                | "function_expression"
                | "generator_function"
                | "internal_module"
                | "module" => HOISTS,
                _ => 0,
            },
        };
        if let Some(opened) =
            opens_anonymous(self.grammar, kind, parent.map(|frame| frame.node.kind()))
        {
            self.path.push(anonymous);
            return Ok(opened);
        }
        if !scope_kinds(self.grammar).contains(&kind) {
            return Ok(Opened::Nothing);
        }
        let name = if kind == "impl_item" {
            match node.child_by_field_name("type") {
                Some(target) => self
                    .first_type_name(target)?
                    .map(|found| type_name_parts(self.grammar, found).0),
                None => None,
            }
        } else {
            node.child_by_field_name("name")
                .filter(|name| ident_kinds(self.grammar).contains(&name.kind()))
        };
        let Some(text) = name.and_then(|name| node_text(&name, self.source)) else {
            // A TypeScript namespace named by a dotted path or a string
            // (`namespace a.b {}`, `declare module "x" {}`) keeps its
            // contents to itself, though no path names it.
            if matches!(kind, "internal_module" | "module") {
                self.path.push(anonymous);
                return Ok(Opened::Anonymous);
            }
            return Ok(Opened::Nothing);
        };
        let rendered = match rendered {
            0 => text.len(),
            before => before + 2 + text.len(),
        };
        if rendered > MAX_SCOPE_PATH_BYTES {
            return Err(OverBudget);
        }
        self.path.push(PathEntry {
            segment: Segment::Named(text),
            id: None,
            rendered,
            bearer: bearer_of(self.grammar, kind),
        });
        // Interned now, so a second block of the same namespace in this
        // document is seen as one: the scope table merges the blocks'
        // names, which the language does not.
        if self.grammar != Grammar::Rust && matches!(kind, "internal_module" | "module") {
            let id = self.scope_id(self.path.len())?;
            if !self.namespaces.insert(id) {
                *self.scopes.bearers.entry((id, self.document)).or_insert(0) |= REOPENED;
            }
        }
        Ok(Opened::Named)
    }

    /// The interned id of the first `depth` path components — interned
    /// lazily, so only paths a retained row lives in are ever stored,
    /// each new scope and each document's first bearer record charged to
    /// the retained bytes.
    fn scope_id(&mut self, depth: usize) -> Result<usize, OverBudget> {
        let mut at = ScopeTable::root_for(self.grammar);
        for entry in self.path.iter_mut().take(depth) {
            if let Some(id) = entry.id {
                at = id;
                continue;
            }
            let (id, cost) = match entry.segment {
                Segment::Named(name) => {
                    let (id, fresh) = self.scopes.intern_named(at, name);
                    let key = (id, self.document);
                    let before = self.scopes.bearers.get(&key).copied();
                    // A module or namespace and a same-name function or
                    // type are one scope here, but neither block sees the
                    // other's names.
                    let merged = before
                        .is_some_and(|before| (before & PATH_SCOPE) != (entry.bearer & PATH_SCOPE));
                    let recorded = before.is_some();
                    *self.scopes.bearers.entry(key).or_insert(0) |=
                        entry.bearer | if merged { REOPENED } else { 0 };
                    let node = if fresh {
                        SCOPE_NODE_BYTES + 2 * name.len()
                    } else {
                        0
                    };
                    let record = if recorded { 0 } else { BEARER_ENTRY_BYTES };
                    (id, node + record)
                }
                Segment::Anonymous(start) => {
                    let (id, fresh) = self.scopes.intern_anonymous(at, (self.document, start));
                    (id, if fresh { SCOPE_NODE_BYTES } else { 0 })
                }
            };
            spend(self.retained_left, cost)?;
            entry.id = Some(id);
            at = id;
        }
        Ok(at)
    }

    /// The named type a value-level definition's annotation spells —
    /// the first type-name node inside its `return_type`/`type` field —
    /// resolved from the scope the annotation sits in.
    fn type_ref_of(&mut self, def: Node<'_>) -> Result<Option<TypeRef>, OverBudget> {
        let Some(annotation) = def
            .child_by_field_name("return_type")
            .or_else(|| def.child_by_field_name("type"))
        else {
            return Ok(None);
        };
        let Some(found) = self.first_type_name(annotation)? else {
            return Ok(None);
        };
        let (name_node, qualifier) = type_name_parts(self.grammar, found);
        let Some(name) = node_text(&name_node, self.source) else {
            return Ok(None);
        };
        let qualifier = match qualifier.and_then(|path| node_text(&path, self.source)) {
            Some(text) => Some(self.retain(&text.replace('.', "::"))?),
            None => None,
        };
        Ok(Some(TypeRef {
            name: self.retain(name)?,
            qualifier,
            span: Span::of(&name_node),
            scope: self.scope_id(self.path.len())?,
        }))
    }

    /// The first type-name node inside `node`, preorder — `Result`
    /// in `-> Result<Token>`, the whole `a::Token` path before its
    /// parts. Every visited node draws on the file's budget.
    fn first_type_name<'tree>(
        &mut self,
        node: Node<'tree>,
    ) -> Result<Option<Node<'tree>>, OverBudget> {
        let kinds = type_name_kinds(self.grammar);
        let mut cursor = node.walk();
        loop {
            self.charge()?;
            let current = cursor.node();
            if current.is_named() && kinds.contains(&current.kind()) {
                return Ok(Some(current));
            }
            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return Ok(None);
                }
            }
        }
    }

    /// `(statement, declares)` for a TypeScript node about to open — see
    /// [`Frame`]. A list looks ahead once, as it opens, for the `using`
    /// declaration its first item holds; its later items read that
    /// answer rather than look again.
    fn using_context(
        &mut self,
        node: Node<'_>,
        field: Option<&str>,
        parent: Option<&Frame<'_>>,
    ) -> Result<(bool, bool), OverBudget> {
        let Some(parent) = parent.filter(|_| self.grammar != Grammar::Rust) else {
            return Ok((false, false));
        };
        let statement = match parent.node.kind() {
            "expression_statement" => true,
            "for_statement" => field == Some("initializer"),
            "await_expression" => parent.statement,
            // A list's first item starts where the list does.
            "sequence_expression" => {
                parent.statement && node.start_byte() == parent.node.start_byte()
            }
            _ => false,
        };
        let declares = match node.kind() {
            "assignment_expression" if parent.node.kind() == "sequence_expression" => {
                parent.declares
            }
            "assignment_expression" => statement && self.declares_using(node)?,
            "sequence_expression" => statement && self.heads_using(node)?,
            _ => false,
        };
        Ok((statement, declares))
    }

    /// Is `assignment` a `using x = …` declaration? tree-sitter-typescript
    /// 0.23.2 reads one (and `await using`) as an assignment behind an
    /// anonymous `using` token. The token must come first — not an error
    /// node — on the line `left` starts (a line break after `using` ends
    /// its statement), and `left` must be a plain name: a declaration
    /// binds no pattern, so `using [a] = …` indexes a variable named
    /// `using`. Each cursor step — comments before `left` included —
    /// draws on the file's node budget.
    fn declares_using(&mut self, assignment: Node<'_>) -> Result<bool, OverBudget> {
        let mut cursor = assignment.walk();
        self.charge()?;
        if !cursor.goto_first_child() {
            return Ok(false);
        }
        let token = cursor.node();
        if token.is_named() || token.kind() != "using" {
            return Ok(false);
        }
        while cursor.field_name() != Some("left") {
            self.charge()?;
            if !cursor.goto_next_sibling() {
                return Ok(false);
            }
        }
        let left = cursor.node();
        Ok(left.kind() == "identifier" && left.start_position().row == token.start_position().row)
    }

    /// Does `list` open with a `using` declaration? `using a = …, b = …`
    /// reads as a list of assignments whose first alone carries the
    /// token — inside an `await` for `await using` — yet every one
    /// declares. Each cursor step draws on the file's node budget.
    fn heads_using(&mut self, list: Node<'_>) -> Result<bool, OverBudget> {
        let mut cursor = list.walk();
        self.charge()?;
        if !cursor.goto_first_child() {
            return Ok(false);
        }
        let first = cursor.node();
        match first.kind() {
            "assignment_expression" => self.declares_using(first),
            "await_expression" => {
                // The awaited assignment follows the `await` token and any
                // comment after it.
                let mut inner = first.walk();
                let mut more = inner.goto_first_child();
                while more && (!inner.node().is_named() || inner.node().is_extra()) {
                    self.charge()?;
                    more = inner.goto_next_sibling();
                }
                let awaited = inner.node();
                Ok(more
                    && awaited.kind() == "assignment_expression"
                    && self.declares_using(awaited)?)
            }
            _ => Ok(false),
        }
    }
}

/// The node owning a generic parameter whose name this identifier is —
/// `type_parameter`/`const_parameter` → `type_parameters` → owner.
fn generic_owner<'tree>(frames: &[Frame<'tree>], field: Option<&str>) -> Option<Node<'tree>> {
    let mut up = frames.iter().rev();
    let parameter = up.next()?;
    if field != Some("name")
        || !matches!(parameter.node.kind(), "type_parameter" | "const_parameter")
    {
        return None;
    }
    up.nth(1).map(|owner| owner.node)
}

/// Does a Rust node whose ancestors are `frames` sit at a module's top
/// level — in the source file or a `mod` body, an expression statement
/// around it aside?
fn at_module_level(frames: &[Frame<'_>]) -> bool {
    let mut up = frames.iter().rev().map(|frame| frame.node.kind());
    let mut parent = up.next();
    if parent == Some("expression_statement") {
        parent = up.next();
    }
    match parent {
        Some("source_file") => true,
        Some("declaration_list") => up.next() == Some("mod_item"),
        _ => false,
    }
}

/// What `node` hands its descendants.
fn inherit(
    grammar: Grammar,
    node: Node<'_>,
    opened: Opened,
    parent: Option<&Frame<'_>>,
) -> Inherited {
    let above = parent.map_or_else(Inherited::default, |frame| frame.inherited);
    let kind = node.kind();
    Inherited {
        use_tree: above.use_tree || kind == "use_declaration",
        // A member body's definitions are members until another scope
        // opens — a method's own body declares locals and items.
        members: member_bearers(grammar).contains(&kind)
            || (opened == Opened::Nothing && above.members),
    }
}

/// Is an identifier in a Rust `use` tree the name the declaration
/// binds? `use a::b;`, `use a::{b, c::d};` and `use b;` bind their last
/// segments; `use … as x` binds its alias, a definition row of its own.
fn rust_import_leaf(
    parent: &str,
    field: Option<&str>,
    parent_field: Option<&str>,
    grand: Option<&Frame<'_>>,
) -> bool {
    let leaf_of = |kind: &str, field: Option<&str>| {
        matches!(
            (kind, field),
            ("use_declaration", Some("argument")) | ("use_list", None)
        )
    };
    leaf_of(parent, field)
        || (parent == "scoped_identifier"
            && field == Some("name")
            && grand.is_some_and(|above| leaf_of(above.node.kind(), parent_field)))
}

/// Does an identifier in `field` of `parent` bind an import outside a
/// Rust `use` tree — `extern crate`, or a TypeScript import clause,
/// specifier (its alias when it has one) or namespace import — or bind
/// like one, as TypeScript `infer` and mapped-type keys do?
fn binds_import(grammar: Grammar, parent: &Frame<'_>, field: Option<&str>) -> bool {
    match grammar {
        Grammar::Rust => parent.node.kind() == "extern_crate_declaration",
        Grammar::TypeScript | Grammar::Tsx => match (parent.node.kind(), field) {
            // `infer U` (its constraint's names too) and a mapped type's
            // `[K in …]` bind names the index does not follow.
            ("infer_type", _) | ("mapped_type_clause", Some("name")) => true,
            ("import_specifier", Some("alias")) => true,
            ("import_specifier", _) => parent.node.child_by_field_name("alias").is_none(),
            (
                "import_clause" | "namespace_import" | "import_alias" | "import_require_clause",
                _,
            ) => true,
            _ => false,
        },
    }
}

/// The path kinds whose `name` field is a use's last segment: the
/// namespace the path names and the field its qualifier sits in.
fn path_shape(grammar: Grammar, kind: &str) -> Option<(Namespace, &'static str)> {
    match (grammar, kind) {
        (Grammar::Rust, "scoped_identifier") => Some((Namespace::Value, "path")),
        (Grammar::Rust, "scoped_type_identifier") => Some((Namespace::Type, "path")),
        (Grammar::TypeScript | Grammar::Tsx, "nested_type_identifier") => {
            Some((Namespace::Type, "module"))
        }
        _ => None,
    }
}

/// Is `(parent, field)` an allowlisted `namespace` position?
fn in_position(grammar: Grammar, namespace: Namespace, parent: &str, field: Option<&str>) -> bool {
    let table = match (grammar, namespace) {
        (Grammar::Rust, Namespace::Value) => RUST_VALUE_POSITIONS,
        (Grammar::Rust, Namespace::Type) => RUST_TYPE_POSITIONS,
        (Grammar::TypeScript | Grammar::Tsx, Namespace::Value) => TS_VALUE_POSITIONS,
        (Grammar::TypeScript | Grammar::Tsx, Namespace::Type) => TS_TYPE_POSITIONS,
    };
    table.contains(&(parent, field))
}

/// `(parent node kind, field)` where a Rust `identifier` is read as a
/// value (tree-sitter-rust 0.24.2 node types; `None` = an unnamed
/// child). A path in one of these spots binds its last segment.
const RUST_VALUE_POSITIONS: &[(&str, Option<&str>)] = &[
    ("arguments", None),
    ("array_expression", None),
    ("array_expression", Some("length")),
    ("array_type", Some("length")),
    ("assignment_expression", Some("left")),
    ("assignment_expression", Some("right")),
    ("await_expression", None),
    ("base_field_initializer", None),
    ("binary_expression", Some("left")),
    ("binary_expression", Some("right")),
    ("block", None),
    ("break_expression", None),
    ("call_expression", Some("function")),
    ("closure_expression", Some("body")),
    ("compound_assignment_expr", Some("left")),
    ("compound_assignment_expr", Some("right")),
    ("const_item", Some("value")),
    ("const_parameter", Some("value")),
    ("enum_variant", Some("value")),
    ("expression_statement", None),
    ("field_expression", Some("value")),
    ("field_initializer", Some("value")),
    ("for_expression", Some("value")),
    ("generic_function", Some("function")),
    ("if_expression", Some("condition")),
    ("index_expression", None),
    ("let_chain", None),
    ("let_condition", Some("value")),
    ("let_declaration", Some("value")),
    ("match_arm", Some("value")),
    ("match_expression", Some("value")),
    ("match_pattern", Some("condition")),
    ("parenthesized_expression", None),
    ("range_expression", None),
    ("reference_expression", Some("value")),
    ("return_expression", None),
    ("shorthand_field_initializer", None),
    ("static_item", Some("value")),
    ("try_expression", None),
    ("tuple_expression", None),
    ("type_cast_expression", Some("value")),
    ("unary_expression", None),
    ("while_expression", Some("condition")),
    ("yield_expression", None),
];

/// `(parent node kind, field)` where a Rust `type_identifier` names a
/// type — annotations, generic arguments, bounds, `impl` targets.
const RUST_TYPE_POSITIONS: &[(&str, Option<&str>)] = &[
    ("abstract_type", Some("trait")),
    ("array_type", Some("element")),
    ("bounded_type", None),
    ("bracketed_type", None),
    ("closure_expression", Some("return_type")),
    ("const_item", Some("type")),
    ("const_parameter", Some("type")),
    ("dynamic_type", Some("trait")),
    ("field_declaration", Some("type")),
    ("function_item", Some("return_type")),
    ("function_signature_item", Some("return_type")),
    ("function_type", Some("return_type")),
    ("function_type", Some("trait")),
    ("generic_type", Some("type")),
    ("generic_type_with_turbofish", Some("type")),
    ("higher_ranked_trait_bound", Some("type")),
    ("impl_item", Some("trait")),
    ("impl_item", Some("type")),
    ("let_declaration", Some("type")),
    ("ordered_field_declaration_list", Some("type")),
    ("parameter", Some("type")),
    ("parameters", None),
    ("pointer_type", Some("type")),
    ("qualified_type", Some("alias")),
    ("qualified_type", Some("type")),
    ("reference_type", Some("type")),
    ("removed_trait_bound", None),
    ("static_item", Some("type")),
    ("struct_expression", Some("name")),
    ("struct_pattern", Some("type")),
    ("trait_bounds", None),
    ("tuple_type", None),
    ("type_arguments", None),
    ("type_binding", Some("type")),
    ("type_cast_expression", Some("type")),
    ("type_item", Some("type")),
    ("type_parameter", Some("default_type")),
    ("use_bounds", None),
    ("where_predicate", Some("left")),
];

/// `(parent node kind, field)` where a TypeScript `identifier` (or a
/// shorthand property) is read as a value (tree-sitter-typescript
/// 0.23.2 node types).
const TS_VALUE_POSITIONS: &[(&str, Option<&str>)] = &[
    ("arguments", None),
    ("array", None),
    ("arrow_function", Some("body")),
    ("as_expression", None),
    ("assignment_expression", Some("left")),
    ("assignment_expression", Some("right")),
    ("assignment_pattern", Some("right")),
    ("augmented_assignment_expression", Some("left")),
    ("augmented_assignment_expression", Some("right")),
    ("await_expression", None),
    ("binary_expression", Some("left")),
    ("binary_expression", Some("right")),
    ("call_expression", Some("function")),
    ("computed_property_name", None),
    ("expression_statement", None),
    ("extends_clause", Some("value")),
    ("for_in_statement", Some("left")),
    ("for_in_statement", Some("right")),
    ("for_statement", Some("condition")),
    ("for_statement", Some("increment")),
    ("for_statement", Some("initializer")),
    ("instantiation_expression", Some("function")),
    ("member_expression", Some("object")),
    ("new_expression", Some("constructor")),
    ("non_null_expression", None),
    ("object", None),
    ("object_assignment_pattern", Some("right")),
    ("optional_parameter", Some("value")),
    ("pair", Some("value")),
    ("parenthesized_expression", None),
    ("public_field_definition", Some("value")),
    ("required_parameter", Some("value")),
    ("return_statement", None),
    ("satisfies_expression", None),
    ("sequence_expression", None),
    ("spread_element", None),
    ("subscript_expression", Some("index")),
    ("subscript_expression", Some("object")),
    ("switch_case", Some("value")),
    ("template_substitution", None),
    ("ternary_expression", Some("alternative")),
    ("ternary_expression", Some("condition")),
    ("ternary_expression", Some("consequence")),
    ("throw_statement", None),
    ("type_assertion", None),
    ("unary_expression", Some("argument")),
    ("update_expression", Some("argument")),
    ("variable_declarator", Some("value")),
    ("yield_expression", None),
];

/// `(parent node kind, field)` where a TypeScript `type_identifier`
/// names a type.
const TS_TYPE_POSITIONS: &[(&str, Option<&str>)] = &[
    ("adding_type_annotation", None),
    ("array_type", None),
    ("as_expression", None),
    ("conditional_type", Some("alternative")),
    ("conditional_type", Some("consequence")),
    ("conditional_type", Some("left")),
    ("conditional_type", Some("right")),
    ("constraint", None),
    ("constructor_type", Some("type")),
    ("default_type", None),
    ("extends_type_clause", Some("type")),
    ("function_type", Some("return_type")),
    ("generic_type", Some("name")),
    ("implements_clause", None),
    ("index_signature", Some("index_type")),
    ("index_type_query", None),
    ("intersection_type", None),
    ("lookup_type", None),
    ("mapped_type_clause", Some("type")),
    ("omitting_type_annotation", None),
    ("opting_type_annotation", None),
    ("optional_type", None),
    ("parenthesized_type", None),
    ("readonly_type", None),
    ("rest_type", None),
    ("satisfies_expression", None),
    ("template_type", None),
    ("tuple_type", None),
    ("type_alias_declaration", Some("value")),
    ("type_annotation", None),
    ("type_arguments", None),
    ("type_predicate", Some("type")),
    ("union_type", None),
];

/// Definition kinds whose name IS the type it denotes — a type query on
/// `Token` resolves to `Token`'s own definition, and only these are
/// annotation targets (a same-name value never is).
const TYPE_LEVEL_KINDS: &[&str] = &[
    "struct",
    "union",
    "enum",
    "trait",
    "type",
    "class",
    "interface",
    "type_parameter",
];

/// `(parent node kind, field, reported symbol kind)` for the Rust
/// grammar (tree-sitter-rust 0.24.2 node types): an identifier-shaped
/// child in that field of that node is a definition. `impl` carries no
/// name field — it is a scope bearer only.
const RUST_DEFS: &[(&str, &str, &str)] = &[
    ("function_item", "name", "function"),
    ("function_signature_item", "name", "method"),
    ("struct_item", "name", "struct"),
    ("union_item", "name", "union"),
    ("enum_item", "name", "enum"),
    ("enum_variant", "name", "member"),
    ("trait_item", "name", "trait"),
    ("type_item", "name", "type"),
    ("associated_type", "name", "type"),
    ("type_parameter", "name", "type_parameter"),
    ("const_item", "name", "const"),
    ("const_parameter", "name", "parameter"),
    ("static_item", "name", "static"),
    ("mod_item", "name", "module"),
    ("field_declaration", "name", "field"),
    ("let_declaration", "pattern", "variable"),
    ("parameter", "pattern", "parameter"),
    ("macro_definition", "name", "macro"),
    ("use_as_clause", "alias", "alias"),
];

/// Identifier-shaped node kinds in the Rust grammar — every occurrence
/// that is neither a definition's name nor a binding is a use site.
const RUST_IDENTIFIERS: &[&str] = &[
    "identifier",
    "type_identifier",
    "field_identifier",
    "shorthand_field_identifier",
];

/// Rust node kinds that open a named scope; `impl_item` contributes its
/// implemented type's name.
const RUST_SCOPES: &[&str] = &[
    "mod_item",
    "impl_item",
    "trait_item",
    "enum_item",
    "struct_item",
    "union_item",
    "function_item",
    "macro_definition",
];

/// Rust containers whose definitions are members.
const RUST_MEMBER_BEARERS: &[&str] = &[
    "impl_item",
    "trait_item",
    "struct_item",
    "enum_item",
    "union_item",
];

/// The TypeScript/TSX definition table (tree-sitter-typescript 0.23.2)
/// — same shape as the Rust table. `enum_body`'s `name` field repeats
/// once per bare member, which the cursor walk sees child by child.
const TS_DEFS: &[(&str, &str, &str)] = &[
    ("function_declaration", "name", "function"),
    ("generator_function_declaration", "name", "function"),
    ("function_expression", "name", "function"),
    ("generator_function", "name", "function"),
    ("function_signature", "name", "function"),
    ("method_definition", "name", "method"),
    ("method_signature", "name", "method"),
    ("abstract_method_signature", "name", "method"),
    ("class_declaration", "name", "class"),
    ("abstract_class_declaration", "name", "class"),
    ("class", "name", "class"),
    ("interface_declaration", "name", "interface"),
    ("enum_declaration", "name", "enum"),
    ("enum_body", "name", "member"),
    ("enum_assignment", "name", "member"),
    ("type_alias_declaration", "name", "type"),
    ("type_parameter", "name", "type_parameter"),
    ("variable_declarator", "name", "variable"),
    ("required_parameter", "pattern", "parameter"),
    ("optional_parameter", "pattern", "parameter"),
    ("public_field_definition", "name", "field"),
    ("property_signature", "name", "field"),
    ("internal_module", "name", "namespace"),
    ("module", "name", "namespace"),
];

const TS_IDENTIFIERS: &[&str] = &[
    "identifier",
    "type_identifier",
    "property_identifier",
    "shorthand_property_identifier",
    "shorthand_property_identifier_pattern",
    "private_property_identifier",
];

const TS_SCOPES: &[&str] = &[
    "internal_module",
    "module",
    "class_declaration",
    "abstract_class_declaration",
    "interface_declaration",
    "enum_declaration",
    "function_declaration",
    "generator_function_declaration",
    "method_definition",
];

/// TypeScript containers whose definitions are members — classes,
/// interfaces, enums, object types and object literals.
const TS_MEMBER_BEARERS: &[&str] = &[
    "class_declaration",
    "abstract_class_declaration",
    "class",
    "interface_declaration",
    "enum_declaration",
    "object_type",
    "object",
];

fn def_kind(grammar: Grammar, parent: &str, field: Option<&str>) -> Option<&'static str> {
    let field = field?;
    let table = match grammar {
        Grammar::Rust => RUST_DEFS,
        Grammar::TypeScript | Grammar::Tsx => TS_DEFS,
    };
    table
        .iter()
        .find(|(kind, name_field, _)| *kind == parent && *name_field == field)
        .map(|(_, _, symbol_kind)| *symbol_kind)
}

fn ident_kinds(grammar: Grammar) -> &'static [&'static str] {
    match grammar {
        Grammar::Rust => RUST_IDENTIFIERS,
        Grammar::TypeScript | Grammar::Tsx => TS_IDENTIFIERS,
    }
}

fn scope_kinds(grammar: Grammar) -> &'static [&'static str] {
    match grammar {
        Grammar::Rust => RUST_SCOPES,
        Grammar::TypeScript | Grammar::Tsx => TS_SCOPES,
    }
}

fn member_bearers(grammar: Grammar) -> &'static [&'static str] {
    match grammar {
        Grammar::Rust => RUST_MEMBER_BEARERS,
        Grammar::TypeScript | Grammar::Tsx => TS_MEMBER_BEARERS,
    }
}

/// What a named scope of `kind` is: a module a path may walk into (a
/// Rust `mod` also bounds a bare walk), or a function. A type is
/// neither: a path through one hangs on impls and dispatch the index
/// does not model (DEC-029).
fn bearer_of(grammar: Grammar, kind: &str) -> u8 {
    match (grammar, kind) {
        (Grammar::Rust, "mod_item") => PATH_SCOPE | MODULE_SCOPE,
        (Grammar::TypeScript | Grammar::Tsx, "internal_module" | "module") => PATH_SCOPE | HOISTS,
        (Grammar::Rust, "function_item") => FUNCTION_SCOPE,
        (
            Grammar::TypeScript | Grammar::Tsx,
            "function_declaration" | "generator_function_declaration" | "method_definition",
        ) => FUNCTION_SCOPE | HOISTS,
        _ => 0,
    }
}

/// Does a node of `kind` (under `parent`) open an anonymous scope — and
/// does its name, if any, live inside it? A TypeScript namespace's body
/// block is the namespace's own scope. A signature-only declaration or
/// a function type holds its parameters and generics, never leaking
/// them to the scope around it.
fn opens_anonymous(grammar: Grammar, kind: &str, parent: Option<&str>) -> Option<Opened> {
    match grammar {
        Grammar::Rust => match kind {
            "block" | "closure_expression" | "match_arm" | "if_expression" | "while_expression"
            | "for_expression" => Some(Opened::Anonymous),
            "function_signature_item" | "function_type" => Some(Opened::Signature),
            _ => None,
        },
        Grammar::TypeScript | Grammar::Tsx => match kind {
            "statement_block" if !matches!(parent, Some("internal_module" | "module")) => {
                Some(Opened::Anonymous)
            }
            // A conditional type holds its `infer` names, an index
            // signature its mapped key.
            "arrow_function"
            | "function_expression"
            | "generator_function"
            | "class"
            | "catch_clause"
            | "for_in_statement"
            | "for_statement"
            | "switch_body"
            | "conditional_type"
            | "index_signature" => Some(Opened::Anonymous),
            "function_signature"
            | "method_signature"
            | "abstract_method_signature"
            | "call_signature"
            | "construct_signature"
            | "function_type"
            | "constructor_type" => Some(Opened::Signature),
            _ => None,
        },
    }
}

/// Type-name node kinds — the plain name plus its qualified form, which
/// preorder reaches first.
fn type_name_kinds(grammar: Grammar) -> &'static [&'static str] {
    match grammar {
        Grammar::Rust => &["type_identifier", "scoped_type_identifier"],
        Grammar::TypeScript | Grammar::Tsx => &["type_identifier", "nested_type_identifier"],
    }
}

/// A type-name node's last segment plus its qualifier node, if the
/// name is qualified.
fn type_name_parts<'tree>(
    grammar: Grammar,
    node: Node<'tree>,
) -> (Node<'tree>, Option<Node<'tree>>) {
    let qualifier_field = match (grammar, node.kind()) {
        (Grammar::Rust, "scoped_type_identifier") => "path",
        (Grammar::TypeScript | Grammar::Tsx, "nested_type_identifier") => "module",
        _ => return (node, None),
    };
    match node.child_by_field_name("name") {
        Some(name) => (name, node.child_by_field_name(qualifier_field)),
        None => (node, None),
    }
}

/// The binding context a child inherits: a binding pattern starts at a
/// parameter's/declaration's pattern field and flows to every
/// descendant, until a part that names something else — a
/// tuple-struct/struct pattern's path, a field name, a range bound, a
/// default value, a destructured key. The start fixes where its names
/// become visible: after a `let` statement or declarator (its
/// initializer reads the outer name), from a `for` loop's body, and for
/// an `if let`/`while let` only until its block ends. A parameter, arm
/// or `catch` binding ends with its own function, closure, arm or
/// clause, so a same-name sibling function's parameters never reach
/// into another's body.
fn child_local(
    grammar: Grammar,
    frames: &[Frame<'_>],
    field: Option<&str>,
    child: Node<'_>,
) -> Option<Local> {
    let parent = frames.last()?;
    // A path (`foo::bar`, `Foo<T>`, `obj.prop`) names something else —
    // checked first so a path placed directly in a pattern field (`a::B
    // =>`) never starts a binding.
    if matches!(
        child.kind(),
        "scoped_identifier"
            | "scoped_type_identifier"
            | "generic_type"
            | "member_expression"
            | "subscript_expression"
    ) {
        return None;
    }
    let node = parent.node;
    // Visible from the identifier until the end of the owner `up`
    // frames above the pattern's parent.
    let here = |kind, up: usize| {
        Some(Local {
            kind,
            from: None,
            until: frames
                .iter()
                .rev()
                .nth(up)
                .map_or(u64::MAX, |owner| owner.node.end_byte() as u64),
        })
    };
    let after = |kind, from: Option<u64>, until| Some(Local { kind, from, until });
    let end = node.end_byte() as u64;
    match grammar {
        Grammar::Rust => match (node.kind(), field) {
            // `parameter` → `parameters`/`closure_parameters` → owner.
            ("parameter", Some("pattern")) => here("parameter", 2),
            ("closure_parameters", _) if child.kind() != "parameter" => here("parameter", 1),
            ("let_declaration", Some("pattern")) => after("variable", Some(end), u64::MAX),
            ("let_condition", Some("pattern")) => {
                after("variable", Some(end), condition_block_end(frames))
            }
            ("for_expression", Some("pattern")) => after("variable", body_start(node), u64::MAX),
            // The arm's pattern — its `condition` field is the guard.
            ("match_pattern", None) => here("variable", 1),
            ("tuple_struct_pattern" | "struct_pattern", Some("type")) | ("range_pattern", _) => {
                None
            }
            ("field_pattern", Some("name")) if child.kind() != "shorthand_field_identifier" => None,
            _ => parent.local,
        },
        Grammar::TypeScript | Grammar::Tsx => match (node.kind(), field) {
            // `required_parameter` → `formal_parameters` → owner.
            ("required_parameter" | "optional_parameter", Some("pattern")) => here("parameter", 2),
            ("arrow_function", Some("parameter")) => here("parameter", 0),
            // A `var` is hoisted to its function (kind "var"); `let` and
            // `const` are block-scoped.
            ("variable_declarator", Some("name")) => {
                let hoisted = frames
                    .len()
                    .checked_sub(2)
                    .and_then(|at| frames.get(at))
                    .is_some_and(|above| above.node.kind() == "variable_declaration");
                after(
                    if hoisted { "var" } else { "variable" },
                    Some(end),
                    u64::MAX,
                )
            }
            // A `using` declaration binds a block-scoped local, like
            // `const`; every other assignment declares nothing.
            ("assignment_expression", Some("left"))
                if child.kind() == "identifier" && parent.declares =>
            {
                after("variable", Some(end), u64::MAX)
            }
            ("catch_clause", Some("parameter")) => here("variable", 0),
            // `for (const x of …)` declares; a bare `for (x of …)` assigns.
            ("for_in_statement", Some("left")) => match node.child_by_field_name("kind") {
                Some(declared) => after(
                    if declared.kind() == "var" {
                        "var"
                    } else {
                        "variable"
                    },
                    body_start(node),
                    u64::MAX,
                ),
                None => parent.local,
            },
            ("pair_pattern", Some("key"))
            | ("object_assignment_pattern" | "assignment_pattern", Some("right")) => None,
            _ => parent.local,
        },
    }
}

fn body_start(node: Node<'_>) -> Option<u64> {
    node.child_by_field_name("body")
        .map(|body| body.start_byte() as u64)
}

/// Where an `if let`/`while let` binding stops being visible: the end
/// of the block it guards. The walk's frames end at the `let_condition`;
/// its `if`/`while` sits one level up, or two through a `let_chain`.
fn condition_block_end(frames: &[Frame<'_>]) -> u64 {
    frames
        .iter()
        .rev()
        .skip(1)
        .take(2)
        .find_map(|frame| match frame.node.kind() {
            "if_expression" => frame.node.child_by_field_name("consequence"),
            "while_expression" => frame.node.child_by_field_name("body"),
            _ => None,
        })
        .map_or(u64::MAX, |block| block.end_byte() as u64)
}

/// Can this identifier inside a binding pattern be a binding? A Rust
/// bare pattern spelled uppercase names a unit variant or constant
/// (`None =>`) — a use, and an opaque one: patterns are no use position.
/// ponytail: case convention stands in for name resolution of pattern
/// identifiers; resolve against in-scope variants when that matters.
fn is_binding_name(grammar: Grammar, kind: &str, text: &str) -> bool {
    match grammar {
        Grammar::Rust => {
            matches!(kind, "identifier" | "shorthand_field_identifier")
                && !text.starts_with(|first: char| first.is_uppercase())
        }
        Grammar::TypeScript | Grammar::Tsx => {
            matches!(kind, "identifier" | "shorthand_property_identifier_pattern")
        }
    }
}

/// A grammar's own parser over the source, stopped once it has taken
/// `limit` progress checks or runs past `deadline` — no shared parser
/// cache, no language server. Returns the tree (`None` when the grammar
/// cannot load or the parse stopped: the file produced no rows) and the
/// checks the parse took. The checks do not see GLR reduction or error
/// recovery (see [`MAX_PARSE_CHECKS`]): in-process, this parse is not
/// bounded — isolating it is the wiring slice's gate (DEC-028).
fn parse(
    grammar: Grammar,
    source: &str,
    limit: u64,
    deadline: Option<Instant>,
) -> (Option<tree_sitter::Tree>, u64) {
    let mut parser = Parser::new();
    if parser.set_language(&grammar.ts_language()).is_err() {
        return (None, 0);
    }
    let mut checks = 0;
    let mut progress = |_: &ParseState| {
        // A deadline past what `Instant` can represent stops every parse
        // rather than leaving one unbounded.
        if checks >= limit || deadline.is_none_or(|end| Instant::now() >= end) {
            return ControlFlow::Break(());
        }
        checks += 1;
        ControlFlow::Continue(())
    };
    let bytes = source.as_bytes();
    let tree = parser.parse_with_options(
        &mut |offset, _| bytes.get(offset..).unwrap_or_default(),
        None,
        Some(ParseOptions::new().progress_callback(&mut progress)),
    );
    (tree, checks)
}

/// The project-root-relative package root a file's module path is read
/// from (DEC-030 #4): the nearest enclosing directory holding a
/// `Cargo.toml`, searched upward from the file's own directory and never
/// past the pinned query root. A file under no package — the query root
/// itself, or a tree with no manifest — is read from the query root, so a
/// single-package project derives exactly what it did before.
fn package_root_of(absolute: &Path, root: &Path) -> PathBuf {
    // `ancestors` rather than `parent`: the walk is over filesystem
    // paths, and this module's tree-sitter walk must never look like it
    // reaches a node's parent.
    for directory in absolute.ancestors().skip(1) {
        if directory.join("Cargo.toml").is_file() {
            return directory
                .strip_prefix(root)
                .map_or_else(|_| PathBuf::new(), Path::to_path_buf);
        }
        if directory == root {
            break;
        }
    }
    PathBuf::new()
}

/// A Rust file's module path from its package-root-relative location
/// under the Cargo layout (DEC-029): `src/lib.rs`, `src/main.rs`, a
/// top-level `lib.rs`/`main.rs`, and in the target directories
/// `src/bin/`, `tests/`, `examples/` and `benches/` each `*.rs` and each
/// `*/main.rs` are crate roots (an empty path); a target directory's
/// `x/mod.rs` is the module `x` a root there declares. `src/a.rs` and
/// `src/a/mod.rs` are `a`, `src/b/c.rs` is `b::c`. Any other location
/// derives none: a deeper target file (`tests/support/x.rs` is `x` of a
/// multi-file test `support`, or `support::x` of a test declaring
/// `mod support;`), `src/mod.rs`, a name that is not utf-8.
///
/// The path is relative to `package` — the project root's nearest
/// enclosing directory holding a `Cargo.toml` (DEC-030 #4) — not to the
/// query root, so a query scoped to `crates/x` still addresses module
/// `a::b` the same way a whole-project query does. It is the layout's
/// convention: a `#[path]` attribute, or a file no `mod` declares, is
/// not seen.
fn module_path(relative: &Path, package: &Path) -> Option<Vec<Box<str>>> {
    // `strip_prefix` answers a `Result` whose error names nothing beyond
    // "no such prefix" — the same fact this `Option` return already
    // states — so the prefix that does not match yields no module.
    let below = relative.strip_prefix(package).ok()?;
    let parts = below
        .iter()
        .map(|part| part.to_str())
        .collect::<Option<Vec<&str>>>()?;
    let (file, dirs) = parts.split_last()?;
    let stem = file.strip_suffix(".rs")?;
    match (dirs, stem) {
        ([] | ["src"], "lib" | "main")
        | (["src", "bin"] | ["tests" | "examples" | "benches"], _)
        | (["src", "bin", _] | ["tests" | "examples" | "benches", _], "main") => Some(Vec::new()),
        (["src", "bin", module] | ["tests" | "examples" | "benches", module], "mod") => {
            Some(vec![(*module).into()])
        }
        (["src", "bin", ..], _) => None,
        (["src", nested @ ..], _) => {
            let mut path: Vec<Box<str>> = nested.iter().map(|&dir| dir.into()).collect();
            if stem != "mod" {
                path.push(stem.into());
            }
            // `src/mod.rs` is no crate root and no module.
            (!path.is_empty()).then_some(path)
        }
        _ => None,
    }
}

/// [`module_path`] as the `::`-joined name a project graph places a
/// document under (DEC-029/030 #4): the same layout, read by the same
/// function, so an edge and a symbol row can never name two different
/// modules. `None` when the location derives no module — a target
/// directory's deeper file, `src/mod.rs`, a name that is not utf-8 —
/// and `None` is the whole answer: the crate-root spelling belongs to a
/// location the layout actually places there, and is never substituted
/// for an unknown one.
pub fn module_name(relative: &Path, package: &Path) -> Option<String> {
    let path = module_path(relative, package)?;
    Some(
        path.iter()
            .map(|segment| &**segment)
            .collect::<Vec<&str>>()
            .join("::"),
    )
}

/// The project-relative files a Rust module path names under `package`
/// (DEC-030 #4) — the same Cargo layout [`module_path`] reads, in the
/// other direction, so the two cannot drift: `a::b` is
/// `package/src/a/b.rs` or `package/src/a/b/mod.rs`, and the empty path
/// is `package/src/lib.rs` or `package/src/main.rs`. Candidates come in
/// preference order; the caller confirms each against the files the
/// generation indexed, so an unclaimed module stays unknown rather than
/// invented. A segment the layout cannot spell yields no candidate.
pub fn module_files(package: &Path, module: &str) -> Vec<PathBuf> {
    let mut path = package.join("src");
    let segments: Vec<&str> = module.split("::").filter(|s| !s.is_empty()).collect();
    if !segments.iter().all(|segment| is_module_segment(segment)) {
        return Vec::new();
    }
    for segment in segments {
        path.push(segment);
    }
    if module.is_empty() {
        return vec![path.join("lib.rs"), path.join("main.rs")];
    }
    let nested = path.with_extension("rs");
    vec![nested, path.join("mod.rs")]
}

/// A module path segment is a plain identifier: anything else is not a
/// path the layout can spell.
fn is_module_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !segment.starts_with(|c: char| c.is_ascii_digit())
}

/// The content-derived document version: a sha-256 prefix coerced
/// i32-positive — same bytes, same version, and a change under a
/// pinned version is detectably different.
fn content_version(bytes: &[u8]) -> i32 {
    let digest = sha2::Sha256::digest(bytes);
    i32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) & i32::MAX
}

/// `file://` URI for an absolute path — percent-encodes every byte
/// outside RFC 3986 unreserved plus `/:@`; a path that is not UTF-8 or
/// fails `Uri` parse names no document. Public so callers compare
/// document identities with the index's own encoder.
/// ponytail: a Windows `C:\…` path percent-encodes its separators — a
/// parseable but non-canonical uri; flip `\` to `/` when a Windows leg
/// lands.
pub fn path_to_uri(path: &Path) -> Option<Uri> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let text = path.to_str()?;
    let mut uri = String::with_capacity(text.len() + 8);
    uri.push_str("file://");
    for byte in text.as_bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~'
            | b'/'
            | b':'
            | b'@' => uri.push(char::from(*byte)),
            _ => {
                uri.push('%');
                uri.push(char::from(HEX[(byte >> 4) as usize]));
                uri.push(char::from(HEX[(byte & 0x0f) as usize]));
            }
        }
    }
    Uri::from_str(&uri).ok()
}

/// The node's own text — byte offsets from the parse are char
/// boundaries in valid utf-8, so `get` slices rather than panics; a
/// `None` (impossible post-decode-check) skips the node.
fn node_text<'a>(node: &Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(node.start_byte()..node.end_byte())
}

#[cfg(test)]
mod tests {
    use super::{Anchor, FileStamp, module_files, module_path, parse, spelled_anchor};
    use crate::context::Grammar;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    #[test]
    fn parse_stops_at_a_spent_deadline() {
        // The deadline is read inside the parse as well as before it: a
        // parse that reaches a progress check past it stops, whatever
        // checks are left.
        let source = format!("fn f(){{{}}}", "a;".repeat(1000));
        assert_eq!(
            parse(Grammar::Rust, &source, u64::MAX, Some(Instant::now())).1,
            0
        );
        assert!(
            parse(Grammar::Rust, &source, u64::MAX, Some(Instant::now()))
                .0
                .is_none()
        );
        let ahead = Instant::now().checked_add(Duration::from_secs(24 * 60 * 60));
        let (tree, checks) = parse(Grammar::Rust, &source, u64::MAX, ahead);
        assert!(tree.is_some() && checks > 0, "{checks}");
    }

    #[test]
    fn unverifiable_mtime_is_never_current() {
        let unknown = FileStamp {
            len: 7,
            modified: None,
        };
        let known = FileStamp {
            len: 7,
            modified: Some(1),
        };
        assert!(known.is_current(known));
        assert!(!unknown.is_current(unknown), "no mtime on either side");
        assert!(!known.is_current(unknown));
        assert!(!unknown.is_current(known));
        assert!(!known.is_current(FileStamp {
            len: 8,
            modified: Some(1)
        }));
    }

    #[test]
    fn spelled_qualifiers_anchor_at_root_module_or_lexically() {
        let shape = |qualifier: &str| match spelled_anchor(qualifier) {
            Some(Anchor::Root(rest)) => format!("root {rest}"),
            Some(Anchor::Module(rest)) => format!("module {rest}"),
            Some(Anchor::Lexical(rest)) => format!("lexical {rest}"),
            None => "unusable".to_string(),
        };
        for (qualifier, expected) in [
            ("a", "lexical a"),
            ("x::a", "lexical x::a"),
            ("crate", "root "),
            ("crate::a", "root a"),
            ("self", "module "),
            ("self::a", "module a"),
            ("super::a", "unusable"),
            ("a::super", "unusable"),
        ] {
            assert_eq!(shape(qualifier), expected, "{qualifier}");
        }
    }

    #[test]
    fn module_paths_follow_the_cargo_layout() {
        // `Some("")` is a crate root.
        for (relative, expected) in [
            ("src/lib.rs", Some("")),
            ("src/main.rs", Some("")),
            ("src/bin/t.rs", Some("")),
            ("lib.rs", Some("")),
            ("main.rs", Some("")),
            ("tests/t.rs", Some("")),
            ("examples/e.rs", Some("")),
            ("benches/b.rs", Some("")),
            // A multi-file target's `main.rs` is its crate root, and a
            // `mod.rs` beside the roots is the module one of them declares.
            ("src/bin/x/main.rs", Some("")),
            ("tests/x/main.rs", Some("")),
            ("src/bin/x/mod.rs", Some("x")),
            ("tests/support/mod.rs", Some("support")),
            // Ambiguous: `y` of the target `x`, or `x::y` of another root
            // there through `x/mod.rs`.
            ("src/bin/x/y.rs", None),
            ("tests/support/x.rs", None),
            ("src/a.rs", Some("a")),
            ("src/a/mod.rs", Some("a")),
            ("src/x/y/z.rs", Some("x::y::z")),
            ("src/mod.rs", None),
            ("scripts/tool.rs", None),
            ("src/a.ts", None),
        ] {
            let derived =
                module_path(Path::new(relative), Path::new("")).map(|path| path.join("::"));
            assert_eq!(derived.as_deref(), expected, "{relative}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let name = std::ffi::OsStr::from_bytes(b"src/caf\xe9.rs");
            assert_eq!(
                module_path(Path::new(name), Path::new("")),
                None,
                "a non-utf-8 name"
            );
        }
    }

    #[test]
    fn module_paths_are_read_from_the_package_root() {
        // The same layout under a package that is not the query root: a
        // workspace member derives its own module path, and a file
        // outside every package stays relative to the query root.
        for (package, relative, expected) in [
            ("crates/x", "crates/x/src/a.rs", Some("a")),
            ("crates/x", "crates/x/src/lib.rs", Some("")),
            ("crates/x", "crates/x/src/b/c.rs", Some("b::c")),
            ("", "src/a.rs", Some("a")),
            ("crates/x", "src/a.rs", None),
        ] {
            let derived =
                module_path(Path::new(relative), Path::new(package)).map(|path| path.join("::"));
            assert_eq!(derived.as_deref(), expected, "{package}/{relative}");
        }
        assert_eq!(
            module_files(Path::new("crates/x"), "a::b"),
            vec![
                PathBuf::from("crates/x/src/a/b.rs"),
                PathBuf::from("crates/x/src/a/b/mod.rs"),
            ]
        );
        assert_eq!(
            module_files(Path::new("crates/x"), ""),
            vec![
                PathBuf::from("crates/x/src/lib.rs"),
                PathBuf::from("crates/x/src/main.rs"),
            ]
        );
        // A path segment the layout cannot spell names no file — an
        // absent answer, never a guessed one.
        assert!(module_files(Path::new(""), "a::..::b").is_empty());
        assert!(module_files(Path::new(""), "a::1b").is_empty());
    }
}
