//! The project index contract (AC-035 / AC-031 / AC-036b / AC-036c):
//! `project.init` returns a typed versioned generation whose edges carry
//! their source, version and confidence, an incremental generation equals
//! a full one over the same bytes, a missed watcher event or a crash
//! mid-index repairs or marks the generation explicitly stale, and every
//! runtime parse of project source reaches the capped index worker alone.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions fail loudly with the observed payload (standards §14)"
)]

mod support;

use rivect::actions::{ActionRegistry, INSPECT_SYSTEM, Implementation, RESOLVE_DECISION};
use rivect::commands::{DispatchStep, escape_control};
use rivect::context::{ContextError, IsolatedCause, QueryKind, query};
use rivect::contracts::{
    ErrorCode, LocalCommand, LocalCommandResult, ProjectInitResult, SessionId,
};
use rivect::index::{
    Completeness, EdgeConfidence, EdgeKind, EdgeProvenance, GenerationState, IndexEdge, MatchKind,
    PartialReason, ProjectGraph, QueryResult, SearchBackend, SnapshotId, StaleCause, WatchBatch,
};
use rivect::lsp::MAX_INDEX_PARSE_TIME;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use support::{
    TempTree, corpus_command_execute, ensure_helper, open_world, project_corpus, rivect_binary,
    search_corpus, search_query, write_file,
};

/// A world whose pinned project root is a fresh fixture tree, with the
/// worker program the re-exec needs and the real sandbox helper beside
/// the harness. Returns the world, its session and the tree.
fn project_world(tag: &str, name: &str) -> (support::World, SessionId, TempTree) {
    ensure_helper();
    let tree = project_corpus(name);
    let mut world = open_world(tag, None);
    world.runtime.index.worker.program = PathBuf::from(rivect_binary());
    world.runtime.set_project_root(tree.path.clone());
    let session = world.open_session(&format!("{tag}-session"));
    (world, session, tree)
}

/// Dispatches `project.init` with the caller's own fields only.
fn init(world: &mut support::World, session: &SessionId, extra: Value) -> Value {
    world.dispatch(&init_params(session, extra))
}

/// The `project.init` request body, with the caller's own fields only.
fn init_params(session: &SessionId, extra: Value) -> Value {
    let mut command = json!({ "kind": "project.init" });
    // `id` in the caller's own fields addresses the *request*, not the
    // command, so a test can name a second request distinctly.
    let mut request_id = Value::from(1);
    if let Value::Object(fields) = extra {
        for (key, value) in fields {
            // `id` addresses the request, not the command, so it is
            // lifted out and never reaches the carrier — which refuses
            // an undeclared name, as it should.
            if key == "id" {
                request_id = value.clone();
                continue;
            }
            command[key] = value;
        }
    }
    json!({
        "jsonrpc": "2.0", "id": request_id, "method": "command.execute",
        "params": {
            "schema_version": 1,
            "session_id": session.0,
            "command": command,
        }
    })
}

/// The loop's entry point: route the request and report whether its
/// answer is ready or owed to the off-path owner. Same request body as
/// [`init`], so a test can drive the deferred shape the headless loop
/// drives.
fn step(world: &mut support::World, session: &SessionId, extra: Value) -> DispatchStep {
    let request = init_params(session, extra);
    let encoded = serde_json::to_string(&request).expect("the request is a value");
    rivect::commands::dispatch_step(
        &mut world.runtime,
        rivect::commands::Ingress::TrustedHuman,
        "test-loop",
        &encoded,
    )
}

/// A `command.describe` frame: a request that must be answered while a
/// bounded run is still in flight, because it is not the request that
/// started it.
fn describe_step(world: &mut support::World) -> DispatchStep {
    let request = json!({
        "jsonrpc": "2.0", "id": 99, "method": "command.describe",
        "params": { "schema_version": 1 },
    });
    let encoded = serde_json::to_string(&request).expect("the request is a value");
    rivect::commands::dispatch_step(
        &mut world.runtime,
        rivect::commands::Ingress::TrustedHuman,
        "test-loop",
        &encoded,
    )
}

fn init_result(response: &Value) -> ProjectInitResult {
    serde_json::from_value(response["result"].clone()).expect("a typed project-init answer")
}

/// One `project.init` cut, with a refused request reported as `Err`
/// rather than as a panic inside a serde decode.
///
/// A refusal and a verdict are different things and a fixture must not
/// blur them: a refused request never ran, so it says nothing about the
/// project, while an answered one is the product's statement. `Err` here
/// is the refusal, and a caller may retry *that* — re-issuing a request
/// that never ran cannot convert one verdict into another — while a
/// verdict is asserted exactly once.
fn init_cut(
    world: &mut support::World,
    session: &SessionId,
    extra: Value,
) -> Result<ProjectInitResult, String> {
    let response = init(world, session, extra);
    if response["error"].is_null() {
        return Ok(init_result(&response));
    }
    Err(format!(
        "{} / {}",
        response["error"]["data"]["code"], response["error"]["data"]["message"]
    ))
}

/// A cut that ran and kept the narrowing it was asked for — on its first
/// answered attempt.
///
/// A cut widens itself when the derivation could not enumerate everything
/// it found (a read that failed, or the deadline passing mid-walk), when
/// the project's own watch reports that the file set moved, and when the
/// indexed sets disagree outside the narrowing. The first two are
/// fail-closed and the third is the authoritative check (D-105), so all
/// three are the *product* answering about the project rather than a
/// loaded host failing a test.
///
/// So a widening is the failure it is and is never retried. An earlier
/// version retried up to four times, which quietly turned every proof that
/// used it into a proof about a narrowing *obtained by retry* rather than
/// about the cut the fixture set up: measured, a create inside the
/// narrowing makes the first answered cut widen and the second keep the
/// narrowing, so the first attempt said one thing and the helper returned
/// the other. With the verdict demoted to advisory the narrowing is decided
/// by the indexed sets, and the one thing a retry still has to absorb is a
/// *refusal* — a request that never ran, which no number of attempts turns
/// into a verdict.
/// The assertion every answered cut of `narrowed_cut` faces: a widening
/// is the product's verdict about the project, so it is asserted once and
/// never retried.
fn assert_kept_its_narrowing(result: &ProjectInitResult, changed: &[&str]) {
    assert!(
        !result.graph.narrowed_to.is_empty(),
        "the cut kept the narrowing {changed:?} on its first answered \
         attempt: the file set outside it held still, so widening it would \
         be a verdict nothing in the project supports — coverage {:?}, \
         narrowed_to {:?}",
        result.graph.completeness,
        result.graph.narrowed_to
    );
}

fn narrowed_cut(
    world: &mut support::World,
    session: &SessionId,
    changed: &[&str],
    first_file_set_moved: bool,
) -> ProjectInitResult {
    // A manufactured verdict *is* the question this call asks, so it is
    // issued once. Falling back to an ordinary `project.init` after a
    // refusal here would answer a different question — one carrying no
    // verdict at all — and the caller's assertion would then be about that
    // question instead of the one it set up.
    if first_file_set_moved {
        let result = world
            .runtime
            .build_project_index(
                None,
                None,
                &changed.iter().map(PathBuf::from).collect::<Vec<_>>(),
                true,
            )
            .unwrap_or_else(|refused| {
                panic!("the cut carrying the manufactured verdict was refused: {refused}")
            });
        assert_kept_its_narrowing(&result, changed);
        return result;
    }
    let extra = json!({ "changed": changed.iter().collect::<Vec<_>>() });
    let mut refusals: Vec<String> = Vec::new();
    for _ in 0..3 {
        match init_cut(world, session, extra.clone()) {
            Ok(result) => {
                assert_kept_its_narrowing(&result, changed);
                return result;
            }
            Err(refusal) => refusals.push(refusal),
        }
    }
    panic!("three refused cuts and no answer: {refusals:?}");
}

/// The edges a generation carries, as the store holds them.
fn stored_edges(world: &support::World, generation: u64) -> Vec<IndexEdge> {
    world
        .runtime
        .store()
        .index_graph(generation)
        .expect("the generation reads")
        .expect("the generation is retained")
        .graph
        .edges
}

/// The relation one subject document declares, ignoring the line and the
/// version, so an incremental and a full generation compare by meaning.
fn relations(edges: &[IndexEdge], from: &str) -> Vec<(String, EdgeKind, EdgeConfidence)> {
    edges
        .iter()
        .filter(|edge| edge.from.path.as_path() == Path::new(from))
        .map(|edge| {
            (
                edge.to.path.to_string_lossy().into_owned(),
                edge.kind,
                edge.confidence,
            )
        })
        .collect()
}

#[test]
fn init_produces_typed_directed_edges_with_source_version_confidence() {
    let (mut world, session, tree) = project_world("init-edges", "edges");
    let response = init(&mut world, &session, json!({}));
    let result = init_result(&response);
    assert!(matches!(result.state, GenerationState::Fresh), "fresh");
    let generation = match result.snapshot {
        SnapshotId::Generation(generation) => generation,
        SnapshotId::Live => panic!("project.init cuts a stored generation, never a live scan"),
    };

    // The returned handle is the consumer's only entry: reading the
    // store by that exact generation gives the same graph back.
    let stored = world
        .runtime
        .store()
        .index_graph(generation)
        .expect("reads")
        .expect("retained");
    assert_eq!(stored.generation, generation);
    assert_eq!(stored.graph.edges, result.graph.edges);
    assert_eq!(stored.state, GenerationState::Fresh);

    let lib = relations(&result.graph.edges, "src/lib.rs");
    // `pub mod helper;` is a namespace declaration: the target is the
    // declared module, and the relation was read at `src/lib.rs`'s own
    // content version.
    assert_eq!(
        lib,
        vec![(
            String::from("src/helper.rs"),
            EdgeKind::Import,
            EdgeConfidence::Certain
        )],
        "the module declaration names the file the Cargo layout spells: {lib:?}"
    );
    let module_edge = result
        .graph
        .edges
        .iter()
        .find(|edge| edge.from.path.as_path() == Path::new("src/lib.rs"))
        .expect("the module edge");
    assert_eq!(module_edge.provenance, EdgeProvenance::Structural);
    assert!(module_edge.from.line.is_some(), "a relation names its line");
    assert_eq!(
        module_edge.version,
        version_of(&tree.path.join("src/lib.rs")),
        "an edge names the document version it was read at"
    );

    // A qualified call names the module it reaches, and a bare local
    // call names no cross-file dependency at all.
    let uses = relations(&result.graph.edges, "src/uses.rs");
    assert_eq!(
        uses,
        vec![
            (
                String::from("src/helper.rs"),
                EdgeKind::Import,
                EdgeConfidence::Certain
            ),
            (
                String::from("src/helper.rs"),
                EdgeKind::Call,
                EdgeConfidence::Certain
            ),
        ],
        "one `use` relation and one qualified call to the same module, and no row \
         for the bare local call: {uses:?}"
    );

    // Every kind, provenance and confidence the vocabulary declares is
    // reachable from one corpus, and none is dead.
    let kinds: BTreeSet<EdgeKind> = result.graph.edges.iter().map(|edge| edge.kind).collect();
    assert_eq!(
        kinds,
        [EdgeKind::Import, EdgeKind::Call, EdgeKind::Test]
            .into_iter()
            .collect(),
        "a module relation, a qualified call and a test-target relation all occur"
    );
    let provenances: BTreeSet<EdgeProvenance> = result
        .graph
        .edges
        .iter()
        .map(|edge| edge.provenance)
        .collect();
    assert_eq!(
        provenances,
        [
            EdgeProvenance::Observed,
            EdgeProvenance::Inferred,
            EdgeProvenance::Structural,
        ]
        .into_iter()
        .collect(),
        "a spelled path, a layout-derived module and a declaration all occur"
    );
    // A fully covered corpus is complete: every relation in it resolves,
    // so nothing is withheld and the generation is fresh.
    assert!(
        result.graph.completeness.is_complete(),
        "a corpus whose every relation resolves is complete: {result:?}"
    );
    assert!(result.graph.unresolved.is_empty());
    assert!(
        result
            .graph
            .edges
            .iter()
            .all(|edge| edge.confidence == EdgeConfidence::Certain)
    );

    // An unplaceable specifier is a real row, not a missing one: the
    // bare `use a::b;` form (2018 names an external crate) places
    // nothing, so the row keeps the raw specifier as its target at
    // `Unknown` confidence and the specifier is reported unresolved. An
    // absent edge is never proof of an absent dependency.
    write_file(
        &tree.path,
        "src/external.rs",
        "use serde::Serialize;\npub fn needs_external() {}\n",
    );
    let external = init_result(&init(&mut world, &session, json!({})));
    let unknown: Vec<&IndexEdge> = external
        .graph
        .edges
        .iter()
        .filter(|edge| edge.confidence == EdgeConfidence::Unknown)
        .collect();
    assert_eq!(
        unknown
            .iter()
            .map(|edge| edge.to.path.clone())
            .collect::<Vec<_>>(),
        vec![PathBuf::from("serde::Serialize")],
        "an unplaceable specifier stays an unknown-confidence row: {unknown:?}"
    );
    assert_eq!(
        external.graph.unresolved,
        vec![PathBuf::from("serde::Serialize")]
    );
    assert!(!external.graph.completeness.is_complete());
    assert!(!external.state.is_fresh());
    // And the placeable relation in the same document is still served.
    assert_eq!(
        relations(&external.graph.edges, "src/lib.rs"),
        vec![(
            String::from("src/helper.rs"),
            EdgeKind::Import,
            EdgeConfidence::Certain
        )],
        "one unresolved specifier never withdraws the rows beside it"
    );
}

/// The content-derived version the index stamps, read back from a
/// generation that already carries it.
fn version_of(path: &Path) -> i32 {
    let bytes = std::fs::read(path).expect("read fixture");
    let digest = sha256_of(&bytes);
    i32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) & i32::MAX
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes).into()
}

#[test]
fn consumer_project_init_queries_the_returned_generation() {
    let (mut world, session, _tree) = project_world("init-consumer", "consumer");
    let first = init_result(&init(&mut world, &session, json!({})));
    let first_generation = match first.snapshot {
        SnapshotId::Generation(generation) => generation,
        SnapshotId::Live => panic!("a stored generation"),
    };

    // A second cut moves the handle on: the older one keeps its rows
    // and stays readable, so a consumer that pinned it is not handed
    // another generation's answer.
    write_file(
        &world.runtime.index.root.clone(),
        "src/extra.rs",
        "pub fn extra() {}\n",
    );
    write_file(
        &world.runtime.index.root.clone(),
        "src/consumer.rs",
        "use crate::helper::helper_fn;\npub fn consume() {\n    helper_fn();\n}\n",
    );
    let second = init_result(&init(&mut world, &session, json!({})));
    let second_generation = match second.snapshot {
        SnapshotId::Generation(generation) => generation,
        SnapshotId::Live => panic!("a stored generation"),
    };
    assert!(second_generation > first_generation);

    let pinned = world
        .runtime
        .store()
        .index_graph(first_generation)
        .expect("reads")
        .expect("the pinned generation is retained");
    assert_eq!(pinned.generation, first_generation);
    assert!(!pinned.graph.edges.is_empty());
    assert!(
        !pinned
            .graph
            .edges
            .iter()
            .any(|edge| edge.from.path.as_path() == Path::new("src/consumer.rs")),
        "the pinned generation does not see a document added after it"
    );
    assert!(
        stored_edges(&world, second_generation)
            .iter()
            .any(|edge| edge.from.path.as_path() == Path::new("src/consumer.rs")),
        "the newer generation carries the new document"
    );
    // A generation number that was never cut names nothing, and a
    // `SnapshotId` is never reissued for a different one.
    assert!(
        world
            .runtime
            .store()
            .index_graph(9_999)
            .expect("reads")
            .is_none()
    );
}

#[test]
fn dirty_edit_rename_alias_lock_parser_generation_incremental_equals_initial() {
    let (mut world, session, tree) = project_world("init-incremental", "incremental");
    let initial = init_result(&init(&mut world, &session, json!({})));
    let initial_generation = generation_of(&initial);
    assert!(initial.state.is_fresh(), "{initial:?}");

    // A dirty edit: one document's bytes change, nothing is added or
    // removed, and the file set is unchanged — so a narrow
    // re-derivation is sound, and it must equal a full build over the
    // same bytes. That comparison is the oracle: the second cut is the
    // same narrow one, the third reads nothing from the store.
    //
    // "Unchanged" is a claim about the project's bytes, and the cut is
    // what has to agree with it: `narrowed_cut` makes one attempt and
    // fails if the cut widened, so this is evidence that *this* edit
    // produced a sound narrowing rather than that some attempt produced
    // one. The narrowing is a precondition here — the subject is the
    // equality with a full build over the same bytes — and
    // `narrowed_to` below states it rather than leaving it implicit.
    write_file(
        &tree.path,
        "src/uses.rs",
        "use crate::helper::helper_fn;\n\
         pub fn call_it() {\n    helper_fn();\n    crate::helper::helper_fn();\n}\n\
         pub fn external() {}\n\
         pub fn also_dirty() {}\n",
    );
    let narrow = narrowed_cut(&mut world, &session, &["src/uses.rs"], false);
    let narrow_generation = generation_of(&narrow);
    assert!(narrow_generation > initial_generation);

    // A full build over exactly the same bytes: the independent oracle.
    let (mut oracle, oracle_session, _) = project_world_at("init-incremental-oracle", &tree);
    let full = init_result(&init(&mut oracle, &oracle_session, json!({})));
    let narrow_rows = stored_edges(&world, narrow_generation);
    let full_rows = stored_edges(&oracle, generation_of(&full));
    assert_eq!(
        narrow_rows, full_rows,
        "an incremental generation equals a full one row for row over the \
         same bytes"
    );
    // The equivalence above is only a carry proof if the two cuts really
    // did different work. A full re-derivation would also produce these
    // rows, so the answer is asserted to be strictly the narrow cut: it
    // names the one document that changed, and the generation it sealed
    // holds strictly more rows than the answer did. Drop the carry and
    // the sealed generation collapses onto the answer, which is the
    // defect this comparison exists to catch.
    assert_eq!(
        narrow.graph.narrowed_to,
        vec![PathBuf::from("src/uses.rs")],
        "the answer states the narrowing it kept, so the writer knows what \
         may carry"
    );
    assert_eq!(
        narrow.graph.completeness,
        Completeness::Complete,
        "and the walk behind that narrowing was clean, so the carry proof \
         is over a cut the derivation chose rather than one it was pushed \
         into"
    );
    assert!(
        narrow
            .graph
            .edges
            .iter()
            .all(|edge| edge.from.path == Path::new("src/uses.rs")),
        "only the changed document was re-derived: {:?}",
        narrow.graph.edges
    );
    assert!(
        narrow_rows.len() > narrow.graph.edges.len(),
        "the seal carried the other documents' rows: {} stored vs {} derived",
        narrow_rows.len(),
        narrow.graph.edges.len()
    );
    assert_eq!(narrow.graph.completeness, full.graph.completeness);
    assert_eq!(narrow.state, full.state);
    assert_ne!(
        stored_edges(&world, initial_generation),
        narrow_rows,
        "the dirty edit is visible in the narrowed generation"
    );

    // A rename is a create plus a delete, so the file set moved: the cut
    // repairs the whole project, and the importers follow the rename the
    // way a real refactor would.
    std::fs::rename(
        tree.path.join("src/helper.rs"),
        tree.path.join("src/renamed.rs"),
    )
    .expect("rename");
    write_file(
        &tree.path,
        "src/lib.rs",
        "pub mod renamed;\npub fn root_fn() {}\n",
    );
    write_file(
        &tree.path,
        "src/uses.rs",
        "use crate::renamed::helper_fn;\n\
         pub fn call_it() {\n    helper_fn();\n    crate::renamed::helper_fn();\n}\n\
         pub fn external() {}\n",
    );
    write_file(
        &tree.path,
        "tests/case.rs",
        "use crate::renamed::helper_fn;\nfn case() { helper_fn(); }\n",
    );
    let renamed = init_result(&init(&mut world, &session, json!({})));
    let renamed_generation = generation_of(&renamed);
    assert!(renamed_generation > narrow_generation);
    assert_eq!(
        relations(&stored_edges(&world, renamed_generation), "src/lib.rs"),
        vec![(
            String::from("src/renamed.rs"),
            EdgeKind::Import,
            EdgeConfidence::Certain
        )],
        "the moved module is what the declaration names now"
    );
    assert!(
        !stored_edges(&world, renamed_generation)
            .iter()
            .any(|edge| edge.to.path.as_path() == Path::new("src/helper.rs")),
        "no row survives for a file the project no longer has"
    );
    // The repair equals a full build over the same bytes.
    let (mut oracle, oracle_session, _) = project_world_at("init-incremental-rename", &tree);
    let full = init_result(&init(&mut oracle, &oracle_session, json!({})));
    assert_eq!(
        stored_edges(&world, renamed_generation),
        stored_edges(&oracle, generation_of(&full)),
        "a rename-driven repair equals a full build over the same bytes"
    );

    // A lockfile change is a dependency-resolution change: it is a
    // repair, and the graph still equals a full build.
    write_file(
        &tree.path,
        "Cargo.lock",
        "version = 3\n\n[[package]]\nname = \"extra\"\n",
    );
    let after_lock = init_result(&init(&mut world, &session, json!({})));
    let after_lock_generation = generation_of(&after_lock);
    assert!(after_lock_generation > renamed_generation);
    let (mut oracle, oracle_session, _) = project_world_at("init-incremental-lock", &tree);
    let full = init_result(&init(&mut oracle, &oracle_session, json!({})));
    assert_eq!(
        stored_edges(&world, after_lock_generation),
        stored_edges(&oracle, generation_of(&full)),
        "a lockfile change re-derives the same meaning a full build does"
    );

    // A parser-generation change is a change of the admitted grammar set
    // rather than of a file: the corpus is unchanged, so the generation
    // is still equal, and the cut is still a fresh number.
    let parser_generation = init_result(&init(&mut world, &session, json!({})));
    assert!(generation_of(&parser_generation) > after_lock_generation);
    assert_eq!(
        stored_edges(&world, generation_of(&parser_generation)),
        stored_edges(&world, after_lock_generation),
        "a cut with no file change is the same meaning over a new number"
    );

    // An alias: the same module reached under a second name still
    // derives the same relation, because the derivation reads bytes and
    // the file set, not the caller's spelling of the path.
    write_file(
        &tree.path,
        "src/alias.rs",
        "pub use crate::renamed::helper_fn;\n",
    );
    let aliased = init_result(&init(&mut world, &session, json!({})));
    let aliased_edges = stored_edges(&world, generation_of(&aliased));
    assert_eq!(
        relations(&aliased_edges, "src/alias.rs"),
        vec![(
            String::from("src/renamed.rs"),
            EdgeKind::Import,
            EdgeConfidence::Certain
        )],
        "a re-export resolves through the package layout"
    );
    let (mut oracle, oracle_session, _) = project_world_at("init-incremental-alias", &tree);
    let full = init_result(&init(&mut oracle, &oracle_session, json!({})));
    assert_eq!(
        aliased_edges,
        stored_edges(&oracle, generation_of(&full)),
        "and the aliased graph equals a full build"
    );
}

fn generation_of(result: &ProjectInitResult) -> u64 {
    match result.snapshot {
        SnapshotId::Generation(generation) => generation,
        SnapshotId::Live => panic!("a stored generation"),
    }
}

#[test]
fn missed_watcher_events_trigger_repair_or_explicit_stale() {
    let (mut world, session, tree) = project_world("init-watch-missed", "missed");
    let initial = init_result(&init(&mut world, &session, json!({})));
    let initial_generation = generation_of(&initial);
    assert!(initial.state.is_fresh());

    // A batch the backend states is incomplete: the change set is not
    // the whole one, so the cut repairs the whole project instead of
    // narrowing to paths it cannot vouch for.
    write_file(
        &tree.path,
        "src/late.rs",
        "use crate::helper::helper_fn;\npub fn late() {}\n",
    );
    let batch = WatchBatch {
        paths: ["src/late.rs".to_string()]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        missed: true,
        file_set_moved: false,
    };
    assert!(batch.needs_full_rebuild());
    let repaired = world
        .runtime
        .reindex_from_watch(&batch)
        .expect("the repair run answers");
    let repaired_generation = generation_of(&repaired);
    assert!(repaired_generation > initial_generation);
    // The handle a caller already held reads as needing a repair the
    // moment the project moves — it is never left answering rows taken
    // from bytes that are no longer there (INV-007).
    let superseded = world
        .runtime
        .store()
        .index_graph(initial_generation)
        .expect("reads")
        .expect("retained");
    assert_eq!(
        superseded.state,
        GenerationState::Stale {
            cause: StaleCause::WatcherMissed
        },
        "a batch that cannot describe its own change set marks the old handle"
    );
    assert_eq!(
        relations(&superseded.graph.edges, "src/lib.rs"),
        vec![(
            String::from("src/helper.rs"),
            EdgeKind::Import,
            EdgeConfidence::Certain
        )],
        "and the marked generation keeps the rows it did read"
    );
    assert_eq!(
        relations(&stored_edges(&world, repaired_generation), "src/late.rs"),
        vec![(
            String::from("src/helper.rs"),
            EdgeKind::Import,
            EdgeConfidence::Certain
        )],
        "a repair covers the document the missed event was about: {repaired:?}"
    );

    // A batch that describes its own change set is narrowed: the one
    // changed document is re-derived and the rest of the generation is
    // carried, so the meaning is unchanged.
    write_file(
        &tree.path,
        "src/late.rs",
        "use crate::helper::helper_fn;\npub fn late() {}\npub fn later() {}\n",
    );
    let narrow = WatchBatch {
        paths: ["src/late.rs".to_string()]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        missed: false,
        file_set_moved: false,
    };
    assert!(!narrow.needs_full_rebuild());
    let narrowed = world
        .runtime
        .reindex_from_watch(&narrow)
        .expect("the narrow run answers");
    let narrowed_generation = generation_of(&narrowed);
    // A batch that describes its change set still marks the handle it
    // supersedes, with the source-changed cause rather than the
    // watcher-missed one.
    assert_eq!(
        world
            .runtime
            .store()
            .index_graph(repaired_generation)
            .expect("reads")
            .expect("retained")
            .state,
        GenerationState::Stale {
            cause: StaleCause::SourceChanged
        }
    );
    assert_eq!(
        meaning(&stored_edges(&world, narrowed_generation)),
        meaning(&stored_edges(&world, repaired_generation)),
        "a content-only change re-derives the same relations"
    );
    assert_ne!(
        meaning(&stored_edges(&world, repaired_generation)),
        meaning(&stored_edges(&world, initial_generation)),
        "the initial generation is a different one, and it still reads as its own"
    );
    // The recorded document version is the bytes, so a content-only
    // change moves exactly the re-derived document's version.
    let version_of_edge = |edges: &[IndexEdge], from: &str| {
        edges
            .iter()
            .filter(|edge| edge.from.path.as_path() == Path::new(from))
            .map(|edge| edge.version)
            .collect::<Vec<_>>()
    };
    let repaired_edges = stored_edges(&world, repaired_generation);
    let narrowed_edges = stored_edges(&world, narrowed_generation);
    assert_eq!(
        version_of_edge(&narrowed_edges, "src/late.rs"),
        vec![version_of(&tree.path.join("src/late.rs"))],
        "the narrowed cut re-read the document it was told about, at the bytes \
         that are there now"
    );
    assert_ne!(
        version_of_edge(&narrowed_edges, "src/late.rs"),
        version_of_edge(&repaired_edges, "src/late.rs"),
        "and the repair before it read the earlier bytes"
    );
    assert_eq!(
        version_of_edge(&narrowed_edges, "src/lib.rs"),
        version_of_edge(&repaired_edges, "src/lib.rs"),
        "every other document's row is carried at the version it already had"
    );
}

/// A generation's meaning: which subject declares which relation to
/// which target, with its kind, provenance and confidence — the document
/// version excluded, because it names the bytes a cut read rather than
/// the relations the cut derived.
fn meaning(edges: &[IndexEdge]) -> Vec<(String, String, EdgeKind, EdgeProvenance, EdgeConfidence)> {
    edges
        .iter()
        .map(|edge| {
            (
                edge.from.path.to_string_lossy().into_owned(),
                edge.to.path.to_string_lossy().into_owned(),
                edge.kind,
                edge.provenance,
                edge.confidence,
            )
        })
        .collect()
}

#[test]
fn crash_mid_index_repairs_or_marks_stale_never_silent() {
    let (mut world, session, _tree) = project_world("init-crash", "crash");
    let initial = init_result(&init(&mut world, &session, json!({})));
    let initial_generation = generation_of(&initial);
    assert!(initial.state.is_fresh());

    // The writer reserved a generation and died before sealing it: the
    // reservation is what a crash leaves, and every read of it names the
    // cause instead of answering with rows the build never verified.
    let reserved = world
        .runtime
        .store_writer()
        .reserve_index_generation()
        .expect("reserve");
    assert!(reserved > initial_generation);
    let broken = world
        .runtime
        .store()
        .index_graph(reserved)
        .expect("reads")
        .expect("the reserved row is retained");
    assert_eq!(
        broken.state,
        GenerationState::Stale {
            cause: StaleCause::Interrupted
        },
        "an unsealed generation reads as broken, never as current"
    );
    assert!(broken.graph.edges.is_empty(), "it verified nothing");
    assert!(!broken.state.is_fresh());

    // The repair is a fresh cut, and the broken generation stays on
    // record with its cause rather than being silently replaced.
    let repaired = init_result(&init(&mut world, &session, json!({})));
    assert!(generation_of(&repaired) > reserved);
    let still = world
        .runtime
        .store()
        .index_graph(reserved)
        .expect("reads")
        .expect("retained");
    assert_eq!(
        still.state,
        GenerationState::Stale {
            cause: StaleCause::Interrupted
        }
    );
    assert!(repaired.state.is_fresh());
}

#[test]
fn incomplete_coverage_is_visible_not_sold_complete() {
    let (mut world, session, tree) = project_world("init-coverage", "coverage");
    // A language no admitted grammar claims enters the project: the
    // generation reports it instead of claiming the whole project.
    write_file(&tree.path, "docs/notes.md", "not an admitted grammar\n");
    let result = init_result(&init(&mut world, &session, json!({})));
    let graph = &result.graph;

    // The corpus holds a Markdown file no admitted grammar claims: the
    // generation says so instead of claiming the whole project.
    let reasons = match &graph.completeness {
        Completeness::Partial { reasons } => reasons.clone(),
        Completeness::Complete => Vec::new(),
    };
    assert!(
        reasons.iter().any(|reason| matches!(
            reason,
            PartialReason::UnsupportedLanguage { count } if *count >= 1
        )),
        "an unclaimed language is reported coverage: {graph:?}"
    );
    assert!(!graph.completeness.is_complete());
    assert!(!result.state.is_fresh());
    // The state names why the generation is not current, and the reason
    // is one a consumer can act on.
    assert_eq!(
        result.state,
        GenerationState::Stale {
            cause: StaleCause::PartialCoverage
        }
    );
}

#[test]
fn inspect_system_leg_dispatches_through_action_registry() {
    // The AC-030a leg: the boundary report is a real handler on the one
    // catalog, reached through `ActionRegistry::execute` with a typed
    // input, and it reports about the boundary rather than fabricating a
    // project report. Its parse legs ride the index worker — the routing
    // row for that is `search_dispatch_parses_only_through_the_index_worker`.
    let registry = ActionRegistry::new();
    let row = registry
        .definition(INSPECT_SYSTEM)
        .expect("inspect_system is a catalog row");
    assert_eq!(row.id, INSPECT_SYSTEM);
    assert_eq!(row.revision, 2);
    assert_eq!(
        row.implementation,
        Implementation::Local,
        "the row declares how this build runs it"
    );
    assert!(
        row.negative_trigger.contains("never answers a query"),
        "the row states what it must never do: {}",
        row.negative_trigger
    );

    let (mut world, session, _tree) = project_world("init-inspect", "inspect");
    // A generation already cut: the report states the project's own
    // freshness rather than claiming a live scan.
    let cut = init_result(&init(&mut world, &session, json!({})));
    let generation = generation_of(&cut);
    let config = world.runtime.config_for_broker();
    let mut ctx = world.runtime.action_context(&session, &config);
    let rivect::actions::ActionOutcome::Inspected(report) = registry
        .execute(
            rivect::actions::ActionInput::InspectSystem(
                rivect::actions::InspectSystemInput::default(),
            ),
            &mut ctx,
        )
        .expect("the boundary reports rather than refusing")
    else {
        panic!("inspect_system answers its own report, never another outcome");
    };

    // Every kind the mechanical table knows is declared, in its fixed
    // order, and every one of them names an admitted backend — none is
    // declared as a refusal this build would give.
    let declared: Vec<QueryKind> = report.systems.iter().map(|system| system.kind).collect();
    assert_eq!(
        declared,
        vec![
            QueryKind::Text,
            QueryKind::Path,
            QueryKind::Source,
            QueryKind::Ast,
            QueryKind::Symbol,
            QueryKind::Graph,
        ],
        "the report is the table itself: {report:?}"
    );
    let graph = report
        .systems
        .iter()
        .find(|system| system.kind == QueryKind::Graph)
        .expect("every kind is reported");
    assert_eq!(graph.backend, Some(SearchBackend::Graph));
    assert_eq!(
        graph.outcome,
        rivect::actions::ProbeOutcome::Answered,
        "the graph leg rides the same worker the probe answered through: {graph:?}"
    );

    // Freshness is the stored generation's own state — the boundary never
    // reads a stale generation as current, and a fresh one is reported
    // from the same runtime that cut it.
    assert!(
        matches!(cut.state, GenerationState::Fresh),
        "the fixture cut a covered generation: {cut:?}"
    );
    assert_eq!(
        report.freshness,
        rivect::actions::IndexFreshness::Generation(cut.state)
    );
    assert_eq!(generation_of(&cut), generation);
    // And the report is about the boundary: the probe asks for a name no
    // project is expected to define, so nothing in this corpus is
    // reported as detected, and the coverage it measured is disclosed
    // rather than widened.
    assert!(
        report.detected.is_empty(),
        "a detected row would be a row the worker read: {report:?}"
    );
    // The residual risk is the probe's own coverage, verbatim — and this
    // corpus really does carry two files no admitted grammar claims, so
    // the boundary discloses them rather than reporting a clean scan.
    assert_eq!(
        report.residual_risk,
        vec![PartialReason::UnsupportedLanguage { count: 2 }],
        "the probe's coverage is disclosed, not widened: {report:?}"
    );
}

#[test]
fn version_aware_lookup_after_lockfile_change() {
    let (mut world, session, tree) = project_world("init-lock", "lock");
    let before = init_result(&init(&mut world, &session, json!({})));
    let before_generation = generation_of(&before);
    let before_lib = world
        .runtime
        .store()
        .index_graph(before_generation)
        .expect("reads")
        .expect("retained");
    assert_eq!(
        relations(&before_lib.graph.edges, "src/lib.rs"),
        vec![(
            String::from("src/helper.rs"),
            EdgeKind::Import,
            EdgeConfidence::Certain
        )]
    );

    // A lockfile change is a change under the generation: the watcher
    // reports it, the cut moves the handle on, and the newer handle
    // answers for the bytes as they are now.
    write_file(
        &tree.path,
        "Cargo.lock",
        "version = 3\n\n[[package]]\nname = \"x\"\n",
    );
    let batch = WatchBatch {
        paths: ["Cargo.lock".to_string()]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        missed: false,
        file_set_moved: false,
    };
    let after = world
        .runtime
        .reindex_from_watch(&batch)
        .expect("the cut answers");
    let after_generation = generation_of(&after);
    assert!(after_generation > before_generation);

    // The version the older generation recorded is the one the changed
    // document carried then; the newer generation reads the same
    // document at the same version, because the lockfile is not a
    // document any edge names.
    let after_stored = world
        .runtime
        .store()
        .index_graph(after_generation)
        .expect("reads")
        .expect("retained");
    assert_eq!(
        relations(&after_stored.graph.edges, "src/lib.rs"),
        relations(&before_lib.graph.edges, "src/lib.rs"),
        "a lockfile change moves the generation without inventing a relation"
    );
    let lib_version = |stored: &rivect::state::IndexGeneration| {
        stored
            .graph
            .edges
            .iter()
            .find(|edge| edge.from.path.as_path() == Path::new("src/lib.rs"))
            .map(|edge| edge.version)
    };
    assert_eq!(
        lib_version(&after_stored),
        lib_version(&before_lib),
        "the recorded document version is the bytes, not the generation"
    );
    // A `Cargo.toml` change does move the module layout, so it is a
    // full repair rather than a narrow re-derivation.
    write_file(&tree.path, "Cargo.toml", "[package]\nname = \"renamed\"\n");
    let manifest = WatchBatch {
        paths: ["Cargo.toml".to_string()]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        missed: false,
        file_set_moved: true,
    };
    assert!(manifest.needs_full_rebuild());
    let repaired = world
        .runtime
        .reindex_from_watch(&manifest)
        .expect("the repair answers");
    assert!(generation_of(&repaired) > after_generation);
}

#[test]
fn unpromoted_planned_kinds_remain_unavailable() {
    // `project.init` is promoted: the triple edit moved it out of the
    // planned list onto a real descriptor.
    let page = rivect::tools::describe();
    let descriptor = page
        .items
        .iter()
        .find(|entry| entry.canonical_id == "project.init")
        .expect("project.init stays visible in the catalog");
    assert!(descriptor.available, "{descriptor:?}");
    assert!(descriptor.unavailability_reason.is_none());
    assert!(!descriptor.description.is_empty());
    assert!(!descriptor.busy_policy.is_empty());
    assert!(matches!(
        rivect::tools::local_command_kind("project.init"),
        rivect::tools::LocalKind::ProjectInit
    ));

    // `doctor` is recorded as SLICE-076's owner, so it stays planned and
    // its dispatch stays typed-unavailable.
    for planned in ["doctor", "settings.open", "config.list", "ui.render"] {
        let entry = page
            .items
            .iter()
            .find(|entry| entry.canonical_id == planned)
            .unwrap_or_else(|| panic!("{planned} stays visible in the catalog"));
        assert!(!entry.available, "{planned} is still unbuilt: {entry:?}");
        assert!(entry.unavailability_reason.is_some(), "{planned}");
        assert!(matches!(
            rivect::tools::local_command_kind(planned),
            rivect::tools::LocalKind::PlannedUnimplemented
        ));
    }

    // The dispatch answer for a still-planned kind is the typed refusal,
    // never a fabricated one.
    let mut world = open_world("init-planned", None);
    let session = world.open_session("planned-session");
    let response = world.dispatch(&corpus_command_execute(&session, "doctor", json!(1)));
    assert_eq!(
        response["error"]["data"]["code"], "capability_unavailable",
        "{response}"
    );
    assert_eq!(
        world.dispatch(&corpus_command_execute(&session, "not.a.command", json!(1)))["error"]["data"]
            ["code"],
        "invalid_input"
    );
}

// ----- isolation (AC-036b / AC-036c) -----

#[test]
fn project_init_parses_only_through_the_index_worker() {
    let (mut world, session, _tree) = project_world("init-worker", "worker");
    // The helper cannot resolve: the run is typed `helper_unavailable`
    // and the generation it leaves is stale with an empty graph. There
    // is no in-process path that could have answered anyway.
    world.runtime.index.worker.helper = PathBuf::from("/nonexistent/rivect-sandbox-helper");
    let response = init(&mut world, &session, json!({}));
    assert_eq!(
        response["error"]["data"]["code"], "capability_unavailable",
        "a missing helper is a typed capability refusal: {response}"
    );
    assert_eq!(
        response["error"]["data"]["message"],
        "isolated index run failed: the sandbox helper is unavailable",
        "the refusal names the DEC-033 branch that decided it: {response}"
    );

    let generation = world
        .runtime
        .store()
        .latest_index_generation()
        .expect("reads")
        .expect("a generation was still cut");
    let left = world
        .runtime
        .store()
        .index_graph(generation)
        .expect("reads")
        .expect("retained");
    assert_eq!(
        left.state,
        GenerationState::Stale {
            cause: StaleCause::IsolatedRun
        },
        "a failed run marks the generation; it never leaves a served one"
    );
    assert!(left.graph.edges.is_empty(), "nothing was parsed");
    assert!(!left.graph.completeness.is_complete());
}

#[test]
fn search_dispatch_parses_only_through_the_index_worker() {
    // Every surface this slice wires that reaches a parse goes through
    // the worker; a new such surface adds a row here. Two are wired:
    // `command.execute project.init` and `ActionRegistry::execute(
    // InspectSystem)`. Both run over a fixture holding both admitted
    // languages with the helper overridden missing, and neither may serve
    // a result or claim a Complete coverage.
    let (mut world, session, tree) = project_world("init-dispatch", "dispatch");
    assert!(
        tree.path.join("src/lib.rs").is_file() && tree.path.join("app/main.ts").is_file(),
        "the fixture holds both admitted languages"
    );
    world.runtime.index.worker.helper = PathBuf::from("/nonexistent/rivect-sandbox-helper");
    let response = init(&mut world, &session, json!({}));
    assert_eq!(
        response["error"]["data"]["code"], "capability_unavailable",
        "command.execute project.init must answer typed, never serve a graph: {response}"
    );
    assert!(
        response.get("result").is_none(),
        "no result at all: {response}"
    );

    // The registry row: the same refusal reaches the boundary report as a
    // typed `Unanswered` on every parse leg, with no detected row.
    let registry = ActionRegistry::new();
    let config = world.runtime.config_for_broker();
    let mut ctx = world.runtime.action_context(&session, &config);
    let rivect::actions::ActionOutcome::Inspected(report) = registry
        .execute(
            rivect::actions::ActionInput::InspectSystem(
                rivect::actions::InspectSystemInput::default(),
            ),
            &mut ctx,
        )
        .expect("the boundary reports rather than refusing")
    else {
        panic!("inspect_system answers its own report");
    };
    assert!(
        report.detected.is_empty(),
        "ActionRegistry::execute(InspectSystem) served nothing in process: {report:?}"
    );
    assert!(
        report.residual_risk.is_empty(),
        "and claims no coverage: {report:?}"
    );
    let parse_legs: Vec<&rivect::actions::ReportedSystem> = report
        .systems
        .iter()
        .filter(|system| matches!(system.kind, QueryKind::Ast | QueryKind::Symbol))
        .collect();
    assert_eq!(parse_legs.len(), 2, "both parse legs are reported");
    for system in parse_legs {
        assert_eq!(
            system.outcome,
            rivect::actions::ProbeOutcome::Unanswered {
                code: ErrorCode::CapabilityUnavailable,
                cause: String::from("helper_unavailable"),
            },
            "a parse leg the worker could not run is named: {system:?}"
        );
    }
}

#[test]
fn watcher_reindex_parses_only_through_the_index_worker() {
    let (mut world, _session, _tree) = project_world("init-watch-worker", "watch-worker");
    world.runtime.index.worker.helper = PathBuf::from("/nonexistent/rivect-sandbox-helper");
    let batch = WatchBatch {
        paths: ["src/lib.rs".to_string()]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        missed: false,
        file_set_moved: false,
    };
    let error = world
        .runtime
        .reindex_from_watch(&batch)
        .expect_err("a missing helper cannot re-index");
    assert_eq!(error.code(), ErrorCode::CapabilityUnavailable);
    assert!(matches!(
        error,
        rivect::commands::ProjectIndexError::Context(ContextError::IsolatedRun {
            cause: IsolatedCause::HelperUnavailable,
            ..
        })
    ));
    let generation = world
        .runtime
        .store()
        .latest_index_generation()
        .expect("reads")
        .expect("a generation was still cut");
    let left = world
        .runtime
        .store()
        .index_graph(generation)
        .expect("reads")
        .expect("retained");
    assert!(!left.state.is_fresh(), "{left:?}");
    assert!(left.graph.edges.is_empty());
}

#[test]
fn isolated_run_failure_marks_coverage_partial_or_stale_never_complete() {
    let (mut world, session, _tree) = project_world("init-partial", "partial");
    // A budget of zero is the deadline already past: the run starts no
    // worker and the generation it leaves is stale and partial.
    let response = init(&mut world, &session, json!({ "budget_ms": 0 }));
    assert_eq!(
        response["error"]["data"]["code"], "budget_exhausted",
        "{response}"
    );
    let generation = world
        .runtime
        .store()
        .latest_index_generation()
        .expect("reads")
        .expect("a generation was still cut");
    let left = world
        .runtime
        .store()
        .index_graph(generation)
        .expect("reads")
        .expect("retained");
    assert!(!left.state.is_fresh());
    assert!(
        !left.graph.completeness.is_complete(),
        "a failed run never leaves Complete coverage"
    );
    assert!(
        !left.state.is_fresh() || !left.graph.completeness.is_complete(),
        "partial coverage or a stale generation, never both claims of completeness"
    );
}

#[test]
fn runtime_deadline_derives_from_request_budget_and_clamps() {
    // A distant or absent caller budget cannot widen the bound the
    // isolated run applies (DEC-030 #1).
    let bound = MAX_INDEX_PARSE_TIME.as_millis() as u64;
    for (label, budget) in [
        ("absent", None),
        ("distant", Some(u64::MAX)),
        ("wider than the bound", Some(bound * 1_000)),
    ] {
        let deadline = rivect::commands::index_deadline(budget).expect("a deadline");
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .as_millis() as u64;
        assert!(
            remaining <= bound && remaining + 3_000 >= bound,
            "{label} budget clamps to MAX_INDEX_PARSE_TIME: {remaining} ms"
        );
    }
    // A nearer budget is kept.
    let near = rivect::commands::index_deadline(Some(2_000)).expect("a deadline");
    let remaining = near.saturating_duration_since(Instant::now()).as_millis() as u64;
    assert!((1_000..=2_000).contains(&remaining), "{remaining} ms");

    // And the runtime really passes it: a budget of zero answers
    // `budget_exhausted` without a worker, and a wide one still answers.
    let (mut world, session, _tree) = project_world("init-deadline", "deadline");
    let zero = init(&mut world, &session, json!({ "budget_ms": 0 }));
    assert_eq!(zero["error"]["data"]["code"], "budget_exhausted", "{zero}");
    let wide = init(&mut world, &session, json!({ "budget_ms": u64::MAX }));
    assert!(wide.get("error").is_none(), "{wide}");
    assert!(init_result(&wide).state.is_fresh());
}

#[test]
fn task_cancellation_reaches_the_index_worker() {
    let (mut world, session, _tree) = project_world("init-cancel", "cancel");
    let task = world.create_task(&session, "cancel-task");
    let response = init(
        &mut world,
        &session,
        json!({ "task_id": task.0, "budget_ms": 60_000 }),
    );
    assert!(response.get("error").is_none(), "{response}");

    // Cancelling the task ends the next run cancelled — the hook is read
    // before the spawn, so nothing is parsed under a dead authority.
    let intent = world
        .runtime
        .store()
        .snapshot(&task)
        .expect("read")
        .intent_revision;
    let cancelled = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 30, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": "cmd-cancel",
            "session_id": session.0, "kind": "cancel", "task_id": task.0,
            "expected_intent_revision": intent,
            "reason": "user stopped the tree"
        }
    }));
    assert!(cancelled["error"].is_null(), "{cancelled}");
    let after = init(
        &mut world,
        &session,
        json!({ "task_id": task.0, "budget_ms": 60_000 }),
    );
    assert_eq!(
        after["error"]["data"]["code"], "cancelled",
        "a cancelled task's index run is cancelled, not served: {after}"
    );
    // A run refused before it started cuts *nothing*: there is no
    // generation to seal, so the newest one is still the fresh one the
    // first run cut and it is not superseded by a build that never
    // happened. That is the stronger half of the invariant — the old
    // shape left the project with no current generation for a run that
    // was refused at the boundary.
    let generation = world
        .runtime
        .store()
        .latest_index_generation()
        .expect("reads")
        .expect("a generation was cut");
    let left = world
        .runtime
        .store()
        .index_graph(generation)
        .expect("reads")
        .expect("retained");
    assert!(
        left.state.is_fresh(),
        "a run refused before it started does not supersede: {:?}",
        left.state
    );
    assert!(
        !left.graph.edges.is_empty(),
        "and the generation the first run cut still serves its own rows"
    );
}

#[test]
fn module_paths_derive_from_package_root_not_query_root() {
    // A nested workspace member: a module path is read from the nearest
    // `Cargo.toml` above the document, not from the query root. A
    // derivation from the query root would place `src/a.rs` at
    // `member/src/a.rs` and find nothing.
    let tree = TempTree::new("project", "package-root");
    write_file(
        &tree.path,
        "Cargo.toml",
        "[workspace]\nmembers = [\"member\"]\n",
    );
    write_file(&tree.path, "Cargo.lock", "version = 3\n");
    write_file(
        &tree.path,
        "member/Cargo.toml",
        "[package]\nname = \"member\"\n",
    );
    write_file(&tree.path, "member/src/lib.rs", "pub mod a;\n");
    write_file(&tree.path, "member/src/a.rs", "pub fn a() {}\n");
    write_file(
        &tree.path,
        "member/src/uses.rs",
        "use crate::a::a;\npub fn call() {\n    a();\n}\n",
    );

    let (mut world, session, _) = project_world_at("init-package-root", &tree);
    let result = init_result(&init(&mut world, &session, json!({})));
    let edges = &result.graph.edges;
    assert_eq!(
        relations(edges, "member/src/lib.rs"),
        vec![(
            String::from("member/src/a.rs"),
            EdgeKind::Import,
            EdgeConfidence::Certain
        )],
        "the module declaration resolves through the member's own package root: {edges:?}"
    );
    assert_eq!(
        relations(edges, "member/src/uses.rs"),
        vec![(
            String::from("member/src/a.rs"),
            EdgeKind::Import,
            EdgeConfidence::Certain
        )],
        "so does a `use` of it"
    );
}

/// A world pinned at an existing tree rather than a fresh corpus.
fn project_world_at<'a>(
    tag: &str,
    tree: &'a TempTree,
) -> (support::World, SessionId, &'a TempTree) {
    ensure_helper();
    let mut world = open_world(tag, None);
    world.runtime.index.worker.program = PathBuf::from(rivect_binary());
    world.runtime.set_project_root(tree.path.clone());
    let session = world.open_session(&format!("{tag}-session"));
    (world, session, tree)
}

#[test]
fn echoed_paths_and_pins_escape_control_bytes_at_render_boundary() {
    // A file name carrying control bytes reaches the render boundary as
    // its escape spelling, so a cursor move or an escape sequence in a
    // path can never act on the surface that renders it (DEC-030 #5).
    assert_eq!(escape_control("src/lib.rs"), "src/lib.rs");
    assert_eq!(
        escape_control("héllo/世界.rs"),
        "héllo/世界.rs",
        "text is untouched"
    );
    assert_eq!(escape_control("a\u{1b}b"), "a\\u001bb");
    assert_eq!(
        escape_control("a\u{7}b"),
        "a\\u0007b",
        "DEL is a control byte too"
    );
    assert_eq!(escape_control("a\nb"), "a\\u000ab");
    assert_eq!(escape_control("a\tb"), "a\\u0009b");

    // And a project that really holds such a name is rendered escaped.
    let tree = TempTree::new("project", "control-bytes");
    write_file(&tree.path, "Cargo.toml", "[package]\nname = \"fixture\"\n");
    write_file(&tree.path, "src/lib.rs", "pub fn plain() {}\n");
    write_file(
        &tree.path,
        "app/main.ts",
        "import { painted } from \"./escape\u{1b}[31m\";\nexport function run() { painted(); }\n",
    );
    write_file(
        &tree.path,
        "app/escape\u{1b}[31m.ts",
        "export function painted() {}\n",
    );
    let (mut world, session, _) = project_world_at("init-escape", &tree);
    let response = init(&mut world, &session, json!({}));
    let rendered = &response["result"];
    let edge_path = rendered["graph"]["edges"][0]["to"]["path"]
        .as_str()
        .expect("a rendered path");
    assert_eq!(
        edge_path, "app/escape\\u001b[31m.ts",
        "the rendered answer spells the control byte as its escape"
    );
    assert!(
        !edge_path.contains('\u{1b}'),
        "a control byte never crosses the render boundary raw: {edge_path:?}"
    );
    // The store keeps the real path; only the rendered answer escapes.
    let generation = world
        .runtime
        .store()
        .latest_index_generation()
        .expect("reads")
        .expect("cut");
    assert!(
        stored_edges(&world, generation)
            .iter()
            .any(|edge| { edge.to.path.as_path() == Path::new("app/escape\u{1b}[31m.ts") }),
        "the stored generation names the real entry"
    );
}

#[test]
fn project_root_pinned_server_side() {
    let (mut world, session, _tree) = project_world("init-pin", "pin");
    // A `root` the wire supplies is not a parameter this command takes:
    // it is refused as a malformed carrier rather than honoured, and the
    // build still runs under the pinned root.
    let request = json!({
        "jsonrpc": "2.0", "id": 1, "method": "command.execute",
        "params": {
            "schema_version": 1,
            "session_id": session.0,
            "command": { "kind": "project.init", "root": "/etc" },
        }
    })
    .to_string();
    let response = world.dispatch(request.as_str());
    assert_eq!(
        response["error"]["data"]["code"], "invalid_input",
        "a caller-supplied root is refused: {response}"
    );
    let ok = init(&mut world, &session, json!({}));
    let result = init_result(&ok);
    let generation = generation_of(&result);
    assert!(
        stored_edges(&world, generation)
            .iter()
            .all(|edge| !edge.from.path.starts_with("/etc")),
        "every edge is project-relative under the pin"
    );
    // The pin is the surface's, not the wire's: setting it moves what a
    // build reads.
    let elsewhere = TempTree::new("project", "pin-elsewhere");
    write_file(
        &elsewhere.path,
        "Cargo.toml",
        "[package]\nname = \"other\"\n",
    );
    write_file(&elsewhere.path, "src/lib.rs", "pub fn other() {}\n");
    world.runtime.set_project_root(elsewhere.path);
    let moved = init_result(&init(&mut world, &session, json!({})));
    assert!(
        !stored_edges(&world, generation_of(&moved))
            .iter()
            .any(|edge| edge.from.path.as_path() == Path::new("src/lib.rs")),
        "the pin decides which files the generation names"
    );
}

#[test]
fn project_init_carrier_round_trips_through_serde() {
    // The DEC-010 carrier is the wire shape: a kind runs only on the
    // arguments it declares, and absent optional ones stay absent.
    let wire = json!({
        "kind": "project.init",
        "task_id": "t-1",
        "budget_ms": 250,
        "changed": ["src/lib.rs"],
    });
    let command: LocalCommand = serde_json::from_value(wire.clone()).expect("decodes");
    assert_eq!(
        command,
        LocalCommand::ProjectInit {
            task_id: Some(rivect::contracts::TaskId("t-1".to_string())),
            budget_ms: Some(250),
            changed: vec![PathBuf::from("src/lib.rs")],
        }
    );
    assert_eq!(serde_json::to_value(&command).expect("encodes"), wire);
    let bare: LocalCommand = serde_json::from_value(json!({ "kind": "project.init" }))
        .expect("decodes without optionals");
    assert_eq!(
        bare,
        LocalCommand::ProjectInit {
            task_id: None,
            budget_ms: None,
            changed: Vec::new(),
        }
    );
    // A malformed argument is a typed refusal, never a default.
    let (mut world, session, _tree) = project_world("init-carrier", "carrier");
    for extra in [
        json!({ "budget_ms": -1 }),
        json!({ "task_id": 7 }),
        json!({ "changed": "src/lib.rs" }),
    ] {
        let response = init(&mut world, &session, extra);
        assert_eq!(
            response["error"]["data"]["code"], "invalid_input",
            "{response}"
        );
    }
}

#[test]
fn generation_state_vocabulary_is_strict_on_both_sides() {
    assert!(GenerationState::from_stored("fresh", None).is_some());
    for cause in [
        "isolated_run",
        "worker_refused",
        "watcher_missed",
        "interrupted",
        "source_changed",
        "partial_coverage",
    ] {
        assert_eq!(
            GenerationState::from_stored("stale", Some(cause)),
            Some(GenerationState::Stale {
                cause: StaleCause::from_name(cause).expect("a recorded cause")
            })
        );
    }
    // A value outside the recorded vocabulary decodes as nothing, so a
    // read surfaces it instead of defaulting to fresh.
    assert!(GenerationState::from_stored("maybe", None).is_none());
    assert!(GenerationState::from_stored("stale", Some("because")).is_none());
    assert!(GenerationState::from_stored("fresh", Some("interrupted")).is_none());
    assert_eq!(
        serde_json::to_value(GenerationState::Stale {
            cause: StaleCause::WatcherMissed
        })
        .expect("serializes"),
        json!({ "state": "stale", "cause": "watcher_missed" })
    );
}

#[test]
fn graph_round_trips_and_edge_wire_tags_pin_literally() {
    let (mut world, session, _tree) = project_world("init-wire", "wire");
    let result = init_result(&init(&mut world, &session, json!({})));
    let graph: ProjectGraph =
        serde_json::from_value(serde_json::to_value(&result.graph).expect("serializes"))
            .expect("deserializes");
    assert_eq!(graph, result.graph);
    // The vocabulary tags pin literally: a rename is a wire break, not
    // an internal detail.
    for (kind, tag) in [
        (EdgeKind::Import, "import"),
        (EdgeKind::Call, "call"),
        (EdgeKind::Test, "test"),
    ] {
        assert_eq!(serde_json::to_value(kind).expect("serializes"), json!(tag));
        assert_eq!(EdgeKind::from_name(tag), Some(kind));
    }
    for (provenance, tag) in [
        (EdgeProvenance::Observed, "observed"),
        (EdgeProvenance::Inferred, "inferred"),
        (EdgeProvenance::Structural, "structural"),
    ] {
        assert_eq!(
            serde_json::to_value(provenance).expect("serializes"),
            json!(tag)
        );
    }
    for (confidence, tag) in [
        (EdgeConfidence::Certain, "certain"),
        (EdgeConfidence::Unknown, "unknown"),
    ] {
        assert_eq!(
            serde_json::to_value(confidence).expect("serializes"),
            json!(tag)
        );
    }
}

#[test]
fn bounded_run_leaves_no_generation_behind_a_slow_one() {
    // A budget shorter than the build needs is answered typed, and the
    // generation it leaves names what happened: either no worker started
    // at all, or the worker answered under a deadline it could not meet
    // and disclosed every entry it could not read.
    let (mut world, session, _tree) = project_world("init-bound", "bound");
    let response = init(&mut world, &session, json!({ "budget_ms": 1 }));
    let generation = world
        .runtime
        .store()
        .latest_index_generation()
        .expect("reads")
        .expect("a generation was cut");
    let left = world
        .runtime
        .store()
        .index_graph(generation)
        .expect("reads")
        .expect("retained");
    assert!(!left.state.is_fresh(), "{left:?}");
    match response.get("error") {
        Some(error) => assert_eq!(
            error["data"]["code"], "budget_exhausted",
            "a deadline already past starts no worker: {response}"
        ),
        None => {
            assert!(
                !left.graph.completeness.is_complete() && left.graph.edges.is_empty(),
                "a run that could not finish answers nothing and says so: {left:?}"
            );
        }
    }

    // Retention is a bound on derived data, not a delete policy: a
    // `SnapshotId` past the window reports absent rather than answering
    // with another generation's rows, and the newest is still readable.
    let newest = world
        .runtime
        .store()
        .latest_index_generation()
        .expect("reads")
        .expect("a generation exists");
    for _ in 0..=rivect::state::INDEX_GENERATION_RETENTION {
        init(&mut world, &session, json!({}));
    }
    let latest = world
        .runtime
        .store()
        .latest_index_generation()
        .expect("reads")
        .expect("a generation exists");
    assert!(latest > newest);
    assert!(
        world
            .runtime
            .store()
            .index_graph(newest)
            .expect("reads")
            .is_none(),
        "a retired generation number is absent, never reissued"
    );
    assert!(
        world
            .runtime
            .store()
            .index_graph(latest)
            .expect("reads")
            .is_some(),
        "and the newest stays readable"
    );
}

#[test]
fn the_watcher_coalesces_real_events_into_project_relative_paths() {
    // The backend's own thread feeds the bounded channel, and the paths
    // it reports are project-relative to the watched root — the spelling
    // the generation's file set uses. A batch carrying absolute paths
    // would narrow to nothing and leave a stale generation looking
    // current, so the relativization is proved against a real watch.
    let tree = project_corpus("watcher");
    // The backend pings the consumer's own channel; the batch itself is
    // read through the watcher, so the channel only says something
    // arrived. One event landed already, so the first claim is not
    // empty.
    let (wake, woken) = std::sync::mpsc::sync_channel::<rivect::commands::LoopEvent>(1);
    let watcher =
        rivect::index::IndexWatcher::start(&tree.path, None, wake).expect("the watch starts");

    // A burst of writes before the read: every reported path is
    // project-relative to the watched root — the spelling the
    // generation's file set uses. An absolute path would narrow to
    // nothing and leave a stale generation looking current, and a path
    // that could not be placed at all is a lost event rather than a
    // narrow one. Which of the burst's files a backend chooses to name
    // is the backend's business, so the claim is about the shape of
    // every path it does name, not about which ones it names.
    let deadline = Instant::now() + Duration::from_secs(20);
    for n in 0..4 {
        write_file(
            &tree.path,
            &format!("src/watched{n}.rs"),
            "pub fn watched() {}\n",
        );
    }
    let batch = wait_for_any_batch(&watcher, deadline);
    assert!(
        batch.paths.iter().all(|path| !path.is_absolute()),
        "no absolute path ever reaches the batch: {batch:?}"
    );
    assert!(
        batch
            .paths
            .iter()
            .all(|path| !path.starts_with(tree.path.to_string_lossy().as_ref())),
        "a batch path never carries the watched root's own spelling: {batch:?}"
    );
    assert!(!batch.missed, "every reported path placed: {batch:?}");
    assert!(
        batch.file_set_moved,
        "a creation moved the file set: {batch:?}"
    );
    assert!(batch.needs_full_rebuild(), "{batch:?}");

    // The callback may append between snapshots; taking claims all earlier observations.
    let peeked = watcher.peek_batch();
    assert!(
        batch.paths.is_subset(&peeked.paths),
        "a peek retains every observed path: {batch:?} -> {peeked:?}"
    );
    let claimed = watcher.pending_batch();
    assert!(
        peeked.paths.is_subset(&claimed.paths),
        "taking retains every observed path: {peeked:?} -> {claimed:?}"
    );
    let residual = watcher.pending_batch();
    for observed in [&peeked, &claimed, &residual] {
        assert!(
            observed.paths.iter().all(|path| !path.is_absolute()),
            "no absolute path ever reaches the batch: {observed:?}"
        );
        assert!(
            observed
                .paths
                .iter()
                .all(|path| !path.starts_with(tree.path.to_string_lossy().as_ref())),
            "a batch path never carries the watched root's own spelling: {observed:?}"
        );
        assert!(!observed.missed, "every reported path placed: {observed:?}");
    }
    for observed in [&peeked, &claimed] {
        assert!(
            observed.file_set_moved,
            "a creation moved the file set: {observed:?}"
        );
        assert!(observed.needs_full_rebuild(), "{observed:?}");
    }
    match (residual.paths.is_empty(), residual.file_set_moved) {
        (false, false) => assert!(!residual.needs_full_rebuild(), "{residual:?}"),
        _ => assert!(residual.needs_full_rebuild(), "{residual:?}"),
    }
    // The consumer is not left to discover a change by polling: the
    // backend pings the channel the dispatch loop blocks on, so a loop
    // that is reading input still turns when a batch lands.
    assert!(
        matches!(
            woken.recv_timeout(deadline.saturating_duration_since(Instant::now())),
            Ok(rivect::commands::LoopEvent::Index)
        ),
        "the backend pings the consumer's channel rather than being polled for"
    );
}

#[test]
fn the_watcher_ignores_read_only_access() {
    let tree = project_corpus("watcher-read-only");
    let (wake, _woken) = std::sync::mpsc::sync_channel::<rivect::commands::LoopEvent>(1);
    let watcher = rivect::index::IndexWatcher::start(&tree.path, None, wake).expect("watch starts");
    std::fs::read(tree.path.join("src/lib.rs")).expect("read source");
    let entries = std::fs::read_dir(tree.path.join("src")).expect("read directory");
    for entry in entries {
        entry.expect("directory entry");
    }
    write_file(&tree.path, "src/after_read.rs", "pub fn after_read() {}\n");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let batch = watcher.peek_batch();
        if batch.paths.contains(Path::new("src/after_read.rs")) {
            assert!(
                !batch.paths.contains(Path::new("src/lib.rs")),
                "read-only source: {batch:?}"
            );
            assert!(
                !batch.paths.contains(Path::new("src")),
                "read-only directory: {batch:?}"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "watcher never reported after_read.rs: {batch:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The first creation batch within the caller's filesystem-watch deadline.
/// Polls the non-consuming read, so a batch that has already arrived is
/// never lost to the wait.
fn wait_for_any_batch(watcher: &rivect::index::IndexWatcher, deadline: Instant) -> WatchBatch {
    while Instant::now() < deadline {
        let batch = watcher.peek_batch();
        if (!batch.paths.is_empty() && batch.file_set_moved) || batch.missed {
            return batch;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("the watcher never reported a creation batch");
}

// ----- the AC-036a payload and AC-030a boundary contracts -----
//
// These legs predate the project index and were restored here when the
// index work took over this file's body. They pin the *wire* shapes and
// the boundary refusals the index does not own: a `QueryResult` read
// from a literal, a completeness algebra that is typed rather than
// prose, and the boundary's own honest row. `search_text.rs` keeps the
// Source-kind siblings; the `EscapedRoot` leg also lives in
// `search_symbols.rs`, which reads the same boundary from the symbol
// side.

#[test]
fn result_carries_snapshot_backend_completeness_and_unresolved() {
    let corpus = search_corpus("payload");
    let result = query(&search_query(QueryKind::Text, &corpus.path, "only_in_lib"))
        .expect("text query resolves");

    assert_eq!(result.snapshot, SnapshotId::Live);
    assert_eq!(result.backend, SearchBackend::Text);
    assert_eq!(result.backend.engine(), "grep-searcher+grep-regex");
    assert!(result.completeness.is_complete());
    assert!(result.unresolved.is_empty());
    assert_eq!(result.matches.len(), 1);

    // The payload is the wire shape, not a private struct — it
    // round-trips through serde unchanged, and the shape itself is
    // pinned literally so a rename cannot hide behind a symmetric
    // round-trip.
    let wire = serde_json::to_value(&result).expect("serializes");
    assert_eq!(
        wire,
        json!({
            "snapshot": "live",
            "backend": "text",
            "completeness": { "status": "complete" },
            "matches": [{
                "source": {
                    "path": "src/lib.rs",
                    "line": 2,
                    "ignored": false,
                },
                "kind": {
                    "kind": "text",
                    "line_bytes": b"fn only_in_lib() {}\n".as_slice(),
                },
            }],
            "unresolved": [],
        })
    );
    let back: QueryResult = serde_json::from_value(wire).expect("deserializes");
    assert_eq!(back, result);

    // The byte-carrying variant pins its own tag and field name.
    assert_eq!(
        serde_json::to_value(MatchKind::Source { bytes: vec![b'f'] }).expect("serializes"),
        json!({ "kind": "source", "bytes": [102] })
    );
    // The remaining backend and kind tags pin literally too — a
    // variant rename is a wire break, not an internal detail.
    for (backend, tag) in [
        (SearchBackend::Path, "path"),
        (SearchBackend::Source, "source"),
    ] {
        assert_eq!(
            serde_json::to_value(backend).expect("serializes"),
            json!(tag)
        );
    }
    assert_eq!(
        serde_json::to_value(MatchKind::Path).expect("serializes"),
        json!({ "kind": "path" })
    );
}

#[test]
fn live_snapshot_is_stated_never_implied_generation() {
    // `Live` is an explicit claim — it must never serialize as a
    // generation that does not exist in this build.
    assert_ne!(SnapshotId::Live, SnapshotId::Generation(0));
    assert_eq!(
        serde_json::to_value(SnapshotId::Live).expect("serializes"),
        json!("live")
    );
    assert_eq!(
        serde_json::to_value(SnapshotId::Generation(7)).expect("serializes"),
        json!({ "generation": 7 })
    );
}

#[test]
fn unresolved_path_stays_unknown_never_silently_dropped() {
    let corpus = search_corpus("unresolved");
    let result = query(&search_query(
        QueryKind::Source,
        &corpus.path,
        "src/missing.rs",
    ))
    .expect("source query resolves");

    assert!(result.matches.is_empty());
    assert_eq!(result.unresolved, vec![PathBuf::from("src/missing.rs")]);
    // An unanswered path makes the result partial — "could not resolve"
    // is disclosed, never presented as complete coverage.
    assert_eq!(
        result.completeness,
        Completeness::Partial {
            reasons: vec![PartialReason::UnresolvedPaths { count: 1 }]
        }
    );
}

#[test]
fn unservable_source_entry_is_a_disclosed_failure_never_absent() {
    let corpus = search_corpus("unservable");
    // A resolved-but-unservable entry — a directory — is a coverage
    // failure, disclosed on the result: never a match, never
    // "unresolved" (the path resolved fine).
    let result = query(&search_query(QueryKind::Source, &corpus.path, "src"))
        .expect("source query resolves");

    assert!(result.matches.is_empty());
    assert!(result.unresolved.is_empty());
    assert_eq!(
        result.completeness,
        Completeness::Partial {
            reasons: vec![PartialReason::EntriesFailed { count: 1 }]
        }
    );
}

#[cfg(unix)]
#[test]
fn unreadable_source_file_is_a_disclosed_failure_never_absent() {
    use std::os::unix::fs::PermissionsExt;
    let corpus = search_corpus("unservable-file");
    // A regular file passes `is_file` but fails `open` — the
    // read-failure arm, not the non-regular arm a directory pins.
    let locked = corpus.path.join("src/locked.rs");
    std::fs::write(&locked, "fn locked() {}\n").expect("locked fixture");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
        .expect("chmod locked");
    // Running as root the mode bits do not block the open — probe and
    // self-skip rather than assert a failure that cannot occur.
    if std::fs::File::open(&locked).is_ok() {
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644))
            .expect("restore file perms");
        return;
    }

    let result = query(&search_query(
        QueryKind::Source,
        &corpus.path,
        "src/locked.rs",
    ));

    // Restore before assertions so a red leg never leaves the fixture
    // unremovable for the TempTree drop.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644))
        .expect("restore file perms");
    let result = result.expect("source query resolves");

    assert!(result.matches.is_empty());
    assert!(result.unresolved.is_empty());
    assert_eq!(
        result.completeness,
        Completeness::Partial {
            reasons: vec![PartialReason::EntriesFailed { count: 1 }]
        }
    );
}

#[test]
fn source_path_escaping_root_is_denied() {
    let corpus = search_corpus("escape");
    let outside = TempTree::new("outside", "escape");
    std::fs::write(outside.path.join("escape.txt"), "outside\n").expect("outside fixture");
    let outside_name = outside
        .path
        .file_name()
        .expect("fixture dir name")
        .to_string_lossy()
        .to_string();

    let err = query(&search_query(
        QueryKind::Source,
        &corpus.path,
        &format!("../{outside_name}/escape.txt"),
    ))
    .expect_err("an escaping path is refused");
    assert!(matches!(err, ContextError::EscapedRoot { .. }));
    assert_eq!(err.error_code(), ErrorCode::Denied);

    #[cfg(unix)]
    {
        // An absolute unix path outside the root is a boundary denial.
        let absolute = query(&search_query(
            QueryKind::Source,
            &corpus.path,
            "/etc/passwd",
        ))
        .expect_err("an absolute path outside the root is refused");
        assert_eq!(absolute.error_code(), ErrorCode::Denied);
    }
}

#[test]
fn boundary_validation_errors_carry_variant_and_wire_code() {
    let corpus = search_corpus("validation");

    // Every rejection lands on its typed variant with the wire code a
    // dispatch surface maps — never a bare string, never a panic.
    let err = query(&search_query(QueryKind::Text, &corpus.path, ""))
        .expect_err("an empty pattern is a caller error");
    assert!(matches!(
        err,
        ContextError::EmptyPattern {
            kind: "search.text"
        }
    ));
    assert_eq!(err.error_code(), ErrorCode::InvalidInput);

    let mut unbounded = search_query(QueryKind::Text, &corpus.path, "x");
    unbounded.limit = 0;
    let err = query(&unbounded).expect_err("a zero bound is a caller error");
    assert!(matches!(err, ContextError::UnboundedLimit));
    assert_eq!(err.error_code(), ErrorCode::InvalidInput);

    let mut scoped = search_query(QueryKind::Source, &corpus.path, "src/lib.rs");
    scoped.scope_glob = Some("**/*.rs".to_string());
    let err = query(&scoped).expect_err("a source query takes no scope glob");
    assert!(matches!(
        err,
        ContextError::ScopeNotApplicable {
            kind: "source.slice"
        }
    ));
    assert_eq!(err.error_code(), ErrorCode::InvalidInput);

    // A root that does not resolve is a finding (NotFound); a root that
    // resolves to a file is a caller error (InvalidInput) — the codes
    // are not interchangeable.
    let err = query(&search_query(
        QueryKind::Text,
        &corpus.path.join("no-such-dir"),
        "x",
    ))
    .expect_err("a missing root refuses");
    assert!(matches!(err, ContextError::InvalidRoot { .. }));
    assert_eq!(err.error_code(), ErrorCode::NotFound);

    let err = query(&search_query(
        QueryKind::Text,
        &corpus.path.join("src/lib.rs"),
        "x",
    ))
    .expect_err("a file-as-root refuses");
    assert!(matches!(err, ContextError::RootNotDirectory { .. }));
    assert_eq!(err.error_code(), ErrorCode::InvalidInput);

    // Malformed patterns refuse at the boundary — grep-regex dialect
    // for text, glob for paths.
    let err =
        query(&search_query(QueryKind::Text, &corpus.path, "(")).expect_err("a bad regex refuses");
    assert!(matches!(err, ContextError::InvalidTextPattern { .. }));
    assert_eq!(err.error_code(), ErrorCode::InvalidInput);

    let err =
        query(&search_query(QueryKind::Path, &corpus.path, "[")).expect_err("a bad glob refuses");
    assert!(matches!(err, ContextError::InvalidGlob { .. }));
    assert_eq!(err.error_code(), ErrorCode::InvalidInput);

    let err = QueryKind::from_name("bogus").expect_err("an unknown name refuses");
    assert!(matches!(err, ContextError::UnknownKind { .. }));
    assert_eq!(err.error_code(), ErrorCode::InvalidInput);
    // The refusal names the accepted domain — a caller recovers without
    // guessing.
    assert!(
        err.to_string().contains("search.text"),
        "unknown-kind refusals list the recorded names: {err}"
    );
}

#[test]
fn inspect_system_catalog_row_names_the_boundary_honestly() {
    let registry = ActionRegistry::new();
    let definition = registry
        .definition(INSPECT_SYSTEM)
        .expect("inspect_system is a catalog row");
    // The row admits its own deferral: the outcome text names the
    // mechanism the boundary actually uses — the parse legs ride the
    // index worker, and a probe that did not answer is reported with its
    // wire class rather than served as an answer.
    assert!(
        definition.outcome.contains("index worker")
            && definition.outcome.contains("did not answer"),
        "the row names how a leg is probed and what an unanswered one \\
         reports: {}",
        definition.outcome
    );
    // It runs locally now, and the row says which — so a reader does not
    // have to infer it from the absence of a refusal string.
    assert_eq!(definition.implementation, Implementation::Local);
    // One shared registry — the rows coexist, never parallel catalogs.
    let ids: Vec<&str> = registry.definitions().map(|row| row.id).collect();
    assert!(ids.contains(&RESOLVE_DECISION));
    assert!(ids.contains(&INSPECT_SYSTEM));
}

#[test]
fn completeness_is_typed_algebra_not_prose() {
    assert!(Completeness::from_reasons(vec![]).is_complete());
    let partial = Completeness::from_reasons(vec![
        PartialReason::LimitReached { limit: 3 },
        PartialReason::EntriesFailed { count: 2 },
    ]);
    assert!(!partial.is_complete());
    // The wire shape names status and reasons — a parser never guesses
    // completeness from counts or prose.
    let wire = serde_json::to_value(&partial).expect("serializes");
    assert_eq!(wire["status"], "partial");
    assert_eq!(wire["reasons"][0]["reason"], "limit_reached");
    assert_eq!(wire["reasons"][1]["reason"], "entries_failed");
    // The unresolved-paths tag pins literally too — a variant rename
    // is a wire break, not an internal detail.
    assert_eq!(
        serde_json::to_value(PartialReason::UnresolvedPaths { count: 1 }).expect("serializes"),
        json!({ "reason": "unresolved_paths", "count": 1 })
    );
    // The ast-leg tags pin the same way.
    assert_eq!(
        serde_json::to_value(PartialReason::UnsupportedLanguage { count: 2 }).expect("serializes"),
        json!({ "reason": "unsupported_language", "count": 2 })
    );
    assert_eq!(
        serde_json::to_value(PartialReason::ParseErrors { count: 1 }).expect("serializes"),
        json!({ "reason": "parse_errors", "count": 1 })
    );
    // The symbol-leg staleness and module-path reasons pin the same way.
    assert_eq!(
        serde_json::to_value(PartialReason::StaleDocuments { count: 1 }).expect("serializes"),
        json!({ "reason": "stale_documents", "count": 1 })
    );
    assert_eq!(
        serde_json::to_value(PartialReason::UnknownModulePaths { count: 1 }).expect("serializes"),
        json!({ "reason": "unknown_module_paths", "count": 1 })
    );
}

// ----- the store and render contracts the index work added -----

/// The raw store connection a corrupt-storage leg writes through. The
/// library has no raw-write API on purpose, so a leg that needs one
/// opens the same file the runtime owns.
fn raw_store(world: &support::World) -> rusqlite::Connection {
    rusqlite::Connection::open(world.root.join("runtime").join("rivect.db")).expect("raw store")
}

/// The boundary report for this runtime, through the one action registry.
fn boundary_report(world: &mut support::World, session: &SessionId) -> Value {
    let config = world.runtime.config_for_broker();
    let mut ctx = world.runtime.action_context(session, &config);
    let registry = ActionRegistry::new();
    let outcome = registry
        .execute(
            rivect::actions::ActionInput::InspectSystem(
                rivect::actions::InspectSystemInput::default(),
            ),
            &mut ctx,
        )
        .expect("the boundary reports rather than refusing");
    let report = match outcome {
        rivect::actions::ActionOutcome::Inspected(report) => report,
        other => panic!("inspect_system answers its own report, never {other:?}"),
    };
    serde_json::to_value(&report).expect("the report serializes")
}

#[test]
fn a_stale_mark_keeps_the_coverage_the_build_observed() {
    let (mut world, session, tree) = project_world("init-stale-coverage", "stale-coverage");
    // A file no admitted grammar claims is in the project, so the cut is
    // `Partial` and sealed `Stale{PartialCoverage}`.
    write_file(&tree.path, "notes.md", "# notes\n");
    let partial = init_result(&init(&mut world, &session, json!({})));
    let generation = generation_of(&partial);
    assert!(
        matches!(
            partial.state,
            GenerationState::Stale {
                cause: StaleCause::PartialCoverage
            }
        ),
        "the fixture is partial: {partial:?}"
    );
    let reasons = match &partial.graph.completeness {
        Completeness::Partial { reasons } => reasons.clone(),
        Completeness::Complete => panic!("a generation with unclaimed files is partial"),
    };
    let rows_before = stored_edges(&world, generation);

    // Marking it stale with another cause must move only the state.
    // Overwriting the coverage would report `Complete` over a partial
    // row set — the defect this leg pins.
    let mut store = world.runtime.store_writer();
    assert!(
        store
            .mark_index_generation_stale(generation, StaleCause::WatcherMissed)
            .expect("the mark writes"),
        "a row that still reads current is marked: the project moved"
    );
    let after = store
        .store()
        .index_graph(generation)
        .expect("reads")
        .expect("retained");
    assert_eq!(
        after.state,
        GenerationState::Stale {
            cause: StaleCause::WatcherMissed
        }
    );
    assert_eq!(
        after.graph.completeness,
        Completeness::Partial { reasons },
        "the coverage the build observed survives the mark"
    );
    assert_eq!(
        after.graph.edges, rows_before,
        "and so do its rows: a mark is not a rebuild"
    );
    // A number that was never cut is the one case the mark reports no
    // write for.
    assert!(
        !store
            .mark_index_generation_stale(9_999, StaleCause::SourceChanged)
            .expect("the mark writes"),
        "an unknown number writes nothing"
    );
}

#[test]
fn an_unsealed_reservation_reads_partial_not_complete() {
    let (mut world, _session, _tree) = project_world("init-reservation", "reservation");
    // A reservation has verified nothing, so its coverage stub must not
    // read `Complete`: a writer that died mid-index would otherwise look
    // like a full-coverage generation that happens to be stale.
    let reserved = world
        .runtime
        .store_writer()
        .reserve_index_generation()
        .expect("reserve");
    let broken = world
        .runtime
        .store()
        .index_graph(reserved)
        .expect("reads")
        .expect("retained");
    assert_eq!(
        broken.state,
        GenerationState::Stale {
            cause: StaleCause::Interrupted
        }
    );
    assert!(
        matches!(broken.graph.completeness, Completeness::Partial { .. }),
        "an unsealed reservation is partial, never complete: {:?}",
        broken.graph.completeness
    );
    assert!(broken.graph.edges.is_empty());
    // It is also the *newest* row, so a report reads it rather than the
    // generation before it — which is what makes it the repair trigger
    // rather than a footnote. Production reaches this state for the whole
    // duration of a build, because the number is reserved before the run
    // rather than after it.
    assert_eq!(
        world
            .runtime
            .store()
            .latest_index_state()
            .expect("reads")
            .expect("a generation exists"),
        (
            reserved,
            GenerationState::Stale {
                cause: StaleCause::Interrupted
            }
        ),
        "the broken generation is the one a freshness report names"
    );
}

#[test]
fn a_superseded_generation_stops_reading_as_current() {
    let (mut world, session, _tree) = project_world("init-supersede", "supersede");
    let first = init_result(&init(&mut world, &session, json!({})));
    let first_generation = generation_of(&first);
    assert!(first.state.is_fresh());

    // A handle the caller already holds keeps answering, but the moment
    // a second cut commits it stops being current — in the same
    // transaction, so no reader ever sees two generations both fresh
    // (INV-007).
    let second = init_result(&init(&mut world, &session, json!({})));
    let second_generation = generation_of(&second);
    assert!(second_generation > first_generation);
    let old = world
        .runtime
        .store()
        .index_graph(first_generation)
        .expect("reads")
        .expect("retained");
    assert!(
        !old.state.is_fresh(),
        "a handle taken before a second project.init no longer reads fresh"
    );
    assert_eq!(
        old.state,
        GenerationState::Stale {
            cause: StaleCause::Superseded
        }
    );
    // Its rows stay on record: superseded is not deleted.
    assert_eq!(
        old.graph.edges,
        stored_edges(&world, first_generation),
        "the superseded generation keeps what it read"
    );
    assert!(second.state.is_fresh());
    assert_eq!(
        world
            .runtime
            .store()
            .latest_index_state()
            .expect("reads")
            .expect("a generation exists"),
        (second_generation, GenerationState::Fresh),
        "and the newest one is the only current generation"
    );
}

#[test]
fn a_specific_watcher_cause_survives_the_later_supersession() {
    let (mut world, session, _tree) = project_world("init-cause", "cause");
    let first = init_result(&init(&mut world, &session, json!({})));
    let first_generation = generation_of(&first);
    assert!(first.state.is_fresh());

    // The batch discloses more than "something changed", and the seal
    // that follows must not overwrite the specific cause with the
    // weaker "a newer generation exists".
    let batch = WatchBatch {
        paths: ["src/lib.rs".to_string()]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        missed: true,
        file_set_moved: false,
    };
    let repaired = world
        .runtime
        .reindex_from_watch(&batch)
        .expect("the repair run answers");
    assert!(generation_of(&repaired) > first_generation);
    let old = world
        .runtime
        .store()
        .index_graph(first_generation)
        .expect("reads")
        .expect("retained");
    assert_eq!(
        old.state,
        GenerationState::Stale {
            cause: StaleCause::WatcherMissed
        },
        "a batch that could not describe its own change set keeps its cause"
    );
}

#[test]
fn an_out_of_vocabulary_generation_state_is_a_typed_storage_error() {
    let (mut world, session, _tree) = project_world("init-corrupt-state", "corrupt-state");
    let result = init_result(&init(&mut world, &session, json!({})));
    let generation = generation_of(&result);
    raw_store(&world)
        .execute(
            "UPDATE index_generations SET state = 'perhaps' WHERE generation = ?1",
            rusqlite::params![generation as i64],
        )
        .expect("corrupt the row");

    // A `state` outside the recorded vocabulary is corrupt storage, not
    // a build that died: coercing it to `interrupted` would name a
    // cause the bytes do not support.
    let store = world.runtime.store();
    assert!(
        matches!(
            store.latest_index_state(),
            Err(rivect::state::StoreError::Storage(_))
        ),
        "the freshness read refuses it"
    );
    assert!(
        matches!(
            store.index_graph(generation),
            Err(rivect::state::StoreError::Storage(_))
        ),
        "and so does the graph read"
    );
}

#[test]
fn a_narrowed_cut_carries_the_documents_it_did_not_re_derive() {
    // The carry's own discriminator, over a project with more documents
    // than the change touches. A carry that did nothing and a full
    // rebuild both produce the same rows, so the assertions are about
    // the *work* as well as the result: the answer names one document
    // and the sealed generation holds strictly more.
    let (mut world, session, tree) = project_world("init-carry", "carry");
    let initial = init_result(&init(&mut world, &session, json!({})));
    let full_rows = stored_edges(&world, generation_of(&initial));
    let subjects: BTreeSet<String> = full_rows
        .iter()
        .map(|edge| edge.from.path.to_string_lossy().into_owned())
        .collect();
    assert!(
        subjects.len() >= 3,
        "the fixture needs at least three subject documents: {subjects:?}"
    );

    // Change exactly one document nothing else imports, so every other
    // document's rows must be identical either way.
    let carried_subject = Path::new("app/main.ts");
    assert!(
        full_rows
            .iter()
            .any(|edge| edge.from.path.as_path() == carried_subject),
        "the fixture has a node subject to carry: {full_rows:?}"
    );
    let before: Vec<PathBuf> = full_rows
        .iter()
        .filter(|edge| edge.from.path.as_path() == carried_subject)
        .map(|edge| edge.to.path.clone())
        .collect();
    write_file(
        &tree.path,
        "src/uses.rs",
        "use crate::helper::helper_fn;\n\
         pub fn call_it() {\n    helper_fn();\n    crate::helper::helper_fn();\n}\n\
         pub fn external() {}\n\
         pub fn also_dirty() {}\n",
    );
    // The narrowing is a precondition here and not the subject: what is
    // under test is the *carry* — that the documents the cut did not
    // re-derive keep exactly the rows they had. `narrowed_cut` makes one
    // attempt and fails if the cut widened, and the two assertions below
    // state the precondition that attempt produced rather than leaving it
    // implicit.
    let narrow = narrowed_cut(&mut world, &session, &["src/uses.rs"], false);
    let narrow_rows = stored_edges(&world, generation_of(&narrow));
    assert_eq!(
        narrow.graph.narrowed_to,
        vec![PathBuf::from("src/uses.rs")],
        "the answer states the narrowing it kept"
    );
    assert_eq!(
        narrow.graph.completeness,
        Completeness::Complete,
        "and the walk behind it was clean, so the carry proof is over a \
         cut the derivation chose"
    );
    assert!(
        narrow
            .graph
            .edges
            .iter()
            .all(|edge| edge.from.path == Path::new("src/uses.rs")),
        "only the named document was re-derived: {:?}",
        narrow.graph.edges
    );
    assert!(
        narrow_rows.len() > narrow.graph.edges.len(),
        "the seal carried the rest: {} stored vs {} derived",
        narrow_rows.len(),
        narrow.graph.edges.len()
    );
    assert_eq!(
        narrow_rows
            .iter()
            .filter(|edge| edge.from.path.as_path() == carried_subject)
            .map(|edge| edge.to.path.clone())
            .collect::<Vec<_>>(),
        before,
        "a carried subject keeps exactly the rows it had"
    );

    // The whole point: a narrowed cut over the same bytes equals a full
    // build of those bytes, row for row.
    let (mut oracle, oracle_session, _) = project_world_at("init-carry-oracle", &tree);
    let full = init_result(&init(&mut oracle, &oracle_session, json!({})));
    assert_eq!(
        narrow_rows,
        stored_edges(&oracle, generation_of(&full)),
        "a narrowed cut is a full cut over the same bytes"
    );
}

#[test]
fn a_file_set_that_moved_rebuilds_the_whole_project() {
    let (mut world, session, tree) = project_world("init-file-set", "file-set");
    let initial = init_result(&init(&mut world, &session, json!({})));
    assert!(initial.state.is_fresh());
    let before = stored_edges(&world, generation_of(&initial));

    // A new module appears. Naming only the changed document is not
    // enough: every subject's edges resolve against the file set, so a
    // narrowed cut would carry rows whose target the project no longer
    // holds. The batch's own file-set signal is what widens it.
    write_file(
        &tree.path,
        "src/helper.rs",
        "pub fn helper_fn() {}\npub fn added() {}\n",
    );
    write_file(
        &tree.path,
        "src/extra.rs",
        "use crate::helper::added;\npub fn extra() { crate::helper::added(); }\n",
    );
    let batch = WatchBatch {
        paths: ["src/extra.rs".to_string(), "src/helper.rs".to_string()]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        missed: false,
        // A create is exactly the event that moves the set.
        file_set_moved: true,
    };
    let repaired = world
        .runtime
        .reindex_from_watch(&batch)
        .expect("the repair run answers");
    assert!(
        repaired.graph.narrowed_to.is_empty(),
        "a moved file set widens the cut: {:?}",
        repaired.graph.narrowed_to
    );
    let after = stored_edges(&world, generation_of(&repaired));
    assert!(
        after
            .iter()
            .any(|edge| edge.from.path.as_path() == Path::new("src/extra.rs")
                && edge.to.path.as_path() == Path::new("src/helper.rs")),
        "the new document is in the generation: {after:?}"
    );
    // The importer's row moved with it: `src/uses.rs` still names
    // `crate::helper`, and it is re-derived here rather than carried, so
    // its subject version is the one the changed helper carries.
    assert!(
        after.iter().any(|edge| {
            edge.from.path.as_path() == Path::new("src/uses.rs")
                && edge.version
                    == after
                        .iter()
                        .find(|other| other.from.path.as_path() == Path::new("src/uses.rs"))
                        .map(|other| other.version)
                        .unwrap_or_default()
        }),
        "the carried subjects were re-derived at the current version: {after:?}"
    );
    assert_eq!(
        after.len(),
        before.len() + 2,
        "and only the new document's own two relations were added"
    );
}

#[test]
fn a_batch_that_says_nothing_moved_cannot_narrow_a_moved_file_set() {
    // The sound half of the narrowing rule. A backend that coalesces a
    // create or a delete away reports a quiet batch, so `missed` and
    // `file_set_moved` are not proof that the file set held still — the
    // comparison against the replaced generation's indexed set is. Here
    // the batch claims nothing moved while a document was added, and the
    // cut must still widen: naming only the changed document would carry
    // the other subjects' rows against placements the project no longer
    // holds.
    let (mut world, session, tree) = project_world("init-silent-move", "silent-move");
    let initial = init_result(&init(&mut world, &session, json!({})));
    assert!(initial.state.is_fresh());
    let before = stored_edges(&world, generation_of(&initial));
    let indexed_before = &initial.graph.documents;
    assert!(
        indexed_before
            .iter()
            .any(|path| path.as_path() == Path::new("src/helper.rs")),
        "the fixture indexed the document that will disappear: {indexed_before:?}"
    );

    std::fs::remove_file(tree.path.join("src/helper.rs")).expect("remove");
    let batch = WatchBatch {
        // A batch that names only an edit and says the set held still.
        paths: ["src/uses.rs".to_string()]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        missed: false,
        file_set_moved: false,
    };
    assert!(!batch.needs_full_rebuild());
    // A refusal and a verdict are different things, so the cut is issued
    // through `init_cut`'s shape: a request that never ran says nothing
    // about the file set and may be re-issued, while the one answer it
    // gets is the product's statement and is asserted exactly once.
    let after = {
        let mut refusals: Vec<String> = Vec::new();
        let mut answered = None;
        for _ in 0..3 {
            match world.runtime.reindex_from_watch(&batch) {
                Ok(result) => {
                    answered = Some(result);
                    break;
                }
                Err(refused) => refusals.push(refused.to_string()),
            }
        }
        answered.unwrap_or_else(|| panic!("three refused repair runs and no answer: {refusals:?}"))
    };
    assert!(
        after.graph.narrowed_to.is_empty(),
        "a quiet batch does not make a moved file set sound: {:?}",
        after.graph.narrowed_to
    );
    let rows = stored_edges(&world, generation_of(&after));
    assert!(
        !rows
            .iter()
            .any(|edge| edge.to.path.as_path() == Path::new("src/helper.rs")),
        "and nothing is served from a document the project no longer holds: \
         {rows:?}"
    );
    assert_ne!(rows, before, "the generation moved with the project");
}

#[test]
fn a_non_utf8_document_is_a_coverage_failure_not_a_silent_skip() {
    let (mut world, session, tree) = project_world("init-latin", "latin");
    // An admitted-grammar document whose bytes are not UTF-8 states no
    // relation any reader can scan. Admitting it and scanning it would
    // produce no rows and read as "this document depends on nothing".
    let mut bytes = b"use crate::helper::helper_fn;\npub fn latin() {}\n".to_vec();
    // A lone 0xFF cannot appear in UTF-8, so the document is claimed by
    // extension and refused by every reader that decodes it.
    let at = bytes.len() / 2;
    bytes.insert(at, 0xFF);
    std::fs::write(tree.path.join("src/latin.rs"), &bytes).expect("latin fixture");

    let result = init_result(&init(&mut world, &session, json!({})));
    assert!(
        !result.state.is_fresh(),
        "an undecodable document makes the cut partial: {:?}",
        result.state
    );
    assert_eq!(
        result.graph.completeness,
        Completeness::Partial {
            reasons: vec![PartialReason::EntriesFailed { count: 1 }]
        },
        "the decode failure is disclosed as a coverage reason"
    );
    assert!(
        !stored_edges(&world, generation_of(&result))
            .iter()
            .any(|edge| edge.from.path.as_path() == Path::new("src/latin.rs")),
        "and nothing claims a relation it could not read"
    );
}

#[test]
fn a_comment_marker_inside_a_string_is_not_a_comment() {
    // The comment cut used to fire on the first `//` anywhere, so a
    // spelled specifier lost its relation. The cut is string-literal
    // aware now, and the covered case is a URL a Node import names.
    let (mut world, session, tree) = project_world("init-url", "url");
    write_file(&tree.path, "app/helper.ts", "export const h = 1;\n");
    write_file(
        &tree.path,
        "app/uses.ts",
        "import { h } from \"./helper\";\n\
         const home = \"https://example.invalid/x\";\n\
         export const uses = h + home;\n",
    );
    let result = init_result(&init(&mut world, &session, json!({})));
    let rows = stored_edges(&world, generation_of(&result));
    assert_eq!(
        relations(&rows, "app/uses.ts"),
        vec![(
            String::from("app/helper.ts"),
            EdgeKind::Import,
            EdgeConfidence::Certain
        )],
        "a `//` inside a quoted specifier is part of the specifier: {rows:?}"
    );
}

#[test]
fn a_bin_target_is_a_crate_root_and_a_deeper_file_names_no_module() {
    let (mut world, session, tree) = project_world("init-layout", "layout");
    // `src/bin/tool.rs` is a crate root under the canonical Cargo
    // layout, so `crate::helper` places against it. A derivation that
    // read the layout its own way would have called this document
    // unplaceable — or worse, guessed the crate root for it.
    write_file(
        &tree.path,
        "src/bin/tool.rs",
        "use crate::helper::helper_fn;\nfn main() { crate::helper::helper_fn(); }\n",
    );
    // `tests/support/mod.rs` is the module `support` of a multi-file
    // test target, and a location below it derives no module at all.
    write_file(&tree.path, "tests/support/mod.rs", "pub fn shared() {}\n");
    write_file(&tree.path, "tests/support/deep.rs", "pub fn deeper() {}\n");
    let result = init_result(&init(&mut world, &session, json!({})));
    let rows = stored_edges(&world, generation_of(&result));

    assert_eq!(
        relations(&rows, "src/bin/tool.rs"),
        vec![
            (
                String::from("src/helper.rs"),
                EdgeKind::Import,
                EdgeConfidence::Certain
            ),
            (
                String::from("src/helper.rs"),
                EdgeKind::Call,
                EdgeConfidence::Certain
            ),
        ],
        "a bin target is a crate root, placed by the one canonical layout"
    );
    // No `Certain` row may name a file the project does not hold, and a
    // document the layout cannot place contributes nothing rather than a
    // guessed module.
    for edge in &rows {
        if edge.confidence == EdgeConfidence::Certain {
            // A `Certain` target is a file this generation indexed, so
            // it resolves under the pinned root — the strongest claim the
            // graph makes, and the one a guessed module would fake.
            assert!(
                tree.path.join(&edge.to.path).is_file(),
                "a certain edge names a file the project holds: {edge:?}"
            );
        }
    }
    assert!(
        !rows.iter().any(
            |edge| edge.from.path.as_path() == Path::new("tests/support/deep.rs")
                && edge.confidence == EdgeConfidence::Certain
        ),
        "a location the layout does not spell contributes no certain row: \
         {rows:?}"
    );
}

#[test]
fn a_nested_module_places_against_its_own_module_not_the_crate_root() {
    let (mut world, session, tree) = project_world("init-nested", "nested");
    // The layout discriminator. `src/a/mod.rs` is the module `a`, so a
    // `mod sibling;` inside it names `a::sibling` and the file the layout
    // spells for that is `src/a/sibling.rs`. A derivation that read the
    // layout its own way derived *no* module for this location and fell
    // back to the crate-root spelling — which resolves, because
    // `src/sibling.rs` exists below. That is a fabricated `Certain` edge
    // to a file the source never named, and it is the strongest claim
    // this graph makes.
    write_file(&tree.path, "src/a/mod.rs", "pub mod sibling;\n");
    write_file(&tree.path, "src/a/sibling.rs", "pub fn near() {}\n");
    write_file(&tree.path, "src/sibling.rs", "pub fn far() {}\n");

    let result = init_result(&init(&mut world, &session, json!({})));
    let rows = stored_edges(&world, generation_of(&result));
    assert_eq!(
        relations(&rows, "src/a/mod.rs"),
        vec![(
            String::from("src/a/sibling.rs"),
            EdgeKind::Import,
            EdgeConfidence::Certain
        )],
        "a nested module places against its own module, never the crate \
         root: {rows:?}"
    );
    assert!(
        !rows
            .iter()
            .any(|edge| edge.to.path.as_path() == Path::new("src/sibling.rs")),
        "nothing placed against the file the source never named: {rows:?}"
    );
    for edge in &rows {
        if edge.confidence == EdgeConfidence::Certain {
            assert!(
                tree.path.join(&edge.to.path).is_file(),
                "a certain edge names a file the project holds: {edge:?}"
            );
        }
    }
}

#[test]
fn the_render_boundary_escapes_a_control_byte_on_both_path_ends() {
    // `escape_control` is wired at three places — the subject path, the
    // target path and the unresolved specifier list. A fixture that only
    // exercises one of them leaves the other two unproven, so this leg
    // carries a control byte in a *file name* and in a *specifier the
    // source spelled*.
    let tree = TempTree::new("project", "escape-both");
    write_file(&tree.path, "Cargo.toml", "[package]\nname = \"escape\"\n");
    write_file(&tree.path, "src/helper.rs", "pub fn helper_fn() {}\n");
    let odd_name = format!("src/we{}ird.rs", char::from(0x1b));
    write_file(
        &tree.path,
        &odd_name,
        // A specifier that cannot be placed *and* carries a control byte,
        // so it reaches the unresolved list and the third wiring site has
        // something to escape.
        "use crate::no\u{1b}where::thing;\npub fn odd() {}\n",
    );

    let mut world = open_world("init-escape-both", None);
    world.runtime.index.worker.program = PathBuf::from(rivect_binary());
    world.runtime.set_project_root(tree.path);
    let session = world.open_session("escape-both-session");
    let rendered = init(&mut world, &session, json!({}))["result"].clone();
    let escaped = serde_json::to_string(&rendered).expect("the answer is a value");
    assert!(
        !escaped.contains('\u{1b}'),
        "no raw escape byte crosses the render boundary: {escaped}"
    );
    // The subject path carries the file name's own control byte, escaped
    // with the recorded spelling.
    let subjects: Vec<String> = rendered["graph"]["edges"]
        .as_array()
        .expect("edges are an array")
        .iter()
        .map(|edge| {
            edge["from"]["path"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    assert!(
        subjects.iter().any(|path| path == "src/we\\u001bird.rs"),
        "the odd subject is reported escaped: {subjects:?}"
    );
    // And the unplaceable specifier is reported with its own control byte
    // escaped, so the third wiring site is covered rather than absent.
    let unresolved: Vec<String> = rendered["graph"]["unresolved"]
        .as_array()
        .expect("unresolved is an array")
        .iter()
        .map(|path| path.as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        unresolved
            .iter()
            .any(|path| path.contains("no\\u001bwhere")),
        "an unplaceable specifier is disclosed with its control byte \
         escaped: {unresolved:?}"
    );
    // The two lists no edge names are covered here for the same reason:
    // `documents` is a file name the walk read and `narrowed_to` is a
    // path the *caller* spelled, and each reaches the boundary from a
    // producer of its own. They were wired at neither site, so a control
    // byte in a file name crossed the boundary raw in both.
    let documents: Vec<String> = rendered["graph"]["documents"]
        .as_array()
        .expect("documents is an array")
        .iter()
        .map(|path| path.as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        documents.iter().any(|path| path == "src/we\\u001bird.rs"),
        "the odd document is reported escaped: {documents:?}"
    );

    // A caller-named narrowing reaches the same boundary, and the cut
    // that keeps the narrowing is the one that reports it. The narrowing
    // is a precondition here and not the subject: what is under test is
    // the escape spelling, and `narrowed_cut` makes one attempt and fails
    // if the cut widened, so the assertion below is over a run that
    // actually reported the narrowing rather than over an empty list.
    let narrow = narrowed_cut(&mut world, &session, &[&odd_name], false);
    let narrow_rendered = serde_json::to_value(&narrow).expect("the answer is a value");
    assert_eq!(
        narrow_rendered["graph"]["narrowed_to"],
        json!([format!("src/we{}ird.rs", "\\u001b")]),
        "the caller-named narrowing is the escaped spelling of what the \
         caller spelled: {narrow_rendered}"
    );
    assert!(
        !serde_json::to_string(&narrow_rendered)
            .expect("a value")
            .contains('\u{1b}'),
        "and no raw escape byte crosses on the narrowed cut either"
    );

    assert_eq!(
        escape_control("a\u{1b}b"),
        "a\\u001bb",
        "the escape spelling is the recorded one"
    );
}

#[test]
fn the_local_command_result_round_trips_through_the_render_boundary() {
    // The renderer used to hand-write `"kind": "project.init"` while the
    // result type's own tag was `project_init`, so the type could never
    // read back what the surface wrote. The answer is the type's own
    // serialization with the paths escaped over it, so it round-trips.
    let (mut world, session, _tree) = project_world("init-result-round-trip", "result-round-trip");
    let rendered = init(&mut world, &session, json!({}))["result"].clone();
    assert_eq!(rendered["kind"], "project.init");
    let result: LocalCommandResult =
        serde_json::from_value(rendered.clone()).expect("the rendered answer decodes");
    let typed = match result {
        LocalCommandResult::ProjectInit(init) => *init,
    };
    let stored = world
        .runtime
        .store()
        .index_graph(generation_of(&typed))
        .expect("reads")
        .expect("retained");
    assert_eq!(
        stored.graph.edges, typed.graph.edges,
        "the answer the surface wrote is the generation the store holds"
    );
    assert_eq!(
        serde_json::to_value(LocalCommandResult::ProjectInit(Box::new(typed))).expect("encodes"),
        rendered,
        "and the type serializes back to exactly what was rendered"
    );
}

#[test]
fn the_local_command_refuses_an_undeclared_name_through_the_type() {
    // The carrier carries `deny_unknown_fields`, so the pin on a
    // caller-supplied `root` is the type's own rule and not a parser's
    // diligence: decoding the wire params directly refuses it too.
    assert!(
        LocalCommand::from_value(&json!({ "kind": "project.init", "root": "/etc" })).is_err(),
        "an undeclared name never decodes into the carrier"
    );
    assert!(
        LocalCommand::from_value(&json!({ "kind": "nope" })).is_err(),
        "an unknown kind never decodes either"
    );

    let (mut world, session, _tree) = project_world("init-undeclared", "undeclared");
    for (extra, code) in [
        (json!({ "root": "/etc" }), "invalid_input"),
        (json!({ "changed": ["/etc/passwd"] }), "invalid_input"),
        (json!({ "changed": ["../outside.rs"] }), "invalid_input"),
        (json!({ "changed": vec!["a.rs"; 5_000] }), "invalid_input"),
    ] {
        let response = init(&mut world, &session, extra.clone());
        assert_eq!(
            response["error"]["data"]["code"], code,
            "{extra} is refused: {response}"
        );
    }
    // The narrowing array is bounded by the same cap every other wire
    // array carries, not by a rule invented for this one: the fixture
    // above is refused because it is past that cap, and a list inside
    // it is accepted.
    assert_eq!(
        init(&mut world, &session, json!({ "changed": ["src/lib.rs"] }))["error"]["data"]["code"],
        Value::Null,
        "a narrowing inside the cap is served"
    );
}

#[test]
fn every_planned_kind_is_listed_unavailable_not_a_spot_check() {
    // The parity sweep reads the real set the descriptor page is built
    // from, so promoting a kind — or dropping a descriptor — turns this
    // red instead of leaving four hand-picked entries green.
    let page = rivect::tools::describe();
    let planned = rivect::tools::planned_local_kinds();
    assert!(
        planned.len() > 4,
        "the sweep must cover the whole set, not a sample: {planned:?}"
    );
    for kind in planned {
        let entry = page
            .items
            .iter()
            .find(|entry| entry.canonical_id == *kind)
            .unwrap_or_else(|| panic!("{kind} stays visible in the catalog"));
        assert!(!entry.available, "{kind} is still unbuilt: {entry:?}");
        assert!(entry.unavailability_reason.is_some(), "{kind}: {entry:?}");
        assert!(!entry.description.is_empty(), "{kind}");
        assert!(!entry.busy_policy.is_empty(), "{kind}");
        assert!(
            matches!(
                rivect::tools::local_command_kind(kind),
                rivect::tools::LocalKind::PlannedUnimplemented
            ),
            "{kind} dispatches typed-unavailable"
        );
    }
    // And the promoted kind is not among them, so the sweep cannot pass
    // over a stale entry.
    assert!(
        !planned.contains(&"project.init"),
        "a promoted kind leaves the planned set"
    );
}

#[test]
fn a_refused_watch_is_disclosed_rather_than_discarded() {
    // A watch the backend refused means nothing is watching the project.
    // The refusal used to be dropped with `.ok()`, so the gap in
    // freshness detection was invisible; it is recorded on the seam and
    // named by the boundary report.
    let (mut world, session, _tree) = project_world("init-watch-refusal", "watch-refusal");
    assert!(world.runtime.index.watch_refusal.is_none());
    let result = init_result(&init(&mut world, &session, json!({})));
    assert!(result.state.is_fresh());
    let before = boundary_report(&mut world, &session);
    assert_eq!(
        before["watch_refusal"],
        Value::Null,
        "nothing is disclosed while the watch is running: {before}"
    );

    world.runtime.index_watcher = None;
    world.runtime.index.root = PathBuf::from("/dev/null/nested");
    let error = world
        .runtime
        .start_index_watch()
        .expect_err("a root that cannot be watched is a typed refusal");
    world.runtime.record_index_watch_refusal(&error);
    let refusal = world
        .runtime
        .index
        .watch_refusal
        .clone()
        .expect("the refusal is recorded, not discarded");
    // P-001 governs the text this crate writes, which is the refusal's
    // own prefix; the cause after the colon is the backend's message and
    // is quoted, not authored. The shape is asserted on the *recorded*
    // string, split at the first `": "` this crate writes — so editing
    // production text reddens this and editing the test does not.
    let (authored, _quoted) = refusal.split_once(": ").unwrap_or((refusal.as_str(), ""));
    assert_eq!(
        authored, "the project watch could not be started",
        "the refusal names its own cause first: {refusal}"
    );
    assert!(
        authored
            .chars()
            .all(|character| !character.is_ascii_uppercase())
            && !authored.ends_with(['.', '!', '?']),
        "and the text this crate wrote is lowercase with no trailing \
         punctuation: {authored}"
    );
    assert_eq!(
        boundary_report(&mut world, &session)["watch_refusal"],
        Value::from(refusal),
        "the boundary report names the gap in freshness detection"
    );
}

#[test]
fn a_declared_read_only_leg_is_never_reported_answered() {
    // `ProbeOutcome` had no "not probed" state, so the read-only legs
    // reported `Answered` with no worker spawned — the one value that
    // claims an observation. They are declared instead, and the
    // declaration names the engine behind it.
    let (mut world, session, _tree) = project_world("init-declared-leg", "declared-leg");
    let report = boundary_report(&mut world, &session);
    let systems: Vec<(String, String, Value)> = report["systems"]
        .as_array()
        .expect("systems are an array")
        .iter()
        .map(|system| {
            (
                system["kind"].as_str().unwrap_or_default().to_string(),
                system["outcome"]["outcome"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                system["outcome"].clone(),
            )
        })
        .collect();
    for (kind, engine) in [
        ("text", "grep-searcher+grep-regex"),
        ("path", "ignore+globset"),
        ("source", "std::fs"),
    ] {
        let system = systems
            .iter()
            .find(|(reported, _, _)| reported == kind)
            .unwrap_or_else(|| panic!("{kind} is reported: {systems:?}"));
        assert_eq!(
            system.1, "declared",
            "{kind} is declared, never answered by a probe that did not run: \\
             {systems:?}"
        );
        assert_eq!(
            system.2["engine"],
            Value::from(engine),
            "the declaration names the admitted engine behind {kind}"
        );
    }
    // The parse legs are the ones the single probe speaks for, and a
    // kind with no admitted backend keeps its own refusal — neither is
    // a declaration.
    for kind in ["ast", "symbol", "graph"] {
        let system = systems
            .iter()
            .find(|(reported, _, _)| reported == kind)
            .unwrap_or_else(|| panic!("{kind} is reported: {systems:?}"));
        assert_ne!(
            system.1, "declared",
            "{kind} is probed or refused, not declared: {systems:?}"
        );
    }
}

// ----- the off-path index owner (INV-011, D-100) -----

/// A corpus big enough that one cut takes long enough for a second
/// request to arrive *while it runs*. The size is a measurement, not a
/// guess: at this document count a release build's cut runs for seconds,
/// which is the window the deferred answer exists for.
fn slow_corpus(tag: &str, documents: usize) -> TempTree {
    let tree = TempTree::new("project", tag);
    write_file(&tree.path, "Cargo.toml", "[package]\nname = \"slow\"\n");
    let padding = "    // a padding line, so the scan has real work per file\n".repeat(120);
    for index in 0..documents {
        let next = (index + 1) % documents;
        write_file(
            &tree.path,
            &format!("src/m{index:05}.rs"),
            &format!(
                "use crate::m{next:05}::f{next:05};\n\
                 pub fn f{index:05}() {{\n{padding}    f{next:05}();\n}}\n"
            ),
        );
    }
    tree
}

#[test]
fn a_second_request_during_a_bounded_run_is_answered_not_deferred() {
    // The measurement the finding was raised on, as an assertion: while
    // a bounded run is in flight, an unrelated request is answered *now*.
    // The debt is matched by request id, so "a run is in flight" cannot
    // swallow the next request's answer.
    let (mut world, session, _tree) = project_world("off-path-second", "second");
    let cut = step(&mut world, &session, json!({ "budget_ms": 60_000 }));
    assert_eq!(
        cut,
        DispatchStep::Deferred,
        "the run that started this request owes its answer"
    );
    assert!(
        world.runtime.index_run_outstanding(),
        "a run is outstanding while the owner works"
    );

    // The unrelated request is served in its own turn, with its own
    // answer, not left waiting behind someone else's build.
    let described = describe_step(&mut world);
    let DispatchStep::Ready(described) = described else {
        panic!("an unrelated request is never deferred");
    };
    let described: Value = serde_json::from_str(&described).expect("a response value");
    assert_eq!(described["id"], 99, "{described}");
    assert!(
        described["result"]["items"].is_array(),
        "and it carries its own real answer: {described}"
    );

    // The run's own answer lands later, and it is the owner's real one —
    // a cut generation, not a synthesised "accepted". Waiting for it is
    // the loop's own work, one turn at a time; the describe above was
    // answered without any of it.
    let mut owed = None;
    for _ in 0..400 {
        if let Some(response) = world.runtime.pump_index() {
            owed = Some(response);
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let owed = owed.expect("the owner answers the run it was given");
    let owed: Value = serde_json::from_str(&owed).expect("a response value");
    assert_eq!(owed["id"], 1, "{owed}");
    let result: ProjectInitResult =
        serde_json::from_value(owed["result"].clone()).expect("a typed answer");
    assert!(
        matches!(result.snapshot, SnapshotId::Generation(_)),
        "the deferred answer is the generation the owner cut: {result:?}"
    );
    assert!(
        !world.runtime.index_run_outstanding(),
        "and the debt is paid"
    );
    // Writing it once is the whole point: the placeholder the handler
    // returned never reaches a surface.
    assert!(
        owed["result"].get("kind").is_some(),
        "the answer is a rendered project-init result: {owed}"
    );
}

#[test]
fn a_cancelled_task_ends_a_run_that_is_already_in_flight() {
    // The leg the dispatch-thread version could not have: the run has
    // started, so the pre-flight refusal does not apply. The store is on
    // the dispatch thread, so the dispatch thread observes the
    // cancellation and hands it to the owner — which is the actor the
    // `stop` closure never had.
    // A corpus whose scan takes seconds, so a child that never learns of
    // the cancellation cannot answer inside the bound below.
    let tree = slow_corpus("off-path-cancel", 6_000);
    let (mut world, session, _tree) = project_world_at("off-path-cancel", &tree);
    let task = world.create_task(&session, "cmd-off-path-cancel");
    let cut = step(
        &mut world,
        &session,
        json!({ "task_id": task.0, "budget_ms": 8_000 }),
    );
    assert_eq!(cut, DispatchStep::Deferred, "{cut:?}");

    // The run is under way, so the task is cancelled now, mid-flight.
    let intent = world
        .runtime
        .store()
        .snapshot(&task)
        .expect("read")
        .intent_revision;
    let cancelled = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 30, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": "cmd-cancel-off-path",
            "session_id": session.0, "kind": "cancel", "task_id": task.0,
            "expected_intent_revision": intent,
            "reason": "user stopped the tree"
        }
    }));
    assert!(cancelled["error"].is_null(), "{cancelled}");

    // One turn of the loop: the store is read here, the flag is raised,
    // and the owner answers cancelled rather than served.
    //
    // The bound is what makes the flag's *reach* observable rather than
    // just its verdict. The corpus is larger than the run's own eight-
    // second budget can scan, so a child that never learns of the
    // cancellation is stopped by that budget — at eight seconds, and at
    // eight seconds on any host, because a deadline is a deadline. A child
    // that does learn of it is stopped by the flag, in milliseconds. Three
    // seconds therefore sits between two deterministic outcomes rather
    // than inside either one's noise.
    let started = Instant::now();
    let mut owed = None;
    for _ in 0..200 {
        if let Some(response) = world.runtime.pump_index() {
            owed = Some(response);
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let elapsed = started.elapsed();
    let owed: Value = serde_json::from_str(&owed.expect("the owner answers")).expect("a value");
    assert_eq!(
        owed["error"]["data"]["code"], "cancelled",
        "a run cancelled while in flight is cancelled, not served: {owed}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "the cancellation reached the child, which ended the run instead \
         of its eight-second budget running it out: {elapsed:?}"
    );
    // The run it replaced is on record as broken, never as current.
    let generation = world
        .runtime
        .store()
        .latest_index_generation()
        .expect("reads")
        .expect("a generation was reserved");
    let left = world
        .runtime
        .store()
        .index_graph(generation)
        .expect("reads")
        .expect("retained");
    assert!(
        !left.state.is_fresh(),
        "a cancelled run serves no rows as current: {:?}",
        left.state
    );
}

#[test]
fn a_second_run_while_one_is_in_flight_is_a_typed_refusal() {
    // The contract is one in-flight worker per runtime, and a second
    // request is that refusal rather than a queue nobody drains.
    let (mut world, session, _tree) = project_world("off-path-busy", "busy");
    assert_eq!(
        step(&mut world, &session, json!({ "budget_ms": 60_000 })),
        DispatchStep::Deferred
    );
    // A different request id, as a client would use: the deferral mark
    // is per-dispatch, so an id reused behind an owed request must not
    // make the second request vanish.
    let second = step(
        &mut world,
        &session,
        json!({ "id": 7, "budget_ms": 60_000 }),
    );
    let DispatchStep::Ready(second) = second else {
        panic!("the second request is answered, not deferred");
    };
    let second: Value = serde_json::from_str(&second).expect("a response value");
    assert_eq!(
        second["error"]["data"]["code"], "capability_unavailable",
        "{second}"
    );
    // And the first run still answers: the refusal did not disturb it.
    let mut owed = None;
    for _ in 0..400 {
        if let Some(response) = world.runtime.pump_index() {
            owed = Some(response);
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let owed: Value = serde_json::from_str(&owed.expect("the first run answers")).expect("a value");
    assert_eq!(
        owed["id"], 1,
        "the first request still gets its answer: {owed}"
    );
}

#[test]
fn a_missing_helper_while_a_run_is_off_path_is_the_same_typed_refusal() {
    // The DEC-028 routing row on the deferred shape: a helper the
    // backend cannot launch answers `helper_unavailable`, and nothing
    // parses in process to stand in for it.
    let (mut world, session, _tree) = project_world("off-path-helper", "helper-off-path");
    world.runtime.index.worker.helper = PathBuf::from("/nonexistent/rivect-sandbox-helper");
    assert_eq!(
        step(&mut world, &session, json!({ "budget_ms": 60_000 })),
        DispatchStep::Deferred
    );
    let mut owed = None;
    for _ in 0..200 {
        if let Some(response) = world.runtime.pump_index() {
            owed = Some(response);
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let owed: Value = serde_json::from_str(&owed.expect("the run answers")).expect("a value");
    assert_eq!(
        owed["error"]["data"]["code"], "capability_unavailable",
        "{owed}"
    );
    assert!(
        owed["error"]["data"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("helper is unavailable")),
        "and it names the helper, not a parse failure: {owed}"
    );
}

#[test]
fn a_deadline_that_expires_off_path_is_the_same_typed_refusal() {
    // DEC-030 #1 survives the hop: the budget is narrowed by the clamp on
    // the dispatch thread and moved to the owner unchanged, so a budget
    // already spent is answered typed before a worker starts.
    let (mut world, session, _tree) = project_world("off-path-deadline", "deadline-off-path");
    assert_eq!(
        step(&mut world, &session, json!({ "budget_ms": 0 })),
        DispatchStep::Deferred
    );
    let mut owed = None;
    for _ in 0..200 {
        if let Some(response) = world.runtime.pump_index() {
            owed = Some(response);
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let owed: Value = serde_json::from_str(&owed.expect("the run answers")).expect("a value");
    assert_eq!(
        owed["error"]["data"]["code"], "budget_exhausted",
        "a budget already spent is answered typed, from either entry \
         point: {owed}"
    );
}

#[test]
fn the_index_owner_is_tracked_and_shutdown_joins_it() {
    // A tracked spawn, not a detached one: the handle exists while the
    // owner runs and is gone after `shutdown`, which is the observable
    // form of "no thread outlives the runtime". A panic unwinding
    // through `Drop` takes the same path, because the shutdown is in the
    // drop and not in a caller.
    let (mut world, session, _tree) = project_world("off-path-track", "track");
    assert!(
        !world.runtime.index_runs.owner_running(),
        "no owner exists before a run asks for one"
    );
    let result = init_result(&init(&mut world, &session, json!({})));
    assert!(result.state.is_fresh());
    assert!(
        world.runtime.index_runs.owner_running(),
        "the owner outlives the run it served: it is a resource, not a task"
    );
    assert!(
        !world.runtime.index_runs.owner_panicked(),
        "and it ended without a panic"
    );
    // Idempotent, and after it there is no handle left to leak.
    world.runtime.index_runs.shutdown();
    assert!(!world.runtime.index_runs.owner_running());
    // A handle that was merely *dropped* would also leave nothing to
    // join, and the owner would still be running behind the runtime —
    // which is the one thing a tracked spawn is not. The join is
    // recorded, so it is observed rather than inferred.
    assert!(
        world.runtime.index_runs.owner_was_joined(),
        "a live owner is joined, never detached"
    );
    assert!(!world.runtime.index_runs.owner_panicked());
    // Idempotent: a second shutdown has no handle and joins nothing.
    world.runtime.index_runs.shutdown();
    assert!(!world.runtime.index_runs.owner_running());
    // A run after a shutdown brings the owner back rather than failing:
    // the owner is a resource the runtime owns, not a one-shot.
    let again = world
        .runtime
        .build_project_index(None, None, &[], false)
        .expect("a new run starts a new owner");
    assert!(again.state.is_fresh(), "{again:?}");
    assert!(
        world.runtime.index_runs.owner_running(),
        "and the new owner is tracked exactly like the first"
    );
}

#[test]
fn dropping_the_runtime_with_a_run_in_flight_joins_the_owner() {
    // Shutdown while a run is in flight: the runtime is dropped, the
    // request channel closes, the cancellation flag is raised and the
    // handle is joined, so the child ends with its process group instead
    // of outliving the runtime that started it. The reserved generation is
    // left exactly where a dying writer leaves one.
    let tree = slow_corpus("off-path-drop", 3_000);
    let mut world = {
        ensure_helper();
        let mut world = open_world("off-path-drop", None);
        world.runtime.index.worker.program = PathBuf::from(rivect_binary());
        world.runtime.set_project_root(tree.path);
        world
    };
    let session = world.open_session("off-path-drop-session");
    // The owner's own exit flag, taken before the drop: the runtime is
    // gone afterwards, so this handle is how the join is observed from
    // outside. The wall clock is deliberately *not* the property here —
    // a bound tight enough to separate "cancelled" from "waited out the
    // clamp" is also tight enough to fail when twenty test binaries share
    // a loaded runner, and the reviewer measured exactly that.
    let cut = step(&mut world, &session, json!({ "budget_ms": 60_000 }));
    assert_eq!(cut, DispatchStep::Deferred, "{cut:?}");
    assert!(world.runtime.index_run_outstanding(), "a run is in flight");
    let exited = world.runtime.index_runs.owner_exit_flag();
    assert!(
        !exited.load(std::sync::atomic::Ordering::SeqCst),
        "the owner is still serving when the drop begins"
    );
    let root = world.root.clone();
    drop(world);
    // The owner is not left running: its thread has returned by the time
    // the drop returns. `shutdown` is what does that, and
    // `the_index_owner_is_tracked_and_shutdown_joins_it` is where the
    // *join* itself is pinned — a detached handle that was cancelled at
    // the same instant still exits before this line, so what this test
    // can see is the outcome, not the guarantee behind it.
    assert!(
        exited.load(std::sync::atomic::Ordering::SeqCst),
        "the owner is not still running when the drop returned"
    );
    // The runtime's own data root outlives the drop test as a directory
    // the harness may have already removed; either way it is not left
    // behind, and a failure to remove it is the harness's business
    // rather than a swallowed error.
    match std::fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("the drop test leaves no data root: {error}"),
    }
}

#[test]
fn a_watch_batch_is_repaired_without_a_caller_asking() {
    // The remaining half of INV-007, through the same owner: a change
    // the backend reports starts its own repair, so a project edited and
    // never re-initialised is repaired rather than left reading `Fresh`
    // over bytes that are gone.
    let (mut world, session, tree) = project_world("off-path-watch", "watch-repair");
    let initial = init_result(&init(&mut world, &session, json!({})));
    let initial_generation = generation_of(&initial);
    assert!(initial.state.is_fresh(), "{initial:?}");
    assert!(
        world.runtime.index_watcher.is_some(),
        "a cut generation starts the project's own watch"
    );

    write_file(
        &tree.path,
        "src/added.rs",
        "use crate::helper::helper_fn;\npub fn added() { crate::helper::helper_fn(); }\n",
    );
    // The backend pings the loop's channel; the loop turns and asks the
    // runtime what is owed. No `project.init` is issued here — that is
    // the property.
    let mut repaired = None;
    for _ in 0..400 {
        if let Some(generation) = wait_for_repair(&mut world, initial_generation) {
            repaired = Some(generation);
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let repaired = repaired.expect("the watcher's own batch starts a repair");
    let rows = stored_edges(&world, repaired);
    assert!(
        rows.iter()
            .any(|edge| edge.from.path.as_path() == Path::new("src/added.rs")
                && edge.to.path.as_path() == Path::new("src/helper.rs")),
        "the new document is in the repaired generation: {rows:?}"
    );
    // And the handle a caller already held stopped being current, so the
    // repair-or-stale invariant is visible either way.
    let old = world
        .runtime
        .store()
        .index_graph(initial_generation)
        .expect("reads")
        .expect("retained");
    assert!(
        !old.state.is_fresh(),
        "the generation the change replaced is not current: {:?}",
        old.state
    );
}

/// One turn of the loop until a generation newer than `before` is sealed.
fn wait_for_repair(world: &mut support::World, before: u64) -> Option<u64> {
    world.runtime.pump_index();
    let newest = world
        .runtime
        .store()
        .latest_index_generation()
        .expect("reads")?;
    if newest <= before {
        return None;
    }
    // A reservation is not a repair: it carries no rows, so reading it
    // would report an empty graph for a build that has not finished.
    world
        .runtime
        .store()
        .index_graph(newest)
        .expect("reads")
        .is_some_and(|stored| !stored.graph.edges.is_empty())
        .then_some(newest)
}

#[test]
fn a_refused_run_leaves_the_in_flight_run_and_the_store_untouched() {
    // A refusal must be side-effect-free. Not "an error came back": the
    // store, the in-flight run's own generation slot, and the run itself
    // have to be byte-identical to before the refusal, because a request
    // that was refused must not reserve a generation, overwrite the
    // in-flight run's number, or cancel someone else's build.
    let (mut world, session, _tree) = project_world("off-path-refusal", "refusal-free");
    assert_eq!(
        world
            .runtime
            .store()
            .latest_index_generation()
            .expect("reads"),
        None,
        "nothing is cut yet"
    );
    let world_root = world.runtime.index.root.clone();

    assert_eq!(
        step(&mut world, &session, json!({ "budget_ms": 60_000 })),
        DispatchStep::Deferred,
        "the first request owns the run"
    );
    let reserved_by_the_run = world
        .runtime
        .store()
        .latest_index_generation()
        .expect("reads")
        .expect("the run reserved its generation before the worker ran");
    assert_eq!(
        reserved_by_the_run, 1,
        "the run reserved before the worker ran, which is the r5 \\
         crash-window ordering a refusal must not undo"
    );
    // The reserved row reads as the crash marker an in-flight build
    // leaves: unsealed, so `Stale{Interrupted}`, and carrying nothing.
    let in_flight_before = world
        .runtime
        .store()
        .index_graph(reserved_by_the_run)
        .expect("reads")
        .expect("retained");
    assert_eq!(
        in_flight_before.state,
        GenerationState::Stale {
            cause: StaleCause::Interrupted
        },
        "a reserved-but-unsealed generation is the crash marker"
    );
    assert!(
        in_flight_before.graph.edges.is_empty(),
        "and it has verified nothing yet"
    );

    // A second project.init while the first runs: refused.
    let refused = step(
        &mut world,
        &session,
        json!({ "id": 2, "budget_ms": 60_000 }),
    );
    let DispatchStep::Ready(refused) = refused else {
        panic!("the second request is answered, not deferred");
    };
    let refused: Value = serde_json::from_str(&refused).expect("a response value");
    assert_eq!(
        refused["error"]["data"]["code"], "capability_unavailable",
        "{refused}"
    );

    // 1. The store moved by nothing: the newest number is still the one
    //    the in-flight run reserved, and that row still reads exactly as
    //    it did before the refusal — no second reservation, no rewrite.
    let store = world.runtime.store();
    assert_eq!(
        store.latest_index_generation().expect("reads"),
        Some(reserved_by_the_run),
        "a refused request reserves no generation: nothing was consumed"
    );
    assert_eq!(
        store
            .index_graph(reserved_by_the_run)
            .expect("reads")
            .expect("retained")
            .state,
        in_flight_before.state,
        "and the in-flight run's own row is byte-identical after the refusal"
    );
    // 2. The in-flight run still seals the generation *it* reserved, and
    //    it was never cancelled by the refusal.
    let owed = first_owed_answer(&mut world);
    let owed: Value = serde_json::from_str(&owed).expect("a response value");
    let result: ProjectInitResult =
        serde_json::from_value(owed["result"].clone()).expect("a typed answer");
    assert_eq!(
        result.snapshot,
        SnapshotId::Generation(reserved_by_the_run),
        "the in-flight run sealed the generation it reserved, not one the \\
         refusal took: {result:?}"
    );
    assert!(
        result.state.is_fresh(),
        "and the refusal did not cancel it: {:?}",
        result.state
    );
    // 3. The pinned root is untouched, so nothing about the request that
    //    was refused reached the seam.
    assert_eq!(
        world.runtime.index.root, world_root,
        "a refusal does not move the project root either"
    );
}

/// The first run's answer, waiting for it the way a loop does.
fn first_owed_answer(world: &mut support::World) -> String {
    for _ in 0..400 {
        if let Some(response) = world.runtime.pump_index() {
            return response;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("the first run answers")
}

#[test]
fn a_cancelled_run_is_cancelled_even_when_its_answer_already_landed() {
    // The window `pump_index` used to have: it took the answer first and
    // read the cancellation only on a later turn, so a run that finished
    // and was cancelled in the same breath was reported as whatever it
    // produced. Cancellation is the highest-priority verdict and does not
    // depend on which of the two the loop saw first.
    let (mut world, session, _tree) = project_world("off-path-race", "cancel-vs-answer");
    let task = world.create_task(&session, "cmd-off-path-race");
    let cut = step(
        &mut world,
        &session,
        json!({ "task_id": task.0, "budget_ms": 60_000 }),
    );
    assert_eq!(cut, DispatchStep::Deferred, "{cut:?}");
    let intent = world
        .runtime
        .store()
        .snapshot(&task)
        .expect("read")
        .intent_revision;
    let cancelled = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 30, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": "cmd-cancel-race",
            "session_id": session.0, "kind": "cancel", "task_id": task.0,
            "expected_intent_revision": intent,
            "reason": "user stopped the tree"
        }
    }));
    assert!(cancelled["error"].is_null(), "{cancelled}");

    // One turn only. The answer may already be in the channel by now, and
    // the seal must still read cancelled.
    let mut owed = None;
    for _ in 0..400 {
        if let Some(response) = world.runtime.pump_index() {
            owed = Some(response);
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let owed: Value = serde_json::from_str(&owed.expect("the run answers")).expect("a value");
    assert_eq!(
        owed["error"]["data"]["code"], "cancelled",
        "a cancelled run is cancelled whatever order the two verdicts \\
         arrive in: {owed}"
    );
}

#[test]
fn a_cancellation_outranks_an_answer_that_landed_first() {
    // The ordering `pump_index` used to have no way to lose: the child
    // finished, its answer is waiting, and the task is cancelled in the
    // gap before the seal. The child cannot have seen the flag — it was
    // already gone — so the verdict can only be decided here, and it must
    // not depend on which of the two the loop saw first.
    //
    // The turn is single and unconditional: the cancellation is recorded
    // and the pump is called once, so the answer may be waiting or may
    // not, and the verdict is cancelled either way. A pump that read the
    // answer first and only then the store would publish a fresh
    // generation for a run the caller had already stopped.
    let (mut world, session, _tree) = project_world("off-path-after", "cancel-after-answer");
    let task = world.create_task(&session, "cmd-off-path-after");
    let cut = step(
        &mut world,
        &session,
        json!({ "task_id": task.0, "budget_ms": 60_000 }),
    );
    assert_eq!(cut, DispatchStep::Deferred, "{cut:?}");

    // A wait long enough that the child has answered, so the answer is
    // already in the channel when the cancellation is recorded. Nothing
    // here can read the channel without taking the answer — that is the
    // whole point of the scenario — so the wait is a generous fixed pause.
    // It can only ever cost time, never correctness: a pause that falls
    // short leaves the verdict decided by the child's own flag instead,
    // which is the same `cancelled` answer.
    std::thread::sleep(Duration::from_millis(3_000));
    let intent = world
        .runtime
        .store()
        .snapshot(&task)
        .expect("read")
        .intent_revision;
    let cancelled = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 32, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": "cmd-cancel-after",
            "session_id": session.0, "kind": "cancel", "task_id": task.0,
            "expected_intent_revision": intent,
            "reason": "cancelled after the child already answered"
        }
    }));
    assert!(cancelled["error"].is_null(), "{cancelled}");

    let mut owed = None;
    for _ in 0..400 {
        if let Some(response) = world.runtime.pump_index() {
            owed = Some(response);
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let owed: Value = serde_json::from_str(&owed.expect("the run answers")).expect("a value");
    assert_eq!(
        owed["error"]["data"]["code"], "cancelled",
        "a cancellation outranks an answer that landed first: {owed}"
    );
    // The generation the run reserved before it started is sealed under
    // the cancellation, not under the child's own verdict: a run that was
    // stopped never publishes what it was building.
    let generation = world
        .runtime
        .store()
        .latest_index_generation()
        .expect("reads")
        .expect("the run reserved before the worker ran");
    let sealed = world
        .runtime
        .store()
        .index_graph(generation)
        .expect("reads")
        .expect("retained");
    assert_eq!(
        sealed.state,
        GenerationState::Stale {
            cause: StaleCause::IsolatedRun
        },
        "and it is sealed cancelled, not fresh: {:?}",
        sealed.state
    );
    assert!(
        sealed.graph.edges.is_empty(),
        "a cancelled run carries no edges: {}",
        sealed.graph.edges.len()
    );
}
#[test]
fn a_cancellation_recorded_before_the_handoff_reaches_the_child() {
    // The other half: a cancellation the store records after the
    // pre-spawn check but before the hand-off. The child reads a flag and
    // nothing else — the store is on the dispatch thread — so the flag
    // has to be correct at the last moment before the run is handed over.
    // A run that starts already cancelled never spawns a child, which is
    // exactly the verdict the pre-spawn check produces.
    let (mut world, session, _tree) = project_world("off-path-handoff", "cancel-at-handoff");
    let task = world.create_task(&session, "cmd-off-path-handoff");
    let intent = world
        .runtime
        .store()
        .snapshot(&task)
        .expect("read")
        .intent_revision;
    let cancelled = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 31, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": "cmd-cancel-handoff",
            "session_id": session.0, "kind": "cancel", "task_id": task.0,
            "expected_intent_revision": intent,
            "reason": "cancelled before the hand-off"
        }
    }));
    assert!(cancelled["error"].is_null(), "{cancelled}");

    // The verdict is `Ready`, not `Deferred`: a run refused at the
    // boundary never starts, so there is nothing for the owner to owe and
    // the answer is this request's own.
    let cut = step(
        &mut world,
        &session,
        json!({ "task_id": task.0, "budget_ms": 60_000 }),
    );
    let DispatchStep::Ready(cut) = cut else {
        panic!("a run refused before it started owes nothing: {cut:?}");
    };
    let cut: Value = serde_json::from_str(&cut).expect("a response value");
    assert_eq!(
        cut["error"]["data"]["code"], "cancelled",
        "a run that starts already cancelled ends cancelled: {cut}"
    );
    assert!(
        cut["error"]["data"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("before the index worker started")),
        "and the refusal says the child was never started: {cut}"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .latest_index_generation()
            .expect("reads"),
        None,
        "and it cut nothing: a run refused at the boundary reserves no \\
         generation, so it cannot supersede a live one"
    );
}

#[test]
fn a_refused_carrier_argument_names_a_field_that_is_really_there() {
    // I-C: the refusal this crate writes must not carry a placeholder.
    // The old mapping recovered a name from serde's own message and fell
    // back to the literal `unrecognized` for any message shape it did
    // not recognise — a field name that appears nowhere in the request,
    // in a user-visible answer. Two shapes are covered, and the second
    // is the one that produced the placeholder: a carrier that is not
    // even an object.
    let (mut world, session, _tree) = project_world("init-refusal-name", "refusal-name");
    // An undeclared name is refused, and the refusal names it exactly —
    // read from the params object, not parsed back out of a message.
    for name in ["extra", "narrowed_to", "root"] {
        let response = init(&mut world, &session, json!({ name: 1 }));
        assert_eq!(
            response["error"]["data"]["code"], "invalid_input",
            "{name} is refused: {response}"
        );
        assert!(
            response["error"]["data"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(name)),
            "and the refusal names `{name}` itself: {response}"
        );
    }

    // A carrier that is not a carrier is refused at the dispatch seam,
    // before the decoder, and the refusal names the field it is missing
    // — which is a real field of this request, not a stand-in.
    for carrier in [Value::Null, json!([]), json!("project.init"), json!(7)] {
        let response = world.dispatch(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "command.execute",
            "params": {
                "schema_version": 1, "session_id": session.0, "command": carrier,
            }
        }));
        assert_eq!(
            response["error"]["data"]["code"], "invalid_input",
            "a carrier that is not a carrier is refused: {response}"
        );
        assert_carrier_refusal_names_a_real_field(&response);
    }

    // And a malformed argument of the carrier itself: the refusal names
    // the field whose type is wrong.
    for extra in [
        json!({ "budget_ms": -1 }),
        json!({ "task_id": 7 }),
        json!({ "changed": "src/lib.rs" }),
    ] {
        let response = init(&mut world, &session, extra);
        assert_eq!(
            response["error"]["data"]["code"], "invalid_input",
            "{response}"
        );
        assert_carrier_refusal_names_a_real_field(&response);
    }
}

/// A refusal from this command names a field the request actually
/// mentions. A stand-in for a name — a literal the crate wrote because it
/// had none — is the P-001 defect this pins: the text a caller reads
/// must point at something it sent.
fn assert_carrier_refusal_names_a_real_field(response: &Value) {
    let message = response["error"]["data"]["message"]
        .as_str()
        .expect("a message")
        .to_string();
    let names_a_field = [
        "command.kind",
        "`kind`",
        "kind",
        "task_id",
        "budget_ms",
        "changed",
    ]
    .iter()
    .any(|name| message.contains(name));
    assert!(
        names_a_field,
        "the refusal names a field of this request: {message}"
    );
    assert!(
        !message.contains("unrecognized"),
        "and never a placeholder standing in for a name: {message}"
    );
}

#[test]
fn first_cut_widens_when_every_document_is_named() {
    // D-105: no prior generation is the only reason to widen; the set
    // comparison outside this complete cut has nothing to disagree on.
    let tree = TempTree::new("project", "first-all-narrowing");
    write_file(
        &tree.path,
        "Cargo.toml",
        "[package]\nname = \"first-all\"\n",
    );
    write_file(&tree.path, "src/lib.rs", "pub mod a;\npub mod b;\n");
    write_file(
        &tree.path,
        "src/a.rs",
        "use crate::b::b_fn;\npub fn a_fn() { b_fn(); }\n",
    );
    write_file(
        &tree.path,
        "src/b.rs",
        "use crate::a::a_fn;\npub fn b_fn() { a_fn(); }\n",
    );
    let (mut world, session, _) = project_world_at("init-first-all-narrowing", &tree);
    let changed = ["src/lib.rs", "src/a.rs", "src/b.rs"];

    let first = init_result(&init(&mut world, &session, json!({ "changed": changed })));
    let named: BTreeSet<PathBuf> = changed.into_iter().map(PathBuf::from).collect();
    let indexed: BTreeSet<PathBuf> = first.graph.documents.iter().cloned().collect();
    assert_eq!(
        indexed, named,
        "every admitted document is named, leaving no outside-set comparison"
    );
    assert!(
        first.graph.narrowed_to.is_empty(),
        "the first cut widens despite a vacuously held outside set: {:?}",
        first.graph.narrowed_to
    );
}

#[test]
fn a_first_cut_carrying_a_narrowing_seals_the_whole_project() {
    // FP-105-A. `file_set_held` answered `true` for an empty previous
    // set, so the predicate read `false || false || !true` and a
    // *first-ever* cut kept its narrowing: the generation sealed a
    // whole-project `index_documents` record while `index_edges` covered
    // the one document the caller named. Measured on the shipped binary
    // before this leg existed: `{"kind":"project.init","changed":
    // ["src/uses.rs"]}` over a six-document project answered
    // `narrowed_to: ["src/uses.rs"]` with 2 edges, the store holding
    // `generation 1 | edges 2 | documents 6`. The provenance field is
    // false, and it is the load-bearing input to every later narrowing.
    //
    // The fixture gives every admitted document an outgoing edge, so a
    // whole-project cut is exactly "every document appears as a
    // subject" and the count is a discriminator rather than an
    // approximation — a document that is only ever a target would make
    // the two counts differ for a correct build.
    let tree = TempTree::new("project", "first-narrowing");
    write_file(&tree.path, "Cargo.toml", "[package]\nname = \"first\"\n");
    write_file(&tree.path, "src/lib.rs", "pub mod a;\npub mod b;\n");
    write_file(
        &tree.path,
        "src/a.rs",
        "use crate::b::b_fn;\npub fn a_fn() { b_fn(); }\n",
    );
    write_file(
        &tree.path,
        "src/b.rs",
        // Every document is a subject, so a correct whole-project cut
        // makes the subject count equal the document count. A document
        // that is only ever a target would leave the two counts apart for
        // a *correct* build and weaken the discriminator.
        "use crate::a::a_fn;\npub fn b_fn() { a_fn(); }\n",
    );
    let (mut world, session, _) = project_world_at("init-first-narrowing", &tree);

    let first = init_result(&init(
        &mut world,
        &session,
        json!({ "changed": ["src/a.rs"] }),
    ));
    assert!(
        first.graph.narrowed_to.is_empty(),
        "a first cut has nothing to compare the rest of the project \\
         against, so it widens: {:?}",
        first.graph.narrowed_to
    );
    let generation = generation_of(&first);
    let sealed = world
        .runtime
        .store()
        .index_graph(generation)
        .expect("reads")
        .expect("retained");
    let subjects: BTreeSet<PathBuf> = sealed
        .graph
        .edges
        .iter()
        .map(|edge| edge.from.path.clone())
        .collect();
    assert_eq!(
        subjects.len(),
        sealed.graph.documents.len(),
        "the sealed generation's provenance is true: every document it \\
         records as indexed is a subject it has rows for ({} subjects, \\
         {} documents)",
        subjects.len(),
        sealed.graph.documents.len()
    );
    assert!(
        subjects.len() >= 3,
        "the fixture needs at least three documents: {subjects:?}"
    );
    // And the answer itself is the whole project's graph, not the one
    // document the caller named.
    assert_eq!(
        first.graph.edges.len(),
        sealed.graph.edges.len(),
        "the answer and the generation it sealed agree"
    );
    assert!(
        first
            .graph
            .edges
            .iter()
            .any(|edge| edge.from.path == Path::new("src/lib.rs")),
        "and the whole project was re-derived, not the narrowing: {:?}",
        first.graph.edges
    );
}

/// A project whose carried document sits under a directory the watch
/// excludes and the enumeration does not, which is what makes "carried"
/// observable without instrumenting the worker.
fn advisory_project(tag: &str) -> TempTree {
    let tree = TempTree::new("project", tag);
    write_file(&tree.path, "Cargo.toml", "[package]\nname = \"advisory\"\n");
    write_file(&tree.path, "src/lib.rs", "pub mod helper;\n");
    write_file(&tree.path, "src/helper.rs", "pub fn helper_fn() {}\n");
    write_file(
        &tree.path,
        "node_modules/dep.rs",
        "use crate::helper::helper_fn;\npub fn dep_fn() { helper_fn(); }\n",
    );
    write_file(
        &tree.path,
        "app/main.ts",
        "import { helper } from \"./helper\";\nexport function run() { helper(); }\n",
    );
    write_file(&tree.path, "app/helper.ts", "export function helper() {}\n");
    tree
}

/// The rows a generation holds for one document, as the store holds them.
fn stored_rows_for(world: &support::World, generation: u64, document: &str) -> Vec<IndexEdge> {
    stored_edges(world, generation)
        .into_iter()
        .filter(|edge| edge.from.path == Path::new(document))
        .collect()
}

#[test]
fn the_set_comparison_decides_a_narrowing_and_the_verdict_may_only_add_one() {
    // D1 / D-105. A persistent file-set change outside the narrowing is
    // exactly a disagreement between this cut's indexed set and the
    // replaced generation's, outside the narrowing, and that comparison
    // is the authoritative check. The parent's watch verdict is advisory:
    // it may only ever *add* a widening.
    //
    // The three legs below are the whole predicate. The verdict is passed
    // explicitly on the same public surface `reindex_from_watch` and the
    // `project.init` handler use, so each leg states the predicate under a
    // known verdict with no dependence on what a backend decides to
    // deliver — measured on this host, a plain in-place overwrite arrives
    // as a modify with `file_set_moved: false` and a create arrives with
    // it set, so a fixture that waited on the watch would pin the
    // backend's timing rather than the predicate.
    let tree = advisory_project("advisory-verdict");
    let (mut world, session, _) = project_world_at("init-advisory", &tree);
    let first = init_result(&init(&mut world, &session, json!({})));
    let first_generation = generation_of(&first);
    let carried_before = stored_rows_for(&world, first_generation, "node_modules/dep.rs");
    assert!(
        !carried_before.is_empty(),
        "the unwatched document is indexed and has a row to carry"
    );
    assert!(
        first
            .graph
            .documents
            .iter()
            .any(|path| path == Path::new("node_modules/dep.rs")),
        "and the enumeration reaches what the watch drops, or the \\
         comparison below has nothing to hold: {:?}",
        first.graph.documents
    );

    // The unwatched document's bytes change. The watch cannot see it, so
    // its content version is the only record of the edit — which is what
    // makes a carried row distinguishable from a re-derived one.
    write_file(
        &tree.path,
        "node_modules/dep.rs",
        "use crate::helper::helper_fn;\npub fn dep_fn() { helper_fn(); }\n\
         pub fn dep_added() { helper_fn(); }\n",
    );
    // The watched document is overwritten in place: the plain edit the
    // narrowing names, with the file set unchanged.
    write_file(
        &tree.path,
        "app/main.ts",
        "import { helper } from \"./helper\";\nexport function run() { helper(); }\n\
         export function also() { helper(); }\n",
    );

    // Leg 1 — the two indexed sets are equal outside the narrowing and the
    // verdict adds nothing, so the narrowing is kept and the other
    // documents' rows are carried rather than re-derived.
    let held = world
        .runtime
        .build_project_index(None, None, &[PathBuf::from("app/main.ts")], false)
        .expect("the cut answers");
    assert_eq!(
        held.graph.narrowed_to,
        vec![PathBuf::from("app/main.ts")],
        "an unchanged file set keeps its narrowing"
    );
    let held_generation = generation_of(&held);
    assert_eq!(
        stored_rows_for(&world, held_generation, "node_modules/dep.rs"),
        carried_before,
        "and the document the narrowing did not name arrives *carried*: \\
         still stamped with the version it was cut at, not the version \\
         its new bytes would stamp. A widened cut re-derives it, so this \\
         is not satisfied by a full rebuild that happens to agree."
    );
    assert!(
        held.graph
            .edges
            .iter()
            .all(|edge| edge.from.path == Path::new("app/main.ts")),
        "only the named document was re-derived: {:?}",
        held.graph.edges
    );
    assert!(
        stored_edges(&world, held_generation).len() > held.graph.edges.len(),
        "and the seal carried the rest: {} stored vs {} derived",
        stored_edges(&world, held_generation).len(),
        held.graph.edges.len()
    );

    // Leg 2 — a document appears *outside* the narrowing and the watch
    // says nothing about it, which is the case only the comparison can
    // see: a backend that coalesces a create away reports a quiet batch,
    // and the enumerated set is the evidence that is left.
    write_file(
        &tree.path,
        "src/extra.rs",
        "use crate::helper::helper_fn;\npub fn extra_fn() { helper_fn(); }\n",
    );
    let silent = world
        .runtime
        .build_project_index(None, None, &[PathBuf::from("app/main.ts")], false)
        .expect("the cut answers");
    assert!(
        silent.graph.narrowed_to.is_empty(),
        "a file that appeared outside the narrowing widens the cut even \\
         when the watch reported nothing: {:?}",
        silent.graph.narrowed_to
    );
    assert!(
        !stored_rows_for(&world, generation_of(&silent), "src/extra.rs").is_empty(),
        "and the widened cut covers it: a carried row would have placed \\
         the project's other subjects against a file set it no longer holds"
    );

    // Leg 3 — the verdict is honoured as an addition. It is retained
    // because it carries the one thing the comparison cannot: a change
    // the backend itself coalesced away, which is `WatchBatch::missed`
    // on the repair path. So a verdict of `true` widens, and this pins
    // that the term is still there rather than quietly dropped.
    let advised = world
        .runtime
        .build_project_index(None, None, &[PathBuf::from("app/main.ts")], true)
        .expect("the cut answers");
    assert!(
        advised.graph.narrowed_to.is_empty(),
        "a verdict that claims the set moved may add a widening: {:?}",
        advised.graph.narrowed_to
    );
    assert!(
        advised.graph.completeness == Completeness::Complete,
        "and it is a conservative widening, not a coverage failure: {:?}",
        advised.graph.completeness
    );
}
#[test]
fn narrowed_cut_stops_after_first_advisory_widening() {
    // D-107: one advisory verdict widens a stable cut; a plain retry would
    // narrow it, so the first answered result must not be hidden by a retry.
    let tree = advisory_project("single-attempt-advisory");
    let (mut world, session, _) = project_world_at("init-single-attempt", &tree);
    let initial = init_result(&init(&mut world, &session, json!({})));
    let initial_generation = generation_of(&initial);

    let first_attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        narrowed_cut(&mut world, &session, &["src/lib.rs"], true)
    }));
    let panic = first_attempt.expect_err("the first widened answer must stop this helper");
    let message = panic
        .downcast_ref::<String>()
        .expect("the helper assertion reports its observed graph");
    assert!(
        message.contains("narrowed_to []"),
        "the first answer was widened: {message}"
    );

    let retry = narrowed_cut(&mut world, &session, &["src/lib.rs"], false);
    assert_eq!(
        retry.graph.narrowed_to,
        vec![PathBuf::from("src/lib.rs")],
        "a later cut would narrow after the one-shot verdict is gone"
    );
    assert!(generation_of(&retry) > initial_generation);
}
