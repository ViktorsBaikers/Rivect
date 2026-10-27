//! In-process text/path/source search over the admitted SRC-008 stack
//! (AC-036a leg): ignore/hidden/scope semantics, byte-faithful
//! encodings, mechanical backend dispatch and honest completeness —
//! never an external `rg`/`fd`, never a model in the choice, never a
//! truncated or partially covered answer sold as whole.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions fail loudly with the observed payload (standards §14)"
)]

mod support;

use rivect::actions::{
    ActionInput, ActionOutcome, ActionRegistry, BOUNDARY_PROBE_NAME, INSPECT_SYSTEM,
    Implementation, IndexFreshness, InspectSystemInput, ProbeOutcome,
};
use rivect::context::{ContextError, IgnorePolicy, QueryKind, backend_for, query};
use rivect::contracts::ErrorCode;
use rivect::index::{
    Completeness, MatchKind, PartialReason, SearchBackend, SnapshotId, SymbolRole,
};
use rivect::lsp::SymbolOp;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use support::{
    corpus_command_execute, ensure_helper, open_world, rivect_binary, search_corpus, search_query,
    tree_of,
};

#[test]
fn text_query_respects_ignore_hidden_and_scope_rules() {
    let corpus = search_corpus("ignore-scope");
    let mut request = search_query(QueryKind::Text, &corpus.path, "shared_marker");
    request.scope_glob = Some("**/*.rs".to_string());

    let result = query(&request).expect("text query resolves");

    assert_eq!(result.backend, SearchBackend::Text);
    assert_eq!(result.snapshot, SnapshotId::Live);
    assert_eq!(result.completeness, Completeness::Complete);
    // `shared_marker` exists in five places across the fixture — the
    // ignored build/, the hidden dir, the ignored non-scope secret.txt
    // and the scope-excluded docs/ are all absent; only the scoped-in
    // ordinary file reports.
    let paths: BTreeSet<&Path> = result
        .matches
        .iter()
        .map(|hit| hit.source.path.as_path())
        .collect();
    assert_eq!(paths, BTreeSet::from([Path::new("src/lib.rs")]));
    assert_eq!(result.matches[0].source.line, Some(1));
    assert!(!result.matches[0].source.ignored);
    assert!(result.unresolved.is_empty());
}

#[test]
fn include_ignored_marks_what_rules_would_exclude() {
    let corpus = search_corpus("include-ignored");
    let mut request = search_query(QueryKind::Text, &corpus.path, "shared_marker");
    request.scope_glob = Some("**/*.rs".to_string());
    request.ignore = IgnorePolicy::Include;

    let result = query(&request).expect("include-ignored query resolves");

    let by_path: BTreeMap<&Path, bool> = result
        .matches
        .iter()
        .map(|hit| (hit.source.path.as_path(), hit.source.ignored))
        .collect();
    // The ignored file is present — flagged as what the rules would
    // have dropped — while the ordinary hit stays unflagged.
    assert_eq!(
        by_path.get(Path::new("build/generated.rs")),
        Some(&true),
        "the ignored file appears with its provenance flag"
    );
    assert_eq!(by_path.get(Path::new("src/lib.rs")), Some(&false));
    // Hidden is not an ignore rule: `.hidden/` stays filtered even under
    // include, and the ignored non-scope file stays scope-excluded.
    assert!(!by_path.contains_key(Path::new(".hidden/note.rs")));
    assert!(!by_path.contains_key(Path::new("secret.txt")));
    assert!(!by_path.contains_key(Path::new("docs/notes.md")));
    assert_eq!(result.completeness, Completeness::Complete);
}

#[test]
fn unicode_and_wide_grapheme_content_matches_exactly() {
    let corpus = search_corpus("unicode");
    let file = std::fs::read(corpus.path.join("src/unicode.rs")).expect("fixture bytes");
    let mut lines = file.split(|byte| *byte == b'\n');
    let first = lines.next().expect("line one");
    let second = lines.next().expect("line two");

    for (needle, expected_line, expected_bytes) in [("こんにちは世界", 1, first), ("👩🏽‍💻", 2, second)]
    {
        let request = search_query(QueryKind::Text, &corpus.path, needle);
        let result = query(&request).expect("unicode query resolves");
        assert_eq!(result.matches.len(), 1, "needle {needle}");
        let hit = &result.matches[0];
        assert_eq!(hit.source.path, PathBuf::from("src/unicode.rs"));
        assert_eq!(hit.source.line, Some(expected_line));
        let MatchKind::Text { line_bytes } = &hit.kind else {
            panic!("a text hit carries the matched line bytes");
        };
        // Raw matched line bytes, terminator included — compared against
        // the fixture's own bytes, never a transcoded rendering.
        let mut expected = expected_bytes.to_vec();
        expected.push(b'\n');
        assert_eq!(line_bytes.as_slice(), expected.as_slice());
    }
}

#[test]
fn single_byte_encoding_matches_bytes_not_utf8_text() {
    let corpus = search_corpus("encoding");
    // An ASCII needle matches the single-byte file's ASCII line — the
    // corpus mixes UTF-8 and windows-1251 on purpose.
    let ascii = query(&search_query(
        QueryKind::Text,
        &corpus.path,
        "single_byte_marker",
    ))
    .expect("text query resolves");
    assert_eq!(ascii.matches.len(), 1);
    assert_eq!(ascii.matches[0].source.path, PathBuf::from("src/cp1251.rs"));
    // A UTF-8 needle can never match windows-1251 bytes: the engine is
    // byte-faithful — it does not silently transcode the corpus into
    // something the needle could hit.
    let utf8 =
        query(&search_query(QueryKind::Text, &corpus.path, "Привет")).expect("text query resolves");
    assert!(utf8.matches.is_empty());
    assert_eq!(utf8.completeness, Completeness::Complete);
}

#[test]
fn nul_byte_never_silently_truncates_coverage() {
    let corpus = search_corpus("binary");
    // A NUL earlier in the file must not quietly end the search —
    // binary detection is pinned off, so a hit on the same line still
    // reports with the file's own bytes.
    std::fs::write(
        corpus.path.join("src/binary.rs"),
        b"\x00fn binary_marker() {}\n",
    )
    .expect("binary fixture");

    let result = query(&search_query(
        QueryKind::Text,
        &corpus.path,
        "binary_marker",
    ))
    .expect("text query resolves");

    let hit = result
        .matches
        .iter()
        .find(|hit| hit.source.path == Path::new("src/binary.rs"))
        .expect("a match on a NUL-carrying line still reports");
    assert_eq!(hit.source.line, Some(1));
    let MatchKind::Text { line_bytes } = &hit.kind else {
        panic!("a text hit carries the matched line bytes");
    };
    assert_eq!(line_bytes.as_slice(), b"\x00fn binary_marker() {}\n");
    assert_eq!(result.completeness, Completeness::Complete);
}

#[test]
fn path_query_never_reads_content() {
    let corpus = search_corpus("path");
    let mut expected: Vec<PathBuf> = [
        "src/cp1251.rs",
        "src/lib.rs",
        "src/many.rs",
        "src/unicode.rs",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    #[cfg(unix)]
    {
        // A permission-locked file is still listed: a backend that
        // opened content would fail or drop it, and the path backend
        // has no file-open step at all.
        use std::os::unix::fs::PermissionsExt;
        let locked = corpus.path.join("src/locked.rs");
        std::fs::write(&locked, "fn locked() {}\n").expect("locked fixture");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .expect("chmod locked");
        expected.push(PathBuf::from("src/locked.rs"));
    }
    expected.sort();

    let request = search_query(QueryKind::Path, &corpus.path, "*.rs");
    let result = query(&request).expect("path query resolves");

    assert_eq!(result.backend, SearchBackend::Path);
    // `sort_by_file_path` makes the walk deterministic — hit order is
    // the sorted enumeration itself, not whatever order the walk
    // happened to yield.
    let paths: Vec<PathBuf> = result
        .matches
        .iter()
        .map(|hit| hit.source.path.clone())
        .collect();
    assert_eq!(paths, expected);
    for hit in &result.matches {
        assert_eq!(
            hit.kind,
            MatchKind::Path,
            "a path hit carries identity only — never content bytes"
        );
        assert_eq!(hit.source.line, None);
    }
    assert_eq!(result.completeness, Completeness::Complete);
}

#[test]
fn truncated_result_marks_partial_never_complete() {
    let corpus = search_corpus("truncate");
    let mut request = search_query(QueryKind::Text, &corpus.path, "repeated_marker");
    request.limit = 3;

    let result = query(&request).expect("bounded query resolves");

    assert_eq!(result.matches.len(), 3, "the caller's bound is honored");
    assert_eq!(
        result.completeness,
        Completeness::Partial {
            reasons: vec![PartialReason::LimitReached { limit: 3 }]
        },
        "a bounded answer is typed partial — never complete"
    );
    assert!(!result.completeness.is_complete());
}

#[test]
fn path_query_bound_marks_partial_never_drops_tail_silently() {
    let corpus = search_corpus("path-truncate");
    let mut request = search_query(QueryKind::Path, &corpus.path, "*.rs");
    request.limit = 2;

    let result = query(&request).expect("path query resolves");

    assert_eq!(result.matches.len(), 2, "the caller's bound is honored");
    assert_eq!(
        result.completeness,
        Completeness::Partial {
            reasons: vec![PartialReason::LimitReached { limit: 2 }]
        },
        "matches beyond the bound are a typed partial, not a silent drop"
    );
}

#[test]
fn bare_path_name_promotes_to_anywhere_in_scope() {
    let corpus = search_corpus("bare-name");
    let result =
        query(&search_query(QueryKind::Path, &corpus.path, "lib.rs")).expect("path query resolves");

    // No separator, no metas — the bare name promotes to `**/lib.rs`
    // and finds the file under src/.
    assert_eq!(
        result
            .matches
            .iter()
            .map(|hit| hit.source.path.as_path())
            .collect::<Vec<_>>(),
        vec![Path::new("src/lib.rs")]
    );
    assert_eq!(result.completeness, Completeness::Complete);
}

#[test]
fn path_query_scope_glob_excludes_out_of_scope_paths() {
    let corpus = search_corpus("path-scope");
    let mut request = search_query(QueryKind::Path, &corpus.path, "*.md");
    request.scope_glob = Some("**/*.rs".to_string());

    let result = query(&request).expect("path query resolves");

    // The pattern matches the doc file, but the caller's scope glob
    // restricts candidates to `*.rs` — the hit is excluded, never
    // listed.
    assert!(
        !result
            .matches
            .iter()
            .any(|hit| hit.source.path == Path::new("docs/notes.md"))
    );
    assert!(result.matches.is_empty());
    assert_eq!(result.completeness, Completeness::Complete);
    // Sanity: without the scope restriction the same pattern finds it.
    let unscoped = query(&search_query(QueryKind::Path, &corpus.path, "*.md"))
        .expect("unscoped path query resolves");
    assert!(
        unscoped
            .matches
            .iter()
            .any(|hit| hit.source.path == Path::new("docs/notes.md"))
    );
}

#[test]
fn path_include_flags_what_rules_would_exclude() {
    let corpus = search_corpus("path-include");
    let mut request = search_query(QueryKind::Path, &corpus.path, "*.rs");
    request.ignore = IgnorePolicy::Include;

    let result = query(&request).expect("include path query resolves");

    let by_path: BTreeMap<&Path, bool> = result
        .matches
        .iter()
        .map(|hit| (hit.source.path.as_path(), hit.source.ignored))
        .collect();
    // The ignored file is present — flagged as what the rules would
    // have dropped — while the ordinary hits stay unflagged.
    assert_eq!(
        by_path.get(Path::new("build/generated.rs")),
        Some(&true),
        "the ignored file appears with its provenance flag"
    );
    assert_eq!(by_path.get(Path::new("src/lib.rs")), Some(&false));
    // Hidden is not an ignore rule: `.hidden/` stays filtered even
    // under include.
    assert!(!by_path.contains_key(Path::new(".hidden/note.rs")));
    assert_eq!(result.completeness, Completeness::Complete);
}

#[cfg(unix)]
#[test]
fn unreadable_entry_counts_as_partial_never_dropped() {
    use std::os::unix::fs::PermissionsExt;
    let corpus = search_corpus("entries-failed");
    // A directory the walker cannot read is a real scan failure — the
    // result must disclose it, not quietly shrink the coverage claim.
    let locked = corpus.path.join("docs");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
        .expect("chmod locked dir");
    // Running as root the mode bits do not block the listing — probe
    // and self-skip rather than assert a failure that cannot occur.
    if std::fs::read_dir(&locked).is_ok() {
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755))
            .expect("restore dir perms");
        return;
    }

    let result = query(&search_query(
        QueryKind::Text,
        &corpus.path,
        "shared_marker",
    ));

    // Restore before assertions so a red leg never leaves the fixture
    // unremovable for the TempTree drop.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755))
        .expect("restore dir perms");
    let result = result.expect("text query resolves");

    let Completeness::Partial { ref reasons } = result.completeness else {
        panic!("an unreadable entry is a disclosed partial, never complete");
    };
    assert!(
        reasons.iter().any(|reason| matches!(
            reason,
            PartialReason::EntriesFailed { count } if *count >= 1
        )),
        "the failed directory read is counted: {reasons:?}"
    );
    // Partial coverage is still served — the readable hit reports, the
    // unenumerable dir contributes nothing.
    assert!(
        result
            .matches
            .iter()
            .any(|hit| hit.source.path == Path::new("src/lib.rs"))
    );
    assert!(
        !result
            .matches
            .iter()
            .any(|hit| hit.source.path.starts_with("docs"))
    );
}

#[cfg(unix)]
#[test]
fn unopenable_file_counts_as_partial_never_dropped() {
    use std::os::unix::fs::PermissionsExt;
    let corpus = search_corpus("open-failed");
    // The walker enumerates the file fine — the failure is the
    // searcher's own open, which folds into EntriesFailed like an
    // unlistable directory does.
    let locked = corpus.path.join("src/locked.rs");
    std::fs::write(&locked, "fn shared_marker() {}\n").expect("locked fixture");
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
        QueryKind::Text,
        &corpus.path,
        "shared_marker",
    ));

    // Restore before assertions so a red leg never leaves the fixture
    // unremovable for the TempTree drop.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644))
        .expect("restore file perms");
    let result = result.expect("text query resolves");

    let Completeness::Partial { ref reasons } = result.completeness else {
        panic!("an unopenable file is a disclosed partial, never complete");
    };
    assert!(
        reasons.iter().any(|reason| matches!(
            reason,
            PartialReason::EntriesFailed { count } if *count >= 1
        )),
        "the failed open is counted: {reasons:?}"
    );
    // Partial coverage is still served — the readable hit reports, the
    // unopenable file contributes nothing.
    assert!(
        result
            .matches
            .iter()
            .any(|hit| hit.source.path == Path::new("src/lib.rs"))
    );
    assert!(
        !result
            .matches
            .iter()
            .any(|hit| hit.source.path == Path::new("src/locked.rs"))
    );
}

#[test]
fn backend_selection_is_mechanical_and_never_calls_llm() {
    // The dispatch table is fixed: each kind resolves to its admitted
    // backend — never a model's pick, and never an honest `None` left
    // where a backend exists.
    assert_eq!(backend_for(QueryKind::Text), Some(SearchBackend::Text));
    assert_eq!(backend_for(QueryKind::Path), Some(SearchBackend::Path));
    assert_eq!(backend_for(QueryKind::Source), Some(SearchBackend::Source));
    assert_eq!(backend_for(QueryKind::Ast), Some(SearchBackend::Ast));
    assert_eq!(backend_for(QueryKind::Symbol), Some(SearchBackend::Symbol));
    assert_eq!(backend_for(QueryKind::Graph), Some(SearchBackend::Graph));
    // The recorded interface names classify exactly onto their kinds —
    // reference queries are the typed-symbol-index leg, not the impact
    // graph.
    for (name, kind) in [
        ("search.text", QueryKind::Text),
        ("search.paths", QueryKind::Path),
        ("source.slice", QueryKind::Source),
        ("search.structure", QueryKind::Ast),
        ("code.symbol", QueryKind::Symbol),
        ("code.references", QueryKind::Symbol),
        ("code.impact", QueryKind::Graph),
    ] {
        assert_eq!(
            QueryKind::from_name(name).expect("recorded name"),
            kind,
            "{name}"
        );
    }
    // Unrecorded names stay typed refusals — an invented or dropped
    // alias is never a best-effort guess.
    for name in [
        "search.path",
        "source.read",
        "search.ast",
        "search.impact",
        "search.symbols",
        "search.refs",
    ] {
        assert!(
            matches!(
                QueryKind::from_name(name),
                Err(ContextError::UnknownKind { .. })
            ),
            "{name} is not a recorded interface name"
        );
    }
    // The refusal's reported domain is exactly the recorded vocabulary —
    // every listed name parses, and nothing else is claimed.
    let Err(ContextError::UnknownKind { known, .. }) = QueryKind::from_name("bogus") else {
        panic!("an unknown name refuses");
    };
    let mut listed = known.to_vec();
    listed.sort_unstable();
    assert_eq!(
        listed,
        [
            "code.impact",
            "code.references",
            "code.symbol",
            "search.paths",
            "search.structure",
            "search.text",
            "source.slice",
        ]
    );
    for name in known {
        assert!(QueryKind::from_name(name).is_ok(), "{name} round-trips");
    }
    // A live query rides no provider seam — the world harness counts
    // sends and the facade cannot reach one.
    let world = open_world("mechanical", None);
    let corpus = search_corpus("mechanical");
    let result = query(&search_query(
        QueryKind::Text,
        &corpus.path,
        "shared_marker",
    ))
    .expect("text query resolves");
    assert_eq!(result.backend, SearchBackend::Text);
    assert_eq!(world.provider_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn symbol_names_dispatch_and_impact_answers_through_the_graph_backend() {
    let corpus = search_corpus("unsupported");
    // `code.symbol`/`code.references` dispatch to the admitted typed
    // index — both route to one kind, and each name's op carries its
    // semantics: `shared_marker` is defined once in src/lib.rs and used
    // nowhere, so the symbol name serves exactly that definition and the
    // reference name serves no typed row at all — only non-exact text
    // hints from the unclaimed prose.
    for (name, kind, role, rows) in [
        ("code.symbol", QueryKind::Symbol, SymbolRole::Definition, 1),
        (
            "code.references",
            QueryKind::Symbol,
            SymbolRole::Reference,
            0,
        ),
    ] {
        assert_eq!(
            QueryKind::from_name(name).expect("recorded name"),
            kind,
            "{name}"
        );
        let mut request = search_query(kind, &corpus.path, "shared_marker");
        request.symbol_op = SymbolOp::from_interface_name(name);
        let result = query(&request).expect("the symbol leg resolves");
        assert_eq!(result.backend, SearchBackend::Symbol, "{name}");
        let typed: Vec<SymbolRole> = result
            .matches
            .iter()
            .filter_map(|hit| match &hit.kind {
                MatchKind::Symbol(payload) => Some(payload.role),
                MatchKind::Text { .. } => None,
                other => panic!("{name} served a non-symbol, non-hint row: {other:?}"),
            })
            .collect();
        assert_eq!(typed, vec![role; rows], "{name}");
    }
    // The one kind left joins the table now: `code.impact` answers with
    // the derived graph instead of refusing. The corpus carries no package
    // root, so the derivation places no relation row — the named document
    // is still the walk's own node, and the answer discloses exactly that
    // rather than refusing the surface.
    assert_eq!(
        QueryKind::from_name("code.impact").expect("recorded name"),
        QueryKind::Graph
    );
    let answered = query(&search_query(QueryKind::Graph, &corpus.path, "src/lib.rs"))
        .expect("a kind with an admitted backend answers");
    assert_eq!(answered.backend, SearchBackend::Graph);
    assert_eq!(answered.backend.engine(), "ignore+derive_edges");
    assert!(answered.matches.is_empty(), "an impact row is not a match");
    let impact = answered
        .impact
        .as_ref()
        .expect("the graph leg answers with the traversal it ran");
    assert_eq!(
        impact
            .nodes
            .iter()
            .map(|node| node.document.path.as_path())
            .collect::<Vec<_>>(),
        vec![Path::new("src/lib.rs")],
        "the named document is the walk's own node: {impact:?}"
    );
    assert!(
        impact.edges.is_empty(),
        "no package root means no relation row was placed: {impact:?}"
    );
    assert!(answered.unresolved.is_empty(), "{answered:?}");
    // A path that resolves outside the root is a boundary denial, exactly
    // as the source leg denies it — the graph leg walks no document the
    // caller could not name.
    let err = query(&search_query(QueryKind::Graph, &corpus.path, ".."))
        .expect_err("a path outside the root is denied at the boundary");
    assert!(
        matches!(err, ContextError::EscapedRoot { .. }),
        "the graph leg keeps the root boundary: {err:?}"
    );
    assert_eq!(err.error_code(), ErrorCode::Denied);
    // An unknown interface name is a caller error, not a best guess.
    let err = QueryKind::from_name("search.magic").expect_err("unknown names refuse");
    assert_eq!(err.error_code(), ErrorCode::InvalidInput);
}

#[test]
fn source_query_returns_bytes_with_provenance() {
    let corpus = search_corpus("source");
    let result = query(&search_query(
        QueryKind::Source,
        &corpus.path,
        "src/cp1251.rs",
    ))
    .expect("source query resolves");

    assert_eq!(result.backend, SearchBackend::Source);
    assert_eq!(result.snapshot, SnapshotId::Live);
    assert_eq!(result.completeness, Completeness::Complete);
    let hit = result.matches.first().expect("one source hit");
    assert_eq!(hit.source.path, PathBuf::from("src/cp1251.rs"));
    assert_eq!(hit.source.line, None);
    assert!(!hit.source.ignored);
    let MatchKind::Source { bytes } = &hit.kind else {
        panic!("a source hit carries the exact file bytes");
    };
    assert_eq!(
        *bytes,
        std::fs::read(corpus.path.join("src/cp1251.rs")).expect("fixture bytes")
    );

    // An ignored file named explicitly is still served — flagged with
    // what the rules would have done, not silently ordinary.
    let ignored = query(&search_query(QueryKind::Source, &corpus.path, "secret.txt"))
        .expect("an explicit ignored path still resolves");
    let hit = ignored.matches.first().expect("ignored source hit");
    assert!(hit.source.ignored, "the hit reports its ignore provenance");

    // The bound is a byte cap — a capped read is partial, never whole.
    let mut capped = search_query(QueryKind::Source, &corpus.path, "src/cp1251.rs");
    capped.limit = 8;
    let capped = query(&capped).expect("capped source resolves");
    assert_eq!(
        capped.completeness,
        Completeness::Partial {
            reasons: vec![PartialReason::LimitReached { limit: 8 }]
        }
    );
    let hit = capped.matches.first().expect("capped source hit");
    let MatchKind::Source { bytes } = &hit.kind else {
        panic!("a capped source hit still carries bytes");
    };
    assert_eq!(
        bytes.len(),
        8,
        "the cap bounds the payload itself — a partial flag on full bytes fails"
    );
}

#[cfg(unix)]
#[test]
fn source_flag_walk_failure_is_disclosed_match_still_served() {
    use std::os::unix::fs::PermissionsExt;
    let corpus = search_corpus("baseline-failed");
    // An ancestor dir that is traversable but unlistable: canonicalize
    // and the file open still succeed, but the `ignored`-flag walk
    // cannot list it — a real scan failure folded into EntriesFailed.
    let dir = corpus.path.join("src");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o111))
        .expect("chmod unlistable dir");
    // Running as root the mode bits do not block the listing — probe
    // and self-skip rather than assert a failure that cannot occur.
    if std::fs::read_dir(&dir).is_ok() {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("restore dir perms");
        return;
    }

    let result = query(&search_query(QueryKind::Source, &corpus.path, "src/lib.rs"));

    // Restore before assertions so a red leg never leaves the fixture
    // unremovable for the TempTree drop.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
        .expect("restore dir perms");
    let result = result.expect("source query resolves");

    // The resolved file still serves — the flag walk's failure is
    // disclosed coverage, never a reason to drop the hit.
    let hit = result
        .matches
        .first()
        .expect("the resolved file still serves");
    assert_eq!(hit.source.path, PathBuf::from("src/lib.rs"));
    let Completeness::Partial { ref reasons } = result.completeness else {
        panic!("a failed flag walk is a disclosed partial, never complete");
    };
    assert!(
        reasons.iter().any(|reason| matches!(
            reason,
            PartialReason::EntriesFailed { count } if *count >= 1
        )),
        "the failed listing is counted: {reasons:?}"
    );
}

#[test]
fn inspect_system_leg_dispatches_through_action_registry() {
    // The row is a local handler now, and the invariant behind this pin
    // is the one that always mattered: a parse-leg surface is never
    // served in process. A worker the handler cannot reach must be
    // reported as `Unanswered` with its own wire class, carrying no
    // detected row — not served, not Complete, and never a fabricated
    // system report.
    let registry = ActionRegistry::new();
    let definition = registry
        .definition(INSPECT_SYSTEM)
        .expect("inspect_system is a catalog row");
    assert_eq!(definition.id, INSPECT_SYSTEM);
    assert_eq!(definition.revision, 2);
    assert_eq!(definition.implementation, Implementation::Local);

    let tree = tree_of(
        "inspect-system",
        &[("src/lib.rs", "pub fn served_by_the_worker() {}\n")],
    );
    ensure_helper();
    let mut world = open_world("inspect", None);
    world.runtime.index.worker.program = PathBuf::from(rivect_binary());
    world.runtime.set_project_root(tree.path);
    let session = world.open_session("inspect-session");
    let config = world.runtime.config_for_broker();

    // With the worker unreachable, every parse leg reports the refusal
    // and nothing is detected.
    world.runtime.index.worker.helper = PathBuf::from("/nonexistent/rivect-sandbox-helper");
    let mut ctx = world.runtime.action_context(&session, &config);
    let ActionOutcome::Inspected(report) = registry
        .execute(
            ActionInput::InspectSystem(InspectSystemInput::default()),
            &mut ctx,
        )
        .expect("the boundary reports rather than refusing")
    else {
        panic!("inspect_system answers its own report, never another outcome");
    };
    assert!(report.detected.is_empty(), "nothing was read: {report:?}");
    assert!(report.residual_risk.is_empty(), "no coverage was measured");
    assert_eq!(
        report.freshness,
        IndexFreshness::Live,
        "no generation was ever cut"
    );
    for system in report.systems.iter().filter(|system| {
        matches!(
            system.kind,
            QueryKind::Ast | QueryKind::Symbol | QueryKind::Graph
        )
    }) {
        assert_eq!(
            system.outcome,
            ProbeOutcome::Unanswered {
                code: ErrorCode::CapabilityUnavailable,
                cause: String::from("helper_unavailable"),
            },
            "a parse leg the worker could not run is named, not served: {system:?}"
        );
    }
    // The graph leg declares its own backend now: the boundary reports the
    // surface as admitted and never as the "no backend" row that belonged
    // to a refused kind.
    let graph = report
        .systems
        .iter()
        .find(|system| system.kind == QueryKind::Graph)
        .expect("every kind is reported");
    assert_eq!(graph.backend, Some(SearchBackend::Graph));
    assert_eq!(
        graph.outcome,
        ProbeOutcome::Unanswered {
            code: ErrorCode::CapabilityUnavailable,
            cause: String::from("helper_unavailable"),
        }
    );

    // With the worker reachable, the same dispatch answers: the parse
    // legs are `Answered`, and the report is the worker's own facts.
    world.runtime.index.worker.helper =
        rivect_sandbox_helper::helper_binary().expect("the real helper");
    let mut ctx = world.runtime.action_context(&session, &config);
    let ActionOutcome::Inspected(report) = registry
        .execute(
            ActionInput::InspectSystem(InspectSystemInput::default()),
            &mut ctx,
        )
        .expect("the boundary reports")
    else {
        panic!("inspect_system answers its own report");
    };
    for system in report.systems.iter().filter(|system| {
        matches!(
            system.kind,
            QueryKind::Ast | QueryKind::Symbol | QueryKind::Graph
        )
    }) {
        assert_eq!(
            system.outcome,
            ProbeOutcome::Answered,
            "the worker answered this parse leg: {system:?}"
        );
    }
    // The boundary reports about itself, not about a corpus: the probe
    // asks for a name no project is expected to define, so a project
    // that happened to define it would appear as a detected row and
    // never as an invented one.
    assert!(
        report
            .detected
            .iter()
            .all(|row| row.name == BOUNDARY_PROBE_NAME),
        "a detected row is a row the worker read: {report:?}"
    );
    assert!(
        !report
            .detected
            .iter()
            .any(|row| row.name == "served_by_the_worker"),
        "the boundary did not read the corpus for its own report"
    );
}

#[test]
fn no_external_rg_or_fd_invoked() {
    // The engines are in-process libraries — provenance names the crate
    // stack on every result, and the mechanical
    // `process_spawns_only_at_boundary` convention test makes any
    // `process::Command` in these modules fail the suite outright.
    let corpus = search_corpus("in-process");
    for (kind, pattern, backend) in [
        (QueryKind::Text, "shared_marker", SearchBackend::Text),
        (QueryKind::Path, "*.rs", SearchBackend::Path),
        (QueryKind::Source, "src/lib.rs", SearchBackend::Source),
        (QueryKind::Graph, "src/lib.rs", SearchBackend::Graph),
    ] {
        let result = query(&search_query(kind, &corpus.path, pattern)).expect("query resolves");
        assert_eq!(result.backend, backend);
        assert_eq!(
            result.backend.engine(),
            match backend {
                SearchBackend::Text => "grep-searcher+grep-regex",
                SearchBackend::Path => "ignore+globset",
                SearchBackend::Source => "std::fs",
                SearchBackend::Ast => "tree-sitter+ast-grep-core",
                SearchBackend::Symbol => "tree-sitter+lsp-types",
                SearchBackend::Graph => "ignore+derive_edges",
            },
            "provenance names the in-process engine, never a subprocess"
        );
    }
}

#[test]
fn search_names_are_not_command_execute_kinds() {
    let mut world = open_world("kinds", None);
    let session = world.open_session("kinds-session");
    for (id, kind) in [
        (10, "search.text"),
        (11, "search.symbols"),
        (12, "code.symbol"),
        (13, "source.slice"),
    ] {
        let response = world.dispatch(&corpus_command_execute(&session, kind, json!(id)));
        assert_eq!(
            response["error"]["data"]["code"], "invalid_input",
            "{kind} is an interface-style name, not a command kind"
        );
    }
    // The describe page never lists them either — a name that cannot
    // execute stays out of the advertised command catalog.
    let page = rivect::tools::describe();
    assert!(
        !page.items.iter().any(|descriptor| {
            descriptor.canonical_id.starts_with("search.")
                || descriptor.canonical_id.starts_with("code.")
                || descriptor.canonical_id.starts_with("source.")
        }),
        "future interface names are not advertised command kinds"
    );
}
