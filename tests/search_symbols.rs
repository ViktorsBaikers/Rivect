//! Semantic symbol navigation over the typed in-process index
//! (AC-031/AC-036 legs + AC-039a contribution): definition/reference/
//! type queries resolve through the SRC-007 grammars with `lsp-types`
//! document identity (uri/version/encoding/root), same-name symbols are
//! disambiguated by scope, a stale document version is never served as
//! a current answer, and the text fallback is a labelled hint — never
//! a reference.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions fail loudly with the observed payload (standards §14)"
)]

mod support;

use rivect::context::{ContextError, IgnorePolicy, QueryKind, backend_for, query};
use rivect::contracts::ErrorCode;
use rivect::index::{
    Completeness, MatchKind, PartialReason, QueryResult, SearchBackend, SearchMatch, SnapshotId,
    SymbolMatch, SymbolRole,
};
use rivect::lsp::{
    CandidateFile, DocumentPin, MAX_SYMBOL_ROWS, SymbolIndex, SymbolOp, SymbolRequest, path_to_uri,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use support::{TempTree, find_subsequence, search_query, symbol_corpus, symbol_query, tree_of};

/// The `MatchKind::Symbol` payload of one match — every other kind is a
/// contract violation on this leg.
fn symbol_hit(hit: &SearchMatch) -> &SymbolMatch {
    let MatchKind::Symbol(payload) = &hit.kind else {
        panic!(
            "a symbol-leg hit carries MatchKind::Symbol, got {:?}",
            hit.kind
        );
    };
    payload
}

/// The `(path, scope)` pair of one symbol hit.
fn hit_at(hit: &SearchMatch) -> (&Path, &str) {
    (hit.source.path.as_path(), symbol_hit(hit).scope.as_str())
}

#[test]
fn definition_reference_type_queries_resolve_through_typed_index() {
    let corpus = symbol_corpus("ops");

    // `code.symbol` — definition: the named defs land as typed index
    // rows over the real grammars, never as text or ast shapes.
    let result = query(&symbol_query(&corpus.path, "helper", SymbolOp::Definition))
        .expect("definition query resolves");
    assert_eq!(result.backend, SearchBackend::Symbol);
    assert_eq!(result.backend.engine(), "tree-sitter+lsp-types");
    // The index is rebuilt per query from a live scan — no store owns a
    // generation yet, so none is invented.
    assert_eq!(result.snapshot, SnapshotId::Live);
    // The unclaimed notes.py contributes its literal hint — partition it
    // from the typed rows before asserting symbol payloads.
    let defs: Vec<(&Path, &str)> = result
        .matches
        .iter()
        .filter(|hit| matches!(hit.kind, MatchKind::Symbol(_)))
        .map(hit_at)
        .collect();
    assert_eq!(
        defs,
        vec![
            (Path::new("src/app.ts"), ""),
            (Path::new("src/lib.rs"), "a"),
            (Path::new("src/lib.rs"), "b"),
        ],
        "every `helper` definition across covered languages"
    );
    for hit in &result.matches {
        if !matches!(hit.kind, MatchKind::Symbol(_)) {
            continue;
        }
        let payload = symbol_hit(hit);
        assert_eq!(payload.role, SymbolRole::Definition);
        assert!(
            payload.resolved,
            "a definition row is resolved by construction"
        );
    }

    // `code.references` — reference finding: the call sites report
    // through the same index — `summon`'s bare call at lib.rs:3 and
    // the two qualified calls at lib.rs:9; the fallback hint lands
    // behind the typed rows.
    let refs = symbol_query(&corpus.path, "helper", SymbolOp::References);
    let result = query(&refs).expect("references query resolves");
    let lines: Vec<u64> = result
        .matches
        .iter()
        .filter(|hit| matches!(hit.kind, MatchKind::Symbol(_)))
        .map(|hit| hit.source.line.expect("a reference carries a line"))
        .collect();
    assert_eq!(lines, vec![3, 9, 9], "the three call sites in lib.rs");
    for hit in &result.matches {
        if !matches!(hit.kind, MatchKind::Symbol(_)) {
            continue;
        }
        assert_eq!(symbol_hit(hit).role, SymbolRole::Reference);
        assert!(symbol_hit(hit).resolved, "`helper` is defined in coverage");
    }

    // `code.symbol` + Type — `a::helper` returns `Token`: the row lands
    // on Token's own definition, marked a type answer.
    let typed = symbol_query(&corpus.path, "a::helper", SymbolOp::Type);
    let result = query(&typed).expect("type query resolves");
    let type_rows: Vec<&SymbolMatch> = result
        .matches
        .iter()
        .filter(|hit| matches!(hit.kind, MatchKind::Symbol(_)))
        .map(symbol_hit)
        .collect();
    assert_eq!(type_rows.len(), 1, "`a::helper` has one named type");
    assert_eq!(type_rows[0].role, SymbolRole::Type);
    assert_eq!(type_rows[0].name, "Token");
    assert_eq!(type_rows[0].symbol_kind, "struct");
    assert_eq!(type_rows[0].scope, "");
    assert!(type_rows[0].resolved);
    // `b::helper` declares no return type — no typed row, only the
    // literal hint from the unclaimed file.
    let untyped = symbol_query(&corpus.path, "b::helper", SymbolOp::Type);
    let result = query(&untyped).expect("type query resolves");
    assert_eq!(result.matches.len(), 1, "{:?}", result.matches);
    assert!(
        matches!(result.matches[0].kind, MatchKind::Text { .. }),
        "a unit return names no type — only the non-exact hint serves"
    );
}

#[test]
fn same_name_symbols_disambiguated_by_scope() {
    let corpus = symbol_corpus("same-name");

    // A bare name serves every scope's definition — the rows are
    // distinguishable by the scope qualifier they carry.
    let result = query(&symbol_query(&corpus.path, "helper", SymbolOp::Definition))
        .expect("bare-name query resolves");
    let scopes: Vec<&str> = result
        .matches
        .iter()
        .filter(|hit| matches!(hit.kind, MatchKind::Symbol(_)))
        .map(|hit| symbol_hit(hit).scope.as_str())
        .collect();
    assert_eq!(
        scopes,
        vec!["", "a", "b"],
        "one row per scope, sorted by path"
    );

    // A `scope::name` pattern selects exactly that scope's symbol —
    // the sibling with the same name is never confused for it.
    let result = query(&symbol_query(
        &corpus.path,
        "a::helper",
        SymbolOp::Definition,
    ))
    .expect("qualified query resolves");
    let typed: Vec<&SearchMatch> = result
        .matches
        .iter()
        .filter(|hit| matches!(hit.kind, MatchKind::Symbol(_)))
        .collect();
    assert_eq!(typed.len(), 1);
    let payload = symbol_hit(typed[0]);
    assert_eq!(payload.scope, "a");
    assert_eq!(payload.symbol_kind, "function");

    // References disambiguate by binding: `a::helper` matches the
    // spelled `a::helper()` call AND the bare `helper()` inside
    // `summon`, which binds lexically to `a`'s helper — never
    // `b::helper()`.
    let refs = symbol_query(&corpus.path, "a::helper", SymbolOp::References);
    let result = query(&refs).expect("qualified references resolve");
    let lines: Vec<u64> = result
        .matches
        .iter()
        .filter(|hit| matches!(hit.kind, MatchKind::Symbol(_)))
        .map(|hit| hit.source.line.expect("a reference carries a line"))
        .collect();
    assert_eq!(
        lines,
        vec![3, 9],
        "summon's bare call inside scope a plus the spelled a::helper()"
    );
}

#[test]
fn document_version_encoding_root_carried_in_requests() {
    let corpus = symbol_corpus("identity");
    let canonical = corpus.path.canonicalize().expect("canonical corpus root");
    // The index's own encoder names the identities — a percent-encoded
    // temp path compares equal, never by `format!` coincidence.
    let root_uri = path_to_uri(&canonical).expect("root uri");
    let doc_uri = path_to_uri(&canonical.join("src/lib.rs")).expect("document uri");
    assert!(root_uri.as_str().starts_with("file://"));

    let mut pinned = symbol_query(&corpus.path, "helper", SymbolOp::Definition);
    pinned.document = Some(DocumentPin {
        path: PathBuf::from("src/lib.rs"),
        version: None,
        encoding: None,
    });
    let result = query(&pinned).expect("pinned query resolves");

    // Every served row carries the full document identity — uri,
    // content version, the negotiated position encoding and the
    // workspace root — the LSP-compatible contract, no subprocess. The
    // pin is document-scoped: lib.rs's two `helper`s, never app.ts's.
    assert_eq!(result.matches.len(), 2, "{:?}", result.matches);
    for hit in &result.matches {
        let payload = symbol_hit(hit);
        assert_eq!(payload.uri, doc_uri);
        assert_eq!(payload.root, root_uri);
        assert_eq!(payload.encoding.as_str(), "utf-8");
        assert_eq!(hit.source.path, Path::new("src/lib.rs"));
    }
    // The same document reports the same version on every row — a
    // stable content-derived identity.
    let version = symbol_hit(&result.matches[0]).version;
    assert_eq!(
        symbol_hit(&result.matches[1]).version,
        version,
        "one document, one version"
    );

    // The request's version pin binds when it matches the indexed
    // version — the document identity round-trips through the request.
    let mut pinned = symbol_query(&corpus.path, "helper", SymbolOp::Definition);
    pinned.document = Some(DocumentPin {
        path: PathBuf::from("src/lib.rs"),
        version: Some(version),
        encoding: Some(lsp_types::PositionEncodingKind::UTF8),
    });
    let result = query(&pinned).expect("a matching version pin resolves");
    assert_eq!(result.matches.len(), 2);
    assert_eq!(result.completeness, Completeness::Complete);

    // An encoding the index cannot serve is a typed refusal, never a
    // silently reinterpreted position space.
    let mut pinned = symbol_query(&corpus.path, "helper", SymbolOp::Definition);
    pinned.document = Some(DocumentPin {
        path: PathBuf::from("src/lib.rs"),
        version: None,
        encoding: Some(lsp_types::PositionEncodingKind::UTF16),
    });
    let err = query(&pinned).expect_err("a utf-16 pin is refused typed");
    assert!(matches!(
        err,
        ContextError::UnsupportedPositionEncoding { encoding: "utf-16" }
    ));
    assert_eq!(err.error_code(), ErrorCode::InvalidInput);
    assert!(
        !err.to_string().ends_with(['.', '!', '?', ';']),
        "display is lowercase without terminal punctuation: {err}"
    );
}

#[test]
fn stale_document_version_never_shown_as_current_diagnostic() {
    let corpus = symbol_corpus("stale");
    let canonical = corpus.path.canonicalize().expect("canonical corpus root");
    let files = vec![
        CandidateFile {
            absolute: canonical.join("src/lib.rs"),
            relative: PathBuf::from("src/lib.rs"),
            ignored: false,
        },
        CandidateFile {
            absolute: canonical.join("src/app.ts"),
            relative: PathBuf::from("src/app.ts"),
            ignored: false,
        },
    ];
    let index = SymbolIndex::build(
        &canonical,
        files,
        SymbolRequest {
            name: "helper",
            scope: None,
            op: SymbolOp::Definition,
            document: None,
            limit: 64,
        },
        unhurried(),
    );
    let before = index.answer();
    assert_eq!(before.stale_documents, 0, "a fresh build is not stale");
    assert_eq!(before.matches.len(), 3);
    // lib.rs's own version — taken from its rows, never another file's.
    let lib_versions: Vec<i32> = before
        .matches
        .iter()
        .filter(|hit| hit.source.path == Path::new("src/lib.rs"))
        .map(|hit| symbol_hit(hit).version)
        .collect();
    assert_eq!(lib_versions.len(), 2);
    assert_eq!(lib_versions[0], lib_versions[1]);
    let lib_version = lib_versions[0];

    // Before the edit the pin is current: the facade accepts it and
    // serves exactly the pinned document's `a::helper` at that version.
    let mut pinned = symbol_query(&corpus.path, "a::helper", SymbolOp::Definition);
    pinned.document = Some(DocumentPin {
        path: PathBuf::from("src/lib.rs"),
        version: Some(lib_version),
        encoding: None,
    });
    let accepted = query(&pinned).expect("the current version pin is accepted");
    assert_eq!(accepted.matches.len(), 1, "{:?}", accepted.matches);
    assert_eq!(symbol_hit(&accepted.matches[0]).version, lib_version);
    assert_eq!(accepted.completeness, Completeness::Complete);

    // The document changes under the built index. Rows computed under
    // the old version must not be served as current.
    std::fs::write(
        corpus.path.join("src/lib.rs"),
        "pub fn caller() { b::helper(); }\npub struct Token;\npub mod a { pub fn helper() {} }\n",
    )
    .expect("edit the fixture");

    let after = index.answer();
    assert_eq!(after.stale_documents, 1, "the edited document is stale");
    assert_eq!(after.matches.len(), 1, "{:?}", after.matches);
    assert_eq!(
        after.matches[0].source.path,
        Path::new("src/app.ts"),
        "only the fresh document's rows are served"
    );

    // Through the facade: the same pin after the edit is a typed
    // conflict — the index cannot answer for a version that is gone,
    // and serving the new bytes under the old pin would be the
    // stale-version lie AC-039a forbids.
    let err = query(&pinned).expect_err("a stale version pin is refused");
    let ContextError::StaleDocumentVersion { pinned, actual, .. } = err else {
        panic!("a stale pin is StaleDocumentVersion, got {err:?}");
    };
    assert_eq!(pinned, lib_version);
    assert_ne!(actual, lib_version, "the edit moved the content version");
    assert_eq!(err.error_code(), ErrorCode::Conflict);
    assert!(
        !err.to_string().ends_with(['.', '!', '?', ';']),
        "display is lowercase without terminal punctuation: {err}"
    );
}

#[test]
fn same_length_edit_is_stale() {
    // The mtime leg: equal length, different bytes — the stamp's mtime
    // alone must flag it.
    let tree = tree_of("same-length", &[("src/lib.rs", "fn helper() {}\n")]);
    let canonical = tree.path.canonicalize().expect("canonical root");
    let index = SymbolIndex::build(
        &canonical,
        vec![CandidateFile {
            absolute: canonical.join("src/lib.rs"),
            relative: PathBuf::from("src/lib.rs"),
            ignored: false,
        }],
        SymbolRequest {
            name: "helper",
            scope: None,
            op: SymbolOp::Definition,
            document: None,
            limit: 64,
        },
        unhurried(),
    );
    assert_eq!(index.answer().matches.len(), 1);
    let file = std::fs::File::options()
        .write(true)
        .open(canonical.join("src/lib.rs"))
        .expect("open fixture");
    std::io::Write::write_all(&mut &file, b"fn helpex() {}\n").expect("same-length edit");
    file.set_modified(std::time::SystemTime::now() + Duration::from_secs(5))
        .expect("move the mtime");
    drop(file);
    let after = index.answer();
    assert_eq!(after.stale_documents, 1);
    assert!(after.matches.is_empty(), "{:?}", after.matches);
}

#[test]
fn answer_coordinates_match_the_document() {
    let corpus = symbol_corpus("coordinates");
    let bytes = std::fs::read(corpus.path.join("src/lib.rs")).expect("fixture bytes");

    let result = query(&symbol_query(&corpus.path, "caller", SymbolOp::Definition))
        .expect("definition query resolves");
    assert_eq!(result.matches.len(), 1);
    let hit = &result.matches[0];
    let payload = symbol_hit(hit);

    // The byte span is the name node's own span — `caller` inside
    // `pub fn caller()` — and the facade line is 1-based like every leg.
    let needle = b"fn caller";
    let name_start = find_subsequence(&bytes, needle).expect("fixture needle") + 3;
    let name_end = name_start + "caller".len();
    assert_eq!(payload.start_byte as usize, name_start);
    assert_eq!(payload.end_byte as usize, name_end);
    assert_eq!(
        &bytes[name_start..name_end],
        b"caller",
        "the span slices the name out of the document"
    );
    let line = bytes[..name_start]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count() as u64;
    assert_eq!(hit.source.line, Some(line + 1));
    // The LSP range is zero-based utf-8: line index and byte column —
    // for a utf-8 encoding the byte column IS the character offset.
    assert_eq!(payload.range.start.line as u64, line);
    let line_start = bytes[..name_start]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map(|idx| idx + 1)
        .unwrap_or(0);
    assert_eq!(
        payload.range.start.character as usize,
        name_start - line_start
    );
    let end_line_start = bytes[..name_end]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map(|idx| idx + 1)
        .unwrap_or(0);
    assert_eq!(payload.range.end.line as u64, line);
    assert_eq!(
        payload.range.end.character as usize,
        name_end - end_line_start
    );

    // A multibyte char earlier on the same line: the utf-8 column is the
    // byte offset — `É` is two bytes, one char, one utf-16 unit — so a
    // char- or utf-16-counting range is off by one here.
    let source = "const S: &str = \"\u{c9}\"; fn target() {}\n";
    let tree = tree_of("multibyte", &[("src/wide.rs", source)]);
    let result = query(&symbol_query(&tree.path, "target", SymbolOp::Definition))
        .expect("definition query resolves");
    assert_eq!(result.matches.len(), 1);
    let payload = symbol_hit(&result.matches[0]);
    let byte_column = source.find("target").expect("needle");
    let char_column = source[..byte_column].chars().count();
    assert_ne!(byte_column, char_column, "the fixture discriminates");
    assert_eq!(payload.range.start.character as usize, byte_column);
    assert_eq!(
        payload.range.end.character as usize,
        byte_column + "target".len()
    );
    assert_eq!(payload.start_byte as usize, byte_column);
}

#[test]
fn text_fallback_labelled_non_exact_never_a_reference() {
    let corpus = symbol_corpus("fallback");
    // `notes.py` has a `helper` definition no admitted grammar can
    // claim — the leg falls back to a literal byte hint, labelled by
    // its own kind so it can never pass for a typed reference.
    let refs = symbol_query(&corpus.path, "helper", SymbolOp::References);
    let result = query(&refs).expect("references query resolves");

    let fallback: Vec<&SearchMatch> = result
        .matches
        .iter()
        .filter(|hit| hit.source.path == Path::new("src/notes.py"))
        .collect();
    assert_eq!(fallback.len(), 1, "one literal hint in the Python file");
    assert_eq!(fallback[0].source.line, Some(1), "the hint's 1-based line");
    let MatchKind::Text { line_bytes } = &fallback[0].kind else {
        panic!("a fallback hit stays MatchKind::Text — labelled non-exact");
    };
    assert_eq!(line_bytes.as_slice(), b"def helper():\n");
    let wire = serde_json::to_value(&fallback[0].kind).expect("kind serializes");
    assert_eq!(wire["kind"], "text");
    assert!(
        wire.get("role").is_none() && wire.get("symbol_kind").is_none(),
        "no symbol or reference claim on a text hint: {wire}"
    );

    // The uncovered file stays disclosed — a hint is not coverage.
    let Completeness::Partial { ref reasons } = result.completeness else {
        panic!("the unclaimed language is a disclosed partial");
    };
    assert!(
        reasons
            .iter()
            .any(|reason| matches!(reason, PartialReason::UnsupportedLanguage { count: 1 })),
        "notes.py counts as uncovered: {reasons:?}"
    );
    // And the typed rows still serve beside the hint.
    assert!(
        result
            .matches
            .iter()
            .any(|hit| matches!(hit.kind, MatchKind::Symbol(_))),
        "the typed index rows are served beside the fallback hint"
    );
}

#[test]
fn unresolved_path_stays_unknown_not_absent_dependency() {
    let corpus = symbol_corpus("unresolved");

    // A pinned document that cannot be resolved is reported `unknown`:
    // named in `unresolved`, typed partial — never an empty-complete
    // "nothing there" answer.
    let mut pinned = symbol_query(&corpus.path, "helper", SymbolOp::Definition);
    pinned.document = Some(DocumentPin {
        path: PathBuf::from("src/missing.rs"),
        version: None,
        encoding: None,
    });
    let result = query(&pinned).expect("an unresolved pin still returns a result");
    assert!(result.matches.is_empty());
    assert_eq!(result.unresolved, vec![PathBuf::from("src/missing.rs")]);
    assert_eq!(
        result.completeness,
        Completeness::Partial {
            reasons: vec![PartialReason::UnresolvedPaths { count: 1 }]
        }
    );
    // A version pinned on a path that does not resolve cannot be
    // verified — refused, never answered without it.
    pinned.document = Some(DocumentPin {
        path: PathBuf::from("src/missing.rs"),
        version: Some(1),
        encoding: None,
    });
    let err = query(&pinned).expect_err("an unverifiable version pin refuses");
    assert!(matches!(
        err,
        ContextError::UnverifiableDocumentVersion { .. }
    ));

    // The same honesty at the symbol level: `zap()` is called but no
    // definition exists inside coverage — the reference row reports
    // `resolved: false`, an unknown edge, never an absent dependency.
    let refs = symbol_query(&corpus.path, "zap", SymbolOp::References);
    let result = query(&refs).expect("references query resolves");
    let zap: Vec<&SymbolMatch> = result.matches.iter().map(symbol_hit).collect();
    assert_eq!(zap.len(), 1, "the use is a real reference row");
    assert!(
        !zap[0].resolved,
        "no in-coverage definition — stays unknown"
    );
}

// ----- honesty legs -----

#[test]
fn symbol_backend_joins_the_mechanical_table() {
    // The fixed dispatch table grows exactly one row — the graph leg is
    // admitted beside it.
    assert_eq!(backend_for(QueryKind::Symbol), Some(SearchBackend::Symbol));
    assert_eq!(backend_for(QueryKind::Graph), Some(SearchBackend::Graph));
    assert_eq!(QueryKind::Symbol.as_str(), "code.symbol");
    // The recorded vocabulary is unchanged — both names classify onto
    // the symbol leg and no new interface name appeared.
    for name in ["code.symbol", "code.references"] {
        assert_eq!(
            QueryKind::from_name(name).expect("recorded name"),
            QueryKind::Symbol,
            "{name}"
        );
    }
    let Err(ContextError::UnknownKind { known, .. }) = QueryKind::from_name("bogus") else {
        panic!("an unknown name refuses");
    };
    assert_eq!(known.len(), 7, "the recorded vocabulary stays seven names");
}

#[test]
fn symbol_matches_are_typed_rows_never_ast_or_text() {
    let corpus = symbol_corpus("typed-rows");
    let result = query(&symbol_query(&corpus.path, "helper", SymbolOp::Definition))
        .expect("definition query resolves");
    assert_eq!(symbol_rows(&result).len(), 3, "{:?}", result.matches);

    for hit in &result.matches {
        if hit.source.path == Path::new("src/notes.py") {
            continue; // the fallback hint is covered by its own leg
        }
        let payload = symbol_hit(hit);
        let expected_language = if hit.source.path.ends_with("app.ts") {
            "typescript"
        } else {
            "rust"
        };
        assert_eq!(payload.language, expected_language);
        assert_eq!(payload.name, "helper");
        assert_eq!(payload.symbol_kind, "function");
        // The wire shape pins literally — a renamed field or tag is a
        // contract break, not an internal detail.
        let wire = serde_json::to_value(&hit.kind).expect("kind serializes");
        assert_eq!(wire["kind"], "symbol");
        assert_eq!(wire["role"], "definition");
        assert_eq!(wire["encoding"], "utf-8");
        assert!(
            wire["uri"]
                .as_str()
                .expect("uri string")
                .starts_with("file://"),
            "the document uri is a file uri: {wire}"
        );
        assert!(wire["version"].is_number(), "the version is an i32: {wire}");
        assert_eq!(
            serde_json::to_value(SearchBackend::Symbol).expect("serializes"),
            json!("symbol")
        );
    }
}

#[test]
fn symbol_leg_shares_the_completeness_algebra() {
    // A damaged tree still serves its intact symbols but discloses the
    // damaged span — the same algebra the ast leg reports; an oversized
    // file is a failed entry, never an unbounded read; a claimed file
    // that is not utf-8 cannot name its symbols.
    let corpus = completeness_corpus("completeness");

    let result = query(&symbol_query(&corpus.path, "intact", SymbolOp::Definition))
        .expect("symbol query resolves");
    assert_eq!(
        result.matches.len(),
        1,
        "the intact function inside the damaged file still indexes"
    );
    // Oversized + non-utf-8 = two failed entries; the damaged file and
    // the Python file each disclosed — in the facade's fixed order.
    assert_eq!(
        result.completeness,
        partial(vec![
            PartialReason::EntriesFailed { count: 2 },
            PartialReason::UnsupportedLanguage { count: 1 },
            PartialReason::ParseErrors { count: 1 },
        ])
    );

    // The caller's bound truncates like every other leg.
    let mut bounded = symbol_query(&corpus.path, "helper", SymbolOp::Definition);
    bounded.limit = 1;
    let result = query(&bounded).expect("bounded query resolves");
    assert_eq!(result.matches.len(), 1);
    // The bound leads the facade's order, the coverage gaps after it.
    assert_eq!(
        result.completeness,
        partial(vec![
            PartialReason::LimitReached { limit: 1 },
            PartialReason::EntriesFailed { count: 2 },
            PartialReason::UnsupportedLanguage { count: 1 },
            PartialReason::ParseErrors { count: 1 },
        ]),
        "the bound is disclosed"
    );
}

#[test]
fn symbol_leg_respects_ignore_scope_and_validation() {
    let corpus = symbol_corpus("filters");

    // scope_glob restricts candidates exactly like the other legs.
    let mut scoped = symbol_query(&corpus.path, "helper", SymbolOp::Definition);
    scoped.scope_glob = Some("src/app.ts".to_string());
    let result = query(&scoped).expect("scoped query resolves");
    assert_eq!(result.matches.len(), 1);
    assert_eq!(symbol_hit(&result.matches[0]).language, "typescript");

    // Include surfaces the ignored build/ file flagged.
    let mut included = symbol_query(&corpus.path, "generated", SymbolOp::Definition);
    included.ignore = IgnorePolicy::Include;
    let result = query(&included).expect("include query resolves");
    let generated = result
        .matches
        .iter()
        .find(|hit| hit.source.path == Path::new("build/generated.rs"))
        .expect("the ignored file's def is served flagged");
    assert!(generated.source.ignored);

    // The symbol-only fields are refused on other kinds — a caller
    // error, never silently ignored input.
    let mut text = search_query(QueryKind::Text, &corpus.path, "x");
    text.symbol_op = Some(SymbolOp::References);
    let err = query(&text).expect_err("symbol_op on a text query refuses");
    assert!(matches!(
        err,
        ContextError::SymbolFieldNotApplicable {
            field: "symbol_op",
            ..
        }
    ));
    assert_eq!(err.error_code(), ErrorCode::InvalidInput);

    let mut path = search_query(QueryKind::Path, &corpus.path, "*.rs");
    path.document = Some(DocumentPin {
        path: PathBuf::from("src/lib.rs"),
        version: None,
        encoding: None,
    });
    let err = query(&path).expect_err("a document pin on a path query refuses");
    assert!(matches!(
        err,
        ContextError::SymbolFieldNotApplicable {
            field: "document",
            ..
        }
    ));

    // An escaping pin path is a boundary denial, same as source.slice —
    // the escapee must exist for canonicalize to reach the check.
    let outside = TempTree::new("symbol-outside", "filters");
    std::fs::write(outside.path.join("escape.txt"), "nope\n").expect("escapee");
    let escaped_rel = PathBuf::from("..")
        .join(outside.path.file_name().expect("fixture name"))
        .join("escape.txt");
    let mut escaped = symbol_query(&corpus.path, "helper", SymbolOp::Definition);
    escaped.document = Some(DocumentPin {
        path: escaped_rel,
        version: None,
        encoding: None,
    });
    let err = query(&escaped).expect_err("an escaping pin is denied");
    assert!(
        matches!(err, ContextError::EscapedRoot { .. }),
        "an escape is EscapedRoot, got {err:?}"
    );
    assert_eq!(err.error_code(), ErrorCode::Denied);

    // A qualifier with no name is no pattern.
    let err = query(&symbol_query(&corpus.path, "a::", SymbolOp::Definition))
        .expect_err("a bare qualifier refuses");
    assert!(
        matches!(
            err,
            ContextError::EmptyPattern {
                kind: "code.symbol"
            }
        ),
        "got {err:?}"
    );
}

// ----- repair legs -----

/// The typed rows of a result — the fallback's text hints filtered out.
fn symbol_rows(result: &QueryResult) -> Vec<&SymbolMatch> {
    result
        .matches
        .iter()
        .filter(|hit| matches!(hit.kind, MatchKind::Symbol(_)))
        .map(symbol_hit)
        .collect()
}

/// The 1-based lines of every typed row at `path`, in answer order.
fn lines_at(result: &QueryResult, path: &str) -> Vec<u64> {
    result
        .matches
        .iter()
        .filter(|hit| {
            matches!(hit.kind, MatchKind::Symbol(_)) && hit.source.path == Path::new(path)
        })
        .map(|hit| hit.source.line.expect("a symbol row carries a line"))
        .collect()
}

fn partial(reasons: Vec<PartialReason>) -> Completeness {
    Completeness::Partial { reasons }
}

/// One file's index for `request`, built straight over its candidate —
/// the seam the work counters are read from.
fn index_one<'a>(tree: &TempTree, relative: &str, request: SymbolRequest<'a>) -> SymbolIndex<'a> {
    index_files(tree, &[relative], request)
}

fn index_files<'a>(
    tree: &TempTree,
    relatives: &[&str],
    request: SymbolRequest<'a>,
) -> SymbolIndex<'a> {
    index_files_by(tree, relatives, request, unhurried())
}

/// `relatives`' index whose parses stop at `deadline`.
fn index_files_by<'a>(
    tree: &TempTree,
    relatives: &[&str],
    request: SymbolRequest<'a>,
    deadline: Option<Instant>,
) -> SymbolIndex<'a> {
    let canonical = tree.path.canonicalize().expect("canonical root");
    let files = relatives
        .iter()
        .map(|relative| CandidateFile {
            absolute: canonical.join(relative),
            relative: PathBuf::from(relative),
            ignored: false,
        })
        .collect::<Vec<_>>();
    SymbolIndex::build(&canonical, files, request, deadline)
}

/// A deadline no test reaches: the budget tests count parse checks
/// exactly, whatever the machine's load.
fn unhurried() -> Option<Instant> {
    Instant::now().checked_add(Duration::from_secs(24 * 60 * 60))
}

/// The completeness the facade folds an unpinned [`request`] answer
/// into, reasons in the facade's order. The budget boundaries build
/// their index straight, [`unhurried`]: through the facade their
/// fixtures race its wall-clock parse deadline on a loaded machine.
fn folded(index: &SymbolIndex<'_>, answer: &rivect::lsp::SymbolAnswer) -> Completeness {
    let coverage = &index.coverage;
    let failed = coverage.failed + answer.unreadable_fallback;
    let unsupported = coverage
        .unsupported
        .saturating_sub(answer.unreadable_fallback);
    let mut reasons = Vec::new();
    if answer.truncated {
        reasons.push(PartialReason::LimitReached { limit: 64 });
    }
    for (count, reason) in [
        (failed, PartialReason::EntriesFailed { count: failed }),
        (
            unsupported,
            PartialReason::UnsupportedLanguage { count: unsupported },
        ),
        (
            coverage.damaged,
            PartialReason::ParseErrors {
                count: coverage.damaged,
            },
        ),
        (
            answer.stale_documents,
            PartialReason::StaleDocuments {
                count: answer.stale_documents,
            },
        ),
        (
            answer.unknown_module_paths,
            PartialReason::UnknownModulePaths {
                count: answer.unknown_module_paths,
            },
        ),
    ] {
        if count > 0 {
            reasons.push(reason);
        }
    }
    Completeness::from_reasons(reasons)
}

fn request(name: &str, op: SymbolOp) -> SymbolRequest<'_> {
    SymbolRequest {
        name,
        scope: None,
        op,
        document: None,
        limit: 64,
    }
}

#[test]
fn deep_nesting_fails_the_file_typed_within_linear_work() {
    // 2000 nested modules — a per-identifier ancestor search is cubic
    // here; the cursor walk stops at the depth cap having visited a
    // number of nodes linear in the levels it entered.
    let levels = 2000;
    let source = format!("{}{}", "mod a{".repeat(levels), "}".repeat(levels));
    let tree = tree_of("deep", &[("src/deep.rs", &source)]);
    let result =
        query(&symbol_query(&tree.path, "a", SymbolOp::Definition)).expect("query resolves");
    assert!(
        symbol_rows(&result).is_empty(),
        "an over-cap file serves no rows"
    );
    assert_eq!(
        result.completeness,
        partial(vec![PartialReason::EntriesFailed { count: 1 }]),
        "the over-cap file is a typed failed entry, never a silent complete"
    );
    let index = index_one(&tree, "src/deep.rs", request("a", SymbolOp::Definition));
    let visited = index.coverage.nodes_visited;
    // Each `mod a{` level is five nodes before the next one opens, two
    // tree levels deep: the walk reaches the 1024 cap after 512 levels.
    assert!(
        (512..=4 * 1024).contains(&visited),
        "linear in the entered levels, got {visited}"
    );
}

#[test]
fn wide_flat_file_work_is_linear() {
    // 80k sibling uses — a root-down parent search per identifier is
    // quadratic in siblings. `fn f(){` + n×`a;` + `}` is exactly 10 + 3n
    // nodes, and the walk visits each once.
    let uses = 80_000u64;
    let source = format!("fn f(){{{}}}\n", "a;".repeat(uses as usize));
    let tree = tree_of("wide", &[("src/wide.rs", &source)]);
    let index = index_one(&tree, "src/wide.rs", request("f", SymbolOp::Definition));
    let answer = index.answer();
    assert_eq!(lines_of(&answer), vec![("src/wide.rs".to_string(), 1)]);
    assert_eq!(folded(&index, &answer), Completeness::Complete);
    assert_eq!(index.coverage.nodes_visited, 10 + 3 * uses);

    // Under the row budget the same width serves its uses: every one
    // is a real reference row, unbound — `a` is defined nowhere — and
    // resolving them costs a bounded number of steps per use.
    let under = 65_535u64;
    let source = format!("fn f(){{{}}}\n", "a;".repeat(under as usize));
    let tree = tree_of("wide-refs", &[("src/wide.rs", &source)]);
    let index = index_one(&tree, "src/wide.rs", request("a", SymbolOp::References));
    let answer = index.answer();
    assert_eq!(answer.matches.len(), 64);
    assert!(
        answer
            .matches
            .iter()
            .map(symbol_hit)
            .all(|row| row.role == SymbolRole::Reference && !row.resolved)
    );
    assert_eq!(
        folded(&index, &answer),
        partial(vec![PartialReason::LimitReached { limit: 64 }])
    );
    // Exact: the first use walks the block, `f` and the root (3 steps)
    // and memoizes the empty result; each later use hits the memo at
    // its block (1 step) — under + 2 in all.
    assert_eq!(answer.resolution_steps, under + 2);
}

#[test]
fn same_path_locals_across_documents_resolve_in_linear_steps() {
    // Two hundred documents share the function path `take`, each with
    // its own parameter: a use must find its own document's local
    // without scanning every other document's.
    let bodies: Vec<(String, &str)> = (0..200)
        .map(|n| {
            (
                format!("src/f{n:03}.rs"),
                "fn take(config: u8) -> u8 { config }\n",
            )
        })
        .collect();
    let files: Vec<(&str, &str)> = bodies
        .iter()
        .map(|(path, body)| (path.as_str(), *body))
        .collect();
    let tree = tree_of("same-path-locals", &files);
    let relatives: Vec<&str> = files.iter().map(|(path, _)| *path).collect();
    let mut wide = request("config", SymbolOp::References);
    wide.limit = 200;
    let index = index_files(&tree, &relatives, wide);
    let answer = index.answer();
    assert_eq!(answer.matches.len(), 200);
    assert!(
        answer.matches.iter().all(|hit| symbol_hit(hit).resolved),
        "each use binds its own document's parameter"
    );
    // Exact: each use walks its own block and `take` (2 steps) and
    // decides there (1 step) — never another document's parameter.
    assert_eq!(answer.resolution_steps, 3 * 200);
}

#[test]
fn depth_cap_boundary_is_exact() {
    use rivect::lsp::MAX_TREE_DEPTH;
    assert_eq!(MAX_TREE_DEPTH, 1024, "the recorded depth cap");
    let levels = MAX_TREE_DEPTH / 2;
    // source_file(0) → mod_item(1) → declaration_list(2) → …: a
    // bodiless innermost `mod a;` puts its tokens at exactly
    // MAX_TREE_DEPTH; one more bodied level puts the braces one deeper.
    let at_cap = format!(
        "{}mod a;{}",
        "mod a{".repeat(levels - 1),
        "}".repeat(levels - 1)
    );
    let over_cap = format!("{}{}", "mod a{".repeat(levels), "}".repeat(levels));
    let tree = tree_of("depth-cap", &[("src/at.rs", &at_cap)]);
    let mut at = symbol_query(&tree.path, "a", SymbolOp::Definition);
    at.limit = levels;
    let result = query(&at).expect("at-cap query resolves");
    assert_eq!(symbol_rows(&result).len(), levels);
    assert_eq!(result.completeness, Completeness::Complete);

    let tree = tree_of("depth-over", &[("src/over.rs", &over_cap)]);
    let mut over = symbol_query(&tree.path, "a", SymbolOp::Definition);
    over.limit = levels;
    let result = query(&over).expect("over-cap query resolves");
    assert!(symbol_rows(&result).is_empty());
    assert_eq!(
        result.completeness,
        partial(vec![PartialReason::EntriesFailed { count: 1 }])
    );
}

#[test]
fn node_budget_boundary_is_exact() {
    use rivect::lsp::MAX_FILE_NODES;
    assert_eq!(MAX_FILE_NODES, 1_048_576, "the recorded node budget");
    // `fn f(){` + n×`a;` + `}` is 10 + 3n nodes, anonymous tokens
    // included — n lands the walk exactly on the budget.
    assert_eq!((MAX_FILE_NODES - 10) % 3, 0, "fixture arithmetic");
    let n = (MAX_FILE_NODES - 10) / 3;
    let at = format!("fn f(){{{}}}", "a;".repeat(n));
    let over = format!("fn f(){{{}}}", "a;".repeat(n + 1));
    let tree = tree_of("nodes-at", &[("src/at.rs", &at)]);
    let index = index_one(&tree, "src/at.rs", request("f", SymbolOp::Definition));
    let answer = index.answer();
    assert_eq!(lines_of(&answer), vec![("src/at.rs".to_string(), 1)]);
    assert_eq!(folded(&index, &answer), Completeness::Complete);
    assert_eq!(index.coverage.nodes_visited, MAX_FILE_NODES as u64);
    let tree = tree_of("nodes-over", &[("src/over.rs", &over)]);
    let index = index_one(&tree, "src/over.rs", request("f", SymbolOp::Definition));
    let answer = index.answer();
    assert!(answer.matches.is_empty());
    assert_eq!(
        folded(&index, &answer),
        partial(vec![PartialReason::EntriesFailed { count: 1 }])
    );
}

#[test]
fn row_budget_boundary_is_exact() {
    assert_eq!(MAX_SYMBOL_ROWS, 65_536, "the recorded row budget");
    let at = "fn x(){}\n".repeat(MAX_SYMBOL_ROWS);
    let tree = tree_of("rows", &[("src/many.rs", &at)]);
    let index = index_one(&tree, "src/many.rs", request("x", SymbolOp::Definition));
    let answer = index.answer();
    assert_eq!(answer.matches.len(), 64);
    assert!(
        answer
            .matches
            .iter()
            .all(|hit| symbol_hit(hit).role == SymbolRole::Definition)
    );
    assert_eq!(
        folded(&index, &answer),
        partial(vec![PartialReason::LimitReached { limit: 64 }]),
        "exactly the row budget is fully indexed"
    );
    // One more retained row overflows the build: the file carrying it
    // is a typed failed entry, never silently truncated.
    std::fs::write(tree.path.join("src/one_more.rs"), "fn x(){}\n").expect("overflow file");
    let index = index_files(
        &tree,
        &["src/many.rs", "src/one_more.rs"],
        request("x", SymbolOp::Definition),
    );
    assert_eq!(
        folded(&index, &index.answer()),
        partial(vec![
            PartialReason::LimitReached { limit: 64 },
            PartialReason::EntriesFailed { count: 1 },
        ])
    );

    // The budget is charged row by row: a file with far more uses than
    // the budget stops walking at the first row past it instead of
    // walking to its end and failing afterwards.
    let over = 70_000usize;
    let source = format!("fn x(){{}}\nfn f(){{{}}}\n", "x;".repeat(over));
    let tree = tree_of("rows-early", &[("src/uses.rs", &source)]);
    let index = index_one(&tree, "src/uses.rs", request("x", SymbolOp::References));
    assert_eq!(index.coverage.failed, 1);
    let visited = index.coverage.nodes_visited;
    assert!(
        (3 * 65_535..3 * over as u64).contains(&visited),
        "the walk stops at the first row past the budget, got {visited}"
    );
}

#[test]
fn definition_and_type_queries_never_spend_the_row_budget_on_uses() {
    // One definition among more uses than the row budget holds: only a
    // references query reads use rows, so the others index the file.
    let source = format!("fn x(){{}}\nfn f(){{{}}}\n", "x;".repeat(65_536));
    let tree = tree_of("defs-only", &[("src/uses.rs", &source)]);
    for op in [SymbolOp::Definition, SymbolOp::Type] {
        let index = index_one(&tree, "src/uses.rs", request("x", op));
        assert_eq!(
            folded(&index, &index.answer()),
            Completeness::Complete,
            "{op:?}"
        );
    }
    let index = index_one(&tree, "src/uses.rs", request("x", SymbolOp::Definition));
    assert_eq!(
        lines_of(&index.answer()),
        vec![("src/uses.rs".to_string(), 1)]
    );
}

#[test]
fn pinned_but_unindexed_document_is_never_complete_empty() {
    let corpus = symbol_corpus("unindexed");
    let pin = |path: &str, version: Option<i32>| DocumentPin {
        path: PathBuf::from(path),
        version,
        encoding: None,
    };
    let unresolved = |request: &rivect::context::Query, path: &str| {
        let result = query(request).expect("an unindexed pin still answers");
        assert!(result.matches.is_empty(), "{path}: no rows");
        assert_eq!(result.unresolved, vec![PathBuf::from(path)], "{path}");
        assert_eq!(
            result.completeness,
            partial(vec![PartialReason::UnresolvedPaths { count: 1 }]),
            "{path}"
        );
    };

    // Outside the caller's scope glob.
    let mut scoped = symbol_query(&corpus.path, "helper", SymbolOp::Definition);
    scoped.scope_glob = Some("src/app.ts".to_string());
    scoped.document = Some(pin("src/lib.rs", None));
    unresolved(&scoped, "src/lib.rs");

    // Ignored under Respect, a directory, an unclaimed language.
    for path in ["build/generated.rs", "src", "src/notes.py"] {
        let mut pinned = symbol_query(&corpus.path, "helper", SymbolOp::Definition);
        pinned.document = Some(pin(path, None));
        unresolved(&pinned, path);
    }

    // A pinned version that no indexed document can verify is refused.
    for path in ["src/notes.py", "build/generated.rs"] {
        let mut pinned = symbol_query(&corpus.path, "helper", SymbolOp::Definition);
        pinned.document = Some(pin(path, Some(1)));
        let err = query(&pinned).expect_err("an unverifiable version pin refuses");
        assert!(
            matches!(err, ContextError::UnverifiableDocumentVersion { .. }),
            "{path}: {err:?}"
        );
        assert_eq!(err.error_code(), ErrorCode::Conflict, "{path}: {err}");
    }
}

#[test]
fn pinned_type_query_serves_other_document_types_unresolved() {
    let tree = tree_of(
        "cross-file",
        &[
            ("src/types.rs", "pub struct Config;\n"),
            ("src/make.rs", "pub fn make() -> Config { Config }\n"),
        ],
    );
    let mut typed = symbol_query(&tree.path, "make", SymbolOp::Type);
    typed.document = Some(DocumentPin {
        path: PathBuf::from("src/make.rs"),
        version: None,
        encoding: None,
    });
    let result = query(&typed).expect("pinned type query resolves");
    assert_eq!(result.matches.len(), 1, "{:?}", result.matches);
    let row = symbol_hit(&result.matches[0]);
    assert_eq!(result.matches[0].source.path, Path::new("src/types.rs"));
    assert_eq!(
        (row.name.as_str(), row.symbol_kind.as_str()),
        ("Config", "struct")
    );
    // Served, never claimed: the type lives in another document, and
    // imports are not followed — so the edge is not certain.
    assert!(!row.resolved, "another document's type is never certain");
}

const BINDINGS_RS: &str = "fn config() {}
fn take(config: u8) -> u8 {
    config
}
fn closure() -> u8 {
    let f = |config: u8|
        config;
    let g = |(config, _): (u8, u8)| 0;
    let (config, other) = (1, 2);
    match Some(other) {
        Some(config) => {}
        None => {}
    }
    if let Some(config) = Some(other) {}
    for config in [1] {}
    f(1) + g((1, 2))
}
fn call() { config(); }
union U { a: u8 }
trait T { type Item; }
fn generic<config>(value: config) {}
fn konst<const config: usize>() -> usize { config }
use std::fmt as config;
";

const BINDINGS_TS: &str = "enum Color { Red, Green = 2 }
abstract class Shape { abstract area(): number; }
declare function sig(): void;
function take(config: number, { inner }: { inner: number }): number {
    return config + inner;
}
const [first, second] = [1, 2];
const handler = (config: number) =>
    config;
try { first; } catch (config) {
    second;
}
for (const config of [1]) {}
let config = 0;
for (config of [1]) {}
function id<config>(x: config): config { return x; }
const fe = function config() {};
const ce = class config {};
";

#[test]
fn binding_positions_are_never_reference_rows() {
    let tree = tree_of(
        "bindings",
        &[("src/bind.rs", BINDINGS_RS), ("src/shapes.ts", BINDINGS_TS)],
    );
    let refs = query(&symbol_query(&tree.path, "config", SymbolOp::References))
        .expect("references resolve");
    assert_eq!(
        lines_at(&refs, "src/bind.rs"),
        vec![3, 7, 18, 21, 22],
        "rust: params, closure params, let/match/if-let/for bindings, type and \
         const parameters and `use … as` aliases are never uses"
    );
    assert_eq!(
        lines_at(&refs, "src/shapes.ts"),
        vec![5, 9, 15, 16, 16],
        "typescript: params, catch, declared for-of, type parameters and \
         function/class expression names are never uses; a bare for-of \
         target is an assignment — a use"
    );
    // The root also holds the `use … as config` import, whose target the
    // index does not follow: the root call is unknown, never guessed as
    // the root `fn config`, and so is every local `config` — its pattern
    // may name what the import brings. Only the type parameter binds.
    assert_eq!(
        resolved_at(&refs, "src/bind.rs"),
        vec![(3, false), (7, false), (18, false), (21, true), (22, false)]
    );
    assert!(
        resolved_at(&refs, "src/shapes.ts")
            .iter()
            .all(|(_, resolved)| *resolved),
        "every typescript use binds lexically: {refs:?}"
    );
    let defs = query(&symbol_query(&tree.path, "config", SymbolOp::Definition))
        .expect("definitions resolve");
    assert_eq!(
        lines_at(&defs, "src/bind.rs"),
        vec![1, 2, 6, 8, 9, 11, 14, 15, 21, 22, 23]
    );
    assert_eq!(
        lines_at(&defs, "src/shapes.ts"),
        vec![4, 8, 10, 13, 14, 16, 17, 18]
    );
    // An uppercase bare pattern names a variant or constant — a use.
    let none =
        query(&symbol_query(&tree.path, "None", SymbolOp::References)).expect("references resolve");
    assert_eq!(lines_at(&none, "src/bind.rs"), vec![12]);
    let inner = query(&symbol_query(&tree.path, "inner", SymbolOp::References))
        .expect("references resolve");
    assert_eq!(lines_at(&inner, "src/shapes.ts"), vec![5]);
}

/// One definition per row of the Rust definition table, each under a
/// unique name.
const DEF_KINDS_RS: &str = "fn k_fn() {}
trait KTrait { type KAssoc; fn k_sig(); }
struct KStruct;
union KUnion { k_ufield: u8 }
enum KEnum { KVariant }
type KAlias = u8;
const K_CONST: u8 = 0;
static K_STATIC: u8 = 0;
mod k_mod {}
struct KFields { k_field: u8 }
fn k_host(k_param: u8) { let k_let = 0; }
macro_rules! k_macro { () => {} }
fn k_gen<KParam, const K_CPARAM: usize>() {}
use std::fmt as k_alias;
";

/// One definition per row of the TypeScript definition table.
const DEF_KINDS_TS: &str = "function tFn() {}
function* tGen() {}
declare function tSig(): void;
class TClass { tMethod() {} tField = 1; }
interface TIface { tMsig(): void; tProp: number; }
abstract class TAbs { abstract tAbsM(): void; }
enum TEnum { TBare, TSet = 2 }
type TType = number;
const tVar = 1;
function tHost(tReq: number, tOpt?: number) {}
namespace tNs {}
module tMod {}
function tGeneric<TParam>() {}
const tFe = function tFeName() {};
const tGe = function* tGeName() {};
const tCe = class TCeName {};
";

#[test]
fn every_admitted_definition_kind_is_a_definition_row() {
    let tree = tree_of(
        "def-kinds",
        &[
            ("src/kinds.rs", DEF_KINDS_RS),
            ("src/kinds.ts", DEF_KINDS_TS),
        ],
    );
    for (name, kind, scope) in [
        // rust: every definition-table row
        ("k_fn", "function", ""),
        ("k_sig", "method", "KTrait"),
        ("KStruct", "struct", ""),
        ("KUnion", "union", ""),
        ("KEnum", "enum", ""),
        ("KVariant", "member", "KEnum"),
        ("KTrait", "trait", ""),
        ("KAlias", "type", ""),
        ("KAssoc", "type", "KTrait"),
        ("K_CONST", "const", ""),
        ("K_STATIC", "static", ""),
        ("k_mod", "module", ""),
        ("k_ufield", "field", "KUnion"),
        ("k_field", "field", "KFields"),
        ("k_let", "variable", "k_host"),
        ("k_param", "parameter", "k_host"),
        ("k_macro", "macro", ""),
        ("KParam", "type_parameter", "k_gen"),
        ("K_CPARAM", "parameter", "k_gen"),
        ("k_alias", "alias", ""),
        // typescript: every definition-table row
        ("tFn", "function", ""),
        ("tGen", "function", ""),
        ("tSig", "function", ""),
        ("tMethod", "method", "TClass"),
        ("tMsig", "method", "TIface"),
        ("tAbsM", "method", "TAbs"),
        ("TClass", "class", ""),
        ("TAbs", "class", ""),
        ("TIface", "interface", ""),
        ("TEnum", "enum", ""),
        ("TBare", "member", "TEnum"),
        ("TSet", "member", "TEnum"),
        ("TType", "type", ""),
        ("tVar", "variable", ""),
        ("tReq", "parameter", "tHost"),
        ("tOpt", "parameter", "tHost"),
        ("tField", "field", "TClass"),
        ("tProp", "field", "TIface"),
        ("tNs", "namespace", ""),
        ("tMod", "namespace", ""),
        ("TParam", "type_parameter", "tGeneric"),
        // an expression's own name is scoped to the expression, which
        // no path addresses — the rendered scope skips it
        ("tFeName", "function", ""),
        ("tGeName", "function", ""),
        ("TCeName", "class", ""),
    ] {
        let result = query(&symbol_query(&tree.path, name, SymbolOp::Definition))
            .expect("definition query resolves");
        let rows = symbol_rows(&result);
        assert_eq!(rows.len(), 1, "{name}: {rows:?}");
        assert_eq!(
            (rows[0].symbol_kind.as_str(), rows[0].scope.as_str()),
            (kind, scope),
            "{name}"
        );
    }
}

const TYPES_TS: &str = "type User = { n: number };
const Account = 1;
type Account = { id: number };
let acct: Account;
";

const TYPES_RS: &str = "mod a {
    pub enum E { V }
    pub struct Token;
    pub fn helper() -> Token { Token }
}
mod c {
    pub struct Token;
}
pub fn lost() -> Missing { loop {} }
";

#[test]
fn type_queries_resolve_type_level_targets_only() {
    let tree = tree_of(
        "types",
        &[("src/user.ts", TYPES_TS), ("src/nested.rs", TYPES_RS)],
    );
    let type_of = |pattern: &str| {
        let result =
            query(&symbol_query(&tree.path, pattern, SymbolOp::Type)).expect("type query resolves");
        symbol_rows(&result)
            .iter()
            .map(|row| {
                (
                    row.name.clone(),
                    row.symbol_kind.clone(),
                    row.scope.clone(),
                    row.resolved,
                )
            })
            .collect::<Vec<_>>()
    };
    let row = |name: &str, kind: &str, scope: &str, resolved: bool| {
        (
            name.to_string(),
            kind.to_string(),
            scope.to_string(),
            resolved,
        )
    };
    // A type-level name is its own type — never a property inside it.
    assert_eq!(type_of("User"), vec![row("User", "type", "", true)]);
    // The annotation names a type, never the same-name value.
    assert_eq!(type_of("acct"), vec![row("Account", "type", "", true)]);
    // An enum member's type is its enum, found in the enum's scope.
    assert_eq!(type_of("V"), vec![row("E", "enum", "a", true)]);
    // The nearest enclosing `Token` — never the sibling module's.
    assert_eq!(
        type_of("a::helper"),
        vec![row("Token", "struct", "a", true)]
    );
    // An annotation naming nothing in coverage stays unknown, at the
    // spelling site.
    assert_eq!(type_of("lost"), vec![row("Missing", "type", "", false)]);
}

const SHADOW_RS: &str = "mod a {
    pub fn helper() {}
    mod b {
        pub fn helper() {}
        fn y() { helper(); }
    }
    fn z() { helper(); }
}
fn w() { zzz::helper(); a::helper(); }
mod m { pub struct Foo; impl Foo { pub fn new() {} } }
";

#[test]
fn references_bind_lexically_not_by_name_prefix() {
    let tree = tree_of("shadow", &[("src/shadow.rs", SHADOW_RS)]);
    // `y`'s bare call binds the nearer `a::b::helper` — never `a::helper`.
    // `zzz::helper()` binds nowhere — it is served unresolved rather
    // than dropped from the qualified answer.
    let refs = query(&symbol_query(&tree.path, "a::helper", SymbolOp::References))
        .expect("qualified references resolve");
    assert_eq!(
        resolved_at(&refs, "src/shadow.rs"),
        vec![(7, true), (9, false), (9, true)]
    );
    // A qualifier naming no scope in coverage stays unknown.
    let refs = query(&symbol_query(&tree.path, "helper", SymbolOp::References))
        .expect("bare references resolve");
    let resolved: Vec<(u64, bool)> = refs
        .matches
        .iter()
        .map(|hit| (hit.source.line.expect("line"), symbol_hit(hit).resolved))
        .collect();
    assert_eq!(
        resolved,
        vec![(5, true), (7, true), (9, false), (9, true)],
        "zzz::helper has no zzz — unknown, never guessed"
    );
    // A qualified definition query matches the scope's trailing
    // segments — `Foo::new` addresses `m::Foo::new`.
    let defs = query(&symbol_query(&tree.path, "Foo::new", SymbolOp::Definition))
        .expect("qualified definition resolves");
    let rows = symbol_rows(&defs);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].scope, "m::Foo");
}

#[test]
fn local_bindings_never_resolve_across_documents() {
    // Two files, one function path `take`: only one declares the
    // parameter. No import can name a local, so the other file's bare
    // `config` stays unknown — and so does a use of another document's
    // item (`helper`): imports are not followed, so a candidate outside
    // the use's own document is never certain.
    let tree = tree_of(
        "locals",
        &[
            ("src/a.rs", "fn take(config: u8) -> u8 { config }\n"),
            ("src/b.rs", "fn take() -> u8 { config }\nfn helper() {}\n"),
            ("src/c.rs", "fn call() { helper(); }\n"),
            ("src/a.ts", "const config = 1;\n"),
            ("src/b.ts", "config;\n"),
        ],
    );
    let refs = query(&symbol_query(&tree.path, "config", SymbolOp::References))
        .expect("references resolve");
    let resolved: Vec<(&Path, bool)> = refs
        .matches
        .iter()
        .map(|hit| (hit.source.path.as_path(), symbol_hit(hit).resolved))
        .collect();
    assert_eq!(
        resolved,
        vec![
            (Path::new("src/a.rs"), true),
            (Path::new("src/b.rs"), false),
            (Path::new("src/b.ts"), false),
        ]
    );
    let refs = query(&symbol_query(&tree.path, "helper", SymbolOp::References))
        .expect("references resolve");
    assert_eq!(symbol_rows(&refs).len(), 1);
    assert!(
        !symbol_rows(&refs)[0].resolved,
        "another document's item is never certain"
    );
}

#[test]
fn typescript_scopes_shadow_like_rust() {
    let source = "namespace a {
    function helper() {}
    namespace b {
        function helper() {}
        function y() { helper(); }
    }
    function z() { helper(); }
}
";
    let tree = tree_of("ts-shadow", &[("src/shadow.ts", source)]);
    let refs = query(&symbol_query(&tree.path, "a::helper", SymbolOp::References))
        .expect("qualified references resolve");
    assert_eq!(lines_at(&refs, "src/shadow.ts"), vec![7]);
    let refs = query(&symbol_query(
        &tree.path,
        "a::b::helper",
        SymbolOp::References,
    ))
    .expect("qualified references resolve");
    assert_eq!(lines_at(&refs, "src/shadow.ts"), vec![5]);
}

#[test]
fn pinned_include_serves_the_ignored_document_flagged() {
    let corpus = symbol_corpus("pin-include");
    let mut pinned = symbol_query(&corpus.path, "generated", SymbolOp::Definition);
    pinned.ignore = IgnorePolicy::Include;
    pinned.document = Some(DocumentPin {
        path: PathBuf::from("build/generated.rs"),
        version: None,
        encoding: None,
    });
    let result = query(&pinned).expect("an included pin resolves");
    assert_eq!(result.matches.len(), 1, "{:?}", result.matches);
    assert!(result.matches[0].source.ignored, "flagged, never ordinary");
    assert_eq!(result.completeness, Completeness::Complete);
    assert!(result.unresolved.is_empty());
}

#[test]
fn reference_interface_name_never_serves_definitions() {
    let corpus = symbol_corpus("interface-name");
    // Through the interface name alone: the name routes the kind and
    // carries the op — `code.references` answers uses, `code.symbol`
    // definitions, and neither can fall back to the other.
    let by_name = |name: &str| {
        let mut request = search_query(
            QueryKind::from_name(name).expect("recorded name"),
            &corpus.path,
            "helper",
        );
        request.symbol_op = SymbolOp::from_interface_name(name);
        query(&request).expect("the named query resolves")
    };
    let refs = symbol_rows(&by_name("code.references"))
        .iter()
        .map(|row| row.role)
        .collect::<Vec<_>>();
    assert_eq!(refs, vec![SymbolRole::Reference; 3]);
    let defs = symbol_rows(&by_name("code.symbol"))
        .iter()
        .map(|row| row.role)
        .collect::<Vec<_>>();
    assert_eq!(defs, vec![SymbolRole::Definition; 3]);
    for name in ["search.text", "code.impact", "bogus"] {
        assert_eq!(SymbolOp::from_interface_name(name), None, "{name}");
    }
    // An op-less symbol query is refused — never defaulted.
    let err = query(&search_query(QueryKind::Symbol, &corpus.path, "helper"))
        .expect_err("an op-less symbol query refuses");
    assert!(matches!(err, ContextError::SymbolOpRequired), "{err:?}");
    assert_eq!(err.error_code(), ErrorCode::InvalidInput);
}

#[test]
fn symbol_pattern_bound_is_exact() {
    let corpus = symbol_corpus("pattern-bound");
    let at = "x".repeat(1024);
    query(&symbol_query(&corpus.path, &at, SymbolOp::Definition))
        .expect("a 1024-byte pattern is served");
    let over = "x".repeat(1025);
    let err = query(&symbol_query(&corpus.path, &over, SymbolOp::Definition))
        .expect_err("a 1025-byte pattern is refused");
    assert!(
        matches!(err, ContextError::SymbolPatternTooLarge { limit: 1024 }),
        "{err:?}"
    );
    assert_eq!(err.error_code(), ErrorCode::InvalidInput);
}

#[test]
fn unsupported_encoding_never_echoes_caller_text() {
    let corpus = symbol_corpus("encoding-echo");
    let hostile = "z".repeat(4096);
    let mut pinned = symbol_query(&corpus.path, "helper", SymbolOp::Definition);
    pinned.document = Some(DocumentPin {
        path: PathBuf::from("src/lib.rs"),
        version: None,
        encoding: Some(lsp_types::PositionEncodingKind::from(hostile.clone())),
    });
    let err = query(&pinned).expect_err("an unknown encoding refuses");
    assert!(
        matches!(
            err,
            ContextError::UnsupportedPositionEncoding {
                encoding: "unrecognized"
            }
        ),
        "{err:?}"
    );
    assert!(
        !err.to_string().contains(&hostile[..64]),
        "caller text is never echoed: {err}"
    );
    // The other LSP-defined encoding the index does not serve names
    // itself, never another's string.
    pinned.document = Some(DocumentPin {
        path: PathBuf::from("src/lib.rs"),
        version: None,
        encoding: Some(lsp_types::PositionEncodingKind::UTF32),
    });
    let err = query(&pinned).expect_err("a utf-32 pin refuses");
    assert!(
        matches!(
            err,
            ContextError::UnsupportedPositionEncoding { encoding: "utf-32" }
        ),
        "{err:?}"
    );
    assert_eq!(err.error_code(), ErrorCode::InvalidInput);
}

// ----- resolution certainty (DEC-024, amended by DEC-025) -----

/// `(line, resolved)` for every typed row at `path`, in answer order.
fn resolved_at(result: &QueryResult, path: &str) -> Vec<(u64, bool)> {
    result
        .matches
        .iter()
        .filter(|hit| {
            matches!(hit.kind, MatchKind::Symbol(_)) && hit.source.path == Path::new(path)
        })
        .map(|hit| {
            (
                hit.source.line.expect("a symbol row carries a line"),
                symbol_hit(hit).resolved,
            )
        })
        .collect()
}

const MEMBERS_RS: &str = "struct S { len: u8 }
fn f(s: S) -> u8 {
    let len = 1;
    let t = S { len: 2 };
    let u = S { len };
    let S { len: w } = t;
    s.len + len
}
mod a {
    pub fn helper() {}
    fn g(x: X) { x.helper(); helper(); }
}
";

const MEMBERS_TS: &str = "function helper() {}
const o = { helper: 1 };
o.helper;
helper();
";

#[test]
fn receiver_qualified_access_never_binds_lexically() {
    let tree = tree_of(
        "members",
        &[
            ("src/members.rs", MEMBERS_RS),
            ("src/members.ts", MEMBERS_TS),
        ],
    );
    // A field or member name belongs to its receiver's type, which the
    // index does not model: `s.len`, `S { len: 2 }` and `S { len: w }`
    // stay unknown — only the shorthand `S { len }` and the bare `len`
    // are genuine lexical uses of the local.
    let refs =
        query(&symbol_query(&tree.path, "len", SymbolOp::References)).expect("references resolve");
    assert_eq!(
        resolved_at(&refs, "src/members.rs"),
        vec![(4, false), (5, true), (6, false), (7, false), (7, true)]
    );
    // `x.helper()` is a method call on an unknown receiver — never a
    // certain use of `a::helper`, so it is served unresolved; the bare
    // call beside it binds.
    let refs = query(&symbol_query(&tree.path, "a::helper", SymbolOp::References))
        .expect("qualified references resolve");
    assert_eq!(
        resolved_at(&refs, "src/members.rs"),
        vec![(11, false), (11, true)]
    );
    // TypeScript: an object key and a property access never bind the
    // top-level function.
    let refs = query(&symbol_query(&tree.path, "helper", SymbolOp::References))
        .expect("references resolve");
    assert_eq!(
        resolved_at(&refs, "src/members.ts"),
        vec![(2, false), (3, false), (4, true)]
    );
}

#[test]
fn candidates_spanning_documents_are_ambiguous_not_resolved() {
    let tree = tree_of(
        "ambiguous",
        &[
            (
                "src/a.rs",
                "pub struct Token;\npub fn mine() -> Token { Token }\n",
            ),
            ("src/b.rs", "pub struct Token;\n"),
            ("src/c.rs", "pub fn helper() -> Token { loop {} }\n"),
        ],
    );
    let type_of = |pattern: &str| {
        let result =
            query(&symbol_query(&tree.path, pattern, SymbolOp::Type)).expect("type query resolves");
        result
            .matches
            .iter()
            .map(|hit| {
                let row = symbol_hit(hit);
                (
                    hit.source.path.to_string_lossy().into_owned(),
                    row.name.clone(),
                    row.resolved,
                )
            })
            .collect::<Vec<_>>()
    };
    // Two documents define a root `Token` and the use's own defines
    // none: either could be meant — both served, neither claimed.
    assert_eq!(
        type_of("helper"),
        vec![
            ("src/a.rs".to_string(), "Token".to_string(), false),
            ("src/b.rs".to_string(), "Token".to_string(), false),
        ]
    );
    // The use's own document defines one — it wins, certainly.
    assert_eq!(
        type_of("mine"),
        vec![("src/a.rs".to_string(), "Token".to_string(), true)]
    );
    let refs = query(&symbol_query(&tree.path, "Token", SymbolOp::References))
        .expect("references resolve");
    assert_eq!(resolved_at(&refs, "src/a.rs"), vec![(2, true), (2, true)]);
    assert_eq!(resolved_at(&refs, "src/c.rs"), vec![(1, false)]);
}

const DECL_ORDER_RS: &str = "fn helper() {}
fn f() { helper(); let helper = 1; }
fn g() { let c = |helper: u8| helper; helper(); }
fn m(o: Option<u8>, config: u8) -> u8 { if let Some(config) = o { config } else { config } }
fn n(config: u8) -> u8 { let c = |o: Option<u8>| match o { Some(config) => config, None => config }; c(None) }
fn k(helper: u8) { let helper = helper + 1; }
";

#[test]
fn anonymous_scopes_and_declaration_order_bind_locals() {
    let tree = tree_of("decl-order", &[("src/order.rs", DECL_ORDER_RS)]);
    // A call before a later `let` binds the outer item; a closure's
    // parameter binds only inside the closure. The file's top level is
    // module `order`, not the crate root.
    let refs = query(&symbol_query(
        &tree.path,
        "order::helper",
        SymbolOp::References,
    ))
    .expect("top-level references resolve");
    assert_eq!(lines_at(&refs, "src/order.rs"), vec![2, 3]);
    let refs = query(&symbol_query(&tree.path, "helper", SymbolOp::References))
        .expect("references resolve");
    assert_eq!(
        resolved_at(&refs, "src/order.rs"),
        vec![(2, true), (3, true), (3, true), (6, true)]
    );
    // `let helper = helper + 1` reads the parameter, not itself.
    let refs = query(&symbol_query(&tree.path, "k::helper", SymbolOp::References))
        .expect("parameter references resolve");
    assert_eq!(lines_at(&refs, "src/order.rs"), vec![6]);
    // The parameter and the `if let`/arm binding both live in `m`/`n`: the
    // qualifier that defines both answers the certain uses of both.
    let refs = query(&symbol_query(&tree.path, "m::config", SymbolOp::References))
        .expect("parameter references resolve");
    assert_eq!(
        resolved_at(&refs, "src/order.rs"),
        vec![(4, true), (4, true)]
    );
    let refs = query(&symbol_query(&tree.path, "n::config", SymbolOp::References))
        .expect("parameter references resolve");
    assert_eq!(
        resolved_at(&refs, "src/order.rs"),
        vec![(5, true), (5, true)]
    );
    // An `if let` binding is not visible in the `else` branch; a match
    // arm's binding is not visible in the next arm — there the root
    // function is what the call names.
    let tree = tree_of(
        "decl-order-leak",
        &[(
            "src/lib.rs",
            "fn config() {}\n\
             fn m(o: Option<u8>) { if let Some(config) = o { config; } else { config(); } }\n\
             fn n(o: Option<u8>) { match o { Some(config) => { config; } None => { config(); } } }\n",
        )],
    );
    let refs = query(&symbol_query(&tree.path, "::config", SymbolOp::References))
        .expect("root references resolve");
    assert_eq!(resolved_at(&refs, "src/lib.rs"), vec![(2, true), (3, true)]);
}

#[test]
fn typescript_anonymous_scopes_match_rust() {
    let tree = tree_of(
        "ts-anonymous",
        &[
            (
                "src/ns.ts",
                "namespace a {
    export function helper() {}
    helper();
    export const f = (helper: () => void) => helper();
}
",
            ),
            (
                "src/order.ts",
                "function helper() {}
function f() { helper(); let helper = 1; }
function g() { const c = (helper: number) => helper; helper(); }
for (const { helper } of [{ helper: 1 }]) { helper; }
",
            ),
        ],
    );
    // An arrow's parameter shadows the namespace's function only inside
    // the arrow — both live in `a`, so `a::helper` answers each certain
    // use.
    let refs = query(&symbol_query(&tree.path, "a::helper", SymbolOp::References))
        .expect("qualified references resolve");
    assert_eq!(resolved_at(&refs, "src/ns.ts"), vec![(3, true), (4, true)]);
    // A use before a later `let` in the same block is in its temporal
    // dead zone — it names the local, not the outer function, so the
    // edge stays unknown rather than claimed for either. A destructured
    // for-of binding is scoped to the loop.
    let refs = query(&symbol_query(&tree.path, "helper", SymbolOp::References))
        .expect("references resolve");
    assert_eq!(
        resolved_at(&refs, "src/order.ts"),
        vec![(2, false), (3, true), (3, true), (4, false), (4, true)]
    );
    // The dead zone shadows even an item another document defines in
    // the same (shared root) scope.
    let tree = tree_of(
        "ts-dead-zone",
        &[
            ("src/a.ts", "function helper() {}\n"),
            ("src/b.ts", "helper();\nlet helper = 1;\n"),
        ],
    );
    let refs = query(&symbol_query(&tree.path, "helper", SymbolOp::References))
        .expect("references resolve");
    assert_eq!(resolved_at(&refs, "src/b.ts"), vec![(1, false)]);
}

#[test]
fn unbound_qualified_uses_are_served_unresolved() {
    let tree = tree_of(
        "unbound-qualified",
        &[(
            "src/lib.rs",
            "fn w() { crate::zzz::helper(); self::zzz::helper(); zzz::helper(); }\n",
        )],
    );
    // No `zzz` exists, so none binds — each stays unknown but is still
    // served by a qualified answer.
    let refs = query(&symbol_query(
        &tree.path,
        "zzz::helper",
        SymbolOp::References,
    ))
    .expect("references resolve");
    let rows = symbol_rows(&refs);
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert!(rows.iter().all(|row| !row.resolved));
    // Anchored at the crate root: a spelling that binds nowhere could
    // still name it through an unfollowed import — every such use is
    // served, unresolved, never dropped as an absence.
    let refs = query(&symbol_query(
        &tree.path,
        "crate::zzz::helper",
        SymbolOp::References,
    ))
    .expect("references resolve");
    let rows = symbol_rows(&refs);
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert!(rows.iter().all(|row| !row.resolved));
}

// ----- binding certainty (DEC-025) -----

const MEMBER_BEARERS_RS: &str = "struct S { config: u8 }
fn config() {}
impl S { fn f(&self) { config(); } }
struct T;
impl T { fn new() -> T { T } fn g() { new(); } }
enum E { A }
impl E { fn h() { A; } }
";

const MEMBER_BEARERS_TS: &str = "function validate() {}
class C { validate() { return validate(); } }
type Opts = { config: number };
config;
const h = { save() {} };
save();
class Api { fetch() { return fetch(1); } }
";

#[test]
fn members_are_never_bare_lexical_candidates() {
    let tree = tree_of(
        "member-bearers",
        &[
            ("src/member.rs", MEMBER_BEARERS_RS),
            ("src/member.ts", MEMBER_BEARERS_TS),
        ],
    );
    let refs = |pattern: &str, path: &str| {
        let result = query(&symbol_query(&tree.path, pattern, SymbolOp::References))
            .expect("references resolve");
        resolved_at(&result, path)
    };
    // A struct field shares the method's scope; the bare call inside
    // the impl still names the file's top-level function (module
    // `member`), never `S::config`.
    assert_eq!(refs("member::config", "src/member.rs"), vec![(3, true)]);
    assert_eq!(refs("S::config", "src/member.rs"), vec![]);
    // An associated function or a variant is not in scope bare.
    assert_eq!(refs("new", "src/member.rs"), vec![(5, false)]);
    assert_eq!(refs("A", "src/member.rs"), vec![(7, false)]);
    // TypeScript: a class method delegating to the same-name root
    // function binds the root; object-type fields and object-literal
    // methods are never root candidates.
    assert_eq!(refs("::validate", "src/member.ts"), vec![(2, true)]);
    assert_eq!(refs("C::validate", "src/member.ts"), vec![]);
    assert_eq!(refs("config", "src/member.ts"), vec![(4, false)]);
    assert_eq!(refs("save", "src/member.ts"), vec![(6, false)]);
    assert_eq!(refs("fetch", "src/member.ts"), vec![(7, false)]);
}

#[test]
fn other_documents_imports_and_module_boundaries_are_never_certain() {
    let token_refs = |tree: &TempTree, name: &str, path: &str| {
        let result = query(&symbol_query(&tree.path, name, SymbolOp::References))
            .expect("references resolve");
        resolved_at(&result, path)
    };
    // A single candidate in another document is not certain: the use's
    // own import names some other `Token`.
    let tree = tree_of(
        "import-leaf",
        &[
            ("src/a.rs", "pub struct Token;\n"),
            ("src/c.rs", "use external::Token;\nfn f(t: Token) {}\n"),
        ],
    );
    assert_eq!(
        token_refs(&tree, "Token", "src/c.rs"),
        vec![(1, false), (2, false)]
    );
    let tree = tree_of(
        "ts-import",
        &[
            ("src/a.ts", "export class Token {}\n"),
            (
                "src/c.ts",
                "import { Token } from \"lib\";\nlet t: Token;\n",
            ),
        ],
    );
    assert_eq!(
        token_refs(&tree, "Token", "src/c.ts"),
        vec![(1, false), (2, false)]
    );
    // The prelude's `Result` is not another file's `type Result`.
    let tree = tree_of(
        "prelude",
        &[
            ("src/e.rs", "fn f() -> Result<(), ()> { Ok(()) }\n"),
            ("src/r.rs", "pub type Result = u8;\n"),
        ],
    );
    assert_eq!(token_refs(&tree, "Result", "src/e.rs"), vec![(1, false)]);
    let typed = query(&symbol_query(&tree.path, "f", SymbolOp::Type)).expect("type resolves");
    assert_eq!(
        resolved_at(&typed, "src/r.rs"),
        vec![(1, false)],
        "the other document's candidate is served, never claimed"
    );
    // A bare name does not cross a `mod` boundary; an import on the
    // chain makes the name unknown.
    let tree = tree_of(
        "mod-boundary",
        &[(
            "src/d.rs",
            "struct Token;\n\
             mod m { use external::Token; fn f(_: Token) {} }\n\
             mod n { fn g(_: Token) {} }\n\
             fn k(_: Token) {}\n",
        )],
    );
    assert_eq!(
        token_refs(&tree, "Token", "src/d.rs"),
        vec![(2, false), (2, false), (3, false), (4, true)]
    );
    // Own-document preference is per lookup: `b.rs`'s `mod tests` never
    // borrows `a.rs`'s `tests::fixture` for a bare call.
    let tree = tree_of(
        "mod-tests",
        &[
            ("src/a.rs", "mod tests { fn fixture() {} }\n"),
            (
                "src/b.rs",
                "fn fixture() {}\nmod tests { fn t() { fixture(); } }\n",
            ),
        ],
    );
    assert_eq!(token_refs(&tree, "fixture", "src/b.rs"), vec![(2, false)]);
    assert_eq!(
        token_refs(&tree, "tests::fixture", "src/b.rs"),
        vec![(2, false)]
    );
}

#[test]
fn qualified_answers_serve_every_unbindable_use() {
    let tree = tree_of(
        "unbindable",
        &[
            (
                "src/ns.ts",
                "namespace a { export function helper() {} }\na.helper();\n",
            ),
            (
                "src/m.rs",
                "mod a { pub fn helper() {} }\nfn f(x: X) { x.helper(); }\n",
            ),
        ],
    );
    let result = query(&symbol_query(&tree.path, "a::helper", SymbolOp::References))
        .expect("qualified references resolve");
    // Never Complete-empty for a name that is used: the receiver calls
    // cannot be bound, so they are served unresolved.
    assert_eq!(resolved_at(&result, "src/ns.ts"), vec![(2, false)]);
    assert_eq!(resolved_at(&result, "src/m.rs"), vec![(2, false)]);
}

#[test]
fn path_segments_macro_names_and_signature_params_never_bind() {
    let tree = tree_of(
        "opaque-positions",
        &[
            (
                "src/seg.rs",
                "mod config { pub const DEFAULT: u8 = 0; pub fn load() -> u8 { 0 } }\n\
                 fn f() -> u8 { let config = config::load(); config::DEFAULT + config }\n",
            ),
            (
                "src/fmt.rs",
                "use std::fmt;\n\
                 struct S;\n\
                 fn write() {}\n\
                 impl fmt::Display for S {\n\
                 \x20   fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, \"s\") }\n\
                 }\n",
            ),
            (
                "src/sig.rs",
                "trait T { fn m(x: u8); fn d(&self) -> u8 { x } }\n",
            ),
            (
                "src/handler.ts",
                "type Handler = (event: Event) => void;\nevent;\n",
            ),
            (
                "src/sig.ts",
                "declare function sig<T>(x: T): T;\nlet y: T;\nx;\n",
            ),
        ],
    );
    let refs = |pattern: &str, path: &str| {
        let result = query(&symbol_query(&tree.path, pattern, SymbolOp::References))
            .expect("references resolve");
        resolved_at(&result, path)
    };
    // Path qualifier segments are never bound; the bare local is.
    assert_eq!(
        refs("config", "src/seg.rs"),
        vec![(2, false), (2, false), (2, true)]
    );
    // A macro name is not the same-name function; `fmt` path segments
    // and the import leaf never bind to the `fmt` method.
    assert_eq!(refs("write", "src/fmt.rs"), vec![(5, false)]);
    assert_eq!(
        refs("fmt", "src/fmt.rs"),
        vec![(1, false), (4, false), (5, false), (5, false)]
    );
    // A signature's parameters never leak into the enclosing scope.
    assert_eq!(refs("x", "src/sig.rs"), vec![(1, false)]);
    assert_eq!(refs("event", "src/handler.ts"), vec![(2, false)]);
    assert_eq!(refs("x", "src/sig.ts"), vec![(3, false)]);
    assert_eq!(
        refs("T", "src/sig.ts"),
        vec![(1, true), (1, true), (2, false)]
    );
}

#[test]
fn same_name_sibling_functions_keep_their_own_parameters() {
    let tree = tree_of(
        "sibling-params",
        &[(
            "src/twins.rs",
            "#[cfg(a)] fn f(x: u8) -> u8 { x }\n#[cfg(b)] fn f(y: u8) -> u8 { x }\n",
        )],
    );
    let refs =
        query(&symbol_query(&tree.path, "x", SymbolOp::References)).expect("references resolve");
    assert_eq!(
        resolved_at(&refs, "src/twins.rs"),
        vec![(1, true), (2, false)]
    );
}

#[test]
fn dotted_namespace_keeps_its_contents_inside() {
    let tree = tree_of(
        "dotted-namespace",
        &[(
            "src/dotted.ts",
            "namespace a.b { export function helper() {} }\nhelper();\n",
        )],
    );
    let refs = query(&symbol_query(&tree.path, "helper", SymbolOp::References))
        .expect("references resolve");
    assert_eq!(resolved_at(&refs, "src/dotted.ts"), vec![(2, false)]);
}

#[test]
fn several_own_document_candidates_are_never_certain() {
    let tree = tree_of(
        "cfg-twins",
        &[(
            "src/twins.rs",
            "#[cfg(a)] struct T;\n#[cfg(b)] struct T;\nfn g() -> T { loop {} }\n",
        )],
    );
    let typed = query(&symbol_query(&tree.path, "g", SymbolOp::Type)).expect("type resolves");
    assert_eq!(
        resolved_at(&typed, "src/twins.rs"),
        vec![(1, false), (2, false)]
    );
    let refs =
        query(&symbol_query(&tree.path, "T", SymbolOp::References)).expect("references resolve");
    assert_eq!(resolved_at(&refs, "src/twins.rs"), vec![(3, false)]);
}

#[test]
fn macro_super_label_and_lifetime_uses_never_bind() {
    let tree = tree_of(
        "dec024-rules",
        &[(
            "src/rules.rs",
            "fn h() {}\n\
             mod m { fn h() {} fn g() { println!(\"{}\", h); super::h(); 'h: loop { break 'h; } } }\n\
             fn f<'h>(x: &'h u8) {}\n\
             fn k() { println!(\"{}\", h); h(); }\n",
        )],
    );
    let refs =
        query(&symbol_query(&tree.path, "h", SymbolOp::References)).expect("references resolve");
    // The macro's token tree and the `super::` path stay unknown — even
    // beside the root `h` a plain call binds, and with `m`'s own `h`
    // there for `super` misread as `self::` or dropped to bind; a label
    // or lifetime spelled `h` is no symbol row at all.
    assert_eq!(
        resolved_at(&refs, "src/rules.rs"),
        vec![(2, false), (2, false), (4, false), (4, true)]
    );
}

#[test]
fn local_visibility_ranges_follow_their_constructs() {
    let tree = tree_of(
        "visibility",
        &[
            (
                "src/vis.rs",
                "fn a(o: Option<u8>) -> u8 {\n\
                 \x20   while let Some(x) = o { x; }\n\
                 \x20   x\n\
                 }\n\
                 fn b(o: Option<u8>) -> u8 {\n\
                 \x20   let Some(x) = o else { return x; };\n\
                 \x20   x\n\
                 }\n\
                 fn c() -> u8 {\n\
                 \x20   let x = 1;\n\
                 \x20   { let x = 2; x; }\n\
                 \x20   x\n\
                 }\n",
            ),
            (
                "src/vis.ts",
                "function s(v: number) {\n\
                 \x20   switch (v) { case 1: let y = 1; y; }\n\
                 \x20   y;\n\
                 \x20   try {} catch (y) { y; }\n\
                 \x20   y;\n\
                 }\n",
            ),
        ],
    );
    let refs =
        query(&symbol_query(&tree.path, "x", SymbolOp::References)).expect("references resolve");
    assert_eq!(
        resolved_at(&refs, "src/vis.rs"),
        vec![
            (2, true),
            (3, false),
            (6, false),
            (7, true),
            (11, true),
            (12, true)
        ]
    );
    let refs =
        query(&symbol_query(&tree.path, "y", SymbolOp::References)).expect("references resolve");
    assert_eq!(
        resolved_at(&refs, "src/vis.ts"),
        vec![(2, true), (3, false), (4, true), (5, false)]
    );
}

#[test]
fn qualified_definitions_address_anonymous_scopes_inside_the_named_one() {
    // The row renders scope `f` — the query `f::x` finds it.
    let tree = tree_of(
        "anonymous-definition",
        &[("src/anon.rs", "fn f() { { let x = 1; } }\n")],
    );
    let defs = query(&symbol_query(&tree.path, "f::x", SymbolOp::Definition))
        .expect("definitions resolve");
    let rows = symbol_rows(&defs);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].scope, "f");
}

#[test]
fn qualified_references_answer_what_the_same_qualifier_defines() {
    // A local in an anonymous scope renders its named scope: the
    // qualifier that finds its definition finds its certain uses too.
    let tree = tree_of(
        "anonymous-references",
        &[
            ("src/anon.rs", "fn f() { let x = 1; x + 1; }\n"),
            ("src/anon.ts", "function outer() { const g = (p) => p; }\n"),
            (
                "src/lib.rs",
                "fn helper() {}\nfn f() { { let helper = 1; helper; } helper(); }\n",
            ),
        ],
    );
    let answer = |pattern: &str, op: SymbolOp| {
        let result = query(&symbol_query(&tree.path, pattern, op)).expect("query resolves");
        assert_eq!(result.completeness, Completeness::Complete, "{pattern}");
        result
    };
    for (pattern, path) in [("f::x", "src/anon.rs"), ("outer::p", "src/anon.ts")] {
        let defs = answer(pattern, SymbolOp::Definition);
        assert_eq!(lines_at(&defs, path), vec![1], "{pattern}");
        let refs = answer(pattern, SymbolOp::References);
        assert_eq!(resolved_at(&refs, path), vec![(1, true)], "{pattern}");
    }
    // A shadowing local answers its own named scope; the use past its
    // block still binds the root function — nothing dropped, nothing
    // newly claimed.
    let refs = answer("f::helper", SymbolOp::References);
    assert_eq!(resolved_at(&refs, "src/lib.rs"), vec![(2, true)]);
    let refs = answer("::helper", SymbolOp::References);
    assert_eq!(resolved_at(&refs, "src/lib.rs"), vec![(2, true)]);
    let refs = answer("helper", SymbolOp::References);
    assert_eq!(resolved_at(&refs, "src/lib.rs"), vec![(2, true), (2, true)]);
}

#[test]
fn type_parameters_of_unrelated_documents_never_spend_the_row_budget() {
    // A full row budget of type parameters in a document no subject
    // lives in: pooled, they would leave no row for the next file.
    let generics = "fn g<T>() {}\n".repeat(MAX_SYMBOL_ROWS);
    let tree = tree_of(
        "type-param-pool",
        &[
            ("src/generic.rs", &generics),
            ("src/p.rs", "fn p<T>() -> T { loop {} }\n"),
            ("src/q.rs", "type Q = u8;\n"),
        ],
    );
    let files = ["src/generic.rs", "src/p.rs", "src/q.rs"];
    let index = index_files(&tree, &files, request("Q", SymbolOp::Type));
    let answer = index.answer();
    assert_eq!(lines_of(&answer), vec![("src/q.rs".to_string(), 1)]);
    assert_eq!(folded(&index, &answer), Completeness::Complete);
    // A document holding the subject keeps its own type parameters.
    let answer = index_files(&tree, &files, request("p", SymbolOp::Type)).answer();
    let rows: Vec<&SymbolMatch> = answer.matches.iter().map(symbol_hit).collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        (rows[0].symbol_kind.as_str(), rows[0].scope.as_str()),
        ("type_parameter", "p")
    );
    assert!(rows[0].resolved);
}

/// `(file, name, source, expected (line, resolved) per use)` — one
/// document per case, so no case's items reach another.
type BindingCase = (
    &'static str,
    &'static str,
    &'static str,
    &'static [(u64, bool)],
);

const ADJACENT_FORMS: &[BindingCase] = &[
    // Generic arguments, where clauses, bounds: type positions bind.
    (
        "args.rs",
        "A",
        "struct A; fn f() -> Vec<A> { loop {} }\n",
        &[(1, true)],
    ),
    (
        "where.rs",
        "T",
        "trait Tr {} fn g<T>() where T: Tr {}\n",
        &[(1, true)],
    ),
    (
        "bound.rs",
        "Tr",
        "trait Tr {} fn g<T>() where T: Tr {}\n",
        &[(1, true)],
    ),
    // A struct's and its impl's generics share the scope `S`; each is
    // visible over its own owner only. An alias's never leaks.
    (
        "impl.rs",
        "T",
        "struct S<T>(T);\nimpl<T> S<T> { fn f(_: T) {} }\n",
        &[(1, true), (2, true), (2, true)],
    ),
    (
        "alias.rs",
        "T",
        "type Alias<T> = Vec<T>;\nfn f(_: T) {}\n",
        &[(1, true), (2, false)],
    ),
    (
        "alias.ts",
        "T",
        "type Box<T> = { v: T };\nlet b: T;\n",
        &[(1, true), (2, false)],
    ),
    // Closures and async blocks capture; a nested fn item does not — but
    // it still sees the items of the body around it.
    (
        "closure.rs",
        "x",
        "fn h() { let x = 1; let c = || x; }\n",
        &[(1, true)],
    ),
    (
        "async.rs",
        "x",
        "async fn a() { let x = 1; async { x }; }\n",
        &[(1, true)],
    ),
    (
        "nested.rs",
        "x",
        "fn outer() { let x = 1; fn inner() -> u8 { x } }\n",
        &[(1, false)],
    ),
    (
        "generic.rs",
        "T",
        "fn outer<T>() { fn inner(_: T) {} }\n",
        &[(1, false)],
    ),
    (
        "sibling.rs",
        "a",
        "fn outer() { fn a() {} fn b() { a(); } }\n",
        &[(1, true)],
    ),
    (
        "const.rs",
        "C",
        "fn outer() { const C: u8 = 1; fn inner() -> u8 { C } }\n",
        &[(1, true)],
    ),
    // Anchored paths; a `use` in a body and a glob make a name unknown.
    // `crate::` outside a crate-root document names another file's root.
    (
        "crate.rs",
        "helper",
        "mod a { pub fn helper() {} }\nmod b { fn g() { crate::a::helper(); } }\n",
        &[(2, false)],
    ),
    (
        "self.rs",
        "helper",
        "mod a { pub fn helper() {} fn g() { self::helper(); } }\n",
        &[(1, true)],
    ),
    (
        "use.rs",
        "helper",
        "mod m { pub fn helper() {} }\nfn f() { use m::helper; helper(); }\n",
        &[(2, false), (2, false)],
    ),
    (
        "glob.rs",
        "A",
        "enum E { A }\nuse E::*;\nfn f() { A; }\n",
        &[(3, false)],
    ),
    // TypeScript positions no lexical walk can settle.
    (
        "typeof.ts",
        "x",
        "const x = 1;\ntype T = typeof x;\n",
        &[(2, false)],
    ),
    (
        "decorator.ts",
        "dec",
        "function dec(a: any) {}\n@dec class A {}\n",
        &[(2, false)],
    ),
    (
        "export.ts",
        "helper",
        "function helper() {}\nexport { helper };\nexport default helper;\n",
        &[(2, false), (3, false)],
    ),
    (
        "jsx.tsx",
        "Comp",
        "function Comp() { return null; }\nconst e = <Comp />;\n",
        &[(2, false)],
    ),
    (
        "enum.ts",
        "A",
        "const A = 1;\nenum E { A = 2, B = A }\n",
        &[(2, false)],
    ),
    // A class field initializer reads the outer name, never the field.
    (
        "field.ts",
        "y",
        "const y = 1;\nclass C { y = 2; z = y; }\n",
        &[(2, true)],
    ),
];

#[test]
fn adjacent_forms_bind_only_where_certain() {
    for &(file, name, source, expected) in ADJACENT_FORMS {
        let path = format!("src/{file}");
        let tree = tree_of("adjacent", &[(&path, source)]);
        let result = query(&symbol_query(&tree.path, name, SymbolOp::References))
            .expect("references resolve");
        assert_eq!(resolved_at(&result, &path), expected, "{file}: {source}");
    }
}

// ----- narrowed certainty (DEC-029) -----

const VAR_TS: &str = "const x = 0;\nfunction f() { if (true) { var x = 1; } return x; }\n";

/// Forms whose certainty DEC-029 deletes, beside the positive forms
/// that must stay certain. Same shape as `ADJACENT_FORMS`.
const NARROWED_FORMS: &[BindingCase] = &[
    // A path through a type is type-qualified: its target hangs on
    // trait dispatch, impls on other types or generics — never certain.
    (
        "trait_impl.rs",
        "len",
        "trait Len { fn len(&self) -> usize; }\n\
         impl Len for String { fn len(&self) -> usize { 0 } }\n\
         fn f(s: &String) -> usize { String::len(s) }\n",
        &[(3, false)],
    ),
    (
        "impl_for.rs",
        "new",
        "trait Tr { fn new() -> Self; }\n\
         impl<T> Tr for Vec<T> { fn new() -> Self { loop {} } }\n\
         fn g() { Vec::new(); }\n",
        &[(3, false)],
    ),
    (
        "generic_self.rs",
        "new",
        "trait Make { fn new() -> Self; }\n\
         struct T;\n\
         impl T { fn new() -> T { T } }\n\
         fn g<T: Make>() -> T { T::new() }\n",
        &[(4, false)],
    ),
    (
        "local_alias.rs",
        "new",
        "fn f() { type S = Other; S::new() }\n",
        &[(1, false)],
    ),
    (
        "variant.rs",
        "A",
        "enum E { A }\nfn f() { E::A; }\n",
        &[(2, false)],
    ),
    // A type-level binding of the first segment shadows the module.
    (
        "shadowed_module.rs",
        "new",
        "mod T { pub fn new() {} }\nfn g<T>() { T::new(); }\n",
        &[(2, false)],
    ),
    // A same-document module stays certain.
    (
        "module.rs",
        "new",
        "mod m { pub fn new() {} }\nfn g() { m::new(); }\n",
        &[(2, true)],
    ),
    // `crate::` anchors only in a crate-root document.
    (
        "lib.rs",
        "helper",
        "mod a { pub fn helper() {} }\nmod b { fn g() { crate::a::helper(); } }\n",
        &[(2, true)],
    ),
    (
        "bin/tool.rs",
        "helper",
        "mod a { pub fn helper() {} }\nmod b { fn g() { crate::a::helper(); } }\n",
        &[(2, true)],
    ),
    // A TypeScript `var` is function-scoped and hoisted.
    ("var.ts", "x", VAR_TS, &[(2, false)]),
    (
        "for_var.ts",
        "i",
        "const i = 0;\nfunction g() { for (var i = 0; ; ) {} return i; }\n",
        &[(2, false)],
    ),
    // Mapped-type keys and `infer` bind names the walk does not follow.
    (
        "mapped.ts",
        "K",
        "type K = string;\ntype M<T> = { [K in keyof T]: T[K] };\n",
        &[(2, false), (2, false)],
    ),
    (
        "infer.ts",
        "U",
        "type U = number;\ntype E<T> = T extends Array<infer U> ? U : never;\n",
        &[(2, false), (2, false)],
    ),
    (
        "infer_class.ts",
        "T",
        "class T {}\ntype M<X> = X extends Array<infer T> ? T : never;\n",
        &[(2, false), (2, false)],
    ),
    // A namespace reopened in one document.
    (
        "reopened.ts",
        "helper",
        "function helper() {}\n\
         namespace a { function helper() {} }\n\
         namespace a { helper(); }\n",
        &[(3, false)],
    ),
    // A pattern identifier may name a same-name constant.
    (
        "const_pattern.rs",
        "limit",
        "const limit: u8 = 3;\nfn f(x: u8) -> u8 { match x { limit => limit, _ => 0 } }\n",
        &[(2, false)],
    ),
    // An import of the name may bring a constant the pattern names.
    (
        "imported_pattern.rs",
        "limit",
        "use consts::limit;\nfn f(x: u8) -> u8 { match x { limit => limit, _ => 0 } }\n",
        &[(1, false), (2, false)],
    ),
    // So may a glob, whatever the local's case.
    (
        "glob_pattern.rs",
        "limit",
        "use consts::*;\nfn f(x: u8) -> u8 { match x { limit => limit, _ => 0 } }\n",
        &[(2, false)],
    ),
    (
        "glob_upper.rs",
        "Unit",
        "use units::*;\nfn f() { let Unit = make(); Unit; }\n",
        &[(2, false)],
    ),
    // A plain TypeScript assignment declares nothing: both names are the
    // outer `let`'s.
    (
        "assign.ts",
        "x",
        "let x = 0;\nfunction g() { x = 1; return x; }\n",
        &[(2, true), (2, true)],
    ),
    // A module and a same-name function (or TypeScript class) are one
    // scope to the index, but their blocks do not share names.
    (
        "mixed.rs",
        "x",
        "fn x() {}\nmod helper { pub fn x() {} }\nfn helper() { x(); }\n",
        &[(3, false)],
    ),
    (
        "mixed_fn.ts",
        "x",
        "const x = 0;\nnamespace f { export const x = 1; }\nfunction f() { return x; }\n",
        &[(3, false)],
    ),
    (
        "mixed_class.ts",
        "x",
        "const x = 0;\nnamespace C { export const x = 1; }\nclass C { m() { return x; } }\n",
        &[(3, false)],
    ),
    // `super` is never guessed, not even from below a crate root.
    (
        "lib.rs",
        "h",
        "fn h() {}\nmod a { fn h() {} mod b { fn g() { super::h(); } } }\n",
        &[(2, false)],
    ),
    // A brace-delimited macro may introduce items; a parenthesized
    // statement macro is read as introducing none (a known limit).
    (
        "brace_macro.rs",
        "CONFIG",
        "static CONFIG: u8 = 0;\n\
         fn f() { thread_local! { static CONFIG: u8 = 1; } CONFIG.with(|c| *c); }\n",
        &[(2, false), (2, false)],
    ),
    (
        "paren_macro.rs",
        "CONFIG",
        "static CONFIG: u8 = 0;\nfn g() -> u8 { println!(\"x\"); CONFIG }\n",
        &[(2, true)],
    ),
    // A glob or an item macro reaches the patterns in its own scope and
    // the scopes inside it — never a sibling function's.
    (
        "glob_tests_module.rs",
        "x",
        "fn a(){let x=1;x;} fn b(){let x=2;x;} #[cfg(test)] mod tests { use super::*; fn t(){ let x=3; x; } }\n",
        &[(1, true), (1, true), (1, false)],
    ),
    (
        "glob_nested_module.rs",
        "v",
        "mod a { fn f() { let v = 1; v; } mod b { use g::*; fn h() { let v = 2; v; } } }\n",
        &[(1, true), (1, false)],
    ),
    // The walk up does not stop at a module: a root glob reaches no
    // pattern inside `mod m`, but over-reaching only leaves it unknown.
    (
        "glob_root_nested.rs",
        "limit",
        "use consts::*;\nmod m { fn f(x: u8) -> u8 { match x { limit => limit, _ => 0 } } }\n",
        &[(2, false)],
    ),
    (
        "glob_merged_bearer.rs",
        "v",
        "fn x() { let v = 1; v; }\nmod x { use g::*; }\n",
        &[(1, false)],
    ),
    (
        "brace_macro_sibling.rs",
        "v",
        "fn a() { thread_local! { static X: u8 = 1; } }\nfn f() { let v = 1; v; }\n",
        &[(2, true)],
    ),
    (
        "brace_macro_local.rs",
        "v",
        "fn f() { thread_local! { static X: u8 = 1; } let v = 1; v; }\n",
        &[(1, false)],
    ),
    (
        "brace_macro_closure.rs",
        "v",
        "fn f() { let c = || { thread_local! { static X: u8 = 1; } }; let v = 1; v; }\n",
        &[(1, true)],
    ),
    // At a module's top level any macro may define items, whatever its
    // delimiter.
    (
        "item_macro.rs",
        "limit",
        "mk_consts!(limit);\nfn f(x: u8) -> u8 { match x { limit => limit, _ => 0 } }\n",
        &[(1, false), (2, false)],
    ),
    (
        "item_macro_mod.rs",
        "limit",
        "mod m { mk_consts!(limit); fn f(x: u8) -> u8 { match x { limit => limit, _ => 0 } } }\n",
        &[(1, false), (1, false)],
    ),
];

#[test]
fn narrowed_forms_are_certain_only_where_decided() {
    let mismatches: Vec<(&str, Vec<(u64, bool)>)> = NARROWED_FORMS
        .iter()
        .filter_map(|&(file, name, source, expected)| {
            let path = format!("src/{file}");
            let tree = tree_of("narrowed", &[(&path, source)]);
            let result = query(&symbol_query(&tree.path, name, SymbolOp::References))
                .expect("references resolve");
            let actual = resolved_at(&result, &path);
            (actual != expected).then_some((file, actual))
        })
        .collect();
    assert!(mismatches.is_empty(), "{mismatches:#?}");

    // A hoisted `var` is still a definition — of the function scope.
    let tree = tree_of("var-definition", &[("src/var.ts", VAR_TS)]);
    let defs =
        query(&symbol_query(&tree.path, "x", SymbolOp::Definition)).expect("definitions resolve");
    let rows: Vec<(u64, &str, &str)> = defs
        .matches
        .iter()
        .map(|hit| {
            let row = symbol_hit(hit);
            (
                hit.source.line.expect("line"),
                row.symbol_kind.as_str(),
                row.scope.as_str(),
            )
        })
        .collect();
    assert_eq!(rows, vec![(1, "variable", ""), (2, "var", "f")]);
}

#[test]
fn glob_shadows_only_the_locals_under_it() {
    // `use super::*;` in a test module may bring a constant a pattern in
    // that module names — never one a sibling function outside it binds.
    // A qualified answer serves the certain use it names plus every use
    // bound nowhere, unresolved.
    let source = "fn a(){let x=1;x;} fn b(){let x=2;x;} #[cfg(test)] mod tests { use super::*; fn t(){ let x=3; x; } }\n";
    let tree = tree_of("glob-scope", &[("src/lib.rs", source)]);
    let rows = |pattern: &str| {
        let refs = query(&symbol_query(&tree.path, pattern, SymbolOp::References))
            .expect("references resolve");
        assert_eq!(refs.completeness, Completeness::Complete, "{pattern}");
        symbol_rows(&refs)
            .iter()
            .map(|row| (row.range.start.character, row.resolved))
            .collect::<Vec<_>>()
    };
    assert_eq!(rows("x"), vec![(15, true), (34, true), (94, false)]);
    assert_eq!(rows("a::x"), vec![(15, true), (94, false)]);
    assert_eq!(rows("tests::t::x"), vec![(94, false)]);

    // Which scopes lie under a glob is walked once per scope: the first
    // local's block, `f`'s body, `f` and the globbed root (4), every
    // later block and the memoized body above it (2) — 2n + 2.
    let n = 500u64;
    let source = format!(
        "use m::*;\nfn f() {{ {}}}\n",
        "{ let v = 1; } ".repeat(n as usize)
    );
    let tree = tree_of("glob-memo", &[("src/lib.rs", &source)]);
    let index = index_one(&tree, "src/lib.rs", request("v", SymbolOp::References));
    assert_eq!(index.answer().resolution_steps, 2 * n + 2);
}

#[test]
fn rust_anchors_never_apply_to_typescript() {
    // `crate` is an ordinary namespace name in TypeScript: the annotation
    // names the namespace's `I`, never the root one.
    let tree = tree_of(
        "ts-crate",
        &[(
            "src/crate.ts",
            "namespace crate { export interface I {} }\ninterface I {}\nlet x: crate.I;\n",
        )],
    );
    let result = query(&symbol_query(&tree.path, "x", SymbolOp::Type)).expect("type resolves");
    let rows: Vec<(u64, &str, bool)> = result
        .matches
        .iter()
        .map(|hit| {
            let row = symbol_hit(hit);
            (
                hit.source.line.expect("line"),
                row.scope.as_str(),
                row.resolved,
            )
        })
        .collect();
    assert_eq!(rows, vec![(1, "crate", true)]);

    // Query-side too: `crate::` and `self::` anchor Rust modules, never a
    // TypeScript root — which `::name` still addresses.
    let tree = tree_of(
        "ts-query-anchor",
        &[("src/root.ts", "function helper() {}\nhelper();\n")],
    );
    for (pattern, expected) in [
        ("crate::helper", vec![]),
        ("self::helper", vec![]),
        ("::helper", vec![(2, true)]),
    ] {
        let refs = query(&symbol_query(&tree.path, pattern, SymbolOp::References))
            .expect("references resolve");
        assert_eq!(resolved_at(&refs, "src/root.ts"), expected, "{pattern}");
    }
}

#[test]
fn file_module_qualified_definition_is_never_complete_empty() {
    let tree = tree_of(
        "file-modules",
        &[
            ("src/lib.rs", "mod a;\nmod b;\n"),
            ("src/a.rs", "pub struct A;\npub fn helper() -> A { A }\n"),
            ("src/b/c.rs", "pub struct C;\npub fn helper() -> C { C }\n"),
        ],
    );
    let answer = |pattern: &str, op: SymbolOp| {
        let result = query(&symbol_query(&tree.path, pattern, op)).expect("query resolves");
        assert_eq!(result.completeness, Completeness::Complete, "{pattern}");
        result
            .matches
            .iter()
            .map(|hit| {
                (
                    hit.source.path.to_string_lossy().into_owned(),
                    symbol_hit(hit).name.clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    let row = |path: &str, name: &str| (path.to_string(), name.to_string());
    for pattern in ["a::helper", "crate::a::helper"] {
        assert_eq!(
            answer(pattern, SymbolOp::Definition),
            vec![row("src/a.rs", "helper")],
            "{pattern}"
        );
    }
    for pattern in ["b::c::helper", "c::helper", "crate::b::c::helper"] {
        assert_eq!(
            answer(pattern, SymbolOp::Definition),
            vec![row("src/b/c.rs", "helper")],
            "{pattern}"
        );
    }
    assert_eq!(
        answer("a::helper", SymbolOp::Type),
        vec![row("src/a.rs", "A")]
    );
    assert_eq!(
        answer("b::c::helper", SymbolOp::Type),
        vec![row("src/b/c.rs", "C")]
    );
    // `crate::helper` names the crate root, which holds no `helper` — a
    // file module's top level is not the root.
    assert_eq!(answer("crate::helper", SymbolOp::Definition), vec![]);

    // A directory module's `mod.rs` is the module its directory names.
    let tree = tree_of(
        "dir-module",
        &[
            ("src/lib.rs", "mod a;\n"),
            ("src/a/mod.rs", "pub fn helper() {}\n"),
        ],
    );
    let result = query(&symbol_query(&tree.path, "a::helper", SymbolOp::Definition))
        .expect("definition resolves");
    assert_eq!(result.completeness, Completeness::Complete);
    assert_eq!(lines_at(&result, "src/a/mod.rs"), vec![1]);
}

#[test]
fn const_parameters_bind_inside_every_generic_owner() {
    // A const generic is visible over its owner whatever container owns
    // it. It is a declaration, not a pattern, but the index holds it
    // unknown beside a same-name item of the document like any Rust local
    // — never the outer const.
    for source in [
        "const N: usize = 1;\nstruct A<const N: usize>([u8; N]);\n",
        "const N: usize = 1;\nstruct A<const N: usize> { a: [u8; N] }\n",
        "const N: usize = 1;\nenum A<const N: usize> { V([u8; N]) }\n",
        "const N: usize = 1;\nunion A<const N: usize> { a: [u8; N] }\n",
        "const N: usize = 1;\nstruct A<const N: usize = N>;\n",
        "const N: usize = 1;\nimpl<const N: usize> A<N> { fn f() -> usize { N } }\n",
        "const N: usize = 1;\ntrait T<const N: usize> { fn f() -> usize { N } }\n",
    ] {
        let tree = tree_of("const-param", &[("src/lib.rs", source)]);
        for pattern in ["N", "::N"] {
            let refs = query(&symbol_query(&tree.path, pattern, SymbolOp::References))
                .expect("references resolve");
            let rows = resolved_at(&refs, "src/lib.rs");
            assert!(
                !rows.is_empty() && rows.iter().all(|&(line, resolved)| line == 2 && !resolved),
                "{pattern}: {source}: {rows:?}"
            );
        }
    }
    // Alone in its document, the parameter is the binding.
    for (source, expected) in [
        ("struct A<const N: usize>([u8; N]);\n", vec![(1, true)]),
        (
            "trait T<const N: usize> { fn f() -> usize { N } }\n",
            vec![(1, true)],
        ),
        (
            "impl<const N: usize> A<N> { fn f() -> usize { N } }\n",
            vec![(1, false), (1, true)],
        ),
    ] {
        let tree = tree_of("const-param-alone", &[("src/lib.rs", source)]);
        let refs = query(&symbol_query(&tree.path, "N", SymbolOp::References))
            .expect("references resolve");
        assert_eq!(resolved_at(&refs, "src/lib.rs"), expected, "{source}");
    }
}

#[test]
fn typescript_using_declares_a_block_local() {
    // `using x = …` (tree-sitter-typescript reads an assignment behind a
    // `using` token) declares `x` in its block: the use after it names
    // that local, never the same-name root function. So does each name
    // of `using a = …, x = …`, read as a sequence of assignments with the
    // token on the first alone.
    let tree = tree_of(
        "ts-using",
        &[
            (
                "src/using.ts",
                "function validate() {}\nfunction g() { using validate = null as any; validate; }\n",
            ),
            (
                "src/await.ts",
                "function validate() {}\nasync function g() { await using validate = null as any; validate; }\n",
            ),
            (
                "src/for.ts",
                "function validate() {}\nfunction g() { for (using validate = null as any; ; ) { validate; } }\n",
            ),
            (
                "src/list.ts",
                "function validate() {}\nfunction g() { using a = null as any, validate = null as any; validate; }\n",
            ),
            (
                "src/await_list.ts",
                "function validate() {}\nasync function g() { await using a = null as any, validate = null as any; validate; }\n",
            ),
            (
                "src/await_comment_list.ts",
                "function validate() {}\nasync function g() { await /* c */ using a = null as any, validate = null as any; validate; }\n",
            ),
            (
                "src/for_list.ts",
                "function validate() {}\nfunction g() { for (using a = null as any, validate = null as any; ; ) { validate; } }\n",
            ),
        ],
    );
    let refs = |pattern: &str, path: &str| {
        let result = query(&symbol_query(&tree.path, pattern, SymbolOp::References))
            .expect("references resolve");
        assert_eq!(result.completeness, Completeness::Complete, "{pattern}");
        resolved_at(&result, path)
    };
    for path in [
        "src/using.ts",
        "src/await.ts",
        "src/for.ts",
        "src/list.ts",
        "src/await_list.ts",
        "src/await_comment_list.ts",
        "src/for_list.ts",
    ] {
        assert_eq!(refs("::validate", path), vec![], "{path}");
        assert_eq!(refs("g::validate", path), vec![(2, true)], "{path}");
        let defs = query(&symbol_query(&tree.path, "validate", SymbolOp::Definition))
            .expect("definitions resolve");
        assert_eq!(lines_at(&defs, path), vec![1, 2], "{path}");
    }
    // Past the comment after `await`: the list's second name (column 58)
    // is a declaration, and the use (column 82) binds it.
    let mut pinned = symbol_query(&tree.path, "g::validate", SymbolOp::References);
    pinned.document = Some(pin("src/await_comment_list.ts", None));
    let result = query(&pinned).expect("pinned references resolve");
    let rows: Vec<(u32, u32, bool)> = symbol_rows(&result)
        .iter()
        .map(|row| {
            (
                row.range.start.line,
                row.range.start.character,
                row.resolved,
            )
        })
        .collect();
    assert_eq!(rows, vec![(1, 82, true)]);
    let defs = query(&symbol_query(&tree.path, "validate", SymbolOp::Definition))
        .expect("definitions resolve");
    assert!(
        symbol_rows(&defs)
            .iter()
            .any(|row| row.uri.as_str().ends_with("await_comment_list.ts")
                && (row.range.start.line, row.range.start.character) == (1, 58)),
        "{:?}",
        defs.matches
    );
}

#[test]
fn only_a_using_declaration_declares() {
    // A declaration binds a plain name, on the `using` token's own line:
    // `using [v] = …` indexes a variable named `using`, and a line break
    // after `using` ends its statement. Neither declares anything — the
    // names stay uses of what the scope already holds, none dropped from
    // a root-qualified answer.
    for (source, name, uses, defs) in [
        (
            "let v = 1;\nfunction g() { using[v] = 3; v; }\n",
            "v",
            vec![(2, false), (2, true)],
            vec![1],
        ),
        (
            "let v = 1;\nfunction g() { using\nv = 2; v; }\n",
            "v",
            vec![(3, true), (3, true)],
            vec![1],
        ),
        (
            "function validate() {}\nlet using: any; using[validate] = 1;\n",
            "validate",
            vec![(2, false)],
            vec![1],
        ),
        (
            "function validate() {}\nusing [validate] = [1];\n",
            "validate",
            vec![(2, false)],
            vec![1],
        ),
        // A plain sequence of assignments declares nothing, in a statement
        // or a `for` head.
        (
            "let v = 1;\nfunction g() { a = 1, v = 2; v; }\n",
            "v",
            vec![(2, true), (2, true)],
            vec![1],
        ),
        (
            "let v = 1;\nfunction g() { for (i = 0, v = 2; ; ) { v; } }\n",
            "v",
            vec![(2, true), (2, true)],
            vec![1],
        ),
        // Only a list's first item stands where the statement does: a
        // later `await using` is an operand, however the list opened.
        (
            "let b = 0;\nasync function g() { a = 1, await using b = 2; b; }\n",
            "b",
            vec![(2, true), (2, true)],
            vec![1],
        ),
        // A declaration stands as a statement or a `for` head only: an
        // argument or a parenthesized list is an assignment.
        (
            "let v = 1;\nfunction g() { f(using v = 1); v; }\n",
            "v",
            vec![(2, true), (2, true)],
            vec![1],
        ),
        (
            "let v = 1;\nfunction g() { c ? (using a = 1, v = 2) : 0; v; }\n",
            "v",
            vec![(2, true), (2, true)],
            vec![1],
        ),
    ] {
        let tree = tree_of("ts-not-using", &[("src/t.ts", source)]);
        for pattern in [name.to_string(), format!("::{name}")] {
            let refs = query(&symbol_query(&tree.path, &pattern, SymbolOp::References))
                .expect("references resolve");
            assert_eq!(refs.completeness, Completeness::Complete, "{source}");
            assert_eq!(resolved_at(&refs, "src/t.ts"), uses, "{pattern}: {source}");
        }
        let found = query(&symbol_query(&tree.path, name, SymbolOp::Definition))
            .expect("definitions resolve");
        assert_eq!(lines_at(&found, "src/t.ts"), defs, "{source}");
    }
}

#[test]
fn damaged_documents_claim_no_certain_use() {
    // An error or missing node may hold the declaration a use names: a
    // `for (using … of …)` head is outside the grammar, and `let x = @;`
    // takes the next call as its own value. No use in a damaged document
    // is certain — each is served unresolved under every qualifier, pinned
    // or not, and the damage is disclosed. Its definitions serve as ever.
    for (path, source) in [
        (
            "src/of.ts",
            "function validate() {}\nfunction g(xs: any) { for (using validate of xs) { use(validate); } }\n",
        ),
        (
            "src/call.ts",
            "function validate() {}\nfunction g(xs: any) { for (using validate of xs) { validate(); } }\n",
        ),
        (
            "src/await.ts",
            "function validate() {}\nasync function g(xs: any) { for (await using validate of xs) { validate(); } }\n",
        ),
        (
            "src/let.rs",
            "fn validate() {}\nfn g() { let validate = @; validate(); }\n",
        ),
        // Damaged by a missing node alone — the `;` the `let` lacks.
        (
            "src/missing.rs",
            "fn validate() {}\nfn g() { validate(); let v = 2 }\n",
        ),
    ] {
        let tree = tree_of("damaged-uses", &[(path, source)]);
        let damaged = partial(vec![PartialReason::ParseErrors { count: 1 }]);
        let rows = |pattern: &str, pinned: bool| {
            let mut request = symbol_query(&tree.path, pattern, SymbolOp::References);
            if pinned {
                request.document = Some(pin(path, None));
            }
            let refs = query(&request).expect("references resolve");
            assert_eq!(refs.completeness, damaged, "{pattern}: {path}");
            symbol_rows(&refs)
                .iter()
                .map(|row| {
                    (
                        row.range.start.line,
                        row.range.start.character,
                        row.resolved,
                    )
                })
                .collect::<Vec<_>>()
        };
        let bare = rows("validate", false);
        let body_use = source
            .lines()
            .nth(1)
            .and_then(|line| line.rfind("validate"))
            .expect("the body use");
        assert!(
            bare.iter()
                .any(|&(line, column, _)| (line, column as usize) == (1, body_use)),
            "{path}: {bare:?}"
        );
        assert!(
            bare.iter().all(|&(.., resolved)| !resolved),
            "{path}: {bare:?}"
        );
        for pattern in ["::validate", "g::validate"] {
            assert_eq!(rows(pattern, false), bare, "{pattern}: {path}");
            assert_eq!(rows(pattern, true), bare, "pinned {pattern}: {path}");
        }
        let defs = query(&symbol_query(&tree.path, "validate", SymbolOp::Definition))
            .expect("definitions resolve");
        assert_eq!(lines_at(&defs, path).first(), Some(&1), "{path}");
    }

    // A type answer serves its damaged document's candidate, unresolved.
    let tree = tree_of(
        "damaged-type",
        &[(
            "src/lib.rs",
            "struct Config;\nfn make() -> Config { let c = @; Config }\n",
        )],
    );
    for pinned in [false, true] {
        let mut typed = symbol_query(&tree.path, "make", SymbolOp::Type);
        if pinned {
            typed.document = Some(pin("src/lib.rs", None));
        }
        let result = query(&typed).expect("type resolves");
        assert_eq!(
            resolved_at(&result, "src/lib.rs"),
            vec![(1, false)],
            "{pinned}"
        );
        assert_eq!(
            result.completeness,
            partial(vec![PartialReason::ParseErrors { count: 1 }])
        );
    }
}

#[test]
fn underivable_module_path_is_disclosed_typed() {
    // `scripts/tool.rs` is in no crate layout the index derives module
    // paths for: whether its `helper` is `a::helper` cannot be told, so a
    // qualified answer discloses it rather than claiming completeness.
    let tree = tree_of(
        "underivable",
        &[
            ("src/a.rs", "pub fn helper() {}\n"),
            ("scripts/tool.rs", "pub fn helper() {}\n"),
        ],
    );
    let result = query(&symbol_query(&tree.path, "a::helper", SymbolOp::Definition))
        .expect("definition resolves");
    assert_eq!(lines_at(&result, "src/a.rs"), vec![1]);
    assert!(lines_at(&result, "scripts/tool.rs").is_empty());
    assert_eq!(
        serde_json::to_value(&result.completeness).expect("serializes"),
        json!({
            "status": "partial",
            "reasons": [{ "reason": "unknown_module_paths", "count": 1 }]
        })
    );
    // A bare name needs no module path.
    let result =
        query(&symbol_query(&tree.path, "helper", SymbolOp::Definition)).expect("resolves");
    assert_eq!(result.completeness, Completeness::Complete);
}

#[test]
fn file_module_qualified_references_are_never_complete_empty() {
    // A use bound at its file's top level lives at that file's module
    // path: `a::helper` names `src/a.rs`'s own `helper`, so its certain
    // use is served, never dropped into a Complete-empty answer.
    let tree = tree_of(
        "file-module-refs",
        &[
            ("src/lib.rs", "mod a;\nmod b;\n"),
            ("src/a.rs", "fn helper() {}\nfn g() { helper(); }\n"),
            (
                "src/b/c.rs",
                "fn helper() {}\nfn g(x: X) { helper(); x.helper(); }\n",
            ),
        ],
    );
    let refs = |pattern: &str, path: &str| {
        let result = query(&symbol_query(&tree.path, pattern, SymbolOp::References))
            .expect("references resolve");
        assert_eq!(result.completeness, Completeness::Complete, "{pattern}");
        resolved_at(&result, path)
    };
    for pattern in ["a::helper", "crate::a::helper"] {
        assert_eq!(refs(pattern, "src/a.rs"), vec![(2, true)], "{pattern}");
        // `c.rs`'s certain use names `b::c::helper`, never `a::helper`;
        // only its unbindable receiver call is served, unresolved.
        assert_eq!(refs(pattern, "src/b/c.rs"), vec![(2, false)], "{pattern}");
    }
    for pattern in ["b::c::helper", "c::helper", "crate::b::c::helper"] {
        assert_eq!(
            refs(pattern, "src/b/c.rs"),
            vec![(2, true), (2, false)],
            "{pattern}"
        );
        assert_eq!(refs(pattern, "src/a.rs"), vec![], "{pattern}");
    }

    // A file in no layout the index derives a module path for: whether
    // its certain use names `a::helper` cannot be told, so the answer
    // discloses it typed rather than claiming completeness.
    let tree = tree_of(
        "file-module-refs-underivable",
        &[
            ("src/a.rs", "fn helper() {}\nfn g() { helper(); }\n"),
            ("scripts/tool.rs", "fn helper() {}\nfn g() { helper(); }\n"),
        ],
    );
    let result = query(&symbol_query(&tree.path, "a::helper", SymbolOp::References))
        .expect("references resolve");
    assert_eq!(resolved_at(&result, "src/a.rs"), vec![(2, true)]);
    assert_eq!(resolved_at(&result, "scripts/tool.rs"), vec![]);
    assert_eq!(
        serde_json::to_value(&result.completeness).expect("serializes"),
        json!({
            "status": "partial",
            "reasons": [{ "reason": "unknown_module_paths", "count": 1 }]
        })
    );
}

#[test]
fn reference_module_paths_follow_nested_mods_crate_roots_and_pins() {
    let tree = tree_of(
        "file-module-refs-attack",
        &[
            (
                "src/lib.rs",
                "mod a;\nfn helper() {}\nfn g() { helper(); }\n",
            ),
            (
                "src/a.rs",
                "fn helper() {}\nmod inner { fn helper() {} fn h() { helper(); } }\nfn g() { helper(); }\n",
            ),
            ("src/a.ts", "function helper() {}\nhelper();\n"),
        ],
    );
    let refs = |pattern: &str, path: &str| {
        let result = query(&symbol_query(&tree.path, pattern, SymbolOp::References))
            .expect("references resolve");
        assert_eq!(result.completeness, Completeness::Complete, "{pattern}");
        resolved_at(&result, path)
    };
    // A `mod` inside a file module nests under the file's path.
    for pattern in [
        "a::inner::helper",
        "crate::a::inner::helper",
        "inner::helper",
    ] {
        assert_eq!(refs(pattern, "src/a.rs"), vec![(2, true)], "{pattern}");
    }
    assert_eq!(refs("a::helper", "src/a.rs"), vec![(3, true)]);
    // The crate root holds only `lib.rs`'s top level.
    for pattern in ["crate::helper", "::helper"] {
        assert_eq!(refs(pattern, "src/lib.rs"), vec![(3, true)], "{pattern}");
        assert_eq!(refs(pattern, "src/a.rs"), vec![], "{pattern}");
    }
    assert_eq!(refs("a::helper", "src/lib.rs"), vec![]);
    assert_eq!(refs("helper", "src/lib.rs"), vec![(3, true)]);
    assert_eq!(refs("helper", "src/a.rs"), vec![(2, true), (3, true)]);
    // A TypeScript file is no Rust module: its top level stays the root.
    assert_eq!(refs("a::helper", "src/a.ts"), vec![]);
    assert_eq!(refs("::helper", "src/a.ts"), vec![(2, true)]);
    // A pinned answer matches the pinned document's module path too.
    let mut pinned = symbol_query(&tree.path, "a::helper", SymbolOp::References);
    pinned.document = Some(pin("src/a.rs", None));
    let result = query(&pinned).expect("pinned references resolve");
    assert_eq!(result.completeness, Completeness::Complete);
    assert_eq!(resolved_at(&result, "src/a.rs"), vec![(3, true)]);
    assert_eq!(symbol_rows(&result).len(), 1);
}

// ----- module paths from the package root (DEC-030 #4) -----

#[test]
fn module_paths_read_from_the_package_root_not_the_query_root() {
    // A workspace member: a module path is read from the nearest
    // `Cargo.toml` above the document, not from the query root. A
    // query-root-relative derivation would place `member/src/a.rs` at
    // module `member::src::a` and address nothing, so a qualified
    // definition there would answer `UnknownModulePaths` instead of the
    // row. The same tree queried from the member's own directory answers
    // identically — that is what "the package root, not the query root"
    // means, and the stale-pin rule rides it: the module path a row was
    // placed under is the one its own package spells.
    let tree = tree_of(
        "package-root-module-paths",
        &[
            ("Cargo.toml", "[workspace]\nmembers = [\"member\"]\n"),
            ("Cargo.lock", "version = 3\n"),
            ("member/Cargo.toml", "[package]\nname = \"member\"\n"),
            ("member/src/lib.rs", "mod a;\nfn helper() {}\n"),
            ("member/src/a.rs", "fn helper() {}\nfn g() { helper(); }\n"),
        ],
    );
    let resolved = |root: &Path, pattern: &str| {
        let result =
            query(&symbol_query(root, pattern, SymbolOp::References)).expect("references resolve");
        // The manifests are files no grammar claims, so the coverage
        // discloses them; the module path is the subject under test.
        assert!(
            match &result.completeness {
                Completeness::Partial { reasons } => reasons
                    .iter()
                    .any(|reason| matches!(reason, PartialReason::UnsupportedLanguage { .. })),
                Completeness::Complete => false,
            },
            "{pattern}: the manifests are disclosed coverage, got {result:?}"
        );
        (
            resolved_at(&result, "member/src/a.rs"),
            resolved_at(&result, "src/a.rs"),
        )
    };

    // The member's own directory as the query root: the reference is
    // found at line 2, reported under the query-root-relative path.
    assert_eq!(
        resolved(&tree.path.join("member"), "a::helper"),
        (vec![], vec![(2, true)]),
        "a member-local query root addresses its own module"
    );
    // The workspace root as the query root: the same module and the same
    // row, under the other relative path. A query-root-relative
    // derivation would have placed `member/src/a.rs` at module
    // `member::src::a` and answered nothing here, disclosing
    // `UnknownModulePaths` instead.
    assert_eq!(
        resolved(&tree.path, "a::helper"),
        (vec![(2, true)], vec![]),
        "a workspace-root query root reads the same module through the \
         member's own package root"
    );
    // The crate anchor resolves under that package root too.
    assert_eq!(
        resolved(&tree.path, "crate::a::helper"),
        (vec![(2, true)], vec![]),
        "the crate anchor is the member's crate root"
    );
    // A spelling the layout cannot decide is a certain absence here, not
    // an unknown: every document's module path is known under its own
    // package root, so `member::src::a` is simply not a module. The
    // undischarged case — a document whose module path cannot be derived
    // at all — stays where it was already proved, in
    // `underivable_module_path_is_disclosed_typed`.
    let absent = query(&symbol_query(
        &tree.path,
        "member::src::a::helper",
        SymbolOp::References,
    ))
    .expect("references resolve");
    assert_eq!(
        resolved_at(&absent, "member/src/a.rs"),
        vec![],
        "a query-root spelling is not a module path"
    );
    assert!(
        !result_mentions_unknown_module_paths(&absent),
        "a fully derived path set leaves nothing unknown: {absent:?}"
    );
}

/// Whether an answer carries the undisclosed-module-path reason.
fn result_mentions_unknown_module_paths(result: &QueryResult) -> bool {
    match &result.completeness {
        Completeness::Partial { reasons } => reasons
            .iter()
            .any(|reason| matches!(reason, PartialReason::UnknownModulePaths { .. })),
        Completeness::Complete => false,
    }
}

// ----- resolution work -----

#[test]
fn symbol_index_never_walks_node_links() {
    // The work counters count cursor steps and scope-table steps. A
    // `Node` link walk — parent, sibling or child by index — costs work
    // those counters never see (a rootward parent chain per identifier
    // turned a 14 s build into 320 s with every counter test green), so
    // the index reads ancestors from its own walk stack and children by
    // field name only.
    let source = include_str!("../src/lsp.rs");
    for forbidden in [
        ".parent()",
        "Node::parent",
        ".next_sibling()",
        ".prev_sibling()",
        ".next_named_sibling()",
        ".prev_named_sibling()",
        ".child(",
        ".named_child(",
        "::parent(&",
        "::parent;",
        "Node as",
        "descendant_for_",
        "named_descendant_for_",
        "child_with_descendant",
        ".children(",
        ".named_children(",
        "::parent",
        "::next_sibling",
        "::prev_sibling",
        "::next_named_sibling",
        "::prev_named_sibling",
        "::child(",
        "::named_child(",
        "= Node<",
        "= tree_sitter::Node<",
        "first_child_for_byte(",
        "first_named_child_for_byte(",
        "goto_previous_sibling",
        "goto_descendant",
    ] {
        assert!(
            !source.contains(forbidden),
            "src/lsp.rs walks `{forbidden}`"
        );
    }
}

#[test]
fn using_lookups_cost_one_pass_per_sequence() {
    // A list's `using` declaration is looked up once, as the list opens —
    // past the `await` and every comment after it, or past the comments
    // between `using` and the first name — and every later item reads
    // that answer. Each lookup step draws on the node budget, so the
    // count is exact: a comment costs its node plus one step, an item
    // `, b=1` its five nodes and nothing more. Looked up per item, the
    // comments would be paid again for every item.
    let fixtures: [fn(usize, usize) -> String; 2] = [
        |k, n| {
            format!(
                "async function g() {{ await {}u = 1{}; }}\n",
                "/**/".repeat(k),
                ", b=1".repeat(n)
            )
        },
        |k, n| {
            format!(
                "function g() {{ using {}a = 1{}; }}\n",
                "/**/ ".repeat(k),
                ", b=1".repeat(n)
            )
        },
    ];
    for fixture in fixtures {
        let visited = |k: usize, n: usize| {
            let tree = tree_of("using-lookups", &[("src/list.ts", &fixture(k, n))]);
            let index = index_one(&tree, "src/list.ts", request("b", SymbolOp::References));
            assert_eq!(index.coverage.failed, 0);
            index.coverage.nodes_visited
        };
        let base = visited(0, 1);
        for (k, n) in [(300, 1), (0, 300), (300, 300)] {
            assert_eq!(
                visited(k, n),
                base + 2 * k as u64 + 5 * (n as u64 - 1),
                "{}",
                fixture(1, 2)
            );
        }
    }
}

#[test]
fn same_name_type_answers_serve_each_candidate_list_once() {
    // Every `g` returns `T`, and the document holds `n` same-name
    // `struct T`s: one ambiguous candidate list, served once however
    // many subjects bind to it. Steps: the first subject walks `g` and
    // the root (2), decides (1) and serves its `n` candidates; each
    // later one hits the walk memo (1), decides (1) and finds the list
    // already served (1) — 4n in all.
    let n = 2000u64;
    let source = format!(
        "{}{}",
        "struct T;\n".repeat(n as usize),
        "fn g() -> T { loop {} }\n".repeat(n as usize)
    );
    let tree = tree_of("same-name-types", &[("src/types.rs", &source)]);
    let index = index_one(&tree, "src/types.rs", request("g", SymbolOp::Type));
    let answer = index.answer();
    assert_eq!(answer.matches.len(), 64);
    assert!(answer.truncated);
    assert!(answer.matches.iter().all(|hit| !symbol_hit(hit).resolved));
    assert_eq!(answer.resolution_steps, 4 * n);
}

#[test]
fn later_shadowing_locals_cost_one_walk_per_scope() {
    // `d` nested blocks, each declaring `x` only after the block inside
    // it, and `u` uses in the innermost: no local is visible to them,
    // so the first use skips every level. Steps: that use decides its
    // own block (1), then finds and decides each of the `d` levels (2d),
    // then walks `f` and the root (2); every later use decides its own
    // block and reuses the memoized walk above it (1) — u + 2d + 2.
    let (d, u) = (100u64, 1000u64);
    let source = format!(
        "fn f() {{ {}{}{}}}\n",
        "{ ".repeat(d as usize),
        "x; ".repeat(u as usize),
        "} let x = 1; ".repeat(d as usize)
    );
    let tree = tree_of("late-shadows", &[("src/shadows.rs", &source)]);
    let mut wide = request("x", SymbolOp::References);
    wide.limit = u as usize;
    let index = index_one(&tree, "src/shadows.rs", wide);
    let answer = index.answer();
    assert_eq!(answer.matches.len(), u as usize);
    assert!(answer.matches.iter().all(|hit| !symbol_hit(hit).resolved));
    assert_eq!(answer.resolution_steps, u + 2 * d + 2);
}

/// `u` sibling blocks, each holding one `use_site`, inside `d` nested
/// blocks in `fn f`'s body — every use in a scope of its own.
fn sibling_blocks(d: u64, u: u64, use_site: &str) -> String {
    format!(
        "fn f() {{ {}{}{}}}",
        "{ ".repeat(d as usize),
        format!("{{ {use_site} }} ").repeat(u as usize),
        "} ".repeat(d as usize)
    )
}

/// The resolution steps of a references answer for `name` over one
/// file, every use served.
fn reference_steps(tree: &TempTree, path: &str, name: &str, uses: u64) -> (u64, bool) {
    let mut wide = request(name, SymbolOp::References);
    wide.limit = uses as usize;
    let answer = index_one(tree, path, wide).answer();
    assert_eq!(answer.matches.len() as u64, uses, "every use served");
    let all_resolved = answer.matches.iter().all(|hit| symbol_hit(hit).resolved);
    (answer.resolution_steps, all_resolved)
}

#[test]
fn qualifier_bases_cost_one_walk_per_scope() {
    // Every `m::x()` sits in its own block, so no whole path repeats; the
    // first use looks `m` up through its block, the `d` levels, the body,
    // `f` and the root (d + 4) and resolves the leaf (1); every later use
    // looks it up in its own block (1), finds the memoized base one level
    // up (1) and resolves the leaf (1) — 3u + d + 2. Walked per use, the
    // lookup would cost (d + 5)u.
    let (d, u) = (200u64, 2000u64);
    let source = format!(
        "mod m {{ pub fn x() {{}} }}\n{}\n",
        sibling_blocks(d, u, "m::x();")
    );
    let tree = tree_of("base-memo", &[("src/bases.rs", &source)]);
    let (steps, resolved) = reference_steps(&tree, "src/bases.rs", "x", u);
    assert!(resolved, "each use binds `m::x`");
    assert_eq!(steps, 3 * u + d + 2);
}

#[test]
fn self_anchors_cost_one_walk_per_scope() {
    // As above for `self::x()` inside `mod m`: the first use finds the
    // module through its block, the `d` levels, the body, `f` and `m`
    // (d + 4) and resolves the leaf (1); every later use costs its block
    // (1), the memoized module one level up (1) and the leaf (1) —
    // 3u + d + 2, where a walk per use would cost (d + 5)u.
    let (d, u) = (200u64, 2000u64);
    let source = format!(
        "mod m {{ pub fn x() {{}} {} }}\n",
        sibling_blocks(d, u, "self::x();")
    );
    let tree = tree_of("module-memo", &[("src/modules.rs", &source)]);
    let (steps, resolved) = reference_steps(&tree, "src/modules.rs", "x", u);
    assert!(resolved, "each use binds `m::x`");
    assert_eq!(steps, 3 * u + d + 2);
}

#[test]
fn repeated_paths_resolve_once_per_scope() {
    // `u` uses of one `k`-segment path in one block: the first looks `m1`
    // up through the block, `f` and the root (3), walks the other k - 1
    // segments and resolves the leaf (1) — k + 3; every later use is the
    // memoized path (1) — u + k + 2 in all. Resolved per use, each later
    // one would cost k + 1.
    let (k, u) = (10u64, 2000u64);
    let names: Vec<String> = (1..=k).map(|n| format!("m{n}")).collect();
    let modules = names
        .iter()
        .fold(String::from("pub fn x() {}"), |inner, name| {
            format!("pub mod {name} {{ {inner} }}")
        });
    let path = names.iter().rev().cloned().collect::<Vec<_>>().join("::");
    let source = format!(
        "{modules}\nfn f() {{ {} }}\n",
        format!("{path}::x(); ").repeat(u as usize)
    );
    let tree = tree_of("path-memo", &[("src/paths.rs", &source)]);
    let (steps, resolved) = reference_steps(&tree, "src/paths.rs", "x", u);
    assert!(resolved, "each use binds the innermost `x`");
    assert_eq!(steps, u + k + 2);
}

#[test]
fn type_fallbacks_cost_one_walk_per_scope() {
    // `n` functions returning `T`, `d` modules deep, while `T` lives only
    // in another document: nothing binds (a bare name stops at the
    // module), so each answer falls back to the nearest same-name type
    // item of any document. The first subject walks `g` and the
    // innermost module (2), then falls back through `g`, the `d` modules
    // and the root (d + 2) and serves `T` (1); every later one hits the
    // walk memo (1), the fallback memo (1) and the served list (1) —
    // 3n + d + 2. Walked per subject, each fallback would cost d + 2.
    let (d, n) = (200u64, 2000u64);
    let source = format!(
        "{}{}{}\n",
        "mod a { ".repeat(d as usize),
        "fn g() -> T { loop {} } ".repeat(n as usize),
        "} ".repeat(d as usize)
    );
    let tree = tree_of(
        "fallback-memo",
        &[("src/deep.rs", &source), ("src/t.rs", "pub struct T;\n")],
    );
    let index = index_files(
        &tree,
        &["src/deep.rs", "src/t.rs"],
        request("g", SymbolOp::Type),
    );
    let answer = index.answer();
    assert_eq!(lines_of(&answer), vec![("src/t.rs".to_string(), 1)]);
    assert!(!symbol_hit(&answer.matches[0]).resolved);
    assert_eq!(answer.resolution_steps, 3 * n + d + 2);
}

#[test]
fn dense_parse_stops_at_the_parse_budget() {
    use rivect::lsp::{MAX_FILE_NODES, MAX_PARSE_CHECKS};
    assert_eq!(MAX_PARSE_CHECKS, 65_536, "the recorded parse budget");
    // `fn f(){` + n×`a;` + `}` filling the 1 MiB file cap is about
    // 1.5 M nodes — past the walk's node budget — so its parse stops at
    // the budget and the walk never runs.
    let n = (1024 * 1024 - 8) / 2;
    let dense = format!("fn f(){{{}}}", "a;".repeat(n));
    assert_eq!(dense.len(), 1024 * 1024, "fixture arithmetic");
    let tree = tree_of("parse-budget", &[("src/dense.rs", &dense)]);
    let index = index_one(&tree, "src/dense.rs", request("f", SymbolOp::Definition));
    assert_eq!(index.coverage.failed, 1);
    assert_eq!(index.coverage.nodes_visited, 0, "the walk never ran");
    assert_eq!(index.coverage.parse_checks, MAX_PARSE_CHECKS);
    // The largest walkable dense file parses inside the budget.
    let n = (MAX_FILE_NODES - 10) / 3;
    let at = format!("fn f(){{{}}}", "a;".repeat(n));
    let tree = tree_of("parse-budget-at", &[("src/at.rs", &at)]);
    let index = index_one(&tree, "src/at.rs", request("f", SymbolOp::Definition));
    assert_eq!(index.coverage.failed, 0);
    assert!(
        (1..MAX_PARSE_CHECKS).contains(&index.coverage.parse_checks),
        "headroom under the budget, got {}",
        index.coverage.parse_checks
    );
}

#[test]
fn index_parse_check_pool_is_exact() {
    use rivect::lsp::{MAX_INDEX_PARSE_CHECKS, MAX_PARSE_CHECKS};
    assert_eq!(MAX_INDEX_PARSE_CHECKS, 131_072, "the recorded pool");
    // Two dense 1 MiB files each run to the per-file parse budget; a
    // small probe needs a few checks. The whole build draws on one pool
    // of 131 072 checks — twice the per-file budget — so the second
    // dense file gets only what the first file and the probe left, and a
    // probe after it gets nothing: every parse that would cross the pool
    // is a failed entry. So is a file too small to reach a check, which
    // would otherwise parse past the spent pool.
    let dense = format!("fn d(){{{}}}", "a;".repeat((1024 * 1024 - 8) / 2));
    let probe = format!("fn f(){{{}}}\n", "a;".repeat(100));
    let tree = tree_of(
        "check-pool",
        &[
            ("src/d1.rs", &dense),
            ("src/p1.rs", &probe),
            ("src/d2.rs", &dense),
            ("src/tiny.rs", "fn f(){}\n"),
            ("src/p2.rs", &probe),
        ],
    );
    let probe_checks = index_one(&tree, "src/p1.rs", request("f", SymbolOp::Definition))
        .coverage
        .parse_checks;
    assert!(probe_checks > 0, "the probe's parse reaches a check");
    let tiny = index_one(&tree, "src/tiny.rs", request("f", SymbolOp::Definition));
    assert_eq!(tiny.coverage.parse_checks, 0, "the tiny file reaches none");
    assert_eq!(
        lines_of(&tiny.answer()),
        vec![("src/tiny.rs".to_string(), 1)]
    );

    let index = index_files(
        &tree,
        &[
            "src/d1.rs",
            "src/p1.rs",
            "src/d2.rs",
            "src/tiny.rs",
            "src/p2.rs",
        ],
        request("f", SymbolOp::Definition),
    );
    assert_eq!(index.coverage.parse_checks, 131_072, "exactly the pool");
    assert_eq!(
        index.coverage.failed, 4,
        "both dense files, the tiny file and the late probe"
    );
    assert_eq!(
        lines_of(&index.answer()),
        vec![("src/p1.rs".to_string(), 1)]
    );

    // Without the second dense file the pool never runs dry.
    let index = index_files(
        &tree,
        &["src/d1.rs", "src/p1.rs", "src/p2.rs"],
        request("f", SymbolOp::Definition),
    );
    assert_eq!(
        index.coverage.parse_checks,
        MAX_PARSE_CHECKS + 2 * probe_checks
    );
    assert_eq!(index.coverage.failed, 1);
    assert_eq!(
        lines_of(&index.answer()),
        vec![("src/p1.rs".to_string(), 1), ("src/p2.rs".to_string(), 1)]
    );
}

#[test]
fn spent_parse_deadline_fails_every_file() {
    // A file too small to reach a progress check would still parse past
    // the deadline — so a spent deadline fails every claimed file before
    // its read, deterministically, whatever the machine's speed. `None`
    // is a deadline `Instant` cannot represent: spent too.
    let tree = tree_of(
        "spent-deadline",
        &[
            ("src/a.rs", "fn f() {}\n"),
            ("src/b.ts", "function f() {}\n"),
            ("src/c.rs", "fn f() {}\n"),
        ],
    );
    let relatives = ["src/a.rs", "src/b.ts", "src/c.rs"];
    for deadline in [None, Some(Instant::now())] {
        let index = index_files_by(
            &tree,
            &relatives,
            request("f", SymbolOp::Definition),
            deadline,
        );
        assert_eq!(index.coverage.failed, 3, "{deadline:?}");
        assert_eq!(index.coverage.parse_checks, 0, "{deadline:?}");
        assert!(index.answer().matches.is_empty(), "{deadline:?}");
    }
    // A deadline ahead leaves every one of them indexed.
    let index = index_files_by(
        &tree,
        &relatives,
        request("f", SymbolOp::Definition),
        unhurried(),
    );
    assert_eq!(index.coverage.failed, 0);
    assert_eq!(lines_of(&index.answer()).len(), 3);
}

/// `(path, line)` of every row an index answer serves.
fn lines_of(answer: &rivect::lsp::SymbolAnswer) -> Vec<(String, u64)> {
    answer
        .matches
        .iter()
        .map(|hit| {
            (
                hit.source.path.to_string_lossy().into_owned(),
                hit.source.line.expect("line"),
            )
        })
        .collect()
}

#[test]
fn vanished_unclaimed_file_counts_unreadable() {
    // The hint scan reads unclaimed files when it answers: one gone by
    // then cannot be read, whatever privileges the run has.
    let tree = tree_of(
        "vanished-unclaimed",
        &[
            ("src/lib.rs", "fn helper() {}\n"),
            ("src/notes.py", "helper\n"),
        ],
    );
    let index = index_files(
        &tree,
        &["src/lib.rs", "src/notes.py"],
        request("helper", SymbolOp::Definition),
    );
    let before = index.answer();
    assert_eq!(before.unreadable_fallback, 0);
    assert_eq!(before.matches.len(), 2, "the typed row and the hint");
    std::fs::remove_file(tree.path.join("src/notes.py")).expect("remove the unclaimed file");
    let after = index.answer();
    assert_eq!(after.unreadable_fallback, 1);
    assert_eq!(lines_of(&after), vec![("src/lib.rs".to_string(), 1)]);
}

#[test]
fn index_parse_byte_budget_is_exact() {
    use rivect::lsp::MAX_PARSED_BYTES;
    assert_eq!(MAX_PARSED_BYTES, 32 * 1024 * 1024, "the recorded budget");
    // Comment-only files parse to a handful of nodes, so the bytes are
    // the only budget in play: exactly 32 MiB index, one byte more
    // fails the file that would cross it.
    let mib = 1024 * 1024;
    let comment = |len: usize| format!("//{}", "x".repeat(len - 2));
    let full = comment(mib);
    let last = comment(mib - 9);
    let paths: Vec<String> = (1..=31).map(|n| format!("src/c{n:02}.rs")).collect();
    let mut files: Vec<(&str, &str)> = paths
        .iter()
        .map(|path| (path.as_str(), full.as_str()))
        .collect();
    files.push(("src/c32.rs", &last));
    files.push(("src/q.rs", "fn f(){}\n"));
    let tree = tree_of("parse-bytes", &files);
    let mut relatives: Vec<&str> = files.iter().map(|(path, _)| *path).collect();
    let index = index_files(&tree, &relatives, request("f", SymbolOp::Definition));
    let answer = index.answer();
    assert_eq!(lines_of(&answer), vec![("src/q.rs".to_string(), 1)]);
    assert_eq!(folded(&index, &answer), Completeness::Complete);
    std::fs::write(tree.path.join("src/z.rs"), "\n").expect("one more byte");
    relatives.push("src/z.rs");
    let index = index_files(&tree, &relatives, request("f", SymbolOp::Definition));
    let answer = index.answer();
    assert_eq!(lines_of(&answer), vec![("src/q.rs".to_string(), 1)]);
    assert_eq!(
        folded(&index, &answer),
        partial(vec![PartialReason::EntriesFailed { count: 1 }])
    );
}

// ----- retention budgets -----

#[test]
fn scope_path_bound_is_exact() {
    // A served row renders its scope path; the walk refuses a file
    // whose path would render past 4096 bytes instead of rendering it.
    let fixture = |inner: usize| {
        format!(
            "mod {} {{ mod {} {{ const TARGET: u8 = 0; }} }}\n",
            "m".repeat(2047),
            "n".repeat(inner)
        )
    };
    let tree = tree_of("scope-at", &[("src/at.rs", &fixture(2047))]);
    let result =
        query(&symbol_query(&tree.path, "TARGET", SymbolOp::Definition)).expect("query resolves");
    let rows = symbol_rows(&result);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].scope.len(), 4096, "2047 + `::` + 2047");
    assert_eq!(result.completeness, Completeness::Complete);

    let tree = tree_of("scope-over", &[("src/over.rs", &fixture(2048))]);
    let result =
        query(&symbol_query(&tree.path, "TARGET", SymbolOp::Definition)).expect("query resolves");
    assert!(symbol_rows(&result).is_empty());
    assert_eq!(
        result.completeness,
        partial(vec![PartialReason::EntriesFailed { count: 1 }])
    );
}

#[test]
fn retained_text_budget_is_exact() {
    // A type query retains every type-level name: 4096 names of 4096
    // bytes are exactly the 16 MiB budget; one byte more fails the file
    // that crosses it — the last one walked — typed, while the rest of
    // the index still serves. 255 such definitions fit one file under
    // the 1 MiB parse bound: sixteen full files plus a tail of sixteen.
    assert_eq!(rivect::lsp::MAX_RETAINED_BYTES, 16 * 1024 * 1024);
    let names = |count: usize| {
        "type T = u8;\n"
            .replace('T', &"T".repeat(4096))
            .repeat(count)
    };
    let full = names(255);
    assert!(full.len() <= 1024 * 1024, "fixture arithmetic");
    let tail = |last: usize| {
        let mut source = names(15);
        source.push_str(&format!("type {} = u8;\n", "T".repeat(last)));
        source
    };
    let paths: Vec<String> = (1..=17).map(|n| format!("src/t{n:02}.rs")).collect();
    let fixture = |name: &str, last: usize| {
        let tail = tail(last);
        let mut files: Vec<(&str, &str)> = vec![("src/q.rs", "type Q = u8;\n")];
        files.extend(
            paths[..16]
                .iter()
                .map(|path| (path.as_str(), full.as_str())),
        );
        files.push((paths[16].as_str(), tail.as_str()));
        tree_of(name, &files)
    };
    let mut relatives = vec!["src/q.rs"];
    relatives.extend(paths.iter().map(String::as_str));
    let tree = fixture("text-at", 4096);
    let index = index_files(&tree, &relatives, request("Q", SymbolOp::Type));
    let answer = index.answer();
    assert_eq!(lines_of(&answer), vec![("src/q.rs".to_string(), 1)]);
    assert_eq!(folded(&index, &answer), Completeness::Complete);

    let tree = fixture("text-over", 4097);
    let index = index_files(&tree, &relatives, request("Q", SymbolOp::Type));
    let answer = index.answer();
    assert_eq!(
        lines_of(&answer),
        vec![("src/q.rs".to_string(), 1)],
        "q.rs still serves"
    );
    assert_eq!(
        folded(&index, &answer),
        partial(vec![PartialReason::EntriesFailed { count: 1 }])
    );
}

#[test]
fn nested_qualifiers_retain_one_qualifier_per_path() {
    // Every segment of `a::a::…::a` is a use of `a`, but only the leaf
    // of the whole path sits in a use position: the inner segments are
    // qualifier segments, never bound, so they keep no qualifier text.
    // Stored per segment the qualifiers would grow with the square of
    // the path — about 1.2 MB for 900 segments, past the 16 MiB budget
    // for sixteen paths; kept once per path the file indexes.
    let path = vec!["a"; 900].join("::");
    let source = format!("fn f() {{ {} }}\n", format!("{path}; ").repeat(16));
    let tree = tree_of("nested-qualifiers", &[("src/paths.rs", &source)]);
    let result =
        query(&symbol_query(&tree.path, "a", SymbolOp::References)).expect("query resolves");
    let rows = symbol_rows(&result);
    assert_eq!(rows.len(), 64);
    assert!(rows.iter().all(|row| !row.resolved), "no `a` scope exists");
    assert_eq!(
        result.completeness,
        partial(vec![PartialReason::LimitReached { limit: 64 }])
    );
}

#[test]
fn symbol_file_byte_cap_is_exact() {
    // Dense source crosses the walk's node budget near 700 KiB, so the
    // leg refuses to parse a file past 1 MiB: at the cap it indexes,
    // one byte over it is a failed entry.
    assert_eq!(rivect::lsp::MAX_SYMBOL_FILE_BYTES, 1024 * 1024);
    let fixture = |len: usize| {
        let mut source = String::from("fn f(){}\n//");
        source.push_str(&"x".repeat(len - source.len()));
        source
    };
    let tree = tree_of("bytes-at", &[("src/at.rs", &fixture(1024 * 1024))]);
    let index = index_one(&tree, "src/at.rs", request("f", SymbolOp::Definition));
    let answer = index.answer();
    assert_eq!(lines_of(&answer), vec![("src/at.rs".to_string(), 1)]);
    assert_eq!(folded(&index, &answer), Completeness::Complete);

    let tree = tree_of("bytes-over", &[("src/over.rs", &fixture(1024 * 1024 + 1))]);
    let index = index_one(&tree, "src/over.rs", request("f", SymbolOp::Definition));
    let answer = index.answer();
    assert!(answer.matches.is_empty());
    assert_eq!(
        folded(&index, &answer),
        partial(vec![PartialReason::EntriesFailed { count: 1 }])
    );
}

// ----- pins and coverage -----

/// The completeness fixture: `symbol_corpus` plus one damaged, one
/// oversized and one non-utf-8 Rust file.
fn completeness_corpus(name: &str) -> TempTree {
    let corpus = symbol_corpus(name);
    std::fs::write(
        corpus.path.join("src/broken.rs"),
        "fn intact() {}\nconst BAD: i32 = ;\n",
    )
    .expect("damaged fixture");
    std::fs::File::create(corpus.path.join("src/huge.rs"))
        .expect("huge fixture")
        .set_len(64 * 1024 * 1024 + 1)
        .expect("huge fixture length");
    std::fs::write(corpus.path.join("src/latin1.rs"), b"fn caf\xe9() {}\n")
        .expect("non-utf-8 fixture");
    corpus
}

fn pin(path: &str, version: Option<i32>) -> DocumentPin {
    DocumentPin {
        path: PathBuf::from(path),
        version,
        encoding: None,
    }
}

#[test]
fn pinned_damaged_document_discloses_only_its_own_damage() {
    let corpus = completeness_corpus("pin-damaged");
    let mut pinned = symbol_query(&corpus.path, "intact", SymbolOp::Definition);
    pinned.document = Some(pin("src/broken.rs", None));
    let result = query(&pinned).expect("the damaged pin resolves");
    assert_eq!(symbol_rows(&result).len(), 1);
    // The unrelated failed and unclaimed files cannot hide this
    // document's rows — only its own damage is disclosed.
    assert_eq!(
        result.completeness,
        partial(vec![PartialReason::ParseErrors { count: 1 }])
    );

    // A pinned references answer draws on its own document alone: a
    // second damaged document holding a use it does not serve is not
    // counted.
    std::fs::write(
        corpus.path.join("src/broken_use.rs"),
        "fn g() { intact(); }\nconst BAD: i32 = ;\n",
    )
    .expect("second damaged fixture");
    let mut refs = symbol_query(&corpus.path, "intact", SymbolOp::References);
    refs.document = Some(pin("src/broken.rs", None));
    let result = query(&refs).expect("the damaged pin resolves");
    assert!(symbol_rows(&result).is_empty(), "{:?}", result.matches);
    assert_eq!(
        result.completeness,
        partial(vec![PartialReason::ParseErrors { count: 1 }])
    );
}

#[test]
fn pinned_damaged_document_discloses_its_damage_with_no_rows() {
    // No row matches, yet the pinned document's damaged span may hide
    // one — an empty answer is still partial, never Complete-empty.
    let corpus = completeness_corpus("pin-damaged-empty");
    let mut pinned = symbol_query(&corpus.path, "absent", SymbolOp::Definition);
    pinned.document = Some(pin("src/broken.rs", None));
    let result = query(&pinned).expect("the damaged pin resolves");
    assert!(result.matches.is_empty(), "{:?}", result.matches);
    assert_eq!(
        result.completeness,
        partial(vec![PartialReason::ParseErrors { count: 1 }])
    );
}

#[test]
fn pinned_failed_document_is_a_failed_entry_not_unknown() {
    let corpus = completeness_corpus("pin-failed");
    for path in ["src/latin1.rs", "src/huge.rs"] {
        let mut pinned = symbol_query(&corpus.path, "helper", SymbolOp::Definition);
        pinned.document = Some(pin(path, None));
        let result = query(&pinned).expect("a failed pin still answers");
        assert!(result.matches.is_empty(), "{path}");
        assert!(
            result.unresolved.is_empty(),
            "{path}: it resolved, then failed"
        );
        assert_eq!(
            result.completeness,
            partial(vec![PartialReason::EntriesFailed { count: 1 }]),
            "{path}"
        );
        // Its version cannot be verified either.
        pinned.document = Some(pin(path, Some(1)));
        let err = query(&pinned).expect_err("a version pinned on a failed file refuses");
        assert!(
            matches!(err, ContextError::UnverifiableDocumentVersion { .. }),
            "{path}: {err:?}"
        );
    }
}

#[test]
fn pinned_type_answer_discloses_the_documents_it_draws_on() {
    let tree = tree_of(
        "pin-type-draws",
        &[
            ("src/types.rs", "pub struct Config;\nconst BAD: i32 = ;\n"),
            ("src/make.rs", "pub fn make() -> Config { Config }\n"),
        ],
    );
    let mut typed = symbol_query(&tree.path, "make", SymbolOp::Type);
    typed.document = Some(pin("src/make.rs", None));
    let result = query(&typed).expect("pinned type query resolves");
    assert_eq!(result.matches.len(), 1, "{:?}", result.matches);
    assert_eq!(result.matches[0].source.path, Path::new("src/types.rs"));
    assert!(
        !symbol_hit(&result.matches[0]).resolved,
        "another document's type is served, never claimed"
    );
    // The row comes from a damaged document — that is disclosed even
    // though the pinned one is intact.
    assert_eq!(
        result.completeness,
        partial(vec![PartialReason::ParseErrors { count: 1 }])
    );

    // A type answer may draw on any document, so any stale one counts.
    let tree = tree_of(
        "pin-type-stale",
        &[
            ("src/types.rs", "pub struct Config;\n"),
            ("src/make.rs", "pub fn make() -> Config { Config }\n"),
        ],
    );
    let canonical = tree.path.canonicalize().expect("canonical root");
    let make = path_to_uri(&canonical.join("src/make.rs")).expect("document uri");
    let mut pinned = request("make", SymbolOp::Type);
    pinned.document = Some(&make);
    let index = index_files(&tree, &["src/make.rs", "src/types.rs"], pinned);
    assert_eq!(index.answer().stale_documents, 0);
    std::fs::write(
        tree.path.join("src/types.rs"),
        "pub struct Config; // moved\n",
    )
    .expect("edit the type's document");
    let after = index.answer();
    assert_eq!(after.stale_documents, 1, "the type's document went stale");
    assert!(
        after.matches.iter().all(|hit| !symbol_hit(hit).resolved),
        "{:?}",
        after.matches
    );
}

#[test]
fn pinned_type_answer_discloses_failed_documents() {
    // The document holding `Config` is not utf-8: it failed, so the pinned
    // type answer cannot know the type it names — never Complete.
    // A pinned answer draws on no hint scan: the unclaimed file is no
    // uncovered language to it.
    let tree = tree_of(
        "pin-type-failed",
        &[
            ("src/make.rs", "pub fn make() -> Config { Config }\n"),
            ("src/notes.py", "Config\n"),
        ],
    );
    std::fs::write(
        tree.path.join("src/types.rs"),
        b"pub struct Config;\n// caf\xe9\n",
    )
    .expect("non-utf-8 fixture");
    let mut typed = symbol_query(&tree.path, "make", SymbolOp::Type);
    typed.document = Some(pin("src/make.rs", None));
    let result = query(&typed).expect("pinned type query resolves");
    assert!(
        symbol_rows(&result).iter().all(|row| !row.resolved),
        "{:?}",
        result.matches
    );
    assert_eq!(
        result.completeness,
        partial(vec![PartialReason::EntriesFailed { count: 1 }])
    );
    // Beside a damaged document it may also draw on, both are disclosed;
    // a pinned definition answer still discloses neither.
    std::fs::write(
        tree.path.join("src/broken.rs"),
        "pub struct Other;\nconst BAD: i32 = ;\n",
    )
    .expect("damaged fixture");
    let result = query(&typed).expect("pinned type query resolves");
    assert_eq!(
        result.completeness,
        partial(vec![
            PartialReason::EntriesFailed { count: 1 },
            PartialReason::ParseErrors { count: 1 }
        ])
    );
    typed.symbol_op = Some(SymbolOp::Definition);
    let result = query(&typed).expect("pinned definition resolves");
    assert_eq!(result.completeness, Completeness::Complete);
}

#[test]
fn pinned_definition_counts_only_its_own_staleness() {
    let tree = tree_of(
        "pin-stale-scope",
        &[
            ("src/lib.rs", "fn helper() {}\n"),
            ("src/other.rs", "fn other() {}\n"),
        ],
    );
    let canonical = tree.path.canonicalize().expect("canonical root");
    let lib = path_to_uri(&canonical.join("src/lib.rs")).expect("document uri");
    let mut pinned = request("helper", SymbolOp::Definition);
    pinned.document = Some(&lib);
    let index = index_files(&tree, &["src/lib.rs", "src/other.rs"], pinned);
    std::fs::write(
        tree.path.join("src/other.rs"),
        "fn other() { /* moved */ }\n",
    )
    .expect("edit another document");
    let after = index.answer();
    assert_eq!(
        after.stale_documents, 0,
        "another document's edit is out of scope"
    );
    assert_eq!(after.matches.len(), 1);
}

#[test]
fn unreadable_unclaimed_file_counts_once() {
    // A sparse unclaimed file past the hint scan's 64 MiB read bound is
    // one the scan cannot read — whatever privileges the run has.
    let tree = tree_of(
        "unreadable-unclaimed",
        &[("src/lib.rs", "fn helper() {}\n"), ("src/notes.py", "")],
    );
    std::fs::File::options()
        .write(true)
        .open(tree.path.join("src/notes.py"))
        .expect("open the unclaimed file")
        .set_len(64 * 1024 * 1024 + 1)
        .expect("sparse length past the scan bound");
    let result =
        query(&symbol_query(&tree.path, "helper", SymbolOp::Definition)).expect("query resolves");
    // The hint scan could not read it: a failed entry, not also an
    // uncovered language.
    assert_eq!(
        result.completeness,
        partial(vec![PartialReason::EntriesFailed { count: 1 }])
    );
}

#[test]
fn scope_glob_is_validated_before_the_pin_resolves() {
    let corpus = symbol_corpus("glob-first");
    let mut request = symbol_query(&corpus.path, "helper", SymbolOp::Definition);
    request.scope_glob = Some("src/[".to_string());
    request.document = Some(pin("src/missing.rs", None));
    let err = query(&request).expect_err("a malformed glob refuses");
    assert!(matches!(err, ContextError::InvalidGlob { .. }), "{err:?}");
    assert_eq!(err.error_code(), ErrorCode::InvalidInput);
}
