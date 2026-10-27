//! Structural syntax search over the admitted SRC-007 stack
//! (tree-sitter grammars + ast-grep-core patterns): per-language
//! corpus proof, honest unsupported/damaged coverage, node spans with
//! provenance — and a syntax shape is never sold as a symbol identity.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions fail loudly with the observed payload (standards §14)"
)]

mod support;

use rivect::context::{ContextError, IgnorePolicy, QueryKind, backend_for, query};
use rivect::contracts::ErrorCode;
use rivect::index::{
    Completeness, MatchKind, PartialReason, SearchBackend, SnapshotId, SymbolRole,
};
use rivect::lsp::SymbolOp;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use support::{ast_corpus, find_subsequence, search_query};

/// The byte offset and 1-based line of `needle` inside `bytes` — the
/// span oracle the AST assertions are pinned against.
fn span_of(bytes: &[u8], needle: &[u8]) -> (u64, u64, u64) {
    let start = find_subsequence(bytes, needle).expect("fixture needle present");
    let line = bytes[..start].iter().filter(|byte| **byte == b'\n').count() as u64 + 1;
    (start as u64, (start + needle.len()) as u64, line)
}

/// The `(path, language)` claim of one match — a syntax hit must name
/// its grammar, never a symbol.
fn hit_language(hit: &rivect::index::SearchMatch) -> (&Path, &str) {
    let MatchKind::Ast { language, .. } = &hit.kind else {
        panic!("an ast match carries its language and node kind");
    };
    (hit.source.path.as_path(), language)
}

#[test]
fn ast_pattern_finds_syntax_shapes_on_claimed_languages() {
    let corpus = ast_corpus("shapes");

    // A Rust-shaped pattern compiled under the Rust grammar finds the
    // exact structural shape — and only in files that grammar covers.
    let result = query(&search_query(QueryKind::Ast, &corpus.path, "fn $NAME() {}"))
        .expect("ast query resolves");
    assert_eq!(result.backend, SearchBackend::Ast);
    assert_eq!(result.snapshot, SnapshotId::Live);
    let hits: Vec<(&Path, &str)> = result.matches.iter().map(hit_language).collect();
    assert_eq!(
        hits,
        vec![
            (Path::new("src/lib.rs"), "rust"),
            (Path::new("src/lib.rs"), "rust"),
        ],
        "both empty functions in lib.rs match; the ignored build/ copy does not"
    );
    for hit in &result.matches {
        let MatchKind::Ast { node_kind, .. } = &hit.kind else {
            panic!("ast kind");
        };
        assert_eq!(node_kind, "function_item");
    }

    // The same query cannot see the TypeScript/TSX/Python files: the
    // pattern is not valid syntax under those grammars, so the result
    // discloses the uncovered entries instead of claiming clean space.
    let Completeness::Partial { ref reasons } = result.completeness else {
        panic!("files outside the pattern's grammar coverage are a partial");
    };
    assert!(
        reasons
            .iter()
            .any(|reason| matches!(reason, PartialReason::UnsupportedLanguage { count: 3 })),
        "app.ts + widget.tsx + notes.py are uncovered by a Rust-only pattern: {reasons:?}"
    );

    // A TypeScript-shaped pattern is its own language claim — it finds
    // the function declaration in both TS and TSX grammars.
    let result = query(&search_query(
        QueryKind::Ast,
        &corpus.path,
        "function $NAME($$$PARAMS) { $$$BODY }",
    ))
    .expect("ts pattern resolves");
    let by_path: BTreeMap<&Path, &str> = result.matches.iter().map(hit_language).collect();
    assert_eq!(by_path.get(Path::new("src/app.ts")), Some(&"typescript"));
    assert_eq!(by_path.get(Path::new("src/widget.tsx")), Some(&"tsx"));
    assert!(!by_path.contains_key(Path::new("src/lib.rs")));
    let Completeness::Partial { ref reasons } = result.completeness else {
        panic!("uncovered languages are disclosed");
    };
    assert!(
        reasons
            .iter()
            .any(|reason| matches!(reason, PartialReason::UnsupportedLanguage { count: 2 })),
        "lib.rs + notes.py are uncovered by a TS/TSX pattern: {reasons:?}"
    );
}

#[test]
fn unsupported_language_reports_unsupported_not_empty() {
    let corpus = ast_corpus("unsupported");
    // Scope the walk to the Python file only: the query can cover
    // nothing, and must say so — an explicit partial, never an
    // empty-complete answer.
    let mut request = search_query(QueryKind::Ast, &corpus.path, "fn $NAME() {}");
    request.scope_glob = Some("**/*.py".to_string());

    let result = query(&request).expect("ast query resolves");

    assert!(result.matches.is_empty());
    assert_eq!(
        result.completeness,
        Completeness::Partial {
            reasons: vec![PartialReason::UnsupportedLanguage { count: 1 }]
        },
        "no grammar claims Python — disclosed, never silent"
    );
    assert!(!result.completeness.is_complete());
}

#[test]
fn partial_grammar_coverage_marks_partial() {
    let corpus = ast_corpus("damaged");
    // A Rust file with a syntax error: tree-sitter error recovery still
    // yields the intact function, but the damaged span may hide matches
    // — coverage of this file is partial and the result says so.
    std::fs::write(
        corpus.path.join("src/broken.rs"),
        "fn intact() {}\nconst BAD: i32 = ;\n",
    )
    .expect("damaged fixture");

    let result = query(&search_query(QueryKind::Ast, &corpus.path, "fn $NAME() {}"))
        .expect("ast query resolves");

    // The intact function inside the damaged file is still a real
    // match — partial coverage is served, not dropped.
    assert!(
        result
            .matches
            .iter()
            .any(|hit| hit.source.path == Path::new("src/broken.rs")),
        "the intact subtree still matches"
    );
    let Completeness::Partial { ref reasons } = result.completeness else {
        panic!("a file with error nodes is a disclosed partial");
    };
    assert!(
        reasons
            .iter()
            .any(|reason| matches!(reason, PartialReason::ParseErrors { count: 1 })),
        "the damaged file is counted: {reasons:?}"
    );
    assert!(
        reasons
            .iter()
            .any(|reason| matches!(reason, PartialReason::UnsupportedLanguage { .. })),
        "the Python file stays disclosed too: {reasons:?}"
    );
}

#[test]
fn syntax_match_is_never_reported_as_symbol_identity() {
    let corpus = ast_corpus("identity");
    let result = query(&search_query(QueryKind::Ast, &corpus.path, "fn $NAME() {}"))
        .expect("ast query resolves");

    assert!(!result.matches.is_empty());
    for hit in &result.matches {
        // The payload is structurally an AST shape: it names its
        // grammar and node kind, and no symbol/reference claim exists
        // anywhere on the wire — a syntax coincidence is never a
        // `code.symbol` answer.
        let MatchKind::Ast { .. } = &hit.kind else {
            panic!("a structural hit stays MatchKind::Ast");
        };
        let wire = serde_json::to_value(&hit.kind).expect("kind serializes");
        assert_eq!(wire["kind"], "ast");
        assert!(
            wire.get("symbol").is_none() && wire.get("reference").is_none(),
            "no symbol identity on the wire: {wire}"
        );
    }
    assert_eq!(result.backend, SearchBackend::Ast);
    assert!(
        !result.backend.engine().contains("symbol"),
        "provenance names the grammar engine, never a symbol index"
    );
    // A reference query dispatches to the typed symbol index — syntax
    // matches are never served as symbol identity, and symbol answers
    // never come from the AST leg. Each name carries its own op: `name`
    // is a parameter of both `greet`s (definitions) and used once in
    // app.ts — the reference name serves that use, never a parameter.
    for (name, role, lines) in [
        (
            "code.symbol",
            SymbolRole::Definition,
            vec![("src/app.ts", 1), ("src/lib.rs", 1)],
        ),
        (
            "code.references",
            SymbolRole::Reference,
            vec![("src/app.ts", 2)],
        ),
    ] {
        let kind = QueryKind::from_name(name).expect("recorded name");
        let mut request = search_query(kind, &corpus.path, "name");
        request.symbol_op = SymbolOp::from_interface_name(name);
        let result = query(&request).expect("the symbol backend is admitted");
        assert_eq!(result.backend, SearchBackend::Symbol, "{name}");
        let typed: Vec<(&Path, u64)> = result
            .matches
            .iter()
            .filter_map(|hit| match &hit.kind {
                MatchKind::Symbol(payload) => {
                    assert_eq!(payload.role, role, "{name}");
                    Some((hit.source.path.as_path(), hit.source.line.expect("line")))
                }
                _ => None,
            })
            .collect();
        let expected: Vec<(&Path, u64)> = lines
            .iter()
            .map(|(path, line)| (Path::new(*path), *line))
            .collect();
        assert_eq!(typed, expected, "{name}");
    }
}

#[test]
fn ast_results_carry_language_node_span_and_provenance() {
    let corpus = ast_corpus("provenance");
    let mut request = search_query(QueryKind::Ast, &corpus.path, "fn $NAME() {}");
    request.scope_glob = Some("src/lib.rs".to_string());

    let result = query(&request).expect("ast query resolves");

    assert_eq!(result.backend, SearchBackend::Ast);
    assert_eq!(
        result.backend.engine(),
        "tree-sitter+ast-grep-core",
        "provenance names the real engine stack (SRC-007)"
    );
    assert_eq!(result.snapshot, SnapshotId::Live);
    assert_eq!(result.completeness, Completeness::Complete);
    assert_eq!(result.matches.len(), 2);

    let bytes = std::fs::read(corpus.path.join("src/lib.rs")).expect("fixture bytes");
    let (start, end, line) = span_of(&bytes, b"fn marker_target() {}");
    let hit = result
        .matches
        .iter()
        .find(|hit| hit.source.line == Some(line))
        .expect("the marker_target match");
    assert_eq!(hit.source.path, PathBuf::from("src/lib.rs"));
    assert!(!hit.source.ignored);
    let MatchKind::Ast {
        language,
        node_kind,
        start_byte,
        end_byte,
    } = &hit.kind
    else {
        panic!("ast kind");
    };
    assert_eq!(language.as_str(), "rust");
    assert_eq!(node_kind, "function_item");
    assert_eq!(*start_byte, start);
    assert_eq!(*end_byte, end);

    // The wire shape is pinned literally — a renamed field or tag is a
    // contract break, not an internal detail.
    let wire = serde_json::to_value(&hit.kind).expect("kind serializes");
    assert_eq!(
        wire,
        json!({
            "kind": "ast",
            "language": "rust",
            "node_kind": "function_item",
            "start_byte": start,
            "end_byte": end,
        })
    );
    assert_eq!(
        serde_json::to_value(SearchBackend::Ast).expect("serializes"),
        json!("ast")
    );
}

#[test]
fn grammar_corpus_cases_pass_per_claimed_language() {
    let corpus = ast_corpus("corpus");
    // Every claimed grammar must produce a real match on the corpus —
    // a grammar that cannot parse its fixture is not claimed. One
    // discriminating shape per admitted grammar.
    for (pattern, path, language, node_kind, count) in [
        // lib.rs holds two empty functions; greet's body excludes it.
        ("fn $NAME() {}", "src/lib.rs", "rust", "function_item", 2),
        (
            "function $NAME($$$PARAMS) { $$$BODY }",
            "src/app.ts",
            "typescript",
            "function_declaration",
            1,
        ),
        (
            "function $NAME($$$PARAMS) { $$$BODY }",
            "src/widget.tsx",
            "tsx",
            "function_declaration",
            1,
        ),
    ] {
        let mut request = search_query(QueryKind::Ast, &corpus.path, pattern);
        request.scope_glob = Some(path.to_string());
        let result = query(&request).expect("scoped ast query resolves");
        assert_eq!(
            result.completeness,
            Completeness::Complete,
            "{language} fixture parses cleanly"
        );
        assert_eq!(result.matches.len(), count, "{pattern} on {path}");
        for hit in &result.matches {
            let MatchKind::Ast {
                language: hit_lang,
                node_kind: hit_kind,
                ..
            } = &hit.kind
            else {
                panic!("ast kind");
            };
            assert_eq!(hit_lang.as_str(), language, "{path} reports its grammar");
            assert_eq!(hit_kind, node_kind, "{path} names the matched node kind");
        }
    }
}

#[test]
fn invalid_ast_pattern_is_a_typed_error_not_empty() {
    let corpus = ast_corpus("invalid-pattern");
    // Valid under no admitted grammar — a caller error, never an
    // empty-complete result.
    let err = query(&search_query(QueryKind::Ast, &corpus.path, "fn $NAME( {"))
        .expect_err("a pattern no grammar parses is refused");

    assert!(matches!(err, ContextError::InvalidAstPattern { .. }));
    assert_eq!(err.error_code(), ErrorCode::InvalidInput);
    assert!(
        !err.to_string().ends_with(['.', '!', '?', ';']),
        "display is lowercase without terminal punctuation: {err}"
    );
    // sanity: the same corpus answers a valid pattern
    assert!(
        !query(&search_query(QueryKind::Ast, &corpus.path, "fn $NAME() {}"))
            .expect("valid pattern resolves")
            .matches
            .is_empty()
    );
}

#[test]
fn ast_bound_and_include_semantics_match_other_legs() {
    let corpus = ast_corpus("bounded");
    // The caller's bound is honored — a hit beyond it marks the result
    // partial instead of silently dropping the tail.
    let mut request = search_query(QueryKind::Ast, &corpus.path, "fn $NAME() {}");
    request.scope_glob = Some("**/*.rs".to_string());
    request.limit = 1;
    let result = query(&request).expect("bounded ast query resolves");
    assert_eq!(result.matches.len(), 1);
    let Completeness::Partial { ref reasons } = result.completeness else {
        panic!("a bounded answer is typed partial");
    };
    assert!(
        reasons
            .iter()
            .any(|reason| matches!(reason, PartialReason::LimitReached { limit: 1 })),
        "the bound is disclosed: {reasons:?}"
    );

    // `Include` surfaces the ignored build/ file flagged — the same
    // ignore-provenance rule the text leg follows.
    let mut request = search_query(QueryKind::Ast, &corpus.path, "fn $NAME() {}");
    request.scope_glob = Some("**/*.rs".to_string());
    request.ignore = IgnorePolicy::Include;
    let result = query(&request).expect("include ast query resolves");
    let by_path: BTreeMap<&Path, bool> = result
        .matches
        .iter()
        .map(|hit| (hit.source.path.as_path(), hit.source.ignored))
        .collect();
    assert_eq!(by_path.get(Path::new("build/generated.rs")), Some(&true));
    assert_eq!(by_path.get(Path::new("src/lib.rs")), Some(&false));
}

#[test]
fn ast_backend_joins_the_mechanical_table() {
    // Dispatch stays a fixed table — Ast, Symbol and the graph leg are
    // all admitted now.
    assert_eq!(backend_for(QueryKind::Ast), Some(SearchBackend::Ast));
    assert_eq!(backend_for(QueryKind::Symbol), Some(SearchBackend::Symbol));
    assert_eq!(backend_for(QueryKind::Graph), Some(SearchBackend::Graph));
    assert_eq!(QueryKind::Ast.as_str(), "search.structure");
}

#[test]
fn literal_dollar_bytes_in_rust_patterns_still_match() {
    let corpus = ast_corpus("literal-dollar");
    // `'$'`, `"$schema"` and the `$(`/`$i` transcribers are real Rust
    // bytes — rewriting every `$` sigil would corrupt the pattern into
    // a silent under-match the result reports as complete.
    std::fs::write(
        corpus.path.join("src/dollar.rs"),
        "const DOLLAR: char = '$';\nconst SCHEMA: &str = \"$schema\";\n\nmacro_rules! lit {\n    ($($i:ident),*) => { () };\n}\n",
    )
    .expect("dollar fixture");
    let bytes = std::fs::read(corpus.path.join("src/dollar.rs")).expect("fixture bytes");

    for (pattern, needle) in [
        ("const $C: char = '$';", "'$'"),
        ("const $S: &str = \"$schema\";", "\"$schema\""),
    ] {
        let (start, end, _) = span_of(&bytes, needle.as_bytes());
        let mut request = search_query(QueryKind::Ast, &corpus.path, pattern);
        request.scope_glob = Some("src/dollar.rs".to_string());
        let result =
            query(&request).unwrap_or_else(|err| panic!("pattern `{pattern}` resolves: {err}"));
        assert!(
            result.matches.iter().any(|hit| {
                let MatchKind::Ast {
                    start_byte,
                    end_byte,
                    ..
                } = &hit.kind
                else {
                    return false;
                };
                *start_byte <= start && *end_byte >= end
            }),
            "pattern `{pattern}` matches the literal `{needle}`"
        );
    }

    // The `macro_rules!` transcriber's `$(`/`$i` stay literal — only
    // the `$M` metavar sigil is rewritten.
    let mut request = search_query(
        QueryKind::Ast,
        &corpus.path,
        "macro_rules! $M { ($($i:ident),*) => { () } }",
    );
    request.scope_glob = Some("src/dollar.rs".to_string());
    let result = query(&request).expect("macro pattern resolves");
    assert!(
        result
            .matches
            .iter()
            .any(|hit| hit_language(hit).1 == "rust"),
        "the macro definition still matches"
    );

    // The metavar path itself is untouched — a plain sigil pattern
    // still matches the corpus functions.
    let result = query(&search_query(QueryKind::Ast, &corpus.path, "fn $NAME() {}"))
        .expect("metavar pattern resolves");
    assert!(
        result
            .matches
            .iter()
            .any(|hit| hit.source.path == Path::new("src/lib.rs")),
        "metavars still match"
    );
}

#[test]
fn oversized_file_is_a_failed_entry_not_an_unbounded_read() {
    let corpus = ast_corpus("oversized");
    // A giant generated source past the leg's 64 MiB byte bound fails
    // the entry — the bounded read hauls at most bound + 1 bytes before
    // the oversize verdict lands. `set_len` keeps the fixture sparse.
    let huge = corpus.path.join("src/huge.rs");
    std::fs::File::create(&huge)
        .expect("huge fixture")
        .set_len(64 * 1024 * 1024 + 1)
        .expect("huge fixture length");

    let mut request = search_query(QueryKind::Ast, &corpus.path, "fn $NAME() {}");
    request.scope_glob = Some("**/*.rs".to_string());
    let result = query(&request).expect("ast query resolves");

    // lib.rs still serves; only the oversized entry failed.
    assert_eq!(result.matches.len(), 2);
    assert_eq!(
        result.completeness,
        Completeness::Partial {
            reasons: vec![PartialReason::EntriesFailed { count: 1 }]
        },
        "the oversized file is one failed entry"
    );
}

#[test]
fn file_at_byte_bound_is_damaged_not_failed() {
    let corpus = ast_corpus("at-bound");
    // The size check is a strict `>`: a file of exactly the bound is
    // read, decoded and parsed like any other entry. `set_len` keeps
    // the fixture sparse; all-zero bytes are valid UTF-8 that parse
    // into error nodes — a damaged entry, never a failed one.
    let huge = corpus.path.join("src/huge.rs");
    std::fs::File::create(&huge)
        .expect("huge fixture")
        .set_len(64 * 1024 * 1024)
        .expect("huge fixture length");

    let mut request = search_query(QueryKind::Ast, &corpus.path, "fn $NAME() {}");
    request.scope_glob = Some("**/*.rs".to_string());
    let result = query(&request).expect("ast query resolves");

    assert_eq!(result.matches.len(), 2, "lib.rs still serves both hits");
    assert_eq!(
        result.completeness,
        Completeness::Partial {
            reasons: vec![PartialReason::ParseErrors { count: 1 }]
        },
        "the at-bound file is disclosed damaged, not failed"
    );
}

#[test]
fn oversized_ast_pattern_is_a_typed_refusal() {
    let corpus = ast_corpus("oversized-pattern");
    // Compiling a pattern recurses per nesting level — past the byte
    // bound the refusal is typed, not an uncatchable stack overflow.
    let pattern = "f(".repeat(6 * 1024);
    let err = query(&search_query(QueryKind::Ast, &corpus.path, &pattern))
        .expect_err("an oversized pattern refuses at the boundary");

    let ContextError::AstPatternTooLarge { limit } = err else {
        panic!("an oversized pattern is a typed refusal: {err}");
    };
    assert_eq!(limit, 1024, "the refusal names the bound");
    assert_eq!(err.error_code(), ErrorCode::InvalidInput);
    assert!(
        !err.to_string().ends_with(['.', '!', '?', ';']),
        "display is lowercase without terminal punctuation: {err}"
    );
}

#[test]
fn near_cap_ast_pattern_compiles_and_queries() {
    let corpus = ast_corpus("near-cap");
    // Worst-case nesting costs one byte per level — unary prefix chains
    // like `!`×N — so a 1021-byte pattern recurses ~1020 frames deep
    // through compile, error-scan and drop. The query runs on a fixed
    // 8 MiB stack — the calibration ceiling the bound is sized against;
    // the default test-thread stack is too small for ~1K unoptimized
    // frames. Inside the bound the pattern must compile and serve, not
    // abort: the leg proves the margin, not just the refusal.
    let pattern = "!".repeat(1020) + "x";
    let mut request = search_query(QueryKind::Ast, &corpus.path, &pattern);
    request.scope_glob = Some("src/app.ts".to_string());
    let result = std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || query(&request))
        .expect("probe thread spawns")
        .join()
        .expect("a near-cap pattern compiles and serves without abort")
        .expect("the query resolves");

    assert!(result.matches.is_empty());
    assert_eq!(result.completeness, Completeness::Complete);
}

#[test]
fn pattern_size_bound_admits_at_and_refuses_over() {
    let corpus = ast_corpus("bound-exact");
    // The byte check is a strict `>`: a pattern of exactly the bound
    // compiles and serves, one byte past refuses typed. The padding is
    // a single flat function — a comment inside its block — so the leg
    // pins the size check itself without needing the deep-recursion
    // probe thread.
    let padding = "x".repeat(1024 - "function pad() {/*".len() - "*/}".len());
    let pattern = format!("function pad() {{/*{padding}*/}}");
    assert_eq!(pattern.len(), 1024);

    let result = query(&search_query(QueryKind::Ast, &corpus.path, &pattern))
        .expect("a pattern at the bound is admitted");
    let Completeness::Partial { ref reasons } = result.completeness else {
        panic!("a TypeScript-only pattern discloses the uncovered files");
    };
    assert!(
        reasons
            .iter()
            .any(|reason| matches!(reason, PartialReason::UnsupportedLanguage { count: 2 })),
        "lib.rs + notes.py stay uncovered by the TS/TSX pattern: {reasons:?}"
    );

    let over = format!("{pattern};");
    assert_eq!(over.len(), 1025);
    let err = query(&search_query(QueryKind::Ast, &corpus.path, &over))
        .expect_err("one byte past the bound refuses");
    let ContextError::AstPatternTooLarge { limit } = err else {
        panic!("an over-bound pattern is a typed refusal: {err}");
    };
    assert_eq!(limit, 1024, "the refusal names the bound");
}

#[test]
fn sigil_runs_follow_the_upstream_expando_loop() {
    let corpus = ast_corpus("sigil-runs");
    // The ported `ast-grep-language` loop (vendored 0.45.3
    // pre_process_pattern): a `$`-run rewrites to the expando char only
    // before an `[A-Z_]` name char or as a bare `$$$`; every other run —
    // trailing `$`, `$$`, `$$$$` included — stays literal bytes. Literal
    // dollars are invalid Rust but valid TypeScript identifiers, so the
    // grammar claim itself reports the verdict: a stayed-literal run
    // leaves the `.rs` file uncovered alongside the `.py` file.
    std::fs::write(
        corpus.path.join("src/sigils.ts"),
        "g($);\ng($$);\ng($$$$);\ng();\ng(1);\ng(1, 2);\nlet q = $;\nlet r = $$;\nlet s = $$$$;\nlet t = 0;\n",
    )
    .expect("sigil fixture");

    for (pattern, hits, uncovered) in [
        // A lone `$`, `$$` or `$$$$` run stays a literal identifier —
        // only `$$$` becomes the anonymous multiple that matches any
        // argument run, zero args included.
        ("g($)", 1, 2),
        ("g($$)", 1, 2),
        ("g($$$)", 6, 1),
        ("g($$$$)", 1, 2),
        // Runs closed by a `;` take the in-loop verdict — the `;`
        // iteration flushes the pending run itself.
        ("let $N = $;", 1, 2),
        ("let $N = $$;", 1, 2),
        ("let $N = $$$;", 4, 1),
        ("let $N = $$$$;", 1, 2),
        // A pattern ENDING in the run is the only shape reaching the
        // post-iteration flush: the trailing `$$$` must rewrite to
        // `µµµ` for the pattern to stay valid Rust — a dropped or
        // literal run leaves `let µN =` / `let µN = $$$`, which the
        // Rust grammar rejects, and lib.rs joins the uncovered.
        ("let $N = $$$", 4, 1),
    ] {
        let result = query(&search_query(QueryKind::Ast, &corpus.path, pattern))
            .unwrap_or_else(|err| panic!("pattern `{pattern}` resolves: {err}"));
        assert_eq!(
            result.matches.len(),
            hits,
            "`{pattern}` follows the upstream sigil verdict"
        );
        let Completeness::Partial { ref reasons } = result.completeness else {
            panic!("`{pattern}` leaves the uncovered files disclosed");
        };
        assert!(
            reasons
                .iter()
                .any(|reason| matches!(reason, PartialReason::UnsupportedLanguage { count } if *count == uncovered)),
            "`{pattern}` unclaimed grammars count uncovered: {reasons:?}"
        );
    }

    // `$$F` is a double-sigil capture upstream — under Rust it rewrites
    // to `µµF`; a literal `$$F` is not valid Rust syntax, so the two
    // function hits exist only because the run became a meta-variable.
    let result = query(&search_query(QueryKind::Ast, &corpus.path, "fn $$F() {}"))
        .expect("double-sigil capture resolves");
    assert_eq!(
        result
            .matches
            .iter()
            .filter(|hit| hit_language(hit).1 == "rust")
            .count(),
        2,
        "`$$F` captures both empty function names in lib.rs"
    );
}

#[test]
fn undecodable_file_is_a_disclosed_failure_never_absent() {
    let corpus = ast_corpus("undecodable");
    // Bytes that are not UTF-8 cannot be parsed — the entry fails and
    // the intact files still serve.
    std::fs::write(
        corpus.path.join("src/bad_utf8.rs"),
        b"fn real() {}\nlet bad = \"\xFF\xFE\";\n",
    )
    .expect("invalid utf-8 fixture");

    let mut request = search_query(QueryKind::Ast, &corpus.path, "fn $NAME() {}");
    request.scope_glob = Some("**/*.rs".to_string());
    let result = query(&request).expect("ast query resolves");

    assert_eq!(result.matches.len(), 2, "lib.rs still serves both hits");
    assert_eq!(
        result.completeness,
        Completeness::Partial {
            reasons: vec![PartialReason::EntriesFailed { count: 1 }]
        }
    );
}

#[test]
fn exact_limit_is_complete_not_limit_reached() {
    let corpus = ast_corpus("exact-limit");
    // A bound equal to the match count is not truncation — nothing
    // exists beyond it.
    let mut request = search_query(QueryKind::Ast, &corpus.path, "fn $NAME() {}");
    request.scope_glob = Some("src/lib.rs".to_string());
    request.limit = 2;
    let result = query(&request).expect("ast query resolves");

    assert_eq!(result.matches.len(), 2);
    assert_eq!(result.completeness, Completeness::Complete);
}

#[test]
fn zero_matches_over_full_coverage_is_complete() {
    let corpus = ast_corpus("no-matches");
    // A valid pattern matching nothing over a fully covered scope is
    // an honest empty-complete — nothing failed or hid.
    let mut request = search_query(QueryKind::Ast, &corpus.path, "enum $NAME {}");
    request.scope_glob = Some("src/lib.rs".to_string());
    let result = query(&request).expect("ast query resolves");

    assert!(result.matches.is_empty());
    assert_eq!(result.completeness, Completeness::Complete);
}

#[test]
fn nested_error_nodes_reject_the_pattern_per_grammar() {
    let corpus = ast_corpus("nested-error");
    // `has_error` inspects only the pattern root — an ERROR node
    // nested under a valid wrapper must reject it the same way: this
    // pattern is not valid syntax under any admitted grammar.
    let err = query(&search_query(
        QueryKind::Ast,
        &corpus.path,
        "fn f() { let x = ; }",
    ))
    .expect_err("a pattern with nested error nodes is refused");

    assert!(matches!(err, ContextError::InvalidAstPattern { .. }));
    assert_eq!(err.error_code(), ErrorCode::InvalidInput);
}
