//! Reuse the native index across separate capped workers; check the rows after filesystem changes.

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    reason = "integration assertions and measured worker evidence"
)]

mod support;

use rivect::context::{IsolatedRun, SymbolSession, WORKER_ANSWER_MAX};
use rivect::lsp::SymbolOp;
use std::path::Path;
use std::time::Instant;

#[test]
fn repeated_queries_reuse_fresh_files_and_drop_obsolete_rows() {
    support::ensure_helper();
    let helper = rivect_sandbox_helper::helper_binary().expect("helper");
    let root = tempfile::tempdir().expect("corpus");
    let contents = |i| {
        format!(
            "{}\npub fn needle_{i:02}() {{}}\n",
            "// corpus v1\n".repeat(128)
        )
    };
    for i in 0..48 {
        std::fs::write(root.path().join(format!("mod_{i:02}.rs")), contents(i))
            .expect("corpus file");
    }
    let session = SymbolSession::default();
    let program = support::rivect_binary();
    let run = IsolatedRun {
        program: Path::new(&program),
        helper: &helper,
        deadline: None,
        cancel: &|| false,
        answer_cap: WORKER_ANSWER_MAX,
    };
    let sample = |label: &str, pattern: &str, expected: &[&str], changed: u64| {
        let mut query = support::symbol_query(root.path(), pattern, SymbolOp::Definition);
        if label == "warm" {
            query.limit = 1;
        }
        let start = Instant::now();
        let (answer, work) = session.run(&query, &run).expect("isolated query");
        let micros = start.elapsed().as_micros();
        let work = work.expect("source work measured by worker");
        let paths: Vec<_> = answer
            .matches
            .iter()
            .map(|row| row.source.path.to_str().expect("path"))
            .collect();
        assert_eq!(paths, expected, "{label}");
        assert!(answer.completeness.is_complete(), "{answer:?}");
        println!(
            "index-reuse-v1 {label} wall_us={micros} read={} parsed={} reused={}",
            work.read, work.parsed, work.reused
        );
        assert_eq!(
            work.parsed, changed,
            "{label}: only changed files may be parsed"
        );
        assert_eq!(
            work.read, changed,
            "{label}: only changed source bodies may be read"
        );
    };
    sample("cold", "needle_17", &["mod_17.rs"], 48);
    sample("warm", "needle_17", &["mod_17.rs"], 0);
    let original = root.path().join("mod_17.rs");
    let modified = original
        .metadata()
        .expect("stat")
        .modified()
        .expect("mtime");
    std::fs::write(&original, contents(18)).expect("same-size edit");
    std::fs::File::options()
        .write(true)
        .open(&original)
        .expect("open")
        .set_modified(modified)
        .expect("restore mtime");
    sample("change", "needle_17", &[], 1);
    std::fs::write(&original, contents(17)).expect("restore name");
    std::fs::rename(&original, root.path().join("renamed.rs")).expect("rename");
    sample("rename", "needle_17", &["renamed.rs"], 1);
    std::fs::remove_file(root.path().join("renamed.rs")).expect("delete");
    sample("delete", "needle_17", &[], 0);
    sample("other-name", "needle_18", &["mod_18.rs"], 1);
}
