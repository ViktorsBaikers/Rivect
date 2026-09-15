//! Ratchet tests enforcing `docs/engineering-standards.md` mechanically.
//!
//! These scan `src/` directly, so the invariants hold even when clippy was not
//! what ran — and they catch attempts to locally re-allow workspace-denied
//! lints. Extending a boundary is a conscious act: edit the allowlist constant
//! in this file, in the same diff as the code that needs it.
//!
//! Convention: a `#[cfg(test)]` module must be the last item in a source file;
//! everything after the first `#[cfg(test)]` line is treated as test code and
//! skipped by the source scans.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "test code keeps unwrap/expect conveniences; src/ stays strict (standards §14)"
)]

use std::fs;
use std::path::{Path, PathBuf};

/// Files sanctioned to write process output / exit the process (standards §8 —
/// the CLI boundary owns stderr and the exit code). Paths are relative to `src/`.
const OUTPUT_BOUNDARY: &[&str] = &["main.rs"];

/// Files where process spawning may live (standards §10). A `Command` site
/// anywhere else is a boundary violation until this list is extended on purpose.
const PROCESS_BOUNDARY: &[&str] = &["executor.rs", "executor/macos.rs", "tools.rs"];

/// Panic is a bug, not a control flow (standards §2.2/§4). `unreachable!` with
/// an invariant message and `assert!`/`debug_assert!` stay allowed on purpose.
const PANIC_FAMILY: &[&str] = &[
    ".unwrap()",
    ".expect(",
    "panic!",
    "todo!",
    "unimplemented!",
    "dbg!",
];

/// Direct process output — confined to `OUTPUT_BOUNDARY` (standards §8).
const OUTPUT_FAMILY: &[&str] = &["println!", "eprintln!", "process::exit"];

/// Unsafe constructs — `forbid(unsafe_code)` also covers this at compile time;
/// the scan makes violations visible in the test report too.
const UNSAFE_FAMILY: &[&str] = &[
    "unsafe fn",
    "unsafe {",
    "unsafe{",
    "unsafe impl",
    "unsafe extern",
    "unsafe trait",
];

/// rusqlite API surface — allowed only under `src/state/` (P-002, standards §9).
/// Domain types named `prepare`/`execute` exist outside SQL; only tokens that
/// cannot appear without rusqlite are listed.
const SQL_FAMILY: &[&str] = &[
    "rusqlite",
    "params![",
    "named_params![",
    ".query_row(",
    ".query_map(",
    "TransactionBehavior",
    "OptionalExtension",
];

/// Process spawning — allowed only under `PROCESS_BOUNDARY` (standards §10).
const PROCESS_FAMILY: &[&str] = &["process::Command"];

/// Lint names denied workspace-wide in `Cargo.toml`; re-allowing them per item
/// (outside the sanctioned boundary) is a bypass of the gate, not a judgment
/// call. `dead_code` is included: `#[allow(dead_code)]` on new code is banned
/// outright (standards §3.3).
const DENIED_LINTS: &[&str] = &[
    "unwrap_used",
    "expect_used",
    "panic",
    "todo",
    "unimplemented",
    "dbg_macro",
    "print_stdout",
    "print_stderr",
    "exit",
    "mem_forget",
    "unsafe_code",
    "undocumented_unsafe_blocks",
    "map_err_ignore",
    "let_underscore_must_use",
    "let_underscore_future",
    "arc_with_non_send_sync",
    "unused_async",
    "non_ascii_idents",
    "broken_intra_doc_links",
    "dead_code",
];

/// Untracked concurrency — every spawn is accounted (JoinSet/TaskTracker),
/// every channel bounded, no blocking sleeps (standards §5). `mpsc::channel(`
/// is flagged unless the same line names tokio or `sync_channel` — the only
/// admitted bounded forms.
const CONCURRENCY_FAMILY: &[&str] = &[
    "std::thread::spawn",
    "thread::spawn",
    "std::thread::sleep",
    "thread::sleep",
    "unbounded_channel",
    "mpsc::channel(",
];

/// Debt markers left in comments — no TODO/FIXME inventory lives in `src/`
/// (standards §3.3: no dead code, no speculative placeholders).
const DEBT_MARKERS: &[&str] = &["TODO", "FIXME", "XXX", "HACK"];

/// The only file-level lint allows the standards sanction today: `main.rs` owns
/// process output and exit (standards §8). `rel` is relative to `src/`.
fn permitted_lint_allows(rel: &Path) -> &'static [&'static str] {
    if rel == Path::new("main.rs") {
        &["print_stdout", "print_stderr", "exit"]
    } else {
        &[]
    }
}

fn source_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// All `src/**/*.rs` files as `(absolute, relative)` pairs; `relative` is rooted
/// at `src/` so boundary checks compare module paths, not host directories.
fn source_files() -> Vec<(PathBuf, PathBuf)> {
    let root = source_root();
    let mut files = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read src directory") {
            let path = entry.expect("read dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let rel = path
                    .strip_prefix(&root)
                    .expect("path under src/")
                    .to_path_buf();
                files.push((path, rel));
            }
        }
    }
    files.sort();
    files
}

/// The state layer is the `state` module: `src/state.rs` plus `src/state/**`.
fn is_state_layer(rel: &Path) -> bool {
    rel == Path::new("state.rs") || rel.starts_with(Path::new("state"))
}

fn is_boundary(rel: &Path, boundary: &[&str]) -> bool {
    boundary.iter().any(|b| rel == Path::new(b))
}

/// Non-test portion of a file: everything before the first `#[cfg(test)]`.
fn production_lines(source: &str) -> impl Iterator<Item = (usize, &str)> {
    source
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l))
        .take_while(|(_, l)| !l.trim_start().starts_with("#[cfg(test)]"))
}

#[test]
fn ui_production_scan_includes_run_tui() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/ui.rs");
    let source = fs::read_to_string(path).expect("read ui source");
    assert!(
        production_lines(&source).any(|(_, line)| line.contains("pub fn run_tui(")),
        "ui production scan must include run_tui before trailing test module"
    );
}

#[test]
fn no_panic_family_in_src() {
    let mut violations = Vec::new();
    for (file, _rel) in source_files() {
        let source = fs::read_to_string(&file).expect("read source file");
        for (line_no, line) in production_lines(&source) {
            for pat in PANIC_FAMILY {
                if line.contains(pat) {
                    violations.push(format!("{}:{line_no}: `{pat}`", file.display()));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "panic-family constructs in src/ (standards §2.2):\n{}",
        violations.join("\n")
    );
}

#[test]
fn no_unsafe_in_src() {
    let mut violations = Vec::new();
    for (file, _rel) in source_files() {
        let source = fs::read_to_string(&file).expect("read source file");
        for (line_no, line) in production_lines(&source) {
            for pat in UNSAFE_FAMILY {
                if line.contains(pat) {
                    violations.push(format!("{}:{line_no}: `{pat}`", file.display()));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "unsafe constructs in src/ (standards §10):\n{}",
        violations.join("\n")
    );
}

#[test]
fn output_only_at_cli_boundary() {
    let mut violations = Vec::new();
    for (file, rel) in source_files() {
        if is_boundary(&rel, OUTPUT_BOUNDARY) {
            continue;
        }
        let source = fs::read_to_string(&file).expect("read source file");
        for (line_no, line) in production_lines(&source) {
            for pat in OUTPUT_FAMILY {
                if line.contains(pat) {
                    violations.push(format!("{}:{line_no}: `{pat}`", file.display()));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "process output/exit outside the CLI boundary (standards §8; boundary = {OUTPUT_BOUNDARY:?}):\n{}",
        violations.join("\n")
    );
}

#[test]
fn rusqlite_only_in_state_layer() {
    let mut violations = Vec::new();
    for (file, rel) in source_files() {
        if is_state_layer(&rel) {
            continue;
        }
        let source = fs::read_to_string(&file).expect("read source file");
        for (line_no, line) in production_lines(&source) {
            for pat in SQL_FAMILY {
                if line.contains(pat) {
                    violations.push(format!("{}:{line_no}: `{pat}`", file.display()));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "rusqlite API outside src/state/ (P-002, standards §9):\n{}",
        violations.join("\n")
    );
}

#[test]
fn process_spawns_only_at_boundary() {
    let mut violations = Vec::new();
    for (file, rel) in source_files() {
        if is_boundary(&rel, PROCESS_BOUNDARY) {
            continue;
        }
        let source = fs::read_to_string(&file).expect("read source file");
        for (line_no, line) in production_lines(&source) {
            for pat in PROCESS_FAMILY {
                if line.contains(pat) {
                    violations.push(format!("{}:{line_no}: `{pat}`", file.display()));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "process::Command outside the spawn boundary (standards §10; boundary = {PROCESS_BOUNDARY:?}):\n{}",
        violations.join("\n")
    );
}

fn denied_lint_violations(source: &str, file: &Path, permitted: &[&str]) -> Vec<String> {
    let mut violations = Vec::new();
    let mut attribute: Option<(usize, String)> = None;
    for (line_no, line) in source.lines().enumerate() {
        let trimmed = line.trim_start();
        if attribute.is_none() {
            let starts_attribute = ["#![allow(", "#[allow(", "#![expect(", "#[expect("]
                .iter()
                .any(|prefix| trimmed.starts_with(prefix));
            if starts_attribute {
                attribute = Some((line_no + 1, trimmed.to_string()));
            }
        } else if let Some((_, text)) = attribute.as_mut() {
            text.push_str(trimmed);
        }
        let Some((start, text)) = attribute.as_ref() else {
            continue;
        };
        let Some((_, inner)) = text.split_once('(') else {
            continue;
        };
        let Some(inner) = inner.strip_suffix(")]") else {
            continue;
        };
        for name in inner
            .split(',')
            .map(str::trim)
            .map(|name| name.strip_prefix("clippy::").unwrap_or(name))
        {
            if DENIED_LINTS.contains(&name) && !permitted.contains(&name) {
                violations.push(format!("{}:{}: re-allows `{name}`", file.display(), start));
            }
        }
        attribute = None;
    }
    violations
}

#[test]
fn no_denied_lint_reallow_in_src() {
    let mut violations = Vec::new();
    for (file, rel) in source_files() {
        let permitted = permitted_lint_allows(&rel);
        let source = fs::read_to_string(&file).expect("read source file");
        violations.extend(denied_lint_violations(&source, &file, permitted));
    }
    assert!(
        violations.is_empty(),
        "denied lints re-allowed in src/ — bypasses the Cargo.toml gate (standards §14):\n{}",
        violations.join("\n")
    );
}

#[test]
fn multiline_lint_reallow_is_detected() {
    let source = "#![allow(\n    clippy::panic,\n    reason = \"marker )] payload\",\n)]";
    let file = Path::new("synthetic.rs");
    let violations = denied_lint_violations(source, file, &[]);
    assert_eq!(violations.len(), 1, "multiline re-allow must be reported");
    assert_eq!(
        violations[0], "synthetic.rs:1: re-allows `panic`",
        "violation must identify lint and source shape: {violations:?}"
    );
    let sanctioned = denied_lint_violations(source, file, &["panic"]);
    assert!(sanctioned.is_empty(), "sanctioned lint must remain allowed");
}
#[test]
fn text_too_large_display_uses_text_max_bytes() {
    let path = source_root().join("commands.rs");
    let source = fs::read_to_string(&path).expect("read command source");
    let start = source
        .find("enum SelectionError")
        .expect("selection errors");
    let end = source[start..]
        .find("fn string_array")
        .map(|offset| start + offset)
        .expect("selection parser boundary");
    let selection = &source[start..end];
    assert!(
        selection.contains("custom text exceeds {max} bytes"),
        "TextTooLarge must render the bounded error field"
    );
    assert!(
        selection.contains("max: crate::contracts::TEXT_MAX_BYTES"),
        "TextTooLarge must pass TEXT_MAX_BYTES to its Display field"
    );
    assert!(
        !selection.contains("65_536") && !selection.contains("65536"),
        "TextTooLarge must not hard-code its numeric limit"
    );
}

#[test]
fn no_untracked_concurrency_in_src() {
    let mut violations = Vec::new();
    for (file, _rel) in source_files() {
        let source = fs::read_to_string(&file).expect("read source file");
        for (line_no, line) in production_lines(&source) {
            for pat in CONCURRENCY_FAMILY {
                if line.contains(pat)
                    && !(*pat == "mpsc::channel("
                        && (line.contains("tokio") || line.contains("sync_channel")))
                {
                    violations.push(format!("{}:{line_no}: `{pat}`", file.display()));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "untracked/unbounded concurrency in src/ (standards §5):\n{}",
        violations.join("\n")
    );
}

#[test]
fn no_debt_markers_in_src() {
    let mut violations = Vec::new();
    for (file, _rel) in source_files() {
        let source = fs::read_to_string(&file).expect("read source file");
        for (line_no, line) in production_lines(&source) {
            if !line.trim_start().starts_with("//") {
                continue;
            }
            for pat in DEBT_MARKERS {
                if line.contains(pat) {
                    violations.push(format!("{}:{line_no}: `{pat}`", file.display()));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "debt markers in src/ comments — file the work, don't park it (standards §3.3):\n{}",
        violations.join("\n")
    );
}

#[test]
fn no_cyrillic_in_src() {
    // P-001 bans Cyrillic in strings the code writes; comments may legitimately
    // quote Russian architecture names (project docs are Russian). Whole-line
    // comments are skipped; a string literal can still sit on a code line.
    let mut violations = Vec::new();
    for (file, _rel) in source_files() {
        let source = fs::read_to_string(&file).expect("read source file");
        for (line_no, line) in production_lines(&source) {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            if line.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c)) {
                violations.push(format!("{}:{line_no}", file.display()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "Cyrillic in src/ code — source-authored strings are English (P-001, standards §2):\n{}",
        violations.join("\n")
    );
}
