//! Ratchet tests enforcing `docs/engineering-standards.md` mechanically.
//!
//! These scan `src/` directly, so the invariants hold even when clippy was not
//! what ran — and they catch attempts to locally re-allow workspace-denied
//! lints. Extending a boundary is a conscious act: edit the allowlist constant
//! in this file, in the same diff as the code that needs it.
//!
//! Convention: `production_lines` skips every `#[cfg(test)]` item (its own
//! attributes and body, through its `;` or its closing brace) and resumes
//! after it, so production code after a test item is scanned. A test item
//! still open at the end of a file makes every scan fail.

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
const PROCESS_BOUNDARY: &[&str] = &[
    "executor.rs",
    "executor/linux.rs",
    "executor/macos.rs",
    "mcp.rs",
    "tools.rs",
];

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
    source_files_under(&source_root())
}

/// [`source_files`] for an explicit source root, so fixtures share the traversal.
fn source_files_under(root: &Path) -> Vec<(PathBuf, PathBuf)> {
    files_with_extension(root, "rs")
}

/// Every `*.{extension}` file under `root`, sorted, as `(absolute, relative)`.
fn files_with_extension(root: &Path, extension: &str) -> Vec<(PathBuf, PathBuf)> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read src directory") {
            let path = entry.expect("read dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == extension) {
                let rel = path
                    .strip_prefix(root)
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

/// The literal starting at a byte offset of the scanned source.
enum Literal {
    /// No literal starts here.
    Absent,
    /// The offset just past the literal.
    Ends(usize),
    /// A literal that never closes.
    Open,
}

/// String, raw string, byte string and char literals (a lifetime is not
/// one), so braces and semicolons inside them never count.
fn literal_at(source: &str, at: usize) -> Literal {
    let rest = &source.as_bytes()[at..];
    let prefix = usize::from(rest.first() == Some(&b'b'));
    if rest.get(prefix) == Some(&b'r') {
        let hashes = rest[prefix + 1..]
            .iter()
            .take_while(|byte| **byte == b'#')
            .count();
        let quote = prefix + 1 + hashes;
        if rest.get(quote) != Some(&b'"') {
            return Literal::Absent;
        }
        let mut close = vec![b'"'];
        close.extend(std::iter::repeat_n(b'#', hashes));
        return match rest[quote + 1..]
            .windows(close.len())
            .position(|window| window == close.as_slice())
        {
            Some(found) => Literal::Ends(at + quote + 1 + found + close.len()),
            None => Literal::Open,
        };
    }
    match rest.get(prefix) {
        Some(b'"') => {
            let mut index = prefix + 1;
            while index < rest.len() {
                match rest[index] {
                    b'\\' => index += 2,
                    b'"' => return Literal::Ends(at + index + 1),
                    _ => index += 1,
                }
            }
            Literal::Open
        }
        Some(b'\'') => {
            let body = at + prefix + 1;
            match source[body..].chars().next() {
                Some('\\') => {
                    let after = body + 1;
                    let Some(escaped) = source[after..].chars().next() else {
                        return Literal::Open;
                    };
                    let search = after + escaped.len_utf8();
                    match source.as_bytes()[search..].iter().position(|b| *b == b'\'') {
                        Some(found) => Literal::Ends(search + found + 1),
                        None => Literal::Open,
                    }
                }
                Some(single) => {
                    let close = body + single.len_utf8();
                    if source.as_bytes().get(close) == Some(&b'\'') {
                        Literal::Ends(close + 1)
                    } else {
                        Literal::Absent
                    }
                }
                None => Literal::Absent,
            }
        }
        _ => Literal::Absent,
    }
}

/// The offset just past the test item starting at `start`: through its
/// terminating `;` when it has no body, otherwise through the brace that
/// closes its first `{`. Braces inside literals and comments do not count;
/// `;` inside parentheses or brackets (attribute arguments, array types)
/// does not end the item. `None` when the item never ends.
fn test_item_end(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let (mut index, mut nest, mut braces, mut opened) = (start, 0_usize, 0_usize, false);
    while index < bytes.len() {
        let byte = bytes[index];
        let word_continues =
            index > 0 && (bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'_');
        match byte {
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                let mut depth = 1_usize;
                index += 2;
                while depth > 0 {
                    match (bytes.get(index)?, bytes.get(index + 1)) {
                        (b'/', Some(b'*')) => {
                            depth += 1;
                            index += 2;
                        }
                        (b'*', Some(b'/')) => {
                            depth -= 1;
                            index += 2;
                        }
                        _ => index += 1,
                    }
                }
            }
            b'"' | b'\'' | b'b' | b'r' if !(word_continues && matches!(byte, b'b' | b'r')) => {
                match literal_at(source, index) {
                    Literal::Ends(end) => index = end,
                    Literal::Open => return None,
                    Literal::Absent => index += 1,
                }
            }
            b'(' | b'[' => {
                nest += 1;
                index += 1;
            }
            b')' | b']' => {
                nest = nest.saturating_sub(1);
                index += 1;
            }
            b'{' => {
                braces += 1;
                opened = true;
                index += 1;
            }
            b'}' => {
                braces = braces.saturating_sub(1);
                index += 1;
                if opened && braces == 0 {
                    return Some(index);
                }
            }
            b';' if nest == 0 && !opened => return Some(index + 1),
            _ => index += 1,
        }
    }
    None
}

/// Production lines of one file: every line outside a `#[cfg(test)]`
/// item (a line whose trimmed start is `#[cfg(test)]` begins one). An
/// item that never ends is an error naming its line.
fn try_production_lines(source: &str) -> Result<Vec<(usize, &str)>, String> {
    let mut lines = Vec::new();
    let (mut offset, mut skip_until) = (0_usize, 0_usize);
    for (index, raw) in source.split_inclusive('\n').enumerate() {
        let start = offset;
        offset += raw.len();
        if start < skip_until {
            continue;
        }
        let line = raw.trim_end_matches(['\n', '\r']);
        if line.trim_start().starts_with("#[cfg(test)]") {
            skip_until = test_item_end(source, start)
                .ok_or_else(|| format!("line {}: unterminated `#[cfg(test)]` item", index + 1))?;
            continue;
        }
        lines.push((index + 1, line));
    }
    Ok(lines)
}

/// [`try_production_lines`] for the scans: an unterminated test item
/// fails the scan that reads the file.
fn production_lines(source: &str) -> impl Iterator<Item = (usize, &str)> {
    try_production_lines(source)
        .expect("every #[cfg(test)] item must end")
        .into_iter()
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

/// AC-076: the entry hand is the only way a working directory enters the
/// runtime, and it is what makes instruction discovery reachable at all — a
/// run handed no root discovers nothing. Both product entries make that hand
/// with the directory they were started in; an entry that stops passing one
/// leaves discovery unreachable again. The scan is whitespace-free, so a
/// rustfmt wrap of the call is not a false failure.
#[test]
fn both_entries_hand_a_root_p9() {
    for entry in ["main.rs", "ui.rs"] {
        let source = fs::read_to_string(source_root().join(entry)).expect("read entry source");
        let production: String = production_lines(&source)
            .flat_map(|(_, line)| line.split_whitespace())
            .collect();
        assert!(
            production.contains("set_instructions_root(std::env::current_dir().ok())"),
            "{entry} must hand its working directory to the runtime"
        );
    }
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

/// The one spawn family the standards admit and this check therefore
/// records rather than forbids (FP-098-D / D-100, INV-011).
///
/// Both are `std::thread::spawn` sites whose handle is stored and
/// joined, which is the `JoinSet`/`TaskTracker` discipline the standards
/// require: the check exists to catch an *untracked* spawn, and these two
/// are tracked. Each entry names the caller that owns the handle, so a
/// spawn that loses its handle fails this check's own guard below.
const TRACKED_SPAWNS: &[(&str, &str)] = &[
    (
        "commands.rs",
        "commands.rs::IndexRuns::ensure_owner — the bounded index owner; the \
         handle lives in `IndexRuns::owner` and `IndexRuns::shutdown` joins it \
         from `Drop for Runtime`",
    ),
    (
        "main.rs",
        "main.rs::run_headless — the headless stdin reader; the handle is \
         joined by `run_headless` before it returns",
    ),
    (
        "mcp.rs",
        "mcp.rs::Session::open — the stdio reader thread of one mcp session; the \
         handle lives in `Session::reader` and `Session::shutdown` (also from \
         `Drop for Session`) signals it to stop and joins it, so a peer that \
         keeps its pipe open cannot leave the thread behind",
    ),
];

/// A tracked spawn's caller, so the record cannot outlive its handle.
#[test]
fn every_tracked_spawn_names_a_caller_that_joins_it() {
    for (file, reason) in TRACKED_SPAWNS {
        let path = source_root().join(file);
        let source =
            fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {file}: {error}"));
        assert!(
            reason.contains("join"),
            "{file}: a tracked spawn must say who joins its handle: {reason}"
        );
        assert!(
            source.contains("thread::spawn"),
            "{file}: a tracked spawn entry with no spawn is a stale exemption"
        );
    }
}

/// The ratchet's own rule, as a function of the file and the line, so
/// the rule is testable rather than only observable through whatever
/// `src/` happens to contain today.
///
/// A `thread::spawn` is admitted only in a file [`TRACKED_SPAWNS`] names
/// — the entry records the one sanctioned tracked spawn and nothing
/// else. Every other family member, and every spawn in a file with no
/// entry, is a finding.
fn concurrency_finding(rel: &str, line: &str) -> Option<&'static str> {
    let pattern = CONCURRENCY_FAMILY
        .iter()
        .find(|pattern| line.contains(**pattern))?;
    // A `mpsc::channel(` on a bounded or tokio channel is the admitted
    // spelling; the family lists it because the unbounded form is not.
    if *pattern == "mpsc::channel(" && (line.contains("tokio") || line.contains("sync_channel")) {
        return None;
    }
    let tracked = TRACKED_SPAWNS.iter().any(|(allowed, _)| *allowed == rel);
    let admitted = tracked && line.contains("thread::spawn");
    (!admitted).then_some(*pattern)
}

/// The rule is what a finding rests on, so it is pinned directly: a
/// weakened guard fails here even while `src/` happens to hold nothing
/// that would expose it.
#[test]
fn a_tracked_spawn_entry_admits_only_its_own_file_and_family() {
    let spawn = "    let owner = std::thread::spawn(move || serve(rx));";
    // Admitted: a named file and the spawn family.
    assert_eq!(concurrency_finding("commands.rs", spawn), None);
    assert_eq!(concurrency_finding("main.rs", spawn), None);
    // Refused: the same spawn in a file with no entry.
    assert_eq!(
        concurrency_finding("tools.rs", spawn),
        Some("std::thread::spawn"),
        "an entry for one caller is not an entry for every file"
    );
    // Refused: another family member in an admitted file.
    assert_eq!(
        concurrency_finding("commands.rs", "    let (tx, rx) = mpsc::channel(1);"),
        Some("mpsc::channel("),
        "the entry covers the spawn and not the rest of the family"
    );
    assert_eq!(
        concurrency_finding("main.rs", "    std::thread::sleep(d);"),
        Some("std::thread::sleep"),
        "nor an unbounded wait in the same file"
    );
    // Admitted: a bounded channel spelling is not in the family.
    assert_eq!(
        concurrency_finding("commands.rs", "    let (tx, rx) = sync_channel(1);"),
        None
    );
}

#[test]
fn no_untracked_concurrency_in_src() {
    let mut violations = Vec::new();
    for (file, rel) in source_files() {
        let source = fs::read_to_string(&file).expect("read source file");
        let rel = rel.to_string_lossy().replace('\\', "/");
        let mut spawns = 0;
        for (line_no, line) in production_lines(&source) {
            if let Some(pattern) = concurrency_finding(&rel, line) {
                violations.push(format!("{}:{line_no}: `{pattern}`", file.display()));
            }
            if TRACKED_SPAWNS.iter().any(|(allowed, _)| *allowed == rel)
                && line.contains("thread::spawn")
            {
                spawns += 1;
            }
        }
        assert!(
            !TRACKED_SPAWNS.iter().any(|(allowed, _)| *allowed == rel) || spawns > 0,
            "{rel}: the tracked-spawn entry is stale, nothing spawns there"
        );
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

/// The only `context`/`lsp` functions production code outside those two
/// files may call (DEC-028/033): the isolated runs, the worker mode, the
/// backend table, the URI helper and the module-path layout helper.
/// Untrusted parsing reaches the in-process engine through the worker
/// alone.
const UNTRUSTED_PARSE_ALLOWLIST: &[&str] = &[
    // `context::query_isolated` — the query runtime caller
    // (`commands.rs::build_project_index` is the project one below; the
    // in-process `context::query` stays the worker's own engine).
    "context::query_isolated",
    // SLICE-032: the project-index run `commands.rs::build_project_index`
    // and `commands.rs::reindex_from_watch` make — the second runtime
    // parse surface, and the only one besides `query_isolated`. It is an
    // isolated caller, never an in-process fallback.
    "context::project_index_isolated",
    "context::serve_index_worker",
    "context::backend_for",
    "lsp::path_to_uri",
    // SLICE-032: the Cargo module-path layout `index.rs::Subject`'s
    // candidate resolution reads. It maps a module path to spelled
    // project-relative paths and opens nothing, so it parses no
    // untrusted content; the layout table itself stays in `lsp.rs`, the
    // one owner of it.
    "lsp::module_files",
    // SLICE-032: the same layout read in the other direction, for the
    // module a subject document sits under. Called by
    // `index.rs::derive_edges`, so a graph edge and a symbol row name
    // one module from one function instead of two copies of the layout.
    "lsp::module_name",
];

/// Engine types and crates that parse untrusted content in-process.
const ENGINE_TOKENS: &[&str] = &["SymbolIndex", "tree_sitter", "ast_grep_core", "AstGrep"];

/// Engine entries inside `context.rs`, counted at a word boundary on
/// non-comment production lines. A new call site changes the count and
/// must be reviewed against the worker-only routing before this pin moves.
const ENGINE_ENTRIES: &[(&str, usize)] = &[
    // `query`'s definition only.
    ("query(", 1),
    // Its definition, `query`, and the worker's `worker_answer`.
    ("query_until(", 3),
    ("ast_query(", 2),
    ("symbol_query(", 2),
    ("SymbolIndex::build(", 1),
    ("AstGrep::", 1),
];

/// `context`/`lsp` function paths outside the allowlist, alias or glob
/// imports of those modules, and engine tokens — one line per finding.
fn untrusted_parse_violations(source: &str, file: &Path) -> Vec<String> {
    let mut violations = Vec::new();
    let mut report = |line_no: usize, finding: String| {
        violations.push(format!("{}:{line_no}: {finding}", file.display()));
    };
    // A multi-line `use` is joined into one statement, reported at its
    // first line, so a split brace list cannot hide an import.
    let mut statements: Vec<(usize, String)> = Vec::new();
    let mut open_use: Option<(usize, String)> = None;
    for (line_no, line) in production_lines(source) {
        let trimmed = line.trim();
        if let Some((_, text)) = open_use.as_mut() {
            text.push_str(trimmed);
        } else if ["use ", "pub use ", "pub(crate) use "]
            .iter()
            .any(|prefix| trimmed.starts_with(prefix))
        {
            open_use = Some((line_no, trimmed.to_string()));
        } else {
            statements.push((line_no, trimmed.to_string()));
            continue;
        }
        if trimmed.contains(';')
            && let Some(statement) = open_use.take()
        {
            statements.push(statement);
        }
    }
    statements.extend(open_use);

    for (line_no, text) in &statements {
        for token in ENGINE_TOKENS {
            if text.contains(token) {
                report(*line_no, format!("engine token {token}"));
            }
        }
        for module in ["context", "lsp"] {
            let segment = format!("{module}::");
            let at_boundary = |at: usize| {
                !text[..at]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_')
            };
            if text
                .match_indices(&format!("{module} as "))
                .any(|(at, _)| at_boundary(at))
            {
                report(*line_no, format!("alias import of {module}"));
            }
            for (at, _) in text.match_indices(&segment) {
                if !at_boundary(at) {
                    continue;
                }
                let rest = &text[at + segment.len()..];
                let items: Vec<&str> = match rest.strip_prefix('{') {
                    Some(list) => list.split('}').next().unwrap_or("").split(',').collect(),
                    None => vec![rest],
                };
                for item in items.iter().map(|item| item.trim()) {
                    if item.starts_with('*') {
                        report(*line_no, format!("glob import of {module}"));
                        continue;
                    }
                    let name: String = item
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    // `{self as x}` aliases the module as surely as
                    // `module as x` does.
                    if name == "self" && item.contains(" as ") {
                        report(*line_no, format!("alias import of {module}"));
                        continue;
                    }
                    let is_function = name.starts_with(|c: char| c.is_ascii_lowercase());
                    let path = format!("{module}::{name}");
                    if is_function
                        && name != "self"
                        && !UNTRUSTED_PARSE_ALLOWLIST.contains(&path.as_str())
                    {
                        report(*line_no, path);
                    }
                }
            }
        }
    }
    violations
}

#[test]
fn untrusted_parse_has_no_runtime_caller_outside_the_worker() {
    let mut violations = Vec::new();
    for (file, rel) in source_files() {
        if rel == Path::new("context.rs") || rel == Path::new("lsp.rs") {
            continue;
        }
        let source = fs::read_to_string(&file).expect("read source file");
        violations.extend(untrusted_parse_violations(&source, &file));
    }
    assert!(
        violations.is_empty(),
        "untrusted parsing reachable outside the index worker (DEC-028/033):\n{}",
        violations.join("\n")
    );

    let context = fs::read_to_string(source_root().join("context.rs")).expect("read context.rs");
    for (token, pinned) in ENGINE_ENTRIES {
        let count: usize = production_lines(&context)
            .filter(|(_, line)| !line.trim_start().starts_with("//"))
            .map(|(_, line)| {
                line.match_indices(token)
                    .filter(|(at, _)| {
                        !line[..*at]
                            .chars()
                            .next_back()
                            .is_some_and(|c| c.is_alphanumeric() || c == '_')
                    })
                    .count()
            })
            .sum();
        assert_eq!(
            count, *pinned,
            "context.rs engine entry `{token}` count moved — route the new site through the worker, then re-pin"
        );
    }
}

#[test]
fn untrusted_parse_guard_flags_imports_aliases_and_engine_types() {
    let source = "use crate::context::{\n    Query,\n    query,\n};\nuse crate::context as c;\nuse crate::lsp::*;\nfn f() { tree_sitter::Parser::new(); }\nfn g() { AstGrep::new(root, lang); }\nfn h() { crate::lsp::SymbolIndex::build(); }\nuse crate::context::{Query, QueryKind};\nfn i() { rivect::context::query_isolated(&q, &run); }\nuse crate::context::{self as ctx};\nuse crate::lsp::{Query, self as l};\nuse crate::context::{self};\n";
    let violations = untrusted_parse_violations(source, Path::new("synthetic.rs"));
    assert_eq!(
        violations,
        [
            "synthetic.rs:1: context::query",
            "synthetic.rs:5: alias import of context",
            "synthetic.rs:6: glob import of lsp",
            "synthetic.rs:7: engine token tree_sitter",
            "synthetic.rs:8: engine token AstGrep",
            "synthetic.rs:9: engine token SymbolIndex",
            "synthetic.rs:12: alias import of context",
            "synthetic.rs:13: alias import of lsp",
        ],
        "each finding names its line; allowlisted calls and type imports pass"
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

fn scanned_text(source: &str) -> Vec<String> {
    production_lines(source)
        .map(|(_, line)| line.trim().to_string())
        .collect()
}

#[test]
fn state_production_scan_includes_the_proof_tail() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/state.rs");
    let source = fs::read_to_string(path).expect("read state source");
    let lines = scanned_text(&source);
    assert!(
        lines.iter().any(|line| line == "mod proof {"),
        "the #[cfg(not(test))] proof module is production"
    );
    assert!(
        lines
            .iter()
            .any(|line| line == "pub(super) fn fault(_: Site) -> rusqlite::Result<()> {"),
        "the production proof seam is scanned"
    );
    assert!(
        !lines
            .iter()
            .any(|line| line == "use rusqlite::trace::{TraceEvent, TraceEventCodes};"),
        "the #[cfg(test)] proof twin is not production"
    );
}

#[test]
fn production_scan_resumes_after_every_kind_of_test_item() {
    let violation = "    std::process::exit(1);";
    for (label, head) in [
        (
            "non-tail mod",
            "#[cfg(test)]\nmod tests {\n    fn t() { let _marker = 1; }\n}\n",
        ),
        (
            "early fn",
            "#[cfg(test)]\nfn helper() {\n    let _marker = 2;\n}\n",
        ),
        (
            "use",
            "#[cfg(test)]\nuse std::collections::{BTreeMap, BTreeSet};\n",
        ),
        (
            "literals",
            "#[cfg(test)]\nfn literals() {\n    let _marker = ('}', '{', \"}{\", r#\"}\"#, b'}', '\\'');\n}\n",
        ),
        (
            "stacked attributes",
            "#[cfg(test)]\n#[allow(dead_code, reason = \"a;b\")]\nfn stacked() -> [u8; 2] {\n    let _marker = 3;\n    [0, 0]\n}\n",
        ),
        (
            "comments",
            "#[cfg(test)]\nfn commented() {\n    // }\n    /* } /* } */ } */\n    let _marker = 4;\n}\n",
        ),
    ] {
        let source = format!("fn before() {{}}\n{head}fn after() {{\n{violation}\n}}\n");
        let lines = scanned_text(&source);
        assert!(
            lines.iter().any(|line| line == violation.trim()),
            "{label}: production code after the test item is scanned: {lines:?}"
        );
        assert!(
            !lines.iter().any(|line| line.contains("_marker")),
            "{label}: the test item body is skipped: {lines:?}"
        );
    }
}

#[test]
fn every_scan_family_sees_a_violation_after_a_test_module() {
    for family in [
        PANIC_FAMILY,
        OUTPUT_FAMILY,
        UNSAFE_FAMILY,
        SQL_FAMILY,
        PROCESS_FAMILY,
        CONCURRENCY_FAMILY,
    ] {
        for pattern in family {
            let source =
                format!("#[cfg(test)]\nmod tests {{\n}}\nfn prod() {{\n    {pattern}\n}}\n");
            assert!(
                production_lines(&source).any(|(_, line)| line.contains(pattern)),
                "`{pattern}` placed after a test module must be scanned"
            );
        }
    }
}

#[test]
fn an_unterminated_test_item_is_an_error() {
    assert!(try_production_lines("#[cfg(test)]\nmod tests {\n    fn t() {\n").is_err());
    assert!(try_production_lines("#[cfg(test)]\nuse std::fs").is_err());
    assert!(try_production_lines("fn only() {}\n#[cfg(test)]\nmod t {}\n").is_ok());
}

/// The binding fields only the owner may rebind.
const BINDING_FIELDS: &[&str] = &["owner", "policy", "store", "generation"];

/// The sanctioned rebind sites outside `src/owner.rs`: file (relative to
/// `src/`), nearest enclosing `fn`, normalized line text; each exactly once.
const REBIND_ALLOWED: &[(&str, &str, &str)] = &[
    (
        "commands.rs",
        "ensure_owner",
        "self.owner = Some(std::thread::spawn(move || {",
    ),
    (
        "executor.rs",
        "refresh",
        "snapshot.generation = snapshot.generation.saturating_add(1);",
    ),
    (
        "executor.rs",
        "advance",
        "snapshot.generation = snapshot.generation.saturating_add(1);",
    ),
];

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The name of the `fn` a line declares, if any.
fn declared_fn(line: &str) -> Option<String> {
    let text = line.trim_start();
    let at = text.find("fn ")?;
    if at > 0 && is_word_byte(text.as_bytes()[at - 1]) {
        return None;
    }
    let name: String = text[at + 3..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// Occurrences of `.field` as a whole field name.
fn field_mentions<'a>(text: &'a str, field: &str) -> Vec<&'a str> {
    let pattern = format!(".{field}");
    text.match_indices(pattern.as_str())
        .map(|(at, found)| at + found.len())
        .filter(|end| !text.as_bytes().get(*end).is_some_and(|b| is_word_byte(*b)))
        .map(|end| &text[end..])
        .collect()
}

/// Whether a line assigns (`=`, not `==`/`=>`) or `mem::`-moves a binding field.
fn rebinds_binding_field(text: &str) -> bool {
    let assigns = BINDING_FIELDS.iter().any(|field| {
        field_mentions(text, field).into_iter().any(|rest| {
            let rest = rest.trim_start();
            rest.starts_with('=') && !rest[1..].starts_with(['=', '>'])
        })
    });
    let moves = ["mem::swap(", "mem::replace(", "mem::take("]
        .iter()
        .any(|call| text.contains(call))
        && BINDING_FIELDS
            .iter()
            .any(|field| !field_mentions(text, field).is_empty());
    assigns || moves
}

/// Violations of the single-binding rule in one non-test source file.
fn rebind_violations(rel: &str, source: &str) -> Result<Vec<String>, String> {
    let mut current_fn = String::new();
    let mut sites = Vec::new();
    let mut violations = Vec::new();
    for (line_no, line) in try_production_lines(source)? {
        if let Some(name) = declared_fn(line) {
            current_fn = name;
        }
        let text = line.trim();
        if text.starts_with("//") {
            continue;
        }
        if text.contains("TaskStore::open(") && rel != "owner.rs" {
            violations.push(format!(
                "{rel}:{line_no}: `TaskStore::open(` outside the owner"
            ));
        }
        if rebinds_binding_field(text) {
            sites.push((line_no, current_fn.clone(), text.to_string()));
        }
    }
    for (file, function, text) in REBIND_ALLOWED {
        if *file != rel {
            continue;
        }
        match sites
            .iter()
            .position(|(_, found_fn, found)| found_fn == function && found == text)
        {
            Some(position) => {
                sites.remove(position);
            }
            None => violations.push(format!(
                "{rel}: allowed site `{text}` in `{function}` is missing"
            )),
        }
    }
    for (line_no, function, text) in sites {
        violations.push(format!("{rel}:{line_no}: rebind in `{function}`: `{text}`"));
    }
    Ok(violations)
}

/// Non-test source files outside the named-SQL constants.
fn non_sql_sources() -> Vec<(String, String)> {
    source_files()
        .into_iter()
        .filter(|(_, rel)| !rel.starts_with("state/sql"))
        .map(|(file, rel)| {
            (
                rel.to_string_lossy().into_owned(),
                fs::read_to_string(file).expect("read source file"),
            )
        })
        .collect()
}

#[test]
fn store_open_and_binding_rebind_only_through_owner() {
    let mut violations = Vec::new();
    for (rel, source) in non_sql_sources() {
        violations.extend(rebind_violations(&rel, &source).expect("test items end"));
    }
    assert!(
        violations.is_empty(),
        "store open or binding rebind outside the owner:\n{}",
        violations.join("\n")
    );
}

#[test]
fn rebind_scan_flags_controls_and_passes_the_allowed_sites() {
    for (label, source) in [
        (
            "owner",
            "fn f(rt: &mut Runtime) {\n    runtime.owner = owner;\n}\n",
        ),
        (
            "generation",
            "fn f(o: &mut Owner) {\n    owner.generation = 2;\n}\n",
        ),
        (
            "swap",
            "fn f(rt: &mut Runtime) {\n    std::mem::swap(&mut rt.policy, &mut p);\n}\n",
        ),
        (
            "store",
            "fn f(e: &mut Executor) {\n    executor.store = foreign;\n}\n",
        ),
        ("open", "fn f() {\n    let s = TaskStore::open(&p);\n}\n"),
    ] {
        let found = rebind_violations("other.rs", source).expect("controls end");
        assert_eq!(found.len(), 1, "{label}: {found:?}");
    }
    let allowed =
        "fn ensure_owner(&mut self) {\n    self.owner = Some(std::thread::spawn(move || {\n}\n";
    assert!(
        rebind_violations("commands.rs", allowed)
            .expect("allowed ends")
            .is_empty()
    );
    let wrong_fn =
        "fn elsewhere(&mut self) {\n    self.owner = Some(std::thread::spawn(move || {\n}\n";
    assert!(
        !rebind_violations("commands.rs", wrong_fn)
            .expect("wrong fn ends")
            .is_empty(),
        "an allowed text in another function is flagged"
    );
    let twice = "fn ensure_owner(&mut self) {\n    self.owner = Some(std::thread::spawn(move || {\n    self.owner = Some(std::thread::spawn(move || {\n}\n";
    assert!(
        !rebind_violations("commands.rs", twice)
            .expect("twice ends")
            .is_empty(),
        "a changed count is flagged"
    );
    let generation = "fn refresh() {\n    snapshot.generation = snapshot.generation.saturating_add(1);\n}\nfn advance() {\n    snapshot.generation = snapshot.generation.saturating_add(1);\n}\n";
    assert!(
        rebind_violations("executor.rs", generation)
            .expect("generation ends")
            .is_empty()
    );
}

/// Whether `line` names `word` (case-insensitively) as a whole word.
fn names_word_ci(line: &str, word: &str) -> bool {
    let upper = line.to_ascii_uppercase();
    let word = word.to_ascii_uppercase();
    upper.match_indices(&word).any(|(at, found)| {
        let before = at.checked_sub(1).and_then(|i| upper.as_bytes().get(i));
        let after = upper.as_bytes().get(at + found.len());
        !before.is_some_and(|b| is_word_byte(*b)) && !after.is_some_and(|b| is_word_byte(*b))
    })
}

/// Net `{` minus `}` of one source line, ignoring braces inside string
/// and char literals and after a `//` comment start.
fn code_brace_delta(line: &str) -> isize {
    let chars: Vec<char> = line.chars().collect();
    let (mut index, mut delta) = (0_usize, 0_isize);
    while index < chars.len() {
        match chars[index] {
            '/' if chars.get(index + 1) == Some(&'/') => break,
            '"' => {
                index += 1;
                while index < chars.len() && chars[index] != '"' {
                    index += if chars[index] == '\\' { 2 } else { 1 };
                }
            }
            '\'' => {
                let escaped = chars.get(index + 1) == Some(&'\\');
                let close = index + if escaped { 3 } else { 2 };
                if chars.get(close) == Some(&'\'') {
                    index = close;
                }
            }
            '{' => delta += 1,
            '}' => delta -= 1,
            _ => {}
        }
        index += 1;
    }
    delta
}

/// Violations of the one-connect-site rule in one non-test source file.
fn raw_connection_violations(rel: &str, source: &str) -> Result<Vec<String>, String> {
    let mut violations = Vec::new();
    let mut connect_depth: Option<isize> = None;
    for (line_no, line) in try_production_lines(source)? {
        let text = line.trim();
        if text.starts_with("//") {
            continue;
        }
        if rel == "state.rs" && connect_depth.is_none() && text.contains("fn connect(") {
            connect_depth = Some(0);
        }
        let inside_connect = connect_depth.is_some();
        if let Some(depth) = connect_depth.as_mut() {
            *depth += code_brace_delta(text);
            if *depth <= 0 && text.contains('}') {
                connect_depth = None;
            }
        }
        if (text.contains("Connection::open") || text.contains("Connection::from_handle"))
            && !inside_connect
        {
            violations.push(format!(
                "{rel}:{line_no}: raw connection outside `fn connect`"
            ));
        }
        if text.contains("Connection as ") {
            violations.push(format!("{rel}:{line_no}: `Connection` renamed"));
        }
        if (text.starts_with("type ") || text.starts_with("pub type "))
            && text.contains('=')
            && text.contains("Connection")
        {
            violations.push(format!("{rel}:{line_no}: `Connection` aliased"));
        }
    }
    Ok(violations)
}

/// Raw-connection and named-SQL `ATTACH` findings for every file under `root`.
fn raw_connection_scan(root: &Path) -> Vec<String> {
    let mut violations = Vec::new();
    let named_sql = files_with_extension(root, "sql")
        .into_iter()
        .filter(|(_, rel)| rel.starts_with("state/sql"));
    for (file, rel) in source_files_under(root).into_iter().chain(named_sql) {
        let source = fs::read_to_string(&file).expect("read source file");
        let rel = rel.to_string_lossy().into_owned();
        if file.extension().is_some_and(|ext| ext == "rs") {
            violations.extend(raw_connection_violations(&rel, &source).expect("test items end"));
        }
        if rel.starts_with("state/sql") {
            for (index, line) in source.lines().enumerate() {
                if !line.trim_start().starts_with("//") && names_word_ci(line, "attach") {
                    violations.push(format!("{rel}:{}: ATTACH in named SQL", index + 1));
                }
            }
        }
    }
    violations
}

#[test]
fn no_raw_sqlite_connection_outside_connect() {
    let violations = raw_connection_scan(&source_root());
    assert!(
        violations.is_empty(),
        "raw SQLite connections outside `fn connect`:\n{}",
        violations.join("\n")
    );
}

#[test]
fn raw_connection_scan_flags_controls() {
    let second = "impl TaskStore {\n    fn connect() {\n        Connection::open_with_flags(a, b);\n    }\n    fn other() {\n        Connection::open_with_flags(a, b);\n    }\n}\n";
    let found = raw_connection_violations("state.rs", second).expect("ends");
    assert_eq!(found.len(), 1, "{found:?}");
    // A brace inside a string literal is not a body brace: the function
    // ends at its real closing brace, so a later raw open is flagged.
    let literal = "impl TaskStore {\n    fn connect() {\n        let open = \"{\";\n    }\n    fn other() {\n        Connection::open_with_flags(a, b);\n    }\n}\n";
    let found = raw_connection_violations("state.rs", literal).expect("ends");
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains(":6:"), "{found:?}");
    assert_eq!(code_brace_delta("let a = '{'; let b = \"}{\"; // {"), 0);
    assert!(found[0].contains(":6:"), "{found:?}");
    let alias = "use rusqlite::Connection as Db;\n";
    assert_eq!(
        raw_connection_violations("state.rs", alias)
            .expect("ends")
            .len(),
        1
    );
    let type_alias = "type Handle = rusqlite::Connection;\n";
    assert_eq!(
        raw_connection_violations("state.rs", type_alias)
            .expect("ends")
            .len(),
        1
    );
    assert!(names_word_ci("ATTACH DATABASE x", "attach"));
    assert!(names_word_ci("attach database x", "attach"));
    assert!(!names_word_ci(
        "SELECT attachment_id FROM attachments",
        "attach"
    ));
    // Named SQL is `.sql`, not `.rs`: discovery over a real tree must still
    // reach it, and only the dangerous statement may be flagged.
    let fixture = tempfile::TempDir::with_prefix("rivect-sql-discovery-").expect("fixture root");
    let sql = fixture.path().join("state").join("sql");
    fs::create_dir_all(&sql).expect("create named sql directory");
    fs::write(
        sql.join("attach.sql"),
        "-- named statement\nATTACH DATABASE 'other.db' AS other;\n",
    )
    .expect("write dangerous sql");
    fs::write(
        sql.join("safe.sql"),
        "SELECT attachment_id FROM attachments;\n",
    )
    .expect("write safe sql");
    assert_eq!(
        raw_connection_scan(fixture.path()),
        vec!["state/sql/attach.sql:2: ATTACH in named SQL".to_string()]
    );
}

#[test]
fn no_credential_change_in_rivect() {
    const CALLS: &[&str] = &[
        "setuid",
        "setgid",
        "setresuid",
        "setreuid",
        "seteuid",
        "setgroups",
        "setsid",
    ];
    let mut violations = Vec::new();
    for (file, _rel) in source_files() {
        let source = fs::read_to_string(&file).expect("read source file");
        for (line_no, line) in production_lines(&source) {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for call in CALLS {
                if line.contains(call) {
                    violations.push(format!("{}:{line_no}: `{call}`", file.display()));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "rivect never changes credentials or sessions:\n{}",
        violations.join("\n")
    );
}

/// Every `src/**` line, test modules included, must not clear a poisoned
/// registry.
fn clear_poison_lines(source: &str) -> Vec<usize> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains("clear_poison"))
        .map(|(index, _)| index + 1)
        .collect()
}

#[test]
fn registry_poison_is_never_cleared() {
    let mut violations = Vec::new();
    for (file, _rel) in source_files() {
        let source = fs::read_to_string(&file).expect("read source file");
        for line_no in clear_poison_lines(&source) {
            violations.push(format!("{}:{line_no}", file.display()));
        }
    }
    assert!(
        violations.is_empty(),
        "the writer registry poison flag is never cleared:\n{}",
        violations.join("\n")
    );
    assert_eq!(
        clear_poison_lines("fn f() {\n    REGISTRY.clear_poison();\n}\n"),
        [2]
    );
}

/// The files that own the MCP one-shot artifact (standards §15): the module
/// that opens and appends it, and the dispatcher that names the destination it
/// is admitted against. Evidence a terminal path can delete or rewrite proves
/// nothing, so neither file may hold a removal or a truncating write — the
/// artifact is only ever opened to append. The behavioural half of the claim
/// (the artifact resolves under the operator's data root, outside every
/// disposable child tree) is asserted in `tests/mcp.rs`.
const MCP_EVIDENCE_OWNERS: &[&str] = &["mcp.rs", "commands.rs"];

/// Deletion of a path, whatever it names. Longer spellings first, so a line is
/// reported once, by the most specific call it makes.
const REMOVAL_FAMILY: &[&str] = &["remove_dir_all", "remove_file", "remove_dir"];

/// A write that discards what is already there.
const TRUNCATING_FAMILY: &[&str] = &["truncate(true)", "set_len(", "File::create(", "fs::write("];

/// Every production line of `source` naming one of `needles`, once per line.
fn forbidden_lines(source: &str, needles: &[&'static str]) -> Vec<(usize, &'static str)> {
    let mut found = Vec::new();
    for (line_no, line) in production_lines(source) {
        if let Some(needle) = needles.iter().find(|needle| line.contains(*needle)) {
            found.push((line_no, *needle));
        }
    }
    found
}

#[test]
fn mcp_evidence_is_never_deleted_or_overwritten() {
    let root = source_root();
    let mut violations = Vec::new();
    for owner in MCP_EVIDENCE_OWNERS {
        let path = root.join(owner);
        let source = fs::read_to_string(&path).expect("read an mcp evidence owner");
        for (line_no, needle) in forbidden_lines(&source, REMOVAL_FAMILY) {
            violations.push(format!("{owner}:{line_no}: `{needle}`"));
        }
        for (line_no, needle) in forbidden_lines(&source, TRUNCATING_FAMILY) {
            violations.push(format!("{owner}:{line_no}: `{needle}`"));
        }
    }
    assert!(
        violations.is_empty(),
        "the retained mcp artifact is never deleted or overwritten (one-shot contract §15):\n{}",
        violations.join("\n")
    );
    // Only the artifact's owner resolves a path into the directory it is
    // retained in, so no other module can address the evidence by name.
    let mut spelling = Vec::new();
    for (file, rel) in source_files() {
        let source = fs::read_to_string(&file).expect("read source file");
        if production_lines(&source).any(|(_, line)| line.contains("MCP_REPORTS_DIR")) {
            spelling.push(rel.display().to_string());
        }
    }
    assert_eq!(
        spelling,
        ["mcp.rs"],
        "the reports directory is spelled only by the module that appends to it"
    );
    // The scan can disagree: it reads the shapes it forbids.
    let removal = "fn cleanup(root: &Path) {\n    drop(std::fs::remove_dir_all(root));\n}\n";
    assert_eq!(
        forbidden_lines(removal, REMOVAL_FAMILY),
        [(2, "remove_dir_all")],
        "the ratchet reads a removal path"
    );
    let rewrite = "fn reopen(path: &Path) {\n    File::create(path).expect(\"reopen\");\n}\n";
    assert_eq!(
        forbidden_lines(rewrite, TRUNCATING_FAMILY),
        [(2, "File::create(")],
        "the ratchet reads a truncating write"
    );
    // A skipped test item is not production: a fixture may remove its own root.
    let fixture = "#[cfg(test)]\nmod tests {\n    fn write() {\n        std::fs::remove_file(\"/tmp/x\");\n    }\n}\n";
    assert!(
        forbidden_lines(fixture, REMOVAL_FAMILY).is_empty(),
        "test fixtures are outside the production scan"
    );
}
