//! The canonical public surface (AC-077): one 36-row catalog with every row
//! served, both alias pairs resolving in the dispatcher, help and completions
//! rendered from that page, a machine channel that keeps stdout pure and its
//! exit status distinguishing success, error and pending, and the sessionless
//! doctor answering before any runtime open without touching the root.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test assertions fail loudly with the observed payload; src/ stays strict (standards §14)"
)]

mod support;

use rivect::commands::response_status;
use rivect::contracts::SessionId;
use rivect::tools::{self, LocalKind, Shell};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Output, Stdio};
use std::time::{Duration, Instant};

/// The 36 canonical rows in their published order, written out once here so a
/// reordering, a missing row or an extra row is a diff.
const ROWS: [&str; 36] = [
    "session.new",
    "settings.open",
    "session.list",
    "session.search",
    "session.resume",
    "session.fork",
    "session.export",
    "context.compact",
    "session.recap",
    "checkpoint.preview",
    "checkpoint.apply",
    "permissions.view",
    "model.view",
    "effort.view",
    "runtime.status",
    "context.view",
    "usage.view",
    "command.help",
    "task.cancel",
    "session.exit",
    "workflow.control",
    "harness.control",
    "decisions.control",
    "docs.status",
    "view.clear",
    "config.list",
    "config.search",
    "config.get",
    "config.explain",
    "config.set",
    "config.unset",
    "config.validate",
    "config.export",
    "project.init",
    "doctor",
    "ui.render",
];

/// One dispatch through the shared helper: the frame builder lives in
/// `tests/support`, so both targets name the envelope once.
fn execute(world: &mut support::World, session: &SessionId, kind: &str, extra: Value) -> Value {
    world.dispatch(&support::command_execute(session, kind, extra))
}

/// Runs the built executable with a clean environment: only the variables a
/// process needs to find its own runtime and temporary directory are passed.
fn run_cli(args: &[&str], stdin: Option<&str>) -> Output {
    run_cli_env(args, stdin, &[])
}

/// Runs the built executable with the caller's extra environment on top of
/// the process allowlist.
fn run_cli_env(args: &[&str], stdin: Option<&str>, env: &[(&str, &str)]) -> Output {
    use std::io::Write as _;
    let mut command = std::process::Command::new(support::rivect_binary());
    command
        .args(args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    for (name, value) in env {
        command.env(name, value);
    }
    let mut child = command.spawn().expect("spawn rivect");
    if let Some(text) = stdin {
        child
            .stdin
            .take()
            .expect("stdin pipe")
            .write_all(text.as_bytes())
            .expect("write stdin");
    }
    child.wait_with_output().expect("wait for rivect")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Every path under `root` with its length and content digest, sorted: the
/// zero-effect oracle for the doctor runs. The digest makes a same-length
/// in-place rewrite visible where a length-only record read identical.
fn snapshot(root: &Path) -> Vec<(PathBuf, u64, String)> {
    let mut entries = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(read) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in read.flatten() {
            let path = entry.path();
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            let digest = if metadata.is_dir() {
                "dir".to_string()
            } else {
                match std::fs::read(&path) {
                    Ok(bytes) => support::sha256_hex(&bytes),
                    // An unreadable entry is a distinct state, never the
                    // digest of an empty file.
                    Err(_) => "unreadable".to_string(),
                }
            };
            entries.push((path.clone(), metadata.len(), digest));
            if metadata.is_dir() {
                pending.push(path);
            }
        }
    }
    entries.sort();
    entries
}

#[test]
fn the_zero_effect_oracle_sees_a_same_length_rewrite() {
    // The doctor control records what is on disk, not just how much: a
    // same-length in-place rewrite is a write, and the oracle must see it.
    let root = tempfile::TempDir::with_prefix("rivect-zero-effect-digest-").expect("temp root");
    let target = root.path().join("state.bin");
    std::fs::write(&target, b"aaaa").expect("first bytes");
    let before = snapshot(root.path());
    std::fs::write(&target, b"bbbb").expect("same-length rewrite");
    assert_eq!(
        std::fs::metadata(&target).expect("metadata").len(),
        before[0].1,
        "the control keeps the recorded length"
    );
    assert_ne!(
        snapshot(root.path()),
        before,
        "a same-length in-place rewrite must move the zero-effect oracle"
    );
}

/// Splits a completion script into its words, so a row is matched whole
/// rather than as a substring of another row's name.
fn words(script: &str) -> Vec<String> {
    script
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || character == '.' || character == '_')
        })
        .filter(|word| !word.is_empty())
        .map(str::to_string)
        .collect()
}

/// One `task.submit kind=create` with the caller's goal, so a fixture can name
/// distinct goals instead of the corpus default.
fn create_with_goal(
    world: &mut support::World,
    session: &SessionId,
    command_id: &str,
    goal: &str,
) -> String {
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "task.submit",
        "params": {
            "schema_version": 1,
            "command_id": command_id,
            "session_id": session.0,
            "kind": "create",
            "goal": goal,
            "contract": { "criteria": [], "constraints": [] },
        }
    }));
    assert!(response.get("error").is_none(), "{response}");
    response["result"]["task_id"]
        .as_str()
        .expect("task id")
        .to_string()
}

#[test]
fn catalog_is_the_enumerated_thirty_six_rows_in_order() {
    let catalog = tools::CATALOG
        .iter()
        .map(|row| row.canonical_id)
        .collect::<Vec<_>>();
    assert_eq!(catalog, ROWS.to_vec(), "the catalog is the published order");
    let page = tools::describe();
    assert_eq!(
        page.items.len(),
        ROWS.len() + 2,
        "the page carries the 36 rows and the two tool carriers"
    );
    assert_eq!(
        page.items[..ROWS.len()]
            .iter()
            .map(|item| item.canonical_id.as_str())
            .collect::<Vec<_>>(),
        ROWS.to_vec()
    );
}

#[test]
fn every_catalog_row_is_available_through_its_own_carrier() {
    let page = tools::describe();
    let command_rows = &page.items[..ROWS.len()];
    let available = command_rows
        .iter()
        .filter(|item| item.available)
        .map(|item| item.canonical_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(available.len(), 36, "all 36 rows are served");
    for item in command_rows {
        assert!(item.available, "{} is served: {item:?}", item.canonical_id);
        assert!(
            item.unavailability_reason.is_none(),
            "{}: {item:?}",
            item.canonical_id
        );
        assert!(!item.description.is_empty(), "{}", item.canonical_id);
        assert!(!item.busy_policy.is_empty(), "{}", item.canonical_id);
    }
    assert!(
        tools::unavailable_rows().is_empty(),
        "no catalog row remains unbuilt"
    );
}

#[test]
fn every_available_row_is_reachable_through_its_declared_carrier() {
    // The carrier contract: a local row dispatches to its handler, an RPC row
    // names a served method, a CLI row names the executable's own entry.
    for row in tools::CATALOG {
        if !row.available() {
            continue;
        }
        match row.carrier {
            tools::Carrier::Local => {
                assert!(
                    !matches!(
                        tools::local_command_kind(row.canonical_id),
                        LocalKind::Unknown | LocalKind::PlannedUnimplemented
                    ),
                    "{} dispatches to its handler",
                    row.canonical_id
                );
            }
            tools::Carrier::Rpc(method) => {
                assert!(
                    rivect::commands::served_methods().contains(&method),
                    "{}'s carrier {method} is served",
                    row.canonical_id
                );
            }
            tools::Carrier::Cli(command) => {
                assert!(
                    command.starts_with("rivect "),
                    "{}'s carrier is the executable's own: {command}",
                    row.canonical_id
                );
            }
        }
    }

    // The docs owner answers its own real result: the declared direct source,
    // version-aware policy, bounded cache and an honest unknown quota — no
    // external refresh and no fabricated balance.
    let mut world = support::open_world("public-surface-carriers", None);
    let session = world.open_session("public-surface-carriers");
    let docs = execute(&mut world, &session, "docs.status", json!({}));
    assert!(docs.get("error").is_none(), "{docs}");
    assert_eq!(docs["result"]["kind"], "docs.status", "{docs}");
    assert_eq!(docs["result"]["owner"], "src/docs.rs", "{docs}");
    assert_eq!(docs["result"]["version_aware"], true, "{docs}");
    assert_eq!(
        docs["result"]["source_classes"],
        json!(["direct_local"]),
        "{docs}"
    );
    assert_eq!(docs["result"]["quota"], "unknown", "{docs}");
    assert_eq!(
        docs["result"]["cache"]["max_entries"],
        rivect::docs::CACHE_MAX_ENTRIES,
        "{docs}"
    );

    // Every served row answers through its own handler with a discriminating
    // field, not only its echoed kind. A handler that returned an empty or
    // unrelated projection fails its own line. `session.new` runs first, while
    // the session has no running task, because it refuses a switch beside live
    // work.
    let created = execute(&mut world, &session, "session.new", json!({}));
    assert!(created.get("error").is_none(), "{created}");
    assert_eq!(created["result"]["kind"], "session.new", "{created}");
    assert_ne!(created["result"]["session_id"], session.0, "{created}");
    let task = world.create_task(&session, "public-surface-served-task");
    let carrier_count = rivect::config::carrier_samples().count();
    let served: &[(&str, Value)] = &[
        ("settings.open", json!({})),
        ("session.list", json!({})),
        ("session.search", json!({ "query": "Объяснить" })),
        ("session.export", json!({})),
        ("session.recap", json!({})),
        ("usage.view", json!({})),
        ("permissions.view", json!({})),
        ("model.view", json!({})),
        ("effort.view", json!({})),
        ("harness.control", json!({ "op": "status" })),
        ("workflow.control", json!({ "op": "status" })),
        ("config.list", json!({})),
        ("config.search", json!({ "query": "profile" })),
        ("config.export", json!({})),
        ("config.get", json!({ "key": "workflow.enabled" })),
        ("config.explain", json!({ "key": "decisions.mode" })),
        ("config.validate", json!({})),
        ("view.clear", json!({})),
        ("decisions.control", json!({ "op": "status" })),
        ("docs.status", json!({})),
    ];
    for (kind, extra) in served {
        let response = execute(&mut world, &session, kind, extra.clone());
        assert!(
            response.get("error").is_none(),
            "{kind} is served through its handler: {response}"
        );
        let result = &response["result"];
        assert_eq!(result["kind"], *kind, "{kind}: {response}");
        match *kind {
            "settings.open" => {
                let entries = result["entries"].as_array().expect("entries");
                let keys = entries
                    .iter()
                    .map(|entry| entry["key"].as_str().unwrap_or_default())
                    .collect::<Vec<_>>();
                assert_eq!(
                    keys,
                    vec!["workflow.enabled", "decisions.mode", "context.auto_compact"],
                    "settings.open carries its real base keys: {result}"
                );
                assert_eq!(entries[0]["effective"]["value"], true, "{result}");
                assert!(
                    result["carriers"]
                        .as_array()
                        .is_some_and(|rows| { rows.len() == carrier_count && !rows.is_empty() }),
                    "settings.open names the declared carriers: {result}"
                );
            }
            "session.list" => assert!(
                result["sessions"]["items"]
                    .as_array()
                    .is_some_and(|items| items.iter().any(|row| row["session_id"] == session.0)),
                "the listing carries this session: {result}"
            ),
            "session.search" => assert!(
                result["sessions"]["items"]
                    .as_array()
                    .is_some_and(|items| items.iter().any(|row| row["session_id"] == session.0)),
                "the search matches the recorded goal: {result}"
            ),
            "session.export" => {
                assert_eq!(result["session_id"], session.0, "{result}");
                assert!(
                    result["items"]
                        .as_array()
                        .is_some_and(|items| !items.is_empty()),
                    "the export carries the recorded events: {result}"
                );
            }
            "session.recap" => {
                assert_eq!(result["session_id"], session.0, "{result}");
                assert_eq!(result["tasks"], 1, "the page names the task: {result}");
                assert_eq!(result["counts"]["running"], 1, "{result}");
            }
            "usage.view" => assert_eq!(result["totals"]["settled_count"], 0, "{result}"),
            "permissions.view" => {
                let boundaries = result["boundaries"].as_array().expect("boundaries");
                assert!(
                    boundaries
                        .iter()
                        .any(|row| row["boundary"] == "read_file" && row["mode"] == "manual"),
                    "the read boundary names its mode: {result}"
                );
                assert!(
                    boundaries
                        .iter()
                        .any(|row| row["boundary"] == "mcp.call" && row["mode"] == "auto"),
                    "the egress boundary names its own mode, not read_file's: {result}"
                );
            }
            "model.view" | "effort.view" => assert!(
                result["purposes"].is_array(),
                "{kind} serves its resolved purpose rows: {result}"
            ),
            "harness.control" => {
                assert_eq!(result["op"], "status", "{result}");
                assert_eq!(result["scheduler"]["running"], 0, "{result}");
            }
            "workflow.control" => {
                assert_eq!(result["op"], "status", "{result}");
                assert_eq!(result["entry"]["key"], "workflow.enabled", "{result}");
            }
            "docs.status" => {
                assert_eq!(result["owner"], "src/docs.rs", "{result}");
                assert_eq!(result["quota"], "unknown", "{result}");
                assert_eq!(result["cache"]["cached_entries"], 0, "{result}");
            }
            "config.list" | "config.export" => assert_eq!(
                result["entries"].as_array().map(Vec::len),
                Some(carrier_count),
                "{kind} lists every declared carrier: {result}"
            ),
            "config.search" => assert!(
                result["entries"].as_array().is_some_and(|entries| entries
                    .iter()
                    .any(|entry| entry["key"] == "profiles.default.credential_ref")),
                "the search answers the matching carrier: {result}"
            ),
            "config.get" => {
                assert_eq!(result["entry"]["key"], "workflow.enabled", "{result}");
                assert_eq!(result["entry"]["effective"]["value"], true, "{result}");
                assert!(
                    result["entry"]["source"]["kind"]
                        .as_str()
                        .is_some_and(|kind| !kind.is_empty()),
                    "the entry names its source layer: {result}"
                );
                assert!(
                    result["entry"]["source"]["revision"]
                        .as_str()
                        .is_some_and(|revision| !revision.is_empty()),
                    "{result}"
                );
            }
            "config.explain" => {
                assert_eq!(result["result"]["key"], "decisions.mode", "{result}");
                assert!(
                    result["result"]["effective"].is_string(),
                    "the explain states the effective value: {result}"
                );
                assert!(
                    result["result"]["source_digest"]
                        .as_str()
                        .is_some_and(|digest| !digest.is_empty()),
                    "{result}"
                );
            }
            "config.validate" => {
                assert_eq!(result["present"], false, "no document exists: {result}");
                assert_eq!(result["valid"], true, "{result}");
            }
            "view.clear" => assert_eq!(result["session_id"], session.0, "{result}"),
            "decisions.control" => {
                assert_eq!(result["op"], "status", "{result}");
                assert!(result["result"].is_object(), "{result}");
            }
            other => panic!("unhandled served row {other}"),
        }
    }

    // `session.fork` needs a parent with goals and keeps that parent's
    // surface, so it runs on its own session with one task.
    let parent = world.open_session("public-surface-fork");
    let _goal = world.create_task(&parent, "public-surface-fork-task");
    let fork = execute(
        &mut world,
        &parent,
        "session.fork",
        json!({ "command_id": "fork-public-surface" }),
    );
    assert!(fork.get("error").is_none(), "{fork}");
    assert_eq!(fork["result"]["kind"], "session.fork", "{fork}");
    assert_eq!(fork["result"]["tasks"].as_array().map(Vec::len), Some(1));

    // A local row that needs a task answers its own typed refusal when the
    // task is missing, so the handler — not the catalog — decides.
    for kind in [
        "context.view",
        "checkpoint.preview",
        "checkpoint.apply",
        "context.compact",
        "read_file",
    ] {
        let response = execute(&mut world, &session, kind, json!({}));
        assert_eq!(
            response["error"]["data"]["code"], "invalid_input",
            "{kind}'s handler answers its missing parameter: {response}"
        );
    }
    let _ = task;
    // The RPC-carried rows answer through their own methods: resume attaches
    // to an existing session and the status/help projections are live.
    let resumed = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "session.attach",
        "params": { "schema_version": 1, "bootstrap_id": "public-surface-resume",
                    "session_id": session.0 }
    }));
    assert_eq!(resumed["result"]["session_id"], session.0, "{resumed}");
    let status = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 3, "method": "runtime.status",
        "params": { "schema_version": 1, "session_id": session.0 }
    }));
    assert!(status.get("error").is_none(), "{status}");
    let help = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 4, "method": "command.describe",
        "params": { "schema_version": 1, "session_id": session.0 }
    }));
    assert_eq!(help["result"]["items"].as_array().map(Vec::len), Some(38));
}

#[test]
fn context_and_checkpoint_serve_a_positive_projection_and_fold() {
    let mut world = support::open_world("public-surface-context", None);
    let session = world.open_session("public-surface-context");
    let task = world.create_task(&session, "public-surface-context-task");
    world
        .runtime
        .store_writer()
        .materialize_obligations(&task)
        .expect("obligations");
    for index in 0..4_u8 {
        let observation = format!(
            "read the file and reported {}",
            "a scoped line of the fixture ".repeat(40)
        );
        world
            .runtime
            .store_writer()
            .insert_evidence(
                &task,
                0,
                &format!("task:{}", task.0),
                &observation,
                &format!("{index:02x}").repeat(32),
            )
            .expect("evidence row");
    }

    let view = execute(
        &mut world,
        &session,
        "context.view",
        json!({ "task_id": task.0 }),
    );
    assert!(view.get("error").is_none(), "{view}");
    let total = view["result"]["bytes"]["total"].as_u64().expect("total");
    let history = view["result"]["bytes"]["history"]
        .as_u64()
        .expect("history");
    assert!(total > 0, "the projection measures the context: {view}");
    assert!(history > 0, "the history is a real component: {view}");

    let preview = execute(
        &mut world,
        &session,
        "checkpoint.preview",
        json!({ "task_id": task.0 }),
    );
    assert!(preview.get("error").is_none(), "{preview}");
    assert_eq!(
        preview["result"]["assembled_bytes"].as_u64(),
        Some(total),
        "the preview measures the same assembly: {preview}"
    );
    assert!(
        preview["result"]["checkpoint"].is_null(),
        "nothing was folded yet: {preview}"
    );

    let applied = execute(
        &mut world,
        &session,
        "checkpoint.apply",
        json!({ "task_id": task.0 }),
    );
    assert!(applied.get("error").is_none(), "{applied}");
    let before = applied["result"]["before_bytes"]
        .as_u64()
        .expect("before bytes");
    let after = applied["result"]["after_bytes"]
        .as_u64()
        .expect("after bytes");
    let checkpoint_id = applied["result"]["checkpoint_id"]
        .as_str()
        .expect("checkpoint id");
    assert!(before > after, "the fold shortened the context: {applied}");
    assert!(
        applied["result"]["folded_records"]
            .as_u64()
            .is_some_and(|records| records >= 4),
        "the fold names the records it folded: {applied}"
    );

    let after_preview = execute(
        &mut world,
        &session,
        "checkpoint.preview",
        json!({ "task_id": task.0 }),
    );
    assert!(after_preview.get("error").is_none(), "{after_preview}");
    assert_eq!(
        after_preview["result"]["checkpoint"]["checkpoint_id"], checkpoint_id,
        "the preview reads the checkpoint the apply wrote: {after_preview}"
    );
}

#[test]
fn session_exit_closes_durably_and_the_session_stays_attachable() {
    let mut world = support::open_world("public-surface-close", None);
    let session = world.open_session("public-surface-close");
    let attach = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "session.attach",
        "params": { "schema_version": 1, "bootstrap_id": "public-surface-close-2",
                    "session_id": session.0 }
    }));
    let attachment = attach["result"]["attachment_id"]
        .as_str()
        .expect("attachment id")
        .to_string();

    // The row's carrier is the `session.close` method, and the catalog says so
    // rather than letting the dispatcher answer "unknown local command".
    let row = execute(
        &mut world,
        &session,
        "session.exit",
        json!({ "attachment_id": attachment }),
    );
    assert_eq!(
        row["error"]["data"]["code"], "capability_unavailable",
        "{row}"
    );
    assert!(
        row["error"]["data"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("session.close")),
        "the row names its RPC carrier: {row}"
    );

    let close = |world: &mut support::World, id: &str| {
        world.dispatch(&json!({
            "jsonrpc": "2.0", "id": 3, "method": "session.close",
            "params": { "schema_version": 1, "session_id": session.0,
                        "attachment_id": id }
        }))
    };
    let closed = close(&mut world, &attachment);
    assert!(closed.get("error").is_none(), "{closed}");
    assert_eq!(closed["result"]["state"], "closed", "{closed}");
    assert_eq!(closed["result"]["already_closed"], false, "{closed}");
    assert_eq!(closed["result"]["attachment_id"], attachment, "{closed}");

    // A repeat is idempotent and says the row was already closed.
    let repeated = close(&mut world, &attachment);
    assert!(repeated.get("error").is_none(), "{repeated}");
    assert_eq!(repeated["result"]["already_closed"], true, "{repeated}");

    // The close is durable: a reopened runtime reads the same row closed.
    world.reopen();
    let after_reopen = close(&mut world, &attachment);
    assert!(after_reopen.get("error").is_none(), "{after_reopen}");
    assert_eq!(
        after_reopen["result"]["already_closed"], true,
        "the close survived the reopen: {after_reopen}"
    );

    // Closing an attachment this session never recorded is not found.
    let unknown = close(&mut world, "00000000-0000-4000-8000-000000000099");
    assert_eq!(unknown["error"]["data"]["code"], "not_found", "{unknown}");

    // A close ends one surface, not the conversation: the session still
    // attaches under a fresh attachment.
    let reattached = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 4, "method": "session.attach",
        "params": { "schema_version": 1, "bootstrap_id": "public-surface-close-3",
                    "session_id": session.0 }
    }));
    assert!(reattached.get("error").is_none(), "{reattached}");
    assert_ne!(
        reattached["result"]["attachment_id"], attachment,
        "a fresh attachment is minted: {reattached}"
    );
}

#[test]
fn every_declared_alias_dispatches_and_the_catalog_is_the_source() {
    // The declared alias table, written out once: deleting an alias from the
    // catalog fails this line, and the sweep below proves each one resolves.
    let declared: &[(&str, &[&str])] = &[
        ("session.new", &["new", "clear"]),
        ("settings.open", &["settings", "config"]),
        ("session.list", &["sessions"]),
        ("docs.status", &["docs"]),
        ("decisions.control", &["decisions"]),
    ];
    for row in tools::CATALOG {
        let expected = declared
            .iter()
            .find(|(canonical, _)| *canonical == row.canonical_id)
            .map(|(_, aliases)| *aliases)
            .unwrap_or(&[]);
        assert_eq!(
            row.aliases, expected,
            "{} declares exactly its published aliases",
            row.canonical_id
        );
    }
    assert_eq!(
        tools::catalog_row("read").map(|row| row.canonical_id),
        Some("read_file"),
        "the pre-existing read alias still resolves"
    );

    let mut world = support::open_world("public-surface-alias-sweep", None);
    let session = world.open_session("public-surface-alias-sweep");
    let parent = world.open_session("public-surface-alias-fork");
    let _goal = world.create_task(&parent, "public-surface-alias-fork-task");
    for row in tools::CATALOG {
        for alias in row.aliases {
            assert_eq!(
                tools::local_command_kind(alias),
                tools::local_command_kind(row.canonical_id),
                "alias {alias} reaches {}'s kind",
                row.canonical_id
            );
            let extra = match row.canonical_id {
                "session.search" => json!({ "query": "Объяснить" }),
                "session.fork" => json!({ "command_id": format!("fork-alias-{alias}") }),
                "workflow.control" | "harness.control" | "decisions.control" => {
                    json!({ "op": "status" })
                }
                "config.get" | "config.explain" => json!({ "key": "workflow.enabled" }),
                "config.search" => json!({ "query": "workflow" }),
                _ => json!({}),
            };
            let target = if row.canonical_id == "session.fork" {
                &parent
            } else {
                &session
            };
            let response = execute(&mut world, target, alias, extra);
            assert!(
                !matches!(
                    response["error"]["data"]["code"].as_str(),
                    Some("unknown_method") | Some("unknown_local_command")
                ),
                "alias {alias} is not unknown to the dispatcher: {response}"
            );
            if row.canonical_id == "docs.status" {
                assert_eq!(
                    response["result"]["kind"], "docs.status",
                    "the alias reaches the docs owner's result, not a refusal: {response}"
                );
            }
        }
    }
    // The tool alias reaches the tool handler, not a usage error.
    let read = execute(&mut world, &session, "read", json!({}));
    assert_eq!(read["error"]["data"]["code"], "invalid_input", "{read}");
}

#[test]
fn session_search_pages_and_fork_copies_goals_in_order() {
    let mut world = support::open_world("public-surface-sessions", None);
    let alpha = world.open_session("public-surface-sessions-alpha");
    let beta = world.open_session("public-surface-sessions-beta");
    let gamma = world.open_session("public-surface-sessions-gamma");
    create_with_goal(&mut world, &alpha, "sessions-alpha-1", "alpha goal");
    create_with_goal(&mut world, &beta, "sessions-beta-1", "beta goal");
    create_with_goal(&mut world, &gamma, "sessions-gamma-1", "gamma goal");

    // Match: only the session whose recorded goal contains the query.
    let match_beta = execute(
        &mut world,
        &alpha,
        "session.search",
        json!({ "query": "beta" }),
    );
    assert!(match_beta.get("error").is_none(), "{match_beta}");
    let matched = match_beta["result"]["sessions"]["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|row| row["session_id"].as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        matched,
        vec![beta.0.clone()],
        "the search matches one session"
    );

    // Paging: a page of one carries a cursor, and the second page continues
    // without repeating the first row.
    let first_page = execute(
        &mut world,
        &alpha,
        "session.search",
        json!({ "query": "goal", "page": { "page_size": 1 } }),
    );
    assert!(first_page.get("error").is_none(), "{first_page}");
    let first_items = first_page["result"]["sessions"]["items"]
        .as_array()
        .expect("items");
    assert_eq!(first_items.len(), 1, "the page is bounded: {first_page}");
    let cursor = first_page["result"]["sessions"]["next_cursor"]
        .as_str()
        .expect("a next page is offered")
        .to_string();
    let second_page = execute(
        &mut world,
        &alpha,
        "session.search",
        json!({ "query": "goal", "page": { "page_size": 1, "cursor": cursor } }),
    );
    assert!(second_page.get("error").is_none(), "{second_page}");
    let second_items = second_page["result"]["sessions"]["items"]
        .as_array()
        .expect("items");
    assert_eq!(second_items.len(), 1, "{second_page}");
    assert_ne!(
        second_items[0]["session_id"], first_items[0]["session_id"],
        "the second page does not repeat the first row: {second_page}"
    );

    // A session inserted between pages moves the population: the old cursor
    // is refused instead of silently stitching two generations.
    let delta = world.open_session("public-surface-sessions-delta");
    create_with_goal(&mut world, &delta, "sessions-delta-1", "delta goal");
    let stale = execute(
        &mut world,
        &alpha,
        "session.search",
        json!({ "query": "goal", "page": { "page_size": 1, "cursor": first_page["result"]["sessions"]["next_cursor"] } }),
    );
    assert_eq!(
        stale["error"]["data"]["code"], "conflict",
        "a cursor of another generation conflicts: {stale}"
    );

    // A *task* insert moves the search population even though no session row
    // moved: the generation is the population the query reads, so a stale
    // cursor is refused instead of stitching two result sets.
    let paging_one = world.open_session("public-surface-sessions-paging-one");
    let paging_two = world.open_session("public-surface-sessions-paging-two");
    let paging_other = world.open_session("public-surface-sessions-paging-other");
    create_with_goal(
        &mut world,
        &paging_one,
        "sessions-paging-1",
        "paging token one",
    );
    create_with_goal(
        &mut world,
        &paging_two,
        "sessions-paging-2",
        "paging token two",
    );
    create_with_goal(&mut world, &paging_other, "sessions-paging-3", "other text");
    let before_task = execute(
        &mut world,
        &paging_one,
        "session.search",
        json!({ "query": "paging token", "page": { "page_size": 1 } }),
    );
    assert!(before_task.get("error").is_none(), "{before_task}");
    let task_cursor = before_task["result"]["sessions"]["next_cursor"]
        .as_str()
        .expect("a next page is offered")
        .to_string();
    // The insert lands on a session the query did not match before, so the
    // result set itself changes as well as the population.
    create_with_goal(
        &mut world,
        &paging_other,
        "sessions-paging-4",
        "paging token three",
    );
    let stale_task = execute(
        &mut world,
        &paging_one,
        "session.search",
        json!({ "query": "paging token", "page": { "page_size": 1, "cursor": task_cursor } }),
    );
    assert_eq!(
        stale_task["error"]["data"]["code"], "conflict",
        "a task insert moves the search generation: {stale_task}"
    );

    // Multi-goal ordering: the fork copies goals in creation order, which the
    // fork's own task.created events carry as digests.
    let ordered = world.open_session("public-surface-sessions-ordered");
    create_with_goal(&mut world, &ordered, "sessions-ordered-1", "first goal");
    create_with_goal(&mut world, &ordered, "sessions-ordered-2", "second goal");
    let fork = execute(
        &mut world,
        &ordered,
        "session.fork",
        json!({ "command_id": "fork-ordered" }),
    );
    assert!(fork.get("error").is_none(), "{fork}");
    let forked_session = fork["result"]["session_id"]
        .as_str()
        .expect("forked session")
        .to_string();
    let forked_tasks = fork["result"]["tasks"]
        .as_array()
        .expect("forked tasks")
        .clone();
    assert_eq!(forked_tasks.len(), 2, "{fork}");
    let forked = SessionId(forked_session.clone());
    let export = execute(&mut world, &forked, "session.export", json!({}));
    assert!(export.get("error").is_none(), "{export}");
    let digests = export["result"]["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter(|event| event["type"] == "task.created")
        .map(|event| {
            event["delta"]["goal_digest"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        digests,
        vec![
            support::sha256_hex(b"first goal"),
            support::sha256_hex(b"second goal"),
        ],
        "the fork copies goals in creation order: {export}"
    );

    // Idempotency: the same command id replays the same fork and creates no
    // second session or task.
    let replay = execute(
        &mut world,
        &ordered,
        "session.fork",
        json!({ "command_id": "fork-ordered" }),
    );
    assert!(replay.get("error").is_none(), "{replay}");
    assert_eq!(
        replay["result"]["session_id"], forked_session,
        "a replay answers the recorded fork: {replay}"
    );
    assert_eq!(
        replay["result"]["tasks"],
        Value::Array(forked_tasks),
        "a replay answers the recorded tasks: {replay}"
    );
    let sessions = execute(&mut world, &alpha, "session.list", json!({}));
    let listed = sessions["result"]["sessions"]["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter(|row| row["session_id"] == forked_session)
        .count();
    assert_eq!(
        listed, 1,
        "the replay created no second session: {sessions}"
    );

    // `session.recap` honours the page cursor it advertises: page two follows
    // `next_cursor` instead of re-reading page one, while the counts stay the
    // whole session's.
    let recap_session = world.open_session("public-surface-sessions-recap");
    create_with_goal(&mut world, &recap_session, "sessions-recap-1", "recap one");
    create_with_goal(&mut world, &recap_session, "sessions-recap-2", "recap two");
    let recap_first = execute(
        &mut world,
        &recap_session,
        "session.recap",
        json!({ "page": { "page_size": 1 } }),
    );
    assert!(recap_first.get("error").is_none(), "{recap_first}");
    assert_eq!(recap_first["result"]["tasks"], 1, "{recap_first}");
    assert_eq!(
        recap_first["result"]["counts"]["running"], 2,
        "the counts are the whole session, not the page: {recap_first}"
    );
    let recap_cursor = recap_first["result"]["next_cursor"]
        .as_str()
        .expect("a continuation is offered")
        .to_string();
    let recap_second = execute(
        &mut world,
        &recap_session,
        "session.recap",
        json!({ "page": { "page_size": 1, "cursor": recap_cursor } }),
    );
    assert!(recap_second.get("error").is_none(), "{recap_second}");
    assert_eq!(recap_second["result"]["tasks"], 1, "{recap_second}");
    assert!(
        recap_second["result"]["next_cursor"].is_null(),
        "the second page ends the continuation instead of repeating page one: {recap_second}"
    );
}

#[test]
fn config_reads_serve_values_and_writes_honor_the_stale_digest_cas() {
    // The document carries a secret-shaped connection reference that no config
    // carrier publishes: a surface that dumps the document instead of its
    // declared entries leaks it, and the sweep below is what says so.
    let config = format!(
        "config_version = 1\n\
         [connections.primary]\nkind = \"api_key\"\nendpoint = \"https://api.openai.com/v1\"\n\
         credential_ref = \"keyring:{}\"\n\
         [profiles.default]\ncredential_ref = \"keyring:public-surface-fixture\"\n\
         [models.defaults]\nmodel = {{ mode = \"auto\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"auto\" }}\n",
        support::SECRET_CANARY
    );
    let mut world = support::open_world("public-surface-config", Some(&config));
    let session = world.open_session("public-surface-config");

    let workflow = execute(
        &mut world,
        &session,
        "config.get",
        json!({ "key": "workflow.enabled" }),
    );
    assert!(workflow.get("error").is_none(), "{workflow}");
    assert_eq!(
        workflow["result"]["entry"]["effective"]["value"], true,
        "{workflow}"
    );
    assert!(
        workflow["result"]["entry"]["source"]["kind"]
            .as_str()
            .is_some_and(|kind| !kind.is_empty()),
        "the entry names its source layer: {workflow}"
    );
    let digest = workflow["result"]["source_digest"]
        .as_str()
        .expect("source digest")
        .to_string();

    let reference = execute(
        &mut world,
        &session,
        "config.get",
        json!({ "key": "profiles.default.credential_ref" }),
    );
    assert!(reference.get("error").is_none(), "{reference}");
    assert_eq!(
        reference["result"]["entry"]["effective"]["value"], "keyring:public-surface-fixture",
        "a credential reference is a reference, never resolved material: {reference}"
    );
    assert_eq!(
        reference["result"]["entry"]["source"]["kind"], "user",
        "a document-supplied carrier reads the user layer: {reference}"
    );
    // Every published config field is a declared carrier: none of them can
    // carry the document's secret-shaped connection reference.
    let published = [
        execute(&mut world, &session, "config.list", json!({})),
        execute(
            &mut world,
            &session,
            "config.search",
            json!({ "query": "credential" }),
        ),
        execute(&mut world, &session, "config.export", json!({})),
        execute(&mut world, &session, "config.validate", json!({})),
        execute(
            &mut world,
            &session,
            "config.explain",
            json!({ "key": "profiles.default.credential_ref" }),
        ),
    ];
    for answer in &published {
        assert!(
            !answer.to_string().contains(support::SECRET_CANARY),
            "no published config field carries the document's secret material: {answer}"
        );
    }

    // The documented CAS: a digest that no longer matches refuses before any
    // edit lands, and the document on disk is unchanged.
    let before = std::fs::read_to_string(world.root.join("config.toml")).expect("config read");
    let stale = execute(
        &mut world,
        &session,
        "config.set",
        json!({ "key": "workflow.enabled", "value": false,
                "expected_source_digest": "stale-digest" }),
    );
    assert_eq!(stale["error"]["data"]["code"], "conflict", "{stale}");
    assert_eq!(
        std::fs::read_to_string(world.root.join("config.toml")).expect("config read"),
        before,
        "a refused CAS writes nothing"
    );

    let landed = execute(
        &mut world,
        &session,
        "config.set",
        json!({ "key": "workflow.enabled", "value": false,
                "expected_source_digest": digest }),
    );
    assert!(landed.get("error").is_none(), "{landed}");
    let toggled = execute(
        &mut world,
        &session,
        "config.get",
        json!({ "key": "workflow.enabled" }),
    );
    assert_eq!(
        toggled["result"]["entry"]["effective"]["value"], false,
        "{toggled}"
    );
    let toggled_digest = toggled["result"]["source_digest"]
        .as_str()
        .expect("source digest")
        .to_string();
    assert_ne!(toggled_digest, digest, "the edit moved the sources digest");

    let stale_unset = execute(
        &mut world,
        &session,
        "config.unset",
        json!({ "key": "workflow.enabled", "expected_source_digest": digest }),
    );
    assert_eq!(
        stale_unset["error"]["data"]["code"], "conflict",
        "{stale_unset}"
    );
    let unset = execute(
        &mut world,
        &session,
        "config.unset",
        json!({ "key": "workflow.enabled", "expected_source_digest": toggled_digest }),
    );
    assert!(unset.get("error").is_none(), "{unset}");
    let restored = execute(
        &mut world,
        &session,
        "config.get",
        json!({ "key": "workflow.enabled" }),
    );
    assert_eq!(
        restored["result"]["entry"]["effective"]["value"], true,
        "the unset restored the base value: {restored}"
    );

    // `config.validate` checks the document on disk through the same schema:
    // absent is valid, a rejected document is its typed refusal.
    let absent = support::open_world("public-surface-validate-absent", None);
    let mut absent = absent;
    let absent_session = absent.open_session("public-surface-validate-absent");
    let validated = execute(&mut absent, &absent_session, "config.validate", json!({}));
    assert_eq!(validated["result"]["present"], false, "{validated}");

    std::fs::write(
        world.root.join("config.toml"),
        "config_version = \"not-a-number\"\n",
    )
    .expect("write bad config");
    let rejected = execute(&mut world, &session, "config.validate", json!({}));
    assert_eq!(
        rejected["error"]["data"]["code"], "invalid_input",
        "a rejected document is the schema's typed refusal: {rejected}"
    );
}

#[test]
fn both_alias_pairs_resolve_in_the_dispatcher() {
    let mut world = support::open_world("public-surface-aliases", None);
    let session = world.open_session("public-surface-aliases");

    // `/new` = `/clear` -> session.new: both start a conversation and answer
    // as the canonical kind.
    let new = execute(&mut world, &session, "new", json!({}));
    assert_eq!(new["result"]["kind"], "session.new", "{new}");
    let started = new["result"]["session_id"].as_str().expect("new session");
    assert_ne!(started, session.0);
    let clear = execute(&mut world, &session, "clear", json!({}));
    assert_eq!(clear["result"]["kind"], "session.new", "{clear}");
    assert_ne!(clear["result"]["session_id"], new["result"]["session_id"]);

    // `/settings` = `/config` -> settings.open: both serve the same entries.
    let settings = execute(&mut world, &session, "settings", json!({}));
    let config = execute(&mut world, &session, "config", json!({}));
    assert_eq!(settings["result"]["kind"], "settings.open", "{settings}");
    assert_eq!(config["result"]["kind"], "settings.open", "{config}");
    assert_eq!(settings["result"]["entries"], config["result"]["entries"]);

    // The pre-existing aliases still resolve: `read` reaches the read tool's
    // kind and `decisions` reaches its control row.
    assert!(matches!(
        tools::local_command_kind("read"),
        LocalKind::ReadFile
    ));
    assert!(matches!(
        tools::local_command_kind("decisions"),
        LocalKind::DecisionsControl
    ));
    let decisions = execute(&mut world, &session, "decisions", json!({ "op": "status" }));
    assert_eq!(
        decisions["result"]["kind"], "decisions.control",
        "{decisions}"
    );

    // An alias resolves only as a whole word: `config` is settings.open while
    // `config.list` is its own row.
    assert_eq!(
        tools::local_command_kind("config.list"),
        LocalKind::ConfigList
    );
}

#[test]
fn help_and_completions_are_rendered_from_the_page() {
    let page = tools::describe();
    let help = run_cli(&["--help"], None);
    assert_eq!(help.status.code(), Some(0), "{}", stderr_of(&help));
    let text = stdout_of(&help);
    for line in tools::help_lines(&page) {
        assert!(text.contains(line.trim()), "help is missing: {line}");
    }
    for item in &page.items {
        assert!(
            text.contains(&item.canonical_id),
            "help omits {}",
            item.canonical_id
        );
    }
    assert!(
        text.contains("rivect completions <bash|zsh|fish>"),
        "{text}"
    );
    assert!(text.contains("rivect doctor [--project PATH]"), "{text}");
    assert!(text.contains("rivect [--tui fullscreen|inline]"), "{text}");
    // Both surfaces parse; an unbuilt mode is a grammar refusal, not a
    // silently ignored word.
    assert_eq!(
        run_cli(&["--tui", "inline", "--help"], None).status.code(),
        Some(0)
    );
    assert_eq!(run_cli(&["--tui", "sideways"], None).status.code(), Some(2));

    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
        let output = run_cli(&["completions", shell.id()], None);
        assert_eq!(output.status.code(), Some(0), "{}", stderr_of(&output));
        let script = stdout_of(&output);
        let offered = words(&script);
        for word in tools::completion_words(&page) {
            assert!(
                offered.iter().any(|candidate| candidate == &word),
                "{} completion omits {word}",
                shell.id()
            );
        }
    }
    // `completions` needs exactly one known shell, and a run entry has no
    // `--project`.
    assert_eq!(
        run_cli(&["completions"], None).status.code(),
        Some(2),
        "a missing shell is a usage error"
    );
    assert_eq!(
        run_cli(&["completions", "tcsh"], None).status.code(),
        Some(2),
        "an unknown shell is a usage error"
    );
    assert_eq!(
        run_cli(&["--project", "/tmp"], None).status.code(),
        Some(2),
        "--project belongs to doctor"
    );
}

#[test]
fn ui_review_refuses_unknown_state_and_non_tty_without_opening_a_root() {
    let root = tempfile::TempDir::with_prefix("rivect-ui-review-refusal-").expect("temp");
    let data_root = root.path().join("never opened");
    let env = [("RIVECT_DATA_ROOT", data_root.to_str().expect("utf-8 root"))];

    let unknown = run_cli_env(&["--ui-review", "not-a-state"], None, &env);
    assert_eq!(unknown.status.code(), Some(2), "{unknown:?}");
    let refused = stderr_of(&unknown);
    assert!(
        refused.contains("unknown ui review state not-a-state"),
        "{unknown:?}"
    );
    for state in rivect::ui::review::STATES {
        assert!(
            refused.contains(state),
            "the refusal names the known state {state}: {refused}"
        );
    }
    assert!(
        !data_root.exists(),
        "an unknown state opens no runtime, store or data root"
    );

    // `--help`/`-h` after the flag ask for help, not for a state with that
    // name.
    for help_flag in ["--help", "-h"] {
        let review_help = run_cli_env(&["--ui-review", help_flag], None, &env);
        assert_eq!(
            review_help.status.code(),
            Some(0),
            "{help_flag}: {review_help:?}"
        );
        assert!(
            stdout_of(&review_help).contains("usage:"),
            "{help_flag}: the help banner answers the flag: {review_help:?}"
        );
    }
    assert!(
        !data_root.exists(),
        "help opens no runtime, store or data root"
    );

    let non_tty = run_cli_env(&["--ui-review", "start-no-connection"], None, &env);
    assert_eq!(non_tty.status.code(), Some(2), "{non_tty:?}");
    let refused = stderr_of(&non_tty);
    assert!(
        refused.contains("ui review requires a terminal"),
        "{non_tty:?}"
    );
    assert!(
        refused.contains("stdin and stdout are not terminals"),
        "the refusal names the streams that are not terminals: {refused}"
    );
    assert!(
        refused.contains("allocate a PTY"),
        "the refusal names the recovery: {refused}"
    );
    assert!(
        !data_root.exists(),
        "a non-TTY refusal opens no runtime, store or data root"
    );
}

#[test]
fn help_names_every_run_flag_and_the_surface_precedence() {
    let help = run_cli(&["--help"], None);
    assert_eq!(help.status.code(), Some(0), "{help:?}");
    let text = stdout_of(&help);
    for needle in [
        "flags:",
        "--tui fullscreen|inline",
        "fullscreen is the default",
        "--linear",
        "capture is off by default",
        "--headless",
        "--data-root PATH",
        "--ui-review <state>",
        "last of --tui/--linear wins",
        "RIVECT_LINEAR=1 sets the default surface only when no --tui or --linear flag is given",
    ] {
        assert!(text.contains(needle), "help omits {needle:?}: {text}");
    }
}

#[test]
fn flag_refusals_name_the_accepted_values_and_their_owner() {
    // `--tui linear` is a near miss for the supported `--linear`, so the
    // refusal names the values `--tui` accepts and the flag that owns linear.
    let linear = run_cli(&["--tui", "linear"], None);
    assert_eq!(linear.status.code(), Some(2), "{linear:?}");
    let refused = stderr_of(&linear);
    assert!(refused.contains("unknown --tui mode linear"), "{refused}");
    assert!(
        refused.contains("--tui accepts fullscreen or inline"),
        "{refused}"
    );
    assert!(refused.contains("--linear"), "{refused}");

    // `doctor` lists `--headless` in the banner but owns only its own flags.
    let doctor = run_cli(&["doctor", "--headless"], None);
    assert_eq!(doctor.status.code(), Some(2), "{doctor:?}");
    let refused = stderr_of(&doctor);
    assert!(
        refused.contains("unknown flag --headless for doctor"),
        "{refused}"
    );
    assert!(refused.contains("--project"), "{refused}");
    assert!(refused.contains("--data-root"), "{refused}");
}

#[test]
fn every_completion_word_is_a_dispatcher_request_and_help_agrees() {
    // Every emitted word parses through the grammar into a dispatcher request:
    // stdout carries a JSON answer and stderr never carries the usage banner.
    // A word the grammar rejected would answer the banner on stderr and no
    // JSON on stdout.
    let page = tools::describe();
    let root = tempfile::TempDir::with_prefix("rivect-completion-words-").expect("temp");
    let data_root = root.path().to_str().expect("utf-8 root").to_string();
    let help = stdout_of(&run_cli(&["--help"], None));
    for word in tools::completion_words(&page) {
        let output = run_cli(&[&word, "--data-root", &data_root], None);
        let stdout = stdout_of(&output);
        let stderr = stderr_of(&output);
        assert!(
            serde_json::from_str::<Value>(stdout.trim()).is_ok(),
            "{word} must answer through the dispatcher: stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            !stderr.contains("rivect [--tui fullscreen|inline]"),
            "{word} must not print the grammar's usage banner: {stderr:?}"
        );
        assert!(help.contains(&word), "help must agree with the word {word}");
    }
    // A word the page does not carry is still a grammar refusal, so the check
    // above is discriminating rather than passing on any word.
    let unknown = run_cli(&["not.a.command", "--data-root", &data_root], None);
    assert_eq!(unknown.status.code(), Some(2), "{unknown:?}");
    assert!(
        stderr_of(&unknown).contains("unknown command not.a.command"),
        "{unknown:?}"
    );
}

#[test]
fn a_catalog_omission_leaves_help_and_completions() {
    // The mutant: a page with one row removed. Every rendered word comes from
    // the page, so the dropped row must disappear from both surfaces.
    let mut page = tools::describe();
    let dropped = page.items.remove(10).canonical_id;
    let help = tools::help_lines(&page).join("\n");
    let bash = tools::completions(&page, Shell::Bash);
    assert!(!help.contains(&dropped), "help still names {dropped}");
    assert!(
        !words(&bash).iter().any(|word| word == &dropped),
        "bash completion still offers {dropped}"
    );

    // The unmutated page names it, so the check above is discriminating.
    let full = tools::describe();
    assert!(
        tools::completion_words(&full)
            .iter()
            .any(|word| word == &dropped),
        "the full page offers {dropped}"
    );
}

#[test]
fn machine_stdout_is_answers_only_and_the_exit_status_distinguishes_outcomes() {
    // A served frame answers on stdout only: one JSON object, no ANSI, and an
    // exit status that reports the answer's own class. The doctor frame is the
    // machine request every host can serve without a configured provider.
    let root = tempfile::TempDir::with_prefix("rivect-public-surface-machine-").expect("temp");
    let frame = json!({
        "jsonrpc": "2.0", "id": 1, "method": "command.execute",
        "params": { "schema_version": 1, "command": { "kind": "doctor" } }
    })
    .to_string();
    let output = run_cli(
        &[
            "--headless",
            "--data-root",
            root.path().to_str().expect("utf-8"),
        ],
        Some(&frame),
    );
    assert_eq!(output.status.code(), Some(3), "{}", stderr_of(&output));
    let stdout = stdout_of(&output);
    let answers = stdout.lines().collect::<Vec<_>>();
    assert_eq!(answers.len(), 1, "one answer per request: {stdout}");
    let parsed: Value = serde_json::from_str(answers[0]).expect("machine answer is JSON");
    assert!(parsed.get("result").is_some(), "{parsed}");
    assert!(!stdout.contains('\u{1b}'), "no ANSI on machine stdout");
    assert!(
        !stderr_of(&output).contains('{'),
        "stderr carries diagnostics, never an answer frame: {}",
        stderr_of(&output)
    );

    // A ready answer's class is the wire code's own: a result is success, an
    // error frame is its class, and an error frame without the typed code is
    // internal, never success. The loop's pending state and sticky precedence
    // are asserted against `ExitClass` in the bin's unit tests, where the one
    // owner lives.
    let error = json!({
        "jsonrpc": "2.0", "id": 1,
        "error": { "code": -32000, "message": "capability_unavailable",
                   "data": { "code": "capability_unavailable", "message": "x",
                             "retry_class": "none" } }
    })
    .to_string();
    assert_eq!(response_status(&error), 3);
    let answered = json!({ "jsonrpc": "2.0", "id": 1, "result": { "state": "ready" } }).to_string();
    assert_eq!(response_status(&answered), 0);
    let untyped = json!({
        "jsonrpc": "2.0", "id": 1,
        "error": { "code": -32000, "message": "transport" }
    })
    .to_string();
    assert_eq!(response_status(&untyped), 1);
}

#[test]
fn doctor_answers_ready_degraded_and_held_with_zero_effects() {
    // Ready: a root this build already opened and closed again.
    let ready_dir = tempfile::TempDir::with_prefix("rivect-doctor-ready-").expect("temp root");
    let ready_root = ready_dir.path().to_path_buf();
    {
        let mut world = support::open_world_at(&ready_root, None);
        let session = world.open_session("doctor-ready");
        let _ = world.create_task(&session, "doctor-ready-task");
    }
    let before = snapshot(&ready_root);
    let ready = run_cli(
        &[
            "doctor",
            "--data-root",
            ready_root.to_str().expect("utf-8 root"),
        ],
        None,
    );
    let report: Value = serde_json::from_str(stdout_of(&ready).trim()).expect("doctor JSON");
    assert_eq!(
        ready.status.code(),
        Some(if report["ready"] == true { 0 } else { 3 }),
        "{report}"
    );
    assert_eq!(report["kind"], "doctor", "{report}");
    for check in report["checks"].as_array().expect("checks") {
        assert_eq!(check["state"], "ready", "{check}");
    }
    assert_eq!(snapshot(&ready_root), before, "doctor wrote nothing");

    // Degraded: a config.toml the schema rejects, on a root never opened.
    let degraded_dir = tempfile::TempDir::with_prefix("rivect-doctor-degraded-").expect("temp");
    let degraded_root = degraded_dir.path().to_path_buf();
    std::fs::write(
        degraded_root.join("config.toml"),
        "config_version = \"not-a-number\"\n",
    )
    .expect("write config");
    let degraded = run_cli(
        &[
            "doctor",
            "--data-root",
            degraded_root.to_str().expect("utf-8 root"),
        ],
        None,
    );
    assert_eq!(
        degraded.status.code(),
        Some(3),
        "a degraded root is not ready: {}",
        stderr_of(&degraded)
    );
    let report: Value = serde_json::from_str(stdout_of(&degraded).trim()).expect("doctor JSON");
    assert_eq!(report["ready"], false, "{report}");
    let config = report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|check| check["name"] == "config")
        .expect("config check");
    assert_eq!(config["state"], "degraded", "{config}");
    assert_eq!(
        snapshot(&degraded_root).len(),
        1,
        "doctor created nothing beside the fixture's own config"
    );

    // Held: another live world holds the writer election while the doctor
    // runs, and the probe reports it without disturbing anything.
    let held_dir = tempfile::TempDir::with_prefix("rivect-doctor-held-").expect("temp root");
    let held_root = held_dir.path().to_path_buf();
    // A real election, held for as long as the fixture lives: the doctor runs
    // as its own process, so the conflict is the OS lock's and not a simulated
    // flag.
    let elected = rivect::owner::Owner::elect(&held_root).expect("elect");
    let before = snapshot(&held_root);
    let held = run_cli(
        &[
            "doctor",
            "--data-root",
            held_root.to_str().expect("utf-8 root"),
        ],
        None,
    );
    assert_eq!(held.status.code(), Some(3), "{}", stderr_of(&held));
    let report: Value = serde_json::from_str(stdout_of(&held).trim()).expect("doctor JSON");
    assert_eq!(report["ready"], false, "{report}");
    let owner = report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|check| check["name"] == "owner_lock")
        .expect("owner check");
    assert_eq!(owner["state"], "held", "{owner}");
    assert_eq!(snapshot(&held_root), before, "the probe created nothing");
    drop(elected);

    // Shared holder: a second non-creating shared lock is not a writer, so
    // the probe stays ready and a concurrent election still succeeds.
    let shared_dir = tempfile::TempDir::with_prefix("rivect-doctor-shared-").expect("temp root");
    let shared_root = shared_dir.path().to_path_buf();
    std::fs::create_dir_all(shared_root.join("runtime")).expect("runtime dir");
    let lock_path = shared_root.join(rivect::owner::OWNER_LOCK);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .expect("lock file");
    file.try_lock_shared().expect("shared holder");
    let shared = run_cli(
        &[
            "doctor",
            "--data-root",
            shared_root.to_str().expect("utf-8 root"),
        ],
        None,
    );
    let report: Value = serde_json::from_str(stdout_of(&shared).trim()).expect("doctor JSON");
    let owner = report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|check| check["name"] == "owner_lock")
        .expect("owner check");
    assert_eq!(
        owner["state"], "ready",
        "a shared holder is not a writer: {owner}"
    );

    // A second doctor beside the first: both probe shared and both answer.
    let doctor = || {
        run_cli(
            &[
                "doctor",
                "--data-root",
                shared_root.to_str().expect("utf-8 root"),
            ],
            None,
        )
    };
    let (first, second) = (doctor(), doctor());
    for output in [&first, &second] {
        let report: Value = serde_json::from_str(stdout_of(output).trim()).expect("doctor JSON");
        let owner = report["checks"]
            .as_array()
            .expect("checks")
            .iter()
            .find(|check| check["name"] == "owner_lock")
            .expect("owner check");
        assert_eq!(owner["state"], "ready", "two doctors coexist: {owner}");
    }
    drop(file);

    // The election tolerates a transient shared probe, deterministically: the
    // probe is held across a known window, the elector provably has not
    // finished inside it (it is retrying, not refusing), and the release then
    // lets the same call win. A retry that gave up on the first `WouldBlock`
    // would report `AlreadyOwned` before the release.
    let election_dir = tempfile::TempDir::with_prefix("rivect-election-").expect("temp root");
    let election_root = election_dir.path().to_path_buf();
    std::fs::create_dir_all(election_root.join("runtime")).expect("runtime dir");
    let election_lock = election_root.join(rivect::owner::OWNER_LOCK);
    let holder = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&election_lock)
        .expect("lock file");
    holder.try_lock_shared().expect("shared holder");
    let elect_root = election_root.clone();
    let elector = std::thread::spawn(move || rivect::owner::Owner::elect(&elect_root));
    // The election window is 50ms; 5ms of a held probe is inside it with a
    // wide margin, so a finished elector here means the retry is missing.
    std::thread::sleep(Duration::from_millis(5));
    assert!(
        !elector.is_finished(),
        "the election is retrying a transient probe, not refusing it"
    );
    drop(holder);
    let elected = elector.join().expect("elector thread");
    assert!(
        elected.is_ok(),
        "a transient shared probe must not fail the election: {:?}",
        elected.err()
    );
}

#[test]
fn the_headless_loop_answers_a_doctor_frame_before_opening_the_runtime() {
    let root = tempfile::TempDir::with_prefix("rivect-doctor-frame-").expect("temp root");
    let frame = json!({
        "jsonrpc": "2.0", "id": 7, "method": "command.execute",
        "params": { "schema_version": 1, "command": { "kind": "doctor" } }
    })
    .to_string();
    let output = run_cli(
        &[
            "--headless",
            "--data-root",
            root.path().to_str().expect("utf-8"),
        ],
        Some(&frame),
    );
    assert_eq!(output.status.code(), Some(3), "{}", stderr_of(&output));
    let answer: Value =
        serde_json::from_str(stdout_of(&output).trim()).expect("doctor answer is JSON");
    assert_eq!(answer["id"], 7, "{answer}");
    assert_eq!(answer["result"]["kind"], "doctor", "{answer}");
    assert_eq!(answer["result"]["ready"], false, "{answer}");
    assert_eq!(
        snapshot(root.path()),
        Vec::new(),
        "the answer needed no runtime: no lock, no store, no directory"
    );
}

#[test]
fn a_headless_run_with_no_frame_still_reports_its_boot_diagnostics() {
    // End of input with no doctor frame is not an answer: the runtime opens
    // and its typed config diagnostic reaches stderr, so a broken document is
    // never masked by the pre-open pass.
    let root = tempfile::TempDir::with_prefix("rivect-headless-diagnostic-").expect("temp root");
    std::fs::write(
        root.path().join("config.toml"),
        "config_version = \"not-a-number\"\n",
    )
    .expect("write config");
    let output = run_cli(
        &[
            "--headless",
            "--data-root",
            root.path().to_str().expect("utf-8"),
        ],
        Some(""),
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "a malformed config fails the open: {}",
        stderr_of(&output)
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("config.toml"),
        "the typed diagnostic names the file: {stderr:?}"
    );
    assert!(
        !stderr.contains('{'),
        "stderr carries diagnostics, never an answer frame: {stderr:?}"
    );
    assert!(
        stdout_of(&output).is_empty(),
        "no frame was answered: {:?}",
        stdout_of(&output)
    );
}

/// One headless child with a piped stdin/stdout, so a case can hold the input
/// open, read one answer at a time and decide when the run ends.
fn spawn_headless(data_root: &Path) -> (Child, ChildStdin, BufReader<ChildStdout>) {
    let mut command = std::process::Command::new(support::rivect_binary());
    command
        .arg("--headless")
        .arg("--data-root")
        .arg(data_root)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command.spawn().expect("spawn rivect --headless");
    let stdin = child.stdin.take().expect("stdin pipe");
    let stdout = BufReader::new(child.stdout.take().expect("stdout pipe"));
    (child, stdin, stdout)
}

fn write_frame(stdin: &mut ChildStdin, frame: &Value) {
    writeln!(stdin, "{frame}").expect("write frame");
    stdin.flush().expect("flush frame");
}

fn read_answer(stdout: &mut BufReader<ChildStdout>) -> Value {
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read answer");
    serde_json::from_str(&line).unwrap_or_else(|error| panic!("answer is JSON: {error}: {line}"))
}

/// Runs the binary and gives up after `deadline`: a command whose contract is
/// to answer must not be able to hang the suite that proves it.
fn run_cli_bounded(args: &[&str], deadline: Duration) -> Option<Output> {
    let mut command = std::process::Command::new(support::rivect_binary());
    command
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command.spawn().expect("spawn rivect");
    let started = Instant::now();
    loop {
        match child.try_wait().expect("try_wait") {
            Some(_) => return Some(child.wait_with_output().expect("wait for rivect")),
            None if started.elapsed() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

#[test]
fn a_doctor_frame_after_open_reports_the_own_lock_ready() {
    // The in-loop doctor answers inside the owner process: its own exclusive
    // election is not another writer, so a healthy root reports ready and the
    // run keeps its class instead of forcing 3.
    let root = tempfile::TempDir::with_prefix("rivect-doctor-midloop-").expect("temp root");
    let (mut child, mut stdin, mut stdout) = spawn_headless(root.path());
    write_frame(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "session.attach",
            "params": { "schema_version": 1, "bootstrap_id": "doctor-midloop-session" }
        }),
    );
    let attached = read_answer(&mut stdout);
    assert!(attached.get("error").is_none(), "{attached}");
    // The runtime is open and this process holds the election from here on.
    write_frame(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "id": 2, "method": "command.execute",
            "params": { "schema_version": 1, "command": { "kind": "doctor" } }
        }),
    );
    let report = read_answer(&mut stdout);
    assert_eq!(report["result"]["kind"], "doctor", "{report}");
    assert_eq!(
        report["result"]["ready"], true,
        "a healthy owned root is ready mid-loop: {report}"
    );
    let owner = report["result"]["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|check| check["name"] == "owner_lock")
        .expect("owner check");
    assert_eq!(owner["state"], "ready", "{owner}");
    assert!(
        owner["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("this process holds")),
        "the own lock is named as this process's: {owner}"
    );
    drop(stdin);
    let status = child.wait().expect("wait for the entry");
    assert_eq!(
        status.code(),
        Some(0),
        "a healthy doctor frame does not force exit 3"
    );
}

#[test]
fn a_failed_open_with_live_stdin_still_exits_one() {
    // The pre-open failure path must not join a reader blocked in `read_until`
    // on a stdin the client keeps open: the failure exits 1 within a bounded
    // wait instead of hanging.
    let root = tempfile::TempDir::with_prefix("rivect-failed-open-live-stdin-").expect("temp root");
    std::fs::write(
        root.path().join("config.toml"),
        "config_version = \"not-a-number\"\n",
    )
    .expect("write config");
    let mut command = std::process::Command::new(support::rivect_binary());
    command
        .arg("--headless")
        .arg("--data-root")
        .arg(root.path())
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command.spawn().expect("spawn rivect");
    // Keep the stdin handle alive: the client holds its pipe open. One
    // non-doctor frame is what reaches the open — the pre-open pass answers
    // doctor frames only — so the malformed document is discovered there.
    let mut stdin = child.stdin.take().expect("stdin pipe");
    writeln!(
        stdin,
        "{}",
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "runtime.status",
            "params": { "schema_version": 1, "session_id": "00000000-0000-4000-8000-000000000001" }
        })
    )
    .expect("write frame");
    stdin.flush().expect("flush frame");
    let started = Instant::now();
    let mut exited = false;
    while started.elapsed() < Duration::from_secs(10) {
        if child.try_wait().expect("try_wait").is_some() {
            exited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if !exited {
        let _ = child.kill();
    }
    let status = child.wait().expect("wait for rivect");
    assert_eq!(
        status.code(),
        Some(1),
        "a failed open with a live stdin exits 1 instead of joining the reader"
    );
    drop(stdin);
}

#[test]
fn a_fifo_at_the_store_path_does_not_block_the_doctor() {
    // The store check opens `runtime/rivect.db` the way the config ingress
    // does: non-blocking and regular-file only, so a FIFO swapped onto the
    // path answers degraded instead of hanging the one command that must
    // answer.
    let root = tempfile::TempDir::with_prefix("rivect-doctor-fifo-").expect("temp root");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    let fifo = root.path().join("runtime").join("rivect.db");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(made.success(), "the FIFO fixture was created");
    let output = run_cli_bounded(
        &[
            "doctor",
            "--data-root",
            root.path().to_str().expect("utf-8 root"),
        ],
        Duration::from_secs(10),
    );
    let output = output.expect("the doctor answered instead of blocking on the FIFO");
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let report: Value = serde_json::from_str(stdout_of(&output).trim()).expect("doctor JSON");
    let store = report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|check| check["name"] == "state_db")
        .expect("store check");
    assert_eq!(
        store["state"], "degraded",
        "a non-regular store path is refused, not opened: {store}"
    );
}

#[test]
fn model_and_effort_views_serve_the_resolved_purpose_row() {
    // The views publish the resolved assignment, not only an array shape: a
    // pinned purpose row is what a surface renders.
    let mut world = support::open_world(
        "public-surface-purposes",
        Some(&support::config_pinned_planner()),
    );
    let session = world.open_session("public-surface-purposes");
    let model = execute(&mut world, &session, "model.view", json!({}));
    assert!(model.get("error").is_none(), "{model}");
    let model_row = model["result"]["purposes"]
        .as_array()
        .expect("purposes")
        .iter()
        .find(|row| row["purpose"] == "planner")
        .expect("the pinned purpose is resolved");
    assert_eq!(
        model_row["model"], "primary:fixture-model",
        "the pinned model is served: {model}"
    );
    let effort = execute(&mut world, &session, "effort.view", json!({}));
    assert!(effort.get("error").is_none(), "{effort}");
    let effort_row = effort["result"]["purposes"]
        .as_array()
        .expect("purposes")
        .iter()
        .find(|row| row["purpose"] == "planner")
        .expect("the pinned purpose is resolved");
    assert_eq!(
        effort_row["effort"], "high",
        "the pinned effort is served: {effort}"
    );
}
