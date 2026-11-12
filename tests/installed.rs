//! AC-001/AC-040/AC-080 (TD-03): installed provider rows and support
//! journeys run on the exact packaged artifact whose manifest digest the
//! release activation identity binds. The 74 recorded provider rows plus both
//! login aliases are exercised through the packaged binary as 76 installed
//! rows — the other four TPs come from their own targets, so a 372
//! installed-row claim is rejected. Support preview/export and read-only
//! replay publish nothing, repeat no effect, and replace provider-bound
//! reasoning bytes and credential values with fixed reason codes. Unserved
//! rows stay explicit, and a missing, stale or shrunken row fails instead of
//! passing by narration.
//!
//! The installed ordinary positive runs on the packaged artifact too: the TUI
//! composer's create publishes the production start question, its `begin`
//! answer drains the configured local provider, and the run reports one
//! settlement. Live provider/publication legs stay NOT_RUN.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test assertions fail loudly with the observed payload; src/ stays strict (standards §14)"
)]

mod support;

use rivect::contracts::{RELEASE_MANIFEST_NAME, ReleaseManifest};
use rivect::executor::verify_release_bundle;
use rivect::verification::SEARCH_SERVICES;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

/// The 74 recorded provider rows, in source order, with the dialect the
/// installed build must answer for each.
const PROVIDER_ROWS: [(&str, &str); 74] = [
    ("openai", "responses"),
    ("abliteration", "responses"),
    ("meta", "responses"),
    ("ollama", "responses"),
    ("custom-responses", "responses"),
    ("openrouter", "responses"),
    ("sakana", "responses"),
    ("xai", "responses"),
    ("xai-oauth", "responses"),
    ("openai-codex", "responses"),
    ("openai-codex-device", "responses"),
    ("amazon-bedrock", "converse"),
    ("bedrock-mantle", "responses"),
    ("cursor", "cursor-agent"),
    ("devin", "devin-agent"),
    ("gitlab-duo-agent", "gitlab-workflow"),
    ("ollama-cloud", "ollama-chat"),
    ("google", "gemini"),
    ("google-vertex", "vertex"),
    ("google-antigravity", "cloudcode"),
    ("google-gemini-cli", "cloudcode"),
    ("anthropic", "messages"),
    ("minimax", "messages"),
    ("umans", "messages"),
    ("cloudflare-ai-gateway", "messages"),
    ("custom-messages", "messages"),
    ("vercel-ai-gateway", "messages"),
    ("kimi-code", "messages"),
    ("zai", "messages"),
    ("zai-coding-plan", "messages"),
    ("gitlab-duo", "chat-completions"),
    ("github-copilot", "chat-completions"),
    ("opencode-go", "chat-completions"),
    ("opencode-zen", "chat-completions"),
    ("custom-chat-completions", "chat-completions"),
    ("aiand", "chat-completions"),
    ("aimlapi", "chat-completions"),
    ("alibaba-coding-plan", "chat-completions"),
    ("alibaba-token-plan", "chat-completions"),
    ("coreweave", "chat-completions"),
    ("deepinfra", "chat-completions"),
    ("deepseek", "chat-completions"),
    ("firepass", "chat-completions"),
    ("fireworks", "chat-completions"),
    ("gmi-cloud", "chat-completions"),
    ("groq", "chat-completions"),
    ("huggingface", "chat-completions"),
    ("kilo", "chat-completions"),
    ("litellm", "chat-completions"),
    ("llama.cpp", "chat-completions"),
    ("lm-studio", "chat-completions"),
    ("minimax-code", "chat-completions"),
    ("minimax-code-cn", "chat-completions"),
    ("mistral", "chat-completions"),
    ("moonshot", "chat-completions"),
    ("nanogpt", "chat-completions"),
    ("novita", "chat-completions"),
    ("nvidia", "chat-completions"),
    ("qianfan", "chat-completions"),
    ("qwen-portal", "chat-completions"),
    ("siliconflow", "chat-completions"),
    ("siliconflow-cn", "chat-completions"),
    ("synthetic", "chat-completions"),
    ("together", "chat-completions"),
    ("venice", "chat-completions"),
    ("vllm", "chat-completions"),
    ("wafer-serverless", "chat-completions"),
    ("xiaomi", "chat-completions"),
    ("xiaomi-token-plan-ams", "chat-completions"),
    ("xiaomi-token-plan-cn", "chat-completions"),
    ("xiaomi-token-plan-sgp", "chat-completions"),
    ("yolo-auto", "chat-completions"),
    ("zenmux", "chat-completions"),
    ("zhipu-coding-plan", "chat-completions"),
];

/// Both login alias rows and the canonical provider each stores.
const ALIAS_ROWS: [(&str, &str); 2] = [
    ("openai-codex-device", "openai-codex"),
    ("zai-coding-plan", "zai"),
];

/// The two recorded dialects no installed adapter serves in this build.
const UNSERVED_ROWS: [&str; 2] = ["cursor", "devin"];

/// 74 provider rows plus 2 aliases are installed rows; 74×5+2 is the final
/// acceptance conjunction over all five TPs, never an installed-row count.
const FIVE_TP_CONJUNCTION: usize = 74 * 5 + 2;

fn installed_state(id: &str) -> &'static str {
    if UNSERVED_ROWS.contains(&id) {
        "unserved"
    } else {
        "installed"
    }
}

/// One packaged process with the given frames on stdin, clean environment and
/// only what a process needs to run.
fn run_packaged_frames(bundle: &Path, cwd: &Path, args: &[&str], frames: &[Value]) -> Output {
    let mut command = Command::new(bundle.join("rivect"));
    command
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command.spawn().expect("spawn the packaged rivect");
    {
        let mut stdin = child.stdin.take().expect("packaged stdin");
        for frame in frames {
            writeln!(stdin, "{frame}").expect("write one frame");
        }
    }
    child
        .wait_with_output()
        .expect("wait for the packaged rivect")
}

fn responses(output: &Output) -> Vec<Value> {
    support::release::stdout_of(output)
        .lines()
        .map(|line| serde_json::from_str(line).expect("one JSON response frame"))
        .collect()
}

fn answer(answers: &[Value], id: u64) -> &Value {
    answers
        .iter()
        .find(|answer| answer["id"] == json!(id))
        .unwrap_or_else(|| panic!("no answer for id {id}: {answers:?}"))
}

fn command_frame(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn session_frame(id: u64, session: &Value, method: &str, extra: Value) -> Value {
    let mut params = json!({"schema_version": 1, "session_id": session});
    if let Some(fields) = extra.as_object() {
        for (key, value) in fields {
            params[key] = value.clone();
        }
    }
    command_frame(id, method, params)
}

/// One catalog row through `command.execute`: the kind rides inside
/// `command`, and the row's own parameters stay top-level siblings.
fn local_command(id: u64, session: &Value, kind: &str, extra: Value) -> Value {
    let mut params = json!({
        "schema_version": 1,
        "session_id": session,
        "command": {"kind": kind},
    });
    if let Some(fields) = extra.as_object() {
        for (key, value) in fields {
            params[key] = value.clone();
        }
    }
    command_frame(id, "command.execute", params)
}

/// Whether the observed rows are exactly the expected roster: one row per id,
/// its recorded dialect, its explicit state, and the expected count. A
/// removed, stale, unrecorded or shrunken row fails.
fn roster_complete(expected: &[(&str, &str, &str)], observed: &[(String, Value)]) -> bool {
    observed.len() == expected.len()
        && expected.iter().all(|(id, dialect, state)| {
            observed.iter().filter(|(seen, _)| seen == id).count() == 1
                && observed.iter().any(|(seen, row)| {
                    seen == id && row["dialect"] == json!(dialect) && row["state"] == json!(state)
                })
        })
}

/// The installed build answers every recorded provider row and both aliases
/// on the exact packaged artifact outside the checkout.
#[test]
fn installed_artifact_answers_76_provider_and_alias_rows() {
    let root = tempfile::TempDir::with_prefix("rivect-installed-rows-").expect("fixture root");
    let bundle = support::release::baseline_bundle();
    assert!(
        !bundle.starts_with(env!("CARGO_MANIFEST_DIR")),
        "the bundle is outside the checkout: {}",
        bundle.display()
    );
    let activation = verify_release_bundle(bundle).expect("the packaged artifact activates");
    let manifest_bytes =
        std::fs::read(bundle.join(RELEASE_MANIFEST_NAME)).expect("packaged manifest");
    let manifest: ReleaseManifest =
        serde_json::from_slice(&manifest_bytes).expect("manifest schema");
    assert_eq!(
        activation.manifest_sha256,
        support::release::sha256_file(&bundle.join(RELEASE_MANIFEST_NAME)),
        "the manifest digest is the bytes on disk"
    );
    assert_eq!(manifest.executable.sha256, activation.executable_sha256);
    println!("installed manifest sha256: {}", activation.manifest_sha256);

    let data = root.path().join("data root юникод");
    let cwd = root.path().join("nested working dir").join("юникод cwd");
    std::fs::create_dir_all(&data).expect("data root");
    std::fs::create_dir_all(&cwd).expect("nested cwd");
    let data_argument = data.to_str().expect("utf-8 data root");

    // 74 provider rows, then the two alias rows: the alias ids are recorded
    // provider rows too, and the alias form is exercised as its own row.
    let mut frames = Vec::with_capacity(76);
    let mut expected = Vec::with_capacity(74);
    for (index, (id, dialect)) in PROVIDER_ROWS.iter().enumerate() {
        frames.push(command_frame(
            index as u64 + 1,
            "provider.row",
            json!({"schema_version": 1, "id": id}),
        ));
        expected.push((*id, *dialect, installed_state(id)));
    }
    for (index, (id, _canonical)) in ALIAS_ROWS.iter().enumerate() {
        let frame_id = PROVIDER_ROWS.len() as u64 + index as u64 + 1;
        frames.push(command_frame(
            frame_id,
            "provider.row",
            json!({"schema_version": 1, "id": id}),
        ));
    }

    let output = run_packaged_frames(
        bundle,
        &cwd,
        &["--headless", "--data-root", data_argument],
        &frames,
    );
    assert!(
        output.status.success(),
        "the packaged rows answered: {}",
        support::release::stderr_of(&output)
    );
    let answers = responses(&output);
    assert_eq!(answers.len(), frames.len(), "one answer per frame");

    let mut provider_rows = Vec::with_capacity(74);
    for index in 0..PROVIDER_ROWS.len() {
        let result = &answer(&answers, index as u64 + 1)["result"];
        assert_eq!(result["kind"], "provider.row", "{result}");
        provider_rows.push((
            result["id"].as_str().expect("row id").to_string(),
            result.clone(),
        ));
    }
    let mut alias_rows = Vec::with_capacity(2);
    for (index, (id, canonical)) in ALIAS_ROWS.iter().enumerate() {
        let frame_id = PROVIDER_ROWS.len() as u64 + index as u64 + 1;
        let result = &answer(&answers, frame_id)["result"];
        assert_eq!(result["kind"], "provider.row", "{result}");
        assert_eq!(result["id"], json!(id), "{result}");
        assert_eq!(result["alias_of"], json!(canonical), "{result}");
        assert_eq!(result["state"], "installed", "{result}");
        alias_rows.push((
            result["id"].as_str().expect("alias id").to_string(),
            result.clone(),
        ));
    }

    let installed_rows = provider_rows.len() + alias_rows.len();
    assert_eq!(provider_rows.len(), 74, "74 provider installed rows");
    assert_eq!(alias_rows.len(), 2, "2 alias installed rows");
    assert_eq!(installed_rows, 76, "76 installed rows");
    assert_eq!(FIVE_TP_CONJUNCTION, 372, "the five-TP conjunction is 372");
    assert_ne!(
        installed_rows, FIVE_TP_CONJUNCTION,
        "372 rows are the 74x5+2 five-TP conjunction, never an installed-row claim"
    );
    assert!(
        roster_complete(&expected, &provider_rows),
        "every recorded provider row carries its dialect and explicit state: {provider_rows:?}"
    );

    // Unserved rows are explicit, not silently dropped.
    for id in UNSERVED_ROWS {
        let row = provider_rows
            .iter()
            .find(|(seen, _)| seen == id)
            .map(|(_, row)| row)
            .expect("an unserved row is still present");
        assert_eq!(row["state"], "unserved", "{row}");
        assert_eq!(row["reason_code"], "dialect_unserved", "{row}");
    }
    let unresolved = command_frame(
        200,
        "provider.row",
        json!({"schema_version": 1, "id": "not-a-recorded-row"}),
    );
    let blocked = command_frame(
        201,
        "provider.row",
        json!({"schema_version": 1, "id": "muse-code"}),
    );
    let output = run_packaged_frames(
        bundle,
        &cwd,
        &["--headless", "--data-root", data_argument],
        &[unresolved, blocked],
    );
    let unanswered = responses(&output);
    assert_eq!(answer(&unanswered, 200)["result"]["state"], "unrecorded");
    assert_eq!(
        answer(&unanswered, 200)["result"]["reason_code"],
        "not_recorded"
    );
    assert_eq!(
        answer(&unanswered, 201)["result"]["state"],
        "externally_blocked"
    );
    assert_eq!(
        answer(&unanswered, 201)["result"]["reason_code"],
        "externally_blocked"
    );

    // Fail-closed controls: a removed, stale, unrecorded or shrunken row is
    // not PASS.
    let mut missing = provider_rows.clone();
    missing.remove(0);
    assert!(!roster_complete(&expected, &missing), "a missing row fails");
    let mut stale = provider_rows.clone();
    stale[0].1["dialect"] = json!("stale-dialect");
    assert!(!roster_complete(&expected, &stale), "a stale row fails");
    let mut unrecorded = provider_rows.clone();
    unrecorded[0].1["state"] = json!("unrecorded");
    assert!(
        !roster_complete(&expected, &unrecorded),
        "an unrecorded row fails"
    );
    let mut shrunken = provider_rows.clone();
    shrunken.truncate(10);
    assert!(
        !roster_complete(&expected, &shrunken),
        "a shrunken roster fails"
    );
    assert!(roster_complete(&expected, &provider_rows));
    println!(
        "installed rows: {installed_rows} (74 provider + 2 alias); unserved rows stay explicit"
    );
}

#[test]
fn the_release_zero_effect_oracle_sees_a_same_length_rewrite() {
    // The release zero-write proof records the bytes under its roots, not
    // just their sizes: a same-length in-place rewrite must move it.
    let root = tempfile::TempDir::with_prefix("rivect-release-oracle-digest-").expect("temp root");
    let target = root.path().join("candidate.bin");
    std::fs::write(&target, b"aaaa").expect("first bytes");
    let before = support::release::snapshot(root.path());
    std::fs::write(&target, b"bbbb").expect("same-length rewrite");
    assert_eq!(
        std::fs::metadata(&target).expect("metadata").len(),
        before[0].1,
        "the control keeps the recorded length"
    );
    assert_ne!(
        support::release::snapshot(root.path()),
        before,
        "a same-length in-place rewrite must move the release zero-write oracle"
    );
}

/// Support preview/export and read-only replay publish nothing, repeat no
/// effect, and replace provider-bound reasoning bytes and credential values
/// with fixed reason codes.
#[test]
fn installed_support_and_replay_are_zero_effect_and_redacted() {
    const THINKING_SENTINEL: &str = "THINKING-SENTINEL-bytes";
    const SIGNATURE_SENTINEL: &str = "SIGNATURE-SENTINEL-bytes";
    const ENCRYPTED_SENTINEL: &str = "ENCRYPTED-SENTINEL-bytes";
    const THOUGHT_SIGNATURE_SENTINEL: &str = "THOUGHT-SIGNATURE-SENTINEL-bytes";
    const REDACTED_SENTINEL: &str = "REDACTED-THINKING-SENTINEL-bytes";
    const REASONING_SENTINEL: &str = "REASONING-SENTINEL-bytes";
    const REASONING_TEXT_SENTINEL: &str = "REASONING-TEXT-SENTINEL-bytes";
    const REASONING_DETAILS_SENTINEL: &str = "REASONING-DETAILS-SENTINEL-bytes";
    const SUMMARY_SENTINEL: &str = "SUMMARY-TEXT-SENTINEL-bytes";
    const SECRET_SENTINEL: &str = "SECRET-SENTINEL-bytes";
    const GEMINI_THOUGHT_SENTINEL: &str = "GEMINI-THOUGHT-SENTINEL-bytes";
    const GITLAB_REASONING_SENTINEL: &str = "GITLAB-REASONING-SENTINEL-bytes";
    const ID_TOKEN_SENTINEL: &str = "ID-TOKEN-SENTINEL-bytes";
    const PRIVATE_KEY_SENTINEL: &str = "PRIVATE-KEY-SENTINEL-bytes";

    let root = tempfile::TempDir::with_prefix("rivect-installed-support-").expect("fixture root");
    let bundle = support::release::baseline_bundle();
    let data = root.path().join("data root юникод");
    let cwd = root.path().join("nested working dir").join("юникод cwd");
    std::fs::create_dir_all(&cwd).expect("nested cwd");
    std::fs::create_dir_all(&data).expect("data root");
    let data_argument = data.to_str().expect("utf-8 data root");

    let raw_bundle = json!({
        "session": "local replay state",
        "trace": [
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": THINKING_SENTINEL, "signature": SIGNATURE_SENTINEL}
            ]},
            {"type": "reasoning", "id": "rs_1",
             "summary": [{"type": "summary_text", "text": SUMMARY_SENTINEL}],
             "encrypted_content": [ENCRYPTED_SENTINEL]},
            {"type": "redacted_thinking", "data": REDACTED_SENTINEL},
            {"type": "reasoning_text", "text": REASONING_TEXT_SENTINEL},
            {"parts": [{"thought_signature": THOUGHT_SIGNATURE_SENTINEL}]},
            {"signature": SIGNATURE_SENTINEL},
            {"encrypted_content": ENCRYPTED_SENTINEL},
            {"reasoning": REASONING_SENTINEL},
            {"reasoning_text": REASONING_TEXT_SENTINEL},
            {"reasoning_details": REASONING_DETAILS_SENTINEL},
            {"parts": [{"thought": true, "text": GEMINI_THOUGHT_SENTINEL}]},
            {"message_sub_type": "reasoning", "content": GITLAB_REASONING_SENTINEL},
            {"headers": {
                "authorization": SECRET_SENTINEL,
                "Authorization": SECRET_SENTINEL,
                "API_KEY": [SECRET_SENTINEL],
                "x-api-key": SECRET_SENTINEL,
                "cf-aig-authorization": SECRET_SENTINEL,
                "x-amz-security-token": SECRET_SENTINEL,
                "token": SECRET_SENTINEL,
                "apiKey": SECRET_SENTINEL,
                "x-goog-api-key": SECRET_SENTINEL,
                "bearer_token": SECRET_SENTINEL,
                "accessKeyId": SECRET_SENTINEL,
                "SecretAccessKey": SECRET_SENTINEL,
                "SessionToken": SECRET_SENTINEL,
                "secretKey": SECRET_SENTINEL,
                "id_token": ID_TOKEN_SENTINEL,
                "privateKey": PRIVATE_KEY_SENTINEL
            }}
        ]
    });
    let expected_replacements = json!({
        "reasoning_local_only": 10,
        "signature_local_only": 1,
        "encrypted_reasoning_local_only": 1,
        "secret_local_only": 16,
    });
    let provider_bytes = [
        THINKING_SENTINEL,
        SIGNATURE_SENTINEL,
        ENCRYPTED_SENTINEL,
        THOUGHT_SIGNATURE_SENTINEL,
        REDACTED_SENTINEL,
        REASONING_SENTINEL,
        REASONING_TEXT_SENTINEL,
        REASONING_DETAILS_SENTINEL,
        SUMMARY_SENTINEL,
        SECRET_SENTINEL,
        GEMINI_THOUGHT_SENTINEL,
        GITLAB_REASONING_SENTINEL,
        ID_TOKEN_SENTINEL,
        PRIVATE_KEY_SENTINEL,
    ];

    let first = run_packaged_frames(
        bundle,
        &cwd,
        &["--headless", "--data-root", data_argument],
        &[command_frame(
            1,
            "session.attach",
            json!({"schema_version": 1, "bootstrap_id": "installed-support"}),
        )],
    );
    assert!(
        first.status.success(),
        "the packaged artifact runs: {}",
        support::release::stderr_of(&first)
    );
    let first_answers = responses(&first);
    let session = answer(&first_answers, 1)["result"]["session_id"].clone();

    let export_run = run_packaged_frames(
        bundle,
        &cwd,
        &["--headless", "--data-root", data_argument],
        &[
            command_frame(
                1,
                "session.attach",
                json!({"schema_version": 1, "bootstrap_id": "installed-support"}),
            ),
            local_command(
                2,
                &session,
                "session.export",
                json!({"after_cursor": 0, "page": {"page_size": 200}}),
            ),
            session_frame(
                3,
                &session,
                "support.preview",
                json!({"bundle": raw_bundle}),
            ),
            session_frame(4, &session, "support.export", json!({"bundle": raw_bundle})),
            session_frame(5, &session, "support.export", json!({"bundle": raw_bundle})),
        ],
    );
    assert!(
        export_run.status.success(),
        "the packaged support export answered: {}",
        support::release::stderr_of(&export_run)
    );
    let export_answers = responses(&export_run);
    assert_eq!(export_answers.len(), 5, "one answer per frame");

    let preview = &answer(&export_answers, 3)["result"];
    assert_eq!(preview["kind"], "support.preview", "{preview}");
    assert_eq!(preview["redacted"], true, "{preview}");
    assert_eq!(preview["replacements"], expected_replacements, "{preview}");

    let exported = &answer(&export_answers, 4)["result"];
    assert_eq!(exported["kind"], "support.export", "{exported}");
    assert_eq!(
        exported["replacements"], expected_replacements,
        "{exported}"
    );
    let export_text = exported["bundle"].to_string();
    for sentinel in provider_bytes {
        assert!(
            !support::release::stdout_of(&export_run).contains(sentinel),
            "support output never carries the sentinel {sentinel}"
        );
    }
    for code in [
        "reasoning_local_only",
        "signature_local_only",
        "encrypted_reasoning_local_only",
        "secret_local_only",
    ] {
        assert!(
            export_text.contains(code),
            "the fixed reason code {code} replaces the artifact: {export_text}"
        );
    }

    // A second export of the same bytes yields the identical fixed digest.
    assert_eq!(
        answer(&export_answers, 4)["result"]["digest"],
        answer(&export_answers, 5)["result"]["digest"],
        "fixed reason codes make the export deterministic"
    );

    let exported_bundle = exported["bundle"].clone();
    let replay_run = run_packaged_frames(
        bundle,
        &cwd,
        &["--headless", "--data-root", data_argument],
        &[
            command_frame(
                1,
                "session.attach",
                json!({"schema_version": 1, "bootstrap_id": "installed-support"}),
            ),
            session_frame(
                2,
                &session,
                "support.replay",
                json!({"bundle": exported_bundle}),
            ),
            session_frame(3, &session, "support.replay", json!({"bundle": raw_bundle})),
            local_command(
                4,
                &session,
                "session.export",
                json!({"after_cursor": 0, "page": {"page_size": 200}}),
            ),
            local_command(5, &session, "usage.view", json!({})),
        ],
    );
    assert!(
        replay_run.status.success(),
        "the packaged support replay answered: {}",
        support::release::stderr_of(&replay_run)
    );
    let replay_answers = responses(&replay_run);
    let replay = &answer(&replay_answers, 2)["result"];
    assert_eq!(replay["kind"], "support.replay", "{replay}");
    assert_eq!(replay["verified"], true, "{replay}");
    let raw_replay = &answer(&replay_answers, 3)["result"];
    assert_eq!(raw_replay["verified"], false, "{raw_replay}");
    assert_eq!(
        raw_replay["replacements"], expected_replacements,
        "{raw_replay}"
    );
    for sentinel in provider_bytes {
        assert!(
            !support::release::stdout_of(&replay_run).contains(sentinel),
            "support replay never carries the sentinel {sentinel}"
        );
    }

    // Zero effect: no event landed and no settlement moved across preview,
    // export and both replays.
    assert_eq!(
        answer(&export_answers, 2)["result"]["items"]
            .as_array()
            .map(Vec::len),
        answer(&replay_answers, 4)["result"]["items"]
            .as_array()
            .map(Vec::len),
        "support preview/export/replay publish nothing"
    );
    assert_eq!(
        answer(&replay_answers, 5)["result"]["totals"]["settled_count"],
        0
    );
    assert_eq!(
        answer(&replay_answers, 5)["result"]["totals"]["dispatched_count"],
        0
    );
    println!(
        "support replacements: {}; zero events, zero settlements, zero external effects",
        expected_replacements
    );
}

/// The packaged artifact serves all five recorded search profiles through the
/// typed `docs.search` entry: with each `search.<service>` connection declared
/// against a loopback endpoint and no credential material enrolled, every call
/// answers `missing_credential` before any socket is opened, and `docs.status`
/// remains the pure projection. The successful AUTH/RESULT/RECOVERY paths run
/// offline in `tests/search_services.rs`; real keys stay NOT_RUN.
#[test]
fn packaged_docs_search_binds_five_profiles_and_keeps_docs_status_pure() {
    let root =
        tempfile::TempDir::with_prefix("rivect-installed-docs-search-").expect("fixture root");
    let bundle = support::release::baseline_bundle();
    assert!(
        !bundle.starts_with(env!("CARGO_MANIFEST_DIR")),
        "the bundle is outside the checkout: {}",
        bundle.display()
    );
    let data = root.path().join("data root");
    let cwd = root.path().join("nested working dir");
    std::fs::create_dir_all(&data).expect("data root");
    std::fs::create_dir_all(&cwd).expect("nested cwd");
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind docs peer");
    let endpoint = format!(
        "http://{}",
        listener.local_addr().expect("docs peer address")
    );
    let mut document = support::base_config();
    for service in SEARCH_SERVICES {
        document.push_str(&format!(
            "[connections.\"search.{service}\"]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"keyring:search/{service}\"\n"
        ));
    }
    std::fs::write(data.join("config.toml"), document).expect("packaged config");
    let data_argument = data.to_str().expect("utf-8 data root");

    let first = run_packaged_frames(
        bundle,
        &cwd,
        &["--headless", "--data-root", data_argument],
        &[command_frame(
            1,
            "session.attach",
            json!({"schema_version": 1, "bootstrap_id": "installed-docs-search"}),
        )],
    );
    assert!(
        first.status.success(),
        "the packaged artifact runs: {}",
        support::release::stderr_of(&first)
    );
    let session = answer(&responses(&first), 1)["result"]["session_id"].clone();

    let mut frames = Vec::with_capacity(7);
    for (index, service) in SEARCH_SERVICES.iter().enumerate() {
        frames.push(session_frame(
            index as u64 + 2,
            &session,
            "docs.search",
            json!({"service": service, "query": format!("installed {service}"), "limit": 1}),
        ));
    }
    frames.push(local_command(7, &session, "docs.status", json!({})));
    let output = run_packaged_frames(
        bundle,
        &cwd,
        &["--headless", "--data-root", data_argument],
        &frames,
    );
    assert_eq!(
        output.status.code(),
        Some(3),
        "the typed capability denial is the run's exit class: {}",
        support::release::stderr_of(&output)
    );
    let answers = responses(&output);
    assert_eq!(answers.len(), frames.len(), "one answer per frame");
    for (index, service) in SEARCH_SERVICES.iter().enumerate() {
        let response = answer(&answers, index as u64 + 2);
        let error = response
            .get("error")
            .unwrap_or_else(|| panic!("{service} answered a result without a key: {response}"));
        assert_eq!(
            error["data"]["code"], "capability_unavailable",
            "a missing search key is a typed capability denial: {response}"
        );
        assert!(
            error["data"]["message"].as_str().is_some_and(
                |message| message.contains(&format!("search credential for {service}"))
            ),
            "{response}"
        );
        assert!(response.get("result").is_none(), "{response}");
        println!("ROW TP-SEARCH-{service}-INSTALLED ok");
    }
    let status = &answer(&answers, 7)["result"];
    assert_eq!(status, &json!(rivect::docs::status()), "{status}");
    assert_eq!(status["kind"], "docs.status", "{status}");
    assert_eq!(
        status["source_classes"],
        json!(["direct_local"]),
        "{status}"
    );
    assert_eq!(status["quota"], "unknown", "{status}");
    assert!(status.get("answer").is_none(), "{status}");

    listener
        .set_nonblocking(true)
        .expect("nonblocking packaged docs accept");
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("a missing credential still opened a transport"),
        Err(error) => panic!("packaged docs accept failed: {error}"),
    }
}

/// One loopback Chat Completions peer for the installed ordinary request:
/// every POST is counted and answered with one streamed `read_file` call.
struct OrdinaryPeer {
    endpoint: String,
    address: std::net::SocketAddr,
    requests: std::sync::Arc<std::sync::atomic::AtomicU64>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl OrdinaryPeer {
    fn start(read_path: &'static str) -> Self {
        let listener =
            std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind the ordinary peer");
        let address = listener.local_addr().expect("peer address");
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_requests = requests.clone();
        let thread_stop = stop.clone();
        let handle = std::thread::spawn(move || {
            loop {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                if thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                let Some((method, target, _body)) = read_http(&mut stream) else {
                    continue;
                };
                if method == "POST" && target.starts_with("/v1/chat/completions") {
                    thread_requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let body = chat_stream(read_path);
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let written = stream
                        .write_all(head.as_bytes())
                        .and_then(|()| stream.write_all(body.as_bytes()))
                        .and_then(|()| stream.flush());
                    drop(written);
                } else {
                    let body = json!({"object": "list", "data": []}).to_string();
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let written = stream
                        .write_all(head.as_bytes())
                        .and_then(|()| stream.write_all(body.as_bytes()))
                        .and_then(|()| stream.flush());
                    drop(written);
                }
            }
        });
        Self {
            endpoint: format!("http://{address}/v1"),
            address,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    fn requests(&self) -> u64 {
        self.requests.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for OrdinaryPeer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Ok(stream) = std::net::TcpStream::connect(self.address) {
            drop(stream);
        }
        if let Some(handle) = self.handle.take() {
            let joined = handle.join();
            drop(joined);
        }
    }
}

fn read_http(stream: &mut std::net::TcpStream) -> Option<(String, String, Vec<u8>)> {
    let reader = stream.try_clone().ok()?;
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        if header.trim_end().is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().ok()?;
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).ok()?;
    Some((method, target, body))
}

fn chat_stream(read_path: &str) -> String {
    let arguments = serde_json::to_string(&json!({"path": read_path})).expect("tool arguments");
    let call = json!({
        "index": 0,
        "id": "call-installed",
        "type": "function",
        "function": {"name": "read_file", "arguments": arguments},
    });
    let delta = json!({
        "id": "c1",
        "object": "chat.completion.chunk",
        "choices": [{"index": 0, "delta": {"role": "assistant", "tool_calls": [call]}, "finish_reason": null}],
    });
    let finish = json!({
        "id": "c1",
        "object": "chat.completion.chunk",
        "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
    });
    let usage = json!({
        "id": "c1",
        "choices": [],
        "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},
    });
    format!("data: {delta}\n\ndata: {finish}\n\ndata: {usage}\n\ndata: [DONE]\n\n")
}

fn installed_chat_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.vllm]\nkind = \"local\"\nendpoint = \"{endpoint}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"vllm\", model_id = \"fixture-chat-model\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn ordinary_receipt_path() -> PathBuf {
    std::env::var_os("RIVECT_INSTALLED_ORDINARY_RECEIPT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("installed-ordinary.json")
        })
}

/// Invalidates the retained installed-ordinary receipt before the proof runs,
/// so a failed run cannot leave an earlier candidate's PASS on disk.
fn invalidate_ordinary_receipt() {
    let path = ordinary_receipt_path();
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("invalidate ordinary receipt: {error}"),
    }
}

fn write_ordinary_receipt(candidate: &str) {
    let path = ordinary_receipt_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("receipt parent");
    }
    let receipt = json!({
        "schema_version": 1,
        "status": "pass",
        "candidate_manifest_sha256": candidate,
        "sends": 1,
        "settlements": 1,
    });
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&receipt).expect("receipt bytes"),
    )
    .expect("write the ordinary receipt");
}

/// The packaged artifact runs one ordinary first task from the TUI composer:
/// the create publishes the start question, its card opens, and `begin`
/// drains the configured local provider to one verified outcome and one
/// settlement.
#[test]
fn installed_ordinary_request_completes_with_one_settlement() {
    invalidate_ordinary_receipt();
    let peer = OrdinaryPeer::start("AGENTS.md");
    let root = tempfile::TempDir::with_prefix("rivect-installed-ordinary-").expect("fixture root");
    let bundle = support::release::baseline_bundle();
    assert!(
        !bundle.starts_with(env!("CARGO_MANIFEST_DIR")),
        "the ordinary request runs on the bundle outside the checkout: {}",
        bundle.display()
    );
    let activation = verify_release_bundle(bundle).expect("the packaged artifact activates");
    let candidate = activation.manifest_sha256.clone();
    assert_eq!(
        candidate,
        support::release::sha256_file(&bundle.join(RELEASE_MANIFEST_NAME)),
        "the receipt candidate is the manifest bytes on disk"
    );
    let data = root.path().join("data root");
    let cwd = root.path().join("nested working dir").join("юникод cwd");
    std::fs::create_dir_all(&data).expect("data root");
    std::fs::create_dir_all(&cwd).expect("nested cwd");
    std::fs::write(cwd.join("AGENTS.md"), "installed instructions\n").expect("instruction");
    std::fs::write(
        data.join("config.toml"),
        installed_chat_config(&peer.endpoint),
    )
    .expect("config write");

    let mut command = support::pty_command(bundle.join("rivect"));
    command.arg("--data-root");
    command.arg(&data);
    command.cwd(&cwd);
    let mut pty = support::PtySession::spawn(command, 24, 80, root, data.clone())
        .expect("spawn the packaged TUI");
    assert!(
        pty.wait_for(b"\x1b[?1049h", Duration::from_secs(10))
            .expect("pty read"),
        "the packaged TUI enters the alternate screen"
    );
    pty.send("run the installed task\r".as_bytes())
        .expect("pty send");
    let _card =
        support::wait_for_screen_text(&pty, 24, 80, "awaiting decision", Duration::from_secs(10))
            .expect("start card");
    std::thread::sleep(Duration::from_millis(300));
    pty.send(b"\r").expect("pty send enter");
    let _answered = support::wait_for_screen_text(
        &pty,
        24,
        80,
        "decision answer recorded; task resumed",
        Duration::from_secs(10),
    )
    .expect("answer note");
    let _completed =
        support::wait_for_screen_text(&pty, 24, 80, "completed", Duration::from_secs(10))
            .expect("completed dock");
    pty.send(b"\x1b").expect("pty send exit");
    assert_eq!(
        pty.wait_exit(Duration::from_secs(10)).expect("pty wait"),
        Some(0)
    );
    let db = data.join("runtime").join("rivect.db");
    let conn = rusqlite::Connection::open(&db).expect("open the installed store");
    let settlements: i64 = conn
        .query_row("SELECT COUNT(*) FROM usage_settlements", [], |row| {
            row.get(0)
        })
        .expect("count settlements");
    assert_eq!(settlements, 1);
    assert_eq!(peer.requests(), 1, "one configured-model send");

    let data_argument = data.to_str().expect("utf-8 data root");
    let usage_run = run_packaged_frames(
        bundle,
        &cwd,
        &["--headless", "--data-root", data_argument],
        &[
            command_frame(
                1,
                "session.attach",
                json!({"schema_version": 1, "bootstrap_id": "installed-ordinary-usage"}),
            ),
            local_command(
                2,
                &json!("installed-ordinary-usage"),
                "usage.view",
                json!({}),
            ),
        ],
    );
    assert!(
        usage_run.status.success(),
        "the packaged usage.view answered: {}",
        support::release::stderr_of(&usage_run)
    );
    let usage_answers = responses(&usage_run);
    assert_eq!(
        answer(&usage_answers, 2)["result"]["totals"]["settled_count"],
        1,
        "the packaged usage.view counts the one settlement"
    );

    pty.finish().expect("pty teardown");
    write_ordinary_receipt(&candidate);
    println!("installed ordinary: completed; sends=1 settlements=1");
}
