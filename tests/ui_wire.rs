use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

#[test]
fn private_pipe_projects_submit_and_attach_without_granting_human_authority() {
    let home = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rivect"))
        .arg("--ui-wire-v1")
        .env_clear()
        .env("HOME", home.path())
        .current_dir(home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut call = |method: &str, params: Value| {
        let frame = json!({"jsonrpc":"2.0", "id":1, "method":method,"params":params});
        writeln!(input, "{frame}").unwrap();
        let mut line = String::new();
        assert!(
            output.read_line(&mut line).unwrap() > 0,
            "private core closed before replying to {method}"
        );
        serde_json::from_str::<Value>(&line).unwrap()
    };
    let opened = call(
        "session.open",
        json!({"schema_version":1,"bootstrap_id":"ui-open"}),
    );
    let session = opened["result"]["session_id"].as_str().unwrap();
    let created = call(
        "task.submit",
        json!({"schema_version":1,"session_id":session,
        "command_id":"75f194af-cd1c-495a-95b6-547fcc88cfae","kind":"create","goal":"private goal",
        "contract":{"criteria":[],"constraints":[]},"first_question":true}),
    );
    let snapshot = &created["result"]["snapshot"];
    assert_eq!(snapshot["kind"], "snapshot");
    assert_eq!(snapshot["session_id"], session);
    assert_eq!(snapshot["lifecycle"], "waiting");
    assert_eq!(snapshot["origin"], "machine");
    assert!(
        snapshot["revision"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > 0
    );
    assert!(
        snapshot["event_cursor"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > 0
    );
    let refused = call(
        "task.submit",
        json!({"schema_version":1,"session_id":session,
        "task_id":snapshot["task_id"],"command_id":"ae77fd93-03e6-40e4-a48b-d79690c7ca70",
        "kind":"approve","origin":"human"}),
    );
    assert_eq!(refused["error"]["code"], "denied");
    let wrong_version = call(
        "session.open",
        json!({"schema_version":2,"bootstrap_id":"not-opened"}),
    );
    assert_eq!(wrong_version["error"]["code"], "unsupported_version");
    let other = call(
        "session.open",
        json!({"schema_version":1,"bootstrap_id":"other"}),
    );
    let cross_session = call(
        "task.snapshot",
        json!({"schema_version":1,"session_id":other["result"]["session_id"],"task_id":snapshot["task_id"]}),
    );
    assert_eq!(cross_session["error"]["code"], "not_found");
    let foreign_child = call(
        "task.submit",
        json!({"schema_version":1,"session_id":other["result"]["session_id"],
        "parent_task_id":snapshot["task_id"],"command_id":"7a68a16c-c18c-43cf-b130-63ba88d17255",
        "kind":"create","goal":"foreign lineage","contract":{"criteria":[],"constraints":[]}}),
    );
    assert_eq!(foreign_child["error"]["code"], "denied");
    let attached = call(
        "session.attach",
        json!({"schema_version":1,"session_id":session,"bootstrap_id":"ui-attach"}),
    );
    assert_eq!(attached["result"]["tasks"], json!([snapshot]));
    assert_eq!(attached["result"]["more"], false);
    let retained = call(
        "task.message",
        json!({"schema_version":1,"session_id":session,"command_id":"unconfigured","goal":"keep this goal"}),
    );
    let retained = &retained["result"]["snapshot"];
    assert_eq!(retained["goal"], "keep this goal");
    assert_eq!(retained["lifecycle"], "waiting");
    assert!(retained.get("reply").is_none());
    drop(input);
    assert!(child.wait().unwrap().success());
}

#[test]
fn older_tasks_resume_from_session_bound_keyset() {
    let home = tempfile::tempdir().unwrap();
    let mut child = private_child(home.path()).unwrap();
    let mut call = |method, params| request(&mut child, method, params).unwrap();
    let opened = call("session.open", json!({"bootstrap_id":"history"}));
    let session = &opened["result"]["session_id"];
    for n in 0..22 {
        let receipt = call(
            "task.message",
            json!({"session_id":session,"command_id":format!("history-{n}"),"goal":format!("turn {n}")}),
        );
        assert_eq!(receipt["result"]["status"], "accepted", "{receipt}");
    }
    let page = call(
        "session.attach",
        json!({"session_id":session,"bootstrap_id":"restore"}),
    );
    let tasks = page["result"]["tasks"].as_array().unwrap();
    assert_eq!(tasks.len(), 20);
    assert_eq!(tasks[0]["goal"], "turn 2");
    assert_eq!(tasks[19]["goal"], "turn 21");
    assert_eq!(page["result"]["more"], true);
    let before = &tasks[0]["task_id"];
    let later = call(
        "task.message",
        json!({"session_id":session,"command_id":"after-page","goal":"later"}),
    );
    assert_eq!(later["result"]["status"], "accepted");
    let older = call(
        "session.older",
        json!({"session_id":session,"before":before}),
    );
    let tasks = older["result"]["tasks"].as_array().unwrap();
    assert_eq!(tasks.len(), 2);
    assert_eq!(tasks[0]["goal"], "turn 0");
    assert_eq!(tasks[1]["goal"], "turn 1");
    assert_eq!(older["result"]["more"], false);
    let next = call("session.open", json!({"bootstrap_id":"elsewhere"}));
    let foreign = call(
        "session.older",
        json!({"session_id":next["result"]["session_id"],"before":before}),
    );
    assert_eq!(foreign["error"]["code"], "not_found");
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
}

const LOOPBACK_CONFIG: &str = "config_version = 1\n[connections.loopback]\nkind = \"local\"\nendpoint = \"\"\n[models.defaults]\nmodel = { mode = \"fixed\", connection = \"loopback\", model_id = \"offline\" }\neffort = { mode = \"fixed\", value = \"medium\" }\nfallback = { mode = \"off\" }\n";

fn private_child(root: &std::path::Path) -> std::io::Result<std::process::Child> {
    Command::new(env!("CARGO_BIN_EXE_rivect"))
        .arg("--ui-wire-v1")
        .env_clear()
        .env("HOME", root)
        .env("RIVECT_DATA_ROOT", root)
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
}

fn request(
    child: &mut std::process::Child,
    method: &str,
    mut params: Value,
) -> std::io::Result<Value> {
    params["schema_version"] = json!(1);
    raw_request(
        child,
        json!({"jsonrpc":"2.0","method":method,"params":params,"id":1}),
    )
}

fn raw_request(child: &mut std::process::Child, frame: Value) -> std::io::Result<Value> {
    writeln!(
        child
            .stdin
            .as_mut()
            .ok_or_else(|| std::io::Error::other("missing stdin pipe"))?,
        "{frame}"
    )?;
    let mut line = String::new();
    let stdout = child
        .stdout
        .as_mut()
        .ok_or_else(|| std::io::Error::other("missing stdout pipe"))?;
    BufReader::new(stdout).read_line(&mut line)?;
    Ok(serde_json::from_str(&line)?)
}

#[test]
fn boot_reports_pending_verdict_without_echoing_invalid_config()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let target = root.path().join("config.toml");
    std::fs::write(&target, LOOPBACK_CONFIG)?;
    let runtime = root.path().join("runtime");
    std::fs::create_dir(&runtime)?;
    let mut store = rivect::state::TaskStore::open(&runtime.join("rivect.db"))?;
    let mut config = rivect::config::Config::parse_validated(LOOPBACK_CONFIG)?;
    let edit = config.set("workflow.enabled", rivect::config::ConfigValue::Bool(false))?;
    rivect::config::stage_publication(&mut store, "cli", &target, &edit)?;
    drop(store);
    let secret = "UNSAFE_CONFIG_VALUE_MUST_NOT_REACH_TERMINAL";
    std::fs::write(&target, format!("[{secret}\n"))?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_rivect"))
        .arg("--ui-wire-v1")
        .env_clear()
        .env("HOME", root.path())
        .env("RIVECT_DATA_ROOT", root.path())
        .current_dir(root.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let frame = request(&mut child, "runtime.boot", json!({}))?;
    let output = child.wait_with_output()?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(frame["id"], 1);
    assert_eq!(frame["error"]["code"], "invalid_input");
    assert_eq!(frame["error"]["cause"], "owner configuration failed");
    assert_eq!(frame["error"]["recovery"]["omitted"], 0);
    let rows = frame["error"]["recovery"]["lines"]
        .as_array()
        .ok_or("missing recovery rows")?;
    let note = rows
        .iter()
        .filter_map(Value::as_str)
        .find(|line| line.contains("publication recovery"))
        .ok_or("missing pending-publication verdict")?;
    assert!(note.contains("resolution:"));
    assert!(!frame.to_string().contains(secret));
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("publication recovery"));
    assert!(!stderr.contains(secret));
    Ok(())
}

#[test]
fn local_message_is_retained_without_repeating_dispatch() {
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("data");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("config.toml"), LOOPBACK_CONFIG).unwrap();
    let mut child = private_child(&root).unwrap();
    let mut call = |method, params| request(&mut child, method, params).unwrap();
    let opened = call("session.open", json!({"bootstrap_id":"chat"}));
    let session = &opened["result"]["session_id"];
    let message = json!({"session_id":session,"command_id":"077539ad-c48e-4ee9-bcf0-16999d060fcb","goal":"explain this"});
    let sent = call("task.message", message.clone());
    assert_eq!(sent["result"]["status"], "accepted", "{sent}");
    let task = &sent["result"]["task_id"];
    let params = json!({"session_id":session,"task_id":task});
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let reply = loop {
        let result = call("task.snapshot", params.clone());
        let frame = &result["result"]["frame"];
        assert_eq!(&frame["task_id"], task, "{result}");
        if frame["lifecycle"] != "running" {
            break frame.clone();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "message did not settle"
        );
    };
    assert_eq!(reply["goal"], "explain this");
    assert_eq!(
        reply["reply"],
        "no permitted action; waiting for a decision"
    );
    assert_eq!(reply["lifecycle"], "waiting");
    let switched = call(
        "command.execute",
        json!({"session_id":session,"command":{"kind":"session.new"}}),
    );
    let other = &switched["result"]["session_id"];
    assert!(other.is_string() && other != session);
    let mixed = call("task.snapshot", json!({"session_id":other,"task_id":task}));
    assert_eq!(mixed["error"]["code"], "not_found");
    for method in ["task.snapshot", "task.changes", "task.submit"] {
        let stale = call(
            method,
            json!({"session_id":session,"task_id":task,"after":"0","kind":"create"}),
        );
        assert_eq!(stale["error"]["code"], "denied", "{method}: {stale}");
    }
    let attached = call(
        "session.attach",
        json!({"session_id":session,"bootstrap_id":"return"}),
    );
    assert_eq!(attached["result"]["tasks"][0]["reply"], reply["reply"]);
    let replay = call("task.message", message);
    assert_eq!(&replay["result"]["task_id"], task);
    assert_eq!(replay["result"]["snapshot"]["revision"], reply["revision"]);
    child.stdin.take();
    assert!(child.wait().unwrap().success());
    let db = rusqlite::Connection::open(root.join("runtime/rivect.db")).unwrap();
    let sends: i64 = db
        .query_row("SELECT COUNT(*) FROM usage_settlements", [], |r| r.get(0))
        .unwrap();
    assert_eq!(sends, 1);
    let delta: String = db
        .query_row(
            "SELECT delta_json FROM events WHERE event_type='task.message_settled'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&delta).unwrap(),
        json!({"lifecycle":"waiting"})
    );
}

#[test]
fn interrupted_message_recovers_without_resending() -> std::io::Result<()> {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("config.toml"), LOOPBACK_CONFIG).unwrap();
    let mut child = private_child(root.path())?;
    let opened = request(
        &mut child,
        "session.open",
        json!({"bootstrap_id":"recovery"}),
    )?;
    let session = &opened["result"]["session_id"];
    assert!(child.wait().unwrap().success());
    let db = rusqlite::Connection::open(root.path().join("runtime/rivect.db")).unwrap();
    db.execute_batch("CREATE TRIGGER refuse_reply BEFORE INSERT ON ui_message_replies BEGIN SELECT RAISE(ABORT,'reply interrupted'); END;").unwrap();
    let mut child = private_child(root.path())?;
    let attach = json!({"session_id":session,"bootstrap_id":"recover"});
    assert_eq!(
        request(&mut child, "session.attach", attach.clone())?["result"]["session_id"],
        *session
    );
    let message = json!({"session_id":session,"command_id":"send-once","goal":"durable"});
    let accepted = request(&mut child, "task.message", message.clone())?;
    assert_eq!(accepted["result"]["snapshot"]["lifecycle"], "running");
    let mut eof = String::new();
    assert_eq!(
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut eof)
            .unwrap(),
        0
    );
    assert!(!child.wait().unwrap().success());
    db.execute_batch("DROP TRIGGER refuse_reply").unwrap();
    let mut recovered = private_child(root.path())?;
    let resumed = request(&mut recovered, "session.attach", attach)?;
    let frame = &resumed["result"]["tasks"][0];
    assert_eq!(frame["goal"], "durable");
    assert_eq!(frame["error_code"], "outcome_unknown");
    assert_eq!(frame["lifecycle"], "blocked");
    assert!(frame.get("reply").is_none());
    assert_eq!(
        request(&mut recovered, "task.message", message)?["result"]["snapshot"],
        *frame
    );
    assert!(recovered.wait().unwrap().success());
    let sends: i64 = db
        .query_row("SELECT COUNT(*) FROM usage_settlements", [], |r| r.get(0))
        .unwrap();
    assert_eq!(sends, 1);
    Ok(())
}

#[test]
fn wire_recovery_invalid_switch_preserves_live_send() -> std::io::Result<()> {
    let root = tempfile::tempdir()?;
    // The local listener never answers; only an admitted switch can stop this send.
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let endpoint = format!("http://{}/v1", listener.local_addr()?);
    let config = LOOPBACK_CONFIG
        .replace("loopback", "vllm")
        .replace("endpoint = \"\"", &format!("endpoint = \"{endpoint}\""))
        .replace("mode = \"fixed\", value = \"medium\"", "mode = \"auto\"");
    std::fs::write(root.path().join("config.toml"), config)?;
    let mut child = private_child(root.path())?;
    let opened = request(&mut child, "session.open", json!({"bootstrap_id":"live"}))?;
    let session = &opened["result"]["session_id"];
    let sent = request(
        &mut child,
        "task.message",
        json!({"session_id":session,"command_id":"pending","goal":"keep running"}),
    )?;
    assert_eq!(sent["result"]["snapshot"]["lifecycle"], "running", "{sent}");
    let task = &sent["result"]["task_id"];
    let action = |kind: Value| json!({"session_id":session, "action":kind});
    let inspect = json!({"kind":"settings_center", "request":{"op":"inspect"}});
    let page = request(&mut child, "operator.action", action(inspect.clone()))?;
    let key = "context.auto_compact";
    assert!(
        page["result"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["key"] == key)
    );
    let get = json!({"kind":"settings_center","request":{"op":"get","key":key}});
    assert_eq!(
        request(&mut child, "operator.action", action(get))?["result"],
        page["result"]
    );
    for denied in [
        json!({"kind":"login_cancel"}),
        json!({"kind":"settings_center", "request":{"op":"reset","scope":"user","key":key,
              "expected_source_digest":page["result"]["source_digest"]}}),
    ] {
        assert_eq!(
            request(&mut child, "operator.action", action(denied))?["error"]["code"],
            "conflict"
        );
    }
    let foreign = json!({"session_id":"another-session","action":inspect});
    assert!(request(&mut child, "operator.action", foreign)?["error"]["code"].is_string());
    let switch = json!({"jsonrpc":"2.0","id":-1,"method":"command.execute","params":{
        "schema_version":1,"session_id":session,"command":{"kind":"session.new"}}});
    let mut extra_envelope = switch.clone();
    extra_envelope["extra"] = json!(true);
    let mut extra_params = switch["params"].clone();
    extra_params["extra"] = json!(true);
    for (pointer, invalid) in [
        ("", extra_envelope),
        ("/params", extra_params),
        ("/id", Value::Null),
        ("/id", json!(true)),
        ("/id", json!(1.25)),
        ("/id", json!(u64::MAX)),
        ("/id", json!("x".repeat(257))),
        ("/jsonrpc", json!("1.0")),
        ("/params/schema_version", json!(2)),
        ("/params/session_id", json!("another-session")),
        (
            "/params/command",
            json!({"kind":"session.new","extra":true}),
        ),
    ] {
        let mut frame = switch.clone();
        *frame.pointer_mut(pointer).unwrap() = invalid;
        let refusal = raw_request(&mut child, frame)?;
        assert!(refusal["error"]["code"].is_string(), "{pointer}: {refusal}");
        let snapshot = request(
            &mut child,
            "task.snapshot",
            json!({"session_id":session,"task_id":task}),
        )?;
        assert_eq!(
            snapshot["result"]["frame"]["lifecycle"], "running",
            "{pointer}"
        );
    }
    let switched = raw_request(&mut child, switch)?;
    assert_eq!(&switched["result"]["previous_session_id"], session);
    assert_ne!(&switched["result"]["session_id"], session);
    assert!(child.wait()?.success());
    Ok(())
}

#[test]
fn wire_recovery_snapshot_failure_releases_owner_without_sending() -> std::io::Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("config.toml"), LOOPBACK_CONFIG)?;
    let mut child = private_child(root.path())?;
    let opened = request(
        &mut child,
        "session.open",
        json!({"bootstrap_id":"publish"}),
    )?;
    let session = &opened["result"]["session_id"];
    let db = rusqlite::Connection::open(root.path().join("runtime/rivect.db")).unwrap();
    // Break the projection only; task creation and its idempotency receipt still commit.
    db.execute_batch("ALTER TABLE ui_message_replies RENAME COLUMN reply TO hidden_reply")
        .unwrap();
    let message = json!({"session_id":session,"command_id":"unpublished","goal":"retain me"});
    let failed = request(&mut child, "task.message", message.clone())?;
    assert_eq!(failed["error"]["code"], "outcome_unknown", "{failed}");
    assert!(request(&mut child, "session.recent", json!({})).is_err());
    assert!(!child.wait()?.success());
    db.execute_batch("ALTER TABLE ui_message_replies RENAME COLUMN hidden_reply TO reply")
        .unwrap();
    let mut recovered = private_child(root.path())?;
    let resumed = request(
        &mut recovered,
        "session.attach",
        json!({"session_id":session,"bootstrap_id":"inspect"}),
    )?;
    let tasks = resumed["result"]["tasks"].as_array().unwrap();
    assert_eq!(tasks.len(), 1);
    let frame = &tasks[0];
    assert_eq!(frame["goal"], "retain me");
    assert_eq!(frame["lifecycle"], "blocked");
    assert_eq!(frame["error_code"], "outcome_unknown");
    assert_eq!(
        request(&mut recovered, "task.message", message)?["result"]["snapshot"],
        *frame
    );
    assert!(recovered.wait()?.success());
    let sends: i64 = db
        .query_row("SELECT COUNT(*) FROM usage_settlements", [], |r| r.get(0))
        .unwrap();
    assert_eq!(sends, 0);
    Ok(())
}
