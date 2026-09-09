//! SLICE-001 first-task proof (TP-ADMISSION-PACKET 5b + TP-PUBLIC +
//! TP-BOOT): the native dependency contract, boot confinement before any
//! dispatch, the canonical corpus through both ingresses, crash-safe
//! no-repeat semantics, and the real-PTY TUI cases.

mod support;

use rivect::commands::Ingress;
use rivect::contracts::Lifecycle;
use rivect::executor::{EffectRequest, Executor};
use rivect::resources::{Delivery, NotificationQueue};
use rivect::ui::{ApplyVerdict, Projection};
use serde_json::{Value, json};
use sha2::Digest;
use std::path::PathBuf;
use std::time::Duration;
use support::{
    World, answer_custom, corpus_answer_custom, corpus_answer_option, corpus_config_read,
    corpus_create, corpus_question_current, corpus_status, corpus_steer, open_world, rivect_binary,
    spawn_pty,
};

fn scoped_world(tag: &str, config: Option<&str>) -> (World, PathBuf, PathBuf, String) {
    let mut world = open_world(tag, config);
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-first-task-marker\n").expect("scoped file");
    world.runtime.purpose = "backend_task".to_string();
    let grant = world.runtime.set_read_scope(scope.clone(), file.clone());
    (world, scope, file, grant)
}

#[test]
fn native_dependency_contract() {
    println!("attempt: {}", rivect::BUILD_ATTEMPT_ID);
    let number = rusqlite::version_number();
    println!("linked sqlite: {} ({})", rusqlite::version(), number);
    assert!(
        number >= 3_051_003,
        "linked SQLite must be >= 3.51.3 (WAL-reset fix)"
    );
    let conn = rusqlite::Connection::open_in_memory().expect("open");
    conn.execute_batch(
        "CREATE VIRTUAL TABLE search USING fts5(path, body);
         INSERT INTO search (path, body) VALUES ('a.rs', 'first task marker');
         INSERT INTO search (path, body) VALUES ('b.rs', 'unrelated text');",
    )
    .expect("fts5 create and insert");
    let hits: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM search WHERE search MATCH 'marker'",
            [],
            |row| row.get(0),
        )
        .expect("fts5 query");
    assert_eq!(hits, 1, "FTS5 MATCH must find exactly the marked row");
}

#[test]
fn owner_elects_single_writer() {
    let mut world = open_world("owner-election", None);
    let session = world.open_session("bootstrap-owner");
    assert!(!session.0.is_empty());
    let second = rivect::owner::Owner::elect(&world.root);
    assert!(
        matches!(second, Err(rivect::owner::OwnerError::AlreadyOwned)),
        "a second writer must lose the election, not open a second DB"
    );
    world.reopen();
    // dropping the previous owner released the lock: the new election
    // succeeded (reopen would have panicked on AlreadyOwned), and the
    // reopened owner now holds it exclusively again.
    assert!(
        matches!(
            rivect::owner::Owner::elect(&world.root),
            Err(rivect::owner::OwnerError::AlreadyOwned)
        ),
        "the reopened owner must exclusively hold the election lock"
    );
}

#[test]
fn boot_confinement_before_dispatch() {
    let (mut world, _scope, file, grant) = scoped_world("boot-confinement", None);
    let session = world.open_session("bootstrap-boot");
    let task = world.create_task(&session, "cmd-boot-1");
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );

    // Positive control: one scoped existing-file read.
    let read = rivect::tools::invoke_read(&mut world.runtime, &task, &grant, file.clone())
        .expect("scoped read admitted");
    match read {
        rivect::executor::EffectOutcome::Read { bytes, .. } => {
            assert_eq!(bytes, b"rivect-first-task-marker\n");
        }
        other => panic!("scoped read must succeed, got {other:?}"),
    }

    // Out-of-scope existing file: denied before any byte is touched.
    let outside = world.root.join("outside.txt");
    std::fs::write(&outside, "secret").expect("outside file");
    let denied = rivect::tools::invoke_read(&mut world.runtime, &task, &grant, outside.clone())
        .expect_err("out-of-scope read denied");
    assert!(
        denied.to_string().contains("outside the admitted scope"),
        "{denied}"
    );

    // Write, foreign exec and direct egress are structurally rejected by the
    // read-only worker; there is no ambient fallback.
    for request in [
        EffectRequest::Write {
            grant_id: grant.clone(),
            path: file.clone(),
            bytes: b"x".to_vec(),
        },
        EffectRequest::Exec {
            grant_id: grant.clone(),
            program: PathBuf::from("/usr/bin/env"),
        },
        EffectRequest::Egress {
            grant_id: grant.clone(),
            url: "http://127.0.0.1:1/probe".to_string(),
        },
    ] {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        let admitted = executor
            .admit(&task, request)
            .expect_err("read-only worker rejects");
        assert!(
            admitted.to_string().contains("does not admit"),
            "{admitted}"
        );
    }
    // Forced-admitted write/exec/egress through Executor::execute: the
    // read-only backend rejects them unconditionally with zero observable
    // side effects, verified by file bytes, an exec marker, and a real
    // local TCP accept oracle showing zero connections.
    let exec_marker = world.root.join("exec-marker.out");
    let exec_script = world.root.join("make_marker.sh");
    std::fs::write(
        &exec_script,
        format!("#!/bin/sh\nprintf x > {}\n", exec_marker.display()),
    )
    .expect("exec oracle script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exec_script, std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("egress oracle bind");
    listener
        .set_nonblocking(true)
        .expect("egress oracle nonblocking");
    let egress_addr = listener.local_addr().expect("egress oracle addr");
    let scoped_before = std::fs::read(&file).expect("scoped bytes");
    let outside_before = std::fs::read(&outside).expect("outside bytes");
    for request in [
        EffectRequest::Write {
            grant_id: grant.clone(),
            path: file.clone(),
            bytes: b"tampered".to_vec(),
        },
        EffectRequest::Exec {
            grant_id: grant.clone(),
            program: exec_script.clone(),
        },
        EffectRequest::Egress {
            grant_id: grant.clone(),
            url: format!("http://{egress_addr}/probe"),
        },
    ] {
        let class = request.class();
        let attempt_id = world
            .runtime
            .owner
            .store
            .plan_attempt(&task, class, &request.describe())
            .expect("plan forced attempt");
        let admitted = rivect::executor::AdmittedEffect {
            task_id: task.clone(),
            attempt_id,
            request,
            scope_root: _scope.clone(),
        };
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        let denied = executor
            .execute(&admitted)
            .expect("backend denial is an Ok(Denied) outcome, not an error");
        let rivect::executor::EffectOutcome::Denied { reason } = denied else {
            panic!("non-read effect must be denied");
        };
        assert!(
            reason.contains("read-only worker rejects"),
            "expected the read-only backend rejection, got {reason}"
        );
    }
    assert_eq!(
        std::fs::read(&file).expect("scoped bytes after"),
        scoped_before,
        "in-scope bytes must be unchanged"
    );
    assert_eq!(
        std::fs::read(&outside).expect("outside bytes after"),
        outside_before,
        "out-of-scope bytes must be unchanged"
    );
    assert!(
        !exec_marker.exists(),
        "no exec child effect: marker must not exist"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(300);
    while std::time::Instant::now() < deadline {
        match listener.accept() {
            Ok((_, _)) => panic!("direct egress must never open a connection"),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => panic!("egress oracle failed: {err}"),
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no loopback connection for any denied effect"
    );
    // Revoke: the next dispatch of the same scope is denied before any
    // provider effect.
    world.runtime.policy.revoke(&grant);
    let revoked = rivect::tools::invoke_read(&mut world.runtime, &task, &grant, file.clone())
        .expect_err("revoked grant denies");
    assert!(revoked.to_string().contains("revoked"), "{revoked}");

    // Faulted profile: a subscription pin without a live grant gives zero
    // provider and zero tool effects.
    let mut faulted = open_world("boot-faulted", Some(&support::config_manual_subscription()));
    faulted.runtime.purpose = "main".to_string();
    let session2 = faulted.open_session("bootstrap-faulted");
    let task2 = faulted.create_task(&session2, "cmd-faulted-1");
    let outcome = faulted.runtime.run_decision_step(
        &session2,
        &task2,
        &answer_custom("read nothing"),
        "grant-none",
        false,
    );
    assert!(
        outcome.is_err(),
        "subscription pin without grant must not dispatch"
    );
    assert_eq!(
        faulted
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        faulted.worker_reads(),
        0,
        "zero tool effects for the faulted profile"
    );
}

#[test]
fn provider_public_ingress() {
    let (mut world, _scope, file, grant) =
        scoped_world("public-ingress", Some(&support::config_distinct_pools()));
    let session = world.open_session("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1");
    assert!(!session.0.is_empty());

    // Bootstrap/status/taskless config read: zero tasks, zero model calls.
    let status = world.dispatch(&corpus_status(&session));
    assert!(status["error"].is_null(), "{status}");
    assert_eq!(
        status["result"]["tasks"]["items"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(status["result"]["tasks"]["snapshot_generation"], 0);
    let workflow = &status["result"]["workflow"];
    assert_eq!(workflow["key"], "workflow.enabled");
    assert_eq!(workflow["effective"]["kind"], "visible");
    assert_eq!(workflow["effective"]["value"], true);
    assert_eq!(workflow["source"]["kind"], "shipped");
    let expected_shipped = support::sha256_hex(rivect::config::SHIPPED_DEFAULTS_TOML.as_bytes());
    assert_eq!(workflow["source"]["revision"], expected_shipped);

    let config_read = world.dispatch(&corpus_config_read(&session));
    assert!(config_read["error"].is_null(), "{config_read}");
    let user_bytes = std::fs::read(world.root.join("config.toml")).expect("user config");
    let mut expected_digest = sha2::Sha256::new();
    sha2::Digest::update(
        &mut expected_digest,
        rivect::config::SHIPPED_DEFAULTS_TOML.as_bytes(),
    );
    sha2::Digest::update(&mut expected_digest, &user_bytes);
    let expected_source_digest = rivect::config::hex(&sha2::Digest::finalize(expected_digest));
    assert_eq!(
        config_read["result"]["source_digest"],
        expected_source_digest
    );
    assert_eq!(
        config_read["result"]["entries"]["items"][0]["key"],
        "workflow.enabled"
    );

    // Create: accepted receipt revision 1 / running, contract and constraints.
    let create = world.dispatch(&corpus_create(
        &session,
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4",
    ));
    let result = &create["result"];
    assert!(create["error"].is_null(), "{create}");
    assert_eq!(result["status"], "accepted");
    assert_eq!(result["task_revision"], 1);
    assert_eq!(result["intent_revision"], 1);
    assert_eq!(result["event_cursor"], 1);
    assert_eq!(result["contract_revision"], 1);
    assert_eq!(result["snapshot"]["lifecycle"], "running");
    assert_eq!(
        result["snapshot"]["constraints"]["items"][0],
        "Не изменять файлы."
    );
    assert!(
        !result["snapshot"]["criteria"]["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        result["snapshot"]["obligations"]["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let task = rivect::contracts::TaskId(result["task_id"].as_str().expect("task id").to_string());

    // Replay with the same command_id: same receipt, no second task.
    let replay = world.dispatch(&corpus_create(
        &session,
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4",
    ));
    assert_eq!(replay["result"]["task_id"], result["task_id"]);
    let status = world.dispatch(&corpus_status(&session));
    assert_eq!(
        status["result"]["tasks"]["items"].as_array().map(Vec::len),
        Some(1)
    );

    // Before publish there is no pending question.
    let current = world.dispatch(&corpus_question_current(&session, &task, json!(5)));
    assert!(current["result"]["question"].is_null(), "{current}");
    assert_eq!(current["result"]["task_revision"], 1);

    // The production publish_question commit: revision 2, waiting, decision
    // blocker; intent and contract revisions unchanged.
    let question = world.publish(&session, &task);
    let current = world.dispatch(&corpus_question_current(&session, &task, json!(5)));
    let q = &current["result"]["question"];
    assert_eq!(current["result"]["task_revision"], 2);
    assert_eq!(q["question_revision"], 1);
    assert_eq!(q["prompt"], "Какую форму использовать?");
    assert_eq!(q["options"].as_array().map(Vec::len), Some(5));
    assert_eq!(q["recommended_option_id"], "brief");
    let snapshot = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 55, "method": "task.snapshot",
        "params": { "schema_version": 1, "session_id": session.0, "task_id": task.0 }
    }));
    assert_eq!(snapshot["result"]["revision"], 2);
    assert_eq!(snapshot["result"]["lifecycle"], "waiting");
    let blockers = snapshot["result"]["blockers"].as_array().expect("blockers");
    assert!(!blockers.is_empty());
    assert_eq!(blockers[0]["reason"], "dependency_blocked");
    assert_eq!(blockers[0]["condition"]["kind"], "decision");
    assert_eq!(
        blockers[0]["condition"]["question_id"],
        question.question_id.0
    );
    // The historical create receipt stays at revision 1/running.
    assert_eq!(result["snapshot"]["revision"], 1);

    // Answer via the trusted adapter: applied, one task, not completed.
    let answer = world.dispatch(&corpus_answer_option(
        &session,
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa6",
        &task,
        &question,
        "steps",
        json!(6),
    ));
    assert!(answer["error"].is_null(), "{answer}");
    assert_eq!(answer["result"]["status"], "applied");
    assert_eq!(answer["result"]["task_revision"], 3);
    let status = world.dispatch(&corpus_status(&session));
    assert_eq!(
        status["result"]["tasks"]["items"].as_array().map(Vec::len),
        Some(1)
    );
    assert_ne!(
        status["result"]["tasks"]["items"][0]["lifecycle"],
        "completed"
    );
    let (answer_json, author) = world
        .runtime
        .owner
        .store
        .answered_question(&task)
        .expect("durable answer")
        .expect("answer recorded");
    assert_eq!(author, "human");
    assert!(answer_json.contains("steps"), "{answer_json}");

    // Sequential second answer on the same question: conflict, no second
    // decision or effect.
    let second = world.dispatch(&corpus_answer_option(
        &session,
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa6b",
        &task,
        &question,
        "steps",
        json!(6),
    ));
    assert_eq!(second["error"]["data"]["code"], "conflict");

    // Steer with the actual current revisions: applied, new intent epoch.
    let stale = world.dispatch(&corpus_steer(
        &session,
        "cmd-steer-stale",
        &task,
        99,
        3,
        json!(80),
    ));
    assert_eq!(stale["error"]["data"]["code"], "stale_intent");
    let steer = world.dispatch(&corpus_steer(
        &session,
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa8",
        &task,
        1,
        3,
        json!(8),
    ));
    assert!(steer["error"].is_null(), "{steer}");
    assert_eq!(steer["result"]["intent_revision"], 2);

    // Answer origin is visible in the durable event log.
    let events = world
        .runtime
        .owner
        .store
        .events_after(&session, Some(&task), 0, 50)
        .expect("events");
    let answered = events
        .iter()
        .find(|e| e.event_type == "question.answered")
        .expect("answered event");
    assert_eq!(answered.origin, "human");

    // Negative controls: machine spoof, unknown kind, foreign version.
    let machine = world.dispatch_machine(&corpus_answer_option(
        &session,
        "cmd-machine-1",
        &task,
        &question,
        "steps",
        json!(9),
    ));
    assert_eq!(machine["error"]["data"]["code"], "denied");

    let unknown_kind = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 10, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-uk-1", "session_id": session.0, "kind": "mutate", "task_id": task.0 }
    }));
    assert_eq!(unknown_kind["error"]["data"]["code"], "invalid_input");

    let bad_version = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 11, "method": "task.submit",
        "params": { "schema_version": 2, "command_id": "cmd-bv-1", "session_id": session.0, "kind": "create", "goal": "x", "contract": { "criteria": [], "constraints": [] } }
    }));
    assert_eq!(bad_version["error"]["data"]["code"], "unsupported_version");

    let unknown_method = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 12, "method": "runtime.event",
        "params": { "schema_version": 1, "session_id": session.0 }
    }));
    assert_eq!(unknown_method["error"]["code"], -32601);
    assert_eq!(unknown_method["error"]["data"]["code"], "unknown_method");

    // Disabled option and custom+option together are invalid_input.
    let fresh_task = world.create_task(&session, "cmd-fresh-1");
    let fresh_q = world.publish(&session, &fresh_task);
    let disabled = world.dispatch(&corpus_answer_option(
        &session,
        "cmd-dis-1",
        &fresh_task,
        &fresh_q,
        "diagram",
        json!(13),
    ));
    assert_eq!(disabled["error"]["data"]["code"], "invalid_input");
    let both = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 14, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": "cmd-both-1", "session_id": session.0,
            "kind": "answer", "task_id": fresh_task.0,
            "expected_intent_revision": 1, "question_id": fresh_q.question_id.0, "question_revision": 1,
            "selection": { "kind": "option", "option_id": "brief", "text": "оба поля" }
        }
    }));
    assert_eq!(both["error"]["data"]["code"], "invalid_input");
    // The pending question survives the rejected answers.
    let still = world.dispatch(&corpus_question_current(&session, &fresh_task, json!(15)));
    assert!(!still["result"]["question"].is_null());

    // Custom branch preserves exact multi-line bytes.
    let custom = world.dispatch(&corpus_answer_custom(
        &session,
        "cmd-custom-1",
        &fresh_task,
        &fresh_q,
        "Кратко объяснить.\nЗатем привести пример.",
        json!(7),
    ));
    assert!(custom["error"].is_null(), "{custom}");
    let (custom_json, _) = world
        .runtime
        .owner
        .store
        .answered_question(&fresh_task)
        .expect("durable custom answer")
        .expect("recorded");
    assert!(
        custom_json.contains("Кратко объяснить.\\nЗатем привести пример."),
        "{custom_json}"
    );

    // The local loopback useful path: one provider call, one scoped read,
    // evidence and completion, all offline.
    let outcome = world.runtime.run_decision_step(
        &session,
        &fresh_task,
        &answer_custom(&format!("read {}", file.display())),
        &grant,
        false,
    );
    match outcome.expect("decision step") {
        rivect::controller::StepOutcome::Completed { snapshot } => {
            assert_eq!(snapshot.lifecycle, Lifecycle::Completed);
        }
        other => panic!("expected completion, got {other:?}"),
    }
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[test]
fn consumer_public_ingress() {
    let (mut world, _scope, _file, _grant) =
        scoped_world("consumer-ingress", Some(&support::config_distinct_pools()));
    let session = world.open_session("bootstrap-consumer");
    let task = world.create_task(&session, "cmd-consumer-1");
    let question = world.publish(&session, &task);

    // task.collection from the same scoped snapshot; stale cursor conflicts.
    let collection = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 20, "method": "task.collection",
        "params": { "schema_version": 1, "session_id": session.0, "task_id": task.0, "collection": "constraints", "page": { "page_size": 20 } }
    }));
    assert!(collection["error"].is_null(), "{collection}");
    assert_eq!(collection["result"]["items"][0], "Не изменять файлы.");
    assert_eq!(collection["result"]["snapshot_generation"], 2);
    let stale = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 21, "method": "task.collection",
        "params": { "schema_version": 1, "session_id": session.0, "task_id": task.0, "collection": "constraints", "page": { "page_size": 20, "cursor": "gen:999" } }
    }));
    assert_eq!(stale["error"]["data"]["code"], "conflict");

    // Durable replay is stable and ordered; the same read returns the same
    // event ids.
    let first = world
        .runtime
        .owner
        .store
        .events_after(&session, Some(&task), 0, 50)
        .expect("events");
    assert!(!first.is_empty());
    let again = world
        .runtime
        .owner
        .store
        .events_after(&session, Some(&task), 0, 50)
        .expect("events");
    assert_eq!(first.len(), again.len());
    for (a, b) in first.iter().zip(again.iter()) {
        assert_eq!(a.event_id, b.event_id);
        assert_eq!(a.cursor, b.cursor);
    }

    // Consumer projection: apply only last+1; duplicates ignored; gaps and
    // permutations force a resync, never a skip-through.
    let mut projection = Projection::new(0);
    assert_eq!(projection.apply(&first[0]), ApplyVerdict::Applied);
    assert_eq!(projection.apply(&first[0]), ApplyVerdict::Duplicate);
    if first.len() >= 2 {
        assert_eq!(projection.apply(&first[1]), ApplyVerdict::Applied);
    }
    let gap = support::event_for_test(99, projection.last_revision + 5);
    assert_eq!(projection.apply(&gap), ApplyVerdict::Resync);
    let old = support::event_for_test(1, 1);
    assert_eq!(projection.apply(&old), ApplyVerdict::Duplicate);

    // Client-origin notifications are never commands.
    let spoof = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 22, "method": "runtime.resync",
        "params": { "schema_version": 1, "session_id": session.0 }
    }));
    assert_eq!(spoof["error"]["code"], -32601);

    // Known-but-unavailable command kinds never fake success.
    let unavailable = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 23, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0, "command": { "kind": "project.init", "root": "/tmp" } }
    }));
    assert_eq!(
        unavailable["error"]["data"]["code"],
        "capability_unavailable"
    );
    let describe = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 24, "method": "command.describe",
        "params": { "schema_version": 1, "session_id": session.0, "page": { "page_size": 50 } }
    }));
    let items = describe["result"]["items"].as_array().expect("catalog");
    assert!(
        items
            .iter()
            .any(|d| d["canonical_id"] == "read_file" && d["available"] == true)
    );
    assert!(
        items
            .iter()
            .any(|d| d["canonical_id"] == "project.init" && d["available"] == false)
    );

    let _ = question;
}

#[test]
fn crash_restart_no_repeat_effect() {
    let (mut world, _scope, file, grant) =
        scoped_world("crash-restart", Some(&support::config_distinct_pools()));
    let session = world.open_session("bootstrap-crash");
    // Two criteria: the reconciled evidence must satisfy every obligation.
    let create = json!({
        "jsonrpc": "2.0", "id": 29, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-crash-1", "session_id": session.0,
                    "kind": "create", "goal": "Две проверки по одному чтению.",
                    "contract": { "criteria": ["Первая проверка.", "Вторая проверка."], "constraints": [] } }
    });
    let response = world.dispatch(&create.to_string());
    let task = rivect::contracts::TaskId(
        response["result"]["task_id"]
            .as_str()
            .expect("task")
            .to_string(),
    );
    let question = world.publish(&session, &task);
    let answer = world.dispatch(&corpus_answer_custom(
        &session,
        "cmd-crash-answer",
        &task,
        &question,
        &format!("read {}", file.display()),
        json!(30),
    ));
    assert!(answer["error"].is_null(), "{answer}");

    // EDGE-003: dispatch happened, the real worker read happened once, the
    // receipt was lost. The old attempt stays unknown and the task blocks.
    let outcome = world
        .runtime
        .run_decision_step(
            &session,
            &task,
            &answer_custom(&format!("read {}", file.display())),
            &grant,
            true,
        )
        .expect("crash step");
    let rivect::controller::StepOutcome::OutcomeUnknown {
        attempt_id,
        snapshot,
    } = outcome
    else {
        panic!("expected unknown outcome");
    };
    assert_eq!(snapshot.lifecycle, Lifecycle::Blocked);
    assert!(
        snapshot
            .blockers
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .any(|b| b.reason == rivect::contracts::ErrorCode::OutcomeUnknown)
    );
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        world.worker_reads(),
        1,
        "the crash path performs exactly one real worker read"
    );
    // No-repeat guard: a duplicate decision attempt on the blocked task
    // produces no provider call and no worker read.
    let duplicate = world
        .runtime
        .run_decision_step(
            &session,
            &task,
            &answer_custom(&format!("read {}", file.display())),
            &grant,
            false,
        )
        .expect("duplicate step resolves");
    assert!(
        matches!(
            duplicate,
            rivect::controller::StepOutcome::OutcomeUnknown { .. }
        ),
        "a task with an unresolved attempt must return the existing unknown, got {duplicate:?}"
    );
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the duplicate decision attempt must not dispatch"
    );
    assert_eq!(
        world.worker_reads(),
        1,
        "the duplicate attempt must not read"
    );

    // Restart: same owner data root, new election, counters preserved.
    world.reopen();
    let grant = world.runtime.set_read_scope(_scope.clone(), file.clone());
    let snapshot = world
        .runtime
        .owner
        .store
        .snapshot(&task)
        .expect("snapshot after restart");
    assert_eq!(
        snapshot.lifecycle,
        Lifecycle::Blocked,
        "blocked state persisted across restart"
    );
    assert_eq!(
        world
            .runtime
            .owner
            .store
            .attempt_state(&attempt_id)
            .expect("state"),
        Some("unknown".to_string())
    );
    assert_eq!(world.worker_reads(), 1, "the restart replays no effect");

    // Reconcile validation: nonexistent, cross-task, and repeated reconcile
    // all fail closed.
    let bogus = world
        .runtime
        .reconcile_unknown(&session, &task, "attempt-does-not-exist", true);
    assert!(bogus.is_err(), "a nonexistent attempt id must fail closed");
    let other_task = world.create_task(&session, "cmd-crash-cross");
    let cross = world
        .runtime
        .reconcile_unknown(&session, &other_task, &attempt_id, true);
    assert!(cross.is_err(), "a cross-task attempt id must fail closed");

    // Safe reconciliation from the durable marker: the read really happened,
    // so the attempt confirms without a second worker read, every obligation
    // completes on the real digest, and executed=false cannot reject a
    // proven read.
    let before_reads = world.worker_reads();
    let after_reconcile = world
        .runtime
        .reconcile_unknown(&session, &task, &attempt_id, false)
        .expect("reconcile");
    assert_eq!(after_reconcile.lifecycle, Lifecycle::Completed);
    assert_eq!(
        world.worker_reads(),
        before_reads,
        "reconciliation re-reads nothing"
    );
    assert_eq!(
        world
            .runtime
            .owner
            .store
            .attempt_state(&attempt_id)
            .ok()
            .flatten(),
        Some("confirmed".to_string()),
        "executed=false must not reject a marker that proves execution"
    );
    let snapshot = world
        .runtime
        .owner
        .store
        .snapshot(&task)
        .expect("snapshot after reconcile");
    assert!(
        snapshot
            .obligations
            .items
            .iter()
            .all(|o| { o.execution == rivect::contracts::ObligationExecution::Satisfied }),
        "every obligation must be satisfied by the reconciled evidence"
    );
    let retained = world
        .runtime
        .owner
        .store
        .retained(&rivect::verification::boundary_id(&attempt_id))
        .expect("retained")
        .expect("retained record exists");
    let parsed_retained: rivect::verification::RetainedAttempt =
        serde_json::from_str(&retained).expect("retained record parses");
    let expected_file_digest =
        support::sha256_hex(&std::fs::read(&file).expect("read scoped file"));
    assert_eq!(
        parsed_retained.digest, expected_file_digest,
        "the retained digest must be the real file digest"
    );
    assert_eq!(
        rivect::verification::RetainedStage::Terminal,
        parsed_retained.stage,
        "the retained record must be terminal-synced"
    );
    // The worker-reported digest must agree with the independent file digest.
    let real_digest = world.last_read_digest().expect("digest of the real read");
    assert_eq!(
        real_digest, expected_file_digest,
        "worker digest must equal the independent file digest"
    );
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "reconcile never dispatches on the reopened runtime"
    );
    // A repeated reconcile of the settled attempt fails closed.
    let repeated = world
        .runtime
        .reconcile_unknown(&session, &task, &attempt_id, true);
    assert!(
        repeated.is_err(),
        "a settled attempt cannot reconcile twice"
    );

    // EDGE-002: duplicate and permuted events after the durable commit never
    // produce a second effect or a torn snapshot.
    let events = world
        .runtime
        .owner
        .store
        .events_after(&session, Some(&task), 0, 100)
        .expect("events");
    let mut projection = Projection::new(0);
    for event in events.iter() {
        projection.apply(event);
    }
    let mut duplicated = events.clone();
    duplicated.extend(events.clone());
    let mut permuted = events.clone();
    if permuted.len() >= 2 {
        permuted.swap(0, 1);
    }
    let mut replay_projection = Projection::new(0);
    for event in duplicated.iter().chain(permuted.iter()) {
        replay_projection.apply(event);
    }
    assert_eq!(
        replay_projection.last_revision, projection.last_revision,
        "replay must not advance the aggregate"
    );
    assert_eq!(world.worker_reads(), 1, "event replay re-reads nothing");

    // A fresh separately requested identical action is a new task and a new
    // attempt: exactly one more worker read and one more dispatch.
    let task2 = world.create_task(&session, "cmd-crash-2");
    let question2 = world.publish(&session, &task2);
    let answer2 = world.dispatch(&corpus_answer_custom(
        &session,
        "cmd-crash-answer-2",
        &task2,
        &question2,
        &format!("read {}", file.display()),
        json!(31),
    ));
    assert!(answer2["error"].is_null(), "{answer2}");
    let outcome = world
        .runtime
        .run_decision_step(
            &session,
            &task2,
            &answer_custom(&format!("read {}", file.display())),
            &grant,
            false,
        )
        .expect("fresh re-request step");
    let rivect::controller::StepOutcome::Completed { snapshot } = outcome else {
        panic!("expected completion after the fresh re-request");
    };
    assert_eq!(snapshot.lifecycle, Lifecycle::Completed);
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the fresh re-request dispatches exactly once on the new runtime"
    );
    assert_eq!(
        world.worker_reads(),
        2,
        "exactly two worker reads total: crash plus fresh re-request"
    );
}

#[test]
fn revoke_and_cancel_block_dispatch() {
    let (mut world, _scope, file, grant) =
        scoped_world("revoke-cancel", Some(&support::config_distinct_pools()));
    let session = world.open_session("bootstrap-revoke");
    let task = world.create_task(&session, "cmd-revoke-1");
    let question = world.publish(&session, &task);
    let answer = world.dispatch(&corpus_answer_custom(
        &session,
        "cmd-revoke-answer",
        &task,
        &question,
        &format!("read {}", file.display()),
        json!(40),
    ));
    assert!(answer["error"].is_null(), "{answer}");

    // Cancel blocks the next dispatch before the provider effect.
    let cancel = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 41, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-cancel-1", "session_id": session.0,
                    "kind": "cancel", "task_id": task.0, "expected_intent_revision": 1, "reason": "стоп" }
    }));
    assert!(cancel["error"].is_null(), "{cancel}");
    assert_eq!(cancel["result"]["status"], "applied");
    let outcome = world
        .runtime
        .run_decision_step(
            &session,
            &task,
            &answer_custom(&format!("read {}", file.display())),
            &grant,
            false,
        )
        .expect("cancelled step");
    match outcome {
        rivect::controller::StepOutcome::NoAction { snapshot } => {
            assert_eq!(snapshot.lifecycle, Lifecycle::Cancelled);
        }
        other => panic!("cancelled task must not dispatch, got {other:?}"),
    }
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );

    // Revoke blocks the next dispatch of a live task.
    let task2 = world.create_task(&session, "cmd-revoke-2");
    let question2 = world.publish(&session, &task2);
    let answer2 = world.dispatch(&corpus_answer_custom(
        &session,
        "cmd-revoke-answer-2",
        &task2,
        &question2,
        &format!("read {}", file.display()),
        json!(42),
    ));
    assert!(answer2["error"].is_null(), "{answer2}");
    world.runtime.policy.revoke(&grant);
    let err = world
        .runtime
        .run_decision_step(
            &session,
            &task2,
            &answer_custom(&format!("read {}", file.display())),
            &grant,
            false,
        )
        .expect_err("revoked scope denies dispatch");
    assert!(err.to_string().contains("revoked"), "{err}");
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        world.worker_reads(),
        0,
        "revoked scope produces zero worker reads"
    );

    // Replay of a stale cancel on the terminal task: already_terminal ack.
    let terminal_cancel = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 43, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-cancel-2", "session_id": session.0,
                    "kind": "cancel", "task_id": task.0, "expected_intent_revision": 1 }
    }));
    assert_eq!(terminal_cancel["result"]["status"], "already_terminal");
    // A stale-intent cancel on a terminal task is still stale_intent.
    let stale_cancel = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 44, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-cancel-3", "session_id": session.0,
                    "kind": "cancel", "task_id": task.0, "expected_intent_revision": 99 }
    }));
    assert_eq!(stale_cancel["error"]["data"]["code"], "stale_intent");
}

#[test]
fn slow_reader_overflow_resync() {
    let mut queue = NotificationQueue::new(8);
    for i in 0..12u64 {
        queue.push(support::event_for_test(i, i + 1));
    }
    let drained = queue.drain(100);
    assert!(
        matches!(drained[0], Delivery::ResyncMarker),
        "overflow must yield one resync marker first"
    );
    let events = drained[1..]
        .iter()
        .filter(|d| matches!(d, Delivery::Event(_)))
        .count();
    assert_eq!(
        events, 4,
        "only post-overflow events are delivered, the backlog is dropped"
    );
    for i in 12..24u64 {
        queue.push(support::event_for_test(i, i + 1));
    }
    let drained = queue.drain(100);
    assert!(matches!(drained[0], Delivery::ResyncMarker));
    // The consumer recovers by re-reading from the snapshot, never by
    // applying live hints as a continuous journal.
    let (mut world, _scope, _file, _grant) = scoped_world("slow-reader", None);
    let session = world.open_session("bootstrap-slow");
    let task = world.create_task(&session, "cmd-slow-1");
    let _ = world.publish(&session, &task);
    let events = world
        .runtime
        .owner
        .store
        .events_after(&session, Some(&task), 0, 100)
        .expect("events");
    let mut projection = Projection::new(0);
    for event in &events {
        projection.apply(event);
    }
    assert!(
        projection.last_revision >= 2,
        "recovery replays the full aggregate"
    );
}

#[test]
fn request_limits_and_manifest_immutability() {
    let (mut world, _scope, file, _grant) =
        scoped_world("limits", Some(&support::config_distinct_pools()));
    let session = world.open_session("bootstrap-limits");

    // Oversized goal text is rejected before any dispatch.
    let oversized = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 50, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-big-1", "session_id": session.0,
                    "kind": "create", "goal": "x".repeat(rivect::contracts::TEXT_MAX_BYTES + 1),
                    "contract": { "criteria": ["c"], "constraints": [] } }
    }));
    assert_eq!(oversized["error"]["data"]["code"], "invalid_input");

    // Oversized request frame is rejected at the boundary.
    let huge = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":51,\"method\":\"config.read\",\"params\":{{\"schema_version\":1,\"session_id\":\"{}\",\"keys\":[\"{}\"]}}}}",
        session.0,
        "k".repeat(rivect::contracts::REQUEST_MAX_BYTES)
    );
    assert!(huge.len() > rivect::contracts::REQUEST_MAX_BYTES);
    let response = rivect::commands::dispatch_runtime_request(
        &mut world.runtime,
        Ingress::TrustedHuman,
        support::CONNECTION_ID,
        &huge,
    );
    let parsed: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(parsed["error"]["data"]["code"], "invalid_input");

    // In-flight manifest immutability: a pending settings change never
    // rewrites the frozen manifest.
    let manifest = world
        .runtime
        .broker
        .prepare(
            "backend_task",
            &world.runtime.config_for_broker(),
            "goal: probe",
        )
        .expect("manifest prepared");
    let frozen = manifest.clone();
    // The user now switches the config to a subscription pin without grant.
    std::fs::write(
        world.root.join("config.toml"),
        support::config_manual_subscription(),
    )
    .expect("config change");
    world.runtime.effective =
        rivect::config::resolve_effective(Some(&support::config_manual_subscription()))
            .expect("effective");
    // Dispatch still sends exactly the frozen manifest; the provider records
    // it verbatim, purpose and every field included.
    let reply = world
        .runtime
        .broker
        .dispatch(&manifest)
        .expect("dispatch frozen manifest");
    assert!(!reply.text.is_empty());
    let recorded = world
        .last_manifest()
        .expect("provider recorded the manifest");
    assert_eq!(
        recorded, frozen,
        "provider must receive the exact frozen manifest"
    );
    // A new prepare under the changed config is capability-unavailable.
    let denied =
        world
            .runtime
            .broker
            .prepare("main", &world.runtime.config_for_broker(), "goal: probe");
    assert!(
        denied.is_err(),
        "subscription pin without grant must fail eligibility"
    );
    let _ = file;
}

#[test]
fn evidence_invalidation_blocks_completion() {
    let (mut world, _scope, file, grant) =
        scoped_world("invalidation", Some(&support::config_distinct_pools()));
    let session = world.open_session("bootstrap-invalidation");
    let create = json!({
        "jsonrpc": "2.0", "id": 60, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-inv-1", "session_id": session.0,
                    "kind": "create", "goal": "Две проверки.",
                    "contract": { "criteria": ["Первая проверка.", "Вторая проверка."], "constraints": [] } }
    });
    let response = world.dispatch(&create.to_string());
    let task = rivect::contracts::TaskId(
        response["result"]["task_id"]
            .as_str()
            .expect("task")
            .to_string(),
    );
    let question = world.publish(&session, &task);
    let answer = world.dispatch(&corpus_answer_custom(
        &session,
        "cmd-inv-answer",
        &task,
        &question,
        &format!("read {}", file.display()),
        json!(61),
    ));
    assert!(answer["error"].is_null(), "{answer}");
    let outcome = world
        .runtime
        .run_decision_step(
            &session,
            &task,
            &answer_custom(&format!("read {}", file.display())),
            &grant,
            false,
        )
        .expect("complete with both criteria");
    assert!(matches!(
        outcome,
        rivect::controller::StepOutcome::Completed { .. }
    ));

    // Invalidation: the affected evidence goes stale, the task re-blocks,
    // unaffected evidence keeps its provenance.
    let evidence = world
        .runtime
        .owner
        .store
        .events_after(&session, None, 0, 0)
        .is_ok();
    assert!(evidence);
    let snapshot_before = world.runtime.owner.store.snapshot(&task).expect("snapshot");
    let obligations = &snapshot_before.obligations.items;
    assert_eq!(obligations.len(), 2);
    assert!(
        obligations
            .iter()
            .all(|o| o.execution == rivect::contracts::ObligationExecution::Satisfied)
    );
    let second_evidence = world
        .runtime
        .owner
        .store
        .insert_evidence(&task, 1, "task:probe", "extra basis", "probe-digest")
        .expect("second evidence");
    let blocked_task = world
        .runtime
        .owner
        .store
        .invalidate_evidence(&second_evidence)
        .expect("invalidate");
    assert_eq!(blocked_task, task.0);
    let blocked = world.runtime.owner.store.snapshot(&task).expect("snapshot");
    assert_eq!(blocked.lifecycle, Lifecycle::Blocked);
    assert_eq!(blocked.revision, snapshot_before.revision + 1);
    let obligations = &blocked.obligations.items;
    assert_eq!(
        obligations[1].execution,
        rivect::contracts::ObligationExecution::Stale
    );
    assert_eq!(
        obligations[1].applicability,
        rivect::contracts::ObligationApplicability::Unresolved
    );
    assert_eq!(
        obligations[0].execution,
        rivect::contracts::ObligationExecution::Satisfied
    );

    // EDGE-001: unresolved obligation + empty ready queue rejects completion.
    let err = world
        .runtime
        .owner
        .store
        .complete_if_eligible(&session, &task)
        .expect_err("completion must be rejected");
    assert!(err.to_string().contains("unresolved"), "{err}");
    let after = world.runtime.owner.store.snapshot(&task).expect("snapshot");
    assert_ne!(after.lifecycle, Lifecycle::Completed);
    assert!(
        after
            .blockers
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .any(|b| b.reason == rivect::contracts::ErrorCode::DependencyBlocked),
        "waiting/blocked must carry a non-empty reason"
    );
}

#[test]
fn tui_fullscreen_restore() {
    let mut pty = spawn_pty(&rivect_binary(), 24, 80);
    assert!(
        pty.wait_for(b"\x1b[?1049h", Duration::from_secs(10)),
        "alternate screen must be entered on start; got {:?}",
        String::from_utf8_lossy(&pty.collected())
    );
    pty.send(b"q");
    let code = pty.wait_exit(Duration::from_secs(10));
    assert_eq!(code, Some(0), "normal quit exits 0");
    let stream = pty.collected();
    assert!(
        support::find_subsequence(&stream, b"\x1b[?1049l").is_some(),
        "alt screen must be left"
    );
    assert!(
        support::find_subsequence(&stream, b"\x1b[?25h").is_some(),
        "cursor must be visible again"
    );
}

#[test]
fn tui_mouse_off_default() {
    let mut pty = spawn_pty(&rivect_binary(), 24, 80);
    assert!(
        pty.wait_for(b"\x1b[?1049h", Duration::from_secs(10)),
        "alternate screen must be entered on start"
    );
    let stream = pty.collected();
    for mouse_enable in [
        &b"\x1b[?1000h"[..],
        b"\x1b[?1002h",
        b"\x1b[?1003h",
        b"\x1b[?1006h",
        b"\x1b[?1015h",
    ] {
        assert!(
            support::find_subsequence(&stream, mouse_enable).is_none(),
            "mouse capture must stay off by default: found {mouse_enable:?}"
        );
    }
    // Ctrl-C cancels and still restores the terminal.
    pty.send(&[0x03]);
    let code = pty.wait_exit(Duration::from_secs(10));
    assert_eq!(code, Some(130), "cancel exits 130");
    let stream = pty.collected();
    assert!(support::find_subsequence(&stream, b"\x1b[?1049l").is_some());
    assert!(support::find_subsequence(&stream, b"\x1b[?25h").is_some());
}

#[test]
fn headless_non_tty_machine_surface() {
    use std::io::Write;
    let data_root = support::temp_dir("headless");
    let mut child = std::process::Command::new(rivect_binary())
        .arg("--headless")
        .arg("--data-root")
        .arg(&data_root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn headless");
    let request = json!({
        "jsonrpc": "2.0", "id": 1, "method": "session.open",
        "params": { "schema_version": 1, "bootstrap_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1" }
    });
    {
        let mut stdin = child.stdin.take().expect("stdin");
        writeln!(stdin, "{request}").expect("write request");
        stdin.flush().expect("flush");
    }
    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(0), "headless exits 0 on EOF");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        !stdout.contains('\u{1b}'),
        "machine stdout must not contain ANSI: {stdout:?}"
    );
    for line in stdout.lines() {
        let parsed: Value = serde_json::from_str(line).expect("each stdout line is one JSON frame");
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["id"], 1);
        assert!(parsed["result"]["session_id"].is_string(), "{parsed}");
    }
}

#[test]
#[ignore = "live consumptive path: requires a fresh root grant per test-plan; stays NOT_RUN without it"]
fn live_first_useful_provider_task() {
    let grant = std::env::var("RIVECT_LIVE_GRANT").expect(
        "no live grant: this case is NOT_RUN by design until root separately authorizes the consumptive run",
    );
    assert!(!grant.is_empty());
    panic!("live wiring arrives with the granted provider slice; refusing to fake a live result");
}
