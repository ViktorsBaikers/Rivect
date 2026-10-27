//! SLICE-001 first-task proof (TP-ADMISSION-PACKET 5b + TP-PUBLIC +
//! TP-BOOT): the native dependency contract, boot confinement before any
//! dispatch, the canonical corpus through both ingresses, crash-safe
//! no-repeat semantics, and the real-PTY TUI cases.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/discard conveniences; src/ stays strict (standards §14)"
)]

mod support;

use rivect::commands::Ingress;
use rivect::contracts::{AnswerSelection, Lifecycle, OptionId, ProjectInitResult};
use rivect::executor::EffectRequest;
use rivect::index::SnapshotId;
use rivect::model::RequestManifest;
use rivect::providers::{Provider, ProviderError, ProviderReply};
use rivect::resources::{Delivery, NotificationQueue, UsageDelta};
use rivect::ui::{ApplyVerdict, Projection};
use serde_json::{Value, json};
use sha2::Digest;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use support::{
    World, answer_custom, corpus_answer_custom, corpus_answer_option, corpus_config_read,
    corpus_create, corpus_question_current, corpus_status, corpus_steer, ensure_helper, open_world,
    rivect_binary, spawn_pty,
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

/// Freezes an already-published answer onto a scheduler node without
/// driving `scheduler_step`: production answer ingress drains the loop,
/// so tests that still own `run_decision_step` build the runnable node
/// directly.
fn freeze_answered(
    world: &mut World,
    session: &rivect::contracts::SessionId,
    task: &rivect::contracts::TaskId,
    question: &rivect::contracts::Question,
    selection: AnswerSelection,
) {
    world
        .runtime
        .store_writer()
        .answer_question(
            session,
            task,
            &question.question_id,
            question.question_revision,
            &selection,
            "human",
        )
        .expect("answer question");
    world
        .runtime
        .scheduler
        .submit_answered(task.clone(), selection, world.runtime.scoped_grant.clone())
        .expect("submit answered node")
        .expect("answered task is runnable");
}

struct NoToolProvider;

impl Provider for NoToolProvider {
    fn name(&self) -> &'static str {
        "no-tool"
    }

    /// The scripted double answers any manifest it is handed.
    fn serves(&self, _connection: &str, _entry: &rivect::config::Connection) -> bool {
        true
    }

    fn send(&mut self, _manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        Ok(ProviderReply {
            text: String::new(),
            tool_calls: Vec::new(),
            usage: UsageDelta::Unknown,
        })
    }
}

#[test]
fn typed_errors_preserve_source_chains() {
    let mut broker =
        rivect::model::Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
    let model_error = broker
        .prepare(
            "worker",
            &rivect::config::Config::default(),
            "/world/typed",
            "",
        )
        .expect_err("missing model defaults must fail");
    assert!(
        matches!(
            model_error,
            rivect::model::ModelError::Config(rivect::config::ConfigError {
                issue: rivect::config::ConfigIssue::Required { ref field },
                ..
            }) if field == "models.defaults"
        ),
        "{model_error}"
    );
    assert!(
        std::error::Error::source(&model_error)
            .and_then(|source| source.downcast_ref::<rivect::config::ConfigError>())
            .is_some(),
        "model errors must retain the typed configuration source"
    );

    let world = open_world("typed-error-source", None);
    let worker_error = support::platform_read_once(
        &world.root.join("missing-scope"),
        &world.root.join("missing-target"),
    )
    .expect_err("missing scope must fail");
    assert!(
        matches!(
            worker_error,
            rivect::executor::WorkerError::ScopeRootUnavailable { .. }
        ),
        "{worker_error}"
    );
    assert!(
        std::error::Error::source(&worker_error)
            .and_then(|source| source.downcast_ref::<std::io::Error>())
            .is_some(),
        "worker errors must retain the operating-system source"
    );
}

#[test]
fn create_receipt_identity_rejects_changed_constraints() {
    let mut world = open_world("create-receipt-constraints", None);
    let session = world.open_session("bootstrap-create-receipt-constraints");
    let first = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "task.submit",
        "params": {
            "schema_version": 1,
            "command_id": "create-receipt-constraints-command",
            "session_id": session.0,
            "kind": "create",
            "goal": "Preserve the constraint identity.",
            "contract": {
                "criteria": ["Return the requested result."],
                "constraints": ["Do not change files."]
            }
        }
    });
    let accepted = world.dispatch(&first);
    assert!(
        accepted["error"].is_null(),
        "first create must succeed: {accepted}"
    );

    let mut changed = first;
    changed["params"]["contract"]["constraints"] = json!(["Change files only with permission."]);
    let replay = world.dispatch(&changed);
    assert!(
        replay["result"].is_null(),
        "changed input must not replay the first snapshot: {replay}"
    );
    assert_eq!(replay["error"]["data"]["code"], "conflict");
}

#[test]
fn events_read_rejects_invalid_after_cursor() {
    let mut world = open_world("events-after-cursor", None);
    let session = world.open_session("bootstrap-events-after-cursor");
    let task = world.create_task(&session, "events-after-cursor-create");

    let in_range = world.dispatch(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "events.read",
        "params": {
            "schema_version": 1,
            "session_id": session.0,
            "after_cursor": 10,
            "task_id": task.0
        }
    }));
    assert!(
        in_range["error"].is_null(),
        "in-range cursor must work: {in_range}"
    );
    assert!(
        in_range["result"]["items"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );

    for cursor in [json!(1u64 << 63), json!(u64::MAX), json!("10"), json!(-1)] {
        let response = world.dispatch(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "events.read",
            "params": {
                "schema_version": 1,
                "session_id": session.0,
                "after_cursor": cursor
            }
        }));
        assert!(
            response["result"].is_null(),
            "invalid cursor must not return a page: {response}"
        );
        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(response["error"]["data"]["code"], "invalid_input");
    }

    let state_error = world
        .runtime
        .store()
        .events_after(&session, None, u64::MAX, 20)
        .expect_err("state API must reject an out-of-range cursor");
    assert!(matches!(
        state_error,
        rivect::state::StoreError::InvalidInput(rivect::state::InvalidCause::EventCursorOutOfRange)
    ));
}

#[test]
fn task_collection_valid_cursor_enforces_generation() {
    let mut world = open_world("collection-cursor", None);
    let session = world.open_session("bootstrap-collection-cursor");
    let task = world.create_task(&session, "collection-cursor-create");
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "task.collection",
        "params": {
            "schema_version": 1,
            "session_id": session.0,
            "task_id": task.0,
            "collection": "criteria",
            "page": { "cursor": "gen:999:offset:20" }
        }
    }));
    assert!(
        response["result"].is_null(),
        "stale collection cursor must not be ignored: {response}"
    );
    assert_eq!(response["error"]["data"]["code"], "conflict");
}

#[test]
fn task_collection_pages_attempts_with_next_cursor() {
    let mut world = open_world("collection-paging", None);
    let session = world.open_session("bootstrap-collection-paging");
    let task = world.create_task(&session, "collection-paging-create");
    for index in 0..5 {
        world
            .runtime
            .store_writer()
            .plan_attempt(
                &task,
                rivect::contracts::EffectClass::Read,
                &format!("paged attempt {index}"),
            )
            .expect("plan paged attempt");
    }
    let generation = world
        .runtime
        .store()
        .snapshot(&task)
        .expect("task snapshot")
        .revision;

    // First page: page_size is honored, next_cursor advances by page_size.
    let first = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 30, "method": "task.collection",
        "params": { "schema_version": 1, "session_id": session.0, "task_id": task.0, "collection": "attempts", "page": { "page_size": 2 } }
    }));
    assert!(first["error"].is_null(), "{first}");
    assert_eq!(first["result"]["items"].as_array().map(Vec::len), Some(2));
    assert_eq!(first["result"]["snapshot_generation"], json!(generation));
    assert_eq!(
        first["result"]["next_cursor"],
        json!(format!("gen:{generation}:offset:2"))
    );

    // Second page: the emitted cursor advances the offset and never repeats
    // the first page's items.
    let second = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 31, "method": "task.collection",
        "params": { "schema_version": 1, "session_id": session.0, "task_id": task.0, "collection": "attempts", "page": { "page_size": 2, "cursor": format!("gen:{generation}:offset:2") } }
    }));
    assert!(second["error"].is_null(), "{second}");
    assert_eq!(second["result"]["items"].as_array().map(Vec::len), Some(2));
    assert_ne!(
        second["result"]["items"][0]["attempt_id"], first["result"]["items"][0]["attempt_id"],
        "the second page must not repeat the first page's items"
    );
    assert_eq!(
        second["result"]["next_cursor"],
        json!(format!("gen:{generation}:offset:4"))
    );

    // Last page: one item remains and next_cursor is absent.
    let last = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 32, "method": "task.collection",
        "params": { "schema_version": 1, "session_id": session.0, "task_id": task.0, "collection": "attempts", "page": { "page_size": 2, "cursor": format!("gen:{generation}:offset:4") } }
    }));
    assert!(last["error"].is_null(), "{last}");
    assert_eq!(last["result"]["items"].as_array().map(Vec::len), Some(1));
    assert!(last["result"]["next_cursor"].is_null());

    // An offset past the collection is an empty last page, not an error.
    let past = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 33, "method": "task.collection",
        "params": { "schema_version": 1, "session_id": session.0, "task_id": task.0, "collection": "attempts", "page": { "page_size": 2, "cursor": format!("gen:{generation}:offset:99") } }
    }));
    assert!(past["error"].is_null(), "{past}");
    assert_eq!(past["result"]["items"].as_array().map(Vec::len), Some(0));
    assert!(past["result"]["next_cursor"].is_null());
}

#[test]
fn read_once_enforces_byte_boundary() {
    let world = open_world("read-boundary", None);
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let exact = scope.join("exact.bin");
    let exact_bytes = vec![b'x'; support::PLATFORM_READ_MAX_BYTES];
    std::fs::write(&exact, &exact_bytes).expect("exact file");
    let observation = support::platform_read_once(&scope, &exact).expect("exact size");
    assert_eq!(observation.bytes, exact_bytes);
    assert_eq!(observation.digest, support::sha256_hex(&observation.bytes));

    let hardlink = scope.join("hardlink.bin");
    std::fs::hard_link(&exact, &hardlink).expect("hardlink");
    let linked = support::platform_read_once(&scope, &hardlink).expect("hardlink read");
    assert_eq!(linked.bytes, exact_bytes);

    let outside = world.root.join("outside-secret.txt");
    std::fs::write(&outside, b"outside").expect("outside file");
    let escape = scope.join("escape");
    std::os::unix::fs::symlink(&outside, &escape).expect("escape symlink");
    assert!(matches!(
        support::platform_read_once(&scope, &escape),
        Err(rivect::executor::WorkerError::OutsideScope { .. })
    ));

    let oversized = scope.join("oversized.bin");
    std::fs::write(&oversized, vec![b'x'; support::PLATFORM_READ_MAX_BYTES + 1])
        .expect("oversized file");
    assert!(matches!(
        support::platform_read_once(&scope, &oversized),
        Err(rivect::executor::WorkerError::TooLarge)
    ));

    let denied = scope.join("oversized-denied.bin");
    std::fs::write(&denied, vec![b'x'; support::PLATFORM_READ_MAX_BYTES + 1])
        .expect("oversized denied file");
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000))
        .expect("deny oversized file");
    assert!(matches!(
        support::platform_read_once(&scope, &denied),
        Err(rivect::executor::WorkerError::TooLarge)
    ));
}

#[test]
fn read_once_denies_fifo_without_writer() -> Result<(), Box<dyn std::error::Error>> {
    let mut world = open_world("read-fifo-denied", None);
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope)?;
    let fifo = scope.join("pipe");
    let status = std::process::Command::new("mkfifo").arg(&fifo).status();
    if status.is_err() {
        world.retain();
    }
    let status = status?;
    assert!(status.success(), "mkfifo must create the pipe");
    // No writer holds the other end: a static FIFO is denied by the
    // pre-open regular-file check, and a swap into the open window cannot
    // block the O_NONBLOCK opened handle before the same fd-level check.
    assert!(matches!(
        support::platform_read_once(&scope, &fifo),
        Err(rivect::executor::WorkerError::NotRegularFile { .. })
    ));
    Ok(())
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
        matches!(
            denied,
            rivect::executor::ExecutorError::Worker(
                rivect::executor::WorkerError::OutsideScope { ref target }
            ) if target == &outside
        ),
        "{denied}"
    );

    // Write, foreign exec and direct egress are structurally rejected at
    // the grant gate: the read-only scope grant admits no other class,
    // long before any mode consult or worker leg.
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
        let mut executor = world.runtime.executor();
        let admitted = executor
            .admit(&task, request, rivect::policy::PermissionMode::Manual)
            .expect_err("the read grant rejects non-read classes");
        assert!(
            matches!(
                admitted,
                rivect::executor::ExecutorError::Policy(
                    rivect::policy::PolicyError::ClassNotAdmitted { .. }
                )
            ),
            "{admitted}"
        );
    }
    // Forged write/exec/egress admissions that bypass admit must not
    // bypass the mode gate: with an all-class grant and the interim
    // manual mode, every non-read cell asks at the execute-time
    // reconsult, so no worker leg runs — verified by file bytes, an exec
    // marker, and a real local TCP accept oracle showing zero
    // connections. There is no ambient path around the gate.
    let exec_marker = world.root.join("exec-marker.out");
    // The exec oracle script lives inside the granted scope so the mode
    // gate — not the scope consult — is the discriminator for the leg.
    let exec_script = _scope.join("make_marker.sh");
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
    let all_classes = world.runtime.policy_writer().grant_classes(
        _scope.clone(),
        vec![
            rivect::contracts::EffectClass::Read,
            rivect::contracts::EffectClass::Write,
            rivect::contracts::EffectClass::Exec,
            rivect::contracts::EffectClass::Egress,
        ],
    );
    for request in [
        EffectRequest::Write {
            grant_id: all_classes.clone(),
            path: file.clone(),
            bytes: b"tampered".to_vec(),
        },
        EffectRequest::Exec {
            grant_id: all_classes.clone(),
            program: exec_script.clone(),
        },
        EffectRequest::Egress {
            grant_id: all_classes.clone(),
            url: format!("http://{egress_addr}/probe"),
        },
    ] {
        let class = request.class();
        let attempt_id = world
            .runtime
            .store_writer()
            .plan_attempt(&task, class, &request.describe())
            .expect("plan forced attempt");
        let admitted = rivect::executor::AdmittedEffect {
            task_id: task.clone(),
            attempt_id,
            request,
            mode: rivect::policy::PermissionMode::Manual,
            expected_identity: None,
            scope_root: _scope.clone(),
        };
        let mut executor = world.runtime.executor();
        let error = executor
            .execute(&admitted)
            .expect_err("a forged manual-mode non-read effect must ask at the mode gate");
        assert!(
            matches!(error, rivect::executor::ExecutorError::ModeAsk),
            "{error}"
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
    let deadline = std::time::Instant::now() + Duration::from_millis(300);
    while std::time::Instant::now() < deadline {
        match listener.accept() {
            Ok((_, _)) => panic!("direct egress must never open a connection"),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => panic!("egress oracle failed: {err}"),
        }
        std::thread::sleep(Duration::from_millis(20));
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
    world.runtime.policy_writer().revoke(&grant);
    let revoked = rivect::tools::invoke_read(&mut world.runtime, &task, &grant, file.clone())
        .expect_err("revoked grant denies");
    assert!(
        matches!(
            revoked,
            rivect::executor::ExecutorError::Policy(rivect::policy::PolicyError::Revoked { .. })
        ),
        "{revoked}"
    );

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
        matches!(
            outcome,
            Err(rivect::controller::ControllerError::Policy(
                rivect::policy::PolicyError::UnknownGrant { .. }
            ))
        ),
        "subscription pin without grant must not dispatch: {outcome:?}"
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
    let (mut world, _scope, _file, _grant) =
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
    Digest::update(
        &mut expected_digest,
        rivect::config::SHIPPED_DEFAULTS_TOML.as_bytes(),
    );
    Digest::update(&mut expected_digest, &user_bytes);
    let expected_source_digest = rivect::config::hex(&Digest::finalize(expected_digest));
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
    assert_eq!(q["prompt"], "Which form should we use?");
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

    // Answer via the trusted adapter: applied, one task; the production
    // drain runs the loopback useful path to completion, so the response
    // reports the settled row — revision 4, the completion commit — not
    // the answer-commit snapshot the drain moved past.
    let answer = world.dispatch(&corpus_answer_custom(
        &session,
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa6",
        &task,
        &question,
        "steps",
        json!(6),
    ));
    assert!(answer["error"].is_null(), "{answer}");
    assert_eq!(answer["result"]["status"], "applied");
    assert_eq!(answer["result"]["task_revision"], 4);
    assert_eq!(answer["result"]["snapshot"]["revision"], 4);
    assert_eq!(answer["result"]["snapshot"]["lifecycle"], "completed");
    let status = world.dispatch(&corpus_status(&session));
    assert_eq!(
        status["result"]["tasks"]["items"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        status["result"]["tasks"]["items"][0]["lifecycle"],
        "completed"
    );
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "answer drain dispatches the admitted read once"
    );
    assert_eq!(
        world.worker_reads(),
        1,
        "answer drain performs one scoped read"
    );
    let (answer_json, author) = world
        .runtime
        .store()
        .answered_question(&task)
        .expect("durable answer")
        .expect("answer recorded");
    assert_eq!(author, "human");
    assert!(answer_json.contains("steps"), "{answer_json}");

    // Sequential second answer on the completed task: already_terminal,
    // no second decision or effect.
    let second = world.dispatch(&corpus_answer_option(
        &session,
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa6b",
        &task,
        &question,
        "steps",
        json!(6),
    ));
    assert_eq!(second["error"]["data"]["code"], "already_terminal");
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a second answer must not dispatch again"
    );

    // A completed task cannot be steered: terminal cannot reopen, even
    // when the named intent is stale.
    let stale = world.dispatch(&corpus_steer(
        &session,
        "cmd-steer-stale",
        &task,
        99,
        3,
        json!(80),
    ));
    assert_eq!(stale["error"]["data"]["code"], "conflict");
    let steer = world.dispatch(&corpus_steer(
        &session,
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa8",
        &task,
        1,
        3,
        json!(8),
    ));
    assert_eq!(steer["error"]["data"]["code"], "conflict");

    // Answer origin is visible in the durable event log.
    let events = world
        .runtime
        .store()
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
        .store()
        .answered_question(&fresh_task)
        .expect("durable custom answer")
        .expect("recorded");
    assert!(
        custom_json.contains("Кратко объяснить.\\nЗатем привести пример."),
        "{custom_json}"
    );

    // Custom text still runs the admitted scoped read at drain time; the
    // exact multi-line bytes stay durable.
    let custom_snapshot = world
        .runtime
        .store()
        .snapshot(&fresh_task)
        .expect("custom snapshot");
    assert_eq!(custom_snapshot.lifecycle, Lifecycle::Completed);
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        2,
        "each answered task drains exactly one loopback dispatch"
    );
}

#[test]
fn known_ready_action_starts_without_provider_dispatch() {
    let (mut world, _scope, file, grant) =
        scoped_world("known-ready", Some(&support::config_distinct_pools()));
    let session = world.open_session("bootstrap-known-ready");
    let task = world.create_task(&session, "cmd-known-ready");
    let question = world.publish(&session, &task);
    freeze_answered(
        &mut world,
        &session,
        &task,
        &question,
        AnswerSelection::Option {
            option_id: OptionId("brief".to_string()),
        },
    );
    let outcome = world
        .runtime
        .run_decision_step(
            &session,
            &task,
            &AnswerSelection::Option {
                option_id: OptionId("brief".to_string()),
            },
            &grant,
            false,
        )
        .expect("known-ready step");
    assert!(matches!(
        outcome,
        rivect::controller::StepOutcome::Completed { .. }
    ));
    assert_eq!(world.runtime.provider_calls, 0);
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );

    let planned_task = world.create_task(&session, "cmd-material-plan");
    let planned_question = world.publish(&session, &planned_task);
    freeze_answered(
        &mut world,
        &session,
        &planned_task,
        &planned_question,
        AnswerSelection::Custom {
            text: "steps".to_string(),
        },
    );
    let planned = world
        .runtime
        .run_decision_step(
            &session,
            &planned_task,
            &AnswerSelection::Custom {
                text: "steps".to_string(),
            },
            &grant,
            false,
        )
        .expect("material-plan step");
    assert!(matches!(
        planned,
        rivect::controller::StepOutcome::Completed { .. }
    ));
    assert_eq!(world.runtime.provider_calls, 1);
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(world.worker_reads(), 2);
    assert!(world.last_manifest().is_some());
    assert!(file.exists());
}

#[test]
fn no_ready_provider_blocks_and_reaches_dock_projection() {
    let root = tempfile::TempDir::with_prefix("rivect-no-ready-provider-").expect("fixture root");
    std::fs::write(
        root.path().join("config.toml"),
        support::config_distinct_pools(),
    )
    .expect("config");
    let mut runtime = rivect::commands::Runtime::open(root.path(), Box::new(NoToolProvider))
        .expect("owner elected");
    runtime.purpose = "backend_task".to_string();
    let scope = root.path().join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "no-ready-marker\n").expect("scoped file");
    let grant = runtime.set_read_scope(scope, file.clone());
    let (session, _, _, _) = runtime
        .store_writer()
        .open_session("bootstrap-no-ready", support::CONNECTION_ID, None)
        .expect("session");
    let create_response = rivect::commands::dispatch_runtime_request(
        &mut runtime,
        Ingress::TrustedHuman,
        support::CONNECTION_ID,
        &corpus_create(&session, "cmd-no-ready"),
    );
    let create_response: Value = serde_json::from_str(&create_response).expect("create response");
    let task = rivect::contracts::TaskId(
        create_response["result"]["task_id"]
            .as_str()
            .expect("task")
            .to_string(),
    );
    let question = rivect::contracts::Question::fixture(&task, 1);
    runtime
        .store_writer()
        .publish_question(&session, &question)
        .expect("question");
    let answer = answer_custom("request provider judgment");
    runtime
        .store_writer()
        .answer_question(
            &session,
            &task,
            &question.question_id,
            question.question_revision,
            &answer,
            "human",
        )
        .expect("answer");

    let outcome = runtime
        .run_decision_step(&session, &task, &answer, &grant, false)
        .expect("no-ready decision step");
    let rivect::controller::StepOutcome::Waiting { snapshot } = outcome else {
        panic!("expected waiting outcome");
    };
    assert_eq!(snapshot.lifecycle, Lifecycle::Blocked);
    assert_eq!(runtime.provider_calls, 1);

    let snapshot_response = rivect::commands::dispatch_runtime_request(
        &mut runtime,
        Ingress::TrustedHuman,
        support::CONNECTION_ID,
        &json!({
            "jsonrpc": "2.0",
            "id": 90,
            "method": "task.snapshot",
            "params": {
                "schema_version": 1,
                "session_id": session.0,
                "task_id": task.0
            }
        })
        .to_string(),
    );
    let snapshot_response: Value =
        serde_json::from_str(&snapshot_response).expect("snapshot response");
    assert_eq!(snapshot_response["result"]["lifecycle"], "blocked");
    let blocker = &snapshot_response["result"]["blockers"][0];
    assert!(
        blocker["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty())
    );
    assert_eq!(blocker["condition"]["kind"], "no_ready_action");

    let status_response = rivect::commands::dispatch_runtime_request(
        &mut runtime,
        Ingress::TrustedHuman,
        support::CONNECTION_ID,
        &corpus_status(&session),
    );
    let status: Value = serde_json::from_str(&status_response).expect("status response");
    let dock_item = &status["result"]["todo"]["items"][0];
    assert_eq!(dock_item["lifecycle"], "blocked");
    assert_eq!(dock_item["blockers"][0]["reason"], blocker["reason"]);
    assert!(
        dock_item["blockers"][0]["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty())
    );
}

#[test]
fn recover_events_rejects_foreign_session() {
    let (mut world, _scope, _file, _grant) = scoped_world("recover-foreign-session", None);
    let session = world.open_session("bootstrap-recover-foreign");
    let task = world.create_task(&session, "cmd-recover-foreign");
    let events = world
        .runtime
        .store()
        .events_after(&session, Some(&task), 0, 50)
        .expect("events");
    let foreign = rivect::contracts::SessionId("foreign-session".to_string());
    assert!(matches!(
        world
            .runtime
            .store_writer()
            .recover_events(&foreign, &events),
        Err(rivect::state::StoreError::Conflict(
            rivect::state::ConflictCause::EventSessionMismatch { .. }
        ))
    ));
}

#[test]
fn recover_events_rejects_unknown_aggregate() {
    let (mut world, _scope, _file, _grant) = scoped_world("recover-unknown-aggregate", None);
    let session = world.open_session("bootstrap-recover-unknown");
    let task = world.create_task(&session, "cmd-recover-unknown");
    let events = world
        .runtime
        .store()
        .events_after(&session, Some(&task), 0, 50)
        .expect("events");
    let mut unknown = events.into_iter().next().expect("event");
    unknown.aggregate_id = "unknown-aggregate".to_string();
    assert!(matches!(
        world
            .runtime
            .store_writer()
            .recover_events(&session, &[unknown]),
        Err(rivect::state::StoreError::Conflict(
            rivect::state::ConflictCause::EventNotFound { .. }
        ))
    ));
}

#[test]
fn recover_events_rejects_malformed_delta_without_commit() {
    let (mut world, _scope, _file, _grant) = scoped_world("recover-malformed-delta", None);
    let session = world.open_session("bootstrap-recover-malformed-delta");
    let task = world.create_task(&session, "cmd-recover-malformed-delta");
    let events = world
        .runtime
        .store()
        .events_after(&session, Some(&task), 0, 50)
        .expect("events");
    let canonical_event = events.first().expect("event").clone();
    let db_path = world.root.join("runtime").join("rivect.db");
    let before_delta: String = rusqlite::Connection::open(&db_path)
        .expect("open database")
        .query_row(
            "SELECT delta_json FROM events WHERE event_id = ?1",
            rusqlite::params![canonical_event.event_id.0],
            |row| row.get(0),
        )
        .expect("read event delta");
    let connection = rusqlite::Connection::open(&db_path).expect("open database");
    connection
        .execute(
            "UPDATE events SET delta_json = ?2 WHERE event_id = ?1",
            rusqlite::params![canonical_event.event_id.0, "not-json"],
        )
        .expect("corrupt event delta");
    drop(connection);

    let mut replay = canonical_event;
    replay.delta = Value::Null;
    let error = world
        .runtime
        .store_writer()
        .recover_events(&session, &[replay])
        .expect_err("malformed durable delta must abort recovery");
    assert!(
        matches!(error, rivect::state::StoreError::Storage(_)),
        "{error}"
    );
    let after_delta: String = rusqlite::Connection::open(&db_path)
        .expect("open database")
        .query_row(
            "SELECT delta_json FROM events WHERE event_id = ?1",
            rusqlite::params![events[0].event_id.0],
            |row| row.get(0),
        )
        .expect("read event delta");
    assert_eq!(after_delta, "not-json");
    assert_ne!(before_delta, "not-json");
}

#[test]
fn durable_todo_scheduler_restart_agree() {
    let (mut world, _scope, _file, _grant) =
        scoped_world("todo-scheduler", Some(&support::config_distinct_pools()));
    let session = world.open_session("bootstrap-todo-scheduler");
    let task = world.create_task(&session, "cmd-todo-scheduler");
    let running = world.dispatch(&corpus_status(&session));
    assert!(running["error"].is_null(), "{running}");
    assert_eq!(
        running["result"]["todo"]["items"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(running["result"]["todo"]["items"][0]["task_id"], task.0);
    assert_eq!(
        running["result"]["todo"]["items"][0]["lifecycle"],
        "running"
    );
    assert_eq!(running["result"]["scheduler"]["items"][0]["ready"], true);
    assert_eq!(
        running["result"]["tasks"]["snapshot_generation"],
        running["result"]["todo"]["snapshot_generation"]
    );
    assert_eq!(
        running["result"]["tasks"]["snapshot_generation"],
        running["result"]["scheduler"]["snapshot_generation"]
    );
    let question = world.publish(&session, &task);
    let waiting = world.dispatch(&corpus_status(&session));
    assert_eq!(
        waiting["result"]["todo"]["items"][0]["lifecycle"],
        "waiting"
    );
    assert!(
        !waiting["result"]["todo"]["items"][0]["blockers"]
            .as_array()
            .expect("todo blockers")
            .is_empty()
    );
    assert_eq!(waiting["result"]["scheduler"]["items"][0]["ready"], false);
    let todo_before_restart = waiting["result"]["todo"].clone();
    let scheduler_before_restart = waiting["result"]["scheduler"].clone();
    world.reopen();
    let after_restart = world.dispatch(&corpus_status(&session));
    assert_eq!(after_restart["result"]["todo"], todo_before_restart);
    assert_eq!(
        after_restart["result"]["scheduler"],
        scheduler_before_restart
    );
    assert_eq!(
        after_restart["result"]["tasks"]["items"][0]["lifecycle"],
        "waiting"
    );
    assert_eq!(question.task_id, task);
}

#[test]
fn runtime_status_pages_tasks_without_overlap() {
    let (mut world, _scope, _file, _grant) = scoped_world("status-pages", None);
    let session = world.open_session("bootstrap-status-pages");
    for index in 0..21 {
        world.create_task(&session, &format!("cmd-status-page-{index}"));
    }
    let mut cursor = None;
    let mut task_ids = Vec::new();
    for page_index in 0..11 {
        let mut request = json!({
            "jsonrpc": "2.0", "id": 70 + page_index, "method": "runtime.status",
            "params": { "schema_version": 1, "session_id": session.0, "page": { "page_size": 2 } }
        });
        if let Some(value) = cursor.clone() {
            request["params"]["page"]["cursor"] = Value::String(value);
        }
        let response = world.dispatch(&request);
        assert!(response["error"].is_null(), "{response}");
        let expected_len = if page_index < 10 { 2 } else { 1 };
        for section in ["tasks", "todo", "scheduler"] {
            let page = &response["result"][section];
            let items = page["items"].as_array().expect("page items");
            assert_eq!(items.len(), expected_len, "{section} page: {response}");
            if page_index < 10 {
                assert!(
                    page["next_cursor"].is_string(),
                    "{section} non-final page must return cursor: {response}"
                );
            } else {
                assert!(
                    page["next_cursor"].is_null(),
                    "{section} final page must omit cursor: {response}"
                );
            }
        }
        for item in response["result"]["tasks"]["items"]
            .as_array()
            .expect("task page")
        {
            task_ids.push(item["task_id"].as_str().expect("task id").to_string());
        }
        cursor = response["result"]["tasks"]["next_cursor"]
            .as_str()
            .map(str::to_string);
    }
    assert_eq!(task_ids.len(), 21);
    let mut unique = task_ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), task_ids.len(), "pages must not overlap");

    for index in 21..=36 {
        world.create_task(&session, &format!("cmd-status-default-{index}"));
    }
    let default_page = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 73, "method": "runtime.status",
        "params": { "schema_version": 1, "session_id": session.0 }
    }));
    assert!(default_page["error"].is_null(), "{default_page}");
    for section in ["tasks", "todo", "scheduler"] {
        let page = &default_page["result"][section];
        assert_eq!(
            page["items"].as_array().expect("default page").len(),
            rivect::contracts::PAGE_DEFAULT as usize,
            "{section} default page must use PAGE_DEFAULT"
        );
        assert!(page["next_cursor"].is_string(), "{section}: {default_page}");
    }
}

#[test]
fn runtime_status_page_cursor_boundary_and_rejects_invalid_offsets() {
    let (mut world, _scope, _file, _grant) = scoped_world("status-cursor-boundary", None);
    let session = world.open_session("bootstrap-status-cursor-boundary");
    for index in 0..20 {
        world.create_task(&session, &format!("cmd-cursor-boundary-{index}"));
    }

    let huge_page = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 71, "method": "runtime.status",
        "params": {
            "schema_version": 1, "session_id": session.0,
            "page": { "page_size": 4_294_967_296u64 }
        }
    }));
    assert!(huge_page["error"].is_null(), "{huge_page}");
    assert_eq!(
        huge_page["result"]["tasks"]["items"]
            .as_array()
            .expect("clamped page")
            .len(),
        20
    );
    assert!(huge_page["result"]["tasks"]["next_cursor"].is_null());
    let zero_page = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 72, "method": "runtime.status",
        "params": {
            "schema_version": 1, "session_id": session.0,
            "page": { "page_size": 0 }
        }
    }));
    assert_eq!(
        zero_page["error"]["data"]["code"], "invalid_input",
        "{zero_page}"
    );
    let scalar_page = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 73, "method": "runtime.status",
        "params": {
            "schema_version": 1, "session_id": session.0, "page": 5
        }
    }));
    assert_eq!(
        scalar_page["error"]["data"]["code"], "invalid_input",
        "{scalar_page}"
    );
    let scalar_cursor = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 74, "method": "runtime.status",
        "params": {
            "schema_version": 1, "session_id": session.0,
            "page": { "cursor": 5 }
        }
    }));
    assert_eq!(
        scalar_cursor["error"]["data"]["code"], "invalid_input",
        "{scalar_cursor}"
    );
    assert_eq!(
        scalar_cursor["error"]["data"]["message"],
        "page cursor must be gen:<generation>:offset:<offset>",
        "{scalar_cursor}"
    );
    let exact = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 74, "method": "runtime.status",
        "params": {
            "schema_version": 1, "session_id": session.0,
            "page": { "page_size": rivect::contracts::PAGE_DEFAULT }
        }
    }));
    assert!(exact["error"].is_null(), "{exact}");
    assert_eq!(
        exact["result"]["tasks"]["items"]
            .as_array()
            .expect("exact page")
            .len(),
        rivect::contracts::PAGE_DEFAULT as usize
    );
    assert!(exact["result"]["tasks"]["next_cursor"].is_null());

    world.create_task(&session, "cmd-cursor-boundary-last");
    let over = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 75, "method": "runtime.status",
        "params": {
            "schema_version": 1, "session_id": session.0,
            "page": { "page_size": rivect::contracts::PAGE_DEFAULT }
        }
    }));
    assert!(over["error"].is_null(), "{over}");
    let generation = over["result"]["tasks"]["snapshot_generation"]
        .as_u64()
        .expect("generation");
    assert!(over["result"]["tasks"]["next_cursor"].is_string());
    let next_cursor_guard = world.runtime.store().task_status_page(
        &session,
        2,
        Some((generation, i64::MAX as u64 - 1)),
    );
    assert!(matches!(
        next_cursor_guard,
        Err(rivect::state::StoreError::InvalidInput(
            rivect::state::InvalidCause::CursorOffsetOutOfRange
        ))
    ));
    let before = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 76, "method": "runtime.status",
        "params": { "schema_version": 1, "session_id": session.0 }
    }));
    for offset in [u64::MAX, 1u64 << 63] {
        let rejected = world.dispatch(&json!({
            "jsonrpc": "2.0", "id": 77, "method": "runtime.status",
            "params": {
                "schema_version": 1, "session_id": session.0,
                "page": {
                    "page_size": 2,
                    "cursor": format!("gen:{generation}:offset:{offset}")
                }
            }
        }));
        assert_eq!(
            rejected["error"]["data"]["code"], "invalid_input",
            "{rejected}"
        );
        assert_eq!(
            rejected["error"]["data"]["message"], "page cursor offset is out of range",
            "{rejected}"
        );
        assert!(rejected["result"].is_null(), "{rejected}");
    }
    let after = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 76, "method": "runtime.status",
        "params": { "schema_version": 1, "session_id": session.0 }
    }));
    assert_eq!(after, before, "invalid cursors must not change state");
}

#[test]
fn runtime_status_blockers_match_task_snapshots_across_lifecycles() {
    let (mut world, _scope, _file, _grant) = scoped_world(
        "status-blocker-lifecycles",
        Some(&support::config_distinct_pools()),
    );
    let session = world.open_session("bootstrap-status-blocker-lifecycles");

    let blocked_with_question = world.create_task(&session, "cmd-blocked-pending-question");
    world.publish(&session, &blocked_with_question);
    let db_path = world.runtime.owner().runtime_dir().join("rivect.db");
    let connection = rusqlite::Connection::open(&db_path).expect("open owner db");
    connection
        .execute(
            "UPDATE tasks SET lifecycle = 'blocked' WHERE task_id = ?1",
            rusqlite::params![blocked_with_question.0],
        )
        .expect("force blocked lifecycle");
    drop(connection);

    let running_with_unknown = world.create_task(&session, "cmd-running-unknown-attempt");
    let attempt = world
        .runtime
        .store_writer()
        .plan_attempt(
            &running_with_unknown,
            rivect::contracts::EffectClass::Read,
            "unknown running attempt",
        )
        .expect("plan attempt");
    world
        .runtime
        .store_writer()
        .attempt_unknown(&attempt, "unknown running outcome")
        .expect("mark attempt unknown");

    let waiting_with_obligation_response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 78, "method": "task.submit",
        "params": {
            "schema_version": 1,
            "command_id": "cmd-waiting-unresolved-obligation",
            "session_id": session.0,
            "kind": "create",
            "goal": "waiting unresolved obligation",
            "contract": { "criteria": ["criterion"], "constraints": [] }
        }
    }));
    assert!(
        waiting_with_obligation_response["error"].is_null(),
        "{waiting_with_obligation_response}"
    );
    let waiting_with_obligation = rivect::contracts::TaskId(
        waiting_with_obligation_response["result"]["task_id"]
            .as_str()
            .expect("waiting task")
            .to_string(),
    );
    world
        .runtime
        .store_writer()
        .materialize_obligations(&waiting_with_obligation)
        .expect("materialize obligation");
    let connection = rusqlite::Connection::open(&db_path).expect("open owner db");
    connection
        .execute(
            "UPDATE tasks SET lifecycle = 'waiting' WHERE task_id = ?1",
            rusqlite::params![waiting_with_obligation.0],
        )
        .expect("force waiting lifecycle");
    drop(connection);

    let status = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 79, "method": "runtime.status",
        "params": {
            "schema_version": 1, "session_id": session.0,
            "page": { "page_size": rivect::contracts::PAGE_MAX }
        }
    }));
    assert!(status["error"].is_null(), "{status}");
    for item in status["result"]["tasks"]["items"]
        .as_array()
        .expect("status tasks")
    {
        let task_status: rivect::contracts::TaskStatus =
            serde_json::from_value(item.clone()).expect("task status");
        let snapshot = world
            .runtime
            .store()
            .snapshot(&task_status.task_id)
            .expect("task snapshot");
        assert_eq!(
            task_status.blockers, snapshot.blockers,
            "batched blockers must match snapshot for {}",
            task_status.task_id.0
        );
    }
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
        .store()
        .events_after(&session, Some(&task), 0, 50)
        .expect("events");
    assert!(!first.is_empty());
    let again = world
        .runtime
        .store()
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
    let mut fork = first[0].clone();
    fork.delta = json!({ "fork": true });
    assert_eq!(projection.apply(&fork), ApplyVerdict::Resync);
    if first.len() >= 2 {
        assert_eq!(projection.apply(&first[1]), ApplyVerdict::Applied);
    }
    let gap = support::event_for_test(99, projection.last_revision + 5);
    assert_eq!(projection.apply(&gap), ApplyVerdict::Resync);
    let old = first.last().expect("events").clone();
    assert_eq!(projection.apply(&old), ApplyVerdict::Duplicate);

    // Client-origin notifications are never commands.
    let spoof = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 22, "method": "runtime.resync",
        "params": { "schema_version": 1, "session_id": session.0 }
    }));
    assert_eq!(spoof["error"]["code"], -32601);

    // Known-but-unavailable command kinds never fake success. `doctor`
    // is the kind that still carries the invariant: it is recorded to
    // `PLANNED_LOCAL_KINDS` and stays unavailable until its own owner
    // (SLICE-076), so a dispatch of it must answer the typed refusal and
    // no result at all. `project.init` no longer carries it — that kind
    // was promoted, so it now has a handler and a real descriptor.
    let unavailable = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 23, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0, "command": { "kind": "doctor" } }
    }));
    assert_eq!(
        unavailable["error"]["data"]["code"],
        "capability_unavailable"
    );
    assert!(
        unavailable.get("result").is_none(),
        "a known-but-unavailable kind fakes nothing: {unavailable}"
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
    // The catalog half of the same invariant: the promoted kind reports
    // itself available with a real description and no unavailability
    // reason, while a still-planned kind keeps `available: false` and
    // names why.
    let project_init = items
        .iter()
        .find(|d| d["canonical_id"] == "project.init")
        .expect("the promoted kind stays in the catalog");
    assert_eq!(project_init["available"], true, "{project_init}");
    assert!(
        project_init["unavailability_reason"].is_null()
            && !project_init["description"]
                .as_str()
                .unwrap_or_default()
                .is_empty(),
        "an available kind advertises itself: {project_init}"
    );
    let planned = items
        .iter()
        .find(|d| d["canonical_id"] == "doctor")
        .expect("a still-planned kind stays in the catalog");
    assert_eq!(planned["available"], false, "{planned}");
    assert!(
        !planned["unavailability_reason"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "an unbuilt kind names why: {planned}"
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
    freeze_answered(
        &mut world,
        &session,
        &task,
        &question,
        answer_custom(&format!("read {}", file.display())),
    );

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
        .store()
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
            .store()
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

    // Recovery re-delivers the durable stream through the owner after restart.
    let events = world
        .runtime
        .store()
        .events_after(&session, Some(&task), 0, 100)
        .expect("events after restart");
    assert!(!events.is_empty(), "the crash stream must be durable");
    let api_before = world.dispatch(&json!({
        "jsonrpc": "2.0",
        "id": 74,
        "method": "task.snapshot",
        "params": { "schema_version": 1, "session_id": session.0, "task_id": task.0 }
    }));
    assert_eq!(api_before["result"]["lifecycle"], "blocked");
    assert_eq!(
        api_before["result"]["blockers"][0]["reason"],
        "outcome_unknown"
    );
    let status_before_replay = world.dispatch(&corpus_status(&session));
    assert!(
        status_before_replay["result"]["todo"]["items"]
            .as_array()
            .expect("todo items")
            .iter()
            .any(|item| item["task_id"] == task.0),
        "todo projection contains task before recovery"
    );
    {
        let connection =
            rusqlite::Connection::open(world.runtime.owner().runtime_dir().join("rivect.db"))
                .expect("open owner db");
        connection
            .execute(
                "DELETE FROM todo_projection WHERE task_id = ?1",
                rusqlite::params![&task.0],
            )
            .expect("dirty todo projection");
    }
    let dirty_status = world.dispatch(&corpus_status(&session));
    assert!(
        dirty_status["result"]["todo"]["items"]
            .as_array()
            .expect("dirty todo items")
            .iter()
            .all(|item| item["task_id"] != task.0),
        "projection mutation is observable before recovery"
    );
    assert!(
        dirty_status["result"]["scheduler"]["items"]
            .as_array()
            .expect("dirty scheduler items")
            .iter()
            .all(|item| item["task_id"] != task.0),
        "scheduler follows dirty todo projection"
    );
    let before_replay = world
        .runtime
        .store()
        .snapshot(&task)
        .expect("snapshot before recovery");
    let durable_counts = |world: &World| {
        rusqlite::Connection::open(world.runtime.owner().runtime_dir().join("rivect.db"))
            .expect("open owner db")
            .query_row(
                "SELECT (SELECT COUNT(*) FROM events), (SELECT COUNT(*) FROM attempts)",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .expect("read durable recovery counts")
    };
    let counts_before_replay = durable_counts(&world);
    let mut replayed = events.iter().rev().cloned().collect::<Vec<_>>();
    replayed.extend(events.iter().cloned());
    world
        .runtime
        .store_writer()
        .recover_events(&session, &replayed)
        .expect("owner recovers duplicate and permuted events");
    let status_after_replay = world.dispatch(&corpus_status(&session));
    assert_eq!(
        status_after_replay["result"]["todo"], status_before_replay["result"]["todo"],
        "owner recovery restores todo projection"
    );
    assert_eq!(
        status_after_replay["result"]["scheduler"], status_before_replay["result"]["scheduler"],
        "owner recovery restores scheduler projection"
    );
    let api_after = world.dispatch(&json!({
        "jsonrpc": "2.0",
        "id": 74,
        "method": "task.snapshot",
        "params": { "schema_version": 1, "session_id": session.0, "task_id": task.0 }
    }));
    assert_eq!(api_after, api_before, "recovery returns one API snapshot");
    assert_eq!(
        world
            .runtime
            .store()
            .snapshot(&task)
            .expect("snapshot after recovery"),
        before_replay,
        "owner replay must keep one consistent snapshot"
    );
    let counts_after_replay = durable_counts(&world);
    assert_eq!(
        counts_after_replay, counts_before_replay,
        "recovery must not dispatch or create another durable attempt"
    );
    assert_eq!(world.worker_reads(), 1, "recovery replays no effect");
    let mut conflicting = events[0].clone();
    conflicting.delta = json!({ "conflict": true });
    assert!(matches!(
        world
            .runtime
            .store_writer()
            .recover_events(&session, &[conflicting]),
        Err(rivect::state::StoreError::Conflict(
            rivect::state::ConflictCause::EventConflict { .. }
        ))
    ));

    // Safe reconciliation from the durable marker: the read really happened,
    // so the attempt confirms without a second worker read, every obligation
    // completes on the real digest, and executed=false cannot reject a
    // proven read.
    let before_reads = world.worker_reads();
    let before_provider_calls = world
        .provider_calls
        .load(std::sync::atomic::Ordering::SeqCst);
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
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        before_provider_calls,
        "reconciliation re-dispatches no provider effect"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .attempt_state(&attempt_id)
            .ok()
            .flatten(),
        Some("confirmed".to_string()),
        "executed=false must not reject a marker that proves execution"
    );
    let snapshot = world
        .runtime
        .store()
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
        .store()
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
    // A repeated reconcile of the settled attempt fails closed.
    let repeated = world
        .runtime
        .reconcile_unknown(&session, &task, &attempt_id, true);
    assert!(
        repeated.is_err(),
        "a settled attempt cannot reconcile twice"
    );

    // Client projection still ignores duplicate/out-of-order notifications.
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
    freeze_answered(
        &mut world,
        &session,
        &task2,
        &question2,
        answer_custom(&format!("read {}", file.display())),
    );
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
fn post_confirmation_duplicate_identity_is_scoped_to_command() {
    let (mut world, _scope, file, grant) = scoped_world(
        "post-confirmation-dedupe",
        Some(&support::config_distinct_pools()),
    );
    let session = world.open_session("bootstrap-post-confirmation-dedupe");
    let task = world.create_task(&session, "cmd-post-confirmed-1");
    let question = world.publish(&session, &task);
    let answer = world.dispatch(&corpus_answer_custom(
        &session,
        "cmd-post-confirmed-answer-1",
        &task,
        &question,
        &format!("read {}", file.display()),
        json!(80),
    ));
    assert!(answer["error"].is_null(), "{answer}");
    let first = world
        .runtime
        .run_decision_step(
            &session,
            &task,
            &answer_custom(&format!("read {}", file.display())),
            &grant,
            false,
        )
        .expect("first confirmation");
    match first {
        rivect::controller::StepOutcome::NoAction { snapshot } => {
            assert_eq!(snapshot.lifecycle, Lifecycle::Completed);
        }
        other => panic!("answer drain must have completed the task, got {other:?}"),
    }
    assert_eq!(world.worker_reads(), 1);
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    let replay = world.dispatch(&corpus_create(&session, "cmd-post-confirmed-1"));
    assert!(replay["error"].is_null(), "{replay}");
    assert_eq!(replay["result"]["task_id"], task.0);
    assert_eq!(
        world.worker_reads(),
        1,
        "same command id must replay receipt"
    );
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "same command id must not dispatch again"
    );

    let task2 = world.create_task(&session, "cmd-post-confirmed-2");
    assert_ne!(task2, task, "new command must create a distinct task");
    let question2 = world.publish(&session, &task2);
    let answer2 = world.dispatch(&corpus_answer_custom(
        &session,
        "cmd-post-confirmed-answer-2",
        &task2,
        &question2,
        &format!("read {}", file.display()),
        json!(81),
    ));
    assert!(answer2["error"].is_null(), "{answer2}");
    let second = world
        .runtime
        .run_decision_step(
            &session,
            &task2,
            &answer_custom(&format!("read {}", file.display())),
            &grant,
            false,
        )
        .expect("second confirmation");
    match second {
        rivect::controller::StepOutcome::NoAction { snapshot } => {
            assert_eq!(snapshot.lifecycle, Lifecycle::Completed);
        }
        other => panic!("answer drain must have completed the new task, got {other:?}"),
    }
    assert_eq!(
        world.worker_reads(),
        2,
        "new command must perform own effect"
    );
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        2,
        "new command must dispatch own effect"
    );
}

#[test]
fn unknown_without_safe_read_stays_blocked() {
    let (mut world, _scope, file, grant) = scoped_world(
        "unknown-no-safe-read",
        Some(&support::config_distinct_pools()),
    );
    let session = world.open_session("bootstrap-unknown-no-safe-read");
    let task = world.create_task(&session, "cmd-unknown-no-safe-read");
    let question = world.publish(&session, &task);
    freeze_answered(
        &mut world,
        &session,
        &task,
        &question,
        answer_custom(&format!("read {}", file.display())),
    );

    let unknown = world
        .runtime
        .run_decision_step(
            &session,
            &task,
            &answer_custom(&format!("read {}", file.display())),
            &grant,
            true,
        )
        .expect("unconfirmed read");
    let rivect::controller::StepOutcome::OutcomeUnknown {
        attempt_id,
        snapshot,
    } = unknown
    else {
        panic!("expected unknown outcome");
    };
    assert_eq!(snapshot.lifecycle, Lifecycle::Blocked);
    assert_eq!(
        world.worker_reads(),
        1,
        "unconfirmed path performs one read"
    );
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "unconfirmed path dispatches once"
    );
    let (_, state, detail) = world
        .runtime
        .store()
        .attempt_record(&attempt_id)
        .expect("attempt record")
        .expect("unconfirmed attempt");
    assert_eq!(state, "unknown");
    assert!(
        detail
            .as_deref()
            .is_some_and(|value| value.starts_with("read-performed sha256=")),
        "unconfirmed effect must initially retain its read marker"
    );

    // Corrupt the durable receipt after the real effect, so reconciliation
    // cannot establish whether the read completed.
    world
        .runtime
        .store_writer()
        .attempt_unknown(&attempt_id, "receipt lost before safe read")
        .expect("corrupt read marker");
    let before_reads = world.worker_reads();
    let before_provider_calls = world
        .provider_calls
        .load(std::sync::atomic::Ordering::SeqCst);
    let error = world
        .runtime
        .reconcile_unknown(&session, &task, &attempt_id, true)
        .expect_err("safe read without marker must remain unknown");
    assert!(matches!(
        error,
        rivect::state::StoreError::InvalidInput(
            rivect::state::InvalidCause::MissingReadMarker { .. }
        )
    ));
    let snapshot = world.runtime.store().snapshot(&task).expect("snapshot");
    assert_eq!(snapshot.lifecycle, Lifecycle::Blocked);
    assert!(
        snapshot
            .blockers
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .any(|blocker| { blocker.reason == rivect::contracts::ErrorCode::OutcomeUnknown })
    );
    let duplicate = world
        .runtime
        .run_decision_step(
            &session,
            &task,
            &answer_custom(&format!("read {}", file.display())),
            &grant,
            false,
        )
        .expect("unknown guard");
    let rivect::controller::StepOutcome::OutcomeUnknown {
        attempt_id: retained_attempt,
        snapshot: retained_snapshot,
    } = duplicate
    else {
        panic!("missing marker must keep the task unknown");
    };
    assert_eq!(retained_attempt, attempt_id);
    assert_eq!(retained_snapshot.lifecycle, Lifecycle::Blocked);
    assert_eq!(world.worker_reads(), before_reads, "no second safe read");
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        before_provider_calls,
        "blocked unknown task does not dispatch again"
    );
}

/// A fixed-option answer names the one permitted read itself — no model
/// attempt exists to carry retention, so the effect attempt owns the
/// pre-effect record. A crash between dispatch and confirmation leaves
/// that record parseable at `PreEffect`, never silently absent.
#[test]
fn option_answer_crash_retains_the_effect_attempts_pre_effect_record() {
    let (mut world, _scope, file, grant) = scoped_world(
        "option-crash-pre-effect",
        Some(&support::config_distinct_pools()),
    );
    let session = world.open_session("bootstrap-option-crash");
    let task = world.create_task(&session, "cmd-option-crash");
    let question = world.publish(&session, &task);
    let option = AnswerSelection::Option {
        option_id: OptionId("brief".to_string()),
    };
    freeze_answered(&mut world, &session, &task, &question, option.clone());

    let outcome = world
        .runtime
        .run_decision_step(&session, &task, &option, &grant, true)
        .expect("crash step");
    let rivect::controller::StepOutcome::OutcomeUnknown {
        attempt_id,
        snapshot,
    } = outcome
    else {
        panic!("expected unknown outcome");
    };
    assert_eq!(snapshot.lifecycle, Lifecycle::Blocked);
    assert_eq!(
        world.worker_reads(),
        1,
        "the crash path performs exactly one real worker read"
    );
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a fixed option never reaches the provider"
    );
    let retained = world
        .runtime
        .store()
        .retained(&rivect::verification::boundary_id(&attempt_id))
        .expect("retained")
        .expect("the effect attempt's retained record exists");
    let parsed_retained: rivect::verification::RetainedAttempt =
        serde_json::from_str(&retained).expect("retained record parses");
    assert_eq!(parsed_retained.attempt_id, attempt_id);
    assert_eq!(
        parsed_retained.stage,
        rivect::verification::RetainedStage::PreEffect,
        "the option-admitted effect attempt retains its pre-effect record"
    );
    assert_eq!(parsed_retained.cause, "fixed option admitted read");
    assert!(file.exists());
}

#[test]
fn blocked_task_stays_blocked_after_neighbor_completes() {
    let (mut world, _scope, _file, _grant) =
        scoped_world("blocked-neighbor", Some(&support::config_distinct_pools()));
    let session = world.open_session("bootstrap-blocked-neighbor");
    let blocked = world.create_task(&session, "cmd-blocked-neighbor");
    world
        .runtime
        .store_writer()
        .materialize_obligations(&blocked)
        .expect("materialize blocked obligation");
    let attempt = world
        .runtime
        .store_writer()
        .plan_attempt(
            &blocked,
            rivect::contracts::EffectClass::Read,
            "read allowed file",
        )
        .expect("plan unknown attempt");
    world
        .runtime
        .store_writer()
        .attempt_unknown(&attempt, "receipt lost")
        .expect("persist unknown attempt");
    world
        .runtime
        .store_writer()
        .mark_outcome_unknown(&blocked)
        .expect("block unknown task");

    let blocked_before = world.dispatch(&json!({
        "jsonrpc": "2.0",
        "id": 70,
        "method": "task.snapshot",
        "params": { "schema_version": 1, "session_id": session.0, "task_id": blocked.0 }
    }));
    assert_eq!(blocked_before["result"]["lifecycle"], "blocked");
    assert_eq!(
        blocked_before["result"]["blockers"][0]["reason"],
        "outcome_unknown"
    );
    assert_eq!(
        blocked_before["result"]["obligations"]["items"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );

    let second_attempt = world
        .runtime
        .store_writer()
        .plan_attempt(
            &blocked,
            rivect::contracts::EffectClass::Read,
            "read allowed file from second attempt",
        )
        .expect("plan sibling attempt on the same obligation");
    world
        .runtime
        .store_writer()
        .attempt_confirmed(&second_attempt)
        .expect("complete sibling attempt");

    let blocked_after = world.dispatch(&json!({
        "jsonrpc": "2.0",
        "id": 72,
        "method": "task.snapshot",
        "params": { "schema_version": 1, "session_id": session.0, "task_id": blocked.0 }
    }));
    assert_eq!(blocked_after["result"]["lifecycle"], "blocked");
    assert_eq!(
        blocked_after["result"]["blockers"][0]["reason"],
        "outcome_unknown"
    );
    assert_eq!(
        blocked_after["result"]["revision"],
        blocked_before["result"]["revision"]
    );
    let attempts = blocked_after["result"]["attempts"]["items"]
        .as_array()
        .expect("same task attempts");
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0]["attempt_id"].as_str(), Some(attempt.as_str()));
    assert_eq!(attempts[0]["state"], "unknown");
    assert_eq!(
        attempts[1]["attempt_id"].as_str(),
        Some(second_attempt.as_str())
    );
    assert_eq!(attempts[1]["state"], "confirmed");
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

    // The answer drain already completed the task, so cancel is already_terminal.
    let cancel = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 41, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-cancel-1", "session_id": session.0,
                    "kind": "cancel", "task_id": task.0, "expected_intent_revision": 1, "reason": "стоп" }
    }));
    assert!(cancel["error"].is_null(), "{cancel}");
    assert_eq!(cancel["result"]["status"], "already_terminal");
    let outcome = world
        .runtime
        .run_decision_step(
            &session,
            &task,
            &answer_custom(&format!("read {}", file.display())),
            &grant,
            false,
        )
        .expect("terminal step");
    match outcome {
        rivect::controller::StepOutcome::NoAction { snapshot } => {
            assert_eq!(snapshot.lifecycle, Lifecycle::Completed);
        }
        other => panic!("drained task must stay terminal, got {other:?}"),
    }
    let after_drain_calls = world
        .provider_calls
        .load(std::sync::atomic::Ordering::SeqCst);
    let after_drain_reads = world.worker_reads();
    assert_eq!(after_drain_calls, 1, "answer drain dispatched once");
    assert_eq!(
        after_drain_reads, 1,
        "answer drain performed one scoped read"
    );

    // Cancel blocks the next dispatch of a live task before the provider effect.
    let live = world.create_task(&session, "cmd-cancel-live-task");
    let live_question = world.publish(&session, &live);
    freeze_answered(
        &mut world,
        &session,
        &live,
        &live_question,
        answer_custom(&format!("read {}", file.display())),
    );
    let cancel_live = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 42, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-cancel-live", "session_id": session.0,
                    "kind": "cancel", "task_id": live.0, "expected_intent_revision": 1, "reason": "стоп" }
    }));
    assert!(cancel_live["error"].is_null(), "{cancel_live}");
    assert_eq!(cancel_live["result"]["status"], "applied");
    let cancelled = world
        .runtime
        .run_decision_step(
            &session,
            &live,
            &answer_custom(&format!("read {}", file.display())),
            &grant,
            false,
        )
        .expect("cancelled step");
    match cancelled {
        rivect::controller::StepOutcome::NoAction { snapshot } => {
            assert_eq!(snapshot.lifecycle, Lifecycle::Cancelled);
        }
        other => panic!("cancelled task must not dispatch, got {other:?}"),
    }
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        after_drain_calls,
        "cancel must not dispatch"
    );

    // Revoke blocks the next dispatch of a live task.
    let task2 = world.create_task(&session, "cmd-revoke-2");
    let question2 = world.publish(&session, &task2);
    freeze_answered(
        &mut world,
        &session,
        &task2,
        &question2,
        answer_custom(&format!("read {}", file.display())),
    );
    world.runtime.policy_writer().revoke(&grant);
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
    assert!(
        matches!(
            err,
            rivect::controller::ControllerError::Policy(
                rivect::policy::PolicyError::Revoked { .. }
            )
        ),
        "{err}"
    );
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        after_drain_calls,
        "revoked scope must not dispatch"
    );
    assert_eq!(
        world.worker_reads(),
        after_drain_reads,
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
        .store()
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
    let too_many_criteria = vec!["c"; rivect::contracts::ARRAY_MAX_ITEMS + 1];
    let too_many = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 52, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-too-many", "session_id": session.0,
                    "kind": "create", "goal": "bounded contract",
                    "contract": { "criteria": too_many_criteria, "constraints": [] } }
    }));
    assert_eq!(too_many["error"]["data"]["code"], "invalid_input");
    let non_string_criteria = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 53, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": "cmd-non-string-criteria",
            "session_id": session.0, "kind": "create", "goal": "invalid criteria",
            "contract": { "criteria": ["ok", 7], "constraints": [] }
        }
    }));
    assert_eq!(
        non_string_criteria["error"]["data"]["code"],
        "invalid_input"
    );
    let non_array_constraints = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 54, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": "cmd-non-array-constraints",
            "session_id": session.0, "kind": "create", "goal": "invalid constraints",
            "contract": { "criteria": [], "constraints": "text" }
        }
    }));
    assert_eq!(
        non_array_constraints["error"]["data"]["code"],
        "invalid_input"
    );
    assert_eq!(
        world.dispatch(&corpus_status(&session))["result"]["tasks"]["items"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );

    let exact_criteria = vec!["c"; rivect::contracts::ARRAY_MAX_ITEMS];
    let exactly_bounded = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 55, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-exact-bound", "session_id": session.0,
                    "kind": "create", "goal": "bounded contract",
                    "contract": { "criteria": exact_criteria, "constraints": [] } }
    }));
    assert!(exactly_bounded["error"].is_null(), "{exactly_bounded}");
    let bounded_task = rivect::contracts::TaskId(
        exactly_bounded["result"]["task_id"]
            .as_str()
            .expect("bounded task")
            .to_string(),
    );
    let bounded_question = world.publish(&session, &bounded_task);
    let snapshot_before_answer = world
        .runtime
        .store()
        .snapshot(&bounded_task)
        .expect("snapshot before oversized answer");
    let oversized_answer = world.dispatch(&corpus_answer_custom(
        &session,
        "cmd-oversized-answer",
        &bounded_task,
        &bounded_question,
        &"x".repeat(rivect::contracts::TEXT_MAX_BYTES + 1),
        json!(54),
    ));
    assert_eq!(oversized_answer["error"]["data"]["code"], "invalid_input");
    assert_eq!(
        oversized_answer["error"]["data"]["message"],
        format!(
            "custom text exceeds {} bytes",
            rivect::contracts::TEXT_MAX_BYTES
        )
    );
    assert_eq!(
        world
            .runtime
            .store()
            .snapshot(&bounded_task)
            .expect("snapshot after oversized answer"),
        snapshot_before_answer
    );

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
    let world_id = world.runtime.scope_root.display().to_string();
    let manifest = world
        .runtime
        .broker
        .prepare(
            "backend_task",
            &world.runtime.config_for_broker(),
            &world_id,
            "goal: probe",
        )
        .expect("manifest prepared");
    // The manifest is bound to the execution world of its sources and
    // proofs (AC-013) and carries a context epoch (AC-061 contribution).
    assert_eq!(manifest.world, world_id);
    assert!(manifest.epoch_id.starts_with("epoch-"));
    assert_eq!(manifest.mutation_reason, None);
    let frozen = manifest.clone();
    // The user now switches the config to a subscription pin without grant.
    std::fs::write(
        world.root.join("config.toml"),
        support::config_distinct_pools_with_manual_subscription(),
    )
    .expect("config change");
    world
        .runtime
        .reload_config()
        .expect("the owner reloads the changed config");
    assert!(
        world
            .runtime
            .effective()
            .parsed
            .as_ref()
            .is_some_and(|config| {
                config.connections.contains_key("subscription")
                    && config.connections.contains_key("local")
            }),
        "the owner observes both the new pin and the frozen connection"
    );
    // Dispatch still sends exactly the frozen manifest; the provider records
    // it verbatim, purpose and every field included.
    let reply = world
        .runtime
        .broker
        .dispatch(&world_id, &manifest)
        .expect("dispatch frozen manifest");
    assert!(!reply.text.is_empty());
    let recorded = world
        .last_manifest()
        .expect("provider recorded the manifest");
    assert_eq!(
        recorded, frozen,
        "provider must receive the exact frozen manifest"
    );
    // The frozen manifest cannot be replayed from another execution
    // world, even under the changed config (AC-013).
    let foreign = world.runtime.broker.dispatch("/world/foreign", &manifest);
    assert!(
        matches!(
            foreign,
            Err(rivect::model::ModelError::WorldMismatch { .. })
        ),
        "a foreign-world dispatch must reject"
    );
    // A new prepare under the changed config is capability-unavailable.
    let denied = world.runtime.broker.prepare(
        "main",
        &world.runtime.config_for_broker(),
        &world_id,
        "goal: probe",
    );
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
    freeze_answered(
        &mut world,
        &session,
        &task,
        &question,
        answer_custom(&format!("read {}", file.display())),
    );
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
        .store()
        .events_after(&session, None, 0, 0)
        .is_ok();
    assert!(evidence);
    let snapshot_before = world.runtime.store().snapshot(&task).expect("snapshot");
    let obligations = &snapshot_before.obligations.items;
    assert_eq!(obligations.len(), 2);
    assert!(
        obligations
            .iter()
            .all(|o| o.execution == rivect::contracts::ObligationExecution::Satisfied)
    );
    let second_evidence = world
        .runtime
        .store_writer()
        .insert_evidence(&task, 1, "task:probe", "extra basis", "probe-digest")
        .expect("second evidence");
    let blocked_task = world
        .runtime
        .store_writer()
        .invalidate_evidence(&second_evidence)
        .expect("invalidate");
    assert_eq!(blocked_task, task.0);
    let blocked = world.runtime.store().snapshot(&task).expect("snapshot");
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
        .store_writer()
        .complete_if_eligible(&session, &task)
        .expect_err("completion must be rejected");
    assert!(
        matches!(
            err,
            rivect::state::StoreError::Conflict(
                rivect::state::ConflictCause::CompletionOpen { unresolved, .. }
            ) if unresolved > 0
        ),
        "{err}"
    );
    let after = world.runtime.store().snapshot(&task).expect("snapshot");
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

const TUI_ROWS: usize = 24;
const TUI_COLS: usize = 80;

fn wait_for_visible_tui_text(
    pty: &support::PtySession,
    needle: &str,
    timeout: Duration,
) -> Result<String, support::PtyIoError> {
    support::wait_for_screen_text(pty, TUI_ROWS, TUI_COLS, needle, timeout)
}

#[test]
fn tui_enter_dispatches_tasks_and_help() {
    let mut pty = spawn_pty(&rivect_binary(), TUI_ROWS as u16, TUI_COLS as u16);
    assert!(
        pty.wait_for(b"\x1b[?1049h", Duration::from_secs(10))
            .expect("pty read"),
        "alternate screen must be entered on start"
    );
    pty.send(b"\r/help\r").expect("pty send");
    let visible =
        wait_for_visible_tui_text(&pty, "Commands:", Duration::from_secs(10)).expect("pty screen");
    assert!(
        visible.contains("Commands:"),
        "Enter on /help must show help through the fullscreen entry path: {visible:?}"
    );
    assert!(
        !visible.contains("q quits when composer is empty"),
        "help must not advertise empty-composer q quit: {visible:?}"
    );
    assert!(
        !visible.contains("Submitted task:"),
        "empty Enter and /help must not create a task: {visible:?}"
    );

    pty.send(b"task from q\r").expect("pty send");
    let visible = wait_for_visible_tui_text(
        &pty,
        "Submitted task: task from q (accepted: ",
        Duration::from_secs(10),
    )
    .expect("pty screen");
    assert!(
        visible.contains("Submitted task: task from q (accepted: "),
        "non-empty Enter must show the accepted task receipt: {visible:?}"
    );
    assert!(
        visible.contains(": running"),
        "task dock must show accepted work: {visible:?}"
    );
    pty.send(b"\x1b").expect("pty send");
    assert_eq!(
        pty.wait_exit(Duration::from_secs(10)).expect("pty wait"),
        Some(0)
    );
    pty.finish().expect("pty teardown");
}

#[test]
fn tui_lowercase_q_starts_composer_and_dispatches_exact_goal() {
    let mut pty = spawn_pty(&rivect_binary(), TUI_ROWS as u16, TUI_COLS as u16);
    assert!(
        pty.wait_for(b"\x1b[?1049h", Duration::from_secs(10))
            .expect("pty read"),
        "alternate screen must be entered on start"
    );

    pty.send(b"q").expect("pty send");
    let visible =
        wait_for_visible_tui_text(&pty, "> q", Duration::from_secs(10)).expect("pty screen");
    assert!(
        visible.contains("> q"),
        "first lowercase q must remain in composer while TUI runs: {visible:?}"
    );

    pty.send(b"uery the root\r").expect("pty send");
    let visible = wait_for_visible_tui_text(
        &pty,
        "Submitted task: query the root (accepted: ",
        Duration::from_secs(10),
    )
    .expect("pty screen");
    assert!(
        visible.contains("Submitted task: query the root (accepted: "),
        "TUI must dispatch exact goal after q-first input: {visible:?}"
    );

    pty.send(b"\x1b").expect("pty send");
    assert_eq!(
        pty.wait_exit(Duration::from_secs(10)).expect("pty wait"),
        Some(0)
    );

    let db_path = pty.data_root().join("runtime").join("rivect.db");
    let conn = rusqlite::Connection::open(&db_path).expect("open TUI runtime database");
    let goal: Vec<u8> = conn
        .query_row(
            "SELECT goal_bytes FROM tasks WHERE goal_bytes = ?1",
            rusqlite::params![b"query the root".to_vec()],
            |row| row.get(0),
        )
        .expect("query persisted TUI goal");
    assert_eq!(
        goal.as_slice(),
        b"query the root",
        "TUI dispatch must persist exact goal bytes"
    );
    drop(conn);
    pty.finish().expect("pty teardown");
}

#[test]
fn tui_bracketed_paste_fills_the_composer_without_submitting() {
    let mut pty = spawn_pty(&rivect_binary(), TUI_ROWS as u16, TUI_COLS as u16);
    assert!(
        pty.wait_for(b"\x1b[?1049h", Duration::from_secs(10))
            .expect("pty read"),
        "alternate screen must be entered on start"
    );

    // One atomic paste event: the pasted newline joins the draft as a
    // space — it must not submit the way the raw byte stream's `\n`
    // did before bracketed paste.
    pty.send("\x1b[200~multi line\npaste goal\x1b[201~".as_bytes())
        .expect("pty send");
    let visible =
        wait_for_visible_tui_text(&pty, "> multi line paste goal", Duration::from_secs(10))
            .expect("pty screen");
    assert!(
        visible.contains("> multi line paste goal"),
        "the pasted text reaches the composer draft: {visible:?}"
    );
    assert!(
        !visible.contains("Submitted task:"),
        "a pasted newline never submits: {visible:?}"
    );

    // Only a real Enter submits — and it submits the joined draft
    // verbatim.
    pty.send(b"\r").expect("pty send");
    let visible = wait_for_visible_tui_text(
        &pty,
        "Submitted task: multi line paste goal (accepted: ",
        Duration::from_secs(10),
    )
    .expect("pty screen");
    assert!(
        visible.contains("Submitted task: multi line paste goal"),
        "the joined draft is the submitted goal: {visible:?}"
    );

    pty.send(b"\x1b").expect("pty send");
    assert_eq!(
        pty.wait_exit(Duration::from_secs(10)).expect("pty wait"),
        Some(0)
    );
    pty.finish().expect("pty teardown");
}

#[test]
fn tui_char_chords_never_type_their_letter_into_the_composer() {
    let mut pty = spawn_pty(&rivect_binary(), TUI_ROWS as u16, TUI_COLS as u16);
    assert!(
        pty.wait_for(b"\x1b[?1049h", Duration::from_secs(10))
            .expect("pty read"),
        "alternate screen must be entered on start"
    );

    // A Ctrl or Alt chord is a command the composer does not bind:
    // its letter must never land in the draft (Ctrl+W is not "w").
    // `\x17` is the Ctrl+W byte; `ESC`+`v` in one write merges into a
    // single Alt+V event, the same merge `\x1b\r` makes.
    pty.send(b"\x17").expect("pty send");
    pty.send(b"\x1bv").expect("pty send");
    pty.send(b"x").expect("pty send");
    let visible =
        wait_for_visible_tui_text(&pty, "> x", Duration::from_secs(10)).expect("pty screen");
    assert!(
        visible.contains("> x"),
        "the bare char lands and neither chord typed its letter: {visible:?}"
    );
    assert!(
        !visible.contains("wvx"),
        "a chord must not type its letter: {visible:?}"
    );

    // The draft is exactly the bare char — Enter submits it verbatim.
    pty.send(b"\r").expect("pty send");
    let visible = wait_for_visible_tui_text(&pty, "Submitted task: x (", Duration::from_secs(10))
        .expect("pty screen");
    assert!(
        visible.contains("Submitted task: x ("),
        "the composer held exactly the typed char: {visible:?}"
    );

    pty.send(b"\x1b").expect("pty send");
    assert_eq!(
        pty.wait_exit(Duration::from_secs(10)).expect("pty wait"),
        Some(0)
    );
    pty.finish().expect("pty teardown");
}

#[test]
fn tui_data_root_flag_overrides_environment() {
    let root = tempfile::TempDir::with_prefix("rivect-tui-flag-").expect("tui flag root");
    let flag_root = root.path().join("flag");
    let env_root = root.path().join("env");
    std::fs::create_dir_all(&flag_root).expect("flag root");
    std::fs::create_dir_all(&env_root).expect("env root");
    let flag_text = flag_root.to_string_lossy().to_string();
    let mut pty = support::spawn_pty_with_args(
        &rivect_binary(),
        24,
        80,
        root,
        &flag_root,
        &env_root,
        &["--data-root", &flag_text],
    );
    assert!(
        pty.wait_for(b"\x1b[?1049h", Duration::from_secs(10))
            .expect("pty read"),
        "TUI must start"
    );
    pty.send(b"p\r").expect("pty send");
    pty.pump_for(Duration::from_secs(2)).expect("pty pump");
    pty.send(b"\x1b").expect("pty send");
    let exit = pty.wait_exit(Duration::from_secs(10)).expect("pty wait");
    assert_eq!(exit, Some(0), "TUI must exit cleanly");
    assert!(
        flag_root.join("runtime").join("rivect.db").exists(),
        "TUI must use --data-root"
    );
    assert!(
        !env_root.join("runtime").exists(),
        "TUI must not use RIVECT_DATA_ROOT when flag is present"
    );
    pty.finish().expect("pty teardown");

    let env_only_root =
        tempfile::TempDir::with_prefix("rivect-tui-env-only-").expect("tui env-only root");
    let env_only_path = env_only_root.path().to_path_buf();
    let mut env_only = support::spawn_pty_with_args(
        &rivect_binary(),
        24,
        80,
        env_only_root,
        &env_only_path,
        &env_only_path,
        &[],
    );
    assert!(
        env_only
            .wait_for(b"\x1b[?1049h", Duration::from_secs(10))
            .expect("pty read"),
        "TUI must start without --data-root"
    );
    env_only.send(b"p\r").expect("pty send");
    env_only.pump_for(Duration::from_secs(2)).expect("pty pump");
    env_only.send(b"\x1b").expect("pty send");
    assert_eq!(
        env_only
            .wait_exit(Duration::from_secs(10))
            .expect("pty wait"),
        Some(0)
    );
    assert!(
        env_only_path.join("runtime").join("rivect.db").exists(),
        "TUI without flag must use RIVECT_DATA_ROOT"
    );
    env_only.finish().expect("pty teardown");
}

#[test]
fn tui_fullscreen_restore() {
    let mut pty = spawn_pty(&rivect_binary(), 24, 80);
    assert!(
        pty.wait_for(b"\x1b[?1049h", Duration::from_secs(10))
            .expect("pty read"),
        "alternate screen must be entered on start; got {:?}",
        String::from_utf8_lossy(&pty.collected().expect("pty read"))
    );
    pty.send(b"\x1b").expect("pty send");
    let code = pty.wait_exit(Duration::from_secs(10)).expect("pty wait");
    assert_eq!(code, Some(0), "normal quit exits 0");
    let stream = pty.collected().expect("pty read");
    assert!(
        support::find_subsequence(&stream, b"\x1b[?1049l").is_some(),
        "alt screen must be left"
    );
    assert!(
        support::find_subsequence(&stream, b"\x1b[?25h").is_some(),
        "cursor must be visible again"
    );
    pty.finish().expect("pty teardown");
}

#[test]
fn tui_error_restores_terminal() {
    let root = tempfile::TempDir::with_prefix("rivect-pty-error-").expect("pty error root");
    let data_root = root.path().join("root-file");
    std::fs::write(&data_root, b"not a directory").expect("root file");
    let mut pty =
        support::spawn_pty_with_args(&rivect_binary(), 24, 80, root, &data_root, &data_root, &[]);

    assert!(
        pty.wait_for(b"\x1b[?1049h", Duration::from_secs(10))
            .expect("pty read"),
        "alternate screen must be entered on start"
    );
    pty.send(b"a\r").expect("pty send");
    assert_eq!(
        pty.wait_exit(Duration::from_secs(10)).expect("pty wait"),
        Some(1)
    );
    std::hint::black_box(
        pty.wait_for(b"\x1b[?1049l", Duration::from_secs(2))
            .expect("pty read"),
    );
    let stream = pty.collected().expect("pty read");
    assert!(
        support::find_subsequence(&stream, b"\x1b[?1049l").is_some(),
        "open error must leave alternate screen"
    );
    assert!(
        support::find_subsequence(&stream, b"\x1b[?25h").is_some(),
        "open error must show cursor"
    );
    pty.finish().expect("pty teardown");
}

#[test]
fn tui_mouse_off_default() {
    let mut pty = spawn_pty(&rivect_binary(), 24, 80);
    assert!(
        pty.wait_for(b"\x1b[?1049h", Duration::from_secs(10))
            .expect("pty read"),
        "alternate screen must be entered on start"
    );
    let stream = pty.collected().expect("pty read");
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
    pty.send(&[0x03]).expect("pty send");
    let code = pty.wait_exit(Duration::from_secs(10)).expect("pty wait");
    assert_eq!(code, Some(130), "cancel exits 130");
    let stream = pty.collected().expect("pty read");
    assert!(support::find_subsequence(&stream, b"\x1b[?1049l").is_some());
    assert!(support::find_subsequence(&stream, b"\x1b[?25h").is_some());
    pty.finish().expect("pty teardown");
}

/// An obviously fake provider key: it exists only so the allowlist proof
/// below has a credential-shaped variable to keep out of PTY children.
const FAKE_PROVIDER_KEY: &str = "rivect-fake-provider-key-not-a-credential";

#[test]
fn pty_wrappers_pass_only_the_allowlist_and_fixture_input() {
    let mut command = std::process::Command::new(std::env::current_exe().expect("current exe"));
    command
        .args([
            "pty_env_probe_child",
            "--exact",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "--color",
            "never",
        ])
        .env_clear();
    for key in support::PTY_ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command.env("OPENAI_API_KEY", FAKE_PROVIDER_KEY);
    let result = command.output();
    let output = match result {
        Ok(output) => output,
        Err(error) => panic!("the pty env probe intermediate did not run: {error}"),
    };
    assert!(
        output.status.success(),
        "the pty env probe intermediate failed: {}",
        output.status
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout
            .lines()
            .any(|line| line == "test pty_env_probe_child ... ok"),
        "the probe did not report ok ({})",
        output.status
    );
    let results: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("test result: "))
        .collect();
    assert_eq!(
        results.len(),
        1,
        "the probe run must print exactly one result line"
    );
    assert!(
        results[0].starts_with("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "),
        "the probe result line is not the single success ({})",
        output.status
    );
}

#[test]
#[ignore = "pty env probe child: its parent spawns it with the fake key"]
fn pty_env_probe_child() {
    assert!(
        std::env::var_os("OPENAI_API_KEY").is_some_and(|value| value == FAKE_PROVIDER_KEY),
        "the probe needs the fixture OPENAI_API_KEY from its parent"
    );
    let root = tempfile::TempDir::with_prefix("rivect-pty-env-").expect("pty env root");
    let data = root.path().join("data");
    std::fs::create_dir_all(&data).expect("data dir");
    let mut pty = support::spawn_pty_with_args(
        "/usr/bin/env",
        TUI_ROWS as u16,
        TUI_COLS as u16,
        root,
        &data,
        &data,
        &[],
    );
    assert_eq!(
        pty.wait_exit(Duration::from_secs(10)).expect("pty wait"),
        Some(0)
    );
    let stream = pty.collected().expect("pty read");
    let expected = format!("RIVECT_DATA_ROOT={}", data.display());
    assert!(
        support::find_subsequence(&stream, expected.as_bytes()).is_some(),
        "the pty child must see RIVECT_DATA_ROOT"
    );
    assert!(
        support::find_subsequence(&stream, b"OPENAI_API_KEY").is_none(),
        "the pty child must not inherit OPENAI_API_KEY"
    );
    pty.finish().expect("pty teardown");
}

#[test]
fn headless_non_tty_machine_surface() {
    use std::io::Write;
    let mut data_root = tempfile::TempDir::with_prefix("rivect-headless-").expect("fixture root");
    let spawned = std::process::Command::new(rivect_binary())
        .arg("--headless")
        .arg("--data-root")
        .arg(data_root.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();
    if spawned.is_err() {
        support::retain_root(&mut data_root);
    }
    let mut child = spawned.expect("spawn headless");
    let request = json!({
        "jsonrpc": "2.0", "id": 1, "method": "session.open",
        "params": { "schema_version": 1, "bootstrap_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1" }
    });
    let wrote = child.stdin.take().map(|mut stdin| {
        writeln!(stdin, "{request}")?;
        stdin.flush()
    });
    let waited = child.wait_with_output();
    if !matches!(wrote, Some(Ok(()))) || waited.is_err() {
        support::retain_root(&mut data_root);
    }
    wrote.expect("stdin").expect("write request");
    let output = waited.expect("wait");
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
fn headless_config_error_names_path_and_stage() {
    let mut data_root =
        tempfile::TempDir::with_prefix("rivect-config-error-path-").expect("fixture root");
    std::fs::write(data_root.path().join("config.toml"), "[workflow\n").expect("invalid config");
    let output = std::process::Command::new(rivect_binary())
        .arg("--headless")
        .arg("--data-root")
        .arg(data_root.path())
        .output();
    if output.is_err() {
        support::retain_root(&mut data_root);
    }
    let output = output.expect("run headless");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let path_text = data_root
        .path()
        .join("config.toml")
        .to_string_lossy()
        .to_string();
    let expected_prefix =
        format!("runtime open failed: owner configuration failed: {path_text}: parse: ");
    assert!(
        stderr.trim_end().starts_with(&expected_prefix),
        "owner/config/parse chain must name path and stage: {stderr}"
    );
}

#[test]
fn headless_rejects_oversized_config() {
    let mut data_root =
        tempfile::TempDir::with_prefix("rivect-config-oversized-").expect("fixture root");
    std::fs::write(
        data_root.path().join("config.toml"),
        vec![b'x'; rivect::contracts::REQUEST_MAX_BYTES + 1],
    )
    .expect("oversized config");
    let output = std::process::Command::new(rivect_binary())
        .arg("--headless")
        .arg("--data-root")
        .arg(data_root.path())
        .output();
    if output.is_err() {
        support::retain_root(&mut data_root);
    }
    let output = output.expect("run headless");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "configuration exceeds {} bytes",
            rivect::contracts::REQUEST_MAX_BYTES
        )),
        "oversized config must expose typed limit: {stderr}"
    );
}

#[test]
fn headless_rejects_oversized_stdin_frame() {
    use std::io::Write;
    let mut data_root =
        tempfile::TempDir::with_prefix("rivect-headless-oversized-").expect("fixture root");
    let spawned = std::process::Command::new(rivect_binary())
        .arg("--headless")
        .arg("--data-root")
        .arg(data_root.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();
    if spawned.is_err() {
        support::retain_root(&mut data_root);
    }
    let mut child = spawned.expect("spawn headless");
    let mut input = vec![b'x'; rivect::contracts::REQUEST_MAX_BYTES + 1];
    input.push(b'\n');
    let wrote = child.stdin.take().map(|mut stdin| stdin.write_all(&input));
    let waited = child.wait_with_output();
    if !matches!(wrote, Some(Ok(()))) || waited.is_err() {
        support::retain_root(&mut data_root);
    }
    wrote.expect("stdin").expect("write oversized request");
    let output = waited.expect("wait headless");
    assert_eq!(
        output.status.code(),
        Some(1),
        "oversized stdin frame must exit with code 1"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("stdin request exceeds"),
        "bounded stdin error must be visible: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn headless_classifies_oversized_non_utf8_frame_as_limit() {
    use std::io::Write;
    let mut data_root = tempfile::TempDir::with_prefix("rivect-headless-oversized-non-utf8-")
        .expect("fixture root");
    let spawned = std::process::Command::new(rivect_binary())
        .arg("--headless")
        .arg("--data-root")
        .arg(data_root.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();
    if spawned.is_err() {
        support::retain_root(&mut data_root);
    }
    let mut child = spawned.expect("spawn headless");
    let mut input = vec![0xff; rivect::contracts::REQUEST_MAX_BYTES + 1];
    input.push(b'\n');
    let wrote = child.stdin.take().map(|mut stdin| stdin.write_all(&input));
    let waited = child.wait_with_output();
    if !matches!(wrote, Some(Ok(()))) || waited.is_err() {
        support::retain_root(&mut data_root);
    }
    wrote
        .expect("stdin")
        .expect("write oversized non-utf8 request");
    let output = waited.expect("wait headless");
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("stdin request exceeds"),
        "oversized non-utf8 input must use limit error: {stderr:?}"
    );
    assert!(
        !stderr.contains("stdin failed"),
        "oversized non-utf8 input must not be classified as stdin failure: {stderr:?}"
    );
}

/// Stages one pending publication row under `root`'s owner store, then
/// breaks the config so `Runtime::open` collects the verdict and fails:
/// the failed-open drain must still hand the line to an operator-visible
/// channel on every surface.
fn stage_pending_verdict_then_broken_config(root: &Path) {
    let target = root.join("config.toml");
    std::fs::write(&target, support::base_config()).expect("seed config");
    // The owner store lives under `runtime/` — the path `Owner::elect`
    // opens — so the staged row is visible to `Runtime::open`.
    let runtime_dir = root.join("runtime");
    std::fs::create_dir_all(&runtime_dir).expect("runtime dir");
    let mut store =
        rivect::state::TaskStore::open(&runtime_dir.join("rivect.db")).expect("open store");
    let mut parsed =
        rivect::config::Config::parse_validated(&support::base_config()).expect("valid config");
    let edit = parsed
        .set("workflow.enabled", rivect::config::ConfigValue::Bool(false))
        .expect("workflow edit");
    rivect::config::stage_publication(&mut store, "cli", &target, &edit)
        .expect("stage publication intent");
    drop(store);
    std::fs::write(&target, b"[workflow\n").expect("malformed config");
}

#[test]
fn headless_failed_open_reports_verdict_before_error() {
    let mut data_root =
        tempfile::TempDir::with_prefix("rivect-headless-open-verdict-").expect("fixture root");
    stage_pending_verdict_then_broken_config(data_root.path());
    let output = std::process::Command::new(rivect_binary())
        .arg("--headless")
        .arg("--data-root")
        .arg(data_root.path())
        .env_clear()
        .output();
    if output.is_err() {
        support::retain_root(&mut data_root);
    }
    let output = output.expect("run headless");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let verdict = stderr.find("publication recovery");
    let failure = stderr.find("runtime open failed");
    assert!(
        matches!((verdict, failure), (Some(v), Some(f)) if v < f),
        "the pending verdict must reach stderr ahead of the open error: {stderr}"
    );
}

#[test]
fn tui_failed_open_reports_verdict_before_alternate_screen() {
    let root = tempfile::TempDir::with_prefix("rivect-pty-open-verdict-").expect("pty root");
    let data_root = root.path().to_path_buf();
    stage_pending_verdict_then_broken_config(&data_root);
    let mut pty =
        support::spawn_pty_with_args(&rivect_binary(), 24, 80, root, &data_root, &data_root, &[]);
    // The degraded session still enters the alternate screen and renders
    // the open failure on its transcript — asserted on the reconstructed
    // screen, since the renderer emits positioned words, not raw lines.
    let visible = wait_for_visible_tui_text(&pty, "session open failed", Duration::from_secs(10))
        .expect("pty screen");
    assert!(
        visible.contains("session open failed"),
        "the transcript records the open failure inside the session: {visible:?}"
    );
    assert!(
        visible.contains("publication recovery"),
        "the carried verdict reaches the transcript inside the session: {visible:?}"
    );
    let stream = pty.collected().expect("pty read");
    let verdict = support::find_subsequence(&stream, b"publication recovery");
    let entered = support::find_subsequence(&stream, b"\x1b[?1049h");
    assert!(
        matches!((verdict, entered), (Some(v), Some(e)) if v < e),
        "the pending verdict must reach the terminal before the alternate screen takes it: {:?}",
        String::from_utf8_lossy(&stream)
    );
    pty.send(&[0x1b]).expect("pty send");
    assert_eq!(
        pty.wait_exit(Duration::from_secs(10)).expect("pty wait"),
        Some(0),
        "Esc leaves the degraded session normally"
    );
    pty.finish().expect("pty teardown");
}

#[test]
fn tui_lazy_retry_failed_open_reports_verdict_after_restore() {
    let root = tempfile::TempDir::with_prefix("rivect-pty-lazy-open-verdict-").expect("pty root");
    let data_root = root.path().to_path_buf();
    stage_pending_verdict_then_broken_config(&data_root);
    let mut pty =
        support::spawn_pty_with_args(&rivect_binary(), 24, 80, root, &data_root, &data_root, &[]);
    // The degraded session leaves the dispatch slot empty, so a submitted
    // task drives the lazy-retry open: it fails the same way and its
    // propagated error is the only channel left once the guard restores
    // the primary screen.
    let visible = wait_for_visible_tui_text(&pty, "session open failed", Duration::from_secs(10))
        .expect("pty screen");
    assert!(
        visible.contains("session open failed"),
        "the degraded session records the eager open failure: {visible:?}"
    );
    pty.send(b"retry the open\r").expect("pty send");
    assert_eq!(
        pty.wait_exit(Duration::from_secs(10)).expect("pty wait"),
        Some(1),
        "the failed lazy retry must propagate out of the loop"
    );
    // The post-restore slice is polled to a deadline rather than read once.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut stream = pty.collected().expect("pty read");
    loop {
        let tail = support::find_subsequence(&stream, b"\x1b[?1049l")
            .map(|leave| &stream[leave + b"\x1b[?1049l".len()..]);
        if tail
            .is_some_and(|tail| support::find_subsequence(tail, b"publication recovery").is_some())
            || std::time::Instant::now() >= deadline
        {
            break;
        }
        pty.pump_for(Duration::from_millis(25)).expect("pty pump");
        stream = pty.collected().expect("pty read");
    }
    let leave = support::find_subsequence(&stream, b"\x1b[?1049l");
    assert!(
        leave.is_some(),
        "the propagated error must leave the alternate screen: {:?}",
        String::from_utf8_lossy(&stream)
    );
    let restored = &stream[leave.expect("leave offset") + b"\x1b[?1049l".len()..];
    assert!(
        support::find_subsequence(restored, b"publication recovery").is_some(),
        "the carried verdict must reach the restored primary screen: {:?}",
        String::from_utf8_lossy(restored)
    );
    let restored_text = String::from_utf8_lossy(restored);
    let failure_prefix = "tui failed: tui runtime open failed: owner configuration failed";
    assert_eq!(
        restored_text.matches(failure_prefix).count(),
        1,
        "the restored screen names the CLI, context and cause exactly once: {restored_text:?}"
    );
    assert_eq!(
        restored_text.matches("publication recovery").count(),
        1,
        "the restored screen holds exactly one verdict: {restored_text:?}"
    );
    assert!(
        matches!(
            (
                restored_text.find(failure_prefix),
                restored_text.find("publication recovery")
            ),
            (Some(failure), Some(verdict)) if failure < verdict
        ),
        "the failure prefix precedes the carried verdict: {restored_text:?}"
    );
    pty.finish().expect("pty teardown");
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

/// The headless loop's real surface (D-101 / FP-098-D, I-B).
///
/// `src/main.rs` was rewritten as one loop over one bounded channel with
/// two producers, and its in-process coverage drives `Runtime` directly.
/// This leg drives the *process*: one `project.init` frame on stdin, the
/// owed answer on stdout with no second frame written, and exit 0 when
/// stdin closes. A coherent revert of the loop — back to one blocking
/// read per turn with the run inline — would drop the answer or hang, and
/// this is what says so.
///
/// The project root is pinned server-side, so a headless index can only
/// read the data root. The fixture therefore *is* the data root: a small
/// Cargo project, with the runtime's own state beside it.
#[test]
fn headless_loop_writes_the_deferred_index_answer_and_exits_on_close() {
    ensure_helper();
    let mut root =
        tempfile::TempDir::with_prefix("rivect-headless-deferred-index-").expect("fixture root");
    std::fs::create_dir_all(root.path().join("src")).expect("fixture dir");
    std::fs::write(
        root.path().join("Cargo.toml"),
        "[package]\nname = \"headless\"\n",
    )
    .expect("manifest");
    std::fs::write(
        root.path().join("src/lib.rs"),
        "pub mod helper;\npub fn root_fn() {}\n",
    )
    .expect("lib");
    std::fs::write(root.path().join("src/helper.rs"), "pub fn helper_fn() {}\n").expect("helper");

    let spawned = std::process::Command::new(rivect_binary())
        .args(["--headless", "--data-root"])
        .arg(root.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();
    if spawned.is_err() {
        support::retain_root(&mut root);
    }
    let mut child = spawned.expect("spawn headless");

    // The session, then exactly one project.init frame. Nothing else is
    // written, so every response after the session.open is the owed one.
    // Every step stays a value until the child is reaped; a failed step
    // retains the root before any panic site consumes it.
    let stdin_pipe = child.stdin.take();
    let stdout_pipe = child.stdout.take();
    if stdin_pipe.is_none() || stdout_pipe.is_none() {
        support::retain_root(&mut root);
    }
    let mut stdin = stdin_pipe.expect("stdin");
    let mut stdout = std::io::BufReader::new(stdout_pipe.expect("stdout"));
    let mut send = |value: Value| -> std::io::Result<()> {
        use std::io::Write as _;
        writeln!(stdin, "{value}")?;
        stdin.flush()
    };
    let sent_open = send(serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "session.open",
        "params": { "schema_version": 1, "bootstrap_id": "b-headless" },
    }));
    let sent_init = send(serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "command.execute",
        "params": {
            "schema_version": 1, "session_id": "m1",
            "command": { "kind": "project.init", "budget_ms": 60_000 },
        },
    }));
    // Closing stdin is the loop's exit: the owed answer is written on the
    // way out, so the drain has to read it before the process ends.
    drop(stdin);

    let mut first = String::new();
    let first_read = std::io::BufRead::read_line(&mut stdout, &mut first);
    let mut second = String::new();
    let second_read = std::io::BufRead::read_line(&mut stdout, &mut second);
    // Nothing else: the loop wrote no placeholder for the deferred id.
    let mut extra = String::new();
    let extra_read = std::io::BufRead::read_line(&mut stdout, &mut extra);
    let status = child.wait();
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        use std::io::Read as _;
        let _read = pipe.read_to_string(&mut stderr);
    }
    if sent_open.is_err()
        || sent_init.is_err()
        || first_read.is_err()
        || second_read.is_err()
        || extra_read.is_err()
        || status.is_err()
    {
        support::retain_root(&mut root);
    }
    sent_open.expect("write frame");
    sent_init.expect("write frame");
    first_read.expect("read the first response");
    let opened: Value = serde_json::from_str(&first).expect("a session.open answer");
    assert_eq!(opened["id"], 1, "the session opened: {opened}");

    second_read.expect("the owed answer arrives on its own");
    let owed: Value = serde_json::from_str(&second).expect("a project-init answer");
    assert_eq!(owed["id"], 2, "the owed answer carries its own id: {owed}");
    let result: ProjectInitResult =
        serde_json::from_value(owed["result"].clone()).expect("a typed answer");
    assert!(
        matches!(result.snapshot, SnapshotId::Generation(_)),
        "the deferred answer is a cut generation, not a synthesised \\
         acceptance: {result:?}"
    );
    assert_eq!(result.graph.narrowed_to, Vec::<PathBuf>::new());

    let read = extra_read.expect("drain");
    assert_eq!(read, 0, "no further response is written: {extra:?}");

    let status = status.expect("the loop exits on stdin close");
    assert_eq!(status.code(), Some(0), "and it exits cleanly: {status:?}");
    assert!(
        stderr.is_empty(),
        "machine stderr carries no diagnostics for a clean run: {stderr}"
    );
}

// ----- AC-049: a forced runtime compaction keeps the continuation -----

/// The scope one model's spend is recorded under: the model is part of the
/// name, so a switch appends its own scope instead of relabelling an
/// earlier one.
fn model_spend_scope(task: &rivect::contracts::TaskId, model: &str) -> String {
    format!("task:{}/model:{model}", task.0)
}

/// Creates the fixture task with two criteria: the recorded read proves the
/// first and leaves the second outstanding, which is the work a continuation
/// has to carry across a compaction.
fn create_two_criteria_task(
    world: &mut World,
    session: &rivect::contracts::SessionId,
    command_id: &str,
) -> rivect::contracts::TaskId {
    let created = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 4, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": command_id, "session_id": session.0,
            "kind": "create",
            "goal": "Объяснить тему в выбранной форме.",
            "contract": {
                "criteria": [
                    "Дать объяснение в выбранной форме.",
                    "Проверить объяснение по файлу.",
                ],
                "constraints": ["Не изменять файлы."],
            },
            "attachments": [],
        },
    }));
    let task_id = created["result"]["task_id"].as_str();
    assert!(task_id.is_some(), "create failed: {created}");
    rivect::contracts::TaskId(task_id.expect("task id").to_string())
}

/// A task carrying an open question, real tool results, spend and a scoped
/// read: the working state a forced compaction has to carry across.
struct Continuation {
    world: World,
    session: rivect::contracts::SessionId,
    task: rivect::contracts::TaskId,
    question: rivect::contracts::Question,
    file: PathBuf,
}

fn continuation_task(tag: &str) -> Continuation {
    let (mut world, _scope, file, _grant) =
        scoped_world(tag, Some(&support::config_distinct_pools()));
    let session = world.open_session(&format!("bootstrap-{tag}"));
    let task = create_two_criteria_task(&mut world, &session, &format!("cmd-{tag}"));
    let question = world.publish(&session, &task);
    // The obligations are the rows evidence is recorded against, so they
    // exist before the first result lands.
    world
        .runtime
        .store_writer()
        .materialize_obligations(&task)
        .expect("obligations");
    // The episodic history is what a compaction folds: real tool results far
    // longer than the one checkpoint line that replaces them. They prove the
    // first criterion and leave the second outstanding, so the remainder the
    // continuation carries is real work rather than a constant zero.
    for index in 0..4_u8 {
        let observation = format!(
            "read {} and reported {}",
            file.display(),
            "a scoped line of the file ".repeat(30)
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
    let obligations = world
        .runtime
        .store()
        .snapshot(&task)
        .expect("snapshot")
        .obligations
        .items;
    assert_eq!(
        obligations.len(),
        2,
        "the fixture task carries two criteria: {obligations:?}"
    );
    assert_eq!(
        obligations
            .iter()
            .filter(|obligation| {
                obligation.execution != rivect::contracts::ObligationExecution::Satisfied
            })
            .count(),
        1,
        "one criterion stays unproven, so the remainder has work to name: {obligations:?}"
    );
    let scope = model_spend_scope(&task, "alpha");
    let mut writer = world.runtime.store_writer();
    writer.open_budget(&scope, 10_000).expect("budget scope");
    writer
        .budget_reserve("reserve-alpha", &[&scope], 400)
        .expect("reserve");
    writer
        .budget_charge("reserve-alpha", Some(320))
        .expect("charge");
    Continuation {
        world,
        session,
        task,
        question,
        file,
    }
}

fn compact(c: &mut Continuation) -> rivect::state::CompactionReport {
    c.world
        .runtime
        .store_writer()
        .force_compaction(&c.session, &c.task)
        .expect("forced compaction")
}

fn assembled(c: &Continuation) -> rivect::state::AssembledContext {
    c.world
        .runtime
        .store()
        .assembled_context(&c.task)
        .expect("assembled context")
}

fn resume(c: &mut Continuation) -> rivect::controller::ContinuationOutcome {
    c.world
        .runtime
        .resume_continuation(&c.session, &c.task)
        .expect("resume")
}

/// How many read effects this task recorded: the count a compaction must
/// leave at exactly one.
fn recorded_effects(c: &Continuation) -> usize {
    c.world
        .runtime
        .store()
        .snapshot(&c.task)
        .expect("snapshot")
        .attempts
        .items
        .iter()
        .filter(|attempt| attempt.effect_class == rivect::contracts::EffectClass::Read)
        .count()
}

#[test]
fn forced_compaction_preserves_intent_answer_remainder_and_spend_p1() {
    let mut c = continuation_task("compaction-p1");
    let open = c
        .world
        .runtime
        .store()
        .current_question(&c.task)
        .expect("question read")
        .expect("an open question");
    let intent = c
        .world
        .runtime
        .store()
        .snapshot(&c.task)
        .expect("snapshot")
        .intent_revision;
    let report = compact(&mut c);
    let after = c
        .world
        .runtime
        .store()
        .current_question(&c.task)
        .expect("question read")
        .expect("the open question survives the compaction");
    assert_eq!(
        after.0, open.0,
        "a forced compaction must not replace the open question"
    );
    assert_eq!(after.1, open.1, "nor its revision");
    let checkpoint = c
        .world
        .runtime
        .store()
        .continuation_checkpoint(&c.task)
        .expect("checkpoint read")
        .expect("the compaction recorded a checkpoint");
    assert_eq!(checkpoint.checkpoint_id, report.checkpoint_id);
    assert_eq!(
        checkpoint.intent_revision, intent,
        "the checkpoint keeps the intent revision the question was pinned to"
    );
    assert_eq!(
        checkpoint.question_id.as_deref(),
        Some(open.0.question_id.0.as_str()),
        "the checkpoint names the question it carried"
    );
    let context = assembled(&c);
    assert!(
        context.decision.contains(&open.0.question_id.0),
        "the next request still carries the question: {context:?}"
    );
    assert!(
        context.intent.contains(&format!("intent: {intent}")),
        "and its intent: {context:?}"
    );
}

#[test]
fn forced_compaction_preserves_intent_answer_remainder_and_spend_p2() {
    let mut c = continuation_task("compaction-p2");
    let question = c.question.clone();
    freeze_answered(
        &mut c.world,
        &c.session,
        &c.task,
        &question,
        answer_custom(&format!("read {}", c.file.display())),
    );
    let given = c
        .world
        .runtime
        .store()
        .answered_question(&c.task)
        .expect("answer read")
        .expect("the answer is durable before the compaction");
    compact(&mut c);
    let kept = c
        .world
        .runtime
        .store()
        .answered_question(&c.task)
        .expect("answer read")
        .expect("the answer survives the compaction");
    assert_eq!(
        kept, given,
        "a forced compaction must not replace the answer already given"
    );
    // The remainder is real work before the resume and none of it after:
    // the continuation is what carries it across, so the two states have to
    // differ rather than repeat a constant.
    let before_resume = assembled(&c).remainder;
    assert!(
        before_resume.contains("outstanding: 1\n"),
        "the outstanding criterion is still open after the compaction: {before_resume:?}"
    );
    let outcome = resume(&mut c);
    let rivect::controller::ContinuationOutcome::Resumed { snapshot, .. } = outcome else {
        panic!("the remainder must run after the compaction, got {outcome:?}");
    };
    assert_eq!(
        snapshot.lifecycle,
        Lifecycle::Completed,
        "the remainder still runs to completion: {snapshot:?}"
    );
    let after_resume = assembled(&c).remainder;
    assert_ne!(
        after_resume, before_resume,
        "the resumed step closes what remained, so the remainder is not a constant"
    );
    assert!(
        after_resume.contains("outstanding: 0\n"),
        "the outstanding work is what the resumed step closed: {after_resume:?}"
    );
    assert_eq!(c.world.worker_reads(), 1, "the remainder read exactly once");
}

#[test]
fn forced_compaction_preserves_intent_answer_remainder_and_spend_p3() {
    let mut c = continuation_task("compaction-p3");
    let scope = model_spend_scope(&c.task, "alpha");
    let before = c
        .world
        .runtime
        .store()
        .budget_status(&scope)
        .expect("budget status")
        .spent;
    assert_eq!(before, 320, "the spend recorded before the compaction");
    compact(&mut c);
    let after = c
        .world
        .runtime
        .store()
        .budget_status(&scope)
        .expect("budget status")
        .spent;
    assert_eq!(
        after, before,
        "a forced compaction leaves recorded spend unchanged"
    );
    let context = assembled(&c);
    assert!(
        context.spend.contains(&format!("{scope} {before}")),
        "the continuation reports the recorded spend: {context:?}"
    );
}

#[test]
fn forced_compaction_preserves_intent_answer_remainder_and_spend_p4() {
    let mut c = continuation_task("compaction-p4");
    let before = assembled(&c);
    let report = compact(&mut c);
    let after = assembled(&c);
    assert!(
        report.after_bytes < report.before_bytes,
        "a forced runtime compaction must shrink the assembled context, got {report:?}"
    );
    assert!(
        report.after_bytes + 512 < report.before_bytes,
        "a compaction that only appended a record leaves the size unchanged: {report:?}"
    );
    assert_eq!(after.text.len(), report.after_bytes, "{report:?}");
    assert!(
        before.history.contains("read "),
        "the raw history is assembled before the compaction: {before:?}"
    );
    assert!(
        !after.history.contains("read "),
        "the folded history must not keep the raw text: {after:?}"
    );
    assert_eq!(
        after.decision, before.decision,
        "the question and the answer stay byte-identical"
    );
    assert_eq!(
        after.remainder, before.remainder,
        "what remains stays byte-identical"
    );
    // The carried remainder is the fixture's unproven criterion, so the
    // byte-identical check above compares real work rather than a constant
    // "outstanding: 0".
    let pending = c
        .world
        .runtime
        .store()
        .snapshot(&c.task)
        .expect("snapshot")
        .obligations
        .items
        .into_iter()
        .find(|obligation| {
            obligation.execution != rivect::contracts::ObligationExecution::Satisfied
        })
        .expect("the fixture leaves one criterion outstanding");
    assert!(
        before.remainder.contains(&pending.id) && before.remainder.contains("outstanding: 1\n"),
        "the remainder names the outstanding work and its count: {before:?}"
    );
    assert_eq!(after.spend, before.spend, "the spend stays byte-identical");
    assert_eq!(
        after.intent, before.intent,
        "the intent stays byte-identical"
    );
    assert_eq!(
        after.evidence, before.evidence,
        "the records the continuation carries stay byte-identical"
    );
    let checkpoint = c
        .world
        .runtime
        .store()
        .continuation_checkpoint(&c.task)
        .expect("checkpoint read")
        .expect("checkpoint");
    assert!(
        checkpoint.folded_records >= 4,
        "the checkpoint names how many episodic records it folded: {checkpoint:?}"
    );
    // Folding again would replace the one folded line with another of the
    // same size, so the fold is refused typed: a compaction that cannot
    // shorten the context never reports one.
    let refused = c
        .world
        .runtime
        .store_writer()
        .force_compaction(&c.session, &c.task);
    assert!(
        matches!(
            refused,
            Err(rivect::state::StoreError::Conflict(
                rivect::state::ConflictCause::CompactionNotShorter { .. }
            ))
        ),
        "a fold that would not shorten the history is refused: {refused:?}"
    );
    let unchanged = c
        .world
        .runtime
        .store()
        .continuation_checkpoint(&c.task)
        .expect("checkpoint read")
        .expect("checkpoint");
    assert_eq!(
        unchanged.checkpoint_id, checkpoint.checkpoint_id,
        "the refused fold wrote no second checkpoint"
    );
    assert_eq!(
        assembled(&c).text.len(),
        report.after_bytes,
        "and the context is exactly what the accepted fold left"
    );
}

#[test]
fn forced_compaction_preserves_intent_answer_remainder_and_spend_p5() {
    // E4: a model switch inside the continuation spends under its own scope
    // and never relabels the spend recorded before it.
    let mut c = continuation_task("compaction-p5");
    let scope = model_spend_scope(&c.task, "alpha");
    compact(&mut c);
    let recorded = c
        .world
        .runtime
        .store()
        .continuation_checkpoint(&c.task)
        .expect("checkpoint read")
        .expect("checkpoint")
        .spend;
    assert_eq!(
        recorded,
        vec![rivect::state::SpendEntry {
            scope: scope.clone(),
            spent: 320,
        }],
        "the checkpoint records the spend per scope"
    );
    let before_spend = assembled(&c).spend;
    assert!(
        before_spend.contains(&format!("{scope} 320")),
        "the live ledger names the model that spent it: {before_spend:?}"
    );
    // The test switches the model inside the continuation: a pinned
    // backend_task model replaces the auto pool.
    let world_id = c.world.runtime.scope_root.display().to_string();
    let before_model = c
        .world
        .runtime
        .broker
        .prepare(
            "backend_task",
            &c.world.runtime.config_for_broker(),
            &world_id,
            "goal: probe",
        )
        .expect("manifest before the switch")
        .model;
    let switched = format!(
        "{}\n[models.purposes.backend_task]\nmodel = {{ mode = \"fixed\", connection = \"primary\", model_id = \"fixture-model\" }}\neffort = {{ mode = \"auto\" }}\n",
        support::base_config()
    );
    std::fs::write(c.world.root.join("config.toml"), switched).expect("config change");
    c.world.runtime.reload_config().expect("the owner reloads");
    let after_model = c
        .world
        .runtime
        .broker
        .prepare(
            "backend_task",
            &c.world.runtime.config_for_broker(),
            &world_id,
            "goal: probe",
        )
        .expect("manifest after the switch")
        .model;
    assert_ne!(
        after_model, before_model,
        "the switch must change the model the task runs under"
    );
    // The new model spends under its own scope: the live ledger really
    // moves, which is what makes the unchanged record below a claim instead
    // of a second read of the same value.
    let beta = model_spend_scope(&c.task, "beta");
    let mut writer = c.world.runtime.store_writer();
    writer.open_budget(&beta, 10_000).expect("beta scope");
    writer
        .budget_reserve("reserve-beta", &[&beta], 200)
        .expect("beta reserve");
    writer
        .budget_charge("reserve-beta", Some(120))
        .expect("beta charge");
    let after_spend = assembled(&c).spend;
    assert_ne!(
        after_spend, before_spend,
        "the switched model's spend reaches the live ledger: {after_spend:?}"
    );
    assert!(
        after_spend.contains(&format!("{beta} 120")),
        "the new model's spend is a row of its own: {after_spend:?}"
    );
    assert!(
        after_spend.contains(&format!("{scope} 320")),
        "the row the previous model spent stays as it was: {after_spend:?}"
    );
    // The recorded spend is still exactly what the compaction wrote: the
    // switch appended a scope, it did not relabel the recorded one.
    let kept = c
        .world
        .runtime
        .store()
        .continuation_checkpoint(&c.task)
        .expect("checkpoint read")
        .expect("checkpoint")
        .spend;
    assert_eq!(
        kept,
        vec![rivect::state::SpendEntry {
            scope: scope.clone(),
            spent: 320,
        }],
        "the spend recorded under the previous model is unchanged by the switch: {kept:?}"
    );
    assert!(
        kept.iter().all(|entry| entry.scope != beta),
        "and the checkpoint recorded before the switch does not gain its scope: {kept:?}"
    );
    assert_eq!(
        c.world
            .runtime
            .store()
            .budget_status(&scope)
            .expect("alpha status")
            .spent,
        320,
        "the previous model's ledger row is untouched"
    );
}

#[test]
fn forced_compaction_preserves_intent_answer_remainder_and_spend_p6() {
    let mut c = continuation_task("compaction-p6");
    let question = c.question.clone();
    freeze_answered(
        &mut c.world,
        &c.session,
        &c.task,
        &question,
        answer_custom(&format!("read {}", c.file.display())),
    );
    compact(&mut c);
    // A pinned input moves between the compaction and the resume: the
    // intent the checkpoint pinned is no longer the task's intent.
    let snapshot = c.world.runtime.store().snapshot(&c.task).expect("snapshot");
    c.world
        .runtime
        .store_writer()
        .steer_task(
            &c.session,
            &c.task,
            snapshot.intent_revision,
            snapshot.revision,
            "a different instruction",
        )
        .expect("steer");
    let outcome = resume(&mut c);
    let rivect::controller::ContinuationOutcome::Stale { pin } = &outcome else {
        panic!("a mutated pin must report staleness, got {outcome:?}");
    };
    assert_eq!(*pin, "intent", "the refusal names the input that moved");
    let summary = outcome.summary();
    assert!(summary.contains("stale"), "{summary}");
    assert!(
        summary.contains("replay refused"),
        "the continuation refuses to replay: {summary}"
    );
    assert_eq!(
        c.world.worker_reads(),
        0,
        "a stale continuation performs no effect"
    );
    assert_eq!(
        c.world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "and dispatches nothing"
    );
}

#[test]
fn forced_compaction_preserves_intent_answer_remainder_and_spend_p7() {
    // The effect runs before the compaction and the resume afterwards runs
    // the task's own step, so the count below is checked after a real
    // resume rather than after one that found nothing to do.
    let mut c = continuation_task("compaction-p7");
    let question = c.question.clone();
    let answer = answer_custom(&format!("read {}", c.file.display()));
    freeze_answered(&mut c.world, &c.session, &c.task, &question, answer.clone());
    // The answered node stays queued: the one step driver performs the
    // effect here, so the node the resume admits is still this task's.
    let grant = c.world.runtime.scoped_grant.clone();
    let step = c
        .world
        .runtime
        .run_decision_step(&c.session, &c.task, &answer, &grant, false)
        .expect("the answered step runs");
    assert!(
        matches!(step, rivect::controller::StepOutcome::Completed { .. }),
        "the effect ran once before the compaction: {step:?}"
    );
    assert_eq!(recorded_effects(&c), 1, "one recorded read effect");
    assert_eq!(c.world.worker_reads(), 1, "and one real worker read");
    let dispatched = c
        .world
        .provider_calls
        .load(std::sync::atomic::Ordering::SeqCst);
    compact(&mut c);
    let resumed = resume(&mut c);
    let rivect::controller::ContinuationOutcome::Resumed { snapshot, .. } = resumed else {
        panic!("the resume runs this task's queued step, got {resumed:?}");
    };
    assert_eq!(
        snapshot.lifecycle,
        Lifecycle::Completed,
        "the resumed step finds the work already done: {snapshot:?}"
    );
    assert_eq!(
        recorded_effects(&c),
        1,
        "the recorded effect count stays exactly one across compaction and the resumed step"
    );
    assert_eq!(
        c.world.worker_reads(),
        1,
        "the resumed step repeats no effect"
    );
    assert_eq!(
        c.world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        dispatched,
        "and dispatches no model call of its own"
    );
}

#[test]
fn forced_compaction_preserves_intent_answer_remainder_and_spend_p8() {
    let mut c = continuation_task("compaction-p8");
    let records = c
        .world
        .runtime
        .store()
        .evidence_for_task(&c.task)
        .expect("records");
    assert_eq!(
        records.len(),
        4,
        "the fixture's recorded reads: {records:?}"
    );
    let target = records
        .first()
        .expect("a scoped record")
        .evidence_id
        .0
        .clone();
    // The one criterion the recorded read proved: the deletion below is
    // about this row's support, not a count that could name either.
    let supported_id = c
        .world
        .runtime
        .store()
        .snapshot(&c.task)
        .expect("snapshot")
        .obligations
        .items
        .into_iter()
        .find(|obligation| {
            obligation.execution == rivect::contracts::ObligationExecution::Satisfied
        })
        .expect("the recorded read proves one criterion")
        .id;
    compact(&mut c);
    let index = c
        .world
        .runtime
        .store()
        .scoped_index(&c.task)
        .expect("derived index");
    assert!(
        index.iter().any(|record| record.evidence_id == target),
        "the checkpoint recorded the scoped record: {index:?}"
    );
    assert!(
        assembled(&c).text.contains(&target),
        "and the continuation carries it before the deletion"
    );
    c.world
        .runtime
        .store_writer()
        .delete_scoped_record(&c.task, &target)
        .expect("delete the scoped record");
    let remaining = c
        .world
        .runtime
        .store()
        .evidence_for_task(&c.task)
        .expect("records");
    assert!(
        !remaining
            .iter()
            .any(|record| record.evidence_id.0 == target),
        "the authoritative row is gone"
    );
    let index = c
        .world
        .runtime
        .store()
        .scoped_index(&c.task)
        .expect("derived index");
    assert!(
        !index.iter().any(|record| record.evidence_id == target),
        "a deleted scoped record is not served from the derived index: {index:?}"
    );
    let context = assembled(&c);
    assert!(
        !context.text.contains(&target),
        "and the continuation does not return it: {context:?}"
    );
    // The obligation the record supported is still proven by the three rows
    // that remain, so the deletion must not reopen it.
    let supported = c
        .world
        .runtime
        .store()
        .snapshot(&c.task)
        .expect("snapshot")
        .obligations
        .items;
    assert!(
        supported.iter().any(|obligation| {
            obligation.id == supported_id
                && obligation.execution == rivect::contracts::ObligationExecution::Satisfied
        }),
        "three records still support the criterion the deletion touched: {supported:?}"
    );
    // Deleting the last supporting record reopens the obligation in the
    // same transaction: a satisfied row without evidence would claim proof
    // that is gone, and the continuation would report work already done.
    for record in &records[1..] {
        c.world
            .runtime
            .store_writer()
            .delete_scoped_record(&c.task, &record.evidence_id.0)
            .expect("delete the last supporting records");
    }
    let reopened = c
        .world
        .runtime
        .store()
        .snapshot(&c.task)
        .expect("snapshot")
        .obligations
        .items;
    assert!(
        !reopened.iter().any(|obligation| {
            obligation.id == supported_id
                && obligation.execution == rivect::contracts::ObligationExecution::Satisfied
        }),
        "the criterion no record supports is reopened: {reopened:?}"
    );
    assert!(
        c.world
            .runtime
            .store()
            .evidence_for_task(&c.task)
            .expect("records")
            .is_empty(),
        "every authoritative row is gone"
    );
    assert!(
        c.world
            .runtime
            .store()
            .scoped_index(&c.task)
            .expect("derived index")
            .is_empty(),
        "and the derived index serves none of them"
    );
    let context = assembled(&c);
    assert!(
        !context.text.contains(&target),
        "the continuation returns no deleted record: {context:?}"
    );
    assert!(
        context.remainder.contains("outstanding: 2\n"),
        "both criteria are outstanding again, so the reopened row is carried: {context:?}"
    );
}

#[test]
fn forced_compaction_preserves_intent_answer_remainder_and_spend_p9() {
    let mut c = continuation_task("compaction-p9");
    let target = c
        .world
        .runtime
        .store()
        .evidence_for_task(&c.task)
        .expect("records")
        .into_iter()
        .next()
        .expect("a scoped record");
    c.world
        .runtime
        .store_writer()
        .invalidate_evidence(&target.evidence_id.0)
        .expect("invalidate");
    compact(&mut c);
    let index = c
        .world
        .runtime
        .store()
        .scoped_index(&c.task)
        .expect("derived index");
    let recorded = index
        .iter()
        .find(|record| record.evidence_id == target.evidence_id.0)
        .expect("the record survives the compaction");
    assert_eq!(
        recorded.validity, "stale",
        "the recorded validity travels with the record: {recorded:?}"
    );
    assert_eq!(recorded.digest, target.digest, "and so does its digest");
    let context = assembled(&c);
    assert!(
        context
            .evidence
            .contains(&format!("{} stale {}", target.evidence_id.0, target.digest)),
        "the continuation returns the evidence with its recorded validity: {context:?}"
    );
}

#[test]
fn forced_compaction_preserves_intent_answer_remainder_and_spend_p10() {
    let mut c = continuation_task("compaction-p10");
    let question = c.question.clone();
    freeze_answered(
        &mut c.world,
        &c.session,
        &c.task,
        &question,
        answer_custom(&format!("read {}", c.file.display())),
    );
    let step = c
        .world
        .runtime
        .scheduler_step(&c.session)
        .expect("the answered node runs");
    assert!(
        matches!(step, rivect::controller::SchedulerStep::Ran { .. }),
        "{step:?}"
    );
    compact(&mut c);
    let resumed = resume(&mut c);
    assert!(
        matches!(
            resumed,
            rivect::controller::ContinuationOutcome::NoContinuation
        ),
        "an empty result after resume is no continuation: {resumed:?}"
    );
    let summary = resumed.summary();
    assert_eq!(summary, "no continuation", "the reported line");
    assert!(
        !summary.contains("nothing further is needed"),
        "an empty step is not a verdict that nothing further is needed: {summary}"
    );
}
