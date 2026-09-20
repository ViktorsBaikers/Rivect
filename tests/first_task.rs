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
use rivect::contracts::{AnswerSelection, Lifecycle, OptionId};
use rivect::executor::{EffectRequest, Executor};
use rivect::model::RequestManifest;
use rivect::providers::{Provider, ProviderError, ProviderReply};
use rivect::resources::{Delivery, NotificationQueue};
use rivect::ui::{ApplyVerdict, Projection};
use serde_json::{Value, json};
use sha2::Digest;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use support::{
    World, answer_custom, corpus_answer_custom, corpus_answer_option, corpus_config_read,
    corpus_create, corpus_question_current, corpus_status, corpus_steer, open_world, rivect_binary,
    spawn_pty, spawn_pty_with_args,
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
        .owner
        .store
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

    fn send(&mut self, _manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        Ok(ProviderReply {
            text: String::new(),
            tool_calls: Vec::new(),
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
    let worker_error = rivect::executor::macos::read_once(
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
        .owner
        .store
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
            .owner
            .store
            .plan_attempt(
                &task,
                rivect::contracts::EffectClass::Read,
                &format!("paged attempt {index}"),
            )
            .expect("plan paged attempt");
    }
    let generation = world
        .runtime
        .owner
        .store
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
    let exact_bytes = vec![b'x'; rivect::executor::macos::READ_MAX_BYTES];
    std::fs::write(&exact, &exact_bytes).expect("exact file");
    let observation = rivect::executor::macos::read_once(&scope, &exact).expect("exact size");
    assert_eq!(observation.bytes, exact_bytes);
    assert_eq!(observation.digest, support::sha256_hex(&observation.bytes));

    let hardlink = scope.join("hardlink.bin");
    std::fs::hard_link(&exact, &hardlink).expect("hardlink");
    let linked = rivect::executor::macos::read_once(&scope, &hardlink).expect("hardlink read");
    assert_eq!(linked.bytes, exact_bytes);

    let outside = world.root.join("outside-secret.txt");
    std::fs::write(&outside, b"outside").expect("outside file");
    let escape = scope.join("escape");
    std::os::unix::fs::symlink(&outside, &escape).expect("escape symlink");
    assert!(matches!(
        rivect::executor::macos::read_once(&scope, &escape),
        Err(rivect::executor::WorkerError::OutsideScope { .. })
    ));

    let oversized = scope.join("oversized.bin");
    std::fs::write(
        &oversized,
        vec![b'x'; rivect::executor::macos::READ_MAX_BYTES + 1],
    )
    .expect("oversized file");
    assert!(matches!(
        rivect::executor::macos::read_once(&scope, &oversized),
        Err(rivect::executor::WorkerError::TooLarge)
    ));

    let denied = scope.join("oversized-denied.bin");
    std::fs::write(
        &denied,
        vec![b'x'; rivect::executor::macos::READ_MAX_BYTES + 1],
    )
    .expect("oversized denied file");
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000))
        .expect("deny oversized file");
    assert!(matches!(
        rivect::executor::macos::read_once(&scope, &denied),
        Err(rivect::executor::WorkerError::TooLarge)
    ));
}

#[test]
fn read_once_denies_fifo_without_writer() -> Result<(), Box<dyn std::error::Error>> {
    let world = open_world("read-fifo-denied", None);
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope)?;
    let fifo = scope.join("pipe");
    let status = std::process::Command::new("mkfifo").arg(&fifo).status()?;
    assert!(status.success(), "mkfifo must create the pipe");
    // No writer holds the other end: a static FIFO is denied by the
    // pre-open regular-file check, and a swap into the open window cannot
    // block the O_NONBLOCK opened handle before the same fd-level check.
    assert!(matches!(
        rivect::executor::macos::read_once(&scope, &fifo),
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
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
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
    let all_classes = world.runtime.policy.grant_classes(
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
            .owner
            .store
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
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
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
    world.runtime.policy.revoke(&grant);
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
    // drain runs the loopback useful path to completion.
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
        .owner
        .store
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

    // Custom text still runs the admitted scoped read at drain time; the
    // exact multi-line bytes stay durable.
    let custom_snapshot = world
        .runtime
        .owner
        .store
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
        AnswerSelection::Option {
            option_id: OptionId("steps".to_string()),
        },
    );
    let planned = world
        .runtime
        .run_decision_step(
            &session,
            &planned_task,
            &AnswerSelection::Option {
                option_id: OptionId("steps".to_string()),
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
    let root = support::temp_dir("no-ready-provider");
    std::fs::write(root.join("config.toml"), support::config_distinct_pools()).expect("config");
    let mut runtime =
        rivect::commands::Runtime::open(&root, Box::new(NoToolProvider)).expect("owner elected");
    runtime.purpose = "backend_task".to_string();
    let scope = root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "no-ready-marker\n").expect("scoped file");
    let grant = runtime.set_read_scope(scope, file.clone());
    let (session, _, _, _) = runtime
        .owner
        .store
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
        .owner
        .store
        .publish_question(&session, &question)
        .expect("question");
    let answer = answer_custom("request provider judgment");
    runtime
        .owner
        .store
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
        .owner
        .store
        .events_after(&session, Some(&task), 0, 50)
        .expect("events");
    let foreign = rivect::contracts::SessionId("foreign-session".to_string());
    assert!(matches!(
        world.runtime.owner.store.recover_events(&foreign, &events),
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
        .owner
        .store
        .events_after(&session, Some(&task), 0, 50)
        .expect("events");
    let mut unknown = events.into_iter().next().expect("event");
    unknown.aggregate_id = "unknown-aggregate".to_string();
    assert!(matches!(
        world
            .runtime
            .owner
            .store
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
        .owner
        .store
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
        .owner
        .store
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
    let next_cursor_guard = world.runtime.owner.store.task_status_page(
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
    let db_path = world.runtime.owner.runtime_dir().join("rivect.db");
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
        .owner
        .store
        .plan_attempt(
            &running_with_unknown,
            rivect::contracts::EffectClass::Read,
            "unknown running attempt",
        )
        .expect("plan attempt");
    world
        .runtime
        .owner
        .store
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
        .owner
        .store
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
            .owner
            .store
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

    // Recovery re-delivers the durable stream through the owner after restart.
    let events = world
        .runtime
        .owner
        .store
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
            rusqlite::Connection::open(world.runtime.owner.runtime_dir().join("rivect.db"))
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
        .owner
        .store
        .snapshot(&task)
        .expect("snapshot before recovery");
    let durable_counts = |world: &World| {
        rusqlite::Connection::open(world.runtime.owner.runtime_dir().join("rivect.db"))
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
        .owner
        .store
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
            .owner
            .store
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
            .owner
            .store
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
        .owner
        .store
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
        .owner
        .store
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
    let snapshot = world.runtime.owner.store.snapshot(&task).expect("snapshot");
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

#[test]
fn blocked_task_stays_blocked_after_neighbor_completes() {
    let (mut world, _scope, _file, _grant) =
        scoped_world("blocked-neighbor", Some(&support::config_distinct_pools()));
    let session = world.open_session("bootstrap-blocked-neighbor");
    let blocked = world.create_task(&session, "cmd-blocked-neighbor");
    world
        .runtime
        .owner
        .store
        .materialize_obligations(&blocked)
        .expect("materialize blocked obligation");
    let attempt = world
        .runtime
        .owner
        .store
        .plan_attempt(
            &blocked,
            rivect::contracts::EffectClass::Read,
            "read allowed file",
        )
        .expect("plan unknown attempt");
    world
        .runtime
        .owner
        .store
        .attempt_unknown(&attempt, "receipt lost")
        .expect("persist unknown attempt");
    world
        .runtime
        .owner
        .store
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
        .owner
        .store
        .plan_attempt(
            &blocked,
            rivect::contracts::EffectClass::Read,
            "read allowed file from second attempt",
        )
        .expect("plan sibling attempt on the same obligation");
    world
        .runtime
        .owner
        .store
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
        .owner
        .store
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
            .owner
            .store
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
    assert!(
        matches!(
            err,
            rivect::state::StoreError::Conflict(
                rivect::state::ConflictCause::CompletionOpen { unresolved, .. }
            ) if unresolved > 0
        ),
        "{err}"
    );
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

const TUI_ROWS: usize = 24;
const TUI_COLS: usize = 80;

fn reconstruct_tui_screen(bytes: &[u8]) -> String {
    let mut cells = vec![vec![b' '; TUI_COLS]; TUI_ROWS];
    let mut row = 0;
    let mut col = 0;
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'\x1b' => {
                index += 1;
                if index >= bytes.len() {
                    break;
                }
                if bytes[index] != b'[' {
                    index += 1;
                    continue;
                }
                index += 1;
                let params_start = index;
                while index < bytes.len() && !(0x40..=0x7e).contains(&bytes[index]) {
                    index += 1;
                }
                if index == bytes.len() {
                    break;
                }
                let final_byte = bytes[index];
                let params = &bytes[params_start..index];
                index += 1;
                if params.first() == Some(&b'?') {
                    continue;
                }
                let parameters = params
                    .split(|byte| *byte == b';')
                    .map(|parameter| {
                        if parameter.is_empty() {
                            None
                        } else {
                            std::str::from_utf8(parameter)
                                .ok()
                                .and_then(|value| value.parse::<usize>().ok())
                        }
                    })
                    .collect::<Vec<_>>();
                let parameter = |position: usize, default: usize| {
                    parameters
                        .get(position)
                        .and_then(|value| *value)
                        .unwrap_or(default)
                };
                match final_byte {
                    b'H' | b'f' => {
                        row = parameter(0, 1).max(1).saturating_sub(1).min(TUI_ROWS - 1);
                        col = parameter(1, 1).max(1).saturating_sub(1).min(TUI_COLS - 1);
                    }
                    b'A' => row = row.saturating_sub(parameter(0, 1).max(1)),
                    b'B' => row = row.saturating_add(parameter(0, 1).max(1)).min(TUI_ROWS - 1),
                    b'C' | b'a' => {
                        col = col.saturating_add(parameter(0, 1).max(1)).min(TUI_COLS - 1)
                    }
                    b'D' => col = col.saturating_sub(parameter(0, 1).max(1)),
                    b'G' => col = parameter(0, 1).max(1).saturating_sub(1).min(TUI_COLS - 1),
                    b'd' => row = parameter(0, 1).max(1).saturating_sub(1).min(TUI_ROWS - 1),
                    b'E' => {
                        row = row.saturating_add(parameter(0, 1).max(1)).min(TUI_ROWS - 1);
                        col = 0;
                    }
                    b'F' => {
                        row = row.saturating_sub(parameter(0, 1).max(1));
                        col = 0;
                    }
                    b'J' => match parameter(0, 0) {
                        0 => {
                            for cell in &mut cells[row][col..] {
                                *cell = b' ';
                            }
                            for line in cells.iter_mut().skip(row + 1) {
                                line.fill(b' ');
                            }
                        }
                        1 => {
                            for line in cells.iter_mut().take(row) {
                                line.fill(b' ');
                            }
                            for cell in &mut cells[row][..=col] {
                                *cell = b' ';
                            }
                        }
                        2 | 3 => {
                            for line in &mut cells {
                                line.fill(b' ');
                            }
                        }
                        _ => {}
                    },
                    b'K' => match parameter(0, 0) {
                        0 => cells[row][col..].fill(b' '),
                        1 => cells[row][..=col].fill(b' '),
                        2 => cells[row].fill(b' '),
                        _ => {}
                    },
                    _ => {}
                }
                continue;
            }
            b'\r' => col = 0,
            b'\n' => row = (row + 1).min(TUI_ROWS - 1),
            b'\x08' => col = col.saturating_sub(1),
            byte if (0x20..=0x7e).contains(&byte) => {
                cells[row][col] = byte;
                col = (col + 1).min(TUI_COLS - 1);
            }
            _ => {}
        }
        index += 1;
    }

    cells
        .iter()
        .map(|line| {
            String::from_utf8_lossy(line)
                .trim_end_matches(' ')
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn wait_for_visible_tui_text(pty: &support::PtySession, needle: &str, timeout: Duration) -> String {
    let deadline = std::time::Instant::now() + timeout;
    let mut visible = reconstruct_tui_screen(&pty.collected());
    while !visible.contains(needle) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
        visible = reconstruct_tui_screen(&pty.collected());
    }
    visible
}

#[test]
fn tui_enter_dispatches_tasks_and_help() {
    let mut pty = spawn_pty(&rivect_binary(), TUI_ROWS as u16, TUI_COLS as u16);
    assert!(
        pty.wait_for(b"\x1b[?1049h", Duration::from_secs(10)),
        "alternate screen must be entered on start"
    );
    pty.send(b"\r/help\r");
    let visible = wait_for_visible_tui_text(&pty, "Commands:", Duration::from_secs(10));
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

    pty.send(b"task from q\r");
    let visible = wait_for_visible_tui_text(
        &pty,
        "Submitted task: task from q (accepted: ",
        Duration::from_secs(10),
    );
    assert!(
        visible.contains("Submitted task: task from q (accepted: "),
        "non-empty Enter must show the accepted task receipt: {visible:?}"
    );
    assert!(
        visible.contains(": running"),
        "task dock must show accepted work: {visible:?}"
    );
    pty.send(b"\x1b");
    assert_eq!(pty.wait_exit(Duration::from_secs(10)), Some(0));
}

#[test]
fn tui_lowercase_q_starts_composer_and_dispatches_exact_goal() {
    let mut pty = spawn_pty(&rivect_binary(), TUI_ROWS as u16, TUI_COLS as u16);
    assert!(
        pty.wait_for(b"\x1b[?1049h", Duration::from_secs(10)),
        "alternate screen must be entered on start"
    );

    pty.send(b"q");
    let visible = wait_for_visible_tui_text(&pty, "> q", Duration::from_secs(10));
    assert!(
        visible.contains("> q"),
        "first lowercase q must remain in composer while TUI runs: {visible:?}"
    );

    pty.send(b"uery the root\r");
    let visible = wait_for_visible_tui_text(
        &pty,
        "Submitted task: query the root (accepted: ",
        Duration::from_secs(10),
    );
    assert!(
        visible.contains("Submitted task: query the root (accepted: "),
        "TUI must dispatch exact goal after q-first input: {visible:?}"
    );

    pty.send(b"\x1b");
    assert_eq!(pty.wait_exit(Duration::from_secs(10)), Some(0));

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
}

#[test]
fn tui_data_root_flag_overrides_environment() {
    let flag_root = support::temp_dir("tui-flag-root");
    let env_root = support::temp_dir("tui-env-root");
    let flag_text = flag_root.to_string_lossy().to_string();
    let mut pty = spawn_pty_with_args(
        &rivect_binary(),
        24,
        80,
        &flag_root,
        &env_root,
        &["--data-root", &flag_text],
    );
    assert!(
        pty.wait_for(b"\x1b[?1049h", Duration::from_secs(10)),
        "TUI must start"
    );
    pty.send(b"p\r");
    std::thread::sleep(Duration::from_secs(2));
    pty.send(b"\x1b");
    let exit = pty.wait_exit(Duration::from_secs(10));
    assert_eq!(exit, Some(0), "TUI must exit cleanly");
    assert!(
        flag_root.join("runtime").join("rivect.db").exists(),
        "TUI must use --data-root"
    );
    assert!(
        !env_root.join("runtime").exists(),
        "TUI must not use RIVECT_DATA_ROOT when flag is present"
    );

    let env_only_root = support::temp_dir("tui-env-only-root");
    let mut env_only = spawn_pty_with_args(
        &rivect_binary(),
        24,
        80,
        &env_only_root,
        &env_only_root,
        &[],
    );
    assert!(
        env_only.wait_for(b"\x1b[?1049h", Duration::from_secs(10)),
        "TUI must start without --data-root"
    );
    env_only.send(b"p\r");
    std::thread::sleep(Duration::from_secs(2));
    env_only.send(b"\x1b");
    assert_eq!(env_only.wait_exit(Duration::from_secs(10)), Some(0));
    assert!(
        env_only_root.join("runtime").join("rivect.db").exists(),
        "TUI without flag must use RIVECT_DATA_ROOT"
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
    pty.send(b"\x1b");
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
fn tui_error_restores_terminal() {
    use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
    use std::io::{Read, Write};

    let data_root = support::temp_dir("pty-error").join("root-file");
    std::fs::write(&data_root, b"not a directory").expect("root file");
    let pty_system = NativePtySystem::default();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("openpty");
    let mut command = CommandBuilder::new(rivect_binary());
    command.env("RIVECT_DATA_ROOT", &data_root);
    let mut child = pair.slave.spawn_command(command).expect("spawn");
    let mut writer = pair.master.take_writer().expect("writer");
    let mut reader = pair.master.try_clone_reader().expect("reader");
    let stream = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = stream.clone();
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => sink
                    .lock()
                    .expect("pty lock")
                    .extend_from_slice(&chunk[..n]),
            }
        }
    });

    let started_deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < started_deadline
        && support::find_subsequence(&stream.lock().expect("pty lock"), b"\x1b[?1049h").is_none()
    {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        support::find_subsequence(&stream.lock().expect("pty lock"), b"\x1b[?1049h").is_some(),
        "alternate screen must be entered on start"
    );
    writer.write_all(b"a\r").expect("input");
    writer.flush().expect("flush");

    let exit_deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut exit_code = None;
    while std::time::Instant::now() < exit_deadline {
        if let Ok(Some(status)) = child.try_wait() {
            exit_code = Some(status.exit_code());
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if exit_code.is_none() {
        let _ = child.kill();
    }
    assert_eq!(exit_code, Some(1));

    let restore_deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < restore_deadline
        && support::find_subsequence(&stream.lock().expect("pty lock"), b"\x1b[?1049l").is_none()
    {
        std::thread::sleep(Duration::from_millis(25));
    }
    let stream = stream.lock().expect("pty lock");
    assert!(
        support::find_subsequence(&stream, b"\x1b[?1049l").is_some(),
        "open error must leave alternate screen"
    );
    assert!(
        support::find_subsequence(&stream, b"\x1b[?25h").is_some(),
        "open error must show cursor"
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
fn headless_config_error_names_path_and_stage() {
    let data_root = support::temp_dir("config-error-path");
    std::fs::write(data_root.join("config.toml"), "[workflow\n").expect("invalid config");
    let output = std::process::Command::new(rivect_binary())
        .arg("--headless")
        .arg("--data-root")
        .arg(&data_root)
        .output()
        .expect("run headless");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let path_text = data_root.join("config.toml").to_string_lossy().to_string();
    let expected_prefix =
        format!("runtime open failed: owner configuration failed: {path_text}: parse: ");
    assert!(
        stderr.trim_end().starts_with(&expected_prefix),
        "owner/config/parse chain must name path and stage: {stderr}"
    );
}

#[test]
fn headless_rejects_oversized_config() {
    let data_root = support::temp_dir("config-oversized");
    std::fs::write(
        data_root.join("config.toml"),
        vec![b'x'; rivect::contracts::REQUEST_MAX_BYTES + 1],
    )
    .expect("oversized config");
    let output = std::process::Command::new(rivect_binary())
        .arg("--headless")
        .arg("--data-root")
        .arg(&data_root)
        .output()
        .expect("run headless");
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
    let data_root = support::temp_dir("headless-oversized");
    let mut child = std::process::Command::new(rivect_binary())
        .arg("--headless")
        .arg("--data-root")
        .arg(&data_root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn headless");
    let mut input = vec![b'x'; rivect::contracts::REQUEST_MAX_BYTES + 1];
    input.push(b'\n');
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&input)
        .expect("write oversized request");
    let output = child.wait_with_output().expect("wait headless");
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
    let data_root = support::temp_dir("headless-oversized-non-utf8");
    let mut child = std::process::Command::new(rivect_binary())
        .arg("--headless")
        .arg("--data-root")
        .arg(&data_root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn headless");
    let mut input = vec![0xff; rivect::contracts::REQUEST_MAX_BYTES + 1];
    input.push(b'\n');
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&input)
        .expect("write oversized non-utf8 request");
    let output = child.wait_with_output().expect("wait headless");
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
    let data_root = support::temp_dir("headless-open-verdict");
    stage_pending_verdict_then_broken_config(&data_root);
    let output = std::process::Command::new(rivect_binary())
        .arg("--headless")
        .arg("--data-root")
        .arg(&data_root)
        .env_clear()
        .output()
        .expect("run headless");
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
    let data_root = support::temp_dir("pty-open-verdict");
    stage_pending_verdict_then_broken_config(&data_root);
    let mut pty = spawn_pty_with_args(&rivect_binary(), 24, 80, &data_root, &data_root, &[]);
    // The degraded session still enters the alternate screen and renders
    // the open failure on its transcript — asserted on the reconstructed
    // screen, since the renderer emits positioned words, not raw lines.
    let visible = wait_for_visible_tui_text(&pty, "session open failed", Duration::from_secs(10));
    assert!(
        visible.contains("session open failed"),
        "the transcript records the open failure inside the session: {visible:?}"
    );
    assert!(
        visible.contains("publication recovery"),
        "the carried verdict reaches the transcript inside the session: {visible:?}"
    );
    let stream = pty.collected();
    let verdict = support::find_subsequence(&stream, b"publication recovery");
    let entered = support::find_subsequence(&stream, b"\x1b[?1049h");
    assert!(
        matches!((verdict, entered), (Some(v), Some(e)) if v < e),
        "the pending verdict must reach the terminal before the alternate screen takes it: {:?}",
        String::from_utf8_lossy(&stream)
    );
    pty.send(&[0x1b]);
    assert_eq!(
        pty.wait_exit(Duration::from_secs(10)),
        Some(0),
        "Esc leaves the degraded session normally"
    );
}

#[test]
fn tui_lazy_retry_failed_open_reports_verdict_after_restore() {
    let data_root = support::temp_dir("pty-lazy-open-verdict");
    stage_pending_verdict_then_broken_config(&data_root);
    let mut pty = spawn_pty_with_args(&rivect_binary(), 24, 80, &data_root, &data_root, &[]);
    // The degraded session leaves the dispatch slot empty, so a submitted
    // task drives the lazy-retry open: it fails the same way and its
    // propagated error is the only channel left once the guard restores
    // the primary screen.
    let visible = wait_for_visible_tui_text(&pty, "session open failed", Duration::from_secs(10));
    assert!(
        visible.contains("session open failed"),
        "the degraded session records the eager open failure: {visible:?}"
    );
    pty.send(b"retry the open\r");
    assert_eq!(
        pty.wait_exit(Duration::from_secs(10)),
        Some(1),
        "the failed lazy retry must propagate out of the loop"
    );
    // The drain thread keeps appending past the observed exit, so the
    // post-restore slice is polled to a deadline rather than read once.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut stream = pty.collected();
    loop {
        let tail = support::find_subsequence(&stream, b"\x1b[?1049l")
            .map(|leave| &stream[leave + b"\x1b[?1049l".len()..]);
        if tail
            .is_some_and(|tail| support::find_subsequence(tail, b"publication recovery").is_some())
            || std::time::Instant::now() >= deadline
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
        stream = pty.collected();
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
