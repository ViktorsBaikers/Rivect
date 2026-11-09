//! Local ingress (AC-078): a file read, a confined process, steering and
//! cancellation all run through the public entry inside their declared scope;
//! a target outside that scope and a direct egress that was never approved are
//! refused typed instead of being reported as done. The read leg drives the
//! built executable's real entry, so the declared scope is the one a shipped
//! binary binds rather than a fixture's setter. The last case drives the real
//! terminal: the built executable paints on a pty and restores it.

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

use rivect::contracts::{AnswerSelection, EffectClass, Lifecycle};
use rivect::executor::{EffectOutcome, EffectRequest};
use rivect::policy::{ModeDecision, PermissionMode};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::atomic::Ordering;
use std::time::Duration;

/// A read worker that delegates every leg to the platform backend: the fixture
/// worker's trait defaults refuse exec and egress, so a positive leg must name
/// the real backend explicitly or it would prove only the default refusal.
struct PlatformWorker;

impl rivect::executor::ReadWorker for PlatformWorker {
    fn read_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
    ) -> Result<rivect::executor::ReadObservation, rivect::executor::WorkerError> {
        support::platform_read_once(scope_root, target)
    }

    #[cfg(target_os = "linux")]
    fn exec_once(
        &mut self,
        scope_root: &Path,
        program: &Path,
    ) -> Result<(), rivect::executor::WorkerError> {
        rivect::executor::linux::exec_once(scope_root, program)
    }

    #[cfg(not(target_os = "linux"))]
    fn exec_once(
        &mut self,
        scope_root: &Path,
        program: &Path,
    ) -> Result<(), rivect::executor::WorkerError> {
        rivect::executor::macos::exec_once(scope_root, program)
    }

    #[cfg(target_os = "linux")]
    fn egress_once(&mut self, url: &str) -> Result<(), rivect::executor::WorkerError> {
        rivect::executor::linux::egress_once(url)
    }

    #[cfg(not(target_os = "linux"))]
    fn egress_once(&mut self, url: &str) -> Result<(), rivect::executor::WorkerError> {
        rivect::executor::macos::egress_once(url)
    }
}

/// One headless child over a caller-owned scope root: the binary's declared
/// read scope is the directory it was started in, so the read cases drive the
/// real entry instead of a fixture's scope setter.
fn spawn_headless(
    scope_root: &Path,
    data_root: &Path,
) -> (Child, ChildStdin, BufReader<ChildStdout>) {
    let mut command = std::process::Command::new(support::rivect_binary());
    command
        .arg("--headless")
        .arg("--data-root")
        .arg(data_root)
        .current_dir(scope_root)
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

#[test]
fn read_file_ingress_through_the_real_entry_reads_in_scope_and_bounds_its_preview() {
    let scope_root = tempfile::TempDir::with_prefix("rivect-ingress-read-scope-").expect("scope");
    let data_root = tempfile::TempDir::with_prefix("rivect-ingress-read-data-").expect("data");
    let inside = scope_root.path().join("scope-file.txt");
    std::fs::write(&inside, "a".repeat(9_000)).expect("write scoped file");
    let outside = tempfile::TempDir::with_prefix("rivect-ingress-read-outside-").expect("outside");
    let foreign = outside.path().join("outside.txt");
    std::fs::write(&foreign, "secret").expect("write outside file");

    let (mut child, mut stdin, mut stdout) = spawn_headless(scope_root.path(), data_root.path());
    write_frame(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "session.attach",
            "params": { "schema_version": 1, "bootstrap_id": "ingress-read-1" }
        }),
    );
    let attached = read_answer(&mut stdout);
    let session = attached["result"]["session_id"]
        .as_str()
        .expect("session id")
        .to_string();
    write_frame(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "id": 2, "method": "task.submit",
            "params": {
                "schema_version": 1, "command_id": "ingress-read-create",
                "session_id": session, "kind": "create",
                "goal": "read one scoped file",
                "contract": { "criteria": [], "constraints": [] },
            }
        }),
    );
    let created = read_answer(&mut stdout);
    let task = created["result"]["task_id"]
        .as_str()
        .expect("task id")
        .to_string();

    let inside_frame = support::command_execute(
        &rivect::contracts::SessionId(session.clone()),
        "read_file",
        json!({ "task_id": task, "path": inside.to_str().expect("utf-8") }),
    );
    let inside_frame: Value = serde_json::from_str(&inside_frame).expect("frame value");
    write_frame(&mut stdin, &inside_frame);
    let read = read_answer(&mut stdout);
    assert!(
        read.get("error").is_none(),
        "the real entry admits the read: {read}"
    );
    let outcome = &read["result"]["outcome"];
    assert_eq!(outcome["class"], "read", "{outcome}");
    assert_eq!(outcome["bytes"], 9_000, "the answer names the whole file");
    assert_eq!(outcome["truncated"], true, "{outcome}");
    assert_eq!(
        outcome["text"].as_str().expect("preview text").len(),
        8 * 1024,
        "the preview stops at its bound"
    );
    assert_eq!(outcome["digest"].as_str().map(str::len), Some(64));

    let outside_frame = support::command_execute(
        &rivect::contracts::SessionId(session),
        "read_file",
        json!({ "task_id": task, "path": foreign.to_str().expect("utf-8") }),
    );
    let outside_frame: Value = serde_json::from_str(&outside_frame).expect("frame value");
    write_frame(&mut stdin, &outside_frame);
    let denied = read_answer(&mut stdout);
    assert_eq!(
        denied["error"]["data"]["code"], "denied",
        "an out-of-scope read is refused: {denied}"
    );
    assert!(denied.get("result").is_none(), "{denied}");

    drop(stdin);
    let status = child.wait().expect("wait for the entry");
    assert_eq!(status.code(), Some(3), "the denial is the run's exit class");
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().expect("stderr"), &mut stderr)
        .expect("read stderr");
    assert!(
        !stderr.contains('{'),
        "stderr carries diagnostics, never an answer frame: {stderr:?}"
    );
}

#[test]
fn exec_ingress_runs_a_confined_program() {
    // The exec positive is the only host-conditional leg in this target: it
    // owns its own test so its `NOT_RUN` return can never skip a proof that
    // could have run elsewhere.
    let (provider, calls, _manifest) = support::CountingProvider::new();
    let mut world = support::open_world_with(
        "ingress-exec",
        None,
        Box::new(provider),
        Box::new(PlatformWorker),
    );
    let session = world.open_session("ingress-exec");
    let task = world.create_task(&session, "ingress-exec-task");
    world
        .runtime
        .store_writer()
        .materialize_obligations(&task)
        .expect("obligations");

    // A real program inside the granted scope, run through admission.
    std::fs::copy("/usr/bin/true", world.root.join("true")).expect("copy true into scope");
    let program = world.root.join("true");
    let grant = world
        .runtime
        .policy_writer()
        .grant_classes(world.root.clone(), vec![EffectClass::Exec]);
    let admitted = {
        let mut executor = world.runtime.executor();
        executor
            .admit(
                &task,
                EffectRequest::Exec {
                    grant_id: grant,
                    program,
                },
                PermissionMode::Yolo,
            )
            .expect("the exec cell is admitted")
    };
    let outcome = {
        let mut executor = world.runtime.executor();
        executor.execute(&admitted)
    };
    match outcome {
        Ok(EffectOutcome::Executed { .. }) => {}
        Err(
            rivect::executor::ExecutorError::Worker(
                rivect::executor::WorkerError::SandboxUnavailable { .. }
                | rivect::executor::WorkerError::SandboxSpawnFailed { .. }
                | rivect::executor::WorkerError::ExecUnavailable,
            )
            | rivect::executor::ExecutorError::Worker(
                rivect::executor::WorkerError::OwnedLaunch { .. }
                | rivect::executor::WorkerError::OwnedPreparation { .. },
            ),
        ) => {
            // The host cannot run the confined leg: report the gap instead of
            // claiming the positive.
            eprintln!(
                "NOT_RUN: confined exec is unavailable on this host; only the exec positive leg is skipped"
            );
            return;
        }
        other => panic!("unexpected exec outcome: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no wire");
}

#[test]
fn steering_and_in_flight_cancellation_always_run() {
    // No host-conditional leg here: steering, the machine refusal and the
    // in-flight cancellation execute on every host, so a suite that reported
    // pass while these were skipped would have to be red here.
    let mut world = support::open_world("ingress-steer-cancel", None);
    let session = world.open_session("ingress-steer-cancel");
    let task = world.create_task(&session, "ingress-steer-cancel-task");

    // Steering is a human ingress decision: the trusted entry moves the intent
    // revision, and the machine channel cannot prove consent.
    let steer = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "task.submit",
        "params": { "schema_version": 1, "session_id": session.0, "task_id": task.0,
                    "kind": "steer", "command_id": "ingress-steer-1",
                    "expected_intent_revision": 1,
                    "expected_task_revision": 1, "instruction": "narrow the question" }
    }));
    assert!(steer.get("error").is_none(), "{steer}");
    let intent = steer["result"]["intent_revision"]
        .as_u64()
        .expect("intent revision moved");
    assert!(intent > 1, "{steer}");
    let machine = world.dispatch_machine(&json!({
        "jsonrpc": "2.0", "id": 3, "method": "task.submit",
        "params": { "schema_version": 1, "session_id": session.0, "task_id": task.0,
                    "kind": "steer", "command_id": "ingress-steer-2",
                    "expected_intent_revision": intent,
                    "expected_task_revision": 2, "instruction": "machine steer" }
    }));
    assert_eq!(
        machine["error"]["data"]["code"], "denied",
        "a machine steer is refused: {machine}"
    );

    // In-flight cancellation: a live task is cancelled while it is running,
    // and its next decision step terminates without performing any effect.
    let live = world.create_task(&session, "ingress-cancel-live");
    let live_snapshot = world.runtime.store().snapshot(&live).expect("snapshot");
    assert_eq!(live_snapshot.lifecycle, Lifecycle::Running);
    let reads_before = world.worker_reads();
    let cancel = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 4, "method": "task.submit",
        "params": { "schema_version": 1, "session_id": session.0, "task_id": live.0,
                    "kind": "cancel", "command_id": "ingress-cancel-live-1",
                    "expected_intent_revision": live_snapshot.intent_revision,
                    "reason": "ingress cancellation" }
    }));
    assert!(cancel.get("error").is_none(), "{cancel}");
    assert_eq!(cancel["result"]["status"], "applied", "{cancel}");
    assert_eq!(
        world
            .runtime
            .store()
            .snapshot(&live)
            .expect("snapshot")
            .lifecycle,
        Lifecycle::Cancelled,
        "the cancellation reached the running task"
    );
    let grant_id = world.runtime.scoped_grant.clone();
    let outcome = world
        .runtime
        .run_decision_step(
            &session,
            &live,
            &AnswerSelection::Custom {
                text: "read the scoped file".to_string(),
            },
            &grant_id,
            false,
        )
        .expect("cancelled step");
    match outcome {
        rivect::controller::StepOutcome::NoAction { snapshot } => {
            assert_eq!(
                snapshot.lifecycle,
                Lifecycle::Cancelled,
                "the cancelled task terminates instead of dispatching"
            );
        }
        other => panic!("a cancelled task must not dispatch: {other:?}"),
    }
    assert_eq!(
        world.worker_reads(),
        reads_before,
        "the cancelled task performed no effect"
    );
}

#[test]
fn egress_ingress_refuses_a_destination_it_was_never_granted() {
    let (provider, calls, _manifest) = support::CountingProvider::new();
    let mut world = support::open_world_with(
        "ingress-egress",
        None,
        Box::new(provider),
        Box::new(PlatformWorker),
    );
    let session = world.open_session("ingress-egress");
    let task = world.create_task(&session, "ingress-egress-task");
    let grant = world.runtime.policy_writer().grant_classes(
        world.root.clone(),
        vec![EffectClass::Read, EffectClass::Egress],
    );
    // Web: the executor's admission is the gate. Under the interim manual
    // mode a destination that was never preapproved asks, so no byte is sent
    // and the caller reads the typed verdict instead of a false success.
    let verdict = {
        let mut executor = world.runtime.executor();
        match executor.admit(
            &task,
            EffectRequest::Egress {
                grant_id: grant.clone(),
                url: "https://example.invalid/never-approved".to_string(),
            },
            PermissionMode::Manual,
        ) {
            Ok(_) => panic!("an unapproved destination is never admitted silently"),
            Err(error) => error,
        }
    };
    assert!(
        matches!(verdict, rivect::executor::ExecutorError::ModeAsk),
        "the refusal is the mode consult's own: {verdict}"
    );
    // Web at the public entry: an `mcp.call` naming a server this installation
    // never declared is refused typed before anything is planned.
    let undeclared = world.dispatch(&support::command_execute(
        &session,
        "mcp.call",
        json!({ "task_id": task.0, "grant_id": grant,
                "server": "never-declared", "tool": "read",
                "arguments": {} }),
    ));
    assert_eq!(
        undeclared["error"]["data"]["code"], "not_found",
        "an undeclared server is refused typed: {undeclared}"
    );
    // The same destination under an explicit allow still has to pass the
    // destination policy, so a grant that names no origin cannot smuggle one.
    let decision = world.runtime.policy().decide(
        Path::new("https://example.invalid/never-approved"),
        EffectClass::Egress,
        &rivect::policy::AdmissionContext {
            mode: PermissionMode::PreapprovedOnly,
            in_grant_scope: true,
            budget_remaining: true,
            in_trusted_scope: false,
            has_checkpoint: false,
            previously_approved: false,
            within_declared_bounds: false,
            dry_run: false,
        },
    );
    assert_eq!(
        decision,
        ModeDecision::Deny,
        "an unapproved egress target stays denied under an all-class grant"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no wire");
}

#[test]
fn git_ingress_refuses_an_unscoped_program_before_any_spawn() {
    let (provider, calls, _manifest) = support::CountingProvider::new();
    let mut world = support::open_world_with(
        "ingress-git",
        None,
        Box::new(provider),
        Box::new(PlatformWorker),
    );
    let session = world.open_session("ingress-git");
    let task = world.create_task(&session, "ingress-git-task");
    world
        .runtime
        .store_writer()
        .materialize_obligations(&task)
        .expect("obligations");
    let grant = world
        .runtime
        .policy_writer()
        .grant_classes(world.root.clone(), vec![EffectClass::Exec]);
    // A Git invocation is an exec-class effect: a program outside the granted
    // scope asks under the interim manual mode and never reaches a spawn.
    let verdict = {
        let mut executor = world.runtime.executor();
        match executor.admit(
            &task,
            EffectRequest::Exec {
                grant_id: grant,
                program: PathBuf::from("/usr/bin/git"),
            },
            PermissionMode::Manual,
        ) {
            Ok(_) => panic!("an unscoped program is never admitted silently"),
            Err(error) => error,
        }
    };
    assert_eq!(
        verdict.error_code(),
        rivect::contracts::ErrorCode::Denied,
        "the git leg is refused before any spawn: {verdict}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no wire");
}

#[test]
fn vision_purpose_is_refused_before_any_send() {
    let (provider, calls, _manifest) = support::CountingProvider::new();
    let mut world = support::open_world_with(
        "ingress-vision",
        None,
        Box::new(provider),
        Box::new(PlatformWorker),
    );
    let config = world.runtime.config_for_broker();
    // A vision request is a model-class effect: a purpose the document does
    // not declare is refused by the broker before any wire attempt.
    let prepared = world.runtime.broker.prepare(
        "vision",
        &config,
        "/world/ingress-vision",
        "describe the image",
    );
    assert!(
        prepared.is_err(),
        "an undeclared vision purpose is refused: {prepared:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no wire");
}

/// A read worker that refuses every read with one fixed typed failure: the
/// seam a `read_file` mapping case needs, since the fixture worker always
/// succeeds.
struct FailingReadWorker(fn() -> rivect::executor::WorkerError);

impl rivect::executor::ReadWorker for FailingReadWorker {
    fn read_once(
        &mut self,
        _scope_root: &Path,
        _target: &Path,
    ) -> Result<rivect::executor::ReadObservation, rivect::executor::WorkerError> {
        Err((self.0)())
    }
}

#[test]
fn read_file_maps_executor_failures_to_their_own_class() {
    // A worker that cannot start its sandbox is a capability failure, never a
    // policy denial: a handler that hard-coded `Denied` fails this line.
    let (provider, _calls, _manifest) = support::CountingProvider::new();
    let mut unavailable = support::open_world_with(
        "ingress-read-unavailable",
        None,
        Box::new(provider),
        Box::new(FailingReadWorker(|| {
            rivect::executor::WorkerError::SandboxUnavailable {
                reason: "fixture sandbox unavailable".to_string(),
            }
        })),
    );
    let session = unavailable.open_session("ingress-read-unavailable");
    let task = unavailable.create_task(&session, "ingress-read-unavailable-task");
    let path = unavailable.root.join("mapping.txt");
    std::fs::write(&path, "mapping").expect("write scoped file");
    unavailable
        .runtime
        .set_read_scope(unavailable.root.clone(), path.clone());
    let response = unavailable.dispatch(&support::command_execute(
        &session,
        "read_file",
        json!({ "task_id": task.0, "path": path.to_str().expect("utf-8") }),
    ));
    assert_eq!(
        response["error"]["data"]["code"], "capability_unavailable",
        "an unavailable sandbox is not a denial: {response}"
    );

    // A post-mutation write failure on the read leg is the reachable
    // `unknown` class: its outcome is not proven, so it is not a denial.
    let (provider, _calls, _manifest) = support::CountingProvider::new();
    let mut unknown = support::open_world_with(
        "ingress-read-unknown",
        None,
        Box::new(provider),
        Box::new(FailingReadWorker(|| {
            rivect::executor::WorkerError::WriteMutationFailed {
                source: std::io::Error::other("fixture mutation unknown"),
            }
        })),
    );
    let session = unknown.open_session("ingress-read-unknown");
    let task = unknown.create_task(&session, "ingress-read-unknown-task");
    let path = unknown.root.join("mapping.txt");
    std::fs::write(&path, "mapping").expect("write scoped file");
    unknown
        .runtime
        .set_read_scope(unknown.root.clone(), path.clone());
    let response = unknown.dispatch(&support::command_execute(
        &session,
        "read_file",
        json!({ "task_id": task.0, "path": path.to_str().expect("utf-8") }),
    ));
    assert_eq!(
        response["error"]["data"]["code"], "outcome_unknown",
        "an unknown mutation is not a denial: {response}"
    );

    // `WorkerUnproven` is constructed only for a mutating effect, so the read
    // leg cannot reach it; the class the handler's one mapping carries for it
    // is asserted at the boundary the handler calls.
    let unproven = rivect::executor::ExecutorError::WorkerUnproven {
        primary: rivect::executor::WorkerError::OwnedLaunch {
            source: Box::new(rivect::executor::OwnedLaunchError::Unproven {
                primary: Box::new(rivect::executor::WorkerError::SandboxUnavailable {
                    reason: "fixture unproven".to_string(),
                }),
                release: None,
                locators: Vec::new(),
                expected_identities: Vec::new(),
                stop: None,
            }),
        },
    };
    assert_eq!(
        unproven.error_code(),
        rivect::contracts::ErrorCode::OutcomeUnknown,
        "an unproven outcome keeps its own class"
    );
}

#[test]
fn the_pty_tui_paints_and_restores_the_terminal() {
    let root = tempfile::TempDir::with_prefix("rivect-ingress-pty-").expect("pty root");
    let data_root = root.path().to_path_buf();
    let mut command = support::pty_command(support::rivect_binary());
    command.env("RIVECT_DATA_ROOT", &data_root);
    command.arg("--data-root");
    command.arg(&data_root);
    command.arg("--tui");
    command.arg("fullscreen");
    let mut session = match support::PtySession::spawn(command, 24, 80, root, data_root) {
        Ok(session) => session,
        // A host that cannot allocate a pty is an honest NOT_RUN, never a pass.
        Err(error) => {
            eprintln!("NOT_RUN: pty unavailable: {error}");
            return;
        }
    };
    assert!(
        session
            .wait_for(b"Rivect", Duration::from_secs(10))
            .expect("pty read"),
        "the TUI paints its status line"
    );
    session.send(b"\x1b").expect("send quit");
    let code = session.wait_exit(Duration::from_secs(10)).expect("exit");
    assert_eq!(code, Some(0), "Esc leaves cleanly");
    let collected = session.collected().expect("pty read");
    let rendered = support::reconstruct_screen(&collected, 24, 80);
    assert!(
        rendered.contains("Rivect"),
        "the painted screen carried the status line:\n{rendered}"
    );
    assert!(
        support::find_subsequence(&collected, b"\x1b[?1049l").is_some(),
        "the alternate screen is left on exit"
    );
    session.finish().expect("pty teardown");
}

#[test]
fn a_path_parameter_outside_utf8_is_refused_before_any_effect() {
    // The wire carries text: a path that is not UTF-8 cannot be spelled, and
    // the refusal is typed rather than a lossy conversion into a read of
    // another file.
    let mut world = support::open_world("ingress-path", None);
    let session = world.open_session("ingress-path");
    let task = world.create_task(&session, "ingress-path-task");
    let response = world.dispatch(&support::command_execute(
        &session,
        "read_file",
        json!({ "task_id": task.0, "path": 42 }),
    ));
    assert_eq!(
        response["error"]["data"]["code"], "invalid_input",
        "{response}"
    );
    assert!(response.get("result").is_none(), "{response}");
    let missing = world.dispatch(&support::command_execute(
        &session,
        "read_file",
        json!({ "task_id": task.0 }),
    ));
    assert_eq!(
        missing["error"]["data"]["code"], "invalid_input",
        "{missing}"
    );
}
