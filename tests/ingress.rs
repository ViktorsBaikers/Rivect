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
use std::os::unix::fs::PermissionsExt;
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

/// The local MCP fixture: one newline-delimited JSON-RPC subset
/// (`initialize`, `tools/call`), declared by the operator's document exactly
/// as `tests/mcp.rs` declares its server. The mode selects the one answer a
/// case needs; the fixture records the frames it received and the calls it
/// served, so the assertions read the peer rather than our own buffer.
const MCP_FIXTURE_SERVER: &str = r#"
import json, os, sys

def flag(name, default=None):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default

MODE = flag("--mode", "success")
ROOT = flag("--root", ".")
FRAMES = os.path.join(ROOT, "frames.log")
CALLS = os.path.join(ROOT, "call.count")

def append(path, text):
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())

def counter(path):
    value = 0
    if os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            raw = handle.read().strip()
        value = int(raw) if raw else 0
    value += 1
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(str(value))
    return value

def reply(payload):
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    append(FRAMES, line)
    try:
        request = json.loads(line)
    except ValueError:
        continue
    method = request.get("method")
    identity = request.get("id")
    if method == "initialize":
        served = request.get("params", {}).get("protocolVersion")
        reply({"jsonrpc": "2.0", "id": identity,
               "result": {"protocolVersion": served, "capabilities": {},
                          "serverInfo": {"name": "rivect-ingress-fixture"}}})
        continue
    if method != "tools/call":
        reply({"jsonrpc": "2.0", "id": identity,
               "error": {"code": -32601, "message": "unsupported method"}})
        continue
    counter(CALLS)
    if MODE == "input_required":
        reply({"jsonrpc": "2.0", "id": identity,
               "result": {"resultType": "input_required", "requestState": "state-1"}})
        continue
    if MODE == "oversize":
        # One line past the client's 64 KiB frame bound: the call must stay
        # an unknown outcome, never a 70 KiB payload in the answer.
        reply({"jsonrpc": "2.0", "id": identity,
               "result": {"resultType": "complete",
                          "content": [{"type": "text", "text": "x" * 70000}]}})
        continue
    reply({"jsonrpc": "2.0", "id": identity,
           "result": {"resultType": "complete",
                      "content": [{"type": "text", "text": "done"}]}})
"#;

struct McpFixture {
    directory: tempfile::TempDir,
}

impl McpFixture {
    fn new(tag: &str) -> Self {
        let directory = tempfile::TempDir::with_prefix(format!("rivect-ingress-mcp-{tag}-"))
            .expect("create the mcp fixture root");
        let script = directory.path().join("server.py");
        let program = directory.path().join("server.sh");
        std::fs::write(&script, MCP_FIXTURE_SERVER).expect("write the mcp fixture server");
        std::fs::write(
            &program,
            format!("#!/bin/sh\nexec python3 {} \"$@\"\n", script.display()),
        )
        .expect("write the mcp fixture launcher");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
            .expect("make the mcp fixture launcher executable");
        Self { directory }
    }

    fn root(&self) -> &Path {
        self.directory.path()
    }

    fn frames(&self) -> String {
        std::fs::read_to_string(self.root().join("frames.log")).unwrap_or_default()
    }

    fn calls(&self) -> u64 {
        std::fs::read_to_string(self.root().join("call.count"))
            .ok()
            .and_then(|raw| raw.trim().parse().ok())
            .unwrap_or(0)
    }
}

/// The operator's document: three declared servers over the same local
/// program, each with its own origin and mode. The request names a server and
/// never supplies a program, an environment or an origin.
fn mcp_fixture_config(fixture: &McpFixture) -> String {
    format!(
        "config_version = 1\n\
         [connections.local]\n\
         kind = \"local\"\n\
         endpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"auto\" }}\n\
         [mcp.servers.inbound]\n\
         origin = \"mcp+stdio://ingress-inbound\"\n\
         program = \"{program}\"\n\
         args = [\"--mode\", \"success\", \"--root\", \"{root}\"]\n\
         [mcp.servers.holding]\n\
         origin = \"mcp+stdio://ingress-holding\"\n\
         program = \"{program}\"\n\
         args = [\"--mode\", \"input_required\", \"--root\", \"{root}\"]\n\
         [mcp.servers.large]\n\
         origin = \"mcp+stdio://ingress-large\"\n\
         program = \"{program}\"\n\
         args = [\"--mode\", \"oversize\", \"--root\", \"{root}\"]\n",
        program = fixture.root().join("server.sh").display(),
        root = fixture.root().display(),
    )
}

/// The first executable named `git` on this host, if any: the positive exec
/// leg runs the real program inside the granted scope.
fn system_git() -> Option<PathBuf> {
    std::env::var_os("PATH")
        .and_then(|paths| paths.to_str().map(str::to_string))
        .and_then(|paths| {
            paths
                .split(':')
                .map(|directory| Path::new(directory).join("git"))
                .find(|candidate| candidate.is_file())
        })
}

/// The harmless control program: proves the host's confined exec works before
/// the git leg distinguishes a host gap from the git boundary.
fn system_true() -> Option<PathBuf> {
    ["/usr/bin/true", "/bin/true"]
        .into_iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.is_file())
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
    // owns its own test so its `NOT_RUN` record can never skip a proof that
    // could have run elsewhere.
    support::not_run::reset("ingress.exec");
    let Some(git) = system_git() else {
        support::not_run::record("ingress.exec", "no git program on PATH");
        eprintln!("NOT_RUN: no git program on PATH; the exec positive leg is skipped");
        return;
    };
    let Some(true_source) = system_true() else {
        support::not_run::record("ingress.exec", "no host true program for the exec control");
        eprintln!("NOT_RUN: no host true program; the exec positive leg is skipped");
        return;
    };
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

    // The proof entry is the production executor admission/execute pair
    // (`EffectRequest::Exec`), not a higher shell or PTY entry this build does
    // not expose. The harmless control first distinguishes a host gap from a
    // program the boundary denies; the positive is the real git binary copied
    // into the granted scope, whose argv[0] `git-version` dispatches git's own
    // `version` builtin and exits 0 without arguments.
    let control_program = world.root.join("control-true");
    std::fs::copy(&true_source, &control_program).expect("copy true into scope");
    std::fs::set_permissions(&control_program, std::fs::Permissions::from_mode(0o755))
        .expect("make the control executable");
    let program = world.root.join("git-version");
    std::fs::copy(&git, &program).expect("copy git into scope");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
        .expect("make the scoped git executable");
    assert!(
        control_program.starts_with(&world.root) && program.starts_with(&world.root),
        "both programs are inside the declared scope"
    );
    let grant = world
        .runtime
        .policy_writer()
        .grant_classes(world.root.clone(), vec![EffectClass::Exec]);
    let run = |world: &mut support::World,
               task: &rivect::contracts::TaskId,
               program: &Path|
     -> Result<EffectOutcome, rivect::executor::ExecutorError> {
        let admitted = {
            let mut executor = world.runtime.executor();
            executor.admit(
                task,
                EffectRequest::Exec {
                    grant_id: grant.clone(),
                    program: program.to_path_buf(),
                },
                PermissionMode::Yolo,
            )?
        };
        let mut executor = world.runtime.executor();
        executor.execute(&admitted)
    };
    let host_unavailable = |error: &rivect::executor::ExecutorError| {
        matches!(
            error,
            rivect::executor::ExecutorError::Worker(
                rivect::executor::WorkerError::SandboxUnavailable { .. }
                    | rivect::executor::WorkerError::SandboxSpawnFailed { .. }
                    | rivect::executor::WorkerError::ExecUnavailable,
            ) | rivect::executor::ExecutorError::Worker(
                rivect::executor::WorkerError::OwnedLaunch { .. }
                    | rivect::executor::WorkerError::OwnedPreparation { .. },
            )
        )
    };
    match run(&mut world, &task, &control_program) {
        Ok(EffectOutcome::Executed { detail }) => {
            // The worker never captures the child's stdout, caps stderr at
            // 64 KiB, and the effect carries one fixed observation: the
            // execution's output cannot grow the answer.
            assert_eq!(detail, "exec-performed exit=ok", "{detail}");
            assert!(
                detail.len() <= 64,
                "the captured detail is bounded: {detail}"
            );
        }
        Err(error) if host_unavailable(&error) => {
            support::not_run::record(
                "ingress.exec",
                "confined exec unavailable on this host (sandbox namespaces/landlock)",
            );
            eprintln!(
                "NOT_RUN: confined exec is unavailable on this host; only the exec positive leg is skipped"
            );
            return;
        }
        other => panic!("the control program must execute: {other:?}"),
    }

    // DEC-033's exec rule carries `read-file` beside `write-file` on the
    // literal /dev/null; a confined `cat` of that device discriminates the
    // read half alone, so dropping it turns this leg red.
    #[cfg(target_os = "linux")]
    {
        support::ensure_helper();
        let cat_source = ["/usr/bin/cat", "/bin/cat"]
            .into_iter()
            .map(PathBuf::from)
            .find(|candidate| candidate.is_file())
            .expect("a host cat program");
        let cat = world.root.join("cat-dev-null");
        std::fs::copy(&cat_source, &cat).expect("copy cat into the scope");
        std::fs::set_permissions(&cat, std::fs::Permissions::from_mode(0o755))
            .expect("make the scoped cat executable");
        let cat = cat.canonicalize().expect("canonical cat");
        let confinement =
            rivect::executor::linux::exec_confinement(&world.root).expect("exec confinement");
        let launcher = rivect::executor::linux::SandboxLauncher::default();
        let admitted = rivect::executor::linux::run_confined(
            &launcher,
            &confinement,
            &cat,
            &[std::ffi::OsStr::new("/dev/null")],
        )
        .expect("confined read of /dev/null");
        assert!(
            admitted.exit_ok,
            "the admitted /dev/null read succeeds: {}",
            admitted.stderr
        );
        let denied = rivect::executor::linux::run_confined(
            &launcher,
            &confinement,
            &cat,
            &[std::ffi::OsStr::new("/dev/zero")],
        )
        .expect("confined read of /dev/zero");
        assert!(
            !denied.exit_ok,
            "a read of another device is denied: {}",
            denied.stderr
        );
    }

    // Cancellation outranks a new effect: a cancelled task's admitted exec
    // never reaches the worker, so nothing was spawned.
    let cancelled = world.create_task(&session, "ingress-exec-cancelled");
    world
        .runtime
        .store_writer()
        .materialize_obligations(&cancelled)
        .expect("obligations");
    let snapshot = world
        .runtime
        .store()
        .snapshot(&cancelled)
        .expect("snapshot");
    let cancel = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 9, "method": "task.submit",
        "params": { "schema_version": 1, "session_id": session.0, "task_id": cancelled.0,
                    "kind": "cancel", "command_id": "ingress-exec-cancel",
                    "expected_intent_revision": snapshot.intent_revision,
                    "reason": "ingress cancellation" }
    }));
    assert_eq!(cancel["result"]["status"], "applied", "{cancel}");
    match run(&mut world, &cancelled, &control_program) {
        Err(rivect::executor::ExecutorError::Cancelled) => {}
        other => panic!("a cancelled exec is refused: {other:?}"),
    }

    // The positive: the real git program executes inside the declared scope.
    match run(&mut world, &task, &program) {
        Ok(EffectOutcome::Executed { detail }) => {
            assert_eq!(detail, "exec-performed exit=ok", "{detail}");
            assert!(
                detail.len() <= 64,
                "the captured detail is bounded: {detail}"
            );
        }
        Err(rivect::executor::ExecutorError::Worker(
            rivect::executor::WorkerError::SandboxDenied { .. },
        )) => {
            // The boundary executed the harmless control but denied git: the
            // git positive is not proven, and a retained NOT_RUN would let a
            // removed /dev/null rule read green. Fail instead.
            panic!("the exec boundary denied the real git program after the control executed");
        }
        // The control program already executed, so this host's sandbox is
        // available: every later failure is the git leg's own and a hard
        // failure, never a retained NOT_RUN. Only the control match above
        // may classify an unavailable sandbox.
        other => panic!("the git positive must execute once the control did: {other:?}"),
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
fn egress_ingress_runs_a_declared_mcp_call_with_a_bound_and_cancellation() {
    // The declared public web/egress entry is `command.execute` kind
    // `mcp.call`: the server, program and origin are operator data, and the
    // executor's egress admission is the gate before the first byte.
    let fixture = McpFixture::new("positive");
    let (provider, provider_calls, _manifest) = support::CountingProvider::new();
    let mut world = support::open_world_with(
        "ingress-mcp-positive",
        Some(&mcp_fixture_config(&fixture)),
        Box::new(provider),
        Box::new(PlatformWorker),
    );
    let session = world.open_session("ingress-mcp-positive");
    let task = world.create_task(&session, "ingress-mcp-positive-task");
    let grant = world
        .runtime
        .policy_writer()
        .grant_classes(world.root.clone(), vec![EffectClass::Egress]);

    // Before the operator's destination consent, the declared server is
    // refused at the executor's own admission: no frame reaches the peer.
    let unapproved = world.dispatch(&support::command_execute(
        &session,
        "mcp.call",
        json!({ "task_id": task.0, "grant_id": grant,
                "server": "inbound", "tool": "fixture.echo", "arguments": {} }),
    ));
    assert_eq!(
        unapproved["error"]["data"]["code"], "denied",
        "an unapproved declared origin is refused: {unapproved}"
    );
    assert_eq!(
        fixture.frames(),
        "",
        "an unapproved destination sends no byte"
    );

    for origin in [
        "mcp+stdio://ingress-inbound",
        "mcp+stdio://ingress-holding",
        "mcp+stdio://ingress-large",
    ] {
        let scope = rivect::policy::preapproval_scope(EffectClass::Egress, &grant, origin)
            .expect("the egress preapproval key");
        world
            .runtime
            .store_writer()
            .record_preapproval(&scope, "operator", 600)
            .expect("record the destination consent");
    }

    // Positive: the declared-scope call succeeds and answers the peer's own
    // content; the fixture served exactly one handshake and one call frame.
    let call = world.dispatch(&support::command_execute(
        &session,
        "mcp.call",
        json!({ "task_id": task.0, "grant_id": grant,
                "server": "inbound", "tool": "fixture.echo",
                "arguments": { "text": "hello" } }),
    ));
    assert!(call.get("error").is_none(), "the call is admitted: {call}");
    let result = &call["result"];
    assert_eq!(result["kind"], "mcp.call", "{call}");
    assert_eq!(result["state"], "succeeded", "{call}");
    assert_eq!(result["result"][0]["text"], "done", "{call}");
    assert!(
        result["bytes_sent"].as_u64().unwrap_or(0) > 0,
        "the call crossed the peer: {call}"
    );
    assert_eq!(fixture.calls(), 1, "the peer served one tools/call");
    assert_eq!(
        fixture.frames().lines().count(),
        2,
        "one handshake and one call frame"
    );

    // Output bound: a peer answer past the bounded frame never becomes the
    // result; the outcome stays unknown and its retained artifact is bounded.
    let large = world.dispatch(&support::command_execute(
        &session,
        "mcp.call",
        json!({ "task_id": task.0, "grant_id": grant,
                "server": "large", "tool": "fixture.echo", "arguments": {} }),
    ));
    assert!(
        large.get("error").is_none(),
        "the refused bound is an outcome: {large}"
    );
    let result = &large["result"];
    assert_eq!(result["state"], "outcome_unknown", "{large}");
    assert_eq!(result["reason_code"], "frame_over_bound", "{large}");
    assert!(result["result"].is_null(), "{large}");
    assert!(
        !large.to_string().contains(&"x".repeat(69_000)),
        "the oversized peer line is never copied into the answer"
    );
    let artifact = world.root.join(
        result["artifact"]
            .as_str()
            .expect("the call names its retained artifact"),
    );
    let lines: Vec<String> = std::fs::read_to_string(&artifact)
        .expect("the retained artifact reads")
        .lines()
        .map(str::to_string)
        .collect();
    assert!(!lines.is_empty(), "the terminal outcome is retained");
    assert!(
        lines.len() <= rivect::mcp::MCP_RETAINED_MAX_LINES,
        "the retained line count is bounded"
    );
    for line in &lines {
        assert!(
            line.len() <= rivect::mcp::MCP_RETAINED_MAX_LINE_BYTES,
            "a retained line is bounded: {} bytes",
            line.len()
        );
    }

    // Cancellable: a pending call is one logical operation; cancelling its
    // task settles it as an unknown remote outcome without a second byte.
    let cancelled = world.create_task(&session, "ingress-mcp-cancel");
    let pending = world.dispatch(&support::command_execute(
        &session,
        "mcp.call",
        json!({ "task_id": cancelled.0, "grant_id": grant,
                "server": "holding", "tool": "fixture.echo", "arguments": {} }),
    ));
    assert!(pending.get("error").is_none(), "{pending}");
    assert_eq!(pending["result"]["state"], "input_required", "{pending}");
    let operation = pending["result"]["logical_operation_id"]
        .as_str()
        .expect("the pending call names its operation")
        .to_string();
    let frames = fixture.frames();
    let snapshot = world
        .runtime
        .store()
        .snapshot(&cancelled)
        .expect("snapshot");
    let cancel = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 11, "method": "task.submit",
        "params": { "schema_version": 1, "session_id": session.0, "task_id": cancelled.0,
                    "kind": "cancel", "command_id": "ingress-mcp-cancel",
                    "expected_intent_revision": snapshot.intent_revision,
                    "reason": "ingress cancellation" }
    }));
    assert_eq!(cancel["result"]["status"], "applied", "{cancel}");
    let resumed = world.dispatch(&support::command_execute(
        &session,
        "mcp.call",
        json!({ "task_id": cancelled.0, "grant_id": grant,
                "server": "holding", "tool": "fixture.echo",
                "arguments": {}, "operation": operation }),
    ));
    assert!(resumed.get("error").is_none(), "{resumed}");
    assert_eq!(resumed["result"]["state"], "outcome_unknown", "{resumed}");
    assert_eq!(resumed["result"]["reason_code"], "cancelled", "{resumed}");
    assert_eq!(
        fixture.frames(),
        frames,
        "a cancelled operation sends no further byte"
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0, "no provider wire");
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
    support::not_run::reset("ingress.vision");
    let (provider, calls, _manifest) = support::CountingProvider::new();
    let mut world = support::open_world_with(
        "ingress-vision",
        None,
        Box::new(provider),
        Box::new(PlatformWorker),
    );
    let config = world.runtime.config_for_broker();
    // The offline positive lives in tests/vision; this is its unsupported
    // control: an undeclared vision purpose is refused by the broker before
    // any wire attempt even when the payload is a valid PNG.
    let prepared = world.runtime.broker.prepare_vision(
        "vision",
        &config,
        "/world/ingress-vision",
        "describe the image",
        rivect::model::InputOrigin::Human,
        &rivect::model::RankingFacts::unknown(),
        rivect::model::PendingImage {
            declared: rivect::model::ImageMedia::Png,
            bytes: b"\x89PNG\r\n\x1a\nfixture".to_vec(),
        },
    );
    match prepared {
        Err(rivect::model::ModelError::NoEligibleCandidate { purpose, rejected }) => {
            assert_eq!(purpose, "vision", "the refusal names the requested purpose");
            assert!(
                rejected.is_empty(),
                "an undeclared purpose enumerates no declared candidate: {rejected:?}"
            );
        }
        other => panic!("an undeclared vision purpose is refused typed: {other:?}"),
    }
    assert!(
        !config.models.purposes.contains_key("vision"),
        "the shipped purpose set declares no vision entry"
    );
    // No live vision endpoint is claimed: the offline typed path is proved
    // by tests/vision, and the external leg stays the deferred owner row.
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
    support::not_run::reset("ingress.pty");
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
            support::not_run::record("ingress.pty", &format!("pty unavailable: {error}"));
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
