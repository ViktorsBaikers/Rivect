//! AC-024 (REQ-017): while the user's explicit `workflow.enabled = false`
//! is in force no native dispatch starts — not after a compaction, a
//! fallback pause, a restart or a resume — the effects already completed
//! stay exactly as they were, and turning the workflow back on never
//! resumes the paused task by itself. The tools, memory and the explicit
//! `context.compact` keep working at off: only the native entry points are
//! gated, never the custom/tool path.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test fixtures use expect/unwrap for setup and panic on wrong outcomes (standards §14)"
)]

mod support;

use rivect::contracts::{AnswerSelection, Lifecycle, Question, SessionId, TaskId};
use rivect::model::RequestManifest;
use rivect::providers::{LoopbackProvider, Provider, ProviderError, ProviderReply};
use rivect::state::PlanGateHold;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use support::World;

/// The one blocker the off pause raises: its own kind and its own owner,
/// never the plan gate's — the plan settlement rewrites its single hold row
/// and would take a plan-owned pause with it.
const OFF_BLOCKER: &str = "workflow_off:paused";
const OFF_BLOCKER_OWNER: &str = "workflow";

struct Fixture {
    world: World,
    session: SessionId,
    file: PathBuf,
}

fn fixture_at(root: &Path, tag: &str) -> Fixture {
    let world = support::open_world_at(root, Some(&support::config_distinct_pools()));
    fixture_over(world, tag)
}

fn fixture(tag: &str) -> Fixture {
    let world = support::open_world(tag, Some(&support::config_distinct_pools()));
    fixture_over(world, tag)
}

/// A world over the scoped read the decision step performs: the purpose
/// the step dispatches under, the grant that admits the read and the file
/// both name.
fn fixture_over(mut world: World, tag: &str) -> Fixture {
    support::ensure_helper();
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-workflow-off-marker\n").expect("scoped file");
    world.runtime.purpose = "backend_task".to_string();
    world.runtime.set_read_scope(scope, file.clone());
    let session = world.open_session(&format!("bootstrap-{tag}"));
    Fixture {
        world,
        session,
        file,
    }
}

/// One task over the given criteria: a task whose contract keeps work
/// outstanding is the one a pause has to preserve.
fn create_task(f: &mut Fixture, command_id: &str, criteria: &[&str]) -> TaskId {
    let created = f.world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 4, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": command_id, "session_id": f.session.0,
            "kind": "create",
            "goal": "Explain the topic in the chosen form.",
            "contract": { "criteria": criteria, "constraints": ["Do not change files."] },
            "attachments": [],
        },
    }));
    let task_id = created["result"]["task_id"].as_str();
    assert!(task_id.is_some(), "task create failed: {created}");
    TaskId(task_id.expect("task id").to_string())
}

/// A task carrying recorded history long enough to fold: the compaction
/// proof needs a fold that really shrinks something.
fn task_with_history(f: &mut Fixture, command_id: &str) -> TaskId {
    let task = create_task(
        f,
        command_id,
        &[
            "Explain the topic.",
            "Check the explanation against the file.",
            "Name the remaining risk.",
        ],
    );
    f.world.publish(&f.session, &task);
    f.world
        .runtime
        .store_writer()
        .materialize_obligations(&task)
        .expect("obligations");
    for index in 0..4_u8 {
        let observation = format!(
            "read {} and reported {}",
            f.file.display(),
            "a scoped line of the file ".repeat(30)
        );
        f.world
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
    task
}

fn open_question(f: &mut Fixture, task: &TaskId) -> Question {
    f.world.publish(&f.session, task)
}

fn answer_custom(
    f: &mut Fixture,
    command_id: &str,
    task: &TaskId,
    question: &Question,
    text: &str,
) -> Value {
    f.world.dispatch(&support::corpus_answer_custom(
        &f.session,
        command_id,
        task,
        question,
        text,
        json!(7001),
    ))
}

fn answer_option(
    f: &mut Fixture,
    command_id: &str,
    task: &TaskId,
    question: &Question,
    option_id: &str,
) -> Value {
    f.world.dispatch(&support::corpus_answer_option(
        &f.session,
        command_id,
        task,
        question,
        option_id,
        json!(7002),
    ))
}

/// Lands one `workflow.enabled` toggle through the user's own config
/// carrier — the only mutator of the flag, so the value stays an explicit
/// user one.
fn set_workflow(f: &mut Fixture, enabled: bool) {
    let response = f.world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7003, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": f.session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": enabled }
    }));
    assert!(
        response["error"].is_null(),
        "the workflow toggle must land: {response}"
    );
    assert_eq!(
        workflow_flag(f),
        Some(enabled),
        "the applied effective config carries the explicit user value"
    );
}

fn workflow_flag(f: &Fixture) -> Option<bool> {
    f.world
        .runtime
        .effective()
        .parsed
        .as_ref()
        .expect("the user document is parsed")
        .workflow
        .enabled
}

fn lifecycle(f: &Fixture, task: &TaskId) -> Lifecycle {
    f.world
        .runtime
        .store()
        .snapshot(task)
        .expect("snapshot")
        .lifecycle
}

fn status_item(f: &mut Fixture, task: &TaskId) -> Value {
    let response = f.world.dispatch(&support::corpus_status(&f.session));
    assert!(response["error"].is_null(), "runtime.status: {response}");
    let items = response["result"]["tasks"]["items"]
        .as_array()
        .expect("task page");
    items
        .iter()
        .find(|item| item["task_id"].as_str() == Some(task.0.as_str()))
        .cloned()
        .expect("the task is on runtime.status")
}

fn has_off_blocker(item: &Value) -> bool {
    item["blockers"].as_array().is_some_and(|list| {
        list.iter().any(|blocker| {
            blocker["condition"]["action_id"].as_str() == Some(OFF_BLOCKER)
                && blocker["owner"].as_str() == Some(OFF_BLOCKER_OWNER)
        })
    })
}

fn provider_calls(f: &Fixture) -> u64 {
    f.world.provider_calls.load(Ordering::SeqCst)
}

/// AC-024/EDGE-016: off lands while the tree is mid-run — the next native
/// dispatch never starts, and the effect already completed reads back
/// exactly as it did before the toggle.
#[test]
fn off_blocks_new_native_dispatch_p1() {
    let mut f = fixture("off-p1");
    // A completed effect on the board before the toggle: one fixed-option
    // answer performs the scoped read and settles its attempt.
    let completed = create_task(&mut f, "p1-completed", &["Explain the topic."]);
    let question = open_question(&mut f, &completed);
    let answered = answer_option(
        &mut f,
        "p1-completed-answer",
        &completed,
        &question,
        "brief",
    );
    assert!(answered["error"].is_null(), "{answered}");
    let reads_after_effect = f.world.worker_reads();
    assert!(reads_after_effect >= 1, "the fixture performed its read");
    let snapshot_before = f
        .world
        .runtime
        .store()
        .snapshot(&completed)
        .expect("snapshot");
    let evidence_before = f
        .world
        .runtime
        .store()
        .evidence_for_task(&completed)
        .expect("evidence");
    assert!(
        !evidence_before.is_empty(),
        "the completed effect recorded evidence"
    );

    // A second task is waiting mid-run when the user turns the workflow off.
    let running = create_task(&mut f, "p1-running", &["Explain the topic."]);
    let pending = open_question(&mut f, &running);
    let calls_before = provider_calls(&f);
    let reads_before = f.world.worker_reads();
    set_workflow(&mut f, false);

    // The answer still applies to the store, but no native dispatch starts.
    let read_line = format!("read {}", f.file.display());
    let refused = answer_custom(&mut f, "p1-running-answer", &running, &pending, &read_line);
    assert!(refused["error"].is_null(), "the answer commits: {refused}");
    assert_eq!(
        provider_calls(&f),
        calls_before,
        "no provider was dispatched after off"
    );
    assert_eq!(
        f.world.worker_reads(),
        reads_before,
        "no effect ran after off"
    );
    assert_eq!(lifecycle(&f, &running), Lifecycle::Paused);

    // The dispatch entry itself refuses, not only the answering carrier.
    let outcome = f
        .world
        .runtime
        .run_decision_step(
            &f.session,
            &running,
            &AnswerSelection::Custom {
                text: format!("read {}", f.file.display()),
            },
            &f.world.runtime.scoped_grant.clone(),
            false,
        )
        .expect("the dispatch entry answers");
    assert!(
        matches!(outcome, rivect::controller::StepOutcome::Paused { .. }),
        "the dispatch entry answers a pause, never a dispatch: {outcome:?}"
    );
    assert_eq!(
        provider_calls(&f),
        calls_before,
        "the direct entry dispatched nothing either"
    );
    assert_eq!(f.world.worker_reads(), reads_before, "and ran no effect");
    assert_eq!(
        lifecycle(&f, &running),
        Lifecycle::Paused,
        "the refusal is recorded, not silently dropped: {outcome:?}"
    );

    // The already completed effect is untouched by the off transition.
    let snapshot_after = f
        .world
        .runtime
        .store()
        .snapshot(&completed)
        .expect("snapshot");
    assert_eq!(
        snapshot_after.attempts.items, snapshot_before.attempts.items,
        "a settled attempt row is never rewritten by off"
    );
    assert_eq!(
        snapshot_after.revision, snapshot_before.revision,
        "nor is the completed task's revision"
    );
    assert_eq!(
        f.world
            .runtime
            .store()
            .evidence_for_task(&completed)
            .expect("evidence"),
        evidence_before,
        "the completed effect's evidence survives off byte-identically"
    );
}

/// AC-024: a compaction at off folds nothing new — the pause is not
/// episodic history — and the next native dispatch is still refused.
#[test]
fn off_survives_compaction_p2() {
    let mut f = fixture("off-p2");
    let task = task_with_history(&mut f, "p2-task");
    set_workflow(&mut f, false);
    let calls_before = provider_calls(&f);
    let reads_before = f.world.worker_reads();
    let refused = f
        .world
        .runtime
        .run_decision_step(
            &f.session,
            &task,
            &AnswerSelection::Custom {
                text: format!("read {}", f.file.display()),
            },
            &f.world.runtime.scoped_grant.clone(),
            false,
        )
        .expect("the dispatch entry answers");
    assert!(
        matches!(refused, rivect::controller::StepOutcome::Paused { .. }),
        "{refused:?}"
    );
    assert_eq!(provider_calls(&f), calls_before, "{refused:?}");
    assert_eq!(lifecycle(&f, &task), Lifecycle::Paused);
    let row_after_pause = f.world.runtime.store().snapshot(&task).expect("snapshot");

    // The user-invoked compaction still runs at off and folds the history
    // it found — it is a tool, never a native dispatch.
    let response = f.world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7004, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": f.session.0,
                    "command": { "kind": "context.compact" },
                    "task_id": task.0 }
    }));
    assert!(
        response["error"].is_null(),
        "context.compact completes at off: {response}"
    );
    assert!(
        response["result"]["folded_records"].as_u64().unwrap_or(0) > 0,
        "the fold replaced real records: {response}"
    );

    // A second fold has nothing new left: the pause is not history.
    let again = f
        .world
        .runtime
        .store_writer()
        .force_compaction(&f.session, &task);
    assert!(
        again.is_err(),
        "nothing new is foldable after the pause: {again:?}"
    );
    assert_eq!(
        workflow_flag(&f),
        Some(false),
        "the compaction never resets the explicit user false"
    );
    assert_eq!(
        lifecycle(&f, &task),
        Lifecycle::Paused,
        "the compaction neither folds the pause away nor resumes the task"
    );
    assert_eq!(
        f.world
            .runtime
            .store()
            .snapshot(&task)
            .expect("snapshot")
            .attempts
            .items,
        row_after_pause.attempts.items,
        "the fold adds no attempt row"
    );

    // The next native dispatch is still refused, provider and worker alike.
    let after_compaction = f
        .world
        .runtime
        .run_decision_step(
            &f.session,
            &task,
            &AnswerSelection::Custom {
                text: format!("read {}", f.file.display()),
            },
            &f.world.runtime.scoped_grant.clone(),
            false,
        )
        .expect("the dispatch entry answers");
    assert!(
        matches!(
            after_compaction,
            rivect::controller::StepOutcome::Paused { .. }
        ),
        "the fold leaves the refusal in force: {after_compaction:?}"
    );
    assert_eq!(provider_calls(&f), calls_before, "still no dispatch");
    assert_eq!(f.world.worker_reads(), reads_before, "still no effect");
}

/// The manual-fallback double: the first physical send fails on the pinned
/// connection, every later send is the real offline loopback — so the
/// pause under test is the production manual-fallback pause.
struct FailsOnce {
    inner: LoopbackProvider,
    sends: Arc<AtomicU64>,
    failed: bool,
}

impl Provider for FailsOnce {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn serves(&self, connection: &str, entry: &rivect::config::Connection) -> bool {
        self.inner.serves(connection, entry)
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        if self.failed {
            return self.inner.send(manifest);
        }
        self.failed = true;
        Err(ProviderError::UnknownConnection {
            connection: "local".to_string(),
        })
    }
}

/// The fallback corpus: one pinned local connection, one eligible local
/// reserve, and a manual fallback so a failed pin pauses into a choice
/// instead of substituting silently.
fn manual_fallback_config() -> String {
    "config_version = 1\n\
     [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
     [connections.reserve]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11435\"\n\
     [models.defaults]\n\
     model = { mode = \"auto\" }\n\
     effort = { mode = \"auto\" }\n\
     fallback = { mode = \"auto\" }\n\
     [models.purposes.relay]\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"primary-pin\" }\n\
     effort = { mode = \"fixed\", value = \"medium\" }\n\
     fallback = { mode = \"manual\" }\n"
        .to_string()
}

/// AC-024: an answered fallback candidate is a native dispatch; at off it
/// cannot start one, so the frozen manifest is never re-sent.
#[test]
fn off_survives_fallback_p3() {
    let sends = Arc::new(AtomicU64::new(0));
    let provider = FailsOnce {
        inner: LoopbackProvider::new(),
        sends: sends.clone(),
        failed: false,
    };
    let mut world = support::open_world_with(
        "off-p3",
        Some(&manual_fallback_config()),
        Box::new(provider),
        Box::new(support::PlatformWorker::default()),
    );
    support::ensure_helper();
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-workflow-off-marker\n").expect("scoped file");
    world.runtime.purpose = "relay".to_string();
    world.runtime.set_read_scope(scope, file.clone());
    let session = world.open_session("bootstrap-off-p3");
    let mut f = Fixture {
        world,
        session,
        file,
    };
    let task = create_task(&mut f, "p3-task", &["Explain the topic."]);
    let question = open_question(&mut f, &task);
    // The pinned send fails and the production manual-fallback pause
    // publishes its own choice: nothing is substituted silently.
    let answered = answer_custom(&mut f, "p3-first", &task, &question, "steps");
    assert!(answered["error"].is_null(), "{answered}");
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "the failed pin sent exactly once"
    );
    let served = f
        .world
        .runtime
        .store()
        .current_question(&task)
        .expect("question read")
        .expect("the fallback choice is served");
    let candidate = served.0.options[0].option_id.0.clone();

    set_workflow(&mut f, false);

    // The answered candidate would dispatch the frozen manifest: at off it
    // cannot start that native step.
    let picked = answer_option(&mut f, "p3-pick", &task, &served.0, &candidate);
    assert!(picked["error"].is_null(), "the pick commits: {picked}");
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "no substitute was dispatched at off"
    );
    assert_eq!(
        workflow_flag(&f),
        Some(false),
        "the refused fallback dispatch never resets the explicit user false"
    );
    assert_eq!(lifecycle(&f, &task), Lifecycle::Paused);
}

/// AC-024: a restart plus a store reopen re-reads the user's explicit
/// false, and the native dispatch stays refused; the pause is durable.
#[test]
fn off_survives_reopen_p4() {
    let root = tempfile::TempDir::with_prefix("rivect-off-p4-").expect("private fixture");
    let mut f = fixture_at(root.path(), "off-p4");
    let task = create_task(&mut f, "p4-task", &["Explain the topic."]);
    let question = open_question(&mut f, &task);
    set_workflow(&mut f, false);
    let calls_before = provider_calls(&f);
    let read_line = format!("read {}", f.file.display());
    answer_custom(&mut f, "p4-answer", &task, &question, &read_line);
    assert_eq!(provider_calls(&f), calls_before);
    assert_eq!(lifecycle(&f, &task), Lifecycle::Paused);

    f.world.reopen();

    assert_eq!(
        workflow_flag(&f),
        Some(false),
        "the explicit user false is still the effective value after a restart"
    );
    assert_eq!(
        lifecycle(&f, &task),
        Lifecycle::Paused,
        "the pause record survives the reopen"
    );
    let calls_after_reopen = provider_calls(&f);
    let reopened = f
        .world
        .runtime
        .run_decision_step(
            &f.session,
            &task,
            &AnswerSelection::Custom {
                text: format!("read {}", f.file.display()),
            },
            &f.world.runtime.scoped_grant.clone(),
            false,
        )
        .expect("the dispatch entry answers");
    assert!(
        matches!(reopened, rivect::controller::StepOutcome::Paused { .. }),
        "the native dispatch is still refused after the reopen: {reopened:?}"
    );
    assert_eq!(
        provider_calls(&f),
        calls_after_reopen,
        "the native dispatch is still refused after the reopen"
    );
}

/// One task whose continuation is real work: an answered node, recorded
/// history and a forced compaction, so a resume attempt has something to
/// run.
fn continuation_task(f: &mut Fixture, command_id: &str) -> TaskId {
    let task = task_with_history(f, command_id);
    let question = f
        .world
        .runtime
        .store()
        .current_question(&task)
        .expect("question read")
        .expect("the published question")
        .0;
    let selection = AnswerSelection::Custom {
        text: format!("read {}", f.file.display()),
    };
    f.world
        .runtime
        .store_writer()
        .answer_question(
            &f.session,
            &task,
            &question.question_id,
            question.question_revision,
            &selection,
            "human",
        )
        .expect("answer question");
    let grant = f.world.runtime.scoped_grant.clone();
    f.world
        .runtime
        .scheduler
        .submit_answered(task.clone(), selection, grant)
        .expect("submit answered node")
        .expect("the answered task is runnable");
    task
}

/// AC-024: a resume attempt is a native dispatch; at off it leaves the
/// task paused instead of running the remainder.
#[test]
fn off_survives_resume_p5() {
    let mut f = fixture("off-p5");
    // The positive control: with the workflow on the same fixture resumes,
    // so the refusal below is the gate and not an empty continuation.
    let resumable = continuation_task(&mut f, "p5-resumable");
    f.world
        .runtime
        .store_writer()
        .force_compaction(&f.session, &resumable)
        .expect("forced compaction");
    let resumed = f
        .world
        .runtime
        .resume_continuation(&f.session, &resumable)
        .expect("resume answers");
    assert!(
        matches!(
            resumed,
            rivect::controller::ContinuationOutcome::Resumed { .. }
        ),
        "the fixture has a remainder to resume: {resumed:?}"
    );

    let paused_task = continuation_task(&mut f, "p5-paused");
    f.world
        .runtime
        .store_writer()
        .force_compaction(&f.session, &paused_task)
        .expect("forced compaction");
    set_workflow(&mut f, false);
    let outcome = f
        .world
        .runtime
        .resume_continuation(&f.session, &paused_task)
        .expect("resume answers");
    assert_eq!(
        outcome,
        rivect::controller::ContinuationOutcome::Paused,
        "at off the resume reports the pause, never a run: {outcome:?}"
    );
    assert_eq!(
        workflow_flag(&f),
        Some(false),
        "the resume attempt never resets the explicit user false"
    );
    assert_eq!(
        lifecycle(&f, &paused_task),
        Lifecycle::Paused,
        "the resume attempt leaves the task paused"
    );
}

/// AC-024/PROH-010: turning the workflow back on does not resume the
/// paused task — only a new intent does.
#[test]
fn on_does_not_resume_paused_task_p6() {
    let mut f = fixture("off-p6");
    let task = task_with_history(&mut f, "p6-task");
    set_workflow(&mut f, false);
    let calls_before = provider_calls(&f);
    f.world
        .runtime
        .run_decision_step(
            &f.session,
            &task,
            &AnswerSelection::Custom {
                text: format!("read {}", f.file.display()),
            },
            &f.world.runtime.scoped_grant.clone(),
            false,
        )
        .expect("the dispatch entry answers");
    assert_eq!(lifecycle(&f, &task), Lifecycle::Paused);

    set_workflow(&mut f, true);

    assert_eq!(
        provider_calls(&f),
        calls_before,
        "the toggle itself dispatches nothing"
    );
    assert_eq!(
        lifecycle(&f, &task),
        Lifecycle::Paused,
        "on leaves the paused task paused"
    );
    let status = status_item(&mut f, &task);
    assert_eq!(
        status["lifecycle"].as_str(),
        Some("paused"),
        "runtime.status still shows the pause: {status}"
    );
    assert!(
        has_off_blocker(&status),
        "and still names what holds it: {status}"
    );
}

/// AC-024 (DEC-011/S-1): the explicit `context.compact` is a tool the user
/// invoked, not a native dispatch — it completes at off.
#[test]
fn explicit_compact_still_runs_at_off_p7() {
    let mut f = fixture("off-p7");
    let task = task_with_history(&mut f, "p7-task");
    set_workflow(&mut f, false);
    f.world
        .runtime
        .run_decision_step(
            &f.session,
            &task,
            &AnswerSelection::Custom {
                text: format!("read {}", f.file.display()),
            },
            &f.world.runtime.scoped_grant.clone(),
            false,
        )
        .expect("the dispatch entry answers");
    assert_eq!(lifecycle(&f, &task), Lifecycle::Paused);

    let response = f.world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7005, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": f.session.0,
                    "command": { "kind": "context.compact" },
                    "task_id": task.0 }
    }));
    assert!(
        response["error"].is_null(),
        "a user-invoked context.compact still completes at off: {response}"
    );
    assert_eq!(response["result"]["kind"].as_str(), Some("context.compact"));
    assert!(
        response["result"]["before_bytes"].as_u64().unwrap_or(0)
            > response["result"]["after_bytes"].as_u64().unwrap_or(0),
        "the fold is the owner's real fold: {response}"
    );
    assert_eq!(
        lifecycle(&f, &task),
        Lifecycle::Paused,
        "the compaction neither resumes nor unpauses the task"
    );
}

/// AC-024/I5: the single `plan_gate_holds` row is deleted and rewritten by
/// the plan settlement, so the off pause keeps its own record; a
/// settlement that rewrites the plan fact leaves the pause intact.
#[test]
fn off_pause_has_its_own_owner_p8() {
    let mut f = fixture("off-p8");
    let task = task_with_history(&mut f, "p8-task");
    set_workflow(&mut f, false);
    f.world
        .runtime
        .run_decision_step(
            &f.session,
            &task,
            &AnswerSelection::Custom {
                text: format!("read {}", f.file.display()),
            },
            &f.world.runtime.scoped_grant.clone(),
            false,
        )
        .expect("the dispatch entry answers");
    assert_eq!(lifecycle(&f, &task), Lifecycle::Paused);

    // The plan-gate fact appears beside the off pause.
    let held = f
        .world
        .runtime
        .store_writer()
        .hold_for_plan_gate(&task, PlanGateHold::Unassessed)
        .expect("the gate hold is recorded");
    assert_eq!(held, Some(PlanGateHold::Unassessed));
    // The settlement owns that single row: the observed kind it is handed
    // back is the one settlement normalized, never the caller's.
    let rewritten = f
        .world
        .runtime
        .store_writer()
        .hold_for_plan_gate(&task, PlanGateHold::Paused)
        .expect("the gate hold is rewritten");
    assert_eq!(
        rewritten,
        Some(PlanGateHold::Unassessed),
        "settlement rewrites the plan-gate row"
    );
    assert_eq!(
        lifecycle(&f, &task),
        Lifecycle::Paused,
        "and the off pause is not that row, so it survives"
    );
    let status = status_item(&mut f, &task);
    assert!(
        has_off_blocker(&status),
        "the pause still names its own blocker: {status}"
    );
}

/// AC-024/DX-C1: the pause is cleared by the implemented `task.steer` with
/// a new intent revision — never by the toggle and never by a hypothetical
/// resume verb.
#[test]
fn off_pause_recovery_verb_works_p9() {
    let mut f = fixture("off-p9");
    let task = task_with_history(&mut f, "p9-task");
    set_workflow(&mut f, false);
    f.world
        .runtime
        .run_decision_step(
            &f.session,
            &task,
            &AnswerSelection::Custom {
                text: format!("read {}", f.file.display()),
            },
            &f.world.runtime.scoped_grant.clone(),
            false,
        )
        .expect("the dispatch entry answers");

    // The pause is on the status surface, and `on` alone does not clear it.
    set_workflow(&mut f, true);
    let paused = status_item(&mut f, &task);
    assert_eq!(paused["lifecycle"].as_str(), Some("paused"), "{paused}");
    assert!(has_off_blocker(&paused), "{paused}");
    let calls_before_steer = provider_calls(&f);

    let snapshot = f.world.runtime.store().snapshot(&task).expect("snapshot");
    let steer = f.world.dispatch(&support::corpus_steer(
        &f.session,
        "p9-steer",
        &task,
        snapshot.intent_revision,
        snapshot.revision,
        json!(7006),
    ));
    assert!(steer["error"].is_null(), "the steer applies: {steer}");
    let steered = f.world.runtime.store().snapshot(&task).expect("snapshot");
    assert_eq!(
        steered.intent_revision,
        snapshot.intent_revision + 1,
        "the steer opens a new intent revision"
    );
    assert_eq!(
        steered.lifecycle,
        Lifecycle::Running,
        "the new intent is what clears the pause"
    );
    assert!(
        !has_off_blocker(&status_item(&mut f, &task)),
        "the off blocker is gone with it"
    );

    // The native dispatch starts again on the new intent.
    let outcome = f
        .world
        .runtime
        .run_decision_step(
            &f.session,
            &task,
            &AnswerSelection::Custom {
                text: format!("read {}", f.file.display()),
            },
            &f.world.runtime.scoped_grant.clone(),
            false,
        )
        .expect("the dispatch entry answers");
    assert!(
        provider_calls(&f) > calls_before_steer,
        "the dispatch is allowed again after the steer: {outcome:?}"
    );
}
