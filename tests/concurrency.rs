//! Bounded tree concurrency proof: a waiting parent frees its execution
//! slot before it waits, independent branches are not globally
//! serialized, shared caps hold, and cancel + reset + reconnect + late
//! callback never resurrect dispatch (AC-010/012, PROH-002,
//! EDGE-002/003). The supervisor cases bound sterile retries without
//! stopping useful work (AC-011, INV-027, PROH-005). The runtime-driven
//! cases exercise the production path: task submission builds tree
//! nodes, the runtime loop releases a waiting parent's slot, and the
//! cancel ingress drains the tree.

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

use rivect::contracts::{
    AnswerSelection, ErrorCode, Event, EventId, Lifecycle, ObligationApplicability,
    ObligationExecution, OptionId, SessionId, TaskId,
};
use rivect::controller::{
    ControllerError, SchedulerStep, StepOutcome, step_error_observation, step_outcome_observation,
};
use rivect::executor::{EffectOutcome, EffectRequest, ExecutorError, ReadWorker, WorkerError};
use rivect::model::{Broker, ModelError, RequestManifest};
use rivect::policy::{PermissionMode, PolicyError};
use rivect::providers::{Provider, ProviderError, ProviderReply, ToolCall};
use rivect::resources::{FlightRole, ReadFlights, UsageDelta};
use rivect::scheduler::{
    CompleteTransition, DeliverVerdict, NodeState, Scheduler, SchedulerError, WaitTransition,
};
use rivect::state::{
    BudgetStatus, ConflictCause, InvalidCause, Missing, SettlementState, StoreError, TaskStore,
};
use rivect::supervisor::{
    ClassThresholds, FailureSignature, Observation, OperationClass, PolicyFault, Reaction,
    StallCause, Supervisor, SupervisorError, SupervisorPolicy, WATCH_LIMIT,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use support::{World, answer_custom, corpus_answer_option, open_world};

fn scoped_world(tag: &str) -> (World, PathBuf, String) {
    scope_world(open_world(tag, Some(&support::config_distinct_pools())))
}

/// The scoped world over an injected provider/worker pair: the feed
/// cases stub one seam while the scope, grant and purpose stay the
/// production shape.
fn scoped_world_with(
    tag: &str,
    provider: Box<dyn Provider>,
    worker: Box<dyn ReadWorker>,
) -> (World, PathBuf, String) {
    scope_world(support::open_world_with(
        tag,
        Some(&support::config_distinct_pools()),
        provider,
        worker,
    ))
}

fn scope_world(mut world: World) -> (World, PathBuf, String) {
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-concurrency-marker\n").expect("scoped file");
    world.runtime.purpose = "backend_task".to_string();
    let grant = world.runtime.set_read_scope(scope, file.clone());
    (world, file, grant)
}

fn node_answer(file: &Path) -> String {
    format!("read {}", file.display())
}

fn stub_task(name: &str) -> TaskId {
    TaskId(format!("task-{name}"))
}

fn late_event(session: &SessionId, task: Option<&TaskId>, event_type: &str) -> Event {
    Event {
        schema_version: 1,
        event_id: EventId::generate(),
        aggregate_id: "aggregate-concurrency".to_string(),
        aggregate_revision: 1,
        cursor: 1,
        session_id: session.clone(),
        task_id: task.cloned(),
        event_type: event_type.to_string(),
        delta: json!({}),
        origin: "system".to_string(),
    }
}

/// Creates one task through the real ingress as a child of `parent`.
fn create_child_task(
    world: &mut World,
    session: &SessionId,
    command_id: &str,
    parent: &TaskId,
) -> TaskId {
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": command_id, "session_id": session.0,
            "kind": "create", "goal": "child step under the parent task",
            "parent_task_id": parent.0,
            "attachments": []
        }
    }));
    let result = response.get("result").cloned().unwrap_or(Value::Null);
    assert!(
        result.get("task_id").and_then(Value::as_str).is_some(),
        "child create failed: {response}"
    );
    TaskId(result["task_id"].as_str().expect("task id").to_string())
}

/// Publishes the pending question and freezes the answer onto a
/// scheduler node without driving `scheduler_step`: production dispatch
/// drains the loop (T12); these scheduler proofs still own stepping.
fn answer_task(
    world: &mut World,
    session: &SessionId,
    _command_id: &str,
    task: &TaskId,
    text: &str,
    _id: i64,
) {
    let question = world.publish(session, task);
    let selection = AnswerSelection::Custom {
        text: text.to_string(),
    };
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
        .expect("submit node");
}

/// Cancels one task through the real ingress: the store cancels the
/// task and the scheduler tree drains in the same command.
fn cancel_task_via_ingress(world: &mut World, session: &SessionId, task: &TaskId) {
    let intent_revision = world
        .runtime
        .store()
        .snapshot(task)
        .expect("snapshot")
        .intent_revision;
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 30, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": "cmd-cancel",
            "session_id": session.0, "kind": "cancel", "task_id": task.0,
            "expected_intent_revision": intent_revision,
            "reason": "user stopped the tree"
        }
    }));
    assert!(response["error"].is_null(), "{response}");
}

fn ran_task(world: &World, node: usize) -> TaskId {
    world
        .runtime
        .scheduler
        .node_context(node)
        .expect("node context")
        .task
}

#[test]
fn one_slot_parent_child_completes_via_ingress_driven_wait() {
    let (mut world, file, _grant) = scoped_world("one-slot-parent");
    world.runtime.scheduler = Scheduler::new(1, 4);
    let session = world.open_session("bootstrap-one-slot-parent");
    let parent_task = world.create_task(&session, "cmd-parent");
    answer_task(
        &mut world,
        &session,
        "cmd-parent-answer",
        &parent_task,
        &node_answer(&file),
        1,
    );

    // The child is created under the parent through the real ingress.
    let child_task = create_child_task(&mut world, &session, "cmd-child", &parent_task);
    answer_task(
        &mut world,
        &session,
        "cmd-child-answer",
        &child_task,
        &node_answer(&file),
        2,
    );

    // PROH-002 through the runtime loop: the parent admits first,
    // releases the only slot by waiting on its child inside the pass,
    // and the child completes — exactly one provider call so far, the
    // child's. The child was admissible only because the parent no
    // longer holds the slot.
    match world
        .runtime
        .scheduler_step(&session)
        .expect("child step runs")
    {
        SchedulerStep::Ran { node, outcome } => {
            assert_eq!(ran_task(&world, node), child_task);
            assert!(
                matches!(*outcome, StepOutcome::Completed { .. }),
                "child decision step must complete, got {outcome:?}"
            );
        }
        other => panic!("expected the child to run, got {other:?}"),
    }
    assert_eq!(world.provider_calls.load(Ordering::SeqCst), 1);

    // The parent resumes only after its child settled, then completes.
    match world
        .runtime
        .scheduler_step(&session)
        .expect("parent step runs")
    {
        SchedulerStep::Ran { node, outcome } => {
            assert_eq!(ran_task(&world, node), parent_task);
            assert!(
                matches!(*outcome, StepOutcome::Completed { .. }),
                "parent decision step must complete, got {outcome:?}"
            );
        }
        other => panic!("expected the parent to resume, got {other:?}"),
    }
    assert_eq!(world.provider_calls.load(Ordering::SeqCst), 2);
    let child_snapshot = world
        .runtime
        .store()
        .snapshot(&child_task)
        .expect("child snapshot");
    assert_eq!(child_snapshot.lifecycle, Lifecycle::Completed);
    let parent_snapshot = world
        .runtime
        .store()
        .snapshot(&parent_task)
        .expect("parent snapshot");
    assert_eq!(parent_snapshot.lifecycle, Lifecycle::Completed);

    // Tree drained, caps respected throughout, exactly one dispatch per task.
    assert!(matches!(
        world.runtime.scheduler_step(&session),
        Ok(SchedulerStep::Idle)
    ));
    assert_eq!(world.runtime.scheduler.running_count(), 0);
    assert_eq!(world.runtime.scheduler.held_units(), 0);
}

#[test]
fn reanswer_through_ingress_never_stalls_the_waiting_parent() {
    let (mut world, file, _grant) = scoped_world("reanswer-retire");
    world.runtime.scheduler = Scheduler::new(1, 4);
    let session = world.open_session("bootstrap-reanswer-retire");
    let parent_task = world.create_task(&session, "cmd-parent");
    answer_task(
        &mut world,
        &session,
        "cmd-parent-answer",
        &parent_task,
        &node_answer(&file),
        1,
    );
    let first_child = create_child_task(&mut world, &session, "cmd-child-1", &parent_task);
    answer_task(
        &mut world,
        &session,
        "cmd-child-1-answer",
        &first_child,
        &node_answer(&file),
        2,
    );
    let second_child = create_child_task(&mut world, &session, "cmd-child-2", &parent_task);
    answer_task(
        &mut world,
        &session,
        "cmd-child-2-answer",
        &second_child,
        &node_answer(&file),
        3,
    );

    // Pass 1: the parent waits on both children, the first completes;
    // the second child's node is still queued with the parent Waiting.
    match world
        .runtime
        .scheduler_step(&session)
        .expect("first child step runs")
    {
        SchedulerStep::Ran { node, outcome } => {
            assert_eq!(ran_task(&world, node), first_child);
            assert!(matches!(*outcome, StepOutcome::Completed { .. }));
        }
        other => panic!("expected the first child to run, got {other:?}"),
    }
    assert_eq!(world.provider_calls.load(Ordering::SeqCst), 1);
    let parent_node = world
        .runtime
        .scheduler
        .node_of_task(&parent_task)
        .expect("parent node");
    assert_eq!(
        world
            .runtime
            .scheduler
            .state(parent_node)
            .expect("parent state"),
        NodeState::Waiting
    );

    // A follow-up question for the still-queued second child is answered
    // again through the real ingress: the stale queued node retires and
    // the fresh node takes over the parent's wait accounting.
    answer_task(
        &mut world,
        &session,
        "cmd-child-2-reanswer",
        &second_child,
        &node_answer(&file),
        4,
    );

    // Pass 2: the fresh second-child node completes at the store...
    match world
        .runtime
        .scheduler_step(&session)
        .expect("second child step runs")
    {
        SchedulerStep::Ran { node, outcome } => {
            assert_eq!(ran_task(&world, node), second_child);
            assert!(matches!(*outcome, StepOutcome::Completed { .. }));
        }
        other => panic!("expected the second child's fresh node to run, got {other:?}"),
    }
    assert_eq!(world.provider_calls.load(Ordering::SeqCst), 2);

    // ...and the parent actually resumes and completes: the retired node
    // settled the wait instead of leaving a zombie unfinished count.
    match world
        .runtime
        .scheduler_step(&session)
        .expect("parent step runs")
    {
        SchedulerStep::Ran { node, outcome } => {
            assert_eq!(ran_task(&world, node), parent_task);
            assert!(matches!(*outcome, StepOutcome::Completed { .. }));
        }
        other => panic!("expected the parent to resume, got {other:?}"),
    }
    assert_eq!(world.provider_calls.load(Ordering::SeqCst), 3);
    let parent_snapshot = world
        .runtime
        .store()
        .snapshot(&parent_task)
        .expect("parent snapshot");
    assert_eq!(parent_snapshot.lifecycle, Lifecycle::Completed);
    assert!(matches!(
        world.runtime.scheduler_step(&session),
        Ok(SchedulerStep::Idle)
    ));
    assert_eq!(world.runtime.scheduler.running_count(), 0);
    assert_eq!(world.runtime.scheduler.held_units(), 0);
}

#[test]
fn replayed_create_cannot_reparent_the_original_task() {
    let (mut world, file, _grant) = scoped_world("replay-reparent");
    world.runtime.scheduler = Scheduler::new(1, 4);
    let session = world.open_session("bootstrap-replay-reparent");
    let first_parent = world.create_task(&session, "cmd-first-parent");
    answer_task(
        &mut world,
        &session,
        "cmd-first-parent-answer",
        &first_parent,
        &node_answer(&file),
        1,
    );
    let second_parent = world.create_task(&session, "cmd-second-parent");
    let child_task = create_child_task(&mut world, &session, "cmd-child", &first_parent);

    // The same command_id with the same goal but a DIFFERENT parent
    // passes the store's create dedupe (parent linkage is not part of
    // the digest) and answers with the original task: the replay must
    // not re-adopt the task under the new parent.
    let replay = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": "cmd-child", "session_id": session.0,
            "kind": "create", "goal": "child step under the parent task",
            "parent_task_id": second_parent.0,
            "attachments": []
        }
    }));
    assert!(replay["error"].is_null(), "{replay}");
    assert_eq!(
        replay["result"]["task_id"].as_str(),
        Some(child_task.0.as_str())
    );

    answer_task(
        &mut world,
        &session,
        "cmd-child-answer",
        &child_task,
        &node_answer(&file),
        2,
    );

    // Cancelling the ORIGINAL parent drains the child: the linkage
    // stayed with the first create, so the child never dispatches
    // under the replayed parent.
    cancel_task_via_ingress(&mut world, &session, &first_parent);
    assert!(matches!(
        world.runtime.scheduler_step(&session),
        Ok(SchedulerStep::Idle)
    ));
    assert_eq!(world.provider_calls.load(Ordering::SeqCst), 0);
    let child_snapshot = world
        .runtime
        .store()
        .snapshot(&child_task)
        .expect("child snapshot");
    assert_ne!(child_snapshot.lifecycle, Lifecycle::Completed);
}

#[test]
fn independent_branch_runs_beside_waiting_family_through_driver() {
    let (mut world, file, _grant) = scoped_world("independent-branch");
    world.runtime.scheduler = Scheduler::new(1, 4);
    let session = world.open_session("bootstrap-independent-branch");
    let parent_task = world.create_task(&session, "cmd-parent");
    answer_task(
        &mut world,
        &session,
        "cmd-parent-answer",
        &parent_task,
        &node_answer(&file),
        1,
    );
    let first_child = create_child_task(&mut world, &session, "cmd-child-1", &parent_task);
    answer_task(
        &mut world,
        &session,
        "cmd-child-1-answer",
        &first_child,
        &node_answer(&file),
        2,
    );
    let branch_task = world.create_task(&session, "cmd-branch");
    answer_task(
        &mut world,
        &session,
        "cmd-branch-answer",
        &branch_task,
        &node_answer(&file),
        3,
    );
    // The second child is answered AFTER the branch, so the branch sits
    // ahead of it in the strict-FIFO queue while the family waits.
    let second_child = create_child_task(&mut world, &session, "cmd-child-2", &parent_task);
    answer_task(
        &mut world,
        &session,
        "cmd-child-2-answer",
        &second_child,
        &node_answer(&file),
        4,
    );
    let parent_node = world
        .runtime
        .scheduler
        .node_of_task(&parent_task)
        .expect("parent node");

    // Pass 1: the parent waits on two unfinished children (no slot
    // held), the first completes — the count stays above zero.
    match world
        .runtime
        .scheduler_step(&session)
        .expect("first child step runs")
    {
        SchedulerStep::Ran { node, outcome } => {
            assert_eq!(ran_task(&world, node), first_child);
            assert!(matches!(*outcome, StepOutcome::Completed { .. }));
        }
        other => panic!("expected the first child to run, got {other:?}"),
    }
    assert_eq!(
        world
            .runtime
            .scheduler
            .state(parent_node)
            .expect("parent state"),
        NodeState::Waiting
    );

    // Pass 2: the unrelated branch runs while the family is GENUINELY
    // still Waiting — the second child keeps the parent's unfinished
    // count above zero — so a waiting family never globally serializes
    // the tree.
    match world
        .runtime
        .scheduler_step(&session)
        .expect("branch step runs")
    {
        SchedulerStep::Ran { node, outcome } => {
            assert_eq!(ran_task(&world, node), branch_task);
            assert!(matches!(*outcome, StepOutcome::Completed { .. }));
        }
        other => panic!("expected the branch to run, got {other:?}"),
    }
    assert_eq!(
        world
            .runtime
            .scheduler
            .state(parent_node)
            .expect("parent state"),
        NodeState::Waiting
    );

    // Pass 3: the last child completes and requeues the parent.
    match world
        .runtime
        .scheduler_step(&session)
        .expect("second child step runs")
    {
        SchedulerStep::Ran { node, outcome } => {
            assert_eq!(ran_task(&world, node), second_child);
            assert!(matches!(*outcome, StepOutcome::Completed { .. }));
        }
        other => panic!("expected the second child to run, got {other:?}"),
    }
    assert_eq!(
        world
            .runtime
            .scheduler
            .state(parent_node)
            .expect("parent state"),
        NodeState::Ready
    );

    // Pass 4: the parent resumes only after its last child settled.
    match world
        .runtime
        .scheduler_step(&session)
        .expect("parent step runs")
    {
        SchedulerStep::Ran { node, outcome } => {
            assert_eq!(ran_task(&world, node), parent_task);
            assert!(matches!(*outcome, StepOutcome::Completed { .. }));
        }
        other => panic!("expected the parent to resume, got {other:?}"),
    }
    assert!(matches!(
        world.runtime.scheduler_step(&session),
        Ok(SchedulerStep::Idle)
    ));
    assert_eq!(world.provider_calls.load(Ordering::SeqCst), 4);
}

#[test]
fn decision_step_error_settles_node_and_tree_recovers() {
    let (mut world, file, grant) = scoped_world("error-settles");
    world.runtime.scheduler = Scheduler::new(1, 4);
    let session = world.open_session("bootstrap-error-settles");
    let first_task = world.create_task(&session, "cmd-first");
    answer_task(
        &mut world,
        &session,
        "cmd-first-answer",
        &first_task,
        &node_answer(&file),
        1,
    );
    let second_task = world.create_task(&session, "cmd-second");
    answer_task(
        &mut world,
        &session,
        "cmd-second-answer",
        &second_task,
        &node_answer(&file),
        2,
    );

    // Both runnable nodes froze the now-revoked grant: their decision
    // steps fail at mutable admission, before any provider effect.
    world.runtime.policy_writer().revoke(&grant);
    assert!(world.runtime.scheduler_step(&session).is_err());
    assert_eq!(world.runtime.scheduler.running_count(), 0);
    assert_eq!(world.runtime.scheduler.held_units(), 0);

    // A second failing node must not meet a tree already stalled by the
    // first: the slot was released, so it admits and fails too.
    assert!(world.runtime.scheduler_step(&session).is_err());
    assert_eq!(world.runtime.scheduler.running_count(), 0);
    assert_eq!(world.runtime.scheduler.held_units(), 0);
    assert_eq!(world.provider_calls.load(Ordering::SeqCst), 0);

    // A fresh scope grant unblocks the tree: the next answered task
    // runs to completion through the same driver.
    world
        .runtime
        .set_read_scope(world.root.join("scope"), file.clone());
    let third_task = world.create_task(&session, "cmd-third");
    answer_task(
        &mut world,
        &session,
        "cmd-third-answer",
        &third_task,
        &node_answer(&file),
        3,
    );
    match world
        .runtime
        .scheduler_step(&session)
        .expect("third step runs")
    {
        SchedulerStep::Ran { node, outcome } => {
            assert_eq!(ran_task(&world, node), third_task);
            assert!(matches!(*outcome, StepOutcome::Completed { .. }));
        }
        other => panic!("expected the third task to run, got {other:?}"),
    }
    assert_eq!(world.provider_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn cancel_ingress_drains_tree_remaining_children_never_dispatch() {
    let (mut world, file, _grant) = scoped_world("cancel-ingress");
    world.runtime.scheduler = Scheduler::new(1, 4);
    let session = world.open_session("bootstrap-cancel-ingress");
    let parent_task = world.create_task(&session, "cmd-parent");
    answer_task(
        &mut world,
        &session,
        "cmd-parent-answer",
        &parent_task,
        &node_answer(&file),
        1,
    );
    let first_child = create_child_task(&mut world, &session, "cmd-child-1", &parent_task);
    answer_task(
        &mut world,
        &session,
        "cmd-child-1-answer",
        &first_child,
        &node_answer(&file),
        2,
    );
    let second_child = create_child_task(&mut world, &session, "cmd-child-2", &parent_task);
    answer_task(
        &mut world,
        &session,
        "cmd-child-2-answer",
        &second_child,
        &node_answer(&file),
        3,
    );

    // Pass 1: the parent waits on its children, the first completes.
    match world
        .runtime
        .scheduler_step(&session)
        .expect("first child step runs")
    {
        SchedulerStep::Ran { node, outcome } => {
            assert_eq!(ran_task(&world, node), first_child);
            assert!(matches!(*outcome, StepOutcome::Completed { .. }));
        }
        other => panic!("expected the first child to run, got {other:?}"),
    }
    let spent = world.provider_calls.load(Ordering::SeqCst);
    assert_eq!(spent, 1);
    // The user cancels through the real ingress: the store cancels the
    // task and the scheduler tree drains in the same command, so the
    // remaining child never admits or dispatches.
    cancel_task_via_ingress(&mut world, &session, &parent_task);

    // Reset, reconnect, and the late child-completed callback arrive
    // together; one scheduler pass observes every delivery and admits
    // nothing from the cancelled tree.
    world
        .runtime
        .notifications
        .push(late_event(&session, None, "quota.reset"));
    world
        .runtime
        .notifications
        .push(late_event(&session, None, "connection.reattached"));
    world
        .runtime
        .notifications
        .push(late_event(&session, Some(&second_child), "child.completed"));
    assert!(matches!(
        world.runtime.scheduler_step(&session),
        Ok(SchedulerStep::Idle)
    ));
    assert_eq!(world.runtime.scheduler.ignored_late_deliveries(), 1);
    assert_eq!(world.provider_calls.load(Ordering::SeqCst), spent);

    // A repeated cancel through the ingress is the store's historical
    // answer, and the tree stays drained: no resurrection.
    cancel_task_via_ingress(&mut world, &session, &parent_task);
    assert!(matches!(
        world.runtime.scheduler_step(&session),
        Ok(SchedulerStep::Idle)
    ));
    assert_eq!(world.provider_calls.load(Ordering::SeqCst), spent);

    // Spent cost and completed effects survive the cancellation.
    let first_snapshot = world
        .runtime
        .store()
        .snapshot(&first_child)
        .expect("first child snapshot");
    assert_eq!(first_snapshot.lifecycle, Lifecycle::Completed);
    let parent_snapshot = world
        .runtime
        .store()
        .snapshot(&parent_task)
        .expect("parent snapshot");
    assert_eq!(parent_snapshot.lifecycle, Lifecycle::Cancelled);
    let second_snapshot = world
        .runtime
        .store()
        .snapshot(&second_child)
        .expect("second child snapshot");
    assert_ne!(second_snapshot.lifecycle, Lifecycle::Completed);
    assert_eq!(world.runtime.scheduler.running_count(), 0);

    // A scheduler-level repeat drain is a pure no-op on the already
    // cancelled tree.
    assert_eq!(
        world
            .runtime
            .scheduler
            .cancel_task_tree(&parent_task)
            .expect("repeat drain"),
        Vec::<usize>::new()
    );

    // A child answered AFTER the cancellation lands on a settled tree:
    // the answer stays durable, but no runnable node is built, so it
    // never dispatches.
    let late_child = create_child_task(&mut world, &session, "cmd-late-child", &parent_task);
    answer_task(
        &mut world,
        &session,
        "cmd-late-child-answer",
        &late_child,
        &node_answer(&file),
        4,
    );
    assert!(matches!(
        world.runtime.scheduler_step(&session),
        Ok(SchedulerStep::Idle)
    ));
    assert_eq!(world.provider_calls.load(Ordering::SeqCst), spent);

    // Late completion callbacks for the cancelled nodes stay inert.
    assert!(matches!(
        world.runtime.scheduler_step(&session),
        Ok(SchedulerStep::Idle)
    ));
    assert_eq!(world.provider_calls.load(Ordering::SeqCst), spent);
}

#[test]
fn cancel_of_unanswered_parent_drains_root_attached_descendants() {
    let (mut world, file, _grant) = scoped_world("cancel-unanswered-parent");
    world.runtime.scheduler = Scheduler::new(1, 4);
    let session = world.open_session("bootstrap-cancel-unanswered");
    // The parent is never answered, so it carries no scheduler node.
    let parent_task = world.create_task(&session, "cmd-parent");
    let child_task = create_child_task(&mut world, &session, "cmd-child", &parent_task);
    answer_task(
        &mut world,
        &session,
        "cmd-child-answer",
        &child_task,
        &node_answer(&file),
        1,
    );
    // The answered child's node attached as a ROOT: its nearest
    // node-carrying ancestor does not exist.
    let child_node = world
        .runtime
        .scheduler
        .node_of_task(&child_task)
        .expect("child node");

    // Cancelling the never-answered parent through the real ingress
    // must still drain the descendant: the cancelled task's remaining
    // children never admit or dispatch (AC-012), regardless of which
    // ancestors carried nodes.
    cancel_task_via_ingress(&mut world, &session, &parent_task);
    assert_eq!(
        world
            .runtime
            .scheduler
            .state(child_node)
            .expect("child node state"),
        NodeState::Cancelled
    );
    assert!(matches!(
        world.runtime.scheduler_step(&session),
        Ok(SchedulerStep::Idle)
    ));
    assert_eq!(world.provider_calls.load(Ordering::SeqCst), 0);
    let child_snapshot = world
        .runtime
        .store()
        .snapshot(&child_task)
        .expect("child snapshot");
    assert_ne!(child_snapshot.lifecycle, Lifecycle::Completed);
    assert_eq!(world.runtime.scheduler.running_count(), 0);
    assert_eq!(world.runtime.scheduler.held_units(), 0);
}

/// AC-012 residual: the cancel drain records the cancelled task
/// subtree, so a later answer for a descendant whose nearest
/// node-carrying ancestor survived the cancelled middle still grows no
/// runnable node — the answer stays durable, nothing reattaches under
/// the surviving ancestor, and the cancelled subtree never dispatches.
#[test]
fn reanswer_after_cancelled_middle_never_reattaches_under_surviving_ancestor() {
    let (mut world, file, _grant) = scoped_world("cancel-middle-reattach");
    world.runtime.scheduler = Scheduler::new(1, 4);
    let session = world.open_session("bootstrap-cancel-middle");
    // The root is answered and carries a live node; the middle task is
    // never answered, so it carries none.
    let root_task = world.create_task(&session, "cmd-root");
    answer_task(
        &mut world,
        &session,
        "cmd-root-answer",
        &root_task,
        &node_answer(&file),
        1,
    );
    let middle_task = create_child_task(&mut world, &session, "cmd-middle", &root_task);
    // The descendant's node attaches to the ROOT's node: its nearest
    // node-carrying ancestor sits above the node-less middle.
    let descendant_task = create_child_task(&mut world, &session, "cmd-descendant", &middle_task);
    answer_task(
        &mut world,
        &session,
        "cmd-descendant-answer",
        &descendant_task,
        &node_answer(&file),
        2,
    );
    let drained_node = world
        .runtime
        .scheduler
        .node_of_task(&descendant_task)
        .expect("descendant node");

    // Cancelling the node-less middle drains the descendant's node even
    // though it hangs under the surviving root.
    cancel_task_via_ingress(&mut world, &session, &middle_task);
    assert_eq!(
        world
            .runtime
            .scheduler
            .state(drained_node)
            .expect("drained node state"),
        NodeState::Cancelled
    );

    // A later real answer for the descendant fails closed: no fresh
    // runnable node replaces the drained one, so nothing can reattach
    // under the root's live node.
    answer_task(
        &mut world,
        &session,
        "cmd-descendant-reanswer",
        &descendant_task,
        &node_answer(&file),
        3,
    );
    assert_eq!(
        world.runtime.scheduler.node_of_task(&descendant_task),
        Some(drained_node)
    );
    assert_eq!(
        world
            .runtime
            .scheduler
            .state(drained_node)
            .expect("drained node state"),
        NodeState::Cancelled
    );

    // The step loop proves the dispatch half: the only runnable work
    // left is the surviving root itself — exactly one dispatch, and
    // never one for the cancelled subtree.
    match world
        .runtime
        .scheduler_step(&session)
        .expect("root step runs")
    {
        SchedulerStep::Ran { node, outcome } => {
            assert_eq!(ran_task(&world, node), root_task);
            assert!(
                matches!(*outcome, StepOutcome::Completed { .. }),
                "root decision step must complete, got {outcome:?}"
            );
        }
        other => panic!("expected the surviving root to run, got {other:?}"),
    }
    assert_eq!(world.provider_calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        world.runtime.scheduler_step(&session),
        Ok(SchedulerStep::Idle)
    ));
    assert_eq!(world.provider_calls.load(Ordering::SeqCst), 1);
    assert_eq!(world.runtime.scheduler.running_count(), 0);
    assert_eq!(world.runtime.scheduler.held_units(), 0);
}

#[test]
fn ready_independent_branch_runs_beside_slow_sibling() {
    let mut scheduler = Scheduler::new(2, 4);
    let slow = scheduler
        .submit(
            None,
            stub_task("slow"),
            answer_custom("read nothing"),
            "grant".to_string(),
            1,
        )
        .expect("slow submitted");
    let fast = scheduler
        .submit(
            None,
            stub_task("fast"),
            answer_custom("read nothing"),
            "grant".to_string(),
            1,
        )
        .expect("fast submitted");
    let queued = scheduler
        .submit(
            None,
            stub_task("queued"),
            answer_custom("read nothing"),
            "grant".to_string(),
            1,
        )
        .expect("queued submitted");

    // The slow sibling stays Running forever in this proof; the ready
    // independent branch must not wait behind it.
    assert_eq!(scheduler.admit_next(), Some(slow));
    assert_eq!(scheduler.admit_next(), Some(fast));
    assert_eq!(scheduler.running_count(), 2);
    assert_eq!(scheduler.held_units(), 2);

    // Caps hold: the third ready node waits while both slots are taken.
    assert_eq!(scheduler.admit_next(), None);
    assert_eq!(
        scheduler.state(slow).expect("slow state"),
        NodeState::Running
    );
    assert_eq!(
        scheduler.state(fast).expect("fast state"),
        NodeState::Running
    );
    assert_eq!(
        scheduler.state(queued).expect("queued state"),
        NodeState::Ready
    );
}

#[test]
fn resource_cap_blocks_head_of_line_without_bypass() {
    let mut scheduler = Scheduler::new(4, 3);
    // An unrepresentable reservation is rejected at submit: a node that
    // can never fit must not stall the queue head forever. Scope: the
    // ingress path always submits a one-unit reservation, so this
    // rejection is reachable only through the direct submit seam.
    assert!(
        scheduler
            .submit(
                None,
                stub_task("oversize"),
                answer_custom("read nothing"),
                "grant".to_string(),
                4,
            )
            .is_err()
    );
    let heavy = scheduler
        .submit(
            None,
            stub_task("heavy"),
            answer_custom("read nothing"),
            "grant".to_string(),
            2,
        )
        .expect("heavy submitted");
    let second_heavy = scheduler
        .submit(
            None,
            stub_task("second-heavy"),
            answer_custom("read nothing"),
            "grant".to_string(),
            2,
        )
        .expect("second heavy submitted");
    let light = scheduler
        .submit(
            None,
            stub_task("light"),
            answer_custom("read nothing"),
            "grant".to_string(),
            1,
        )
        .expect("light submitted");

    assert_eq!(scheduler.admit_next(), Some(heavy));
    assert_eq!(scheduler.held_units(), 2);

    // The queue is strict FIFO: the head that does not fit blocks the
    // smaller node behind it (backpressure, no bypass).
    assert_eq!(scheduler.admit_next(), None);
    assert_eq!(scheduler.held_units(), 2);
    assert_eq!(
        scheduler.state(second_heavy).expect("second heavy state"),
        NodeState::Ready
    );

    assert!(matches!(
        scheduler.complete(heavy),
        Ok(CompleteTransition::Completed { resumed: None })
    ));
    assert_eq!(scheduler.held_units(), 0);

    // FIFO order survives the capacity wait: second heavy runs first.
    assert_eq!(scheduler.admit_next(), Some(second_heavy));
    assert_eq!(scheduler.admit_next(), Some(light));
    assert_eq!(scheduler.held_units(), 3);
    assert_eq!(scheduler.admit_next(), None);
    assert!(matches!(
        scheduler.complete(second_heavy),
        Ok(CompleteTransition::Completed { resumed: None })
    ));
    assert!(matches!(
        scheduler.complete(light),
        Ok(CompleteTransition::Completed { resumed: None })
    ));
    assert_eq!(scheduler.running_count(), 0);
}

#[test]
fn waiting_parent_resumes_only_after_last_child_settles() {
    let mut scheduler = Scheduler::new(1, 4);
    let parent = scheduler
        .submit(
            None,
            stub_task("parent"),
            answer_custom("read nothing"),
            "grant".to_string(),
            1,
        )
        .expect("parent submitted");
    assert_eq!(scheduler.admit_next(), Some(parent));
    let first = scheduler
        .submit(
            Some(parent),
            stub_task("first"),
            answer_custom("read nothing"),
            "grant".to_string(),
            1,
        )
        .expect("first submitted");
    let second = scheduler
        .submit(
            Some(parent),
            stub_task("second"),
            answer_custom("read nothing"),
            "grant".to_string(),
            1,
        )
        .expect("second submitted");
    assert!(matches!(
        scheduler.begin_wait(parent),
        Ok(WaitTransition::Released)
    ));

    assert_eq!(scheduler.admit_next(), Some(first));
    // One settled child never wakes the parent early.
    assert!(matches!(
        scheduler.complete(first),
        Ok(CompleteTransition::Completed { resumed: None })
    ));
    assert_eq!(
        scheduler.state(parent).expect("parent state"),
        NodeState::Waiting
    );
    // A ready node that never ran cannot complete.
    assert!(matches!(
        scheduler.complete(second),
        Err(SchedulerError::NotRunning { .. })
    ));
    // The freed slot goes to the remaining child, never to the parent.
    assert_eq!(scheduler.admit_next(), Some(second));
    assert!(matches!(
        scheduler.complete(second),
        Ok(CompleteTransition::Completed { resumed }) if resumed == Some(parent)
    ));
    assert_eq!(
        scheduler.state(parent).expect("parent state"),
        NodeState::Ready
    );
    assert_eq!(scheduler.admit_next(), Some(parent));
}

#[test]
fn cancel_tree_drains_pre_order_and_stays_idempotent() {
    let mut scheduler = Scheduler::new(1, 4);
    let session = SessionId("session-stub".to_string());
    let parent = scheduler
        .submit(
            None,
            stub_task("parent"),
            answer_custom("read nothing"),
            "grant".to_string(),
            1,
        )
        .expect("parent submitted");
    assert_eq!(scheduler.admit_next(), Some(parent));
    let first = scheduler
        .submit(
            Some(parent),
            stub_task("first"),
            answer_custom("read nothing"),
            "grant".to_string(),
            1,
        )
        .expect("first submitted");
    let second = scheduler
        .submit(
            Some(parent),
            stub_task("second"),
            answer_custom("read nothing"),
            "grant".to_string(),
            1,
        )
        .expect("second submitted");
    assert!(matches!(
        scheduler.begin_wait(parent),
        Ok(WaitTransition::Released)
    ));
    assert_eq!(scheduler.admit_next(), Some(first));

    // Cancellation drains the whole subtree in pre-order and releases
    // the running child.
    let drained = scheduler.cancel_tree(parent).expect("tree cancelled");
    assert_eq!(drained, vec![parent, first, second]);
    assert_eq!(scheduler.running_count(), 0);
    assert_eq!(scheduler.held_units(), 0);
    for node in [parent, first, second] {
        assert_eq!(
            scheduler.state(node).expect("node state"),
            NodeState::Cancelled
        );
    }
    assert_eq!(scheduler.admit_next(), None);

    // A repeated cancel is a pure no-op: no state change, no counts, no
    // resurrection while any sibling ever runs again.
    let repeat = scheduler.cancel_tree(parent).expect("repeat cancel");
    assert_eq!(repeat, Vec::<usize>::new());
    assert_eq!(scheduler.running_count(), 0);
    assert_eq!(
        scheduler.state(parent).expect("parent state"),
        NodeState::Cancelled
    );
    assert_eq!(scheduler.admit_next(), None);

    // The late callback settles nothing and is counted, not dropped.
    assert!(matches!(
        scheduler.complete(first),
        Ok(CompleteTransition::IgnoredCancelled)
    ));
    assert_eq!(scheduler.ignored_late_deliveries(), 1);
    assert!(matches!(
        scheduler.deliver(&late_event(
            &session,
            Some(&stub_task("parent")),
            "child.completed"
        )),
        DeliverVerdict::IgnoredCancelled
    ));
    assert_eq!(scheduler.ignored_late_deliveries(), 2);
    assert_eq!(scheduler.admit_next(), None);

    // A cancelled parent never gains new children.
    assert!(matches!(
        scheduler.submit(
            Some(parent),
            stub_task("late"),
            answer_custom("read nothing"),
            "grant".to_string(),
            1,
        ),
        Err(SchedulerError::ParentSettled { .. })
    ));
    // And the cancelled parent cannot begin a wait it never earned.
    assert!(matches!(
        scheduler.begin_wait(parent),
        Err(SchedulerError::NotRunning { .. })
    ));
}

#[test]
fn repeated_cancel_never_resumes_a_waiting_grandparent_early() {
    let mut scheduler = Scheduler::new(2, 4);
    let grandparent = scheduler
        .submit(
            None,
            stub_task("grandparent"),
            answer_custom("read nothing"),
            "grant".to_string(),
            1,
        )
        .expect("grandparent submitted");
    assert_eq!(scheduler.admit_next(), Some(grandparent));
    let parent = scheduler
        .submit(
            Some(grandparent),
            stub_task("parent"),
            answer_custom("read nothing"),
            "grant".to_string(),
            1,
        )
        .expect("parent submitted");
    let uncle = scheduler
        .submit(
            Some(grandparent),
            stub_task("uncle"),
            answer_custom("read nothing"),
            "grant".to_string(),
            1,
        )
        .expect("uncle submitted");
    assert!(matches!(
        scheduler.begin_wait(grandparent),
        Ok(WaitTransition::Released)
    ));
    assert_eq!(scheduler.admit_next(), Some(parent));
    assert_eq!(scheduler.admit_next(), Some(uncle));

    // Cancelling the parent branch settles the waiting grandparent's
    // count exactly once; the uncle keeps running.
    assert_eq!(
        scheduler.cancel_tree(parent).expect("branch cancelled"),
        vec![parent]
    );
    assert_eq!(
        scheduler.state(grandparent).expect("grandparent state"),
        NodeState::Waiting
    );

    // The re-cancel must not drop the count a second time and requeue
    // the grandparent while the uncle is still Running.
    assert_eq!(
        scheduler.cancel_tree(parent).expect("re-cancel"),
        Vec::<usize>::new()
    );
    assert_eq!(
        scheduler.state(grandparent).expect("grandparent state"),
        NodeState::Waiting
    );
    assert_eq!(
        scheduler.state(uncle).expect("uncle state"),
        NodeState::Running
    );
    assert_eq!(scheduler.running_count(), 1);
    assert_eq!(scheduler.admit_next(), None);

    // The grandparent resumes only when its last live child settles.
    assert!(matches!(
        scheduler.complete(uncle),
        Ok(CompleteTransition::Completed { resumed }) if resumed == Some(grandparent)
    ));
    assert_eq!(scheduler.admit_next(), Some(grandparent));
}

/// Scope: a cancelled task is terminal in the store, so the ingress can
/// never build a fresh node for the same task — the cancel→resubmit
/// half of latest-node keying is provable only at this scheduler seam.
/// The ingress halves (a late delivery counted against the cancelled
/// latest node) are proven by
/// `cancel_ingress_drains_tree_remaining_children_never_dispatch`.
#[test]
fn deliver_keys_to_the_latest_node_of_a_task() {
    let mut scheduler = Scheduler::new(2, 4);
    let session = SessionId("session-stub".to_string());
    let task = stub_task("resubmitted");
    let first = scheduler
        .submit(
            None,
            task.clone(),
            answer_custom("read nothing"),
            "grant".to_string(),
            1,
        )
        .expect("first submitted");
    assert_eq!(scheduler.admit_next(), Some(first));
    assert_eq!(
        scheduler.cancel_tree(first).expect("cancelled"),
        vec![first]
    );

    // After a cancel and resubmit, the task's fresh node is live: a
    // delivery for it is observed, not miscounted against the
    // historical cancelled node.
    scheduler
        .submit(
            None,
            task.clone(),
            answer_custom("read nothing"),
            "grant".to_string(),
            1,
        )
        .expect("resubmitted");
    assert_eq!(
        scheduler.deliver(&late_event(&session, Some(&task), "child.completed")),
        DeliverVerdict::Observed
    );
    assert_eq!(scheduler.ignored_late_deliveries(), 0);
}

// ----- supervisor: progress versus sterile retry (AC-011, INV-027) -----

/// One policy for every class so a test pins detector behavior at
/// small caps; the default policy keeps the real per-class spread.
fn strict_policy(
    window: usize,
    exact: usize,
    fuzzy: usize,
    ping_pong: usize,
    no_progress: usize,
    cooldown: u32,
) -> SupervisorPolicy {
    let thresholds = ClassThresholds {
        window,
        exact_repeat: exact,
        fuzzy_repeat: fuzzy,
        ping_pong,
        no_progress,
        cooldown,
    };
    SupervisorPolicy {
        read: thresholds,
        test: thresholds,
        retrieve: thresholds,
    }
}

#[test]
fn sterile_exact_repeat_fires_once_at_cap_then_cooldown_bounds_the_loop() {
    let scheduler = Scheduler::new(2, 4);
    let mut supervisor = Supervisor::new(SupervisorPolicy::default()).expect("policy validates");
    let task = stub_task("denied-loop");
    let failure = || {
        Observation::failure(
            task.clone(),
            OperationClass::Read,
            "read_file",
            "/scope/allowed.txt",
            "denied: scope",
        )
    };

    assert_eq!(supervisor.observe(&scheduler, failure()), None);
    assert_eq!(supervisor.observe(&scheduler, failure()), None);
    let reaction = supervisor
        .observe(&scheduler, failure())
        .expect("the configured cap fires");
    assert_eq!(
        reaction.cause,
        StallCause::ExactRepeat {
            signature: FailureSignature {
                tool: "read_file".to_string(),
                args: "/scope/allowed.txt".to_string(),
                result: "denied: scope".to_string(),
            },
            repeats: 3,
        }
    );
    assert_eq!(reaction.task, task);
    assert_eq!(reaction.class, OperationClass::Read);
    assert_eq!(
        reaction.thresholds,
        ClassThresholds {
            window: 8,
            exact_repeat: 3,
            fuzzy_repeat: 4,
            ping_pong: 6,
            no_progress: 8,
            cooldown: 4,
        }
    );
    assert_eq!(supervisor.reactions(&task).len(), 1);

    // Cooldown: identical failures stay quiet — one reaction per firing.
    for _ in 0..4 {
        assert_eq!(supervisor.observe(&scheduler, failure()), None);
    }
    assert_eq!(supervisor.reactions(&task).len(), 1);

    // Bounded, not permanent: once the cooldown elapses, a still-sterile
    // window fires exactly one new reaction.
    let refire = supervisor
        .observe(&scheduler, failure())
        .expect("rearmed firing");
    assert!(matches!(refire.cause, StallCause::ExactRepeat { repeats, .. } if repeats >= 3));
    assert_eq!(supervisor.reactions(&task).len(), 2);
}

/// INV-027 ordering: when the exact (tool+args+result) and fuzzy
/// (tool+args) conditions hold on the same observation, the exact
/// signature fires first.
#[test]
fn exact_signature_fires_before_fuzzy_at_equal_thresholds() {
    let scheduler = Scheduler::new(2, 4);
    let mut supervisor =
        Supervisor::new(strict_policy(8, 3, 3, 6, 8, 2)).expect("policy validates");
    let task = stub_task("precedence");
    for observed in 1..=2 {
        assert_eq!(
            supervisor.observe(
                &scheduler,
                Observation::failure(
                    task.clone(),
                    OperationClass::Read,
                    "read_file",
                    "/scope/f",
                    "denied: scope"
                )
            ),
            None,
            "below the cap on observation {observed}"
        );
    }
    let reaction = supervisor
        .observe(
            &scheduler,
            Observation::failure(
                task.clone(),
                OperationClass::Read,
                "read_file",
                "/scope/f",
                "denied: scope",
            ),
        )
        .expect("cap reached");
    assert!(matches!(
        reaction.cause,
        StallCause::ExactRepeat { repeats: 3, .. }
    ));

    // Same tool+args with varying results: only the fuzzy detector can
    // ever trip, and it does at its own cap.
    let varying = stub_task("varying-results");
    for index in 0..2 {
        assert_eq!(
            supervisor.observe(
                &scheduler,
                Observation::failure(
                    varying.clone(),
                    OperationClass::Read,
                    "read_file",
                    "/scope/f",
                    &format!("denied: attempt {index}")
                )
            ),
            None
        );
    }
    let reaction = supervisor
        .observe(
            &scheduler,
            Observation::failure(
                varying.clone(),
                OperationClass::Read,
                "read_file",
                "/scope/f",
                "denied: attempt 2",
            ),
        )
        .expect("fuzzy cap reached");
    assert!(matches!(
        reaction.cause,
        StallCause::FuzzyRepeat { repeats: 3, .. }
    ));
}

#[test]
fn ping_pong_alternation_between_two_failures_is_detected() {
    let scheduler = Scheduler::new(2, 4);
    let mut supervisor =
        Supervisor::new(strict_policy(8, 3, 4, 6, 8, 2)).expect("policy validates");
    let task = stub_task("ping-pong");
    let red = ("test_run", "cargo test", "assertion failed");
    let broken = ("build", "cargo build", "compile error");
    // Five alternations stay below the cap; the sixth fires.
    for turn in 0..5 {
        let (tool, args, result) = if turn % 2 == 0 { red } else { broken };
        assert_eq!(
            supervisor.observe(
                &scheduler,
                Observation::failure(task.clone(), OperationClass::Test, tool, args, result)
            ),
            None
        );
    }
    let reaction = supervisor
        .observe(
            &scheduler,
            Observation::failure(
                task.clone(),
                OperationClass::Test,
                broken.0,
                broken.1,
                broken.2,
            ),
        )
        .expect("the alternation cap fires");
    assert_eq!(
        reaction.cause,
        StallCause::PingPong {
            first: FailureSignature {
                tool: broken.0.to_string(),
                args: broken.1.to_string(),
                result: broken.2.to_string(),
            },
            second: FailureSignature {
                tool: red.0.to_string(),
                args: red.1.to_string(),
                result: red.2.to_string(),
            },
            alternations: 6,
        }
    );
}

/// The ping-pong detector matches the trailing cycle exactly as the
/// exact and fuzzy detectors match trailing runs: one unmatched sample
/// earlier in the streak never disqualifies the cycle behind it.
#[test]
fn ping_pong_matches_the_trailing_cycle_not_the_whole_streak() {
    let scheduler = Scheduler::new(2, 4);
    let mut supervisor =
        Supervisor::new(strict_policy(8, 3, 4, 5, 8, 2)).expect("policy validates");
    let task = stub_task("late-ping-pong");
    let red = ("test_run", "cargo test", "assertion failed");
    let broken = ("build", "cargo build", "compile error");
    let stray = ("lint", "cargo clippy", "warning denied");
    // An unmatched failure older than the cycle, then five alternating
    // ones ending on the newest.
    assert_eq!(
        supervisor.observe(
            &scheduler,
            Observation::failure(
                task.clone(),
                OperationClass::Test,
                stray.0,
                stray.1,
                stray.2
            )
        ),
        None
    );
    for turn in 0..4 {
        let (tool, args, result) = if turn % 2 == 0 { broken } else { red };
        assert_eq!(
            supervisor.observe(
                &scheduler,
                Observation::failure(task.clone(), OperationClass::Test, tool, args, result)
            ),
            None,
            "trailing cycle {turn} below the cap"
        );
    }
    let reaction = supervisor
        .observe(
            &scheduler,
            Observation::failure(
                task.clone(),
                OperationClass::Test,
                broken.0,
                broken.1,
                broken.2,
            ),
        )
        .expect("the trailing cycle fires despite the older stray");
    assert!(matches!(
        &reaction.cause,
        StallCause::PingPong { first, second, alternations: 5 }
            if first.tool == broken.0 && second.tool == red.0
    ));
}

/// A policy whose detectors could never fire — or could never stay
/// bounded — is rejected at construction, not discovered dead at
/// runtime (INV-027).
#[test]
fn degenerate_detector_policies_are_rejected_at_construction() {
    assert_eq!(
        Supervisor::new(strict_policy(8, 3, 4, 6, 8, 2))
            .expect("a sound policy constructs")
            .reactions(&stub_task("unused")),
        &[]
    );
    let rejects = [
        (
            strict_policy(7, 3, 4, 6, 8, 2),
            PolicyFault::WindowBelowCap { window: 7, cap: 8 },
        ),
        (
            strict_policy(8, 5, 3, 6, 8, 2),
            PolicyFault::FuzzyBelowExact { fuzzy: 3, exact: 5 },
        ),
        (
            strict_policy(8, 3, 4, 1, 8, 2),
            PolicyFault::PingPongBelowPair { cap: 1 },
        ),
        (
            strict_policy(8, 3, 4, 6, 8, 0),
            PolicyFault::ZeroCooldown { cooldown: 0 },
        ),
    ];
    for (policy, fault) in rejects {
        let error = Supervisor::new(policy).expect_err("degenerate policy rejected");
        assert_eq!(
            error,
            SupervisorError::InvalidPolicy {
                class: OperationClass::Read,
                fault,
            }
        );
    }
}

/// The in-memory watch set is bounded LRU: a task pushed out of the
/// window rebuilds from zero, so its detector stays quiet where a
/// retained window would have fired — the durable journal, not the
/// map, is the history.
#[test]
fn watch_set_is_bounded_lru_so_an_evicted_task_rebuilds_from_zero() {
    let scheduler = Scheduler::new(2, 4);
    let mut supervisor =
        Supervisor::new(strict_policy(8, 3, 4, 6, 8, 2)).expect("policy validates");
    let first = stub_task("first-watched");
    let failure = |task: TaskId| {
        Observation::failure(
            task,
            OperationClass::Read,
            "read_file",
            "/scope",
            "denied: scope",
        )
    };
    // Two identical failures: one below the exact cap.
    for _ in 0..2 {
        assert_eq!(supervisor.observe(&scheduler, failure(first.clone())), None);
    }
    // WATCH_LIMIT newer tasks push `first` out of the bounded set.
    for index in 0..WATCH_LIMIT {
        assert_eq!(
            supervisor.observe(&scheduler, failure(stub_task(&format!("churn-{index}")))),
            None
        );
    }
    // Evicted: the third identical failure is only the first of a
    // fresh window — a retained window would fire the exact detector.
    assert_eq!(
        supervisor.observe(&scheduler, failure(first.clone())),
        None,
        "an evicted task rebuilds its window from zero"
    );
}

/// The catch-all detector: failures that never repeat a signature still
/// stall the task when nothing useful happens.
#[test]
fn no_progress_detector_bounds_varying_failure_signatures() {
    let scheduler = Scheduler::new(2, 4);
    let mut supervisor =
        Supervisor::new(strict_policy(8, 3, 4, 6, 5, 2)).expect("policy validates");
    let task = stub_task("drifting-failures");
    let tools = ["run", "lint", "build", "test", "fmt"];
    for (index, tool) in tools.iter().enumerate().take(4) {
        let observation = Observation::failure(
            task.clone(),
            OperationClass::Read,
            tool,
            "/scope",
            &format!("failed {index}"),
        );
        assert_eq!(supervisor.observe(&scheduler, observation), None);
    }
    let observation = Observation::failure(
        task.clone(),
        OperationClass::Read,
        "fmt",
        "/scope",
        "failed 4",
    );
    let reaction = supervisor
        .observe(&scheduler, observation)
        .expect("no-progress cap fires");
    assert_eq!(reaction.cause, StallCause::NoProgress { observations: 5 });
}

/// PROH-005 false-positive controls: heartbeat (quiet long test),
/// evidence growth (paginated retrieval) and new inputs (RED→GREEN)
/// each keep identical repeats unmarked.
#[test]
fn heartbeat_evidence_growth_and_new_inputs_prevent_sterile_marks() {
    let scheduler = Scheduler::new(2, 4);
    let mut supervisor =
        Supervisor::new(strict_policy(8, 3, 3, 6, 5, 2)).expect("policy validates");

    // A quiet long test: the same signature far beyond every cap, a
    // heartbeat between runs, no prose at all.
    let quiet = stub_task("quiet-long-test");
    for _ in 0..12 {
        let observation = Observation::failure(
            quiet.clone(),
            OperationClass::Test,
            "test_run",
            "cargo test --all",
            "no prose yet",
        )
        .with_heartbeat();
        assert_eq!(supervisor.observe(&scheduler, observation), None);
    }

    // Paginated retrieval: identical reads where every page grows
    // evidence — missing prose is not sterility.
    let pager = stub_task("paginated-retrieval");
    for _ in 0..10 {
        let observation = Observation::failure(
            pager.clone(),
            OperationClass::Retrieve,
            "read_file",
            "/scope/log",
            "page served",
        )
        .with_evidence_growth(4096);
        assert_eq!(supervisor.observe(&scheduler, observation), None);
    }

    // RED→GREEN: failing runs at the cap's edge, each edit between runs
    // carries new inputs; the green run grows evidence.
    let tdd = stub_task("red-green");
    let red_run = |progress: bool| {
        let observation = Observation::failure(
            tdd.clone(),
            OperationClass::Test,
            "test_run",
            "cargo test filter",
            "assertion failed: sum",
        );
        if progress {
            observation.with_new_inputs()
        } else {
            observation
        }
    };
    assert_eq!(supervisor.observe(&scheduler, red_run(false)), None);
    assert_eq!(supervisor.observe(&scheduler, red_run(false)), None);
    assert_eq!(supervisor.observe(&scheduler, red_run(true)), None);
    assert_eq!(supervisor.observe(&scheduler, red_run(false)), None);
    assert_eq!(supervisor.observe(&scheduler, red_run(false)), None);
    let green = Observation::failure(
        tdd.clone(),
        OperationClass::Test,
        "test_run",
        "cargo test filter",
        "ok. 3 passed",
    )
    .with_evidence_growth(256);
    assert_eq!(supervisor.observe(&scheduler, green), None);

    assert_eq!(supervisor.reactions(&quiet), &[]);
    assert_eq!(supervisor.reactions(&pager), &[]);
    assert_eq!(supervisor.reactions(&tdd), &[]);
}

/// Waiting on children is bounded progress (REQ-010): the first
/// `no_progress` observations while the task's node is Waiting count
/// useful, but a wait that outlives that grace is itself the stall —
/// the suppression can never hide a stalled stream forever. A task
/// that is not waiting still trips the detectors at their caps.
#[test]
fn waiting_is_bounded_progress_not_invisible_forever() {
    let mut scheduler = Scheduler::new(1, 4);
    let parent_task = stub_task("waiting-parent");
    let parent = scheduler
        .submit(
            None,
            parent_task.clone(),
            answer_custom("read nothing"),
            "grant".to_string(),
            1,
        )
        .expect("parent submitted");
    assert_eq!(scheduler.admit_next(), Some(parent));
    scheduler
        .submit(
            Some(parent),
            stub_task("child"),
            answer_custom("read nothing"),
            "grant".to_string(),
            1,
        )
        .expect("child submitted");
    assert!(matches!(
        scheduler.begin_wait(parent),
        Ok(WaitTransition::Released)
    ));

    let mut supervisor =
        Supervisor::new(strict_policy(8, 3, 3, 6, 5, 2)).expect("policy validates");
    let parent_failure = || {
        Observation::failure(
            parent_task.clone(),
            OperationClass::Read,
            "read_file",
            "/scope/f",
            "denied: scope",
        )
    };
    // Grace: the first five waiting observations (no_progress = 5) are
    // progress by waiting.
    for _ in 0..5 {
        assert_eq!(supervisor.observe(&scheduler, parent_failure()), None);
    }
    assert_eq!(supervisor.reactions(&parent_task), &[]);
    // Bound: identical failures keep arriving while the node waits;
    // past the grace they count sterile and the exact detector fires
    // at its cap — a stalled wait is visible, not invisible forever.
    for _ in 0..2 {
        assert_eq!(supervisor.observe(&scheduler, parent_failure()), None);
    }
    let reaction = supervisor
        .observe(&scheduler, parent_failure())
        .expect("the wait outlived its grace");
    assert!(matches!(
        reaction.cause,
        StallCause::ExactRepeat { repeats: 3, .. }
    ));

    // The sibling discriminator: without the waiting node the same
    // stream trips the exact detector at its cap with no grace.
    let looping = stub_task("looping");
    for _ in 0..2 {
        let observation = Observation::failure(
            looping.clone(),
            OperationClass::Read,
            "read_file",
            "/scope/f",
            "denied: scope",
        );
        assert_eq!(supervisor.observe(&scheduler, observation), None);
    }
    let observation = Observation::failure(
        looping.clone(),
        OperationClass::Read,
        "read_file",
        "/scope/f",
        "denied: scope",
    );
    let reaction = supervisor
        .observe(&scheduler, observation)
        .expect("non-waiting task fires");
    assert!(matches!(
        reaction.cause,
        StallCause::ExactRepeat { repeats: 3, .. }
    ));
}

/// INV-027: thresholds are per operation class — the same sterile
/// stream trips Read at 3 and Test only at 5; no universal limit.
#[test]
fn thresholds_are_per_operation_class_not_one_universal_limit() {
    let scheduler = Scheduler::new(2, 4);
    let mut supervisor = Supervisor::new(SupervisorPolicy::default()).expect("policy validates");
    let reader = stub_task("reader-loop");
    for observed in 1..=2 {
        let observation = Observation::failure(
            reader.clone(),
            OperationClass::Read,
            "read_file",
            "/scope/f",
            "denied: scope",
        );
        assert_eq!(
            supervisor.observe(&scheduler, observation),
            None,
            "read below cap {observed}"
        );
    }
    let observation = Observation::failure(
        reader.clone(),
        OperationClass::Read,
        "read_file",
        "/scope/f",
        "denied: scope",
    );
    let read_reaction = supervisor
        .observe(&scheduler, observation)
        .expect("read cap is 3");
    assert_eq!(read_reaction.thresholds.exact_repeat, 3);

    let tester = stub_task("tester-loop");
    for observed in 1..=4 {
        let observation = Observation::failure(
            tester.clone(),
            OperationClass::Test,
            "test_run",
            "cargo test",
            "assertion failed",
        );
        assert_eq!(
            supervisor.observe(&scheduler, observation),
            None,
            "test below cap {observed}"
        );
    }
    let observation = Observation::failure(
        tester.clone(),
        OperationClass::Test,
        "test_run",
        "cargo test",
        "assertion failed",
    );
    let test_reaction = supervisor
        .observe(&scheduler, observation)
        .expect("test cap is 5");
    assert_eq!(test_reaction.thresholds.exact_repeat, 5);
    assert_ne!(read_reaction.thresholds, test_reaction.thresholds);
}

/// The reaction record is the durable audit surface: one row per
/// firing, retrieved page-wise with the cause and the limits/cooldown
/// that were in force.
#[test]
fn reaction_records_are_durable_and_pageable_in_task_state() {
    let (mut world, _file, _grant) = scoped_world("supervisor-journal");
    let session = world.open_session("bootstrap-supervisor-journal");
    let task = world.create_task(&session, "cmd-sterile-loop");
    let scheduler = Scheduler::new(2, 4);
    let mut supervisor =
        Supervisor::new(strict_policy(8, 3, 3, 6, 5, 1)).expect("policy validates");
    let mut fired = Vec::new();
    for _ in 0..7 {
        let observation = Observation::failure(
            task.clone(),
            OperationClass::Read,
            "read_file",
            "/scope/f",
            "denied: scope",
        );
        if let Some(reaction) = supervisor.observe(&scheduler, observation) {
            fired.push(reaction);
        }
    }
    // Cooldown 1: firings at 3, 5 and 7 — one reaction per firing.
    assert_eq!(fired.len(), 3);
    for reaction in &fired {
        world
            .runtime
            .store_writer()
            .record_supervisor_reaction(reaction)
            .expect("reaction recorded");
    }

    let (first_page, has_more) = world
        .runtime
        .store()
        .supervisor_reactions(&task, 2, 0)
        .expect("first page");
    assert!(has_more);
    assert_eq!(first_page.len(), 2);
    assert_eq!(first_page[0].cause, fired[0].cause);
    assert_eq!(first_page[1].cause, fired[1].cause);
    assert_eq!(first_page[0].task, task);
    assert_eq!(first_page[0].thresholds, fired[0].thresholds);

    let (last_page, has_more) = world
        .runtime
        .store()
        .supervisor_reactions(&task, 2, 2)
        .expect("second page");
    assert!(!has_more);
    assert_eq!(last_page.len(), 1);
    assert_eq!(last_page[0].cause, fired[2].cause);
}

/// AC-011 on the production path: the runtime-owned supervisor reads
/// the scheduler's own outcome stream — no test-injected observe call —
/// and the one bounded reaction lands in the durable journal. An
/// enrolled deny on the scoped file denies every decision step before
/// any provider call: this runtime's concrete recurring failure
/// fingerprint.
#[test]
fn runtime_supervisor_journals_reactions_from_real_denied_outcomes() {
    let (mut world, file, _grant) = scoped_world("supervisor-wired");
    let session = world.open_session("bootstrap-supervisor-wired");
    let task = world.create_task(&session, "cmd-supervisor-loop");
    world
        .runtime
        .policy_writer()
        .enroll_deny(&file)
        .expect("deny enrolled on the scoped file");

    let journal = |world: &World| {
        world
            .runtime
            .store()
            .supervisor_reactions(&task, 8, 0)
            .expect("journal read")
    };
    let mut denied = 0;
    for round in 0..4 {
        answer_task(
            &mut world,
            &session,
            &format!("cmd-supervisor-answer-{round}"),
            &task,
            &node_answer(&file),
            round + 10,
        );
        match world.runtime.scheduler_step(&session).expect("step runs") {
            SchedulerStep::Ran { outcome, .. } => {
                assert!(
                    matches!(*outcome, StepOutcome::EffectDenied { .. }),
                    "expected a denied step, got {outcome:?}"
                );
                denied += 1;
            }
            other => panic!("expected a denied step, got {other:?}"),
        }
        // Default read class: exact cap 3, cooldown 4 — one reaction
        // per firing, then quiet while the cooldown lasts.
        let expected = if denied < 3 { 0 } else { 1 };
        let (reactions, has_more) = journal(&world);
        assert!(!has_more);
        assert_eq!(
            reactions.len(),
            expected,
            "after {denied} denials the journal holds {reactions:?}"
        );
    }

    let (reactions, _) = journal(&world);
    let reaction = reactions.first().expect("one firing journaled");
    assert_eq!(reaction.task, task);
    assert_eq!(reaction.thresholds.exact_repeat, 3);
    assert!(matches!(
        &reaction.cause,
        StallCause::ExactRepeat { signature, repeats: 3 }
            if signature.tool == "read_file" && signature.result == "mode deny"
    ));
    // The enrolled deny gates the dispatch before any provider effect:
    // the sterile loop cost zero model calls.
    assert_eq!(world.provider_calls.load(Ordering::SeqCst), 0);
}

// ----- supervisor: the full outcome and error observation map -----
// DEC-016: every `StepOutcome` variant and every failed decision step
// feeds its typed observation fingerprint through the production
// driver — `EffectDenied` is not the only fed variant and no `Err`
// class bypasses the feed. The supervisor still never dispatches
// (INV-020): mapping is observation-only.

/// Provider stub whose reply never proposes a read: the decision step
/// settles as `waiting` (no ready action) without touching the worker.
struct NoReadProvider;

impl Provider for NoReadProvider {
    fn name(&self) -> &'static str {
        "no-read"
    }

    /// The scripted double answers any manifest it is handed.
    fn serves(&self, _connection: &str, _entry: &rivect::config::Connection) -> bool {
        true
    }

    fn send(&mut self, _manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        Ok(ProviderReply {
            text: "no permitted action".to_string(),
            tool_calls: Vec::new(),
            usage: UsageDelta::Unknown,
            wire_retries: 0,
        })
    }
}

/// Provider stub whose single read_file call names an absolute path
/// outside the granted scope: executor admission fails closed with the
/// typed outside-scope worker denial before any attempt is planned.
struct OutsideScopeProvider {
    target: String,
}

impl Provider for OutsideScopeProvider {
    fn name(&self) -> &'static str {
        "outside-scope"
    }

    /// The scripted double answers any manifest it is handed.
    fn serves(&self, _connection: &str, _entry: &rivect::config::Connection) -> bool {
        true
    }

    fn send(&mut self, _manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        Ok(ProviderReply {
            text: "read outside the scope".to_string(),
            tool_calls: vec![ToolCall {
                tool: "read_file".to_string(),
                path: Some(self.target.clone()),
            }],
            usage: UsageDelta::Unknown,
            wire_retries: 0,
        })
    }
}

/// Provider stub whose dispatch always fails: the decision step errors
/// at the broker boundary before any attempt is planned.
struct FailingProvider;

impl Provider for FailingProvider {
    fn name(&self) -> &'static str {
        "failing"
    }

    /// The scripted double answers any manifest it is handed — its
    /// failure arrives from `send`, preserving the scripted outcome.
    fn serves(&self, _connection: &str, _entry: &rivect::config::Connection) -> bool {
        true
    }

    fn send(&mut self, _manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        Err(ProviderError::UnknownConnection {
            connection: "local".to_string(),
        })
    }
}

/// Runs one decision step for `task` through the production driver,
/// building the runnable node directly: repeated rounds do not need a
/// fresh ingress answer, whose publisher requires a `running` task.
fn drive_step(
    world: &mut World,
    session: &SessionId,
    task: &TaskId,
    grant: &str,
    answer: &str,
) -> Result<SchedulerStep, ControllerError> {
    world
        .runtime
        .scheduler
        .submit_answered(
            task.clone(),
            AnswerSelection::Custom {
                text: answer.to_string(),
            },
            grant.to_string(),
        )
        .expect("scheduler accepts the node")
        .expect("task outside cancelled subtrees");
    world.runtime.scheduler_step(session)
}

fn journal(world: &World, task: &TaskId) -> Vec<Reaction> {
    world
        .runtime
        .store()
        .supervisor_reactions(task, 8, 0)
        .expect("journal read")
        .0
}

/// The map itself: every `StepOutcome` variant and every
/// `ControllerError` class carries its own typed fingerprint, and no
/// two classes share one — errors never collapse into the
/// effect-denied family. `Completed` cannot repeat inside one task
/// (the task turns terminal) and scheduler/serialization failures are
/// unreachable through the production driver; this map keeps those
/// classes pinned while the feed tests below drive the reachable ones.
#[test]
fn every_outcome_and_error_class_maps_to_a_distinct_typed_observation() {
    let (mut world, _file, _grant) = scoped_world("observation-map");
    let session = world.open_session("bootstrap-observation-map");
    let task = world.create_task(&session, "cmd-observation-map");
    let snapshot = world.runtime.store().snapshot(&task).expect("snapshot");
    let answer = AnswerSelection::Custom {
        text: "read /scope/f".to_string(),
    };
    let outcomes = [
        step_outcome_observation(
            &task,
            &answer,
            &StepOutcome::Completed {
                snapshot: snapshot.clone(),
            },
        ),
        step_outcome_observation(
            &task,
            &answer,
            &StepOutcome::EffectDenied {
                reason: "mode deny".to_string(),
                snapshot: snapshot.clone(),
            },
        ),
        step_outcome_observation(
            &task,
            &answer,
            &StepOutcome::OutcomeUnknown {
                attempt_id: "attempt-1".to_string(),
                snapshot: snapshot.clone(),
            },
        ),
        step_outcome_observation(
            &task,
            &answer,
            &StepOutcome::Waiting {
                snapshot: snapshot.clone(),
            },
        ),
        step_outcome_observation(&task, &answer, &StepOutcome::NoAction { snapshot }),
    ];
    let errors = [
        ControllerError::Store(StoreError::missing_task(&task.0)),
        ControllerError::Policy(PolicyError::Revoked {
            grant_id: "grant-1".to_string(),
        }),
        ControllerError::Model(ModelError::Provider(ProviderError::UnknownConnection {
            connection: "local".to_string(),
        })),
        ControllerError::Executor(ExecutorError::Cancelled),
        ControllerError::Scheduler(SchedulerError::UnknownNode { node: 7 }),
        ControllerError::Serialization(
            serde_json::from_str::<()>("not json").expect_err("serde fails"),
        ),
        ControllerError::ApplicabilityUnknown,
    ];
    let error_observations: Vec<_> = errors
        .iter()
        .map(|error| step_error_observation(&task, &answer, error))
        .collect();

    let mut fingerprints = std::collections::HashSet::new();
    for observation in &outcomes {
        assert_eq!(
            observation.signature.tool, "read_file",
            "outcome keeps the permitted-action tool"
        );
        assert_eq!(observation.signature.args, "read /scope/f");
        assert!(
            fingerprints.insert((
                observation.signature.tool.clone(),
                observation.signature.args.clone(),
                observation.signature.result.clone()
            )),
            "shared fingerprint: {}",
            observation.signature
        );
    }
    for observation in &error_observations {
        assert_eq!(
            observation.signature.tool, "decision_step",
            "errors never share the effect-denied tool"
        );
        assert_eq!(observation.signature.args, "read /scope/f");
        assert!(
            fingerprints.insert((
                observation.signature.tool.clone(),
                observation.signature.args.clone(),
                observation.signature.result.clone()
            )),
            "shared fingerprint: {}",
            observation.signature
        );
    }

    assert_eq!(outcomes[0].signature.result, "completed");
    assert_eq!(outcomes[1].signature.result, "mode deny");
    assert_eq!(outcomes[2].signature.result, "outcome unknown: attempt-1");
    assert_eq!(outcomes[3].signature.result, "waiting");
    assert_eq!(outcomes[4].signature.result, "no action");
    for (observation, prefix) in error_observations.iter().zip([
        "store error: ",
        "policy error: ",
        "model error: ",
        "executor error: ",
        "scheduler error: ",
        "serialization error: ",
        "applicability error: ",
    ]) {
        assert!(
            observation.signature.result.starts_with(prefix),
            "class keeps its typed prefix: {}",
            observation.signature
        );
    }
}

/// DEC-068: an applicability evaluation that returns unknown/error
/// marks the materialized obligation `unresolved` without touching its
/// execution — the stale-evidence writer (`invalidate_evidence`, proved
/// by `evidence_invalidation_blocks_completion` in first_task) is a
/// different leg — and the unchanged `COMPLETION_COUNTS` gate rejects
/// completion with the unresolved count. The step itself fails through
/// the production driver, so the supervisor's Err feed observes it.
#[test]
fn applicability_evaluation_error_marks_obligation_unresolved_not_stale_and_blocks_completion() {
    let (mut world, _file, grant) = scoped_world("feed-applicability");
    let session = world.open_session("bootstrap-feed-applicability");
    let task = world.create_task(&session, "cmd-feed-applicability");
    world
        .runtime
        .scheduler
        .submit_answered(
            task.clone(),
            AnswerSelection::Option {
                option_id: OptionId(rivect::controller::APPLICABILITY_UNKNOWN_OPTION.to_string()),
            },
            grant.clone(),
        )
        .expect("scheduler accepts the node")
        .expect("task outside cancelled subtrees");
    let error = world
        .runtime
        .scheduler_step(&session)
        .expect_err("an applicability-evaluation unknown fails the step");
    assert!(
        matches!(error, ControllerError::ApplicabilityUnknown),
        "{error:?}"
    );

    let snapshot = world.runtime.store().snapshot(&task).expect("snapshot");
    assert_eq!(snapshot.lifecycle, Lifecycle::Blocked);
    let obligations = &snapshot.obligations.items;
    assert_eq!(obligations.len(), 1);
    assert_eq!(
        obligations[0].applicability,
        ObligationApplicability::Unresolved
    );
    assert_eq!(obligations[0].execution, ObligationExecution::Pending);

    // EDGE-001 through the unchanged completion gate: unresolved
    // applicability alone — no stale execution — rejects completion.
    let err = world
        .runtime
        .store_writer()
        .complete_if_eligible(&session, &task)
        .expect_err("unresolved applicability rejects completion");
    assert!(
        matches!(
            &err,
            StoreError::Conflict(ConflictCause::CompletionOpen { unresolved, .. })
                if *unresolved > 0
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
            .any(|b| b.reason == ErrorCode::DependencyBlocked),
        "blocked must carry the dependency-blocked reason"
    );
}

/// A revoked grant fails every decision step at mutable admission; the
/// repeated errors fire the exact-repeat detector and journal the
/// policy fingerprint — never the effect-denied one.
#[test]
fn revoked_grant_errors_feed_a_typed_policy_observation() {
    let (mut world, file, grant) = scoped_world("feed-policy");
    let session = world.open_session("bootstrap-feed-policy");
    let task = world.create_task(&session, "cmd-feed-policy");
    world.runtime.policy_writer().revoke(&grant);

    for _ in 0..3 {
        let error = drive_step(&mut world, &session, &task, &grant, &node_answer(&file))
            .expect_err("revoked grant fails the step");
        assert!(
            matches!(error, ControllerError::Policy(PolicyError::Revoked { .. })),
            "{error:?}"
        );
    }

    let reactions = journal(&world, &task);
    assert_eq!(reactions.len(), 1, "exact cap 3 fires once: {reactions:?}");
    assert_eq!(reactions[0].thresholds.exact_repeat, 3);
    assert_eq!(
        reactions[0].cause,
        StallCause::ExactRepeat {
            signature: FailureSignature {
                tool: "decision_step".to_string(),
                args: node_answer(&file),
                result: format!("policy error: grant {grant} revoked"),
            },
            repeats: 3,
        }
    );
}

/// A read_file call naming a target outside the granted scope fails
/// executor admission with the typed outside-scope denial; the repeated
/// errors journal the executor fingerprint through the same Err feed.
#[test]
fn outside_scope_admission_errors_feed_a_typed_executor_observation() {
    let (mut world, file, grant) = scoped_world_with(
        "feed-executor",
        Box::new(OutsideScopeProvider {
            target: "/etc/hosts".to_string(),
        }),
        Box::new(support::PlatformWorker::default()),
    );
    let session = world.open_session("bootstrap-feed-executor");
    let task = world.create_task(&session, "cmd-feed-executor");

    for _ in 0..3 {
        let error = drive_step(&mut world, &session, &task, &grant, &node_answer(&file))
            .expect_err("outside-scope read fails admission");
        assert!(
            matches!(
                error,
                ControllerError::Executor(ExecutorError::Worker(WorkerError::OutsideScope { .. }))
            ),
            "{error:?}"
        );
    }

    let reactions = journal(&world, &task);
    assert_eq!(reactions.len(), 1, "exact cap 3 fires once: {reactions:?}");
    assert!(
        matches!(
            &reactions[0].cause,
            StallCause::ExactRepeat { signature, repeats: 3 }
                if signature.tool == "decision_step"
                    && signature.result.starts_with("executor error: ")
        ),
        "{}",
        reactions[0].cause
    );
}

/// A failing provider errors the decision step at the broker boundary;
/// the repeated errors journal the model fingerprint.
#[test]
fn provider_errors_feed_a_typed_model_observation() {
    let (mut world, file, grant) = scoped_world_with(
        "feed-model",
        Box::new(FailingProvider),
        Box::new(support::PlatformWorker::default()),
    );
    let session = world.open_session("bootstrap-feed-model");
    let task = world.create_task(&session, "cmd-feed-model");

    for _ in 0..3 {
        let error = drive_step(&mut world, &session, &task, &grant, &node_answer(&file))
            .expect_err("provider failure fails the step");
        assert!(matches!(error, ControllerError::Model(_)), "{error:?}");
    }

    let reactions = journal(&world, &task);
    assert_eq!(reactions.len(), 1, "exact cap 3 fires once: {reactions:?}");
    assert!(
        matches!(
            &reactions[0].cause,
            StallCause::ExactRepeat { signature, repeats: 3 }
                if signature.tool == "decision_step"
                    && signature.result.starts_with("model error: ")
        ),
        "{}",
        reactions[0].cause
    );
}

/// A runnable node whose task never reached the store fails the step
/// at the first snapshot; the repeated store errors journal the store
/// fingerprint.
#[test]
fn store_errors_feed_a_typed_store_observation() {
    let (mut world, _file, grant) = scoped_world("feed-store");
    let session = world.open_session("bootstrap-feed-store");
    let missing = stub_task("feed-store");

    for _ in 0..3 {
        let error = drive_step(&mut world, &session, &missing, &grant, "read /scope/f")
            .expect_err("missing task fails the step");
        assert!(matches!(error, ControllerError::Store(_)), "{error:?}");
    }

    let reactions = journal(&world, &missing);
    assert_eq!(reactions.len(), 1, "exact cap 3 fires once: {reactions:?}");
    assert!(
        matches!(
            &reactions[0].cause,
            StallCause::ExactRepeat { signature, repeats: 3 }
                if signature.tool == "decision_step"
                    && signature.result.starts_with("store error: ")
        ),
        "{}",
        reactions[0].cause
    );
}

/// A provider that never proposes a read settles every step as
/// `waiting`; the repeated outcomes journal the waiting fingerprint —
/// the sterile no-action loop AC-011 bounds.
#[test]
fn waiting_outcomes_feed_a_typed_observation() {
    let (mut world, file, grant) = scoped_world_with(
        "feed-waiting",
        Box::new(NoReadProvider),
        Box::new(support::PlatformWorker::default()),
    );
    let session = world.open_session("bootstrap-feed-waiting");
    let task = world.create_task(&session, "cmd-feed-waiting");

    for _ in 0..3 {
        match drive_step(&mut world, &session, &task, &grant, &node_answer(&file))
            .expect("step runs")
        {
            SchedulerStep::Ran { outcome, .. } => assert!(
                matches!(*outcome, StepOutcome::Waiting { .. }),
                "expected a waiting step, got {outcome:?}"
            ),
            other => panic!("expected a waiting step, got {other:?}"),
        }
    }

    let reactions = journal(&world, &task);
    assert_eq!(reactions.len(), 1, "exact cap 3 fires once: {reactions:?}");
    assert_eq!(
        reactions[0].cause,
        StallCause::ExactRepeat {
            signature: FailureSignature {
                tool: "read_file".to_string(),
                args: node_answer(&file),
                result: "waiting".to_string(),
            },
            repeats: 3,
        }
    );
}

/// A dispatch whose receipt was lost keeps one unknown attempt; every
/// later decision step returns the same unresolved outcome, and the
/// repeated outcomes journal the unknown fingerprint.
#[test]
fn unresolved_attempt_outcomes_feed_a_typed_observation() {
    let (mut world, file, grant) = scoped_world("feed-unknown");
    let session = world.open_session("bootstrap-feed-unknown");
    let task = world.create_task(&session, "cmd-feed-unknown");
    let answer = AnswerSelection::Custom {
        text: node_answer(&file),
    };
    let StepOutcome::OutcomeUnknown { attempt_id, .. } = world
        .runtime
        .run_decision_step(&session, &task, &answer, &grant, true)
        .expect("crash step runs")
    else {
        panic!("crash emulation returns an unknown outcome");
    };

    for _ in 0..3 {
        match drive_step(&mut world, &session, &task, &grant, &node_answer(&file))
            .expect("step runs")
        {
            SchedulerStep::Ran { outcome, .. } => assert!(
                matches!(&*outcome, StepOutcome::OutcomeUnknown { attempt_id: unresolved, .. } if unresolved == &attempt_id),
                "expected the same unresolved outcome, got {outcome:?}"
            ),
            other => panic!("expected an unresolved step, got {other:?}"),
        }
    }

    let reactions = journal(&world, &task);
    assert_eq!(reactions.len(), 1, "exact cap 3 fires once: {reactions:?}");
    assert_eq!(
        reactions[0].cause,
        StallCause::ExactRepeat {
            signature: FailureSignature {
                tool: "read_file".to_string(),
                args: node_answer(&file),
                result: format!("outcome unknown: {attempt_id}"),
            },
            repeats: 3,
        }
    );
}

/// One healthy round completes the task; the terminal guard answers
/// every later node with `no_action`, and the repeated outcomes journal
/// the no-action fingerprint.
#[test]
fn terminal_no_action_outcomes_feed_a_typed_observation() {
    let (mut world, file, grant) = scoped_world("feed-no-action");
    let session = world.open_session("bootstrap-feed-no-action");
    let task = world.create_task(&session, "cmd-feed-no-action");
    answer_task(
        &mut world,
        &session,
        "cmd-feed-no-action-first",
        &task,
        &node_answer(&file),
        11,
    );
    match world
        .runtime
        .scheduler_step(&session)
        .expect("first step runs")
    {
        SchedulerStep::Ran { outcome, .. } => assert!(
            matches!(*outcome, StepOutcome::Completed { .. }),
            "expected a completed step, got {outcome:?}"
        ),
        other => panic!("expected a completed step, got {other:?}"),
    }

    for _ in 0..3 {
        match drive_step(&mut world, &session, &task, &grant, &node_answer(&file))
            .expect("step runs")
        {
            SchedulerStep::Ran { outcome, .. } => assert!(
                matches!(*outcome, StepOutcome::NoAction { .. }),
                "expected a no-action step, got {outcome:?}"
            ),
            other => panic!("expected a no-action step, got {other:?}"),
        }
    }

    let reactions = journal(&world, &task);
    assert_eq!(reactions.len(), 1, "exact cap 3 fires once: {reactions:?}");
    assert_eq!(
        reactions[0].cause,
        StallCause::ExactRepeat {
            signature: FailureSignature {
                tool: "read_file".to_string(),
                args: node_answer(&file),
                result: "no action".to_string(),
            },
            repeats: 3,
        }
    );
}

/// Schema residual (DEC-016): a database created at intermediate
/// commit 0131781 keeps an id-less `supervisor_reactions`; opening it
/// under the current schema rebuilds the journal with the `id` append
/// identity — preserving journal order — and stays idempotent on
/// reopen, so `ORDER BY id` paging works under either shape.
#[test]
fn idless_supervisor_reactions_journal_migrates_in_place() {
    let root =
        tempfile::TempDir::with_prefix("rivect-supervisor-migration-").expect("fixture root");
    let path = root.path().join("state.db");
    let task = stub_task("migration");
    let reaction = |suffix: usize| Reaction {
        task: task.clone(),
        class: OperationClass::Read,
        cause: StallCause::NoProgress {
            observations: suffix,
        },
        thresholds: SupervisorPolicy::default().read,
    };
    {
        let conn = rusqlite::Connection::open(&path).expect("raw connection");
        conn.execute_batch(
            "CREATE TABLE supervisor_reactions (
                task_id TEXT NOT NULL,
                reaction_json TEXT NOT NULL
            ) STRICT;
            CREATE INDEX IF NOT EXISTS idx_supervisor_reactions_task
                ON supervisor_reactions (task_id);",
        )
        .expect("intermediate schema created");
        for suffix in 1..=2 {
            conn.execute(
                "INSERT INTO supervisor_reactions (task_id, reaction_json) VALUES (?1, ?2)",
                rusqlite::params![
                    task.0,
                    serde_json::to_string(&reaction(suffix)).expect("json")
                ],
            )
            .expect("intermediate row inserted");
        }
    }

    let mut store = TaskStore::open(&path).expect("store opens and migrates");
    let (page, has_more) = store
        .supervisor_reactions(&task, 1, 0)
        .expect("first page after migration");
    assert!(has_more);
    assert_eq!(page[0].cause, reaction(1).cause);
    let (page, has_more) = store
        .supervisor_reactions(&task, 1, 1)
        .expect("second page after migration");
    assert!(!has_more);
    assert_eq!(page[0].cause, reaction(2).cause);

    // New rows append after the migrated ones: id ordering continues.
    store
        .record_supervisor_reaction(&reaction(3))
        .expect("reaction recorded");
    let (page, _) = store.supervisor_reactions(&task, 2, 1).expect("tail page");
    assert_eq!(page.len(), 2);
    assert_eq!(page[0].cause, reaction(2).cause);
    assert_eq!(page[1].cause, reaction(3).cause);

    // Reopen: the migration is idempotent and the journal survives.
    drop(store);
    let store = TaskStore::open(&path).expect("reopen is a no-op migration");
    let (page, _) = store.supervisor_reactions(&task, 3, 0).expect("full page");
    assert_eq!(page.len(), 3);
}

// ----- atomic tree budget (INV-022, EDGE-008, AC-059 contribution) -----

/// Two children of one waiting parent compete for the last reserveable
/// budget at their shared level: the FIFO head admits and holds the only
/// reservation, the sibling waits in the ready queue, and a direct
/// over-reserve is a typed denial — never a double-spend.
#[test]
fn last_budget_reserve_admits_one_child_and_the_other_waits() {
    let root = tempfile::TempDir::with_prefix("rivect-budget-last-reserve-").expect("fixture root");
    let mut store = TaskStore::open(&root.path().join("state.db")).expect("store opens");
    let mut scheduler = Scheduler::new(4, 16);

    let parent = stub_task("budget-parent");
    let parent_node = scheduler
        .submit(
            None,
            parent.clone(),
            answer_custom("plan two children"),
            "grant".to_string(),
            1,
        )
        .expect("parent submitted");
    let first = scheduler
        .submit(
            Some(parent_node),
            stub_task("budget-child-a"),
            answer_custom("read nothing"),
            "grant".to_string(),
            3,
        )
        .expect("first child submitted");
    scheduler
        .submit(
            Some(parent_node),
            stub_task("budget-child-b"),
            answer_custom("read nothing"),
            "grant".to_string(),
            3,
        )
        .expect("second child submitted");
    // A dispatch draws from its own scope and every ancestor's: the
    // children's own levels are generous, the shared parent level fits
    // the parent plus exactly one child bound.
    store
        .open_budget(parent.0.as_str(), 4)
        .expect("budget scope opens");
    for task in [stub_task("budget-child-a"), stub_task("budget-child-b")] {
        store
            .open_budget(task.0.as_str(), 3)
            .expect("budget scope opens");
    }
    assert_eq!(
        scheduler.budget_scopes(first).expect("chain resolves"),
        vec![parent.clone(), stub_task("budget-child-a")],
        "the applicable levels are the node's own task and every ancestor, root first"
    );

    let mut reservations = 0usize;
    let mut admitted = Vec::new();
    for _ in 0..3 {
        reservations += 1;
        let reservation = format!("res-{reservations}");
        let node = scheduler.admit_next_bounded(|scopes, units| {
            let levels: Vec<&str> = scopes.iter().map(|task| task.0.as_str()).collect();
            match store.budget_reserve(&reservation, &levels, u64::from(units)) {
                Ok(()) => true,
                // The waiting sibling's denial is the typed budget
                // conflict at the shared level; any other error is a
                // bug, not a wait.
                Err(StoreError::Conflict(ConflictCause::BudgetExhausted { ref scope, .. })) => {
                    assert_eq!(
                        scope,
                        parent.0.as_str(),
                        "the shared level denies, not the child's own"
                    );
                    false
                }
                Err(other) => panic!("unexpected reserve outcome: {other}"),
            }
        });
        match node {
            Some(node) => admitted.push(node),
            None => break,
        }
        if node == Some(parent_node) {
            // The admitted parent immediately blocks on its children:
            // slot and units release before the wait (PROHIL-002), so
            // the caps never mask the budget race.
            assert!(matches!(
                scheduler.begin_wait(parent_node),
                Ok(WaitTransition::Released)
            ));
        }
    }

    assert_eq!(
        admitted,
        vec![parent_node, first],
        "the parent and the FIFO-head child admit; the sibling does not"
    );
    assert_eq!(
        scheduler.state(first).expect("first ran"),
        NodeState::Running
    );
    assert_eq!(
        scheduler
            .state(
                scheduler
                    .node_of_task(&stub_task("budget-child-b"))
                    .expect("second node")
            )
            .expect("second waits"),
        NodeState::Ready
    );
    // The shared level holds the parent's and exactly one child's live
    // reservations: no double-spend.
    assert_eq!(
        store.budget_status(parent.0.as_str()).expect("status"),
        BudgetStatus {
            limit_units: 4,
            spent: 0,
            reserved: 4
        }
    );

    // Each child's own level shows the race's outcome: the admitted
    // child's reserve landed, the refused sibling's ledger stayed
    // untouched — its wait cost nothing at its own scope.
    assert_eq!(
        store
            .budget_status(stub_task("budget-child-a").0.as_str())
            .expect("admitted child status"),
        BudgetStatus {
            limit_units: 3,
            spent: 0,
            reserved: 3
        }
    );
    assert_eq!(
        store
            .budget_status(stub_task("budget-child-b").0.as_str())
            .expect("refused child status"),
        zero_reserved(3)
    );

    // A direct claim on the exhausted level is a typed denial.
    let denial = store
        .budget_reserve("res-direct", &[parent.0.as_str()], 1)
        .expect_err("no room at the shared level");
    assert!(
        matches!(
            denial,
            StoreError::Conflict(ConflictCause::BudgetExhausted { ref scope, .. })
                if scope == parent.0.as_str()
        ),
        "wrong denial: {denial}"
    );
}

/// A reservation spans every applicable level atomically: a bound that
/// fits the first level but not a later one rolls the earlier level's
/// provisional hold back — the denial applies nowhere — and the
/// invariant `spent + reserved + bound(next) <= limit` holds at each
/// level after every transition.
#[test]
fn budget_reserve_checks_every_applicable_level_atomically() {
    let root = tempfile::TempDir::with_prefix("rivect-budget-levels-").expect("fixture root");
    let mut store = TaskStore::open(&root.path().join("state.db")).expect("store opens");
    store.open_budget("root", 8).expect("root opens");
    store.open_budget("branch", 4).expect("branch opens");

    // Bound 5 fits the first (root) level but not the later branch
    // level: the hold the root level already took inside the spanning
    // transaction must roll back. A fail-fast implementation that only
    // pre-checked every level would pass too — one that applies each
    // level's increment as it goes cannot: the root would keep
    // reserved units for a reservation that never existed.
    let denied = store
        .budget_reserve("res-wide", &["root", "branch"], 5)
        .expect_err("the later branch level cannot fit");
    assert!(
        matches!(
            denied,
            StoreError::Conflict(ConflictCause::BudgetExhausted { ref scope, .. })
                if scope == "branch"
        ),
        "wrong denial: {denied}"
    );
    assert_eq!(store.budget_status("root").expect("root"), zero_reserved(8));
    assert_eq!(
        store.budget_status("branch").expect("branch"),
        zero_reserved(4)
    );
    assert!(
        matches!(
            store.budget_reservation("res-wide"),
            Err(StoreError::NotFound(Missing::Reservation(_)))
        ),
        "a denied reservation leaves no rows"
    );

    store
        .budget_reserve("res-fit", &["root", "branch"], 4)
        .expect("both levels fit");
    assert_eq!(
        store.budget_status("root").expect("root"),
        BudgetStatus {
            limit_units: 8,
            spent: 0,
            reserved: 4
        }
    );
    assert_eq!(
        store.budget_status("branch").expect("branch"),
        BudgetStatus {
            limit_units: 4,
            spent: 0,
            reserved: 4
        }
    );

    // A confirmed cost below the bound spends only the confirmed units
    // at every level, and admission reopens within the invariant.
    store
        .budget_charge("res-fit", Some(3))
        .expect("confirmed charge");
    for scope in ["root", "branch"] {
        assert_eq!(
            store.budget_status(scope).expect("status"),
            BudgetStatus {
                limit_units: if scope == "root" { 8 } else { 4 },
                spent: 3,
                reserved: 0
            }
        );
    }

    // A confirmed zero is a real confirmation: it spends zero — never
    // the bound, and never the unknown-cost retention — while the hold
    // still clears at every level.
    store
        .budget_reserve("res-zero", &["root", "branch"], 1)
        .expect("one unit fits every freed level");
    store
        .budget_charge("res-zero", Some(0))
        .expect("confirmed-zero charge");
    for scope in ["root", "branch"] {
        assert_eq!(
            store.budget_status(scope).expect("status"),
            BudgetStatus {
                limit_units: if scope == "root" { 8 } else { 4 },
                spent: 3,
                reserved: 0
            },
            "a confirmed zero adds no spent units at either level"
        );
    }
    store
        .budget_reserve("res-next", &["root", "branch"], 1)
        .expect("the freed levels admit again");
}

fn zero_reserved(limit_units: u64) -> BudgetStatus {
    BudgetStatus {
        limit_units,
        spent: 0,
        reserved: 0,
    }
}

/// The offline provider reports no usage for a sent request, so the
/// sent cost stays unknown: the reservation retains the full bound as
/// spent — never released as zero — and the retention is visible on
/// the reservation record (INV-022, EDGE-008).
#[test]
fn unknown_sent_cost_is_retained_not_released_as_zero() {
    let config = rivect::config::Config::parse_validated(&support::config_distinct_pools())
        .expect("config validates");
    let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
    let manifest = broker
        .prepare(
            "backend_task",
            &config,
            "/world/budget",
            "goal: budget fixture",
        )
        .expect("manifest");
    assert!(manifest.cost_bound > 0, "the bound is a finite number");
    let reply = broker
        .dispatch(&mut rivect::model::NullLedger, "/world/budget", &manifest)
        .expect("offline dispatch");
    assert!(!reply.text.is_empty(), "the request really was sent");

    // The explain's `confirmed` is a stub offline — the loopback
    // provider reports no usage to read — so only the ledger behavior
    // below can prove retention; asserting `confirmed == None` here
    // would just pin the stub. The bound the charge path must retain
    // is the frozen manifest bound the explain carries.
    let sent_cost = broker.sent_cost_explain(&manifest);
    assert_eq!(sent_cost.bound, manifest.cost_bound);

    let root = tempfile::TempDir::with_prefix("rivect-budget-unknown-cost-").expect("fixture root");
    let mut store = TaskStore::open(&root.path().join("state.db")).expect("store opens");
    store
        .open_budget("task-budget", manifest.cost_bound)
        .expect("budget opens at the bound");
    store
        .budget_reserve(&manifest.attempt_id, &["task-budget"], manifest.cost_bound)
        .expect("reserve the sent request");
    store
        .budget_charge(&manifest.attempt_id, sent_cost.confirmed)
        .expect("unknown charge retains the bound");

    let status = store.budget_status("task-budget").expect("status");
    assert_eq!(status.reserved, 0, "the reservation resolved");
    assert_eq!(
        status.spent, manifest.cost_bound,
        "an unknown sent cost retains the full bound, never zero"
    );
    assert!(
        status.spent != 0,
        "retention at the bound is the opposite of a zero release"
    );
    assert_eq!(
        store
            .budget_reservation(&manifest.attempt_id)
            .expect("record"),
        rivect::state::BudgetReservation {
            state: rivect::state::BudgetReservationState::Charged,
            bound: manifest.cost_bound,
            charged: None,
        }
    );
}

/// A reservation is the proof reserve: it stays `reserved` — visibly
/// neither spent nor released — until one explicit resolution, and it
/// resolves exactly once. A replayed reservation id is a typed
/// conflict, so the same units can never be spent twice.
#[test]
fn budget_reservation_resolves_exactly_once() {
    let root = tempfile::TempDir::with_prefix("rivect-budget-once-").expect("fixture root");
    let mut store = TaskStore::open(&root.path().join("state.db")).expect("store opens");
    store.open_budget("once", 10).expect("budget opens");
    store
        .budget_reserve("res-1", &["once"], 4)
        .expect("reserve");

    // A scope opens once: a replayed open never re-limits a live ledger.
    let reopened = store
        .open_budget("once", 99)
        .expect_err("scope ids are single-use");
    assert!(matches!(
        reopened,
        StoreError::Conflict(ConflictCause::BudgetScopeExists { .. })
    ));

    // The proof reserve is held, not silently spent.
    assert_eq!(
        store.budget_status("once").expect("held"),
        BudgetStatus {
            limit_units: 10,
            spent: 0,
            reserved: 4
        }
    );
    assert_eq!(
        store.budget_reservation("res-1").expect("record"),
        rivect::state::BudgetReservation {
            state: rivect::state::BudgetReservationState::Reserved,
            bound: 4,
            charged: None,
        }
    );

    store.budget_charge("res-1", None).expect("single charge");
    let replay = store
        .budget_charge("res-1", None)
        .expect_err("a charged reservation never resolves again");
    assert!(matches!(
        replay,
        StoreError::Conflict(ConflictCause::ReservationNotReserved { .. })
    ));
    let late_release = store
        .budget_release("res-1")
        .expect_err("release after charge is a double resolution");
    assert!(matches!(
        late_release,
        StoreError::Conflict(ConflictCause::ReservationNotReserved { .. })
    ));
    assert_eq!(
        store.budget_status("once").expect("unchanged by replays"),
        BudgetStatus {
            limit_units: 10,
            spent: 4,
            reserved: 0
        }
    );

    // A reservation that never sent releases its units untouched.
    store
        .budget_reserve("res-2", &["once"], 4)
        .expect("second reserve");
    store.budget_release("res-2").expect("release");
    assert_eq!(
        store.budget_status("once").expect("released"),
        spent_only(10, 4)
    );
    let charged_after_release = store
        .budget_charge("res-2", None)
        .expect_err("a released reservation never charges");
    assert!(matches!(
        charged_after_release,
        StoreError::Conflict(ConflictCause::ReservationNotReserved { .. })
    ));

    // The reservation id is the replay key: the same id never reserves twice.
    let replayed_id = store
        .budget_reserve("res-1", &["once"], 1)
        .expect_err("reservation ids are single-use");
    assert!(matches!(
        replayed_id,
        StoreError::Conflict(ConflictCause::ReservationAlreadyRecorded { .. })
    ));
}

fn spent_only(limit_units: u64, spent: u64) -> BudgetStatus {
    BudgetStatus {
        limit_units,
        spent,
        reserved: 0,
    }
}

/// Creates one root task through the real ingress: single-flight cases
/// need durable tasks so every admitted attempt lands in the ledger.
fn flight_task(world: &mut World, session: &SessionId, command_id: &str) -> TaskId {
    let response = world.dispatch(&support::corpus_create(session, command_id));
    assert!(
        response
            .get("result")
            .and_then(|r| r.get("task_id"))
            .is_some(),
        "task create failed: {response}"
    );
    TaskId(
        response["result"]["task_id"]
            .as_str()
            .expect("task id")
            .to_string(),
    )
}

/// Admits one read through the single-flight executor seam and reports
/// the flight role the registry recorded for the fresh attempt.
fn admit_flight_read(
    world: &mut World,
    flights: &mut ReadFlights,
    task: &TaskId,
    grant: &str,
    file: &Path,
    mode: PermissionMode,
) -> (rivect::executor::AdmittedEffect, Option<FlightRole>) {
    let mut executor = world.runtime.executor_with_flights(flights);
    let admitted = executor
        .admit(
            task,
            EffectRequest::Read {
                grant_id: grant.to_string(),
                path: file.to_path_buf(),
            },
            mode,
        )
        .expect("permitted read admits");
    let role = flights.role(&admitted.attempt_id);
    (admitted, role)
}

/// Executes one admitted read through the single-flight executor seam.
fn execute_flight_read(
    world: &mut World,
    flights: &mut ReadFlights,
    admitted: &rivect::executor::AdmittedEffect,
) -> Result<EffectOutcome, ExecutorError> {
    let mut executor = world.runtime.executor_with_flights(flights);
    executor.execute(admitted)
}

/// Two identical permitted reads under one grant merge into one flight:
/// the first admit leads, the second joins, one physical read charges
/// the worker, and both attempts settle confirmed with the same digest
/// (INV-023, AC-060 contribution).
#[test]
fn identical_permitted_reads_merge_into_one_physical_charge() {
    let (mut world, file, grant) = scoped_world("singleflight-merge");
    let session = world.open_session("bootstrap-singleflight-merge");
    let task_a = flight_task(&mut world, &session, "cmd-flight-a");
    let task_b = flight_task(&mut world, &session, "cmd-flight-b");
    let mut flights = ReadFlights::new();

    let (admitted_a, role_a) = admit_flight_read(
        &mut world,
        &mut flights,
        &task_a,
        &grant,
        &file,
        PermissionMode::Manual,
    );
    let (admitted_b, role_b) = admit_flight_read(
        &mut world,
        &mut flights,
        &task_b,
        &grant,
        &file,
        PermissionMode::Manual,
    );
    assert_eq!(
        role_a,
        Some(FlightRole::Leader),
        "first admit opens the flight"
    );
    assert_eq!(
        role_b,
        Some(FlightRole::Follower),
        "identical admit joins it"
    );

    let outcome_a =
        execute_flight_read(&mut world, &mut flights, &admitted_a).expect("leader read executes");
    let outcome_b = execute_flight_read(&mut world, &mut flights, &admitted_b)
        .expect("follower receives the shared result");
    let EffectOutcome::Read {
        bytes: bytes_a,
        digest: digest_a,
    } = outcome_a
    else {
        panic!("leader outcome is a read");
    };
    let EffectOutcome::Read {
        digest: digest_b, ..
    } = outcome_b
    else {
        panic!("follower outcome is a read");
    };
    assert_eq!(bytes_a, b"rivect-concurrency-marker\n");
    assert_eq!(digest_a, digest_b, "both subscribers observe one read");
    assert_eq!(world.worker_reads(), 1, "one physical charge");

    for admitted in [&admitted_a, &admitted_b] {
        let (owner, state, detail) = world
            .runtime
            .store()
            .attempt_record(&admitted.attempt_id)
            .expect("attempt record")
            .expect("attempt exists");
        assert_eq!(owner, admitted.task_id.0);
        assert_eq!(state, "confirmed");
        let detail = detail.expect("confirmed detail");
        assert!(
            detail.contains(&format!("sha256={digest_a}")),
            "shared digest journalled: {detail}"
        );
    }
}

/// Reads differing in access scope, file snapshot, or permission mode
/// never merge: each lands its own flight and its own physical read
/// (INV-023: differing rights/snapshots never merge).
#[test]
fn differing_scope_snapshot_or_mode_never_merges_reads() {
    let (mut world, file, grant) = scoped_world("singleflight-no-merge");
    let session = world.open_session("bootstrap-singleflight-no-merge");
    let task_a = flight_task(&mut world, &session, "cmd-no-merge-a");
    let task_b = flight_task(&mut world, &session, "cmd-no-merge-b");
    let mut flights = ReadFlights::new();

    // Differing access scope: a wider grant over the same file is a
    // different right, so it leads its own flight.
    let wide_grant = world.runtime.policy_writer().grant_read(world.root.clone());
    let (admitted_a, role_a) = admit_flight_read(
        &mut world,
        &mut flights,
        &task_a,
        &grant,
        &file,
        PermissionMode::Manual,
    );
    let (admitted_b, role_b) = admit_flight_read(
        &mut world,
        &mut flights,
        &task_b,
        &wide_grant,
        &file,
        PermissionMode::Manual,
    );
    assert_eq!(role_a, Some(FlightRole::Leader));
    assert_eq!(
        role_b,
        Some(FlightRole::Leader),
        "a different scope never joins the flight"
    );
    execute_flight_read(&mut world, &mut flights, &admitted_a).expect("scoped read executes");
    execute_flight_read(&mut world, &mut flights, &admitted_b).expect("wide read executes");
    assert_eq!(world.worker_reads(), 2, "differing rights charge twice");

    // Differing snapshot: a replaced file is a new dev/ino binding.
    let task_c = flight_task(&mut world, &session, "cmd-no-merge-c");
    let task_d = flight_task(&mut world, &session, "cmd-no-merge-d");
    let mut snapshot_flights = ReadFlights::new();
    let (admitted_c, role_c) = admit_flight_read(
        &mut world,
        &mut snapshot_flights,
        &task_c,
        &grant,
        &file,
        PermissionMode::Manual,
    );
    let replacement = world.root.join("scope").join("replacement.txt");
    std::fs::write(&replacement, "replacement snapshot\n").expect("replacement write");
    std::fs::rename(&replacement, &file).expect("snapshot swap");
    let (admitted_d, role_d) = admit_flight_read(
        &mut world,
        &mut snapshot_flights,
        &task_d,
        &grant,
        &file,
        PermissionMode::Manual,
    );
    assert_eq!(role_c, Some(FlightRole::Leader));
    assert_eq!(
        role_d,
        Some(FlightRole::Leader),
        "a replaced snapshot never joins the flight"
    );
    let reads_before = world.worker_reads();
    execute_flight_read(&mut world, &mut snapshot_flights, &admitted_c)
        .expect("old snapshot read executes");
    execute_flight_read(&mut world, &mut snapshot_flights, &admitted_d)
        .expect("new snapshot read executes");
    assert_eq!(world.worker_reads(), reads_before + 2);

    // Differing permission mode: both verdicts are permits, but the
    // rights they were granted under differ, so the reads stay apart.
    let task_e = flight_task(&mut world, &session, "cmd-no-merge-e");
    let task_f = flight_task(&mut world, &session, "cmd-no-merge-f");
    let mut mode_flights = ReadFlights::new();
    std::fs::write(&file, "mode discriminator\n").expect("stable snapshot for mode pair");
    let (admitted_e, role_e) = admit_flight_read(
        &mut world,
        &mut mode_flights,
        &task_e,
        &grant,
        &file,
        PermissionMode::Manual,
    );
    let (admitted_f, role_f) = admit_flight_read(
        &mut world,
        &mut mode_flights,
        &task_f,
        &grant,
        &file,
        PermissionMode::ReadOnly,
    );
    assert_eq!(role_e, Some(FlightRole::Leader));
    assert_eq!(
        role_f,
        Some(FlightRole::Leader),
        "a different permission mode never joins the flight"
    );
    let reads_before = world.worker_reads();
    execute_flight_read(&mut world, &mut mode_flights, &admitted_e).expect("manual read executes");
    execute_flight_read(&mut world, &mut mode_flights, &admitted_f)
        .expect("read-only read executes");
    assert_eq!(world.worker_reads(), reads_before + 2);
}

/// One cancelled subscriber leaves the shared flight running for the
/// others: the remaining members still receive the one physical read,
/// and only the cancelled member's attempt settles rejected
/// (EDGE-008, INV-023).
#[test]
fn cancelled_subscriber_leaves_other_flight_members_running() {
    let (mut world, file, grant) = scoped_world("singleflight-cancel");
    let session = world.open_session("bootstrap-singleflight-cancel");
    let task_a = flight_task(&mut world, &session, "cmd-flight-keep-a");
    let task_b = flight_task(&mut world, &session, "cmd-flight-drop-b");
    let task_c = flight_task(&mut world, &session, "cmd-flight-keep-c");
    let mut flights = ReadFlights::new();

    let (admitted_a, _) = admit_flight_read(
        &mut world,
        &mut flights,
        &task_a,
        &grant,
        &file,
        PermissionMode::Manual,
    );
    let (admitted_b, _) = admit_flight_read(
        &mut world,
        &mut flights,
        &task_b,
        &grant,
        &file,
        PermissionMode::Manual,
    );
    let (admitted_c, _) = admit_flight_read(
        &mut world,
        &mut flights,
        &task_c,
        &grant,
        &file,
        PermissionMode::Manual,
    );

    cancel_task_via_ingress(&mut world, &session, &task_b);

    let outcome_a = execute_flight_read(&mut world, &mut flights, &admitted_a)
        .expect("surviving member still executes");
    let outcome_c = execute_flight_read(&mut world, &mut flights, &admitted_c)
        .expect("other surviving member receives the shared result");
    assert!(matches!(outcome_a, EffectOutcome::Read { .. }));
    assert!(matches!(outcome_c, EffectOutcome::Read { .. }));
    assert_eq!(
        world.worker_reads(),
        1,
        "cancel of one subscriber charges once"
    );

    let error_b = execute_flight_read(&mut world, &mut flights, &admitted_b)
        .expect_err("cancelled member is Cancelled, not Denied");
    assert!(
        matches!(error_b, ExecutorError::Cancelled),
        "cancelled subscriber errors closed: {error_b}"
    );
    let (_, state_b, _) = world
        .runtime
        .store()
        .attempt_record(&admitted_b.attempt_id)
        .expect("attempt record")
        .expect("attempt exists");
    assert_eq!(state_b, "rejected", "only the cancelled member rejects");
}

/// A deny enrolled after admission denies every flight member at its
/// own execute-time consult: verdicts stay independent and no physical
/// read is charged while the verdict denies (INV-023: independent
/// verdicts never merge).
#[test]
fn deny_enrolled_after_admit_denies_each_flight_member_independently() {
    let (mut world, file, grant) = scoped_world("singleflight-deny-flip");
    let session = world.open_session("bootstrap-singleflight-deny");
    let task_a = flight_task(&mut world, &session, "cmd-flight-deny-a");
    let task_b = flight_task(&mut world, &session, "cmd-flight-deny-b");
    let mut flights = ReadFlights::new();

    let (admitted_a, _) = admit_flight_read(
        &mut world,
        &mut flights,
        &task_a,
        &grant,
        &file,
        PermissionMode::Manual,
    );
    let (admitted_b, _) = admit_flight_read(
        &mut world,
        &mut flights,
        &task_b,
        &grant,
        &file,
        PermissionMode::Manual,
    );

    world
        .runtime
        .policy_writer()
        .enroll_deny(&file)
        .expect("deny enrolls on the target");

    let error_a = execute_flight_read(&mut world, &mut flights, &admitted_a)
        .expect_err("leader consult denies after the flip");
    let error_b = execute_flight_read(&mut world, &mut flights, &admitted_b)
        .expect_err("follower consult denies after the flip");
    assert!(matches!(error_a, ExecutorError::ModeDenied), "{error_a:?}");
    assert!(matches!(error_b, ExecutorError::ModeDenied), "{error_b:?}");
    assert_eq!(
        world.worker_reads(),
        0,
        "a denying verdict never charges a physical read"
    );
}

/// Non-read effects never enter or split a read flight: a write admits
/// between two identical read admits without joining the registry or
/// disturbing the merge (INV-023: effects never merge).
#[test]
fn non_read_effects_never_enter_or_split_a_read_flight() {
    let (mut world, file, grant) = scoped_world("singleflight-effect-bypass");
    let session = world.open_session("bootstrap-singleflight-effect");
    let task_a = flight_task(&mut world, &session, "cmd-flight-read-a");
    let task_b = flight_task(&mut world, &session, "cmd-flight-read-b");
    let task_w = flight_task(&mut world, &session, "cmd-flight-write");
    let write_grant = world.runtime.policy_writer().grant_classes(
        world.root.join("scope"),
        vec![rivect::contracts::EffectClass::Write],
    );
    let mut flights = ReadFlights::new();

    let (admitted_a, role_a) = admit_flight_read(
        &mut world,
        &mut flights,
        &task_a,
        &grant,
        &file,
        PermissionMode::Manual,
    );
    let admitted_w = {
        let mut executor = world.runtime.executor_with_flights(&mut flights);
        executor
            .admit(
                &task_w,
                EffectRequest::Write {
                    grant_id: write_grant,
                    path: file.clone(),
                    bytes: b"write beside the flight\n".to_vec(),
                },
                PermissionMode::Yolo,
            )
            .expect("yolo write admits")
    };
    assert!(
        flights.role(&admitted_w.attempt_id).is_none(),
        "effects never enter the read flight registry"
    );
    let (admitted_b, role_b) = admit_flight_read(
        &mut world,
        &mut flights,
        &task_b,
        &grant,
        &file,
        PermissionMode::Manual,
    );
    assert_eq!(role_a, Some(FlightRole::Leader));
    assert_eq!(
        role_b,
        Some(FlightRole::Follower),
        "the effect neither split nor joined the read flight"
    );

    execute_flight_read(&mut world, &mut flights, &admitted_a).expect("read a executes");
    execute_flight_read(&mut world, &mut flights, &admitted_b).expect("read b executes");
    assert_eq!(
        world.worker_reads(),
        1,
        "only the read flight charges reads"
    );
}

#[test]
fn answer_through_dispatch_runtime_request_drives_a_decision_step_without_a_direct_scheduler_step_call()
 {
    let (mut world, _file, _grant) = scoped_world("dispatch-drain");
    let session = world.open_session("bootstrap-dispatch-drain");
    let task = world.create_task(&session, "cmd-drain");
    let reads_before = world.worker_reads();
    let question = world.publish(&session, &task);
    let answer = world.dispatch(&corpus_answer_option(
        &session,
        "cmd-drain-answer",
        &task,
        &question,
        "brief",
        json!(1),
    ));
    assert!(answer["error"].is_null(), "{answer}");
    assert!(
        world.worker_reads() > reads_before,
        "dispatch must drive the known-ready read without a direct scheduler_step"
    );
    match world
        .runtime
        .scheduler_step(&session)
        .expect("drain already reached idle")
    {
        SchedulerStep::Idle => {}
        other => panic!("expected idle after dispatch drain, got {other:?}"),
    }

    let skipped = world.create_task(&session, "cmd-cancelled-answer");
    world
        .runtime
        .scheduler
        .cancel_task_tree(&skipped)
        .expect("cancel scheduler tree only");
    let reads_mid = world.worker_reads();
    let question = world.publish(&session, &skipped);
    let response = world.dispatch(&corpus_answer_option(
        &session,
        "cmd-cancelled-answer-cmd",
        &skipped,
        &question,
        "brief",
        json!(2),
    ));
    assert!(response["error"].is_null(), "{response}");
    assert_eq!(
        world.worker_reads(),
        reads_mid,
        "submit_answered Ok(None) must not drive a decision step"
    );
}

#[test]
fn budget_charge_rejects_confirmed_above_bound_and_charge_sql_requires_reserved_ge_bound() {
    let root =
        tempfile::TempDir::with_prefix("rivect-budget-charge-guards-").expect("fixture root");
    let path = root.path().join("state.db");
    {
        let mut store = TaskStore::open(&path).expect("store opens");
        store.open_budget("root", 8).expect("root opens");
        store
            .budget_reserve("res-over", &["root"], 4)
            .expect("reserve bound 4");
        let over = store
            .budget_charge("res-over", Some(5))
            .expect_err("confirmed above bound");
        assert!(
            matches!(
                over,
                StoreError::InvalidInput(InvalidCause::ConfirmedExceedsBound {
                    confirmed: 5,
                    bound: 4
                })
            ),
            "{over}"
        );
        store
            .budget_reserve("res-fit", &["root"], 3)
            .expect("second reserve");
        store
            .budget_charge("res-fit", Some(3))
            .expect("confirmed at bound spends when reserved covers the bound");
        assert_eq!(
            store.budget_status("root").expect("status"),
            BudgetStatus {
                limit_units: 8,
                spent: 3,
                reserved: 4
            }
        );
    }
    // CHARGE_BUDGET_SCOPE is `UPDATE ... WHERE reserved >= bound`: a live
    // reservation whose scope reserved units sit below its bound must
    // match zero rows and surface ChargeReservedBelowBound, not spend.
    // The public reserve path always increments reserved by the bound, so
    // the undercut is a ledger repair — the same shape the SQL CHECK
    // exists to refuse.
    {
        let conn = rusqlite::Connection::open(&path).expect("raw connection");
        conn.execute(
            "UPDATE budget_scopes SET reserved = 1 WHERE scope = ?1",
            rusqlite::params!["root"],
        )
        .expect("undercut reserved below the live reservation bound");
    }
    let mut store = TaskStore::open(&path).expect("reopen");
    let under = store
        .budget_charge("res-over", Some(1))
        .expect_err("charge needs reserved >= bound");
    assert!(
        matches!(
            under,
            StoreError::Conflict(ConflictCause::ChargeReservedBelowBound {
                reserved: 1,
                bound: 4,
                ref scope
            }) if scope == "root"
        ),
        "{under}"
    );
}

/// The refusal is typed and readable through the public API alone.
fn assert_writer_refused(error: &StoreError) {
    assert!(
        matches!(error, StoreError::Storage(_))
            && error.to_string().contains("already has a writer"),
        "a second writer is refused: {error}"
    );
}

#[test]
fn second_task_store_through_hard_link_alias_is_refused() {
    let world = open_world("writer-alias", None);
    let db = world.runtime.owner().runtime_dir().join("rivect.db");
    let alias = db.with_file_name("alias.db");
    std::fs::hard_link(&db, &alias).expect("hard link the owner database");
    for name in [&db, &alias] {
        let Err(refused) = TaskStore::open(name) else {
            panic!("the runtime owns this inode");
        };
        assert_writer_refused(&refused);
    }
    std::fs::remove_file(&alias).expect("remove the alias");
}

/// Child entry of the cross-process writer leg: opens the database the
/// marker names and reports the outcome on stdout.
#[test]
#[ignore = "child entry: spawned by cross_process_second_writer_is_refused_before_sql"]
fn cross_process_writer_open_child() {
    use std::io::Write as _;
    let db = std::env::var_os("RIVECT_WRITER_DB").expect("the writer marker names the database");
    let line = match TaskStore::open(Path::new(&db)) {
        Ok(_store) => "WRITER_OPEN admitted\n".to_string(),
        Err(error) => format!("WRITER_OPEN refused {error}\n"),
    };
    std::io::stdout()
        .lock()
        .write_all(line.as_bytes())
        .expect("report the outcome");
}

/// One child opener over `db`; every custody step stays a value until the
/// reap and a failed step retains the root before failing.
fn child_open(db: &Path, root: &mut support::TempTree) -> String {
    let spawned = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "cross_process_writer_open_child",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env_clear()
        .env("RIVECT_WRITER_DB", db)
        .output();
    if spawned.is_err() {
        root.retain();
    }
    let output = spawned.expect("run the child opener");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.starts_with("WRITER_OPEN "))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("the child reported its outcome: {output:?}"))
}

#[test]
fn cross_process_second_writer_is_refused_before_sql() {
    let mut root = support::TempTree::new("concurrency", "writer-cross");
    let db = root.path.join("state.db");
    let holder = TaskStore::open(&db).expect("holder opens");
    let snapshot = |path: &Path| std::fs::read(path).ok();
    let wal = db.with_file_name("state.db-wal");
    let (main_before, wal_before) = (snapshot(&db), snapshot(&wal));
    let refused = child_open(&db, &mut root);
    assert!(
        refused.starts_with("WRITER_OPEN refused ") && refused.contains("already has a writer"),
        "a second process is refused by the held lock: {refused}"
    );
    // The refusal precedes every statement, so the holder's files are
    // byte-for-byte what they were.
    assert_eq!(snapshot(&db), main_before);
    assert_eq!(snapshot(&wal), wal_before);
    drop(holder);
    assert_eq!(
        child_open(&db, &mut root),
        "WRITER_OPEN admitted",
        "the lock is released when the holder drops"
    );
}

// ----- durable settlement through the broker boundary (AC-057/059) -----

/// One prepared manifest on a broker with the given provider: the
/// settlement legs start from this frozen request, exactly as a real
/// dispatch does.
fn prepared_manifest(
    broker: &mut Broker,
    config: &rivect::config::Config,
    inputs: &str,
) -> RequestManifest {
    broker
        .prepare("main", config, "/world/settle", inputs)
        .expect("the fixture request prepares")
}

fn settle_context() -> rivect::model::SendContext {
    rivect::model::SendContext {
        purpose: "main".to_string(),
        connection: "local".to_string(),
        parent_attempt_id: None,
        ranking_basis: None,
    }
}

/// A bound large enough to exercise a refusal: one unit per 4096 input
/// bytes, plus one for the request itself.
fn wide_inputs() -> String {
    "x".repeat(9_000)
}

/// The frozen bound is reserved at EVERY open scope in one transaction: a
/// level that cannot fit denies the whole reservation, so neither scope
/// holds units and no settlement row exists.
#[test]
fn reserve_spans_every_open_scope_atomically() {
    let root = tempfile::TempDir::with_prefix("rivect-settle-scopes-").expect("fixture root");
    let mut store = TaskStore::open(&root.path().join("state.db")).expect("store opens");
    store.open_budget("wide", 4).expect("wide scope opens");
    store.open_budget("narrow", 3).expect("narrow scope opens");
    let config = rivect::config::Config::parse_validated(&support::config_one_provider())
        .expect("fixture config validates");
    let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
    let manifest = prepared_manifest(&mut broker, &config, &wide_inputs());
    assert_eq!(manifest.cost_bound, 4, "the wide request's bound is 4");

    let denied = store.begin_send(&["wide", "narrow"], &settle_context(), &manifest);
    assert!(
        matches!(
            denied,
            Err(StoreError::Conflict(ConflictCause::BudgetExhausted { ref scope, .. }))
                if scope == "narrow"
        ),
        "the later level denies the whole reservation: {denied:?}"
    );
    assert!(
        matches!(
            store.settlement(&manifest.attempt_id),
            Err(StoreError::NotFound(_))
        ),
        "a denied begin writes no settlement row"
    );
    assert_eq!(store.budget_status("wide").expect("wide").reserved, 0);
    assert_eq!(store.budget_status("narrow").expect("narrow").reserved, 0);
}

/// An entered send whose provider fails retains the bound: the row closes
/// unknown with the bound charged, never released as zero.
#[test]
fn entered_send_failure_retains_the_bound() {
    let root = tempfile::TempDir::with_prefix("rivect-settle-entered-").expect("fixture root");
    let mut store = TaskStore::open(&root.path().join("state.db")).expect("store opens");
    store.open_budget("entered", 10).expect("budget opens");
    let config = rivect::config::Config::parse_validated(&support::config_one_provider())
        .expect("fixture config validates");
    let mut broker = Broker::new(Box::new(FailingProvider));
    let manifest = prepared_manifest(&mut broker, &config, "goal: entered failure");

    let sent = {
        let mut ledger = rivect::state::StoreLedger::new(&mut store, vec!["entered".to_string()]);
        broker.dispatch(&mut ledger, "/world/settle", &manifest)
    };
    assert!(sent.is_err(), "the entered send fails: {sent:?}");
    let record = store
        .settlement(&manifest.attempt_id)
        .expect("a row exists");
    assert_eq!(record.state, SettlementState::Settled);
    assert_eq!(record.bins.total_tokens, None);
    assert_eq!(record.unknown_reason.as_deref(), Some("send failed"));
    assert_eq!(record.charged_units, Some(manifest.cost_bound));
    let status = store.budget_status("entered").expect("scope status");
    assert_eq!(status.spent, manifest.cost_bound, "the bound is retained");
    assert_eq!(status.reserved, 0);
}

/// A refusal before the send exits creates neither a reservation nor a
/// row: the ledger is never touched by a pre-send denial.
#[test]
fn pre_send_failure_never_reserves() {
    let root = tempfile::TempDir::with_prefix("rivect-settle-presend-").expect("fixture root");
    let mut store = TaskStore::open(&root.path().join("state.db")).expect("store opens");
    store.open_budget("presend", 10).expect("budget opens");
    let config = rivect::config::Config::parse_validated(&support::config_one_provider())
        .expect("fixture config validates");
    let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
    let manifest = prepared_manifest(&mut broker, &config, "goal: pre-send denial");
    // The dispatch re-check reads the broker's current view: a connection
    // removed after prepare denies before the ledger seam.
    let stripped = rivect::config::Config::parse_validated(
        "config_version = 1\n[connections.other]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n[models.defaults]\nmodel = { mode = \"fixed\", connection = \"other\", model_id = \"m\" }\neffort = { mode = \"fixed\", value = \"high\" }\nfallback = { mode = \"off\" }\n",
    )
    .expect("stripped config validates");
    broker.set_config(&stripped);

    let sent = {
        let mut ledger = rivect::state::StoreLedger::new(&mut store, vec!["presend".to_string()]);
        broker.dispatch(&mut ledger, "/world/settle", &manifest)
    };
    assert!(sent.is_err(), "the pre-send re-check denies: {sent:?}");
    assert!(
        matches!(
            store.settlement(&manifest.attempt_id),
            Err(StoreError::NotFound(_))
        ),
        "a pre-send denial writes no row"
    );
    assert_eq!(store.budget_status("presend").expect("scope").reserved, 0);
}

/// One failing primary and one answering fallback: each physical child
/// attempt settles exactly once, and the substitute's row names the
/// attempt it fell back from.
#[test]
fn primary_fallback_and_substitute_each_settle_once() {
    /// The first send fails and later sends answer: a chain entry that
    /// passed the re-check but failed its own send is skipped, and the
    /// next entry answers.
    struct FirstSendFails {
        calls: u32,
    }

    impl Provider for FirstSendFails {
        fn name(&self) -> &'static str {
            "first-send-fails"
        }

        fn serves(&self, _connection: &str, entry: &rivect::config::Connection) -> bool {
            entry.kind == rivect::config::ConnKind::Local
        }

        fn send(&mut self, _manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
            self.calls += 1;
            if self.calls == 1 {
                return Err(ProviderError::ProviderFailed {
                    connection: "primary".to_string(),
                    reason: "fixture primary failure".to_string(),
                });
            }
            Ok(ProviderReply {
                text: "fallback answer".to_string(),
                tool_calls: Vec::new(),
                usage: UsageDelta::Exact {
                    prompt_tokens: 2,
                    completion_tokens: 1,
                    total_tokens: 3,
                },
                wire_retries: 0,
            })
        }
    }

    let root = tempfile::TempDir::with_prefix("rivect-settle-fallback-").expect("fixture root");
    let mut store = TaskStore::open(&root.path().join("state.db")).expect("store opens");
    store.open_budget("chain", 10).expect("budget opens");
    let config = rivect::config::Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [connections.reserve]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11435\"\n\
         [models.defaults]\n\
         model = { mode = \"fixed\", connection = \"local\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"high\" }\n\
         fallback = { mode = \"auto\", chain = [{ mode = \"fixed\", connection = \"reserve\", model_id = \"fixture-reserve\" }] }\n",
    )
    .expect("fixture config validates");
    let mut broker = Broker::new(Box::new(FirstSendFails { calls: 0 }));
    let manifest = broker
        .prepare("main", &config, "/world/settle", "goal: chain")
        .expect("the fixture request prepares");
    let primary_attempt = manifest.attempt_id.clone();

    let reply = {
        let mut ledger = rivect::state::StoreLedger::new(&mut store, vec!["chain".to_string()]);
        broker
            .dispatch(&mut ledger, "/world/settle", &manifest)
            .expect("the fallback answers")
    };
    assert_eq!(reply.text, "fallback answer");

    let primary = store.settlement(&primary_attempt).expect("primary row");
    assert_eq!(primary.state, SettlementState::Settled);
    assert_eq!(
        primary.bins.total_tokens, None,
        "the failed primary's usage is unknown"
    );
    assert_eq!(primary.charged_units, Some(manifest.cost_bound));

    let totals = store.settlement_totals().expect("totals");
    assert_eq!(
        totals.settled_count, 2,
        "one row per physical child attempt"
    );
    assert_eq!(totals.dispatched_count, 0, "no row stays open");
    assert_eq!(
        totals.total_tokens,
        Some(3),
        "only the answering send's bins count"
    );
}

/// The production executor shares one flight registry: two identical
/// permitted reads admitted through `runtime.executor()` execute once and
/// both observe the same physical read.
#[test]
fn runtime_executor_merges_identical_reads_and_charges_once() {
    let (mut world, file, grant) = scoped_world("runtime-flights");
    let session = world.open_session("bootstrap-runtime-flights");
    let task_a = flight_task(&mut world, &session, "cmd-runtime-flight-a");
    let task_b = flight_task(&mut world, &session, "cmd-runtime-flight-b");
    let request = |grant: &str| EffectRequest::Read {
        grant_id: grant.to_string(),
        path: file.clone(),
    };
    let admitted_a = world
        .runtime
        .executor()
        .admit(&task_a, request(&grant), PermissionMode::Manual)
        .expect("the leader admits");
    let admitted_b = world
        .runtime
        .executor()
        .admit(&task_b, request(&grant), PermissionMode::Manual)
        .expect("the follower admits");
    let outcome_a = world
        .runtime
        .executor()
        .execute(&admitted_a)
        .expect("the leader reads");
    let outcome_b = world
        .runtime
        .executor()
        .execute(&admitted_b)
        .expect("the follower takes the shared observation");
    let (
        EffectOutcome::Read {
            digest: digest_a, ..
        },
        EffectOutcome::Read {
            digest: digest_b, ..
        },
    ) = (outcome_a, outcome_b)
    else {
        panic!("both identical reads answer");
    };
    assert_eq!(digest_a, digest_b, "both subscribers observe one read");
    assert_eq!(
        world.worker_reads(),
        1,
        "one physical charge through the runtime registry"
    );
}

/// The substitute's settlement names the attempt it fell back from and
/// carries only its own bins: a parent total is derived from the recorded
/// lineage, never duplicated into a second total.
#[test]
fn substitute_settlement_records_its_parent_and_its_own_bins() {
    struct FirstFails {
        calls: u32,
    }

    impl Provider for FirstFails {
        fn name(&self) -> &'static str {
            "first-fails"
        }

        fn serves(&self, _connection: &str, entry: &rivect::config::Connection) -> bool {
            entry.kind == rivect::config::ConnKind::Local
        }

        fn send(&mut self, _manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
            self.calls += 1;
            if self.calls == 1 {
                return Err(ProviderError::ProviderFailed {
                    connection: "local".to_string(),
                    reason: "fixture failure".to_string(),
                });
            }
            Ok(ProviderReply {
                text: "reserve answered".to_string(),
                tool_calls: Vec::new(),
                usage: UsageDelta::Exact {
                    prompt_tokens: 2,
                    completion_tokens: 1,
                    total_tokens: 3,
                },
                wire_retries: 0,
            })
        }
    }

    let root = tempfile::TempDir::with_prefix("rivect-lineage-").expect("fixture root");
    let mut store = TaskStore::open(&root.path().join("state.db")).expect("store opens");
    store.open_budget("lineage", 10).expect("budget opens");
    let config = rivect::config::Config::parse_validated(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [connections.reserve]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11435\"\n\
         [models.defaults]\n\
         model = { mode = \"fixed\", connection = \"local\", model_id = \"fixture-model\" }\n\
         effort = { mode = \"fixed\", value = \"high\" }\n\
         fallback = { mode = \"auto\", chain = [{ mode = \"fixed\", connection = \"reserve\", model_id = \"reserve-model\" }] }\n",
    )
    .expect("fixture config validates");
    let mut broker = Broker::new(Box::new(FirstFails { calls: 0 }));
    let manifest = broker
        .prepare("main", &config, "/world/lineage", "goal: lineage")
        .expect("prepares");
    let primary = manifest.attempt_id.clone();
    {
        let mut ledger = rivect::state::StoreLedger::new(&mut store, vec!["lineage".to_string()]);
        broker
            .dispatch(&mut ledger, "/world/lineage", &manifest)
            .expect("the fallback answers");
    }
    let children = store
        .settlements_for_parent(&primary)
        .expect("lineage read");
    assert_eq!(children.len(), 1, "one substitute settles under the parent");
    assert_eq!(
        children[0].parent_attempt_id.as_deref(),
        Some(primary.as_str())
    );
    assert_eq!(children[0].bins.total_tokens, Some(3));
    let primary_row = store.settlement(&primary).expect("primary row");
    assert_eq!(primary_row.bins.total_tokens, None);
    assert_eq!(
        store.settlement_totals().expect("totals").total_tokens,
        Some(3),
        "the lineage is not counted twice"
    );
}

/// Two writers racing for the last unit at one scope: exactly one admits,
/// one is refused, and one row exists. The store's single writer serializes
/// the calls, so the race is over the admission statement, not the file.
#[test]
fn racing_begins_admit_one_send() {
    use std::sync::{Arc, Mutex};
    let root = tempfile::TempDir::with_prefix("rivect-begin-race-").expect("fixture root");
    let mut store = TaskStore::open(&root.path().join("state.db")).expect("store opens");
    // Each fixture request carries a bound of two units, so one unit of room
    // is not enough for either — the scope holds exactly one send's bound.
    store.open_budget("race", 2).expect("budget opens");
    let config = rivect::config::Config::parse_validated(&support::config_one_provider())
        .expect("config validates");
    let mut broker = Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
    let first = broker
        .prepare("main", &config, "/world/race", "goal: one")
        .expect("first prepares");
    let second = broker
        .prepare("main", &config, "/world/race", "goal: two")
        .expect("second prepares");
    let shared = Arc::new(Mutex::new(store));
    let manifests = [first, second];
    let outcomes: Vec<Result<(), StoreError>> = std::thread::scope(|scope| {
        let handles: Vec<_> = manifests
            .iter()
            .map(|manifest| {
                let shared = Arc::clone(&shared);
                scope.spawn(move || {
                    let mut store = shared.lock().expect("store lock");
                    store
                        .begin_send(&["race"], &settle_context(), manifest)
                        .map(|_ticket| ())
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("thread joins"))
            .collect()
    });
    let admitted = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
    let refused = outcomes
        .iter()
        .filter(|outcome| {
            matches!(
                outcome,
                Err(StoreError::Conflict(ConflictCause::BudgetExhausted { .. }))
            )
        })
        .count();
    assert_eq!((admitted, refused), (1, 1), "{outcomes:?}");
    let mut shared = shared;
    let store = Arc::get_mut(&mut shared)
        .expect("sole owner")
        .get_mut()
        .expect("lock");
    assert_eq!(
        store.settlement_totals().expect("totals").dispatched_count,
        1,
        "one begun send, one row"
    );
    let status = store.budget_status("race").expect("scope");
    assert_eq!(status.reserved, 2, "only the admitted send's bound is held");
}

/// A real ledger refusal at the dispatch boundary becomes `Waiting` with a
/// recorded reason, and the next reservation resolution clears it.
#[test]
fn budget_refusal_waits_then_resumes_after_the_resolution() {
    let (mut world, file, grant) = scoped_world("budget-wait");
    world.runtime.purpose = "backend_task".to_string();
    let session = world.open_session("bootstrap-budget-wait");
    let task = world.create_task(&session, "cmd-budget-wait");
    answer_task(
        &mut world,
        &session,
        "cmd-budget-answer",
        &task,
        &node_answer(&file),
        1,
    );
    let scope = task.0.clone();
    // Every frozen request carries at least two units (one per 4096 input
    // bytes plus one), so the scope holds exactly one send's bound.
    world
        .runtime
        .store_writer()
        .open_budget(&scope, 2)
        .expect("the task's scope opens");
    world
        .runtime
        .store_writer()
        .budget_reserve("blocker", &[scope.as_str()], 2)
        .expect("the last units are held");

    match drive_step(&mut world, &session, &task, &grant, &node_answer(&file)) {
        Ok(SchedulerStep::Ran { outcome, .. }) => assert!(
            matches!(*outcome, StepOutcome::Waiting { .. }),
            "a budget refusal waits: {outcome:?}"
        ),
        other => panic!("the step never ran: {other:?}"),
    }
    assert_eq!(
        world.runtime.broker.admitted_attempts(),
        0,
        "the refused primary's admission and frozen inputs are dropped"
    );
    let reason = world
        .runtime
        .budget_waiting_reason(&session, &task)
        .expect("the waiting reason is recorded")
        .to_string();
    assert!(
        reason.contains(&scope),
        "the reason names the refused scope: {reason}"
    );
    // The status payload is the product surface: the refusal it serves
    // carries the task and the same reason, not just a test-only accessor.
    let served = world.dispatch(&support::corpus_status(&session));
    let waiting = served["result"]["budget_waiting"]
        .as_array()
        .expect("the status serves the waiting list");
    let entry = waiting
        .iter()
        .find(|entry| entry["task_id"].as_str() == Some(task.0.as_str()))
        .expect("the status serves the refused task");
    assert!(
        entry["reason"]
            .as_str()
            .expect("the entry names its reason")
            .contains(&scope),
        "the served reason names the refused scope: {entry}"
    );

    // The resolution frees the unit: the next step is no longer waiting and
    // the recorded reason is gone.
    world
        .runtime
        .store_writer()
        .budget_charge("blocker", Some(0))
        .expect("the blocker resolves");
    let resumed = drive_step(&mut world, &session, &task, &grant, &node_answer(&file));
    assert!(
        !matches!(
            resumed,
            Ok(SchedulerStep::Ran { ref outcome, .. })
                if matches!(**outcome, StepOutcome::Waiting { .. })
        ),
        "the resolved scope no longer waits: {resumed:?}"
    );
    assert!(
        world
            .runtime
            .budget_waiting_reason(&session, &task)
            .is_none(),
        "the waiting reason clears once a send gets through"
    );
    let served = world.dispatch(&support::corpus_status(&session));
    assert!(
        served["result"]["budget_waiting"]
            .as_array()
            .expect("the status serves the waiting list")
            .iter()
            .all(|entry| entry["task_id"].as_str() != Some(task.0.as_str())),
        "the cleared reason leaves the status surface: {served}"
    );
    // The resumed step really settled: one row through the ledger, the
    // bound charged, and the served economy no longer reports an open send.
    let manifest = world
        .last_manifest()
        .expect("the resumed step reached the provider");
    let row = world
        .runtime
        .store()
        .settlement(&manifest.attempt_id)
        .expect("the resumed send settles");
    assert_eq!(row.state, SettlementState::Settled);
    assert_eq!(row.charged_units, Some(manifest.cost_bound));
    let economy = &served["result"]["economy"];
    assert_eq!(economy["pending_sends"], json!(0));
    assert_eq!(economy["charged_units"], json!(manifest.cost_bound));
}

/// One budget-refused descendant waits; cancelling the parent drains the
/// whole subtree and the served waiting list names none of it.
#[test]
fn cancelled_parent_clears_the_cancelled_subtrees_budget_waiting() {
    let (mut world, file, grant) = scoped_world("budget-cancel-subtree");
    world.runtime.purpose = "backend_task".to_string();
    let session = world.open_session("bootstrap-budget-cancel-subtree");
    let parent = world.create_task(&session, "cmd-budget-cancel-parent");
    let child = create_child_task(&mut world, &session, "cmd-budget-cancel-child", &parent);
    world
        .runtime
        .store_writer()
        .open_budget(&child.0, 0)
        .expect("the child's scope cannot fit its bound");
    let refused = drive_step(&mut world, &session, &child, &grant, &node_answer(&file));
    assert!(
        matches!(
            refused,
            Ok(SchedulerStep::Ran { ref outcome, .. })
                if matches!(**outcome, StepOutcome::Waiting { .. })
        ),
        "the child waits on its budget: {refused:?}"
    );
    let served = world.dispatch(&support::corpus_status(&session));
    assert!(
        served["result"]["budget_waiting"]
            .as_array()
            .expect("the status serves the waiting list")
            .iter()
            .any(|entry| entry["task_id"].as_str() == Some(child.0.as_str())),
        "the child's refusal is served before the cancel: {served}"
    );

    cancel_task_via_ingress(&mut world, &session, &parent);
    let served = world.dispatch(&support::corpus_status(&session));
    assert!(
        served["result"]["budget_waiting"]
            .as_array()
            .expect("the status serves the waiting list")
            .iter()
            .all(|entry| entry["task_id"].as_str() != Some(child.0.as_str())
                && entry["task_id"].as_str() != Some(parent.0.as_str())),
        "the cancelled subtree leaves the waiting surface: {served}"
    );
}

/// A waiting task newer than one tasks page is still served: the waiting
/// record is keyed by session, not by the status page slice.
#[test]
fn budget_waiting_is_served_beyond_the_tasks_page() {
    let (mut world, file, grant) = scoped_world("budget-wait-page");
    world.runtime.purpose = "backend_task".to_string();
    let session = world.open_session("bootstrap-budget-wait-page");
    // `corpus_status` requests the 20-row page the status surface serves.
    const STATUS_PAGE: usize = 20;
    for index in 0..STATUS_PAGE {
        world.create_task(&session, &format!("cmd-budget-page-{index}"));
    }
    let waiting_task = world.create_task(&session, "cmd-budget-page-waiting");
    world
        .runtime
        .store_writer()
        .open_budget(&waiting_task.0, 0)
        .expect("the waiting scope cannot fit its bound");
    let refused = drive_step(
        &mut world,
        &session,
        &waiting_task,
        &grant,
        &node_answer(&file),
    );
    assert!(
        matches!(
            refused,
            Ok(SchedulerStep::Ran { ref outcome, .. })
                if matches!(**outcome, StepOutcome::Waiting { .. })
        ),
        "the task waits on its budget: {refused:?}"
    );

    let served = world.dispatch(&support::corpus_status(&session));
    let page = served["result"]["tasks"]["items"]
        .as_array()
        .expect("the status serves a tasks page");
    assert_eq!(page.len(), STATUS_PAGE, "the page is full");
    assert!(
        !page
            .iter()
            .any(|task| task["task_id"].as_str() == Some(waiting_task.0.as_str())),
        "the waiting task sits outside the page: {served}"
    );
    let entry = served["result"]["budget_waiting"]
        .as_array()
        .expect("the status serves the waiting list")
        .iter()
        .find(|entry| entry["task_id"].as_str() == Some(waiting_task.0.as_str()))
        .expect("the waiting task is served beyond the page");
    assert!(
        entry["reason"]
            .as_str()
            .expect("the entry names its reason")
            .contains(&waiting_task.0),
        "the served reason names the refused scope: {entry}"
    );

    // The waiting list is session-scoped: another session serves none of it.
    let other = world.open_session("bootstrap-budget-wait-other");
    let other_status = world.dispatch(&support::corpus_status(&other));
    assert!(
        other_status["result"]["budget_waiting"]
            .as_array()
            .expect("the other session serves a waiting list")
            .is_empty(),
        "another session sees none of this session's waits: {other_status}"
    );
}
