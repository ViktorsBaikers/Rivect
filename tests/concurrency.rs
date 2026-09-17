//! Bounded tree concurrency proof: a waiting parent frees its execution
//! slot before it waits, independent branches are not globally
//! serialized, shared caps hold, and cancel + reset + reconnect + late
//! callback never resurrect dispatch (AC-010/AC-012, PROH-002,
//! EDGE-002/003). The runtime-driven cases exercise the production
//! path: task submission builds tree nodes, the runtime loop releases a
//! waiting parent's slot, and the cancel ingress drains the tree.

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

use rivect::contracts::{Event, EventId, Lifecycle, SessionId, TaskId};
use rivect::controller::{SchedulerStep, StepOutcome};
use rivect::scheduler::{
    CompleteTransition, DeliverVerdict, NodeState, Scheduler, SchedulerError, WaitTransition,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use support::{World, answer_custom, corpus_answer_custom, open_world};

fn scoped_world(tag: &str) -> (World, PathBuf, String) {
    let mut world = open_world(tag, Some(&support::config_distinct_pools()));
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

/// Publishes the pending question and answers it through the real
/// ingress, which also builds the task's runnable scheduler node.
fn answer_task(
    world: &mut World,
    session: &SessionId,
    command_id: &str,
    task: &TaskId,
    text: &str,
    id: i64,
) {
    let question = world.publish(session, task);
    let response = world.dispatch(&corpus_answer_custom(
        session,
        command_id,
        task,
        &question,
        text,
        json!(id),
    ));
    assert!(response["error"].is_null(), "{response}");
}

/// Cancels one task through the real ingress: the store cancels the
/// task and the scheduler tree drains in the same command.
fn cancel_task_via_ingress(world: &mut World, session: &SessionId, task: &TaskId) {
    let intent_revision = world
        .runtime
        .owner
        .store
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
        .owner
        .store
        .snapshot(&child_task)
        .expect("child snapshot");
    assert_eq!(child_snapshot.lifecycle, Lifecycle::Completed);
    let parent_snapshot = world
        .runtime
        .owner
        .store
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
        .owner
        .store
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
        .owner
        .store
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
    world.runtime.policy.revoke(&grant);
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
        .owner
        .store
        .snapshot(&first_child)
        .expect("first child snapshot");
    assert_eq!(first_snapshot.lifecycle, Lifecycle::Completed);
    let parent_snapshot = world
        .runtime
        .owner
        .store
        .snapshot(&parent_task)
        .expect("parent snapshot");
    assert_eq!(parent_snapshot.lifecycle, Lifecycle::Cancelled);
    let second_snapshot = world
        .runtime
        .owner
        .store
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
        .owner
        .store
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
