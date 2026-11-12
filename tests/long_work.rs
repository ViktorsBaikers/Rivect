//! Bounded worker proof (AC-083a): `long_work.start` records one worker's
//! deadline, settled-send bound and ledger-unit bound on the task's own
//! scope, the dispatch transaction and the step gate enforce them, and a
//! reached bound or an explicit stop ends the worker terminally — no
//! renewal, no second ledger, no new grant, and cancellation leaves the
//! shared ledger intact. The parent/child cases prove a delegated child
//! cannot spend past an ancestor's bound through the one scheduler, store
//! and ledger.

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

use rivect::config::ConnKind;
use rivect::contracts::{AnswerSelection, Lifecycle, OptionId, Question, SessionId, TaskId};
use rivect::controller::{SchedulerStep, StepOutcome, output_settlement, step_outcome_observation};
use rivect::model::{RequestManifest, SendContext, SendOutcome};
use rivect::providers::{Provider, ProviderError, ProviderReply};
use rivect::resources::{OutputSettlement, UsageDelta};
use rivect::scheduler::{NodeState, Scheduler};
use rivect::state::{
    BudgetReservationState, BudgetStatus, ConflictCause, Missing, SettlementState, StoreError,
    WorkBudget, WorkBudgetState,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use support::World;

/// A provider that answers every admitted send with no tool call: the step
/// then reports a waiting outcome instead of completing the task, so a
/// proof can dispatch the same task more than once.
struct QuietProvider {
    calls: Arc<AtomicU64>,
}

impl Provider for QuietProvider {
    fn name(&self) -> &'static str {
        "quiet"
    }

    fn serves(&self, _connection: &str, entry: &rivect::config::Connection) -> bool {
        entry.kind == ConnKind::Local
    }

    fn send(&mut self, _manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderReply {
            text: String::new(),
            tool_calls: Vec::new(),
            usage: UsageDelta::Unknown,
            wire_retries: 0,
            dropped_reasoning: 0,
        })
    }
}

/// Every send fails at the provider: the fallback chain's next leg is the
/// one that must be refused by the send bound.
struct FailingProvider {
    calls: Arc<AtomicU64>,
}

impl Provider for FailingProvider {
    fn name(&self) -> &'static str {
        "failing"
    }

    fn serves(&self, _connection: &str, entry: &rivect::config::Connection) -> bool {
        entry.kind == ConnKind::Local
    }

    fn send(&mut self, _manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(ProviderError::UnsupportedParameter {
            connection: "local".to_string(),
            parameter: "fixture-parameter",
            model: "fixture-model".to_string(),
        })
    }
}

/// Two local connections under one purpose whose fallback chain names the
/// reserve: the entered primary settles, then the fallback leg dispatches
/// inside the same step.
fn fallback_config() -> String {
    "config_version = 1\n\
     [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
     [connections.reserve]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11435\"\n\
     [models.defaults]\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"fixture-model\" }\n\
     effort = { mode = \"fixed\", value = \"high\" }\n\
     fallback = { mode = \"off\" }\n\
     [models.purposes.backend_task]\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"fixture-model\" }\n\
     fallback = { mode = \"auto\", chain = [ { mode = \"fixed\", connection = \"reserve\", model_id = \"reserve-model\" } ] }\n"
        .to_string()
}

/// Two local connections under one purpose whose fallback is the operator's
/// manual choice: the failed primary pauses and the served candidate is the
/// one the answer picks.
fn manual_config() -> String {
    "config_version = 1\n\
     [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
     [connections.reserve]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11435\"\n\
     [models.defaults]\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"fixture-model\" }\n\
     effort = { mode = \"fixed\", value = \"high\" }\n\
     fallback = { mode = \"manual\" }\n\
     [models.purposes.backend_task]\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"fixture-model\" }\n\
     fallback = { mode = \"manual\" }\n"
        .to_string()
}

/// The first send fails and every later one would answer: the manual pause is
/// what the failure produces, and the substitute's own send is what the bound
/// must refuse.
struct FailFirstProvider {
    calls: Arc<AtomicU64>,
}

impl Provider for FailFirstProvider {
    fn name(&self) -> &'static str {
        "fail-first"
    }

    fn serves(&self, _connection: &str, entry: &rivect::config::Connection) -> bool {
        entry.kind == ConnKind::Local
    }

    fn send(&mut self, _manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == 1 {
            return Err(ProviderError::ProviderFailed {
                connection: "local".to_string(),
                reason: "fixture failure".to_string(),
            });
        }
        Ok(ProviderReply {
            text: String::new(),
            tool_calls: Vec::new(),
            usage: UsageDelta::Unknown,
            wire_retries: 0,
            dropped_reasoning: 0,
        })
    }
}

fn send_context() -> SendContext {
    SendContext {
        purpose: "backend_task".to_string(),
        connection: "local".to_string(),
        parent_attempt_id: None,
        ranking_basis: None,
    }
}

struct Fixture {
    world: World,
    session: SessionId,
    task: TaskId,
    file: PathBuf,
    grant: String,
    now: Arc<AtomicU64>,
    calls: Arc<AtomicU64>,
}

impl Fixture {
    fn budget(&self, task: &TaskId) -> WorkBudget {
        self.world
            .runtime
            .store()
            .work_budget(task)
            .expect("work budget read")
            .expect("the worker was recorded through the ingress")
    }

    fn status(&self, task: &TaskId) -> BudgetStatus {
        self.world
            .runtime
            .store()
            .budget_status(&task.0)
            .expect("the shared ledger answers")
    }

    fn settled_rows(&self) -> u64 {
        self.world
            .runtime
            .store()
            .settlement_totals()
            .expect("settlement totals")
            .settled_count
    }

    /// The task's `budget_scopes` rows under the store's own prefix
    /// convention: its own scope plus any labelled scope the task spent
    /// under. A second ledger would show up here as a second row.
    fn scope_rows(&self, task: &TaskId) -> u64 {
        let db = self.world.root.join("runtime").join("rivect.db");
        let conn = rusqlite::Connection::open(db).expect("the store opens for the row count");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM budget_scopes WHERE scope = ?1 OR scope LIKE ?1 || '/%'",
                [&task.0],
                |row| row.get(0),
            )
            .expect("the scope count reads");
        u64::try_from(count).expect("a row count is non-negative")
    }

    /// The request-relative deadline the wire carries.
    fn start(
        &mut self,
        task: &TaskId,
        deadline_seconds: u64,
        send_bound: u64,
        unit_bound: u64,
    ) -> Value {
        let request = json!({
            "jsonrpc": "2.0", "id": 71, "method": "long_work.start",
            "params": {
                "schema_version": 1,
                "session_id": self.session.0,
                "task_id": task.0,
                "deadline_seconds": deadline_seconds,
                "send_bound": send_bound,
                "unit_bound": unit_bound,
            }
        });
        self.world.dispatch(&request)
    }

    fn stop(&mut self, task: &TaskId) -> Value {
        let request = json!({
            "jsonrpc": "2.0", "id": 72, "method": "long_work.stop",
            "params": {
                "schema_version": 1,
                "session_id": self.session.0,
                "task_id": task.0,
            }
        });
        self.world.dispatch(&request)
    }

    /// One production decision step for the task: the answered node is
    /// submitted to the runtime's one scheduler and the loop's own step runs
    /// it through the dispatch gates.
    fn step(&mut self, task: &TaskId) -> SchedulerStep {
        let answer = AnswerSelection::Custom {
            text: format!("read {}", self.file.display()),
        };
        self.world
            .runtime
            .scheduler
            .submit_answered(task.clone(), answer, self.grant.clone())
            .expect("scheduler accepts the node")
            .expect("the task is outside every cancelled subtree");
        self.world
            .runtime
            .scheduler_step(&self.session)
            .expect("the decision step runs")
    }

    /// Opens a dispatched settlement at the task's scope and leaves it open:
    /// the row is not a settled send until it closes.
    fn begin_unsettled(&mut self, task: &TaskId) -> RequestManifest {
        let manifest = self
            .world
            .runtime
            .broker
            .prepare(
                "backend_task",
                &self.world.runtime.config_for_broker(),
                "/world/long-work",
                "goal: pending send",
            )
            .expect("the pending send prepares");
        self.world
            .runtime
            .store_writer()
            .begin_send(&[task.0.as_str()], &send_context(), &manifest)
            .expect("the send opens its dispatched row");
        manifest
    }

    fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

fn fixture_with(
    tag: &str,
    config: &str,
    provider: Box<dyn Provider>,
    calls: Arc<AtomicU64>,
) -> Fixture {
    let now = Arc::new(AtomicU64::new(1_000));
    let mut world = support::open_world_with(
        tag,
        Some(config),
        provider,
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-long-work-marker\n").expect("scoped file");
    world.runtime.purpose = "backend_task".to_string();
    let grant = world.runtime.set_read_scope(scope, file.clone());
    world.runtime.work_clock = Box::new({
        let now = now.clone();
        move || now.load(Ordering::SeqCst)
    });
    let session = world.open_session(&format!("{tag}-session"));
    let task = world.create_task(&session, &format!("{tag}-task"));
    Fixture {
        world,
        session,
        task,
        file,
        grant,
        now,
        calls,
    }
}

fn fixture(tag: &str) -> Fixture {
    let calls = Arc::new(AtomicU64::new(0));
    fixture_with(
        tag,
        &support::config_distinct_pools(),
        Box::new(QuietProvider {
            calls: calls.clone(),
        }),
        calls,
    )
}

fn fallback_fixture(tag: &str) -> Fixture {
    let calls = Arc::new(AtomicU64::new(0));
    fixture_with(
        tag,
        &fallback_config(),
        Box::new(FailingProvider {
            calls: calls.clone(),
        }),
        calls,
    )
}

fn manual_fixture(tag: &str) -> Fixture {
    let calls = Arc::new(AtomicU64::new(0));
    fixture_with(
        tag,
        &manual_config(),
        Box::new(FailFirstProvider {
            calls: calls.clone(),
        }),
        calls,
    )
}

fn stopped_reason(step: SchedulerStep) -> String {
    match step {
        SchedulerStep::Ran { outcome, .. } => match *outcome {
            StepOutcome::WorkStopped { reason, .. } => reason,
            other => panic!("expected a terminal work stop, got {other:?}"),
        },
        other => panic!("expected a step, got {other:?}"),
    }
}

fn assert_ran(step: &SchedulerStep) {
    assert!(
        matches!(step, SchedulerStep::Ran { .. }),
        "the step must run, got {step:?}"
    );
}

fn assert_conflict(response: &Value) {
    assert!(
        response.get("result").is_none(),
        "the replay must be refused: {response}"
    );
    assert_eq!(
        response["error"]["data"]["code"],
        json!("conflict"),
        "the refusal is the typed conflict: {response}"
    );
}

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

fn answer_task(world: &mut World, session: &SessionId, task: &TaskId, file: &Path) {
    let question = world.publish(session, task);
    let selection = AnswerSelection::Custom {
        text: format!("read {}", file.display()),
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
        .expect("scheduler accepts the node")
        .expect("the task is outside every cancelled subtree");
}

#[test]
fn long_work_start_records_the_bound_and_is_the_only_producer() {
    let mut fixture = fixture("long-work-start");
    assert!(
        fixture
            .world
            .runtime
            .store()
            .work_budget(&fixture.task)
            .expect("read")
            .is_none(),
        "no row exists before the ingress records one"
    );

    let response = fixture.start(&fixture.task.clone(), 600, 3, 5);
    assert!(
        response.get("result").is_some(),
        "long_work.start answers: {response}"
    );
    let result = &response["result"];
    assert_eq!(result["state"], json!("open"));
    assert_eq!(
        result["deadline_unix_seconds"],
        json!(1_600),
        "the response serves the absolute deadline the clock recorded"
    );
    assert_eq!(result["send_bound"], json!(3));
    assert_eq!(result["unit_bound"], json!(5));
    assert_eq!(result["settled_sends"], json!(0));
    assert_eq!(result["spent_units"], json!(0));
    assert_eq!(result["reserved_units"], json!(0));

    let recorded = fixture.budget(&fixture.task);
    assert_eq!(recorded.state, WorkBudgetState::Open);
    assert_eq!(recorded.deadline_unix_seconds, 1_600);
    assert_eq!(recorded.send_bound, 3);
    assert_eq!(recorded.unit_bound, 5);
    assert_eq!(recorded.stop_reason, None);
    assert_eq!(fixture.status(&fixture.task).limit_units, 5);
    assert_eq!(fixture.scope_rows(&fixture.task), 1, "one ledger scope");

    // The ingress is the only producer: a second start of the same task is a
    // typed conflict and leaves the recorded bound exactly as it was.
    let replay = fixture.start(&fixture.task.clone(), 900, 9, 9);
    assert_conflict(&replay);
    let unchanged = fixture.budget(&fixture.task);
    assert_eq!(unchanged.deadline_unix_seconds, 1_600);
    assert_eq!(unchanged.send_bound, 3);
    assert_eq!(unchanged.unit_bound, 5);
    assert_eq!(
        fixture.scope_rows(&fixture.task),
        1,
        "still one ledger scope"
    );
}

#[test]
fn long_work_stop_is_terminal_and_needs_a_new_request() {
    let mut fixture = fixture("long-work-stop");
    let task = fixture.task.clone();
    assert!(fixture.start(&task, 600, 3, 5).get("result").is_some());

    let stopped = fixture.stop(&task);
    assert!(
        stopped.get("result").is_some(),
        "long_work.stop answers: {stopped}"
    );
    assert_eq!(stopped["result"]["state"], json!("stopped"));
    assert_eq!(stopped["result"]["stop_reason"], json!("stopped"));

    // The stopped row is terminal at the step boundary too: the worker never
    // dispatches again and the recorded reason is the one it reports.
    assert_eq!(stopped_reason(fixture.step(&task)), "stopped");
    assert_eq!(fixture.calls(), 0);

    // A second stop and a second start both refuse: only a new request — a
    // fresh task's own budget — can start bounded work again.
    assert_conflict(&fixture.stop(&task));
    assert_conflict(&fixture.start(&task, 600, 3, 5));
    let fresh = fixture
        .world
        .create_task(&fixture.session, "long-work-stop-fresh");
    assert!(
        fixture.start(&fresh, 600, 3, 5).get("result").is_some(),
        "a fresh task starts its own budget"
    );
    assert_eq!(fixture.budget(&task).state, WorkBudgetState::Stopped);
}

#[test]
fn long_work_stop_names_a_task_cause_for_an_unknown_task() {
    let mut fixture = fixture("long-work-stop-unknown");
    let task = fixture.task.clone();

    // A task this store never held reports the task cause, not a missing
    // work-budget row.
    let unknown = TaskId("no-such-task".to_string());
    let refused = fixture.stop(&unknown);
    assert_eq!(refused["error"]["data"]["code"], json!("not_found"));
    assert!(
        refused["error"]["data"]["message"]
            .as_str()
            .expect("the refusal carries a message")
            .starts_with(&StoreError::missing_task(&unknown.0).to_string()),
        "the refusal names the missing task: {refused}"
    );

    // A task that exists without a recorded worker reports the work-budget
    // cause.
    let refused = fixture.stop(&task);
    assert_eq!(refused["error"]["data"]["code"], json!("not_found"));
    assert!(
        refused["error"]["data"]["message"]
            .as_str()
            .expect("the refusal carries a message")
            .starts_with(&StoreError::NotFound(Missing::WorkBudget(task.0.clone())).to_string()),
        "the refusal names the missing worker row: {refused}"
    );
}

#[test]
fn work_budget_stops_at_the_recorded_deadline() {
    let mut fixture = fixture("long-work-deadline");
    let task = fixture.task.clone();
    assert!(fixture.start(&task, 60, 5, 10).get("result").is_some());

    let first = fixture.step(&task);
    assert_ran(&first);
    assert_eq!(
        fixture.calls(),
        1,
        "the step before the deadline dispatches"
    );
    let spent = fixture.budget(&task);
    assert_eq!(spent.settled_sends, 1, "the shared ledger counted the send");
    assert_eq!(spent.spent, 2, "the unknown send retained its frozen bound");

    fixture.now.store(1_060, Ordering::SeqCst);
    assert_eq!(stopped_reason(fixture.step(&task)), "work deadline reached");
    assert_eq!(fixture.calls(), 1, "the expired step never dispatches");
    let stopped = fixture.budget(&task);
    assert_eq!(stopped.state, WorkBudgetState::Stopped);
    assert_eq!(
        stopped.stop_reason.as_deref(),
        Some("work deadline reached")
    );
    // The stop deletes nothing: the send it already settled is still there.
    let ledger = fixture.status(&task);
    assert_eq!(ledger.limit_units, 10);
    assert_eq!(ledger.spent, 2);
    assert_eq!(ledger.reserved, 0);
    assert_eq!(fixture.settled_rows(), 1);
}

#[test]
fn work_budget_stops_at_the_send_bound() {
    let mut fixture = fixture("long-work-sends");
    let task = fixture.task.clone();
    assert!(fixture.start(&task, 600, 1, 10).get("result").is_some());

    assert_ran(&fixture.step(&task));
    assert_eq!(fixture.calls(), 1);
    assert_eq!(fixture.budget(&task).settled_sends, 1);

    assert_eq!(
        stopped_reason(fixture.step(&task)),
        "work send bound reached"
    );
    assert_eq!(fixture.calls(), 1, "the bound stops before the next send");
    let stopped = fixture.budget(&task);
    assert_eq!(stopped.state, WorkBudgetState::Stopped);
    assert_eq!(
        stopped.stop_reason.as_deref(),
        Some("work send bound reached")
    );
}

#[test]
fn work_budget_stops_at_the_unit_bound() {
    let mut fixture = fixture("long-work-units");
    let task = fixture.task.clone();
    // One send's frozen bound is two units, so the scope fits exactly one.
    assert!(fixture.start(&task, 600, 10, 2).get("result").is_some());

    let first = fixture.step(&task);
    assert_ran(&first);
    assert_eq!(fixture.calls(), 1);
    assert_eq!(
        fixture.budget(&task).spent,
        2,
        "the send charged the shared ledger's own scope"
    );

    assert_eq!(
        stopped_reason(fixture.step(&task)),
        "work unit bound reached"
    );
    assert_eq!(fixture.calls(), 1, "the spent scope admits no further send");
    assert_eq!(fixture.status(&task).spent, 2);
    let stopped = fixture.budget(&task);
    assert_eq!(stopped.state, WorkBudgetState::Stopped);
    assert_eq!(
        stopped.stop_reason.as_deref(),
        Some("work unit bound reached")
    );
    // The durable stop is terminal: a later step reports the recorded cause
    // and dispatches nothing.
    assert_eq!(
        stopped_reason(fixture.step(&task)),
        "work unit bound reached"
    );
    assert_eq!(fixture.calls(), 1);
    assert_eq!(fixture.settled_rows(), 1);
}

#[test]
fn unit_bound_below_the_frozen_bound_stops_instead_of_waiting() {
    let mut fixture = fixture("long-work-remainder");
    let task = fixture.task.clone();
    // Three units cannot fund a second two-unit send: the first send fits,
    // the remainder can never fit, so waiting for a resolution would only
    // run to the deadline.
    assert!(fixture.start(&task, 600, 10, 3).get("result").is_some());

    assert_ran(&fixture.step(&task));
    assert_eq!(fixture.calls(), 1);
    assert_eq!(fixture.budget(&task).spent, 2);

    assert_eq!(
        stopped_reason(fixture.step(&task)),
        "work unit bound reached"
    );
    assert_eq!(fixture.calls(), 1, "the remainder never dispatches");
    assert_eq!(fixture.budget(&task).state, WorkBudgetState::Stopped);
    assert_eq!(
        fixture
            .world
            .runtime
            .budget_waiting_reason(&fixture.session, &task),
        None,
        "a stopped worker is not a waiting one"
    );
}

#[test]
fn expired_worker_does_not_renew_itself() {
    println!("ROW A22 ok");
    let mut fixture = fixture("long-work-expired");
    let task = fixture.task.clone();
    assert!(fixture.start(&task, 0, 5, 10).get("result").is_some());

    assert_eq!(stopped_reason(fixture.step(&task)), "work deadline reached");
    assert_eq!(
        fixture.calls(),
        0,
        "an already-expired worker never dispatches"
    );

    // Nothing renews it: a later step reports the recorded stop, a new start
    // is refused, and the ledger holds no spend at all.
    assert_eq!(stopped_reason(fixture.step(&task)), "work deadline reached");
    assert_eq!(fixture.calls(), 0);
    assert_conflict(&fixture.start(&task, 600, 5, 10));
    let recorded = fixture.budget(&task);
    assert_eq!(recorded.state, WorkBudgetState::Stopped);
    assert_eq!(fixture.status(&task).spent, 0);
    assert_eq!(fixture.status(&task).limit_units, 10);
}

#[test]
fn stopped_worker_creates_no_second_ledger_or_grant() {
    println!("ROW A22 ok");
    let mut fixture = fixture("long-work-no-second");
    let task = fixture.task.clone();
    assert!(fixture.start(&task, 600, 5, 10).get("result").is_some());
    assert_ran(&fixture.step(&task));
    assert_eq!(fixture.calls(), 1);
    let spent_before = fixture.status(&task).spent;

    assert!(fixture.stop(&task).get("result").is_some());
    assert_eq!(stopped_reason(fixture.step(&task)), "stopped");
    assert_eq!(fixture.calls(), 1);

    // The stop created no second ledger: the one scope keeps its limit and
    // its spend, and the one settlement row is still the only charge.
    let after = fixture.status(&task);
    assert_eq!(after.limit_units, 10);
    assert_eq!(after.spent, spent_before);
    assert_eq!(after.reserved, 0);
    assert_eq!(fixture.scope_rows(&task), 1, "one ledger scope, not two");
    assert_eq!(fixture.settled_rows(), 1);
    assert_conflict(&fixture.start(&task, 600, 5, 10));
    assert_eq!(fixture.budget(&task).state, WorkBudgetState::Stopped);

    // No second grant was minted: grant ids are monotonic, so the read scope's
    // grant-1 is the only right this runtime holds.
    assert!(
        fixture.world.runtime.policy().grant("grant-2").is_none(),
        "the ingress granted no second right"
    );
}

#[test]
fn cancelled_worker_leaves_the_shared_ledger_intact() {
    let mut fixture = fixture("long-work-cancelled");
    let task = fixture.task.clone();
    assert!(fixture.start(&task, 600, 5, 10).get("result").is_some());
    assert_ran(&fixture.step(&task));
    assert_eq!(fixture.calls(), 1);
    let before = fixture.status(&task);
    let settlements_before = fixture.settled_rows();

    let intent_revision = fixture
        .world
        .runtime
        .store()
        .snapshot(&task)
        .expect("snapshot")
        .intent_revision;
    let cancelled = fixture.world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 30, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": "cmd-long-work-cancel",
            "session_id": fixture.session.0, "kind": "cancel", "task_id": task.0,
            "expected_intent_revision": intent_revision,
            "reason": "user stopped the worker"
        }
    }));
    assert!(cancelled["error"].is_null(), "{cancelled}");

    // Cancellation deletes nothing: the same scope, the same spend and the
    // same settlement row survive it, and the scheduler grows no new node.
    let after = fixture.status(&task);
    assert_eq!(after.limit_units, before.limit_units);
    assert_eq!(after.spent, before.spent);
    assert_eq!(after.reserved, 0);
    assert_eq!(fixture.settled_rows(), settlements_before);
    assert_eq!(fixture.scope_rows(&task), 1);
    assert!(fixture.budget(&task).state == WorkBudgetState::Open);
    assert!(
        fixture
            .world
            .runtime
            .scheduler
            .submit_answered(
                task.clone(),
                AnswerSelection::Custom {
                    text: format!("read {}", fixture.file.display()),
                },
                fixture.grant.clone(),
            )
            .expect("scheduler answers")
            .is_none(),
        "a cancelled worker never grows runnable work again"
    );
    assert!(matches!(
        fixture.world.runtime.scheduler_step(&fixture.session),
        Ok(SchedulerStep::Idle)
    ));
    assert_eq!(fixture.calls(), 1, "cancellation dispatched nothing");
}

#[test]
fn dispatched_settlement_does_not_count_as_a_settled_send() {
    let mut fixture = fixture("long-work-dispatched");
    let task = fixture.task.clone();
    assert!(fixture.start(&task, 600, 1, 10).get("result").is_some());

    let pending = fixture.begin_unsettled(&task);
    assert_eq!(
        fixture
            .world
            .runtime
            .store()
            .settlement(&pending.attempt_id)
            .expect("the dispatched row reads")
            .state,
        SettlementState::Dispatched
    );
    assert_eq!(
        fixture.budget(&task).settled_sends,
        0,
        "an open dispatch is not a settled send"
    );

    // The gate admits the step on the settled count alone: the open row does
    // not fill the bound of one.
    assert_ran(&fixture.step(&task));
    assert_eq!(fixture.calls(), 1);
    assert_eq!(fixture.budget(&task).settled_sends, 1);
    assert_eq!(
        fixture
            .world
            .runtime
            .store()
            .settlement(&pending.attempt_id)
            .expect("the dispatched row reads")
            .state,
        SettlementState::Dispatched,
        "the pending row stayed open"
    );
    assert_eq!(
        stopped_reason(fixture.step(&task)),
        "work send bound reached"
    );
    assert_eq!(fixture.calls(), 1);
}

#[test]
fn reserved_units_trip_the_unit_bound() {
    let mut fixture = fixture("long-work-reserved");
    let task = fixture.task.clone();
    assert!(fixture.start(&task, 600, 10, 2).get("result").is_some());

    let pending = fixture.begin_unsettled(&task);
    let held = fixture.budget(&task);
    assert_eq!(held.spent, 0);
    assert_eq!(held.reserved, 2, "the open send holds its bound");

    assert_eq!(
        stopped_reason(fixture.step(&task)),
        "work unit bound reached"
    );
    assert_eq!(fixture.calls(), 0, "the held units admit no send");
    assert_eq!(fixture.budget(&task).state, WorkBudgetState::Stopped);
    // The stop releases nothing: the pending reservation is still the send's.
    assert_eq!(
        fixture
            .world
            .runtime
            .store()
            .budget_reservation(&pending.attempt_id)
            .expect("the reservation reads")
            .state,
        BudgetReservationState::Reserved
    );
}

#[test]
fn fallback_leg_cannot_exceed_the_send_bound() {
    let mut fixture = fallback_fixture("long-work-fallback");
    let task = fixture.task.clone();
    assert!(fixture.start(&task, 600, 1, 10).get("result").is_some());

    // The primary enters and fails; the fallback leg's dispatch transaction
    // refuses at the bound the primary filled, so the step ends terminally
    // instead of sending a second physical request.
    assert_eq!(
        stopped_reason(fixture.step(&task)),
        "work send bound reached"
    );
    assert_eq!(fixture.calls(), 1, "only the entered primary was sent");
    assert_eq!(fixture.settled_rows(), 1, "one physical send settled");
    let stopped = fixture.budget(&task);
    assert_eq!(stopped.state, WorkBudgetState::Stopped);
    assert_eq!(
        stopped.stop_reason.as_deref(),
        Some("work send bound reached")
    );
    assert_eq!(
        fixture
            .world
            .runtime
            .budget_waiting_reason(&fixture.session, &task),
        None,
        "the refusal is a stop, not a wait"
    );

    assert_eq!(
        stopped_reason(fixture.step(&task)),
        "work send bound reached"
    );
    assert_eq!(fixture.calls(), 1);
}

#[test]
fn delegated_child_send_refuses_at_the_parent_bound() {
    let mut fixture = fixture("long-work-delegated-send");
    let parent = fixture.task.clone();
    let child = create_child_task(
        &mut fixture.world,
        &fixture.session,
        "long-work-delegated-child",
        &parent,
    );
    assert!(fixture.start(&parent, 600, 1, 10).get("result").is_some());
    assert!(fixture.start(&child, 600, 10, 10).get("result").is_some());

    let first = fixture
        .world
        .runtime
        .broker
        .prepare(
            "backend_task",
            &fixture.world.runtime.config_for_broker(),
            "/world/long-work",
            "goal: delegated send",
        )
        .expect("the first send prepares");
    let scopes = [parent.0.as_str(), child.0.as_str()];
    let ticket = fixture
        .world
        .runtime
        .store_writer()
        .begin_send(&scopes, &send_context(), &first)
        .expect("the first send opens");
    fixture
        .world
        .runtime
        .store_writer()
        .finish_send(
            &ticket,
            &SendOutcome::Settled {
                usage: UsageDelta::Unknown,
                wire_retries: 0,
            },
        )
        .expect("the first send settles");
    assert_eq!(fixture.budget(&parent).settled_sends, 1);

    // A second child send in the same ledger must be refused at the parent's
    // filled bound, even though the child's own bound has room.
    let second = fixture
        .world
        .runtime
        .broker
        .prepare(
            "backend_task",
            &fixture.world.runtime.config_for_broker(),
            "/world/long-work",
            "goal: delegated send two",
        )
        .expect("the second send prepares");
    let refused =
        fixture
            .world
            .runtime
            .store_writer()
            .begin_send(&scopes, &send_context(), &second);
    assert!(
        matches!(
            refused,
            Err(StoreError::Conflict(ConflictCause::WorkSendBoundReached {
                ref task_id,
                settled_sends: 1,
                send_bound: 1,
            })) if task_id == &parent.0
        ),
        "the parent bound refuses the child's second send: {refused:?}"
    );
    assert_eq!(
        fixture.status(&parent).spent,
        2,
        "the first send charged once"
    );
    assert_eq!(fixture.status(&child).spent, 2);
    assert_eq!(fixture.settled_rows(), 1, "no second physical send settled");
}

#[test]
fn parent_bound_stops_a_delegated_child_step() {
    let calls = Arc::new(AtomicU64::new(0));
    let mut world = support::open_world_with(
        "long-work-parent-bound",
        Some(&support::config_distinct_pools()),
        Box::new(QuietProvider {
            calls: calls.clone(),
        }),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-long-work-parent-bound\n").expect("scoped file");
    world.runtime.purpose = "backend_task".to_string();
    world.runtime.set_read_scope(scope, file.clone());
    world.runtime.scheduler = Scheduler::new(1, 4);
    let session = world.open_session("long-work-parent-bound-session");
    let parent = world.create_task(&session, "long-work-parent-bound-task");
    let first_child = create_child_task(&mut world, &session, "long-work-bound-child-a", &parent);
    let second_child = create_child_task(&mut world, &session, "long-work-bound-child-b", &parent);

    // Only the parent records a budget: the children draw from its level.
    let started = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 73, "method": "long_work.start",
        "params": {
            "schema_version": 1, "session_id": session.0, "task_id": parent.0,
            "deadline_seconds": 600, "send_bound": 1, "unit_bound": 10,
        }
    }));
    assert!(started.get("result").is_some(), "{started}");
    answer_task(&mut world, &session, &parent, &file);
    answer_task(&mut world, &session, &first_child, &file);
    answer_task(&mut world, &session, &second_child, &file);

    // The parent parks on its children and releases the only slot; the first
    // child's send fills the parent's bound of one.
    match world
        .runtime
        .scheduler_step(&session)
        .expect("first child step runs")
    {
        SchedulerStep::Ran { node, outcome } => {
            assert_eq!(
                world
                    .runtime
                    .scheduler
                    .node_context(node)
                    .expect("node context")
                    .task,
                first_child
            );
            assert!(
                matches!(*outcome, StepOutcome::Waiting { .. }),
                "the quiet provider leaves the step waiting, got {outcome:?}"
            );
        }
        other => panic!("expected the first child to run, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let parent_node = world
        .runtime
        .scheduler
        .node_of_task(&parent)
        .expect("parent node");
    assert_eq!(
        world
            .runtime
            .scheduler
            .state(parent_node)
            .expect("parent state"),
        NodeState::Waiting,
        "the parent still waits on its second child"
    );
    let parent_budget = world
        .runtime
        .store()
        .work_budget(&parent)
        .expect("parent budget read")
        .expect("the parent worker was recorded");
    assert_eq!(parent_budget.settled_sends, 1);

    // The second child's step is stopped by the ancestor's filled bound; the
    // child records no budget of its own.
    match world
        .runtime
        .scheduler_step(&session)
        .expect("second child step runs")
    {
        SchedulerStep::Ran { node, outcome } => {
            assert_eq!(
                world
                    .runtime
                    .scheduler
                    .node_context(node)
                    .expect("node context")
                    .task,
                second_child
            );
            assert!(
                matches!(
                    *outcome,
                    StepOutcome::WorkStopped { ref reason, .. }
                        if reason == "work send bound reached"
                ),
                "the ancestor bound stops the delegated child, got {outcome:?}"
            );
        }
        other => panic!("expected the second child to run, got {other:?}"),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the child dispatched nothing"
    );
    assert!(
        world
            .runtime
            .store()
            .work_budget(&first_child)
            .expect("child budget read")
            .is_none(),
        "the children never recorded their own budget"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .work_budget(&parent)
            .expect("parent budget read")
            .expect("parent worker")
            .state,
        WorkBudgetState::Stopped
    );
}

#[test]
fn work_stopped_projects_a_failed_output_and_a_named_observation() {
    let fixture = fixture("long-work-projection");
    let task = fixture.task.clone();
    let snapshot = fixture
        .world
        .runtime
        .store()
        .snapshot(&task)
        .expect("snapshot");
    let outcome = StepOutcome::WorkStopped {
        reason: "work unit bound reached".to_string(),
        snapshot,
    };
    assert_eq!(
        output_settlement(&outcome),
        Some(OutputSettlement::Failed {
            cause: "work unit bound reached".to_string(),
        }),
        "a terminal stop fails the stream it ends"
    );
    let observation = step_outcome_observation(
        &task,
        &AnswerSelection::Custom {
            text: "read".to_string(),
        },
        &outcome,
    );
    assert_eq!(observation.signature.tool, "read_file");
    assert_eq!(
        observation.signature.result,
        "work stopped: work unit bound reached"
    );
}

#[test]
fn parent_child_progress_and_park_use_the_one_scheduler() {
    let mut world =
        support::open_world("long-work-parent", Some(&support::config_distinct_pools()));
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-long-work-parent\n").expect("scoped file");
    world.runtime.purpose = "backend_task".to_string();
    world.runtime.set_read_scope(scope, file.clone());
    world.runtime.scheduler = Scheduler::new(1, 4);
    let session = world.open_session("long-work-parent-session");
    let parent = world.create_task(&session, "long-work-parent-task");
    let child = create_child_task(&mut world, &session, "long-work-child-task", &parent);

    for (task, command) in [(&parent, "parent-start"), (&child, "child-start")] {
        let response = world.dispatch(&json!({
            "jsonrpc": "2.0", "id": 73, "method": "long_work.start",
            "params": {
                "schema_version": 1, "session_id": session.0, "task_id": task.0,
                "deadline_seconds": 600, "send_bound": 2, "unit_bound": 10,
            }
        }));
        assert!(response.get("result").is_some(), "{command}: {response}");
    }
    answer_task(&mut world, &session, &parent, &file);
    answer_task(&mut world, &session, &child, &file);

    // PROH-002 through the one scheduler: the parent parks on its child and
    // releases the only slot, so the child's step is the one that runs.
    match world
        .runtime
        .scheduler_step(&session)
        .expect("child step runs")
    {
        SchedulerStep::Ran { node, outcome } => {
            assert_eq!(
                world
                    .runtime
                    .scheduler
                    .node_context(node)
                    .expect("node context")
                    .task,
                child
            );
            assert!(
                matches!(*outcome, StepOutcome::Completed { .. }),
                "the child completes, got {outcome:?}"
            );
        }
        other => panic!("expected the child to run, got {other:?}"),
    }
    let parent_node = world
        .runtime
        .scheduler
        .node_of_task(&parent)
        .expect("parent node");
    assert_eq!(
        world
            .runtime
            .scheduler
            .state(parent_node)
            .expect("parent state"),
        NodeState::Ready,
        "the parent parked, released the only slot and requeued on the child's completion"
    );
    assert_eq!(world.runtime.scheduler.running_count(), 0);
    assert_eq!(world.runtime.scheduler.held_units(), 0);

    // The child's send drew the shared parent level too, and the parent's own
    // step still fits its send bound of two.
    let parent_budget = world
        .runtime
        .store()
        .work_budget(&parent)
        .expect("parent budget read")
        .expect("the parent worker was recorded");
    assert_eq!(parent_budget.settled_sends, 1);
    match world
        .runtime
        .scheduler_step(&session)
        .expect("parent step runs")
    {
        SchedulerStep::Ran { node, outcome } => {
            assert_eq!(
                world
                    .runtime
                    .scheduler
                    .node_context(node)
                    .expect("node context")
                    .task,
                parent
            );
            assert!(
                matches!(*outcome, StepOutcome::Completed { .. }),
                "the resumed parent completes, got {outcome:?}"
            );
        }
        other => panic!("expected the parent to resume, got {other:?}"),
    }

    // One store, one ledger, one scheduler: both scopes keep their spend and
    // the tree drains with no node left running.
    assert_eq!(
        world
            .runtime
            .store()
            .snapshot(&parent)
            .expect("parent snapshot")
            .lifecycle,
        Lifecycle::Completed
    );
    assert_eq!(
        world
            .runtime
            .store()
            .snapshot(&child)
            .expect("child snapshot")
            .lifecycle,
        Lifecycle::Completed
    );
    assert_eq!(
        world
            .runtime
            .store()
            .budget_status(&parent.0)
            .expect("parent scope"),
        BudgetStatus {
            limit_units: 10,
            spent: 4,
            reserved: 0,
        },
        "the parent level carries both sends"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .budget_status(&child.0)
            .expect("child scope"),
        BudgetStatus {
            limit_units: 10,
            spent: 2,
            reserved: 0,
        }
    );
    assert_eq!(
        world
            .runtime
            .store()
            .work_budget(&parent)
            .expect("parent budget read")
            .expect("parent worker")
            .settled_sends,
        2
    );
    assert!(matches!(
        world.runtime.scheduler_step(&session),
        Ok(SchedulerStep::Idle)
    ));
    assert_eq!(world.runtime.scheduler.running_count(), 0);
    assert_eq!(world.runtime.scheduler.held_units(), 0);
    assert!(
        world
            .runtime
            .scheduler
            .cancel_task_tree(&parent)
            .expect("teardown of a settled tree")
            .is_empty(),
        "teardown cancels no live node and leaves the ledger as it was"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .budget_status(&parent.0)
            .expect("parent scope")
            .spent,
        4
    );
}

#[test]
fn parent_deadline_stops_a_delegated_child_step() {
    let mut fixture = fixture("long-work-parent-deadline");
    fixture.world.runtime.scheduler = Scheduler::new(1, 4);
    let parent = fixture.task.clone();
    let child = create_child_task(
        &mut fixture.world,
        &fixture.session,
        "long-work-deadline-child",
        &parent,
    );
    // Only the parent records a budget, and its deadline is already reached:
    // the child's step must read the ancestor row, not its own (there is
    // none) and not the scheduler's admission.
    assert!(fixture.start(&parent, 0, 5, 10).get("result").is_some());
    answer_task(&mut fixture.world, &fixture.session, &parent, &fixture.file);
    answer_task(&mut fixture.world, &fixture.session, &child, &fixture.file);

    match fixture
        .world
        .runtime
        .scheduler_step(&fixture.session)
        .expect("child step runs")
    {
        SchedulerStep::Ran { node, outcome } => {
            assert_eq!(
                fixture
                    .world
                    .runtime
                    .scheduler
                    .node_context(node)
                    .expect("node context")
                    .task,
                child
            );
            assert!(
                matches!(
                    *outcome,
                    StepOutcome::WorkStopped { ref reason, .. }
                        if reason == "work deadline reached"
                ),
                "the ancestor deadline stops the delegated child, got {outcome:?}"
            );
        }
        other => panic!("expected the child to run, got {other:?}"),
    }
    assert_eq!(
        fixture.calls(),
        0,
        "the expired ancestor admits no delegated send"
    );
    assert!(
        fixture
            .world
            .runtime
            .store()
            .work_budget(&child)
            .expect("child budget read")
            .is_none(),
        "the child recorded no budget of its own"
    );
    let stopped = fixture.budget(&parent);
    assert_eq!(stopped.state, WorkBudgetState::Stopped);
    assert_eq!(
        stopped.stop_reason.as_deref(),
        Some("work deadline reached")
    );
}

#[test]
fn stopped_parent_stops_a_delegated_child_step() {
    let mut fixture = fixture("long-work-parent-stopped");
    fixture.world.runtime.scheduler = Scheduler::new(1, 4);
    let parent = fixture.task.clone();
    let child = create_child_task(
        &mut fixture.world,
        &fixture.session,
        "long-work-stopped-child",
        &parent,
    );
    assert!(fixture.start(&parent, 600, 5, 10).get("result").is_some());
    assert!(fixture.stop(&parent).get("result").is_some());
    answer_task(&mut fixture.world, &fixture.session, &parent, &fixture.file);
    answer_task(&mut fixture.world, &fixture.session, &child, &fixture.file);

    // The parent parks before running, so the child is the step that reads
    // the stopped ancestor's row.
    match fixture
        .world
        .runtime
        .scheduler_step(&fixture.session)
        .expect("child step runs")
    {
        SchedulerStep::Ran { node, outcome } => {
            assert_eq!(
                fixture
                    .world
                    .runtime
                    .scheduler
                    .node_context(node)
                    .expect("node context")
                    .task,
                child
            );
            assert!(
                matches!(
                    *outcome,
                    StepOutcome::WorkStopped { ref reason, .. } if reason == "stopped"
                ),
                "the stopped ancestor stops the delegated child, got {outcome:?}"
            );
        }
        other => panic!("expected the child to run, got {other:?}"),
    }
    assert_eq!(fixture.calls(), 0, "the stopped ancestor sends nothing");
    assert_eq!(fixture.budget(&parent).state, WorkBudgetState::Stopped);
}

#[test]
fn manual_substitute_refusal_stops_at_the_send_bound() {
    let mut fixture = manual_fixture("long-work-manual");
    let task = fixture.task.clone();
    assert!(fixture.start(&task, 600, 1, 10).get("result").is_some());

    // The primary send fails and the manual fallback publishes its served
    // choice; the failed primary is the one physical send so far.
    assert_ran(&fixture.step(&task));
    assert_eq!(fixture.calls(), 1);
    assert_eq!(fixture.budget(&task).settled_sends, 1);
    assert!(
        fixture.world.runtime.paused_attempts.contains_key(&task.0),
        "the failed primary stays paused on its served choice"
    );

    let current = fixture.world.dispatch(&support::corpus_question_current(
        &fixture.session,
        &task,
        json!(4102),
    ));
    let served = current["result"]["question"].clone();
    assert_eq!(served["task_id"].as_str(), Some(task.0.as_str()));
    let options: Vec<&str> = served["options"]
        .as_array()
        .expect("options")
        .iter()
        .filter_map(|option| option["option_id"].as_str())
        .collect();
    assert_eq!(
        options,
        ["reserve"],
        "the failed primary is not a candidate"
    );
    let question: Question = serde_json::from_value(served).expect("served question parses");

    // The answer commits the manual pick; the step that dispatches the
    // substitute is stopped at the bound the failed primary filled.
    let selection = AnswerSelection::Option {
        option_id: OptionId("reserve".to_string()),
    };
    fixture
        .world
        .runtime
        .store_writer()
        .answer_question(
            &fixture.session,
            &task,
            &question.question_id,
            question.question_revision,
            &selection,
            "human",
        )
        .expect("the served choice answers");
    fixture
        .world
        .runtime
        .scheduler
        .submit_answered(task.clone(), selection, fixture.grant.clone())
        .expect("scheduler accepts the node")
        .expect("the task is outside every cancelled subtree");
    match fixture
        .world
        .runtime
        .scheduler_step(&fixture.session)
        .expect("pick step runs")
    {
        SchedulerStep::Ran { outcome, .. } => {
            assert!(
                matches!(
                    *outcome,
                    StepOutcome::WorkStopped { ref reason, .. }
                        if reason == "work send bound reached"
                ),
                "the manual substitute stops at the bound, got {outcome:?}"
            );
        }
        other => panic!("expected a step, got {other:?}"),
    }
    assert_eq!(fixture.calls(), 1, "the substitute never sent");
    assert_eq!(fixture.settled_rows(), 1, "one physical send settled");
    let stopped = fixture.budget(&task);
    assert_eq!(stopped.state, WorkBudgetState::Stopped);
    assert_eq!(
        stopped.stop_reason.as_deref(),
        Some("work send bound reached")
    );
}
