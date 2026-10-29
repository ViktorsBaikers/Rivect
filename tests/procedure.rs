//! Saved procedure segments on the real store (AC-053, REQ-043): a segment
//! derived from an executed plan runs its steps through the existing executor,
//! stops its remainder on an unknown effect, a revoked right or a fork outside
//! its snapshot, keeps every settled step with its result, and returns control
//! through the ordinary path without repeating an effect. The scheduler's own
//! step path starts the saved segment, so the stop decision is reachable in a
//! shipped run rather than only from a controller call a test builds.
//!
//! Every case drives the production seams — `TaskStore` for the plan and the
//! run, `ActionRegistry` for the plan the segment is derived from, the runtime's
//! own scheduler and executor for the step and the effects — and asserts a
//! positive discriminating observation: the durable step count, the stored
//! results and the effect sink's own counters, never "the run returned early".
//! The offline loopback is the only provider; no network and no credentials are
//! involved.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/discard conveniences; src/ stays strict (standards §14)"
)]

mod support;

use rivect::actions::{
    ActionInput, ActionOutcome, ActionRegistry, ContractBasis, PlanRequest, RequestKind, Selection,
    Surface, SurfaceScan, WorkPart,
};
use rivect::config::Config;
use rivect::contracts::{
    AnswerSelection, EffectClass, ErrorCode, KNOWN_READY_OPTION, Lifecycle, ObligationExecution,
    OptionId, Question, ResumeCondition, SessionId, TaskId,
};
use rivect::controller::{
    ControllerError, SchedulerStep, SegmentStepOutcome, StepOutcome as DecisionOutcome,
};
use rivect::executor::{EffectRequest, ReadObservation, ReadWorker, WorkerError, WriteIdentity};
use rivect::policy::PermissionMode;
use rivect::procedure::{
    ProcedureError, ProcedureRun, RunStart, RunState, SegmentBinding, SegmentTemplate, SettledStep,
    StepOutcome, StepStanding, StopTrigger,
};
use rivect::state::{PlanRowChange, PlanRowUpdate, TaskStore};
use sha2::Digest;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use support::World;

// ----- fixtures -----

fn local_config() -> String {
    "config_version = 1\n\
     [connections.local]\n\
     kind = \"local\"\n\
     endpoint = \"http://127.0.0.1:11434\"\n\
     [models.defaults]\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"procedure-fixture\" }\n\
     effort = { mode = \"auto\" }\n\
     fallback = { mode = \"auto\" }\n"
        .to_string()
}

fn plan_config() -> Config {
    Config::parse_validated(&local_config()).expect("fixture config parses")
}

/// One real step target per position, and the read sink that counts the effects
/// the segment actually performs.
struct Fixture {
    world: World,
    session: SessionId,
    task: TaskId,
    scope: PathBuf,
    targets: [PathBuf; 3],
    reads: Arc<Mutex<BTreeMap<String, u64>>>,
    /// The model dispatches the offline provider was asked to serve: the
    /// single-step path spends one, a started segment spends none.
    dispatches: Arc<AtomicU64>,
}

impl Fixture {
    fn reads(&self, path: &Path) -> u64 {
        self.reads
            .lock()
            .expect("sink lock")
            .get(&path.display().to_string())
            .copied()
            .unwrap_or(0)
    }

    fn digest(&self, path: &Path) -> String {
        let bytes = std::fs::read(path).expect("step target reads");
        format!(
            "read-performed sha256={}",
            rivect::config::hex(&sha2::Sha256::digest(&bytes))
        )
    }

    fn store(&self) -> &TaskStore {
        self.world.runtime.store()
    }

    fn grant_read(&mut self) -> String {
        let scope = self.scope.clone();
        self.world.runtime.policy_writer().grant_read(scope)
    }

    fn procedure(&mut self) -> SegmentTemplate {
        self.world
            .runtime
            .record_procedure_segment(&self.task)
            .expect("the executed plan derives a segment")
    }

    fn steps(&self, run: &ProcedureRun) -> Vec<SettledStep> {
        self.store()
            .procedure_run_steps(&run.run_id)
            .expect("the run steps read")
    }

    fn step(
        &mut self,
        procedure_id: &str,
        binding: &SegmentBinding,
        mode: PermissionMode,
    ) -> SegmentStepOutcome {
        let task = self.task.clone();
        self.world
            .runtime
            .run_procedure_step(&task, procedure_id, binding, mode, RunStart::Resume)
            .expect("the bounded step reports an outcome")
    }
}

/// A read sink over the real platform worker plus one write the sandbox could
/// not settle: the fixture write leg fails after the mutation point, which is
/// exactly the durable `unknown` the executor's settlement already records.
struct SinkWorker {
    inner: support::PlatformWorker,
    reads: Arc<Mutex<BTreeMap<String, u64>>>,
    /// The file name whose write the fixture leaves unsettled: the write lands
    /// where it cannot be confirmed, which is the durable `unknown` the executor
    /// already records for a proven mutation.
    unsettled: &'static str,
}

impl ReadWorker for SinkWorker {
    fn read_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
    ) -> Result<ReadObservation, WorkerError> {
        let observation = self.inner.read_once(scope_root, target)?;
        *self
            .reads
            .lock()
            .expect("sink lock")
            .entry(target.display().to_string())
            .or_insert(0) += 1;
        Ok(observation)
    }

    fn write_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
        expected: WriteIdentity,
        bytes: &[u8],
    ) -> Result<(), WorkerError> {
        if target.file_name() == Some(std::ffi::OsStr::new(self.unsettled)) {
            return Err(WorkerError::WriteMutationFailed {
                source: std::io::Error::other("fixture: the write may have landed"),
            });
        }
        self.inner.write_once(scope_root, target, expected, bytes)
    }
}

/// A read sink where one physical step may have run and the platform lost its
/// answer. The executor keeps exactly one durable record for that: the attempt
/// settles `unknown`, which is the condition a segment stops its remainder on
/// (EDGE-003). The unproven step is counted in physical order, so the same
/// fixture serves a segment whose live binding reads one target per step.
///
/// The executor names an unprovable settlement through one answer class
/// (`WorkerError::WriteMutationFailed`), whatever request produced it, so that
/// is what the fixture answers for the read whose confirmation is lost: there
/// is no read-shaped spelling of "the effect ran and its answer is gone".
struct UnprovenReadWorker {
    inner: support::PlatformWorker,
    reads: Arc<Mutex<BTreeMap<String, u64>>>,
    /// The 1-based physical read whose settlement is lost.
    unproven: u64,
    seen: u64,
}

impl ReadWorker for UnprovenReadWorker {
    fn read_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
    ) -> Result<ReadObservation, WorkerError> {
        self.seen += 1;
        if self.seen == self.unproven {
            return Err(WorkerError::WriteMutationFailed {
                source: std::io::Error::other("fixture: the step ran and its answer was lost"),
            });
        }
        let observation = self.inner.read_once(scope_root, target)?;
        *self
            .reads
            .lock()
            .expect("sink lock")
            .entry(target.display().to_string())
            .or_insert(0) += 1;
        Ok(observation)
    }

    fn write_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
        expected: WriteIdentity,
        bytes: &[u8],
    ) -> Result<(), WorkerError> {
        self.inner.write_once(scope_root, target, expected, bytes)
    }
}

fn fixture(tag: &str) -> Fixture {
    let reads = Arc::new(Mutex::new(BTreeMap::new()));
    let worker = SinkWorker {
        inner: support::PlatformWorker::default(),
        reads: reads.clone(),
        // The second target is the step the fixture leaves unsettled, so the
        // unknown effect lands in the middle of the segment.
        unsettled: "step-two.txt",
    };
    fixture_with(tag, Box::new(worker), reads)
}

/// A fixture whose `unproven`-th physical read leaves its settlement lost.
fn unproven_fixture(tag: &str, unproven: u64) -> Fixture {
    let reads = Arc::new(Mutex::new(BTreeMap::new()));
    let worker = UnprovenReadWorker {
        inner: support::PlatformWorker::default(),
        reads: reads.clone(),
        unproven,
        seen: 0,
    };
    fixture_with(tag, Box::new(worker), reads)
}

fn fixture_with(
    tag: &str,
    worker: Box<dyn ReadWorker>,
    reads: Arc<Mutex<BTreeMap<String, u64>>>,
) -> Fixture {
    let (provider, dispatches, _manifest) = support::CountingProvider::new();
    let mut world =
        support::open_world_with(tag, Some(&local_config()), Box::new(provider), worker);
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("create the effect scope");
    let targets = ["step-one.txt", "step-two.txt", "step-three.txt"].map(|name| scope.join(name));
    for target in &targets {
        std::fs::write(target, format!("fixture body of {}\n", target.display()))
            .expect("create the step target");
    }
    let session = world.open_session(&format!("{tag}-session"));
    let task = world.create_task(&session, &format!("{tag}-task"));
    Fixture {
        world,
        session,
        task,
        scope,
        targets,
        reads,
        dispatches,
    }
}

/// Drives one pass of the product's own step loop for the task: the answered
/// question is frozen onto a real scheduler node, and only the pass starts work.
fn scheduler_pass(fixture: &mut Fixture) -> Result<SchedulerStep, ControllerError> {
    let question = fixture.world.publish(&fixture.session, &fixture.task);
    let selection = AnswerSelection::Custom {
        text: format!("read {}", fixture.targets[0].display()),
    };
    fixture
        .world
        .runtime
        .store_writer()
        .answer_question(
            &fixture.session,
            &fixture.task,
            &question.question_id,
            question.question_revision,
            &selection,
            "human",
        )
        .expect("the answer commits");
    let grant = fixture.world.runtime.scoped_grant.clone();
    fixture
        .world
        .runtime
        .scheduler
        .submit_answered(fixture.task.clone(), selection, grant)
        .expect("the node submits");
    let session = fixture.session.clone();
    fixture.world.runtime.scheduler_step(&session)
}

fn part(id: &str, depends_on: &[&str]) -> WorkPart {
    WorkPart {
        id: id.to_string(),
        criteria: Vec::new(),
        depends_on: depends_on.iter().map(|dep| (*dep).to_string()).collect(),
        proof: format!("cargo test --test {id}"),
    }
}

fn request(
    kind: RequestKind,
    contract: ContractBasis,
    parts: Vec<WorkPart>,
    task: &TaskId,
) -> PlanRequest {
    PlanRequest {
        task_id: task.clone(),
        kind,
        surfaces: SurfaceScan::Known([Surface::Local].into()),
        contract,
        parts,
        delegation: None,
        author: None,
    }
}

fn select(world: &mut World, session: &SessionId, request: &PlanRequest) -> Selection {
    let config = plan_config();
    ActionRegistry::new()
        .select(
            request,
            &[],
            &mut world.runtime.action_context(session, &config),
        )
        .expect("the selection records")
}

fn run(world: &mut World, session: &SessionId, input: ActionInput) -> ActionOutcome {
    let config = plan_config();
    ActionRegistry::new()
        .execute(input, &mut world.runtime.action_context(session, &config))
        .expect("the plan handler runs")
}

/// Closes one plan row the way a handler does: the semantic leg of
/// `assess_plan` stands in for the broker leg, exactly as the plan suite's own
/// fixture does, so the row is a real executed step of a real plan.
fn close_row(fixture: &mut Fixture, selection: &Selection, capability: &str, output: &str) {
    fixture
        .world
        .runtime
        .store_writer()
        .update_plan_row(
            &fixture.task,
            &PlanRowUpdate {
                capability,
                handler: capability,
                selection_revision: selection.revision,
                facts_digest: &selection.facts_digest,
                change: PlanRowChange::Close {
                    execution: ObligationExecution::Satisfied,
                    outcome_json: output.to_string(),
                },
            },
        )
        .expect("the plan row closes");
}

/// Drives a real executed plan of three steps: frame, plan, assess.
fn three_step_plan(fixture: &mut Fixture) -> Selection {
    let task = fixture.task.clone();
    let plan = request(
        RequestKind::Change,
        ContractBasis::Absent,
        vec![part("schema", &[]), part("endpoint", &["schema"])],
        &task,
    );
    let selection = select(&mut fixture.world, &fixture.session, &plan);
    run(
        &mut fixture.world,
        &fixture.session,
        ActionInput::FrameGoal(plan.clone()),
    );
    run(
        &mut fixture.world,
        &fixture.session,
        ActionInput::PlanWork(plan),
    );
    close_row(
        fixture,
        &selection,
        "assess_plan",
        "{\"semantic\":\"pass\"}",
    );
    selection
}

/// Drives a real executed plan of one step: the contract is already approved,
/// so the plan records its own revision and nothing else closes.
fn one_step_plan(fixture: &mut Fixture) -> Selection {
    let task = fixture.task.clone();
    let plan = request(
        RequestKind::PlanOnly,
        ContractBasis::Approved,
        vec![part("schema", &[]), part("endpoint", &["schema"])],
        &task,
    );
    let selection = select(&mut fixture.world, &fixture.session, &plan);
    run(
        &mut fixture.world,
        &fixture.session,
        ActionInput::PlanWork(plan),
    );
    selection
}

/// The three read parameters of a segment whose steps read one target each.
fn three_reads(fixture: &mut Fixture) -> SegmentBinding {
    let (one, two, three) = (
        fixture.grant_read(),
        fixture.grant_read(),
        fixture.grant_read(),
    );
    let targets = fixture.targets.clone();
    SegmentBinding::new()
        .bind(
            1,
            EffectRequest::Read {
                grant_id: one,
                path: targets[0].clone(),
            },
        )
        .bind(
            2,
            EffectRequest::Read {
                grant_id: two,
                path: targets[1].clone(),
            },
        )
        .bind(
            3,
            EffectRequest::Read {
                grant_id: three,
                path: targets[2].clone(),
            },
        )
}

fn stop_of(outcome: SegmentStepOutcome) -> ProcedureRun {
    match outcome {
        SegmentStepOutcome::Stopped { run, .. } => run,
        other => panic!("the remainder must stop, got {other:?}"),
    }
}

fn settled_of(outcome: SegmentStepOutcome) -> (ProcedureRun, SettledStep) {
    match outcome {
        SegmentStepOutcome::Stepped { run, step } => (run, step),
        other => panic!("one step must settle and the segment continue, got {other:?}"),
    }
}

// ----- cases -----

/// AC-053 / EDGE-003: a 3-step segment whose second effect settles `unknown`
/// stops the remainder, keeps step one's result, and leaves the executed-step
/// count where the stop found it.
#[test]
fn unknown_effect_stops_the_remainder_p1() {
    let mut fixture = fixture("p1");
    three_step_plan(&mut fixture);
    let segment = fixture.procedure();
    assert_eq!(segment.steps.len(), 3, "the executed plan has three steps");
    assert_eq!(
        segment
            .steps
            .iter()
            .map(|step| step.tool.as_str())
            .collect::<Vec<_>>(),
        vec!["frame_goal", "plan_work", "assess_plan"],
        "the steps are the plan rows that closed, in selection order"
    );
    // The saved record names what a later run must honour: the tool and schema
    // it ran under, the conditions it stops on, and each step's expected output.
    assert_eq!(segment.tool_version, rivect::executor::backend());
    assert_eq!(
        segment.schema_version,
        rivect::procedure::PROCEDURE_SCHEMA_VERSION
    );
    assert_eq!(
        segment.stop_conditions,
        vec![
            StopTrigger::NewMaterialChoice,
            StopTrigger::RevokedRight,
            StopTrigger::UnknownEffect
        ],
        "the saved segment names every condition it stops on"
    );
    let saved = fixture
        .store()
        .procedure_segment(&segment.procedure_id)
        .expect("the saved segment reads back");
    assert_eq!(saved, segment, "the saved segment is the derived one");
    assert_eq!(
        saved.steps[2].expected_output, "{\"semantic\":\"pass\"}",
        "every step kept the output the executed plan produced"
    );
    assert_eq!(saved.steps[0].tool, "frame_goal");
    assert_eq!(saved.steps[1].tool, "plan_work");
    let scope_key = fixture
        .scope
        .canonicalize()
        .expect("the scope canonicalizes");
    fixture
        .world
        .runtime
        .store_writer()
        .open_budget(scope_key.to_str().expect("scope is utf-8"), 8)
        .expect("the write step's budget opens");
    let (read_one, read_three) = (fixture.grant_read(), fixture.grant_read());
    let write_scope = fixture.scope.clone();
    let write_grant = fixture
        .world
        .runtime
        .policy_writer()
        .grant_classes(write_scope, vec![EffectClass::Write]);
    let targets = fixture.targets.clone();
    let binding = SegmentBinding::new()
        .bind(
            1,
            EffectRequest::Read {
                grant_id: read_one,
                path: targets[0].clone(),
            },
        )
        .bind(
            2,
            EffectRequest::Write {
                grant_id: write_grant,
                path: targets[1].clone(),
                bytes: b"step two".to_vec(),
            },
        )
        .bind(
            3,
            EffectRequest::Read {
                grant_id: read_three,
                path: targets[2].clone(),
            },
        );
    let procedure_id = segment.procedure_id.clone();
    let (run, step) = settled_of(fixture.step(&procedure_id, &binding, PermissionMode::Auto));
    assert_eq!(step.position, 1, "the first step is the one that settled");
    assert_eq!(
        step.result,
        fixture.digest(&targets[0]),
        "step one's result is readable"
    );
    assert_eq!(run.cursor, 1);

    let run = stop_of(fixture.step(&procedure_id, &binding, PermissionMode::Auto));
    assert_eq!(run.state, RunState::Stopped, "the remainder did not run");
    let stop = run.stop.clone().expect("the stop is recorded");
    assert_eq!(stop.trigger, StopTrigger::UnknownEffect);

    // The executed-step count and every completed result are read back from the
    // store, not from the returned value.
    let steps = fixture.steps(&run);
    assert_eq!(steps.len(), 1, "only the settled step has a row");
    assert_eq!(steps[0].position, 1);
    assert_eq!(steps[0].result, fixture.digest(&targets[0]));
    // The step whose outcome is unknown stays prepared: it is the run's own
    // durable marker that its effect may have landed, so no continuation
    // re-issues it even once the attempt is reconciled.
    let prepared = fixture
        .store()
        .prepared_procedure_step(&run.run_id)
        .expect("the prepared step reads")
        .expect("the unsettled step keeps its row");
    assert_eq!(
        prepared.position, 2,
        "the unsettled step is never re-issued"
    );
    assert_eq!(
        prepared.standing,
        StepStanding::Unresolved,
        "the row and the attempt that may have landed stay together"
    );

    // Control returned through the ordinary path: the task is blocked on the
    // same reconciliation blocker the projection already owns.
    let snapshot = fixture.store().snapshot(&fixture.task).expect("snapshot");
    assert_eq!(snapshot.lifecycle, Lifecycle::Blocked);
    assert!(
        snapshot
            .blockers
            .clone()
            .unwrap_or_default()
            .iter()
            .any(|blocker| blocker.reason == ErrorCode::OutcomeUnknown
                && matches!(blocker.condition, ResumeCondition::Reconciliation { .. })),
        "the task's own blocker names the unknown effect"
    );

    // No new effect was performed, and a resume attempt does not add one.
    assert_eq!(fixture.reads(&targets[0]), 1);
    assert_eq!(fixture.reads(&targets[2]), 0, "the remainder never ran");
    let run = stop_of(fixture.step(&procedure_id, &binding, PermissionMode::Auto));
    assert_eq!(run.cursor, 1, "the executed-step count does not grow");
    assert_eq!(fixture.steps(&run).len(), 1);
    assert_eq!(
        fixture.reads(&targets[0]),
        1,
        "the settled step is not repeated"
    );
    assert_eq!(fixture.reads(&targets[2]), 0);
}

/// AC-053 / EDGE-004: a right revoked between the steps stops the rest, and the
/// steps that settled keep their results.
#[test]
fn revoked_right_stops_the_remainder_p2() {
    let mut fixture = fixture("p2");
    three_step_plan(&mut fixture);
    let segment = fixture.procedure();
    let binding = three_reads(&mut fixture);
    let procedure_id = segment.procedure_id.clone();
    let targets = fixture.targets.clone();

    let (run, step) = settled_of(fixture.step(&procedure_id, &binding, PermissionMode::Manual));
    assert_eq!(step.position, 1);
    assert_eq!(step.result, fixture.digest(&targets[0]));
    assert_eq!(run.cursor, 1);

    // Two completed steps, both with their own result, before the third is
    // refused: the count the stop leaves behind is what the store holds.
    let (run, step) = settled_of(fixture.step(&procedure_id, &binding, PermissionMode::Manual));
    assert_eq!(step.position, 2);
    assert_eq!(step.result, fixture.digest(&targets[1]));
    assert_eq!(run.cursor, 2);

    // The third step's right is revoked between the steps: the effect-time
    // re-check refuses it and nothing else runs.
    let revoked = binding
        .request(3)
        .expect("step three is bound")
        .grant_id()
        .to_string();
    fixture.world.runtime.policy_writer().revoke(&revoked);

    let run = stop_of(fixture.step(&procedure_id, &binding, PermissionMode::Manual));
    assert_eq!(run.state, RunState::Stopped);
    let stop = run.stop.clone().expect("the stop is recorded");
    assert_eq!(stop.trigger, StopTrigger::RevokedRight);
    assert!(
        stop.detail.contains(&revoked),
        "the stop names the revoked right: {}",
        stop.detail
    );

    let steps = fixture.steps(&run);
    assert_eq!(steps.len(), 2, "both completed steps keep their row");
    assert_eq!(steps[0].position, 1);
    assert_eq!(steps[0].result, fixture.digest(&targets[0]));
    assert_eq!(steps[1].position, 2);
    assert_eq!(steps[1].result, fixture.digest(&targets[1]));
    assert_eq!(run.cursor, 2, "the cursor reached the second step");
    // The refused step ran no effect, so its row is released: what a stop keeps
    // is only a step whose attempt could have landed.
    assert_eq!(
        fixture
            .store()
            .prepared_procedure_step(&run.run_id)
            .expect("the prepared step reads"),
        None,
        "a refused step leaves no prepared row behind"
    );
    assert_eq!(fixture.reads(&targets[0]), 1);
    assert_eq!(fixture.reads(&targets[1]), 1);
    assert_eq!(
        fixture.reads(&targets[2]),
        0,
        "the refused step ran no effect"
    );
    // A refusal that ran nothing leaves no unknown-outcome block behind: the
    // blocker a caller reads is the task's own projection, not the stop record.
    assert!(
        !fixture
            .store()
            .snapshot(&fixture.task)
            .expect("snapshot")
            .blockers
            .unwrap_or_default()
            .iter()
            .any(|blocker| blocker.reason == ErrorCode::OutcomeUnknown),
        "a refused step is not an unknown effect"
    );

    // A further attempt still does not grow the executed-step count.
    let run = stop_of(fixture.step(&procedure_id, &binding, PermissionMode::Manual));
    assert_eq!(run.cursor, 2);
    assert_eq!(fixture.steps(&run).len(), 2);
    assert_eq!(fixture.reads(&targets[2]), 0);
}

/// AC-053: a fork the segment's snapshot never held stops the remainder and
/// returns control to the path that already waits on it.
#[test]
fn new_material_choice_stops_the_remainder_p3() {
    let mut fixture = fixture("p3");
    three_step_plan(&mut fixture);
    let segment = fixture.procedure();
    let binding = three_reads(&mut fixture);
    let procedure_id = segment.procedure_id.clone();
    let targets = fixture.targets.clone();

    let (run, step) = settled_of(fixture.step(&procedure_id, &binding, PermissionMode::Manual));
    assert_eq!(step.position, 1);
    assert_eq!(run.cursor, 1);

    // A real fork question with a new revision, published between the steps.
    let mut question = Question::fixture(&fixture.task, 1);
    question.question_revision = 2;
    let session = fixture.session.clone();
    fixture
        .world
        .runtime
        .store_writer()
        .publish_question(&session, &question)
        .expect("the fork publishes");

    let outcome = fixture.step(&procedure_id, &binding, PermissionMode::Manual);
    let snapshot = match &outcome {
        SegmentStepOutcome::Stopped { snapshot, .. } => snapshot.clone(),
        other => panic!("the segment must stop on the new fork, got {other:?}"),
    };
    let run = stop_of(outcome);
    assert_eq!(run.state, RunState::Stopped);
    let stop = run.stop.clone().expect("the stop is recorded");
    assert_eq!(stop.trigger, StopTrigger::NewMaterialChoice);
    assert!(
        stop.detail.contains(&question.question_id.0),
        "the stop names the fork: {}",
        stop.detail
    );
    assert!(
        stop.detail.contains("revision 2"),
        "the stop names its revision"
    );

    // The returned snapshot is the ordinary answer for that fork.
    assert_eq!(snapshot.lifecycle, Lifecycle::Waiting);
    assert!(
        snapshot
            .blockers
            .clone()
            .unwrap_or_default()
            .iter()
            .any(|blocker| matches!(
                &blocker.condition,
                ResumeCondition::Decision { question_id, revision }
                    if question_id == &question.question_id && *revision == 2
            )),
        "the task waits on the same fork the segment stopped for"
    );

    let steps = fixture.steps(&run);
    assert_eq!(steps.len(), 1, "the completed step keeps its row");
    assert_eq!(steps[0].position, 1);
    assert_eq!(steps[0].result, fixture.digest(&targets[0]));
    assert_eq!(fixture.reads(&targets[0]), 1);
    assert_eq!(
        fixture.reads(&targets[1]),
        0,
        "the loop never reached step two"
    );
    assert_eq!(fixture.reads(&targets[2]), 0, "the remainder never ran");
}

/// AC-053 / PROH-003: a resume attempt after a stop leaves the store and the
/// effect sink each seeing the completed step exactly once.
#[test]
fn completed_effect_is_never_repeated_p4() {
    let mut fixture = fixture("p4");
    three_step_plan(&mut fixture);
    let segment = fixture.procedure();
    let binding = three_reads(&mut fixture);
    let procedure_id = segment.procedure_id.clone();
    let targets = fixture.targets.clone();

    let (run, step) = settled_of(fixture.step(&procedure_id, &binding, PermissionMode::Manual));
    assert_eq!(step.position, 1);
    let run_id = run.run_id.clone();

    // The remainder stops on a fork; the segment is now resumable from the step
    // it actually reached.
    let mut question = Question::fixture(&fixture.task, 1);
    question.question_revision = 3;
    let session = fixture.session.clone();
    fixture
        .world
        .runtime
        .store_writer()
        .publish_question(&session, &question)
        .expect("the fork publishes");
    let stopped = stop_of(fixture.step(&procedure_id, &binding, PermissionMode::Manual));
    assert_eq!(stopped.run_id, run_id, "the resume continues the same run");
    assert_eq!(stopped.cursor, 1);

    let settled_before = fixture.steps(&stopped);
    assert_eq!(settled_before.len(), 1);
    assert_eq!(fixture.reads(&targets[0]), 1);

    // The block is cleared the way the normal path clears it: the answer to the
    // fork it stopped for, so the run's snapshot and the live state agree again.
    fixture
        .world
        .runtime
        .store_writer()
        .answer_question(
            &session,
            &fixture.task,
            &question.question_id,
            question.question_revision,
            &AnswerSelection::Option {
                option_id: OptionId(KNOWN_READY_OPTION.to_string()),
            },
            "human",
        )
        .expect("the fork is answered");

    // The resume continues after the settled step and actually executes the
    // next one: the step count grows by exactly one and no target is read twice.
    let (resumed, step) = settled_of(fixture.step(&procedure_id, &binding, PermissionMode::Manual));
    assert_eq!(resumed.run_id, run_id, "the resume continues the same run");
    assert_eq!(step.position, 2, "the resume ran the next step");
    assert_eq!(resumed.state, RunState::Running);
    assert_eq!(
        resumed.cursor, 2,
        "the resume starts after the settled step"
    );
    let settled_after = fixture.steps(&resumed);
    assert_eq!(settled_after.len(), 2, "the store holds both settled steps");
    assert_eq!(settled_after[0].position, 1);
    assert_eq!(settled_after[0].result, settled_before[0].result);
    assert_eq!(settled_after[1].position, 2);
    assert_eq!(settled_after[1].result, fixture.digest(&targets[1]));
    assert_eq!(
        fixture.reads(&targets[0]),
        1,
        "the completed effect is not re-issued"
    );
    assert_eq!(fixture.reads(&targets[1]), 1, "the resumed step ran once");
    assert_eq!(fixture.reads(&targets[2]), 0);
}

/// AC-053, spec edge cases: a one-step segment has no remainder — stop and
/// completion coincide, and no partial remainder row exists.
#[test]
fn single_step_segment_has_no_remainder_p5() {
    let mut fixture = fixture("p5");
    one_step_plan(&mut fixture);
    let segment = fixture.procedure();
    assert_eq!(segment.steps.len(), 1, "the executed plan has one step");
    assert_eq!(segment.steps[0].tool, "plan_work");
    assert!(
        segment.remainder_after(0).len() == 1,
        "the single step is the whole segment"
    );
    assert!(
        segment.remainder_after(1).is_empty(),
        "a one-step segment has no remainder"
    );
    let binding = three_reads(&mut fixture);
    let procedure_id = segment.procedure_id.clone();
    let targets = fixture.targets.clone();

    let outcome = fixture.step(&procedure_id, &binding, PermissionMode::Manual);
    let run = match outcome {
        SegmentStepOutcome::Completed { run, .. } => run,
        other => panic!("one step completes as one unit, got {other:?}"),
    };
    assert_eq!(run.state, RunState::Completed);
    assert_eq!(run.cursor, 1);
    assert!(run.stop.is_none(), "completion is not a stop");
    assert!(run.remainder(&segment).is_empty());

    let steps = fixture.steps(&run);
    assert_eq!(steps.len(), 1, "the one step settled once");
    assert_eq!(steps[0].position, 1);
    assert_eq!(steps[0].result, fixture.digest(&targets[0]));
    assert_eq!(fixture.reads(&targets[0]), 1);
    assert_eq!(
        fixture.reads(&targets[1]),
        0,
        "no partial remainder row ran"
    );
}

/// Master §12.9: every value of a new run is validated again. A saved segment
/// whose selection moved is refused before its first effect.
#[test]
fn superseded_segment_refuses_before_any_effect_p6() {
    let mut fixture = fixture("p6");
    three_step_plan(&mut fixture);
    let segment = fixture.procedure();
    let binding = three_reads(&mut fixture);
    let targets = fixture.targets.clone();

    // A new selection: same task, different facts, so the saved segment's
    // selection revision is no longer the current one.
    let task = fixture.task.clone();
    let replanned = request(
        RequestKind::PlanOnly,
        ContractBasis::Approved,
        vec![part("schema", &[]), part("endpoint", &["schema"])],
        &task,
    );
    select(&mut fixture.world, &fixture.session, &replanned);

    let procedure_id = segment.procedure_id.clone();
    let error = fixture
        .world
        .runtime
        .run_procedure_step(
            &task,
            &procedure_id,
            &binding,
            PermissionMode::Manual,
            RunStart::Resume,
        )
        .expect_err("a superseded segment is refused");
    assert!(
        matches!(
            &error,
            ControllerError::Procedure(ProcedureError::PlanSuperseded { .. })
        ),
        "{error}"
    );
    assert_eq!(fixture.reads(&targets[0]), 0, "no effect ran");
    assert_eq!(fixture.reads(&targets[1]), 0);
    assert_eq!(fixture.reads(&targets[2]), 0);
    // The durable value the refusal read: the task's selection moved past the
    // one the saved segment names.
    let current = fixture
        .store()
        .plan_selection(&task)
        .expect("the selection reads")
        .expect("the fixture recorded a selection");
    assert!(
        current.revision > segment.selection_revision,
        "the segment names selection {} and the task is on {}",
        segment.selection_revision,
        current.revision
    );
}

/// AC-053 / PROH-003: a completed segment is not run a second time by default,
/// so a later start cannot issue the effects it already performed.
#[test]
fn completed_segment_refuses_a_second_run() {
    let mut fixture = fixture("p7");
    three_step_plan(&mut fixture);
    let segment = fixture.procedure();
    let binding = three_reads(&mut fixture);
    let procedure_id = segment.procedure_id.clone();
    let targets = fixture.targets.clone();

    settled_of(fixture.step(&procedure_id, &binding, PermissionMode::Manual));
    settled_of(fixture.step(&procedure_id, &binding, PermissionMode::Manual));
    let completed = match fixture.step(&procedure_id, &binding, PermissionMode::Manual) {
        SegmentStepOutcome::Completed { run, .. } => run,
        other => panic!("the last step completes the run, got {other:?}"),
    };
    assert_eq!(completed.state, RunState::Completed);
    assert_eq!(completed.cursor, 3);

    let task = fixture.task.clone();
    let error = fixture
        .world
        .runtime
        .run_procedure_step(
            &task,
            &procedure_id,
            &binding,
            PermissionMode::Manual,
            RunStart::Resume,
        )
        .expect_err("a completed segment is not re-run by default");
    assert!(
        matches!(
            &error,
            ControllerError::Procedure(ProcedureError::AlreadyCompleted { .. })
        ),
        "{error}"
    );
    // The refusal performed nothing: every target was read exactly once.
    assert_eq!(fixture.reads(&targets[0]), 1);
    assert_eq!(fixture.reads(&targets[1]), 1);
    assert_eq!(fixture.reads(&targets[2]), 1);

    // The explicit request is what runs the segment again, from the first step.
    let fresh = fixture
        .world
        .runtime
        .run_procedure_step(
            &task,
            &procedure_id,
            &binding,
            PermissionMode::Manual,
            RunStart::Fresh,
        )
        .expect("a fresh start opens a second run");
    let fresh = match fresh {
        SegmentStepOutcome::Stepped { run, step } => {
            assert_eq!(step.position, 1, "a fresh run starts at the first step");
            run
        }
        other => panic!("the first step of a fresh run settles, got {other:?}"),
    };
    assert_eq!(fresh.state, RunState::Running);
    assert_eq!(fresh.cursor, 1);
    assert_ne!(fresh.run_id, completed.run_id, "a new run, not the old one");
    assert_eq!(
        fixture.reads(&targets[0]),
        2,
        "only the explicit request issues the effect again"
    );
}

/// AC-053 / PROH-003: an attempt that ran and never settled is the durable
/// proof that an effect may have landed, so the segment issues no step past it.
#[test]
fn unsettled_running_attempt_stops_the_segment() {
    let mut fixture = fixture("p8");
    three_step_plan(&mut fixture);
    let segment = fixture.procedure();
    let binding = three_reads(&mut fixture);
    let targets = fixture.targets.clone();
    let task = fixture.task.clone();

    // An effect that reached the worker and never settled leaves the attempt
    // running: nothing recorded whether it landed. A directory is the cheapest
    // target the worker refuses, and the failure lands after the running gate.
    let grant = fixture.grant_read();
    let directory = fixture.scope.join("not-a-file");
    std::fs::create_dir(&directory).expect("the refused target exists");
    let admitted = fixture
        .world
        .runtime
        .executor()
        .admit(
            &task,
            EffectRequest::Read {
                grant_id: grant,
                path: directory,
            },
            PermissionMode::Manual,
        )
        .expect("the read admits");
    fixture
        .world
        .runtime
        .executor()
        .execute_unconfirmed(&admitted)
        .expect_err("the missing target fails the read");
    let attempt = admitted.attempt_id.clone();
    assert_eq!(
        fixture
            .store()
            .attempt_state(&attempt)
            .expect("the attempt reads"),
        Some("running".to_string()),
        "the interrupted effect left its attempt unresolved"
    );

    let run = stop_of(fixture.step(&segment.procedure_id, &binding, PermissionMode::Manual));
    let stop = run.stop.clone().expect("the stop is recorded");
    assert_eq!(stop.trigger, StopTrigger::UnknownEffect);
    assert!(
        stop.detail.contains(&attempt),
        "the stop names the unresolved attempt: {}",
        stop.detail
    );
    assert_eq!(run.cursor, 0, "no step ran past the unresolved attempt");
    assert_eq!(fixture.steps(&run).len(), 0);
    assert_eq!(fixture.reads(&targets[0]), 0, "no effect was issued");
}

/// AC-053: a segment that reaches its last step completes with every result
/// readable — three settled rows, the cursor at the last step, nothing ahead.
#[test]
fn three_step_segment_completes_with_every_result() {
    let mut fixture = fixture("p9");
    three_step_plan(&mut fixture);
    let segment = fixture.procedure();
    let binding = three_reads(&mut fixture);
    let procedure_id = segment.procedure_id.clone();
    let targets = fixture.targets.clone();

    settled_of(fixture.step(&procedure_id, &binding, PermissionMode::Manual));
    settled_of(fixture.step(&procedure_id, &binding, PermissionMode::Manual));
    let completed = match fixture.step(&procedure_id, &binding, PermissionMode::Manual) {
        SegmentStepOutcome::Completed { run, .. } => run,
        other => panic!("the last step completes the run, got {other:?}"),
    };
    assert_eq!(completed.state, RunState::Completed);
    assert_eq!(completed.cursor, 3, "every step settled");
    assert!(completed.stop.is_none(), "completion is not a stop");
    assert!(
        completed.remainder(&segment).is_empty(),
        "a completed run has nothing ahead of it"
    );
    let steps = fixture.steps(&completed);
    assert_eq!(steps.len(), 3);
    for (step, target) in steps.iter().zip(targets.iter()) {
        assert_eq!(
            step.result,
            fixture.digest(target),
            "step {} kept its own result",
            step.position
        );
    }
    assert_eq!(
        steps.iter().map(|step| step.position).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "the rows are the three steps in order"
    );
    assert_eq!(fixture.reads(&targets[0]), 1);
    assert_eq!(fixture.reads(&targets[1]), 1);
    assert_eq!(fixture.reads(&targets[2]), 1);
}

/// AC-053 / PROH-003: a step whose attempt never reached its effect is released
/// rather than blocking the run, and the step it recorded is the one that runs.
#[test]
fn prepared_step_that_never_started_is_released_and_reissued() {
    let mut fixture = fixture("p10");
    three_step_plan(&mut fixture);
    let segment = fixture.procedure();
    let binding = three_reads(&mut fixture);
    let procedure_id = segment.procedure_id.clone();
    let targets = fixture.targets.clone();
    let task = fixture.task.clone();

    let (run, _) = settled_of(fixture.step(&procedure_id, &binding, PermissionMode::Manual));
    assert_eq!(run.cursor, 1);

    // The interruption: the step was prepared, its effect was refused before the
    // worker ran, and the call that would have released the row never returned.
    let grant = fixture.grant_read();
    let directory = fixture.scope.join("not-a-file");
    std::fs::create_dir(&directory).expect("the refused target exists");
    let interrupted = SegmentBinding::new().bind(
        2,
        EffectRequest::Read {
            grant_id: grant,
            path: directory,
        },
    );
    fixture
        .world
        .runtime
        .executor()
        .run_segment_step(&task, &segment, &run, &interrupted, PermissionMode::Manual)
        .expect_err("the missing target refuses the step");

    // The durable record names the attempt that never started, so the step is
    // provably not one that may have landed.
    let prepared = fixture
        .store()
        .prepared_procedure_step(&run.run_id)
        .expect("the prepared step reads")
        .expect("the interrupted step keeps its row");
    assert_eq!(prepared.position, 2);
    assert_eq!(prepared.standing, StepStanding::NotStarted);
    assert_eq!(
        fixture
            .store()
            .attempt_state(&prepared.attempt_id)
            .expect("the attempt reads"),
        Some("rejected".to_string()),
        "the attempt never reached the effect"
    );

    // Nothing of it holds the run: the next call releases the row and runs the
    // step it recorded, once.
    let (run, step) = settled_of(fixture.step(&procedure_id, &binding, PermissionMode::Manual));
    assert_eq!(step.position, 2);
    assert_eq!(run.cursor, 2);
    assert_eq!(fixture.steps(&run).len(), 2);
    assert_eq!(
        fixture
            .store()
            .prepared_procedure_step(&run.run_id)
            .expect("the prepared step reads"),
        None,
        "a step that never started leaves nothing behind"
    );
    assert_eq!(fixture.reads(&targets[0]), 1);
    assert_eq!(fixture.reads(&targets[1]), 1);
    assert_eq!(fixture.reads(&targets[2]), 0);
}

/// AC-053 / PROH-003: a step whose effect landed and whose settlement was lost
/// is settled from the ledger, never run again.
#[test]
fn landed_step_settles_from_the_ledger_instead_of_running_again() {
    let mut fixture = fixture("p11");
    three_step_plan(&mut fixture);
    let segment = fixture.procedure();
    let binding = three_reads(&mut fixture);
    let procedure_id = segment.procedure_id.clone();
    let targets = fixture.targets.clone();
    let task = fixture.task.clone();

    let (run, _) = settled_of(fixture.step(&procedure_id, &binding, PermissionMode::Manual));
    assert_eq!(run.cursor, 1);

    // The effect lands and the run's own settlement is lost: the step ran, the
    // ledger kept its result, and the row stayed prepared.
    let outcome = fixture
        .world
        .runtime
        .executor()
        .run_segment_step(&task, &segment, &run, &binding, PermissionMode::Manual)
        .expect("the step performs its effect");
    let (attempt_id, result) = match outcome {
        StepOutcome::Settled { attempt_id, result } => (attempt_id, result),
        other => panic!("the read settles, got {other:?}"),
    };
    assert_eq!(result, fixture.digest(&targets[1]));
    assert_eq!(fixture.reads(&targets[1]), 1);
    let prepared = fixture
        .store()
        .prepared_procedure_step(&run.run_id)
        .expect("the prepared step reads")
        .expect("the landed step keeps its row");
    assert_eq!(prepared.position, 2);
    assert_eq!(prepared.attempt_id, attempt_id);
    assert_eq!(prepared.standing, StepStanding::Landed);

    // The next call completes the lost settlement from the ledger and runs the
    // final step: the effect that already landed is not issued a second time.
    let completed = match fixture.step(&procedure_id, &binding, PermissionMode::Manual) {
        SegmentStepOutcome::Completed { run, .. } => run,
        other => panic!("the ledger settlement completes the run, got {other:?}"),
    };
    assert_eq!(completed.state, RunState::Completed);
    assert_eq!(completed.cursor, 3);
    let steps = fixture.steps(&completed);
    assert_eq!(steps.len(), 3);
    assert_eq!(steps[1].position, 2);
    assert_eq!(
        steps[1].attempt_id, attempt_id,
        "the step keeps the attempt that landed"
    );
    assert_eq!(steps[1].result, result, "the result comes from the ledger");
    assert_eq!(steps[2].position, 3);
    assert_eq!(fixture.reads(&targets[0]), 1);
    assert_eq!(
        fixture.reads(&targets[1]),
        1,
        "the landed effect is not re-issued"
    );
    assert_eq!(fixture.reads(&targets[2]), 1);
}

/// AC-053: the product's own step path starts the saved segment. Its steps run
/// through the executor's admission, and an effect that may have landed stops
/// the remainder with the completed step kept and control returned.
#[test]
fn scheduler_runs_the_saved_segment_p1() {
    // The second physical step may have run and lost its answer, so the segment
    // reaches its unknown-effect condition in the middle of the run.
    let mut fixture = unproven_fixture("p12-scheduler", 2);
    three_step_plan(&mut fixture);
    let segment = fixture.procedure();
    assert_eq!(segment.steps.len(), 3, "the executed plan has three steps");
    let target = fixture.targets[0].clone();
    // The live parameter this run binds: the read the task is permitted now.
    fixture
        .world
        .runtime
        .set_read_scope(fixture.scope.clone(), target.clone());

    let outcome = scheduler_pass(&mut fixture).expect("the pass runs");
    let snapshot = match outcome {
        SchedulerStep::Ran { outcome, .. } => match *outcome {
            DecisionOutcome::OutcomeUnknown {
                attempt_id,
                snapshot,
            } => {
                assert!(!attempt_id.is_empty(), "the unknown attempt is named");
                snapshot
            }
            other => panic!("the second step may have landed, got {other:?}"),
        },
        other => panic!("the answered task is admitted and stepped, got {other:?}"),
    };
    // Control returned through the ordinary path: the blocker the
    // unknown-outcome projection already owns.
    assert_eq!(snapshot.lifecycle, Lifecycle::Blocked);
    assert!(
        snapshot
            .blockers
            .clone()
            .unwrap_or_default()
            .iter()
            .any(|blocker| blocker.reason == ErrorCode::OutcomeUnknown
                && matches!(blocker.condition, ResumeCondition::Reconciliation { .. })),
        "the task's own blocker names the unknown effect"
    );
    // The segment pre-empted the blind single step, and the remainder issued no
    // effect: one step settled, so the sink saw exactly one read.
    assert_eq!(
        fixture.dispatches.load(Ordering::SeqCst),
        0,
        "the saved segment runs before the single-step path"
    );
    assert_eq!(
        fixture.reads(&target),
        1,
        "only the first step performed an effect"
    );

    // The run the scheduler started keeps its completed step and stopped before
    // the rest: the next attempt continues that run and repeats nothing.
    let binding = three_reads(&mut fixture);
    let procedure_id = segment.procedure_id.clone();
    let run = stop_of(fixture.step(&procedure_id, &binding, PermissionMode::Manual));
    assert_eq!(run.state, RunState::Stopped);
    assert_eq!(
        run.stop.clone().expect("the stop is recorded").trigger,
        StopTrigger::UnknownEffect
    );
    assert_eq!(run.cursor, 1, "only the first step settled");
    let steps = fixture.steps(&run);
    assert_eq!(steps.len(), 1, "the completed step keeps its row");
    assert_eq!(steps[0].position, 1);
    assert_eq!(
        steps[0].result,
        fixture.digest(&target),
        "the completed step's result is readable"
    );
    assert_eq!(
        fixture.reads(&target),
        1,
        "the stop issued no further effect"
    );
    assert_eq!(
        fixture.reads(&fixture.targets[1]),
        0,
        "the next step never performed its effect"
    );
    assert_eq!(fixture.dispatches.load(Ordering::SeqCst), 0);
}

/// AC-053 positive control: a task with no saved segment steps exactly as
/// today — one dispatch, one permitted read, the completed task.
#[test]
fn scheduler_without_a_segment_is_unchanged_p2() {
    let mut fixture = fixture("p13-no-segment");
    let target = fixture.targets[0].clone();
    fixture
        .world
        .runtime
        .set_read_scope(fixture.scope.clone(), target.clone());

    let outcome = scheduler_pass(&mut fixture).expect("the pass runs");
    let snapshot = match outcome {
        SchedulerStep::Ran { outcome, .. } => match *outcome {
            DecisionOutcome::Completed { snapshot } => snapshot,
            other => panic!("the unchanged step completes, got {other:?}"),
        },
        other => panic!("the answered task is admitted and stepped, got {other:?}"),
    };
    assert_eq!(snapshot.lifecycle, Lifecycle::Completed);
    assert_eq!(
        fixture.dispatches.load(Ordering::SeqCst),
        1,
        "the single-step path spends its one dispatch"
    );
    assert_eq!(
        fixture.reads(&target),
        1,
        "the one permitted read is performed"
    );
}

/// AC-053: the parameters a run binds come from its own snapshot, never from the
/// recording — every step performs the read this run is permitted now, and its
/// result names the live file rather than the output the plan recorded.
#[test]
fn segment_binding_uses_the_current_snapshot_p3() {
    // The third physical step may have run and lost its answer, so two steps
    // settle through the scheduler and their results stay readable.
    let mut fixture = unproven_fixture("p14-snapshot", 3);
    three_step_plan(&mut fixture);
    let segment = fixture.procedure();
    let target = fixture.targets[0].clone();
    // The live target moved after the recording: the run reads this file now,
    // and the recorded expected output is not what a step performs.
    std::fs::write(&target, "the snapshot this run starts from\n")
        .expect("the live target is rewritten");
    fixture
        .world
        .runtime
        .set_read_scope(fixture.scope.clone(), target.clone());
    let recorded = segment.steps[0].expected_output.clone();

    let outcome = scheduler_pass(&mut fixture).expect("the pass runs");
    assert!(
        matches!(outcome, SchedulerStep::Ran { .. }),
        "the saved segment starts on the step path, got {outcome:?}"
    );
    assert_eq!(
        fixture.reads(&target),
        2,
        "both settled steps performed the live read"
    );
    let live = fixture.digest(&target);
    assert_ne!(live, recorded, "the recording is not what a step performs");

    let binding = three_reads(&mut fixture);
    let procedure_id = segment.procedure_id.clone();
    let run = stop_of(fixture.step(&procedure_id, &binding, PermissionMode::Manual));
    assert_eq!(
        run.state,
        RunState::Stopped,
        "the third step may have landed"
    );
    assert_eq!(run.cursor, 2);
    let steps = fixture.steps(&run);
    assert_eq!(steps.len(), 2, "both completed steps are readable");
    for step in &steps {
        assert_eq!(
            step.result, live,
            "step {} bound the run's live snapshot",
            step.position
        );
        assert_ne!(step.result, recorded);
    }
    assert_eq!(
        fixture.reads(&fixture.targets[2]),
        0,
        "the stopped step performed no effect"
    );
}

/// AC-053: a segment with nothing ahead of it runs every saved step on the
/// scheduler path and hands control to the task's own completion guard.
#[test]
fn scheduler_runs_every_step_of_the_saved_segment() {
    let mut fixture = fixture("p16-complete");
    three_step_plan(&mut fixture);
    let segment = fixture.procedure();
    let target = fixture.targets[0].clone();
    fixture
        .world
        .runtime
        .set_read_scope(fixture.scope.clone(), target.clone());

    let pass = scheduler_pass(&mut fixture);
    // All three saved steps ran through the executor's admission, and the blind
    // single step spent no dispatch.
    assert_eq!(
        fixture.reads(&target),
        3,
        "every saved step performed its effect"
    );
    assert_eq!(fixture.dispatches.load(Ordering::SeqCst), 0);
    assert!(segment.remainder_after(3).is_empty());
    // The task's own completion guard answers for the finished run: this
    // fixture's obligations are still open, so the step pauses instead of
    // reporting the task complete.
    assert!(
        matches!(pass, Err(ControllerError::Store(_))),
        "the completion guard answers for the finished segment, got {pass:?}"
    );
}
