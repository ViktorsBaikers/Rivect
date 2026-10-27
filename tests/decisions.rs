//! The versioned ask/auto decision layer: one shared
//! action catalog, the promoted `decisions.control` carrier, the
//! append-only answer-attempt journal, and the decision card on the
//! 60x20 acceptance geometry.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    reason = "test assertions fail loudly with the observed screen or verdict; the pty handle mirrors the shared corpus harness (standards §14)"
)]

mod support;

use crossterm::event::{Event as TermEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use rivect::actions::{
    ASSESS_PLAN, ActionContext, ActionError, ActionInput, ActionOutcome, ActionRegistry,
    CHALLENGE_DIRECTION, DECISION_OPTION_SLOTS, DECISIONS_CONTROL, DESIGN_CONTRACTS,
    DecisionAuthor, Delegation, FRAME_GOAL, INSPECT_SYSTEM, Implementation, PLAN_WORK,
    RESOLVE_DECISION,
};
use rivect::config::Config;
use rivect::contracts::{
    AnswerAttemptOutcome, AnswerSelection, Availability, EffectClass, EvidenceValidity,
    KNOWN_READY_OPTION, OptionId, Question, QuestionOption, SessionId, TEXT_MAX_BYTES, TaskId,
};
use rivect::policy::ModeDecision;
use rivect::state::{ConflictCause, InvalidCause, Missing, StoreError};
use rivect::tools::{LocalKind, describe, local_command_kind};
use rivect::ui::{
    DECISION_ANSWERED_NOTE, DECISION_DRAFT_LIMIT_NOTE, DECISION_LEFT_NOTE,
    DECISION_PASTE_REFUSED_NOTE, DECISION_SETTLED_NOTE, DECISION_TITLE, DecisionPanel, PANEL_TITLE,
    PermissionPanel, handle_decision_event, initial_view, render,
};
use serde_json::json;
use std::time::Duration;
use support::{
    corpus_answer_custom, corpus_answer_option, corpus_decisions_control, corpus_question_current,
    corpus_steer, decision_input, open_world, rivect_binary, spawn_pty,
};

// ----- support: shared world + context builders -----

fn decision_config(mode: Option<&str>) -> Config {
    let text = match mode {
        Some(mode) => format!(
            "{}\n[decisions]\nmode = \"{mode}\"\n",
            support::base_config()
        ),
        None => support::base_config(),
    };
    Config::parse_validated(&text).expect("decision config parses")
}

fn world_with_task(tag: &str) -> (support::World, SessionId, TaskId) {
    let mut world = open_world(tag, None);
    let session = world.open_session("decision-session");
    let task = world.create_task(&session, "cmd-decision-task");
    (world, session, task)
}

fn action_ctx<'a>(
    world: &'a mut support::World,
    session: &'a SessionId,
    config: &'a Config,
) -> ActionContext<'a> {
    world.runtime.action_context(session, config)
}

fn asked_question(outcome: ActionOutcome) -> Question {
    match outcome {
        ActionOutcome::Asked { question, .. } => question,
        other => panic!("expected Asked, got {other:?}"),
    }
}

// ----- action catalog -----

#[test]
fn catalog_serves_one_versioned_resolve_decision() {
    let registry = ActionRegistry::new();
    let definition = registry
        .definition(RESOLVE_DECISION)
        .expect("resolve_decision is registered");
    assert_eq!(definition.id, RESOLVE_DECISION);
    assert_eq!(definition.revision, 1);
    // The rows this catalog owns are an exact subset — each id once, each
    // implementation pinned — so a later slice may register its own rows
    // without rewriting this test (D-066 L-1); a shadow copy of an owned
    // row still fails the one-id-once check.
    let ids: Vec<&str> = registry.definitions().map(|row| row.id).collect();
    let owned = [
        (RESOLVE_DECISION, Implementation::Local),
        (INSPECT_SYSTEM, Implementation::Local),
        (FRAME_GOAL, Implementation::Local),
        (CHALLENGE_DIRECTION, Implementation::Purpose),
        (DESIGN_CONTRACTS, Implementation::Purpose),
        (PLAN_WORK, Implementation::Local),
        (ASSESS_PLAN, Implementation::LocalAndPurpose),
    ];
    for (id, implementation) in owned {
        assert_eq!(
            ids.iter().filter(|listed| **listed == id).count(),
            1,
            "{id} is registered exactly once: {ids:?}"
        );
        // Every row declares how this build runs it (PG-1): the plan's
        // semantic legs are Broker purposes, never local templates.
        let row = registry.definition(id).expect("owned row");
        assert_eq!(row.id, id);
        assert_eq!(row.implementation, implementation, "{id}");
    }
    let inspect = registry
        .definition(INSPECT_SYSTEM)
        .expect("inspect_system is registered");
    assert_eq!(inspect.id, INSPECT_SYSTEM);
    assert_eq!(inspect.revision, 2);
    assert!(
        registry.definition("bogus.action").is_none(),
        "unknown ids stay out of the catalog"
    );
    assert_eq!(RESOLVE_DECISION, "resolve_decision");
    assert_eq!(DECISIONS_CONTROL, "decisions.control");
    assert_eq!(DECISION_OPTION_SLOTS, 5);
}

#[test]
fn catalog_registers_assumption_verification_actions() {
    let registry = ActionRegistry::new();
    for id in ["test_assumption", "prepare_environment"] {
        let definition = registry
            .definition(id)
            .unwrap_or_else(|| panic!("{id} is not registered"));
        assert_eq!(definition.id, id);
        assert_eq!(definition.implementation, Implementation::Local);
        assert_eq!(
            registry.definitions().filter(|row| row.id == id).count(),
            1,
            "{id} is registered exactly once"
        );
    }
}

#[test]
fn missing_executable_or_fixture_reports_setup_gap_not_product_defect() {
    for cause in [
        rivect::verification::SetupGapCause::MissingExecutable,
        rivect::verification::SetupGapCause::MissingFixture,
        rivect::verification::SetupGapCause::EnvironmentUnavailable,
        rivect::verification::SetupGapCause::ImportFailure,
        rivect::verification::SetupGapCause::ZeroTestsSelected,
    ] {
        let classification = rivect::verification::classify_assumption(
            rivect::verification::ExpectedResult::Pass,
            rivect::verification::CheckObservation::SetupGap(cause),
        );
        assert_eq!(
            classification,
            rivect::verification::AssumptionClassification::SetupGap(cause)
        );
        assert_ne!(
            classification,
            rivect::verification::AssumptionClassification::ProductDefect
        );
    }
}

mod assumptions {
    use super::*;
    use rivect::actions::{PrepareEnvironmentInput, TestAssumptionInput};
    use rivect::controller::ControllerError;
    use rivect::executor::{ExecutorError, ReadObservation, ReadWorker, WorkerError};
    use rivect::policy::{PermissionMode, PolicyError};
    use rivect::verification::{
        AssumptionCheckRecord, AssumptionClassification, AssumptionSeam, CheckObservation,
        ExpectedResult, RetainedAttempt, SetupGapCause, assumption_boundary_id,
        assumption_evidence, setup_gap_evidence,
    };
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const ASSERTION: &str = "fixture content matches expected restore value";

    #[derive(Clone, Copy)]
    enum RestoreFailure {
        None,
        BeforeMutation,
        AfterMutation,
    }

    /// Contract-capable write double: executor admission controls whether
    /// it can restore the already-existing fixture target.
    struct RestoreWorker {
        writes: Arc<AtomicUsize>,
        failure: RestoreFailure,
    }

    impl ReadWorker for RestoreWorker {
        fn read_once(
            &mut self,
            _scope_root: &Path,
            target: &Path,
        ) -> Result<ReadObservation, WorkerError> {
            Err(WorkerError::TargetMissing {
                target: target.to_path_buf(),
            })
        }

        fn write_once(
            &mut self,
            scope_root: &Path,
            target: &Path,
            _expected: rivect::executor::WriteIdentity,
            bytes: &[u8],
        ) -> Result<(), WorkerError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            if !target.starts_with(scope_root) {
                return Err(WorkerError::OutsideScope {
                    target: target.to_path_buf(),
                });
            }
            if matches!(self.failure, RestoreFailure::BeforeMutation) {
                return Err(WorkerError::WriteFailed {
                    source: std::io::Error::other("injected restore refusal"),
                });
            }
            std::fs::write(target, bytes).map_err(|source| WorkerError::WriteFailed { source })?;
            if matches!(self.failure, RestoreFailure::AfterMutation) {
                return Err(WorkerError::WriteMutationFailed {
                    source: std::io::Error::other("injected lost restore receipt"),
                });
            }
            Ok(())
        }
    }

    struct Fixture {
        world: support::World,
        session: SessionId,
        task: TaskId,
        scope: PathBuf,
        fixture: PathBuf,
        writes: Arc<AtomicUsize>,
    }

    fn fixture(tag: &str, fails: bool) -> Fixture {
        fixture_with_failure(
            tag,
            if fails {
                RestoreFailure::BeforeMutation
            } else {
                RestoreFailure::None
            },
        )
    }

    fn fixture_with_failure(tag: &str, failure: RestoreFailure) -> Fixture {
        let (mut world, session, task) = world_with_task(tag);
        let scope = world.root.join("environment-scope");
        std::fs::create_dir_all(&scope).expect("scope dir");
        let fixture = scope.join("fixture.json");
        std::fs::write(&fixture, "stale fixture").expect("initial fixture");
        let writes = Arc::new(AtomicUsize::new(0));
        world.runtime.read_worker = Box::new(RestoreWorker {
            writes: writes.clone(),
            failure,
        });
        Fixture {
            world,
            session,
            task,
            scope: scope.canonicalize().expect("canonical scope"),
            fixture: fixture.canonicalize().expect("canonical fixture"),
            writes,
        }
    }

    fn check(
        task: &TaskId,
        check_id: &str,
        expected_result: ExpectedResult,
        assertion: &str,
        observation: CheckObservation,
    ) -> TestAssumptionInput {
        TestAssumptionInput {
            task_id: task.clone(),
            check_id: check_id.to_string(),
            expected_result,
            assertion: assertion.to_string(),
            observation,
        }
    }

    fn run(fixture: &mut Fixture, input: ActionInput) -> Result<ActionOutcome, ActionError> {
        let config = decision_config(None);
        ActionRegistry::new().execute(
            input,
            &mut action_ctx(&mut fixture.world, &fixture.session, &config),
        )
    }

    fn tested(fixture: &mut Fixture, input: TestAssumptionInput) -> AssumptionCheckRecord {
        match run(fixture, ActionInput::TestAssumption(input)).expect("assumption records") {
            ActionOutcome::AssumptionTested(record) => record,
            other => panic!("expected AssumptionTested, got {other:?}"),
        }
    }

    fn prepare(fixture: &Fixture, check_id: &str, grant_id: &str) -> PrepareEnvironmentInput {
        PrepareEnvironmentInput {
            task_id: fixture.task.clone(),
            check_id: check_id.to_string(),
            grant_id: grant_id.to_string(),
            target: fixture.fixture.clone(),
            replacement: b"restored fixture".to_vec(),
        }
    }

    fn retained(fixture: &Fixture, boundary_id: &str) -> Option<RetainedAttempt> {
        fixture
            .world
            .runtime
            .store()
            .retained(boundary_id)
            .expect("retained read")
            .map(|json| serde_json::from_str(&json).expect("retained attempt parses"))
    }

    fn retained_assumption_events(fixture: &Fixture) -> Vec<RetainedAttempt> {
        let database =
            rusqlite::Connection::open(fixture.world.root.join("runtime").join("rivect.db"))
                .expect("retained database");
        let mut statement = database
            .prepare(
                "SELECT record_json FROM retained
                 WHERE boundary_id LIKE 'ret:assumption:%'
                    OR boundary_id LIKE 'ret:terminal:ret:assumption:%'
                 ORDER BY boundary_id",
            )
            .expect("retained query");
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("retained rows")
            .map(|json| {
                serde_json::from_str(&json.expect("retained row JSON"))
                    .expect("retained assumption event parses")
            })
            .collect()
    }

    fn run_fixture_check(
        path: &Path,
        expected_content: &str,
        world: &mut support::World,
    ) -> CheckObservation {
        let status = std::process::Command::new("/bin/sh")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args(["-c", "test \"$(cat \"$1\")\" = \"$2\"", "fixture-check"])
            .arg(path)
            .arg(expected_content)
            .status();
        if status.is_err() {
            world.retain();
        }
        let status = status.expect("fixture check starts");
        if status.success() {
            CheckObservation::Passed
        } else {
            CheckObservation::Failed
        }
    }

    fn attempts(fixture: &Fixture) -> usize {
        fixture
            .world
            .runtime
            .store()
            .snapshot(&fixture.task)
            .expect("snapshot")
            .attempts
            .items
            .len()
    }

    fn write_grant(fixture: &mut Fixture) -> String {
        let scope = fixture.scope.to_str().expect("canonical scope is UTF-8");
        fixture
            .world
            .runtime
            .store_writer()
            .retain(
                "restore fixture checkpoint",
                &rivect::executor::checkpoint_boundary_id(scope),
            )
            .expect("restore checkpoint");
        fixture
            .world
            .runtime
            .policy_writer()
            .grant_classes(fixture.scope.clone(), vec![EffectClass::Write])
    }

    #[test]
    fn ac030a_test_assumption_and_prepare_environment_positive_and_negative_triggers() {
        let mut fixture = fixture("assumption-ac030a", false);
        let task = fixture.task.clone();

        let confirmed = tested(
            &mut fixture,
            check(
                &task,
                "passes",
                ExpectedResult::Pass,
                ASSERTION,
                CheckObservation::Passed,
            ),
        );
        assert_eq!(
            confirmed.classification,
            AssumptionClassification::Confirmed
        );
        assert_eq!(confirmed.boundary_id, None);

        let defect = tested(
            &mut fixture,
            check(
                &task,
                "product",
                ExpectedResult::Pass,
                ASSERTION,
                CheckObservation::Failed,
            ),
        );
        assert_eq!(
            defect.classification,
            AssumptionClassification::ProductDefect
        );
        assert_eq!(
            defect.boundary_id.as_deref(),
            Some(assumption_boundary_id(&task, "product", AssumptionSeam::ProductDefect,).as_str()),
            "a product result has separate retained evidence"
        );

        let gap = tested(
            &mut fixture,
            check(
                &task,
                "setup",
                ExpectedResult::Pass,
                ASSERTION,
                CheckObservation::SetupGap(SetupGapCause::MissingFixture),
            ),
        );
        assert_eq!(
            gap.classification,
            AssumptionClassification::SetupGap(SetupGapCause::MissingFixture)
        );

        let grant = write_grant(&mut fixture);
        let input = prepare(&fixture, "setup", &grant);
        let requested = run(&mut fixture, ActionInput::PrepareEnvironment(input))
            .expect("setup gap admits a restore request");
        assert!(!format!("{requested:?}").contains("restored fixture"));
        let ActionOutcome::EnvironmentRequested { restore, original } = requested else {
            panic!("expected EnvironmentRequested, got {requested:?}");
        };
        assert_eq!(restore.grant_id, grant);
        assert_eq!(restore.target, fixture.fixture);
        assert_eq!(restore.replacement, b"restored fixture");
        assert_eq!(original, gap);

        let input = prepare(&fixture, "product", &grant);
        let not_needed = run(&mut fixture, ActionInput::PrepareEnvironment(input))
            .expect_err("a product defect is never repaired by environment work");
        assert!(matches!(not_needed, ActionError::EnvironmentNotNeeded));
        let input = prepare(&fixture, "unrecorded", &grant);
        let missing = run(&mut fixture, ActionInput::PrepareEnvironment(input))
            .expect_err("an unrecorded check has no setup gap");
        assert!(matches!(missing, ActionError::AssumptionNotRecorded));

        let mut relative = prepare(&fixture, "setup", &grant);
        relative.target = PathBuf::from("fixture.json");
        let mut parent = prepare(&fixture, "setup", &grant);
        parent.target = fixture.scope.join("..").join("fixture.json");
        let empty_grant = prepare(&fixture, "setup", " ");
        let bad_id = prepare(&fixture, "bad id", &grant);
        let mut oversized = prepare(&fixture, "setup", &grant);
        oversized.replacement = vec![b'x'; rivect::executor::macos::WRITE_MAX_BYTES + 1];
        for (input, label) in [
            (relative, "relative target"),
            (parent, "parent traversal"),
            (empty_grant, "empty grant"),
            (bad_id, "illegal check id"),
            (oversized, "oversized restore"),
        ] {
            let error = run(&mut fixture, ActionInput::PrepareEnvironment(input)).expect_err(label);
            assert_eq!(
                error.error_code(),
                rivect::contracts::ErrorCode::InvalidInput,
                "{label}"
            );
        }
        assert_eq!(
            attempts(&fixture),
            0,
            "malformed requests stop before admission"
        );
        assert_eq!(fixture.writes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn assertion_never_weakened_to_pass() {
        let mut fixture = fixture("assumption-no-weakening", false);
        let task = fixture.task.clone();
        let original = tested(
            &mut fixture,
            check(
                &task,
                "contract",
                ExpectedResult::Pass,
                ASSERTION,
                CheckObservation::Failed,
            ),
        );
        assert_eq!(
            original.classification,
            AssumptionClassification::ProductDefect
        );

        for (expected, assertion, label) in [
            (ExpectedResult::Fail, ASSERTION, "flipped expected result"),
            (
                ExpectedResult::Pass,
                "cargo test --test fixture_contract",
                "weaker assertion",
            ),
        ] {
            let error = run(
                &mut fixture,
                ActionInput::TestAssumption(check(
                    &task,
                    "contract",
                    expected,
                    assertion,
                    CheckObservation::Passed,
                )),
            )
            .expect_err(label);
            assert!(
                matches!(
                    error,
                    ActionError::Store(StoreError::Conflict(ConflictCause::AssumptionCheckChanged))
                ),
                "{label}: {error:?}"
            );
        }
        let stored = fixture
            .world
            .runtime
            .store()
            .assumption_check(&fixture.session, &task, "contract")
            .expect("stored read")
            .expect("stored check");
        assert_eq!(
            stored, original,
            "a rejected rewrite leaves the defect visible"
        );

        let fixed = tested(
            &mut fixture,
            check(
                &task,
                "contract",
                ExpectedResult::Pass,
                ASSERTION,
                CheckObservation::Passed,
            ),
        );
        assert_eq!(fixed.classification, AssumptionClassification::Confirmed);
        assert_eq!(fixed.assertion_digest, original.assertion_digest);
    }

    #[test]
    fn no_dependency_install_without_grant() {
        let mut fixture = fixture("assumption-no-install", false);
        let task = fixture.task.clone();
        let read_grant = fixture
            .world
            .runtime
            .policy_writer()
            .grant_read(fixture.scope.clone());
        let write_grant = write_grant(&mut fixture);
        let cases = [
            (
                "unknown",
                "grant-missing".to_string(),
                PermissionMode::Auto,
                "unknown grant",
            ),
            (
                "read-only",
                read_grant,
                PermissionMode::Auto,
                "read-only grant",
            ),
            (
                "manual",
                write_grant.clone(),
                PermissionMode::Manual,
                "write needs consent",
            ),
        ];
        let session = fixture.session.clone();
        for (check_id, grant, mode, label) in cases {
            tested(
                &mut fixture,
                check(
                    &task,
                    check_id,
                    ExpectedResult::Pass,
                    ASSERTION,
                    CheckObservation::SetupGap(SetupGapCause::MissingExecutable),
                ),
            );
            let error = fixture
                .world
                .runtime
                .prepare_environment(&session, prepare(&fixture, check_id, &grant), mode)
                .expect_err(label);
            match (check_id, error) {
                (
                    "unknown",
                    ControllerError::Executor(ExecutorError::Policy(PolicyError::UnknownGrant {
                        ..
                    })),
                )
                | (
                    "read-only",
                    ControllerError::Executor(ExecutorError::Policy(
                        PolicyError::ClassNotAdmitted {
                            class: EffectClass::Write,
                            ..
                        },
                    )),
                )
                | ("manual", ControllerError::Executor(ExecutorError::ModeAsk)) => {}
                (check_id, error) => panic!("{label}: wrong denial for {check_id}: {error:?}"),
            }
            let prefix = format!("assumption:{check_id}:");
            let events: Vec<RetainedAttempt> = retained_assumption_events(&fixture)
                .into_iter()
                .filter(|event| event.attempt_id.starts_with(&prefix))
                .collect();
            assert_eq!(events.len(), 2, "{label}: denial retains both events");
            assert!(
                events.iter().any(|event| {
                    event.stage == rivect::verification::RetainedStage::Terminal
                        && event.cause == rivect::contracts::ErrorCode::Denied.as_str()
                }),
                "{label}: terminal denial is retained"
            );
        }
        assert_eq!(
            fixture.writes.load(Ordering::SeqCst),
            0,
            "no install or restore ran"
        );
        assert_eq!(
            std::fs::read(&fixture.fixture).expect("fixture remains readable"),
            b"stale fixture",
            "a denied preparation leaves fixture unchanged"
        );

        let auto_check = "auto-control";
        tested(
            &mut fixture,
            check(
                &task,
                auto_check,
                ExpectedResult::Pass,
                ASSERTION,
                CheckObservation::SetupGap(SetupGapCause::MissingExecutable),
            ),
        );
        let scope = fixture.scope.to_str().expect("canonical scope is UTF-8");
        fixture
            .world
            .runtime
            .store_writer()
            .open_budget(scope, 1)
            .expect("auto-write budget");
        let prepared = fixture
            .world
            .runtime
            .prepare_environment(
                &session,
                prepare(&fixture, auto_check, &write_grant),
                PermissionMode::Auto,
            )
            .expect("scoped Auto grant permits restore");
        assert_eq!(prepared.original.expected_result, ExpectedResult::Pass);
        assert_eq!(fixture.writes.load(Ordering::SeqCst), 1);
        assert_eq!(
            std::fs::read(&fixture.fixture).expect("fixture after allowed restore"),
            b"restored fixture"
        );
    }
    #[test]
    fn missing_environment_grant_retains_denial_without_effect() {
        for (tag, check_id, grant_id) in [
            ("assumption-no-grant-missing", "missing-grant", ""),
            ("assumption-no-grant-blank", "blank-grant", " \t "),
        ] {
            let mut fixture = fixture(tag, false);
            let task = fixture.task.clone();
            tested(
                &mut fixture,
                check(
                    &task,
                    check_id,
                    ExpectedResult::Pass,
                    ASSERTION,
                    CheckObservation::SetupGap(SetupGapCause::MissingExecutable),
                ),
            );

            let session = fixture.session.clone();
            let error = fixture
                .world
                .runtime
                .prepare_environment(
                    &session,
                    prepare(&fixture, check_id, grant_id),
                    PermissionMode::Auto,
                )
                .expect_err("blank grant rejected");
            assert!(matches!(
                error,
                ControllerError::Action(ActionError::MissingEnvironmentGrant)
            ));

            let boundary =
                assumption_boundary_id(&task, check_id, AssumptionSeam::PrepareEnvironment);
            let rejection = retained(&fixture, &boundary).expect("sanitized denial retained");
            assert_eq!(rejection.cause, "missing_environment_grant");
            assert_eq!(
                rejection.stage,
                rivect::verification::RetainedStage::Terminal
            );
            assert_eq!(fixture.writes.load(Ordering::SeqCst), 0);
            assert_eq!(attempts(&fixture), 0);
            assert_eq!(
                std::fs::read(&fixture.fixture).expect("fixture remains readable"),
                b"stale fixture"
            );
        }
    }

    #[test]
    fn denied_restore_can_retry_with_grant_on_same_check() {
        let mut fixture = fixture("assumption-denied-then-granted", false);
        let task = fixture.task.clone();
        let gap = tested(
            &mut fixture,
            check(
                &task,
                "retry",
                ExpectedResult::Pass,
                ASSERTION,
                CheckObservation::SetupGap(SetupGapCause::MissingExecutable),
            ),
        );
        let session = fixture.session.clone();
        let denied = fixture
            .world
            .runtime
            .prepare_environment(
                &session,
                prepare(&fixture, "retry", "grant-missing"),
                PermissionMode::Auto,
            )
            .expect_err("unknown grant denies first attempt");
        assert!(matches!(
            denied,
            ControllerError::Executor(ExecutorError::Policy(PolicyError::UnknownGrant { .. }))
        ));

        let denied_events: Vec<RetainedAttempt> = retained_assumption_events(&fixture)
            .into_iter()
            .filter(|event| event.attempt_id.starts_with("assumption:retry:"))
            .collect();
        assert_eq!(
            denied_events.len(),
            2,
            "denial appends pending and terminal rows"
        );
        let denied_pending = denied_events
            .iter()
            .find(|event| event.stage == rivect::verification::RetainedStage::PreEffect)
            .expect("first attempt pre-effect row");
        let denied_terminal = denied_events
            .iter()
            .find(|event| event.stage == rivect::verification::RetainedStage::Terminal)
            .expect("first attempt terminal row");
        assert_eq!(denied_pending.attempt_id, denied_terminal.attempt_id);
        assert_ne!(denied_pending.boundary_id, denied_terminal.boundary_id);
        assert_eq!(
            denied_terminal.cause,
            rivect::contracts::ErrorCode::Denied.as_str()
        );
        assert_eq!(denied_terminal.admitted_attempt_id, None);

        let grant = write_grant(&mut fixture);
        let scope = fixture.scope.to_str().expect("canonical scope is UTF-8");
        fixture
            .world
            .runtime
            .store_writer()
            .open_budget(scope, 1)
            .expect("auto-write budget");
        let prepared = fixture
            .world
            .runtime
            .prepare_environment(
                &session,
                prepare(&fixture, "retry", &grant),
                PermissionMode::Auto,
            )
            .expect("grant admits retry on same check");
        assert_eq!(prepared.original, gap);
        assert_eq!(fixture.writes.load(Ordering::SeqCst), 1);
        assert_eq!(
            std::fs::read(&fixture.fixture).expect("restored fixture"),
            b"restored fixture"
        );

        let events: Vec<RetainedAttempt> = retained_assumption_events(&fixture)
            .into_iter()
            .filter(|event| event.attempt_id.starts_with("assumption:retry:"))
            .collect();
        assert_eq!(events.len(), 4, "both attempts retain separate event rows");
        let attempt_ids: std::collections::BTreeSet<&str> = events
            .iter()
            .map(|event| event.attempt_id.as_str())
            .collect();
        assert_eq!(attempt_ids.len(), 2);
        let restored = events
            .iter()
            .find(|event| {
                event.admitted_attempt_id.as_deref() == Some(prepared.attempt_id.as_str())
            })
            .expect("terminal event links to admitted attempt");
        assert_eq!(
            restored.stage,
            rivect::verification::RetainedStage::Terminal
        );
        assert_eq!(restored.cause, "environment restore completed");
        assert_eq!(
            retained(
                &fixture,
                gap.boundary_id.as_deref().expect("setup boundary")
            ),
            Some(setup_gap_evidence(
                &task,
                "retry",
                SetupGapCause::MissingExecutable
            ))
        );
    }

    #[test]
    fn failure_emit_seams_map_to_stable_boundary_ids_and_retained_evidence() {
        let mut fixture = fixture("assumption-seams", true);
        let task = fixture.task.clone();
        let secret_assertion = "assert token sk-live-canary-7f3a is accepted";
        let debug_input = check(
            &fixture.task,
            "redaction",
            ExpectedResult::Pass,
            secret_assertion,
            CheckObservation::Passed,
        );
        assert!(!format!("{debug_input:?}").contains("sk-live-canary"));
        let mut ids = std::collections::BTreeSet::new();
        for (check_id, cause) in [
            ("missing-executable", SetupGapCause::MissingExecutable),
            ("missing-fixture", SetupGapCause::MissingFixture),
            ("unavailable", SetupGapCause::EnvironmentUnavailable),
            ("import-failure", SetupGapCause::ImportFailure),
            ("zero-tests", SetupGapCause::ZeroTestsSelected),
        ] {
            let record = tested(
                &mut fixture,
                check(
                    &task,
                    check_id,
                    ExpectedResult::Pass,
                    secret_assertion,
                    CheckObservation::SetupGap(cause),
                ),
            );
            let evidence = setup_gap_evidence(&task, check_id, cause);
            assert_eq!(record.boundary_id, Some(evidence.boundary_id.clone()));
            ids.insert(evidence.boundary_id.clone());
            let retained = retained(&fixture, &evidence.boundary_id).expect("setup gap retained");
            assert_eq!(retained, evidence);
            assert!(!format!("{retained:?}").contains("sk-live-canary"));
        }

        for (check_id, expected, observed, seam) in [
            (
                "product-defect",
                ExpectedResult::Pass,
                CheckObservation::Failed,
                AssumptionSeam::ProductDefect,
            ),
            (
                "not-reproduced",
                ExpectedResult::Fail,
                CheckObservation::Passed,
                AssumptionSeam::NotReproduced,
            ),
        ] {
            let record = tested(
                &mut fixture,
                check(&task, check_id, expected, secret_assertion, observed),
            );
            let boundary = assumption_boundary_id(&task, check_id, seam);
            assert_eq!(record.boundary_id.as_deref(), Some(boundary.as_str()));
            assert!(retained(&fixture, &boundary).is_some());
            ids.insert(boundary);
        }

        let session = fixture.session.clone();
        let admission_check = "admission";
        tested(
            &mut fixture,
            check(
                &task,
                admission_check,
                ExpectedResult::Pass,
                secret_assertion,
                CheckObservation::SetupGap(SetupGapCause::MissingExecutable),
            ),
        );
        let admission = fixture
            .world
            .runtime
            .prepare_environment(
                &session,
                prepare(&fixture, admission_check, "grant-missing"),
                PermissionMode::Auto,
            )
            .expect_err("unknown grant blocks admission");
        assert!(matches!(
            admission,
            ControllerError::Executor(ExecutorError::Policy(PolicyError::UnknownGrant { .. }))
        ));
        let admission_prefix = format!("assumption:{admission_check}:");
        let admission_events: Vec<RetainedAttempt> = retained_assumption_events(&fixture)
            .into_iter()
            .filter(|event| event.attempt_id.starts_with(&admission_prefix))
            .collect();
        assert_eq!(admission_events.len(), 2);
        let admission_terminal = admission_events
            .iter()
            .find(|event| event.stage == rivect::verification::RetainedStage::Terminal)
            .expect("admission failure retained");
        assert_eq!(
            admission_terminal.cause,
            rivect::contracts::ErrorCode::Denied.as_str()
        );
        assert_eq!(admission_terminal.admitted_attempt_id, None);

        let execution_check = "execution";
        tested(
            &mut fixture,
            check(
                &task,
                execution_check,
                ExpectedResult::Pass,
                secret_assertion,
                CheckObservation::SetupGap(SetupGapCause::MissingFixture),
            ),
        );
        let grant = write_grant(&mut fixture);
        let execution = fixture
            .world
            .runtime
            .prepare_environment(
                &session,
                prepare(&fixture, execution_check, &grant),
                PermissionMode::AcceptEdits,
            )
            .expect_err("injected write failure is retained");
        assert!(
            matches!(
                execution,
                ControllerError::Executor(ExecutorError::Worker(WorkerError::WriteFailed { .. }))
            ),
            "{execution:?}"
        );
        assert_eq!(fixture.writes.load(Ordering::SeqCst), 1);
        let execution_prefix = format!("assumption:{execution_check}:");
        let execution_events: Vec<RetainedAttempt> = retained_assumption_events(&fixture)
            .into_iter()
            .filter(|event| event.attempt_id.starts_with(&execution_prefix))
            .collect();
        assert_eq!(execution_events.len(), 2);
        let execution_terminal = execution_events
            .iter()
            .find(|event| event.stage == rivect::verification::RetainedStage::Terminal)
            .expect("execution failure retained");
        assert_eq!(
            execution_terminal.cause,
            rivect::contracts::ErrorCode::Denied.as_str()
        );
        assert!(execution_terminal.admitted_attempt_id.is_some());

        for id in &ids {
            assert!(id.starts_with("ret:assumption:"), "{id}");
            assert!(!id.contains(&task.0), "{id}");
        }
        assert_eq!(
            ids.len(),
            7,
            "each classification seam keeps stable identity"
        );
    }

    #[test]
    fn unknown_restore_outcome_keeps_retained_evidence() {
        let mut fixture =
            fixture_with_failure("assumption-restore-unknown", RestoreFailure::AfterMutation);
        let task = fixture.task.clone();
        tested(
            &mut fixture,
            check(
                &task,
                "unknown",
                ExpectedResult::Pass,
                ASSERTION,
                CheckObservation::SetupGap(SetupGapCause::MissingFixture),
            ),
        );
        let grant = write_grant(&mut fixture);
        let session = fixture.session.clone();
        let error = fixture
            .world
            .runtime
            .prepare_environment(
                &session,
                prepare(&fixture, "unknown", &grant),
                PermissionMode::AcceptEdits,
            )
            .expect_err("post-mutation error is unknown");
        assert_eq!(
            error.error_code(),
            rivect::contracts::ErrorCode::OutcomeUnknown
        );
        assert_eq!(fixture.writes.load(Ordering::SeqCst), 1);
        assert_eq!(
            std::fs::read(&fixture.fixture).expect("fixture after mutation"),
            b"restored fixture"
        );
        assert!(
            fixture
                .world
                .runtime
                .store()
                .snapshot(&task)
                .expect("snapshot")
                .attempts
                .items
                .iter()
                .any(|attempt| attempt.state == rivect::contracts::AttemptState::Unknown),
            "executor keeps unknown outcome in its ledger"
        );
        let prefix = "assumption:unknown:";
        let events: Vec<RetainedAttempt> = retained_assumption_events(&fixture)
            .into_iter()
            .filter(|event| event.attempt_id.starts_with(prefix))
            .collect();
        assert_eq!(events.len(), 2);
        let terminal = events
            .iter()
            .find(|event| event.stage == rivect::verification::RetainedStage::Terminal)
            .expect("unknown effect retained");
        assert_eq!(
            terminal.cause,
            rivect::contracts::ErrorCode::OutcomeUnknown.as_str()
        );
        assert!(terminal.admitted_attempt_id.is_some());
    }

    #[test]
    fn missing_restore_target_is_real_setup_failure_with_product_control() {
        let (world, session, task) = world_with_task("assumption-real-missing-target");
        let scope = world.root.join("environment-scope");
        std::fs::create_dir_all(&scope).expect("scope dir");
        let target = scope.join("fixture.json");
        std::fs::write(&target, "stale fixture").expect("initial fixture");
        let mut missing_fixture = Fixture {
            world,
            session: session.clone(),
            task: task.clone(),
            scope: scope.canonicalize().expect("canonical scope"),
            fixture: target.canonicalize().expect("canonical fixture"),
            writes: Arc::new(AtomicUsize::new(0)),
        };
        tested(
            &mut missing_fixture,
            check(
                &task,
                "missing-target",
                ExpectedResult::Pass,
                ASSERTION,
                CheckObservation::SetupGap(SetupGapCause::MissingFixture),
            ),
        );
        let grant = write_grant(&mut missing_fixture);
        std::fs::remove_file(&missing_fixture.fixture).expect("remove actual restore target");
        let error = missing_fixture
            .world
            .runtime
            .prepare_environment(
                &session,
                prepare(&missing_fixture, "missing-target", &grant),
                PermissionMode::AcceptEdits,
            )
            .expect_err("missing target blocks restore at executor boundary");
        assert!(matches!(
            error,
            ControllerError::Executor(ExecutorError::Worker(WorkerError::TargetMissing { .. }))
        ));
        assert!(
            !missing_fixture.fixture.exists(),
            "missing target stays absent"
        );
        assert_eq!(attempts(&missing_fixture), 0);
        let events: Vec<RetainedAttempt> = retained_assumption_events(&missing_fixture)
            .into_iter()
            .filter(|event| event.attempt_id.starts_with("assumption:missing-target:"))
            .collect();
        assert_eq!(events.len(), 2);
        let terminal = events
            .iter()
            .find(|event| event.stage == rivect::verification::RetainedStage::Terminal)
            .expect("real setup failure retained");
        assert_eq!(
            terminal.cause,
            rivect::contracts::ErrorCode::Denied.as_str()
        );
        assert_eq!(terminal.admitted_attempt_id, None);

        let mut control = fixture("assumption-real-product-control", false);
        let control_task = control.task.clone();
        let observation =
            run_fixture_check(&control.fixture, "restored fixture", &mut control.world);
        assert_eq!(observation, CheckObservation::Failed);
        let product = tested(
            &mut control,
            check(
                &control_task,
                "product-control",
                ExpectedResult::Pass,
                ASSERTION,
                observation,
            ),
        );
        assert_eq!(product.observation, CheckObservation::Failed);
        assert_eq!(
            product.classification,
            AssumptionClassification::ProductDefect
        );
    }

    #[test]
    fn retention_faults_keep_records_atomic_and_before_effect_cleanup() {
        let cases = [
            (
                "fault-missing-executable",
                ExpectedResult::Pass,
                CheckObservation::SetupGap(SetupGapCause::MissingExecutable),
                AssumptionSeam::SetupGap(SetupGapCause::MissingExecutable),
            ),
            (
                "fault-missing-fixture",
                ExpectedResult::Pass,
                CheckObservation::SetupGap(SetupGapCause::MissingFixture),
                AssumptionSeam::SetupGap(SetupGapCause::MissingFixture),
            ),
            (
                "fault-environment",
                ExpectedResult::Pass,
                CheckObservation::SetupGap(SetupGapCause::EnvironmentUnavailable),
                AssumptionSeam::SetupGap(SetupGapCause::EnvironmentUnavailable),
            ),
            (
                "fault-import-failure",
                ExpectedResult::Pass,
                CheckObservation::SetupGap(SetupGapCause::ImportFailure),
                AssumptionSeam::SetupGap(SetupGapCause::ImportFailure),
            ),
            (
                "fault-zero-tests",
                ExpectedResult::Pass,
                CheckObservation::SetupGap(SetupGapCause::ZeroTestsSelected),
                AssumptionSeam::SetupGap(SetupGapCause::ZeroTestsSelected),
            ),
            (
                "fault-product-defect",
                ExpectedResult::Pass,
                CheckObservation::Failed,
                AssumptionSeam::ProductDefect,
            ),
            (
                "fault-not-reproduced",
                ExpectedResult::Fail,
                CheckObservation::Passed,
                AssumptionSeam::NotReproduced,
            ),
        ];
        for (check_id, expected, observation, seam) in cases {
            let mut fixture = fixture(check_id, false);
            let task = fixture.task.clone();
            let boundary = assumption_boundary_id(&task, check_id, seam);
            let database =
                rusqlite::Connection::open(fixture.world.root.join("runtime").join("rivect.db"))
                    .expect("fault database");
            database
                .execute_batch(
                    "CREATE TRIGGER retained_insert_fault BEFORE INSERT ON retained
                     BEGIN SELECT RAISE(ABORT, 'injected retained insert failure'); END;",
                )
                .expect("retained insert fault");
            drop(database);

            let result = run(
                &mut fixture,
                ActionInput::TestAssumption(check(
                    &task,
                    check_id,
                    expected,
                    ASSERTION,
                    observation,
                )),
            );
            assert!(
                matches!(result, Err(ActionError::Store(StoreError::Storage(_)))),
                "{check_id}: retained emit failure must stop the action: {result:?}"
            );
            assert!(
                fixture
                    .world
                    .runtime
                    .store()
                    .assumption_check(&fixture.session, &task, check_id)
                    .expect("check read")
                    .is_none(),
                "{check_id}: check row rolls back with its evidence"
            );
            assert!(
                retained(&fixture, &boundary).is_none(),
                "{check_id}: no partial row"
            );
        }

        let mut preadmit_fixture = fixture("fault-restore-preadmit", false);
        let task = preadmit_fixture.task.clone();
        tested(
            &mut preadmit_fixture,
            check(
                &task,
                "restore",
                ExpectedResult::Pass,
                ASSERTION,
                CheckObservation::SetupGap(SetupGapCause::MissingFixture),
            ),
        );
        let grant = write_grant(&mut preadmit_fixture);
        let boundary = assumption_boundary_id(&task, "restore", AssumptionSeam::PrepareEnvironment);
        let database = rusqlite::Connection::open(
            preadmit_fixture
                .world
                .root
                .join("runtime")
                .join("rivect.db"),
        )
        .expect("pre-effect fault database");
        database
            .execute_batch(
                "CREATE TRIGGER retained_preadmit_fault BEFORE INSERT ON retained
                 WHEN NEW.boundary_id LIKE 'ret:assumption:%'
                 BEGIN SELECT RAISE(ABORT, 'injected pre-effect retain failure'); END;",
            )
            .expect("pre-effect fault");
        drop(database);
        let session = preadmit_fixture.session.clone();
        let error = preadmit_fixture
            .world
            .runtime
            .prepare_environment(
                &session,
                prepare(&preadmit_fixture, "restore", &grant),
                PermissionMode::AcceptEdits,
            )
            .expect_err("pre-effect evidence must land before worker entry");
        assert!(matches!(
            error,
            ControllerError::Store(StoreError::Storage(_))
        ));
        assert_eq!(preadmit_fixture.writes.load(Ordering::SeqCst), 0);
        assert_eq!(attempts(&preadmit_fixture), 0);
        assert!(retained(&preadmit_fixture, &boundary).is_none());

        let mut terminal_fixture = fixture("fault-restore-terminal", false);
        let task = terminal_fixture.task.clone();
        tested(
            &mut terminal_fixture,
            check(
                &task,
                "restore",
                ExpectedResult::Pass,
                ASSERTION,
                CheckObservation::SetupGap(SetupGapCause::MissingFixture),
            ),
        );
        let grant = write_grant(&mut terminal_fixture);
        let database = rusqlite::Connection::open(
            terminal_fixture
                .world
                .root
                .join("runtime")
                .join("rivect.db"),
        )
        .expect("terminal fault database");
        database
            .execute_batch(
                "CREATE TRIGGER retained_terminal_fault BEFORE INSERT ON retained
                 WHEN NEW.boundary_id LIKE 'ret:terminal:ret:assumption:%'
                 BEGIN SELECT RAISE(ABORT, 'injected terminal retain failure'); END;",
            )
            .expect("terminal fault");
        drop(database);
        let session = terminal_fixture.session.clone();
        let error = terminal_fixture
            .world
            .runtime
            .prepare_environment(
                &session,
                prepare(&terminal_fixture, "restore", &grant),
                PermissionMode::AcceptEdits,
            )
            .expect_err("terminal evidence failure remains visible");
        assert!(matches!(
            error,
            ControllerError::Store(StoreError::Storage(_))
        ));
        assert_eq!(terminal_fixture.writes.load(Ordering::SeqCst), 1);
        let pending = retained_assumption_events(&terminal_fixture)
            .into_iter()
            .find(|event| {
                event.attempt_id.starts_with("assumption:restore:")
                    && event.stage == rivect::verification::RetainedStage::PreEffect
            })
            .expect("pre-effect evidence survives");
        assert_eq!(
            pending.stage,
            rivect::verification::RetainedStage::PreEffect
        );
        assert_eq!(
            std::fs::read(&terminal_fixture.fixture).expect("restored bytes"),
            b"restored fixture"
        );
    }

    #[test]
    fn boundary_id_collision_rejected() {
        let mut fixture = fixture("assumption-boundary-collision", false);
        let task = fixture.task.clone();
        let first = assumption_evidence(
            &task,
            "collision",
            AssumptionSeam::SetupGap(SetupGapCause::MissingExecutable),
            "setup gap: missing_executable",
        );
        let mut alias = assumption_evidence(
            &task,
            "collision",
            AssumptionSeam::SetupGap(SetupGapCause::MissingFixture),
            "setup gap: missing_fixture",
        );
        assert_ne!(first.boundary_id, alias.boundary_id);
        alias.boundary_id = first.boundary_id.clone();
        let mut store = fixture.world.runtime.store_writer();
        store.retain_attempt(&first).expect("first seam retained");
        let error = store
            .retain_attempt(&alias)
            .expect_err("an aliased seam is denied");
        assert!(matches!(
            error,
            StoreError::Conflict(ConflictCause::RetainedBoundaryCollision { .. })
        ));
        assert_eq!(retained(&fixture, &first.boundary_id), Some(first));
    }

    #[test]
    fn cleanup_never_overwrites_retained_rows() {
        let mut fixture = fixture("assumption-cleanup", false);
        let task = fixture.task.clone();
        let gap = tested(
            &mut fixture,
            check(
                &task,
                "cleanup",
                ExpectedResult::Pass,
                ASSERTION,
                CheckObservation::SetupGap(SetupGapCause::EnvironmentUnavailable),
            ),
        );
        let boundary_id = gap.boundary_id.expect("setup gap boundary");
        let before = retained(&fixture, &boundary_id).expect("setup evidence");
        let mut cleanup = before.clone();
        cleanup.cause = "cleanup succeeded".to_string();
        let mut store = fixture.world.runtime.store_writer();
        assert!(store.retain_attempt(&cleanup).is_err());
        let raw_cleanup = serde_json::to_string(&cleanup).expect("json");
        let conflict = store.retain(&raw_cleanup, &boundary_id);
        assert!(
            matches!(
                conflict,
                Err(StoreError::Conflict(
                    ConflictCause::RetainedBoundaryCollision { .. }
                ))
            ),
            "{conflict:?}"
        );
        assert_eq!(retained(&fixture, &boundary_id), Some(before));
    }
    #[test]
    fn retained_rows_reject_forged_sql_transition() {
        let mut fixture = fixture("assumption-retained-sql-immutable", false);
        let task = fixture.task.clone();
        let mut pending = assumption_evidence(
            &task,
            "forged",
            AssumptionSeam::PrepareEnvironment,
            "environment restore pending",
        );
        pending.stage = rivect::verification::RetainedStage::PreEffect;
        pending.digest = rivect::verification::record_digest(&pending.attempt_id, "pre");
        fixture
            .world
            .runtime
            .store_writer()
            .retain_attempt(&pending)
            .expect("pre-effect evidence retained");

        let original_json = serde_json::to_string(&pending).expect("pre-effect JSON");
        let mut forged = pending.clone();
        forged.stage = rivect::verification::RetainedStage::Terminal;
        forged.cause = "cleanup succeeded".to_string();
        forged.digest = rivect::verification::record_digest(&forged.attempt_id, &forged.cause);
        let forged_json = serde_json::to_string(&forged).expect("forged terminal JSON");
        let connection =
            rusqlite::Connection::open(fixture.world.root.join("runtime").join("rivect.db"))
                .expect("retained database");
        let update = connection.execute(
            "UPDATE retained SET record_json = ?1 WHERE boundary_id = ?2 AND record_json = ?3",
            rusqlite::params![forged_json, pending.boundary_id, original_json],
        );

        assert!(update.is_err(), "SQL must reject the forged transition");
        assert_eq!(
            retained(&fixture, &pending.boundary_id),
            Some(pending),
            "pre-effect evidence remains unchanged"
        );
    }

    #[test]
    fn granted_env_restore_returns_original_check_same_expected() {
        let mut fixture = fixture("assumption-restore", false);
        let task = fixture.task.clone();
        let gap = tested(
            &mut fixture,
            check(
                &task,
                "restore",
                ExpectedResult::Pass,
                ASSERTION,
                CheckObservation::SetupGap(SetupGapCause::MissingFixture),
            ),
        );
        let boundary_id = gap.boundary_id.clone().expect("setup gap boundary");
        let setup_evidence = retained(&fixture, &boundary_id).expect("setup evidence");
        let grant = write_grant(&mut fixture);
        let session = fixture.session.clone();
        let prepared = fixture
            .world
            .runtime
            .prepare_environment(
                &session,
                prepare(&fixture, "restore", &grant),
                PermissionMode::AcceptEdits,
            )
            .expect("granted restore");
        assert_eq!(prepared.original, gap);
        assert_eq!(fixture.writes.load(Ordering::SeqCst), 1);
        let observation =
            run_fixture_check(&fixture.fixture, "restored fixture", &mut fixture.world);
        assert_eq!(observation, CheckObservation::Passed, "rerun passes");
        let rerun = tested(
            &mut fixture,
            check(
                &task,
                "restore",
                prepared.original.expected_result,
                ASSERTION,
                observation,
            ),
        );
        assert_eq!(rerun.expected_result, gap.expected_result);
        assert_eq!(rerun.assertion_digest, gap.assertion_digest);
        assert_eq!(rerun.classification, AssumptionClassification::Confirmed);
        assert_eq!(retained(&fixture, &boundary_id), Some(setup_evidence));
    }

    #[test]
    fn restored_fixture_that_still_fails_check_is_product_defect() {
        let mut fixture = fixture("assumption-restore-still-fails", false);
        let task = fixture.task.clone();
        let gap = tested(
            &mut fixture,
            check(
                &task,
                "restore",
                ExpectedResult::Pass,
                ASSERTION,
                CheckObservation::SetupGap(SetupGapCause::MissingFixture),
            ),
        );
        let grant = write_grant(&mut fixture);
        let session = fixture.session.clone();
        let mut restore = prepare(&fixture, "restore", &grant);
        restore.replacement = b"still failing".to_vec();
        let prepared = fixture
            .world
            .runtime
            .prepare_environment(&session, restore, PermissionMode::AcceptEdits)
            .expect("granted restore");
        assert_eq!(prepared.original, gap);
        assert_eq!(fixture.writes.load(Ordering::SeqCst), 1);

        let observation =
            run_fixture_check(&fixture.fixture, "restored fixture", &mut fixture.world);
        assert_eq!(observation, CheckObservation::Failed);
        let rerun = tested(
            &mut fixture,
            check(
                &task,
                "restore",
                prepared.original.expected_result,
                ASSERTION,
                observation,
            ),
        );
        assert_eq!(rerun.observation, CheckObservation::Failed);
        assert_eq!(rerun.expected_result, gap.expected_result);
        assert_eq!(rerun.assertion_digest, gap.assertion_digest);
        assert_eq!(
            rerun.classification,
            AssumptionClassification::ProductDefect
        );
    }
}

#[test]
fn material_fork_under_background_surfaces_one_versioned_question() {
    let (mut world, session, task) = world_with_task("decision-ask");
    let registry = ActionRegistry::new();
    let config = decision_config(None);

    let outcome = registry
        .resolve_decision(
            decision_input(&task),
            &mut action_ctx(&mut world, &session, &config),
        )
        .expect("ask mode resolves by publishing");
    let question = asked_question(outcome);

    let (pending, _) = world
        .runtime
        .store()
        .current_question(&task)
        .expect("current question")
        .expect("the fork is pending");
    assert_eq!(pending.question_id, question.question_id);
    assert_eq!(pending.question_revision, 1);
    assert_eq!(pending.task_id, task);
    assert_eq!(pending.options.len(), DECISION_OPTION_SLOTS);
    assert_eq!(
        pending.recommended_option_id.0, "stage",
        "recommendation is display state carried on the question"
    );
    let snapshot = world.runtime.store().snapshot(&task).expect("snapshot");
    assert_eq!(
        pending.intent_revision, snapshot.intent_revision,
        "the question pins the live intent revision"
    );
    assert_eq!(
        snapshot.lifecycle,
        rivect::contracts::Lifecycle::Waiting,
        "a published fork waits on its question"
    );

    // A09: the running task's material fork surfaces through the parent's
    // own control point — `question.current` serves that one versioned
    // question, and serving it never auto-answers.
    let served = world.dispatch(&corpus_question_current(&session, &task, json!(50)));
    assert!(served["error"].is_null(), "{served}");
    assert_eq!(
        served["result"]["question"]["question_id"].as_str(),
        Some(question.question_id.0.as_str()),
        "the parent control point serves the fork's one question"
    );
    assert_eq!(
        served["result"]["question"]["question_revision"].as_u64(),
        Some(1),
        "the served question is the versioned row the fork pinned"
    );
}

#[test]
fn repeated_identical_fork_dedupes_to_the_same_question() {
    let (mut world, session, task) = world_with_task("decision-dedupe");
    let registry = ActionRegistry::new();
    let config = decision_config(None);

    let first = asked_question(
        registry
            .resolve_decision(
                decision_input(&task),
                &mut action_ctx(&mut world, &session, &config),
            )
            .expect("first publish"),
    );
    let second = asked_question(
        registry
            .resolve_decision(
                decision_input(&task),
                &mut action_ctx(&mut world, &session, &config),
            )
            .expect("an identical repeat dedupes instead of failing"),
    );
    assert_eq!(
        first.question_id, second.question_id,
        "the repeat serves the live question, not a second row"
    );
}

#[test]
fn a_different_pending_fork_conflicts() {
    let (mut world, session, task) = world_with_task("decision-conflict");
    let registry = ActionRegistry::new();
    let config = decision_config(None);
    registry
        .resolve_decision(
            decision_input(&task),
            &mut action_ctx(&mut world, &session, &config),
        )
        .expect("first publish");

    let mut changed = decision_input(&task);
    changed.prompt = "a different fork entirely".to_string();
    let error = registry
        .resolve_decision(changed, &mut action_ctx(&mut world, &session, &config))
        .expect_err("a different pending fork must not shadow-queue");
    assert!(
        matches!(
            error,
            ActionError::Store(StoreError::Conflict(ConflictCause::PendingQuestionExists))
        ),
        "the conflict is typed: {error}"
    );
}

#[test]
fn empty_queue_from_question_reports_waiting_not_done() {
    let (mut world, session, task) = world_with_task("decision-empty-queue");
    let calls_before = world
        .provider_calls
        .load(std::sync::atomic::Ordering::SeqCst);
    let question = world.publish(&session, &task);

    // The pending question emptied the runnable queue: the task reports
    // waiting and names the decision it waits on — never done.
    let snapshot = world.runtime.store().snapshot(&task).expect("snapshot");
    assert_eq!(snapshot.lifecycle, rivect::contracts::Lifecycle::Waiting);
    assert!(
        !snapshot.lifecycle.is_terminal(),
        "an empty queue is never a completed task"
    );
    let blockers = snapshot
        .blockers
        .expect("a waiting task names what it waits on");
    assert!(
        blockers.iter().any(|blocker| {
            blocker.reason == rivect::contracts::ErrorCode::DependencyBlocked
                && matches!(
                    &blocker.condition,
                    rivect::contracts::ResumeCondition::Decision { question_id, .. }
                        if *question_id == question.question_id
                )
        }),
        "the blocker names the pending question: {blockers:?}"
    );

    // No busy retry either: publishing and reporting a waiting queue
    // dispatched nothing to the provider.
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        calls_before,
        "waiting on a question never spins a retry"
    );

    // The control point confirms the queue is empty *because of* the
    // question — it still serves the one pending row, not a done state.
    let served = world.dispatch(&corpus_question_current(&session, &task, json!(70)));
    assert!(served["error"].is_null(), "{served}");
    assert_eq!(
        served["result"]["question"]["question_id"].as_str(),
        Some(question.question_id.0.as_str()),
        "the pending question, not a done report, answers the poll"
    );
}

#[test]
fn machine_answer_without_delegation_stays_denied() {
    let (mut world, session, task) = world_with_task("decision-auto-undelegated");
    let registry = ActionRegistry::new();
    let config = decision_config(Some("auto"));

    let mut input = decision_input(&task);
    input.author = Some(DecisionAuthor::System);
    let outcome = registry
        .resolve_decision(input, &mut action_ctx(&mut world, &session, &config))
        .expect("undelegated auto still resolves by asking");
    let question = asked_question(outcome);
    assert!(
        world
            .runtime
            .store()
            .current_question(&task)
            .expect("current")
            .is_some(),
        "the fork waits as a real pending question: {}",
        question.question_id.0
    );
    assert!(
        world
            .runtime
            .store()
            .answered_question(&task)
            .expect("answered")
            .is_none(),
        "auto without delegation never answers"
    );

    // An agent author without a delegation is denied identically — the
    // delegation scope, not the author kind, is what auto answers under.
    let other = world.create_task(&session, "cmd-auto-undelegated-agent");
    let mut input = decision_input(&other);
    input.author = Some(DecisionAuthor::Agent);
    let outcome = registry
        .resolve_decision(input, &mut action_ctx(&mut world, &session, &config))
        .expect("undelegated agent still resolves by asking");
    asked_question(outcome);
    assert!(
        world
            .runtime
            .store()
            .answered_question(&other)
            .expect("answered")
            .is_none(),
        "an agent without delegation never answers either"
    );

    // The wire arm of the same gate: a machine-ingress answer quoting the
    // published question denies outright and journals its own class —
    // the delegation-less machine path applies nowhere.
    let machine = world.dispatch_machine(&corpus_answer_option(
        &session,
        "cmd-machine-denied",
        &task,
        &question,
        "stage",
        json!(60),
    ));
    assert_eq!(
        machine["error"]["data"]["code"], "denied",
        "machine ingress denies typed: {machine}"
    );
    let attempts = world
        .runtime
        .store()
        .answer_attempts(&task)
        .expect("attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].outcome, AnswerAttemptOutcome::Denied);
    assert_eq!(attempts[0].author, "machine");
    assert_eq!(attempts[0].denial.as_deref(), Some("machine_ingress"));
    assert!(
        world
            .runtime
            .store()
            .current_question(&task)
            .expect("current")
            .is_some(),
        "the denial preserved the pending fork"
    );
}

#[test]
fn auto_records_system_or_agent_author_inside_delegated_scope() {
    let (mut world, session, task) = world_with_task("decision-auto-delegated");
    let registry = ActionRegistry::new();
    let config = decision_config(Some("auto"));

    let mut input = decision_input(&task);
    input.author = Some(DecisionAuthor::System);
    input.delegation = Some(Delegation {
        action: RESOLVE_DECISION.to_string(),
        task_id: task.clone(),
    });
    let outcome = registry
        .resolve_decision(input, &mut action_ctx(&mut world, &session, &config))
        .expect("delegated auto answers");
    let ActionOutcome::Answered {
        question_id,
        selection,
        author,
        ..
    } = outcome
    else {
        panic!("expected Answered, got {outcome:?}");
    };
    assert_eq!(author, "system");
    assert_eq!(
        selection,
        AnswerSelection::Option {
            option_id: OptionId("stage".to_string())
        },
        "the machine answer selects the recommended position"
    );

    let (answer_json, origin) = world
        .runtime
        .store()
        .answered_question(&task)
        .expect("answered")
        .expect("the answer is durable");
    assert_eq!(origin, "system", "the machine author records, not human");
    assert!(answer_json.contains("\"stage\""), "{answer_json}");
    assert!(
        world
            .runtime
            .store()
            .current_question(&task)
            .expect("current")
            .is_none(),
        "answered question {} leaves nothing pending",
        question_id.0
    );
    let attempts = world
        .runtime
        .store()
        .answer_attempts(&task)
        .expect("attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].outcome, AnswerAttemptOutcome::Applied);
    assert_eq!(attempts[0].author, "system");
}

#[test]
fn auto_never_gains_rights_payment_or_authority() {
    // The delegated auto answer is a decision write and nothing else:
    // no grant, no budget movement, no terminal authority — the task
    // resumes to ordinary running work.
    let (mut world, session, task) = world_with_task("decision-auto-bounds");
    let registry = ActionRegistry::new();
    let config = decision_config(Some("auto"));

    let mut input = decision_input(&task);
    input.author = Some(DecisionAuthor::Agent);
    input.delegation = Some(Delegation {
        action: RESOLVE_DECISION.to_string(),
        task_id: task.clone(),
    });
    let outcome = registry
        .resolve_decision(input, &mut action_ctx(&mut world, &session, &config))
        .expect("delegated auto answers");
    let ActionOutcome::Answered { author, .. } = outcome else {
        panic!("expected Answered, got {outcome:?}")
    };
    assert_eq!(author, "agent", "the machine author records as itself");

    // Rights and payment journals stay empty: the answer seam cannot
    // mint a preapproval, open a budget scope, or take a reservation.
    let conn =
        rusqlite::Connection::open(world.root.join("runtime").join("rivect.db")).expect("conn");
    for (table, label) in [
        ("preapprovals", "rights"),
        ("budget_scopes", "payment scopes"),
        ("budget_reservations", "payment reservations"),
    ] {
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("journal table reads");
        assert_eq!(count, 0, "an auto answer never grows {label}");
    }
    drop(conn);

    // The answer event carries the machine origin — never the human's.
    let feed = world
        .runtime
        .store()
        .events_after(&session, Some(&task), 0, 100)
        .expect("task feed");
    let answered: Vec<&rivect::contracts::Event> = feed
        .iter()
        .filter(|event| event.event_type == "question.answered")
        .collect();
    assert_eq!(answered.len(), 1, "one answer event: {feed:?}");
    assert_eq!(
        answered[0].origin, "agent",
        "the answer is attributed to the machine, never human"
    );

    // And no authority either: the task did not complete itself — it
    // resumed to running work and waits for the ordinary dispatch path.
    assert_eq!(
        world
            .runtime
            .store()
            .snapshot(&task)
            .expect("snapshot")
            .lifecycle,
        rivect::contracts::Lifecycle::Running,
        "the answered task resumes; it never completes or cancels itself"
    );
}

#[test]
fn auto_delegation_scoped_to_another_task_still_asks() {
    let (mut world, session, task) = world_with_task("decision-delegation-scope");
    let other = world.create_task(&session, "cmd-decision-other");
    let registry = ActionRegistry::new();
    let config = decision_config(Some("auto"));

    let mut input = decision_input(&task);
    input.author = Some(DecisionAuthor::Agent);
    input.delegation = Some(Delegation {
        action: RESOLVE_DECISION.to_string(),
        task_id: other,
    });
    let outcome = registry
        .resolve_decision(input, &mut action_ctx(&mut world, &session, &config))
        .expect("a mis-scoped delegation falls back to ask");
    asked_question(outcome);
    assert!(
        world
            .runtime
            .store()
            .answered_question(&task)
            .expect("answered")
            .is_none(),
        "a delegation for another task covers nothing here"
    );
}

#[test]
fn auto_rejects_human_impersonation_and_missing_author() {
    let (mut world, session, task) = world_with_task("decision-author-gate");
    let registry = ActionRegistry::new();
    let config = decision_config(Some("auto"));
    let delegation = || {
        Some(Delegation {
            action: RESOLVE_DECISION.to_string(),
            task_id: task.clone(),
        })
    };

    let mut human = decision_input(&task);
    human.delegation = delegation();
    human.author = Some(DecisionAuthor::Human);
    let error = registry
        .resolve_decision(human, &mut action_ctx(&mut world, &session, &config))
        .expect_err("a machine answer never impersonates a human");
    assert!(
        matches!(error, ActionError::AutoImpersonatesHuman),
        "{error}"
    );

    let mut anonymous = decision_input(&task);
    anonymous.delegation = delegation();
    let error = registry
        .resolve_decision(anonymous, &mut action_ctx(&mut world, &session, &config))
        .expect_err("a delegated answer must name its machine author");
    assert!(matches!(error, ActionError::AutoAuthorRequired), "{error}");

    assert!(
        world
            .runtime
            .store()
            .current_question(&task)
            .expect("current")
            .is_none(),
        "a rejected author publishes nothing"
    );
}

#[test]
fn fork_validation_rejects_dishonest_shapes() {
    let (mut world, session, task) = world_with_task("decision-validation");
    let registry = ActionRegistry::new();
    let config = decision_config(None);
    let mut reject = |input: rivect::actions::ResolveDecisionInput, label: &str| -> ActionError {
        registry
            .resolve_decision(input, &mut action_ctx(&mut world, &session, &config))
            .expect_err(label)
    };

    let mut four = decision_input(&task);
    four.options.pop();
    assert!(matches!(
        reject(four, "four positions"),
        ActionError::OptionSlots {
            expected: 5,
            actual: 4
        }
    ));

    let mut six = decision_input(&task);
    six.options.push(QuestionOption {
        option_id: OptionId("extra".to_string()),
        label: "Extra".to_string(),
        consequences: "One too many.".to_string(),
        availability: Availability::Enabled,
    });
    assert!(matches!(
        reject(six, "six positions"),
        ActionError::OptionSlots {
            expected: 5,
            actual: 6
        }
    ));

    let mut dup = decision_input(&task);
    dup.options[1].option_id = dup.options[0].option_id.clone();
    assert!(matches!(
        reject(dup, "duplicate ids"),
        ActionError::DuplicateOptionId { .. }
    ));

    let mut silent = decision_input(&task);
    silent.options[4].availability = Availability::Disabled {
        reason: String::new(),
    };
    assert!(matches!(
        reject(silent, "disabled without a reason"),
        ActionError::DisabledWithoutReason { .. }
    ));

    let mut dead_pick = decision_input(&task);
    dead_pick.recommended_option_id = OptionId("drop".to_string());
    assert!(matches!(
        reject(dead_pick, "recommended position disabled"),
        ActionError::RecommendationNotSelectable { .. }
    ));

    let mut basisless = decision_input(&task);
    basisless.recommendation_basis = "   ".to_string();
    assert!(matches!(
        reject(basisless, "empty basis"),
        ActionError::EmptyBasis
    ));

    let mut promptless = decision_input(&task);
    promptless.prompt = String::new();
    assert!(matches!(
        reject(promptless, "empty prompt"),
        ActionError::EmptyPrompt
    ));

    let mut oversized = decision_input(&task);
    oversized.prompt = "x".repeat(TEXT_MAX_BYTES + 1);
    assert!(matches!(
        reject(oversized, "oversized prompt"),
        ActionError::PromptTooLarge {
            max: TEXT_MAX_BYTES
        }
    ));

    let mut bad_id = decision_input(&task);
    bad_id.options[0].option_id = OptionId("no spaces!".to_string());
    assert!(matches!(
        reject(bad_id, "illegal option id"),
        ActionError::InvalidOptionId { .. }
    ));
}

#[test]
fn execute_dispatches_on_the_typed_input() {
    let (mut world, session, task) = world_with_task("decision-execute");
    let registry = ActionRegistry::new();
    let config = decision_config(None);
    let outcome = registry
        .execute(
            ActionInput::ResolveDecision(decision_input(&task)),
            &mut action_ctx(&mut world, &session, &config),
        )
        .expect("typed dispatch resolves");
    asked_question(outcome);
}

// ----- TP-PUBLIC: the provider/consumer contract pair -----

#[test]
fn provider_question_answer() {
    // Provider leg: the catalog mints one versioned `Question` and the
    // wire serves that exact contract shape — no second schema exists
    // between the producer and its consumers.
    let (mut world, session, task) = world_with_task("tp-provider-question");
    let registry = ActionRegistry::new();
    let config = decision_config(None);
    let produced = asked_question(
        registry
            .resolve_decision(
                decision_input(&task),
                &mut action_ctx(&mut world, &session, &config),
            )
            .expect("ask publishes the provider artifact"),
    );
    let served = world.dispatch(&corpus_question_current(&session, &task, json!(190)));
    assert!(served["error"].is_null(), "{served}");
    let wire_question: Question = serde_json::from_value(served["result"]["question"].clone())
        .expect("the wire serves the canonical Question shape");
    assert_eq!(
        wire_question, produced,
        "provider output and wire artifact are the same versioned contract"
    );
}

#[test]
fn consumer_question_answer() {
    // Consumer leg: the served `Question` is answered through the shared
    // wire seam with the canonical `AnswerSelection` — applied, journaled
    // against the pinned revisions, and attributed to the human
    // principal. Model pools + a scoped read mirror the wire answer's
    // world so the resumed node can dispatch.
    let mut world = open_world(
        "tp-consumer-question",
        Some(&support::config_distinct_pools()),
    );
    let session = world.open_session("decision-session");
    let task = world.create_task(&session, "cmd-consumer-task");
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-consumer-marker\n").expect("scoped file");
    world.runtime.purpose = "backend_task".to_string();
    world.runtime.set_read_scope(scope, file);

    let registry = ActionRegistry::new();
    let config = decision_config(None);
    asked_question(
        registry
            .resolve_decision(
                decision_input(&task),
                &mut action_ctx(&mut world, &session, &config),
            )
            .expect("ask publishes"),
    );
    // The consumer acts on the wire shape, not the in-memory artifact.
    let served = world.dispatch(&corpus_question_current(&session, &task, json!(191)));
    let served_question: Question = serde_json::from_value(served["result"]["question"].clone())
        .expect("canonical wire question");
    let answered = world.dispatch(&corpus_answer_option(
        &session,
        "cmd-consumer-answer",
        &task,
        &served_question,
        "stage",
        json!(192),
    ));
    assert!(answered["error"].is_null(), "{answered}");
    assert_eq!(answered["result"]["status"], "applied");

    let attempts = world
        .runtime
        .store()
        .answer_attempts(&task)
        .expect("attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].outcome, AnswerAttemptOutcome::Applied);
    assert_eq!(
        attempts[0].selection,
        AnswerSelection::Option {
            option_id: OptionId("stage".to_string())
        },
        "the canonical selection round-tripped the shared seam"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .snapshot(&task)
            .expect("snapshot")
            .lifecycle,
        rivect::contracts::Lifecycle::Completed,
        "the consumer's answer resumed the task to completion"
    );
}

// ----- append-only answer journal -----

#[test]
fn answer_attempts_journal_applied_and_denied_in_order() {
    let (mut world, session, task) = world_with_task("decision-journal");
    let question = world.publish(&session, &task);
    let mut store = world.runtime.store_writer();

    let stale = store
        .answer_question(
            &session,
            &task,
            &question.question_id,
            99,
            &AnswerSelection::Option {
                option_id: OptionId(KNOWN_READY_OPTION.to_string()),
            },
            "human",
        )
        .expect_err("a wrong revision denies");
    assert!(matches!(
        stale,
        StoreError::Conflict(ConflictCause::QuestionRevision { .. })
    ));

    let disabled = store
        .answer_question(
            &session,
            &task,
            &question.question_id,
            question.question_revision,
            &AnswerSelection::Option {
                option_id: OptionId("diagram".to_string()),
            },
            "human",
        )
        .expect_err("a disabled option denies");
    assert!(matches!(
        disabled,
        StoreError::InvalidInput(InvalidCause::DisabledOption { .. })
    ));

    let unknown = store
        .answer_question(
            &session,
            &task,
            &question.question_id,
            question.question_revision,
            &AnswerSelection::Option {
                option_id: OptionId("bogus".to_string()),
            },
            "human",
        )
        .expect_err("an unknown option denies");
    assert!(matches!(
        unknown,
        StoreError::InvalidInput(InvalidCause::UnknownOption { .. })
    ));

    let empty = store
        .answer_question(
            &session,
            &task,
            &question.question_id,
            question.question_revision,
            &AnswerSelection::Custom {
                text: "   ".to_string(),
            },
            "human",
        )
        .expect_err("an empty custom answer denies");
    assert!(matches!(
        empty,
        StoreError::InvalidInput(InvalidCause::EmptyCustomAnswer)
    ));

    store
        .answer_question(
            &session,
            &task,
            &question.question_id,
            question.question_revision,
            &AnswerSelection::Option {
                option_id: OptionId(KNOWN_READY_OPTION.to_string()),
            },
            "human",
        )
        .expect("the valid answer applies");

    let attempts = store.store().answer_attempts(&task).expect("attempts");
    assert_eq!(attempts.len(), 5, "{attempts:?}");
    let denials: Vec<&str> = attempts[..4]
        .iter()
        .map(|attempt| {
            attempt
                .denial
                .as_deref()
                .expect("denied rows carry a cause")
        })
        .collect();
    assert_eq!(
        denials,
        [
            "stale_revision",
            "disabled_option",
            "unknown_option",
            "empty_custom"
        ],
        "denials journal typed causes in commit order"
    );
    assert!(
        attempts[..4]
            .iter()
            .all(|a| a.outcome == AnswerAttemptOutcome::Denied),
        "every rejection is journaled denied"
    );
    let applied = &attempts[4];
    assert_eq!(applied.outcome, AnswerAttemptOutcome::Applied);
    assert_eq!(applied.author, "human");
    assert!(applied.denial.is_none());
    assert!(
        attempts.windows(2).all(|pair| pair[0].id < pair[1].id),
        "attempt ids are monotonic — append-only, never rewritten"
    );
}

#[test]
fn answer_attempts_survive_reopen() {
    let root =
        tempfile::TempDir::with_prefix("rivect-decision-journal-reopen-").expect("fixture root");
    let task;
    {
        let mut world = support::open_world_at(root.path(), None);
        let session = world.open_session("reopen-session");
        let created = world.create_task(&session, "cmd-reopen");
        let question = world.publish(&session, &created);
        world
            .runtime
            .store_writer()
            .answer_question(
                &session,
                &created,
                &question.question_id,
                99,
                &AnswerSelection::Custom {
                    text: "too late".to_string(),
                },
                "human",
            )
            .expect_err("the denial journals before close");
        task = created;
    }
    let world = support::open_world_at(root.path(), None);
    let attempts = world
        .runtime
        .store()
        .answer_attempts(&task)
        .expect("attempts after reopen");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].outcome, AnswerAttemptOutcome::Denied);
    assert_eq!(attempts[0].denial.as_deref(), Some("stale_revision"));
}

#[test]
fn dispatch_layer_denials_journal_the_attempt() {
    let (mut world, session, task) = world_with_task("decision-wire-denials");
    let question = world.publish(&session, &task);

    // Machine ingress: an SDK answer never proves consent — the denial
    // journals under the machine principal, not silently.
    let machine = world.dispatch_machine(&corpus_answer_option(
        &session,
        "cmd-machine-answer",
        &task,
        &question,
        KNOWN_READY_OPTION,
        json!(140),
    ));
    assert_eq!(
        machine["error"]["data"]["code"], "denied",
        "machine ingress denies typed: {machine}"
    );

    // A missing revision pin: the attempt names the question, the
    // denial journals against it.
    let missing_pin = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 141, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-no-pin", "session_id": session.0,
                    "kind": "answer", "task_id": task.0,
                    "question_id": question.question_id.0, "question_revision": 1,
                    "selection": { "kind": "option", "option_id": KNOWN_READY_OPTION } }
    }));
    assert_eq!(
        missing_pin["error"]["data"]["code"], "invalid_input",
        "a missing revision pin denies typed: {missing_pin}"
    );

    // An unparseable selection journals its raw request bytes.
    let malformed = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 142, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-bad-selection", "session_id": session.0,
                    "kind": "answer", "task_id": task.0,
                    "expected_intent_revision": question.intent_revision,
                    "question_id": question.question_id.0, "question_revision": question.question_revision,
                    "selection": { "kind": "bogus" } }
    }));
    assert_eq!(
        malformed["error"]["data"]["code"], "invalid_input",
        "an unparseable selection denies typed: {malformed}"
    );

    // A valid pin set without the field journals too — the required-
    // field denial is still an answer attempt, and its recorded payload
    // is the absent `selection` verbatim: null.
    let selectionless = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 143, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-no-selection", "session_id": session.0,
                    "kind": "answer", "task_id": task.0,
                    "expected_intent_revision": question.intent_revision,
                    "question_id": question.question_id.0, "question_revision": question.question_revision }
    }));
    assert!(
        selectionless["error"]["data"]["message"]
            .as_str()
            .is_some_and(|m| m == "selection is required"),
        "the required-field denial surfaces: {selectionless}"
    );

    // A stale intent pin denies before the store gate — still journaled.
    let stale = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 144, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-stale-intent", "session_id": session.0,
                    "kind": "answer", "task_id": task.0,
                    "expected_intent_revision": question.intent_revision + 9,
                    "question_id": question.question_id.0, "question_revision": question.question_revision,
                    "selection": { "kind": "option", "option_id": KNOWN_READY_OPTION } }
    }));
    assert_eq!(
        stale["error"]["data"]["code"], "stale_intent",
        "a stale intent pin denies typed: {stale}"
    );

    let attempts = world
        .runtime
        .store()
        .answer_attempts(&task)
        .expect("attempts");
    assert_eq!(
        attempts
            .iter()
            .map(|attempt| (
                attempt.author.as_str(),
                attempt.denial.as_deref().unwrap_or("")
            ))
            .collect::<Vec<_>>(),
        [
            ("machine", "machine_ingress"),
            ("human", "missing_revision_fields"),
            ("human", "invalid_selection"),
            ("human", "missing_selection"),
            ("human", "stale_intent"),
        ],
        "every dispatch-layer denial journals in commit order: {attempts:?}"
    );
    assert_eq!(
        attempts[3].selection,
        AnswerSelection::Custom {
            text: "null".to_string()
        },
        "the absent field journals verbatim and the typed read degrades \
         to the raw payload: {attempts:?}"
    );
    assert!(
        attempts
            .iter()
            .all(|attempt| attempt.outcome == AnswerAttemptOutcome::Denied),
        "no dispatch denial applies"
    );
    assert!(
        world
            .runtime
            .store()
            .current_question(&task)
            .expect("current")
            .is_some(),
        "every denial preserved the pending question"
    );
}

#[test]
fn snapshot_failures_journal_their_typed_class() {
    let (mut world, session, task) = world_with_task("decision-snapshot-class");
    let question = world.publish(&session, &task);

    // A missing task is the baseline: the snapshot lookup fails
    // NotFound and the journal records that class.
    let ghost = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 190, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-ghost-task", "session_id": session.0,
                    "kind": "answer", "task_id": "task-does-not-exist",
                    "expected_intent_revision": question.intent_revision,
                    "question_id": question.question_id.0, "question_revision": question.question_revision,
                    "selection": { "kind": "option", "option_id": KNOWN_READY_OPTION } }
    }));
    assert_eq!(
        ghost["error"]["data"]["code"], "not_found",
        "the missing task surfaces its own code: {ghost}"
    );

    // A storage fault must journal "storage", never masquerade as
    // not_found: a foreign connection drops the tasks table so the
    // owner's next snapshot reads a genuine backend failure.
    {
        let conn =
            rusqlite::Connection::open(world.root.join("runtime").join("rivect.db")).expect("conn");
        conn.execute_batch("DROP TABLE tasks")
            .expect("the fault lands");
    }
    let broken = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 191, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-broken-store", "session_id": session.0,
                    "kind": "answer", "task_id": task.0,
                    "expected_intent_revision": question.intent_revision,
                    "question_id": question.question_id.0, "question_revision": question.question_revision,
                    "selection": { "kind": "option", "option_id": KNOWN_READY_OPTION } }
    }));
    assert_eq!(
        broken["error"]["data"]["code"], "storage_unavailable",
        "the storage fault surfaces its own code: {broken}"
    );

    // Each attempt journaled under the store's own class — the journal
    // table is untouched by the fault, so both rows read back.
    let ghost_attempts = world
        .runtime
        .store()
        .answer_attempts(&TaskId("task-does-not-exist".to_string()))
        .expect("ghost attempts");
    assert_eq!(
        ghost_attempts
            .iter()
            .map(|attempt| attempt.denial.as_deref())
            .collect::<Vec<_>>(),
        [Some("not_found")]
    );
    let attempts = world
        .runtime
        .store()
        .answer_attempts(&task)
        .expect("attempts");
    assert_eq!(
        attempts
            .iter()
            .map(|attempt| attempt.denial.as_deref())
            .collect::<Vec<_>>(),
        [Some("storage")],
        "a backend failure never reports the not_found class: {attempts:?}"
    );
}

#[test]
fn steer_supersedes_the_pinned_question_and_frees_the_fork() {
    let (mut world, session, task) = world_with_task("decision-steer-waiting");
    let stale = world.publish(&session, &task);
    let pinned = world.runtime.store().snapshot(&task).expect("snapshot");

    let steered = world.dispatch(&corpus_steer(
        &session,
        "cmd-steer-waiting",
        &task,
        pinned.intent_revision,
        pinned.revision,
        json!(150),
    ));
    assert!(steered["error"].is_null(), "{steered}");

    let snapshot = world.runtime.store().snapshot(&task).expect("snapshot");
    assert_eq!(
        snapshot.lifecycle,
        rivect::contracts::Lifecycle::Running,
        "a superseded wait ends — nothing is blocked on the dead fork"
    );
    assert!(
        world
            .runtime
            .store()
            .current_question(&task)
            .expect("current")
            .is_none(),
        "the stale pin hides from the current read"
    );

    // The dead row stays for audit: answering it denies and journals.
    let denied = world
        .runtime
        .store_writer()
        .answer_question(
            &session,
            &task,
            &stale.question_id,
            stale.question_revision,
            &AnswerSelection::Option {
                option_id: OptionId(KNOWN_READY_OPTION.to_string()),
            },
            "human",
        )
        .expect_err("a superseded question never answers");
    assert!(
        matches!(
            denied,
            StoreError::StaleIntent { expected, current }
                if expected == stale.intent_revision && current == snapshot.intent_revision
        ),
        "the denial names the stale pin, not a generic conflict: {denied}"
    );
    let attempts = world
        .runtime
        .store()
        .answer_attempts(&task)
        .expect("attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].outcome, AnswerAttemptOutcome::Denied);
    assert_eq!(attempts[0].denial.as_deref(), Some("stale_intent"));

    // The kill rides the task's replay feed as its own event — the
    // aggregate is the dead question at its own revision, so the task's
    // monotonic stream is untouched and `task_id` keeps the death inside
    // the task filter.
    let feed = world
        .runtime
        .store()
        .events_after(&session, Some(&task), 0, 100)
        .expect("task event feed");
    let superseded: Vec<&rivect::contracts::Event> = feed
        .iter()
        .filter(|event| event.event_type == "question.superseded")
        .collect();
    assert_eq!(
        superseded.len(),
        1,
        "one supersession event per killed row: {feed:?}"
    );
    let death = superseded[0];
    assert_eq!(death.aggregate_id, stale.question_id.0);
    assert_eq!(death.aggregate_revision, stale.question_revision);
    assert_eq!(death.task_id.as_ref(), Some(&task));
    assert_eq!(death.origin, "human");
    assert_eq!(
        death.delta,
        json!({
            "question_id": stale.question_id.0,
            "question_revision": stale.question_revision,
            "stale_intent_revision": stale.intent_revision,
            "live_intent_revision": snapshot.intent_revision,
        }),
        "the delta names both pins: {death:?}"
    );
    // A spec-conformant client applies the revision-contiguity rule per
    // aggregate: filtered to the task stream, the feed still climbs
    // revision by revision with no interleaved question revision.
    let mut projection = rivect::ui::Projection::new(0);
    for event in feed.iter().filter(|event| event.aggregate_id == task.0) {
        assert_eq!(
            projection.apply(event),
            rivect::ui::ApplyVerdict::Applied,
            "task-aggregate events stay monotonic: {event:?}"
        );
    }

    // The steered intent's fork publishes — the dead row never blocks it.
    let fresh = Question::fixture(&task, snapshot.intent_revision);
    world
        .runtime
        .store_writer()
        .publish_question(&session, &fresh)
        .expect("the new fork publishes on the steered intent");
    let current = world
        .runtime
        .store()
        .current_question(&task)
        .expect("current")
        .expect("a live pending question again");
    assert_eq!(current.0.question_id, fresh.question_id);
    assert_eq!(current.0.intent_revision, snapshot.intent_revision);
    assert_eq!(
        world
            .runtime
            .store()
            .snapshot(&task)
            .expect("snapshot")
            .lifecycle,
        rivect::contracts::Lifecycle::Waiting,
        "the new fork waits on its question"
    );
}

#[test]
fn publish_supersedes_a_leftover_pending_row_and_journals_it() {
    let (mut world, session, task) = world_with_task("decision-publish-supersede");
    // Steer the running task so the live intent moves to 2 with no
    // pending row attached.
    let steered = world.dispatch(&corpus_steer(
        &session,
        "cmd-steer-running",
        &task,
        1,
        1,
        json!(170),
    ));
    assert!(steered["error"].is_null(), "{steered}");

    // A pending row pinned to the dead intent — the shape a foreign
    // writer or a pre-journal build leaves behind. The store API itself
    // cannot mint this shape (steer kills stale pendings in its own
    // transaction), so the fixture writes the row directly into the
    // runtime database.
    let leftover = Question::fixture(&task, 1);
    {
        let conn =
            rusqlite::Connection::open(world.root.join("runtime").join("rivect.db")).expect("conn");
        conn.execute(
            "INSERT INTO questions (question_id, task_id, revision, intent_revision, prompt, body_json, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending')",
            rusqlite::params![
                leftover.question_id.0,
                task.0,
                leftover.question_revision as i64,
                leftover.intent_revision as i64,
                leftover.prompt,
                serde_json::to_string(&leftover).expect("fixture serializes"),
            ],
        )
        .expect("leftover pending row lands");
    }

    // Publishing the live-intent fork kills the leftover inside the
    // publish transaction — and the death journals as an event, origin
    // "state", not silently.
    let fresh = Question::fixture(&task, 2);
    world
        .runtime
        .store_writer()
        .publish_question(&session, &fresh)
        .expect("the live-intent fork publishes over the leftover");

    let feed = world
        .runtime
        .store()
        .events_after(&session, Some(&task), 0, 100)
        .expect("task event feed");
    let superseded: Vec<&rivect::contracts::Event> = feed
        .iter()
        .filter(|event| event.event_type == "question.superseded")
        .collect();
    assert_eq!(
        superseded.len(),
        1,
        "the publish-path kill journals exactly once: {feed:?}"
    );
    let death = superseded[0];
    assert_eq!(death.aggregate_id, leftover.question_id.0);
    assert_eq!(death.aggregate_revision, leftover.question_revision);
    assert_eq!(death.task_id.as_ref(), Some(&task));
    assert_eq!(death.origin, "state");
    assert_eq!(death.delta["stale_intent_revision"], json!(1));
    assert_eq!(death.delta["live_intent_revision"], json!(2));

    let current = world
        .runtime
        .store()
        .current_question(&task)
        .expect("current")
        .expect("the fresh question is live");
    assert_eq!(current.0.question_id, fresh.question_id);
    assert_eq!(current.0.intent_revision, 2);
}

#[test]
fn publish_rejects_a_fork_pinned_to_a_superseded_intent() {
    let (mut world, session, task) = world_with_task("decision-stale-fork");
    // Crafted before the steer, the fork pins the intent that was live then.
    let stale_pin = Question::fixture(&task, 1);
    let steered = world.dispatch(&corpus_steer(
        &session,
        "cmd-steer-first",
        &task,
        1,
        1,
        json!(160),
    ));
    assert!(steered["error"].is_null(), "{steered}");

    let error = world
        .runtime
        .store_writer()
        .publish_question(&session, &stale_pin)
        .expect_err("a stale-pinned fork must not publish");
    assert!(matches!(error, StoreError::StaleIntent { .. }), "{error}");
    assert!(
        world
            .runtime
            .store()
            .current_question(&task)
            .expect("current")
            .is_none(),
        "the rejected publish published nothing"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .snapshot(&task)
            .expect("snapshot")
            .lifecycle,
        rivect::contracts::Lifecycle::Running,
        "the rejected fork never moved the task"
    );
}

// ----- terminal lifecycle supersedes the pending question -----

#[test]
fn terminal_lifecycle_classification_is_closed() {
    // The closed set the question kill and the answer gate read from:
    // completed and cancelled are terminal; every live lifecycle still
    // owns its pending question.
    use rivect::contracts::Lifecycle;
    for terminal in [Lifecycle::Completed, Lifecycle::Cancelled] {
        assert!(terminal.is_terminal(), "{terminal:?} is terminal");
    }
    for live in [
        Lifecycle::Running,
        Lifecycle::Waiting,
        Lifecycle::Paused,
        Lifecycle::Blocked,
    ] {
        assert!(!live.is_terminal(), "{live:?} still admits work");
    }
}

/// Pending/superseded question counts read straight off the durable
/// store — the terminal transition's kill is a row-state claim, not a
/// view the projection could hide.
fn question_state_counts(db: &std::path::Path, task: &TaskId) -> (i64, i64) {
    let conn = rusqlite::Connection::open(db).expect("conn");
    let count = |state: &str| -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM questions WHERE task_id = ?1 AND state = ?2",
            rusqlite::params![task.0, state],
            |row| row.get(0),
        )
        .expect("question count")
    };
    (count("pending"), count("superseded"))
}

#[test]
fn cancel_supersedes_the_pending_question_and_journals_it() {
    let (mut world, session, task) = world_with_task("decision-cancel-waiting");
    let question = world.publish(&session, &task);
    assert!(
        world
            .runtime
            .store()
            .current_question(&task)
            .expect("current")
            .is_some(),
        "the fork waits pending"
    );

    let cancelled = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 210, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-cancel-waiting", "session_id": session.0,
                    "kind": "cancel", "task_id": task.0,
                    "expected_intent_revision": 1, "reason": "operator aborted" }
    }));
    assert!(cancelled["error"].is_null(), "{cancelled}");
    assert_eq!(cancelled["result"]["status"], "applied");
    assert_eq!(
        cancelled["result"]["snapshot"]["lifecycle"], "cancelled",
        "the response carries the terminal snapshot: {cancelled}"
    );

    let db = world.root.join("runtime").join("rivect.db");
    assert_eq!(
        question_state_counts(&db, &task),
        (0, 1),
        "the pending row died with its task — superseded, never answered"
    );
    assert!(
        world
            .runtime
            .store()
            .current_question(&task)
            .expect("current")
            .is_none(),
        "a terminal task has no current question"
    );

    // The kill rides the task feed as its own event — same transaction
    // as the cancel, never a silent row update.
    let feed = world
        .runtime
        .store()
        .events_after(&session, Some(&task), 0, 100)
        .expect("task feed");
    let superseded: Vec<&rivect::contracts::Event> = feed
        .iter()
        .filter(|event| event.event_type == "question.superseded")
        .collect();
    assert_eq!(superseded.len(), 1, "one supersession event: {feed:?}");
    assert_eq!(superseded[0].aggregate_id, question.question_id.0);
    assert_eq!(superseded[0].aggregate_revision, question.question_revision);
    assert_eq!(superseded[0].task_id.as_ref(), Some(&task));
    assert_eq!(superseded[0].origin, "human");
    assert_eq!(
        superseded[0].delta["lifecycle"], "cancelled",
        "the delta names the terminal lifecycle that killed it: {:?}",
        superseded[0].delta
    );
    let kills: Vec<&rivect::contracts::Event> = feed
        .iter()
        .filter(|event| event.event_type == "task.cancelled")
        .collect();
    assert_eq!(kills.len(), 1, "{feed:?}");
    assert_eq!(kills[0].delta["reason"], "operator aborted");
    assert_eq!(
        kills[0].origin, "human",
        "the operator's cancel journals its human origin: {feed:?}"
    );

    // The dead row never answers: the denial is terminal and journaled.
    let denied = world
        .runtime
        .store_writer()
        .answer_question(
            &session,
            &task,
            &question.question_id,
            question.question_revision,
            &AnswerSelection::Option {
                option_id: OptionId(KNOWN_READY_OPTION.to_string()),
            },
            "human",
        )
        .expect_err("a terminal task's question never answers");
    assert!(
        matches!(denied, StoreError::AlreadyTerminal),
        "the denial names the terminal state: {denied}"
    );
    let attempts = world
        .runtime
        .store()
        .answer_attempts(&task)
        .expect("attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].outcome, AnswerAttemptOutcome::Denied);
    assert_eq!(attempts[0].denial.as_deref(), Some("already_terminal"));

    // The wire read agrees: no current question on the dead task.
    let current = world.dispatch(&corpus_question_current(&session, &task, json!(211)));
    assert!(
        current["result"]["question"].is_null(),
        "question.current reports none on the terminal task: {current}"
    );
}

#[test]
fn completion_supersedes_the_pending_question_and_journals_it() {
    let (mut world, session, task) = world_with_task("decision-complete-waiting");
    let question = world.publish(&session, &task);

    // A waiting task whose ledger is clean completes through the same
    // seam the drain's tail runs — the pending row dies inside the
    // transition's transaction.
    let snapshot = world
        .runtime
        .store_writer()
        .complete_if_eligible(&session, &task)
        .expect("a waiting task with a clean ledger completes");
    assert_eq!(snapshot.lifecycle, rivect::contracts::Lifecycle::Completed);

    let db = world.root.join("runtime").join("rivect.db");
    assert_eq!(
        question_state_counts(&db, &task),
        (0, 1),
        "completion killed the pending row"
    );
    assert!(
        world
            .runtime
            .store()
            .current_question(&task)
            .expect("current")
            .is_none(),
        "a completed task has no current question"
    );

    let feed = world
        .runtime
        .store()
        .events_after(&session, Some(&task), 0, 100)
        .expect("task feed");
    let superseded: Vec<&rivect::contracts::Event> = feed
        .iter()
        .filter(|event| event.event_type == "question.superseded")
        .collect();
    assert_eq!(superseded.len(), 1, "one supersession event: {feed:?}");
    assert_eq!(superseded[0].aggregate_id, question.question_id.0);
    assert_eq!(superseded[0].origin, "state");
    assert_eq!(superseded[0].delta["lifecycle"], "completed");
    assert!(
        feed.iter()
            .any(|event| event.event_type == "task.completed"),
        "the completion event rides the same feed: {feed:?}"
    );

    let denied = world
        .runtime
        .store_writer()
        .answer_question(
            &session,
            &task,
            &question.question_id,
            question.question_revision,
            &AnswerSelection::Option {
                option_id: OptionId(KNOWN_READY_OPTION.to_string()),
            },
            "human",
        )
        .expect_err("a completed task's question never answers");
    assert!(matches!(denied, StoreError::AlreadyTerminal), "{denied}");
}

#[test]
fn already_terminal_cancel_heals_a_leftover_pending_row() {
    let (mut world, session, task) = world_with_task("decision-cancel-heal");
    // Cancel the running task first — no question ever published.
    let first = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 220, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-cancel-live", "session_id": session.0,
                    "kind": "cancel", "task_id": task.0,
                    "expected_intent_revision": 1, "reason": "operator aborted" }
    }));
    assert_eq!(first["result"]["status"], "applied", "{first}");

    // A pending row outliving its task is the pre-journal/foreign-writer
    // shape — the fixture writes it directly, like the leftover row the
    // publish-seam test drives.
    let leftover = Question::fixture(&task, 1);
    {
        let conn =
            rusqlite::Connection::open(world.root.join("runtime").join("rivect.db")).expect("conn");
        conn.execute(
            "INSERT INTO questions (question_id, task_id, revision, intent_revision, prompt, body_json, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending')",
            rusqlite::params![
                leftover.question_id.0,
                task.0,
                leftover.question_revision as i64,
                leftover.intent_revision as i64,
                leftover.prompt,
                serde_json::to_string(&leftover).expect("fixture serializes"),
            ],
        )
        .expect("leftover pending row lands");
    }

    // The idempotent observe is not write-free: the already-terminal
    // cancel still kills and journals the stale row.
    let replayed = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 221, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-cancel-replay", "session_id": session.0,
                    "kind": "cancel", "task_id": task.0,
                    "expected_intent_revision": 1, "reason": "operator aborted" }
    }));
    assert_eq!(
        replayed["result"]["status"], "already_terminal",
        "the replay acks terminal honestly: {replayed}"
    );
    let db = world.root.join("runtime").join("rivect.db");
    assert_eq!(
        question_state_counts(&db, &task),
        (0, 1),
        "the leftover row healed superseded"
    );
    assert!(
        world
            .runtime
            .store()
            .current_question(&task)
            .expect("current")
            .is_none(),
        "the terminal read never resurrects the leftover"
    );
    let feed = world
        .runtime
        .store()
        .events_after(&session, Some(&task), 0, 100)
        .expect("task feed");
    let superseded: Vec<&rivect::contracts::Event> = feed
        .iter()
        .filter(|event| event.event_type == "question.superseded")
        .collect();
    assert_eq!(
        superseded.len(),
        1,
        "the heal journaled exactly once: {feed:?}"
    );
    assert_eq!(superseded[0].aggregate_id, leftover.question_id.0);
    assert_eq!(superseded[0].delta["lifecycle"], "cancelled");
    assert_eq!(superseded[0].origin, "human");
}

#[test]
fn waiting_task_with_a_stale_leftover_admits_the_replacement_fork() {
    let (mut world, session, task) = world_with_task("decision-waiting-leftover");
    let first = world.publish(&session, &task);

    // A pending row outliving its intent is the shape a pre-journal
    // write or a foreign writer leaves: the task still waits on its
    // question while the row's pin names an intent the task no longer
    // holds. The store's own seams cannot mint it — the steer that
    // moves an intent supersedes the row in the same commit — so the
    // fixture bumps the live intent directly.
    {
        let conn =
            rusqlite::Connection::open(world.root.join("runtime").join("rivect.db")).expect("conn");
        conn.execute(
            "UPDATE tasks SET intent_revision = 2 WHERE task_id = ?1",
            rusqlite::params![task.0],
        )
        .expect("the live intent moves past the pending row");
    }
    assert_eq!(
        world
            .runtime
            .store()
            .snapshot(&task)
            .expect("snapshot")
            .lifecycle,
        rivect::contracts::Lifecycle::Waiting,
        "the task still waits — only the row's pin went stale"
    );

    // The publish path hides the stale row from `current_question`,
    // admits the replacement on the widened `waiting` arm, and kills
    // the leftover inside the same transaction.
    let registry = ActionRegistry::new();
    let config = decision_config(None);
    let outcome = registry
        .resolve_decision(
            decision_input(&task),
            &mut action_ctx(&mut world, &session, &config),
        )
        .expect("a waiting task publishes the replacement fork");
    let published = asked_question(outcome);
    assert_ne!(published.question_id, first.question_id);
    assert_eq!(
        published.intent_revision, 2,
        "the fork pins the live intent"
    );

    let db = world.root.join("runtime").join("rivect.db");
    assert_eq!(
        question_state_counts(&db, &task),
        (1, 1),
        "the leftover superseded beside the fresh pending row"
    );
    let (current, _) = world
        .runtime
        .store()
        .current_question(&task)
        .expect("current")
        .expect("the replacement is the task's live question");
    assert_eq!(current.question_id, published.question_id);
    assert_eq!(
        world
            .runtime
            .store()
            .snapshot(&task)
            .expect("snapshot")
            .lifecycle,
        rivect::contracts::Lifecycle::Waiting,
        "republishing never leaves the waiting lifecycle"
    );

    // The kill journals its own event: the stale pin and the live
    // intent it died to are both named, under the state origin.
    let feed = world
        .runtime
        .store()
        .events_after(&session, Some(&task), 0, 100)
        .expect("task feed");
    let superseded: Vec<&rivect::contracts::Event> = feed
        .iter()
        .filter(|event| event.event_type == "question.superseded")
        .collect();
    assert_eq!(
        superseded.len(),
        1,
        "the republish-path kill journals exactly once: {feed:?}"
    );
    assert_eq!(superseded[0].aggregate_id, first.question_id.0);
    assert_eq!(superseded[0].origin, "state");
    assert_eq!(superseded[0].delta["stale_intent_revision"], json!(1));
    assert_eq!(superseded[0].delta["live_intent_revision"], json!(2));
}

#[test]
fn terminal_task_never_serves_or_admits_a_leftover_question() {
    let (mut world, session, task) = world_with_task("decision-terminal-leftover");
    // Cancel the running task first — no question ever published.
    let cancelled = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 225, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-cancel-first", "session_id": session.0,
                    "kind": "cancel", "task_id": task.0,
                    "expected_intent_revision": 1, "reason": "operator aborted" }
    }));
    assert_eq!(cancelled["result"]["status"], "applied", "{cancelled}");

    // A foreign writer leaves a pending row beside the terminal task —
    // pinned to the live intent, so only the lifecycle clause hides it.
    let leftover = Question::fixture(&task, 1);
    {
        let conn =
            rusqlite::Connection::open(world.root.join("runtime").join("rivect.db")).expect("conn");
        conn.execute(
            "INSERT INTO questions (question_id, task_id, revision, intent_revision, prompt, body_json, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending')",
            rusqlite::params![
                leftover.question_id.0,
                task.0,
                leftover.question_revision as i64,
                leftover.intent_revision as i64,
                leftover.prompt,
                serde_json::to_string(&leftover).expect("fixture serializes"),
            ],
        )
        .expect("leftover pending row lands");
    }

    // Reads never resurrect it — the SQL lifecycle clause, not the pin.
    assert!(
        world
            .runtime
            .store()
            .current_question(&task)
            .expect("current")
            .is_none(),
        "a pending row beside a terminal task is never current"
    );
    let current = world.dispatch(&corpus_question_current(&session, &task, json!(226)));
    assert!(
        current["result"]["question"].is_null(),
        "question.current agrees on the wire: {current}"
    );

    // Writes deny on the lifecycle — the store seam and the action
    // seam name the same typed conflict, and the row is never healed
    // by a failed publish.
    let denied = world
        .runtime
        .store_writer()
        .publish_question(&session, &Question::fixture(&task, 1))
        .expect_err("a terminal task admits no fork");
    assert!(
        matches!(
            denied,
            StoreError::Conflict(ConflictCause::QuestionOnLifecycle { ref lifecycle })
                if lifecycle == "cancelled"
        ),
        "the denial names the lifecycle: {denied}"
    );
    let registry = ActionRegistry::new();
    let config = decision_config(None);
    let denied = registry
        .resolve_decision(
            decision_input(&task),
            &mut action_ctx(&mut world, &session, &config),
        )
        .expect_err("the action seam denies identically");
    assert!(
        matches!(
            denied,
            ActionError::Store(StoreError::Conflict(
                ConflictCause::QuestionOnLifecycle { ref lifecycle }
            )) if lifecycle == "cancelled"
        ),
        "the typed conflict reaches the action boundary: {denied}"
    );
    assert_eq!(
        question_state_counts(&world.root.join("runtime").join("rivect.db"), &task),
        (1, 0),
        "a denied publish never heals — the row stays for audit"
    );
}

#[test]
fn wire_answer_on_a_settled_tree_reports_the_terminal_snapshot() {
    let (mut world, session, task) = world_with_task("decision-wire-settled");
    let question = world.publish(&session, &task);

    // The tree drains while the question stays pending — the task row
    // itself is untouched, so the wire answer still commits; only the
    // scheduler refuses to grow runnable work for it.
    world
        .runtime
        .scheduler
        .cancel_task_tree(&task)
        .expect("tree cancel drains");

    // A second pending row pinned under the live intent — the leftover
    // a foreign writer or a pre-journal build can leave beside a task
    // the scheduler already declared dead. The settle must kill it and
    // journal the kill under its own origin, not the operator's.
    let leftover = Question::fixture(&task, 1);
    {
        let conn =
            rusqlite::Connection::open(world.root.join("runtime").join("rivect.db")).expect("conn");
        conn.execute(
            "INSERT INTO questions (question_id, task_id, revision, intent_revision, prompt, body_json, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending')",
            rusqlite::params![
                leftover.question_id.0,
                task.0,
                leftover.question_revision as i64,
                leftover.intent_revision as i64,
                leftover.prompt,
                serde_json::to_string(&leftover).expect("fixture serializes"),
            ],
        )
        .expect("leftover pending row lands");
    }

    let answered = world.dispatch(&corpus_answer_option(
        &session,
        "cmd-settled-answer",
        &task,
        &question,
        KNOWN_READY_OPTION,
        json!(230),
    ));
    assert!(answered["error"].is_null(), "{answered}");
    assert_eq!(
        answered["result"]["status"], "applied",
        "the answer is durable: {answered}"
    );
    assert_eq!(
        answered["result"]["snapshot"]["lifecycle"], "cancelled",
        "the wire response reports the terminal snapshot, never the \
         pre-resume running row: {answered}"
    );

    // Durable state agrees — the resume settled the row through the
    // cancel seam and journaled the death with its reason.
    assert_eq!(
        world
            .runtime
            .store()
            .snapshot(&task)
            .expect("snapshot")
            .lifecycle,
        rivect::contracts::Lifecycle::Cancelled
    );
    let attempts = world
        .runtime
        .store()
        .answer_attempts(&task)
        .expect("attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        attempts[0].outcome,
        AnswerAttemptOutcome::Applied,
        "the committed answer stays durable"
    );
    let feed = world
        .runtime
        .store()
        .events_after(&session, Some(&task), 0, 100)
        .expect("task feed");
    assert!(
        feed.iter()
            .any(|event| event.event_type == "question.answered"),
        "the answer event journaled: {feed:?}"
    );
    let kills: Vec<&rivect::contracts::Event> = feed
        .iter()
        .filter(|event| event.event_type == "task.cancelled")
        .collect();
    assert_eq!(kills.len(), 1, "{feed:?}");
    assert!(
        kills[0].delta["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("settled or cancelled")),
        "the settle reason names the dead tree: {:?}",
        kills[0].delta
    );
    // The settle is state-driven: the scheduler declared the tree dead
    // before the answer arrived, so `task.cancelled` — and the
    // supersession of the leftover pending row it rode in on — journal
    // under the state machine's origin, never `human`.
    assert_eq!(
        kills[0].origin, "state",
        "a scheduler-driven settle must not impersonate the operator: {feed:?}"
    );
    let superseded: Vec<&rivect::contracts::Event> = feed
        .iter()
        .filter(|event| event.event_type == "question.superseded")
        .collect();
    assert_eq!(
        superseded.len(),
        1,
        "the settle killed the leftover pending row: {feed:?}"
    );
    assert_eq!(superseded[0].aggregate_id, leftover.question_id.0);
    assert_eq!(
        superseded[0].origin, "state",
        "the kill's provenance is the settle, not a human: {feed:?}"
    );
    assert_eq!(superseded[0].delta["lifecycle"], "cancelled");
    assert!(
        world
            .runtime
            .store()
            .current_question(&task)
            .expect("current")
            .is_none(),
        "the answered+settled question is not pending"
    );
}

#[test]
fn cross_task_question_id_never_answers() {
    let (mut world, session, task) = world_with_task("decision-cross-task");
    let other = world.create_task(&session, "cmd-decision-other-task");
    let question = world.publish(&session, &task);
    let selection = AnswerSelection::Option {
        option_id: OptionId(KNOWN_READY_OPTION.to_string()),
    };

    // Store seam: the question id is bound to its task — quoting it
    // against a sibling denies not_found and journals on the sibling.
    let denied = world
        .runtime
        .store_writer()
        .answer_question(
            &session,
            &other,
            &question.question_id,
            question.question_revision,
            &selection,
            "human",
        )
        .expect_err("another task's question id never answers");
    assert!(
        matches!(denied, StoreError::NotFound(Missing::Question(_))),
        "the binding denial is not_found, not a generic conflict: {denied}"
    );
    let attempts = world
        .runtime
        .store()
        .answer_attempts(&other)
        .expect("attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].outcome, AnswerAttemptOutcome::Denied);
    assert_eq!(attempts[0].denial.as_deref(), Some("not_found"));

    // Wire seam: the same cross-task quote denies with the same code.
    let wired = world.dispatch(&corpus_answer_option(
        &session,
        "cmd-cross-task-answer",
        &other,
        &question,
        KNOWN_READY_OPTION,
        json!(240),
    ));
    assert_eq!(
        wired["error"]["data"]["code"], "not_found",
        "the wire denial keeps the not_found code: {wired}"
    );

    // Both rows untouched: the victim's question still waits, its
    // journal empty; the quoting task never moved.
    assert!(
        world
            .runtime
            .store()
            .current_question(&task)
            .expect("current")
            .is_some(),
        "the victim's fork survives the cross-task quote"
    );
    assert!(
        world
            .runtime
            .store()
            .answer_attempts(&task)
            .expect("attempts")
            .is_empty(),
        "the victim's journal stays clean"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .snapshot(&other)
            .expect("snapshot")
            .lifecycle,
        rivect::contracts::Lifecycle::Running,
        "the quoting task was never moved by the denial"
    );

    // Symmetric sibling: the same id under its own task answers fine.
    world
        .runtime
        .store_writer()
        .answer_question(
            &session,
            &task,
            &question.question_id,
            question.question_revision,
            &selection,
            "human",
        )
        .expect("the owning task answers its own question");
}

#[test]
fn stale_evidence_keeps_completion_closed() {
    let (mut world, session, task) = world_with_task("decision-stale-evidence");
    world
        .runtime
        .store_writer()
        .materialize_obligations(&task)
        .expect("criteria materialize");
    world
        .runtime
        .store_writer()
        .insert_evidence_for_task(&task, "decision fork", "first basis", "digest-1")
        .expect("evidence satisfies every obligation");

    // `invalidate_evidence` writes the stale validity and reverts the
    // obligation in separate statements: a crash between them leaves a
    // stale row under a satisfied obligation — the only shape the
    // stale-count guard exists for. The foreign write lands exactly
    // that shape.
    let db = world.root.join("runtime").join("rivect.db");
    {
        let conn = rusqlite::Connection::open(&db).expect("conn");
        conn.execute(
            "UPDATE evidence SET validity = 'stale' WHERE task_id = ?1",
            rusqlite::params![task.0],
        )
        .expect("the crash-window stale mark lands");
    }

    let denied = world
        .runtime
        .store_writer()
        .complete_if_eligible(&session, &task)
        .expect_err("a stale evidence row holds completion closed");
    assert!(
        matches!(
            denied,
            StoreError::Conflict(ConflictCause::CompletionStale { stale: 1 })
        ),
        "the denial names the stale count: {denied}"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .snapshot(&task)
            .expect("snapshot")
            .lifecycle,
        rivect::contracts::Lifecycle::Running,
        "the refused completion never moved the task"
    );
    let rows = world
        .runtime
        .store()
        .evidence_for_task(&task)
        .expect("evidence");
    assert!(
        rows.iter()
            .all(|row| row.validity == EvidenceValidity::Stale),
        "the stale mark kept its provenance: {rows:?}"
    );
}

#[test]
fn denial_journal_failure_preserves_the_denial_and_surfaces_the_gap() {
    let (mut world, session, task) = world_with_task("decision-denial-journal");
    let question = world.publish(&session, &task);

    // Jam the append-only journal: a foreign connection renames the
    // table so the next denied-attempt write fails — while the denial
    // path itself is untouched.
    let db = world.root.join("runtime").join("rivect.db");
    {
        let conn = rusqlite::Connection::open(&db).expect("conn");
        conn.execute_batch("ALTER TABLE answer_attempts RENAME TO answer_attempts_jammed")
            .expect("the jam lands");
    }

    // Store seam: the denial stays the typed primary error and the
    // journal failure rides along named — never masked, never silent.
    let failed = world
        .runtime
        .store_writer()
        .answer_question(
            &session,
            &task,
            &question.question_id,
            99,
            &AnswerSelection::Option {
                option_id: OptionId(KNOWN_READY_OPTION.to_string()),
            },
            "human",
        )
        .expect_err("the journal failure still reports the denial");
    match &failed {
        StoreError::DenialJournalFailed { denial, journal } => {
            assert!(
                matches!(
                    denial.as_ref(),
                    StoreError::Conflict(ConflictCause::QuestionRevision { .. })
                ),
                "the denial keeps its own type: {denial}"
            );
            assert!(
                matches!(journal.as_ref(), StoreError::Storage(_)),
                "the journal failure names storage: {journal}"
            );
        }
        other => panic!("expected DenialJournalFailed, got {other}"),
    }
    assert_eq!(
        failed.code(),
        rivect::contracts::ErrorCode::Conflict,
        "the wire code stays the denial's, not the journal's"
    );
    assert!(
        failed
            .to_string()
            .contains("the denial journal write failed"),
        "the gap is named in the message: {failed}"
    );

    // Wire seam — store-level denial: the response carries the denial's
    // code with the journal failure named in the message.
    let stale = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 250, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-jammed-stale", "session_id": session.0,
                    "kind": "answer", "task_id": task.0,
                    "expected_intent_revision": question.intent_revision,
                    "question_id": question.question_id.0, "question_revision": 99,
                    "selection": { "kind": "option", "option_id": KNOWN_READY_OPTION } }
    }));
    assert_eq!(
        stale["error"]["data"]["code"], "conflict",
        "the stale pin keeps its own wire code: {stale}"
    );
    assert!(
        stale["error"]["data"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("the denial journal write failed")),
        "the journal gap rides the wire error: {stale}"
    );

    // Wire seam — request-level denial: the machine-ingress refusal
    // journals through the same seam, so a jammed journal reports
    // `denied` with the gap named, not a dropped denial.
    let machine = world.dispatch_machine(&corpus_answer_option(
        &session,
        "cmd-jammed-machine",
        &task,
        &question,
        KNOWN_READY_OPTION,
        json!(251),
    ));
    assert_eq!(
        machine["error"]["data"]["code"], "denied",
        "the machine denial keeps its own code: {machine}"
    );
    assert!(
        machine["error"]["data"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("the denial journal write failed")),
        "the request-level journal gap is named: {machine}"
    );

    // Unjam and read back: nothing was journaled — the failures were
    // reported, never silently swallowed nor half-written.
    {
        let conn = rusqlite::Connection::open(&db).expect("conn");
        conn.execute_batch("ALTER TABLE answer_attempts_jammed RENAME TO answer_attempts")
            .expect("the jam lifts");
    }
    assert!(
        world
            .runtime
            .store()
            .answer_attempts(&task)
            .expect("attempts")
            .is_empty(),
        "no attempt row materialized while the journal was jammed"
    );
    assert!(
        world
            .runtime
            .store()
            .current_question(&task)
            .expect("current")
            .is_some(),
        "the denied attempts preserved the pending question"
    );
}

#[test]
fn stale_replayed_or_invalid_answer_denied_history_preserved() {
    // Same scoped fixture as the consumer leg: the frozen answer's
    // resumed node needs a grant-backed read to drain to completion.
    let mut world = open_world(
        "decision-wire-replay",
        Some(&support::config_distinct_pools()),
    );
    let session = world.open_session("decision-session");
    let task = world.create_task(&session, "cmd-replay-task");
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-replay-marker\n").expect("scoped file");
    world.runtime.purpose = "backend_task".to_string();
    world.runtime.set_read_scope(scope, file);
    let question = world.publish(&session, &task);

    // A stale question revision denies at the shared store gate and
    // journals its own class.
    let stale = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 262, "method": "task.submit",
        "params": { "schema_version": 1, "command_id": "cmd-stale-revision", "session_id": session.0,
                    "kind": "answer", "task_id": task.0,
                    "expected_intent_revision": question.intent_revision,
                    "question_id": question.question_id.0, "question_revision": 99,
                    "selection": { "kind": "option", "option_id": KNOWN_READY_OPTION } }
    }));
    assert_eq!(
        stale["error"]["data"]["code"], "conflict",
        "a stale question revision conflicts typed: {stale}"
    );

    // An unknown option id is an invalid answer: denied, journaled.
    let invalid = world.dispatch(&corpus_answer_option(
        &session,
        "cmd-unknown-option",
        &task,
        &question,
        "bogus",
        json!(263),
    ));
    assert_eq!(
        invalid["error"]["data"]["code"], "invalid_input",
        "an unknown option id denies typed: {invalid}"
    );

    // Every malformed selection shape denies typed at the wire and
    // journals `invalid_selection` — the field-level parse refusal,
    // never a generic bad-request.
    for (command_id, selection, fragment, request_id) in [
        (
            "cmd-conflicting-selection",
            json!({ "kind": "option", "option_id": KNOWN_READY_OPTION, "text": "both" }),
            "cannot carry both",
            264,
        ),
        (
            "cmd-missing-option-id",
            json!({ "kind": "option" }),
            "option_id",
            265,
        ),
        (
            "cmd-missing-custom-text",
            json!({ "kind": "custom" }),
            "custom text",
            266,
        ),
    ] {
        let denied = world.dispatch(&json!({
            "jsonrpc": "2.0", "id": request_id, "method": "task.submit",
            "params": { "schema_version": 1, "command_id": command_id, "session_id": session.0,
                        "kind": "answer", "task_id": task.0,
                        "expected_intent_revision": question.intent_revision,
                        "question_id": question.question_id.0,
                        "question_revision": question.question_revision,
                        "selection": selection }
        }));
        assert_eq!(
            denied["error"]["data"]["code"], "invalid_input",
            "a malformed selection denies typed: {denied}"
        );
        assert!(
            denied["error"]["data"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(fragment)),
            "the refusal names its field: {denied}"
        );
    }

    // The denials left the pending fork untouched.
    assert!(
        world
            .runtime
            .store()
            .current_question(&task)
            .expect("current")
            .is_some(),
        "the denials preserved the pending question"
    );

    let first = world.dispatch(&corpus_answer_option(
        &session,
        "cmd-answer-first",
        &task,
        &question,
        KNOWN_READY_OPTION,
        json!(260),
    ));
    assert!(first["error"].is_null(), "{first}");
    assert_eq!(first["result"]["status"], "applied");
    let settled = world.runtime.store().snapshot(&task).expect("snapshot");
    assert_eq!(
        settled.lifecycle,
        rivect::contracts::Lifecycle::Completed,
        "the drain ran the resumed node to completion"
    );
    assert_eq!(
        first["result"]["snapshot"]["lifecycle"], "completed",
        "the wire answer carries the post-drain snapshot, never the \
         pre-resume running row: {first}"
    );
    assert_eq!(
        first["result"]["task_revision"].as_u64(),
        Some(settled.revision),
        "the response revision is the row the drain left behind: {first}"
    );

    // A crash-mid-answer replay arrives with a fresh command_id: the
    // durable row is terminal, so the replay denies already_terminal —
    // it never rewrites the committed answer.
    let replay = world.dispatch(&corpus_answer_option(
        &session,
        "cmd-answer-replay",
        &task,
        &question,
        KNOWN_READY_OPTION,
        json!(261),
    ));
    assert_eq!(
        replay["error"]["data"]["code"], "already_terminal",
        "the replay denies on the terminal row: {replay}"
    );
    let attempts = world
        .runtime
        .store()
        .answer_attempts(&task)
        .expect("attempts");
    assert_eq!(
        attempts
            .iter()
            .map(|attempt| (attempt.outcome, attempt.denial.as_deref().unwrap_or("")))
            .collect::<Vec<_>>(),
        [
            (AnswerAttemptOutcome::Denied, "stale_revision"),
            (AnswerAttemptOutcome::Denied, "unknown_option"),
            (AnswerAttemptOutcome::Denied, "invalid_selection"),
            (AnswerAttemptOutcome::Denied, "invalid_selection"),
            (AnswerAttemptOutcome::Denied, "invalid_selection"),
            (AnswerAttemptOutcome::Applied, ""),
            (AnswerAttemptOutcome::Denied, "already_terminal")
        ],
        "every denial journaled its own class in commit order beside the \
         preserved applied row: {attempts:?}"
    );
}

#[test]
fn evidence_rows_project_typed() {
    let (mut world, _session, task) = world_with_task("decision-evidence");
    world
        .runtime
        .store_writer()
        .materialize_obligations(&task)
        .expect("criteria materialize as obligations");
    let evidence_id = world
        .runtime
        .store_writer()
        .insert_evidence(
            &task,
            0,
            "decision fork",
            "the operator picked the staged rollout",
            "digest-obs-1",
        )
        .expect("evidence inserts");
    let rows = world
        .runtime
        .store()
        .evidence_for_task(&task)
        .expect("evidence reads");
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.evidence_id.0, evidence_id);
    assert_eq!(row.task_id, task);
    assert_eq!(row.scope, "decision fork");
    assert_eq!(row.observation, "the operator picked the staged rollout");
    assert_eq!(row.digest, "digest-obs-1");
    assert_eq!(row.validity, EvidenceValidity::Current);
    assert!(!row.obligation_id.is_empty());
}

// ----- decisions.control carrier -----

#[test]
fn decisions_control_is_a_shipped_local_kind() {
    assert!(matches!(
        local_command_kind(DECISIONS_CONTROL),
        LocalKind::DecisionsControl
    ));
    let page = describe();
    let descriptor = page
        .items
        .iter()
        .find(|item| item.canonical_id == DECISIONS_CONTROL)
        .expect("the catalog ships decisions.control");
    assert!(descriptor.available, "{descriptor:?}");
    assert!(descriptor.unavailability_reason.is_none());
    assert!(
        descriptor.aliases.iter().any(|alias| alias == "decisions"),
        "the short alias ships: {descriptor:?}"
    );
    assert!(
        !descriptor.description.contains("planned"),
        "a real description, not the planned placeholder: {descriptor:?}"
    );
    assert!(
        page.items
            .iter()
            .all(|item| !(item.canonical_id == DECISIONS_CONTROL && !item.available)),
        "no unavailable twin lingers in the catalog"
    );
}

#[test]
fn decisions_control_status_reports_shipped_ask() {
    let mut world = open_world("decision-status", None);
    let session = world.open_session("decision-status-session");

    let response = world.dispatch(&corpus_decisions_control(
        &session,
        "status",
        None,
        None,
        json!(101),
    ));
    assert!(response["error"].is_null(), "{response}");
    let result = &response["result"]["result"];
    assert_eq!(result["key"], "decisions.mode");
    assert_eq!(result["effective"], "ask", "ask is the shipped default");
    assert!(
        result["source_digest"].as_str().is_some(),
        "the read returns the digest a write preconditions on"
    );
}

#[test]
fn decisions_control_roundtrips_through_existing_dispatcher() {
    // The carrier is a shipped local kind: `command.execute` resolves
    // `decisions.control` through `local_command_kind`, so the round trip
    // below rides the existing dispatcher, never a bespoke path.
    assert!(matches!(
        local_command_kind(DECISIONS_CONTROL),
        LocalKind::DecisionsControl
    ));
    let mut world = open_world("decision-round-trip", Some(&support::base_config()));
    let session = world.open_session("decision-round-trip-session");
    let status = world.dispatch(&corpus_decisions_control(
        &session,
        "status",
        None,
        None,
        json!(110),
    ));
    let digest = status["result"]["result"]["source_digest"]
        .as_str()
        .expect("status digest")
        .to_string();

    let switched = world.dispatch(&corpus_decisions_control(
        &session,
        "auto",
        Some("cmd-mode-auto"),
        Some(&digest),
        json!(111),
    ));
    assert!(switched["error"].is_null(), "{switched}");
    assert_eq!(switched["result"]["result"]["key"], "decisions.mode");
    assert_eq!(
        world.runtime.effective().decisions_mode(),
        rivect::config::DecisionMode::Auto,
        "the landed edit moves the effective mode"
    );
    let file = std::fs::read_to_string(world.root.join("config.toml")).expect("config bytes");
    assert!(
        file.contains("mode = \"auto\""),
        "the write is durable on disk: {file}"
    );

    // The switched mode must drive the next material fork, not just the
    // config surface: a delegated auto resolve answers through the
    // shared seam under its declared non-human author.
    let registry = ActionRegistry::new();
    let switched_config = world.runtime.config_for_broker();
    let task = world.create_task(&session, "cmd-fork-auto");
    let mut fork = decision_input(&task);
    fork.author = Some(DecisionAuthor::Agent);
    fork.delegation = Some(Delegation {
        action: RESOLVE_DECISION.to_string(),
        task_id: task.clone(),
    });
    let outcome = registry
        .resolve_decision(
            fork,
            &mut action_ctx(&mut world, &session, &switched_config),
        )
        .expect("a switched auto mode resolves delegated");
    let ActionOutcome::Answered { author, .. } = outcome else {
        panic!("auto mode answers a delegated fork: {outcome:?}")
    };
    assert_eq!(author, "agent", "the declared author reports back");
    let (_, origin) = world
        .runtime
        .store()
        .answered_question(&task)
        .expect("answered")
        .expect("the delegated answer is durable");
    assert_eq!(origin, "agent", "the non-human author persists");

    let stale = world.dispatch(&corpus_decisions_control(
        &session,
        "ask",
        Some("cmd-mode-stale"),
        Some(&digest),
        json!(112),
    ));
    assert_eq!(
        stale["error"]["data"]["code"], "conflict",
        "a stale digest must conflict, not silently pass: {stale}"
    );

    let digest = world.runtime.effective().sources_digest.clone();
    let reset = world.dispatch(&corpus_decisions_control(
        &session,
        "inherit",
        Some("cmd-mode-inherit"),
        Some(&digest),
        json!(113),
    ));
    assert!(reset["error"].is_null(), "{reset}");
    assert_eq!(
        world.runtime.effective().decisions_mode(),
        rivect::config::DecisionMode::Ask,
        "inherit restores ask semantics"
    );

    // And the reset mode drives its fork the other way: the same input
    // now publishes a versioned question instead of answering.
    let inherited_config = world.runtime.config_for_broker();
    let task = world.create_task(&session, "cmd-fork-inherit");
    let outcome = registry
        .resolve_decision(
            decision_input(&task),
            &mut action_ctx(&mut world, &session, &inherited_config),
        )
        .expect("inherit resolves by asking");
    asked_question(outcome);
}

#[test]
fn decisions_control_switch_never_answer_or_grant() {
    let mut world = open_world("decision-mode-switch", Some(&support::base_config()));
    let session = world.open_session("decision-switch-session");
    let task = world.create_task(&session, "cmd-switch-task");

    // Under the shipped ask mode the material fork publishes.
    let registry = ActionRegistry::new();
    let pending = asked_question(
        registry
            .resolve_decision(
                decision_input(&task),
                &mut action_ctx(&mut world, &session, &decision_config(None)),
            )
            .expect("ask mode publishes"),
    );

    // Flip to auto through the control carrier: the write lands on the
    // current digest.
    let status = world.dispatch(&corpus_decisions_control(
        &session,
        "status",
        None,
        None,
        json!(180),
    ));
    let digest = status["result"]["result"]["source_digest"]
        .as_str()
        .expect("status digest")
        .to_string();
    let switched = world.dispatch(&corpus_decisions_control(
        &session,
        "auto",
        Some("cmd-mode-switch"),
        Some(&digest),
        json!(181),
    ));
    assert!(switched["error"].is_null(), "{switched}");
    assert_eq!(
        world.runtime.effective().decisions_mode(),
        rivect::config::DecisionMode::Auto,
        "the landed edit moves the effective mode"
    );

    // The already-pending question is untouched by the switch: same
    // question at the same revisions, task still waiting, no answer
    // journaled, no supersession event emitted.
    let (live, _task_revision) = world
        .runtime
        .store()
        .current_question(&task)
        .expect("current")
        .expect("the pending question survives the mode switch");
    assert_eq!(
        live, pending,
        "the mode switch neither answered nor replaced the pending fork"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .snapshot(&task)
            .expect("snapshot")
            .lifecycle,
        rivect::contracts::Lifecycle::Waiting,
        "the task still waits on its question"
    );
    assert!(
        world
            .runtime
            .store()
            .answer_attempts(&task)
            .expect("attempts")
            .is_empty(),
        "a config write is never an answer"
    );
    assert!(
        world
            .runtime
            .store()
            .events_after(&session, Some(&task), 0, 100)
            .expect("task feed")
            .iter()
            .all(|event| event.event_type != "question.superseded"),
        "the switch superseded nothing"
    );

    // And it is never a consent carrier either: the write minted no
    // policy grant and recorded no preapproval anywhere.
    assert!(
        world.runtime.policy().grant("grant-1").is_none(),
        "the switch issued no grant"
    );
    let conn =
        rusqlite::Connection::open(world.root.join("runtime").join("rivect.db")).expect("conn");
    let grants: i64 = conn
        .query_row("SELECT COUNT(*) FROM preapprovals", [], |row| row.get(0))
        .expect("preapprovals read");
    assert_eq!(grants, 0, "the switch recorded no consent scope");
    drop(conn);
}

#[test]
fn decisions_control_switch_then_material_fork_observes_mode() {
    let mut world = open_world("decision-mode-observe", Some(&support::base_config()));
    let session = world.open_session("decision-observe-session");

    // Flip to auto through the control carrier on the current digest.
    let status = world.dispatch(&corpus_decisions_control(
        &session,
        "status",
        None,
        None,
        json!(182),
    ));
    let digest = status["result"]["result"]["source_digest"]
        .as_str()
        .expect("status digest")
        .to_string();
    let switched = world.dispatch(&corpus_decisions_control(
        &session,
        "auto",
        Some("cmd-mode-observe"),
        Some(&digest),
        json!(183),
    ));
    assert!(switched["error"].is_null(), "{switched}");
    assert_eq!(
        world.runtime.effective().decisions_mode(),
        rivect::config::DecisionMode::Auto,
        "the landed edit moves the effective mode"
    );

    // The consumed digest is a dead key: a second write quoting it
    // conflicts instead of landing twice.
    let dead = world.dispatch(&corpus_decisions_control(
        &session,
        "ask",
        Some("cmd-dead-key"),
        Some(&digest),
        json!(184),
    ));
    assert_eq!(
        dead["error"]["data"]["code"], "conflict",
        "the pre-switch digest is dead: {dead}"
    );

    // The switch applies to the next fork, not retroactively: a new
    // task's delegated fork resolves under the observed auto mode.
    let registry = ActionRegistry::new();
    let switched_config = world.runtime.config_for_broker();
    let task = world.create_task(&session, "cmd-fork-after-switch");
    let mut fork = decision_input(&task);
    fork.author = Some(DecisionAuthor::Agent);
    fork.delegation = Some(Delegation {
        action: RESOLVE_DECISION.to_string(),
        task_id: task,
    });
    let outcome = registry
        .resolve_decision(
            fork,
            &mut action_ctx(&mut world, &session, &switched_config),
        )
        .expect("auto mode resolves the post-switch fork");
    assert!(
        matches!(outcome, ActionOutcome::Answered { .. }),
        "post-switch forks answer through the shared seam: {outcome:?}"
    );
}

#[test]
fn decisions_control_rejects_bad_ops_and_shape() {
    let mut world = open_world("decision-control-shape", None);
    let session = world.open_session("decision-shape-session");

    let bogus = world.dispatch(&corpus_decisions_control(
        &session,
        "yolo",
        Some("cmd-bogus"),
        Some("digest"),
        json!(120),
    ));
    assert_eq!(
        bogus["error"]["data"]["code"], "invalid_input",
        "an unknown op denies typed: {bogus}"
    );
    assert!(
        bogus["error"]["data"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("unknown decisions.control op")),
        "the op set is closed and typed: {bogus}"
    );

    let read_with_mutation = world.dispatch(&corpus_decisions_control(
        &session,
        "status",
        Some("cmd-status-mutation"),
        None,
        json!(121),
    ));
    assert_eq!(
        read_with_mutation["error"]["data"]["code"], "invalid_input",
        "status forbids mutation fields: {read_with_mutation}"
    );

    // The digest alone is a mutation field too — status refuses it
    // without the command_id present.
    let status_with_digest = world.dispatch(&corpus_decisions_control(
        &session,
        "status",
        None,
        Some("digest"),
        json!(1215),
    ));
    assert_eq!(
        status_with_digest["error"]["data"]["code"], "invalid_input",
        "status forbids the digest precondition: {status_with_digest}"
    );

    // A write with no op names the missing field.
    let no_op = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 1216, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "decisions.control" } }
    }));
    assert_eq!(
        no_op["error"]["data"]["code"], "invalid_input",
        "the missing op denies typed: {no_op}"
    );
    assert!(
        no_op["error"]["data"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("command.op")),
        "the missing op is named: {no_op}"
    );

    // A write with an empty command_id names the field rather than
    // minting an empty receipt key.
    let empty_command_id = world.dispatch(&corpus_decisions_control(
        &session,
        "auto",
        Some(""),
        Some("digest"),
        json!(1217),
    ));
    assert_eq!(
        empty_command_id["error"]["data"]["code"], "invalid_input",
        "an empty command_id denies typed: {empty_command_id}"
    );
    assert!(
        empty_command_id["error"]["data"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("command_id")),
        "an empty command_id is refused: {empty_command_id}"
    );

    let write_without_precondition = world.dispatch(&corpus_decisions_control(
        &session,
        "auto",
        Some("cmd-no-digest"),
        None,
        json!(122),
    ));
    assert_eq!(
        write_without_precondition["error"]["data"]["code"], "invalid_input",
        "a write without the digest precondition is refused: {write_without_precondition}"
    );

    let no_session = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 123, "method": "command.execute",
        "params": { "schema_version": 1, "command": { "kind": "decisions.control" }, "op": "status" }
    }));
    assert_eq!(
        no_session["error"]["data"]["code"], "invalid_input",
        "a sessionless command denies typed: {no_session}"
    );

    // An unknown parameter is rejected, never silently dropped.
    let unknown = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 124, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "decisions.control" }, "op": "status", "bogus": true }
    }));
    assert_eq!(
        unknown["error"]["data"]["code"], "invalid_input",
        "an unknown parameter denies typed: {unknown}"
    );
    assert!(
        unknown["error"]["data"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("unknown parameter")),
        "an unknown parameter is named: {unknown}"
    );
}

#[test]
fn decisions_control_dedupes_command_id_and_rejects_reuse() {
    let mut world = open_world("decision-cmd-dedupe", Some(&support::base_config()));
    let session = world.open_session("decision-dedupe-session");
    let status = world.dispatch(&corpus_decisions_control(
        &session,
        "status",
        None,
        None,
        json!(130),
    ));
    let digest = status["result"]["result"]["source_digest"]
        .as_str()
        .expect("status digest")
        .to_string();

    let first = world.dispatch(&corpus_decisions_control(
        &session,
        "auto",
        Some("cmd-mode-dedupe"),
        Some(&digest),
        json!(131),
    ));
    assert!(first["error"].is_null(), "{first}");

    // The same command_id with the same intent replays the recorded
    // result — the digest precondition that turned stale on landing
    // never gates the replay, and no second publication lands.
    let replay = world.dispatch(&corpus_decisions_control(
        &session,
        "auto",
        Some("cmd-mode-dedupe"),
        Some(&digest),
        json!(132),
    ));
    assert_eq!(
        replay["result"], first["result"],
        "a matching replay answers the receipt verbatim: {replay}"
    );

    // The id is bound to its params: reusing it for a different intent
    // conflicts instead of silently mutating again.
    let fresh = world.runtime.effective().sources_digest.clone();
    let divergent = world.dispatch(&corpus_decisions_control(
        &session,
        "ask",
        Some("cmd-mode-dedupe"),
        Some(&fresh),
        json!(133),
    ));
    assert!(
        divergent["error"]["data"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("already recorded")),
        "the reused id conflicts: {divergent}"
    );
    assert_eq!(
        world.runtime.effective().decisions_mode(),
        rivect::config::DecisionMode::Auto,
        "the refused replay never mutated the mode"
    );

    // The receipt binds the principal into the params digest: the same
    // command_id replayed under machine ingress names a different
    // intent and conflicts instead of replaying the human's receipt.
    let machine_replay = world.dispatch_machine(&corpus_decisions_control(
        &session,
        "auto",
        Some("cmd-mode-dedupe"),
        Some(&digest),
        json!(1335),
    ));
    assert!(
        machine_replay["error"]["data"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("already recorded")),
        "the machine replay conflicts on principal: {machine_replay}"
    );

    // The advertised alias resolves to the same carrier.
    let alias = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 134, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "decisions" }, "op": "status" }
    }));
    assert!(
        alias["error"].is_null(),
        "the decisions alias resolves: {alias}"
    );
    assert_eq!(alias["result"]["result"]["effective"], "auto");
}

#[test]
fn decisions_control_lost_receipt_conflicts_stale_and_reheals() {
    let mut world = open_world("decision-receipt-window", Some(&support::base_config()));
    let session = world.open_session("decision-receipt-session");
    let status = world.dispatch(&corpus_decisions_control(
        &session,
        "status",
        None,
        None,
        json!(300),
    ));
    let digest = status["result"]["result"]["source_digest"]
        .as_str()
        .expect("status digest")
        .to_string();

    // The receipt crash window: the managed write lands durable, then
    // the receipt insert fails. A write-only jam — an INSERT trigger —
    // keeps the upfront receipt read honest so the failure lands
    // exactly at the crash point, never earlier.
    let db = world.root.join("runtime").join("rivect.db");
    {
        let conn = rusqlite::Connection::open(&db).expect("conn");
        conn.execute_batch(
            "CREATE TRIGGER jam_receipt BEFORE INSERT ON command_receipts
             BEGIN SELECT RAISE(ABORT, 'receipt journal jammed'); END",
        )
        .expect("the jam lands");
    }
    let write = world.dispatch(&corpus_decisions_control(
        &session,
        "auto",
        Some("cmd-lost-receipt"),
        Some(&digest),
        json!(301),
    ));
    assert_eq!(
        write["error"]["data"]["code"], "storage_unavailable",
        "the lost receipt reports the store failure, never a fake applied: {write}"
    );
    // Fail-closed means durable-and-unacknowledged, never
    // acknowledged-and-lost: the landed edit moved the effective view.
    assert_eq!(
        world.runtime.effective().decisions_mode(),
        rivect::config::DecisionMode::Auto,
        "the landed bytes keep serving through the receipt gap"
    );
    {
        let conn = rusqlite::Connection::open(&db).expect("conn");
        conn.execute_batch("DROP TRIGGER jam_receipt")
            .expect("the jam lifts");
    }

    // A blind replay with the same command_id finds no receipt: it
    // re-runs as a fresh command and the moved digest conflicts — the
    // edit never lands twice.
    let stale_replay = world.dispatch(&corpus_decisions_control(
        &session,
        "auto",
        Some("cmd-lost-receipt"),
        Some(&digest),
        json!(302),
    ));
    assert_eq!(
        stale_replay["error"]["data"]["code"], "conflict",
        "the stale-digest replay conflicts instead of re-applying: {stale_replay}"
    );

    // The retry carrying the moved digest matches the applied intent in
    // the publication journal, takes the receipt, and heals the seam.
    let moved = world.runtime.effective().sources_digest.clone();
    let healed = world.dispatch(&corpus_decisions_control(
        &session,
        "auto",
        Some("cmd-lost-receipt"),
        Some(&moved),
        json!(303),
    ));
    assert!(
        healed["error"].is_null(),
        "the fresh-digest retry receipts the landed edit: {healed}"
    );
    let replayed = world.dispatch(&corpus_decisions_control(
        &session,
        "auto",
        Some("cmd-lost-receipt"),
        Some(&moved),
        json!(304),
    ));
    assert_eq!(
        replayed["result"], healed["result"],
        "the healed command_id replays verbatim from its receipt: {replayed}"
    );
}

// ----- decision card (unit seam) -----

fn card_view(
    world: &mut support::World,
    session: &SessionId,
    task: &TaskId,
) -> rivect::ui::LocalView {
    let question = world.publish(session, task);
    let mut view = initial_view();
    view.decision = Some(DecisionPanel::new(question));
    view
}

fn key(code: KeyCode) -> TermEvent {
    TermEvent::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

/// `key` with an explicit event kind — `Repeat` synthesizes the
/// held-key autorepeat the consent surfaces must refuse.
fn key_kind(code: KeyCode, kind: KeyEventKind) -> TermEvent {
    TermEvent::Key(KeyEvent::new_with_kind(code, KeyModifiers::NONE, kind))
}

#[test]
fn focus_and_recommendation_never_apply_selection() {
    let (mut world, session, task) = world_with_task("card-focus");
    let mut view = card_view(&mut world, &session, &task);
    let rt = &mut world.runtime;

    // The recommended row opens focused — neither the marker nor the
    // focus position is a selection.
    let card = view.decision.as_ref().expect("card open");
    assert_eq!(card.focus(), 0);
    assert_eq!(card.custom_row(), 5);

    handle_decision_event(&key(KeyCode::Down), &mut view, rt, &session);
    handle_decision_event(&key(KeyCode::Up), &mut view, rt, &session);
    assert_eq!(view.decision.as_ref().expect("card").focus(), 0);

    // Sweep all six rows and wrap back onto the recommended position:
    // navigation alone, even dwelling on the recommended row, never
    // commits anything.
    for _ in 0..6 {
        handle_decision_event(&key(KeyCode::Down), &mut view, rt, &session);
    }
    assert_eq!(view.decision.as_ref().expect("card").focus(), 0);

    assert!(view.decision.is_some(), "the card stays open");
    assert!(
        rt.store()
            .current_question(&task)
            .expect("current")
            .is_some(),
        "focus moves never answered the fork"
    );
    assert!(
        rt.store()
            .answered_question(&task)
            .expect("answered")
            .is_none(),
        "the recommended position was never applied"
    );
    assert!(
        rt.store()
            .answer_attempts(&task)
            .expect("attempts")
            .is_empty(),
        "no selection journaled — focus and recommendation are display state"
    );
}

#[test]
fn disabled_options_carry_reason_and_are_not_selectable() {
    let (mut world, session, task) = world_with_task("card-disabled");
    let mut view = card_view(&mut world, &session, &task);
    let rt = &mut world.runtime;

    // The disabled `diagram` row (fixture index 4) carries its reason on
    // the question record itself.
    let reason = match &view.decision.as_ref().expect("card").question.options[4].availability {
        Availability::Disabled { reason } => reason.clone(),
        Availability::Enabled => panic!("the diagram row ships disabled"),
    };
    assert_eq!(reason, "no useful diagram for this topic");

    for _ in 0..4 {
        handle_decision_event(&key(KeyCode::Down), &mut view, rt, &session);
    }
    assert_eq!(view.decision.as_ref().expect("card").focus(), 4);
    handle_decision_event(&key(KeyCode::Enter), &mut view, rt, &session);
    assert!(
        view.decision.is_some(),
        "a disabled position refuses and the card stays open"
    );
    assert!(
        view.transcript.iter().any(|line| {
            line.contains("decision position unavailable") && line.contains(&reason)
        }),
        "the refusal names the carried reason: {:?}",
        view.transcript
    );
    assert!(
        rt.store()
            .current_question(&task)
            .expect("current")
            .is_some(),
        "no substitute selection was applied underneath"
    );
    assert!(
        rt.store()
            .answer_attempts(&task)
            .expect("attempts")
            .is_empty(),
        "a disabled position is not selectable — nothing was even attempted"
    );
}

#[test]
fn enter_applies_only_explicit_choice_on_current_revision() {
    // Model pools + a scoped read, mirroring the wire answer's world:
    // without them the resumed node cannot dispatch and the resume
    // observables below would be unattainable.
    let mut world = open_world("card-commit", Some(&support::config_distinct_pools()));
    let session = world.open_session("decision-session");
    let task = world.create_task(&session, "cmd-decision-task");
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-decision-marker\n").expect("scoped file");
    world.runtime.purpose = "backend_task".to_string();
    world.runtime.set_read_scope(scope, file);
    let calls_before = world
        .provider_calls
        .load(std::sync::atomic::Ordering::SeqCst);

    let mut view = card_view(&mut world, &session, &task);
    let question_id = view
        .decision
        .as_ref()
        .expect("card")
        .question
        .question_id
        .clone();

    handle_decision_event(&key(KeyCode::Down), &mut view, &mut world.runtime, &session);
    handle_decision_event(
        &key(KeyCode::Enter),
        &mut view,
        &mut world.runtime,
        &session,
    );

    assert!(view.decision.is_none(), "a committed card closes");
    assert!(
        view.transcript
            .iter()
            .any(|line| line == DECISION_ANSWERED_NOTE),
        "{:?}",
        view.transcript
    );
    let (answer_json, origin) = world
        .runtime
        .store()
        .answered_question(&task)
        .expect("answered")
        .expect("the card's answer is durable");
    assert_eq!(origin, "human", "the card answers as the human author");
    assert!(answer_json.contains("\"steps\""), "{answer_json}");
    let attempts = world
        .runtime
        .store()
        .answer_attempts(&task)
        .expect("attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].question_id, question_id);
    assert_eq!(attempts[0].outcome, AnswerAttemptOutcome::Applied);
    // The card rides the same resume seam the wire answer takes: the
    // committed answer submitted its runnable node and the drain ran
    // the admitted scoped read — but a fixed option already names the
    // one permitted read, so no provider dispatch is spent interpreting
    // it. Durable state alone would have left the task parked on a
    // drained question.
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        calls_before,
        "a fixed option names the permitted read — the resume spent no dispatch"
    );
    assert_eq!(
        world.worker_reads(),
        1,
        "the drain ran the admitted scoped read"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .snapshot(&task)
            .expect("snapshot")
            .lifecycle,
        rivect::contracts::Lifecycle::Completed,
        "the resumed task ran to completion"
    );

    // The other half of "only on the current revision": a card whose
    // pinned revision the question already moved past refuses — Enter
    // never applies a stale pin.
    let (mut world, session, task) = world_with_task("card-stale-pin");
    let mut view = card_view(&mut world, &session, &task);
    let question = view.decision.as_ref().expect("card").question.clone();

    // The question moves under the open card: a wire answer commits
    // first, so the card's pinned revision is stale.
    world
        .runtime
        .store_writer()
        .answer_question(
            &session,
            &task,
            &question.question_id,
            question.question_revision,
            &AnswerSelection::Option {
                option_id: OptionId(KNOWN_READY_OPTION.to_string()),
            },
            "human",
        )
        .expect("the wire answer lands first");

    handle_decision_event(
        &key(KeyCode::Enter),
        &mut view,
        &mut world.runtime,
        &session,
    );
    assert!(
        view.decision.is_none(),
        "a denied card does not linger on a moved question"
    );
    assert!(
        view.transcript
            .iter()
            .any(|line| line.contains("decision answer denied")),
        "the denial is named: {:?}",
        view.transcript
    );
    let attempts = world
        .runtime
        .store()
        .answer_attempts(&task)
        .expect("attempts");
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].outcome, AnswerAttemptOutcome::Applied);
    assert_eq!(attempts[1].outcome, AnswerAttemptOutcome::Denied);
    assert_eq!(
        attempts[1].denial.as_deref(),
        Some("replayed_answer"),
        "the card's stale pin journals its own class: {attempts:?}"
    );
}

#[test]
fn card_custom_row_writes_a_multiline_answer() {
    // Model pools + a scoped read, mirroring the option-commit leg:
    // a free-text answer needs the model to interpret it, so the
    // dispatch observables below must be attainable.
    let mut world = open_world("card-custom", Some(&support::config_distinct_pools()));
    let session = world.open_session("decision-session");
    let task = world.create_task(&session, "cmd-decision-task");
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "rivect-decision-marker\n").expect("scoped file");
    world.runtime.purpose = "backend_task".to_string();
    world.runtime.set_read_scope(scope, file);
    let calls_before = world
        .provider_calls
        .load(std::sync::atomic::Ordering::SeqCst);

    let mut view = card_view(&mut world, &session, &task);
    let rt = &mut world.runtime;

    for _ in 0..5 {
        handle_decision_event(&key(KeyCode::Down), &mut view, rt, &session);
    }
    let card = view.decision.as_ref().expect("card");
    assert_eq!(card.focus(), card.custom_row());

    // Enter on an empty draft opens editing; Enter inside editing adds
    // a newline rather than submitting.
    handle_decision_event(&key(KeyCode::Enter), &mut view, rt, &session);
    assert!(view.decision.as_ref().expect("card").custom_editing());
    for ch in "hold the".chars() {
        handle_decision_event(&key(KeyCode::Char(ch)), &mut view, rt, &session);
    }
    handle_decision_event(&key(KeyCode::Enter), &mut view, rt, &session);
    for ch in "freeze".chars() {
        handle_decision_event(&key(KeyCode::Char(ch)), &mut view, rt, &session);
    }
    // A bracketed paste lands atomically — its newline is draft text,
    // never an Enter key.
    handle_decision_event(
        &TermEvent::Paste(" window\nagain".to_string()),
        &mut view,
        rt,
        &session,
    );
    handle_decision_event(&key(KeyCode::Esc), &mut view, rt, &session);
    let card = view.decision.as_ref().expect("card");
    assert!(!card.custom_editing(), "Esc finishes editing");
    assert_eq!(card.custom_draft(), "hold the\nfreeze window\nagain");

    handle_decision_event(&key(KeyCode::Enter), &mut view, rt, &session);
    assert!(view.decision.is_none(), "the custom answer commits");
    // Only free-text answers pay a model dispatch — a fixed option
    // already names the permitted read. The card's custom answer proves
    // the dispatch arm still fires: the drain interpreted the answer
    // through one provider call, then ran the scoped read to
    // completion.
    assert_eq!(
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        calls_before + 1,
        "the free-text answer dispatched the resumed node"
    );
    assert_eq!(
        world.worker_reads(),
        1,
        "the drain ran the admitted scoped read"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .snapshot(&task)
            .expect("snapshot")
            .lifecycle,
        rivect::contracts::Lifecycle::Completed,
        "the resumed task ran to completion"
    );
    let (answer_json, _) = world
        .runtime
        .store()
        .answered_question(&task)
        .expect("answered")
        .expect("durable");
    assert!(
        answer_json.contains("hold the\\nfreeze window\\nagain"),
        "the multiline draft is the custom answer: {answer_json}"
    );
}

#[test]
fn card_backspace_removes_the_whole_grapheme() {
    let (mut world, session, task) = world_with_task("card-grapheme-backspace");
    let mut view = card_view(&mut world, &session, &task);
    let rt = &mut world.runtime;
    for _ in 0..5 {
        handle_decision_event(&key(KeyCode::Down), &mut view, rt, &session);
    }
    handle_decision_event(&key(KeyCode::Enter), &mut view, rt, &session);
    assert!(view.decision.as_ref().expect("card").custom_editing());

    // One draft, three extended clusters: a combining mark, a ZWJ
    // sequence, and the pasted newline — each dies in one press, never
    // mid-cluster.
    handle_decision_event(
        &TermEvent::Paste("e\u{301}\u{1F469}\u{200D}\u{1F4BB}\n".to_string()),
        &mut view,
        rt,
        &session,
    );
    assert_eq!(
        view.decision.as_ref().expect("card").custom_draft(),
        "e\u{301}\u{1F469}\u{200D}\u{1F4BB}\n"
    );
    for draft in ["e\u{301}\u{1F469}\u{200D}\u{1F4BB}", "e\u{301}", ""] {
        handle_decision_event(&key(KeyCode::Backspace), &mut view, rt, &session);
        assert_eq!(
            view.decision.as_ref().expect("card").custom_draft(),
            draft,
            "one Backspace removes exactly one cluster"
        );
    }

    // A `\r\n` tail is one cluster too: one Backspace removes the
    // pair — never a stray `\r`.
    handle_decision_event(
        &TermEvent::Paste("x\r\n".to_string()),
        &mut view,
        rt,
        &session,
    );
    handle_decision_event(&key(KeyCode::Backspace), &mut view, rt, &session);
    assert_eq!(view.decision.as_ref().expect("card").custom_draft(), "x");
}

#[test]
fn card_paste_outside_editing_is_refused_and_named() {
    let (mut world, session, task) = world_with_task("card-paste-refused");
    let mut view = card_view(&mut world, &session, &task);
    let rt = &mut world.runtime;

    // A paste aimed at the composer while the card owns input is a
    // refused write — it must be named like every other refused append,
    // never silently dropped.
    handle_decision_event(
        &TermEvent::Paste("composer text".to_string()),
        &mut view,
        rt,
        &session,
    );
    assert!(view.decision.is_some(), "the card stays open");
    assert_eq!(
        view.decision.as_ref().expect("card").custom_draft(),
        "",
        "the refused paste never entered the draft"
    );
    assert!(
        view.transcript
            .iter()
            .any(|line| line == DECISION_PASTE_REFUSED_NOTE),
        "the refused paste is named: {:?}",
        view.transcript
    );
    assert!(
        rt.store()
            .answer_attempts(&task)
            .expect("attempts")
            .is_empty(),
        "a refused paste journals nothing"
    );
}

#[test]
fn card_editing_ignores_modified_char_chords() {
    let (mut world, session, task) = world_with_task("card-modified-chord");
    let mut view = card_view(&mut world, &session, &task);
    let rt = &mut world.runtime;
    for _ in 0..5 {
        handle_decision_event(&key(KeyCode::Down), &mut view, rt, &session);
    }
    handle_decision_event(&key(KeyCode::Enter), &mut view, rt, &session);
    assert!(view.decision.as_ref().expect("card").custom_editing());

    // A bare Ctrl or Alt chord is a command the card does not bind:
    // its letter must never land in the draft (Ctrl+W is not "w").
    for modifiers in [KeyModifiers::CONTROL, KeyModifiers::ALT] {
        handle_decision_event(
            &TermEvent::Key(KeyEvent::new(KeyCode::Char('w'), modifiers)),
            &mut view,
            rt,
            &session,
        );
    }
    // CONTROL|ALT — and its shifted level, which crossterm reports with
    // SHIFT still pressed — is the AltGr pair on Windows: draft text
    // there, a real command chord everywhere else (unix AltGr is
    // ISO_Level3_Shift and never sets these bits). The assertion
    // follows the platform honestly.
    for (ch, modifiers) in [
        ('@', KeyModifiers::CONTROL | KeyModifiers::ALT),
        (
            'Ą',
            KeyModifiers::SHIFT | KeyModifiers::CONTROL | KeyModifiers::ALT,
        ),
    ] {
        handle_decision_event(
            &TermEvent::Key(KeyEvent::new(KeyCode::Char(ch), modifiers)),
            &mut view,
            rt,
            &session,
        );
    }
    // Bare and Shift-ed chars still append; a real terminal reports
    // Shift+Y as `Char('Y')` with SHIFT, never `Char('y')`.
    handle_decision_event(
        &TermEvent::Key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE)),
        &mut view,
        rt,
        &session,
    );
    handle_decision_event(
        &TermEvent::Key(KeyEvent::new(KeyCode::Char('Y'), KeyModifiers::SHIFT)),
        &mut view,
        rt,
        &session,
    );
    let expected = if cfg!(windows) { "@ĄxY" } else { "xY" };
    assert_eq!(
        view.decision.as_ref().expect("card").custom_draft(),
        expected,
        "AltGr chars type on the AltGr platform; the same bits are dead chords elsewhere"
    );
}

#[test]
fn card_esc_leaves_the_question_pending() {
    let (mut world, session, task) = world_with_task("card-esc");
    let mut view = card_view(&mut world, &session, &task);

    handle_decision_event(&key(KeyCode::Esc), &mut view, &mut world.runtime, &session);
    assert!(view.decision.is_none());
    assert!(
        view.transcript
            .iter()
            .any(|line| line == DECISION_LEFT_NOTE),
        "{:?}",
        view.transcript
    );
    assert!(
        world
            .runtime
            .store()
            .current_question(&task)
            .expect("current")
            .is_some(),
        "Esc never answers and never denies"
    );
    assert!(
        world
            .runtime
            .store()
            .answer_attempts(&task)
            .expect("attempts")
            .is_empty(),
        "Esc journals nothing"
    );
}

#[test]
fn held_key_autorepeat_never_commits_or_dismisses() {
    let (mut world, session, task) = world_with_task("card-autorepeat");
    let mut view = card_view(&mut world, &session, &task);
    let rt = &mut world.runtime;

    // The handler carries no clock — the floor lives in the loop — so
    // the event kind is the guard past it: a held key's `Repeat` is the
    // same unaimed input the floor refuses and must not reach the
    // consent arms.
    handle_decision_event(
        &key_kind(KeyCode::Enter, KeyEventKind::Repeat),
        &mut view,
        rt,
        &session,
    );
    assert!(view.decision.is_some(), "autorepeat Enter never commits");
    assert!(
        rt.store()
            .current_question(&task)
            .expect("current")
            .is_some(),
        "autorepeat Enter never answered the fork"
    );
    assert!(
        rt.store()
            .answer_attempts(&task)
            .expect("attempts")
            .is_empty(),
        "autorepeat Enter journaled nothing"
    );

    handle_decision_event(
        &key_kind(KeyCode::Esc, KeyEventKind::Repeat),
        &mut view,
        rt,
        &session,
    );
    assert!(
        view.decision.is_some(),
        "autorepeat Esc never dismisses the card"
    );
    assert!(
        view.decision_dismissed.is_none(),
        "no dismissal marker was recorded"
    );
    assert!(
        !view
            .transcript
            .iter()
            .any(|line| line == DECISION_LEFT_NOTE),
        "the dismiss note never landed: {:?}",
        view.transcript
    );

    // The kind gate is the card's whole surface, not just consent: a
    // held arrow's Repeat is autorepeat too and must not move focus —
    // an unaimed key cannot steer a card either.
    handle_decision_event(
        &key_kind(KeyCode::Down, KeyEventKind::Repeat),
        &mut view,
        rt,
        &session,
    );
    assert_eq!(
        view.decision.as_ref().expect("card").focus(),
        0,
        "held-arrow autorepeat never navigates"
    );

    // A discrete Press is aimed input: Down moves the focus and Enter
    // on the focused enabled row commits and journals the applied
    // attempt.
    handle_decision_event(&key(KeyCode::Down), &mut view, rt, &session);
    assert_eq!(view.decision.as_ref().expect("card").focus(), 1);
    handle_decision_event(&key(KeyCode::Enter), &mut view, rt, &session);
    assert!(
        view.decision.is_none(),
        "an aimed Enter commits and the card closes"
    );
    let attempts = rt.store().answer_attempts(&task).expect("attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].outcome, AnswerAttemptOutcome::Applied);
    assert!(
        rt.store()
            .answered_question(&task)
            .expect("answered")
            .is_some(),
        "the discrete press answered the fork"
    );
}

#[test]
fn card_answer_on_a_settled_tree_reports_settled_not_resumed() {
    let (mut world, session, task) = world_with_task("card-settled");
    let mut view = card_view(&mut world, &session, &task);

    // The tree drains while the question stays pending — the task row
    // itself is untouched, so the card's answer still commits; only the
    // scheduler refuses to grow runnable work for it.
    world
        .runtime
        .scheduler
        .cancel_task_tree(&task)
        .expect("tree cancel drains");

    handle_decision_event(
        &key(KeyCode::Enter),
        &mut view,
        &mut world.runtime,
        &session,
    );

    assert!(view.decision.is_none(), "a committed card still closes");
    assert!(
        view.transcript
            .iter()
            .any(|line| line == DECISION_SETTLED_NOTE),
        "a settled tree is named settled, never resumed: {:?}",
        view.transcript
    );
    assert!(
        !view
            .transcript
            .iter()
            .any(|line| line == DECISION_ANSWERED_NOTE),
        "the resumed claim must not appear: {:?}",
        view.transcript
    );
    let attempts = world
        .runtime
        .store()
        .answer_attempts(&task)
        .expect("attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        attempts[0].outcome,
        AnswerAttemptOutcome::Applied,
        "the answer is durable even though nothing dispatches"
    );
}

#[test]
fn card_ctrl_c_cancels_the_tui() {
    let (mut world, session, task) = world_with_task("card-ctrl-c");
    let mut view = card_view(&mut world, &session, &task);
    let event = TermEvent::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(
        !handle_decision_event(&event, &mut view, &mut world.runtime, &session),
        "Ctrl-C keeps the global cancel affordance"
    );
}

/// Renders one view onto a test buffer and joins the cell symbols per
/// row: exactly the bytes the terminal would receive — the same
/// helper shape `effect_boundary` uses, at the geometry under test.
fn rendered_text(view: &rivect::ui::LocalView, cols: u16, rows: u16) -> String {
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(cols, rows))
        .expect("test terminal");
    render(&mut terminal, view).expect("render view");
    let buffer = terminal.backend().buffer();
    let width = usize::from(buffer.area.width);
    buffer
        .content
        .chunks(width)
        .map(|row| {
            row.iter()
                .map(ratatui::buffer::Cell::symbol)
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn resolve_decision_shows_five_honest_slots_plus_always_multiline_custom() {
    // The shipped fork is five positions plus the always-present custom
    // row — the card paints every one of them with its honest state.
    let (mut world, session, task) = world_with_task("card-slots");
    let question = world.publish(&session, &task);
    assert_eq!(question.options.len(), 5, "five positions ship");
    let mut view = initial_view();
    view.decision = Some(DecisionPanel::new(question));

    // Border glyphs are layout, not content: rows wrap inside them, so
    // the comparison reads the text with the box strokes stripped.
    let frame = rendered_text(&view, 160, 50).replace(['│', '─', '┌', '┐', '└', '┘'], " ");
    let flat = support::squashed(&frame);
    for needle in [
        DECISION_TITLE,
        "1. Brief answer — The essentials without a breakdown. (recommended)",
        "2. Step-by-step — Sequential steps with an explanation of each.",
        "3. Worked example — A full example from the given conditions to the result.",
        "4. Compare options — A table of trade-offs.",
        "5. Diagram — A visual structure diagram. — unavailable: no useful diagram for this topic",
        "6. custom answer — type your own answer",
        "focus 1/6",
        "arrows move",
    ] {
        assert!(flat.contains(needle), "the card paints {needle:?}: {flat}");
    }
}

#[test]
fn card_header_paints_the_pinned_pair_without_clipping() {
    // The narrowest acceptance geometry: the card is 60 cells wide, the
    // pinned header owns three rows inside the border — 58 cells. The
    // pinned pair the answer commits against must fit whole; a clipped
    // tail would read as a truncated id or a dropped revision.
    let (mut world, session, task) = world_with_task("card-header-floor");
    let question = world.publish(&session, &task);
    let mut view = initial_view();
    view.decision = Some(DecisionPanel::new(question.clone()));

    let frame = rendered_text(&view, 60, 20);
    let task_row = frame
        .lines()
        .find(|line| line.contains("task: "))
        .expect("the header paints the task row");
    assert!(
        task_row.trim_end_matches('│').trim_end().ends_with(&task.0),
        "the task id ends its row unclipped: {task_row}"
    );
    let question_row = frame
        .lines()
        .find(|line| line.contains("question: "))
        .expect("the header paints the question row");
    let pinned = format!(
        "{} rev {}",
        question.question_id.0, question.question_revision
    );
    assert!(
        question_row
            .trim_end_matches('│')
            .trim_end()
            .ends_with(&pinned),
        "the pinned pair ends its row unclipped: {question_row}"
    );
}

#[test]
fn decision_card_owns_the_modal_over_a_permission_panel() {
    let (mut world, session, task) = world_with_task("card-modal-order");
    let mut view = card_view(&mut world, &session, &task);
    view.panel = Some(PermissionPanel::new(
        ModeDecision::Ask,
        EffectClass::Write,
        "grant-1",
        "task",
        "session",
        "/tmp/scope",
    ));

    // Input order: while a card is open the decision handler owns the
    // keys — a Down moves the card's focus and the panel never sees it.
    handle_decision_event(&key(KeyCode::Down), &mut view, &mut world.runtime, &session);
    assert_eq!(
        view.decision.as_ref().expect("card").focus(),
        1,
        "the decision card took the key"
    );
    assert!(view.panel.is_some(), "the panel stayed parked underneath");

    // Paint order: the modals share the same centered rect — the card
    // clears and repaints over it, so its header, never the panel's,
    // is what the terminal shows.
    let frame = rendered_text(&view, 80, 24);
    assert!(
        frame.contains(DECISION_TITLE),
        "the decision card paints on top: {frame}"
    );
    assert!(
        !frame.contains(PANEL_TITLE),
        "the permission panel never bleeds through: {frame}"
    );
}

#[test]
fn card_draft_honors_the_wire_size_limit() {
    let (mut world, session, task) = world_with_task("card-draft-limit");
    let mut view = card_view(&mut world, &session, &task);
    let question = view.decision.as_ref().expect("card").question.clone();

    // The wire bound denies first — an oversized custom answer journals
    // invalid_selection and leaves the fork pending.
    let oversized = world.dispatch(&corpus_answer_custom(
        &session,
        "cmd-oversized-custom",
        &task,
        &question,
        &"x".repeat(TEXT_MAX_BYTES + 1),
        json!(270),
    ));
    assert_eq!(
        oversized["error"]["data"]["code"], "invalid_input",
        "the oversized custom answer is denied at the wire: {oversized}"
    );
    let attempts = world
        .runtime
        .store()
        .answer_attempts(&task)
        .expect("attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].denial.as_deref(), Some("invalid_selection"));

    // The card's draft carries the same bound: the paste that fills it
    // lands, the byte past the bound refuses with the named note —
    // never a silent truncate.
    let rt = &mut world.runtime;
    for _ in 0..5 {
        handle_decision_event(&key(KeyCode::Down), &mut view, rt, &session);
    }
    handle_decision_event(&key(KeyCode::Enter), &mut view, rt, &session);
    assert!(view.decision.as_ref().expect("card").custom_editing());
    handle_decision_event(
        &TermEvent::Paste("x".repeat(TEXT_MAX_BYTES)),
        &mut view,
        rt,
        &session,
    );
    assert_eq!(
        view.decision.as_ref().expect("card").custom_draft().len(),
        TEXT_MAX_BYTES,
        "the draft fills exactly to the wire bound"
    );
    handle_decision_event(&TermEvent::Paste("y".to_string()), &mut view, rt, &session);
    assert_eq!(
        view.decision.as_ref().expect("card").custom_draft().len(),
        TEXT_MAX_BYTES,
        "the refused append never grew the draft"
    );
    assert!(
        view.transcript
            .iter()
            .any(|line| line == DECISION_DRAFT_LIMIT_NOTE),
        "the refused append is named: {:?}",
        view.transcript
    );

    // And the bound-sized draft still commits through the shared seam.
    handle_decision_event(&key(KeyCode::Esc), &mut view, rt, &session);
    handle_decision_event(&key(KeyCode::Enter), &mut view, rt, &session);
    let (answer_json, _) = world
        .runtime
        .store()
        .answered_question(&task)
        .expect("answered")
        .expect("the bound-sized draft commits");
    assert!(
        answer_json.contains(&"x".repeat(TEXT_MAX_BYTES)),
        "the max-size custom answer is durable"
    );
}

// ----- PTY proof on the 60x20 acceptance geometry -----

const DECISION_PTY_ROWS: usize = 20;
const DECISION_PTY_COLS: usize = 60;

#[test]
fn pty_terminal_enables_then_restores_bracketed_paste() {
    // The enable lands with the alternate screen at startup; the
    // disable rides the same restore path on exit — enable strictly
    // before its own disable, both paired with the alt-screen dance.
    let mut pty = spawn_pty(
        &rivect_binary(),
        DECISION_PTY_ROWS as u16,
        DECISION_PTY_COLS as u16,
    );
    assert!(
        pty.wait_for(b"\x1b[?2004h", Duration::from_secs(10))
            .expect("pty read"),
        "bracketed paste enables on start"
    );
    pty.send(b"\x1b").expect("pty send");
    assert_eq!(
        pty.wait_exit(Duration::from_secs(10)).expect("pty wait"),
        Some(0)
    );

    let stream = pty.collected().expect("pty read");
    let paste_on = support::find_subsequence(&stream, b"\x1b[?2004h").expect("enable");
    let paste_off = support::find_subsequence(&stream, b"\x1b[?2004l").expect("disable");
    assert!(
        paste_on < paste_off,
        "the disable lands on restore, after the enable"
    );
    let screen_on = support::find_subsequence(&stream, b"\x1b[?1049h").expect("alt screen on");
    let screen_off = support::find_subsequence(&stream, b"\x1b[?1049l").expect("alt screen off");
    assert!(screen_on < screen_off, "the alt screen restores too");
    pty.finish().expect("pty teardown");
}

// ----- plan selection, plan gate, gate hold and visibility -----

/// The plan legs, the gate and its hold: their own module so the
/// contract types they name do not shadow the qualified paths the
/// decision tests above spell out.
mod plan_selection {
    use super::{action_ctx, decision_config, support};
    use rivect::actions::{
        ASSESS_PLAN, ASSESS_READINESS, ASSESS_SECURITY, AUDIT_TESTS, ActionError, ActionInput,
        ActionOutcome, ActionRegistry, Assessment, CHALLENGE_DIRECTION, ContractBasis,
        DELIVER_CHANGE, DESIGN_CONTRACTS, DIAGNOSE_ISSUE, Declined, FRAME_GOAL, FrameUnknown,
        IMPLEMENT_CHANGE, INSPECT_SYSTEM, PLAN_STAGES, PLAN_WORK, PlanFinding, PlanGate,
        PlanRequest, RESOLVE_DECISION, REVIEW_CHANGE, RequestKind, Route, RouteBlock, Selection,
        SkipReason, Surface, SurfaceScan, WorkPart, plan_gate,
    };
    use rivect::contracts::{
        ARRAY_MAX_ITEMS, AnswerSelection, Blocker, CriterionId, EffectClass, ErrorCode, Lifecycle,
        ObligationApplicability, ObligationExecution, OptionId, ResumeCondition, SessionId,
        TEXT_MAX_BYTES, TaskId, TaskSnapshot,
    };
    use rivect::state::{
        ConflictCause, PlanAssessmentWrite, PlanGateHold, PlanObligationRecord, PlanRowChange,
        PlanRowUpdate, PlanVerdict, StoreError, plan_blocker,
    };
    use serde_json::json;
    use std::collections::BTreeSet;
    use support::open_world;

    const PLAN_CRITERIA: [&str; 2] = [
        "Expired tokens are rejected at login.",
        "The public token endpoint keeps its response shape.",
    ];

    /// A world whose config admits the offline read step, with one task
    /// owning the criteria the test chose — the plan legs read the stored
    /// criteria, so each fixture must own them.
    fn plan_world(tag: &str, criteria: &[&str]) -> (support::World, SessionId, TaskId) {
        let mut world = open_world(tag, Some(&support::config_distinct_pools()));
        world.runtime.purpose = "backend_task".to_string();
        let session = world.open_session("plan-session");
        let task = submit_plan_task(
            &mut world,
            &session,
            &format!("cmd-{tag}"),
            "Rotate session tokens.",
            criteria,
        );
        (world, session, task)
    }

    fn submit_plan_task(
        world: &mut support::World,
        session: &SessionId,
        command_id: &str,
        goal: &str,
        criteria: &[&str],
    ) -> TaskId {
        let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 4, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": command_id, "session_id": session.0,
            "kind": "create",
            "goal": goal,
            "contract": { "criteria": criteria, "constraints": ["Keep existing callers working."] },
            "attachments": []
        }
    }));
        TaskId(
            response["result"]["task_id"]
                .as_str()
                .unwrap_or_else(|| panic!("task.submit failed: {response}"))
                .to_string(),
        )
    }

    fn criterion_ids(world: &support::World, task: &TaskId) -> Vec<CriterionId> {
        plan_snapshot(world, task)
            .criteria
            .items
            .into_iter()
            .map(|criterion| criterion.id)
            .collect()
    }

    fn part(id: &str, criteria: &[CriterionId], depends_on: &[&str], proof: &str) -> WorkPart {
        WorkPart {
            id: id.to_string(),
            criteria: criteria.to_vec(),
            depends_on: depends_on.iter().map(|dep| (*dep).to_string()).collect(),
            proof: proof.to_string(),
        }
    }

    fn facts(
        task: &TaskId,
        kind: RequestKind,
        surfaces: &[Surface],
        contract: ContractBasis,
        parts: Vec<WorkPart>,
    ) -> PlanRequest {
        PlanRequest {
            task_id: task.clone(),
            kind,
            surfaces: SurfaceScan::Known(surfaces.iter().copied().collect()),
            contract,
            parts,
            delegation: None,
            author: None,
        }
    }

    /// Two dependent parts covering both criteria with real proofs.
    fn covering_parts(world: &support::World, task: &TaskId) -> Vec<WorkPart> {
        let criteria = criterion_ids(world, task);
        vec![
            part("schema", &criteria[..1], &[], "cargo test --test schema"),
            part(
                "endpoint",
                &criteria[1..],
                &["schema"],
                "cargo test --test endpoint",
            ),
        ]
    }

    /// A coordinated plan-only request on a local surface: every row it
    /// selects has a local handler (readiness through its `assess_plan`
    /// equivalent), so only the semantic leg stands between it and `Open`.
    fn plan_only(world: &support::World, task: &TaskId) -> PlanRequest {
        facts(
            task,
            RequestKind::PlanOnly,
            &[Surface::Local],
            ContractBasis::Absent,
            covering_parts(world, task),
        )
    }

    /// A material change: authorization plus a public interface, no
    /// approved contract.
    fn material(world: &support::World, task: &TaskId) -> PlanRequest {
        facts(
            task,
            RequestKind::Change,
            &[Surface::Auth, Surface::PublicApi],
            ContractBasis::Absent,
            covering_parts(world, task),
        )
    }

    /// A plan-only request whose scan decided nothing: dependent rows wait
    /// on their applicability.
    fn undecided(world: &support::World, task: &TaskId) -> PlanRequest {
        PlanRequest {
            surfaces: SurfaceScan::Unknown,
            ..plan_only(world, task)
        }
    }

    fn select(
        world: &mut support::World,
        session: &SessionId,
        request: &PlanRequest,
        shortlist: &[&str],
    ) -> Selection {
        let config = decision_config(None);
        ActionRegistry::new()
            .select(request, shortlist, &mut action_ctx(world, session, &config))
            .expect("the selection records")
    }

    fn run(
        world: &mut support::World,
        session: &SessionId,
        input: ActionInput,
    ) -> Result<ActionOutcome, ActionError> {
        let config = decision_config(None);
        ActionRegistry::new().execute(input, &mut action_ctx(world, session, &config))
    }

    fn rows(world: &support::World, task: &TaskId) -> Vec<PlanObligationRecord> {
        world
            .runtime
            .store()
            .plan_obligations(task)
            .expect("plan rows read")
    }

    fn row(world: &support::World, task: &TaskId, capability: &str) -> PlanObligationRecord {
        rows(world, task)
            .into_iter()
            .find(|row| row.capability == capability)
            .unwrap_or_else(|| panic!("{capability} is a recorded plan row"))
    }

    fn row_capabilities(world: &support::World, task: &TaskId) -> Vec<String> {
        rows(world, task)
            .into_iter()
            .map(|row| row.capability)
            .collect()
    }

    fn gate(world: &support::World, task: &TaskId) -> PlanGate {
        plan_gate(world.runtime.store(), task).expect("the gate reads")
    }

    fn plan_snapshot(world: &support::World, task: &TaskId) -> TaskSnapshot {
        world.runtime.store().snapshot(task).expect("snapshot")
    }

    fn selected(selection: &Selection) -> Vec<&'static str> {
        selection
            .obligations
            .iter()
            .map(|obligation| obligation.capability)
            .collect()
    }

    fn plan_blockers(snapshot: &TaskSnapshot) -> Vec<Blocker> {
        snapshot
            .blockers
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter(|blocker| blocker.owner == "plan")
            .collect()
    }

    fn store_cause(error: ActionError) -> StoreError {
        match error {
            ActionError::Store(source) => source,
            other => panic!("expected a store refusal, got {other:?}"),
        }
    }

    fn skipped(outcome: &ActionOutcome) -> Option<SkipReason> {
        match outcome {
            ActionOutcome::Skipped { reason, .. } => Some(*reason),
            _ => None,
        }
    }

    fn provider_calls(world: &support::World) -> u64 {
        world
            .provider_calls
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Stands in for the SLICE-176 semantic leg: its only way to close a
    /// row is the one plan-row write, bound to the selection it ran on.
    fn semantic_close(
        world: &mut support::World,
        task: &TaskId,
        selection: &Selection,
        capability: &str,
        handler: &str,
    ) {
        world
            .runtime
            .store_writer()
            .update_plan_row(
                task,
                &PlanRowUpdate {
                    capability,
                    handler,
                    selection_revision: selection.revision,
                    facts_digest: &selection.facts_digest,
                    change: PlanRowChange::Close {
                        execution: ObligationExecution::Satisfied,
                        outcome_json: json!({ "semantic": "pass" }).to_string(),
                    },
                },
            )
            .expect("the semantic close lands through the one plan-row write");
    }

    /// Frames, plans, passes the mechanical leg and closes every row the
    /// assessor owns: the plan-only gate opens.
    fn drive_plan_only_open(
        world: &mut support::World,
        session: &SessionId,
        task: &TaskId,
    ) -> (PlanRequest, Selection) {
        let request = plan_only(world, task);
        let selection = select(world, session, &request, &[]);
        run(world, session, ActionInput::FrameGoal(request.clone())).expect("frame");
        run(world, session, ActionInput::PlanWork(request.clone())).expect("plan");
        let assessed =
            run(world, session, ActionInput::AssessPlan(request.clone())).expect("assess");
        assert!(
            matches!(
                assessed,
                ActionOutcome::Assessed(Assessment {
                    verdict: PlanVerdict::Pass,
                    ..
                })
            ),
            "{assessed:?}"
        );
        semantic_close(world, task, &selection, ASSESS_PLAN, ASSESS_PLAN);
        semantic_close(world, task, &selection, ASSESS_READINESS, ASSESS_PLAN);
        assert_eq!(gate(world, task), PlanGate::Open);
        (request, selection)
    }

    /// The completion guard refuses an open task and parks it: `running`
    /// moves to `waiting`, where the open rows' blockers project.
    fn park(world: &mut support::World, session: &SessionId, task: &TaskId) -> TaskSnapshot {
        let refused = world
            .runtime
            .store_writer()
            .complete_if_eligible(session, task)
            .expect_err("an open plan row keeps completion closed");
        assert!(
            matches!(
                refused,
                StoreError::Conflict(ConflictCause::CompletionOpen { .. })
            ),
            "{refused}"
        );
        plan_snapshot(world, task)
    }

    fn wire_snapshot(
        world: &mut support::World,
        session: &SessionId,
        task: &TaskId,
    ) -> serde_json::Value {
        let response = world.dispatch(&json!({
            "jsonrpc": "2.0", "id": 90, "method": "task.snapshot",
            "params": { "schema_version": 1, "session_id": session.0, "task_id": task.0 }
        }));
        assert!(response["error"].is_null(), "{response}");
        response["result"].clone()
    }

    fn wire_status(world: &mut support::World, session: &SessionId) -> serde_json::Value {
        let response = world.dispatch(&support::corpus_status(session));
        assert!(response["error"].is_null(), "{response}");
        response["result"].clone()
    }

    fn todo_item<'a>(status: &'a serde_json::Value, task: &TaskId) -> &'a serde_json::Value {
        status["todo"]["items"]
            .as_array()
            .and_then(|items| items.iter().find(|item| item["task_id"] == task.0.as_str()))
            .unwrap_or_else(|| panic!("todo lists {}: {status}", task.0))
    }

    fn dock_line(status: &serde_json::Value, task: &TaskId) -> String {
        rivect::ui::task_dock(status)
            .into_iter()
            .find(|line| line.starts_with(&format!("task {}:", task.0)))
            .unwrap_or_else(|| panic!("the dock lists {}", task.0))
    }

    /// One real scoped read grant for the offline decision step; the read
    /// worker runs under the sandbox helper.
    fn plan_grant(world: &mut support::World) -> String {
        support::ensure_helper();
        let scope = world.root.join("plan-scope");
        std::fs::create_dir_all(&scope).expect("scope dir");
        let file = scope.join("allowed.txt");
        std::fs::write(&file, "plan-gate-marker\n").expect("scoped file");
        world.runtime.set_read_scope(scope, file)
    }

    fn plan_db(world: &support::World) -> rusqlite::Connection {
        rusqlite::Connection::open(world.root.join("runtime").join("rivect.db")).expect("raw db")
    }

    /// Whether the plan-owned block mark is present — the persisted
    /// record that only the plan made the task's current block.
    fn plan_owned_mark(world: &support::World, task: &TaskId) -> bool {
        plan_db(world)
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM plan_blocks WHERE task_id = ?1)",
                rusqlite::params![task.0],
                |row| row.get(0),
            )
            .expect("mark reads")
    }

    #[test]
    fn purpose_row_without_a_broker_seam_yields_exact_blocker_never_a_template() {
        let (mut world, session, task) = plan_world("plan-purpose", &PLAN_CRITERIA);
        let request = material(&world, &task);
        let selection = select(&mut world, &session, &request, &[]);
        for capability in [CHALLENGE_DIRECTION, DESIGN_CONTRACTS] {
            assert!(
                selection
                    .obligations
                    .iter()
                    .any(|obligation| obligation.capability == capability
                        && obligation.route == Route::Purpose(capability)),
                "{capability} routes to its Broker purpose: {selection:?}"
            );
            let input = if capability == CHALLENGE_DIRECTION {
                ActionInput::ChallengeDirection(request.clone())
            } else {
                ActionInput::DesignContracts(request.clone())
            };
            let error = run(&mut world, &session, input).expect_err("no broker seam in this build");
            assert!(
                matches!(error, ActionError::Unavailable { action } if action == capability),
                "{error:?}"
            );
            assert_eq!(error.error_code(), ErrorCode::CapabilityUnavailable);
            // The row stays open on the exact blocker: no template output
            // closed it and it never reads as not applicable.
            let stored = row(&world, &task, capability);
            assert_eq!(stored.applicability, ObligationApplicability::Required);
            assert_eq!(stored.execution, ObligationExecution::Pending);
            assert_eq!(stored.outcome_json, None, "no template closed {capability}");
            assert_eq!(stored.handler.as_deref(), Some(capability));
            assert_eq!(
                stored.blocker,
                Some(plan_blocker(ErrorCode::CapabilityUnavailable, capability))
            );
        }
        let snapshot = plan_snapshot(&world, &task);
        assert_eq!(snapshot.lifecycle, Lifecycle::Blocked);
        for capability in [CHALLENGE_DIRECTION, DESIGN_CONTRACTS] {
            assert!(
                plan_blockers(&snapshot)
                    .contains(&plan_blocker(ErrorCode::CapabilityUnavailable, capability)),
                "{capability} is visible as its exact blocker: {:?}",
                snapshot.blockers
            );
        }
        assert!(matches!(gate(&world, &task), PlanGate::Paused { .. }));
        run(&mut world, &session, ActionInput::PlanWork(request.clone())).expect("local plan");
        let mechanical = run(&mut world, &session, ActionInput::AssessPlan(request))
            .expect("mechanical leg is local");
        assert!(
            matches!(
                mechanical,
                ActionOutcome::Assessed(Assessment {
                    verdict: PlanVerdict::Pass,
                    ..
                })
            ),
            "the local verdict cannot close the semantic row"
        );
        for capability in [ASSESS_PLAN, ASSESS_READINESS] {
            let stored = row(&world, &task, capability);
            assert_eq!(stored.execution, ObligationExecution::Pending);
            assert_eq!(
                stored.blocker,
                Some(plan_blocker(ErrorCode::CapabilityUnavailable, capability))
            );
        }
        assert_eq!(provider_calls(&world), 0, "no model call anywhere");
    }

    #[test]
    fn sufficient_contract_skips_decorative_stages() {
        // One-variable pair: same kind, surfaces and parts; only the
        // contract basis differs.
        let (mut world, session, absent_task) = plan_world("plan-sufficient-pair", &PLAN_CRITERIA);
        let approved_task = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-sufficient-approved",
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        let request_for = |world: &support::World, task: &TaskId, contract| {
            let criteria = criterion_ids(world, task);
            facts(
                task,
                RequestKind::Change,
                &[Surface::Auth],
                contract,
                vec![part("rotate", &criteria, &[], "cargo test --test rotate")],
            )
        };
        let absent = request_for(&world, &absent_task, ContractBasis::Absent);
        let approved = request_for(&world, &approved_task, ContractBasis::Approved);
        let absent_selection = select(&mut world, &session, &absent, &[]);
        let approved_selection = select(&mut world, &session, &approved, &[]);
        let stages = |selection: &Selection| -> Vec<&'static str> {
            selected(selection)
                .into_iter()
                .filter(|capability| PLAN_STAGES.contains(capability))
                .collect()
        };
        assert_eq!(
            stages(&absent_selection),
            PLAN_STAGES.to_vec(),
            "a risky surface without a contract runs every stage"
        );
        assert!(
            stages(&approved_selection).is_empty(),
            "an approved contract runs no decorative stage: {approved_selection:?}"
        );
        // Everything but the stages is identical: the basis is the only
        // variable the pair moved.
        let checks = |selection: &Selection| -> Vec<&'static str> {
            selected(selection)
                .into_iter()
                .filter(|capability| !PLAN_STAGES.contains(capability))
                .collect()
        };
        assert_eq!(checks(&absent_selection), checks(&approved_selection));
        assert!(checks(&approved_selection).contains(&ASSESS_SECURITY));
        // The stage handlers report the approved basis instead of running.
        for input in [
            ActionInput::FrameGoal(approved.clone()),
            ActionInput::ChallengeDirection(approved.clone()),
            ActionInput::DesignContracts(approved.clone()),
        ] {
            let outcome = run(&mut world, &session, input).expect("a skip, not a refusal");
            assert_eq!(
                skipped(&outcome),
                Some(SkipReason::AlreadySatisfied),
                "{outcome:?}"
            );
        }
        assert!(
            row_capabilities(&world, &approved_task)
                .iter()
                .all(|capability| !PLAN_STAGES.contains(&capability.as_str())),
            "no stage row was recorded for the approved contract"
        );
    }

    #[test]
    fn sufficient_contract_selection_opens_the_gate_without_a_plan_revision() {
        let (mut world, session, sufficient_task) =
            plan_world("plan-open-sufficient", &PLAN_CRITERIA);
        let typo_task = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-open-typo",
            "Fix the typo in the login banner.",
            &PLAN_CRITERIA,
        );
        let single = |world: &support::World, task: &TaskId, contract| {
            let criteria = criterion_ids(world, task);
            facts(
                task,
                RequestKind::Change,
                &[Surface::Local],
                contract,
                vec![part("banner", &criteria, &[], "cargo test --test banner")],
            )
        };
        let sufficient = single(&world, &sufficient_task, ContractBasis::Approved);
        select(&mut world, &session, &sufficient, &[]);
        assert_eq!(
            gate(&world, &sufficient_task),
            PlanGate::Open,
            "no required plan-phase row and no plan_work: the gate opens without a revision"
        );
        // The execution-phase rows stay required and open: they follow the
        // effect the open gate admits, so they never gate it.
        for capability in [IMPLEMENT_CHANGE, AUDIT_TESTS, ASSESS_READINESS] {
            let stored = row(&world, &sufficient_task, capability);
            assert_eq!(stored.applicability, ObligationApplicability::Required);
            assert_eq!(
                stored.execution,
                ObligationExecution::Pending,
                "{capability} stays open"
            );
            assert!(!stored.stage, "{capability} is execution-phase");
        }
        // Only rows whose handlers land after this position (SLICE-027)
        // are pinned handler-less; `implement_change` gets its handler in
        // SLICE-024.
        let later = [AUDIT_TESTS, ASSESS_READINESS];
        for capability in later {
            let stored = row(&world, &sufficient_task, capability);
            assert_eq!(
                stored.handler, None,
                "{capability}'s handler lands after this position"
            );
            assert_eq!(
                stored.blocker,
                Some(plan_blocker(ErrorCode::CapabilityUnavailable, capability))
            );
        }
        // A handler-less execution row never moves the lifecycle...
        let running = plan_snapshot(&world, &sufficient_task);
        assert_eq!(running.lifecycle, Lifecycle::Running);
        assert_eq!(running.blockers, None);
        // ...it holds completion only: the guard parks the task, and the
        // exact blockers of the later-position rows project.
        let parked = park(&mut world, &session, &sufficient_task);
        assert_eq!(parked.lifecycle, Lifecycle::Waiting);
        for capability in later {
            assert!(
                plan_blockers(&parked)
                    .contains(&plan_blocker(ErrorCode::CapabilityUnavailable, capability)),
                "{capability} is the exact reason completion waits: {:?}",
                parked.blockers
            );
        }

        let typo = single(&world, &typo_task, ContractBasis::Absent);
        let typo_selection = select(&mut world, &session, &typo, &[]);
        assert_eq!(
            selected(&typo_selection)
                .into_iter()
                .filter(|capability| PLAN_STAGES.contains(capability))
                .collect::<Vec<_>>(),
            vec![FRAME_GOAL],
            "a known local typo frames and nothing more"
        );
        assert_eq!(
            gate(&world, &typo_task),
            PlanGate::Paused {
                unresolved: Vec::new(),
                open_stages: vec![FRAME_GOAL.to_string()],
            }
        );
        assert_eq!(
            plan_snapshot(&world, &typo_task).lifecycle,
            Lifecycle::Running,
            "an eligible open stage keeps the task running"
        );
        run(&mut world, &session, ActionInput::FrameGoal(typo)).expect("frame");
        assert_eq!(gate(&world, &typo_task), PlanGate::Open);
        assert_eq!(
            plan_snapshot(&world, &typo_task).lifecycle,
            Lifecycle::Running
        );
        for task in [&sufficient_task, &typo_task] {
            assert!(
                world
                    .runtime
                    .store()
                    .plan_revisions(task)
                    .expect("revisions")
                    .is_empty(),
                "the gate opened with no plan revision at all"
            );
        }
    }

    #[test]
    fn short_request_with_auth_api_or_migration_risk_gets_required_depth() {
        let (mut world, session, short_task) = plan_world("plan-short-risk", &PLAN_CRITERIA);
        let long_goal = "Rotate session tokens. ".repeat(40);
        let long_task = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-long-risk",
            &long_goal,
            &PLAN_CRITERIA,
        );
        // The part names no task-local criterion id, so both requests
        // carry byte-identical facts and differ only in prompt length.
        let single = |task: &TaskId, surface: Surface| {
            facts(
                task,
                RequestKind::Change,
                &[surface],
                ContractBasis::Absent,
                vec![part("only", &[], &[], "cargo test")],
            )
        };
        // Same facts, very different prompt lengths: identical selections,
        // for a known local change and for a risky surface alike.
        for surface in [Surface::Local, Surface::Auth] {
            let short = select(&mut world, &session, &single(&short_task, surface), &[]);
            let long = select(&mut world, &session, &single(&long_task, surface), &[]);
            assert_eq!(
                short.obligations, long.obligations,
                "{surface:?}: the prompt length moves no row"
            );
            assert_eq!(
                short.facts_digest, long.facts_digest,
                "{surface:?}: prompt text is not a fact"
            );
        }

        let depth = [
            CHALLENGE_DIRECTION,
            DESIGN_CONTRACTS,
            PLAN_WORK,
            ASSESS_PLAN,
        ];
        for (surface, security) in [
            (Surface::Local, false),
            (Surface::Auth, true),
            (Surface::PublicApi, false),
            (Surface::Migration, false),
        ] {
            let request = single(&short_task, surface);
            let selection = select(&mut world, &session, &request, &[]);
            let capabilities = selected(&selection);
            let risky = surface != Surface::Local;
            for stage in depth {
                assert_eq!(
                    capabilities.contains(&stage),
                    risky,
                    "{stage} follows the {surface:?} surface, not the prompt length"
                );
            }
            assert_eq!(
                capabilities.contains(&ASSESS_SECURITY),
                security,
                "assess_security follows its trigger classes on {surface:?}"
            );
        }
    }

    #[test]
    fn security_trigger_surfaces_require_assess_security() {
        let (mut world, session, task) = plan_world("plan-security-classes", &PLAN_CRITERIA);
        let one = |task: &TaskId, surfaces: &[Surface], contract| {
            facts(task, RequestKind::Change, surfaces, contract, Vec::new())
        };
        for label in [
            "auth",
            "permissions",
            "secrets",
            "trust",
            "untrusted_input",
            "isolation",
            "dependencies",
            "private_data",
        ] {
            let scan = SurfaceScan::from_labels([label]);
            let SurfaceScan::Known(surfaces) = &scan else {
                panic!("{label} is in the vocabulary");
            };
            let surfaces: Vec<Surface> = surfaces.iter().copied().collect();
            let selection = select(
                &mut world,
                &session,
                &one(&task, &surfaces, ContractBasis::Absent),
                &[],
            );
            let security = selection
                .obligations
                .iter()
                .find(|obligation| obligation.capability == ASSESS_SECURITY)
                .unwrap_or_else(|| panic!("{label} requires assess_security"));
            assert_eq!(security.applicability, ObligationApplicability::Required);
            assert_eq!(security.route, Route::Blocked(RouteBlock::NotInBuild));
            // Every trigger class is a risk surface: without an approved
            // contract both semantic stages precede the effect and the gate
            // stays paused on them.
            for stage in [CHALLENGE_DIRECTION, DESIGN_CONTRACTS] {
                assert!(
                    selection.obligations.iter().any(|obligation| {
                        obligation.capability == stage
                            && obligation.applicability == ObligationApplicability::Required
                            && obligation.route == Route::Purpose(stage)
                    }),
                    "{label} requires {stage}: {selection:?}"
                );
            }
            let PlanGate::Paused { open_stages, .. } = gate(&world, &task) else {
                panic!("{label} without an approved contract never opens the gate");
            };
            for stage in [CHALLENGE_DIRECTION, DESIGN_CONTRACTS] {
                assert!(
                    open_stages.contains(&stage.to_string()),
                    "{label}: {open_stages:?}"
                );
            }
        }
        for surfaces in [
            vec![Surface::Local],
            vec![Surface::PublicApi],
            vec![Surface::Migration],
        ] {
            let selection = select(
                &mut world,
                &session,
                &one(&task, &surfaces, ContractBasis::Absent),
                &[],
            );
            assert!(
                !selected(&selection).contains(&ASSESS_SECURITY),
                "{surfaces:?} is not a security trigger class"
            );
        }

        // An approved contract on a security surface: the gate opens, but
        // `assess_security` stays required, open and handler-less on its
        // exact blocker — it holds completion, never the lifecycle.
        let covered = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-security-approved",
            "Rotate the signing secret.",
            &PLAN_CRITERIA,
        );
        let selection = select(
            &mut world,
            &session,
            &one(&covered, &[Surface::Secrets], ContractBasis::Approved),
            &[],
        );
        assert_eq!(gate(&world, &covered), PlanGate::Open);
        let security = selection
            .obligations
            .iter()
            .find(|obligation| obligation.capability == ASSESS_SECURITY)
            .expect("secrets requires assess_security");
        assert_eq!(security.route, Route::Blocked(RouteBlock::NotInBuild));
        let stored = row(&world, &covered, ASSESS_SECURITY);
        assert_eq!(stored.applicability, ObligationApplicability::Required);
        assert_eq!(stored.execution, ObligationExecution::Pending);
        assert_eq!(stored.handler, None);
        let exact = plan_blocker(ErrorCode::CapabilityUnavailable, ASSESS_SECURITY);
        assert_eq!(stored.blocker, Some(exact.clone()));
        assert_eq!(
            plan_snapshot(&world, &covered).lifecycle,
            Lifecycle::Running
        );
        let parked = park(&mut world, &session, &covered);
        assert_eq!(parked.lifecycle, Lifecycle::Waiting);
        assert!(
            plan_blockers(&parked).contains(&exact),
            "completion waits on assess_security: {:?}",
            parked.blockers
        );
    }

    #[test]
    fn empty_or_unrecognised_surface_scan_is_unresolved_never_no_risk() {
        let (mut world, session, task) = plan_world("plan-empty-scan", &PLAN_CRITERIA);
        let dependent = [
            CHALLENGE_DIRECTION,
            DESIGN_CONTRACTS,
            PLAN_WORK,
            ASSESS_PLAN,
            ASSESS_SECURITY,
        ];
        let scans = [
            SurfaceScan::Known(BTreeSet::new()),
            SurfaceScan::from_labels([]),
            SurfaceScan::from_labels(["auth", "quantum_tunnel"]),
            SurfaceScan::Unknown,
        ];
        assert_eq!(
            scans[1],
            SurfaceScan::Unknown,
            "an empty label list decides nothing"
        );
        assert_eq!(
            scans[2],
            SurfaceScan::Unknown,
            "an unrecognised label decides nothing"
        );
        let mut digests = BTreeSet::new();
        for scan in scans {
            let request = PlanRequest {
                task_id: task.clone(),
                kind: RequestKind::Change,
                surfaces: scan.clone(),
                contract: ContractBasis::Absent,
                parts: Vec::new(),
                delegation: None,
                author: None,
            };
            let selection = select(&mut world, &session, &request, &[]);
            digests.insert(selection.facts_digest.clone());
            for capability in dependent {
                let stored = row(&world, &task, capability);
                assert_eq!(
                    stored.applicability,
                    ObligationApplicability::Unresolved,
                    "{capability} under {scan:?} waits on the scan"
                );
                assert_eq!(
                    stored.blocker,
                    Some(plan_blocker(ErrorCode::DependencyBlocked, capability))
                );
            }
            assert!(
                rows(&world, &task)
                    .iter()
                    .all(|row| row.applicability != ObligationApplicability::NotApplicable),
                "no scan is never no risk"
            );
            assert_eq!(
                row(&world, &task, INSPECT_SYSTEM).applicability,
                ObligationApplicability::Required,
                "an undecided scan requires the inspection that would decide it"
            );
            let PlanGate::Paused { unresolved, .. } = gate(&world, &task) else {
                panic!("an undecided scan never opens the gate");
            };
            assert_eq!(unresolved.len(), dependent.len());
        }
        assert_eq!(digests.len(), 1, "every undecided scan is the same fact");
    }

    #[test]
    fn plan_only_audit_or_diagnose_request_never_edits_or_ships() {
        let (mut world, session, first) = plan_world("plan-kinds", &PLAN_CRITERIA);
        let edits = [IMPLEMENT_CHANGE, DELIVER_CHANGE, AUDIT_TESTS];
        for (index, kind) in [
            RequestKind::PlanOnly,
            RequestKind::Audit,
            RequestKind::Diagnose,
            RequestKind::Change,
            RequestKind::Deliver,
        ]
        .into_iter()
        .enumerate()
        {
            let task = if index == 0 {
                first.clone()
            } else {
                submit_plan_task(
                    &mut world,
                    &session,
                    &format!("cmd-plan-kind-{index}"),
                    "Rotate session tokens.",
                    &PLAN_CRITERIA,
                )
            };
            let request = facts(
                &task,
                kind,
                &[Surface::Local],
                ContractBasis::Absent,
                covering_parts(&world, &task),
            );
            let capabilities = selected(&select(&mut world, &session, &request, &[]));
            let edits_present: Vec<&str> = edits
                .into_iter()
                .filter(|capability| capabilities.contains(capability))
                .collect();
            match kind {
                RequestKind::PlanOnly | RequestKind::Audit | RequestKind::Diagnose => {
                    assert!(
                        edits_present.is_empty(),
                        "{kind:?} never edits or ships: {capabilities:?}"
                    );
                }
                RequestKind::Change => {
                    assert_eq!(edits_present, vec![IMPLEMENT_CHANGE, AUDIT_TESTS]);
                }
                RequestKind::Deliver => {
                    assert_eq!(
                        edits_present,
                        vec![IMPLEMENT_CHANGE, DELIVER_CHANGE, AUDIT_TESTS]
                    );
                }
            }
            assert_eq!(
                capabilities.contains(&REVIEW_CHANGE),
                kind == RequestKind::Audit
            );
            assert_eq!(
                capabilities.contains(&DIAGNOSE_ISSUE),
                kind == RequestKind::Diagnose
            );
            // The kind is persisted on the selection the effect gate reads.
            let record = world
                .runtime
                .store()
                .plan_selection(&task)
                .expect("selection reads")
                .expect("a selection was recorded");
            assert_eq!(record.request_kind, kind);
        }
    }

    #[test]
    fn plan_presence_never_unblocks_execution() {
        let (mut world, session, task) = plan_world("plan-presence", &PLAN_CRITERIA);
        assert_eq!(gate(&world, &task), PlanGate::Unassessed);
        let request = plan_only(&world, &task);
        let selection = select(&mut world, &session, &request, &[]);
        run(
            &mut world,
            &session,
            ActionInput::FrameGoal(request.clone()),
        )
        .expect("frame");
        let planned = run(&mut world, &session, ActionInput::PlanWork(request)).expect("plan");
        assert!(matches!(
            planned,
            ActionOutcome::Planned { revision: 1, .. }
        ));
        // A stored revision without a passing verdict: even with every
        // required row closed, the revision conjunct keeps the gate paused.
        semantic_close(&mut world, &task, &selection, ASSESS_PLAN, ASSESS_PLAN);
        semantic_close(&mut world, &task, &selection, ASSESS_READINESS, ASSESS_PLAN);
        assert!(
            rows(&world, &task)
                .iter()
                .all(|row| row.execution == ObligationExecution::Satisfied),
            "every required row closed"
        );
        assert_eq!(
            gate(&world, &task),
            PlanGate::Paused {
                unresolved: Vec::new(),
                open_stages: vec![ASSESS_PLAN.to_string()],
            },
            "plan presence is never the verdict"
        );
    }

    #[test]
    fn new_plan_revision_reopens_assessment_and_blocks_completion() {
        let (mut world, session, task) = plan_world("plan-new-revision", &PLAN_CRITERIA);
        let (request, _) = drive_plan_only_open(&mut world, &session, &task);
        assert_eq!(plan_snapshot(&world, &task).lifecycle, Lifecycle::Running);
        let replanned = run(&mut world, &session, ActionInput::PlanWork(request)).expect("replan");
        assert!(matches!(
            replanned,
            ActionOutcome::Planned { revision: 2, .. }
        ));
        for capability in [ASSESS_PLAN, ASSESS_READINESS] {
            let stored = row(&world, &task, capability);
            assert_eq!(
                stored.execution,
                ObligationExecution::Pending,
                "revision 2 reopens {capability}"
            );
            assert_eq!(stored.outcome_json, None);
        }
        assert_eq!(
            gate(&world, &task),
            PlanGate::Paused {
                unresolved: Vec::new(),
                open_stages: vec![ASSESS_PLAN.to_string()],
            }
        );
        // The completion guard sees the reopened rows even with every
        // criterion's evidence in place.
        let mut store = world.runtime.store_writer();
        store
            .materialize_obligations(&task)
            .expect("criteria obligations");
        store
            .insert_evidence_for_task(&task, "task", "criteria proven", "digest")
            .expect("criterion evidence");
        let refused = store
            .complete_if_eligible(&session, &task)
            .expect_err("an unassessed revision keeps the task open");
        assert!(
            matches!(
                refused,
                StoreError::Conflict(ConflictCause::CompletionOpen { unsatisfied: 2, .. })
            ),
            "{refused}"
        );
    }

    #[test]
    fn assessment_of_a_superseded_revision_never_lands() {
        let (mut world, session, task) = plan_world("plan-superseded", &PLAN_CRITERIA);
        let request = plan_only(&world, &task);
        let selection = select(&mut world, &session, &request, &[]);
        run(&mut world, &session, ActionInput::PlanWork(request.clone())).expect("revision 1");
        run(&mut world, &session, ActionInput::PlanWork(request.clone())).expect("revision 2");
        // Revision 1 is still unjudged: only the latest-revision predicate
        // can refuse this verdict.
        let refused = world
            .runtime
            .store_writer()
            .record_plan_assessment(
                &task,
                &PlanAssessmentWrite {
                    handler: ASSESS_PLAN,
                    selection_revision: selection.revision,
                    facts_digest: &selection.facts_digest,
                    plan_revision: 1,
                    verdict: PlanVerdict::Pass,
                    assessment_json: "{}",
                    changes: Vec::new(),
                },
            )
            .expect_err("a superseded revision is not assessable");
        assert!(
            matches!(
                refused,
                StoreError::Conflict(ConflictCause::PlanNotAssessable { revision: 1 })
            ),
            "{refused}"
        );
        let revisions = world
            .runtime
            .store()
            .plan_revisions(&task)
            .expect("revisions");
        assert_eq!(revisions.len(), 2);
        assert!(
            revisions.iter().all(|revision| revision.verdict.is_none()),
            "nothing landed: {revisions:?}"
        );
        // The handler judges the latest revision only.
        let assessed = run(&mut world, &session, ActionInput::AssessPlan(request)).expect("assess");
        assert!(
            matches!(
                assessed,
                ActionOutcome::Assessed(Assessment {
                    plan_revision: 2,
                    ..
                })
            ),
            "{assessed:?}"
        );

        // A revision recorded under an earlier selection is never
        // assessable under the current one — even while it is the task's
        // latest and still unjudged.
        let other = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-superseded-selection",
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        let first = plan_only(&world, &other);
        select(&mut world, &session, &first, &[]);
        run(&mut world, &session, ActionInput::PlanWork(first.clone())).expect("revision 1");
        let mut changed = first;
        changed.parts[1].proof = "cargo test --test endpoint --test contract".to_string();
        let current = select(&mut world, &session, &changed, &[]);
        assert_eq!(current.revision, 2, "changed facts bump the selection");
        let refused = world
            .runtime
            .store_writer()
            .record_plan_assessment(
                &other,
                &PlanAssessmentWrite {
                    handler: ASSESS_PLAN,
                    selection_revision: current.revision,
                    facts_digest: &current.facts_digest,
                    plan_revision: 1,
                    verdict: PlanVerdict::Pass,
                    assessment_json: "{}",
                    changes: Vec::new(),
                },
            )
            .expect_err("an earlier selection's revision is not assessable");
        assert!(
            matches!(
                refused,
                StoreError::Conflict(ConflictCause::PlanNotAssessable { revision: 1 })
            ),
            "{refused}"
        );
        let revisions = world
            .runtime
            .store()
            .plan_revisions(&other)
            .expect("revisions");
        assert_eq!(revisions.len(), 1);
        assert_eq!(revisions[0].verdict, None, "nothing landed: {revisions:?}");
        // The handler bound to the current selection finds no revision of
        // its own to judge.
        let outcome = run(&mut world, &session, ActionInput::AssessPlan(changed)).expect("a skip");
        assert_eq!(skipped(&outcome), Some(SkipReason::NeedsInformation));
    }

    #[test]
    fn failed_verdict_then_reselect_reopens_through_a_new_revision_never_already_satisfied() {
        let (mut world, session, task) = plan_world("plan-failed-reselect", &PLAN_CRITERIA);
        let criteria = criterion_ids(&world, &task);
        // The first plan never serves the second criterion.
        let partial = facts(
            &task,
            RequestKind::PlanOnly,
            &[Surface::Local],
            ContractBasis::Absent,
            vec![
                part("schema", &criteria[..1], &[], "cargo test --test schema"),
                part("docs", &criteria[..1], &["schema"], "cargo test --doc"),
            ],
        );
        let recorded = select(&mut world, &session, &partial, &[]);
        run(
            &mut world,
            &session,
            ActionInput::FrameGoal(partial.clone()),
        )
        .expect("frame");
        run(&mut world, &session, ActionInput::PlanWork(partial.clone())).expect("plan");
        let failed = run(
            &mut world,
            &session,
            ActionInput::AssessPlan(partial.clone()),
        )
        .expect("assess");
        let ActionOutcome::Assessed(assessment) = failed else {
            panic!("expected an assessment, got {failed:?}");
        };
        assert_eq!(assessment.verdict, PlanVerdict::Fail);
        assert_eq!(
            assessment.findings,
            vec![PlanFinding::UncoveredCriterion {
                criterion: criteria[1].clone()
            }]
        );
        let stored = row(&world, &task, ASSESS_PLAN);
        assert_eq!(stored.execution, ObligationExecution::Failed);
        assert_eq!(
            stored.blocker,
            Some(plan_blocker(ErrorCode::DependencyBlocked, ASSESS_PLAN))
        );
        assert_eq!(plan_snapshot(&world, &task).lifecycle, Lifecycle::Blocked);
        // Re-running the assessment is a typed refusal, never a satisfied skip.
        let again = run(
            &mut world,
            &session,
            ActionInput::AssessPlan(partial.clone()),
        )
        .expect_err("the failed revision is already judged");
        assert!(matches!(
            store_cause(again),
            StoreError::Conflict(ConflictCause::PlanNotAssessable { revision: 1 })
        ));
        // Identical facts return the current revision unchanged and reopen
        // nothing: the failed row keeps its verdict blocker.
        let failed_row = row(&world, &task, ASSESS_PLAN);
        let same = select(&mut world, &session, &partial, &[]);
        assert_eq!(same.revision, recorded.revision);
        assert_selection_kept(&world, &task, &recorded);
        assert_eq!(row(&world, &task, ASSESS_PLAN), failed_row);
        assert_eq!(plan_snapshot(&world, &task).lifecycle, Lifecycle::Blocked);

        let fixed = plan_only(&world, &task);
        let reselected = select(&mut world, &session, &fixed, &[]);
        assert_eq!(reselected.revision, 2, "changed facts bump the selection");
        assert_eq!(
            row(&world, &task, ASSESS_PLAN).execution,
            ObligationExecution::Pending,
            "the failed row reopens under the new selection"
        );
        assert_eq!(
            plan_snapshot(&world, &task).lifecycle,
            Lifecycle::Running,
            "the plan-owned block released with nothing else holding it"
        );
        run(&mut world, &session, ActionInput::FrameGoal(fixed.clone())).expect("frame");
        let planned =
            run(&mut world, &session, ActionInput::PlanWork(fixed.clone())).expect("plan");
        assert!(matches!(
            planned,
            ActionOutcome::Planned { revision: 2, .. }
        ));
        let passed = run(&mut world, &session, ActionInput::AssessPlan(fixed)).expect("assess");
        assert_ne!(skipped(&passed), Some(SkipReason::AlreadySatisfied));
        assert!(
            matches!(
                passed,
                ActionOutcome::Assessed(Assessment {
                    plan_revision: 2,
                    verdict: PlanVerdict::Pass,
                    ..
                })
            ),
            "{passed:?}"
        );
    }

    #[test]
    fn reselect_with_changed_facts_reopens_satisfied_stages() {
        let (mut world, session, task) = plan_world("plan-reselect-changed", &PLAN_CRITERIA);
        let (request, first) = drive_plan_only_open(&mut world, &session, &task);
        let mut changed = request;
        changed.parts[1].proof = "cargo test --test endpoint --test contract".to_string();
        let second = select(&mut world, &session, &changed, &[]);
        assert_eq!(second.revision, first.revision + 1);
        for capability in [FRAME_GOAL, PLAN_WORK, ASSESS_PLAN, ASSESS_READINESS] {
            let stored = row(&world, &task, capability);
            assert_eq!(
                stored.execution,
                ObligationExecution::Pending,
                "{capability} reopens under changed facts"
            );
            assert_eq!(stored.outcome_json, None);
        }
        // The revision recorded under the earlier selection never opens the
        // new one, and the pause always names a reopened row.
        let PlanGate::Paused { open_stages, .. } = gate(&world, &task) else {
            panic!("the earlier selection's pass never opens the gate");
        };
        assert!(
            open_stages.contains(&PLAN_WORK.to_string()),
            "{open_stages:?}"
        );
        assert!(
            open_stages.contains(&ASSESS_PLAN.to_string()),
            "{open_stages:?}"
        );
        // Even with the semantic leg closed, the earlier revision's pass does
        // not count for this selection.
        run(
            &mut world,
            &session,
            ActionInput::FrameGoal(changed.clone()),
        )
        .expect("frame");
        semantic_close(&mut world, &task, &second, ASSESS_PLAN, ASSESS_PLAN);
        semantic_close(&mut world, &task, &second, ASSESS_READINESS, ASSESS_PLAN);
        assert_eq!(
            gate(&world, &task),
            PlanGate::Paused {
                unresolved: Vec::new(),
                open_stages: vec![PLAN_WORK.to_string(), ASSESS_PLAN.to_string()],
            }
        );
        run(&mut world, &session, ActionInput::PlanWork(changed)).expect("plan");
        assert_eq!(
            gate(&world, &task),
            PlanGate::Paused {
                unresolved: Vec::new(),
                open_stages: vec![ASSESS_PLAN.to_string()],
            },
            "a new revision under the new selection needs its own verdict"
        );
    }

    #[test]
    fn reselect_with_identical_facts_is_idempotent() {
        let (mut world, session, task) = plan_world("plan-reselect-identical", &PLAN_CRITERIA);
        let request = plan_only(&world, &task);
        let first = select(&mut world, &session, &request, &[]);
        run(
            &mut world,
            &session,
            ActionInput::FrameGoal(request.clone()),
        )
        .expect("frame");
        run(&mut world, &session, ActionInput::PlanWork(request.clone())).expect("plan");
        let rows_before = rows(&world, &task);
        let revisions_before = world
            .runtime
            .store()
            .plan_revisions(&task)
            .expect("revisions");
        let task_revision = plan_snapshot(&world, &task).revision;
        let again = select(&mut world, &session, &request, &[]);
        assert_eq!(
            again, first,
            "identical facts return the recorded selection"
        );
        assert_selection_kept(&world, &task, &first);
        assert_eq!(rows(&world, &task), rows_before, "no row was rewritten");
        assert_eq!(
            world
                .runtime
                .store()
                .plan_revisions(&task)
                .expect("revisions"),
            revisions_before
        );
        assert_eq!(plan_snapshot(&world, &task).revision, task_revision);
        assert_eq!(
            row(&world, &task, FRAME_GOAL).execution,
            ObligationExecution::Satisfied,
            "the frame_goal close stays closed"
        );

        // An undecided scan: its scan-derived `unresolved` rows stay as they
        // are, so the selection keeps its revision and a close bound to it
        // still lands. The handler binding is shown on `inspect_system` —
        // never a stale refusal — and the landing close is `frame_goal`'s.
        // That row has carried a handler since this slice's mandated
        // `inspect_system` promotion (D-095/FP-032-B) gave it a local
        // implementation, so the write below lands and the binding rule is
        // demonstrated with a close naming a handler the row does NOT own.
        let undecided_task = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-reselect-undecided",
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        let scan = undecided(&world, &undecided_task);
        let bound = select(&mut world, &session, &scan, &[]);
        let rows_before = rows(&world, &undecided_task);
        let again = select(&mut world, &session, &scan, &[]);
        assert_eq!(
            again.revision, bound.revision,
            "the same selection revision"
        );
        assert_eq!(again.facts_digest, bound.facts_digest);
        assert_selection_kept(&world, &undecided_task, &bound);
        assert_eq!(rows(&world, &undecided_task), rows_before);
        world
            .runtime
            .store_writer()
            .update_plan_row(
                &undecided_task,
                &PlanRowUpdate {
                    capability: INSPECT_SYSTEM,
                    handler: INSPECT_SYSTEM,
                    selection_revision: bound.revision,
                    facts_digest: &bound.facts_digest,
                    change: PlanRowChange::Close {
                        execution: ObligationExecution::Satisfied,
                        outcome_json: "{}".to_string(),
                    },
                },
            )
            .expect("the row names its own handler, so the close lands");
        assert_eq!(
            row(&world, &undecided_task, INSPECT_SYSTEM).execution,
            ObligationExecution::Satisfied,
            "the landed close is the row's own state, not a silent no-op"
        );
        // The binding rule the old refusal demonstrated still holds: only
        // the stored handler writes its row. A close naming a different
        // handler is refused with the same typed conflict, bound to the
        // current selection rather than a stale one.
        let foreign = world
            .runtime
            .store_writer()
            .update_plan_row(
                &undecided_task,
                &PlanRowUpdate {
                    capability: INSPECT_SYSTEM,
                    handler: FRAME_GOAL,
                    selection_revision: bound.revision,
                    facts_digest: &bound.facts_digest,
                    change: PlanRowChange::Close {
                        execution: ObligationExecution::Satisfied,
                        outcome_json: "{}".to_string(),
                    },
                },
            )
            .expect_err("only the stored handler writes its own row");
        assert!(
            matches!(
                foreign,
                StoreError::Conflict(ConflictCause::PlanRowHandler { .. })
            ),
            "bound to the current selection, never stale: {foreign}"
        );
        assert_eq!(
            row(&world, &undecided_task, INSPECT_SYSTEM).execution,
            ObligationExecution::Satisfied,
            "the refused write changed nothing: the row keeps the first close"
        );
        run(&mut world, &session, ActionInput::FrameGoal(scan)).expect("frame");
        assert_eq!(
            row(&world, &undecided_task, FRAME_GOAL).execution,
            ObligationExecution::Satisfied,
            "a close bound to the kept revision lands"
        );

        // A pending PG-15 fork stays pending.
        let fork_task = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-reselect-fork",
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        let asked = world.publish(&session, &fork_task);
        let fork_request = plan_only(&world, &fork_task);
        let fork_selection = select(&mut world, &session, &fork_request, &[]);
        let fork = Blocker {
            reason: ErrorCode::DependencyBlocked,
            owner: "plan".to_string(),
            condition: ResumeCondition::Decision {
                question_id: asked.question_id.clone(),
                revision: asked.question_revision,
            },
        };
        fork_on_plan_work(&mut world, &fork_task, &fork_selection, &fork);
        let again = select(&mut world, &session, &fork_request, &[]);
        assert_eq!(again.revision, fork_selection.revision);
        assert_selection_kept(&world, &fork_task, &fork_selection);
        assert_eq!(
            row(&world, &fork_task, PLAN_WORK).blocker,
            Some(fork.clone())
        );
        assert_eq!(
            plan_snapshot(&world, &fork_task).lifecycle,
            Lifecycle::Waiting,
            "the fork still waits"
        );
        let wire = wire_snapshot(&mut world, &session, &fork_task);
        let decisions = decision_blockers(&wire);
        assert_eq!(decisions.len(), 1, "{wire}");
        assert_eq!(
            decisions[0]["condition"],
            serde_json::to_value(&fork.condition).expect("condition json"),
            "the pending question is the fork's"
        );

        // A passing plan revision still opens the gate.
        let passed_task = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-reselect-passed",
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        let (passed_request, passed_selection) =
            drive_plan_only_open(&mut world, &session, &passed_task);
        let revisions_before = world
            .runtime
            .store()
            .plan_revisions(&passed_task)
            .expect("revisions");
        let again = select(&mut world, &session, &passed_request, &[]);
        assert_eq!(again.revision, passed_selection.revision);
        assert_selection_kept(&world, &passed_task, &passed_selection);
        assert_eq!(
            gate(&world, &passed_task),
            PlanGate::Open,
            "the passing revision still gates"
        );
        assert_eq!(
            world
                .runtime
                .store()
                .plan_revisions(&passed_task)
                .expect("revisions"),
            revisions_before
        );
    }

    #[test]
    fn handler_facts_must_match_the_current_selection() {
        let (mut world, session, task) = plan_world("plan-stale-facts", &PLAN_CRITERIA);
        let request = plan_only(&world, &task);
        // No selection yet: nothing to bind to.
        let missing = run(
            &mut world,
            &session,
            ActionInput::FrameGoal(request.clone()),
        )
        .expect_err("no selection");
        assert!(matches!(
            store_cause(missing),
            StoreError::Conflict(ConflictCause::PlanSelectionMissing)
        ));
        let selection = select(&mut world, &session, &request, &[]);
        let mut stale = request.clone();
        stale.surfaces = SurfaceScan::Known(BTreeSet::from([Surface::Auth]));
        for input in [
            ActionInput::FrameGoal(stale.clone()),
            ActionInput::PlanWork(stale.clone()),
            ActionInput::AssessPlan(stale),
        ] {
            let refused = run(&mut world, &session, input).expect_err("stale facts");
            assert!(matches!(
                store_cause(refused),
                StoreError::Conflict(ConflictCause::PlanSelectionStale { revision: 1 })
            ));
        }
        assert!(
            rows(&world, &task)
                .iter()
                .all(|row| row.execution == ObligationExecution::Pending
                    && row.outcome_json.is_none()),
            "stale facts closed nothing"
        );
        assert!(
            world
                .runtime
                .store()
                .plan_revisions(&task)
                .expect("revisions")
                .is_empty()
        );
        // The store re-checks the binding itself: a stale digest or revision
        // through the one write API writes nothing either.
        for (revision, digest) in [
            (selection.revision, "0000"),
            (selection.revision + 1, selection.facts_digest.as_str()),
        ] {
            let refused = world
                .runtime
                .store_writer()
                .update_plan_row(
                    &task,
                    &PlanRowUpdate {
                        capability: FRAME_GOAL,
                        handler: FRAME_GOAL,
                        selection_revision: revision,
                        facts_digest: digest,
                        change: PlanRowChange::Close {
                            execution: ObligationExecution::Satisfied,
                            outcome_json: "{}".to_string(),
                        },
                    },
                )
                .expect_err("stale binding");
            assert!(
                matches!(
                    refused,
                    StoreError::Conflict(ConflictCause::PlanSelectionStale { revision: 1 })
                ),
                "{refused}"
            );
            assert_eq!(
                row(&world, &task, FRAME_GOAL).execution,
                ObligationExecution::Pending
            );
        }
    }

    /// A pending fork's `Decision` blocker on `plan_work`, written through
    /// the one plan-row write.
    fn fork_on_plan_work(
        world: &mut support::World,
        task: &TaskId,
        selection: &Selection,
        decision: &Blocker,
    ) {
        world
            .runtime
            .store_writer()
            .update_plan_row(
                task,
                &PlanRowUpdate {
                    capability: PLAN_WORK,
                    handler: PLAN_WORK,
                    selection_revision: selection.revision,
                    facts_digest: &selection.facts_digest,
                    change: PlanRowChange::Block(decision.clone()),
                },
            )
            .expect("the owning handler writes the fork");
    }

    fn decision_blockers(wire: &serde_json::Value) -> Vec<serde_json::Value> {
        wire["blockers"]
            .as_array()
            .map(|blockers| {
                blockers
                    .iter()
                    .filter(|blocker| blocker["condition"]["kind"] == "decision")
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn plan_row_blocker_round_trips_a_decision_condition() {
        let (mut world, session, task) = plan_world("plan-decision-blocker", &PLAN_CRITERIA);
        let question = world.publish(&session, &task);
        let request = material(&world, &task);
        let selection = select(&mut world, &session, &request, &[]);
        assert_eq!(
            plan_snapshot(&world, &task).lifecycle,
            Lifecycle::Waiting,
            "a waiting task never flips on a plan write"
        );
        let decision = Blocker {
            reason: ErrorCode::DependencyBlocked,
            owner: "plan".to_string(),
            condition: ResumeCondition::Decision {
                question_id: question.question_id.clone(),
                revision: question.question_revision,
            },
        };
        let write = |world: &mut support::World, handler: &str, revision: u64, digest: &str| {
            world.runtime.store_writer().update_plan_row(
                &task,
                &PlanRowUpdate {
                    capability: DESIGN_CONTRACTS,
                    handler,
                    selection_revision: revision,
                    facts_digest: digest,
                    change: PlanRowChange::Block(decision.clone()),
                },
            )
        };
        let before = row(&world, &task, DESIGN_CONTRACTS);
        // A foreign handler, a stale revision and a stale digest write
        // nothing.
        let foreign = write(
            &mut world,
            CHALLENGE_DIRECTION,
            selection.revision,
            &selection.facts_digest,
        )
        .expect_err("another row's handler");
        assert!(matches!(
            foreign,
            StoreError::Conflict(ConflictCause::PlanRowHandler { .. })
        ));
        write(
            &mut world,
            DESIGN_CONTRACTS,
            selection.revision + 1,
            &selection.facts_digest,
        )
        .expect_err("stale revision");
        write(&mut world, DESIGN_CONTRACTS, selection.revision, "feed").expect_err("stale digest");
        assert_eq!(row(&world, &task, DESIGN_CONTRACTS), before);

        write(
            &mut world,
            DESIGN_CONTRACTS,
            selection.revision,
            &selection.facts_digest,
        )
        .expect("the owning handler writes the fork");
        assert_eq!(
            row(&world, &task, DESIGN_CONTRACTS).blocker,
            Some(decision.clone()),
            "the stored Blocker reads back identical"
        );
        // One wait, one blocker: the waiting task shows the state-owned
        // Decision of its pending question, never a plan-owned duplicate.
        let wire = wire_snapshot(&mut world, &session, &task);
        let decisions = decision_blockers(&wire);
        assert_eq!(
            decisions.len(),
            1,
            "one wait per fork, never a duplicate: {wire}"
        );
        assert_eq!(decisions[0]["owner"], "state", "{wire}");
        assert_eq!(
            decisions[0]["condition"],
            serde_json::to_value(&decision.condition).expect("condition json")
        );

        // A pending fork on a task a foreign block moved to `blocked`: the
        // state-owned wait is gone with `waiting`, so the plan-owned
        // Decision projects verbatim — still exactly once.
        let foreign_task = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-decision-foreign",
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        let pending = world.publish(&session, &foreign_task);
        let request = plan_only(&world, &foreign_task);
        let fork_selection = select(&mut world, &session, &request, &[]);
        let pending_fork = Blocker {
            condition: ResumeCondition::Decision {
                question_id: pending.question_id.clone(),
                revision: pending.question_revision,
            },
            ..decision.clone()
        };
        fork_on_plan_work(&mut world, &foreign_task, &fork_selection, &pending_fork);
        world
            .runtime
            .store_writer()
            .mark_no_ready(&foreign_task)
            .expect("a foreign block");
        assert_eq!(
            plan_snapshot(&world, &foreign_task).lifecycle,
            Lifecycle::Blocked
        );
        let wire = wire_snapshot(&mut world, &session, &foreign_task);
        let decisions = decision_blockers(&wire);
        assert_eq!(decisions.len(), 1, "{wire}");
        assert_eq!(
            decisions[0],
            serde_json::to_value(&pending_fork).expect("blocker json"),
            "the plan-owned fork projects verbatim"
        );
        let status = wire_status(&mut world, &session);
        assert_eq!(
            todo_item(&status, &foreign_task)["blockers"],
            wire["blockers"],
            "status todo lists the blockers task.get lists"
        );

        // An answered fork projects nothing and never holds: the answer
        // moves the task `waiting -> running` with the row still open, and
        // a later foreign block lists no Decision.
        let answered_task = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-decision-answered",
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        let asked = world.publish(&session, &answered_task);
        let request = plan_only(&world, &answered_task);
        let answered_selection = select(&mut world, &session, &request, &[]);
        let answered_fork = Blocker {
            condition: ResumeCondition::Decision {
                question_id: asked.question_id.clone(),
                revision: asked.question_revision,
            },
            ..decision.clone()
        };
        fork_on_plan_work(
            &mut world,
            &answered_task,
            &answered_selection,
            &answered_fork,
        );
        world
            .runtime
            .store_writer()
            .answer_question(
                &session,
                &answered_task,
                &asked.question_id,
                asked.question_revision,
                &AnswerSelection::Option {
                    option_id: asked.recommended_option_id.clone(),
                },
                "human",
            )
            .expect("answer");
        assert_eq!(
            plan_snapshot(&world, &answered_task).lifecycle,
            Lifecycle::Running,
            "an answered fork's blocker never holds the task"
        );
        let open = row(&world, &answered_task, PLAN_WORK);
        assert_eq!(
            open.execution,
            ObligationExecution::Pending,
            "the row stays open"
        );
        assert_eq!(
            open.blocker,
            Some(answered_fork),
            "the plan-owned copy stays verbatim on the plan rows"
        );
        world
            .runtime
            .store_writer()
            .mark_no_ready(&answered_task)
            .expect("a later foreign block");
        let wire = wire_snapshot(&mut world, &session, &answered_task);
        assert!(
            decision_blockers(&wire).is_empty(),
            "a stale fork never reads as a wait: {wire}"
        );
        let status = wire_status(&mut world, &session);
        assert_eq!(
            todo_item(&status, &answered_task)["blockers"],
            wire["blockers"],
            "status todo lists the blockers task.get lists"
        );

        // An unknown stored condition kind is corrupt storage, typed.
        plan_db(&world)
        .execute(
            "UPDATE plan_obligations SET blocker = ?2 WHERE task_id = ?1 AND capability = 'design_contracts'",
            rusqlite::params![
                task.0,
                r#"{"reason":"dependency_blocked","owner":"plan","condition":{"kind":"telepathy"}}"#
            ],
        )
        .expect("corrupt the row");
        assert!(matches!(
            world.runtime.store().plan_obligations(&task),
            Err(StoreError::Storage(_))
        ));
        let response = world.dispatch(&json!({
            "jsonrpc": "2.0", "id": 91, "method": "task.snapshot",
            "params": { "schema_version": 1, "session_id": session.0, "task_id": task.0 }
        }));
        assert_eq!(
            response["error"]["data"]["code"], "storage_unavailable",
            "{response}"
        );
    }

    #[test]
    fn unresolved_plan_obligation_blocks_with_exact_blocker_and_unblocks_on_resolution() {
        let (mut world, session, task) = plan_world("plan-unresolved-block", &PLAN_CRITERIA);
        let request = undecided(&world, &task);
        select(&mut world, &session, &request, &[]);
        let snapshot = plan_snapshot(&world, &task);
        assert_eq!(snapshot.lifecycle, Lifecycle::Blocked);
        let expected: Vec<Blocker> = rows(&world, &task)
            .into_iter()
            .filter_map(|row| row.blocker)
            .collect();
        assert!(!expected.is_empty());
        assert_eq!(
            snapshot.blockers.unwrap_or_default(),
            expected,
            "one exact plan blocker per waiting row, nothing else"
        );
        for blocker in &expected {
            assert_eq!(blocker.owner, "plan");
            assert!(matches!(
                blocker.condition,
                ResumeCondition::Dependency { .. }
            ));
        }
        assert!(expected.contains(&plan_blocker(ErrorCode::DependencyBlocked, PLAN_WORK)));
        // The census above is exhaustive on its own — `expected` is built
        // from the rows' own blockers and compared to the snapshot's — so
        // this spot-check is per-row, not the census. `inspect_system` left
        // the set when this slice's mandated promotion (D-095/FP-032-B)
        // gave it a local handler: its row is still selected and still
        // visible, it simply waits on nothing. Asserted in the positive
        // direction so the check stays where one stood, and so the
        // registered-but-unblocked row is proved present rather than
        // silently absent.
        let inspect = row(&world, &task, INSPECT_SYSTEM);
        assert_eq!(inspect.handler.as_deref(), Some(INSPECT_SYSTEM));
        assert_eq!(inspect.blocker, None, "{inspect:?}");
        assert!(
            !expected.contains(&plan_blocker(
                ErrorCode::CapabilityUnavailable,
                INSPECT_SYSTEM
            )),
            "a routed row is not on the blocker census: {expected:?}"
        );
        // Exhaustive by name, and derived independently of the blocker
        // column: each census entry names its row through the `Dependency`
        // condition, so the two sets must agree on membership.
        let plan_rows = rows(&world, &task);
        let blocked_rows: Vec<&str> = plan_rows
            .iter()
            .filter(|row| row.blocker.is_some())
            .map(|row| row.capability.as_str())
            .collect();
        let census: Vec<&str> = expected
            .iter()
            .map(|blocker| match &blocker.condition {
                ResumeCondition::Dependency { action_id } => action_id.0.as_str(),
                other => panic!("every plan blocker names its row: {other:?}"),
            })
            .collect();
        assert_eq!(
            census, blocked_rows,
            "the census names exactly the rows that still carry a blocker"
        );

        // The scan decides: the rows are rewritten, nothing holds the task,
        // and the plan-owned block releases.
        let decided = plan_only(&world, &task);
        select(&mut world, &session, &decided, &[]);
        let resolved = plan_snapshot(&world, &task);
        assert_eq!(resolved.lifecycle, Lifecycle::Running);
        assert_eq!(resolved.blockers, None);
    }

    type Raise = fn(&mut support::World, &TaskId);

    /// An unknown attempt in the ledger alone, with no block write: only
    /// the release rule's own source check can keep the task blocked.
    fn raise_unknown_attempt(world: &mut support::World, task: &TaskId) {
        let mut store = world.runtime.store_writer();
        let attempt = store
            .plan_attempt(task, EffectClass::Read, "lost receipt")
            .expect("attempt");
        store
            .attempt_unknown(&attempt, "receipt lost")
            .expect("unknown");
    }

    fn raise_outcome_unknown_block(world: &mut support::World, task: &TaskId) {
        world
            .runtime
            .store_writer()
            .mark_outcome_unknown(task)
            .expect("reconciliation block");
    }

    fn raise_unresolved_criterion(world: &mut support::World, task: &TaskId) {
        let mut store = world.runtime.store_writer();
        store
            .materialize_obligations(task)
            .expect("criteria obligations");
        let criterion = store
            .store()
            .snapshot(task)
            .expect("snapshot")
            .obligations
            .items
            .into_iter()
            .find(|obligation| !obligation.id.starts_with("plan:"))
            .expect("a criterion obligation");
        store
            .mark_applicability_unresolved(&criterion.id)
            .expect("unresolved criterion");
    }

    fn raise_stale_evidence(world: &mut support::World, task: &TaskId) {
        let mut store = world.runtime.store_writer();
        store
            .materialize_obligations(task)
            .expect("criteria obligations");
        store
            .insert_evidence_for_task(task, "task", "criteria proven", "digest")
            .expect("evidence");
        let evidence = store.store().evidence_for_task(task).expect("evidence")[0]
            .evidence_id
            .clone();
        store.invalidate_evidence(&evidence.0).expect("stale");
    }

    fn raise_no_ready(world: &mut support::World, task: &TaskId) {
        world
            .runtime
            .store_writer()
            .mark_no_ready(task)
            .expect("no ready action");
    }

    #[test]
    fn plan_resolution_never_unblocks_a_task_held_by_another_blocker() {
        let (mut world, session, _) = plan_world("plan-foreign-hold", &PLAN_CRITERIA);
        let mut next = 0;
        let mut fresh = |world: &mut support::World| {
            next += 1;
            submit_plan_task(
                world,
                &session,
                &format!("cmd-plan-foreign-{next}"),
                "Rotate session tokens.",
                &PLAN_CRITERIA,
            )
        };
        let block_by_plan = |world: &mut support::World, task: &TaskId| {
            let request = undecided(world, task);
            select(world, &session, &request, &[]);
            assert_eq!(plan_snapshot(world, task).lifecycle, Lifecycle::Blocked);
        };
        let resolve = |world: &mut support::World, task: &TaskId| {
            let request = plan_only(world, task);
            select(world, &session, &request, &[]);
        };
        // Each foreign source raised after and before the plan block; each
        // block writer (`writes_block`) is its own entry, so a writer that
        // left the plan-owned mark behind fails on its own.
        let sources: [(&str, Raise, bool); 5] = [
            ("unknown attempt", raise_unknown_attempt, false),
            ("outcome-unknown block", raise_outcome_unknown_block, true),
            ("unresolved criterion", raise_unresolved_criterion, true),
            ("stale evidence", raise_stale_evidence, true),
            ("no ready action", raise_no_ready, true),
        ];
        for (label, raise, writes_block) in sources {
            let after = fresh(&mut world);
            block_by_plan(&mut world, &after);
            assert!(plan_owned_mark(&world, &after), "the plan made this block");
            raise(&mut world, &after);
            assert_eq!(
                plan_owned_mark(&world, &after),
                !writes_block,
                "{label}: a foreign block takes the plan-owned mark in its own transaction"
            );
            resolve(&mut world, &after);
            assert_eq!(
                plan_snapshot(&world, &after).lifecycle,
                Lifecycle::Blocked,
                "{label} raised after the plan block survives plan resolution"
            );
            let before = fresh(&mut world);
            raise(&mut world, &before);
            block_by_plan(&mut world, &before);
            resolve(&mut world, &before);
            assert_eq!(
                plan_snapshot(&world, &before).lifecycle,
                Lifecycle::Blocked,
                "{label} raised before the plan block survives plan resolution"
            );
        }

        // A pending question keeps the task waiting through both writes.
        let waiting = fresh(&mut world);
        world.publish(&session, &waiting);
        let request = undecided(&world, &waiting);
        select(&mut world, &session, &request, &[]);
        assert_eq!(
            plan_snapshot(&world, &waiting).lifecycle,
            Lifecycle::Waiting
        );
        resolve(&mut world, &waiting);
        assert_eq!(
            plan_snapshot(&world, &waiting).lifecycle,
            Lifecycle::Waiting
        );

        // A cancelled task never flips, and plan writes refuse it.
        let cancelled = fresh(&mut world);
        block_by_plan(&mut world, &cancelled);
        world
            .runtime
            .store_writer()
            .cancel_task(&session, &cancelled, 1, None)
            .expect("cancel");
        let request = plan_only(&world, &cancelled);
        let config = decision_config(None);
        let refused = ActionRegistry::new()
            .select(
                &request,
                &[],
                &mut action_ctx(&mut world, &session, &config),
            )
            .expect_err("a terminal task takes no selection");
        assert_eq!(refused.error_code(), ErrorCode::AlreadyTerminal);
        assert_eq!(
            plan_snapshot(&world, &cancelled).lifecycle,
            Lifecycle::Cancelled
        );
    }

    #[test]
    fn answer_or_steer_ending_a_wait_never_erases_a_plan_block() {
        let (mut world, session, answered) = plan_world("plan-wait-ends", &PLAN_CRITERIA);
        let steered = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-wait-steer",
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        let mut questions = Vec::new();
        for task in [&answered, &steered] {
            questions.push(world.publish(&session, task));
            let request = undecided(&world, task);
            select(&mut world, &session, &request, &[]);
            assert_eq!(
                plan_snapshot(&world, task).lifecycle,
                Lifecycle::Waiting,
                "the plan never flips a waiting task"
            );
        }
        // The wait ends, the plan block stays: the task leaves `waiting`
        // for `blocked`, the returned revision is the one `task.get`
        // reports, and the block is the plan's own — a decided
        // re-selection releases it.
        let settle = |world: &mut support::World, task: &TaskId, task_revision: u64, path: &str| {
            let after = plan_snapshot(world, task);
            assert_eq!(
                after.lifecycle,
                Lifecycle::Blocked,
                "the {path} ends the wait, not the plan block"
            );
            assert!(
                !plan_blockers(&after).is_empty(),
                "{path}: {:?}",
                after.blockers
            );
            let wire = wire_snapshot(world, &session, task);
            assert_eq!(
                wire["revision"].as_u64(),
                Some(task_revision),
                "the {path} returns the revision task.get reports: {wire}"
            );
            let request = plan_only(world, task);
            select(world, &session, &request, &[]);
            assert_eq!(
                plan_snapshot(world, task).lifecycle,
                Lifecycle::Running,
                "{path}: the plan-owned block releases on resolution"
            );
        };
        let question = &questions[0];
        let result = world
            .runtime
            .store_writer()
            .answer_question(
                &session,
                &answered,
                &question.question_id,
                question.question_revision,
                &AnswerSelection::Option {
                    option_id: question.recommended_option_id.clone(),
                },
                "human",
            )
            .expect("answer");
        settle(&mut world, &answered, result.task_revision, "answer");

        let snapshot = plan_snapshot(&world, &steered);
        let result = world
            .runtime
            .store_writer()
            .steer_task(
                &session,
                &steered,
                snapshot.intent_revision,
                snapshot.revision,
                "Narrow it to the login path.",
            )
            .expect("steer");
        settle(&mut world, &steered, result.task_revision, "steer");
    }

    #[test]
    fn blocker_query_names_plan_obligations_not_no_ready_action() {
        let (mut world, session, task) = plan_world("plan-blocker-query", &PLAN_CRITERIA);
        let request = material(&world, &task);
        select(&mut world, &session, &request, &[]);
        let snapshot = plan_snapshot(&world, &task);
        assert_eq!(snapshot.lifecycle, Lifecycle::Blocked);
        let blockers = snapshot
            .blockers
            .expect("a blocked task names its blockers");
        assert!(
            blockers
                .iter()
                .all(|blocker| !matches!(blocker.condition, ResumeCondition::NoReadyAction {})),
            "{blockers:?}"
        );
        assert!(blockers.iter().all(|blocker| blocker.owner == "plan"));
        let status = wire_status(&mut world, &session);
        let item = todo_item(&status, &task);
        assert_eq!(
            item["blockers"],
            serde_json::to_value(&blockers).expect("blockers json"),
            "the batched projection names the same plan blockers"
        );
    }

    #[test]
    fn plan_pause_is_visible_on_the_wire_status_and_dock() {
        let (mut world, session, planned) = plan_world("plan-visible", &PLAN_CRITERIA);
        let plain = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-visible-plain",
            "Explain the token format.",
            &PLAN_CRITERIA,
        );
        let foreign = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-visible-foreign",
            "Explain the token format.",
            &PLAN_CRITERIA,
        );
        let reconciling = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-visible-reconciling",
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        world
            .runtime
            .store_writer()
            .mark_no_ready(&foreign)
            .expect("no ready action");
        let request = material(&world, &planned);
        let selection = select(&mut world, &session, &request, &[]);
        // A reconciliation block first, then plan rows on the same task:
        // its first blocker is foreign.
        raise_unknown_attempt(&mut world, &reconciling);
        raise_outcome_unknown_block(&mut world, &reconciling);
        let request = material(&world, &reconciling);
        select(&mut world, &session, &request, &[]);

        // task.get: every selected row is an obligation, every waiting row an
        // exact blocker.
        let wire = wire_snapshot(&mut world, &session, &planned);
        let obligation_ids: Vec<&str> = wire["obligations"]["items"]
            .as_array()
            .expect("obligations")
            .iter()
            .filter_map(|obligation| obligation["id"].as_str())
            .collect();
        for capability in selected(&selection) {
            assert!(
                obligation_ids.contains(&format!("plan:{capability}").as_str()),
                "plan:{capability} is on task.get: {obligation_ids:?}"
            );
        }
        assert_eq!(wire["lifecycle"], "blocked");
        let wire_blockers = wire["blockers"].clone();
        assert!(
            wire_blockers
                .as_array()
                .expect("blockers")
                .iter()
                .any(
                    |blocker| blocker["condition"]["action_id"] == CHALLENGE_DIRECTION
                        && blocker["reason"] == "capability_unavailable"
                ),
            "{wire_blockers}"
        );

        // Status todo over every task through the one batched projection.
        let status = wire_status(&mut world, &session);
        assert_eq!(todo_item(&status, &planned)["blockers"], wire_blockers);
        assert!(todo_item(&status, &plain).get("blockers").is_none());
        assert_eq!(
            todo_item(&status, &foreign)["blockers"][0]["condition"]["kind"],
            "no_ready_action"
        );
        let reconciling_item = todo_item(&status, &reconciling);
        assert_eq!(reconciling_item["blockers"][0]["reason"], "outcome_unknown");
        assert_eq!(
            reconciling_item["blockers"],
            wire_snapshot(&mut world, &session, &reconciling)["blockers"],
            "the batched projection equals task.get"
        );

        // The dock names the first plan blocker's capability beside the
        // first blocker's reason; every other line keeps its exact form.
        assert_eq!(
            dock_line(&status, &planned),
            format!(
                "task {}: blocked (capability_unavailable: {CHALLENGE_DIRECTION})",
                planned.0
            )
        );
        assert_eq!(
            dock_line(&status, &reconciling),
            format!(
                "task {}: blocked (outcome_unknown: {CHALLENGE_DIRECTION})",
                reconciling.0
            ),
            "a foreign first blocker keeps its reason, the plan capability appended"
        );
        assert_eq!(
            dock_line(&status, &plain),
            format!("task {}: running", plain.0)
        );
        assert_eq!(
            dock_line(&status, &foreign),
            format!("task {}: blocked (dependency_blocked)", foreign.0)
        );
    }

    #[test]
    fn plan_gate_hold_is_persisted_on_task_get_and_the_dock() {
        let (mut world, session, task) = plan_world("plan-gate-hold", &PLAN_CRITERIA);
        let hold_blocker =
            |kind: &str| plan_blocker(ErrorCode::DependencyBlocked, &format!("plan_gate:{kind}"));
        let hold = |world: &mut support::World, task: &TaskId, kind: PlanGateHold| {
            world.runtime.store_writer().hold_for_plan_gate(task, kind)
        };

        // No selection: the refused effect's hold is `Unassessed`.
        assert_eq!(
            hold(&mut world, &task, PlanGateHold::Unassessed).expect("hold"),
            Some(PlanGateHold::Unassessed)
        );
        let held = plan_snapshot(&world, &task);
        assert_eq!(held.lifecycle, Lifecycle::Blocked);
        assert_eq!(held.blockers, Some(vec![hold_blocker("unassessed")]));
        let wire = wire_snapshot(&mut world, &session, &task);
        assert_eq!(
            wire["blockers"],
            serde_json::to_value(vec![hold_blocker("unassessed")]).expect("json")
        );
        let status = wire_status(&mut world, &session);
        assert_eq!(todo_item(&status, &task)["blockers"], wire["blockers"]);
        assert_eq!(
            dock_line(&status, &task),
            format!(
                "task {}: blocked (dependency_blocked: plan_gate:unassessed)",
                task.0
            )
        );
        // Idempotent: the same hold again changes nothing.
        assert_eq!(
            hold(&mut world, &task, PlanGateHold::Unassessed).expect("hold"),
            Some(PlanGateHold::Unassessed)
        );
        assert_eq!(plan_snapshot(&world, &task), held);

        // A selection that leaves the gate closed turns the hold `Paused`.
        let request = plan_only(&world, &task);
        let selection = select(&mut world, &session, &request, &[]);
        assert_eq!(
            plan_snapshot(&world, &task).blockers,
            Some(vec![hold_blocker("paused")])
        );
        // Opening the gate clears the hold and releases the plan-owned block.
        run(
            &mut world,
            &session,
            ActionInput::FrameGoal(request.clone()),
        )
        .expect("frame");
        run(&mut world, &session, ActionInput::PlanWork(request.clone())).expect("plan");
        run(&mut world, &session, ActionInput::AssessPlan(request)).expect("assess");
        semantic_close(&mut world, &task, &selection, ASSESS_PLAN, ASSESS_PLAN);
        assert_eq!(plan_snapshot(&world, &task).lifecycle, Lifecycle::Blocked);
        semantic_close(&mut world, &task, &selection, ASSESS_READINESS, ASSESS_PLAN);
        assert_eq!(gate(&world, &task), PlanGate::Open);
        let released = plan_snapshot(&world, &task);
        assert_eq!(released.lifecycle, Lifecycle::Running);
        assert_eq!(released.blockers, None);
        // An open gate records no hold.
        assert_eq!(
            hold(&mut world, &task, PlanGateHold::Paused).expect("hold"),
            None
        );
        assert_eq!(plan_snapshot(&world, &task).lifecycle, Lifecycle::Running);

        // A terminal task is refused typed with nothing persisted.
        let terminal = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-hold-terminal",
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        world
            .runtime
            .store_writer()
            .cancel_task(&session, &terminal, 1, None)
            .expect("cancel");
        let refused = hold(&mut world, &terminal, PlanGateHold::Unassessed).expect_err("terminal");
        assert!(matches!(refused, StoreError::AlreadyTerminal), "{refused}");
        assert_eq!(refused.code(), ErrorCode::AlreadyTerminal);
        let count: i64 = plan_db(&world)
            .query_row(
                "SELECT COUNT(*) FROM plan_gate_holds WHERE task_id = ?1",
                rusqlite::params![terminal.0],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(count, 0, "nothing persisted for a terminal task");
    }

    #[test]
    fn unassessed_task_is_never_reported_open() {
        let (mut world, session, task) = plan_world("plan-unassessed", &PLAN_CRITERIA);
        assert_eq!(gate(&world, &task), PlanGate::Unassessed);
        assert_ne!(
            gate(&world, &task),
            PlanGate::Open,
            "no selection is not no risk"
        );
        // A handler run without a selection changes nothing.
        let request = plan_only(&world, &task);
        run(&mut world, &session, ActionInput::FrameGoal(request))
            .expect_err("no selection to bind to");
        assert_eq!(gate(&world, &task), PlanGate::Unassessed);
    }

    #[test]
    fn read_only_step_proceeds_on_a_paused_gate() {
        let (mut world, session, baseline) = plan_world("plan-read-step", &PLAN_CRITERIA);
        let unassessed = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-read-unassessed",
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        let paused = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-read-paused",
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        let grant = plan_grant(&mut world);
        // The refused effect's hold on `Unassessed`, and a `Paused` gate.
        world
            .runtime
            .store_writer()
            .hold_for_plan_gate(&unassessed, PlanGateHold::Unassessed)
            .expect("hold");
        let request = plan_only(&world, &paused);
        select(&mut world, &session, &request, &[]);
        assert_eq!(gate(&world, &unassessed), PlanGate::Unassessed);
        assert!(matches!(gate(&world, &paused), PlanGate::Paused { .. }));

        let answer = AnswerSelection::Custom {
            text: "steps".to_string(),
        };
        let mut observed = Vec::new();
        for task in [&baseline, &unassessed, &paused] {
            let calls = provider_calls(&world);
            let reads = world.worker_reads();
            let outcome = world
                .runtime
                .run_decision_step(&session, task, &answer, &grant, false);
            let evidence: Vec<String> = world
                .runtime
                .store()
                .evidence_for_task(task)
                .expect("evidence")
                .into_iter()
                .map(|evidence| evidence.observation)
                .collect();
            observed.push((
                provider_calls(&world) - calls,
                world.worker_reads() - reads,
                evidence,
            ));
            if task == &paused {
                // Only the existing completion guard holds completion: the
                // open plan rows count, the gate is never consulted.
                let error = outcome.expect_err("open plan rows keep completion closed");
                assert!(
                    matches!(
                        error,
                        rivect::controller::ControllerError::Store(StoreError::Conflict(
                            ConflictCause::CompletionOpen { unsatisfied: 4, .. }
                        ))
                    ),
                    "{error}"
                );
            } else {
                assert!(
                    matches!(
                        outcome,
                        Ok(rivect::controller::StepOutcome::Completed { .. })
                    ),
                    "{outcome:?}"
                );
            }
        }
        assert_eq!(
            observed[0].0, 1,
            "the baseline read spends one provider call"
        );
        assert_eq!(observed[0].1, 1, "the baseline reads once");
        assert_eq!(observed[0].2.len(), PLAN_CRITERIA.len());
        assert_eq!(
            observed[1], observed[0],
            "Unassessed: the read proceeds as the baseline"
        );
        assert_eq!(
            observed[2], observed[0],
            "Paused: the read proceeds as the baseline"
        );
    }

    #[test]
    fn applicability_unknown_sentinel_marks_plan_rows_unresolved() {
        let (mut world, session, task) = plan_world("plan-sentinel", &PLAN_CRITERIA);
        let grant = plan_grant(&mut world);
        let request = plan_only(&world, &task);
        select(&mut world, &session, &request, &[]);
        let before = rows(&world, &task);
        let error = world
            .runtime
            .run_decision_step(
                &session,
                &task,
                &AnswerSelection::Option {
                    option_id: OptionId(
                        rivect::controller::APPLICABILITY_UNKNOWN_OPTION.to_string(),
                    ),
                },
                &grant,
                false,
            )
            .expect_err("the sentinel fails the step");
        assert!(
            matches!(
                error,
                rivect::controller::ControllerError::ApplicabilityUnknown
            ),
            "plan ids never turn the sentinel into a store error: {error}"
        );
        let stored = rows(&world, &task);
        assert_marked_keeps_stored(&stored, &before);
        let PlanGate::Paused { unresolved, .. } = gate(&world, &task) else {
            panic!("an undecided evaluation never opens the gate");
        };
        assert_eq!(unresolved.len(), stored.len());
        let snapshot = plan_snapshot(&world, &task);
        assert_eq!(snapshot.lifecycle, Lifecycle::Blocked);
        assert_eq!(plan_blockers(&snapshot), marked_blockers(&stored));

        // A zero-criteria task has no criterion id to cascade from: the
        // task-scoped sentinel marks its plan rows itself.
        let bare = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-sentinel-bare",
            "Rotate session tokens.",
            &[],
        );
        world
            .runtime
            .store_writer()
            .mark_plan_applicability_unresolved(&bare)
            .expect("no selection writes nothing");
        assert!(rows(&world, &bare).is_empty());
        assert_eq!(gate(&world, &bare), PlanGate::Unassessed);
        assert_eq!(plan_snapshot(&world, &bare).lifecycle, Lifecycle::Running);
        let only = |proof: &str| {
            facts(
                &bare,
                RequestKind::PlanOnly,
                &[Surface::Local],
                ContractBasis::Absent,
                vec![part("only", &[], &[], proof)],
            )
        };
        select(&mut world, &session, &only("cargo test"), &[]);
        assert_eq!(plan_snapshot(&world, &bare).lifecycle, Lifecycle::Running);
        let before = rows(&world, &bare);
        world
            .runtime
            .store_writer()
            .mark_plan_applicability_unresolved(&bare)
            .expect("the task-scoped sentinel");
        let stored = rows(&world, &bare);
        assert_marked_keeps_stored(&stored, &before);
        let PlanGate::Paused { unresolved, .. } = gate(&world, &bare) else {
            panic!("an undecided evaluation never opens the gate");
        };
        assert_eq!(unresolved.len(), stored.len());
        let blocked = plan_snapshot(&world, &bare);
        assert_eq!(blocked.lifecycle, Lifecycle::Blocked);
        assert_eq!(plan_blockers(&blocked), marked_blockers(&stored));
        // The block is the plan's own: a decided re-selection releases it.
        select(&mut world, &session, &only("cargo test --lib"), &[]);
        assert_eq!(plan_snapshot(&world, &bare).lifecycle, Lifecycle::Running);

        // A terminal task is refused typed, nothing written.
        let terminal = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-sentinel-terminal",
            "Rotate session tokens.",
            &[],
        );
        let request = PlanRequest {
            task_id: terminal.clone(),
            ..only("cargo test")
        };
        select(&mut world, &session, &request, &[]);
        let before = rows(&world, &terminal);
        world
            .runtime
            .store_writer()
            .cancel_task(&session, &terminal, 1, None)
            .expect("cancel");
        let refused = world
            .runtime
            .store_writer()
            .mark_plan_applicability_unresolved(&terminal)
            .expect_err("a terminal task takes no sentinel");
        assert!(matches!(refused, StoreError::AlreadyTerminal), "{refused}");
        assert_eq!(refused.code(), ErrorCode::AlreadyTerminal);
        assert_eq!(rows(&world, &terminal), before, "nothing written");

        // A closed plan still holds: with every row closed the gate is
        // `Open` and its hold row is gone, so the mark alone blocks —
        // whatever the row stored, a satisfied close included.
        let closed = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-sentinel-closed",
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        world
            .runtime
            .store_writer()
            .hold_for_plan_gate(&closed, PlanGateHold::Unassessed)
            .expect("the refused effect's hold");
        drive_plan_only_open(&mut world, &session, &closed);
        let before = rows(&world, &closed);
        assert!(
            before
                .iter()
                .all(|row| row.execution == ObligationExecution::Satisfied),
            "every plan row is closed: {before:?}"
        );
        assert_eq!(gate(&world, &closed), PlanGate::Open);
        assert_eq!(plan_snapshot(&world, &closed).lifecycle, Lifecycle::Running);
        world
            .runtime
            .store_writer()
            .mark_plan_applicability_unresolved(&closed)
            .expect("the task-scoped sentinel");
        let stored = rows(&world, &closed);
        assert_marked_keeps_stored(&stored, &before);
        let PlanGate::Paused { unresolved, .. } = gate(&world, &closed) else {
            panic!("a marked plan never opens the gate");
        };
        assert_eq!(unresolved.len(), stored.len());
        assert_eq!(plan_snapshot(&world, &closed).lifecycle, Lifecycle::Blocked);
        assert!(plan_owned_mark(&world, &closed));
        let refused = world
            .runtime
            .store_writer()
            .complete_if_eligible(&session, &closed)
            .expect_err("a marked row keeps completion closed");
        assert!(
            matches!(
                refused,
                StoreError::Conflict(ConflictCause::CompletionOpen { unresolved, .. })
                    if unresolved == stored.len() as u64
            ),
            "{refused}"
        );

        // Recovered applicability never stays stuck: on a sufficient
        // contract whose plan-phase rows are all local, an identical
        // re-selection resets the sentinel rows in place.
        let recover = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-sentinel-recover",
            "Rotate session tokens.",
            &[],
        );
        let sufficient = facts(
            &recover,
            RequestKind::PlanOnly,
            &[Surface::Local],
            ContractBasis::Approved,
            vec![part("only", &[], &[], "cargo test")],
        );
        let recorded = select(&mut world, &session, &sufficient, &[]);
        let fresh = rows(&world, &recover);
        assert!(
            fresh
                .iter()
                .all(|row| row.handler.is_some() && row.blocker.is_none()),
            "every row is local: {fresh:?}"
        );
        world
            .runtime
            .store_writer()
            .mark_plan_applicability_unresolved(&recover)
            .expect("the task-scoped sentinel");
        assert_eq!(
            plan_snapshot(&world, &recover).lifecycle,
            Lifecycle::Blocked
        );
        // A handler holding the current revision never clears unknown
        // applicability: any change to an `unresolved` row is refused.
        let marked = rows(&world, &recover);
        for change in [
            PlanRowChange::Close {
                execution: ObligationExecution::Satisfied,
                outcome_json: "{}".to_string(),
            },
            PlanRowChange::Block(plan_blocker(ErrorCode::DependencyBlocked, PLAN_WORK)),
        ] {
            let refused = world
                .runtime
                .store_writer()
                .update_plan_row(
                    &recover,
                    &PlanRowUpdate {
                        capability: PLAN_WORK,
                        handler: PLAN_WORK,
                        selection_revision: recorded.revision,
                        facts_digest: &recorded.facts_digest,
                        change: change.clone(),
                    },
                )
                .expect_err("an unresolved row takes no handler write");
            assert!(
                matches!(
                    refused,
                    StoreError::Conflict(ConflictCause::PlanRowUnresolved { .. })
                ),
                "{change:?}: {refused}"
            );
            assert_eq!(refused.code(), ErrorCode::Conflict);
            assert_eq!(
                rows(&world, &recover),
                marked,
                "{change:?}: nothing written"
            );
        }
        let again = select(&mut world, &session, &sufficient, &[]);
        assert_eq!(
            again.revision, recorded.revision,
            "the same selection revision"
        );
        assert_eq!(again.facts_digest, recorded.facts_digest);
        assert_selection_kept(&world, &recover, &recorded);
        assert!(
            world
                .runtime
                .store()
                .plan_revisions(&recover)
                .expect("revisions")
                .is_empty(),
            "no plan revision"
        );
        assert_eq!(
            rows(&world, &recover),
            fresh,
            "reset in place to open, no blocker"
        );
        let released = plan_snapshot(&world, &recover);
        assert_eq!(released.lifecycle, Lifecycle::Running);
        assert_eq!(released.blockers, None);
        assert!(!plan_owned_mark(&world, &recover));
        for capability in [PLAN_WORK, ASSESS_PLAN] {
            let id = format!("plan:{capability}");
            assert!(
                released.obligations.items.iter().any(|obligation| {
                    obligation.id == id
                        && obligation.applicability == ObligationApplicability::Required
                        && obligation.execution == ObligationExecution::Pending
                }),
                "{capability} is visible and pending: {:?}",
                released.obligations
            );
        }
        assert_eq!(
            gate(&world, &recover),
            PlanGate::Paused {
                unresolved: Vec::new(),
                open_stages: vec![PLAN_WORK.to_string(), ASSESS_PLAN.to_string()],
            }
        );
        // A write bound to the revision recorded before the sentinel lands.
        semantic_close(
            &mut world,
            &recover,
            &recorded,
            ASSESS_READINESS,
            ASSESS_PLAN,
        );
        assert_eq!(
            row(&world, &recover, ASSESS_READINESS).execution,
            ObligationExecution::Satisfied
        );
        let planned = run(&mut world, &session, ActionInput::PlanWork(sufficient))
            .expect("a local close bound to the current revision");
        assert!(
            matches!(planned, ActionOutcome::Planned { .. }),
            "{planned:?}"
        );
        assert_eq!(
            row(&world, &recover, PLAN_WORK).execution,
            ObligationExecution::Satisfied
        );

        // The reset restores applicability only: an open purpose row keeps
        // its stored `capability_unavailable` and a closed row keeps none.
        let purpose = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-sentinel-purpose",
            "Rotate session tokens.",
            &[],
        );
        let risky = facts(
            &purpose,
            RequestKind::Change,
            &[Surface::Auth, Surface::PublicApi],
            ContractBasis::Absent,
            vec![part("only", &[], &[], "cargo test")],
        );
        let purpose_selection = select(&mut world, &session, &risky, &[]);
        semantic_close(
            &mut world,
            &purpose,
            &purpose_selection,
            CHALLENGE_DIRECTION,
            CHALLENGE_DIRECTION,
        );
        let closed = row(&world, &purpose, CHALLENGE_DIRECTION);
        let open = row(&world, &purpose, DESIGN_CONTRACTS);
        assert_eq!(
            open.blocker,
            Some(plan_blocker(
                ErrorCode::CapabilityUnavailable,
                DESIGN_CONTRACTS
            ))
        );
        world
            .runtime
            .store_writer()
            .mark_plan_applicability_unresolved(&purpose)
            .expect("the task-scoped sentinel");
        let again = select(&mut world, &session, &risky, &[]);
        assert_eq!(again.revision, purpose_selection.revision);
        assert_selection_kept(&world, &purpose, &purpose_selection);
        assert_eq!(row(&world, &purpose, CHALLENGE_DIRECTION), closed);
        assert_eq!(row(&world, &purpose, DESIGN_CONTRACTS), open);
        semantic_close(
            &mut world,
            &purpose,
            &purpose_selection,
            DESIGN_CONTRACTS,
            DESIGN_CONTRACTS,
        );

        // Cascade: while the criterion stays `unresolved`, an identical
        // re-selection writes nothing.
        let cascaded = plan_only(&world, &task);
        let cascade_rows = rows(&world, &task);
        let cascade_task = plan_snapshot(&world, &task);
        let current = world
            .runtime
            .store()
            .plan_selection(&task)
            .expect("selection")
            .expect("recorded");
        let again = select(&mut world, &session, &cascaded, &[]);
        assert_eq!(again.revision, current.revision);
        assert_selection_kept(&world, &task, &again);
        assert_eq!(rows(&world, &task), cascade_rows, "nothing written");
        assert!(
            rows(&world, &task)
                .iter()
                .all(|row| row.applicability == ObligationApplicability::Unresolved)
        );
        assert!(matches!(gate(&world, &task), PlanGate::Paused { .. }));
        assert_eq!(plan_snapshot(&world, &task), cascade_task);

        // Once the criterion resolves, the same re-selection resets the
        // rows in place under the same revision and the plan no longer
        // holds the task. No build path resolves a criterion's
        // applicability yet, so the fixture writes it directly.
        plan_db(&world)
            .execute(
                "UPDATE obligations SET applicability = 'required' WHERE task_id = ?1",
                rusqlite::params![task.0],
            )
            .expect("resolve the criterion");
        let again = select(&mut world, &session, &cascaded, &[]);
        assert_eq!(again.revision, current.revision);
        assert_selection_kept(&world, &task, &again);
        let reset = rows(&world, &task);
        assert!(
            reset
                .iter()
                .all(|row| row.applicability == ObligationApplicability::Required
                    && row.blocker.is_none()),
            "{reset:?}"
        );
        let resolved = plan_snapshot(&world, &task);
        assert!(
            plan_blockers(&resolved).is_empty(),
            "the plan holds the task no more"
        );
        // The criterion cascade blocked the task as a foreign block, which
        // plan resolution never erases (PG-9 S-a).
        assert_eq!(resolved.lifecycle, Lifecycle::Blocked);
        assert!(!plan_owned_mark(&world, &task));
        assert!(!matches!(
            gate(&world, &task),
            PlanGate::Paused { ref unresolved, .. } if !unresolved.is_empty()
        ));
        semantic_close(&mut world, &task, &again, FRAME_GOAL, FRAME_GOAL);

        // Handler-owned blockers survive the sentinel and the reset: a pass
        // verdict leaves `assess_plan` pending on `capability_unavailable`,
        // a fail verdict closes it `failed` on `dependency_blocked`.
        let passed = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-sentinel-pass",
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        let request = plan_only(&world, &passed);
        select(&mut world, &session, &request, &[]);
        assess_after_plan(&mut world, &session, &request, PlanVerdict::Pass);
        sentinel_keeps_verdict_blocker(
            &mut world,
            &session,
            &request,
            &plan_blocker(ErrorCode::CapabilityUnavailable, ASSESS_PLAN),
        );
        let failed = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-sentinel-fail",
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        let criteria = criterion_ids(&world, &failed);
        let partial = facts(
            &failed,
            RequestKind::PlanOnly,
            &[Surface::Local],
            ContractBasis::Absent,
            vec![part(
                "schema",
                &criteria[..1],
                &[],
                "cargo test --test schema",
            )],
        );
        select(&mut world, &session, &partial, &[]);
        assess_after_plan(&mut world, &session, &partial, PlanVerdict::Fail);
        assert_eq!(
            row(&world, &failed, ASSESS_PLAN).execution,
            ObligationExecution::Failed
        );
        sentinel_keeps_verdict_blocker(
            &mut world,
            &session,
            &partial,
            &plan_blocker(ErrorCode::DependencyBlocked, ASSESS_PLAN),
        );

        sentinel_keeps_a_pending_fork(&mut world, &session, true);
        sentinel_keeps_a_pending_fork(&mut world, &session, false);
    }

    /// Frames, plans and runs the mechanical leg, which must reach
    /// `verdict`.
    fn assess_after_plan(
        world: &mut support::World,
        session: &SessionId,
        request: &PlanRequest,
        verdict: PlanVerdict,
    ) {
        run(world, session, ActionInput::FrameGoal(request.clone())).expect("frame");
        run(world, session, ActionInput::PlanWork(request.clone())).expect("plan");
        let assessed =
            run(world, session, ActionInput::AssessPlan(request.clone())).expect("assess");
        assert!(
            matches!(&assessed, ActionOutcome::Assessed(assessment) if assessment.verdict == verdict),
            "{assessed:?}"
        );
    }

    /// The stored selection itself, not only the record a re-selection
    /// returns, keeps its revision and digest.
    fn assert_selection_kept(world: &support::World, task: &TaskId, recorded: &Selection) {
        let stored = world
            .runtime
            .store()
            .plan_selection(task)
            .expect("selection")
            .expect("recorded");
        assert_eq!(
            (stored.revision, stored.facts_digest.as_str()),
            (recorded.revision, recorded.facts_digest.as_str()),
            "the stored selection never moves"
        );
    }

    /// The sentinel changes applicability only: execution, outcome and the
    /// stored blocker stay as they were.
    fn assert_marked_keeps_stored(
        marked: &[PlanObligationRecord],
        before: &[PlanObligationRecord],
    ) {
        assert!(!marked.is_empty());
        assert_eq!(marked.len(), before.len());
        for (row, prior) in marked.iter().zip(before) {
            assert_eq!(
                row,
                &PlanObligationRecord {
                    applicability: ObligationApplicability::Unresolved,
                    ..prior.clone()
                },
                "the sentinel never writes the stored blocker"
            );
        }
    }

    /// While marked, every row projects exactly one `dependency_blocked`
    /// named by its capability, in place of its stored blocker.
    fn marked_blockers(marked: &[PlanObligationRecord]) -> Vec<Blocker> {
        marked
            .iter()
            .map(|row| plan_blocker(ErrorCode::DependencyBlocked, &row.capability))
            .collect()
    }

    /// The plan-owned blockers `task.get` lists equal the marked rows'
    /// `dependency_blocked`, and the batched status projection lists the
    /// same blockers as `task.get`.
    fn assert_marked_projection(world: &mut support::World, session: &SessionId, task: &TaskId) {
        let expected = serde_json::to_value(marked_blockers(&rows(world, task))).expect("json");
        let wire = wire_snapshot(world, session, task);
        let listed: Vec<serde_json::Value> = wire["blockers"]
            .as_array()
            .expect("blockers")
            .iter()
            .filter(|blocker| blocker["owner"] == "plan")
            .cloned()
            .collect();
        assert_eq!(serde_json::Value::Array(listed), expected, "{wire}");
        let status = wire_status(world, session);
        assert_eq!(
            todo_item(&status, task)["blockers"],
            wire["blockers"],
            "status todo lists the blockers task.get lists"
        );
    }

    /// Sentinel then identical re-select on a task a verdict holds: the
    /// stored blockers survive both, the task stays `blocked` and the gate
    /// `Paused`; while marked, each row projects only `dependency_blocked`.
    fn sentinel_keeps_verdict_blocker(
        world: &mut support::World,
        session: &SessionId,
        request: &PlanRequest,
        verdict_blocker: &Blocker,
    ) {
        let task = &request.task_id;
        let recorded = select(world, session, request, &[]);
        let before = rows(world, task);
        assert_eq!(
            row(world, task, ASSESS_PLAN).blocker,
            Some(verdict_blocker.clone())
        );
        assert_eq!(plan_snapshot(world, task).lifecycle, Lifecycle::Blocked);
        world
            .runtime
            .store_writer()
            .mark_plan_applicability_unresolved(task)
            .expect("the task-scoped sentinel");
        assert_marked_keeps_stored(&rows(world, task), &before);
        assert_eq!(plan_snapshot(world, task).lifecycle, Lifecycle::Blocked);
        assert!(matches!(gate(world, task), PlanGate::Paused { .. }));
        assert_marked_projection(world, session, task);

        let again = select(world, session, request, &[]);
        assert_eq!(again.revision, recorded.revision);
        assert_selection_kept(world, task, &recorded);
        assert_eq!(
            rows(world, task),
            before,
            "the reset restores applicability only"
        );
        let held = plan_snapshot(world, task);
        assert_eq!(
            held.lifecycle,
            Lifecycle::Blocked,
            "the verdict still holds"
        );
        assert!(
            plan_blockers(&held).contains(verdict_blocker),
            "{:?}",
            held.blockers
        );
        assert!(matches!(gate(world, task), PlanGate::Paused { .. }));
    }

    /// A pending PG-15 fork through the sentinel: the task stays `waiting`,
    /// `task.get` lists the state-owned `Decision` once plus the marked
    /// rows' `dependency_blocked`, the fork stays stored and the gate
    /// `Paused`. `answer_first`: sentinel, answer, re-select — the answer
    /// leaves `waiting` for a plan-owned `blocked` the re-select releases.
    /// Otherwise sentinel, re-select, answer — PG-9 releases the task.
    fn sentinel_keeps_a_pending_fork(
        world: &mut support::World,
        session: &SessionId,
        answer_first: bool,
    ) {
        let task = submit_plan_task(
            world,
            session,
            &format!("cmd-plan-sentinel-fork-{answer_first}"),
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        let asked = world.publish(session, &task);
        let request = plan_only(world, &task);
        let recorded = select(world, session, &request, &[]);
        let fork = Blocker {
            reason: ErrorCode::DependencyBlocked,
            owner: "plan".to_string(),
            condition: ResumeCondition::Decision {
                question_id: asked.question_id.clone(),
                revision: asked.question_revision,
            },
        };
        fork_on_plan_work(world, &task, &recorded, &fork);
        let mut before = rows(world, &task);
        world
            .runtime
            .store_writer()
            .mark_plan_applicability_unresolved(&task)
            .expect("the task-scoped sentinel");
        assert_eq!(
            plan_snapshot(world, &task).lifecycle,
            Lifecycle::Waiting,
            "the sentinel never flips a waiting task"
        );
        assert_marked_keeps_stored(&rows(world, &task), &before);
        assert_eq!(row(world, &task, PLAN_WORK).blocker, Some(fork.clone()));
        assert!(matches!(gate(world, &task), PlanGate::Paused { .. }));
        let wire = wire_snapshot(world, session, &task);
        let decisions = decision_blockers(&wire);
        assert_eq!(decisions.len(), 1, "one wait, one Decision: {wire}");
        assert_eq!(decisions[0]["owner"], "state", "{wire}");
        assert_marked_projection(world, session, &task);

        let answer = |world: &mut support::World| {
            world
                .runtime
                .store_writer()
                .answer_question(
                    session,
                    &task,
                    &asked.question_id,
                    asked.question_revision,
                    &AnswerSelection::Option {
                        option_id: asked.recommended_option_id.clone(),
                    },
                    "human",
                )
                .expect("answer")
        };
        if answer_first {
            let result = answer(world);
            let after = plan_snapshot(world, &task);
            assert_eq!(
                after.lifecycle,
                Lifecycle::Blocked,
                "the answer ends the wait, not the plan hold"
            );
            assert_eq!(result.task_revision, after.revision);
            assert!(plan_owned_mark(world, &task));
            let identity = serde_json::json!({
                "kind": "answered_fork",
                "question_id": asked.question_id.0,
                "question_revision": asked.question_revision,
                "selection_revision": recorded.revision,
                "facts_digest": recorded.facts_digest,
            })
            .to_string();
            let Some(plan_work) = before.iter_mut().find(|row| row.capability == PLAN_WORK) else {
                panic!("the stored fork belongs to plan_work");
            };
            plan_work.outcome_json = Some(identity);
        }
        let again = select(world, session, &request, &[]);
        assert_eq!(again.revision, recorded.revision);
        assert_selection_kept(world, &task, &recorded);
        assert_eq!(
            rows(world, &task),
            before,
            "the reset keeps the fork stored"
        );
        assert!(matches!(gate(world, &task), PlanGate::Paused { .. }));
        if !answer_first {
            assert_eq!(plan_snapshot(world, &task).lifecycle, Lifecycle::Waiting);
            let wire = wire_snapshot(world, session, &task);
            assert_eq!(decision_blockers(&wire).len(), 1, "{wire}");
            answer(world);
        }
        assert_eq!(
            plan_snapshot(world, &task).lifecycle,
            Lifecycle::Running,
            "nothing holds the task any more (PG-9)"
        );
        assert!(!plan_owned_mark(world, &task));
    }

    #[test]
    fn shortlist_never_drops_required_obligation() {
        let (mut world, session, task) = plan_world("plan-shortlist", &PLAN_CRITERIA);
        let request = material(&world, &task);
        let shortlist = [FRAME_GOAL, RESOLVE_DECISION, REVIEW_CHANGE, "bogus.action"];
        let with = select(&mut world, &session, &request, &shortlist);
        let without = select(&mut world, &session, &request, &[]);
        assert_eq!(
            with.obligations, without.obligations,
            "top-K moves no obligation"
        );
        for required in [ASSESS_SECURITY, AUDIT_TESTS, ASSESS_READINESS] {
            assert!(
                selected(&with).contains(&required),
                "{required} survives a shortlist that omits it"
            );
        }
        assert_eq!(
            with.declined,
            vec![
                Declined {
                    action: RESOLVE_DECISION.to_string(),
                    reason: SkipReason::NotNeeded,
                },
                Declined {
                    action: REVIEW_CHANGE.to_string(),
                    reason: SkipReason::NotNeeded,
                },
                Declined {
                    action: "bogus.action".to_string(),
                    reason: SkipReason::Unsupported,
                },
            ],
            "every shortlisted action the facts decline is traced with its reason"
        );
    }

    #[test]
    fn disabled_or_incompatible_handler_yields_visible_obligation_or_exact_blocker() {
        let (mut world, session, change_task) = plan_world("plan-routes", &PLAN_CRITERIA);
        let plan_task = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-routes-plan",
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        let unknown_task = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-routes-unknown",
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        let route = |selection: &Selection, capability: &str| {
            selection
                .obligations
                .iter()
                .find(|obligation| obligation.capability == capability)
                .map(|obligation| obligation.route)
                .unwrap_or_else(|| panic!("{capability} is selected"))
        };
        let request = material(&world, &change_task);
        let change = select(&mut world, &session, &request, &[]);
        // No handler in this build: a visible obligation with its exact
        // blocker, never dropped.
        assert_eq!(
            route(&change, ASSESS_SECURITY),
            Route::Blocked(RouteBlock::NotInBuild)
        );
        assert_eq!(
            route(&change, ASSESS_READINESS),
            Route::Blocked(RouteBlock::NotInBuild)
        );
        let security = row(&world, &change_task, ASSESS_SECURITY);
        assert_eq!(security.handler, None);
        assert_eq!(
            security.blocker,
            Some(plan_blocker(
                ErrorCode::CapabilityUnavailable,
                ASSESS_SECURITY
            ))
        );
        let snapshot = plan_snapshot(&world, &change_task);
        assert!(
            snapshot
                .obligations
                .items
                .iter()
                .any(|obligation| obligation.id == "plan:assess_security"),
            "the obligation stays visible"
        );
        assert!(plan_blockers(&snapshot).contains(&plan_blocker(
            ErrorCode::CapabilityUnavailable,
            ASSESS_SECURITY
        )));
        // A plan artifact's readiness has an allowed local equivalent.
        let request = plan_only(&world, &plan_task);
        let plan = select(&mut world, &session, &request, &[]);
        assert_eq!(
            route(&plan, ASSESS_READINESS),
            Route::Equivalent(ASSESS_PLAN)
        );
        let readiness = row(&world, &plan_task, ASSESS_READINESS);
        assert_eq!(readiness.handler.as_deref(), Some(ASSESS_PLAN));
        assert_eq!(readiness.blocker, None);
        // The registered-vs-missing contrast, after this slice's mandated
        // `inspect_system` promotion (D-095/FP-032-B) gave that row a local
        // handler: it is registered AND runnable, so it routes local and its
        // plan row carries that handler with no route blocker.
        //
        // The 'registered but this build cannot execute it' arm —
        // `Route::Blocked(RouteBlock::Unavailable)`, and with it
        // `Implementation::Unavailable` — is a live contract shape that now
        // has NO catalog subject: every row is Local, Purpose or
        // LocalAndPurpose. The missing half of the contrast is the
        // `ASSESS_SECURITY` to `NotInBuild` case asserted above. This
        // comment is why the `Unavailable` arm must not be read as dead code
        // and deleted when the next row is registered unbuilt.
        let request = undecided(&world, &unknown_task);
        let unknown = select(&mut world, &session, &request, &[]);
        assert_eq!(
            route(&unknown, INSPECT_SYSTEM),
            Route::Local(INSPECT_SYSTEM)
        );
        let inspect = row(&world, &unknown_task, INSPECT_SYSTEM);
        assert_eq!(inspect.handler.as_deref(), Some(INSPECT_SYSTEM));
        assert_eq!(
            inspect.blocker, None,
            "a routed row waits on nothing: {inspect:?}"
        );
        assert!(
            plan_snapshot(&world, &unknown_task)
                .obligations
                .items
                .iter()
                .any(|obligation| obligation.id == "plan:inspect_system"),
            "the obligation stays visible — routed is not dropped"
        );
    }

    #[test]
    fn catalog_never_dumped_into_todo() {
        let (mut world, session, task) = plan_world("plan-no-dump", &PLAN_CRITERIA);
        let criteria = criterion_ids(&world, &task);
        let request = facts(
            &task,
            RequestKind::Change,
            &[Surface::Local],
            ContractBasis::Approved,
            vec![part("banner", &criteria, &[], "cargo test")],
        );
        let selection = select(&mut world, &session, &request, &[]);
        let required = [AUDIT_TESTS, IMPLEMENT_CHANGE, ASSESS_READINESS];
        // Only what the facts require: no catalog row rides along unasked.
        assert_eq!(selected(&selection), required.to_vec());
        let registry = ActionRegistry::new();
        assert!(
            registry
                .definitions()
                .filter(|definition| !required.contains(&definition.id))
                .all(|definition| !selected(&selection).contains(&definition.id)),
            "no catalog row the facts do not require was pulled into a sufficient local change"
        );
        let plan_ids: Vec<String> = plan_snapshot(&world, &task)
            .obligations
            .items
            .into_iter()
            .filter(|obligation| obligation.id.starts_with("plan:"))
            .map(|obligation| obligation.id)
            .collect();
        assert_eq!(
            plan_ids,
            selected(&selection)
                .into_iter()
                .map(|capability| format!("plan:{capability}"))
                .collect::<Vec<_>>()
        );
        // Once the completion guard parks the task, its todo lists the
        // open required rows' blockers — each at most once, none for a
        // catalog row the facts did not select.
        park(&mut world, &session, &task);
        let status = wire_status(&mut world, &session);
        let named: Vec<&str> = todo_item(&status, &task)["blockers"]
            .as_array()
            .expect("a parked task lists its blockers")
            .iter()
            .filter_map(|blocker| blocker["condition"]["action_id"].as_str())
            .collect();
        assert!(
            named.iter().all(|capability| required.contains(capability)),
            "{named:?}"
        );
        assert_eq!(
            named.iter().collect::<BTreeSet<_>>().len(),
            named.len(),
            "one todo blocker per required row, no more: {named:?}"
        );
        for later in [AUDIT_TESTS, ASSESS_READINESS] {
            assert!(named.contains(&later), "{later} is listed: {named:?}");
        }
    }

    #[test]
    fn unknown_applicability_pauses_dependent_work_never_not_applicable() {
        let (mut world, session, task) = plan_world("plan-unknown-pauses", &PLAN_CRITERIA);
        let request = undecided(&world, &task);
        select(&mut world, &session, &request, &[]);
        let framed = run(
            &mut world,
            &session,
            ActionInput::FrameGoal(request.clone()),
        )
        .expect("frame");
        let ActionOutcome::Framed { unknowns, .. } = framed else {
            panic!("frame_goal runs on an undecided scan: {framed:?}");
        };
        assert_eq!(unknowns, vec![FrameUnknown::ImpactSurface]);
        for input in [
            ActionInput::ChallengeDirection(request.clone()),
            ActionInput::DesignContracts(request.clone()),
            ActionInput::PlanWork(request.clone()),
            ActionInput::AssessPlan(request.clone()),
        ] {
            let outcome = run(&mut world, &session, input).expect("a skip, not a refusal");
            assert_eq!(
                skipped(&outcome),
                Some(SkipReason::NeedsInformation),
                "{outcome:?}"
            );
        }
        for capability in [
            CHALLENGE_DIRECTION,
            DESIGN_CONTRACTS,
            PLAN_WORK,
            ASSESS_PLAN,
        ] {
            let stored = row(&world, &task, capability);
            assert_eq!(stored.applicability, ObligationApplicability::Unresolved);
            assert_eq!(stored.execution, ObligationExecution::Pending);
        }
        // An unresolved row never closes on a handler run either.
        let selection = world
            .runtime
            .store()
            .plan_selection(&task)
            .expect("selection")
            .expect("recorded");
        let refused = world
            .runtime
            .store_writer()
            .update_plan_row(
                &task,
                &PlanRowUpdate {
                    capability: PLAN_WORK,
                    handler: PLAN_WORK,
                    selection_revision: selection.revision,
                    facts_digest: &selection.facts_digest,
                    change: PlanRowChange::Close {
                        execution: ObligationExecution::Satisfied,
                        outcome_json: "{}".to_string(),
                    },
                },
            )
            .expect_err("an unresolved row waits for its applicability");
        assert!(matches!(
            refused,
            StoreError::Conflict(ConflictCause::PlanRowUnresolved { .. })
        ));
        assert!(matches!(gate(&world, &task), PlanGate::Paused { .. }));
    }

    #[test]
    fn assess_plan_flags_zero_unknown_or_uncovered_criteria_and_empty_proof() {
        // No criteria at all: coverage cannot be judged.
        let (mut world, session, bare) = plan_world("plan-assess-zero", &[]);
        let request = facts(
            &bare,
            RequestKind::PlanOnly,
            &[Surface::Local],
            ContractBasis::Absent,
            vec![part("only", &[], &[], "cargo test")],
        );
        select(&mut world, &session, &request, &[]);
        run(&mut world, &session, ActionInput::PlanWork(request.clone())).expect("plan");
        let zero = run(&mut world, &session, ActionInput::AssessPlan(request)).expect("assess");
        let ActionOutcome::Assessed(zero) = zero else {
            panic!("expected an assessment: {zero:?}");
        };
        assert_eq!(zero.verdict, PlanVerdict::Fail);
        assert_eq!(zero.findings, vec![PlanFinding::ZeroCriteria]);

        let task = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-assess-flags",
            "Rotate session tokens.",
            &PLAN_CRITERIA,
        );
        let criteria = criterion_ids(&world, &task);
        let unknown = CriterionId("crit-not-on-this-task".to_string());
        let request = facts(
            &task,
            RequestKind::PlanOnly,
            &[Surface::Local],
            ContractBasis::Absent,
            vec![
                part("schema", &criteria[..1], &[], "  "),
                part(
                    "extra",
                    std::slice::from_ref(&unknown),
                    &["schema"],
                    "cargo test --test extra",
                ),
            ],
        );
        select(&mut world, &session, &request, &[]);
        run(&mut world, &session, ActionInput::PlanWork(request.clone())).expect("plan");
        let flagged = run(&mut world, &session, ActionInput::AssessPlan(request)).expect("assess");
        let ActionOutcome::Assessed(flagged) = flagged else {
            panic!("expected an assessment: {flagged:?}");
        };
        assert_eq!(flagged.verdict, PlanVerdict::Fail);
        assert_eq!(
            flagged.findings,
            vec![
                PlanFinding::UncoveredCriterion {
                    criterion: criteria[1].clone()
                },
                PlanFinding::MissingProof {
                    part: "schema".to_string()
                },
                PlanFinding::UnknownCriterion {
                    part: "extra".to_string(),
                    criterion: unknown,
                },
            ]
        );
    }

    #[test]
    fn plan_work_records_and_closes_in_one_transaction() {
        let (mut world, session, task) = plan_world("plan-atomic", &PLAN_CRITERIA);
        let request = plan_only(&world, &task);
        select(&mut world, &session, &request, &[]);
        // Inject a failure into the close step, after the revision insert.
        let db = plan_db(&world);
        db.execute_batch(
            "CREATE TRIGGER plan_work_close_fails BEFORE UPDATE ON plan_obligations
         WHEN NEW.capability = 'plan_work' AND NEW.execution = 'satisfied'
         BEGIN SELECT RAISE(ABORT, 'injected close failure'); END;",
        )
        .expect("install the fault");
        let refused = run(&mut world, &session, ActionInput::PlanWork(request.clone()))
            .expect_err("the injected close fails the write");
        assert!(matches!(store_cause(refused), StoreError::Storage(_)));
        assert!(
            world
                .runtime
                .store()
                .plan_revisions(&task)
                .expect("revisions")
                .is_empty(),
            "a failed close leaves no new revision"
        );
        assert_eq!(
            row(&world, &task, PLAN_WORK).execution,
            ObligationExecution::Pending
        );
        db.execute_batch("DROP TRIGGER plan_work_close_fails;")
            .expect("remove the fault");
        let planned = run(&mut world, &session, ActionInput::PlanWork(request)).expect("plan");
        assert!(matches!(
            planned,
            ActionOutcome::Planned { revision: 1, .. }
        ));
        assert_eq!(
            row(&world, &task, PLAN_WORK).execution,
            ObligationExecution::Satisfied
        );
    }

    #[test]
    fn plan_work_orders_parts_and_rejects_invalid_parts() {
        let (mut world, session, task) = plan_world("plan-order", &PLAN_CRITERIA);
        let criteria = criterion_ids(&world, &task);
        let plan_for = |parts: Vec<WorkPart>| {
            facts(
                &task,
                RequestKind::PlanOnly,
                &[Surface::Local],
                ContractBasis::Absent,
                parts,
            )
        };
        let order_of = |world: &mut support::World, request: PlanRequest| {
            select(world, &session, &request, &[]);
            match run(world, &session, ActionInput::PlanWork(request)).expect("plan") {
                ActionOutcome::Planned { plan, .. } => plan.order,
                other => panic!("expected a plan: {other:?}"),
            }
        };
        // A chain listed in reverse comes back in dependency order.
        let chain = plan_for(vec![
            part("c", &criteria, &["b"], "cargo test --test c"),
            part("b", &[], &["a"], "cargo test --test b"),
            part("a", &[], &[], "cargo test --test a"),
        ]);
        assert_eq!(order_of(&mut world, chain), vec!["a", "b", "c"]);
        // A diamond: every part follows all it depends on; independent
        // parts keep the caller's order.
        let diamond = plan_for(vec![
            part("d", &criteria, &["b", "c"], "cargo test --test d"),
            part("c", &[], &["a"], "cargo test --test c"),
            part("b", &[], &["a"], "cargo test --test b"),
            part("a", &[], &[], "cargo test --test a"),
        ]);
        assert_eq!(order_of(&mut world, diamond), vec!["a", "c", "b", "d"]);
        // The bounds are inclusive: exactly the limit still plans.
        let at_limit: Vec<WorkPart> = (0..ARRAY_MAX_ITEMS)
            .map(|index| part(&format!("p{index}"), &criteria, &[], "cargo test"))
            .collect();
        assert_eq!(
            order_of(&mut world, plan_for(at_limit)).len(),
            ARRAY_MAX_ITEMS
        );
        let longest_proof = plan_for(vec![part(
            "big",
            &criteria,
            &[],
            &"x".repeat(TEXT_MAX_BYTES),
        )]);
        assert_eq!(order_of(&mut world, longest_proof), vec!["big"]);
        let recorded = world
            .runtime
            .store()
            .plan_revisions(&task)
            .expect("revisions")
            .len();
        assert_eq!(recorded, 4);

        let many: Vec<WorkPart> = (0..=ARRAY_MAX_ITEMS)
            .map(|index| part(&format!("p{index}"), &criteria, &[], "cargo test"))
            .collect();
        let dependencies: Vec<String> = (0..=ARRAY_MAX_ITEMS)
            .map(|index| format!("d{index}"))
            .collect();
        let dependencies: Vec<&str> = dependencies.iter().map(String::as_str).collect();
        let invalid: [(&str, Vec<WorkPart>); 8] = [
            ("empty plan", Vec::new()),
            ("too many parts", many),
            (
                "too many dependencies",
                vec![part("wide", &criteria, &dependencies, "cargo test")],
            ),
            (
                "illegal part id",
                vec![part("two words", &criteria, &[], "cargo test")],
            ),
            (
                "oversized proof",
                vec![part("big", &criteria, &[], &"x".repeat(TEXT_MAX_BYTES + 1))],
            ),
            (
                "duplicate part",
                vec![
                    part("a", &criteria, &[], "cargo test"),
                    part("a", &criteria, &[], "cargo test --lib"),
                ],
            ),
            (
                "unknown dependency",
                vec![part("a", &criteria, &["ghost"], "cargo test")],
            ),
            (
                "dependency cycle",
                vec![
                    part("a", &criteria, &["b"], "cargo test"),
                    part("b", &criteria, &["a"], "cargo test"),
                ],
            ),
        ];
        for (label, parts) in invalid {
            let request = plan_for(parts);
            select(&mut world, &session, &request, &[]);
            let error = run(&mut world, &session, ActionInput::PlanWork(request))
                .expect_err("an invalid plan is refused");
            let expected = match label {
                "empty plan" => matches!(error, ActionError::EmptyPlan),
                "too many parts" | "too many dependencies" => {
                    matches!(error, ActionError::PlanTooLarge { .. })
                }
                "illegal part id" => matches!(error, ActionError::InvalidPartId { .. }),
                "oversized proof" => matches!(error, ActionError::ProofTooLarge { .. }),
                "duplicate part" => matches!(error, ActionError::DuplicatePart { .. }),
                "unknown dependency" => matches!(error, ActionError::UnknownDependency { .. }),
                "dependency cycle" => matches!(error, ActionError::DependencyCycle { .. }),
                other => panic!("unlisted case {other}"),
            };
            assert!(expected, "{label}: {error:?}");
            assert_eq!(error.error_code(), ErrorCode::InvalidInput, "{label}");
            assert_eq!(
                world
                    .runtime
                    .store()
                    .plan_revisions(&task)
                    .expect("revisions")
                    .len(),
                recorded,
                "{label}: no revision recorded"
            );
            assert_eq!(
                row(&world, &task, PLAN_WORK).execution,
                ObligationExecution::Pending,
                "{label}: plan_work stays open"
            );
        }
    }

    #[test]
    fn ac030a_plan_handlers_positive_and_negative_triggers() {
        let (mut world, session, task) = plan_world("plan-ac030a", &PLAN_CRITERIA);
        // Positive legs: each local handler fires on its own trigger.
        let request = plan_only(&world, &task);
        select(&mut world, &session, &request, &[]);
        let framed = run(
            &mut world,
            &session,
            ActionInput::FrameGoal(request.clone()),
        )
        .expect("frame");
        let ActionOutcome::Framed {
            criteria,
            constraints,
            unknowns,
        } = framed
        else {
            panic!("expected a frame: {framed:?}");
        };
        assert_eq!(
            criteria
                .iter()
                .map(|criterion| criterion.text.as_str())
                .collect::<Vec<_>>(),
            PLAN_CRITERIA.to_vec(),
            "the task's own criteria, never a rewrite"
        );
        assert_eq!(
            constraints,
            vec!["Keep existing callers working.".to_string()]
        );
        assert!(unknowns.is_empty());
        let planned =
            run(&mut world, &session, ActionInput::PlanWork(request.clone())).expect("plan");
        let ActionOutcome::Planned { revision, plan } = planned else {
            panic!("expected a plan: {planned:?}");
        };
        assert_eq!(revision, 1);
        assert_eq!(
            plan.order,
            vec!["schema".to_string(), "endpoint".to_string()]
        );
        let assessed = run(
            &mut world,
            &session,
            ActionInput::AssessPlan(request.clone()),
        )
        .expect("assess");
        assert!(matches!(
            assessed,
            ActionOutcome::Assessed(Assessment {
                verdict: PlanVerdict::Pass,
                ..
            })
        ));
        let framed_again =
            run(&mut world, &session, ActionInput::FrameGoal(request)).expect("frame");
        assert_eq!(skipped(&framed_again), Some(SkipReason::AlreadySatisfied));

        // Negative legs: a single local part needs no plan and no stages.
        let single_task = submit_plan_task(
            &mut world,
            &session,
            "cmd-plan-ac030a-single",
            "Fix the typo in the login banner.",
            &PLAN_CRITERIA,
        );
        let criteria = criterion_ids(&world, &single_task);
        let single = facts(
            &single_task,
            RequestKind::Change,
            &[Surface::Local],
            ContractBasis::Absent,
            vec![part("banner", &criteria, &[], "cargo test")],
        );
        select(&mut world, &session, &single, &[]);
        for (input, action) in [
            (ActionInput::PlanWork(single.clone()), PLAN_WORK),
            (ActionInput::AssessPlan(single.clone()), ASSESS_PLAN),
            (
                ActionInput::ChallengeDirection(single.clone()),
                CHALLENGE_DIRECTION,
            ),
            (
                ActionInput::DesignContracts(single.clone()),
                DESIGN_CONTRACTS,
            ),
        ] {
            let outcome = run(&mut world, &session, input).expect("a skip");
            assert!(
                matches!(
                    outcome,
                    ActionOutcome::Skipped {
                        action: skipped_action,
                        reason: SkipReason::NotNeeded,
                    } if skipped_action == action
                ),
                "{action} does not fire on a single local part: {outcome:?}"
            );
        }
        assert!(
            world
                .runtime
                .store()
                .plan_revisions(&single_task)
                .expect("revisions")
                .is_empty()
        );
        // Purpose rows: a required row answers the exact capability refusal.
        let (mut material_world, material_session, material_task) =
            plan_world("plan-ac030a-material", &PLAN_CRITERIA);
        let request = material(&material_world, &material_task);
        select(&mut material_world, &material_session, &request, &[]);
        for input in [
            ActionInput::ChallengeDirection(request.clone()),
            ActionInput::DesignContracts(request),
        ] {
            let error = run(&mut material_world, &material_session, input).expect_err("no seam");
            assert_eq!(error.error_code(), ErrorCode::CapabilityUnavailable);
        }
        assert_eq!(provider_calls(&world) + provider_calls(&material_world), 0);
    }

    /// The semantic legs through their Broker purposes, offline: a
    /// scripted `Provider` double answers from the manifest inputs and
    /// logs every call; the runtime's own provider is never touched.
    mod semantic {
        use super::*;
        use rivect::actions::{
            BrokerSeam, DecisionAuthor, Delegation, SemanticRefusal, SemanticVerdict, Surface,
            SurfaceNote,
        };
        use rivect::config::{Config, Connection, EffortAssign, EffortLevel, ModelAssign};
        use rivect::model::{Broker, CallContract, ModelError, RequestManifest};
        use rivect::providers::{
            LoopbackProvider, Provider, ProviderError, ProviderReply, ToolCall,
        };
        use rivect::resources::UsageDelta;
        use serde_json::Value;
        use std::collections::VecDeque;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::{Arc, Mutex};

        const WORLD: &str = "/world/semantic";

        type Script =
            Box<dyn FnMut(&RequestManifest, &Value) -> Result<ProviderReply, ProviderError> + Send>;
        type CallLog = Arc<Mutex<Vec<RequestManifest>>>;

        struct Scripted {
            log: CallLog,
            script: Script,
        }

        impl Provider for Scripted {
            fn name(&self) -> &'static str {
                "scripted"
            }

            fn serves(&self, _connection: &str, _entry: &Connection) -> bool {
                true
            }

            fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
                self.log.lock().expect("log").push(manifest.clone());
                let inputs: Value =
                    serde_json::from_str(&manifest.inputs).expect("manifest inputs are json");
                (self.script)(manifest, &inputs)
            }
        }

        fn scripted(
            script: impl FnMut(&RequestManifest, &Value) -> Result<ProviderReply, ProviderError>
            + Send
            + 'static,
        ) -> (Broker, CallLog) {
            let log = CallLog::default();
            let provider = Scripted {
                log: log.clone(),
                script: Box::new(script),
            };
            (Broker::new(Box::new(provider)), log)
        }

        fn calls(log: &CallLog) -> Vec<RequestManifest> {
            log.lock().expect("log").clone()
        }

        fn assert_manifest_selection(
            manifest: &RequestManifest,
            task: &TaskId,
            selection: &Selection,
            expected_criteria: &[CriterionId],
        ) {
            let inputs: Value =
                serde_json::from_str(&manifest.inputs).expect("manifest inputs are json");
            assert_eq!(inputs["task_id"].as_str(), Some(task.0.as_str()));
            assert_eq!(inputs["selection_revision"], json!(selection.revision));
            assert_eq!(
                inputs["facts_digest"].as_str(),
                Some(selection.facts_digest.as_str())
            );
            let criteria = inputs["criteria"].as_array().expect("manifest criteria");
            assert_eq!(
                criteria
                    .iter()
                    .map(|criterion| criterion["id"].as_str().expect("criterion id"))
                    .collect::<Vec<_>>(),
                expected_criteria
                    .iter()
                    .map(|criterion| criterion.0.as_str())
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                criteria
                    .iter()
                    .map(|criterion| criterion["text"].as_str().expect("criterion text"))
                    .collect::<Vec<_>>(),
                PLAN_CRITERIA.to_vec()
            );
        }

        // Loopback's fixture text is not a semantic answer; this adapter layers
        // the existing manifest-derived reply over its real offline send.
        struct RecordingLoopbackProvider {
            inner: LoopbackProvider,
            sent: CallLog,
            inner_sends: Arc<AtomicU64>,
        }

        impl Provider for RecordingLoopbackProvider {
            fn name(&self) -> &'static str {
                self.inner.name()
            }

            fn serves(&self, connection: &str, entry: &Connection) -> bool {
                self.inner.serves(connection, entry)
            }

            fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
                self.sent
                    .lock()
                    .expect("sent manifests")
                    .push(manifest.clone());
                let loopback_reply = self.inner.send(manifest)?;
                self.inner_sends.store(self.inner.calls(), Ordering::SeqCst);
                let inputs: Value =
                    serde_json::from_str(&manifest.inputs).expect("manifest inputs are json");
                let mut semantic_reply = faithful(manifest, &inputs);
                semantic_reply.usage = loopback_reply.usage;
                Ok(semantic_reply)
            }
        }

        fn loopback_recording_broker() -> (Broker, CallLog, Arc<AtomicU64>) {
            let sent = CallLog::default();
            let inner_sends = Arc::new(AtomicU64::new(0));
            let provider = RecordingLoopbackProvider {
                inner: LoopbackProvider::new(),
                sent: sent.clone(),
                inner_sends: inner_sends.clone(),
            };
            (Broker::new(Box::new(provider)), sent, inner_sends)
        }

        fn reply(text: String) -> ProviderReply {
            ProviderReply {
                text,
                tool_calls: Vec::new(),
                usage: UsageDelta::Unknown,
            }
        }

        /// A note per selected risky surface, written from the inputs: the
        /// text carries the task's goal, so no fixed template can match it.
        fn notes_from(inputs: &Value) -> Vec<Value> {
            let goal = inputs["goal"].as_str().expect("goal");
            inputs["surfaces"]
                .as_array()
                .expect("surfaces")
                .iter()
                .filter(|surface| *surface != "local")
                .map(|surface| {
                    let label = surface.as_str().expect("label");
                    json!({ "surface": label, "text": format!("{goal} :: {label}") })
                })
                .collect()
        }

        /// Answers each purpose from its own manifest inputs.
        fn faithful(manifest: &RequestManifest, inputs: &Value) -> ProviderReply {
            let body = match manifest.purpose.as_str() {
                CHALLENGE_DIRECTION => json!({ "risks": notes_from(inputs) }),
                DESIGN_CONTRACTS => json!({ "contracts": notes_from(inputs) }),
                ASSESS_PLAN => json!({
                    "verdict": "pass",
                    "findings": [format!("revision {} is feasible", inputs["plan"]["revision"])],
                }),
                other => panic!("unexpected purpose {other}"),
            };
            reply(body.to_string())
        }

        fn semantic_config(purposes: &str) -> Config {
            Config::parse_validated(&format!(
                "{}\n[connections.reserve]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11435\"\n{purposes}",
                support::config_distinct_pools()
            ))
            .expect("semantic config parses")
        }

        fn fixed(purpose: &str, fallback: &str) -> String {
            format!(
                "[models.purposes.{purpose}]\nmodel = {{ mode = \"fixed\", connection = \"local\", model_id = \"fixture-model\" }}\neffort = {{ mode = \"fixed\", value = \"high\" }}\nfallback = {{ mode = \"{fallback}\" }}\n"
            )
        }

        fn run_with(
            world: &mut support::World,
            session: &SessionId,
            config: &Config,
            broker: &mut Broker,
            input: ActionInput,
        ) -> Result<ActionOutcome, ActionError> {
            let mut seam = BrokerSeam {
                broker,
                world: WORLD,
            };
            ActionRegistry::new().execute_with_seam(
                input,
                &mut action_ctx(world, session, config),
                Some(&mut seam),
            )
        }

        fn refusal(error: ActionError, action: &str) -> SemanticRefusal {
            assert_eq!(error.error_code(), ErrorCode::DependencyBlocked);
            match error {
                ActionError::SemanticReply {
                    action: refused,
                    cause,
                } if refused == action => cause,
                other => panic!("expected a refused {action} reply, got {other:?}"),
            }
        }

        #[test]
        fn broker_purposes_produce_real_risks_contracts_and_verdict() {
            let (mut world, session, rotate) = plan_world("semantic-positive", &PLAN_CRITERIA);
            let harden_goal = "Harden the public token endpoint.";
            let harden = submit_plan_task(
                &mut world,
                &session,
                "cmd-semantic-harden",
                harden_goal,
                &PLAN_CRITERIA,
            );
            let config = semantic_config(&format!(
                "{}{}{}",
                fixed(CHALLENGE_DIRECTION, "off"),
                fixed(DESIGN_CONTRACTS, "off"),
                fixed(ASSESS_PLAN, "off")
            ));
            let (mut broker, log) = scripted(|manifest, inputs| Ok(faithful(manifest, inputs)));
            for (task, goal) in [(&rotate, "Rotate session tokens."), (&harden, harden_goal)] {
                let request = material(&world, task);
                let selection = select(&mut world, &session, &request, &[]);
                let expected_criteria = criterion_ids(&world, task);
                run(
                    &mut world,
                    &session,
                    ActionInput::FrameGoal(request.clone()),
                )
                .expect("frame");
                let expected = vec![
                    SurfaceNote {
                        surface: Surface::Auth,
                        text: format!("{goal} :: auth"),
                    },
                    SurfaceNote {
                        surface: Surface::PublicApi,
                        text: format!("{goal} :: public_api"),
                    },
                ];
                let challenged = run_with(
                    &mut world,
                    &session,
                    &config,
                    &mut broker,
                    ActionInput::ChallengeDirection(request.clone()),
                )
                .expect("challenge");
                let ActionOutcome::Challenged { risks } = challenged else {
                    panic!("expected risks, got {challenged:?}");
                };
                assert_eq!(risks, expected, "the risks are the purpose's reply");
                let after_challenge = calls(&log);
                assert_manifest_selection(
                    after_challenge.last().expect("challenge manifest"),
                    task,
                    &selection,
                    &expected_criteria,
                );
                let designed = run_with(
                    &mut world,
                    &session,
                    &config,
                    &mut broker,
                    ActionInput::DesignContracts(request.clone()),
                )
                .expect("design");
                let ActionOutcome::Designed { contracts } = designed else {
                    panic!("expected contracts, got {designed:?}");
                };
                assert_eq!(contracts, expected);
                let after_design = calls(&log);
                assert_manifest_selection(
                    after_design.last().expect("design manifest"),
                    task,
                    &selection,
                    &expected_criteria,
                );
                run(&mut world, &session, ActionInput::PlanWork(request.clone())).expect("plan");
                let judged = run_with(
                    &mut world,
                    &session,
                    &config,
                    &mut broker,
                    ActionInput::AssessPlan(request),
                )
                .expect("assess");
                let ActionOutcome::Judged {
                    plan_revision,
                    verdict,
                    findings,
                } = judged
                else {
                    panic!("expected a semantic verdict, got {judged:?}");
                };
                assert_eq!(plan_revision, 1);
                assert_eq!(verdict, SemanticVerdict::Pass);
                assert_eq!(findings, vec!["revision 1 is feasible".to_string()]);
                let after_assess = calls(&log);
                assert_manifest_selection(
                    after_assess.last().expect("assessment manifest"),
                    task,
                    &selection,
                    &expected_criteria,
                );
                for capability in [CHALLENGE_DIRECTION, DESIGN_CONTRACTS, ASSESS_PLAN] {
                    let stored = row(&world, task, capability);
                    assert_eq!(
                        stored.execution,
                        ObligationExecution::Satisfied,
                        "{capability}"
                    );
                    assert_eq!(stored.blocker, None, "{capability}");
                }
                assert!(
                    row(&world, task, DESIGN_CONTRACTS)
                        .outcome_json
                        .is_some_and(|outcome| outcome.contains(&format!("{goal} :: auth"))),
                    "the close records the reply it closed on"
                );
                assert_eq!(gate(&world, task), PlanGate::Open);
            }
            let sent = calls(&log);
            let purposes: Vec<&str> = sent
                .iter()
                .map(|manifest| manifest.purpose.as_str())
                .collect();
            assert_eq!(
                purposes,
                [CHALLENGE_DIRECTION, DESIGN_CONTRACTS, ASSESS_PLAN].repeat(2)
            );
            for [challenge, design, assess] in sent.as_chunks::<3>().0 {
                assert_ne!(
                    challenge.instructions.as_bytes(),
                    design.instructions.as_bytes()
                );
                assert_ne!(
                    challenge.instructions.as_bytes(),
                    assess.instructions.as_bytes()
                );
                assert_ne!(
                    design.instructions.as_bytes(),
                    assess.instructions.as_bytes()
                );
                assert!(
                    challenge
                        .instructions
                        .contains("naming every selected risky surface")
                );
                assert!(
                    design
                        .instructions
                        .contains("covering every selected risky surface")
                );
                assert!(
                    assess
                        .instructions
                        .contains("feasibility, test design and risk against the task criteria")
                );
            }
            for manifest in &sent {
                assert!(manifest.tools.is_empty(), "a purpose declares no tool");
                assert!(
                    matches!(&manifest.model, ModelAssign::Fixed(fixed)
                        if fixed.connection == "local" && fixed.model_id == "fixture-model"),
                    "the purpose override resolves before dispatch: {manifest:?}"
                );
                assert_eq!(
                    manifest.effort,
                    EffortAssign::Fixed {
                        value: EffortLevel::High,
                    }
                );
            }
            assert_eq!(
                provider_calls(&world),
                0,
                "the runtime provider stays untouched"
            );
        }

        #[test]
        fn semantic_fail_keeps_assessment_failed_and_gate_paused() {
            let (mut world, session, task) = plan_world("semantic-verdict-fail", &PLAN_CRITERIA);
            let request = plan_only(&world, &task);
            select(&mut world, &session, &request, &[]);
            run(&mut world, &session, ActionInput::PlanWork(request.clone())).expect("plan");
            let config = semantic_config("");
            let (mut broker, log) = scripted(|_, _| {
                Ok(reply(
                    json!({
                        "verdict": "fail",
                        "findings": ["the refresh path can race token expiry"]
                    })
                    .to_string(),
                ))
            });
            let judged = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::AssessPlan(request),
            )
            .expect("semantic failure is a typed judgment");
            let ActionOutcome::Judged {
                plan_revision,
                verdict,
                findings,
            } = judged
            else {
                panic!("expected a failed judgment, got {judged:?}");
            };
            assert_eq!(plan_revision, 1);
            assert_eq!(verdict, SemanticVerdict::Fail);
            assert_eq!(
                findings,
                vec!["the refresh path can race token expiry".to_string()]
            );
            let failed = row(&world, &task, ASSESS_PLAN);
            assert_eq!(failed.execution, ObligationExecution::Failed);
            assert_eq!(
                failed.blocker,
                Some(plan_blocker(ErrorCode::DependencyBlocked, ASSESS_PLAN))
            );
            let outcome: Value =
                serde_json::from_str(failed.outcome_json.as_deref().expect("failed outcome"))
                    .expect("outcome json");
            assert_eq!(outcome["verdict"], "fail");
            assert_eq!(
                outcome["findings"],
                json!(["the refresh path can race token expiry"])
            );
            assert!(matches!(gate(&world, &task), PlanGate::Paused { .. }));
            assert_eq!(calls(&log).len(), 1);
        }

        #[test]
        fn plan_work_stays_local_with_a_broker_seam_present() {
            let (mut world, session, task) = plan_world("semantic-plan-local", &PLAN_CRITERIA);
            let criteria = criterion_ids(&world, &task);
            let request = facts(
                &task,
                RequestKind::PlanOnly,
                &[Surface::Local],
                ContractBasis::Absent,
                vec![
                    part(
                        "endpoint",
                        &criteria[1..],
                        &["schema"],
                        "cargo test --test endpoint",
                    ),
                    part("schema", &criteria[..1], &[], "cargo test --test schema"),
                ],
            );
            select(&mut world, &session, &request, &[]);
            let config = semantic_config("");
            let (mut broker, log) = scripted(|_, _| panic!("plan_work never calls a model"));
            let planned = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::PlanWork(request),
            )
            .expect("plan");
            let ActionOutcome::Planned { revision, plan } = planned else {
                panic!("expected a plan, got {planned:?}");
            };
            assert_eq!(revision, 1);
            assert_eq!(
                plan.order,
                vec!["schema".to_string(), "endpoint".to_string()]
            );
            assert_eq!(
                row(&world, &task, PLAN_WORK).execution,
                ObligationExecution::Satisfied
            );
            assert!(calls(&log).is_empty(), "no dispatch on the plan_work path");
            assert_eq!(broker.accounted_requests(), 0);
            assert_eq!(broker.admitted_attempts(), 0);
            assert_eq!(provider_calls(&world), 0);
        }

        #[test]
        fn approved_contract_cancelled_task_or_stale_selection_spends_no_broker_call() {
            let (mut world, session, approved_task) =
                plan_world("semantic-no-call", &PLAN_CRITERIA);
            let config = semantic_config("");
            let (mut broker, log) = scripted(|manifest, inputs| Ok(faithful(manifest, inputs)));
            let criteria = criterion_ids(&world, &approved_task);
            let approved = facts(
                &approved_task,
                RequestKind::Change,
                &[Surface::Auth],
                ContractBasis::Approved,
                vec![part("rotate", &criteria, &[], "cargo test --test rotate")],
            );
            select(&mut world, &session, &approved, &[]);
            for input in [
                ActionInput::ChallengeDirection(approved.clone()),
                ActionInput::DesignContracts(approved.clone()),
                ActionInput::AssessPlan(approved),
            ] {
                let outcome = run_with(&mut world, &session, &config, &mut broker, input)
                    .expect("a skip, not a refusal");
                assert!(skipped(&outcome).is_some(), "{outcome:?}");
            }

            let stale_task = submit_plan_task(
                &mut world,
                &session,
                "cmd-semantic-stale",
                "Rotate session tokens.",
                &PLAN_CRITERIA,
            );
            let recorded = material(&world, &stale_task);
            let stale_selection = select(&mut world, &session, &recorded, &[]);
            let stale_row = row(&world, &stale_task, CHALLENGE_DIRECTION);
            let stale = facts(
                &stale_task,
                RequestKind::Change,
                &[Surface::Auth],
                ContractBasis::Absent,
                recorded.parts.clone(),
            );
            let refused = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::ChallengeDirection(stale),
            )
            .expect_err("stale facts");
            assert!(
                matches!(
                    store_cause(refused),
                    StoreError::Conflict(ConflictCause::PlanSelectionStale { .. })
                ),
                "stale facts close nothing"
            );
            assert_eq!(row(&world, &stale_task, CHALLENGE_DIRECTION), stale_row);
            assert_selection_kept(&world, &stale_task, &stale_selection);

            let cancelled_task = submit_plan_task(
                &mut world,
                &session,
                "cmd-semantic-cancelled",
                "Rotate session tokens.",
                &PLAN_CRITERIA,
            );
            let cancelled = material(&world, &cancelled_task);
            select(&mut world, &session, &cancelled, &[]);
            let cancelled_row = row(&world, &cancelled_task, DESIGN_CONTRACTS);
            world
                .runtime
                .store_writer()
                .cancel_task(&session, &cancelled_task, 1, Some("operator aborted"))
                .expect("cancel");
            let refused = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::DesignContracts(cancelled),
            )
            .expect_err("terminal task");
            assert!(matches!(store_cause(refused), StoreError::AlreadyTerminal));
            assert_eq!(
                row(&world, &cancelled_task, DESIGN_CONTRACTS),
                cancelled_row
            );

            let unresolved_task = submit_plan_task(
                &mut world,
                &session,
                "cmd-semantic-unresolved",
                "Rotate session tokens.",
                &PLAN_CRITERIA,
            );
            let unknown = undecided(&world, &unresolved_task);
            select(&mut world, &session, &unknown, &[]);
            let outcome = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::ChallengeDirection(unknown),
            )
            .expect("a skip");
            assert_eq!(skipped(&outcome), Some(SkipReason::NeedsInformation));

            assert!(calls(&log).is_empty(), "no stage spent a Broker call");
            assert_eq!(broker.accounted_requests(), 0);
            assert_eq!(provider_calls(&world), 0);
        }

        #[test]
        fn untrusted_reply_is_refused_and_closes_nothing() {
            let (mut world, session, task) = plan_world("semantic-untrusted", &PLAN_CRITERIA);
            let request = material(&world, &task);
            let selection = select(&mut world, &session, &request, &[]);
            let capabilities = row_capabilities(&world, &task);
            let design_before = row(&world, &task, DESIGN_CONTRACTS);
            let both = json!([
                { "surface": "auth", "text": "token replay" },
                { "surface": "public_api", "text": "response shape drift" }
            ]);
            let with = |extra: Value| {
                let mut body = json!({ "risks": both.clone() });
                for (key, value) in extra.as_object().expect("object") {
                    body[key] = value.clone();
                }
                body.to_string()
            };
            let text = reply;
            let data = SemanticRefusal::Malformed {
                class: serde_json::error::Category::Data,
            };
            let cases: Vec<(&str, ProviderReply, SemanticRefusal)> = vec![
                (
                    "not json",
                    text("the risks are fine".to_string()),
                    SemanticRefusal::Malformed {
                        class: serde_json::error::Category::Syntax,
                    },
                ),
                (
                    "adds plan parts",
                    text(with(json!({ "parts": [{ "id": "extra" }] }))),
                    data.clone(),
                ),
                (
                    "adds rows",
                    text(with(json!({ "rows": ["deliver_change"] }))),
                    data.clone(),
                ),
                (
                    "adds obligations",
                    text(with(json!({ "obligations": ["audit_tests"] }))),
                    data.clone(),
                ),
                (
                    "self-delegates",
                    text(with(
                        json!({ "delegation": { "action": "resolve_decision" } }),
                    )),
                    data.clone(),
                ),
                (
                    "marks the contract approved",
                    text(with(json!({ "contract": "approved" }))),
                    data.clone(),
                ),
                (
                    "unknown note field",
                    text(
                        json!({ "risks": [
                            { "surface": "auth", "text": "a", "closes": "assess_plan" },
                            { "surface": "public_api", "text": "b" }
                        ] })
                        .to_string(),
                    ),
                    data.clone(),
                ),
                (
                    "surface outside the vocabulary",
                    text(json!({ "risks": [{ "surface": "telepathy", "text": "a" }] }).to_string()),
                    data,
                ),
                (
                    "names an unselected surface",
                    text(
                        json!({ "risks": [
                            { "surface": "auth", "text": "a" },
                            { "surface": "public_api", "text": "b" },
                            { "surface": "migration", "text": "c" }
                        ] })
                        .to_string(),
                    ),
                    SemanticRefusal::ForeignSurface {
                        surface: Surface::Migration,
                    },
                ),
                (
                    "leaves a selected surface unanswered",
                    text(json!({ "risks": [{ "surface": "auth", "text": "a" }] }).to_string()),
                    SemanticRefusal::MissingSurface {
                        surface: Surface::PublicApi,
                    },
                ),
                (
                    "over the byte bound",
                    text(format!(
                        "{}{}",
                        json!({ "risks": both.clone() }),
                        " ".repeat(TEXT_MAX_BYTES)
                    )),
                    SemanticRefusal::OverLimit,
                ),
                ("empty", text("  ".to_string()), SemanticRefusal::Empty),
                (
                    "asks for a tool",
                    ProviderReply {
                        text: with(json!({})),
                        tool_calls: vec![ToolCall {
                            tool: "read_file".to_string(),
                            path: Some("secrets.txt".to_string()),
                        }],
                        usage: UsageDelta::Unknown,
                    },
                    SemanticRefusal::ToolCall,
                ),
            ];
            let script: VecDeque<ProviderReply> =
                cases.iter().map(|(_, reply, _)| reply.clone()).collect();
            let script = Mutex::new(script);
            let config = semantic_config("");
            let (mut broker, log) = scripted(move |_, _| {
                Ok(script
                    .lock()
                    .expect("script")
                    .pop_front()
                    .expect("one reply per case"))
            });
            for (label, _, expected) in &cases {
                let error = run_with(
                    &mut world,
                    &session,
                    &config,
                    &mut broker,
                    ActionInput::ChallengeDirection(request.clone()),
                )
                .expect_err(label);
                assert_eq!(&refusal(error, CHALLENGE_DIRECTION), expected, "{label}");
                let stored = row(&world, &task, CHALLENGE_DIRECTION);
                assert_eq!(stored.execution, ObligationExecution::Pending, "{label}");
                assert_eq!(stored.outcome_json, None, "{label}: nothing closed");
                assert_eq!(
                    stored.blocker,
                    Some(plan_blocker(
                        ErrorCode::DependencyBlocked,
                        CHALLENGE_DIRECTION
                    )),
                    "{label}: the row stays open on the exact blocker"
                );
                assert_eq!(
                    row(&world, &task, DESIGN_CONTRACTS),
                    design_before,
                    "{label}"
                );
                assert_eq!(row_capabilities(&world, &task), capabilities, "{label}");
                assert_selection_kept(&world, &task, &selection);
                assert!(
                    world
                        .runtime
                        .store()
                        .plan_revisions(&task)
                        .expect("revisions")
                        .is_empty(),
                    "{label}: no plan part landed"
                );
            }
            assert_eq!(calls(&log).len(), cases.len());
            assert!(matches!(gate(&world, &task), PlanGate::Paused { .. }));
            assert_eq!(provider_calls(&world), 0);
        }

        #[test]
        fn raw_loopback_reply_cannot_close_semantic_row() {
            let (mut world, session, task) = plan_world("semantic-raw-loopback", &PLAN_CRITERIA);
            let request = material(&world, &task);
            select(&mut world, &session, &request, &[]);
            let config = semantic_config("");
            let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
            let refused = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::DesignContracts(request),
            )
            .expect_err("the raw Loopback reply is not semantic");
            assert_eq!(
                refusal(refused, DESIGN_CONTRACTS),
                SemanticRefusal::Malformed {
                    class: serde_json::error::Category::Syntax,
                }
            );
            let stored = row(&world, &task, DESIGN_CONTRACTS);
            assert_eq!(stored.execution, ObligationExecution::Pending);
            assert_eq!(stored.outcome_json, None);
            assert_eq!(
                stored.blocker,
                Some(plan_blocker(ErrorCode::DependencyBlocked, DESIGN_CONTRACTS))
            );
            assert!(
                world
                    .runtime
                    .store()
                    .current_question(&task)
                    .expect("question read")
                    .is_none()
            );
            assert!(
                world
                    .runtime
                    .store()
                    .plan_revisions(&task)
                    .expect("plan revisions")
                    .is_empty()
            );
            assert!(matches!(gate(&world, &task), PlanGate::Paused { .. }));
            assert_eq!(broker.accounted_requests(), 1);
        }

        #[test]
        fn failed_dispatch_ends_its_attempt_and_publishes_no_question() {
            let (mut world, session, task) = plan_world("semantic-attempts", &PLAN_CRITERIA);
            let request = material(&world, &task);
            select(&mut world, &session, &request, &[]);
            let config = semantic_config(&format!(
                "{}{}",
                fixed(DESIGN_CONTRACTS, "manual"),
                fixed(CHALLENGE_DIRECTION, "off")
            ));
            let (mut broker, log) = scripted(|_, _| {
                Err(ProviderError::UnknownConnection {
                    connection: "local".to_string(),
                })
            });

            let manual = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::DesignContracts(request.clone()),
            )
            .expect_err("the send failed");
            assert_eq!(manual.error_code(), ErrorCode::CapabilityUnavailable);
            assert!(
                matches!(
                    &manual,
                    ActionError::SemanticDispatch {
                        action: DESIGN_CONTRACTS,
                        source,
                    } if matches!(**source, ModelError::ManualFallbackPending { .. })
                ),
                "{manual:?}"
            );
            let paused = calls(&log).remove(0);
            assert!(broker.pending_choice(&paused.attempt_id).is_none());
            assert!(broker.admission(&paused.attempt_id).is_none());
            assert!(matches!(
                broker.dispatch(WORLD, &paused),
                Err(ModelError::AttemptCancelled { .. })
            ));
            assert_eq!(
                world.runtime.store().current_question(&task).expect("read"),
                None,
                "the manual-fallback pause never publishes from a plan stage"
            );
            assert_eq!(
                row(&world, &task, DESIGN_CONTRACTS).blocker,
                Some(plan_blocker(
                    ErrorCode::CapabilityUnavailable,
                    DESIGN_CONTRACTS
                ))
            );

            let failed = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::ChallengeDirection(request),
            )
            .expect_err("the send failed");
            assert!(
                matches!(
                    &failed,
                    ActionError::SemanticDispatch {
                        action: CHALLENGE_DIRECTION,
                        source,
                    } if matches!(**source, ModelError::Provider(_))
                ),
                "{failed:?}"
            );
            let spent = calls(&log).remove(1);
            assert!(matches!(
                broker.dispatch(WORLD, &spent),
                Err(ModelError::AttemptCancelled { .. })
            ));
            assert_eq!(
                broker.admitted_attempts(),
                0,
                "no admission outlives a call"
            );
            assert_eq!(calls(&log).len(), 2, "a cancelled attempt never re-sends");
            assert_eq!(
                row(&world, &task, CHALLENGE_DIRECTION).execution,
                ObligationExecution::Pending
            );
            assert_eq!(provider_calls(&world), 0);
        }

        #[test]
        fn answered_fork_survives_provider_error_for_retry() {
            let (mut world, session, task) =
                plan_world("semantic-fork-provider-error", &PLAN_CRITERIA);
            let request = material(&world, &task);
            let selection = select(&mut world, &session, &request, &[]);
            let config = semantic_config("");
            let mut call_count = 0;
            let (mut broker, log) = scripted(move |_, inputs| {
                let call = call_count;
                call_count += 1;
                match call {
                    0 => Ok(reply(
                        json!({ "contracts": notes_from(inputs), "fork": fork_json() }).to_string(),
                    )),
                    1 => Err(ProviderError::UnknownConnection {
                        connection: "local".to_string(),
                    }),
                    _ => Ok(reply(
                        json!({ "contracts": notes_from(inputs) }).to_string(),
                    )),
                }
            });
            let forked = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::DesignContracts(request.clone()),
            )
            .expect("fork");
            let ActionOutcome::Forked { resolution, .. } = forked else {
                panic!("expected a fork, got {forked:?}");
            };
            let ActionOutcome::Asked { question, .. } = *resolution else {
                panic!("expected a pending question");
            };
            world
                .runtime
                .store_writer()
                .answer_question(
                    &session,
                    &task,
                    &question.question_id,
                    question.question_revision,
                    &AnswerSelection::Option {
                        option_id: OptionId("b".to_string()),
                    },
                    "human",
                )
                .expect("answer");
            let failed = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::DesignContracts(request.clone()),
            )
            .expect_err("the next provider call fails");
            assert_eq!(failed.error_code(), ErrorCode::CapabilityUnavailable);
            assert!(matches!(
                failed,
                ActionError::SemanticDispatch {
                    action: DESIGN_CONTRACTS,
                    ..
                }
            ));
            let failed_row = row(&world, &task, DESIGN_CONTRACTS);
            assert_eq!(failed_row.execution, ObligationExecution::Pending);
            assert_eq!(
                failed_row.blocker,
                Some(plan_blocker(
                    ErrorCode::CapabilityUnavailable,
                    DESIGN_CONTRACTS
                ))
            );
            assert!(
                world
                    .runtime
                    .store()
                    .current_question(&task)
                    .expect("question read")
                    .is_none()
            );
            assert!(matches!(gate(&world, &task), PlanGate::Paused { .. }));
            assert_eq!(calls(&log).len(), 2);
            let retried = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::DesignContracts(request),
            )
            .expect("the third call retries with the applied answer");
            assert!(matches!(retried, ActionOutcome::Designed { .. }));
            let sent = calls(&log);
            assert_eq!(sent.len(), 3);
            let third_inputs: Value =
                serde_json::from_str(&sent[2].inputs).expect("third manifest inputs");
            assert_eq!(
                third_inputs["fork_answer"],
                json!({ "kind": "option", "option_id": "b" }),
                "retry retains the human's applied choice"
            );
            let feed = world
                .runtime
                .store()
                .events_after(&session, Some(&task), 0, 100)
                .expect("task feed");
            let published: Vec<_> = feed
                .iter()
                .filter(|event| event.event_type == "question.published")
                .collect();
            assert_eq!(published.len(), 1, "retry does not republish the fork");
            assert_eq!(
                published[0].delta["question_id"],
                question.question_id.0.as_str()
            );
            let identity: Value = serde_json::from_str(
                failed_row
                    .outcome_json
                    .as_deref()
                    .expect("applied fork identity remains on the row"),
            )
            .expect("fork identity JSON");
            assert_eq!(identity["kind"], "answered_fork");
            assert_eq!(identity["question_id"], question.question_id.0.as_str());
            assert_eq!(identity["question_revision"], question.question_revision);
            assert_eq!(identity["selection_revision"], selection.revision);
            assert_eq!(identity["facts_digest"], selection.facts_digest);
        }

        #[test]
        fn answered_fork_then_malformed_reply_replaces_decision_blocker() {
            let (mut world, session, task) = plan_world("semantic-fork-malformed", &PLAN_CRITERIA);
            let request = material(&world, &task);
            select(&mut world, &session, &request, &[]);
            let config = semantic_config("");
            let mut call_count = 0;
            let (mut broker, log) = scripted(move |_, inputs| {
                let call = call_count;
                call_count += 1;
                match call {
                    0 => Ok(reply(
                        json!({ "contracts": notes_from(inputs), "fork": fork_json() }).to_string(),
                    )),
                    1 => Ok(reply("not a semantic reply".to_string())),
                    _ => Ok(reply(
                        json!({ "contracts": notes_from(inputs) }).to_string(),
                    )),
                }
            });
            let forked = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::DesignContracts(request.clone()),
            )
            .expect("fork");
            let ActionOutcome::Forked { resolution, .. } = forked else {
                panic!("expected a fork, got {forked:?}");
            };
            let ActionOutcome::Asked { question, .. } = *resolution else {
                panic!("expected a pending question");
            };
            world
                .runtime
                .store_writer()
                .answer_question(
                    &session,
                    &task,
                    &question.question_id,
                    question.question_revision,
                    &AnswerSelection::Option {
                        option_id: OptionId("b".to_string()),
                    },
                    "human",
                )
                .expect("answer");
            let failed = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::DesignContracts(request.clone()),
            )
            .expect_err("the next reply is malformed");
            assert_eq!(
                refusal(failed, DESIGN_CONTRACTS),
                SemanticRefusal::Malformed {
                    class: serde_json::error::Category::Syntax,
                }
            );
            let failed_row = row(&world, &task, DESIGN_CONTRACTS);
            assert_eq!(failed_row.execution, ObligationExecution::Pending);
            let identity: Value = serde_json::from_str(
                failed_row
                    .outcome_json
                    .as_deref()
                    .expect("applied fork identity remains on the row"),
            )
            .expect("fork identity JSON");
            assert_eq!(identity["kind"], "answered_fork");
            assert_eq!(identity["question_id"], question.question_id.0.as_str());
            assert_eq!(
                failed_row.blocker,
                Some(plan_blocker(ErrorCode::DependencyBlocked, DESIGN_CONTRACTS))
            );
            assert!(
                world
                    .runtime
                    .store()
                    .current_question(&task)
                    .expect("question read")
                    .is_none()
            );
            assert!(matches!(gate(&world, &task), PlanGate::Paused { .. }));
            assert_eq!(calls(&log).len(), 2);
            let retried = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::DesignContracts(request),
            )
            .expect("the retry keeps the applied answer after malformed output");
            assert!(matches!(retried, ActionOutcome::Designed { .. }));
            let sent = calls(&log);
            assert_eq!(sent.len(), 3);
            let third_inputs: Value =
                serde_json::from_str(&sent[2].inputs).expect("third manifest inputs");
            assert_eq!(
                third_inputs["fork_answer"],
                json!({ "kind": "option", "option_id": "b" })
            );
        }

        #[test]
        fn later_pending_fork_waits_after_prior_answer() {
            let (mut world, session, task) = plan_world("semantic-fork-sequence", &PLAN_CRITERIA);
            let request = material(&world, &task);
            select(&mut world, &session, &request, &[]);
            let config = semantic_config("");
            let mut call_count = 0;
            let (mut broker, log) = scripted(move |_, inputs| {
                let call = call_count;
                call_count += 1;
                let body = if call < 2 {
                    json!({ "contracts": notes_from(inputs), "fork": fork_json() })
                } else {
                    json!({ "contracts": notes_from(inputs) })
                };
                Ok(reply(body.to_string()))
            });

            let first = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::DesignContracts(request.clone()),
            )
            .expect("first fork");
            let ActionOutcome::Forked { resolution, .. } = first else {
                panic!("expected the first fork, got {first:?}");
            };
            let ActionOutcome::Asked {
                question: first_question,
                ..
            } = *resolution
            else {
                panic!("ask mode publishes the first fork");
            };
            world
                .runtime
                .store_writer()
                .answer_question(
                    &session,
                    &task,
                    &first_question.question_id,
                    first_question.question_revision,
                    &AnswerSelection::Option {
                        option_id: OptionId("b".to_string()),
                    },
                    "human",
                )
                .expect("first fork answer");

            let second = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::DesignContracts(request.clone()),
            )
            .expect("second fork");
            let ActionOutcome::Forked { resolution, .. } = second else {
                panic!("expected the second fork, got {second:?}");
            };
            let ActionOutcome::Asked {
                question: second_question,
                ..
            } = *resolution
            else {
                panic!("ask mode publishes the second fork");
            };
            assert_ne!(second_question.question_id, first_question.question_id);
            let sent = calls(&log);
            assert_eq!(sent.len(), 2);
            let second_inputs: Value =
                serde_json::from_str(&sent[1].inputs).expect("second manifest inputs");
            assert_eq!(
                second_inputs["fork_answer"],
                json!({ "kind": "option", "option_id": "b" })
            );

            let third = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::DesignContracts(request),
            )
            .expect("a pending second fork spends no call");
            assert_eq!(skipped(&third), Some(SkipReason::NeedsInformation));
            assert_eq!(calls(&log).len(), 2);
            let (current, _) = world
                .runtime
                .store()
                .current_question(&task)
                .expect("question read")
                .expect("second fork stays pending");
            assert_eq!(current.question_id, second_question.question_id);
        }

        fn fork_json() -> Value {
            let option = |id: &str| json!({ "id": id, "label": format!("contract {id}"), "consequences": format!("callers follow {id}") });
            json!({
                "prompt": "Which token rotation contract ships?",
                "options": [
                    option("a"),
                    option("b"),
                    option("c"),
                    option("d"),
                    { "id": "e", "label": "contract e", "consequences": "none", "disabled_reason": "needs a migration" }
                ],
                "recommended": "a",
                "basis": "least caller churn"
            })
        }

        #[test]
        fn design_fork_waits_on_a_versioned_question_and_its_answer_feeds_the_next_call() {
            let (mut world, session, task) = plan_world("semantic-fork", &PLAN_CRITERIA);
            let request = material(&world, &task);
            let selection = select(&mut world, &session, &request, &[]);
            let expected_criteria = criterion_ids(&world, &task);
            let config = semantic_config("");
            let (mut broker, log) = scripted(|_, inputs| {
                let body = match inputs["fork_answer"]["option_id"].as_str() {
                    None => json!({ "contracts": notes_from(inputs), "fork": fork_json() }),
                    Some(chosen) => json!({ "contracts": [
                        { "surface": "auth", "text": format!("contract {chosen} for auth") },
                        { "surface": "public_api", "text": format!("contract {chosen} for public_api") }
                    ] }),
                };
                Ok(reply(body.to_string()))
            });

            let mut seam = BrokerSeam {
                broker: &mut broker,
                world: WORLD,
            };
            let forked = ActionRegistry::new()
                .execute_with_seam(
                    ActionInput::DesignContracts(request.clone()),
                    &mut action_ctx(&mut world, &session, &config),
                    Some(&mut seam),
                )
                .expect("registry dispatch publishes the fork");
            let ActionOutcome::Forked { action, resolution } = forked else {
                panic!("expected a fork, got {forked:?}");
            };
            assert_eq!(action, DESIGN_CONTRACTS);
            let ActionOutcome::Asked { question, .. } = *resolution else {
                panic!("ask mode publishes the fork");
            };
            assert_eq!(question.question_revision, 1);
            assert_eq!(question.options.len(), 5);
            let (current, _) = world
                .runtime
                .store()
                .current_question(&task)
                .expect("read")
                .expect("one pending question");
            assert_eq!(current, question);
            let waiting = row(&world, &task, DESIGN_CONTRACTS);
            assert_eq!(waiting.execution, ObligationExecution::Pending);
            assert_eq!(
                waiting.blocker,
                Some(Blocker {
                    reason: ErrorCode::DependencyBlocked,
                    owner: "plan".to_string(),
                    condition: ResumeCondition::Decision {
                        question_id: question.question_id.clone(),
                        revision: 1,
                    },
                })
            );
            assert_eq!(plan_snapshot(&world, &task).lifecycle, Lifecycle::Waiting);

            let still = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::DesignContracts(request.clone()),
            )
            .expect("a skip");
            assert_eq!(skipped(&still), Some(SkipReason::NeedsInformation));
            assert_eq!(calls(&log).len(), 1, "a pending fork spends nothing");

            world
                .runtime
                .store_writer()
                .answer_question(
                    &session,
                    &task,
                    &question.question_id,
                    1,
                    &AnswerSelection::Option {
                        option_id: OptionId("b".to_string()),
                    },
                    "human",
                )
                .expect("answer");
            let designed = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::DesignContracts(request),
            )
            .expect("design");
            let ActionOutcome::Designed { contracts } = designed else {
                panic!("expected contracts, got {designed:?}");
            };
            assert_eq!(contracts[0].text, "contract b for auth");
            let sent = calls(&log);
            assert_eq!(sent.len(), 2);
            assert_manifest_selection(&sent[0], &task, &selection, &expected_criteria);
            assert_manifest_selection(&sent[1], &task, &selection, &expected_criteria);
            let inputs = |manifest: &RequestManifest| -> Value {
                serde_json::from_str(&manifest.inputs).expect("inputs")
            };
            assert_eq!(inputs(&sent[0])["fork_answer"], Value::Null);
            assert_eq!(
                inputs(&sent[1])["fork_answer"],
                json!({ "kind": "option", "option_id": "b" })
            );
            let closed = row(&world, &task, DESIGN_CONTRACTS);
            assert_eq!(closed.execution, ObligationExecution::Satisfied);
            assert_eq!(closed.blocker, None);
            assert_eq!(provider_calls(&world), 0);

            let auto_task = submit_plan_task(
                &mut world,
                &session,
                "cmd-semantic-fork-auto",
                "Rotate session tokens.",
                &PLAN_CRITERIA,
            );
            let mut delegated = material(&world, &auto_task);
            delegated.delegation = Some(Delegation {
                action: RESOLVE_DECISION.to_string(),
                task_id: auto_task.clone(),
            });
            delegated.author = Some(DecisionAuthor::Agent);
            let auto_selection = select(&mut world, &session, &delegated, &[]);
            let auto_criteria = criterion_ids(&world, &auto_task);
            let auto_config = semantic_config("[decisions]\nmode = \"auto\"\n");
            let (mut auto_broker, auto_log) = scripted(|_, inputs| {
                let body = if inputs["fork_answer"].is_null() {
                    json!({ "contracts": notes_from(inputs), "fork": fork_json() })
                } else {
                    json!({ "contracts": [
                        { "surface": "auth", "text": "delegated contract" },
                        { "surface": "public_api", "text": "delegated contract" }
                    ] })
                };
                Ok(reply(body.to_string()))
            });
            let delegated_fork = run_with(
                &mut world,
                &session,
                &auto_config,
                &mut auto_broker,
                ActionInput::DesignContracts(delegated.clone()),
            )
            .expect("delegated fork");
            let ActionOutcome::Forked { resolution, .. } = delegated_fork else {
                panic!("expected a delegated fork, got {delegated_fork:?}");
            };
            assert!(
                matches!(*resolution, ActionOutcome::Answered { author, .. } if author == "agent"),
                "only the caller's typed delegation and author permit auto"
            );
            assert!(matches!(
                row(&world, &auto_task, DESIGN_CONTRACTS).blocker,
                Some(Blocker {
                    condition: ResumeCondition::Decision { .. },
                    ..
                })
            ));
            let after_auto = run_with(
                &mut world,
                &session,
                &auto_config,
                &mut auto_broker,
                ActionInput::DesignContracts(delegated),
            )
            .expect("the answer feeds a later invocation");
            assert!(matches!(after_auto, ActionOutcome::Designed { .. }));
            let auto_sent = calls(&auto_log);
            assert_eq!(auto_sent.len(), 2);
            assert_manifest_selection(&auto_sent[0], &auto_task, &auto_selection, &auto_criteria);
            assert_manifest_selection(&auto_sent[1], &auto_task, &auto_selection, &auto_criteria);
            assert_eq!(
                serde_json::from_str::<Value>(&auto_sent[1].inputs).expect("inputs")["fork_answer"]
                    ["option_id"],
                "a"
            );
            let ask_task = submit_plan_task(
                &mut world,
                &session,
                "cmd-semantic-fork-undelegated-auto",
                "Rotate session tokens.",
                &PLAN_CRITERIA,
            );
            let mut undelegated = material(&world, &ask_task);
            undelegated.author = Some(DecisionAuthor::Agent);
            let undelegated_selection = select(&mut world, &session, &undelegated, &[]);
            let undelegated_criteria = criterion_ids(&world, &ask_task);
            let surfaced = run_with(
                &mut world,
                &session,
                &auto_config,
                &mut auto_broker,
                ActionInput::DesignContracts(undelegated),
            )
            .expect("undelegated auto asks");
            assert!(
                matches!(
                    surfaced,
                    ActionOutcome::Forked { resolution, .. }
                        if matches!(*resolution, ActionOutcome::Asked { .. })
                ),
                "auto without caller delegation never answers the material choice"
            );
            assert_eq!(calls(&auto_log).len(), 3);
            let auto_sent = calls(&auto_log);
            assert_eq!(auto_sent.len(), 3);
            assert_manifest_selection(
                &auto_sent[2],
                &ask_task,
                &undelegated_selection,
                &undelegated_criteria,
            );

            let reselection_task = submit_plan_task(
                &mut world,
                &session,
                "cmd-semantic-fork-reselection",
                "Rotate session tokens.",
                &PLAN_CRITERIA,
            );
            let original = material(&world, &reselection_task);
            let original_selection = select(&mut world, &session, &original, &[]);
            let selection_criteria = criterion_ids(&world, &reselection_task);
            let mut call_count = 0;
            let (mut reselection_broker, reselection_log) = scripted(move |_, inputs| {
                let body = if call_count < 2 {
                    call_count += 1;
                    json!({ "contracts": notes_from(inputs), "fork": fork_json() })
                } else {
                    assert!(
                        inputs["fork_answer"].is_null(),
                        "a superseded answer binds nowhere"
                    );
                    json!({ "contracts": notes_from(inputs) })
                };
                Ok(reply(body.to_string()))
            });
            let reselection_fork = run_with(
                &mut world,
                &session,
                &config,
                &mut reselection_broker,
                ActionInput::DesignContracts(original.clone()),
            )
            .expect("fork before reselection");
            let ActionOutcome::Forked {
                resolution: original_resolution,
                ..
            } = reselection_fork
            else {
                panic!("expected a pending fork");
            };
            let ActionOutcome::Asked {
                question: original_question,
                ..
            } = *original_resolution
            else {
                panic!("ask mode publishes the original fork");
            };
            let mut changed = original.clone();
            changed.parts[0].proof = "cargo test --test schema-v2".to_string();
            let changed_selection = select(&mut world, &session, &changed, &[]);
            assert_ne!(changed_selection.revision, original_selection.revision);
            assert_ne!(
                changed_selection.facts_digest,
                original_selection.facts_digest
            );
            assert_eq!(
                row(&world, &reselection_task, DESIGN_CONTRACTS).blocker,
                Some(plan_blocker(
                    ErrorCode::CapabilityUnavailable,
                    DESIGN_CONTRACTS
                )),
                "reselection drops the old Decision blocker"
            );
            assert!(
                world
                    .runtime
                    .store()
                    .current_question(&reselection_task)
                    .expect("question read")
                    .is_none(),
                "reselection supersedes the old fork"
            );
            assert_eq!(
                plan_snapshot(&world, &reselection_task).lifecycle,
                Lifecycle::Blocked
            );
            let stale_answer = world
                .runtime
                .store_writer()
                .answer_question(
                    &session,
                    &reselection_task,
                    &original_question.question_id,
                    original_question.question_revision,
                    &AnswerSelection::Option {
                        option_id: OptionId("b".to_string()),
                    },
                    "human",
                )
                .expect_err("a superseded fork cannot be answered");
            assert!(matches!(
                stale_answer,
                StoreError::Conflict(ConflictCause::QuestionNotPending)
            ));
            let answer_attempts = world
                .runtime
                .store()
                .answer_attempts(&reselection_task)
                .expect("answer attempts");
            assert_eq!(answer_attempts.len(), 1);
            assert_eq!(
                answer_attempts[0].outcome,
                rivect::contracts::AnswerAttemptOutcome::Denied
            );
            assert_eq!(
                answer_attempts[0].denial.as_deref(),
                Some("replayed_answer")
            );
            let feed = world
                .runtime
                .store()
                .events_after(&session, Some(&reselection_task), 0, 100)
                .expect("task feed");
            let superseded: Vec<_> = feed
                .iter()
                .filter(|event| event.event_type == "question.superseded")
                .collect();
            assert_eq!(superseded.len(), 1);
            assert_eq!(superseded[0].aggregate_id, original_question.question_id.0);

            let fresh_fork = run_with(
                &mut world,
                &session,
                &config,
                &mut reselection_broker,
                ActionInput::DesignContracts(changed),
            )
            .expect("the new selection can publish its own fork");
            let ActionOutcome::Forked { action, resolution } = fresh_fork else {
                panic!("expected a dispatched decision fork, got {fresh_fork:?}");
            };
            assert_eq!(action, DESIGN_CONTRACTS);
            let ActionOutcome::Asked {
                question: fresh_question,
                ..
            } = *resolution
            else {
                panic!("the new selection asks for its own decision");
            };
            assert_ne!(fresh_question.question_id, original_question.question_id);
            let (current, _) = world
                .runtime
                .store()
                .current_question(&reselection_task)
                .expect("question read")
                .expect("fresh fork is pending");
            assert_eq!(current.question_id, fresh_question.question_id);
            assert_eq!(
                row(&world, &reselection_task, DESIGN_CONTRACTS).blocker,
                Some(Blocker {
                    reason: ErrorCode::DependencyBlocked,
                    owner: "plan".to_string(),
                    condition: ResumeCondition::Decision {
                        question_id: fresh_question.question_id.clone(),
                        revision: fresh_question.question_revision,
                    },
                })
            );
            let reselection_sent = calls(&reselection_log);
            assert_eq!(reselection_sent.len(), 2);
            assert_manifest_selection(
                &reselection_sent[0],
                &reselection_task,
                &original_selection,
                &selection_criteria,
            );
            assert_manifest_selection(
                &reselection_sent[1],
                &reselection_task,
                &changed_selection,
                &selection_criteria,
            );
            for manifest in &reselection_sent {
                assert_eq!(
                    serde_json::from_str::<Value>(&manifest.inputs).expect("inputs")["fork_answer"],
                    Value::Null
                );
            }

            let refused_task = submit_plan_task(
                &mut world,
                &session,
                "cmd-semantic-fork-foreign-block",
                "Rotate session tokens.",
                &PLAN_CRITERIA,
            );
            let refused_request = material(&world, &refused_task);
            select(&mut world, &session, &refused_request, &[]);
            world
                .runtime
                .store_writer()
                .mark_no_ready(&refused_task)
                .expect("a foreign blocker");
            let (mut refused_broker, refused_log) = scripted(|_, inputs| {
                Ok(reply(
                    json!({ "contracts": notes_from(inputs), "fork": fork_json() }).to_string(),
                ))
            });
            let refused = run_with(
                &mut world,
                &session,
                &config,
                &mut refused_broker,
                ActionInput::DesignContracts(refused_request),
            )
            .expect_err("a fork cannot clear a foreign block");
            assert_eq!(refused.error_code(), ErrorCode::Conflict);
            assert_eq!(calls(&refused_log).len(), 1);
            assert_eq!(
                world
                    .runtime
                    .store()
                    .current_question(&refused_task)
                    .expect("question read"),
                None
            );
            assert_eq!(
                row(&world, &refused_task, DESIGN_CONTRACTS).blocker,
                Some(plan_blocker(ErrorCode::DependencyBlocked, DESIGN_CONTRACTS))
            );
            assert_eq!(
                row(&world, &refused_task, DESIGN_CONTRACTS).execution,
                ObligationExecution::Pending
            );
        }

        #[test]
        fn challenge_direction_fork_reselection_supersedes_only_owned_question() {
            let (mut world, session, task) =
                plan_world("semantic-challenge-reselection", &PLAN_CRITERIA);
            let original = material(&world, &task);
            let original_selection = select(&mut world, &session, &original, &[]);
            let expected_criteria = criterion_ids(&world, &task);
            let config = semantic_config("");
            let (mut broker, log) = scripted(|_, inputs| {
                Ok(reply(
                    json!({ "risks": notes_from(inputs), "fork": fork_json() }).to_string(),
                ))
            });

            let forked = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::ChallengeDirection(original.clone()),
            )
            .expect("challenge direction publishes a fork");
            let ActionOutcome::Forked { action, resolution } = forked else {
                panic!("expected a challenge fork, got {forked:?}");
            };
            assert_eq!(action, CHALLENGE_DIRECTION);
            let ActionOutcome::Asked {
                question: original_question,
                ..
            } = *resolution
            else {
                panic!("ask mode publishes the original challenge fork");
            };

            let mut changed = original.clone();
            changed.parts[0].proof = "cargo test --test challenge-v2".to_string();
            let changed_selection = select(&mut world, &session, &changed, &[]);
            assert_ne!(changed_selection.revision, original_selection.revision);
            assert_ne!(
                changed_selection.facts_digest,
                original_selection.facts_digest
            );
            assert!(
                world
                    .runtime
                    .store()
                    .current_question(&task)
                    .expect("question read")
                    .is_none(),
                "selection change supersedes the challenge fork"
            );
            let late_answer = world
                .runtime
                .store_writer()
                .answer_question(
                    &session,
                    &task,
                    &original_question.question_id,
                    original_question.question_revision,
                    &AnswerSelection::Option {
                        option_id: OptionId("b".to_string()),
                    },
                    "human",
                )
                .expect_err("a superseded challenge fork cannot be answered");
            assert!(matches!(
                late_answer,
                StoreError::Conflict(ConflictCause::QuestionNotPending)
            ));
            let attempts = world
                .runtime
                .store()
                .answer_attempts(&task)
                .expect("answer attempts");
            assert_eq!(attempts.len(), 1);
            assert_eq!(
                attempts[0].outcome,
                rivect::contracts::AnswerAttemptOutcome::Denied
            );
            assert_eq!(attempts[0].denial.as_deref(), Some("replayed_answer"));

            let fresh = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::ChallengeDirection(changed.clone()),
            )
            .expect("the changed selection publishes a fresh challenge fork");
            let ActionOutcome::Forked { action, resolution } = fresh else {
                panic!("expected a fresh challenge fork, got {fresh:?}");
            };
            assert_eq!(action, CHALLENGE_DIRECTION);
            let ActionOutcome::Asked {
                question: fresh_question,
                ..
            } = *resolution
            else {
                panic!("the changed selection asks its own challenge question");
            };
            assert_ne!(fresh_question.question_id, original_question.question_id);
            let (current, _) = world
                .runtime
                .store()
                .current_question(&task)
                .expect("question read")
                .expect("fresh challenge fork is pending");
            assert_eq!(current.question_id, fresh_question.question_id);
            assert_eq!(
                row(&world, &task, CHALLENGE_DIRECTION).blocker,
                Some(Blocker {
                    reason: ErrorCode::DependencyBlocked,
                    owner: "plan".to_string(),
                    condition: ResumeCondition::Decision {
                        question_id: fresh_question.question_id.clone(),
                        revision: fresh_question.question_revision,
                    },
                })
            );
            let sent = calls(&log);
            assert_eq!(sent.len(), 2);
            assert_manifest_selection(&sent[0], &task, &original_selection, &expected_criteria);
            assert_manifest_selection(&sent[1], &task, &changed_selection, &expected_criteria);

            let challenge_feed = world
                .runtime
                .store()
                .events_after(&session, Some(&task), 0, 100)
                .expect("challenge task feed");
            let challenge_superseded: Vec<_> = challenge_feed
                .iter()
                .filter(|event| event.event_type == "question.superseded")
                .collect();
            assert_eq!(challenge_superseded.len(), 1);
            assert_eq!(
                challenge_superseded[0].aggregate_id,
                original_question.question_id.0
            );

            let direct_task = submit_plan_task(
                &mut world,
                &session,
                "cmd-semantic-direct-question",
                "Rotate session tokens.",
                &PLAN_CRITERIA,
            );
            let direct_question = world.publish(&session, &direct_task);
            let direct_request = material(&world, &direct_task);
            let original_direct_selection = select(&mut world, &session, &direct_request, &[]);
            let mut changed_direct = direct_request;
            changed_direct.parts[0].proof = "cargo test --test direct-v2".to_string();
            let changed_direct_selection = select(&mut world, &session, &changed_direct, &[]);
            assert_ne!(
                changed_direct_selection.revision,
                original_direct_selection.revision
            );
            assert_ne!(
                changed_direct_selection.facts_digest,
                original_direct_selection.facts_digest
            );
            let (current, _) = world
                .runtime
                .store()
                .current_question(&direct_task)
                .expect("direct question read")
                .expect("direct controller question survives selection change");
            assert_eq!(current.question_id, direct_question.question_id);

            let direct_feed = world
                .runtime
                .store()
                .events_after(&session, Some(&direct_task), 0, 100)
                .expect("direct task feed");
            assert!(
                direct_feed
                    .iter()
                    .all(|event| event.event_type != "question.superseded"),
                "selection changes never supersede a direct controller question"
            );
            let published: Vec<_> = direct_feed
                .iter()
                .filter(|event| event.event_type == "question.published")
                .collect();
            assert_eq!(published.len(), 1);
            assert_eq!(
                published[0].delta["question_id"],
                direct_question.question_id.0.as_str()
            );
        }

        #[test]
        fn per_purpose_instruction_sets_open_distinct_context_epochs() {
            let config = semantic_config("");
            let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
            let decision = broker
                .prepare(CHALLENGE_DIRECTION, &config, WORLD, "inputs")
                .expect("decision core");
            assert_eq!(
                decision.instructions,
                "You are the Rivect decision core. The only permitted action is one scoped file read; request it as `read <path>` on its own line."
            );
            assert_eq!(decision.tools, vec!["read_file".to_string()]);
            assert_eq!(
                decision.wire_bytes(),
                concat!(
                    "You are the Rivect decision core. The only permitted action is one scoped file read; request it as `read <path>` on its own line.\n",
                    "model: auto\n",
                    "tools: read_file\n",
                    "output-reserve: 16384\n\ninputs"
                )
            );
            assert!(matches!(decision.model, ModelAssign::Auto { .. }));
            assert_eq!(decision.effort, EffortAssign::Auto);
            assert!(broker.cancel_attempt(&decision.attempt_id));
            let challenge = CallContract {
                instructions: "challenge the direction",
                tools: &[],
            };
            let design = CallContract {
                instructions: "design the contracts",
                tools: &[],
            };
            let first = broker
                .prepare_call(CHALLENGE_DIRECTION, &config, WORLD, "inputs", &challenge)
                .expect("challenge");
            let again = broker
                .prepare_call(
                    CHALLENGE_DIRECTION,
                    &config,
                    WORLD,
                    "other inputs",
                    &challenge,
                )
                .expect("challenge again");
            assert_eq!(
                first.epoch_id, again.epoch_id,
                "an unchanged prefix replays"
            );
            assert_eq!(again.mutation_reason, None);
            assert_ne!(
                first.epoch_id, decision.epoch_id,
                "the purpose's instruction set opens its own epoch"
            );
            assert!(broker.cancel_attempt(&first.attempt_id));
            assert!(broker.cancel_attempt(&again.attempt_id));
            let designed = broker
                .prepare_call(CHALLENGE_DIRECTION, &config, WORLD, "inputs", &design)
                .expect("another instruction set");
            assert_ne!(designed.epoch_id, first.epoch_id);
            let other_purpose = broker
                .prepare_call(DESIGN_CONTRACTS, &config, WORLD, "inputs", &design)
                .expect("design");
            assert_ne!(other_purpose.epoch_id, designed.epoch_id);
            assert!(broker.cancel_attempt(&designed.attempt_id));
            assert!(broker.cancel_attempt(&other_purpose.attempt_id));
            assert_eq!(broker.admitted_attempts(), 0);
        }

        #[test]
        fn semantic_legs_call_only_the_injected_loopback_provider_one_send_parsed_reply() {
            let (mut world, session, task) = plan_world("semantic-loopback", &PLAN_CRITERIA);
            let request = material(&world, &task);
            select(&mut world, &session, &request, &[]);
            let config = semantic_config("");
            let (mut broker, sent, loopback_sends) = loopback_recording_broker();
            assert_eq!(
                row(&world, &task, CHALLENGE_DIRECTION).execution,
                ObligationExecution::Pending
            );

            let outcome = run_with(
                &mut world,
                &session,
                &config,
                &mut broker,
                ActionInput::ChallengeDirection(request),
            )
            .expect("the injected loopback provider returns a semantic reply");
            let ActionOutcome::Challenged { risks } = outcome else {
                panic!("expected a parsed challenge reply, got {outcome:?}");
            };
            assert_eq!(
                risks,
                vec![
                    SurfaceNote {
                        surface: Surface::Auth,
                        text: "Rotate session tokens. :: auth".to_string(),
                    },
                    SurfaceNote {
                        surface: Surface::PublicApi,
                        text: "Rotate session tokens. :: public_api".to_string(),
                    },
                ]
            );

            let sent = calls(&sent);
            assert_eq!(sent.len(), 1, "exactly one request crossed the seam");
            let manifest = &sent[0];
            assert!(!manifest.attempt_id.is_empty());
            assert!(!manifest.inputs_digest.is_empty());
            assert_eq!(manifest.purpose, CHALLENGE_DIRECTION);
            assert!(manifest.instructions.contains(CHALLENGE_DIRECTION));
            assert!(manifest.tools.is_empty());
            assert!(
                matches!(
                    &manifest.model,
                    ModelAssign::Auto { pool: Some(pool) } if pool.len() == 1 && pool[0] == "local"
                ),
                "the manifest names no provider dialect id: {manifest:?}"
            );
            assert_eq!(loopback_sends.load(Ordering::SeqCst), 1);

            let stored = row(&world, &task, CHALLENGE_DIRECTION);
            assert_eq!(stored.execution, ObligationExecution::Satisfied);
            assert_eq!(stored.blocker, None);
            let stored_outcome: Value = serde_json::from_str(
                stored
                    .outcome_json
                    .as_deref()
                    .expect("the parsed reply closes its row"),
            )
            .expect("the closed row stores its parsed reply");
            assert_eq!(stored_outcome["attempt_id"], manifest.attempt_id);
            assert_eq!(
                stored_outcome["notes"],
                json!([
                    {"surface": "auth", "text": "Rotate session tokens. :: auth"},
                    {"surface": "public_api", "text": "Rotate session tokens. :: public_api"}
                ])
            );
            assert_eq!(broker.accounted_requests(), 1);
            assert_eq!(broker.admitted_attempts(), 0);
            assert_eq!(
                provider_calls(&world),
                0,
                "runtime provider stays untouched"
            );
        }
    }
}
