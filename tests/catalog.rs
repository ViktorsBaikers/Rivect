//! AC-030: each of the 32 semantic capability rows executes its own positive
//! trigger with typed inputs and a real handler outcome, and a separate
//! negative control shows justified non-applicability without extra work.
//! The four groups run in G1-G4 order, and the 32-row conjunction is the last
//! case: no row is covered by a name alone and no `Implementation::Unavailable`
//! row counts as done.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    reason = "test assertions fail loudly with the observed row or verdict (standards §12)"
)]

mod support;

use rivect::actions::{
    ASSESS_EXPERIENCE, ASSESS_PERFORMANCE, ASSESS_PLAN, ASSESS_READINESS, ASSESS_SECURITY,
    AUDIT_TESTS, AUTHOR_TEST, ActionError, ActionInput, ActionOutcome, ActionRegistry,
    AssessExperienceInput, AssessPerformanceInput, AssessReadinessInput, AssessSecurityInput,
    AuditTestsInput, AuthorTestInput, BrokerSeam, CHALLENGE_DIRECTION, CandidateEvidence,
    ChangeMode, CheckKind, CheckResult, ContractBasis, DELIVER_CHANGE, DESIGN_CONTRACTS,
    DIAGNOSE_HARNESS, DIAGNOSE_ISSUE, DecisionAuthor, Delegation, DeliverChangeInput,
    DiagnoseHarnessInput, DiagnoseIssueInput, DiagnosisObservation, EXPLAIN_RESULT,
    ExperienceSurface, ExplainResultInput, ExplanationClaim, FRAME_GOAL, FindingStatus,
    HarnessComponent, HarnessSignal, IMPLEMENT_CHANGE, IMPROVE_PROCEDURE, INSPECT_SYSTEM,
    ImplementChangeInput, Implementation, ImproveProcedureInput, InspectSystemInput, Journey,
    Measurement, OBSERVE_OUTCOME, ObservationSample, ObserveOutcomeInput, PLAN_WORK,
    PREPARE_DELIVERY, PREPARE_ENVIRONMENT, PREPARE_HANDOFF, PlanRequest, PrepareDeliveryInput,
    PrepareEnvironmentInput, PrepareHandoffInput, RECONCILE_FINDINGS, REFACTOR_STRUCTURE,
    REPAIR_APPROACH, REPRODUCE_ISSUE, RESEARCH_EVIDENCE, RESOLVE_DECISION, REVIEW_CHANGE,
    ReconcileFinding, ReconcileFindingsInput, RefactorStructureInput, RepairApproachInput,
    ReproduceIssueInput, ResearchEvidenceInput, ResolveDecisionInput, ReviewChangeInput,
    ReviewFinding, SkipReason, Surface, SurfaceScan, TEST_ASSUMPTION, TestAssumptionInput,
    VALIDATE_CHANGE, VALIDATE_INTEGRATION, ValidateChangeInput, ValidateIntegrationInput, WorkPart,
};
use rivect::config::{
    Config, Connection, SHIPPED_BASE_VERSION, SHIPPED_DEFAULTS_TOML, shipped_revision,
};
use rivect::contracts::{
    ActionId, Blocker, DeliveryCandidate, DeliveryIntent, DeliveryOutcome, EffectClass, ErrorCode,
    ObligationExecution, Question, ResumeCondition, SessionId, TaskId,
};
use rivect::model::Broker;
use rivect::providers::{Provider, ProviderError, ProviderReply};
use rivect::resources::UsageDelta;
use rivect::verification::{CheckObservation, ExpectedResult, SetupGapCause};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;
use support::World;

fn config() -> Config {
    Config::parse_validated(&support::base_config()).expect("catalog config parses")
}

struct Fixture {
    world: World,
    session: SessionId,
    config: Config,
}

impl Fixture {
    fn open(tag: &str) -> Self {
        let mut world = support::open_world(tag, None);
        let session = world.open_session("catalog-session");
        Self {
            world,
            session,
            config: config(),
        }
    }

    fn task(&mut self, command_id: &str) -> TaskId {
        self.world.create_task(&self.session, command_id)
    }

    fn run(&mut self, input: ActionInput) -> Result<ActionOutcome, ActionError> {
        let Fixture {
            world,
            session,
            config,
        } = self;
        ActionRegistry::new().execute(input, &mut world.runtime.action_context(session, config))
    }

    fn select(&mut self, request: &PlanRequest) -> rivect::actions::Selection {
        let Fixture {
            world,
            session,
            config,
        } = self;
        ActionRegistry::new()
            .select(
                request,
                &[],
                &mut world.runtime.action_context(session, config),
            )
            .expect("the selection records")
    }

    fn evidence(&mut self, task: &TaskId, scope: &str) -> String {
        self.world
            .runtime
            .store_writer()
            .materialize_obligations(task)
            .expect("obligations materialize");
        self.world
            .runtime
            .store_writer()
            .insert_evidence_for_task(task, scope, "observed evidence", "digest")
            .expect("evidence records");
        self.world
            .runtime
            .store()
            .evidence_for_task(task)
            .expect("evidence reads")
            .into_iter()
            .next()
            .expect("one evidence row")
            .evidence_id
            .0
    }
}

fn criterion_ids(fixture: &Fixture, task: &TaskId) -> Vec<rivect::contracts::CriterionId> {
    fixture
        .world
        .runtime
        .store()
        .snapshot(task)
        .expect("snapshot")
        .criteria
        .items
        .into_iter()
        .map(|criterion| criterion.id)
        .collect()
}

fn part(id: &str, criteria: &[rivect::contracts::CriterionId], proof: &str) -> WorkPart {
    WorkPart {
        id: id.to_string(),
        criteria: criteria.to_vec(),
        depends_on: Vec::new(),
        proof: proof.to_string(),
    }
}

fn request(
    task: &TaskId,
    kind: rivect::actions::RequestKind,
    surfaces: &[Surface],
    contract: ContractBasis,
    parts: Vec<WorkPart>,
) -> PlanRequest {
    PlanRequest {
        task_id: task.clone(),
        kind,
        surfaces: SurfaceScan::from_labels(surfaces.iter().map(|surface| surface.as_str())),
        contract,
        parts,
        delegation: None,
        author: None,
    }
}

/// An approved local change with one part covering the task's criteria: the
/// selection weighs the execution rows, the framework stages stay closed.
fn approved_local(fixture: &Fixture, task: &TaskId) -> PlanRequest {
    let criteria = criterion_ids(fixture, task);
    request(
        task,
        rivect::actions::RequestKind::Change,
        &[Surface::Local],
        ContractBasis::Approved,
        vec![part("only", &criteria, "cargo test --test catalog")],
    )
}

/// A plan-only request whose single part covers the task's criteria.
fn plan_only(fixture: &Fixture, task: &TaskId) -> PlanRequest {
    let criteria = criterion_ids(fixture, task);
    request(
        task,
        rivect::actions::RequestKind::PlanOnly,
        &[Surface::Local],
        ContractBasis::Absent,
        vec![part("only", &criteria, "cargo test --test catalog")],
    )
}

/// A material request: an absent contract over a risky surface.
fn material(fixture: &Fixture, task: &TaskId) -> PlanRequest {
    let criteria = criterion_ids(fixture, task);
    request(
        task,
        rivect::actions::RequestKind::Change,
        &[Surface::Auth],
        ContractBasis::Absent,
        vec![part("only", &criteria, "cargo test --test auth")],
    )
}

fn decision_input(
    task: &TaskId,
    options: Vec<rivect::contracts::QuestionOption>,
) -> ResolveDecisionInput {
    let question = Question::fixture(task, 1);
    ResolveDecisionInput {
        task_id: task.clone(),
        prompt: question.prompt,
        options,
        recommended_option_id: question.recommended_option_id,
        recommendation_basis: question.recommendation_basis,
        delegation: None,
        author: None,
    }
}

fn check(
    name: &str,
    kind: CheckKind,
    exit_code: i32,
    selected: Option<u64>,
    output_bytes: u64,
) -> CheckResult {
    CheckResult {
        name: name.to_string(),
        kind,
        exit_code,
        selected,
        output_bytes,
    }
}

fn assumption(
    task: &TaskId,
    check_id: &str,
    expected: ExpectedResult,
    observation: CheckObservation,
) -> TestAssumptionInput {
    TestAssumptionInput {
        task_id: task.clone(),
        check_id: check_id.to_string(),
        expected_result: expected,
        assertion: "the catalog row observes its own predicate".to_string(),
        observation,
    }
}

// ----- scripted Broker purposes (offline, no provider or credential call) -----

struct Scripted;

impl Provider for Scripted {
    fn name(&self) -> &'static str {
        "catalog-scripted"
    }

    fn serves(&self, _connection: &str, _entry: &Connection) -> bool {
        true
    }

    fn send(
        &mut self,
        manifest: &rivect::model::RequestManifest,
    ) -> Result<ProviderReply, ProviderError> {
        let inputs: Value =
            serde_json::from_str(&manifest.inputs).expect("manifest inputs are json");
        let body = match manifest.purpose.as_str() {
            CHALLENGE_DIRECTION => json!({ "risks": notes(&inputs) }),
            DESIGN_CONTRACTS => json!({ "contracts": notes(&inputs) }),
            ASSESS_PLAN => json!({
                "verdict": "pass",
                "findings": [format!("revision {} is feasible", inputs["plan"]["revision"])],
            }),
            other => panic!("unexpected purpose {other}"),
        };
        Ok(ProviderReply {
            text: body.to_string(),
            tool_calls: Vec::new(),
            usage: UsageDelta::Unknown,
            wire_retries: 0,
        })
    }
}

fn notes(inputs: &Value) -> Vec<Value> {
    let goal = inputs["goal"].as_str().expect("goal");
    inputs["surfaces"]
        .as_array()
        .expect("surfaces")
        .iter()
        .filter(|surface| *surface != "local")
        .map(|surface| {
            let label = surface.as_str().expect("surface label");
            json!({ "surface": label, "text": format!("{goal} :: {label}") })
        })
        .collect()
}

fn semantic_config(purpose: &str) -> Config {
    Config::parse_validated(&format!(
        "{}\n[models.purposes.{purpose}]\nmodel = {{ mode = \"fixed\", connection = \"local\", model_id = \"fixture-model\" }}\neffort = {{ mode = \"fixed\", value = \"high\" }}\nfallback = {{ mode = \"off\" }}\n",
        support::config_distinct_pools()
    ))
    .expect("semantic catalog config parses")
}

// ----- delivery fixture: local destination, real grant, real candidate -----

fn delivery_intent(scope: &Path, grant: &str) -> (DeliveryIntent, Vec<u8>) {
    let destination = scope.join("delivered-base.toml");
    std::fs::write(&destination, b"the previous release bytes").expect("seed destination");
    let bytes = SHIPPED_DEFAULTS_TOML.as_bytes().to_vec();
    (
        DeliveryIntent {
            candidate: DeliveryCandidate {
                base_version: SHIPPED_BASE_VERSION,
                digest: shipped_revision(),
            },
            destination: destination.to_str().expect("utf-8 destination").to_string(),
            grant_id: grant.to_string(),
            admission_seq: None,
        },
        bytes,
    )
}

fn prepare_delivery(
    fixture: &mut Fixture,
    task: &TaskId,
) -> (tempfile::TempDir, ActionOutcome, DeliveryIntent, Vec<u8>) {
    support::ensure_helper();
    let scope = tempfile::TempDir::with_prefix("rivect-catalog-delivery-").expect("delivery scope");
    let grant = fixture
        .world
        .runtime
        .policy_writer()
        .grant_classes(scope.path().to_path_buf(), vec![EffectClass::Write]);
    let (intent, bytes) = delivery_intent(scope.path(), &grant);
    let outcome = fixture
        .run(ActionInput::PrepareDelivery(PrepareDeliveryInput {
            task_id: task.clone(),
            intent,
        }))
        .expect("the delivery prepares");
    let prepared = match &outcome {
        ActionOutcome::DeliveryPrepared { intent, .. } => intent.clone(),
        other => panic!("expected DeliveryPrepared, got {other:?}"),
    };
    (scope, outcome, prepared, bytes)
}

/// A real write grant over one local fixture scope, the same admission the
/// decisions fixture issues before an environment restore is requested.
fn environment_scope(
    fixture: &mut Fixture,
    tag: &str,
) -> (tempfile::TempDir, std::path::PathBuf, String) {
    let scope = tempfile::TempDir::with_prefix(tag).expect("environment scope");
    let target = scope.path().join("fixture.json");
    std::fs::write(&target, b"stale fixture").expect("seed environment fixture");
    let grant = fixture
        .world
        .runtime
        .policy_writer()
        .grant_classes(scope.path().to_path_buf(), vec![EffectClass::Write]);
    (scope, target, grant)
}

// ----- per-row positive triggers (shared by the group cases and the conjunction) -----

fn positive(fixture: &mut Fixture, action: &'static str) -> ActionOutcome {
    match action {
        FRAME_GOAL => {
            let task = fixture.task("catalog-frame");
            let request = request(
                &task,
                rivect::actions::RequestKind::Change,
                &[Surface::Local],
                ContractBasis::Absent,
                Vec::new(),
            );
            fixture.select(&request);
            fixture
                .run(ActionInput::FrameGoal(request))
                .expect("frame_goal runs")
        }
        INSPECT_SYSTEM => fixture
            .run(ActionInput::InspectSystem(InspectSystemInput::default()))
            .expect("inspect_system runs"),
        RESEARCH_EVIDENCE => {
            let task = fixture.task("catalog-research");
            fixture.evidence(&task, "docs");
            fixture
                .run(ActionInput::ResearchEvidence(ResearchEvidenceInput {
                    task_id: task,
                    scope: "docs".to_string(),
                }))
                .expect("research_evidence runs")
        }
        RESOLVE_DECISION => {
            let task = fixture.task("catalog-decision");
            let question = Question::fixture(&task, 1);
            fixture
                .run(ActionInput::ResolveDecision(decision_input(
                    &task,
                    question.options,
                )))
                .expect("resolve_decision runs")
        }
        CHALLENGE_DIRECTION => {
            let task = fixture.task("catalog-challenge");
            let request = material(fixture, &task);
            fixture.select(&request);
            fixture
                .run(ActionInput::FrameGoal(request.clone()))
                .expect("frame");
            let config = semantic_config(CHALLENGE_DIRECTION);
            let mut broker = Broker::new(Box::new(Scripted));
            let Fixture { world, session, .. } = fixture;
            let mut seam = BrokerSeam {
                broker: &mut broker,
                world: "/world/catalog",
            };
            ActionRegistry::new()
                .execute_with_seam(
                    ActionInput::ChallengeDirection(request),
                    &mut world.runtime.action_context(session, &config),
                    Some(&mut seam),
                )
                .expect("challenge_direction runs")
        }
        DESIGN_CONTRACTS => {
            let task = fixture.task("catalog-design");
            let request = material(fixture, &task);
            fixture.select(&request);
            fixture
                .run(ActionInput::FrameGoal(request.clone()))
                .expect("frame");
            let config = semantic_config(DESIGN_CONTRACTS);
            let mut broker = Broker::new(Box::new(Scripted));
            let Fixture { world, session, .. } = fixture;
            let mut seam = BrokerSeam {
                broker: &mut broker,
                world: "/world/catalog",
            };
            ActionRegistry::new()
                .execute_with_seam(
                    ActionInput::DesignContracts(request),
                    &mut world.runtime.action_context(session, &config),
                    Some(&mut seam),
                )
                .expect("design_contracts runs")
        }
        PLAN_WORK => {
            let task = fixture.task("catalog-plan");
            let request = plan_only(fixture, &task);
            fixture.select(&request);
            fixture
                .run(ActionInput::PlanWork(request))
                .expect("plan_work runs")
        }
        ASSESS_PLAN => {
            let task = fixture.task("catalog-assess-plan");
            let request = plan_only(fixture, &task);
            fixture.select(&request);
            fixture
                .run(ActionInput::PlanWork(request.clone()))
                .expect("plan");
            let config = semantic_config(ASSESS_PLAN);
            let mut broker = Broker::new(Box::new(Scripted));
            let Fixture { world, session, .. } = fixture;
            let mut seam = BrokerSeam {
                broker: &mut broker,
                world: "/world/catalog",
            };
            ActionRegistry::new()
                .execute_with_seam(
                    ActionInput::AssessPlan(request),
                    &mut world.runtime.action_context(session, &config),
                    Some(&mut seam),
                )
                .expect("assess_plan runs")
        }
        TEST_ASSUMPTION => {
            let task = fixture.task("catalog-assumption");
            fixture
                .run(ActionInput::TestAssumption(assumption(
                    &task,
                    "check-pass",
                    ExpectedResult::Pass,
                    CheckObservation::Passed,
                )))
                .expect("test_assumption runs")
        }
        REPRODUCE_ISSUE => {
            let task = fixture.task("catalog-reproduce");
            fixture
                .run(ActionInput::ReproduceIssue(ReproduceIssueInput {
                    task_id: task,
                    check_id: "check-repro".to_string(),
                    assertion: "the defect reproduces".to_string(),
                    observation: CheckObservation::Failed,
                }))
                .expect("reproduce_issue runs")
        }
        DIAGNOSE_ISSUE => {
            let task = fixture.task("catalog-diagnose");
            fixture
                .run(ActionInput::DiagnoseIssue(DiagnoseIssueInput {
                    task_id: task,
                    symptom: "the write times out".to_string(),
                    observations: vec![
                        DiagnosisObservation {
                            hypothesis: "deadlock".to_string(),
                            signal: String::new(),
                        },
                        DiagnosisObservation {
                            hypothesis: "slow disk".to_string(),
                            signal: "fsync takes 4s".to_string(),
                        },
                    ],
                }))
                .expect("diagnose_issue runs")
        }
        PREPARE_ENVIRONMENT => {
            let task = fixture.task("catalog-environment");
            fixture
                .run(ActionInput::TestAssumption(assumption(
                    &task,
                    "check-gap",
                    ExpectedResult::Pass,
                    CheckObservation::SetupGap(SetupGapCause::MissingFixture),
                )))
                .expect("setup gap records");
            let (_scope, target, grant) = environment_scope(fixture, "rivect-catalog-environment-");
            let outcome = fixture
                .run(ActionInput::PrepareEnvironment(PrepareEnvironmentInput {
                    task_id: task,
                    check_id: "check-gap".to_string(),
                    grant_id: grant.clone(),
                    target: target.clone(),
                    replacement: b"restored".to_vec(),
                }))
                .expect("prepare_environment runs");
            let ActionOutcome::EnvironmentRequested { restore, original } = &outcome else {
                panic!("expected EnvironmentRequested, got {outcome:?}");
            };
            assert_eq!(
                restore.grant_id, grant,
                "the request carries the issued grant"
            );
            assert_eq!(restore.target, target);
            assert_eq!(
                original.classification,
                rivect::verification::AssumptionClassification::SetupGap(
                    SetupGapCause::MissingFixture
                )
            );
            outcome
        }
        AUTHOR_TEST => {
            let task = fixture.task("catalog-author");
            fixture
                .run(ActionInput::AuthorTest(AuthorTestInput {
                    task_id: task,
                    mode: ChangeMode::Behavior,
                    check_id: "check-authored".to_string(),
                    expected: ExpectedResult::Fail,
                    red_observed: true,
                    baseline: None,
                }))
                .expect("author_test runs")
        }
        IMPLEMENT_CHANGE => {
            let task = fixture.task("catalog-implement");
            let request = approved_local(fixture, &task);
            fixture.select(&request);
            fixture
                .run(ActionInput::ImplementChange(ImplementChangeInput {
                    request,
                    parts: vec!["only".to_string()],
                }))
                .expect("implement_change runs")
        }
        REFACTOR_STRUCTURE => {
            let task = fixture.task("catalog-refactor");
            fixture
                .run(ActionInput::RefactorStructure(RefactorStructureInput {
                    task_id: task,
                    requested: true,
                    baseline: "cargo test --test catalog".to_string(),
                    weakened_tests: Vec::new(),
                }))
                .expect("refactor_structure runs")
        }
        VALIDATE_CHANGE => {
            let task = fixture.task("catalog-validate");
            fixture
                .run(ActionInput::ValidateChange(ValidateChangeInput {
                    task_id: task,
                    checks: vec![
                        check("clippy", CheckKind::Static, 0, None, 0),
                        check("catalog", CheckKind::Tests, 0, Some(12), 640),
                    ],
                }))
                .expect("validate_change runs")
        }
        AUDIT_TESTS => {
            let task = fixture.task("catalog-audit");
            let request = approved_local(fixture, &task);
            fixture.select(&request);
            fixture
                .run(ActionInput::AuditTests(AuditTestsInput {
                    request,
                    killed: true,
                    alternative_accepted: true,
                }))
                .expect("audit_tests runs")
        }
        REVIEW_CHANGE => {
            let task = fixture.task("catalog-review");
            let request = request(
                &task,
                rivect::actions::RequestKind::Audit,
                &[Surface::Local],
                ContractBasis::Approved,
                Vec::new(),
            );
            fixture.select(&request);
            fixture
                .run(ActionInput::ReviewChange(ReviewChangeInput {
                    request,
                    findings: vec![
                        ReviewFinding {
                            axis: "spec".to_string(),
                            basis: "criterion one".to_string(),
                            text: "criterion one is served".to_string(),
                        },
                        ReviewFinding {
                            axis: "standards".to_string(),
                            basis: "error handling review".to_string(),
                            text: "errors stay typed".to_string(),
                        },
                    ],
                }))
                .expect("review_change runs")
        }
        ASSESS_SECURITY => {
            let task = fixture.task("catalog-security");
            let request = request(
                &task,
                rivect::actions::RequestKind::Change,
                &[Surface::Secrets],
                ContractBasis::Approved,
                vec![part(
                    "only",
                    &criterion_ids(fixture, &task),
                    "cargo test --test catalog",
                )],
            );
            fixture.select(&request);
            fixture
                .run(ActionInput::AssessSecurity(AssessSecurityInput {
                    request,
                    checks: vec![rivect::actions::SecurityCheck {
                        surface: Surface::Secrets,
                        negative_check: "a rounded-trip secret never logs".to_string(),
                        confidence: "observed on the fixture".to_string(),
                    }],
                }))
                .expect("assess_security runs")
        }
        ASSESS_PERFORMANCE => {
            let task = fixture.task("catalog-performance");
            fixture
                .run(ActionInput::AssessPerformance(AssessPerformanceInput {
                    task_id: task,
                    load: "catalog fixture workload".to_string(),
                    baseline: Measurement {
                        samples: 100,
                        nanos: 1_000,
                    },
                    candidate: Measurement {
                        samples: 100,
                        nanos: 900,
                    },
                }))
                .expect("assess_performance runs")
        }
        ASSESS_EXPERIENCE => {
            let task = fixture.task("catalog-experience");
            fixture
                .run(ActionInput::AssessExperience(AssessExperienceInput {
                    task_id: task,
                    surface: ExperienceSurface::Cli,
                    journeys: vec![Journey {
                        entered: "rivect status --json".to_string(),
                        exit_code: 0,
                        output_bytes: 512,
                    }],
                    screenshot: false,
                }))
                .expect("assess_experience runs")
        }
        VALIDATE_INTEGRATION => {
            let task = fixture.task("catalog-integration");
            fixture
                .run(ActionInput::ValidateIntegration(ValidateIntegrationInput {
                    task_id: task,
                    candidate: CandidateEvidence {
                        digest: "candidate-digest".to_string(),
                        consumers: vec!["controller".to_string(), "cli".to_string()],
                        compatibility: vec!["backward".to_string()],
                    },
                    local_passes: vec!["cargo test --test catalog".to_string()],
                }))
                .expect("validate_integration runs")
        }
        RECONCILE_FINDINGS => {
            let task = fixture.task("catalog-reconcile");
            fixture
                .run(ActionInput::ReconcileFindings(ReconcileFindingsInput {
                    task_id: task,
                    findings: vec![
                        ReconcileFinding {
                            id: "f1".to_string(),
                            status: FindingStatus::Confirmed,
                        },
                        ReconcileFinding {
                            id: "f2".to_string(),
                            status: FindingStatus::Refuted,
                        },
                        ReconcileFinding {
                            id: "f3".to_string(),
                            status: FindingStatus::Stale,
                        },
                        ReconcileFinding {
                            id: "f4".to_string(),
                            status: FindingStatus::Duplicate,
                        },
                    ],
                }))
                .expect("reconcile_findings runs")
        }
        REPAIR_APPROACH => {
            let task = fixture.task("catalog-repair");
            let criteria = criterion_ids(fixture, &task);
            let request = request(
                &task,
                rivect::actions::RequestKind::Change,
                &[Surface::Local],
                ContractBasis::Approved,
                vec![
                    part("first", &criteria, "cargo test --test catalog"),
                    part("second", &criteria, "cargo test --test catalog"),
                ],
            );
            fixture
                .run(ActionInput::RepairApproach(RepairApproachInput {
                    request,
                    part: "second".to_string(),
                    replacement: part("second", &criteria, "cargo test --test catalog"),
                }))
                .expect("repair_approach runs")
        }
        ASSESS_READINESS => {
            let task = fixture.task("catalog-readiness");
            let request = approved_local(fixture, &task);
            fixture.select(&request);
            fixture
                .run(ActionInput::ImplementChange(ImplementChangeInput {
                    request: request.clone(),
                    parts: vec!["only".to_string()],
                }))
                .expect("implement_change runs");
            fixture
                .run(ActionInput::AuditTests(AuditTestsInput {
                    request: request.clone(),
                    killed: true,
                    alternative_accepted: true,
                }))
                .expect("audit_tests runs");
            fixture
                .run(ActionInput::AssessReadiness(AssessReadinessInput {
                    request,
                }))
                .expect("assess_readiness runs")
        }
        EXPLAIN_RESULT => {
            let task = fixture.task("catalog-explain");
            let evidence = fixture.evidence(&task, "docs");
            fixture
                .run(ActionInput::ExplainResult(ExplainResultInput {
                    task_id: task,
                    claims: vec![ExplanationClaim {
                        text: "the catalog row ran".to_string(),
                        evidence: Some(evidence),
                    }],
                }))
                .expect("explain_result runs")
        }
        PREPARE_DELIVERY => {
            let task = fixture.task("catalog-prepare-delivery");
            let (_scope, outcome, _, _) = prepare_delivery(fixture, &task);
            outcome
        }
        DELIVER_CHANGE => {
            let task = fixture.task("catalog-deliver");
            let request = request(
                &task,
                rivect::actions::RequestKind::Deliver,
                &[Surface::Local],
                ContractBasis::Approved,
                Vec::new(),
            );
            fixture.select(&request);
            let (_scope, _, intent, bytes) = prepare_delivery(fixture, &task);
            fixture
                .run(ActionInput::DeliverChange(DeliverChangeInput {
                    request,
                    intent,
                    candidate: bytes,
                }))
                .expect("deliver_change runs")
        }
        OBSERVE_OUTCOME => {
            let task = fixture.task("catalog-observe");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after the epoch")
                .as_secs();
            fixture
                .run(ActionInput::ObserveOutcome(ObserveOutcomeInput {
                    task_id: task,
                    budget_end_unix: now + 600,
                    samples: vec![ObservationSample {
                        signal: "latency returned to baseline".to_string(),
                    }],
                }))
                .expect("observe_outcome runs")
        }
        PREPARE_HANDOFF => {
            let task = fixture.task("catalog-handoff");
            fixture
                .run(ActionInput::PrepareHandoff(PrepareHandoffInput {
                    task_id: task,
                }))
                .expect("prepare_handoff runs")
        }
        IMPROVE_PROCEDURE => {
            let task = fixture.task("catalog-procedure");
            let request = plan_only(fixture, &task);
            fixture.select(&request);
            fixture
                .run(ActionInput::PlanWork(request))
                .expect("plan_work runs");
            let outcome = fixture
                .run(ActionInput::ImproveProcedure(ImproveProcedureInput {
                    task_id: task,
                }))
                .expect("improve_procedure runs");
            let ActionOutcome::ProcedureImproved { segment, .. } = &outcome else {
                panic!("expected ProcedureImproved, got {outcome:?}");
            };
            assert_eq!(
                fixture
                    .world
                    .runtime
                    .store()
                    .procedure_segment(&segment.procedure_id)
                    .expect("the saved segment reads back"),
                *segment,
                "the outcome is the segment the store owns"
            );
            outcome
        }
        DIAGNOSE_HARNESS => {
            let task = fixture.task("catalog-harness");
            fixture
                .run(ActionInput::DiagnoseHarness(DiagnoseHarnessInput {
                    task_id: task,
                    fault: HarnessComponent::Adapter,
                    signals: vec![HarnessSignal {
                        component: HarnessComponent::Adapter,
                        signal: "the codec returned a 400 on a valid body".to_string(),
                    }],
                }))
                .expect("diagnose_harness runs")
        }
        other => panic!("no positive trigger for {other}"),
    }
}

/// The row one success-shaped positive outcome belongs to: a skip or a
/// non-success payload (an unready verdict, a validation gap, a user-code
/// harness "diagnosis", an unknown delivery) proves no row.
fn observed_row(outcome: &ActionOutcome) -> &'static str {
    match outcome {
        ActionOutcome::Asked { .. } | ActionOutcome::Answered { .. } => RESOLVE_DECISION,
        ActionOutcome::Inspected(_) => INSPECT_SYSTEM,
        ActionOutcome::Framed { .. } => FRAME_GOAL,
        ActionOutcome::Planned { .. } => PLAN_WORK,
        ActionOutcome::Assessed(assessment)
            if assessment.verdict == rivect::state::PlanVerdict::Pass =>
        {
            ASSESS_PLAN
        }
        ActionOutcome::Judged {
            verdict: rivect::actions::SemanticVerdict::Pass,
            ..
        } => ASSESS_PLAN,
        ActionOutcome::Challenged { .. } => CHALLENGE_DIRECTION,
        ActionOutcome::Designed { .. } => DESIGN_CONTRACTS,
        ActionOutcome::AssumptionTested(record)
            if record.classification
                == rivect::verification::AssumptionClassification::Confirmed =>
        {
            TEST_ASSUMPTION
        }
        ActionOutcome::EnvironmentRequested { .. } => PREPARE_ENVIRONMENT,
        ActionOutcome::Researched { .. } => RESEARCH_EVIDENCE,
        ActionOutcome::Reproduced { .. } => REPRODUCE_ISSUE,
        ActionOutcome::Diagnosed { .. } => DIAGNOSE_ISSUE,
        ActionOutcome::TestAuthored { .. } => AUTHOR_TEST,
        ActionOutcome::Implemented { .. } => IMPLEMENT_CHANGE,
        ActionOutcome::RefactorPlanned { .. } => REFACTOR_STRUCTURE,
        ActionOutcome::Validated { gaps, .. } if gaps.is_empty() => VALIDATE_CHANGE,
        ActionOutcome::Audited { .. } => AUDIT_TESTS,
        ActionOutcome::Reviewed { .. } => REVIEW_CHANGE,
        ActionOutcome::SecurityAssessed { .. } => ASSESS_SECURITY,
        ActionOutcome::PerformanceAssessed { .. } => ASSESS_PERFORMANCE,
        ActionOutcome::ExperienceAssessed { .. } => ASSESS_EXPERIENCE,
        ActionOutcome::IntegrationValidated { .. } => VALIDATE_INTEGRATION,
        ActionOutcome::Reconciled { .. } => RECONCILE_FINDINGS,
        ActionOutcome::ApproachRepaired { .. } => REPAIR_APPROACH,
        ActionOutcome::Readiness { ready: true, .. } => ASSESS_READINESS,
        ActionOutcome::Explained { .. } => EXPLAIN_RESULT,
        ActionOutcome::DeliveryPrepared { .. } => PREPARE_DELIVERY,
        ActionOutcome::Delivered { receipt, .. }
            if receipt.applied && receipt.outcome != DeliveryOutcome::Unknown =>
        {
            DELIVER_CHANGE
        }
        ActionOutcome::Observed { .. } => OBSERVE_OUTCOME,
        ActionOutcome::Handoff { .. } => PREPARE_HANDOFF,
        ActionOutcome::ProcedureImproved { .. } => IMPROVE_PROCEDURE,
        ActionOutcome::HarnessDiagnosed { component, .. }
            if *component != HarnessComponent::UserCode =>
        {
            DIAGNOSE_HARNESS
        }
        ActionOutcome::Skipped { .. } => "skipped",
        ActionOutcome::Forked { .. } => "forked",
        _ => "not-a-success",
    }
}

/// The durable attempt a positive outcome recorded, when the row carries one.
fn attempt_id(outcome: &ActionOutcome) -> Option<&str> {
    match outcome {
        ActionOutcome::Researched { attempt_id, .. }
        | ActionOutcome::Reproduced { attempt_id, .. }
        | ActionOutcome::Diagnosed { attempt_id, .. }
        | ActionOutcome::TestAuthored { attempt_id, .. }
        | ActionOutcome::Implemented { attempt_id, .. }
        | ActionOutcome::RefactorPlanned { attempt_id, .. }
        | ActionOutcome::Validated { attempt_id, .. }
        | ActionOutcome::Audited { attempt_id, .. }
        | ActionOutcome::Reviewed { attempt_id, .. }
        | ActionOutcome::SecurityAssessed { attempt_id, .. }
        | ActionOutcome::PerformanceAssessed { attempt_id, .. }
        | ActionOutcome::ExperienceAssessed { attempt_id, .. }
        | ActionOutcome::IntegrationValidated { attempt_id, .. }
        | ActionOutcome::Reconciled { attempt_id, .. }
        | ActionOutcome::ApproachRepaired { attempt_id, .. }
        | ActionOutcome::Explained { attempt_id, .. }
        | ActionOutcome::DeliveryPrepared { attempt_id, .. }
        | ActionOutcome::Delivered { attempt_id, .. }
        | ActionOutcome::Observed { attempt_id, .. }
        | ActionOutcome::Handoff { attempt_id, .. }
        | ActionOutcome::ProcedureImproved { attempt_id, .. }
        | ActionOutcome::HarnessDiagnosed { attempt_id, .. } => Some(attempt_id),
        ActionOutcome::Readiness { attempt_id, .. } => attempt_id.as_deref(),
        _ => None,
    }
}

fn skip_reason(fixture: &mut Fixture, action: &'static str, input: ActionInput) -> SkipReason {
    match fixture.run(input) {
        Ok(ActionOutcome::Skipped {
            action: skipped,
            reason,
        }) => {
            assert_eq!(skipped, action, "the negative control skipped another row");
            reason
        }
        Ok(other) => panic!("the negative control produced a positive outcome: {other:?}"),
        Err(error) => panic!("the negative control refused instead of skipping: {error}"),
    }
}

fn refused(fixture: &mut Fixture, input: ActionInput) -> ErrorCode {
    match fixture.run(input) {
        Ok(other) => panic!("the negative control produced an outcome: {other:?}"),
        Err(error) => error.error_code(),
    }
}

/// The typed refusal one negative control produced: a code alone does not
/// prove which rule declined the input.
fn refusal(fixture: &mut Fixture, input: ActionInput) -> ActionError {
    match fixture.run(input) {
        Ok(other) => panic!("the negative control produced an outcome: {other:?}"),
        Err(error) => error,
    }
}

/// Runs the row's negative control; every arm is a justified
/// non-applicability, and a positive outcome fails the case.
fn negative(fixture: &mut Fixture, action: &'static str) -> &'static str {
    match action {
        FRAME_GOAL => {
            let task = fixture.task("catalog-neg-frame");
            let request = approved_local(fixture, &task);
            fixture.select(&request);
            let reason = skip_reason(fixture, action, ActionInput::FrameGoal(request));
            assert_eq!(reason, SkipReason::AlreadySatisfied);
        }
        INSPECT_SYSTEM => {
            let task = fixture.task("catalog-neg-inspect");
            let session = fixture.session.clone();
            let revision = fixture
                .world
                .runtime
                .store()
                .snapshot(&task)
                .expect("snapshot")
                .intent_revision;
            fixture
                .world
                .runtime
                .store_writer()
                .cancel_task(&session, &task, revision, Some("catalog negative control"))
                .expect("the task cancels");
            let outcome = fixture
                .run(ActionInput::InspectSystem(InspectSystemInput {
                    budget_ms: None,
                    task_id: Some(task),
                }))
                .expect("inspect_system reports the refusal");
            let ActionOutcome::Inspected(report) = outcome else {
                panic!("expected Inspected, got {outcome:?}");
            };
            assert!(
                report.detected.is_empty(),
                "a cancelled probe serves no fabricated row"
            );
            assert!(
                report.systems.iter().any(|system| matches!(
                    system.outcome,
                    rivect::actions::ProbeOutcome::Unanswered { .. }
                )),
                "the refusal is reported with its wire class"
            );
        }
        RESEARCH_EVIDENCE => {
            let task = fixture.task("catalog-neg-research");
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::ResearchEvidence(ResearchEvidenceInput {
                    task_id: task,
                    scope: "docs".to_string(),
                }),
            );
            assert_eq!(reason, SkipReason::NeedsInformation);
        }
        RESOLVE_DECISION => {
            let task = fixture.task("catalog-neg-decision");
            let question = Question::fixture(&task, 1);
            let mut input = decision_input(&task, question.options);
            input.delegation = Some(Delegation {
                action: RESOLVE_DECISION.to_string(),
                task_id: task,
            });
            input.author = Some(DecisionAuthor::Human);
            let auto = Config::parse_validated(&format!(
                "{}\n[decisions]\nmode = \"auto\"\n",
                support::base_config()
            ))
            .expect("auto catalog config parses");
            let Fixture { world, session, .. } = fixture;
            let error = ActionRegistry::new()
                .execute(
                    ActionInput::ResolveDecision(input),
                    &mut world.runtime.action_context(session, &auto),
                )
                .expect_err("the row never consents for a human");
            assert!(
                matches!(error, ActionError::AutoImpersonatesHuman),
                "a human-attributed auto answer is not this row: {error:?}"
            );
            assert_eq!(error.error_code(), ErrorCode::Denied);
        }
        CHALLENGE_DIRECTION | DESIGN_CONTRACTS => {
            let task = fixture.task("catalog-neg-purpose");
            let request = approved_local(fixture, &task);
            fixture.select(&request);
            let input = if action == CHALLENGE_DIRECTION {
                ActionInput::ChallengeDirection(request)
            } else {
                ActionInput::DesignContracts(request)
            };
            let reason = skip_reason(fixture, action, input);
            assert_eq!(reason, SkipReason::AlreadySatisfied);
            // A still-required purpose row without a broker seam stays an
            // exact capability refusal, never a local template.
            let task = fixture.task("catalog-neg-purpose-unavailable");
            let request = material(fixture, &task);
            fixture.select(&request);
            let input = if action == CHALLENGE_DIRECTION {
                ActionInput::ChallengeDirection(request)
            } else {
                ActionInput::DesignContracts(request)
            };
            let code = refused(fixture, input);
            assert_eq!(code, ErrorCode::CapabilityUnavailable);
        }
        PLAN_WORK => {
            let task = fixture.task("catalog-neg-plan");
            let request = approved_local(fixture, &task);
            fixture.select(&request);
            let reason = skip_reason(fixture, action, ActionInput::PlanWork(request));
            assert_eq!(reason, SkipReason::NotNeeded);
        }
        ASSESS_PLAN => {
            let task = fixture.task("catalog-neg-assess-plan");
            let request = plan_only(fixture, &task);
            fixture.select(&request);
            let reason = skip_reason(fixture, action, ActionInput::AssessPlan(request));
            assert_eq!(reason, SkipReason::NeedsInformation);
        }
        TEST_ASSUMPTION => {
            let task = fixture.task("catalog-neg-assumption");
            let outcome = fixture
                .run(ActionInput::TestAssumption(assumption(
                    &task,
                    "check-gap",
                    ExpectedResult::Pass,
                    CheckObservation::SetupGap(SetupGapCause::MissingFixture),
                )))
                .expect("the setup gap records");
            let ActionOutcome::AssumptionTested(record) = outcome else {
                panic!("expected AssumptionTested, got {outcome:?}");
            };
            assert_eq!(
                record.classification,
                rivect::verification::AssumptionClassification::SetupGap(
                    SetupGapCause::MissingFixture
                ),
                "a setup gap is never a product result"
            );
            assert!(
                record.boundary_id.is_some(),
                "the setup gap keeps its own retained evidence"
            );
        }
        REPRODUCE_ISSUE => {
            let task = fixture.task("catalog-neg-reproduce");
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::ReproduceIssue(ReproduceIssueInput {
                    task_id: task,
                    check_id: "check-repro".to_string(),
                    assertion: "the defect reproduces".to_string(),
                    observation: CheckObservation::SetupGap(SetupGapCause::MissingExecutable),
                }),
            );
            assert_eq!(reason, SkipReason::NeedsInformation);
        }
        DIAGNOSE_ISSUE => {
            let task = fixture.task("catalog-neg-diagnose");
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::DiagnoseIssue(DiagnoseIssueInput {
                    task_id: task,
                    symptom: "the write times out".to_string(),
                    observations: vec![
                        DiagnosisObservation {
                            hypothesis: "deadlock".to_string(),
                            signal: String::new(),
                        },
                        DiagnosisObservation {
                            hypothesis: "slow disk".to_string(),
                            signal: "   ".to_string(),
                        },
                    ],
                }),
            );
            assert_eq!(reason, SkipReason::NeedsInformation);
        }
        PREPARE_ENVIRONMENT => {
            let task = fixture.task("catalog-neg-environment");
            fixture
                .run(ActionInput::TestAssumption(assumption(
                    &task,
                    "check-pass",
                    ExpectedResult::Pass,
                    CheckObservation::Passed,
                )))
                .expect("the completed check records");
            let (_scope, target, grant) =
                environment_scope(fixture, "rivect-catalog-neg-environment-");
            let error = refusal(
                fixture,
                ActionInput::PrepareEnvironment(PrepareEnvironmentInput {
                    task_id: task,
                    check_id: "check-pass".to_string(),
                    grant_id: grant,
                    target,
                    replacement: b"restored".to_vec(),
                }),
            );
            assert!(
                matches!(error, ActionError::EnvironmentNotNeeded),
                "a completed check is not a setup gap: {error}"
            );
        }
        AUTHOR_TEST => {
            let task = fixture.task("catalog-neg-author");
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::AuthorTest(AuthorTestInput {
                    task_id: task,
                    mode: ChangeMode::Typo,
                    check_id: "check-typo".to_string(),
                    expected: ExpectedResult::Pass,
                    red_observed: false,
                    baseline: None,
                }),
            );
            assert_eq!(reason, SkipReason::NotNeeded);
        }
        IMPLEMENT_CHANGE => {
            let task = fixture.task("catalog-neg-implement");
            let request = plan_only(fixture, &task);
            fixture.select(&request);
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::ImplementChange(ImplementChangeInput {
                    request,
                    parts: vec!["only".to_string()],
                }),
            );
            assert_eq!(reason, SkipReason::NotNeeded);
        }
        REFACTOR_STRUCTURE => {
            let task = fixture.task("catalog-neg-refactor");
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::RefactorStructure(RefactorStructureInput {
                    task_id: task,
                    requested: false,
                    baseline: "cargo test --test catalog".to_string(),
                    weakened_tests: Vec::new(),
                }),
            );
            assert_eq!(reason, SkipReason::NotNeeded);
        }
        VALIDATE_CHANGE => {
            let task = fixture.task("catalog-neg-validate");
            let outcome = fixture
                .run(ActionInput::ValidateChange(ValidateChangeInput {
                    task_id: task,
                    checks: vec![check("catalog", CheckKind::Tests, 0, Some(0), 128)],
                }))
                .expect("the zero selection is evaluated");
            let ActionOutcome::Validated { gaps, .. } = outcome else {
                panic!("expected Validated, got {outcome:?}");
            };
            assert_eq!(
                gaps,
                vec![rivect::actions::ValidationGap::ZeroSelection {
                    name: "catalog".to_string()
                }],
                "an exit 0 with an empty selection is a gap, never success"
            );
        }
        AUDIT_TESTS => {
            let task = fixture.task("catalog-neg-audit");
            let request = plan_only(fixture, &task);
            fixture.select(&request);
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::AuditTests(AuditTestsInput {
                    request,
                    killed: true,
                    alternative_accepted: true,
                }),
            );
            assert_eq!(reason, SkipReason::NotNeeded);
        }
        REVIEW_CHANGE => {
            let task = fixture.task("catalog-neg-review");
            let request = approved_local(fixture, &task);
            fixture.select(&request);
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::ReviewChange(ReviewChangeInput {
                    request,
                    findings: vec![ReviewFinding {
                        axis: "spec".to_string(),
                        basis: "criterion".to_string(),
                        text: "served".to_string(),
                    }],
                }),
            );
            assert_eq!(reason, SkipReason::NotNeeded);
        }
        ASSESS_SECURITY => {
            let task = fixture.task("catalog-neg-security");
            let request = approved_local(fixture, &task);
            fixture.select(&request);
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::AssessSecurity(AssessSecurityInput {
                    request,
                    checks: Vec::new(),
                }),
            );
            assert_eq!(reason, SkipReason::NotNeeded);
        }
        ASSESS_PERFORMANCE => {
            let task = fixture.task("catalog-neg-performance");
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::AssessPerformance(AssessPerformanceInput {
                    task_id: task,
                    load: "catalog fixture workload".to_string(),
                    baseline: Measurement {
                        samples: 0,
                        nanos: 0,
                    },
                    candidate: Measurement {
                        samples: 100,
                        nanos: 900,
                    },
                }),
            );
            assert_eq!(reason, SkipReason::NeedsInformation);
        }
        ASSESS_EXPERIENCE => {
            let task = fixture.task("catalog-neg-experience");
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::AssessExperience(AssessExperienceInput {
                    task_id: task,
                    surface: ExperienceSurface::Tui,
                    journeys: Vec::new(),
                    screenshot: true,
                }),
            );
            assert_eq!(reason, SkipReason::NeedsInformation);
        }
        VALIDATE_INTEGRATION => {
            let task = fixture.task("catalog-neg-integration");
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::ValidateIntegration(ValidateIntegrationInput {
                    task_id: task,
                    candidate: CandidateEvidence {
                        digest: "candidate-digest".to_string(),
                        consumers: Vec::new(),
                        compatibility: Vec::new(),
                    },
                    local_passes: vec!["cargo test".to_string()],
                }),
            );
            assert_eq!(reason, SkipReason::NeedsInformation);
        }
        RECONCILE_FINDINGS => {
            let task = fixture.task("catalog-neg-reconcile");
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::ReconcileFindings(ReconcileFindingsInput {
                    task_id: task,
                    findings: Vec::new(),
                }),
            );
            assert_eq!(reason, SkipReason::NotNeeded);
        }
        REPAIR_APPROACH => {
            let task = fixture.task("catalog-neg-repair");
            let criteria = criterion_ids(fixture, &task);
            let request = request(
                &task,
                rivect::actions::RequestKind::Change,
                &[Surface::Local],
                ContractBasis::Approved,
                vec![part("only", &criteria, "cargo test --test catalog")],
            );
            let error = refusal(
                fixture,
                ActionInput::RepairApproach(RepairApproachInput {
                    request,
                    part: "only".to_string(),
                    replacement: WorkPart {
                        id: "only".to_string(),
                        criteria: Vec::new(),
                        depends_on: Vec::new(),
                        proof: "cargo test --test catalog".to_string(),
                    },
                }),
            );
            assert!(
                matches!(error, ActionError::RepairDropsCriterion { .. }),
                "a repair that drops a criterion is refused by name: {error}"
            );
        }
        ASSESS_READINESS => {
            let task = fixture.task("catalog-neg-readiness");
            let request = approved_local(fixture, &task);
            fixture.select(&request);
            let outcome = fixture
                .run(ActionInput::AssessReadiness(AssessReadinessInput {
                    request,
                }))
                .expect("readiness reports the remainder");
            let ActionOutcome::Readiness {
                ready,
                mut remaining,
                ..
            } = outcome
            else {
                panic!("expected Readiness, got {outcome:?}");
            };
            assert!(!ready, "an unclosed row is never ready");
            remaining.sort();
            assert_eq!(
                remaining,
                vec![AUDIT_TESTS.to_string(), IMPLEMENT_CHANGE.to_string()],
                "the open rows are the remaining work"
            );
        }
        EXPLAIN_RESULT => {
            let task = fixture.task("catalog-neg-explain");
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::ExplainResult(ExplainResultInput {
                    task_id: task,
                    claims: Vec::new(),
                }),
            );
            assert_eq!(reason, SkipReason::NotNeeded);
            // An unsupported claim is refused by name, never written as prose.
            let task = fixture.task("catalog-neg-explain-unsupported");
            let error = refusal(
                fixture,
                ActionInput::ExplainResult(ExplainResultInput {
                    task_id: task,
                    claims: vec![ExplanationClaim {
                        text: "an unsupported claim".to_string(),
                        evidence: Some("missing-evidence".to_string()),
                    }],
                }),
            );
            assert!(
                matches!(error, ActionError::UnsupportedClaim { index: 0 }),
                "the unsupported claim is refused by name: {error}"
            );
        }
        PREPARE_DELIVERY => {
            let task = fixture.task("catalog-neg-prepare-delivery");
            let scope =
                tempfile::TempDir::with_prefix("rivect-catalog-neg-delivery-").expect("scope");
            let (intent, _) = delivery_intent(scope.path(), "unknown-grant");
            let destination = intent.destination.clone();
            let code = refused(
                fixture,
                ActionInput::PrepareDelivery(PrepareDeliveryInput {
                    task_id: task,
                    intent,
                }),
            );
            assert_eq!(
                code,
                ErrorCode::Denied,
                "an absent grant is a typed denial, not a prepared intent"
            );
            assert_eq!(
                std::fs::read(&destination).expect("the destination still reads"),
                b"the previous release bytes",
                "preparation writes no destination byte"
            );
            assert!(
                fixture
                    .world
                    .runtime
                    .store()
                    .pending_publications()
                    .expect("publications read")
                    .iter()
                    .all(|row| row.target != destination),
                "an absent grant stages no publication journal row"
            );
        }
        DELIVER_CHANGE => {
            let task = fixture.task("catalog-neg-deliver");
            let request = approved_local(fixture, &task);
            fixture.select(&request);
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::DeliverChange(DeliverChangeInput {
                    request,
                    intent: DeliveryIntent {
                        candidate: DeliveryCandidate {
                            base_version: SHIPPED_BASE_VERSION,
                            digest: shipped_revision(),
                        },
                        destination: "/nonexistent/destination".to_string(),
                        grant_id: "unknown-grant".to_string(),
                        admission_seq: None,
                    },
                    candidate: Vec::new(),
                }),
            );
            assert_eq!(reason, SkipReason::NotNeeded);
        }
        OBSERVE_OUTCOME => {
            let task = fixture.task("catalog-neg-observe");
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::ObserveOutcome(ObserveOutcomeInput {
                    task_id: task,
                    budget_end_unix: 0,
                    samples: vec![ObservationSample {
                        signal: "a signal outside the window".to_string(),
                    }],
                }),
            );
            assert_eq!(reason, SkipReason::NeedsInformation);
        }
        PREPARE_HANDOFF => {
            let task = fixture.task("catalog-neg-handoff");
            let session = fixture.session.clone();
            let revision = fixture
                .world
                .runtime
                .store()
                .snapshot(&task)
                .expect("snapshot")
                .intent_revision;
            fixture
                .world
                .runtime
                .store_writer()
                .cancel_task(&session, &task, revision, Some("catalog negative control"))
                .expect("the task cancels");
            fixture.evidence(&task, "catalog");
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::PrepareHandoff(PrepareHandoffInput { task_id: task }),
            );
            assert_eq!(reason, SkipReason::NotNeeded);
        }
        IMPROVE_PROCEDURE => {
            let task = fixture.task("catalog-neg-procedure");
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::ImproveProcedure(ImproveProcedureInput { task_id: task }),
            );
            assert_eq!(reason, SkipReason::NeedsInformation);
        }
        DIAGNOSE_HARNESS => {
            let task = fixture.task("catalog-neg-harness");
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::DiagnoseHarness(DiagnoseHarnessInput {
                    task_id: task,
                    fault: HarnessComponent::UserCode,
                    signals: vec![HarnessSignal {
                        component: HarnessComponent::UserCode,
                        signal: "the user's own handler returns a bad value".to_string(),
                    }],
                }),
            );
            assert_eq!(reason, SkipReason::NotNeeded);
            // A non-user-code fault never attributes a user-code signal.
            let task = fixture.task("catalog-neg-harness-mismatch");
            let reason = skip_reason(
                fixture,
                action,
                ActionInput::DiagnoseHarness(DiagnoseHarnessInput {
                    task_id: task,
                    fault: HarnessComponent::Adapter,
                    signals: vec![HarnessSignal {
                        component: HarnessComponent::UserCode,
                        signal: "the user's own handler returns a bad value".to_string(),
                    }],
                }),
            );
            assert_eq!(reason, SkipReason::NotNeeded);
        }
        other => panic!("no negative control for {other}"),
    }
    action
}

/// Asserts one row's positive leg: a success-shaped outcome of that exact
/// row and, when the outcome records one, a confirmed attempt. A skip or
/// another row's outcome proves nothing, so it is never counted.
fn assert_positive(fixture: &mut Fixture, action: &'static str) {
    let outcome = positive(fixture, action);
    assert_eq!(
        observed_row(&outcome),
        action,
        "{action} produced another row's outcome: {outcome:?}"
    );
    if let Some(attempt) = attempt_id(&outcome) {
        assert_eq!(
            fixture
                .world
                .runtime
                .store()
                .attempt_state(attempt)
                .expect("attempt state reads"),
            Some("confirmed".to_string()),
            "{action} settled its attempt"
        );
    }
}

/// One group's rows run in order: every positive trigger produces its row's
/// typed outcome with a settled attempt, and every negative control skips or
/// refuses on its own justification.
fn run_group(fixture: &mut Fixture, rows: &[&'static str]) -> usize {
    let mut executed = 0;
    for action in rows {
        assert_positive(fixture, action);
        assert_eq!(negative(fixture, action), *action);
        executed += 1;
    }
    executed
}

fn group_fixture(tag: &str) -> Fixture {
    Fixture::open(tag)
}

#[test]
fn group_g1_research_reproduction_and_diagnosis() {
    let mut fixture = group_fixture("catalog-g1");
    let executed = run_group(
        &mut fixture,
        &[RESEARCH_EVIDENCE, REPRODUCE_ISSUE, DIAGNOSE_ISSUE],
    );
    assert_eq!(executed, 3, "every G1 row executed its own case");
}

#[test]
fn group_g2_authoring_implementation_and_review() {
    let mut fixture = group_fixture("catalog-g2");
    let executed = run_group(
        &mut fixture,
        &[
            AUTHOR_TEST,
            IMPLEMENT_CHANGE,
            REFACTOR_STRUCTURE,
            VALIDATE_CHANGE,
            AUDIT_TESTS,
            REVIEW_CHANGE,
        ],
    );
    assert_eq!(executed, 6, "every G2 row executed its own case");
}

#[test]
fn group_g3_assessments_and_reconciliation() {
    let mut fixture = group_fixture("catalog-g3");
    let executed = run_group(
        &mut fixture,
        &[
            ASSESS_SECURITY,
            ASSESS_PERFORMANCE,
            ASSESS_EXPERIENCE,
            VALIDATE_INTEGRATION,
            RECONCILE_FINDINGS,
            REPAIR_APPROACH,
            ASSESS_READINESS,
            EXPLAIN_RESULT,
        ],
    );
    assert_eq!(executed, 8, "every G3 row executed its own case");
}

#[test]
fn group_g4_delivery_observation_and_handoff() {
    let mut fixture = group_fixture("catalog-g4");
    let executed = run_group(
        &mut fixture,
        &[
            PREPARE_DELIVERY,
            DELIVER_CHANGE,
            OBSERVE_OUTCOME,
            PREPARE_HANDOFF,
            IMPROVE_PROCEDURE,
            DIAGNOSE_HARNESS,
        ],
    );
    assert_eq!(executed, 6, "every G4 row executed its own case");
}

#[test]
fn unknown_delivery_leaves_the_row_unsatisfied_and_the_attempt_unknown() {
    let mut fixture = group_fixture("catalog-delivery-unknown");
    let task = fixture.task("catalog-deliver-unknown");
    let request = request(
        &task,
        rivect::actions::RequestKind::Deliver,
        &[Surface::Local],
        ContractBasis::Approved,
        Vec::new(),
    );
    fixture.select(&request);
    let (_scope, _, intent, bytes) = prepare_delivery(&mut fixture, &task);
    let destination = intent.destination.clone();
    std::fs::write(&destination, b"foreign bytes changed after preparation")
        .expect("the destination now holds foreign bytes");
    let outcome = fixture
        .run(ActionInput::DeliverChange(DeliverChangeInput {
            request,
            intent,
            candidate: bytes,
        }))
        .expect("an unknown outcome is still a typed answer");
    let ActionOutcome::Delivered {
        receipt,
        attempt_id,
    } = &outcome
    else {
        panic!("expected Delivered, got {outcome:?}");
    };
    assert_eq!(receipt.outcome, DeliveryOutcome::Unknown);
    assert!(!receipt.applied, "an unknown outcome is never applied");
    assert_eq!(
        fixture
            .world
            .runtime
            .store()
            .attempt_state(attempt_id)
            .expect("attempt state reads"),
        Some("unknown".to_string()),
        "the effect is journalled as unknown, never confirmed"
    );
    let row = fixture
        .world
        .runtime
        .store()
        .plan_obligations(&task)
        .expect("plan rows read")
        .into_iter()
        .find(|row| row.capability == DELIVER_CHANGE)
        .expect("deliver_change is a recorded row");
    assert_eq!(
        row.execution,
        ObligationExecution::Failed,
        "an unknown delivery never satisfies its row"
    );
    assert_eq!(
        row.blocker,
        Some(Blocker {
            reason: ErrorCode::OutcomeUnknown,
            owner: "plan".to_string(),
            condition: ResumeCondition::Reconciliation {
                action_id: ActionId(DELIVER_CHANGE.to_string()),
            },
        }),
        "the pending effect waits on reconciliation"
    );
}

/// The 32 capability ids the SLICE-007 acceptance names, in its order. The
/// literal list is the denominator: the production registry constant is
/// never used as its own oracle.
const EXPECTED_CAPABILITIES: [&str; 32] = [
    "frame_goal",
    "inspect_system",
    "research_evidence",
    "resolve_decision",
    "challenge_direction",
    "design_contracts",
    "plan_work",
    "assess_plan",
    "test_assumption",
    "reproduce_issue",
    "diagnose_issue",
    "prepare_environment",
    "author_test",
    "implement_change",
    "refactor_structure",
    "validate_change",
    "audit_tests",
    "review_change",
    "assess_security",
    "assess_performance",
    "assess_experience",
    "validate_integration",
    "reconcile_findings",
    "repair_approach",
    "assess_readiness",
    "explain_result",
    "prepare_delivery",
    "deliver_change",
    "observe_outcome",
    "prepare_handoff",
    "improve_procedure",
    "diagnose_harness",
];

#[test]
fn the_32_row_conjunction_runs_last() {
    let expected: BTreeSet<&str> = EXPECTED_CAPABILITIES.into_iter().collect();
    assert_eq!(
        expected.len(),
        EXPECTED_CAPABILITIES.len(),
        "the acceptance list names each capability once"
    );
    let registry = ActionRegistry::new();
    let registered: BTreeSet<&str> = registry.definitions().map(|row| row.id).collect();
    assert_eq!(
        registry.definitions().count(),
        EXPECTED_CAPABILITIES.len(),
        "the registry serves exactly the acceptance rows"
    );
    assert_eq!(
        registered, expected,
        "the registry serves exactly the acceptance rows"
    );
    for id in EXPECTED_CAPABILITIES {
        let definition = registry
            .definition(id)
            .unwrap_or_else(|| panic!("{id} is registered"));
        assert_ne!(
            definition.implementation,
            Implementation::Unavailable,
            "{id} has a real handler"
        );
        assert_eq!(
            registered.iter().filter(|listed| **listed == id).count(),
            1,
            "{id} is registered exactly once"
        );
    }
    let mut fixture = group_fixture("catalog-conjunction");
    let mut positives = 0;
    let mut negatives = 0;
    for id in EXPECTED_CAPABILITIES {
        assert_positive(&mut fixture, id);
        positives += 1;
        assert_eq!(negative(&mut fixture, id), id, "{id}");
        negatives += 1;
    }
    assert_eq!(
        positives, 32,
        "every capability produced an asserted positive outcome"
    );
    assert_eq!(negatives, 32, "every capability has a negative control");
}
