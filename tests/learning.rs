//! Learned definitions on the real store (AC-051, REQ-041): a verified
//! low-risk delta changes the effective instruction part or applicability
//! condition, the next suitable task uses it with no extra model call, an
//! overbroad trigger refuses its negative control, and one rollback leaves the
//! rest of the experience active.
//!
//! Every case drives the production seams — `TaskStore` for the lifecycle,
//! `Broker::prepare`/`dispatch` for the assembled request, `ActionRegistry`
//! for the selection — and asserts a positive discriminating observation, so
//! the case fails when the behaviour it names is absent. The offline loopback
//! is the only provider; no network and no credentials are involved.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/discard conveniences; src/ stays strict (standards §14)"
)]

use rivect::actions::{
    ActionRegistry, ContractBasis, DESIGN_CONTRACTS, PlanRequest, RequestKind, Surface, SurfaceScan,
};
use rivect::config::Config;
use rivect::contracts::{ErrorCode, ObligationApplicability, SessionId};
use rivect::learning::{
    ConditionFact, ConditionFacts, CorpusCase, DEFINITION_MAX_BYTES, DeltaCandidate, DeltaChange,
    DeltaError, DeltaPayload, DeltaState, LearningDefinition, LearningDelta, PredicateEffect,
};
use rivect::model::{Broker, EpochMutationReason};
use rivect::providers::LoopbackProvider;
use rivect::state::{LEARNING_DELTA_RETENTION, StoreError, TaskStore};
use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

mod support;

const WORLD: &str = "/world/learning";
const SUBJECT_PURPOSE: &str = "main";
const PROBE_PURPOSE: &str = "review";
const PROBE: &str = "probe-purpose";
const PROBE_TEXT: &str = "the review purpose runs one mechanical leg before its report";
const DELTA_TEXT: &str =
    "carry the chosen form into the first paragraph before the explanation begins";

// ----- fixtures -----

fn local_config() -> String {
    "config_version = 1\n\
     [connections.local]\n\
     kind = \"local\"\n\
     endpoint = \"http://127.0.0.1:11434\"\n\
     [models.defaults]\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"learning-fixture\" }\n\
     effort = { mode = \"auto\" }\n\
     fallback = { mode = \"auto\" }\n"
        .to_string()
}

fn temp_root(prefix: &str) -> tempfile::TempDir {
    tempfile::TempDir::with_prefix(format!("rivect-learning-{prefix}-")).expect("fixture root")
}

fn open_store(root: &tempfile::TempDir) -> TaskStore {
    TaskStore::open(&root.path().join("state.db")).expect("store opens")
}

fn broker() -> Broker {
    Broker::new(Box::new(LoopbackProvider::new()))
}

fn instruction(text: &str, purpose: Option<&str>) -> DeltaChange {
    DeltaChange {
        payload: DeltaPayload::Instruction {
            text: text.to_string(),
        },
        when: purpose.map(|purpose| ConditionFact::Purpose(purpose.to_string())),
    }
}

fn applicability(capability: &str, effect: PredicateEffect, when: ConditionFact) -> DeltaChange {
    DeltaChange {
        payload: DeltaPayload::Applicability {
            capability: capability.to_string(),
            effect,
        },
        when: Some(when),
    }
}

fn candidate(delta_id: &str, change: DeltaChange) -> DeltaCandidate {
    DeltaCandidate {
        delta_id: delta_id.to_string(),
        base_version: 0,
        change,
        evidence: format!("tests/learning.rs {delta_id}"),
    }
}

fn audit_facts() -> ConditionFacts {
    ConditionFacts::for_selection(
        RequestKind::Audit,
        Some(BTreeSet::from([Surface::PublicApi])),
    )
}

/// The three cases an instruction delta must pass: it transfers to the purpose
/// its condition names, it composes with what is already active, and it stays
/// out of the probe's purpose — where a *different* delta provably applies, so
/// the case would catch an overbroad trigger (I9).
fn instruction_corpus_for(purpose: &str) -> Vec<CorpusCase> {
    vec![
        CorpusCase::Transfer {
            facts: ConditionFacts::for_purpose(purpose),
        },
        CorpusCase::Composition {
            facts: ConditionFacts::for_purpose(purpose),
        },
        CorpusCase::NegativeControl {
            facts: ConditionFacts::for_purpose(PROBE_PURPOSE),
            control: PROBE.to_string(),
        },
    ]
}

fn instruction_corpus() -> Vec<CorpusCase> {
    instruction_corpus_for(SUBJECT_PURPOSE)
}

/// The three cases an applicability delta must pass: it transfers to an audit
/// request, it composes with what is active — measured where it does compose,
/// the definition's selection under those same facts — and it stays out of the
/// probe's purpose where the probe applies.
fn applicability_corpus() -> Vec<CorpusCase> {
    vec![
        CorpusCase::Transfer {
            facts: audit_facts(),
        },
        CorpusCase::Composition {
            facts: audit_facts(),
        },
        CorpusCase::NegativeControl {
            facts: ConditionFacts::for_purpose(PROBE_PURPOSE),
            control: PROBE.to_string(),
        },
    ]
}

/// The control delta the negative-control cases name: a recorded experience
/// that provably applies to its own purpose, so a case can tell "the
/// candidate stays out" from "nothing applies here".
fn probe_candidate() -> DeltaCandidate {
    candidate(PROBE, instruction(PROBE_TEXT, Some(PROBE_PURPOSE)))
}

fn ensure_probe(store: &mut TaskStore) {
    if store.learning_delta(PROBE).is_ok() {
        return;
    }
    store
        .record_learning_delta(&probe_candidate())
        .expect("probe delta recorded");
}

fn ensure_probe_written(writer: &mut rivect::state::StoreWriter<'_>) {
    if writer.store().learning_delta(PROBE).is_ok() {
        return;
    }
    writer
        .record_learning_delta(&probe_candidate())
        .expect("probe delta recorded");
}

/// Records one candidate, runs its corpus and activates it — the lifecycle a
/// verified low-risk delta takes — returning the definition the store composes
/// afterwards.
fn verified(
    store: &mut TaskStore,
    candidate: &DeltaCandidate,
    corpus: &[CorpusCase],
) -> LearningDefinition {
    ensure_probe(store);
    store
        .record_learning_delta(candidate)
        .expect("candidate recorded");
    let verdicts = store
        .record_learning_corpus(&candidate.delta_id, corpus)
        .expect("corpus recorded");
    assert!(
        verdicts.iter().all(|verdict| verdict.passed),
        "the corpus of {} must pass: {verdicts:?}",
        candidate.delta_id
    );
    store
        .activate_learning_delta(&candidate.delta_id, 1)
        .expect("activation")
}

fn delta_error(error: &StoreError) -> &DeltaError {
    match error {
        StoreError::Delta(error) => error,
        other => panic!("expected a typed learning refusal, got {other}"),
    }
}

/// Records, judges and activates one candidate through the runtime's own write
/// surface: the record and corpus writes through its store writer, the
/// activation through the runtime, which installs the definition the store now
/// composes on the broker it prepares with.
fn activate_through_runtime(
    world: &mut support::World,
    candidate: &DeltaCandidate,
    corpus: &[CorpusCase],
) -> LearningDefinition {
    {
        let mut writer = world.runtime.store_writer();
        ensure_probe_written(&mut writer);
        writer
            .record_learning_delta(candidate)
            .expect("candidate recorded");
        let verdicts = writer
            .record_learning_corpus(&candidate.delta_id, corpus)
            .expect("corpus recorded");
        assert!(
            verdicts.iter().all(|verdict| verdict.passed),
            "the corpus of {} must pass: {verdicts:?}",
            candidate.delta_id
        );
    }
    world
        .runtime
        .activate_learning_delta(&candidate.delta_id, 1)
        .expect("activation")
}

// ----- p1: the next request carries the verified delta -----

#[test]
fn verified_delta_changes_the_next_request_p1() {
    let root = temp_root("p1");
    let mut store = open_store(&root);
    let config = Config::parse_validated(&local_config()).expect("valid config");
    let mut broker = broker();
    broker.set_learning_definition(store.learning_definition().expect("definition read"));

    let first = broker
        .prepare("main", &config, WORLD, "goal: explain the selected form")
        .expect("first prepare");
    assert!(
        !first.instructions.contains(DELTA_TEXT),
        "nothing learned yet: {}",
        first.instructions
    );
    let first_reply = broker.dispatch(WORLD, &first).expect("first dispatch");
    assert!(!first_reply.text.is_empty(), "the loopback answered");

    let definition = verified(
        &mut store,
        &candidate(
            "carry-chosen-form",
            instruction(DELTA_TEXT, Some(SUBJECT_PURPOSE)),
        ),
        &instruction_corpus(),
    );
    broker.set_learning_definition(definition);

    let second = broker
        .prepare("main", &config, WORLD, "goal: explain the selected form")
        .expect("second prepare");
    let second_reply = broker.dispatch(WORLD, &second).expect("second dispatch");
    assert!(!second_reply.text.is_empty(), "the loopback answered");

    assert!(
        second.instructions.contains(DELTA_TEXT),
        "the second request carries the learned instruction: {}",
        second.instructions
    );
    assert!(
        second.instructions.starts_with(&first.instructions),
        "the overlay appends to the assembled part instead of replacing it"
    );
    assert_ne!(first.instructions, second.instructions);
    assert_ne!(first.epoch_id, second.epoch_id);
    assert_eq!(
        second.mutation_reason.as_deref(),
        Some("system change"),
        "an instruction delta opens the epoch as a system change"
    );
    let cost = second.epoch_cost.expect("the mutation records its cost");
    assert_eq!(cost.reason, EpochMutationReason::SystemChange);
    assert_eq!(cost.replaced_part, "instructions");
    assert_eq!(
        broker.accounted_requests(),
        2,
        "two physical requests, one per dispatch"
    );
}

// ----- p2: the next suitable task uses it automatically -----

#[test]
fn delta_is_used_automatically_p2() {
    let mut world = support::open_world("learning-auto-p2", Some(&local_config()));
    let session = world.open_session("learning-bootstrap-p2");
    let task = world.create_task(&session, "learning-task-p2");
    let snapshot = world
        .runtime
        .store()
        .snapshot(&task)
        .expect("task snapshot");
    assert_eq!(snapshot.task_id, task, "the fixture task exists");

    // The whole lifecycle runs through the runtime's own write surface: no
    // learning command is invoked and no model is asked anything.
    activate_through_runtime(
        &mut world,
        &candidate(
            "carry-chosen-form",
            instruction(DELTA_TEXT, Some(SUBJECT_PURPOSE)),
        ),
        &instruction_corpus(),
    );

    // Nothing but the activation stands between the write and the next request:
    // the runtime installs the definition it activated, so the same process
    // composes the learned instruction without a restart.
    let config = world.runtime.config_for_broker();
    let manifest = world
        .runtime
        .broker
        .prepare("main", &config, WORLD, "goal: explain another form")
        .expect("prepare after activation");
    assert!(
        manifest.instructions.contains(DELTA_TEXT),
        "the next suitable task carries the learned instruction: {}",
        manifest.instructions
    );
    let reply = world
        .runtime
        .broker
        .dispatch(WORLD, &manifest)
        .expect("dispatch");
    assert!(!reply.text.is_empty(), "the loopback answered");
    assert_eq!(
        world.provider_calls.load(Ordering::SeqCst),
        1,
        "activation and assembly add no model call"
    );
    assert_eq!(world.runtime.broker.accounted_requests(), 1);
}

// ----- p3: the assembled bytes replay bytewise -----

#[test]
fn round_trip_is_bytewise_stable_p3() {
    let root = temp_root("p3");
    let mut store = open_store(&root);
    let config = Config::parse_validated(&local_config()).expect("valid config");
    let definition = verified(
        &mut store,
        &candidate(
            "carry-chosen-form",
            instruction(DELTA_TEXT, Some(SUBJECT_PURPOSE)),
        ),
        &instruction_corpus(),
    );
    let mut broker = broker();
    broker.set_learning_definition(definition);

    let first = broker
        .prepare("main", &config, WORLD, "goal: explain the selected form")
        .expect("first prepare");
    let second = broker
        .prepare("main", &config, WORLD, "goal: explain the selected form")
        .expect("second prepare");

    assert!(
        first.instructions.contains(DELTA_TEXT),
        "the replay still carries the learned part"
    );
    assert_eq!(first.wire_bytes(), second.wire_bytes());
    assert_eq!(first.epoch_id, second.epoch_id);
    assert_eq!(
        second.mutation_reason, None,
        "an unchanged prefix replays its epoch instead of opening a new one"
    );
    assert_eq!(second.epoch_cost, None);
}

// ----- p4: an overbroad trigger refuses the negative control -----

#[test]
fn overbroad_trigger_does_not_activate_p4() {
    let root = temp_root("p4");
    let mut store = open_store(&root);
    // The good delta: it applies to an audit request, which is exactly the
    // fact an overbroad surface trigger also covers.
    let good = candidate(
        "audit-needs-security",
        applicability(
            "assess_security",
            PredicateEffect::Require,
            ConditionFact::Kind(RequestKind::Audit),
        ),
    );
    verified(&mut store, &good, &applicability_corpus());
    assert_eq!(
        store.learning_status().expect("status").active.len(),
        1,
        "the good delta is active"
    );

    // The overbroad delta: a surface trigger that also fires on the audit
    // request the negative control pins, where the good delta already applies.
    let overbroad = candidate(
        "public-api-needs-review",
        applicability(
            "review_change",
            PredicateEffect::Require,
            ConditionFact::Surface(Surface::PublicApi),
        ),
    );
    store
        .record_learning_delta(&overbroad)
        .expect("overbroad candidate recorded");
    // The negative control pins the audit request, where the good delta
    // provably applies and the overbroad surface trigger also fires.
    let overbroad_corpus = vec![
        CorpusCase::Transfer {
            facts: audit_facts(),
        },
        CorpusCase::Composition {
            facts: audit_facts(),
        },
        CorpusCase::NegativeControl {
            facts: audit_facts(),
            control: good.delta_id.clone(),
        },
    ];
    let verdicts = store
        .record_learning_corpus(&overbroad.delta_id, &overbroad_corpus)
        .expect("corpus recorded");
    let control = verdicts
        .iter()
        .find(|verdict| verdict.kind.as_str() == "negative_control")
        .expect("the negative control is recorded");
    assert!(!control.passed, "the overbroad trigger fires: {control:?}");
    assert!(
        control.observed.contains("public-api-needs-review applies"),
        "the verdict names what fired: {}",
        control.observed
    );

    let refused = store
        .activate_learning_delta(&overbroad.delta_id, 1)
        .expect_err("an overbroad trigger never activates");
    match delta_error(&refused) {
        DeltaError::CorpusRejected { kind, .. } => {
            assert_eq!(*kind, "negative_control");
        }
        other => panic!("expected the refused corpus case, got {other}"),
    }
    assert_eq!(refused.code(), ErrorCode::Conflict);

    let status = store.learning_status().expect("status");
    assert_eq!(
        status.active.len(),
        1,
        "the good delta stays active: {status:?}"
    );
    assert_eq!(status.active[0].delta_id, "audit-needs-security");
    assert_eq!(
        store
            .learning_delta(&overbroad.delta_id)
            .expect("row read")
            .state,
        DeltaState::Inactive
    );
}

// ----- p5: a failed composition keeps the delta inactive -----

#[test]
fn failed_composition_keeps_the_delta_inactive_p5() {
    let root = temp_root("p5");
    let mut store = open_store(&root);
    let active_text = "a".repeat(2000);
    let active = candidate(
        "long-active",
        instruction(&active_text, Some(SUBJECT_PURPOSE)),
    );
    let before = verified(&mut store, &active, &instruction_corpus());

    // Under its own bound, but the definition it would compose into is not.
    let oversized = candidate(
        "long-candidate",
        instruction(&"b".repeat(2000), Some(SUBJECT_PURPOSE)),
    );
    store
        .record_learning_delta(&oversized)
        .expect("candidate recorded");
    let verdicts = store
        .record_learning_corpus(&oversized.delta_id, &instruction_corpus())
        .expect("corpus recorded");
    let composition = verdicts
        .iter()
        .find(|verdict| verdict.kind.as_str() == "composition")
        .expect("the composition case is recorded");
    assert!(
        !composition.passed,
        "the composition exceeds its bound: {composition:?}"
    );

    let refused = store
        .activate_learning_delta(&oversized.delta_id, 1)
        .expect_err("a failed composition never activates");
    match delta_error(&refused) {
        DeltaError::CorpusRejected { kind, .. } => assert_eq!(*kind, "composition"),
        other => panic!("expected the refused composition case, got {other}"),
    }

    let after = store.learning_definition().expect("definition read");
    assert_eq!(after, before, "the previous definition stays in force");
    assert_eq!(
        after
            .deltas()
            .iter()
            .map(|delta| delta.delta_id.as_str())
            .collect::<Vec<_>>(),
        vec!["long-active"]
    );
    assert_eq!(
        store
            .learning_delta(&oversized.delta_id)
            .expect("row read")
            .state,
        DeltaState::Inactive
    );
}

// ----- p6: one rollback leaves the rest of the experience active -----

#[test]
fn single_delta_rollback_keeps_other_experience_p6() {
    let root = temp_root("p6");
    let mut store = open_store(&root);
    verified(
        &mut store,
        &candidate(
            "carry-chosen-form",
            instruction(DELTA_TEXT, Some(SUBJECT_PURPOSE)),
        ),
        &instruction_corpus(),
    );
    verified(
        &mut store,
        &candidate(
            "audit-needs-security",
            applicability(
                "assess_security",
                PredicateEffect::Require,
                ConditionFact::Kind(RequestKind::Audit),
            ),
        ),
        &applicability_corpus(),
    );
    assert_eq!(store.learning_status().expect("status").active.len(), 2);

    // Rollback of one delta: the instruction one, pinned to the version its
    // activation left.
    let remaining = store
        .roll_back_learning_delta("carry-chosen-form", 2)
        .expect("rollback");

    let status = store.learning_status().expect("status");
    assert_eq!(
        status
            .active
            .iter()
            .map(|view| view.delta_id.as_str())
            .collect::<Vec<_>>(),
        vec!["audit-needs-security"],
        "the other experience stays active"
    );
    assert_eq!(
        status
            .rolled_back
            .iter()
            .map(|view| view.delta_id.as_str())
            .collect::<Vec<_>>(),
        vec!["carry-chosen-form"]
    );

    let config = Config::parse_validated(&local_config()).expect("valid config");
    let mut broker = broker();
    broker.set_learning_definition(remaining);
    let manifest = broker
        .prepare("main", &config, WORLD, "goal: explain the selected form")
        .expect("prepare");
    assert!(
        !manifest.instructions.contains(DELTA_TEXT),
        "the rolled-back instruction is gone from the next request: {}",
        manifest.instructions
    );

    // The surviving delta still decides applicability.
    let facts = audit_facts();
    assert_eq!(
        store
            .learning_definition()
            .expect("definition read")
            .applicability("assess_security", &facts),
        Some(PredicateEffect::Require)
    );
}

// ----- p7: the schema ledger reads back as generation 2 -----

#[test]
fn schema_generation_is_two_and_idempotent_p7() {
    let root = temp_root("p7");
    let database = root.path().join("state.db");
    {
        let mut store = TaskStore::open(&database).expect("store opens");
        assert_eq!(store.schema_generation().expect("ledger read"), 2);
        store
            .record_learning_delta(&candidate(
                "carry-chosen-form",
                instruction(DELTA_TEXT, Some(SUBJECT_PURPOSE)),
            ))
            .expect("candidate recorded");
    }

    // The engine's own header, not only the store's accessor.
    {
        let conn = rusqlite::Connection::open(&database).expect("raw connection");
        let generation: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("ledger read");
        assert_eq!(generation, 2);
    }

    // The ledger records that the generation's batch ran, not that its schema
    // is present: a second open re-runs the same idempotent batch, so the row
    // the first open wrote is unchanged and the number still holds.
    {
        let store = TaskStore::open(&database).expect("second open");
        assert_eq!(store.schema_generation().expect("ledger read"), 2);
        let record = store.learning_delta("carry-chosen-form").expect("row read");
        assert_eq!(record.state, DeltaState::Inactive);
        assert_eq!(record.version, 1);
        assert_eq!(
            record.base_version, 0,
            "the authored base version round-trips"
        );
    }

    // A store at generation 2 whose learning table was dropped — the rollback
    // the slice note describes — is repaired by the next open instead of
    // opening clean and failing later as untagged storage.
    {
        let conn = rusqlite::Connection::open(&database).expect("raw connection");
        conn.execute_batch("DROP TABLE learning_corpus")
            .expect("the dropped generation-2 table");
    }
    let repaired = TaskStore::open(&database).expect("the repair opens");
    assert!(
        repaired
            .learning_corpus("carry-chosen-form")
            .expect("the repaired table answers")
            .is_empty(),
        "the lost table is back and holds no verdict for the recorded delta"
    );
    assert_eq!(
        repaired.schema_generation().expect("ledger read"),
        2,
        "the repair writes the generation this build reads, never a rewind"
    );
    assert_eq!(
        repaired
            .learning_delta("carry-chosen-form")
            .expect("row read")
            .delta_id,
        "carry-chosen-form",
        "the data beside the repaired table is untouched"
    );
    drop(repaired);

    // A store a newer build wrote is refused typed before any DDL runs: no
    // learning table is created by the refused open.
    let newer = root.path().join("newer.db");
    {
        let conn = rusqlite::Connection::open(&newer).expect("raw connection");
        conn.execute_batch("PRAGMA user_version = 3")
            .expect("newer ledger");
    }
    let Err(refused) = TaskStore::open(&newer) else {
        panic!("a newer generation is refused")
    };
    match refused {
        StoreError::UnsupportedGeneration { found, known } => {
            assert_eq!((found, known), (3, 2));
        }
        other => panic!("expected the generation refusal, got {other}"),
    }
    assert_eq!(refused.code(), ErrorCode::UnsupportedVersion);
    let conn = rusqlite::Connection::open(&newer).expect("raw connection");
    let tables: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('learning_deltas', 'learning_corpus')",
            [],
            |row| row.get(0),
        )
        .expect("schema read");
    assert_eq!(tables, 0, "the refused open ran no DDL");
    // The refusal leaves the newer ledger where the newer build put it: a
    // build that wrote its own generation before refusing would rewind the
    // store, and the next open of the newer build would read it as old.
    let ledger: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("ledger read");
    assert_eq!(ledger, 3, "the refused open never rewrote the newer ledger");
}

// ----- p8: the learned predicate decides the selection -----

#[test]
fn learned_predicate_changes_the_selected_obligation_p8() {
    let mut world = support::open_world("learning-select-p8", Some(&local_config()));
    let session: SessionId = world.open_session("learning-bootstrap-p8");
    let first = world.create_task(&session, "learning-task-p8-a");
    let second = world.create_task(&session, "learning-task-p8-b");
    let third = world.create_task(&session, "learning-task-p8-c");
    let config = world.runtime.config_for_broker();
    let registry = ActionRegistry::new();

    let baseline = registry
        .select(
            &audit_request(&first),
            &[],
            &mut world.runtime.action_context(&session, &config),
        )
        .expect("baseline selection");
    assert!(
        !names(&baseline).contains(&"assess_security"),
        "the request facts alone do not weigh assess_security: {:?}",
        names(&baseline)
    );

    activate_through_runtime(
        &mut world,
        &candidate(
            "audit-needs-security",
            applicability(
                "assess_security",
                PredicateEffect::Require,
                ConditionFact::Kind(RequestKind::Audit),
            ),
        ),
        &applicability_corpus(),
    );

    let learned = registry
        .select(
            &audit_request(&second),
            &[],
            &mut world.runtime.action_context(&session, &config),
        )
        .expect("learned selection");
    let row = learned
        .obligations
        .iter()
        .find(|row| row.capability == "assess_security")
        .unwrap_or_else(|| {
            panic!(
                "the learned condition selects assess_security: {:?}",
                names(&learned)
            )
        });
    assert_eq!(row.applicability, ObligationApplicability::Required);
    // Activation visibility (DEC-011) on the status payload the runtime
    // actually serves, not on a second accessor of our own.
    let status = world.dispatch(&support::corpus_status(&session));
    assert_eq!(
        status["result"]["learning"]["generation"], 2,
        "the schema ledger is visible: {status}"
    );
    assert_eq!(
        status["result"]["learning"]["active"][0]["delta_id"],
        "audit-needs-security"
    );
    assert_eq!(
        status["result"]["learning"]["active"][0]["scope"],
        "applicability"
    );

    let stored = world
        .runtime
        .store()
        .plan_obligations(&second)
        .expect("rows read");
    assert!(
        stored.iter().any(|row| row.capability == "assess_security"
            && row.applicability == ObligationApplicability::Required),
        "the recorded selection carries the learned row: {stored:?}"
    );

    // The reverse case: the same facts on a task selected after the rollback
    // no longer pick the learned capability up.
    world
        .runtime
        .roll_back_learning_delta("audit-needs-security", 2)
        .expect("rollback");
    let reverted = registry
        .select(
            &audit_request(&third),
            &[],
            &mut world.runtime.action_context(&session, &config),
        )
        .expect("reverted selection");
    assert!(
        !names(&reverted).contains(&"assess_security"),
        "the rollback removes the selection: {:?}",
        names(&reverted)
    );

    // Rollback visibility (DEC-011): the withdrawn delta is reported as such
    // and no longer composes the effective definition.
    let after = world.dispatch(&support::corpus_status(&session));
    assert_eq!(
        after["result"]["learning"]["active"]
            .as_array()
            .map(Vec::len),
        Some(0),
        "nothing composes the definition after the rollback: {after}"
    );
    assert_eq!(
        after["result"]["learning"]["rolled_back"][0]["delta_id"],
        "audit-needs-security"
    );
}

fn audit_request(task: &rivect::contracts::TaskId) -> PlanRequest {
    PlanRequest {
        task_id: task.clone(),
        kind: RequestKind::Audit,
        surfaces: SurfaceScan::Known(BTreeSet::from([Surface::PublicApi])),
        contract: ContractBasis::Absent,
        parts: Vec::new(),
        delegation: None,
        author: None,
    }
}

fn names(selection: &rivect::actions::Selection) -> Vec<&'static str> {
    selection
        .obligations
        .iter()
        .map(|row| row.capability)
        .collect()
}

// ----- p9: no verdict rows, no activation -----

#[test]
fn delta_without_verdict_rows_stays_inactive_p9() {
    let root = temp_root("p9");
    let mut store = open_store(&root);
    ensure_probe(&mut store);
    let delta = candidate(
        "carry-chosen-form",
        instruction(DELTA_TEXT, Some(SUBJECT_PURPOSE)),
    );
    store
        .record_learning_delta(&delta)
        .expect("candidate recorded");

    let refused = store
        .activate_learning_delta(&delta.delta_id, 1)
        .expect_err("an unjudged candidate never activates");
    match delta_error(&refused) {
        DeltaError::CorpusMissing { kind, version, .. } => {
            assert_eq!(*kind, "transfer");
            assert_eq!(*version, 1);
        }
        other => panic!("expected the missing verdict refusal, got {other}"),
    }

    // One kind is not the corpus: activation still waits on the other two.
    store
        .record_learning_corpus(
            &delta.delta_id,
            &[CorpusCase::Transfer {
                facts: ConditionFacts::for_purpose(SUBJECT_PURPOSE),
            }],
        )
        .expect("transfer recorded");
    let partial = store
        .activate_learning_delta(&delta.delta_id, 1)
        .expect_err("a partial corpus never activates");
    match delta_error(&partial) {
        DeltaError::CorpusMissing { kind, .. } => assert_eq!(*kind, "composition"),
        other => panic!("expected the next missing kind, got {other}"),
    }
    assert_eq!(
        store
            .learning_delta(&delta.delta_id)
            .expect("row read")
            .state,
        DeltaState::Inactive
    );

    // The complete corpus is what opens it.
    let verdicts = store
        .record_learning_corpus(&delta.delta_id, &instruction_corpus())
        .expect("full corpus recorded");
    assert_eq!(verdicts.len(), 3);
    let definition = store
        .activate_learning_delta(&delta.delta_id, 1)
        .expect("activation");
    assert_eq!(definition.deltas().len(), 1);
}

// ----- p10: retention keeps the primary rows -----

#[test]
fn retention_keeps_primary_rows_p10() {
    let root = temp_root("p10");
    let mut store = open_store(&root);
    verified(
        &mut store,
        &candidate(
            "carry-chosen-form",
            instruction(DELTA_TEXT, Some(SUBJECT_PURPOSE)),
        ),
        &instruction_corpus(),
    );
    // The oldest retained primary row is older than everything pruned below.
    store
        .record_learning_delta(&candidate(
            "first-candidate",
            instruction("the first proposal never activated", Some(SUBJECT_PURPOSE)),
        ))
        .expect("first candidate recorded");
    store
        .record_learning_corpus(
            "first-candidate",
            &[CorpusCase::Transfer {
                facts: ConditionFacts::for_purpose(SUBJECT_PURPOSE),
            }],
        )
        .expect("first verdict recorded");
    let mut proposals = vec!["first-candidate".to_string()];
    for index in 1..=LEARNING_DELTA_RETENTION {
        let delta_id = format!("candidate-{index:02}");
        store
            .record_learning_delta(&candidate(
                &delta_id,
                instruction(
                    "a later proposal that never activated",
                    Some(SUBJECT_PURPOSE),
                ),
            ))
            .expect("candidate recorded");
        proposals.push(delta_id);
    }

    let retained = proposals
        .iter()
        .filter(|delta_id| store.learning_delta(delta_id).is_ok())
        .count();
    assert_eq!(
        retained, LEARNING_DELTA_RETENTION,
        "N+1 candidates evict to N"
    );
    assert!(
        store.learning_delta("first-candidate").is_err(),
        "the oldest proposal is the one evicted"
    );
    assert!(
        store
            .learning_corpus("first-candidate")
            .expect("corpus read")
            .is_empty()
    );

    // The primary rows are untouched: the active delta still composes the
    // definition and still reports its activation.
    assert_eq!(
        store
            .learning_delta("carry-chosen-form")
            .expect("primary row read")
            .state,
        DeltaState::Active
    );
    assert_eq!(
        store
            .learning_definition()
            .expect("definition read")
            .deltas()
            .iter()
            .map(|delta| delta.delta_id.as_str())
            .collect::<Vec<_>>(),
        vec!["carry-chosen-form"]
    );
}

// ----- p11: no credential reference enters learned state -----

#[test]
fn keyring_reference_in_delta_body_is_refused_p11() {
    let root = temp_root("p11");
    let mut store = open_store(&root);
    let refused = store
        .record_learning_delta(&candidate(
            "carry-secret",
            instruction(
                "prefer the credential at keyring:primary for this purpose",
                Some(SUBJECT_PURPOSE),
            ),
        ))
        .expect_err("a credential reference is refused");
    match delta_error(&refused) {
        DeltaError::CredentialReference { delta_id } => assert_eq!(delta_id, "carry-secret"),
        other => panic!("expected the credential refusal, got {other}"),
    }
    assert_eq!(refused.code(), ErrorCode::InvalidInput);
    assert!(
        matches!(
            store.learning_delta("carry-secret"),
            Err(StoreError::NotFound(_))
        ),
        "a refused body is never stored"
    );

    // The reference syntax is case-insensitive: a mixed-case spelling is the
    // same reference and is refused the same way.
    let mixed = store
        .record_learning_delta(&candidate(
            "carry-mixed-secret",
            instruction("prefer the credential at KeyRing:primary", None),
        ))
        .expect_err("a mixed-case reference is refused");
    assert!(matches!(
        delta_error(&mixed),
        DeltaError::CredentialReference { .. }
    ));

    // The same words without the reference syntax are ordinary instruction
    // text and are recorded.
    let allowed = store
        .record_learning_delta(&candidate(
            "carry-form",
            instruction(
                "prefer the credential store the platform already bound",
                None,
            ),
        ))
        .expect("plain text is recorded");
    assert_eq!(allowed.state, DeltaState::Inactive);
}

// ----- p12: one activation wins, the loser re-reads -----

#[test]
fn concurrent_activation_loses_cleanly_p12() {
    let root = temp_root("p12");
    let mut store = open_store(&root);
    ensure_probe(&mut store);
    let delta = candidate(
        "carry-chosen-form",
        instruction(DELTA_TEXT, Some(SUBJECT_PURPOSE)),
    );
    store
        .record_learning_delta(&delta)
        .expect("candidate recorded");
    let verdicts = store
        .record_learning_corpus(&delta.delta_id, &instruction_corpus())
        .expect("corpus recorded");
    assert!(verdicts.iter().all(|verdict| verdict.passed));

    // Two actors read the same inactive version; the first activation moves
    // the row to version 2.
    let pinned = store
        .learning_delta(&delta.delta_id)
        .expect("first read")
        .version;
    assert_eq!(pinned, 1);
    store
        .activate_learning_delta(&delta.delta_id, pinned)
        .expect("the first actor activates");

    let refused = store
        .activate_learning_delta(&delta.delta_id, pinned)
        .expect_err("the second actor loses the conditional transition");
    match delta_error(&refused) {
        DeltaError::ActivationRefused {
            state,
            version,
            expected,
            ..
        } => {
            assert_eq!(*state, DeltaState::Active);
            assert_eq!(*version, 2);
            assert_eq!(*expected, 1);
        }
        other => panic!("expected the activation refusal, got {other}"),
    }
    assert_eq!(refused.code(), ErrorCode::Conflict);

    // The invariant re-reads: exactly one activation happened.
    let status = store.learning_status().expect("status");
    assert_eq!(status.active.len(), 1);
    assert_eq!(status.active[0].delta_id, delta.delta_id);
    assert_eq!(status.active[0].version, 2);
    assert_eq!(
        store
            .learning_delta(&delta.delta_id)
            .expect("row read")
            .version,
        2
    );
}

// ----- p13: an activated decline removes a decided obligation -----

#[test]
fn learned_decline_removes_the_selected_obligation_p13() {
    let mut world = support::open_world("learning-decline-p13", Some(&local_config()));
    let session: SessionId = world.open_session("learning-bootstrap-p13");
    let first = world.create_task(&session, "learning-task-p13-a");
    let second = world.create_task(&session, "learning-task-p13-b");
    let config = world.runtime.config_for_broker();
    let registry = ActionRegistry::new();

    let baseline = registry
        .select(
            &audit_request(&first),
            &[],
            &mut world.runtime.action_context(&session, &config),
        )
        .expect("baseline selection");
    assert!(
        names(&baseline).contains(&"review_change"),
        "the request facts alone require review_change: {:?}",
        names(&baseline)
    );

    activate_through_runtime(
        &mut world,
        &candidate(
            "audit-skips-review",
            applicability(
                "review_change",
                PredicateEffect::Decline,
                ConditionFact::Kind(RequestKind::Audit),
            ),
        ),
        &applicability_corpus(),
    );

    let learned = registry
        .select(
            &audit_request(&second),
            &[],
            &mut world.runtime.action_context(&session, &config),
        )
        .expect("learned selection");
    assert!(
        !names(&learned).contains(&"review_change"),
        "the learned decline removes the obligation the facts required: {:?}",
        names(&learned)
    );
    // The status surface reports the delta that withdrew it (DEC-011).
    let status = world.dispatch(&support::corpus_status(&session));
    assert_eq!(
        status["result"]["learning"]["active"][0]["delta_id"],
        "audit-skips-review"
    );
    assert_eq!(
        status["result"]["learning"]["active"][0]["scope"],
        "applicability"
    );
}

// ----- p14: a learned decline never closes an undecided obligation -----

#[test]
fn learned_decline_keeps_an_undecided_obligation_p14() {
    let mut world = support::open_world("learning-undecided-p14", Some(&local_config()));
    let session: SessionId = world.open_session("learning-bootstrap-p14");
    let first = world.create_task(&session, "learning-task-p14-a");
    let second = world.create_task(&session, "learning-task-p14-b");
    let config = world.runtime.config_for_broker();
    let registry = ActionRegistry::new();

    // The undecided request: the impact scan was never decided, so the
    // security leg is unresolved rather than declined by the facts.
    let undecided_baseline = registry
        .select(
            &undecided_audit_request(&first),
            &[],
            &mut world.runtime.action_context(&session, &config),
        )
        .expect("baseline selection");
    assert!(
        undecided_baseline.obligations.iter().any(|row| {
            row.capability == "assess_security"
                && row.applicability == ObligationApplicability::Unresolved
        }),
        "the request facts leave the security leg unresolved: {:?}",
        names(&undecided_baseline)
    );

    activate_through_runtime(
        &mut world,
        &candidate(
            "audit-declines-security",
            applicability(
                "assess_security",
                PredicateEffect::Decline,
                ConditionFact::Kind(RequestKind::Audit),
            ),
        ),
        &applicability_corpus(),
    );

    let undecided = registry
        .select(
            &undecided_audit_request(&second),
            &[],
            &mut world.runtime.action_context(&session, &config),
        )
        .expect("learned selection");
    assert!(
        undecided.obligations.iter().any(|row| {
            row.capability == "assess_security"
                && row.applicability == ObligationApplicability::Unresolved
        }),
        "an undecided obligation survives an active decline: {:?}",
        names(&undecided)
    );
    let status = world.dispatch(&support::corpus_status(&session));
    assert_eq!(
        status["result"]["learning"]["active"][0]["delta_id"], "audit-declines-security",
        "the status surface reports the active decline: {status}"
    );
}

fn undecided_audit_request(task: &rivect::contracts::TaskId) -> PlanRequest {
    PlanRequest {
        task_id: task.clone(),
        kind: RequestKind::Audit,
        surfaces: SurfaceScan::Unknown,
        contract: ContractBasis::Absent,
        parts: Vec::new(),
        delegation: None,
        author: None,
    }
}

// ----- p15: activation re-checks the composition against the live definition -----

#[test]
fn activation_rechecks_composition_against_the_live_definition_p15() {
    let root = temp_root("p15");
    let mut store = open_store(&root);
    ensure_probe(&mut store);
    let first = candidate(
        "first-form",
        instruction(&"a".repeat(2000), Some(SUBJECT_PURPOSE)),
    );
    let second = candidate(
        "second-form",
        instruction(&"b".repeat(2000), Some(SUBJECT_PURPOSE)),
    );
    // Both corpora run while nothing is active: each composition verdict sees
    // one delta beside the base part and passes.
    for delta in [&first, &second] {
        store
            .record_learning_delta(delta)
            .expect("candidate recorded");
        let verdicts = store
            .record_learning_corpus(&delta.delta_id, &instruction_corpus())
            .expect("corpus recorded");
        let composition = verdicts
            .iter()
            .find(|verdict| verdict.kind.as_str() == "composition")
            .expect("the composition case is recorded");
        assert!(
            composition.passed,
            "each delta fits the bound on its own: {composition:?}"
        );
    }

    store
        .activate_learning_delta(&first.delta_id, 1)
        .expect("the first delta fits the bound");
    let refused = store
        .activate_learning_delta(&second.delta_id, 1)
        .expect_err("the definition the second delta composes is over the bound");
    match delta_error(&refused) {
        DeltaError::CompositionExceeded {
            delta_id,
            size,
            limit,
        } => {
            assert_eq!(delta_id, "second-form");
            assert_eq!(*limit, DEFINITION_MAX_BYTES);
            assert!(
                *size > DEFINITION_MAX_BYTES,
                "the refusal names the composed size: {size}"
            );
        }
        other => panic!("expected the composition refusal, got {other}"),
    }
    assert_eq!(refused.code(), ErrorCode::Conflict);

    // The refused activation left no row behind, and the definition it would
    // have composed is the one the bound refuses.
    let record = store.learning_delta(&second.delta_id).expect("row read");
    assert_eq!(record.state, DeltaState::Inactive);
    assert_eq!(record.version, 1);
    let composed = store
        .learning_definition()
        .expect("definition read")
        .composed_with(&LearningDelta {
            delta_id: record.delta_id.clone(),
            version: record.version,
            change: record.change.clone(),
        });
    let carried = composed.instruction_part(SUBJECT_PURPOSE, "").len();
    assert!(
        carried > DEFINITION_MAX_BYTES,
        "the refused definition carries {carried} bytes, over the {DEFINITION_MAX_BYTES}-byte bound"
    );
    assert_eq!(
        store.learning_status().expect("status").active.len(),
        1,
        "the delta that fits stays the only active one"
    );
}

// ----- p16: a rollback stops the learned instruction in the same process -----

#[test]
fn rollback_stops_the_learned_instruction_in_the_same_process_p16() {
    let mut world = support::open_world("learning-rollback-p16", Some(&local_config()));
    let config = world.runtime.config_for_broker();
    activate_through_runtime(
        &mut world,
        &candidate(
            "carry-chosen-form",
            instruction(DELTA_TEXT, Some(SUBJECT_PURPOSE)),
        ),
        &instruction_corpus(),
    );

    let carried = world
        .runtime
        .broker
        .prepare("main", &config, WORLD, "goal: explain the selected form")
        .expect("prepare after activation");
    assert!(
        carried.instructions.contains(DELTA_TEXT),
        "the activated instruction rides the next request: {}",
        carried.instructions
    );

    world
        .runtime
        .roll_back_learning_delta("carry-chosen-form", 2)
        .expect("rollback");
    let reverted = world
        .runtime
        .broker
        .prepare("main", &config, WORLD, "goal: explain the selected form")
        .expect("prepare after rollback");
    assert!(
        !reverted.instructions.contains(DELTA_TEXT),
        "the rolled-back body stops riding the same process's requests: {}",
        reverted.instructions
    );
    assert_eq!(
        world
            .runtime
            .store()
            .learning_status()
            .expect("status")
            .active
            .len(),
        0,
        "nothing composes the definition after the rollback"
    );
}

// ----- p17: a restarted runtime composes the active delta from its store -----

#[test]
fn restarted_runtime_composes_the_active_delta_p17() {
    let mut world = support::open_world("learning-restart-p17", Some(&local_config()));
    activate_through_runtime(
        &mut world,
        &candidate(
            "carry-chosen-form",
            instruction(DELTA_TEXT, Some(SUBJECT_PURPOSE)),
        ),
        &instruction_corpus(),
    );

    // The process ends and a fresh runtime opens over the same store: nothing
    // it held in memory survives, so the definition it composes can only come
    // from the activation the store recorded.
    world.reopen();
    assert_eq!(
        world
            .runtime
            .store()
            .learning_status()
            .expect("status")
            .active
            .iter()
            .map(|view| view.delta_id.as_str())
            .collect::<Vec<_>>(),
        vec!["carry-chosen-form"],
        "the restarted store still holds the active delta"
    );

    let config = world.runtime.config_for_broker();
    let manifest = world
        .runtime
        .broker
        .prepare("main", &config, WORLD, "goal: explain another form")
        .expect("prepare after the restart");
    assert!(
        manifest.instructions.contains(DELTA_TEXT),
        "a runtime reopened over the store composes the active delta: {}",
        manifest.instructions
    );
}

// ----- p18: the bound covers the base a stage request assembles onto -----

#[test]
fn stage_purpose_deltas_stay_within_the_shipped_bound_p18() {
    let root = temp_root("p18");
    let mut store = open_store(&root);
    ensure_probe(&mut store);
    // A semantic stage assembles its request part onto its own instruction
    // constant, so the bound two deltas must fit is measured from that base,
    // not only from the mandatory decision-core part.
    let corpus = instruction_corpus_for(DESIGN_CONTRACTS);
    let first = candidate(
        "first-stage-form",
        instruction(&"c".repeat(1400), Some(DESIGN_CONTRACTS)),
    );
    let second = candidate(
        "second-stage-form",
        instruction(&"d".repeat(1400), Some(DESIGN_CONTRACTS)),
    );
    // Both corpora run while nothing is active: each composition verdict sees
    // one delta beside the base and passes.
    for delta in [&first, &second] {
        store
            .record_learning_delta(delta)
            .expect("candidate recorded");
        let verdicts = store
            .record_learning_corpus(&delta.delta_id, &corpus)
            .expect("corpus recorded");
        assert!(
            verdicts.iter().all(|verdict| verdict.passed),
            "each delta fits the bound on its own: {verdicts:?}"
        );
    }

    store
        .activate_learning_delta(&first.delta_id, 1)
        .expect("the first delta fits the bound");
    let refused = store
        .activate_learning_delta(&second.delta_id, 1)
        .expect_err("the pair composes past the bound the stage request carries");
    match delta_error(&refused) {
        DeltaError::CompositionExceeded {
            delta_id,
            size,
            limit,
        } => {
            assert_eq!(delta_id, "second-stage-form");
            assert_eq!(*limit, DEFINITION_MAX_BYTES);
            assert!(
                *size > DEFINITION_MAX_BYTES,
                "the refusal names the composed size: {size}"
            );
        }
        other => panic!("expected the composition refusal, got {other}"),
    }
    assert_eq!(refused.code(), ErrorCode::Conflict);
    assert_eq!(
        store
            .learning_delta(&second.delta_id)
            .expect("row read")
            .state,
        DeltaState::Inactive,
        "the refused activation leaves no active row"
    );
    assert_eq!(
        store.learning_status().expect("status").active.len(),
        1,
        "the delta that fits stays the only active one"
    );
}

// ----- p19: the corpus verdict measures the base the request carries -----

#[test]
fn corpus_composition_measures_the_shipped_base_p19() {
    let root = temp_root("p19");
    let mut store = open_store(&root);
    ensure_probe(&mut store);
    let corpus = instruction_corpus_for(DESIGN_CONTRACTS);
    let first = candidate(
        "first-stage-form",
        instruction(&"c".repeat(1400), Some(DESIGN_CONTRACTS)),
    );
    store
        .record_learning_delta(&first)
        .expect("candidate recorded");
    let verdicts = store
        .record_learning_corpus(&first.delta_id, &corpus)
        .expect("corpus recorded");
    assert!(
        verdicts.iter().all(|verdict| verdict.passed),
        "the first delta fits the bound: {verdicts:?}"
    );
    store
        .activate_learning_delta(&first.delta_id, 1)
        .expect("the first delta fits the bound");

    // Judged beside the definition it would join and the base the stage
    // request assembles onto, the second delta is over the bound — the same
    // verdict its activation reaches, taken before any row moves.
    let second = candidate(
        "second-stage-form",
        instruction(&"d".repeat(1400), Some(DESIGN_CONTRACTS)),
    );
    store
        .record_learning_delta(&second)
        .expect("candidate recorded");
    let verdicts = store
        .record_learning_corpus(&second.delta_id, &corpus)
        .expect("corpus recorded");
    let composition = verdicts
        .iter()
        .find(|verdict| verdict.kind.as_str() == "composition")
        .expect("the composition case is recorded");
    assert!(
        !composition.passed,
        "the composition exceeds the shipped bound: {composition:?}"
    );

    let refused = store
        .activate_learning_delta(&second.delta_id, 1)
        .expect_err("a failed composition never activates");
    match delta_error(&refused) {
        DeltaError::CorpusRejected { kind, .. } => assert_eq!(*kind, "composition"),
        other => panic!("expected the refused composition case, got {other}"),
    }
    assert_eq!(
        store
            .learning_delta(&second.delta_id)
            .expect("row read")
            .state,
        DeltaState::Inactive
    );
}
